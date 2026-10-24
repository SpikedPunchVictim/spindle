//! Deploy-config guard: the helper's default NATS account name must be one the deployed
//! `nats-server` actually has.
//!
//! `src/bin/helper.rs`'s `--account-name` / `ACCOUNT_NAME` default comes from
//! [`spindle_helper::DEFAULT_ACCOUNT_NAME`], and the callout responder mints every User JWT
//! against that account. If `deploy/nats/nats-server.conf`'s `accounts:` map does not declare it,
//! the server refuses the connection at CONNECT time — a silent authorization failure, not a
//! startup error on either side. This test derives the names from the conf rather than restating
//! them, so a rename on either side goes red.
//!
//! # Duplicate declarations: last wins
//!
//! td-db47f9's lesson was that a conf parser returning the FIRST match goes false-green when
//! nats-server honours the LAST. This parser therefore scans **every** depth-0 `accounts:`
//! declaration and uses the last one. That is the server's behaviour, verified empirically
//! 2026-10-24 against `nats:2.10-alpine` (v2.10.29, the tag S1 pinned):
//!
//! - a config with two top-level `accounts:` blocks (first `FOO`, second `APP`) started cleanly
//!   and `/accountz` listed only `APP` — the later block **replaces** the earlier one, it does not
//!   merge;
//! - a single `accounts:` map declaring `APP` twice likewise listed one `APP`.
//!
//! `nats-server -t` reports both shapes "valid", so validation alone cannot catch the ambiguity;
//! resolving last-wins here matches what the server actually serves. The parser's own tests below
//! pin that last-wins choice independently of the real conf.

use std::fs;
use std::path::PathBuf;

use spindle_helper::DEFAULT_ACCOUNT_NAME;

/// `<repo root>/deploy/nats/nats-server.conf`, located from this crate's manifest directory
/// (`<repo root>/crates/spindle-helper`).
fn deploy_conf_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .expect("crates/spindle-helper always has a repository root two levels up")
        .join("deploy")
        .join("nats")
        .join("nats-server.conf")
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Colon,
    Comma,
}

/// Tokenizes the subset of the nats-server config language this guard needs: bare/quoted words,
/// the four brackets, `:`, `,`, and `#`-to-end-of-line comments. Tokens are split at braces,
/// brackets, colons and commas even without surrounding whitespace.
fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {}
            '#' => {
                for ch in chars.by_ref() {
                    if ch == '\n' {
                        break;
                    }
                }
            }
            '{' => tokens.push(Token::LBrace),
            '}' => tokens.push(Token::RBrace),
            '[' => tokens.push(Token::LBracket),
            ']' => tokens.push(Token::RBracket),
            ':' => tokens.push(Token::Colon),
            ',' => tokens.push(Token::Comma),
            '"' => {
                let mut word = String::new();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(escaped) => word.push(escaped),
                            None => return Err("unterminated escape in quoted string".to_string()),
                        },
                        Some(ch) => word.push(ch),
                        None => return Err("unterminated quoted string".to_string()),
                    }
                }
                tokens.push(Token::Word(word));
            }
            other => {
                let mut word = String::new();
                word.push(other);
                while let Some(&ch) = chars.peek() {
                    if ch.is_whitespace()
                        || matches!(ch, '{' | '}' | '[' | ']' | ':' | ',' | '#' | '"')
                    {
                        break;
                    }
                    word.push(ch);
                    chars.next();
                }
                tokens.push(Token::Word(word));
            }
        }
    }
    Ok(tokens)
}

/// Index of the bracket that closes `open` (`tokens[open]` must be `{` or `[`).
fn matching_bracket(tokens: &[Token], open: usize) -> Result<usize, String> {
    let (opening, closing) = match tokens.get(open) {
        Some(Token::LBrace) => (Token::LBrace, Token::RBrace),
        Some(Token::LBracket) => (Token::LBracket, Token::RBracket),
        other => {
            return Err(format!(
                "expected an opening bracket at token {open}, found {other:?}"
            ))
        }
    };
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        if *token == opening {
            depth += 1;
        } else if *token == closing {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| format!("unbalanced {closing:?} at token {index}"))?;
            if depth == 0 {
                return Ok(index);
            }
        }
    }
    Err(format!("no closing {closing:?} for token {open}"))
}

/// Returns the account names declared by the **last** depth-0 `accounts:` map in `src`.
///
/// Last-wins is deliberate and matches nats-server (see this file's module docs); a parser that
/// took the first declaration would go false-green on a conf with two of them.
fn account_names(src: &str) -> Result<Vec<String>, String> {
    let tokens = tokenize(src)?;

    // Find the last depth-0 `accounts: {` sequence. Depth-1-or-deeper lookalikes (e.g. an
    // `accounts` key inside some nested block) are not the server's account map.
    let mut last_declaration = None;
    let mut depth = 0usize;
    for index in 0..tokens.len() {
        match &tokens[index] {
            Token::LBrace | Token::LBracket => depth += 1,
            Token::RBrace | Token::RBracket => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("unbalanced closing bracket at token {index}"))?
            }
            Token::Word(word)
                if depth == 0
                    && word == "accounts"
                    && tokens.get(index + 1) == Some(&Token::Colon)
                    && tokens.get(index + 2).is_some_and(|t| *t == Token::LBrace) =>
            {
                last_declaration = Some(index + 2);
            }
            _ => {}
        }
    }
    let open = last_declaration.ok_or_else(|| "no depth-0 `accounts:` map found".to_string())?;
    let close = matching_bracket(&tokens, open)?;

    let mut names = Vec::new();
    let mut index = open + 1;
    while index < close {
        let key = match &tokens[index] {
            Token::Word(key) => key.clone(),
            other => {
                return Err(format!(
                    "expected an account name at token {index}, found {other:?}"
                ))
            }
        };
        if tokens.get(index + 1) != Some(&Token::Colon) {
            return Err(format!("account {key:?} is not followed by `:`"));
        }
        index += 2;
        match tokens.get(index) {
            Some(Token::LBrace) | Some(Token::LBracket) => {
                index = matching_bracket(&tokens, index)? + 1;
            }
            Some(Token::Word(_)) => index += 1,
            other => {
                return Err(format!(
                    "expected a value for account {key:?}, found {other:?}"
                ))
            }
        }
        if tokens.get(index) == Some(&Token::Comma) {
            index += 1;
        }
        names.push(key);
    }
    Ok(names)
}

#[test]
fn default_account_name_is_declared_in_the_deploy_conf() {
    let path = deploy_conf_path();
    let src = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    let accounts =
        account_names(&src).unwrap_or_else(|err| panic!("cannot parse {}: {err}", path.display()));

    assert!(
        !accounts.is_empty(),
        "{} declares an `accounts:` map with no accounts: {accounts:?}",
        path.display()
    );
    assert!(
        accounts.iter().any(|name| name == DEFAULT_ACCOUNT_NAME),
        "spindle_helper::DEFAULT_ACCOUNT_NAME is {DEFAULT_ACCOUNT_NAME:?}, but {} declares \
         accounts {accounts:?}",
        path.display()
    );
}

#[test]
fn parser_takes_the_last_accounts_declaration() {
    // Two depth-0 declarations; nats-server serves the later one, so the parser must too.
    let src = r#"
        accounts: { FIRST: { users: [ { user: a, password: p } ] } }
        # a later block replaces the earlier one
        accounts: {
          SECOND: { nkey: "AAJ..." }
          THIRD: { users: [] }
        }
    "#;
    assert_eq!(
        account_names(src).expect("fixture parses"),
        vec!["SECOND".to_string(), "THIRD".to_string()]
    );
}

#[test]
fn parser_ignores_nested_lookalikes_and_comments() {
    let src = r#"
        authorization {
          embedded {
            accounts: { FAKE: {} }   # not the server's account map
          }
          auth_callout { account: AUTH }
        }
        accounts: {
          # accounts: { ALSO_FAKE: {} } — a comment, ignored
          APP: { nkey: "AAJ..." }
          AUTH: { users: [ { nkey: "UBO..." } ] }
          SYS: {}
        }
    "#;
    assert_eq!(
        account_names(src).expect("fixture parses"),
        vec!["APP".to_string(), "AUTH".to_string(), "SYS".to_string()]
    );
}
