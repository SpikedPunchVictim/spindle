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
//!
//! # The compose copy
//!
//! `deploy/docker-compose.yml` sets `helper.environment.ACCOUNT_NAME`, a second deployed copy:
//! it overrides the binary's compiled default, so a rename applied to the constant and the conf
//! alone would pass the conf guard above while the running stack used the stale name.
//! [`compose_helper_account_name`] derives that value, and
//! [`compose_helper_account_name_matches_the_constant`] asserts the three sources agree.
//!
//! The compose parser is a deliberately small line scan, not a YAML implementation:
//!
//! - structural nesting comes from indentation, with tabs rejected (YAML forbids them for
//!   indentation);
//! - both compose `environment:` forms are handled: mapping (`KEY: "value"`) and list
//!   (`- KEY=value`). The checked-in file currently uses the mapping form only; the list form is
//!   supported because it is equally valid compose and would otherwise silently drop the guard;
//! - duplicate `helper` services, `environment:` blocks and `ACCOUNT_NAME` entries resolve
//!   **last-wins**, matching YAML/compose and the conf parser's lesson above. The reported line is
//!   the winning entry's;
//! - shapes this scan cannot resolve honestly are errors, never silent skips: flow-style or
//!   anchored definitions, a bare `- ACCOUNT_NAME` host pass-through, mixed mapping/list entries,
//!   a null value, and values using compose `$` interpolation;
//! - `#` comments outside quotes are stripped and simple quoted scalars are unquoted.

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

/// `<repo root>/deploy/docker-compose.yml`, located from this crate's manifest directory.
fn compose_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .expect("crates/spindle-helper always has a repository root two levels up")
        .join("deploy")
        .join("docker-compose.yml")
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

/// A non-blank, non-comment source line with its 1-based number and space indentation.
struct SourceLine<'a> {
    number: usize,
    indent: usize,
    text: &'a str,
}

/// Collects the structurally meaningful lines of a compose file, rejecting tab indentation.
///
/// Comment-only and blank lines are dropped: they cannot open or close a block, so the indentation
/// scan below can ignore them.
fn source_lines(src: &str) -> Result<Vec<SourceLine<'_>>, String> {
    let mut lines = Vec::new();
    for (offset, raw) in src.lines().enumerate() {
        let number = offset + 1;
        let body = raw.trim_start_matches([' ', '\t']);
        let leading = &raw[..raw.len() - body.len()];
        if leading.contains('\t') {
            return Err(format!("line {number}: tab indentation is not valid YAML"));
        }
        let text = body.trim_end();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        lines.push(SourceLine {
            number,
            indent: leading.len(),
            text,
        });
    }
    Ok(lines)
}

/// Splits `key: rest` at the first colon outside quotes. Returns `None` when there is no such
/// colon.
fn split_key(text: &str) -> Option<(&str, &str)> {
    let mut quote = None;
    let mut chars = text.char_indices();
    while let Some((index, c)) = chars.next() {
        match quote {
            Some('"') => {
                if c == '\\' {
                    chars.next();
                } else if c == '"' {
                    quote = None;
                }
            }
            Some(q) => {
                if c == q {
                    // YAML's single-quoted escape is a doubled quote.
                    match chars.clone().next() {
                        Some((_, '\'')) => {
                            chars.next();
                        }
                        _ => quote = None,
                    }
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                ':' => return Some((&text[..index], &text[index + 1..])),
                _ => {}
            },
        }
    }
    None
}

/// Returns the key of a `key: value` line, unquoted.
fn key_name(text: &str) -> Option<String> {
    let (key, _) = split_key(text)?;
    yaml_scalar(key.trim()).ok()
}

/// Like [`key_name`], but only for lines that open a block (nothing after the colon except
/// whitespace or a comment).
fn container_key(text: &str) -> Option<String> {
    let (key, rest) = split_key(text)?;
    if !strip_comment(rest).trim().is_empty() {
        return None;
    }
    yaml_scalar(key.trim()).ok()
}

/// Removes a trailing `#` comment, ignoring `#` inside single- or double-quoted scalars.
fn strip_comment(text: &str) -> &str {
    let mut quote = None;
    let mut previous_was_space = true;
    let mut chars = text.char_indices();
    while let Some((index, c)) = chars.next() {
        match quote {
            Some('"') => {
                if c == '\\' {
                    chars.next();
                } else if c == '"' {
                    quote = None;
                }
            }
            Some(q) => {
                if c == q {
                    match chars.clone().next() {
                        Some((_, '\'')) => {
                            chars.next();
                        }
                        _ => quote = None,
                    }
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '#' if previous_was_space => return &text[..index],
                _ => {}
            },
        }
        previous_was_space = c.is_whitespace();
    }
    text
}

/// Unquotes a YAML scalar. Plain scalars pass through unchanged; only the quoted forms this
/// guard's files can use are interpreted.
fn yaml_scalar(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    match raw.chars().next() {
        Some('"') => {
            if raw.len() < 2 || !raw.ends_with('"') {
                return Err(format!("unterminated double-quoted scalar {raw:?}"));
            }
            let inner = &raw[1..raw.len() - 1];
            let mut out = String::new();
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                match c {
                    '"' => return Err(format!("unescaped quote inside {raw:?}")),
                    '\\' => match chars.next() {
                        Some('"') => out.push('"'),
                        Some('\\') => out.push('\\'),
                        Some('n') => out.push('\n'),
                        Some('t') => out.push('\t'),
                        Some(other) => {
                            return Err(format!("unsupported escape `\\{other}` inside {raw:?}"))
                        }
                        None => return Err(format!("unterminated escape inside {raw:?}")),
                    },
                    other => out.push(other),
                }
            }
            Ok(out)
        }
        Some('\'') => {
            if raw.len() < 2 || !raw.ends_with('\'') {
                return Err(format!("unterminated single-quoted scalar {raw:?}"));
            }
            let inner = &raw[1..raw.len() - 1];
            let mut out = String::new();
            let mut chars = inner.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\'' {
                    if chars.peek() == Some(&'\'') {
                        out.push('\'');
                        chars.next();
                    } else {
                        return Err(format!("unescaped quote inside {raw:?}"));
                    }
                } else {
                    out.push(c);
                }
            }
            Ok(out)
        }
        _ => Ok(raw.to_string()),
    }
}

/// True for a YAML sequence entry (`- ...`).
fn is_list_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

/// Parses one `ACCOUNT_NAME` value, rejecting shapes that cannot be compared statically.
fn literal_account_name(raw: &str, line: usize) -> Result<String, String> {
    let raw = strip_comment(raw).trim();
    if raw.is_empty() {
        return Err(format!(
            "line {line}: ACCOUNT_NAME has a null value, which compose resolves ambiguously"
        ));
    }
    let value = yaml_scalar(raw).map_err(|err| format!("line {line}: {err}"))?;
    if value.contains('$') {
        return Err(format!(
            "line {line}: ACCOUNT_NAME uses compose interpolation ({value:?}); this guard cannot \
             evaluate it statically"
        ));
    }
    Ok(value)
}

/// Returns the winning `helper` service's `ACCOUNT_NAME` value and its 1-based source line.
///
/// Duplicate `helper` services, `environment:` blocks and `ACCOUNT_NAME` entries resolve
/// last-wins, matching YAML/compose and the conf parser above. Every unsupported shape is an
/// error rather than a guess; see this file's module docs for the list.
fn compose_helper_account_name(src: &str) -> Result<(String, usize), String> {
    let lines = source_lines(src)?;

    // Last top-level `services:` wins, same duplicate rule as everything else here.
    let services_index = lines
        .iter()
        .rposition(|line| {
            line.indent == 0 && container_key(line.text).as_deref() == Some("services")
        })
        .ok_or_else(|| "no top-level `services:` map found".to_string())?;

    // The `services:` map ends at the next top-level key (e.g. `volumes:`).
    let services_end = (services_index + 1..lines.len())
        .find(|&index| lines[index].indent == 0)
        .unwrap_or(lines.len());
    let service_indent = (services_index + 1..services_end)
        .map(|index| lines[index].indent)
        .min()
        .ok_or_else(|| "top-level `services:` map is empty".to_string())?;

    // Service names are the direct children of `services:`. Last `helper` wins.
    let helper_index = (services_index + 1..services_end)
        .rev()
        .find(|&index| {
            lines[index].indent == service_indent
                && key_name(lines[index].text).as_deref() == Some("helper")
        })
        .ok_or_else(|| "no `helper` service under top-level `services:`".to_string())?;
    let (_, helper_rest) = split_key(lines[helper_index].text)
        .expect("key_name succeeded for this line, so split_key must too");
    if !strip_comment(helper_rest).trim().is_empty() {
        return Err(format!(
            "line {}: flow-style or anchored `helper` service definitions are unsupported; \
             extend this guard rather than silently skipping the service",
            lines[helper_index].number
        ));
    }

    // The helper body runs until the next service entry at `service_indent`.
    let block_end = (helper_index + 1..services_end)
        .find(|&index| lines[index].indent == service_indent)
        .unwrap_or(services_end);
    let child_indent = (helper_index + 1..block_end)
        .map(|index| lines[index].indent)
        .min()
        .ok_or_else(|| "helper service has no body".to_string())?;

    // Last `environment:` block wins; nested lookalikes are deeper than a direct child.
    let env_index = (helper_index + 1..block_end)
        .rev()
        .find(|&index| {
            lines[index].indent == child_indent
                && key_name(lines[index].text).as_deref() == Some("environment")
        })
        .ok_or_else(|| {
            "helper service has no `environment:` block, so ACCOUNT_NAME is not set".to_string()
        })?;
    let (_, env_rest) = split_key(lines[env_index].text)
        .expect("key_name succeeded for this line, so split_key must too");
    if !strip_comment(env_rest).trim().is_empty() {
        return Err(format!(
            "line {}: flow-style or anchored `environment:` blocks are unsupported; extend this \
             guard rather than silently skipping the values",
            lines[env_index].number
        ));
    }

    let env_indent = lines[env_index].indent;
    let env_end = (env_index + 1..block_end)
        .find(|&index| lines[index].indent <= env_indent)
        .unwrap_or(block_end);
    let entries = &lines[env_index + 1..env_end];
    let first = entries.first().ok_or_else(|| {
        "helper service's `environment:` block is empty, so ACCOUNT_NAME is not set".to_string()
    })?;
    let list_form = is_list_item(first.text);

    let mut found = None;
    for line in entries {
        if list_form {
            if !is_list_item(line.text) {
                return Err(format!(
                    "line {}: mixed mapping and list entries in helper `environment:`",
                    line.number
                ));
            }
            let item = strip_comment(line.text[1..].trim()).trim();
            // A list entry may quote the whole `KEY=value` string.
            let item = if item.starts_with('"') || item.starts_with('\'') {
                yaml_scalar(item).map_err(|err| format!("line {}: {err}", line.number))?
            } else {
                item.to_string()
            };
            match item.split_once('=') {
                Some((key, value)) => {
                    let key = yaml_scalar(key.trim())
                        .map_err(|err| format!("line {}: {err}", line.number))?;
                    if key == "ACCOUNT_NAME" {
                        let value = literal_account_name(value, line.number)?;
                        found = Some((value, line.number));
                    }
                }
                None => {
                    let key = yaml_scalar(item.trim())
                        .map_err(|err| format!("line {}: {err}", line.number))?;
                    if key == "ACCOUNT_NAME" {
                        return Err(format!(
                            "line {}: bare `- ACCOUNT_NAME` passes the host environment through; \
                             this guard cannot compare that statically",
                            line.number
                        ));
                    }
                }
            }
        } else {
            if is_list_item(line.text) {
                return Err(format!(
                    "line {}: mixed mapping and list entries in helper `environment:`",
                    line.number
                ));
            }
            let (key, rest) = split_key(line.text).ok_or_else(|| {
                format!(
                    "line {}: expected `KEY: value` in helper `environment:`",
                    line.number
                )
            })?;
            let key =
                yaml_scalar(key.trim()).map_err(|err| format!("line {}: {err}", line.number))?;
            if key == "ACCOUNT_NAME" {
                let value = literal_account_name(rest, line.number)?;
                // Last duplicate wins, as in YAML and in the conf parser above.
                found = Some((value, line.number));
            }
        }
    }

    found.ok_or_else(|| {
        "helper service's `environment:` block does not set ACCOUNT_NAME".to_string()
    })
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

/// The real three-way guard: the constant (this test's `DEFAULT_ACCOUNT_NAME`), the conf's
/// accounts map, and the compose helper service's override must all name the same account.
#[test]
fn compose_helper_account_name_matches_the_constant() {
    let path = compose_path();
    let src = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    let (value, line) = compose_helper_account_name(&src)
        .unwrap_or_else(|err| panic!("cannot parse {}: {err}", path.display()));

    let conf_path = deploy_conf_path();
    let conf_accounts = fs::read_to_string(&conf_path)
        .ok()
        .and_then(|conf| account_names(&conf).ok())
        .map_or_else(|| "<unreadable>".to_string(), |names| format!("{names:?}"));

    assert_eq!(
        value,
        DEFAULT_ACCOUNT_NAME,
        "account-name drift across three sources:\n\
         - constant: spindle_helper::DEFAULT_ACCOUNT_NAME = {DEFAULT_ACCOUNT_NAME:?} \
           (crates/spindle-helper/src/lib.rs)\n\
         - conf: {} declares accounts {conf_accounts}\n\
         - compose: {}:{line} sets helper ACCOUNT_NAME = {value:?}",
        conf_path.display(),
        path.display()
    );
}

#[test]
fn compose_parser_reads_mapping_and_list_forms() {
    let mapping = "\
services:
  postgres:
    environment:
      ACCOUNT_NAME: \"NOT_THE_HELPER\"
  helper:
    build:
      context: ..
    environment:
      NATS_URL: \"nats://nats:4222\"
      ACCOUNT_NAME: \"APP\"   # the winning value
";
    assert_eq!(
        compose_helper_account_name(mapping).expect("mapping fixture parses"),
        ("APP".to_string(), 10)
    );

    let list = "\
services:
  helper:
    environment:
      - NATS_URL=nats://nats:4222
      - ACCOUNT_NAME=APP
";
    assert_eq!(
        compose_helper_account_name(list).expect("list fixture parses"),
        ("APP".to_string(), 5)
    );
}

#[test]
fn compose_parser_takes_the_last_declaration() {
    // Duplicate helper service: the later service definition wins.
    let duplicate_service = "\
services:
  helper:
    environment:
      ACCOUNT_NAME: FIRST
  helper:
    environment:
      ACCOUNT_NAME: SECOND
";
    assert_eq!(
        compose_helper_account_name(duplicate_service).expect("fixture parses"),
        ("SECOND".to_string(), 7)
    );

    // Duplicate key inside one environment map: the later value wins, as YAML/compose do.
    let duplicate_key = "\
services:
  helper:
    environment:
      ACCOUNT_NAME: FIRST
      NATS_URL: nats://nats:4222
      ACCOUNT_NAME: LAST
";
    assert_eq!(
        compose_helper_account_name(duplicate_key).expect("fixture parses"),
        ("LAST".to_string(), 6)
    );
}

#[test]
fn compose_parser_refuses_shapes_it_cannot_resolve() {
    let flow = "\
services:
  helper:
    environment: { ACCOUNT_NAME: APP }
";
    let err = compose_helper_account_name(flow).expect_err("flow map is unsupported");
    assert!(err.contains("flow-style"), "unexpected error: {err}");

    let pass_through = "\
services:
  helper:
    environment:
      - ACCOUNT_NAME
";
    let err =
        compose_helper_account_name(pass_through).expect_err("bare pass-through is ambiguous");
    assert!(
        err.contains("passes the host environment through"),
        "unexpected error: {err}"
    );

    let mixed = "\
services:
  helper:
    environment:
      ACCOUNT_NAME: APP
      - NATS_URL=nats://nats:4222
";
    let err = compose_helper_account_name(mixed).expect_err("mixed forms are unsupported");
    assert!(
        err.contains("mixed mapping and list"),
        "unexpected error: {err}"
    );

    let interpolated = "\
services:
  helper:
    environment:
      ACCOUNT_NAME: ${ACCOUNT_NAME:-APP}
";
    let err = compose_helper_account_name(interpolated).expect_err("interpolation is unsupported");
    assert!(err.contains("interpolation"), "unexpected error: {err}");

    let missing = "\
services:
  helper:
    environment:
      NATS_URL: nats://nats:4222
";
    let err = compose_helper_account_name(missing).expect_err("missing ACCOUNT_NAME is an error");
    assert!(
        err.contains("does not set ACCOUNT_NAME"),
        "unexpected error: {err}"
    );
}
