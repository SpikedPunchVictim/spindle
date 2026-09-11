# Review-record corpus

## What this is

This repo runs adversarial, independent review on its own work: a change lands, a
separate reviewer (often a separate agent session, sometimes the implementer doing a
later audit) tries to break it, and sometimes finds something wrong that had already
shipped or nearly shipped. Each of those findings used to live only inside the commit
message that fixed it. Recovering "how often does the reviewer catch a missing guard
versus a stale citation" meant re-reading up to 193 long commit messages by hand, and
nobody actually did that, so the implementer's process improved (or didn't) on
impression rather than on evidence.

This directory turns those commit messages into a structured, queryable corpus. One
record per source commit, with YAML frontmatter naming a defect `class`, its
`severity`, how it was `detection`-ed, whether it traces to the `original` commit or
to an earlier `correction-commit`, and — the field that matters most for actually
getting better — the specific, executable check that `implementer_could_have_caught_by`
before ever sending the change for review. The point is not to relitigate old commits.
It is to make defect *classes* countable, so a claim like "we keep missing guards on
sibling code paths" or "half of these are corrections that reintroduced the same bug"
can be checked against real counts instead of asserted from memory.

## Layout

- `mined/<short-sha>.md` — second-hand records reconstructed from this repo's own
  commit messages. `provenance: mined-from-commit`, `fidelity: second-hand`. These are
  **the implementer's own account of what a review found**, written after the fact,
  not the reviewer's verbatim words. There are 75 of them today, holding 141 findings.
- `rounds/<review-id>.md` — first-hand records, added going forward, written directly
  from a reviewer's verbatim report at the time of the review. `fidelity: first-hand`.
  This directory does not have any yet; it exists so future reviews have somewhere
  honest to land without retroactively upgrading old evidence.

### Why the fidelity split matters

A second-hand record is good evidence for *class frequency* — the commit either says
"missing-guard" happened or it doesn't, and that's a fact about the corpus regardless
of who is describing it. It is weak evidence for *root cause*, because the person
writing the commit message is the person the review was criticising. An implementer
summarizing their own reviewed-and-rejected work has every incentive, mostly
unconscious, to round the finding down, soften the mechanism, or omit the parts that
reflect worst on the process. Trust the second-hand corpus for "how often" questions.
Be skeptical of it for "why" questions until a first-hand `rounds/` record confirms the
same shape from the reviewer's own words.

## Frontmatter schema

One file per source. Frontmatter is YAML and must parse; the body is prose giving the
commit's own account and, where useful, a short reading of what the record means.

```yaml
---
review_id: <sha or review identifier>
date: <YYYY-MM-DD>                  # commit author date, or review date for rounds/
ticket: <td-xxxxxx or null>
scope_commits: [<sha>, ...]
verdict: REJECT | APPROVE | PARTIAL | UNKNOWN
provenance: mined-from-commit | first-hand-report
fidelity: second-hand | first-hand
source_note: <one line: what carries the review signal, or how the record was captured>
findings:
  - id: F1
    severity: reject | minor | nit | unknown
    class: <kebab-case defect-class slug>
    file: <path or null>
    line: <int or null>
    claim: <what the implementer had asserted, quoted verbatim if the source quotes it>
    reality: <what was actually true>
    detection: empirical | trace | search | reread | unknown
    evidence: <command/output if the source records one, else null>
    introduced_by: <sha or null>
    introduced_by_kind: original | correction-commit | unknown
    implementer_could_have_caught_by: <the specific pre-commit check that would catch it>
    td_ref: <td-id or null>
---
```

`provenance` and `fidelity` travel together: `mined-from-commit` records are always
`second-hand`; a `rounds/` record written from a reviewer's own report is
`first-hand-report` / `first-hand`. Don't mix them on one record.

### class vocabulary

Extend only when nothing existing fits, and prefer an existing slug over a new one.
The classes seen so far, and the family each rolls up to (families are computed by
`tally.py`, not stored — see that script's docstring for why):

- **absent-invariant** — `missing-guard`, `race-induced-fail-open`
- **unverified-claim** — `unverified-coverage-claim`, `false-absence-claim`,
  `unverified-existence-claim`, `unverified-code-claim`, `unverified-external-shape`,
  `fabricated-code-description`, `scope-mismatch`
- **rotting-reference** — `stale-line-citation`, `stale-doc-row`, `inherited-figure`,
  `miscounted-figure`
- **vacuous-check** — `false-green`, `symbolic-constant-not-pinned`,
  `unsound-search-receipt`
- **wrong-explanation** — `wrong-mechanism`
- **unimplementable-spec** — `spec-cannot-execute`
- **cosmetic** — `doc-rendering-defect`

A class that fits none of these becomes its own new slug in the finding, and — until
someone decides where it belongs — falls into the synthetic `unclassified` family,
which `tally.py` reports as a data-quality problem so it gets a real home rather than
silently diluting an existing family's count.

## Records are evidence, not tasks

`td` is the sole task tracker for this repo. A review record documents what a review
found; it does not track what to do about it. If a finding is still actionable, it
gets a `td` id and the record points to it through `td_ref` — never the other way
around, and never a checkbox or status field living in this directory. This corpus
must never grow into a second board. If you catch yourself wanting to mark a record
"open" or "in progress," that state belongs in `td`, and the record should just carry
the `td_ref`.

## Adding a record

1. Pick the right directory: `mined/` only for reconstructing an old commit message;
   `rounds/` for a review happening now, written from the reviewer's own report.
2. Fill in every frontmatter field. Follow the honesty rules below — they matter more
   than completeness.
3. Write the body: what the source said (quoted where it's a mined record), and
   optionally a short reading of what the finding means.
4. Run `python3 .agents/reviews/tally.py` and confirm the new record parses (record
   and finding counts go up by the expected amount, no new parse failure) and that any
   new `class` value either matches existing vocabulary or is a deliberate addition to
   the table above and to `tally.py`'s `FAMILY_MAP`.
5. If the finding is still actionable, file or link a `td` id and set `td_ref`.

### Honesty rules (from the schema)

- **Never invent a field.** If the source doesn't give you enough to fill a field,
  write `null` (or `unknown` where the schema defines that value). A blank is honest;
  a guess is not.
- **Quote verbatim where the source quotes.** Don't paraphrase a claim into something
  stronger or weaker than what was actually said.
- **A mention of review, or a rejected design alternative, is not a review record.**
  Only file one where a review — or the implementer's own later audit — found
  something *wrong* that had already shipped or nearly shipped.
- **`implementer_could_have_caught_by` must name an executable check, never a
  platitude.** "Re-run the measurement at the stated scope" is a check. "Be more
  careful" is not, and does not belong in this field.

## Running the tally

```sh
python3 .agents/reviews/tally.py
```

Prints record and finding counts, parse failures (by name, if any), and — each sorted
by count descending — tallies of `class`, `family`, `severity`, `detection`,
`introduced_by_kind`, `verdict`, and `fidelity`. It also prints the corpus's headline
metric, the `correction-commit` share of findings whose `introduced_by_kind` is known,
and a data-quality section flagging any `class` outside the known vocabulary and any
finding missing `implementer_could_have_caught_by`.

To drill into one pattern instead of the summary:

```sh
python3 .agents/reviews/tally.py --class missing-guard
python3 .agents/reviews/tally.py --family unverified-claim
```

Each prints the matching findings as `<sha>  <severity>  <class>  <one-line summary>`.

The script has no dependencies beyond the standard library (it parses frontmatter with
a regex, the same way the rest of this repo's tooling avoids a YAML dependency for
structured-but-simple files) and resolves every path relative to its own location, so
it works the same whether invoked as `python3 .agents/reviews/tally.py` from the repo
root or by absolute path from anywhere else.
