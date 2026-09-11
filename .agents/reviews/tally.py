#!/usr/bin/env python3
"""Tally defect-class evidence across the review-record corpus.

Walks .agents/reviews/**/*.md (mined/ today, rounds/ once first-hand records
exist), parses each record's YAML frontmatter with a small hand-rolled
regex parser (standard library only -- no PyYAML dependency, matching the
rest of this repo's tooling), and reports counts by class, family,
severity, detection method, introduced_by_kind, verdict, and fidelity.

Families are computed here from FAMILY_MAP rather than stored as a field on
each record, deliberately: regrouping classes into different families is
then a one-line edit to this script, never a rewrite of evidence files.
The records are the evidence; the grouping is just a lens on top of it.

Usage:
    python3 .agents/reviews/tally.py                # full summary
    python3 .agents/reviews/tally.py --class missing-guard
    python3 .agents/reviews/tally.py --family unverified-claim
"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

# Family -> member classes. Edit this table to regroup; it is the only
# place family membership is decided. Any class not listed here maps to
# the synthetic family "unclassified" and is surfaced as a data-quality
# problem (new vocabulary should be added to this table, not silently
# absorbed).
FAMILY_MAP = {
    "absent-invariant": [
        "missing-guard",
        "race-induced-fail-open",
    ],
    "unverified-claim": [
        "unverified-coverage-claim",
        "false-absence-claim",
        "unverified-existence-claim",
        "unverified-code-claim",
        "unverified-external-shape",
        "fabricated-code-description",
        "scope-mismatch",
    ],
    "rotting-reference": [
        "stale-line-citation",
        "stale-doc-row",
        "inherited-figure",
        "miscounted-figure",
    ],
    "vacuous-check": [
        "false-green",
        "symbolic-constant-not-pinned",
        "unsound-search-receipt",
    ],
    "wrong-explanation": [
        "wrong-mechanism",
    ],
    "unimplementable-spec": [
        "spec-cannot-execute",
    ],
    "cosmetic": [
        "doc-rendering-defect",
    ],
}

UNCLASSIFIED_FAMILY = "unclassified"

CLASS_TO_FAMILY = {
    cls: family for family, classes in FAMILY_MAP.items() for cls in classes
}
KNOWN_CLASSES = set(CLASS_TO_FAMILY)

REVIEWS_DIR = Path(__file__).resolve().parent

FRONTMATTER_RE = re.compile(r"^---\r?\n(.*?\r?\n)---\r?\n?", re.DOTALL)
FINDING_START_RE = re.compile(r"^-\s*id:\s*(.*)$")
KEY_VALUE_RE = re.compile(r"^([A-Za-z_]+):\s?(.*)$")


def _unquote(raw):
    """Turn a raw YAML scalar (as captured off one line) into a Python value."""
    value = raw.strip()
    if value == "null" or value == "":
        return None
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        inner = value[1:-1]
        return inner.replace('\\"', '"')
    return value


def parse_frontmatter(text):
    """Parse the leading --- delimited frontmatter block of a record.

    Returns a dict with the top-level fields plus a 'findings' list of
    dicts, or None if no frontmatter block could be found at all.

    This is a purpose-built parser for this repo's fixed record schema
    (SCHEMA.md), not a general YAML parser: it assumes every scalar value
    sits entirely on one line (true for every record checked in), and
    that findings are a flat list of flat dicts under a top-level
    'findings:' key. It will raise ValueError if that shape is violated,
    which the caller reports as a parse failure rather than silently
    producing a half-populated record.
    """
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None

    record = {}
    findings = []
    current = None
    in_findings = False

    for line in m.group(1).splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        finding_start = FINDING_START_RE.match(stripped)
        if in_findings and finding_start:
            if current is not None:
                findings.append(current)
            current = {"id": _unquote(finding_start.group(1))}
            continue

        kv = KEY_VALUE_RE.match(stripped)
        if not kv:
            raise ValueError(f"unparseable frontmatter line: {stripped!r}")
        key, raw_value = kv.group(1), kv.group(2)

        if key == "findings":
            in_findings = True
            continue

        if in_findings:
            if current is None:
                raise ValueError(f"finding field {key!r} before any '- id:'")
            current[key] = _unquote(raw_value)
        else:
            record[key] = _unquote(raw_value)

    if current is not None:
        findings.append(current)

    if not findings:
        raise ValueError("no findings parsed")

    record["findings"] = findings
    return record


def load_records():
    """Walk .agents/reviews/**/*.md (skipping README.md) and parse each.

    Returns (records, failures) where records is a list of
    (path, parsed-dict) and failures is a list of (path, error-message).
    """
    records = []
    failures = []
    for path in sorted(REVIEWS_DIR.rglob("*.md")):
        if path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8")
        try:
            parsed = parse_frontmatter(text)
            if parsed is None:
                raise ValueError("no --- frontmatter block found")
        except ValueError as exc:
            failures.append((path, str(exc)))
            continue
        records.append((path, parsed))
    return records, failures


def family_of(cls):
    return CLASS_TO_FAMILY.get(cls, UNCLASSIFIED_FAMILY)


def truncate(text, width=72):
    if text is None:
        return "(none)"
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    return text[: width - 1].rstrip() + "…"


def print_counter(title, counter):
    print(f"\n{title} (sorted by count):")
    total = sum(counter.values())
    for key, count in counter.most_common():
        label = key if key is not None else "(missing)"
        print(f"  {count:4d}  {label}")
    print(f"  {total:4d}  TOTAL")


def cmd_summary(records, failures):
    all_findings = []
    for path, rec in records:
        sha = path.stem
        for finding in rec["findings"]:
            all_findings.append((sha, rec, finding))

    print("== Corpus ==")
    print(f"records parsed:  {len(records)}")
    print(f"findings parsed: {len(all_findings)}")
    print(f"parse failures:  {len(failures)}")
    for path, err in failures:
        print(f"  FAILED: {path} -- {err}")

    class_counter = Counter(f["class"] for _, _, f in all_findings)
    family_counter = Counter(family_of(f["class"]) for _, _, f in all_findings)
    severity_counter = Counter(f["severity"] for _, _, f in all_findings)
    detection_counter = Counter(f["detection"] for _, _, f in all_findings)
    introduced_counter = Counter(f["introduced_by_kind"] for _, _, f in all_findings)
    verdict_counter = Counter(rec["verdict"] for _, rec in records)
    fidelity_counter = Counter(rec["fidelity"] for _, rec in records)

    print_counter("Class", class_counter)
    print_counter("Family", family_counter)
    print_counter("Severity", severity_counter)
    print_counter("Detection", detection_counter)
    print_counter("Introduced-by kind", introduced_counter)
    print_counter("Verdict (per record)", verdict_counter)
    print_counter("Fidelity (per record)", fidelity_counter)

    known_kinds = [
        f["introduced_by_kind"]
        for _, _, f in all_findings
        if f["introduced_by_kind"] not in (None, "unknown")
    ]
    correction_count = sum(1 for k in known_kinds if k == "correction-commit")
    print("\n== Headline metric ==")
    if known_kinds:
        pct = 100.0 * correction_count / len(known_kinds)
        print(
            f"correction-commit share of findings with known introduced_by_kind: "
            f"{correction_count}/{len(known_kinds)} ({pct:.1f}%)"
        )
    else:
        print("correction-commit share: no findings with known introduced_by_kind")

    print("\n== Data quality ==")
    problems = 0

    bad_class = [
        (sha, f["id"], f["class"])
        for sha, _, f in all_findings
        if f["class"] not in KNOWN_CLASSES
    ]
    if bad_class:
        problems += len(bad_class)
        print(f"unknown class values ({len(bad_class)}):")
        for sha, fid, cls in bad_class:
            print(f"  {sha} {fid}: class={cls!r} not in FAMILY_MAP vocabulary")
    else:
        print("unknown class values: 0")

    missing_check = [
        (sha, f["id"])
        for sha, _, f in all_findings
        if not f.get("implementer_could_have_caught_by")
    ]
    if missing_check:
        problems += len(missing_check)
        print(f"findings missing implementer_could_have_caught_by ({len(missing_check)}):")
        for sha, fid in missing_check:
            print(f"  {sha} {fid}")
    else:
        print("findings missing implementer_could_have_caught_by: 0")

    if problems == 0:
        print("\nno data-quality problems found.")

    return 1 if failures else 0


def cmd_filter(records, cls, family):
    rows = []
    for path, rec in records:
        sha = path.stem
        for finding in rec["findings"]:
            f_class = finding["class"]
            f_family = family_of(f_class)
            if cls is not None and f_class != cls:
                continue
            if family is not None and f_family != family:
                continue
            rows.append((sha, finding))

    if not rows:
        what = f"class={cls!r}" if cls else f"family={family!r}"
        print(f"no findings match {what}")
        return 0

    for sha, finding in rows:
        severity = finding.get("severity") or "unknown"
        f_class = finding.get("class") or "unknown"
        summary = truncate(finding.get("claim"))
        print(f"{sha}  {severity:8s}  {f_class:32s}  {summary}")
    print(f"\n{len(rows)} finding(s) matched")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--class", dest="cls", help="list findings with this class slug")
    parser.add_argument("--family", dest="family", help="list findings in this family")
    args = parser.parse_args(argv)

    if args.cls and args.family:
        parser.error("pass only one of --class or --family")

    records, failures = load_records()

    if args.cls or args.family:
        return cmd_filter(records, args.cls, args.family)
    return cmd_summary(records, failures)


if __name__ == "__main__":
    sys.exit(main())
