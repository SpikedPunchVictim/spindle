---
review_id: bc4f2bb6b1b472bdb9e16d4727d221fe0117506c
date: 2026-08-31
ticket: null
scope_commits: [bc4f2bb6b1b472bdb9e16d4727d221fe0117506c]
verdict: REJECT
provenance: mined-from-commit
fidelity: second-hand
source_note: "The commit is itself an empirical spike ('Probed against the composed stack's nats-server 2.10.29') deliberately run to check a documented claim before building against it; the second finding is the spike's own verdict-logic self-audit."
findings:
  - id: F1
    severity: reject
    class: spec-cannot-execute
    file: DESIGN.md
    line: null
    claim: "DESIGN.md §A4 specifies kicking a live connection with $SYS.REQ.SERVER.<id>.KICK {id: cid}."
    reality: "Probed against the composed stack's nats-server 2.10.29, that payload does not kick anything: the server replies {\"error\":{\"code\":500,\"description\":\"no such client or leafnode id\"}} and the connection stays up. The working field name is cid -- {\"cid\": <cid>} drops the connection and produces a DISCONNECT advisory carrying \"reason\": \"Kicked\"."
    detection: empirical
    evidence: "server replies {\"error\":{\"code\":500,\"description\":\"no such client or leafnode id\"}}"
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "probe the documented $SYS.REQ.SERVER.<id>.KICK payload against a real nats-server instance before writing it into the design doc as fact"
    td_ref: null
  - id: F2
    severity: reject
    class: false-green
    file: spikes/s9-revoke-kick/src/main.rs
    line: null
    claim: "The probe's kick-verdict logic reported CONNECTION ACTUALLY DROPPED (confirmed) as proof that a KICK request actually kicked the target connection."
    reality: "The probe's own first verdict logic was a false green [...]: it counted any DISCONNECT advisory for the target cid as proof of a kick, so both no responders attempts printed \"CONNECTION ACTUALLY DROPPED (confirmed)\" immediately below their own \"connection_state() after: Connected\" line -- their advisories said \"reason\": \"Client Closed\", the probe's own teardown. [...] only the automated verdict lied. A kick is now confirmed solely on reason == \"Kicked\"."
    detection: reread
    evidence: "\"CONNECTION ACTUALLY DROPPED (confirmed)\" printed under a \"connection_state() after: Connected\" line whose advisory actually said reason: \"Client Closed\""
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "gate the kick verdict on the advisory's reason field equal to \"Kicked\" specifically, rather than on the mere presence of any DISCONNECT advisory for the target cid"
    td_ref: null
---

## What the commit says

> DESIGN.md §A4 specifies kicking a live connection with
> `$SYS.REQ.SERVER.<id>.KICK {id: cid}`. Probed against the composed stack's
> nats-server 2.10.29, that payload does not kick anything: the server
> replies `{"error":{"code":500,"description":"no such client or leafnode
> id"}}` and the connection stays up. The working field name is `cid`. [...]
> A reply arrives either way, so an implementation that trusted the reply
> would have reported kicks that never happened. That is the whole reason
> this was probed before being built rather than after.
>
> The probe's own first verdict logic was a false green and is fixed here
> before anything depends on it: it counted any DISCONNECT advisory for the
> target cid as proof of a kick, so both `no responders` attempts printed
> "CONNECTION ACTUALLY DROPPED (confirmed)" immediately below their own
> "connection_state() after: Connected" line — their advisories said
> `"reason": "Client Closed"`, the probe's own teardown. The raw captures
> and RESULTS.md's prose were correct throughout; only the automated verdict
> lied.

## Reading

Two independent findings in one spike. First, the design document's specified KICK payload field name (`id`) is simply wrong against a real NATS server — it produces an error reply while leaving the connection alive, and because NATS always replies to a system request either way, any implementation trusting the reply's mere presence would have logged successful kicks that never happened; this is exactly why the mechanic was probed empirically before being built into production. Second, and more interesting for this repo's pattern, the probe script itself had a false-green bug in its own verdict logic: it treated any disconnect advisory for the target connection ID as proof of a kick, when in two of its own runs the advisory it was reading was the probe's own teardown disconnect, not a kick at all — yet the automated verdict declared success. The raw evidence and the human-written prose in RESULTS.md were correct the whole time; only the automated pass/fail check lied, which is the same shape as 867b806's is_err()-only pinning test. Both findings were caught before any production code depended on them, which is the stated point of spiking this mechanism first.
