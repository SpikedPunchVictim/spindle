# Spindle — repo instructions

## Task tracking

**`td` is the sole task tracker for this repo.** Every actionable item — bugs, features, chores,
decisions — lives on the td board, with its own context, priority, and acceptance criteria.
`td ready` shows the queue; `td usage --new-session -q` restores state in a fresh context.

Do not keep task lists anywhere else. `IMPLEMENTATION_PLAN.md` holds the staged plan and the
narrative record only — stage goals, success criteria, what was proven live and what remains
unproven. Stage status belongs there; tasks belong in td.

Note that `.todos/` is gitignored, so the board is local to this machine and is **not** shared by
cloning the repo. To hand the board to someone else, use `td export` / `td import`, or configure
`td sync` against a shared server (`td sync status` reports the current configuration).

<!-- td-agent-instructions:start -->
<!-- td-agent-instructions:version=3 -->

## Working with td

td keeps task context durable across sessions. In a new context, run `td usage --new-session -q` to see current work.

Use your judgment about how much tracking a task needs. For substantive work: `td start <id>`, record progress with `td log`, hand off with `td handoff <id>`, then `td review <id>`.

Closing needs a review. Say who did it (default trusted mode; delegated/strict allow only the first):

- independent session: `td approve <id> --reason "..."`
- a sub-agent: `td approve <id> --reviewed-by "<who>"`
- you: `td approve <id> --self-review --reason "..."`

Prefer a reviewer with its own `TD_CONTEXT_ID`; never name one who did not review.

Run `td usage` or `td <command> --help`.

<!-- td-agent-instructions:end -->
