// The documented admin command surface and its NATS subjects (DESIGN.md §A3b / §A5, ADR-007).
//
// DESIGN.md fixes the wildcard permission `registry.admin.>` but does not spell out a per-command
// subject mapping, and no helper handler exists yet (DESIGN.md §A5 status column / §A9 divergence list). This module is the
// library's single, explicit statement of that surface:
//
//   registry.admin.<cmd>     for every `cmd` in ADMIN_COMMAND_NAMES
//
// The three names pinned by the committed golden vectors (`vectors/admin-command.json` and
// `vectors/signed/admin-command.json`) are `set_mode`, `evict_host`, and
// `rotate_admission_key`. The remaining names follow ADR-007's operator-capability list verbatim
// ("mint or revoke admission invites", "pre-register a host_fp", "list admitted hosts",
// "suspend/evict a host", "set quota profiles", "read the audit log"). This mapping is provisional
// until the helper's admin handler lands; changing a name here is a protocol change, not a local
// refactor.

import { AdminError } from "./errors.js";

/** Every admin subject starts here (DESIGN.md §A5: `registry.admin.>`). */
export const ADMIN_SUBJECT_PREFIX = "registry.admin." as const;

/** The documented operator command names (see the module comment for their source). */
export const ADMIN_COMMAND_NAMES = [
  // Admission mode.
  "set_mode",
  // Admission invites.
  "mint_invite",
  "revoke_invite",
  // Host admission / lifecycle.
  "pre_register_host",
  "list_hosts",
  "suspend_host",
  "evict_host",
  // Quotas and operator key.
  "set_quota_profile",
  "rotate_admission_key",
  // Audit.
  "read_audit_log",
] as const;

export type AdminCommandName = (typeof ADMIN_COMMAND_NAMES)[number];

const KNOWN = new Set<string>(ADMIN_COMMAND_NAMES);

/** True if `cmd` is one of the documented A3b command names. */
export function isAdminCommandName(cmd: string): cmd is AdminCommandName {
  return KNOWN.has(cmd);
}

/** Maps a documented command name to its subject, e.g. `evict_host` ->
 * `registry.admin.evict_host`. Throws {@link AdminError} `UnknownCommand` otherwise. */
export function adminSubjectFor(cmd: string): string {
  if (!isAdminCommandName(cmd)) throw AdminError.unknownCommand();
  return `${ADMIN_SUBJECT_PREFIX}${cmd}`;
}

/** Validates a full subject and returns the command it names. Throws {@link AdminError}
 * `InvalidSubject` for anything outside `registry.admin.<documented-command>` — including the
 * bare prefix, an unknown suffix, or a different subject hierarchy. */
export function commandForSubject(subject: string): AdminCommandName {
  if (!subject.startsWith(ADMIN_SUBJECT_PREFIX)) throw AdminError.invalidSubject();
  const cmd = subject.slice(ADMIN_SUBJECT_PREFIX.length);
  if (!isAdminCommandName(cmd)) throw AdminError.invalidSubject();
  return cmd;
}

/** Alias for {@link commandForSubject}, named for call sites that are asserting rather than
 * deriving. */
export function assertAdminSubject(subject: string): AdminCommandName {
  return commandForSubject(subject);
}

/** True if `subject` is exactly one of the documented `registry.admin.<command>` subjects. */
export function isAdminSubject(subject: string): boolean {
  try {
    commandForSubject(subject);
    return true;
  } catch {
    return false;
  }
}
