//! One-shot dev-fixture key generator for S1's `server.conf` (docs/SPIKES.md §S1).
//!
//! nats-server's Auth Callout (in non-operator, config-based accounts mode — see RESULTS.md's
//! "server topology" section for why this spike uses that mode rather than full operator/JWT
//! resolver mode) needs three nkey identities fixed at config-authoring time:
//! - the APP account's own nkey (its public key is `auth_callout.issuer`: the callout responder
//!   signs generated User JWTs as if issued *by* this account);
//! - the callout responder's own connect user nkey (this is who nats-server allows to answer
//!   `$SYS.REQ.USER.AUTH`, via `auth_callout.auth_users`);
//! - the SYS account's nkey, for symmetry/documentation (SYS is nats-server's built-in system
//!   account in this config; it does not need its own signing key for this spike).
//!
//! Run once (`cargo run -p spike-s1-callout --bin genkeys`), paste the printed public keys into
//! `server.conf`, and keep the printed seeds only in `run.sh`'s environment (never committed
//! elsewhere) — this is dev/local, TLS-less, throwaway key material (see RESULTS.md).

use nkeys::KeyPair;

fn show(label: &str, kp: &KeyPair) {
    println!("{label}_PUBLIC={}", kp.public_key());
    println!("{label}_SEED={}", kp.seed().expect("seed available"));
}

fn main() {
    // Account nkey: public key becomes `auth_callout.issuer` in server.conf, and the seed signs
    // every User JWT the responder issues.
    let app_account = KeyPair::new_account();
    // The responder's own connect identity (a "user" nkey in nats-server's account-user model):
    // public key is listed in `auth_callout.auth_users` in server.conf and in the AUTH account's
    // `users` block; the seed is how the responder itself connects (nkey-based, no password).
    let callout_user = KeyPair::new_user();

    show("APP_ACCOUNT", &app_account);
    show("CALLOUT_USER", &callout_user);
}
