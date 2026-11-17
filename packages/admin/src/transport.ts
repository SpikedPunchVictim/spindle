// The only transport dependency of @spindle/admin (A10.19).
//
// A3b requires the admin plane to run over NATS with the operator mTLS profile
// (`registry.admin.>`, ADR-002), but this package deliberately does not depend on a NATS client
// (`async-nats`/`nats.ws` are forbidden here). The embedding application supplies an adapter that
// owns connection establishment, the operator credential/mTLS profile, and reply correlation.
//
// Contract for implementations:
// - publish `payload` to exactly `subject` and to no other subject;
// - return the raw bytes of the reply that arrived on the request's reply inbox;
// - reject/resolve with the transport's own error on timeout, disconnect, or no-responders — the
//   client wraps any rejection in a typed `AdminError` with kind `Transport`.
//
// `subject` is always one of the documented `registry.admin.<command>` subjects when called by
// `AdminClient`; an adapter must not rewrite or re-scope it.
export interface AdminTransport {
  request(subject: string, payload: Uint8Array): Promise<Uint8Array>;
}
