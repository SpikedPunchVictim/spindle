// A single, explicit cast site for the `Uint8Array<ArrayBufferLike>` vs. WebCrypto's
// `BufferSource` (= `ArrayBufferView<ArrayBuffer>` | `ArrayBuffer`) type mismatch that TypeScript
// 5.7+'s generic typed-array typings introduce: every `Uint8Array` this package hands to
// `crypto.subtle.*` is always backed by a plain, non-shared `ArrayBuffer` at runtime (never a
// `SharedArrayBuffer`), so the generic parameter TypeScript can't prove is sound in general is
// always sound here. Centralizing the cast in one place — rather than sprinkling `as BufferSource`
// at every call site — keeps that "trust me, it's really an ArrayBuffer" assertion auditable.
export function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}
