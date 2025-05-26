/* tslint:disable */
/* eslint-disable */
/**
 * Generates a compact key pair (secret key, public key) for the specified MAYO variant.
 * This wraps `MAYO.CompactKeyGen`.
 */
export function keypair(mayo_variant_name: string): KeyPairWrapper;
/**
 * Signs a message using a compact secret key.
 * This involves expanding the secret key and then calling `MAYO.Sign`.
 * The returned signature does not include the message.
 */
export function sign(csk: CompactSecretKey, message: Message, mayo_variant_name: string): Signature;
/**
 * Verifies a signature on a "signed message" and recovers the original message if valid.
 * This corresponds to `sign_open` in some APIs.
 * Assumes `signed_message` is `signature_bytes || original_message_bytes`.
 */
export function open(cpk: CompactPublicKey, signed_message: Uint8Array, mayo_variant_name: string): Message | undefined;
/**
 * Hashes a CompactSecretKey (which is a seedsk) using Blake2b-512.
 * Returns a 64-byte hash.
 */
export function hash_compact_secret_key(csk: CompactSecretKey): Uint8Array;
/**
 * CompactPublicKey typically contains SeedPK and a representation of P3 (or its hash).
 */
export class CompactPublicKey {
  free(): void;
  constructor(bytes: Uint8Array);
  get_bytes(): Uint8Array;
  0: Uint8Array;
}
/**
 * CompactSecretKey is typically the same as SeedSK.
 */
export class CompactSecretKey {
  free(): void;
  constructor(bytes: Uint8Array);
  get_bytes(): Uint8Array;
  0: Uint8Array;
}
export class KeyPairWrapper {
  private constructor();
  free(): void;
  sk: CompactSecretKey;
  pk: CompactPublicKey;
}
export class Message {
  free(): void;
  constructor(bytes: Uint8Array);
  get_bytes(): Uint8Array;
  0: Uint8Array;
}
/**
 * Signature containing the solution `s` and the salt.
 */
export class Signature {
  free(): void;
  constructor(bytes: Uint8Array);
  get_bytes(): Uint8Array;
  0: Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_compactsecretkey_free: (a: number, b: number) => void;
  readonly compactsecretkey_get_bytes: (a: number) => [number, number];
  readonly __wbg_compactpublickey_free: (a: number, b: number) => void;
  readonly __wbg_get_compactpublickey_0: (a: number) => [number, number];
  readonly __wbg_set_compactpublickey_0: (a: number, b: number, c: number) => void;
  readonly compactpublickey_new: (a: number, b: number) => number;
  readonly compactpublickey_get_bytes: (a: number) => [number, number];
  readonly __wbg_signature_free: (a: number, b: number) => void;
  readonly signature_get_bytes: (a: number) => [number, number];
  readonly __wbg_message_free: (a: number, b: number) => void;
  readonly message_get_bytes: (a: number) => [number, number];
  readonly compactsecretkey_new: (a: number, b: number) => number;
  readonly signature_new: (a: number, b: number) => number;
  readonly message_new: (a: number, b: number) => number;
  readonly __wbg_set_compactsecretkey_0: (a: number, b: number, c: number) => void;
  readonly __wbg_set_signature_0: (a: number, b: number, c: number) => void;
  readonly __wbg_set_message_0: (a: number, b: number, c: number) => void;
  readonly __wbg_get_compactsecretkey_0: (a: number) => [number, number];
  readonly __wbg_get_signature_0: (a: number) => [number, number];
  readonly __wbg_get_message_0: (a: number) => [number, number];
  readonly __wbg_keypairwrapper_free: (a: number, b: number) => void;
  readonly __wbg_get_keypairwrapper_sk: (a: number) => number;
  readonly __wbg_set_keypairwrapper_sk: (a: number, b: number) => void;
  readonly __wbg_get_keypairwrapper_pk: (a: number) => number;
  readonly __wbg_set_keypairwrapper_pk: (a: number, b: number) => void;
  readonly keypair: (a: number, b: number) => [number, number, number];
  readonly sign: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly open: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly hash_compact_secret_key: (a: number) => [number, number];
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
