/* tslint:disable */
/* eslint-disable */
export function generate_identity_keypair(): KeyPair;
export function generate_signed_prekey(): KeyPair;
export function generate_one_time_prekey(): KeyPair;
export function generate_ephemeral_keypair(): KeyPair;
export function sign_data(private_key: Uint8Array, data: Uint8Array): Uint8Array;
export function verify_signature(public_key: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean;
export function x3dh_initiate(alice_identity_private: Uint8Array, alice_ephemeral_private: Uint8Array, bob_identity_public: Uint8Array, bob_signed_prekey_public: Uint8Array, bob_one_time_prekey_public?: Uint8Array | null): X3DHResult;
export function x3dh_respond(bob_identity_private: Uint8Array, bob_signed_prekey_private: Uint8Array, bob_one_time_prekey_private: Uint8Array | null | undefined, alice_identity_public: Uint8Array, alice_ephemeral_public: Uint8Array): X3DHResult;
export function encrypt_message(shared_secret: Uint8Array, plaintext: Uint8Array, message_number: number): EncryptionResult;
export function decrypt_message(shared_secret: Uint8Array, ciphertext: Uint8Array, message_key: Uint8Array, message_number: number): Uint8Array;
export function hkdf_derive_key(input_key_material: Uint8Array, salt: Uint8Array, info: Uint8Array, output_length: number): Uint8Array;
export function serialize_public_key(public_key: Uint8Array): Uint8Array;
export function deserialize_public_key(serialized_key: Uint8Array): Uint8Array;
export function free_keypair(_keypair: KeyPair): void;
export function free_buffer(_buffer: Uint8Array): void;
export function main(): void;
export class EncryptionResult {
  private constructor();
  free(): void;
  readonly ciphertext: Uint8Array;
  readonly message_key: Uint8Array;
}
export class KeyPair {
  private constructor();
  free(): void;
  readonly public_key: Uint8Array;
  readonly private_key: Uint8Array;
}
export class X3DHResult {
  private constructor();
  free(): void;
  readonly shared_secret: Uint8Array;
  readonly associated_data: Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_encryptionresult_free: (a: number, b: number) => void;
  readonly encryptionresult_ciphertext: (a: number) => any;
  readonly encryptionresult_message_key: (a: number) => any;
  readonly generate_identity_keypair: () => [number, number, number];
  readonly generate_signed_prekey: () => [number, number, number];
  readonly generate_one_time_prekey: () => [number, number, number];
  readonly generate_ephemeral_keypair: () => [number, number, number];
  readonly sign_data: (a: any, b: any) => [number, number, number];
  readonly verify_signature: (a: any, b: any, c: any) => [number, number, number];
  readonly x3dh_initiate: (a: any, b: any, c: any, d: any, e: number) => [number, number, number];
  readonly x3dh_respond: (a: any, b: any, c: number, d: any, e: any) => [number, number, number];
  readonly encrypt_message: (a: any, b: any, c: number) => [number, number, number];
  readonly decrypt_message: (a: any, b: any, c: any, d: number) => [number, number, number];
  readonly hkdf_derive_key: (a: any, b: any, c: any, d: number) => [number, number, number];
  readonly serialize_public_key: (a: any) => [number, number, number];
  readonly deserialize_public_key: (a: any) => [number, number, number];
  readonly free_keypair: (a: number) => void;
  readonly free_buffer: (a: any) => void;
  readonly main: () => void;
  readonly __wbg_x3dhresult_free: (a: number, b: number) => void;
  readonly __wbg_keypair_free: (a: number, b: number) => void;
  readonly x3dhresult_associated_data: (a: number) => any;
  readonly x3dhresult_shared_secret: (a: number) => any;
  readonly keypair_private_key: (a: number) => any;
  readonly keypair_public_key: (a: number) => any;
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
