import { x25519 } from '@noble/curves/ed25519';
import HKDF from 'futoin-hkdf';
import {  chacha20poly1305 } from '@noble/ciphers/chacha';
import {
  randomBytes,
  utf8ToBytes,
  bytesToUtf8,
  bytesToHex,
  hexToBytes,
} from '@noble/hashes/utils';
import { Buffer } from 'buffer';

// Polyfill Buffer for browser (Vite/React) (or the buffer.from wont work, idk why it works in node)
if (
  typeof window !== 'undefined' &&
  !(window as Window & { Buffer?: typeof Buffer }).Buffer
) {
  (window as Window & { Buffer?: typeof Buffer }).Buffer = Buffer;
}

// Generate X25519 keypair (curve25519)
export function deriveKeyPair() {
  const priv: Uint8Array = x25519.utils.randomSecretKey();
  const pub: Uint8Array = x25519.getPublicKey(priv);
  return { priv, pub };
}

export function deriveSharedSecret(
  ourPriv: Uint8Array,
  theirPub: Uint8Array
): Uint8Array {
  return x25519.getSharedSecret(ourPriv, theirPub).slice(0, 32); // Remove leading 0 if present (should not)
}

export function deriveKeyHKDF(
  salt: Uint8Array,
  sharedSecret: Uint8Array,
  info = utf8ToBytes('chat-encryption')
): Uint8Array {
  return HKDF(Buffer.from(sharedSecret), 32, {
    salt: Buffer.from(salt),
    info: Buffer.from(info),
    hash: 'SHA-256',
  });
}

export function encryptMessage(sharedSecret: Uint8Array, plaintext: string) {
  const salt = randomBytes(16); // for HKDF
  const nonce = randomBytes(12); // for AEAD
  const key = deriveKeyHKDF(salt, sharedSecret);
  const aead = chacha20poly1305(key ,nonce); // AEAD instance

  const pt = utf8ToBytes(plaintext);
  const ct = aead.encrypt(nonce, pt); // returns ciphertext + tag

  return { salt, nonce, ciphertext: ct };
}

export function decryptMessage(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array
): string {
  const key = deriveKeyHKDF(salt, sharedSecret);
  const aead = chacha20poly1305(key, nonce);

  const pt = aead.decrypt(nonce, ciphertext); // will throw if auth fails
  return bytesToUtf8(pt);
}

export { bytesToHex, hexToBytes };
