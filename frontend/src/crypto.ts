import { x25519 } from '@noble/curves/ed25519';
import HKDF from 'futoin-hkdf';
import { randomBytes, utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { Buffer } from 'buffer';

// Polyfill Buffer for browser (Vite/React) (or the buffer.from wont work, idk why it works in node)
if (typeof window !== 'undefined' && !(window as Window & { Buffer?: typeof Buffer }).Buffer) {
  (window as Window & { Buffer?: typeof Buffer }).Buffer = Buffer;
}

// Generate X25519 keypair (curve25519)
export function deriveKeyPair() {
  const priv: Uint8Array = x25519.utils.randomSecretKey();
  const pub: Uint8Array = x25519.getPublicKey(priv);
  return { priv, pub };
}

export function deriveSharedSecret(ourPriv: Uint8Array, theirPub: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(ourPriv, theirPub).slice(0, 32); // Remove leading 0 if present (should not)
}

export function deriveKeyHKDF(
  salt: Uint8Array,
  sharedSecret: Uint8Array,
  info = utf8ToBytes('chat-encryption'),
): Uint8Array {
  return HKDF(Buffer.from(sharedSecret), 32, {
    salt: Buffer.from(salt),
    info: Buffer.from(info),
    hash: 'SHA-256',
  });
}

export function encryptMessage(sharedSecret: Uint8Array, plaintext: string) {
  const salt = randomBytes(16);
  const iv = randomBytes(12); // 12 bytes for AES-GCM
  const keyMaterial = deriveKeyHKDF(salt, sharedSecret);

  // Import key for AES-GCM
  return window.crypto.subtle
    .importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt'])
    .then((cryptoKey) => {
      const pt = utf8ToBytes(plaintext);
      return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, pt);
    })
    .then((cipherBuffer) => {
      return { salt, nonce: iv, ciphertext: new Uint8Array(cipherBuffer) };
    });
}

export function decryptMessage(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<string> {
  const keyMaterial = deriveKeyHKDF(salt, sharedSecret);
  return window.crypto.subtle
    .importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['decrypt'])
    .then((cryptoKey) => {
      return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, ciphertext);
    })
    .then((plainBuffer) => {
      return bytesToUtf8(new Uint8Array(plainBuffer));
    });
}

export { bytesToHex, hexToBytes };
