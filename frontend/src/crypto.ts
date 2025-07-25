// X25519 (Curve25519) for Elliptic Curve Diffie-Hellman (ECDH) key exchange
// modern, secure elliptic curve used in many secure protocols (Signal, TLS 1.3, etc.)
import { x25519 } from '@noble/curves/ed25519';
// HKDF (HMAC-based Key Derivation Function) for deriving session keys from shared secrets
// This is a standard way to derive cryptographic keys from a shared secret
import HKDF from 'futoin-hkdf';
// Secure random byte generation and encoding utilities
// These provide cryptographically secure random numbers and encoding/decoding functions
import { randomBytes, utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes } from '@noble/hashes/utils';
// Buffer polyfill for browser compatibility (required for HKDF library)
import { Buffer } from 'buffer';

// Polyfill Buffer for browser (Vite/React) (or the buffer.from wont work, idk why it works in node)
// The HKDF library expects Node.js Buffer, but browsers don't have it by default
if (typeof window !== 'undefined' && !(window as Window & { Buffer?: typeof Buffer }).Buffer) {
  (window as Window & { Buffer?: typeof Buffer }).Buffer = Buffer;
}

// Generate X25519 keypair (curve25519)
// Returns a key pair with private and public keys as Uint8Array
// The private key is used for ECDH, the public key is shared with peers
export function deriveKeyPair() {
  // Generate a random 32-byte private key
  const priv: Uint8Array = x25519.utils.randomSecretKey();
  // Derive the corresponding public key from the private key
  const pub: Uint8Array = x25519.getPublicKey(priv);
  return { priv, pub };
}

// Derive a shared secret using ECDH
// Takes our private key and the peer's public key
// Returns a 32-byte shared secret that both parties can compute independently
// This shared secret is the foundation for deriving session keys
export function deriveSharedSecret(ourPriv: Uint8Array, theirPub: Uint8Array): Uint8Array {
  // Compute the shared secret using ECDH
  // Both parties will get the same result: ECDH(ourPriv, theirPub) = ECDH(theirPriv, ourPub)
  return x25519.getSharedSecret(ourPriv, theirPub).slice(0, 32); // Remove leading 0 if present (should not)
}

// Derive a session key using HKDF (HMAC-based Key Derivation Function)
// This function takes a shared secret and derives a cryptographically strong session key
// salt: random bytes to ensure uniqueness (prevents key reuse)
// sharedSecret: the ECDH shared secret
// info: optional context string to bind the key to a specific use case
export function deriveKeyHKDF(
  salt: Uint8Array,
  sharedSecret: Uint8Array,
  info = utf8ToBytes('chat-encryption'), // Default context for this poc app
): Uint8Array {
  // Use HKDF with SHA-256 to derive a 32-byte key
  // This provides forward secrecy and prevents key reuse attacks
  return HKDF(Buffer.from(sharedSecret), 32, {
    salt: Buffer.from(salt),
    info: Buffer.from(info),
    hash: 'SHA-256',
  });
}

// Encrypt a message using AES-256-GCM (Authenticated Encryption with Associated Data)
// This provides both confidentiality (encryption) and integrity (authentication)
// sharedSecret: the ECDH shared secret
// plaintext: the message to encrypt
// Returns: salt, nonce (IV), and ciphertext
export function encryptMessage(sharedSecret: Uint8Array, plaintext: string) {
  // Generate a random 16-byte salt for key derivation
  // Each message uses a unique salt to prevent key reuse
  const salt = randomBytes(16);
  // Generate a random 12-byte nonce (IV) for AES-GCM
  // Each message uses a unique nonce to ensure security
  const iv = randomBytes(12);
  // Derive the session key using HKDF
  const keyMaterial = deriveKeyHKDF(salt, sharedSecret);

  // Import the key material for use with Web Crypto API
  // This creates a CryptoKey object that can be used for encryption
  return window.crypto.subtle
    .importKey(
      'raw', // Key format (raw bytes)
      keyMaterial, // The key material (32 bytes)
      { name: 'AES-GCM' }, // Algorithm specification
      false, // Extractable (false for security)
      ['encrypt'], // Key usage (only encryption allowed)
    )
    .then((cryptoKey) => {
      // Convert the plaintext to bytes
      const pt = utf8ToBytes(plaintext);
      // Encrypt the plaintext using AES-256-GCM
      // This provides both encryption and authentication
      return window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, // Algorithm and nonce
        cryptoKey, // The session key
        pt, // The plaintext to encrypt
      );
    })
    .then((cipherBuffer) => {
      // Return the salt, nonce, and ciphertext
      // The salt and nonce are needed for decryption
      return { salt, nonce: iv, ciphertext: new Uint8Array(cipherBuffer) };
    });
}

// Decrypt a message using AES-256-GCM
// This function reverses the encryption process
// sharedSecret: the ECDH shared secret (must be the same as used for encryption)
// salt: the salt used for key derivation (from encryption)
// nonce: the nonce used for encryption (from encryption)
// ciphertext: the encrypted message
// Returns: the decrypted plaintext as a string
export function decryptMessage(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<string> {
  // Derive the same session key using the same salt and shared secret
  const keyMaterial = deriveKeyHKDF(salt, sharedSecret);
  // Import the key material for use with Web Crypto API
  return window.crypto.subtle
    .importKey(
      'raw', // Key format (raw bytes)
      keyMaterial, // The key material (32 bytes)
      { name: 'AES-GCM' }, // Algorithm specification
      false, // Extractable (false for security)
      ['decrypt'], // Key usage (only decryption allowed)
    )
    .then((cryptoKey) => {
      // Decrypt the ciphertext using AES-256-GCM
      // This will throw an error if the ciphertext has been tampered with
      return window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce }, // Algorithm and nonce
        cryptoKey, // The session key
        ciphertext, // The ciphertext to decrypt
      );
    })
    .then((plainBuffer) => {
      // Convert the decrypted bytes back to a string
      return bytesToUtf8(new Uint8Array(plainBuffer));
    });
}

// Export utility functions for encoding/decoding
// These are used throughout the application for converting between different data formats
export { bytesToHex, hexToBytes };
