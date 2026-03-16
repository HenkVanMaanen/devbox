// SSH host key generation using Ed25519
// Generates key pairs in OpenSSH format for cloud-init ssh_keys injection

import { ed25519 } from '@noble/curves/ed25519.js';

export interface SSHHostKey {
  privateKey: string;
  publicKey: string;
}

// Base64 decode a string to Uint8Array
function base64Decode(encoded: string): Uint8Array {
  const raw = atob(encoded);
  const result = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    result[i] = raw.codePointAt(i) ?? 0;
  }
  return result;
}

// Base64 encode a Uint8Array, split into 70-char lines
function base64Encode(data: Uint8Array): string {
  const raw = String.fromCodePoint(...data);
  return btoa(raw);
}

// Build the public key blob: string("ssh-ed25519") + string(pubkey_bytes)
function buildPubKeyBlob(publicKey: Uint8Array): Uint8Array {
  return concat(sshStringFromText('ssh-ed25519'), sshString(publicKey));
}

// Concatenate multiple Uint8Arrays
function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// Format private key in OpenSSH PEM format with 70-char line wrapping
function formatPEM(data: Uint8Array): string {
  const b64 = base64Encode(data);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 70) {
    lines.push(b64.slice(i, i + 70));
  }
  return '-----BEGIN OPENSSH PRIVATE KEY-----\n' + lines.join('\n') + '\n-----END OPENSSH PRIVATE KEY-----\n';
}

// Encode data as an SSH "string" (4-byte length prefix + data)
function sshString(data: Uint8Array): Uint8Array {
  const result = new Uint8Array(4 + data.length);
  result.set(uint32BE(data.length));
  result.set(data, 4);
  return result;
}

// Encode a text string as an SSH "string"
function sshStringFromText(text: string): Uint8Array {
  return sshString(new TextEncoder().encode(text));
}

// Encode a uint32 as 4 big-endian bytes
function uint32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >>> 24) & 0xff;
  buf[1] = (n >>> 16) & 0xff;
  buf[2] = (n >>> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

const COMMENT = 'devbox-host-key';
const AUTH_MAGIC = 'openssh-key-v1\0';

// Generate an Ed25519 SSH host key pair
export function generateSSHHostKey(): SSHHostKey {
  const seed = ed25519.utils.randomSecretKey(); // 32 bytes
  const pubKey = ed25519.getPublicKey(seed); // 32 bytes

  // Build public key blob
  const pubKeyBlob = buildPubKeyBlob(pubKey);

  // Build private section
  const checkBytes = crypto.getRandomValues(new Uint8Array(4));
  const checkInt =
    ((checkBytes[0] ?? 0) << 24) | ((checkBytes[1] ?? 0) << 16) | ((checkBytes[2] ?? 0) << 8) | (checkBytes[3] ?? 0);

  // Ed25519 "private key" in OpenSSH format = 64 bytes (seed + public key)
  const ed25519PrivKey = concat(seed, pubKey);

  let privateSection = concat(
    uint32BE(checkInt >>> 0), // checkint1
    uint32BE(checkInt >>> 0), // checkint2 (same)
    sshStringFromText('ssh-ed25519'),
    sshString(pubKey),
    sshString(ed25519PrivKey),
    sshStringFromText(COMMENT),
  );

  // Add padding: 1, 2, 3, 4, ... until length is a multiple of 8
  const padLength = 8 - (privateSection.length % 8);
  if (padLength < 8) {
    const padding = new Uint8Array(padLength);
    for (let i = 0; i < padLength; i++) {
      padding[i] = i + 1;
    }
    privateSection = concat(privateSection, padding);
  }

  // Build full private key blob
  const magic = new TextEncoder().encode(AUTH_MAGIC);
  const fullKey = concat(
    magic,
    sshStringFromText('none'), // cipher
    sshStringFromText('none'), // kdf
    sshString(new Uint8Array(0)), // kdf options (empty)
    uint32BE(1), // number of keys
    sshString(pubKeyBlob), // public key
    sshString(privateSection), // private key section
  );

  return {
    privateKey: formatPEM(fullKey),
    publicKey: `ssh-ed25519 ${base64Encode(pubKeyBlob)} ${COMMENT}`,
  };
}

// Validate that a string looks like an OpenSSH ed25519 private key
export function isValidSSHHostKey(key: SSHHostKey): boolean {
  if (!key.privateKey || !key.publicKey) return false;
  if (!key.privateKey.includes('BEGIN OPENSSH PRIVATE KEY')) return false;
  if (!key.publicKey.startsWith('ssh-ed25519 ')) return false;

  try {
    // Verify the private key can be parsed
    const pem = key.privateKey
      .replace('-----BEGIN OPENSSH PRIVATE KEY-----', '')
      .replace('-----END OPENSSH PRIVATE KEY-----', '')
      .replaceAll('\n', '');
    const decoded = base64Decode(pem);

    // Check AUTH_MAGIC
    const magic = new TextDecoder().decode(decoded.slice(0, AUTH_MAGIC.length));
    return magic === AUTH_MAGIC;
  } catch {
    return false;
  }
}
