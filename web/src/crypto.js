// Finite-field key exchange and key encapsulation with Web Crypto primitives.
// Protocols and key lifecycles: docs/CRYPTOGRAPHY.md.
const subtle = globalThis.crypto?.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
export const GROUP = "RFC3526-MODP3072";
export const PBKDF2_ITERATIONS = 600000;
export const CHUNK_SIZE = 1024 * 1024;
export const MAX_FILE_SIZE = 256 * CHUNK_SIZE;

// RFC 3526 section 4, group 15. Safe prime p=2q+1, generator 2.
export const P = BigInt(
  "0x" +
    `
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
`.replace(/\s/g, ""),
);
export const Q = (P - 1n) / 2n;
export const G = 2n;

export function assert(value, message) {
  if (!value) {
    throw new Error(message);
  }
}

// Stable object-key ordering makes signed JSON identical on JavaScript and Python.
export function canonical(value) {
  if (Array.isArray(value)) {
    return "[" + value.map(canonical).join(",") + "]";
  }
  if (value && typeof value === "object") {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map((key) => JSON.stringify(key) + ":" + canonical(value[key]))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

export const utf8 = (value) => encoder.encode(value);
export const text = (value) => decoder.decode(value);
export const randomBytes = (size) =>
  crypto.getRandomValues(new Uint8Array(size));
export const hex = (bytes) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
export const id = (prefix) => prefix + "_" + hex(randomBytes(16));

export function unhex(value) {
  assert(
    typeof value === "string" && /^(?:[0-9a-f]{2})+$/i.test(value),
    "Hex không hợp lệ",
  );
  return Uint8Array.from(value.match(/../g), (pair) => parseInt(pair, 16));
}

export function b64(bytes) {
  let output = "";
  for (let offset = 0; offset < bytes.length; offset += 32768) {
    output += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
  }
  return btoa(output);
}

export const unb64 = (value) =>
  Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
export const sha = async (bytes) =>
  new Uint8Array(await subtle.digest("SHA-256", bytes));
export const hash = async (bytes) => hex(await sha(bytes));
export const objectHash = async (value) => hash(utf8(canonical(value)));

export function modPow(base, exponent, modulus) {
  assert(modulus > 1n && exponent >= 0n, "Tham số lũy thừa không hợp lệ");
  let output = 1n;
  let current = ((base % modulus) + modulus) % modulus;
  let remaining = exponent;
  while (remaining > 0n) {
    if (remaining & 1n) {
      output = (output * current) % modulus;
    }
    current = (current * current) % modulus;
    remaining >>= 1n;
  }
  return output;
}

export function scalar() {
  // Rejection sampling: no modulo bias, full-order subgroup secret.
  let value;
  do {
    value = BigInt("0x" + hex(randomBytes(384)));
  } while (value < 2n || value >= Q);
  return value;
}

export const groupHex = (value) => value.toString(16).padStart(768, "0");

export function validateGroupKey(publicHex) {
  assert(
    typeof publicHex === "string" && /^[a-f0-9]{768}$/.test(publicHex),
    "DH/ElGamal key phải dài 3072 bit",
  );
  const y = BigInt("0x" + publicHex);
  assert(
    y >= 2n && y <= P - 2n && modPow(y, Q, P) === 1n,
    "Khóa ngoài nhóm con an toàn",
  );
  return y;
}

// Fresh x in [2, q-1], with public value g^x mod p in the order-q subgroup.
export function ephemeral() {
  const privateKey = scalar();
  return { privateKey, publicKey: groupHex(modPow(G, privateKey, P)) };
}

async function aesKey(raw, usages = ["encrypt", "decrypt"]) {
  if (raw instanceof CryptoKey) {
    return raw;
  }
  return subtle.importKey("raw", raw, "AES-GCM", false, usages);
}

export async function encrypt(key, bytes, aad, iv = randomBytes(12)) {
  const data = await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8(aad), tagLength: 128 },
    await aesKey(key),
    bytes,
  );
  return { iv: b64(iv), data: b64(new Uint8Array(data)) };
}

export async function decrypt(key, envelope, aad) {
  try {
    return new Uint8Array(
      await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: unb64(envelope.iv),
          additionalData: utf8(aad),
          tagLength: 128,
        },
        await aesKey(key),
        unb64(envelope.data),
      ),
    );
  } catch {
    throw new Error(
      "Xác minh AES-GCM thất bại: sai khóa hoặc dữ liệu đã bị sửa",
    );
  }
}

export async function hkdf(secret, salt, info, length = 32) {
  const input = await subtle.importKey("raw", secret, "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: typeof info === "string" ? utf8(info) : info,
      },
      input,
      length * 8,
    ),
  );
}

export async function sign(identity, value) {
  return b64(
    new Uint8Array(
      await subtle.sign(
        "Ed25519",
        identity.signingPrivate,
        utf8(canonical(value)),
      ),
    ),
  );
}

export async function verify(publicMaterial, value, signature) {
  const key = await subtle.importKey(
    "jwk",
    publicMaterial.signing,
    "Ed25519",
    false,
    ["verify"],
  );
  const valid = await subtle.verify(
    "Ed25519",
    key,
    unb64(signature),
    utf8(canonical(value)),
  );
  assert(
    valid,
    "Chữ ký Ed25519 không hợp lệ; nội dung hoặc public key đã thay đổi",
  );
  return true;
}

export async function publicFingerprint(publicMaterial) {
  return objectHash({
    signing: publicMaterial.signing,
    elgamal: publicMaterial.elgamal,
    group: publicMaterial.group,
  });
}

async function passwordKey(password, salt) {
  const material = await subtle.importKey(
    "raw",
    utf8(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function authProof(email, password) {
  // Independent password-derived credential. The raw vault password is never
  // sent to Python; this credential cannot directly unwrap the private bundle.
  const salt = await sha(utf8("SecretVault:auth-credential-v2:" + email));
  const material = await subtle.importKey(
    "raw",
    utf8(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  return hex(
    new Uint8Array(
      await subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt,
          iterations: PBKDF2_ITERATIONS,
        },
        material,
        256,
      ),
    ),
  );
}

// An identity combines a signing key, an ElGamal recipient key and a vault key.
// Only the public material and password-encrypted private bundle reach the API.
export async function makeAccount(email, password) {
  assert(subtle, "Cần Chrome/Edge mới và địa chỉ localhost hoặc HTTPS");
  const signing = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const jwk = await subtle.exportKey("jwk", signing.publicKey);
  const elgamal = ephemeral();
  const publicMaterial = {
    signing: { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    elgamal: elgamal.publicKey,
    group: GROUP,
  };
  publicMaterial.fingerprint = await publicFingerprint(publicMaterial);
  const secrets = {
    signing: await subtle.exportKey("jwk", signing.privateKey),
    elgamal: elgamal.privateKey.toString(16),
    vaultKey: b64(randomBytes(32)),
    fingerprint: publicMaterial.fingerprint,
  };
  const salt = randomBytes(32);
  const wrapped = await encrypt(
    await passwordKey(password, salt),
    utf8(canonical(secrets)),
    "SecretVault:account-v2:" + email,
  );
  const bundle = {
    ...wrapped,
    salt: b64(salt),
    kdf: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
  };
  const identity = await unlockAccount(email, password, bundle, publicMaterial);
  return { public: publicMaterial, bundle, identity };
}

export async function unlockAccount(email, password, bundle, publicMaterial) {
  assert(
    bundle.kdf === "PBKDF2-SHA256" && bundle.iterations === PBKDF2_ITERATIONS,
    "Gói khóa dùng KDF không hỗ trợ",
  );
  let secrets;
  try {
    const key = await passwordKey(password, unb64(bundle.salt));
    secrets = JSON.parse(
      text(await decrypt(key, bundle, "SecretVault:account-v2:" + email)),
    );
  } catch {
    throw new Error("Không mở được gói khóa. Kiểm tra mật khẩu hoặc backup");
  }
  assert(
    secrets.fingerprint === (await publicFingerprint(publicMaterial)),
    "Fingerprint của gói khóa không khớp danh tính",
  );
  assert(
    groupHex(modPow(G, BigInt("0x" + secrets.elgamal), P)) ===
      publicMaterial.elgamal,
    "Private key ElGamal không khớp",
  );
  const signingPrivate = await subtle.importKey(
    "jwk",
    secrets.signing,
    "Ed25519",
    false,
    ["sign"],
  );
  const identity = {
    signingPrivate,
    elgamalPrivate: BigInt("0x" + secrets.elgamal),
    vaultKey: unb64(secrets.vaultKey),
  };
  const probe = {
    purpose: "local-key-pair-check",
    fingerprint: secrets.fingerprint,
  };
  await verify(publicMaterial, probe, await sign(identity, probe));
  return identity;
}

// Bind the owner's wrapped file key to both account ID and file ID.
export async function wrapOwner(identity, fileId, ownerId, fileKey) {
  return encrypt(
    identity.vaultKey,
    fileKey,
    "SecretVault:owner-v2:" + ownerId + ":" + fileId,
  );
}

export async function unwrapOwner(identity, file) {
  return decrypt(
    identity.vaultKey,
    file.ownerWrap,
    "SecretVault:owner-v2:" + file.ownerId + ":" + file.id,
  );
}

// ElGamal Hybrid: c1 = g^r; z = y^r; HKDF(z) derives an AES-GCM wrapping key.
// The recipient computes the same z = c1^x. Context binds the envelope to the
// sender, recipient, file and signed manifest. Only the 32-byte file key is wrapped.
export async function wrapElgamal(fileKey, recipientPublic, context) {
  const y = validateGroupKey(recipientPublic);
  const pair = ephemeral();
  const salt = randomBytes(32);
  const shared = unhex(groupHex(modPow(y, pair.privateKey, P)));
  const key = await hkdf(
    shared,
    salt,
    "SecretVault:offline-v2:" + canonical(context),
  );
  const wrapped = await encrypt(key, fileKey, canonical(context));
  shared.fill(0);
  key.fill(0);
  return {
    scheme: "ElGamal-Hybrid-HKDF-SHA256",
    group: GROUP,
    c1: pair.publicKey,
    salt: b64(salt),
    ...wrapped,
  };
}

export async function unwrapElgamal(identity, envelope, context) {
  assert(
    envelope.scheme === "ElGamal-Hybrid-HKDF-SHA256" &&
      envelope.group === GROUP,
    "Sai thuật toán envelope",
  );
  const c1 = validateGroupKey(envelope.c1);
  const shared = unhex(groupHex(modPow(c1, identity.elgamalPrivate, P)));
  const key = await hkdf(
    shared,
    unb64(envelope.salt),
    "SecretVault:offline-v2:" + canonical(context),
  );
  const raw = await decrypt(key, envelope, canonical(context));
  shared.fill(0);
  key.fill(0);
  assert(raw.length === 32, "File key không dài 256 bit");
  return raw;
}

export function shareContext(payload) {
  const {
    purpose,
    fileId,
    senderId,
    recipientId,
    recipientFingerprint,
    manifestHash,
  } = payload;
  return {
    purpose,
    fileId,
    senderId,
    recipientId,
    recipientFingerprint,
    manifestHash,
  };
}

// Ephemeral Diffie-Hellman: z = peerPublic^private mod p on either side.
// Both signed handshake messages enter the transcript hash and HKDF context.
// Callers verify their signatures and identity bindings before invoking this.
export async function sessionKey(privateKey, peerPublicKey, offer, acceptance) {
  const publicValue = validateGroupKey(peerPublicKey);
  const shared = unhex(groupHex(modPow(publicValue, privateKey, P)));
  const transcriptHash = await objectHash({ offer, acceptance });
  const salt = await sha(utf8(offer.nonce + ":" + acceptance.nonce));
  const raw = await hkdf(shared, salt, "SecretVault:live-v2:" + transcriptHash);
  shared.fill(0);
  return { key: raw, transcriptHash };
}

// One random 64-bit prefix per fresh file/session key, followed by a uint32 index.
// Reusing this prefix with the same key for another encryption is not permitted.
export function chunkIv(prefix, index) {
  assert(
    prefix.length === 8 &&
      Number.isInteger(index) &&
      index >= 0 &&
      index < 2 ** 32,
    "Sai nonce chunk",
  );
  const iv = new Uint8Array(12);
  iv.set(prefix);
  new DataView(iv.buffer).setUint32(8, index, false);
  return iv;
}

export function fileAad(fileId, ownerId, index, total, size) {
  return canonical({
    purpose: "file-chunk-v2",
    fileId,
    ownerId,
    index,
    total,
    size,
  });
}

export function liveAad(transcriptHash, index, total) {
  return canonical({ purpose: "live-chunk-v2", transcriptHash, index, total });
}
