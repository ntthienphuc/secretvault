// Device-local unlock cache. No password or derived password credential is stored.
// CryptoKeys are non-extractable, but this still grants access to this browser profile.
const DB = "secretvault-device-v1",
  STORE = "sessions",
  TAB = "sv-device-tab";
const encoder = new TextEncoder(),
  decoder = new TextDecoder();
async function database() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function access(mode, operation) {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      let result;
      const request = operation(tx.objectStore(STORE));
      if (request)
        request.onsuccess = () => {
          result = request.result;
        };
      tx.oncomplete = () => resolve(result);
      tx.onerror = tx.onabort = () =>
        reject(tx.error || new Error("Không lưu được phiên trên thiết bị."));
    });
  } finally {
    db.close();
  }
}
function tabId() {
  let id = sessionStorage.getItem(TAB);
  if (!id) {
    id = crypto.randomUUID();
    sessionStorage.setItem(TAB, id);
  }
  return "tab:" + id;
}
export async function sealSession(
  response,
  identity,
  persistent,
  now = Date.now(),
) {
  const expiresAt = Math.min(
    response.expiresAt || now + 12 * 3600000,
    now + (persistent ? 7 * 24 : 12) * 3600000,
  );
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const context = JSON.stringify({
    version: 1,
    userId: response.user.id,
    expiresAt,
    persistent,
  });
  const plain = encoder.encode(
    JSON.stringify({
      token: response.token,
      user: response.user,
      elgamal: identity.elgamalPrivate.toString(16),
      vaultKey: Array.from(identity.vaultKey),
    }),
  );
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: encoder.encode(context) },
      key,
      plain,
    );
    return {
      version: 1,
      userId: response.user.id,
      expiresAt,
      persistent,
      key,
      iv,
      ciphertext,
      signingPrivate: identity.signingPrivate,
    };
  } finally {
    plain.fill(0);
  }
}
export async function openSession(record, now = Date.now()) {
  if (!record || record.version !== 1 || record.expiresAt <= now) return null;
  const context = JSON.stringify({
    version: 1,
    userId: record.userId,
    expiresAt: record.expiresAt,
    persistent: record.persistent,
  });
  const plain = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: record.iv,
        additionalData: encoder.encode(context),
      },
      record.key,
      record.ciphertext,
    ),
  );
  try {
    const value = JSON.parse(decoder.decode(plain));
    if (value.user.id !== record.userId || record.signingPrivate.extractable)
      throw new Error("Phiên trên thiết bị không hợp lệ.");
    return {
      token: value.token,
      user: value.user,
      expiresAt: record.expiresAt,
      persistent: record.persistent,
      identity: {
        signingPrivate: record.signingPrivate,
        elgamalPrivate: BigInt("0x" + value.elgamal),
        vaultKey: new Uint8Array(value.vaultKey),
      },
    };
  } finally {
    plain.fill(0);
  }
}
export async function saveSession(response, identity, persistent) {
  const id = tabId(),
    record = await sealSession(response, identity, persistent);
  await access("readwrite", (store) => {
    store.delete("remember");
    store.put(record, id);
    if (persistent) store.put(record, "remember");
  });
}
export async function loadSession() {
  const id = tabId();
  let record = await access("readonly", (store) => store.get(id));
  if (!record || record.expiresAt <= Date.now())
    record = await access("readonly", (store) => store.get("remember"));
  return openSession(record);
}
export async function forgetSessions() {
  await access("readwrite", (store) => store.clear());
  sessionStorage.removeItem(TAB);
}
