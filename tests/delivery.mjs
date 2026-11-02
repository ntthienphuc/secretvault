import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import * as C from "../web/src/crypto.js";
const base = process.env.SV_TEST_URL || "http://127.0.0.1:8811";
const results = [],
  stamp = Date.now(),
  password = "Test-Delivery-Password-Only!";
async function check(name, fn) {
  await fn();
  results.push({ name, passed: true });
  console.log("PASS", name);
}
async function req(
  path,
  { user, method = "GET", body, status = 200, binary = false } = {},
) {
  const headers = {};
  if (user) headers.Authorization = "Bearer " + user.token;
  if (body !== undefined)
    headers["Content-Type"] =
      body instanceof Uint8Array
        ? "application/octet-stream"
        : "application/json";
  const r = await fetch(base + path, {
    method,
    headers,
    body:
      body === undefined
        ? undefined
        : body instanceof Uint8Array
          ? body
          : JSON.stringify(body),
  });
  const x =
    binary && r.ok ? new Uint8Array(await r.arrayBuffer()) : await r.json();
  assert.equal(r.status, status, path + ": " + JSON.stringify(x).slice(0, 200));
  return x;
}
async function register(name) {
  const email = name.toLowerCase() + "-" + stamp + "@example.test";
  const a = await C.makeAccount(email, password);
  const authProof = await C.authProof(email, password);
  const r = await req("/api/register", {
    method: "POST",
    body: {
      name,
      email,
      authProof,
      public: a.public,
      bundle: a.bundle,
      proof: await C.sign(a.identity, {
        purpose: "register-v2",
        email,
        public: a.public,
      }),
    },
  });
  return { ...r, identity: a.identity, public: a.public, email, authProof };
}
const sender = await register("DeliverySender"),
  receiver = await register("DeliveryReceiver"),
  other = await register("DeliveryOther");
const raw = new Uint8Array(32769);
for (let i = 0; i < raw.length; i++) raw[i] = i % 251;
async function put(user, id, bytes, name, key = C.randomBytes(32)) {
  const total = Math.max(1, Math.ceil(bytes.length / C.CHUNK_SIZE)),
    prefix = C.randomBytes(8),
    chunks = [];
  for (let i = 0; i < total; i++) {
    const part = bytes.slice(i * C.CHUNK_SIZE, (i + 1) * C.CHUNK_SIZE);
    const e = await C.encrypt(
      key,
      part,
      C.fileAad(id, user.user.id, i, total, bytes.length),
      C.chunkIv(prefix, i),
    );
    const r = await req(`/api/files/${id}/chunks/${i}`, {
      user,
      method: "POST",
      body: C.unb64(e.data),
    });
    chunks.push({ index: i, iv: e.iv, hash: r.hash, plainSize: part.length });
  }
  const manifest = {
    version: 2,
    algorithm: "AES-256-GCM-chunked",
    id,
    ownerId: user.user.id,
    name,
    mime: "application/octet-stream",
    size: bytes.length,
    created: Date.now(),
    chunkSize: C.CHUNK_SIZE,
    chunks,
  };
  await req(`/api/files/${id}/commit`, {
    user,
    method: "POST",
    body: {
      manifest,
      signature: await C.sign(user.identity, manifest),
      ownerWrap: await C.wrapOwner(user.identity, id, user.user.id, key),
    },
  });
  return { id, key, manifest, manifestHash: await C.objectHash(manifest) };
}
let source, share, copyId;
await check(
  "Service advertises offline inbox and per-account quota",
  async () => {
    const h = await req("/api/health");
    assert.equal(h.features.offlineInbox, true);
    const b = await req("/api/bootstrap", { user: receiver });
    assert.equal(b.account.quota, 100 * 1048576);
    assert.equal(b.limits.maxFileSize, 25 * 1048576);
  },
);
await check(
  "Offline share remains available while sender is logged out",
  async () => {
    const id = C.id("f");
    await req("/api/files", {
      user: sender,
      method: "POST",
      body: { id, name: "delivery.bin", size: raw.length },
      status: 201,
    });
    source = await put(sender, id, raw, "delivery.bin");
    await req("/api/contacts", {
      user: sender,
      method: "POST",
      body: {
        peerId: receiver.user.id,
        fingerprint: receiver.public.fingerprint,
      },
    });
    const context = {
      purpose: "offline-v2",
      fileId: id,
      senderId: sender.user.id,
      recipientId: receiver.user.id,
      recipientFingerprint: receiver.public.fingerprint,
      manifestHash: source.manifestHash,
    };
    const payload = {
      ...context,
      envelope: await C.wrapElgamal(
        source.key,
        receiver.public.elgamal,
        context,
      ),
      created: Date.now(),
    };
    share = await req("/api/shares", {
      user: sender,
      method: "POST",
      body: { payload, signature: await C.sign(sender.identity, payload) },
      status: 201,
    });
    await req("/api/logout", { user: sender, method: "POST", body: {} });
    const b = await req("/api/bootstrap", { user: receiver });
    const f = b.files.find((f) => f.id === id);
    assert(f);
    assert(!f.share.receipt);
    assert.equal(
      C.hex(
        await C.unwrapElgamal(
          receiver.identity,
          f.share.payload.envelope,
          C.shareContext(f.share.payload),
        ),
      ),
      C.hex(source.key),
    );
    sender.token = (
      await req("/api/login", {
        method: "POST",
        body: { email: sender.email, authProof: sender.authProof },
      })
    ).token;
  },
);
await check("Inbox listing alone never marks a file received", async () =>
  assert.equal(
    (await req("/api/bootstrap", { user: sender })).notifications.length,
    0,
  ),
);
await check("Only the recipient may send an offline receipt", async () => {
  for (const user of [sender, other])
    await req(`/api/shares/${share.id}/receipt`, {
      user,
      method: "POST",
      body: { kind: "downloaded" },
      status: 403,
    });
});
await check(
  "Downloaded receipt is idempotent and notifies only the sender",
  async () => {
    for (let i = 0; i < 2; i++)
      await req(`/api/shares/${share.id}/receipt`, {
        user: receiver,
        method: "POST",
        body: { kind: "downloaded" },
      });
    const b = await req("/api/bootstrap", { user: sender });
    assert.equal(b.notifications.length, 1);
    assert.equal(b.notifications[0].kind, "downloaded");
    assert(b.shares.find((s) => s.id === share.id).receipt.downloadedAt);
    assert.equal(
      (await req("/api/bootstrap", { user: other })).notifications.length,
      0,
    );
  },
);
await check("Notification read state is isolated per account", async () => {
  const ids = (await req("/api/bootstrap", { user: sender })).notifications.map(
    (n) => n.id,
  );
  await req("/api/notifications/read", {
    user: other,
    method: "POST",
    body: { ids },
  });
  assert.equal(
    (await req("/api/bootstrap", { user: sender })).notifications[0].read_at,
    0,
  );
  await req("/api/notifications/read", {
    user: sender,
    method: "POST",
    body: { ids },
  });
  assert(
    (await req("/api/bootstrap", { user: sender })).notifications[0].read_at >
      0,
  );
});
await check(
  "Client cannot claim saved status without committing an owned copy",
  () =>
    req(`/api/shares/${share.id}/receipt`, {
      user: receiver,
      method: "POST",
      body: { kind: "saved", savedFileId: source.id },
      status: 400,
    }),
);
const copyBody = () => ({
  id: C.id("f"),
  name: "delivery.bin",
  size: raw.length,
  sourceShareId: share.id,
});
await check("Another account cannot import the shared file", () =>
  req("/api/files", {
    user: other,
    method: "POST",
    body: copyBody(),
    status: 403,
  }),
);
await check("Import rejects changed source size or name", () =>
  req("/api/files", {
    user: receiver,
    method: "POST",
    body: { ...copyBody(), size: 1 },
    status: 400,
  }),
);
await check(
  "Recipient quota includes concurrent reservations and blocks copying when full",
  async () => {
    const ids = [];
    for (let i = 0; i < 4; i++) {
      const id = C.id("f");
      ids.push(id);
      await req("/api/files", {
        user: receiver,
        method: "POST",
        body: {
          id,
          name: "reservation.bin",
          size: 25 * 1048576 - (i === 3 ? 2048 : 0),
        },
        status: 201,
      });
    }
    await req("/api/files", {
      user: receiver,
      method: "POST",
      body: copyBody(),
      status: 413,
    });
    for (const id of ids)
      await req(`/api/files/${id}/upload`, {
        user: receiver,
        method: "DELETE",
      });
    assert.equal(
      (await req("/api/bootstrap", { user: receiver })).account.allocated,
      0,
    );
  },
);
await check(
  "Incomplete copy can be canceled without leaking quota or a receipt",
  async () => {
    const body = copyBody();
    await req("/api/files", {
      user: receiver,
      method: "POST",
      body,
      status: 201,
    });
    await req("/api/files", {
      user: receiver,
      method: "POST",
      body: copyBody(),
      status: 409,
    });
    await req(`/api/files/${body.id}/upload`, {
      user: receiver,
      method: "DELETE",
    });
    const b = await req("/api/bootstrap", { user: sender });
    assert.equal(b.notifications.length, 1);
    assert.equal(b.shares.find((s) => s.id === share.id).receipt.savedAt, 0);
  },
);
await check(
  "Owned copy uses fresh encryption and emits saved receipt only after commit",
  async () => {
    const body = copyBody();
    copyId = body.id;
    await req("/api/files", {
      user: receiver,
      method: "POST",
      body,
      status: 201,
    });
    await put(receiver, copyId, raw, "delivery.bin");
    const a = await req(`/api/files/${source.id}/chunks/0`, {
      user: sender,
      binary: true,
    });
    const b = await req(`/api/files/${copyId}/chunks/0`, {
      user: receiver,
      binary: true,
    });
    assert.notEqual(await C.hash(a), await C.hash(b));
    const state = await req("/api/bootstrap", { user: sender });
    assert.equal(state.notifications.length, 2);
    assert(state.shares.find((s) => s.id === share.id).receipt.savedAt > 0);
  },
);
await check(
  "Retrying save returns existing copy and does not consume quota twice",
  async () => {
    const before = (await req("/api/bootstrap", { user: receiver })).account
      .used;
    const r = await req("/api/files", {
      user: receiver,
      method: "POST",
      body: copyBody(),
    });
    assert.equal(r.alreadySaved, true);
    assert.equal(r.id, copyId);
    assert.equal(
      (await req("/api/bootstrap", { user: receiver })).account.used,
      before,
    );
  },
);
await check(
  "Committed files cannot be removed through upload cancellation",
  () =>
    req(`/api/files/${copyId}/upload`, {
      user: receiver,
      method: "DELETE",
      status: 409,
    }),
);
await check("Permanent removal requires owner and trash first", async () => {
  await req(`/api/files/${source.id}/purge`, {
    user: other,
    method: "DELETE",
    status: 403,
  });
  await req(`/api/files/${source.id}/purge`, {
    user: sender,
    method: "DELETE",
    status: 409,
  });
});
await check(
  "Sender can delete original after receipt; quota is released",
  async () => {
    await req(`/api/files/${source.id}`, { user: sender, method: "DELETE" });
    assert((await req("/api/bootstrap", { user: sender })).account.used > 0);
    await req(`/api/files/${source.id}/purge`, {
      user: sender,
      method: "DELETE",
    });
    assert.equal(
      (await req("/api/bootstrap", { user: sender })).account.used,
      0,
    );
  },
);
await check(
  "Recipient copy remains independently decryptable after original is deleted",
  async () => {
    const b = await req("/api/bootstrap", { user: receiver });
    const f = b.files.find((f) => f.id === copyId);
    assert(f && f.ownerId === receiver.user.id && !f.share);
    const key = await C.unwrapOwner(receiver.identity, f);
    const bytes = await req(`/api/files/${copyId}/chunks/0`, {
      user: receiver,
      binary: true,
    });
    const plain = await C.decrypt(
      key,
      { iv: f.manifest.chunks[0].iv, data: C.b64(bytes) },
      C.fileAad(copyId, receiver.user.id, 0, 1, raw.length),
    );
    assert.deepEqual(plain, raw);
    await req(`/api/files/${source.id}/chunks/0`, {
      user: receiver,
      status: 403,
    });
  },
);
await writeFile(
  process.env.SV_DELIVERY_REPORT || ".test-results/api-results.json",
  JSON.stringify(
    { checkedAt: new Date().toISOString(), passed: results.length, results },
    null,
    2,
  ),
);
console.log(JSON.stringify({ passed: results.length }));
