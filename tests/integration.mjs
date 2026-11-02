import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import * as C from "../web/src/crypto.js";
import { algebraVectors } from "./algebra-vectors.mjs";

const base = process.env.SV_TEST_URL || "http://127.0.0.1:8786";
const reportPath =
  process.env.SV_TEST_REPORT ||
  new URL("../.test-results/integration-results.json", import.meta.url);
const results = [];
const stamp = Date.now();
const password = "Test-Account-Password-Only!";

async function check(name, fn) {
  await fn();
  results.push({ name, passed: true });
  console.log("PASS", name);
}

async function request(
  path,
  { user, method = "GET", body, status = 200, binary = false } = {},
) {
  const headers = {};
  if (user) {
    headers.Authorization = "Bearer " + user.token;
  }
  if (body !== undefined) {
    headers["Content-Type"] =
      body instanceof Uint8Array
        ? "application/octet-stream"
        : "application/json";
  }
  const response = await fetch(base + path, {
    method,
    headers,
    body:
      body instanceof Uint8Array
        ? body
        : body === undefined
          ? undefined
          : JSON.stringify(body),
  });
  const value =
    binary && response.ok
      ? new Uint8Array(await response.arrayBuffer())
      : await response.json();
  assert.equal(
    response.status,
    status,
    path + ": " + JSON.stringify(value).slice(0, 250),
  );
  return value;
}

async function register(name) {
  const email = `${name.toLowerCase().replace(/\s/g, "")}-${stamp}@example.test`;
  const account = await C.makeAccount(email, password);
  const proof = await C.sign(account.identity, {
    purpose: "register-v2",
    email,
    public: account.public,
  });
  const response = await request("/api/register", {
    method: "POST",
    body: {
      name,
      email,
      authProof: await C.authProof(email, password),
      public: account.public,
      bundle: account.bundle,
      proof,
    },
  });
  return {
    ...response,
    identity: account.identity,
    public: account.public,
    bundle: account.bundle,
  };
}

let alice;
let bob;
let mallory;
let file;
let original;
let key;
let shareId;

await check("Finite-field DH and ElGamal arithmetic vectors", async () =>
  assert.equal((await algebraVectors()).pass, true),
);
await check(
  "RFC 3526 group15 is 3072 bits with safe subgroup generator",
  async () => {
    assert.equal(C.P.toString(2).length, 3072);
    assert.equal(C.modPow(C.G, C.Q, C.P), 1n);
  },
);
await check("RFC5869 HKDF test case 1 matches 42-byte vector", async () => {
  const vector = await C.hkdf(
    new Uint8Array(22).fill(11),
    C.unhex("000102030405060708090a0b0c"),
    C.unhex("f0f1f2f3f4f5f6f7f8f9"),
    42,
  );
  assert.equal(
    C.hex(vector),
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
  );
});
await check("Unauthenticated file metadata access is rejected", async () =>
  request("/api/bootstrap?user_id=alice", { status: 401 }),
);
await check("Cross-origin requests are rejected", async () => {
  const response = await fetch(base + "/api/health", {
    headers: { Origin: "https://evil.example" },
  });
  assert.equal(response.status, 403);
});
await check("Register 3 independent signed public identities", async () => {
  alice = await register("Alice Test");
  bob = await register("Bob Test");
  mallory = await register("Mallory Test");
  assert.notEqual(alice.public.fingerprint, bob.public.fingerprint);
});
await check(
  "Duplicate registration cannot replace an existing identity",
  async () => {
    const email = alice.user.email;
    const proof = await C.sign(alice.identity, {
      purpose: "register-v2",
      email,
      public: alice.public,
    });
    await request("/api/register", {
      method: "POST",
      body: {
        name: "Changed",
        email,
        authProof: await C.authProof(email, password),
        public: alice.public,
        bundle: alice.bundle,
        proof,
      },
      status: 409,
    });
    assert.equal(
      (
        await request("/api/login", {
          method: "POST",
          body: { email, authProof: await C.authProof(email, password) },
        })
      ).user.public.fingerprint,
      alice.public.fingerprint,
    );
  },
);
await check(
  "Registration rejects malformed email and blank display name",
  async () => {
    await request("/api/register", {
      method: "POST",
      body: { email: "invalid", authProof: "0".repeat(64) },
      status: 400,
    });
    await request("/api/register", {
      method: "POST",
      body: {
        email: `blank-${stamp}@example.test`,
        name: "   ",
        authProof: "0".repeat(64),
      },
      status: 400,
    });
  },
);
await check(
  "A registration with another identity's signature is rejected",
  async () => {
    const email = `forged-${stamp}@example.test`;
    const proof = await C.sign(bob.identity, {
      purpose: "register-v2",
      email,
      public: alice.public,
    });
    await request("/api/register", {
      method: "POST",
      body: {
        email,
        name: "Forged",
        authProof: await C.authProof(email, password),
        public: alice.public,
        bundle: alice.bundle,
        proof,
      },
      status: 400,
    });
  },
);
await check("Login accepts email case/outer-space normalization", async () => {
  const email = "  " + alice.user.email.toUpperCase() + "  ";
  const response = await request("/api/login", {
    method: "POST",
    body: { email, authProof: await C.authProof(alice.user.email, password) },
  });
  assert.equal(response.user.id, alice.user.id);
});
await check(
  "Logging out invalidates only that session and allows a fresh login",
  async () => {
    const body = {
      email: alice.user.email,
      authProof: await C.authProof(alice.user.email, password),
    };
    const session = await request("/api/login", { method: "POST", body });
    await request("/api/logout", { user: session, method: "POST", body: {} });
    await request("/api/bootstrap", { user: session, status: 401 });
    await request("/api/bootstrap", { user: alice });
    const fresh = await request("/api/login", { method: "POST", body });
    assert.notEqual(fresh.token, session.token);
    assert.equal(fresh.user.id, alice.user.id);
  },
);
await check("Wrong password cannot log in", async () =>
  request("/api/login", {
    method: "POST",
    body: {
      email: alice.user.email,
      authProof: await C.authProof(alice.user.email, "Wrong-password-123!"),
    },
    status: 401,
  }),
);
await check(
  "Private identity bundle cannot unlock with wrong password",
  async () =>
    assert.rejects(
      C.unlockAccount(
        alice.user.email,
        "Wrong-password-123!",
        alice.bundle,
        alice.public,
      ),
    ),
);
await check(
  "Server receives a derived credential, never a raw vault password",
  async () =>
    request("/api/login", {
      method: "POST",
      body: { email: alice.user.email, password },
      status: 400,
    }),
);
await check(
  "Authentication credential cannot directly unlock the private bundle",
  async () => {
    const credential = await C.authProof(alice.user.email, password);
    await assert.rejects(
      C.unlockAccount(alice.user.email, credential, alice.bundle, alice.public),
    );
  },
);
await check(
  "Same account unlocks its keys on another session/device",
  async () => {
    const response = await request("/api/login", {
      method: "POST",
      body: {
        email: alice.user.email,
        authProof: await C.authProof(alice.user.email, password),
      },
    });
    const identity = await C.unlockAccount(
      alice.user.email,
      password,
      response.bundle,
      response.user.public,
    );
    await C.verify(
      alice.public,
      { test: 1 },
      await C.sign(identity, { test: 1 }),
    );
  },
);
await check("Pin both peers' public key fingerprints", async () => {
  await request("/api/contacts", {
    user: alice,
    method: "POST",
    body: { peerId: bob.user.id, fingerprint: bob.public.fingerprint },
  });
  await request("/api/contacts", {
    user: bob,
    method: "POST",
    body: { peerId: alice.user.id, fingerprint: alice.public.fingerprint },
  });
});
await check("Wrong contact fingerprint is rejected", async () =>
  request("/api/contacts", {
    user: alice,
    method: "POST",
    body: { peerId: bob.user.id, fingerprint: "0".repeat(64) },
    status: 409,
  }),
);
await check("Encrypt/upload/commit a 3-chunk signed file", async () => {
  original = new Uint8Array(C.CHUNK_SIZE * 2 + 29);
  for (let index = 0; index < original.length; index += 1) {
    original[index] = index % 251;
  }
  key = C.randomBytes(32);
  const fileId = C.id("f");
  await request("/api/files", {
    user: alice,
    method: "POST",
    body: { id: fileId },
    status: 201,
  });
  const chunks = [];
  const prefix = C.randomBytes(8);
  for (let index = 0; index < 3; index += 1) {
    const plain = original.slice(
      index * C.CHUNK_SIZE,
      (index + 1) * C.CHUNK_SIZE,
    );
    const encrypted = await C.encrypt(
      key,
      plain,
      C.fileAad(fileId, alice.user.id, index, 3, original.length),
      C.chunkIv(prefix, index),
    );
    const raw = C.unb64(encrypted.data);
    const uploaded = await request(`/api/files/${fileId}/chunks/${index}`, {
      user: alice,
      method: "POST",
      body: raw,
    });
    chunks.push({
      index,
      iv: encrypted.iv,
      hash: uploaded.hash,
      plainSize: plain.length,
    });
  }
  const manifest = {
    version: 2,
    algorithm: "AES-256-GCM-chunked",
    id: fileId,
    ownerId: alice.user.id,
    name: "integrity-3-chunks.bin",
    mime: "application/octet-stream",
    size: original.length,
    created: Date.now(),
    chunkSize: C.CHUNK_SIZE,
    chunks,
  };
  const signature = await C.sign(alice.identity, manifest);
  const ownerWrap = await C.wrapOwner(
    alice.identity,
    fileId,
    alice.user.id,
    key,
  );
  await request(`/api/files/${fileId}/commit`, {
    user: alice,
    method: "POST",
    body: { manifest, signature, ownerWrap },
  });
  file = {
    id: fileId,
    ownerId: alice.user.id,
    ownerWrap,
    manifest,
    signature,
    manifestHash: await C.objectHash(manifest),
  };
});
await check("Unshared files and owner wraps do not leak to Bob", async () => {
  const remote = await request("/api/bootstrap", { user: bob });
  assert(!remote.files.some((item) => item.id === file.id));
  await request(`/api/files/${file.id}/chunks/0`, { user: bob, status: 403 });
});
await check("Committed ciphertext cannot be overwritten", async () =>
  request(`/api/files/${file.id}/chunks/0`, {
    user: alice,
    method: "POST",
    body: new Uint8Array(16),
    status: 409,
  }),
);
await check("Another user cannot claim file ownership or commit", async () =>
  request(`/api/files/${file.id}/commit`, {
    user: mallory,
    method: "POST",
    body: {},
    status: 403,
  }),
);
await check(
  "Owner AES unwrap and chunk download match original bytes",
  async () => {
    const unwrapped = await C.unwrapOwner(alice.identity, file);
    assert.equal(C.hex(unwrapped), C.hex(key));
    const output = [];
    for (let index = 0; index < 3; index += 1) {
      const data = await request(`/api/files/${file.id}/chunks/${index}`, {
        user: alice,
        binary: true,
      });
      const meta = file.manifest.chunks[index];
      assert.equal(await C.hash(data), meta.hash);
      output.push(
        await C.decrypt(
          unwrapped,
          { iv: meta.iv, data: C.b64(data) },
          C.fileAad(file.id, alice.user.id, index, 3, original.length),
        ),
      );
    }
    assert.equal(
      await C.hash(new Uint8Array(Buffer.concat(output))),
      await C.hash(original),
    );
  },
);
await check("Modified signed manifest is rejected by Ed25519", async () =>
  assert.rejects(
    C.verify(alice.public, { ...file.manifest, size: 9 }, file.signature),
  ),
);
await check("ElGamal invalid subgroup keys 0,1,p-1 are rejected", async () => {
  for (const value of [0n, 1n, C.P - 1n]) {
    assert.throws(() => C.validateGroupKey(C.groupHex(value)));
  }
});
let payload;
await check("Offline ElGamal envelopes are randomized per use", async () => {
  const context = {
    purpose: "offline-v2",
    fileId: file.id,
    senderId: alice.user.id,
    recipientId: bob.user.id,
    recipientFingerprint: bob.public.fingerprint,
    manifestHash: file.manifestHash,
  };
  const envelope = await C.wrapElgamal(key, bob.public.elgamal, context);
  const second = await C.wrapElgamal(key, bob.public.elgamal, context);
  assert.notEqual(envelope.c1, second.c1);
  assert.notEqual(envelope.iv, second.iv);
  payload = { ...context, envelope, created: Date.now() };
});
await check(
  "Tampered offline envelope is rejected at API signature check",
  async () => {
    const signature = await C.sign(alice.identity, payload);
    const changed = structuredClone(payload);
    changed.envelope.c1 = C.groupHex(2n);
    await request("/api/shares", {
      user: alice,
      method: "POST",
      body: { payload: changed, signature },
      status: 400,
    });
  },
);
await check("Store valid signed offline key envelope", async () => {
  const result = await request("/api/shares", {
    user: alice,
    method: "POST",
    body: { payload, signature: await C.sign(alice.identity, payload) },
    status: 201,
  });
  shareId = result.id;
});
await check(
  "Sender can log out before recipient decrypts offline share",
  async () => {
    await request("/api/logout", { user: alice, method: "POST", body: {} });
    await request("/api/bootstrap", { user: alice, status: 401 });
    const remote = await request("/api/bootstrap", { user: bob });
    const received = remote.files.find((item) => item.id === file.id);
    assert(received && !received.ownerWrap);
    await C.verify(
      alice.public,
      received.share.payload,
      received.share.signature,
    );
    const unwrapped = await C.unwrapElgamal(
      bob.identity,
      received.share.payload.envelope,
      C.shareContext(received.share.payload),
    );
    assert.equal(C.hex(unwrapped), C.hex(key));
    await request(`/api/files/${file.id}/chunks/0`, {
      user: bob,
      binary: true,
    });
    const login = await request("/api/login", {
      method: "POST",
      body: {
        email: alice.user.email,
        authProof: await C.authProof(alice.user.email, password),
      },
    });
    alice.token = login.token;
  },
);
await check("Wrong private key cannot open an offline envelope", async () =>
  assert.rejects(
    C.unwrapElgamal(
      mallory.identity,
      payload.envelope,
      C.shareContext(payload),
    ),
  ),
);
await check("Envelope is bound to file and recipient context", async () =>
  assert.rejects(
    C.unwrapElgamal(bob.identity, payload.envelope, {
      ...C.shareContext(payload),
      fileId: C.id("f"),
    }),
  ),
);
await check("AES-GCM fails on a changed ciphertext byte", async () => {
  const data = await request(`/api/files/${file.id}/chunks/0`, {
    user: bob,
    binary: true,
  });
  data[0] ^= 1;
  await assert.rejects(
    C.decrypt(
      key,
      { iv: file.manifest.chunks[0].iv, data: C.b64(data) },
      C.fileAad(file.id, alice.user.id, 0, 3, original.length),
    ),
  );
});
await check(
  "Revocation blocks the recipient's next file download",
  async () => {
    await request("/api/shares/" + shareId, { user: alice, method: "DELETE" });
    await request(`/api/files/${file.id}/chunks/0`, { user: bob, status: 403 });
  },
);

let offer;
let acceptance;
let senderDh;
let receiverDh;
let senderKey;
let receiverKey;
let liveCiphertext;
await check(
  "Signed ephemeral DH offer is accepted for the correct recipient",
  async () => {
    senderDh = C.ephemeral();
    receiverDh = C.ephemeral();
    offer = {
      purpose: "live-offer-v2",
      id: C.id("l"),
      group: C.GROUP,
      senderId: alice.user.id,
      recipientId: bob.user.id,
      recipientFingerprint: bob.public.fingerprint,
      publicKey: senderDh.publicKey,
      nonce: C.b64(C.randomBytes(32)),
      expires: Date.now() + 600000,
      name: "live.bin",
      size: 19,
      mime: "application/octet-stream",
      total: 1,
    };
    await request("/api/live", {
      user: alice,
      method: "POST",
      body: { payload: offer, signature: await C.sign(alice.identity, offer) },
      status: 201,
    });
    acceptance = {
      purpose: "live-accept-v2",
      id: offer.id,
      recipientId: bob.user.id,
      offerHash: await C.objectHash(offer),
      publicKey: receiverDh.publicKey,
      nonce: C.b64(C.randomBytes(32)),
    };
  },
);
await check("Mallory cannot accept Bob's DH offer", async () =>
  request(`/api/live/${offer.id}/accept`, {
    user: mallory,
    method: "POST",
    body: {},
    status: 403,
  }),
);
await check(
  "Changed DH public key invalidates transcript signature",
  async () => {
    const signature = await C.sign(bob.identity, acceptance);
    await request(`/api/live/${offer.id}/accept`, {
      user: bob,
      method: "POST",
      body: {
        payload: { ...acceptance, publicKey: senderDh.publicKey },
        signature,
      },
      status: 400,
    });
  },
);
await check(
  "Correct signed acceptance yields equal HKDF session keys",
  async () => {
    await request(`/api/live/${offer.id}/accept`, {
      user: bob,
      method: "POST",
      body: {
        payload: acceptance,
        signature: await C.sign(bob.identity, acceptance),
      },
    });
    senderKey = await C.sessionKey(
      senderDh.privateKey,
      receiverDh.publicKey,
      offer,
      acceptance,
    );
    receiverKey = await C.sessionKey(
      receiverDh.privateKey,
      senderDh.publicKey,
      offer,
      acceptance,
    );
    assert.equal(C.hex(senderKey.key), C.hex(receiverKey.key));
  },
);
await check(
  "Live payload relay preserves GCM tags and signed hashes",
  async () => {
    const plain = new Uint8Array(19).fill(42);
    const envelope = await C.encrypt(
      senderKey.key,
      plain,
      C.liveAad(senderKey.transcriptHash, 0, 1),
      C.chunkIv(C.randomBytes(8), 0),
    );
    const hash = await C.hash(C.unb64(envelope.data));
    await request(`/api/live/${offer.id}/chunk`, {
      user: alice,
      method: "POST",
      body: { index: 0, ...envelope, hash },
    });
    await request(`/api/live/${offer.id}/chunk`, {
      user: alice,
      method: "POST",
      body: { index: 0, ...envelope, hash },
      status: 409,
    });
    const payload = {
      purpose: "live-finish-v2",
      id: offer.id,
      transcriptHash: senderKey.transcriptHash,
      hashes: [hash],
    };
    await request(`/api/live/${offer.id}/finish`, {
      user: alice,
      method: "POST",
      body: { payload, signature: await C.sign(alice.identity, payload) },
    });
    const received = await request(`/api/live/${offer.id}/chunks/0`, {
      user: bob,
    });
    liveCiphertext = received;
    const decrypted = await C.decrypt(
      receiverKey.key,
      received,
      C.liveAad(receiverKey.transcriptHash, 0, 1),
    );
    assert.deepEqual(decrypted, plain);
    await request(`/api/live/${offer.id}/ack`, {
      user: bob,
      method: "POST",
      body: {},
    });
    const remote = await request("/api/bootstrap", { user: alice });
    assert.equal(
      remote.live.find((item) => item.id === offer.id).state,
      "complete",
    );
  },
);
await check(
  "Live ciphertext cannot be transplanted into a different transcript",
  async () => {
    await assert.rejects(
      C.decrypt(
        receiverKey.key,
        liveCiphertext,
        C.liveAad("0".repeat(64), 0, 1),
      ),
    );
  },
);
await check("Unrelated users cannot read any live payload", async () =>
  request(`/api/live/${offer.id}/chunks/0`, { user: mallory, status: 403 }),
);
if ((await request("/api/health")).version.startsWith("3.")) {
  await check(
    "Hosted transfers release temporary ciphertext after receiver acknowledgment",
    async () =>
      request(`/api/live/${offer.id}/chunks/0`, { user: bob, status: 404 }),
  );
}

const report = {
  timestamp: new Date().toISOString(),
  target: base,
  passed: results.length,
  checks: results,
};
await writeFile(reportPath, JSON.stringify(report, null, 2));

console.log(
  JSON.stringify({ passed: results.length, report: String(reportPath) }),
);
