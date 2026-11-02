import assert from "node:assert/strict";
import { writeFile, mkdir } from "node:fs/promises";
import * as C from "../web/src/crypto.js";
import { sealSession, openSession } from "../web/src/remember.js";
const checks = [];
async function check(name, fn) {
  await fn();
  checks.push(name);
}
const account = await C.makeAccount(
  "remember@example.test",
  "Test-Remember-Password-Only!",
);
const now = Date.now(),
  response = {
    token: "opaque-session",
    user: { id: "u_test", public: account.public },
    expiresAt: now + 7 * 86400000,
  };
const record = await sealSession(response, account.identity, true, now);
await check("Device wrapping and signing keys cannot be exported", async () => {
  assert.equal(record.key.extractable, false);
  assert.equal(record.signingPrivate.extractable, false);
  await assert.rejects(crypto.subtle.exportKey("raw", record.key));
});
await check(
  "Structured clone restores keys and token without the password",
  async () => {
    const restored = await openSession(structuredClone(record), now + 100);
    assert.equal(restored.token, response.token);
    assert.deepEqual(restored.identity.vaultKey, account.identity.vaultKey);
    await C.verify(
      account.public,
      { probe: 1 },
      await C.sign(restored.identity, { probe: 1 }),
    );
    assert.equal(
      restored.identity.elgamalPrivate,
      account.identity.elgamalPrivate,
    );
  },
);
await check(
  "Tampered expiry and user binding fail authentication",
  async () => {
    await assert.rejects(
      openSession({ ...record, expiresAt: record.expiresAt + 1 }, now),
    );
    await assert.rejects(openSession({ ...record, userId: "other" }, now));
  },
);
await check("Tampered encrypted session cannot restore", async () => {
  const copy = structuredClone(record);
  new Uint8Array(copy.ciphertext)[0] ^= 1;
  await assert.rejects(openSession(copy, now));
});
await check("Expired device session is never opened", async () =>
  assert.equal(await openSession(record, record.expiresAt), null),
);
await check("Tab-only session is capped at twelve hours", async () => {
  const tab = await sealSession(response, account.identity, false, now);
  assert.equal(tab.expiresAt, now + 12 * 3600000);
  assert.equal(tab.persistent, false);
});
await check(
  "No password credential or plaintext secret is in the stored record",
  () => {
    assert(!("token" in record));
    assert(!("vaultKey" in record));
    assert(!("elgamal" in record));
    assert(!("password" in record));
    assert(!("authProof" in record));
  },
);
await mkdir(".test-results", { recursive: true });
await writeFile(
  ".test-results/remember-crypto.json",
  JSON.stringify({ passed: checks.length, checks }, null, 2),
);
console.log(JSON.stringify({ passed: checks.length }));
