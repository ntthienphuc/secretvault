import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import * as C from "../web/src/crypto.js";

const base = process.env.SV_TEST_URL || "http://127.0.0.1:8787";
const stamp = Date.now();
const results = [];
async function check(name, fn) {
  await fn();
  results.push({ name, passed: true });
  console.log("PASS", name);
}
async function req(
  path,
  { user, method = "GET", body, status = 200, headers = {} } = {},
) {
  if (user) headers.Authorization = "Bearer " + user.token;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(base + path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    headers,
  });
  const x = await r.json();
  assert.equal(r.status, status, path + JSON.stringify(x).slice(0, 100));
  return x;
}
async function register(name) {
  const email = name.toLowerCase() + "-" + stamp + "@example.test";
  const password = "Test-Account-Password-Only!";
  const a = await C.makeAccount(email, password);
  const body = {
    name,
    email,
    authProof: await C.authProof(email, password),
    public: a.public,
    bundle: a.bundle,
    proof: await C.sign(a.identity, {
      purpose: "register-v2",
      email,
      public: a.public,
    }),
  };
  const r = await req("/api/register", { method: "POST", body });
  return { ...r, body, identity: a.identity };
}
const owner = await register("OwnerTest");
const member = await register("MemberTest");
await check("Admin overview rejects unauthenticated requests", () =>
  req("/api/admin/overview", { status: 401 }),
);
await check("Regular account cannot view operations", () =>
  req("/api/admin/overview", { user: member, status: 403 }),
);
await check("Regular account cannot change quotas or roles", () =>
  req("/api/admin/user", {
    user: member,
    method: "POST",
    body: { userId: owner.user.id, quota: 1048576 },
    status: 403,
  }),
);
await check("Wrong owner activation code is rejected", () =>
  req("/api/admin/claim", {
    user: owner,
    method: "POST",
    body: { code: "invalid" },
    status: 403,
  }),
);
await check("Owner code activates exactly one administrator", async () => {
  await req("/api/admin/claim", {
    user: owner,
    method: "POST",
    body: { code: "test-local-admin-activation" },
  });
  await req("/api/admin/claim", {
    user: member,
    method: "POST",
    body: { code: "test-local-admin-activation" },
    status: 409,
  });
});
await check(
  "Dashboard output excludes credentials and cryptographic payloads",
  async () => {
    const a = await req("/api/admin/overview", { user: owner });
    assert.ok(a.users.length >= 2);
    assert.equal(a.storage.quota, 512 * 1048576);
    for (const field of [
      "password_hash",
      "bundle_json",
      "authProof",
      "public_json",
      "owner_wrap",
      "signature",
      "token_hash",
    ])
      assert.ok(!JSON.stringify(a).includes(field));
  },
);
await check("Admin cannot accidentally disable their own account", () =>
  req("/api/admin/user", {
    user: owner,
    method: "POST",
    body: { userId: owner.user.id, enabled: false },
    status: 400,
  }),
);
await check("Account quota is enforced before file allocation", async () => {
  await req("/api/admin/user", {
    user: owner,
    method: "POST",
    body: { userId: member.user.id, quota: 1048576 },
  });
  await req("/api/files", {
    user: member,
    method: "POST",
    body: { id: C.id("f"), size: 2 * 1048576, name: "quota.bin" },
    status: 413,
  });
});
await check("Hosted file limit rejects files above 25 MiB", () =>
  req("/api/files", {
    user: owner,
    method: "POST",
    body: { id: C.id("f"), size: 26 * 1048576, name: "large.bin" },
    status: 413,
  }),
);
await check(
  "Disabled accounts lose existing sessions and cannot log in",
  async () => {
    await req("/api/admin/user", {
      user: owner,
      method: "POST",
      body: { userId: member.user.id, enabled: false },
    });
    await req("/api/bootstrap", { user: member, status: 401 });
    await req("/api/login", {
      method: "POST",
      body: { email: member.user.email, authProof: member.body.authProof },
      status: 403,
    });
    await req("/api/admin/user", {
      user: owner,
      method: "POST",
      body: { userId: member.user.id, enabled: true },
    });
    await req("/api/login", {
      method: "POST",
      body: { email: member.user.email, authProof: member.body.authProof },
    });
  },
);
await check("CORS permits only configured frontend origins", async () => {
  const good = await fetch(base + "/api/health", {
    headers: { Origin: "http://127.0.0.1:8787" },
  });
  assert.equal(
    good.headers.get("access-control-allow-origin"),
    "http://127.0.0.1:8787",
  );
  const bad = await fetch(base + "/api/health", {
    headers: { Origin: "https://attacker.vercel.app" },
  });
  assert.equal(bad.status, 403);
  const preflight = await fetch(base + "/api/bootstrap", {
    method: "OPTIONS",
    headers: {
      Origin: "http://127.0.0.1:8787",
      "Access-Control-Request-Method": "GET",
      "Access-Control-Request-Headers": "authorization",
    },
  });
  assert.equal(preflight.status, 200);
});
await check(
  "Storage, database and secret files have no public download route",
  async () => {
    for (const p of [
      "/data/secretvault/metadata",
      "/vault-v2.db",
      "/.local/cloud-owner.json",
      "/ciphertext/test.bin",
    ]) {
      const r = await fetch(base + p);
      assert.equal(r.status, 404, p);
    }
  },
);
await writeFile(
  ".test-results/cloud-policy-results.json",
  JSON.stringify({ passed: results.length, results }, null, 2),
);
console.log(JSON.stringify({ passed: results.length }));
