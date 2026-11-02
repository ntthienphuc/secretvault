import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { sessionGuard, downloadShelf } from "../web/src/lifecycle.js";
import { authView, shell } from "../web/src/view.js";

const results = [];
async function check(name, fn) {
  await fn();
  results.push({ name, passed: true });
  console.log("PASS", name);
}
const guard = sessionGuard();
await check(
  "A response from the previous account cannot restore a closed session",
  async () => {
    const pending = guard.capture();
    guard.renew();
    assert.equal(pending(), false);
    assert.equal(guard.capture()(), true);
  },
);
let revoked = [],
  timer,
  children = [];
globalThis.document = {
  createElement(tag) {
    return {
      tag,
      children: [],
      setAttribute() {},
      addEventListener(_, fn) {
        this.handler = fn;
      },
      append(...x) {
        this.children.push(...x);
      },
      click() {
        this.clicked = true;
      },
    };
  },
};
const holder = {
  replaceChildren(...x) {
    children = x;
  },
};
const shelf = downloadShelf(
  holder,
  {
    createObjectURL() {
      return "blob:" + Math.random();
    },
    revokeObjectURL(url) {
      revoked.push(url);
    },
  },
  (fn) => {
    timer = fn;
    return 1;
  },
  () => {},
);
await check("Replacing a download revokes the previous plaintext URL", () => {
  shelf.show(new Blob(["one"]), "one.txt");
  shelf.show(new Blob(["two"]), "two.txt");
  assert.equal(revoked.length, 1);
  assert.equal(children.length, 1);
});
await check(
  "Closing the unlocked session removes and revokes its download",
  () => {
    shelf.clear();
    assert.equal(revoked.length, 2);
    assert.equal(children.length, 0);
  },
);
await check("Download links expire and clear their card", () => {
  shelf.show(new Blob(["three"]), "three.txt");
  timer();
  assert.equal(revoked.length, 3);
  assert.equal(children.length, 0);
});
const base = {
  user: { id: "u", name: "Test", email: "user@example.test", role: "user" },
  view: "vault",
  remote: {
    users: [],
    contacts: [],
    files: [
      {
        id: "f",
        ownerId: "u",
        manifest: { name: "sample.txt", size: 10, created: 1 },
      },
    ],
    shares: [],
    live: [],
    activity: [],
  },
  search: "",
  fileType: "image",
  sort: "newest",
  signatures: new Map(),
  connected: true,
  trash: [],
  incoming: new Map(),
  outgoing: new Map(),
};
await check(
  "An empty type filter offers reset instead of claiming the vault is empty",
  () => {
    const html = shell(base);
    assert.ok(html.includes("Chưa tìm thấy tệp"));
    assert.ok(html.includes('data-action="clear-filters"'));
    assert.ok(!html.includes("Chọn tệp đầu tiên"));
  },
);
await check(
  "Trash is directly navigable and explains quota and share restoration",
  () => {
    const html = shell({ ...base, view: "trash" });
    assert.ok(html.includes('data-view="trash"'));
    assert.ok(html.includes("các quyền chia sẻ chưa thu hồi"));
    assert.ok(html.includes("Thùng rác đang trống"));
  },
);
await check("Untrusted file names and account names stay escaped", () => {
  const html = shell({
    ...base,
    fileType: "all",
    user: { ...base.user, name: "<img src=x onerror=alert(1)>" },
  });
  assert.ok(!html.includes("<img src=x"));
});
await check(
  "Registration states password recovery limits and supports password visibility",
  () => {
    const html = authView({
      authMode: "register",
      service: "ready",
      loginEmail: "",
    });
    assert.ok(html.includes("chưa hỗ trợ khôi phục mật khẩu"));
    assert.ok(html.includes('data-action="toggle-password"'));
  },
);
// Exercise the real API module with a stalled response body.
globalThis.location = { hostname: "localhost" };
globalThis.sessionStorage = {
  getItem() {
    return "";
  },
  setItem() {},
  removeItem() {},
};
const api = await import("../web/src/api.js");
const originalTimeout = globalThis.setTimeout,
  originalClear = globalThis.clearTimeout;
let abort,
  cleared = false;
globalThis.setTimeout = (fn) => {
  abort = fn;
  return 42;
};
globalThis.clearTimeout = () => {
  cleared = true;
};
await check(
  "Request timeout remains active until all response bytes arrive",
  async () => {
    globalThis.fetch = async (_url, { signal }) => ({
      ok: true,
      headers: new Headers({ "Content-Type": "application/json" }),
      json: () =>
        new Promise((_, reject) => {
          signal.addEventListener("abort", () =>
            reject(new DOMException("timeout", "AbortError")),
          );
          queueMicrotask(() => {
            assert.equal(cleared, false);
            abort();
          });
        }),
    });
    await assert.rejects(api.get("/api/health"), /phản hồi chậm/);
    assert.equal(cleared, true);
  },
);
await check(
  "Forbidden responses preserve their status and user-facing error",
  async () => {
    globalThis.fetch = async () => ({
      ok: false,
      status: 403,
      json: async () => ({ error: "Không có quyền" }),
    });
    await assert.rejects(
      api.get("/api/admin/overview"),
      (e) => e.status === 403 && e.message === "Không có quyền",
    );
  },
);
await check(
  "A host waking with HTML is reported as temporarily unavailable",
  async () => {
    globalThis.fetch = async () => ({
      ok: true,
      headers: new Headers({ "Content-Type": "text/html" }),
    });
    await assert.rejects(api.get("/api/health"), (e) => e.status === 503);
  },
);
globalThis.setTimeout = originalTimeout;
globalThis.clearTimeout = originalClear;
const reportPath =
  process.env.SV_WEB_REPORT || ".test-results/web-regressions.json";
await mkdir(dirname(reportPath), { recursive: true });
await writeFile(
  reportPath,
  JSON.stringify(
    { checkedAt: new Date().toISOString(), passed: results.length, results },
    null,
    2,
  ),
);
