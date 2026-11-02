import { API_BASE } from "./config.js";

let token = "";
sessionStorage.removeItem("sv3-session");
export function setToken(value) {
  token = value || "";
}

export async function request(path, options = {}) {
  const binary = options.body instanceof Uint8Array;
  const headers = { ...options.headers };
  if (token) headers.Authorization = "Bearer " + token;
  let body = options.body;
  if (body !== undefined) {
    headers["Content-Type"] = binary
      ? "application/octet-stream"
      : "application/json";
    if (!binary) body = JSON.stringify(body);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120000);
  try {
    const response = await fetch(API_BASE + path, {
      method: options.method || "GET",
      headers,
      body,
      signal: controller.signal,
      cache: "no-store",
      credentials: "omit",
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      const exception = new Error(
        error.error || "Yêu cầu chưa hoàn tất (" + response.status + ")",
      );
      exception.status = response.status;
      throw exception;
    }
    if (
      !options.binary &&
      !response.headers.get("Content-Type")?.includes("application/json")
    ) {
      const error = new Error(
        "Máy chủ đang khởi động. Chờ khoảng một phút rồi thử lại.",
      );
      error.status = 503;
      throw error;
    }
    // The deadline covers response bytes too, not just receipt of HTTP headers.
    return options.binary
      ? new Uint8Array(await response.arrayBuffer())
      : await response.json();
  } catch (error) {
    if (error.status) throw error;
    throw new Error(
      error.name === "AbortError"
        ? "Máy chủ phản hồi chậm. Vui lòng thử lại."
        : "Chưa kết nối được máy chủ. Kiểm tra mạng rồi thử lại; lần mở đầu có thể cần một phút.",
    );
  } finally {
    clearTimeout(timeout);
  }
}

export const get = (path) => request(path);
export const post = (path, body) => request(path, { method: "POST", body });
export const remove = (path) => request(path, { method: "DELETE" });
