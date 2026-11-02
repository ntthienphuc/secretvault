// Placeholders are only used before a resource has data. Refreshes keep real content.
const block = (kind = "line") =>
  '<span class="skeleton-block skeleton-' + kind + '"></span>';
const rows = () =>
  '<div class="skeleton-rows">' +
  Array.from(
    { length: 4 },
    (_, i) =>
      '<div class="skeleton-row"><div class="skeleton-file">' +
      block("icon") +
      "<div>" +
      block(i % 2 ? "title-short" : "title") +
      block("caption") +
      "</div></div>" +
      block("meta") +
      block("meta") +
      block("action") +
      "</div>",
  ).join("") +
  "</div>";

export function loadingContent(label, kind = "files") {
  const stats =
    kind === "admin"
      ? '<div class="admin-stats">' +
        Array.from(
          { length: 4 },
          () =>
            '<div class="panel stat-card">' +
            block("caption") +
            block("number") +
            block("caption") +
            "</div>",
        ).join("") +
        "</div>"
      : "";
  return (
    '<div class="loading-region" data-skeleton="' +
    kind +
    '" aria-busy="true">' +
    '<p class="loading-label" role="status">' +
    label +
    "</p>" +
    '<div class="skeleton-content" aria-hidden="true">' +
    stats +
    '<div class="panel skeleton-panel"><div class="skeleton-toolbar">' +
    block("heading") +
    block("search") +
    "</div>" +
    rows() +
    "</div></div></div>"
  );
}

export function loadingFailure(action) {
  return (
    '<div class="loading-error" role="status"><h2>Chưa tải được dữ liệu</h2><p>Kết nối có thể đang chậm. Bạn có thể thử lại.</p><button type="button" class="button secondary" data-action="' +
    action +
    '">Thử lại</button></div>'
  );
}

export function workspaceLoading(view, failed = false) {
  const labels = {
    vault: "Tệp của tôi",
    shared: "Tệp được gửi cho bạn",
    trash: "Thùng rác",
    admin: "Tổng quan vận hành",
    contacts: "Danh bạ",
    send: "Gửi tệp",
    settings: "Tài khoản",
    setup: "Thiết lập tài khoản",
  };
  return (
    '<div class="page-title"><div><h1>' +
    (labels[view] || "Tệp của tôi") +
    '</h1><p class="muted">Không gian riêng của bạn.</p></div></div>' +
    (failed
      ? loadingFailure("load-workspace")
      : loadingContent(
          "Đang tải không gian của bạn…",
          view === "admin" ? "admin" : "files",
        ))
  );
}

export function restoringView(view) {
  return (
    '<div class="app-shell restoring-shell"><aside class="sidebar" aria-hidden="true"><div class="restore-brand">SecretVault</div><div class="restore-nav">' +
    block("nav") +
    block("nav") +
    block("nav") +
    "</div></aside>" +
    '<div class="workspace"><header class="topbar"><span class="workspace-label">Không gian riêng tư</span><span class="mobile-brand">SecretVault</span></header>' +
    '<main class="page" id="main-content" tabindex="-1"><div class="page-title"><div><h1>Đang mở lại không gian của bạn</h1><p class="muted">Đang kiểm tra phiên đăng nhập đã lưu.</p></div></div>' +
    loadingContent(
      "Đang khôi phục phiên và tải dữ liệu…",
      view === "admin" ? "admin" : "files",
    ) +
    "</main></div></div>"
  );
}
