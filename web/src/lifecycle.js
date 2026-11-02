// A response started by an older sign-in must never restore its closed session.
export function sessionGuard() {
  let generation = 0;
  return {
    renew() {
      generation += 1;
    },
    capture() {
      const current = generation;
      return () => current === generation;
    },
  };
}

// Plaintext download URLs exist only while this account is unlocked.
export function downloadShelf(
  holder,
  urls = URL,
  schedule = setTimeout,
  cancel = clearTimeout,
) {
  let current = null;
  function clear() {
    if (current) {
      cancel(current.timer);
      urls.revokeObjectURL(current.url);
      current = null;
    }
    holder.replaceChildren();
  }
  return {
    clear,
    show(blob, name) {
      clear();
      const url = urls.createObjectURL(blob);
      const card = document.createElement("div");
      card.className = "download-card";
      const label = document.createElement("small");
      label.textContent = "Tệp đã sẵn sàng · Nếu chưa tải, bấm Lưu tệp";
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = name;
      anchor.className = "button primary";
      anchor.textContent = "Lưu tệp: " + name;
      const close = document.createElement("button");
      close.type = "button";
      close.className = "icon-button";
      close.setAttribute("aria-label", "Đóng liên kết tải xuống");
      close.textContent = "×";
      close.addEventListener("click", clear);
      card.append(label, anchor, close);
      holder.replaceChildren(card);
      current = { url, timer: schedule(clear, 120000) };
      anchor.click();
    },
  };
}
