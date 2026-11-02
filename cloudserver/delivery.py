"""Recipient receipts, independently owned copies and recoverable storage cleanup."""

import hashlib
import json
from vaultserver.security import require
from vaultserver.store import now


class DeliveryMixin:
    def recipient_share(self, user, share_id):
        row = self.store.one(
            "SELECT * FROM shares WHERE id=? AND recipient_id=? AND revoked=0",
            (share_id, user["id"]),
        )
        require(
            row is not None and self.store.can_read(row["file_id"], user["id"]),
            "Tệp đã bị xóa hoặc quyền nhận đã được thu hồi.",
            403,
        )
        return row

    def receipt(self, user, share_id, kind, saved_file_id=None):
        require(kind in ("downloaded", "saved"), "Trạng thái nhận không hợp lệ.")
        share = self.recipient_share(user, share_id)
        row = self.store.file(share["file_id"])
        name = json.loads(row["manifest"])["name"]
        timestamp = now()
        self.store.execute(
            "INSERT OR IGNORE INTO share_receipts(share_id) VALUES(?)", (share_id,)
        )
        if kind == "saved":
            copy = self.store.one(
                "SELECT f.* FROM files f JOIN copy_jobs c ON c.file_id=f.id WHERE c.share_id=? AND f.id=? AND f.owner_id=? AND f.ready=1",
                (share_id, saved_file_id, user["id"]),
            )
            require(copy is not None, "Bản sao chưa được lưu hoàn tất.", 409)
            self.store.execute(
                "UPDATE share_receipts SET saved_at=CASE WHEN saved_at=0 THEN ? ELSE saved_at END,saved_file_id=? WHERE share_id=?",
                (timestamp, saved_file_id, share_id),
            )
            message = user["name"] + " đã lưu “" + name + "” vào Tệp của tôi."
        else:
            self.store.execute(
                "UPDATE share_receipts SET downloaded_at=CASE WHEN downloaded_at=0 THEN ? ELSE downloaded_at END WHERE share_id=?",
                (timestamp, share_id),
            )
            message = user["name"] + " đã nhận “" + name + "” để tải về thiết bị."
        notification_id = (
            "n_" + hashlib.sha256((share_id + ":" + kind).encode()).hexdigest()[:32]
        )
        existed = self.store.one(
            "SELECT id FROM notifications WHERE id=?", (notification_id,)
        )
        self.store.execute(
            "INSERT OR IGNORE INTO notifications VALUES(?,?,?,?,?,?,?,0)",
            (
                notification_id,
                share["sender_id"],
                share_id,
                row["id"],
                kind,
                message,
                timestamp,
            ),
        )
        if not existed:
            self.store.activity(share["sender_id"], message)
            self.store.event(user["id"], "share." + kind, name)

    def prepare_copy(self, user, body):
        share_id = body.get("sourceShareId")
        if not share_id:
            return None, None
        require(isinstance(share_id, str), "Lượt chia sẻ không hợp lệ.")
        share = self.recipient_share(user, share_id)
        source = json.loads(self.store.file(share["file_id"])["manifest"])
        require(
            body.get("size") == source["size"] and body.get("name") == source["name"],
            "Bản sao không khớp tệp được gửi.",
        )
        existing = self.store.one(
            "SELECT f.* FROM files f JOIN copy_jobs c ON c.file_id=f.id WHERE c.share_id=? AND c.recipient_id=?",
            (share_id, user["id"]),
        )
        if existing:
            require(
                existing["ready"],
                "Một lần lưu tệp này đang diễn ra. Chờ hoàn tất rồi thử lại.",
                409,
            )
            self.store.execute(
                "UPDATE files SET deleted=0 WHERE id=?", (existing["id"],)
            )
            return share, existing
        return share, None

    def remove_file_data(self, user, file_id, *, purge):
        row = self.store.one(
            "SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, user["id"])
        )
        require(row is not None, "Bạn không có quyền xóa tệp này.", 403)
        if purge:
            require(
                row["deleted"], "Chuyển tệp vào thùng rác trước khi xóa vĩnh viễn.", 409
            )
        else:
            require(not row["ready"], "Tệp đã lưu hoàn tất, không thể hủy upload.", 409)
        self.store.queue_blob_deletion(file_id)
        self.store.execute(
            "DELETE FROM share_receipts WHERE share_id IN (SELECT id FROM shares WHERE file_id=?)",
            (file_id,),
        )
        self.store.execute("DELETE FROM shares WHERE file_id=?", (file_id,))
        self.store.execute("DELETE FROM copy_jobs WHERE file_id=?", (file_id,))
        self.store.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
        self.store.execute("DELETE FROM uploads WHERE file_id=?", (file_id,))
        self.store.execute("DELETE FROM files WHERE id=?", (file_id,))
        if purge:
            self.store.event(
                user["id"],
                "file.deleted",
                json.loads(row["manifest"]).get("name", file_id),
            )
        self.json({"ok": True})
