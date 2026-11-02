# Kiểm thử

## Chạy toàn bộ

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe scripts/test.py
```

Cần Node.js 22 trở lên. Trình chạy tự dùng địa chỉ loopback và dữ liệu tạm; các biến bucket và hosting được loại khỏi môi trường kiểm thử. Không cần token dịch vụ bên ngoài. Kết quả sinh trong `.test-results/`, được loại khỏi Git.

| Nhóm                      | Nội dung                                                                                                       |
| ------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `web-regressions.mjs`     | Chuyển tài khoản, trạng thái rỗng, escape HTML, timeout API, vòng đời URL tải tệp                              |
| `remember.mjs`            | Structured clone CryptoKey, mở lại phiên, hết hạn, sửa cache và không xuất được khóa                           |
| `integration.mjs`         | Vector DH/HKDF, đăng ký/đăng nhập, mã hóa nhiều chunk, ElGamal Hybrid, DH trực tiếp, chữ ký, AAD và phân quyền |
| `cloud-policy.mjs`        | Quản trị, quota, khóa tài khoản, CORS và chặn tài nguyên riêng                                                 |
| `delivery.mjs`            | Nhận sau, receipt, bản sao mã hóa độc lập, thu hồi và giải phóng quota                                         |
| `cloud-persistence.py`    | Khôi phục sau restart, rollback, snapshot hỏng và fallback                                                     |
| `cloud-bucket.py`         | Backend bucket bằng mô phỏng in-memory, riêng tư và lỗi lưu trữ                                                |
| `cloud-availability.py`   | Health check trong lúc ghi, giao dịch nhiều bảng và cấp quyền nguyên tử                                        |
| `delivery-persistence.py` | Khôi phục receipt, thông báo, bản sao và dọn chunk                                                             |
| `remember-server.py`      | Phiên ghi nhớ qua restart, thu hồi khi logout, hết hạn và rollback                                             |
| `bucket-retention.py`     | Giữ ba snapshot, dọn nền và thử lại khi lỗi                                                                    |

## Kiểm tra giao diện

Chạy server local, rồi mở hai hồ sơ trình duyệt với hai tài khoản khác nhau:

1. Đăng ký, đăng nhập sai mật khẩu, đăng nhập đúng và tải lại trang.
2. Upload tệp, tải về và so sánh nội dung với tệp gốc.
3. Gửi để nhận sau; người nhận tải về hoặc lưu riêng; người gửi thấy thông báo.
4. Xóa bản gốc sau khi người nhận đã lưu riêng; xác nhận bản riêng vẫn tải được.
5. Gửi trực tiếp khi hai người online; kiểm tra chấp nhận và nội dung tải về.
6. Chuyển người nhận offline và kiểm tra hướng dẫn gửi để nhận sau.
7. Thử tìm kiếm, lọc, thùng rác, khôi phục, quota và tài khoản không có quyền admin.
8. Kiểm tra ở chiều rộng điện thoại, điều hướng bàn phím, skeleton và nút thử lại khi API lỗi.
9. Đăng xuất rồi tải lại trang; tài khoản không tự mở lại.

## Tự động trên GitHub

Workflow `Tests` cài môi trường Python, Node.js và chạy cùng `scripts/test.py` khi push hoặc mở pull request. Workflow không triển khai web/API và không cần secret của tài khoản hosting.
