# Chạy và triển khai

## Local

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m cloudserver.main
```

Mở `http://127.0.0.1:8787`. Dữ liệu được ghi trong `.data/runtime` và `.data/persistent`. Cấu hình mặc định chỉ lắng nghe loopback. Frontend tự dùng API cùng origin trên `localhost` và `127.0.0.1`.

`.env.example` liệt kê biến cấu hình; ứng dụng không tự nạp file `.env`. Đặt các biến bằng shell hoặc dashboard của nền tảng triển khai.

| Biến                  | Mục đích                                                   |
| --------------------- | ---------------------------------------------------------- |
| `HOST`, `PORT`        | Địa chỉ lắng nghe và cổng                                  |
| `SV_RUNTIME_DIR`      | SQLite và trạng thái runtime                               |
| `SV_PERSISTENT_DIR`   | Lưu trữ local bền vững, hoặc cache khi dùng bucket         |
| `SV_ALLOWED_ORIGINS`  | Các origin được phép gọi API, phân cách bằng dấu phẩy      |
| `SV_FRONTEND_URL`     | URL web xuất hiện trên trang trạng thái API                |
| `SV_BUCKET_ID`        | Bucket riêng tư dạng `owner/name`; bỏ trống khi chạy local |
| `HF_TOKEN`            | Token đọc/ghi bucket, chỉ ở backend                        |
| `SV_ADMIN_CLAIM_HASH` | SHA-256 của mã kích hoạt quản trị                          |
| `SV_LOCAL_WEB`        | Giá trị `1` cho phép backend Render phục vụ thêm web       |

Nếu đổi cổng local, thêm origin tương ứng vào `SV_ALLOWED_ORIGINS`. Truy cập qua tên miền hoặc địa chỉ mạng cần HTTPS để Web Crypto hoạt động.

## Khởi tạo quản trị

1. Chạy `python scripts/admin_code.py`. Giữ riêng **activation code** được in ra.
2. Đặt giá trị hash vào `SV_ADMIN_CLAIM_HASH` ở môi trường backend, rồi khởi động server.
3. Đăng ký hoặc đăng nhập tài khoản của chủ hệ thống, mở `/setup` và nhập activation code.
4. Sau khi kích hoạt thành công, mở `/admin`.

Mã được sử dụng một lần để cấp quản trị viên đầu tiên. Hash nằm trên server; activation code không được đưa vào frontend, Git hoặc đường dẫn công khai. Đăng ký thông thường luôn tạo tài khoản người dùng.

## Backend Render và Hugging Face Storage Bucket

1. Tạo **Storage Bucket riêng tư** trên Hugging Face. Backend yêu cầu bucket private.
2. Tạo token chỉ có quyền cần thiết với bucket đó.
3. Tạo Web Service Python trên Render từ repo này, hoặc dùng `render.yaml`.
4. Build command: `pip install -r requirements.txt`.
5. Start command: `python -m cloudserver.main`; health check: `/api/health`.
6. Đặt `SV_BUCKET_ID`, `HF_TOKEN`, `SV_FRONTEND_URL`, `SV_ALLOWED_ORIGINS` và hash kích hoạt quản trị trong cấu hình dịch vụ.
7. Chạy một instance, một worker. Không chạy hai server cùng ghi vào một bucket.

Render cấp `PORT` và biến nhận diện môi trường; ứng dụng lắng nghe `0.0.0.0` trong môi trường này. Nếu thiếu bucket, backend từ chối khởi động để tránh lưu tài khoản vào filesystem tạm. Cấu hình `autoDeployTrigger: off` yêu cầu triển khai thủ công.

Bucket chứa `secretvault/ciphertext/` và `secretvault/metadata/`. Không cần Space chạy ứng dụng trên Hugging Face. Tham khảo [Storage Buckets](https://huggingface.co/docs/hub/storage-buckets).

## Frontend Vercel

1. Import repo, giữ root ở thư mục gốc.
2. Build command: `node hosting/build-web.mjs`; output directory: `web`.
3. Khi dùng backend riêng, cập nhật URL API ở **`web/src/config.js`**, **`web/service.json`** và chỉ thị **`connect-src` trong `vercel.json`**.
4. Đặt origin Vercel chính xác vào `SV_ALLOWED_ORIGINS` của backend, cùng `SV_FRONTEND_URL`.
5. Kiểm tra web, `/admin`, `/setup`, `/api/health` và một lượt gửi/nhận giữa hai tài khoản.

Ba tệp cấu hình frontend đang trỏ tới dịch vụ SecretVault Online. Token hạ tầng chỉ được đặt trong secret của backend. Tệp upload đi từ trình duyệt tới Render theo chunk, không đi qua Vercel Functions.

## Ứng dụng Windows

Cần Windows x64, Python, Edge WebView2 Runtime và Inno Setup 6 để tạo bộ cài.

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-desktop.txt
.venv\Scripts\python.exe cloud_client_app.py
pwsh -File packaging/build-cloud-client.ps1
```

Kết quả nằm ở `release/SecretVault-Online-Setup-3.2.0-x64.exe`. Build dùng PyInstaller và Inno Setup; thư mục `release/` không được commit vào Git. Bộ cài mặc định không có chữ ký số.

`WEB_URL` trong `cloud_client_app.py` xác định web được mở. Nếu triển khai tên miền khác, cập nhật giá trị này cùng URL trong `packaging/cloud-client.iss` và hướng dẫn `docs/HUONG_DAN_ONLINE.txt` trước khi build.

`--browser` mở web bằng trình duyệt mặc định. `--diagnose` kiểm tra các endpoint công khai và lưu trạng thái trong thư mục dữ liệu ứng dụng của tài khoản Windows hiện tại. Ứng dụng không chạy backend cục bộ.

## Vận hành

- Sao lưu bucket riêng tư và bảo vệ token truy cập. Metadata chứa email, tên tệp và quyền chia sẻ.
- Lưu riêng thư mục `.data/persistent` khi chạy local; giữ cả bản mã và metadata để khôi phục đầy đủ.
- Kiểm tra `/api/health` cho trạng thái liveness. Kết quả thành công không thay thế một lượt kiểm tra ghi/đọc bucket.
- Điều chỉnh quota từng người tại dashboard; các hằng số mặc định nằm trong `cloudserver/store.py`.
- Giữ `SV_ALLOWED_ORIGINS` theo danh sách cụ thể. Không dùng wildcard.
- Gói hosting có cơ chế tạm ngủ có thể làm lần mở đầu chậm; skeleton chỉ diễn đạt trạng thái chờ, không giảm độ trễ backend.
