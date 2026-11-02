# Thiết kế mật mã

SecretVault tách **danh tính công khai**, **khóa bảo vệ nội dung tệp** và **khóa dùng trong từng lần chia sẻ**. Người dùng thao tác bằng tài khoản và tệp; client tự tạo, sử dụng và bảo vệ các khóa.

Phần triển khai nằm trong [`web/src/crypto.js`](../web/src/crypto.js). [`web/src/app.js`](../web/src/app.js) kết hợp các hàm mật mã với quy trình gửi/nhận. Python xác minh chữ ký và quyền truy cập tại [`vaultserver/security.py`](../vaultserver/security.py), [`server.py`](../vaultserver/server.py) và [`cloudserver/handler.py`](../cloudserver/handler.py).

## 1. Tham số và ký hiệu

| Ký hiệu            | Ý nghĩa                                                                     |
| ------------------ | --------------------------------------------------------------------------- |
| `p`                | Số nguyên tố 3072 bit của RFC 3526, nhóm 15                                 |
| `q = (p − 1) / 2`  | Bậc nhóm con nguyên tố                                                      |
| `g = 2`            | Phần tử sinh nhóm con                                                       |
| `x`, `a`, `b`, `r` | Số mũ bí mật ngẫu nhiên trong `[2, q − 1]`                                  |
| `K_file`           | Khóa AES 256 bit riêng cho một tệp                                          |
| `K_vault`          | Khóa AES 256 bit riêng của tài khoản, dùng bọc khóa tệp do tài khoản sở hữu |
| `K_wrap`           | Khóa bọc khóa tệp, dẫn xuất cho một envelope ElGamal Hybrid                 |
| `K_session`        | Khóa mã hóa nội dung trong một phiên gửi trực tiếp                          |

`scalar()` lấy mẫu bằng `crypto.getRandomValues()` và loại mẫu nằm ngoài miền hợp lệ. `validateGroupKey()` kiểm tra `2 ≤ y ≤ p − 2` và `y^q mod p = 1` trước khi dùng một public value để tính bí mật chung. Giá trị nhóm được mã hóa thành 384 byte theo thứ tự big-endian, biểu diễn bằng 768 chữ số hex khi truyền JSON. [RFC 3526, mục 4](https://www.rfc-editor.org/rfc/rfc3526#section-4).

## 2. Danh tính và bảo vệ khóa riêng

Khi đăng ký, `makeAccount()` tạo:

1. Cặp khóa **Ed25519** để ký thông điệp.
2. Cặp khóa **ElGamal**: khóa riêng `x`, khóa công khai `y = g^x mod p`.
3. Khóa kho `K_vault` gồm 32 byte ngẫu nhiên.
4. Fingerprint SHA-256 của JSON công khai gồm khóa ký, khóa ElGamal và tên nhóm.

Khóa ký riêng, `x`, `K_vault` và fingerprint được đặt trong một bundle. Client dẫn xuất khóa bọc bundle bằng **PBKDF2-HMAC-SHA256, 600.000 vòng, salt ngẫu nhiên 32 byte**, rồi mã hóa bundle với AES-256-GCM. AAD chứa email đã chuẩn hóa: `SecretVault:account-v2:<email>`.

Server lưu public material và bundle đã mã hóa. Khi đăng nhập trên thiết bị khác, `unlockAccount()` dẫn xuất lại khóa từ mật khẩu, giải mã bundle, đối chiếu fingerprint, kiểm tra `g^x mod p = y` và ký/xác minh một thông điệp thử để xác nhận cặp Ed25519.

Credential đăng nhập được dẫn xuất riêng bằng PBKDF2 với salt `SHA256("SecretVault:auth-credential-v2:" + email)`. Backend tiếp tục băm credential với salt ngẫu nhiên trước khi lưu. Credential này không trực tiếp mở được bundle, nhưng vẫn là bí mật tương đương mật khẩu đối với API và phải truyền qua HTTPS. Việc dẫn xuất này không phải giao thức PAKE.

Danh bạ ghim fingerprint ở lần gặp đầu tiên và phát hiện thay đổi về sau. Cơ chế này là **trust on first use**; nó không chứng nhận danh tính ngoài đời của chủ email.

## 3. Mã hóa nội dung tệp

Client sinh `K_file` mới cho mỗi tệp, chia nội dung thành các chunk tối đa **1 MiB**, rồi mã hóa bằng AES-256-GCM với tag 128 bit.

```text
IV_i  = random_prefix_64_bits || uint32_be(i)
AAD_i = canonical({ purpose: "file-chunk-v2", fileId, ownerId, index, total, size })
C_i   = AES-GCM-Encrypt(K_file, IV_i, plaintext_i, AAD_i)
```

Tiền tố IV được tạo một lần cho khóa tệp mới; chỉ số chunk không lặp trong tệp. Không được mã hóa lại nội dung khác bằng cùng cặp khóa/IV. AAD ràng buộc chunk với tệp, chủ sở hữu, vị trí, tổng chunk và kích thước.

Manifest ghi tên, MIME, kích thước, IV, thứ tự chunk và SHA-256 của từng bản mã. Chủ sở hữu ký manifest bằng Ed25519. Khi tải về, client xác minh chữ ký, hash, thứ tự và kích thước; AES-GCM kiểm tra tag khi giải mã. Tên và kích thước trong manifest là **metadata server nhìn thấy**, không phải nội dung được mã hóa. [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).

Để chủ sở hữu mở lại tệp, `wrapOwner()` bọc `K_file` bằng `K_vault` với AAD gồm `ownerId` và `fileId`. API không trả `ownerWrap` cho người chỉ được chia sẻ tệp.

## 4. Gửi để nhận sau: ElGamal Hybrid

Luồng này bảo vệ **khóa tệp** bằng khóa công khai dài hạn của người nhận. Người nhận không cần online khi người gửi tạo chia sẻ.

Người nhận có `x` và `y = g^x mod p`. Người gửi lấy `y` từ danh tính đã kiểm tra, tạo số mũ tạm thời `r` và tính:

```text
c1 = g^r mod p
z  = y^r mod p
salt = random(32 bytes)
context = { purpose, fileId, senderId, recipientId,
            recipientFingerprint, manifestHash }
K_wrap = HKDF-SHA256(z, salt, "SecretVault:offline-v2:" + canonical(context), 32)
wrappedKey = AES-GCM-Encrypt(K_wrap, random_IV_96_bits, K_file, canonical(context))
```

Envelope chứa `scheme`, `group`, `c1`, `salt`, `iv` và `data`. Người gửi ký payload gồm context, envelope và thời điểm; backend xác minh chữ ký và quyền sở hữu trước khi lưu chia sẻ.

Người nhận xác minh danh tính người gửi, chữ ký và context, rồi tính:

```text
z = c1^x mod p = (g^r)^x mod p = (g^x)^r mod p
K_wrap = HKDF-SHA256(z, salt, cùng info, 32)
K_file = AES-GCM-Decrypt(K_wrap, envelope, canonical(context))
```

`wrapElgamal()` và `unwrapElgamal()` thực hiện hai phía trên. Đây là **ElGamal Hybrid theo dạng đóng gói khóa và mã hóa đối xứng**: bí mật từ phép toán ElGamal đi qua HKDF, sau đó AES-GCM bọc `K_file`. Ứng dụng không dùng phép nhân `c2 = m · y^r mod p` để mã hóa từng byte của tệp. Các vector số nhỏ trong `tests/algebra-vectors.mjs` chỉ kiểm tra đại số nền; luồng tệp thật dùng nhóm 3072 bit và AEAD.

Hai lần chia sẻ cùng một khóa tệp vẫn tạo envelope khác nhau nhờ `r`, salt và IV mới. Context ngăn việc chuyển envelope sang tệp, người nhận hoặc manifest khác. HKDF sử dụng SHA-256 và phân tách mục đích qua chuỗi `info`. [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).

## 5. Gửi trực tiếp: Diffie–Hellman tạm thời

Cả hai người phải online. Người gửi tạo `a`, `A = g^a mod p`; người nhận tạo `b`, `B = g^b mod p`. Hai bên kiểm tra public value và chữ ký trước khi dùng kết quả trao đổi.

```mermaid
sequenceDiagram
    participant S as Người gửi
    participant API as API trung chuyển
    participant R as Người nhận
    S->>S: Sinh a, A = g^a mod p
    S->>API: offer(A, nonce, thông tin tệp), chữ ký
    API-->>R: Lời mời đã kiểm tra quyền
    R->>R: Kiểm tra offer; sinh b, B = g^b mod p
    R->>API: acceptance(B, nonce, hash offer), chữ ký
    API-->>S: Chấp nhận
    S->>S: z = B^a mod p, dẫn xuất khóa
    R->>R: z = A^b mod p, dẫn xuất khóa
    S->>API: Chunk AES-GCM và thông điệp kết thúc có chữ ký
    API-->>R: Bản mã
    R->>R: Xác minh và giải mã
    R->>API: Xác nhận hoàn tất
```

Lời mời ràng buộc phiên, hai người tham gia, fingerprint người nhận, public value, nonce ngẫu nhiên, hạn dùng và mô tả tệp. Chấp nhận chứa hash lời mời, định danh phiên, public value và nonce người nhận. Cả hai thông điệp đều có chữ ký Ed25519.

`sessionKey()` tính:

```text
z = B^a mod p = A^b mod p
transcriptHash = SHA256(canonical({ offer, acceptance }))
salt = SHA256(UTF8(offer.nonce + ":" + acceptance.nonce))
K_session = HKDF-SHA256(z, salt, "SecretVault:live-v2:" + transcriptHash, 32)
```

AES-GCM dùng `K_session` trực tiếp để mã hóa chunk của phiên. AAD chứa `purpose: "live-chunk-v2"`, transcript hash, chỉ số và tổng chunk. Thông điệp kết thúc ký danh sách hash bản mã cùng transcript hash.

API chỉ trung chuyển payload tạm thời. Sau xác nhận hoàn tất, backend giải phóng bản mã tạm. Reload hoặc đóng ứng dụng làm mất trạng thái DH trong bộ nhớ, vì vậy cần bắt đầu phiên mới. Nếu người nhận offline, giao diện chuyển sang **Gửi để nhận sau**, giữ lựa chọn tệp/email và chờ người gửi xác nhận gửi.

## 6. Chữ ký và mã hóa JSON

`canonical()` sắp xếp khóa object và loại khoảng trắng không cần thiết. Client và Python ký/xác minh cùng byte UTF-8. Ed25519 xác thực manifest, đăng ký danh tính, envelope, offer, acceptance và thông điệp hoàn tất. Chữ ký không mã hóa nội dung và không thay thế kiểm tra quyền truy cập API. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).

## 7. Phiên và vòng đời khóa

| Khóa / trạng thái               | Thời gian sử dụng                          | Lưu trữ                                    |
| ------------------------------- | ------------------------------------------ | ------------------------------------------ |
| Khóa ElGamal và Ed25519 dài hạn | Theo tài khoản                             | Bundle mã hóa trên server; mở trên client  |
| `K_vault`                       | Theo tài khoản                             | Cùng bundle                                |
| `K_file`                        | Theo tệp                                   | Envelope của chủ sở hữu và từng người nhận |
| Số mũ `r`, `K_wrap`             | Một lần bọc/mở khóa                        | Bộ nhớ client                              |
| DH tạm thời, `K_session`        | Một phiên gửi trực tiếp                    | Bộ nhớ client                              |
| Token đăng nhập                 | 12 giờ hoặc tối đa 7 ngày khi chọn ghi nhớ | Hash ở server; cache mã hóa ở client       |

`remember.js` mã hóa token và các bí mật cần để mở lại phiên bằng một AES CryptoKey không cho xuất raw key. Khóa này và khóa ký không xuất được được lưu bằng structured clone trong IndexedDB. Đăng xuất xóa cache và thu hồi phiên trên server. Quyền truy cập hồ sơ trình duyệt vẫn là quyền truy cập tài khoản trong thời hạn ghi nhớ.

Các buffer byte tạm được xóa khi phù hợp, nhưng JavaScript BigInt và bộ thu gom rác không cung cấp bảo đảm xóa toàn bộ bản sao bí mật khỏi bộ nhớ.

## 8. Giả định thiết kế

- Thiết bị, mã frontend được tải và trình duyệt phải đáng tin cậy. XSS hoặc client bị sửa có thể truy cập dữ liệu đang mở.
- HTTPS bảo vệ credential, token và việc phân phối frontend; mã hóa tệp không thay thế TLS.
- Server nhìn thấy email, tên tệp, kích thước, người gửi/nhận và thời điểm hoạt động.
- `modPow()` dùng JavaScript BigInt; thời gian thực thi không được bảo đảm cố định.
- Khóa ElGamal dài hạn cho phép mở chia sẻ cũ: nếu khóa riêng này bị lộ, các envelope đã ghi lại có thể bị giải mã.
- Thu hồi chia sẻ ngăn truy cập tiếp theo qua API; không xóa bản người nhận đã tải hoặc lưu riêng.
- Mất mật khẩu và không còn phiên mở khóa sẽ làm mất khả năng giải mã bundle. Hiện chưa có luồng khôi phục mật khẩu hoặc luân chuyển khóa tài khoản.

## 9. Đọc code và kiểm thử

| Nội dung                                      | Hàm / tệp                                                   |
| --------------------------------------------- | ----------------------------------------------------------- |
| Nhóm hữu hạn và kiểm tra public value         | `P`, `Q`, `G`, `modPow`, `scalar`, `validateGroupKey`       |
| Danh tính, credential và bundle               | `makeAccount`, `authProof`, `unlockAccount`                 |
| Mã hóa tệp                                    | `encrypt`, `decrypt`, `chunkIv`, `fileAad`, `wrapOwner`     |
| ElGamal Hybrid                                | `wrapElgamal`, `unwrapElgamal`, `shareContext`              |
| DH và ràng buộc transcript                    | `ephemeral`, `sessionKey`, `liveAad`                        |
| Điều phối luồng trực tiếp                     | `startLive`, `acceptLive`, `sendLivePayload` trong `app.js` |
| Vector, tamper, sai người nhận, replay và ACL | `tests/integration.mjs`                                     |
| Bản sao độc lập và xác nhận nhận              | `tests/delivery.mjs`                                        |
| Cache khóa trên thiết bị                      | `tests/remember.mjs`                                        |

Chạy toàn bộ bằng `python scripts/test.py` trong môi trường Python đã cài dependencies.
