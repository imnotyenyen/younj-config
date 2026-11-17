# YOUNJ Config Worker v2

Cloudflare Worker làm backend cho `index.html` (YOUNJ Plist Editor). Khác bản cũ: **nhiều mật khẩu**, mỗi mật khẩu có nhãn riêng, có thể đặt hạn dùng, bật/tắt hoặc thu hồi bất cứ lúc nào mà không ảnh hưởng người khác.

## Endpoints (giữ nguyên như bản cũ, không cần sửa index.html ngoài `WORKER_URL`)

| Method | Path | Body | Trả về |
|---|---|---|---|
| GET | `/config` | — | `{ maintenance, auth:{maxAttempts,lockMinutes,mode} }` (không có password/hash) |
| POST | `/auth` | `{ password }` | `{ ok:true, token }` hoặc `{ ok:false, reason:'wrong'\|'locked'\|'config_unavailable', remainAttempts?, remainSeconds? }` |
| POST | `/verify` | `{ token }` | `{ valid }` |

## Quản lý mật khẩu

Mật khẩu được lưu dạng **hash + salt** trong `src/config.json` (không lưu bản gốc). Dùng script:

```bash
node scripts/passwords.mjs add "Bạn C"                 # sinh mật khẩu ngẫu nhiên, hiện 1 lần
node scripts/passwords.mjs add "Khách" --days 7        # tự hết hạn sau 7 ngày
node scripts/passwords.mjs add "VIP" --password "abc"  # tự đặt mật khẩu (nên dùng chuỗi dài)
node scripts/passwords.mjs list                        # xem danh sách + trạng thái
node scripts/passwords.mjs disable p_xxxxxx            # tạm tắt
node scripts/passwords.mjs enable  p_xxxxxx            # bật lại
node scripts/passwords.mjs remove  p_xxxxxx            # xóa hẳn
```

Sau khi sửa: `git add . && git commit -m "update passwords" && git push` → Cloudflare tự deploy lại sau ~1-2 phút.

**Thu hồi ngay:** tắt/xóa mật khẩu nào thì mọi token đã cấp từ mật khẩu đó mất hiệu lực ngay khi deploy xong (index.html gọi `/verify` định kỳ).

## Deploy

1. Tạo repo GitHub mới (**để Private**) và push toàn bộ thư mục này lên.
2. Cloudflare → Workers & Pages → Create → **Connect to Git** → chọn repo.
   - Build command: để trống
   - Deploy command: `npx wrangler deploy`
3. Worker → Settings → Variables and Secrets → thêm secret **`TOKEN_SECRET`** = chuỗi random ≥ 32 ký tự (tự tạo, đừng dùng chuỗi mẫu nào trên mạng).
4. (Khuyến nghị) Tạo KV namespace `younj-rate-limit`, dán ID vào `wrangler.toml` (bỏ comment `[[kv_namespaces]]`), commit + push. Không có KV thì khóa theo IP vẫn chạy nhưng chỉ nhớ trong bộ nhớ tạm của Worker.
5. Lấy URL Worker (VD `https://younj-config.xxx.workers.dev`) và dán vào `index.html`:
   ```js
   const WORKER_URL = 'https://younj-config.xxx.workers.dev';
   ```

## Chỉnh bảo trì / giới hạn thử

Sửa `src/config.json`:

- `maintenance.enabled: true` → trang hiện màn hình bảo trì (kèm `title`, `reason`, `eta`, `contactUrl`).
- `auth.maxAttempts` / `auth.lockMinutes` → số lần sai tối đa / số phút khóa (theo IP).
- `auth.tokenHours` → token sống bao lâu (mặc định 12 giờ).
- `allowedOrigins` → `["*"]` hoặc danh sách domain được phép gọi, VD `["https://ten-ban.github.io"]`.

## Test cục bộ

```bash
node test/run.mjs      # 22 test: nhiều mật khẩu, sai/khóa, hết hạn, thu hồi, token giả, CORS, KV
npm install && npx wrangler dev   # chạy thử Worker trên máy (cần TOKEN_SECRET trong .dev.vars)
```

`.dev.vars` (không commit): `TOKEN_SECRET=chuoi-random-dai-o-day`

## Bảo mật — lưu ý

- Repo **nên private**: hash tuy không đảo ngược được, nhưng repo public cho phép người ngoài thử dò offline. Mật khẩu do script sinh (12 ký tự ngẫu nhiên) đủ mạnh; mật khẩu tự đặt ngắn/dễ đoán thì không.
- Không bao giờ commit `TOKEN_SECRET`. Nếu nghi lộ, đổi secret → mọi token cũ hết hiệu lực.
- Backend chỉ chặn việc *dùng tool*; index.html vẫn là mã công khai phía client.
