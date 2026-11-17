// Test cục bộ: chạy Worker bằng Node với config giả (không dùng mật khẩu thật).
//   node test/run.mjs
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const sha = (s) => createHash('sha256').update(s).digest('hex');
const mk = (id, pw, extra = {}) => ({ id, label: id, salt: 's_' + id, hash: sha('s_' + id + pw), enabled: true, ...extra });

const fixture = {
  maintenance: { enabled: false },
  auth: { mode: 'password', maxAttempts: 3, lockMinutes: 3, tokenHours: 12 },
  passwords: [
    mk('a', 'alpha-pass'),
    mk('b', 'beta-pass'),
    mk('off', 'off-pass', { enabled: false }),
    mk('old', 'old-pass', { expiresAt: '2020-01-01T00:00:00Z' }),
  ],
};

// bản sao tạm của worker + config giả (thêm import attribute để Node nạp được JSON)
const dir = mkdtempSync(join(tmpdir(), 'younj-test-'));
mkdirSync(join(dir, 'src'));
let code = readFileSync(join(root, 'src', 'index.js'), 'utf8').replace("from './config.json';", "from './config.json' with { type: 'json' };");
writeFileSync(join(dir, 'src', 'index.js'), code);
writeFileSync(join(dir, 'src', 'config.json'), JSON.stringify(fixture));
const worker = (await import(pathToFileURL(join(dir, 'src', 'index.js')).href)).default;

const env = { TOKEN_SECRET: 'test-secret-at-least-16-chars-long' };
const call = async (method, path, body, ip = '1.1.1.1', e = env) => {
  const res = await worker.fetch(
    new Request('https://w.test' + path, { method, body: body ? JSON.stringify(body) : undefined, headers: { 'CF-Connecting-IP': ip } }),
    e
  );
  return { status: res.status, data: await res.json() };
};

let pass = 0, fail = 0;
const t = (name, cond) => { cond ? pass++ : fail++; console.log((cond ? 'PASS ' : 'FAIL ') + name); };

// /config
let r = await call('GET', '/config');
t('/config trả maintenance + auth', r.status === 200 && r.data.maintenance && r.data.auth.maxAttempts === 3);
t('/config không lộ hash/password', !JSON.stringify(r.data).match(/hash|salt|alpha-pass/));

// nhiều mật khẩu cùng dùng được
r = await call('POST', '/auth', { password: 'alpha-pass' }, '2.2.2.2');
t('mật khẩu A đúng -> token', r.data.ok === true && !!r.data.token);
const tokA = r.data.token;
r = await call('POST', '/auth', { password: ' beta-pass​ ' }, '3.3.3.3');
t('mật khẩu B đúng (có khoảng trắng/ký tự ẩn) -> token', r.data.ok === true);
const tokB = r.data.token;

// verify
r = await call('POST', '/verify', { token: tokA });
t('/verify token hợp lệ', r.data.valid === true);
r = await call('POST', '/verify', { token: tokA.slice(0, -2) + 'xx' });
t('/verify token bị sửa -> false', r.data.valid === false);
r = await call('POST', '/verify', { token: 'rac.rac' });
t('/verify token rác -> false', r.data.valid === false);
r = await call('POST', '/verify', {});
t('/verify thiếu token -> false', r.data.valid === false);
r = await call('POST', '/verify', { token: tokB }, '9.9.9.9', { TOKEN_SECRET: 'khac-secret-khac-secret-khac' });
t('/verify khác secret -> false', r.data.valid === false);

// mật khẩu tắt / hết hạn
r = await call('POST', '/auth', { password: 'off-pass' }, '4.4.4.4');
t('mật khẩu bị tắt -> từ chối', r.data.ok === false && r.data.reason === 'wrong');
r = await call('POST', '/auth', { password: 'old-pass' }, '5.5.5.5');
t('mật khẩu hết hạn -> từ chối', r.data.ok === false && r.data.reason === 'wrong');

// sai + khóa theo IP
r = await call('POST', '/auth', { password: 'sai1' }, '6.6.6.6');
t('sai lần 1 -> còn 2 lần', r.data.reason === 'wrong' && r.data.remainAttempts === 2);
r = await call('POST', '/auth', { password: 'sai2' }, '6.6.6.6');
t('sai lần 2 -> còn 1 lần', r.data.remainAttempts === 1);
r = await call('POST', '/auth', { password: 'sai3' }, '6.6.6.6');
t('sai lần 3 -> locked 180s', r.data.reason === 'locked' && r.data.remainSeconds === 180 && r.status === 429);
r = await call('POST', '/auth', { password: 'alpha-pass' }, '6.6.6.6');
t('đang khóa: đúng mật khẩu vẫn bị chặn', r.data.ok === false && r.data.reason === 'locked');
r = await call('POST', '/auth', { password: 'alpha-pass' }, '7.7.7.7');
t('IP khác không bị ảnh hưởng', r.data.ok === true);

// đúng thì reset bộ đếm
await call('POST', '/auth', { password: 'x' }, '8.8.8.8');
await call('POST', '/auth', { password: 'beta-pass' }, '8.8.8.8');
r = await call('POST', '/auth', { password: 'x' }, '8.8.8.8');
t('đăng nhập đúng reset bộ đếm sai', r.data.remainAttempts === 2);

// lỗi cấu hình / đầu vào
r = await call('POST', '/auth', { password: 'alpha-pass' }, '1.2.3.4', {});
t('thiếu TOKEN_SECRET -> config_unavailable', r.data.reason === 'config_unavailable');
r = await call('POST', '/auth', {}, '1.2.3.5');
t('thiếu password -> 400', r.status === 400);
r = await call('GET', '/khong-co');
t('route lạ -> 404', r.status === 404);

// CORS preflight
const pre = await worker.fetch(new Request('https://w.test/auth', { method: 'OPTIONS' }), env);
t('OPTIONS preflight 204 + CORS', pre.status === 204 && pre.headers.get('Access-Control-Allow-Origin') === '*');

// KV giả: khóa vẫn hoạt động khi có RATE_LIMIT
const store = new Map();
const kv = { get: async (k) => store.get(k) ?? null, put: async (k, v) => void store.set(k, v), delete: async (k) => void store.delete(k) };
const envKv = { ...env, RATE_LIMIT: kv };
for (let i = 0; i < 3; i++) r = await call('POST', '/auth', { password: 'sai' }, '10.0.0.1', envKv);
t('khóa hoạt động với KV', r.data.reason === 'locked' && store.has('fail:10.0.0.1'));

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
