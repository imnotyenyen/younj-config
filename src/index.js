// YOUNJ Config Worker v2 — nhiều mật khẩu, mỗi mật khẩu có nhãn / hạn dùng / bật-tắt.
// Endpoints (khớp với index.html):
//   GET  /config  -> { maintenance, auth:{maxAttempts,lockMinutes,mode} }   (không lộ password/hash)
//   POST /auth    -> { password } => { ok:true, token } | { ok:false, reason, remainAttempts?, remainSeconds? }
//   POST /verify  -> { token }    => { valid }

import config from './config.json';

const enc = new TextEncoder();

// ---------- helpers ----------
function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function sha256Hex(text) {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}
// so sánh chuỗi không dừng sớm (chống timing attack)
function safeEqual(a, b) {
  const x = enc.encode(String(a));
  const y = enc.encode(String(b));
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

// chuẩn hóa mật khẩu giống phía index.html (bỏ ký tự ẩn, đổi nháy cong)
function normalizePassword(p) {
  return String(p || '')
    .trim()
    .replace(/[​-‍﻿ ]/g, '')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'");
}

// ---------- config ----------
function authCfg() {
  const a = config.auth || {};
  return {
    maxAttempts: Number(a.maxAttempts) > 0 ? Number(a.maxAttempts) : 3,
    lockMinutes: Number(a.lockMinutes) > 0 ? Number(a.lockMinutes) : 3,
    tokenHours: Number(a.tokenHours) > 0 ? Number(a.tokenHours) : 12,
    mode: a.mode || 'password',
  };
}
function isActive(p, now = Date.now()) {
  if (!p || p.enabled === false) return false;
  if (p.expiresAt) {
    const t = Date.parse(p.expiresAt);
    if (Number.isFinite(t) && t <= now) return false;
  }
  return true;
}

// ---------- token ----------
async function signToken(env, payload) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env.TOKEN_SECRET), enc.encode(body));
  return body + '.' + b64url(new Uint8Array(sig));
}
async function readToken(env, token) {
  if (typeof token !== 'string' || token.length > 2048) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  let ok = false;
  try {
    ok = await crypto.subtle.verify('HMAC', await hmacKey(env.TOKEN_SECRET), b64urlDecode(sig), enc.encode(body));
  } catch {
    return null;
  }
  if (!ok) return null;
  try {
    return JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
  } catch {
    return null;
  }
}

// ---------- rate limit (KV nếu có, không thì bộ nhớ isolate) ----------
const memory = new Map();
async function rlGet(env, key) {
  if (env.RATE_LIMIT) {
    const raw = await env.RATE_LIMIT.get(key);
    return raw ? JSON.parse(raw) : null;
  }
  const v = memory.get(key);
  if (v && v.expireAt && v.expireAt < Date.now()) { memory.delete(key); return null; }
  return v || null;
}
async function rlSet(env, key, value, ttlSec) {
  value.expireAt = Date.now() + ttlSec * 1000;
  if (env.RATE_LIMIT) {
    await env.RATE_LIMIT.put(key, JSON.stringify(value), { expirationTtl: Math.max(60, Math.ceil(ttlSec)) });
  } else {
    memory.set(key, value);
  }
}
async function rlDel(env, key) {
  if (env.RATE_LIMIT) await env.RATE_LIMIT.delete(key);
  else memory.delete(key);
}

// ---------- response ----------
function corsHeaders(request) {
  const allowed = config.allowedOrigins || ['*'];
  const origin = request.headers.get('Origin') || '';
  let allow = '*';
  if (!allowed.includes('*')) allow = allowed.includes(origin) ? origin : allowed[0] || '';
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}
function json(request, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders(request) },
  });
}
async function readJson(request) {
  try {
    const text = await request.text();
    if (text.length > 4096) return null;
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// ---------- handlers ----------
function handleConfig(request) {
  const a = authCfg();
  return json(request, {
    maintenance: config.maintenance || { enabled: false },
    auth: { maxAttempts: a.maxAttempts, lockMinutes: a.lockMinutes, mode: a.mode },
    meta: { name: config.name || 'YOUNJ', version: config.version || '2' },
  });
}

async function handleAuth(request, env) {
  if (!env.TOKEN_SECRET || env.TOKEN_SECRET.length < 16) {
    console.error('[config] TOKEN_SECRET thiếu hoặc ngắn hơn 16 ký tự');
    return json(request, { ok: false, reason: 'config_unavailable' }, 500);
  }
  const passwords = (config.passwords || []).filter((p) => p && p.hash && p.salt);
  if (!passwords.length) {
    console.error('[config] src/config.json chưa có mật khẩu nào (cần id, salt, hash)');
    return json(request, { ok: false, reason: 'config_unavailable' }, 500);
  }

  const body = await readJson(request);
  const password = normalizePassword(body && body.password);
  if (!password) return json(request, { ok: false, reason: 'invalid' }, 400);

  const a = authCfg();
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = 'fail:' + ip;
  const lockSec = a.lockMinutes * 60;

  // đang bị khóa?
  const rec = await rlGet(env, key);
  if (rec && rec.lockedUntil && rec.lockedUntil > Date.now()) {
    return json(request, { ok: false, reason: 'locked', remainSeconds: Math.ceil((rec.lockedUntil - Date.now()) / 1000) }, 429);
  }

  // thử tất cả mật khẩu (không dừng sớm)
  let matched = null;
  for (const p of passwords) {
    const h = await sha256Hex(p.salt + password);
    if (safeEqual(h, p.hash) && isActive(p) && !matched) matched = p;
  }

  if (matched) {
    await rlDel(env, key);
    const now = Date.now();
    let exp = now + a.tokenHours * 3600 * 1000;
    if (matched.expiresAt) exp = Math.min(exp, Date.parse(matched.expiresAt));
    const token = await signToken(env, { pid: matched.id, iat: now, exp });
    console.log(`[auth] ok id=${matched.id} label=${matched.label || ''}`);
    return json(request, { ok: true, token });
  }

  // sai mật khẩu
  const fails = (rec && !rec.lockedUntil ? rec.fails : 0) + 1;
  if (fails >= a.maxAttempts) {
    await rlSet(env, key, { fails, lockedUntil: Date.now() + lockSec * 1000 }, lockSec);
    return json(request, { ok: false, reason: 'locked', remainSeconds: lockSec }, 429);
  }
  await rlSet(env, key, { fails }, lockSec);
  return json(request, { ok: false, reason: 'wrong', remainAttempts: a.maxAttempts - fails }, 401);
}

async function handleVerify(request, env) {
  if (!env.TOKEN_SECRET) return json(request, { valid: false }, 500);
  const body = await readJson(request);
  const payload = await readToken(env, body && body.token);
  if (!payload || !payload.exp || payload.exp <= Date.now()) return json(request, { valid: false });
  // mật khẩu gốc phải còn hiệu lực -> xóa/tắt mật khẩu = thu hồi token ngay
  const p = (config.passwords || []).find((x) => x.id === payload.pid);
  return json(request, { valid: isActive(p) });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(request) });
    try {
      if (url.pathname === '/config' && request.method === 'GET') return handleConfig(request);
      if (url.pathname === '/auth' && request.method === 'POST') return await handleAuth(request, env);
      if (url.pathname === '/verify' && request.method === 'POST') return await handleVerify(request, env);
      if (url.pathname === '/' && request.method === 'GET') return json(request, { name: 'younj-config', ok: true });
      // chẩn đoán nhanh: chỉ trả true/false và số lượng, không lộ giá trị nào
      if (url.pathname === '/health' && request.method === 'GET') {
        return json(request, {
          tokenSecretSet: !!env.TOKEN_SECRET,
          tokenSecretLongEnough: !!env.TOKEN_SECRET && env.TOKEN_SECRET.length >= 16,
          passwordsLoaded: (config.passwords || []).filter((p) => p && p.hash && p.salt).length,
          kvBound: !!env.RATE_LIMIT,
        });
      }
      return json(request, { error: 'not_found' }, 404);
    } catch (e) {
      console.error('[error]', e && e.message);
      return json(request, { ok: false, reason: 'config_unavailable' }, 500);
    }
  },
};
