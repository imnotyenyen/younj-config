#!/usr/bin/env node
// Quản lý mật khẩu trong src/config.json (lưu hash, không lưu mật khẩu gốc).
//
//   node scripts/passwords.mjs add <nhãn> [--days N] [--password "tự đặt"]
//   node scripts/passwords.mjs list
//   node scripts/passwords.mjs disable <id>
//   node scripts/passwords.mjs enable <id>
//   node scripts/passwords.mjs remove <id>
//
// Sau khi sửa: git add . && git commit && git push -> Cloudflare tự deploy lại.

import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const file = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'config.json');
const cfg = JSON.parse(readFileSync(file, 'utf8'));
cfg.passwords ||= [];
const save = () => writeFileSync(file, JSON.stringify(cfg, null, 2) + '\n');

const [cmd, ...rest] = process.argv.slice(2);
const flag = (n) => { const i = rest.indexOf('--' + n); return i >= 0 ? rest[i + 1] : undefined; };
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'; // bỏ ký tự dễ nhầm
const genPassword = () => {
  const b = randomBytes(16);
  let s = '';
  for (let i = 0; i < 12; i++) s += ALPHABET[b[i] % ALPHABET.length];
  return s.slice(0, 4) + '-' + s.slice(4, 8) + '-' + s.slice(8);
};
const hash = (salt, pw) => createHash('sha256').update(salt + pw).digest('hex');
const find = (id) => cfg.passwords.find((p) => p.id === id);

switch (cmd) {
  case 'add': {
    const label = rest[0] && !rest[0].startsWith('--') ? rest[0] : 'unnamed';
    const custom = flag('password');
    const pw = custom || genPassword();
    const salt = randomBytes(8).toString('hex');
    let id;
    do { id = 'p_' + randomBytes(3).toString('hex'); } while (find(id));
    const entry = { id, label, salt, hash: hash(salt, pw), enabled: true };
    const days = Number(flag('days'));
    if (days > 0) entry.expiresAt = new Date(Date.now() + days * 86400000).toISOString();
    cfg.passwords.push(entry);
    save();
    console.log(`Đã thêm: ${label} (id ${id})${entry.expiresAt ? ' — hết hạn ' + entry.expiresAt : ''}`);
    console.log(`MẬT KHẨU (chỉ hiện 1 lần, hãy lưu lại): ${pw}`);
    break;
  }
  case 'list':
    for (const p of cfg.passwords) {
      const st = p.enabled === false ? 'TẮT' : p.expiresAt && Date.parse(p.expiresAt) <= Date.now() ? 'HẾT HẠN' : 'bật';
      console.log(`${p.id}\t${st}\t${p.label}\t${p.expiresAt || 'không hết hạn'}`);
    }
    if (!cfg.passwords.length) console.log('(chưa có mật khẩu nào)');
    break;
  case 'disable':
  case 'enable': {
    const p = find(rest[0]);
    if (!p) { console.error('Không thấy id', rest[0]); process.exit(1); }
    p.enabled = cmd === 'enable';
    save();
    console.log(`${cmd} ${p.id} (${p.label})`);
    break;
  }
  case 'remove': {
    const i = cfg.passwords.findIndex((p) => p.id === rest[0]);
    if (i < 0) { console.error('Không thấy id', rest[0]); process.exit(1); }
    const [p] = cfg.passwords.splice(i, 1);
    save();
    console.log(`Đã xóa ${p.id} (${p.label})`);
    break;
  }
  default:
    console.log('Dùng: add <nhãn> [--days N] [--password "..."] | list | disable <id> | enable <id> | remove <id>');
}
