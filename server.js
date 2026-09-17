/* خادم تراخيص أستاذي — بدون اعتماديات خارجية (http + crypto مدمجة فقط)
   التشغيل:  ADMIN_PASSWORD=كلمة_قوية PORT=48721 node server.js
   الترخيص = رمز فريد + اسم عميل + تاريخ انتهاء + عدد أجهزة + ربط أجهزة.
   التذاكر موقعة بـ ECDSA P-256 وتُتحقق في التطبيقات دون إنترنت. */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 48721);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me';
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { licenses: {} }; }
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8'); }
function loadKeys() {
  // مفاتيح ثابتة عبر متغير البيئة (ضروري لأن قرص Render المجاني مؤقت)
  if (process.env.LICENSE_KEYS_JSON) {
    try { return JSON.parse(process.env.LICENSE_KEYS_JSON); } catch {}
  }
  try { return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8')); }
  catch {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256', publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
    const keys = { publicKey, privateKey, createdAt: new Date().toISOString() };
    try { fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2), 'utf8'); } catch {}
    return keys;
  }
}
const keys = loadKeys();
const b64u = buf => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
function signTicket(payload) {
  const data = b64u(Buffer.from(JSON.stringify(payload), 'utf8'));
  // ieee-p1363 (r||s خام) لأن WebCrypto في التطبيقات يتوقع هذه الصيغة لا DER
  const sig = crypto.createSign('SHA256').update(data).sign({ key: keys.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${data}.${b64u(sig)}`;
}
function normCode(code) { return String(code || '').trim().toUpperCase().replace(/[\s-]/g, ''); }
function genCode() {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const part = n => Array.from(crypto.randomBytes(n)).map(b => alphabet[b % alphabet.length]).join('');
  return `AST-${part(4)}-${part(4)}`;
}
function daysFromNow(days) { return new Date(Date.now() + Number(days) * 86400000).toISOString(); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => { raw += c; if (raw.length > 256 * 1024) req.destroy(); });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('JSON غير صالح')); } });
    req.on('error', reject);
  });
}
function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token', 'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS' });
  res.end(JSON.stringify(obj));
}
function adminOk(req) { return req.headers['x-admin-token'] === ADMIN_PASSWORD; }

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return send(res, 204, {});
    const url = new URL(req.url, 'http://localhost');
    // صفحة الإدارة
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/admin')) {
      const html = fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    }
    // المفتاح العام (يُضمَّن في التطبيقات)
    if (req.method === 'GET' && url.pathname === '/api/pubkey') return send(res, 200, { publicKey: keys.publicKey });
    // تفعيل جهاز برمز
    if (req.method === 'POST' && url.pathname === '/api/activate') {
      const { code, deviceId, deviceName } = await readBody(req);
      const db = loadDB();
      const lic = db.licenses[normCode(code)];
      if (!lic) return send(res, 404, { ok: false, reason: 'invalid', message: 'رمز التفعيل غير صحيح.' });
      if (lic.revoked) return send(res, 403, { ok: false, reason: 'revoked', message: 'أُلغي هذا الرمز. تواصل مع المورّد.' });
      if (new Date(lic.expiry).getTime() < Date.now()) return send(res, 403, { ok: false, reason: 'expired', message: 'انتهت صلاحية هذا الرمز.' });
      const dev = String(deviceId || '').trim();
      if (!dev) return send(res, 400, { ok: false, reason: 'no-device', message: 'تعذر التعرف على الجهاز.' });
      lic.devices = lic.devices || {};
      if (!lic.devices[dev] && Object.keys(lic.devices).length >= Number(lic.maxDevices || 1)) {
        return send(res, 403, { ok: false, reason: 'device-limit', message: `بلغ الرمز حد الأجهزة (${lic.maxDevices}). تواصل مع المورّد.` });
      }
      const now = new Date().toISOString();
      lic.devices[dev] = { name: String(deviceName || '').slice(0, 80), firstSeen: lic.devices[dev]?.firstSeen || now, lastSeen: now };
      saveDB(db);
      const ticket = signTicket({ v: 1, code: lic.code, device: dev, exp: lic.expiry, iat: now });
      return send(res, 200, { ok: true, ticket, exp: lic.expiry, clientName: lic.clientName });
    }
    // تحقق دوري من تذكرة
    if (req.method === 'POST' && url.pathname === '/api/verify') {
      const { ticket, deviceId } = await readBody(req);
      const [data, sig] = String(ticket || '').split('.');
      let payload = null;
      try {
        const valid = crypto.createVerify('SHA256').update(data).verify({ key: keys.publicKey, dsaEncoding: 'ieee-p1363' }, unb64u(sig));
        if (valid) payload = JSON.parse(Buffer.from(data.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
      } catch {}
      if (!payload) return send(res, 401, { ok: false, reason: 'bad-ticket' });
      if (String(deviceId || '').trim() !== payload.device) return send(res, 403, { ok: false, reason: 'device-mismatch' });
      const db = loadDB();
      const lic = db.licenses[payload.code];
      if (!lic || lic.revoked) return send(res, 403, { ok: false, reason: 'revoked' });
      if (new Date(lic.expiry).getTime() < Date.now()) return send(res, 403, { ok: false, reason: 'expired' });
      if (lic.devices?.[payload.device]) lic.devices[payload.device].lastSeen = new Date().toISOString();
      saveDB(db);
      const fresh = signTicket({ v: 1, code: lic.code, device: payload.device, exp: lic.expiry, iat: new Date().toISOString() });
      return send(res, 200, { ok: true, ticket: fresh, exp: lic.expiry });
    }
    // ---- الإدارة ----
    if (!url.pathname.startsWith('/api/admin')) return send(res, 404, { ok: false, message: 'غير موجود' });
    if (!adminOk(req)) return send(res, 401, { ok: false, message: 'رمز الإدارة غير صحيح' });
    const db = loadDB();
    if (req.method === 'GET' && url.pathname === '/api/admin/licenses') {
      const list = Object.values(db.licenses).map(l => ({ code: l.code, clientName: l.clientName, createdAt: l.createdAt, expiry: l.expiry, maxDevices: l.maxDevices, revoked: !!l.revoked, devices: Object.entries(l.devices || {}).map(([id, d]) => ({ id, ...d })) }));
      return send(res, 200, { ok: true, licenses: list, pubkey: keys.publicKey, defaultPassword: ADMIN_PASSWORD === 'change-me' });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/licenses') {
      const { clientName, days, expiry, maxDevices } = await readBody(req);
      const code = genCode();
      const exp = expiry || daysFromNow(Math.max(1, Number(days) || 365));
      db.licenses[normCode(code)] = { code, clientName: String(clientName || 'عميل').slice(0, 80), createdAt: new Date().toISOString(), expiry: new Date(exp).toISOString(), maxDevices: Math.max(1, Number(maxDevices) || 1), revoked: false, devices: {} };
      saveDB(db);
      return send(res, 200, { ok: true, license: db.licenses[normCode(code)] });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/revoke') {
      const { code, revoked } = await readBody(req);
      const lic = db.licenses[normCode(code)];
      if (!lic) return send(res, 404, { ok: false });
      lic.revoked = revoked !== false;
      saveDB(db);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/export') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="astadhi-licenses-backup.json"', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify(loadDB(), null, 2));
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/import') {
      const body = await readBody(req);
      if (!body || typeof body !== 'object' || !body.licenses || typeof body.licenses !== 'object') return send(res, 400, { ok: false, message: 'ملف غير صالح' });
      saveDB({ licenses: body.licenses });
      return send(res, 200, { ok: true });
    }
    if (req.method === 'DELETE' && url.pathname === '/api/admin/device') {      const { code, deviceId } = await readBody(req);
      const lic = db.licenses[normCode(code)];
      if (!lic) return send(res, 404, { ok: false });
      if (lic.devices) delete lic.devices[String(deviceId)];
      saveDB(db);
      return send(res, 200, { ok: true });
    }
    return send(res, 404, { ok: false });
  } catch (e) { send(res, 500, { ok: false, message: e.message }); }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`خادم التراخيص يعمل على http://localhost:${PORT}`);
  if (ADMIN_PASSWORD === 'change-me') console.log('تحذير: غيّر ADMIN_PASSWORD قبل الإنتاج!');
});
