// ============================================================================
// WHO2 BACKEND v3  —  Node.js + Express + MongoDB + Socket.io + FCM
// Needs Node 18+ (uses built-in fetch / crypto).
// npm i express mongoose bcryptjs jsonwebtoken cors socket.io node-cron dotenv \
//       compression express-rate-limit nodemailer firebase-admin
// ============================================================================
require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');

// A single unhandled error used to CRASH the whole server (=> "incomplete chunked encoding" in the app).
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e));
process.on('uncaughtException', (e) => console.error('uncaughtException:', e));

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('❌ JWT_SECRET is missing'); process.exit(1); }
const IS_PROD = process.env.NODE_ENV === 'production';
const ALLOW_DEV_OTP = process.env.ALLOW_DEV_OTP === 'true' || !IS_PROD; // set NODE_ENV=production once real OTP providers work
const TZ = process.env.APP_TZ || 'Asia/Kolkata';

// ---------- Firebase Admin (push notifications) – optional ----------
let admin = null;
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    admin = require('firebase-admin');
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
    console.log('✅ Firebase Admin ready (push enabled)');
  } else console.log('ℹ️  FIREBASE_SERVICE_ACCOUNT not set – push notifications disabled');
} catch (e) { console.error('Firebase init failed:', e.message); admin = null; }

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 15e6, pingInterval: 20000, pingTimeout: 25000 });
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '20mb' }));

mongoose.connect(process.env.MONGO_URI)
  .then(() => { console.log('✅ MongoDB connected'); migrate(); })
  .catch((err) => console.error('❌ MongoDB error:', err));

// ============================================================================
// SCHEMAS
// ============================================================================
const S = mongoose.Schema;
const ObjId = S.Types.ObjectId;

const UserSchema = new S({
  fullName: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true }, // phone users get <digits>@who2.mobile
  phoneNumber: { type: String, default: '' },
  about: { type: String, default: 'Hey there! I am using WHO2' },
  profilePic: { type: String, default: '', select: false },
  picVersion: { type: Number, default: 0 },
  fcmTokens: { type: [String], default: [] },
  lastSeen: { type: Date, default: Date.now },
  xp: { type: Number, default: 0 },
  streak: { type: Number, default: 0 },
  lastCheckin: { type: String, default: '' },
  password: { type: String, select: false }, // legacy
});
UserSchema.index({ phoneNumber: 1 }, { unique: true, partialFilterExpression: { phoneNumber: { $type: 'string', $gt: '' } } });
const User = mongoose.model('User', UserSchema);

const OTP = mongoose.model('OTP', new S({
  phone: String,
  otpHash: String,
  attempts: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now, expires: 600 },
}));

const Group = mongoose.model('Group', new S({
  name: { type: String, required: true, trim: true },
  adminId: { type: ObjId, ref: 'User' },
  members: [{ type: ObjId, ref: 'User' }],
  joinCode: { type: String, unique: true },
  currentShadows: [{ type: ObjId, ref: 'User' }],
  gameActive: { type: Boolean, default: false },
  huntAt: { type: Date, default: null },
}));

const GroupRead = mongoose.model('GroupRead', new S({
  groupId: { type: ObjId, index: true }, userId: { type: ObjId, index: true }, lastReadAt: { type: Date, default: Date.now },
}));

const msgCommon = () => ({
  kind: { type: String, default: 'text' }, // text | image | file | voice | call
  text: { type: String, default: '' },
  image: { type: String, default: '', select: false },
  fileUrl: { type: String, default: '', select: false },
  hasImage: { type: Boolean, default: false },
  hasFile: { type: Boolean, default: false },
  fileName: { type: String, default: '' },
  fileSize: { type: Number, default: 0 },
  duration: { type: Number, default: 0 },
  replyToId: { type: String, default: '' },
  replyToText: { type: String, default: '' },
  replyToSender: { type: String, default: '' },
  reactions: { type: [{ userId: ObjId, emoji: String, _id: false }], default: [] },
  deleted: { type: Boolean, default: false },
  clientId: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
});

const MessageSchema = new S({
  ...msgCommon(),
  groupId: { type: ObjId, ref: 'Group', index: true },
  senderId: { type: ObjId, ref: 'User' },
  senderName: String,
  senderPicV: { type: Number, default: 0 },
  system: { type: Boolean, default: false },
  status: { type: String, default: 'delivered' },
});
MessageSchema.index({ groupId: 1, createdAt: -1 });
const Message = mongoose.model('Message', MessageSchema);

const DMSchema = new S({
  ...msgCommon(),
  senderId: { type: ObjId, ref: 'User', index: true },
  receiverId: { type: ObjId, ref: 'User', index: true },
  status: { type: String, enum: ['sent', 'delivered', 'read'], default: 'sent' },
  callType: { type: String, default: '' }, // voice | video
  callStatus: { type: String, default: '' }, // completed | missed | declined
});
DMSchema.index({ senderId: 1, receiverId: 1, createdAt: -1 });
const DirectMessage = mongoose.model('DirectMessage', DMSchema);

const Post = mongoose.model('Post', new S({
  authorId: { type: ObjId, ref: 'User', index: true },
  authorName: String,
  authorPic: { type: String, select: false }, // legacy (heavy) – never sent anymore
  content: { type: String, default: '' },
  image: { type: String, default: '', select: false },
  hasImage: { type: Boolean, default: false },
  likes: [{ type: ObjId, ref: 'User' }],
  comments: [{ authorId: ObjId, authorName: String, text: String, createdAt: { type: Date, default: Date.now } }],
  createdAt: { type: Date, default: Date.now, index: true },
}));

const Story = mongoose.model('Story', new S({
  authorId: { type: ObjId, ref: 'User', index: true },
  authorName: String,
  authorPic: { type: String, select: false },
  content: { type: String, default: '' },
  image: { type: String, default: '', select: false },
  hasImage: { type: Boolean, default: false },
  views: [{ userId: ObjId, at: { type: Date, default: Date.now }, _id: false }],
  replies: [{ senderName: String, text: String, createdAt: { type: Date, default: Date.now } }],
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(Date.now() + 24 * 60 * 60 * 1000), index: { expireAfterSeconds: 0 } },
}));

const Vote = mongoose.model('Vote', new S({
  groupId: { type: ObjId, index: true }, voterId: ObjId, voterName: String, suspectId: ObjId, suspectName: String,
  createdAt: { type: Date, default: Date.now },
}));

// Flags for old documents that were created before the lightweight-lists upgrade
async function migrate() {
  try {
    await Post.updateMany({ hasImage: { $ne: true }, image: { $nin: ['', null] } }, { $set: { hasImage: true } });
    await Story.updateMany({ hasImage: { $ne: true }, image: { $nin: ['', null] } }, { $set: { hasImage: true } });
    await Message.updateMany({ hasImage: { $ne: true }, image: { $nin: ['', null] } }, { $set: { hasImage: true, kind: 'image' } });
    await DirectMessage.updateMany({ hasImage: { $ne: true }, image: { $nin: ['', null] } }, { $set: { hasImage: true, kind: 'image' } });
    await Message.updateMany({ hasFile: { $ne: true }, fileUrl: { $nin: ['', null] } }, { $set: { hasFile: true, kind: 'file' } });
    await DirectMessage.updateMany({ hasFile: { $ne: true }, fileUrl: { $nin: ['', null] } }, { $set: { hasFile: true, kind: 'file' } });
    console.log('✅ Migration done');
  } catch (e) { console.error('Migration error:', e.message); }
}

// ============================================================================
// HELPERS
// ============================================================================
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((err) => {
  console.error(`${req.method} ${req.originalUrl} ->`, err);
  if (!res.headersSent) res.status(500).json({ error: 'Server error' });
});
const oid = (s) => (mongoose.Types.ObjectId.isValid(s) ? new mongoose.Types.ObjectId(s) : null);
const digits = (s) => String(s || '').replace(/\D/g, '');
const isEmail = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e || '');
const realEmail = (e) => (e && !e.endsWith('@who2.mobile') ? e : '');
const dayStr = (d) => d.toLocaleDateString('en-CA', { timeZone: TZ });

const publicUser = (u) => ({
  id: u._id, _id: u._id, name: u.fullName, fullName: u.fullName, email: realEmail(u.email), phone: u.phoneNumber,
  about: u.about, picV: u.picVersion || 0, xp: u.xp, streak: u.streak,
});

const auth = (req, res, next) => {
  const t = (req.header('Authorization') || '').replace('Bearer ', '');
  if (!t) return res.status(401).json({ error: 'Access denied.' });
  try { req.user = jwt.verify(t, JWT_SECRET); next(); } catch (e) { res.status(401).json({ error: 'Session expired. Please log in again.' }); }
};

// attach author profile-picture version (so the app can build a cached avatar URL – no base64 in lists)
async function attachAuthors(docs, idField = 'authorId', outField = 'authorPicV') {
  const ids = [...new Set(docs.map((d) => String(d[idField])).filter(Boolean))];
  if (!ids.length) return docs;
  const users = await User.find({ _id: { $in: ids } }).select('picVersion');
  const map = new Map(users.map((u) => [String(u._id), u.picVersion || 0]));
  docs.forEach((d) => { d[outField] = map.get(String(d[idField])) || 0; });
  return docs;
}

const shape = (m) => { const o = m.toObject ? m.toObject() : { ...m }; delete o.image; delete o.fileUrl; return o; };
const preview = (m) => {
  if (m.deleted) return '🚫 Message deleted';
  if (m.kind === 'voice') return '🎤 Voice message';
  if (m.kind === 'image' || m.hasImage) return m.text ? `📷 ${m.text}` : '📷 Photo';
  if (m.kind === 'file' || m.hasFile) return `📎 ${m.fileName || 'Document'}`;
  return m.text || '';
};

// ---------- presence ----------
const online = new Map(); // userId -> Set(socketId)
const isOnline = (id) => (online.get(String(id))?.size || 0) > 0;
async function isActive(userId) { // connected AND app in foreground
  const socks = await io.in(String(userId)).fetchSockets();
  return socks.some((s) => s.data.fg !== false);
}

// ---------- push (FCM) ----------
async function pushTo(userId, { title, body, data = {}, call = false }) {
  if (!admin) return;
  try {
    const u = await User.findById(userId).select('fcmTokens');
    const tokens = u?.fcmTokens || [];
    if (!tokens.length) return;
    const strData = {};
    Object.entries(data).forEach(([k, v]) => { strData[k] = String(v ?? ''); });
    const msg = { tokens, data: strData, android: { priority: 'high', ttl: call ? 45000 : 86400000 } };
    if (!call) {
      msg.notification = { title, body };
      msg.android.notification = { channelId: 'messages', sound: 'default' };
      if (data.tag) msg.android.notification.tag = String(data.tag);
    }
    const r = await admin.messaging().sendEachForMulticast(msg);
    const dead = [];
    r.responses.forEach((x, i) => { if (!x.success && /registration-token|not-registered|invalid-argument/.test(x.error?.code || '')) dead.push(tokens[i]); });
    if (dead.length) await User.updateOne({ _id: userId }, { $pull: { fcmTokens: { $in: dead } } });
  } catch (e) { console.error('push error:', e.message); }
}

// ---------- OTP delivery ----------
async function sendWhatsApp(phone, otp) {
  const { WA_PHONE_NUMBER_ID, WA_TOKEN, WA_TEMPLATE, WA_LANG } = process.env;
  if (!WA_PHONE_NUMBER_ID || !WA_TOKEN) throw new Error('WhatsApp not configured');
  const r = await fetch(`https://graph.facebook.com/v21.0/${WA_PHONE_NUMBER_ID}/messages`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${WA_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messaging_product: 'whatsapp', to: phone, type: 'template',
      template: {
        name: WA_TEMPLATE || 'who2_otp', language: { code: WA_LANG || 'en' },
        components: [
          { type: 'body', parameters: [{ type: 'text', text: otp }] },
          { type: 'button', sub_type: 'url', index: '0', parameters: [{ type: 'text', text: otp }] },
        ],
      },
    }),
  });
  if (!r.ok) throw new Error(`WhatsApp API ${r.status}: ${await r.text()}`);
}
async function sendSms(phone, otp) {
  const { TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM } = process.env;
  if (!TWILIO_SID || !TWILIO_TOKEN || !TWILIO_FROM) throw new Error('SMS not configured');
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${TWILIO_SID}/Messages.json`, {
    method: 'POST',
    headers: { Authorization: 'Basic ' + Buffer.from(`${TWILIO_SID}:${TWILIO_TOKEN}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ To: '+' + phone, From: TWILIO_FROM, Body: `${otp} is your WHO2 verification code. Do not share it with anyone.` }),
  });
  if (!r.ok) throw new Error(`Twilio ${r.status}: ${await r.text()}`);
}
let mailer = null;
async function sendEmail(to, otp) {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) throw new Error('Email not configured');
  if (!mailer) mailer = nodemailer.createTransport({ host: SMTP_HOST, port: Number(SMTP_PORT) || 587, secure: Number(SMTP_PORT) === 465, auth: { user: SMTP_USER, pass: SMTP_PASS } });
  await mailer.sendMail({
    from: SMTP_FROM || SMTP_USER, to, subject: `${otp} is your WHO2 verification code`,
    text: `Your WHO2 verification code is ${otp}. It expires in 10 minutes. Never share this code.`,
    html: `<div style="font-family:Arial;padding:24px"><h2 style="color:#7a00cc">WHO2</h2><p>Your verification code is</p><p style="font-size:32px;font-weight:bold;letter-spacing:6px">${otp}</p><p style="color:#666">Expires in 10 minutes. Never share this code.</p></div>`,
  });
}

// ============================================================================
// AUTH
// ============================================================================
const otpLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again in a few minutes.' } });

app.get('/', (req, res) => res.send('WHO2 backend is running'));
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date() }));
app.get('/api/stats', wrap(async (req, res) => res.json({ totalUsers: await User.countDocuments() })));

app.post('/api/auth/request-otp', otpLimiter, wrap(async (req, res) => {
  const phone = digits(req.body.phone);
  if (phone.length < 8 || phone.length > 15) return res.status(400).json({ error: 'Enter a valid mobile number with country code' });
  const channels = (Array.isArray(req.body.channels) && req.body.channels.length ? req.body.channels : ['whatsapp', 'sms']).filter((c) => ['whatsapp', 'sms', 'email'].includes(c));
  if (!channels.length) return res.status(400).json({ error: 'Choose how you want to receive the code' });

  const existing = await User.findOne({ phoneNumber: phone }).select('email');
  let email = String(req.body.email || '').trim().toLowerCase();
  if (!email && existing) email = realEmail(existing.email);
  if (channels.includes('email') && !isEmail(email)) return res.status(400).json({ error: 'Enter a valid email to receive the code by email' });

  const prev = await OTP.findOne({ phone });
  if (prev && Date.now() - prev.createdAt.getTime() < 30000) return res.status(429).json({ error: 'Please wait 30 seconds before requesting another code' });

  const otp = String(crypto.randomInt(100000, 1000000));
  await OTP.findOneAndUpdate({ phone }, { otpHash: await bcrypt.hash(otp, 8), attempts: 0, createdAt: new Date() }, { upsert: true });

  const jobs = { whatsapp: () => sendWhatsApp(phone, otp), sms: () => sendSms(phone, otp), email: () => sendEmail(email, otp) };
  const results = await Promise.allSettled(channels.map((c) => jobs[c]()));
  const sent = [];
  results.forEach((r, i) => { if (r.status === 'fulfilled') sent.push(channels[i]); else console.error(`OTP via ${channels[i]} failed:`, r.reason?.message); });

  const out = { message: 'OTP sent', sent, isNewUser: !existing };
  if (!sent.length) {
    if (!ALLOW_DEV_OTP) return res.status(502).json({ error: 'Could not deliver the code. Please try another method.' });
    out.devOtp = otp;
    console.log(`\n📲 [DEV OTP] ${phone} -> ${otp}\n`);
  }
  res.json(out);
}));

app.post('/api/auth/verify-otp', otpLimiter, wrap(async (req, res) => {
  const phone = digits(req.body.phone);
  const otp = String(req.body.otp || '').trim();
  const rec = await OTP.findOne({ phone });
  if (!rec) return res.status(400).json({ error: 'Code expired. Please request a new one.' });
  if (rec.attempts >= 5) { await rec.deleteOne(); return res.status(429).json({ error: 'Too many wrong attempts. Request a new code.' }); }
  if (!(await bcrypt.compare(otp, rec.otpHash))) { rec.attempts += 1; await rec.save(); return res.status(400).json({ error: 'Incorrect code. Please try again.' }); }

  let user = await User.findOne({ phoneNumber: phone });
  let isNew = false;
  if (!user) {
    const fullName = String(req.body.fullName || '').trim();
    if (fullName.length < 2) return res.status(400).json({ error: 'Full name required for new registration' });
    let email = String(req.body.email || '').trim().toLowerCase();
    if (!isEmail(email) || (await User.exists({ email }))) email = `${phone}@who2.mobile`;
    user = await User.create({ fullName, email, phoneNumber: phone });
    isNew = true;
  }
  await rec.deleteOne();
  const token = jwt.sign({ userId: String(user._id), name: user.fullName }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ token, isNew, user: publicUser(user) });
}));

// ============================================================================
// PROFILE / CONTACTS / PUSH TOKEN / ICE
// ============================================================================
app.get('/api/profile', auth, wrap(async (req, res) => {
  const u = await User.findById(req.user.userId);
  if (!u) return res.status(401).json({ error: 'Account not found' });
  res.json(publicUser(u));
}));
app.put('/api/profile', auth, wrap(async (req, res) => {
  const patch = {};
  if (typeof req.body.fullName === 'string' && req.body.fullName.trim().length >= 2) patch.fullName = req.body.fullName.trim().slice(0, 60);
  if (typeof req.body.about === 'string') patch.about = req.body.about.trim().slice(0, 140);
  if (isEmail(req.body.email) && !(await User.exists({ email: req.body.email.toLowerCase(), _id: { $ne: req.user.userId } }))) patch.email = req.body.email.toLowerCase();
  const u = await User.findByIdAndUpdate(req.user.userId, patch, { new: true });
  res.json(publicUser(u));
}));
app.put('/api/profile/picture', auth, wrap(async (req, res) => {
  const pic = String(req.body.profilePic || '');
  if (pic.length > 6e6) return res.status(413).json({ error: 'Image too large' });
  const u = await User.findByIdAndUpdate(req.user.userId, { profilePic: pic, $inc: { picVersion: 1 } }, { new: true });
  res.json(publicUser(u));
}));
app.post('/api/checkin', auth, wrap(async (req, res) => {
  const u = await User.findById(req.user.userId);
  const today = dayStr(new Date());
  if (u.lastCheckin !== today) {
    u.streak = u.lastCheckin === dayStr(new Date(Date.now() - 864e5)) ? u.streak + 1 : 1;
    u.xp += 10;
    u.lastCheckin = today;
    await u.save();
  }
  res.json(publicUser(u));
}));
app.post('/api/fcm-token', auth, wrap(async (req, res) => {
  const t = String(req.body.token || '');
  if (t) await User.updateOne({ _id: req.user.userId }, { $addToSet: { fcmTokens: t } });
  res.json({ ok: true });
}));
app.delete('/api/fcm-token', auth, wrap(async (req, res) => {
  const t = String(req.body.token || '');
  if (t) await User.updateOne({ _id: req.user.userId }, { $pull: { fcmTokens: t } });
  res.json({ ok: true });
}));
app.get('/api/ice', auth, (req, res) => {
  const iceServers = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
  if (process.env.TURN_URLS) iceServers.push({ urls: process.env.TURN_URLS.split(','), username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL });
  res.json({ iceServers });
});

app.post('/api/contacts/sync', auth, wrap(async (req, res) => {
  const phones = [...new Set((req.body.phones || []).map(digits).filter((p) => p.length >= 8))].slice(0, 6000);
  const emails = [...new Set((req.body.emails || []).map((e) => String(e).toLowerCase()).filter(isEmail))].slice(0, 3000);
  const users = await User.find({ _id: { $ne: req.user.userId }, $or: [{ phoneNumber: { $in: phones } }, { email: { $in: emails } }] }).select('fullName phoneNumber about picVersion').lean();
  res.json(users.map((u) => ({ ...u, picV: u.picVersion || 0 })));
}));
app.get('/api/users/by-phone/:phone', auth, wrap(async (req, res) => {
  const u = await User.findOne({ phoneNumber: digits(req.params.phone), _id: { $ne: req.user.userId } }).select('fullName phoneNumber about picVersion').lean();
  if (!u) return res.status(404).json({ error: 'This number is not on WHO2 yet' });
  res.json({ ...u, picV: u.picVersion || 0 });
}));

app.get('/api/users/:id', auth, wrap(async (req, res) => {
  if (!oid(req.params.id)) return res.status(404).json({ error: 'User not found' });
  const u = await User.findById(req.params.id).select('fullName about picVersion lastSeen phoneNumber xp streak').lean();
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({ _id: u._id, fullName: u.fullName, about: u.about, picV: u.picVersion || 0, lastSeen: u.lastSeen, online: isOnline(u._id), phone: u.phoneNumber, xp: u.xp, streak: u.streak });
}));

// ============================================================================
// MEDIA  (images / files / voice are served on demand – lists stay tiny and fast)
// ============================================================================
const MIME = {
  pdf: 'application/pdf', m4a: 'audio/mp4', aac: 'audio/aac', mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', txt: 'text/plain',
  doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', zip: 'application/zip',
};
function sendB64(res, b64, name, isImage) {
  const raw = b64.includes(',') ? b64.split(',')[1] : b64;
  const buf = Buffer.from(raw, 'base64');
  const ext = String(name || '').split('.').pop().toLowerCase();
  res.set('Content-Type', MIME[ext] || (isImage ? 'image/jpeg' : 'application/octet-stream'));
  res.set('Cache-Control', 'private, max-age=31536000, immutable');
  if (!isImage && name) res.set('Content-Disposition', `inline; filename="${encodeURIComponent(name)}"`);
  res.send(buf);
}
app.get('/api/media/:kind/:id', auth, wrap(async (req, res) => {
  const { kind, id } = req.params;
  const wantFile = req.query.f === 'file';
  if (!oid(id)) return res.sendStatus(404);
  if (kind === 'avatar') {
    const u = await User.findById(id).select('+profilePic');
    if (!u || !u.profilePic) return res.sendStatus(404);
    return sendB64(res, u.profilePic, '', true);
  }
  const model = { post: Post, story: Story, dm: DirectMessage, gmsg: Message }[kind];
  if (!model) return res.sendStatus(404);
  const isChat = kind === 'dm' || kind === 'gmsg';
  const doc = await model.findById(id).select(isChat ? '+image +fileUrl groupId senderId receiverId fileName' : '+image');
  if (!doc) return res.sendStatus(404);
  if (kind === 'dm' && ![String(doc.senderId), String(doc.receiverId)].includes(req.user.userId)) return res.sendStatus(403);
  if (kind === 'gmsg' && !(await Group.exists({ _id: doc.groupId, members: req.user.userId }))) return res.sendStatus(403);
  const data = wantFile ? doc.fileUrl : doc.image;
  if (!data) return res.sendStatus(404);
  sendB64(res, data, doc.fileName, !wantFile);
}));

// ============================================================================
// FEED & STORIES
// ============================================================================
app.get('/api/feed', auth, wrap(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 15, 30);
  const q = {};
  if (req.query.before) { const d = new Date(req.query.before); if (!isNaN(d)) q.createdAt = { $lt: d }; }
  const posts = await Post.find(q).sort({ createdAt: -1 }).limit(limit).select('-authorPic -comments.authorPic').lean();
  await attachAuthors(posts);
  let stories = [];
  if (!req.query.before) {
    stories = await Story.find({ expiresAt: { $gt: new Date() } }).sort({ createdAt: 1 }).select('-authorPic -replies').lean();
    await attachAuthors(stories);
    stories = stories.map((s) => ({ ...s, viewCount: (s.views || []).length, viewedByMe: (s.views || []).some((v) => String(v.userId) === req.user.userId), views: undefined }));
  }
  res.json({ posts, stories, hasMore: posts.length === limit });
}));

const imgOk = (s) => typeof s === 'string' && s.length < 14e6;
app.post('/api/posts', auth, wrap(async (req, res) => {
  const content = String(req.body.content || '').trim().slice(0, 2000);
  const image = imgOk(req.body.image) ? req.body.image : '';
  if (!content && !image) return res.status(400).json({ error: 'Write something or add a photo' });
  const post = await Post.create({ authorId: req.user.userId, authorName: req.user.name, content, image, hasImage: !!image });
  io.emit('feed_updated', {});
  res.status(201).json({ _id: post._id });
}));
app.delete('/api/posts/:id', auth, wrap(async (req, res) => {
  const post = await Post.findById(req.params.id).select('authorId');
  if (!post || String(post.authorId) !== req.user.userId) return res.status(403).json({ error: 'Unauthorized' });
  await post.deleteOne();
  res.json({ success: true });
}));
app.post('/api/posts/:id/like', auth, wrap(async (req, res) => {
  const post = await Post.findById(req.params.id).select('likes authorId');
  if (!post) return res.status(404).json({ error: 'Post not found' });
  const i = post.likes.findIndex((x) => String(x) === req.user.userId);
  if (i === -1) {
    post.likes.push(req.user.userId);
    if (String(post.authorId) !== req.user.userId) pushTo(post.authorId, { title: 'WHO2', body: `${req.user.name} liked your post ❤️`, data: { type: 'post' } });
  } else post.likes.splice(i, 1);
  await post.save();
  res.json({ likes: post.likes.length, liked: i === -1 });
}));
app.post('/api/posts/:id/comment', auth, wrap(async (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 1000);
  if (!text) return res.status(400).json({ error: 'Empty comment' });
  const post = await Post.findById(req.params.id).select('comments authorId');
  if (!post) return res.status(404).json({ error: 'Post not found' });
  post.comments.push({ authorId: req.user.userId, authorName: req.user.name, text });
  await post.save();
  if (String(post.authorId) !== req.user.userId) pushTo(post.authorId, { title: 'WHO2', body: `${req.user.name} commented: ${text.slice(0, 80)}`, data: { type: 'post' } });
  res.json({ ok: true });
}));

app.post('/api/stories', auth, wrap(async (req, res) => {
  const content = String(req.body.content || '').trim().slice(0, 500);
  const image = imgOk(req.body.image) ? req.body.image : '';
  if (!content && !image) return res.status(400).json({ error: 'Write something or add a photo' });
  const s = await Story.create({ authorId: req.user.userId, authorName: req.user.name, content, image, hasImage: !!image });
  io.emit('feed_updated', {});
  res.status(201).json({ _id: s._id });
}));
app.delete('/api/stories/:id', auth, wrap(async (req, res) => {
  const s = await Story.findById(req.params.id).select('authorId');
  if (!s || String(s.authorId) !== req.user.userId) return res.status(403).json({ error: 'Unauthorized' });
  await s.deleteOne();
  io.emit('feed_updated', {});
  res.json({ success: true });
}));
app.post('/api/stories/:id/view', auth, wrap(async (req, res) => {
  await Story.updateOne({ _id: req.params.id, authorId: { $ne: req.user.userId }, 'views.userId': { $ne: req.user.userId } }, { $push: { views: { userId: req.user.userId, at: new Date() } } });
  res.json({ ok: true });
}));
app.get('/api/stories/:id/viewers', auth, wrap(async (req, res) => {
  const s = await Story.findById(req.params.id).select('authorId views').lean();
  if (!s || String(s.authorId) !== req.user.userId) return res.status(403).json({ error: 'Unauthorized' });
  const users = await User.find({ _id: { $in: s.views.map((v) => v.userId) } }).select('fullName picVersion').lean();
  const map = new Map(users.map((u) => [String(u._id), u]));
  res.json(s.views.map((v) => ({ _id: v.userId, fullName: map.get(String(v.userId))?.fullName || 'User', picV: map.get(String(v.userId))?.picVersion || 0, at: v.at })).reverse());
}));
app.post('/api/stories/:id/reply', auth, wrap(async (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 1000);
  const story = await Story.findById(req.params.id).select('authorId replies');
  if (!story || !text) return res.status(400).json({ error: 'Cannot reply' });
  story.replies.push({ senderName: req.user.name, text });
  await story.save();
  await createDm({ userId: req.user.userId, name: req.user.name }, String(story.authorId), { text: `↩️ Replied to your story: ${text}` });
  res.json({ ok: true });
}));

// ============================================================================
// DIRECT CHATS
// ============================================================================
function bodyFrom(d) {
  const image = typeof d.image === 'string' ? d.image : '';
  const fileUrl = typeof d.fileData === 'string' ? d.fileData : '';
  if (image.length > 14e6 || fileUrl.length > 14e6) throw new Error('Attachment too large');
  let kind = ['text', 'image', 'file', 'voice'].includes(d.kind) ? d.kind : (image ? 'image' : fileUrl ? 'file' : 'text');
  const text = String(d.text || '').slice(0, 4000);
  if (!text && !image && !fileUrl) throw new Error('Empty message');
  return {
    kind, text, image, fileUrl, hasImage: !!image, hasFile: !!fileUrl,
    fileName: String(d.fileName || '').slice(0, 200), fileSize: Number(d.fileSize) || 0, duration: Number(d.duration) || 0,
    replyToId: String(d.replyToId || ''), replyToText: String(d.replyToText || '').slice(0, 300), replyToSender: String(d.replyToSender || '').slice(0, 80),
    clientId: String(d.clientId || ''),
  };
}

async function createDm(from, toId, d) {
  const body = bodyFrom(d);
  const msg = await DirectMessage.create({ ...body, senderId: from.userId, receiverId: toId, status: isOnline(toId) ? 'delivered' : 'sent' });
  const out = shape(msg);
  io.to(String(toId)).emit('receive_dm', out);
  io.to(String(from.userId)).emit('receive_dm', out);
  if (!(await isActive(toId))) pushTo(toId, { title: from.name, body: preview(out), data: { type: 'dm', chatId: from.userId, title: from.name, tag: `dm_${from.userId}` } });
  return out;
}

app.get('/api/chats', auth, wrap(async (req, res) => {
  const me = oid(req.user.userId);
  const rows = await DirectMessage.aggregate([
    { $match: { $or: [{ senderId: me }, { receiverId: me }] } },
    { $project: { image: 0, fileUrl: 0 } },
    { $sort: { createdAt: -1 } },
    { $group: {
      _id: { $cond: [{ $eq: ['$senderId', me] }, '$receiverId', '$senderId'] },
      last: { $first: '$$ROOT' },
      unread: { $sum: { $cond: [{ $and: [{ $eq: ['$receiverId', me] }, { $ne: ['$status', 'read'] }, { $ne: ['$kind', 'call'] }] }, 1, 0] } },
    } },
    { $sort: { 'last.createdAt': -1 } },
    { $limit: 100 },
  ]);
  const users = await User.find({ _id: { $in: rows.map((r) => r._id) } }).select('fullName about picVersion lastSeen').lean();
  const map = new Map(users.map((u) => [String(u._id), u]));
  // mark everything addressed to me as delivered
  const pending = await DirectMessage.find({ receiverId: me, status: 'sent' }).distinct('senderId');
  if (pending.length) {
    await DirectMessage.updateMany({ receiverId: me, status: 'sent' }, { $set: { status: 'delivered' } });
    pending.forEach((s) => io.to(String(s)).emit('dm_delivered', { receiverId: req.user.userId }));
  }
  res.json(rows.filter((r) => map.has(String(r._id))).map((r) => {
    const u = map.get(String(r._id));
    return { _id: r._id, fullName: u.fullName, about: u.about, picV: u.picVersion || 0, lastSeen: u.lastSeen,
      unreadCount: r.unread, last: { text: preview(r.last), createdAt: r.last.createdAt, mine: String(r.last.senderId) === req.user.userId, status: r.last.status, kind: r.last.kind } };
  }));
}));

app.get('/api/messages/direct/:userId', auth, wrap(async (req, res) => {
  const me = req.user.userId, other = req.params.userId;
  if (!oid(other)) return res.json([]);
  const q = { $or: [{ senderId: me, receiverId: other }, { senderId: other, receiverId: me }] };
  if (req.query.before) { const d = new Date(req.query.before); if (!isNaN(d)) q.createdAt = { $lt: d }; }
  const msgs = await DirectMessage.find(q).sort({ createdAt: -1 }).limit(Math.min(parseInt(req.query.limit, 10) || 40, 100)).lean();
  const r = await DirectMessage.updateMany({ senderId: other, receiverId: me, status: { $ne: 'read' } }, { $set: { status: 'read' } });
  if (r.modifiedCount) io.to(other).emit('dm_read_receipt', { readerId: me });
  res.json(msgs);
}));

app.get('/api/calls', auth, wrap(async (req, res) => {
  const me = req.user.userId;
  const calls = await DirectMessage.find({ kind: 'call', $or: [{ senderId: me }, { receiverId: me }] }).sort({ createdAt: -1 }).limit(60).lean();
  const peerIds = [...new Set(calls.map((c) => String(String(c.senderId) === me ? c.receiverId : c.senderId)))];
  const users = await User.find({ _id: { $in: peerIds } }).select('fullName picVersion').lean();
  const map = new Map(users.map((u) => [String(u._id), u]));
  res.json(calls.map((c) => {
    const out = String(c.senderId) === me; const pid = String(out ? c.receiverId : c.senderId);
    return { _id: c._id, peerId: pid, peerName: map.get(pid)?.fullName || 'User', peerPicV: map.get(pid)?.picVersion || 0, outgoing: out, callType: c.callType, status: c.callStatus, duration: c.duration, createdAt: c.createdAt };
  }));
}));

// ============================================================================
// GROUPS (Secret Squads)
// ============================================================================
app.get('/api/groups', auth, wrap(async (req, res) => {
  const me = req.user.userId;
  const gs = await Group.find({ members: me }).select('name joinCode members adminId').lean();
  const out = await Promise.all(gs.map(async (g) => {
    const rd = await GroupRead.findOne({ groupId: g._id, userId: me }).lean();
    const [unread, last] = await Promise.all([
      Message.countDocuments({ groupId: g._id, createdAt: { $gt: rd?.lastReadAt || new Date(0) }, senderId: { $ne: me } }),
      Message.findOne({ groupId: g._id }).sort({ createdAt: -1 }).select('text kind hasImage hasFile fileName senderName createdAt deleted').lean(),
    ]);
    return { _id: g._id, name: g.name, joinCode: g.joinCode, adminId: g.adminId, memberCount: g.members.length, unreadCount: unread,
      last: last ? { text: `${last.senderName ? last.senderName + ': ' : ''}${preview(last)}`, createdAt: last.createdAt } : null };
  }));
  out.sort((a, b) => new Date(b.last?.createdAt || 0) - new Date(a.last?.createdAt || 0));
  res.json(out);
}));
app.get('/api/groups/:id', auth, wrap(async (req, res) => {
  const g = await Group.findOne({ _id: req.params.id, members: req.user.userId }).populate('members', 'fullName about picVersion').lean();
  if (!g) return res.status(404).json({ error: 'Group not found' });
  res.json({ ...g, members: g.members.map((m) => ({ ...m, picV: m.picVersion || 0 })) });
}));
app.post('/api/groups/create', auth, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 40);
  if (name.length < 2) return res.status(400).json({ error: 'Squad name is too short' });
  let group;
  for (let i = 0; i < 5 && !group; i++) {
    try { group = await Group.create({ name, adminId: req.user.userId, members: [req.user.userId], joinCode: crypto.randomBytes(3).toString('hex').toUpperCase() }); } catch (e) { if (e.code !== 11000) throw e; }
  }
  io.in(req.user.userId).socketsJoin(String(group._id));
  res.status(201).json(group);
}));
app.post('/api/groups/join', auth, wrap(async (req, res) => {
  const group = await Group.findOne({ joinCode: String(req.body.joinCode || '').trim().toUpperCase() });
  if (!group) return res.status(404).json({ error: 'Invalid invite code' });
  if (!group.members.some((m) => String(m) === req.user.userId)) {
    group.members.push(req.user.userId);
    await group.save();
    await systemMsg(group._id, `👋 ${req.user.name} joined the squad`);
  }
  io.in(req.user.userId).socketsJoin(String(group._id));
  res.json(group);
}));
app.post('/api/groups/:id/leave', auth, wrap(async (req, res) => {
  const g = await Group.findOne({ _id: req.params.id, members: req.user.userId });
  if (!g) return res.status(404).json({ error: 'Group not found' });
  g.members = g.members.filter((m) => String(m) !== req.user.userId);
  if (!g.members.length) await g.deleteOne();
  else { if (String(g.adminId) === req.user.userId) g.adminId = g.members[0]; await g.save(); await systemMsg(g._id, `🚪 ${req.user.name} left the squad`); }
  io.in(req.user.userId).socketsLeave(String(g._id));
  res.json({ ok: true });
}));
app.post('/api/groups/:id/read', auth, wrap(async (req, res) => {
  await GroupRead.findOneAndUpdate({ groupId: req.params.id, userId: req.user.userId }, { lastReadAt: new Date() }, { upsert: true });
  res.json({ ok: true });
}));
app.get('/api/groups/:id/messages', auth, wrap(async (req, res) => {
  if (!(await Group.exists({ _id: req.params.id, members: req.user.userId }))) return res.status(403).json({ error: 'Not a member' });
  const q = { groupId: req.params.id };
  if (req.query.before) { const d = new Date(req.query.before); if (!isNaN(d)) q.createdAt = { $lt: d }; }
  const msgs = await Message.find(q).sort({ createdAt: -1 }).limit(Math.min(parseInt(req.query.limit, 10) || 40, 100)).lean();
  await GroupRead.findOneAndUpdate({ groupId: req.params.id, userId: req.user.userId }, { lastReadAt: new Date() }, { upsert: true });
  res.json(msgs);
}));

async function systemMsg(groupId, text) {
  const m = await Message.create({ groupId, senderName: 'WHO2', text, system: true, status: 'delivered' });
  io.to(String(groupId)).emit('receive_group_message', shape(m));
}

// ============================================================================
// SOCKET.IO  (JWT-authenticated)
// ============================================================================
const activeCalls = new Map(); // callId -> { from, to, fromName, type, startedAt, answeredAt, timer }

io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth?.token || '', JWT_SECRET); socket.data.fg = true; next(); }
  catch (e) { next(new Error('unauthorized')); }
});

io.on('connection', async (socket) => {
  const me = socket.user.userId;
  socket.join(me);
  if (!online.has(me)) online.set(me, new Set());
  online.get(me).add(socket.id);
  io.to('p:' + me).emit('presence', { userId: me, online: true });
  try {
    const gs = await Group.find({ members: me }).select('_id');
    gs.forEach((g) => socket.join(String(g._id)));
  } catch (e) {}
  // replay a call that is still ringing for this user
  for (const [callId, c] of activeCalls) if (c.to === me && !c.answeredAt) socket.emit('incoming_call', { callId, from: c.from, name: c.fromName, picV: c.picV, callType: c.type });

  socket.on('app_state', (d) => { socket.data.fg = !!(d && d.fg); });

  // ---- chat ----
  socket.on('send_dm', async (d) => {
    try {
      if (!oid(d.receiverId)) return;
      await createDm({ userId: me, name: socket.user.name }, String(d.receiverId), d);
    } catch (e) { console.error('send_dm:', e.message); socket.emit('send_failed', { clientId: d && d.clientId, error: e.message }); }
  });

  socket.on('send_group_message', async (d) => {
    try {
      const g = await Group.findOne({ _id: d.groupId, members: me }).select('name members');
      if (!g) throw new Error('Not a member');
      const u = await User.findById(me).select('picVersion');
      const msg = await Message.create({ ...bodyFrom(d), groupId: g._id, senderId: me, senderName: socket.user.name, senderPicV: u?.picVersion || 0, status: 'delivered' });
      const out = shape(msg);
      out.groupName = g.name;
      io.to(String(g._id)).emit('receive_group_message', out);
      for (const m of g.members) {
        if (String(m) === me) continue;
        if (!(await isActive(m))) pushTo(m, { title: g.name, body: `${socket.user.name}: ${preview(out)}`, data: { type: 'group', chatId: g._id, title: g.name, tag: `g_${g._id}` } });
      }
    } catch (e) { console.error('send_group_message:', e.message); socket.emit('send_failed', { clientId: d && d.clientId, error: e.message }); }
  });

  socket.on('mark_dm_read', async (d) => {
    try {
      const other = String((d && d.senderId) || '');
      if (!oid(other)) return;
      const r = await DirectMessage.updateMany({ senderId: other, receiverId: me, status: { $ne: 'read' } }, { $set: { status: 'read' } });
      if (r.modifiedCount) io.to(other).emit('dm_read_receipt', { readerId: me });
    } catch (e) {}
  });

  socket.on('typing', (d) => {
    if (!d) return;
    if (d.groupId) socket.to(String(d.groupId)).emit('typing', { chatId: String(d.groupId), userId: me, name: socket.user.name, isTyping: !!d.isTyping });
    else if (oid(d.to)) io.to(String(d.to)).emit('typing', { chatId: me, userId: me, name: socket.user.name, isTyping: !!d.isTyping });
  });

  socket.on('presence_watch', async (d) => {
    const id = String((d && d.userId) || '');
    if (!oid(id)) return;
    socket.join('p:' + id);
    const u = await User.findById(id).select('lastSeen');
    socket.emit('presence', { userId: id, online: isOnline(id), lastSeen: u && u.lastSeen });
  });
  socket.on('presence_unwatch', (d) => { if (d && d.userId) socket.leave('p:' + d.userId); });

  socket.on('react_message', async (d) => {
    try {
      const group = d.kind === 'group';
      const m = await (group ? Message : DirectMessage).findById(d.id).select('senderId receiverId groupId reactions deleted');
      if (!m || m.deleted) return;
      const rooms = group ? [String(m.groupId)] : [String(m.senderId), String(m.receiverId)];
      if (group ? !(await Group.exists({ _id: m.groupId, members: me })) : !rooms.includes(me)) return;
      const i = m.reactions.findIndex((r) => String(r.userId) === me);
      const emoji = String(d.emoji || '').slice(0, 8);
      if (i >= 0 && m.reactions[i].emoji === emoji) m.reactions.splice(i, 1);
      else if (i >= 0) m.reactions[i].emoji = emoji;
      else m.reactions.push({ userId: me, emoji });
      await m.save();
      const payload = { kind: d.kind, id: String(m._id), reactions: m.reactions.map((r) => ({ userId: String(r.userId), emoji: r.emoji })) };
      rooms.forEach((r) => io.to(r).emit('message_updated', payload));
    } catch (e) { console.error('react:', e.message); }
  });

  socket.on('delete_message', async (d) => {
    try {
      const group = d.kind === 'group';
      const m = await (group ? Message : DirectMessage).findById(d.id).select('senderId receiverId groupId');
      if (!m || String(m.senderId) !== me) return;
      await (group ? Message : DirectMessage).updateOne({ _id: m._id }, { $set: { deleted: true, text: '', image: '', fileUrl: '', hasImage: false, hasFile: false, reactions: [] } });
      const rooms = group ? [String(m.groupId)] : [String(m.senderId), String(m.receiverId)];
      rooms.forEach((r) => io.to(r).emit('message_updated', { kind: d.kind, id: String(m._id), deleted: true, reactions: [] }));
    } catch (e) { console.error('delete:', e.message); }
  });

  // ---- game ----
  socket.on('cast_vote', async (d) => {
    try {
      const g = await Group.findOne({ _id: d.groupId, members: me });
      if (!g) return;
      const say = (message) => socket.emit('vote_registered', { message });
      if (!g.gameActive) return say('No active hunt right now. Wait for 6:00 AM!');
      if (String(d.suspectId) === me) return say('You cannot vote for yourself 😉');
      if (!g.members.some((m) => String(m) === String(d.suspectId))) return say('That person is not in this squad.');
      const mine = await Vote.find({ groupId: g._id, voterId: me, createdAt: { $gte: g.huntAt || new Date(0) } });
      if (mine.length >= 2) return say('You already used both votes for today.');
      if (mine.some((v) => String(v.suspectId) === String(d.suspectId))) return say('You already voted for this person.');
      const suspect = await User.findById(d.suspectId).select('fullName');
      await Vote.create({ groupId: g._id, voterId: me, voterName: socket.user.name, suspectId: d.suspectId, suspectName: suspect ? suspect.fullName : '' });
      io.to(String(g._id)).emit('vote_registered', { message: `${socket.user.name} locked in their vote.` });
    } catch (e) { console.error('vote:', e.message); }
  });

  // ---- calls (WebRTC signalling) ----
  socket.on('call_invite', async (d) => {
    try {
      const to = String(d.to || '');
      if (!oid(to) || to === me || !d.callId) return;
      const busy = [...activeCalls.values()].some((c) => c.from === to || c.to === to || c.from === me || c.to === me);
      if (busy) return socket.emit('call_busy', { callId: d.callId });
      const u = await User.findById(me).select('picVersion');
      const c = { from: me, to, fromName: socket.user.name, picV: u?.picVersion || 0, type: d.callType === 'video' ? 'video' : 'voice', startedAt: Date.now(), answeredAt: 0, timer: null };
      c.timer = setTimeout(() => endCall(d.callId, 'missed'), 45000);
      activeCalls.set(d.callId, c);
      io.to(to).emit('incoming_call', { callId: d.callId, from: me, name: c.fromName, picV: c.picV, callType: c.type });
      if (!(await isActive(to))) pushTo(to, { call: true, data: { type: 'call', callId: d.callId, from: me, name: c.fromName, callType: c.type } });
    } catch (e) { console.error('call_invite:', e.message); }
  });
  socket.on('call_accept', (d) => {
    const c = activeCalls.get(d.callId);
    if (!c || c.to !== me) return;
    c.answeredAt = Date.now(); clearTimeout(c.timer);
    io.to(c.from).emit('call_accepted', { callId: d.callId });
  });
  socket.on('call_reject', (d) => endCall(d.callId, 'declined', me));
  socket.on('call_end', (d) => endCall(d.callId, null, me));
  const relay = (ev) => socket.on(ev, (d) => {
    const c = activeCalls.get(d.callId);
    if (!c || (c.from !== me && c.to !== me)) return;
    io.to(c.from === me ? c.to : c.from).emit(ev, { callId: d.callId, sdp: d.sdp, candidate: d.candidate });
  });
  ['call_offer', 'call_answer', 'call_ice'].forEach(relay);

  socket.on('disconnect', async () => {
    const set = online.get(me);
    if (set) { set.delete(socket.id); if (!set.size) online.delete(me); }
    if (!isOnline(me)) {
      const now = new Date();
      await User.updateOne({ _id: me }, { lastSeen: now }).catch(() => {});
      io.to('p:' + me).emit('presence', { userId: me, online: false, lastSeen: now });
    }
  });
});

async function endCall(callId, forced, by) {
  const c = activeCalls.get(callId);
  if (!c) return;
  clearTimeout(c.timer);
  activeCalls.delete(callId);
  let status = forced;
  if (!status) status = c.answeredAt ? 'completed' : (by === c.from ? 'cancelled' : 'declined');
  const duration = c.answeredAt ? Math.round((Date.now() - c.answeredAt) / 1000) : 0;
  [c.from, c.to].forEach((u) => { if (u !== by) io.to(u).emit('call_ended', { callId, reason: status }); });
  if (by) io.to(by).emit('call_ended', { callId, reason: status, self: true });
  try {
    const dbStatus = status === 'cancelled' ? 'missed' : status;
    const m = await DirectMessage.create({ senderId: c.from, receiverId: c.to, kind: 'call', callType: c.type, callStatus: dbStatus, duration, status: 'delivered' });
    const out = shape(m);
    io.to(c.from).emit('receive_dm', out); io.to(c.to).emit('receive_dm', out);
    if (dbStatus === 'missed') pushTo(c.to, { title: 'Missed call', body: `${c.fromName} called you`, data: { type: 'dm', chatId: c.from, title: c.fromName, tag: `dm_${c.from}` } });
  } catch (e) { console.error('call log:', e.message); }
}

// ============================================================================
// DAILY SHADOW HUNT  (6:00 AM in APP_TZ – default Asia/Kolkata)
// ============================================================================
async function runHunt() {
  const groups = await Group.find({ 'members.3': { $exists: true } }); // squads with 4+ members
  for (const g of groups) {
    try {
      if (g.gameActive && g.currentShadows.length) {
        const votes = await Vote.find({ groupId: g._id, createdAt: { $gte: g.huntAt || new Date(0) } });
        const shadowIds = g.currentShadows.map(String);
        const winners = [...new Set(votes.filter((v) => shadowIds.includes(String(v.suspectId))).map((v) => String(v.voterId)))];
        if (winners.length) await User.updateMany({ _id: { $in: winners } }, { $inc: { xp: 50 } });
        const names = await User.find({ _id: { $in: g.currentShadows } }).select('fullName');
        await systemMsg(g._id, `🕵️ Yesterday's Shadows were ${names.map((n) => n.fullName).join(' & ')}. ${winners.length} detective(s) caught one and earned +50 XP!`);
      }
      g.currentShadows = [...g.members].sort(() => Math.random() - 0.5).slice(0, 2);
      g.gameActive = true;
      g.huntAt = new Date();
      await g.save();
      await systemMsg(g._id, '🌑 The Daily Shadow Hunt has begun! 2 Shadows are hiding among you. Chat, observe and cast your votes.');
      for (const m of g.members) pushTo(m, { title: g.name, body: '🌑 The Shadow Hunt has begun! Find the 2 Shadows.', data: { type: 'group', chatId: g._id, title: g.name, tag: `hunt_${g._id}` } });
    } catch (e) { console.error('hunt error:', e.message); }
  }
}
cron.schedule('0 6 * * *', () => runHunt().catch((e) => console.error(e)), { timezone: TZ });

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`✅ WHO2 backend v3 running on port ${PORT} (TZ ${TZ})`));
