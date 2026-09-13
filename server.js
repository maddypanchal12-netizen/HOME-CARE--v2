import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { scryptSync, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, 'data');
const storePath = path.join(dataDir, 'store.json');
fs.mkdirSync(dataDir, { recursive: true });
const port = Number(process.env.API_PORT || 8787);
const app = express();
const clients = new Map();
const db = new Database(path.join(dataDir, 'homecare.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, role TEXT NOT NULL, password TEXT NOT NULL, created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS payments (id TEXT PRIMARY KEY, booking_id TEXT NOT NULL, provider TEXT NOT NULL, status TEXT NOT NULL, amount INTEGER NOT NULL, created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, booking_id TEXT UNIQUE NOT NULL, rating INTEGER NOT NULL, comment TEXT NOT NULL, created_at TEXT NOT NULL);
`);
function hashPassword(password) { const salt = randomUUID(); return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`; }
function passwordMatches(password, stored) { if (!stored?.includes(':')) return password === stored; const [salt, digest] = stored.split(':'); const candidate = scryptSync(password, salt, 64); return timingSafeEqual(candidate, Buffer.from(digest, 'hex')); }

function authUser(req) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  if (!token) return null;
  return db.prepare('SELECT users.id, users.name, users.email, users.role FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token = ? AND sessions.expires_at > ?').get(token, new Date().toISOString()) || null;
}
function requireAuth(req, res, next) {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  req.user = user;
  next();
}
function requireRole(...roles) { return (req, res, next) => { if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient role permissions' }); next(); }; }
function notify(userId, title, body) {
  const item = { id: randomUUID(), userId, title, body, createdAt: new Date().toISOString() };
  db.prepare('INSERT INTO notifications (id,user_id,title,body,created_at) VALUES (?,?,?,?,?)').run(item.id, userId, title, body, item.createdAt);
  publish('notification.created', item);
}

const seed = {
  bookings: [],
  professionals: []
};

function ensureStore() {
  fs.mkdirSync(dataDir, { recursive: true });
  if (!fs.existsSync(storePath)) fs.writeFileSync(storePath, JSON.stringify(seed, null, 2));
}
function readStore() {
  ensureStore();
  const store = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  return store;
}
function writeStore(store) { fs.writeFileSync(storePath, JSON.stringify(store, null, 2)); }
function scopedBookings(store, user) {
  if (user.role === 'admin') return store.bookings;
  if (user.role === 'professional') return store.bookings.filter(booking => booking.professionalId === user.id);
  return store.bookings.filter(booking => booking.customerId === user.id);
}
function publish(type, payload) {
  const message = `data: ${JSON.stringify({ type, payload, at: new Date().toISOString() })}\n\n`;
  clients.forEach((user, client) => {
    const visible = user.role === 'admin' || payload?.userId === user.id || payload?.customerId === user.id || payload?.professionalId === user.id;
    if (visible) client.write(message);
  });
}
function mutate(type, update) {
  const store = readStore();
  const result = update(store);
  writeStore(store);
  publish(type, result);
  return result;
}

const transitions = {
  Pending: ['Confirmed', 'Cancelled'],
  Confirmed: ['Professional Assigned', 'Cancelled'],
  'Professional Assigned': ['On the Way', 'Cancelled'],
  'On the Way': ['Service Started', 'Cancelled'],
  'Service Started': ['Completed'],
  Completed: []
};

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'dist')));

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Email and password are required' });
  const storedUser = db.prepare('SELECT id,name,email,role,password FROM users WHERE lower(email) = lower(?)').get(email.trim());
  const user = storedUser && passwordMatches(password, storedUser.password) ? storedUser : null;
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  if (!storedUser.password.includes(':')) db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashPassword(password), storedUser.id);
  const token = randomUUID();
  db.prepare('INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)').run(token, user.id, new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString());
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});
app.post('/api/auth/signup', (req, res) => {
  const { name, email, password, role = 'customer' } = req.body || {};
  if (!name?.trim() || !email?.trim() || typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Name, email, and a password of at least 8 characters are required' });
  if (!['customer', 'professional'].includes(role)) return res.status(400).json({ error: 'Choose customer or professional account' });
  const user = { id: `${role}-${randomUUID()}`, name: name.trim(), email: email.trim().toLowerCase(), role, password: hashPassword(password), createdAt: new Date().toISOString() };
  try { db.prepare('INSERT INTO users (id,name,email,role,password,created_at) VALUES (?,?,?,?,?,?)').run(user.id, user.name, user.email, user.role, user.password, user.createdAt); } catch { return res.status(409).json({ error: 'An account with this email already exists' }); }
  if (user.role === 'professional') {
    const store = readStore();
    store.professionals.push({ id: user.id, name: user.name, role: 'HomeCare Professional', verification: 'Pending Review', certification: 'Not yet certified', rating: 0 });
    writeStore(store);
  }
  const token = randomUUID();
  db.prepare('INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)').run(token, user.id, new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString());
  res.status(201).json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});
app.post('/api/auth/logout', requireAuth, (req, res) => { db.prepare('DELETE FROM sessions WHERE token = ?').run(req.headers.authorization.replace('Bearer ', '')); res.status(204).end(); });
app.get('/api/auth/me', requireAuth, (req, res) => res.json(req.user));
app.get('/api/availability', (_req, res) => {
  const today = new Date();
  const slots = Array.from({ length: 7 }, (_, offset) => { const date = new Date(today); date.setDate(today.getDate() + offset + 1); return { date: date.toISOString().slice(0, 10), slots: ['09:00 AM', '10:00 AM', '12:30 PM', '03:00 PM'].filter((_, index) => (date.getDate() + index) % 5 !== 0) }; });
  res.json({ generatedAt: new Date().toISOString(), slots });
});
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'homecare-api', now: new Date().toISOString() }));
app.get('/api/bootstrap', requireAuth, (req, res) => {
  const store = readStore();
  const bookings = scopedBookings(store, req.user);
  res.json({
    now: new Date().toISOString(), bookings, professionals: store.professionals,
    stats: { customers: req.user.role === 'admin' ? 2840 : undefined, verifiedProfessionals: store.professionals.filter(item => item.verification === 'Approved').length, activeBookings: bookings.filter(item => !['Completed', 'Cancelled'].includes(item.status)).length, revenue: bookings.reduce((sum, item) => sum + item.amount, 0) }
  });
});
app.get('/api/bookings', requireAuth, (req, res) => res.json(scopedBookings(readStore(), req.user)));
app.post('/api/bookings', requireAuth, (req, res) => {
  if (req.user.role !== 'customer') return res.status(403).json({ error: 'Only customer accounts can create bookings' });
  const { professionalId = null, professional = 'To be assigned', service = 'Deep home cleaning', date, time, address, amount = 1259 } = req.body || {};
  if (!date || !time || !address) return res.status(400).json({ error: 'date, time, and address are required' });
  const booking = { id: `HC-${Date.now().toString().slice(-8)}`, customerId: req.user.id, professionalId, customer: req.user.name, professional, service, date, time, address, amount, status: 'Pending', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  if (Number.isNaN(Date.parse(`${date}T00:00:00`)) || new Date(`${date}T00:00:00`) < new Date(new Date().toDateString())) return res.status(400).json({ error: 'Booking date must be today or later' });
  const created = mutate('booking.created', store => { store.bookings.unshift(booking); return booking; });
  notify(req.user.id, 'Booking received', `${service} is waiting for professional confirmation.`);
  res.status(201).json(created);
});
app.patch('/api/bookings/:id/status', requireAuth, (req, res) => {
  const { status } = req.body || {};
  const updated = mutate('booking.updated', store => {
    const booking = store.bookings.find(item => item.id === req.params.id);
    if (!booking) throw Object.assign(new Error('Booking not found'), { statusCode: 404 });
    if (req.user.role !== 'admin' && booking.professionalId !== req.user.id) throw Object.assign(new Error('You cannot update this booking'), { statusCode: 403 });
    if (!transitions[booking.status]?.includes(status)) throw Object.assign(new Error(`Cannot move booking from ${booking.status} to ${status}`), { statusCode: 409 });
    booking.status = status;
    booking.updatedAt = new Date().toISOString();
    notify(status === 'Completed' ? booking.customerId : booking.professionalId, `Booking ${status.toLowerCase()}`, `${booking.service} · ${booking.date} · ${booking.time}`);
    return booking;
  });
  res.json(updated);
});
app.post('/api/bookings/:id/payment-intent', requireAuth, (req, res) => {
  const booking = readStore().bookings.find(item => item.id === req.params.id);
  if (!booking) return res.status(404).json({ error: 'Booking not found' });
  if (req.user.role !== 'admin' && booking.customerId !== req.user.id && booking.professionalId !== req.user.id) return res.status(403).json({ error: 'You cannot access this booking' });
  const payment = { id: `pay_${randomUUID().slice(0, 12)}`, bookingId: booking.id, provider: 'adapter_pending', status: 'requires_provider', amount: booking.amount, createdAt: new Date().toISOString() };
  db.prepare('INSERT INTO payments (id,booking_id,provider,status,amount,created_at) VALUES (?,?,?,?,?,?)').run(payment.id, payment.bookingId, payment.provider, payment.status, payment.amount, payment.createdAt);
  res.status(202).json({ ...payment, message: 'Payment provider adapter is ready; connect Razorpay or Stripe credentials to capture funds.' });
});
app.get('/api/notifications', requireAuth, (req, res) => res.json(db.prepare('SELECT id,title,body,read,created_at AS createdAt FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(req.user.id)));
app.patch('/api/notifications/:id/read', requireAuth, (req, res) => { const result = db.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id); res.json({ ok: result.changes === 1 }); });
app.post('/api/bookings/:id/reviews', requireAuth, (req, res) => {
  const { rating, comment = '' } = req.body || {};
  const booking = readStore().bookings.find(item => item.id === req.params.id);
  if (!booking || booking.status !== 'Completed') return res.status(409).json({ error: 'Only completed bookings can be reviewed' });
  if (!Number.isInteger(rating) || rating < 1 || rating > 5 || !comment.trim()) return res.status(400).json({ error: 'Rating from 1-5 and a comment are required' });
  const review = { id: randomUUID(), bookingId: booking.id, rating, comment: comment.trim(), createdAt: new Date().toISOString() };
  try { db.prepare('INSERT INTO reviews (id,booking_id,rating,comment,created_at) VALUES (?,?,?,?,?)').run(review.id, review.bookingId, review.rating, review.comment, review.createdAt); } catch { return res.status(409).json({ error: 'This booking already has a review' }); }
  publish('review.created', review);
  res.status(201).json(review);
});
app.get('/api/professionals', (_req, res) => res.json(readStore().professionals));
app.patch('/api/professionals/:id/verification', requireAuth, requireRole('admin'), (req, res) => {
  const { status } = req.body || {};
  if (!['Approved', 'Rejected', 'In Review'].includes(status)) return res.status(400).json({ error: 'Invalid verification status' });
  try {
    const updated = mutate('professional.verification.updated', store => {
      const professional = store.professionals.find(item => item.id === req.params.id);
      if (!professional) throw Object.assign(new Error('Professional not found'), { statusCode: 404 });
      professional.verification = status;
      professional.updatedAt = new Date().toISOString();
      notify(professional.id, `Verification ${status.toLowerCase()}`, 'Your profile verification record was updated by the admin team.');
      return professional;
    });
    res.json(updated);
  } catch (error) { res.status(error.statusCode || 500).json({ error: error.message }); }
});
app.get('/api/events', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).end();
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  res.write(`data: ${JSON.stringify({ type: 'connected', at: new Date().toISOString() })}\n\n`);
  clients.set(res, user);
  req.on('close', () => clients.delete(res));
});

app.use((error, _req, res, _next) => res.status(error.statusCode || 500).json({ error: error.message || 'Unexpected server error' }));
app.get(/^(?!\/api).*/, (_req, res) => res.sendFile(path.join(__dirname, 'dist', 'index.html')));
ensureStore();
app.listen(port, () => console.log(`HomeCare+ API listening on http://localhost:${port}`));
