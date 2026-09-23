const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Photo arrays: up to 10 images, stored as data URLs (already resized/compressed client-side).
// Used for both the business's own photo gallery and its menu photos.
function sanitizePhotoArray(arr){
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, 10).map(u => String(u || '').slice(0, 400000)).filter(Boolean);
}

// About tab attributes — all optional, Google-Maps-style info chips.
const ABOUT_FIELDS = ['accessibility', 'serviceOptions', 'popularFor', 'offerings', 'diningOptions', 'atmosphere', 'crowd', 'payments', 'children', 'parking'];
function sanitizeAbout(obj){
  const clean = {};
  if (obj && typeof obj === 'object'){
    ABOUT_FIELDS.forEach(k => {
      const v = String(obj[k] || '').trim().slice(0, 200);
      if (v) clean[k] = v;
    });
  }
  return clean;
}

// Social links — all optional.
const SOCIAL_FIELDS = ['facebook', 'instagram', 'website'];
function sanitizeSocial(obj){
  const clean = {};
  if (obj && typeof obj === 'object'){
    SOCIAL_FIELDS.forEach(k => {
      const v = String(obj[k] || '').trim().slice(0, 300);
      if (v) clean[k] = v;
    });
  }
  return clean;
}

let businessesCol = null;
let usersCol = null;

// ---------------- Weekly hours (Mon-Sun open/close per day) ----------------
const DAY_KEYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
const DAY_LABELS = { mon: 'Mon', tue: 'Tue', wed: 'Wed', thu: 'Thu', fri: 'Fri', sat: 'Sat', sun: 'Sun' };
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

// Accepts the new per-day object from account.html's hours picker, or a plain
// string (e.g. from admin.html's old-style text field) — stores either safely.
function sanitizeHours(h){
  if (h && typeof h === 'object' && !Array.isArray(h)){
    const clean = {};
    DAY_KEYS.forEach(k => {
      const d = h[k] || {};
      clean[k] = {
        closed: !!d.closed,
        open: TIME_RE.test(d.open) ? d.open : '09:00',
        close: TIME_RE.test(d.close) ? d.close : '17:00'
      };
    });
    return clean;
  }
  return String(h || '').slice(0, 100);
}

function to12Hour(t){
  const [hh, mm] = t.split(':').map(Number);
  const period = hh >= 12 ? 'PM' : 'AM';
  const h12 = hh % 12 === 0 ? 12 : hh % 12;
  return `${h12}:${String(mm).padStart(2, '0')} ${period}`;
}

// Turns the per-day hours object into a readable summary, grouping
// consecutive days that share the same hours (e.g. "Mon–Fri: 9:00 AM – 5:00 PM, Sat–Sun: Closed").
function formatHours(h){
  if (!h) return '';
  if (typeof h === 'string') return h;
  const groups = [];
  DAY_KEYS.forEach(k => {
    const d = h[k];
    if (!d) return;
    const text = d.closed ? 'Closed' : `${to12Hour(d.open)} – ${to12Hour(d.close)}`;
    const last = groups[groups.length - 1];
    if (last && last.text === text) last.days.push(DAY_LABELS[k]);
    else groups.push({ text, days: [DAY_LABELS[k]] });
  });
  return groups.map(g => {
    const label = g.days.length > 1 ? `${g.days[0]}–${g.days[g.days.length - 1]}` : g.days[0];
    return `${label}: ${g.text}`;
  }).join(', ');
}

async function initDb(){
  if (!process.env.MONGODB_URI){
    console.log('No MONGODB_URI set — the site will run but nothing will save.');
    return;
  }
  try {
    const client = new MongoClient(process.env.MONGODB_URI);
    await client.connect();
    const db = client.db('tt_platform');
    businessesCol = db.collection('businesses');
    usersCol = db.collection('users');
    console.log('Connected to database.');
  } catch (err) {
    console.error('Database connection failed:', err.message);
  }
}
initDb();

async function requireUser(req, res, next){
  const token = req.headers['x-auth-token'];
  if (!token || !usersCol) return res.status(401).json({ error: 'Not signed in' });
  try {
    const user = await usersCol.findOne({ sessionToken: token });
    if (!user) return res.status(401).json({ error: 'Not signed in' });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Not signed in' });
  }
}

function requireAdmin(req, res, next){
  const provided = req.headers['x-admin-password'];
  if (!process.env.ADMIN_PASSWORD || provided !== process.env.ADMIN_PASSWORD){
    return res.status(401).json({ error: 'Incorrect admin password' });
  }
  next();
}

// Accounts created before this feature have no accountType saved — treat those as business accounts.
function requireBusinessAccount(req, res, next){
  if (req.user.accountType === 'customer'){
    return res.status(403).json({ error: 'This account is set up for updates only, not for managing a business listing.' });
  }
  next();
}

// ---------------- Public API ----------------
app.get('/api/businesses', async (req, res) => {
  if (!businessesCol) return res.json([]);
  try {
    const q = (req.query.q || '').trim();
    const matchStage = q
      ? { $match: { $or: [
          { name: { $regex: q, $options: 'i' } },
          { description: { $regex: q, $options: 'i' } }
        ] } }
      : { $match: {} };

    const list = await businessesCol.aggregate([
      matchStage,
      {
        $lookup: {
          from: 'users',
          let: { ownerIdStr: '$ownerId' },
          pipeline: [
            { $match: { $expr: { $eq: [{ $toString: '$_id' }, '$$ownerIdStr'] } } },
            { $project: { plan: 1, premiumMethod: 1, premiumExpiresAt: 1 } }
          ],
          as: 'ownerInfo'
        }
      },
      {
        $addFields: {
          ownerIsPremium: {
            $let: {
              vars: { owner: { $arrayElemAt: ['$ownerInfo', 0] } },
              in: {
                $and: [
                  { $eq: ['$$owner.plan', 'premium'] },
                  { $or: [
                      { $ne: ['$$owner.premiumMethod', 'wipay'] },
                      { $eq: ['$$owner.premiumExpiresAt', null] },
                      { $gt: ['$$owner.premiumExpiresAt', '$$NOW'] }
                  ] }
                ]
              }
            }
          }
        }
      },
      {
        $addFields: {
          isFeatured: { $or: [ { $eq: ['$featured', true] }, '$ownerIsPremium' ] }
        }
      },
      { $sort: { isFeatured: -1, name: 1 } },
      { $project: { ownerInfo: 0, ownerIsPremium: 0 } }
    ]).toArray();

    res.json(list);
  } catch (err) {
    console.error('Fetch businesses failed:', err.message);
    res.json([]);
  }
});

app.get('/api/businesses/:id', async (req, res) => {
  if (!businessesCol) return res.status(404).json({ error: 'Not found' });
  try {
    const biz = await businessesCol.findOne({ _id: new ObjectId(req.params.id) });
    if (!biz) return res.status(404).json({ error: 'Not found' });
    res.json(biz);
  } catch (err) {
    res.status(404).json({ error: 'Not found' });
  }
});

function escapeHtml(s){
  return String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

app.get('/biz/:id', async (req, res) => {
  if (!businessesCol) return res.status(404).send('Not found');
  let biz;
  try {
    biz = await businessesCol.findOne({ _id: new ObjectId(req.params.id) });
  } catch (err) {
    biz = null;
  }
  if (!biz) return res.status(404).send('<h1>Listing not found</h1><a href="/">Back to TT Discover</a>');

  const now = new Date();
  const activeDeals = (biz.deals || []).filter(d => !d.endDate || new Date(d.endDate) >= now);

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(biz.name)} — TT Discover</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #fdf6ec; color: #2a2a2a; }
  .topBar {
    background: linear-gradient(135deg, #e0562f, #f2a33c); color: #fff;
    padding: 12px 20px; font-size: 13px;
  }
  .topBar a { color: #fff; text-decoration: none; opacity: 0.9; }
  .hero {
    width: 100%; height: 220px; background-color: #f0d9c0; background-size: cover; background-position: center;
    display: flex; align-items: center; justify-content: center; font-size: 48px;
  }
  .wrap { max-width: 560px; margin: 0 auto; padding: 24px 18px 60px; }
  h1 { font-size: 24px; margin-bottom: 4px; }
  .meta { color: #888; font-size: 13px; margin-bottom: 16px; }
  .desc { font-size: 15px; line-height: 1.6; margin-bottom: 20px; }
  .infoRow { font-size: 14px; margin-bottom: 8px; }
  .infoRow b { color: #555; }
  .infoRow a { color: #e0562f; text-decoration: none; font-weight: 600; }
  .dealBox {
    background: #fff3e8; border: 1px solid #f2a33c; border-radius: 10px;
    padding: 14px 16px; margin-top: 18px;
  }
  .dealBox .title { font-weight: 700; color: #e0562f; margin-bottom: 4px; }
  footer {
    text-align: center; padding: 24px 16px; color: #aaa; font-size: 12px;
    border-top: 1px solid #eee; margin-top: 30px;
  }
  footer a { color: #e0562f; text-decoration: none; font-weight: 600; }
</style>
</head>
<body>
  <div class="topBar"><a href="/">← Back to TT Discover</a></div>
  <div class="hero" ${biz.imageUrl ? `style="background-image:url('${biz.imageUrl}')"` : ''}>${biz.imageUrl ? '' : '🍽️'}</div>
  <div class="wrap">
    <h1>${escapeHtml(biz.name)}</h1>
    <div class="meta">${escapeHtml(biz.category || 'Food')} · ${escapeHtml(biz.area || 'Port of Spain')}</div>
    <div class="desc">${escapeHtml(biz.description)}</div>
    ${biz.address ? `<div class="infoRow"><b>📍 Address:</b> ${escapeHtml(biz.address)}</div>` : ''}
    ${biz.phone ? `<div class="infoRow"><b>📞 Phone:</b> <a href="tel:${escapeHtml(biz.phone)}">${escapeHtml(biz.phone)}</a></div>` : ''}
    ${biz.hours ? `<div class="infoRow"><b>🕒 Hours:</b> ${escapeHtml(formatHours(biz.hours))}</div>` : ''}
    ${activeDeals.map(d => `<div class="dealBox"><div class="title">🔥 ${escapeHtml(d.title)}</div>${escapeHtml(d.description)}</div>`).join('')}
  </div>
  <footer>
    Powered by <a href="/">TT Discover</a> — <a href="/account.html">List your business free</a>
  </footer>
</body>
</html>`);
});

// ---------------- Accounts (for business owners) ----------------
app.post('/api/signup', async (req, res) => {
  if (!usersCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');
    const accountType = req.body && req.body.accountType === 'customer' ? 'customer' : 'business';
    if (!email || !password || password.length < 6){
      return res.status(400).json({ error: 'Email and a password of at least 6 characters are required.' });
    }
    const existing = await usersCol.findOne({ email });
    if (existing) return res.status(400).json({ error: 'An account with that email already exists.' });
    const passwordHash = await bcrypt.hash(password, 10);
    const sessionToken = crypto.randomBytes(24).toString('hex');
    await usersCol.insertOne({ email, passwordHash, sessionToken, accountType, createdAt: new Date() });
    res.json({ token: sessionToken, email });
  } catch (err) {
    console.error('Signup failed:', err.message);
    res.status(500).json({ error: 'Could not create account.' });
  }
});

app.post('/api/login', async (req, res) => {
  if (!usersCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');
    const user = await usersCol.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Incorrect email or password.' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Incorrect email or password.' });
    const sessionToken = crypto.randomBytes(24).toString('hex');
    await usersCol.updateOne({ _id: user._id }, { $set: { sessionToken } });
    res.json({ token: sessionToken, email: user.email });
  } catch (err) {
    console.error('Login failed:', err.message);
    res.status(500).json({ error: 'Could not log in.' });
  }
});

app.get('/api/me', requireUser, async (req, res) => {
  let user = req.user;
  if (user.plan === 'premium' && user.premiumMethod === 'wipay' && user.premiumExpiresAt && new Date(user.premiumExpiresAt) < new Date()){
    await usersCol.updateOne({ _id: user._id }, { $set: { plan: 'free' } });
    user.plan = 'free';
  }
  res.json({
    email: user.email,
    accountType: user.accountType === 'customer' ? 'customer' : 'business',
    preferredArea: user.preferredArea || null,
    plan: user.plan || 'free',
    premiumMethod: user.premiumMethod || null,
    premiumExpiresAt: user.premiumExpiresAt || null
  });
});

app.post('/api/me/preferences', requireUser, async (req, res) => {
  if (!usersCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const preferredArea = String((req.body && req.body.preferredArea) || '').slice(0, 100);
    await usersCol.updateOne({ _id: req.user._id }, { $set: { preferredArea } });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not save preferences.' });
  }
});

// ---------------- Premium payments (WiPay one-time + PayPal recurring) ----------------
const PREMIUM_WIPAY_PRICE_TTD = 75; // covers 3 months — adjust as needed
const PREMIUM_WIPAY_DAYS = 90;

app.post('/api/premium/wipay/start', requireUser, async (req, res) => {
  try {
    const orderId = 'PREM-' + req.user._id.toString() + '-' + Date.now();
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    // Best-effort based on WiPay's documented hosted-checkout flow — exact field names
    // may need a small adjustment once tested against real WiPay sandbox credentials.
    const params = new URLSearchParams({
      account_number: process.env.WIPAY_ACCOUNT_NUMBER || '',
      api_key: process.env.WIPAY_API_KEY || '',
      total: PREMIUM_WIPAY_PRICE_TTD.toFixed(2),
      order_id: orderId,
      currency: 'TTD',
      country_code: 'TT',
      method: 'credit_card',
      response_url: `${baseUrl}/api/premium/wipay/return`,
      origin: req.get('host').replace(/[^a-zA-Z0-9_-]/g, '-')
    });
    res.json({ checkoutUrl: `https://tt.wipayfinancial.com/plugins/payments/request?${params.toString()}` });
  } catch (err) {
    console.error('WiPay start failed:', err.message);
    res.status(500).json({ error: 'Could not start WiPay checkout.' });
  }
});

app.get('/api/premium/wipay/return', async (req, res) => {
  const { order_id, status } = req.query;
  if (status === 'success' && order_id && usersCol){
    const userId = String(order_id).split('-')[1];
    try {
      const expires = new Date(Date.now() + PREMIUM_WIPAY_DAYS * 24 * 60 * 60 * 1000);
      await usersCol.updateOne(
        { _id: new ObjectId(userId) },
        { $set: { plan: 'premium', premiumMethod: 'wipay', premiumExpiresAt: expires } }
      );
    } catch (err) {
      console.error('WiPay confirm failed:', err.message);
    }
  }
  res.redirect('/account.html?premium=' + (status === 'success' ? 'success' : 'failed'));
});

app.get('/api/paypal/config', (req, res) => {
  res.json({ clientId: process.env.PAYPAL_CLIENT_ID || '', planId: process.env.PAYPAL_PLAN_ID || '' });
});

const PAYPAL_BASE = process.env.PAYPAL_ENV === 'sandbox'
  ? 'https://api-m.sandbox.paypal.com'
  : 'https://api-m.paypal.com';

async function paypalAccessToken(){
  const auth = Buffer.from(process.env.PAYPAL_CLIENT_ID + ':' + process.env.PAYPAL_CLIENT_SECRET).toString('base64');
  const resp = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: { 'Authorization': 'Basic ' + auth, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials'
  });
  const data = await resp.json();
  return data.access_token;
}

// Handles PayPal's webhook notifications (cancellations, expirations, failed renewals, etc.)
// Note: this does not yet verify PayPal's webhook signature — fine for sandbox testing,
// but worth hardening before handling real live payments at scale.
app.post('/api/paypal/webhook', async (req, res) => {
  res.sendStatus(200); // acknowledge quickly, PayPal expects a fast response
  try {
    const eventType = req.body && req.body.event_type;
    const subscriptionId = req.body && req.body.resource && req.body.resource.id;
    if (!eventType || !subscriptionId || !usersCol) return;

    const downgradeEvents = [
      'BILLING.SUBSCRIPTION.CANCELLED',
      'BILLING.SUBSCRIPTION.EXPIRED',
      'BILLING.SUBSCRIPTION.SUSPENDED'
    ];
    const upgradeEvents = [
      'BILLING.SUBSCRIPTION.ACTIVATED',
      'BILLING.SUBSCRIPTION.RE-ACTIVATED'
    ];

    if (downgradeEvents.includes(eventType)){
      await usersCol.updateOne({ paypalSubscriptionId: subscriptionId }, { $set: { plan: 'free' } });
      console.log('PayPal webhook: downgraded subscription', subscriptionId, eventType);
    } else if (upgradeEvents.includes(eventType)){
      await usersCol.updateOne(
        { paypalSubscriptionId: subscriptionId },
        { $set: { plan: 'premium', premiumMethod: 'paypal', premiumExpiresAt: null } }
      );
      console.log('PayPal webhook: activated subscription', subscriptionId, eventType);
    }
  } catch (err) {
    console.error('PayPal webhook handling failed:', err.message);
  }
});

app.post('/api/premium/paypal/confirm', requireUser, async (req, res) => {
  try {
    const subscriptionId = req.body && req.body.subscriptionId;
    if (!subscriptionId) return res.status(400).json({ error: 'Missing subscription ID.' });
    const token = await paypalAccessToken();
    const resp = await fetch(`${PAYPAL_BASE}/v1/billing/subscriptions/${subscriptionId}`, {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    const sub = await resp.json();
    if (sub.status !== 'ACTIVE') return res.status(400).json({ error: 'Subscription is not active yet.' });
    await usersCol.updateOne(
      { _id: req.user._id },
      { $set: { plan: 'premium', premiumMethod: 'paypal', paypalSubscriptionId: subscriptionId, premiumExpiresAt: null } }
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('PayPal confirm failed:', err.message);
    res.status(500).json({ error: 'Could not confirm subscription.' });
  }
});

// ---------------- Self-service business listings (signed-in owners) ----------------
app.get('/api/my/businesses', requireUser, async (req, res) => {
  if (!businessesCol) return res.json([]);
  try {
    const list = await businessesCol.find({ ownerId: req.user._id.toString() }).sort({ name: 1 }).toArray();
    res.json(list);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/my/businesses', requireUser, requireBusinessAccount, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const b = req.body || {};
    const doc = {
      ownerId: req.user._id.toString(),
      name: String(b.name || '').slice(0, 100),
      category: String(b.category || 'Food').slice(0, 40),
      logoUrl: String(b.logoUrl || '').slice(0, 400000),
      area: String(b.area || 'Port of Spain').slice(0, 60),
      description: String(b.description || '').slice(0, 500),
      address: String(b.address || '').slice(0, 200),
      phone: String(b.phone || '').slice(0, 40),
      email: String(b.email || '').slice(0, 150),
      hours: sanitizeHours(b.hours),
      imageUrl: String(b.imageUrl || '').slice(0, 400000),
      photos: sanitizePhotoArray(b.photos),
      menuPhotos: sanitizePhotoArray(b.menuPhotos),
      about: sanitizeAbout(b.about),
      social: sanitizeSocial(b.social),
      hiring: !!b.hiring,
      featured: false,
      deals: [],
      posts: [],
      createdAt: new Date()
    };
    if (!doc.name.trim()) return res.status(400).json({ error: 'Business name is required.' });
    if (b.dealTitle){
      doc.deals.push({
        title: String(b.dealTitle).slice(0, 100),
        description: String(b.dealDescription || '').slice(0, 300),
        endDate: b.dealEndDate ? new Date(b.dealEndDate) : null
      });
    }
    const result = await businessesCol.insertOne(doc);
    res.json({ ok: true, id: result.insertedId });
  } catch (err) {
    console.error('Add business failed:', err.message);
    res.status(500).json({ error: 'Could not add business.' });
  }
});

app.put('/api/my/businesses/:id', requireUser, requireBusinessAccount, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const biz = await businessesCol.findOne({ _id: new ObjectId(req.params.id) });
    if (!biz || biz.ownerId !== req.user._id.toString()){
      return res.status(403).json({ error: 'You can only edit your own listing.' });
    }
    const b = req.body || {};
    const update = {
      name: String(b.name || '').slice(0, 100),
      description: String(b.description || '').slice(0, 500),
      address: String(b.address || '').slice(0, 200),
      phone: String(b.phone || '').slice(0, 40),
      hours: sanitizeHours(b.hours),
      imageUrl: String(b.imageUrl || '').slice(0, 400000)
    };
    if (b.category) update.category = String(b.category).slice(0, 40);
    if (Array.isArray(b.photos)) update.photos = sanitizePhotoArray(b.photos);
    if (Array.isArray(b.menuPhotos)) update.menuPhotos = sanitizePhotoArray(b.menuPhotos);
    if (Array.isArray(b.highlights)) update.highlights = sanitizePhotoArray(b.highlights);
    if (typeof b.hiring === 'boolean') update.hiring = b.hiring;
    if (b.about) update.about = sanitizeAbout(b.about);
    if (b.social) update.social = sanitizeSocial(b.social);
    if (typeof b.logoUrl === 'string') update.logoUrl = b.logoUrl.slice(0, 400000);
    if (typeof b.email === 'string') update.email = b.email.slice(0, 150);
    await businessesCol.updateOne({ _id: biz._id }, { $set: update });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not update business.' });
  }
});

app.delete('/api/my/businesses/:id', requireUser, requireBusinessAccount, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const biz = await businessesCol.findOne({ _id: new ObjectId(req.params.id) });
    if (!biz || biz.ownerId !== req.user._id.toString()){
      return res.status(403).json({ error: 'You can only delete your own listing.' });
    }
    await businessesCol.deleteOne({ _id: biz._id });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not delete business.' });
  }
});

app.patch('/api/my/businesses/:id/hiring', requireUser, requireBusinessAccount, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const biz = await businessesCol.findOne({ _id: new ObjectId(req.params.id) });
    if (!biz || biz.ownerId !== req.user._id.toString()){
      return res.status(403).json({ error: 'You can only edit your own listing.' });
    }
    const hiring = !!(req.body && req.body.hiring);
    await businessesCol.updateOne({ _id: biz._id }, { $set: { hiring } });
    res.json({ ok: true, hiring });
  } catch (err) {
    res.status(500).json({ error: 'Could not update hiring status.' });
  }
});

app.post('/api/my/businesses/:id/posts', requireUser, requireBusinessAccount, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const biz = await businessesCol.findOne({ _id: new ObjectId(req.params.id) });
    if (!biz || biz.ownerId !== req.user._id.toString()){
      return res.status(403).json({ error: 'You can only post to your own listing.' });
    }
    const b = req.body || {};
    const title = String(b.title || '').trim().slice(0, 100);
    if (!title) return res.status(400).json({ error: 'A post title is required.' });
    const post = {
      _id: new ObjectId(),
      title,
      content: String(b.content || '').slice(0, 1000),
      imageUrl: String(b.imageUrl || '').slice(0, 400000),
      createdAt: new Date()
    };
    await businessesCol.updateOne({ _id: biz._id }, { $push: { posts: { $each: [post], $position: 0 } } });
    res.json({ ok: true, post });
  } catch (err) {
    res.status(500).json({ error: 'Could not create post.' });
  }
});

app.delete('/api/my/businesses/:id/posts/:postId', requireUser, requireBusinessAccount, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const biz = await businessesCol.findOne({ _id: new ObjectId(req.params.id) });
    if (!biz || biz.ownerId !== req.user._id.toString()){
      return res.status(403).json({ error: 'You can only edit your own listing.' });
    }
    await businessesCol.updateOne({ _id: biz._id }, { $pull: { posts: { _id: new ObjectId(req.params.postId) } } });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not delete post.' });
  }
});

// ---------------- Admin API (password protected) ----------------
app.post('/api/admin/check', requireAdmin, (req, res) => { res.json({ ok: true }); });

app.post('/api/admin/businesses', requireAdmin, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const b = req.body || {};
    const doc = {
      name: String(b.name || '').slice(0, 100),
      category: String(b.category || 'Food').slice(0, 40),
      area: String(b.area || 'Port of Spain').slice(0, 60),
      description: String(b.description || '').slice(0, 500),
      address: String(b.address || '').slice(0, 200),
      phone: String(b.phone || '').slice(0, 40),
      hours: sanitizeHours(b.hours),
      imageUrl: String(b.imageUrl || '').slice(0, 500),
      featured: !!b.featured,
      deals: [],
      createdAt: new Date()
    };
    if (b.dealTitle){
      doc.deals.push({
        title: String(b.dealTitle).slice(0, 100),
        description: String(b.dealDescription || '').slice(0, 300),
        endDate: b.dealEndDate ? new Date(b.dealEndDate) : null
      });
    }
    const result = await businessesCol.insertOne(doc);
    res.json({ ok: true, id: result.insertedId });
  } catch (err) {
    console.error('Add business failed:', err.message);
    res.status(500).json({ error: 'Could not add business' });
  }
});

app.delete('/api/admin/businesses/:id', requireAdmin, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    await businessesCol.deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not delete business' });
  }
});

app.patch('/api/admin/businesses/:id/featured', requireAdmin, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    await businessesCol.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { featured: !!(req.body && req.body.featured) } }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not update business' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('TT Local Platform running on port ' + PORT));
