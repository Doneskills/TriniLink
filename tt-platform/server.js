const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let businessesCol = null;
let usersCol = null;

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

// ---------------- Public API ----------------
app.get('/api/businesses', async (req, res) => {
  if (!businessesCol) return res.json([]);
  try {
    const q = (req.query.q || '').trim();
    const filter = q
      ? { $or: [
          { name: { $regex: q, $options: 'i' } },
          { description: { $regex: q, $options: 'i' } }
        ] }
      : {};
    const list = await businessesCol.find(filter).sort({ name: 1 }).toArray();
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

// ---------------- Accounts (for business owners) ----------------
app.post('/api/signup', async (req, res) => {
  if (!usersCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');
    if (!email || !password || password.length < 6){
      return res.status(400).json({ error: 'Email and a password of at least 6 characters are required.' });
    }
    const existing = await usersCol.findOne({ email });
    if (existing) return res.status(400).json({ error: 'An account with that email already exists.' });
    const passwordHash = await bcrypt.hash(password, 10);
    const sessionToken = crypto.randomBytes(24).toString('hex');
    await usersCol.insertOne({ email, passwordHash, sessionToken, createdAt: new Date() });
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

app.get('/api/me', requireUser, (req, res) => {
  res.json({ email: req.user.email, plan: req.user.plan || 'free' });
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

app.post('/api/my/businesses', requireUser, async (req, res) => {
  if (!businessesCol) return res.status(503).json({ error: 'Database not connected' });
  try {
    const b = req.body || {};
    const doc = {
      ownerId: req.user._id.toString(),
      name: String(b.name || '').slice(0, 100),
      category: String(b.category || 'Food').slice(0, 40),
      area: String(b.area || 'Port of Spain').slice(0, 60),
      description: String(b.description || '').slice(0, 500),
      address: String(b.address || '').slice(0, 200),
      phone: String(b.phone || '').slice(0, 40),
      hours: String(b.hours || '').slice(0, 100),
      imageUrl: String(b.imageUrl || '').slice(0, 500),
      featured: false,
      deals: [],
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

app.put('/api/my/businesses/:id', requireUser, async (req, res) => {
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
      hours: String(b.hours || '').slice(0, 100),
      imageUrl: String(b.imageUrl || '').slice(0, 500)
    };
    await businessesCol.updateOne({ _id: biz._id }, { $set: update });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not update business.' });
  }
});

app.delete('/api/my/businesses/:id', requireUser, async (req, res) => {
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
      hours: String(b.hours || '').slice(0, 100),
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('TT Local Platform running on port ' + PORT));
