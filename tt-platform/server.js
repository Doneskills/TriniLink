const express = require('express');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let businessesCol = null;

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
    console.log('Connected to database.');
  } catch (err) {
    console.error('Database connection failed:', err.message);
  }
}
initDb();

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
