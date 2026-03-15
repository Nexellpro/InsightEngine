require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const db = new sqlite3.Database('./database.db');

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

const JWT_SECRET = process.env.JWT_SECRET || 'insightengine_secret_key';

let stripe = null;
const stripeKey = process.env.STRIPE_SECRET_KEY;
if (stripeKey && !stripeKey.includes('placeholder')) {
    try { stripe = require('stripe')(stripeKey); console.log("✅ Stripe activé."); }
    catch(e) { console.log("⚠️ Stripe non disponible:", e.message); }
} else {
    console.log("⚠️ Stripe non configuré — paiements désactivés.");
}

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        nom TEXT DEFAULT '',
        prenom TEXT DEFAULT '',
        adresse TEXT DEFAULT '',
        ville TEXT DEFAULT '',
        code_postal TEXT DEFAULT '',
        pays TEXT DEFAULT '',
        plan TEXT DEFAULT 'free',
        analyses_this_month INTEGER DEFAULT 0,
        last_reset_month TEXT DEFAULT '',
        stripe_subscription_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) console.error("❌ Erreur table users:", err.message);
        else console.log("✅ Table users prête.");
    });

    db.run(`CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        resume TEXT,
        points_cles TEXT,
        recommandation TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
        if (err) console.error("❌ Erreur table analyses:", err.message);
        else console.log("✅ Table analyses prête.");
    });
});

const API_KEY = process.env.GEMINI_API_KEY;
const genAI = new GoogleGenerativeAI(API_KEY);
let activeModel = null;

async function initModel() {
    console.log("🔍 Connexion aux modèles Google...");
    const candidates = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite"];
    for (const name of candidates) {
        try {
            const model = genAI.getGenerativeModel({ model: name });
            await model.generateContent("test");
            activeModel = model;
            console.log(`✅ Modèle "${name}" activé.`);
            break;
        } catch (e) {
            console.log(`❌ Modèle "${name}" — ${e.message}`);
        }
    }
    if (!activeModel) console.error("🛑 Aucun modèle accessible.");
}
initModel();

const LIMITS = {
    free:    { analyses: 3,        pages: 10  },
    premium: { analyses: Infinity, pages: 500 },
};

function checkAndResetMonthlyCounter(user, callback) {
    const currentMonth = new Date().toISOString().slice(0, 7);
    if (user.last_reset_month !== currentMonth) {
        db.run("UPDATE users SET analyses_this_month = 0, last_reset_month = ? WHERE id = ?",
            [currentMonth, user.id],
            () => callback({ ...user, analyses_this_month: 0, last_reset_month: currentMonth })
        );
    } else {
        callback(user);
    }
}

function optionalAuth(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) { try { req.user = jwt.verify(token, JWT_SECRET); } catch {} }
    next();
}

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Non authentifié." });
    try { req.user = jwt.verify(token, JWT_SECRET); next(); }
    catch { res.status(401).json({ error: "Token invalide." }); }
}

// ─── AUTH : INSCRIPTION ────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis." });
    try {
        const hash = await bcrypt.hash(password, 10);
        const currentMonth = new Date().toISOString().slice(0, 7);
        db.run("INSERT INTO users (email, password, last_reset_month) VALUES (?, ?, ?)",
            [email, hash, currentMonth],
            function(err) {
                if (err) return res.status(400).json({ error: "Cet email est déjà utilisé." });
                const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, { expiresIn: '7d' });
                res.json({ token, user: { id: this.lastID, email, plan: 'free', analyses_this_month: 0 } });
            }
        );
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── AUTH : CONNEXION ──────────────────────────────────────────────
app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Email ou mot de passe incorrect." });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: "Email ou mot de passe incorrect." });
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.id, email: user.email, plan: user.plan, analyses_this_month: user.analyses_this_month } });
    });
});

// ─── AUTH : PROFIL ─────────────────────────────────────────────────
app.get('/auth/me', authMiddleware, (req, res) => {
    db.get("SELECT id, email, nom, prenom, adresse, ville, code_postal, pays, plan, analyses_this_month, last_reset_month FROM users WHERE id = ?",
        [req.user.id], (err, user) => {
            if (err || !user) return res.status(404).json({ error: "Utilisateur introuvable." });
            checkAndResetMonthlyCounter(user, (updatedUser) => res.json(updatedUser));
        }
    );
});

// ─── PROFIL : MODIFIER INFOS ───────────────────────────────────────
app.put('/auth/profile', authMiddleware, (req, res) => {
    const { nom, prenom, adresse, ville, code_postal, pays } = req.body;
    db.run(
        "UPDATE users SET nom = ?, prenom = ?, adresse = ?, ville = ?, code_postal = ?, pays = ? WHERE id = ?",
        [nom || '', prenom || '', adresse || '', ville || '', code_postal || '', pays || '', req.user.id],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: "Profil mis à jour." });
        }
    );
});

// ─── PROFIL : CHANGER EMAIL ────────────────────────────────────────
app.put('/auth/change-email', authMiddleware, (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis." });
    db.get("SELECT * FROM users WHERE id = ?", [req.user.id], async (err, user) => {
        if (err || !user) return res.status(404).json({ error: "Utilisateur introuvable." });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: "Mot de passe incorrect." });
        db.run("UPDATE users SET email = ? WHERE id = ?", [email, req.user.id], function(err) {
            if (err) return res.status(400).json({ error: "Cet email est déjà utilisé." });
            const token = jwt.sign({ id: req.user.id, email }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ success: true, token, message: "Email mis à jour." });
        });
    });
});

// ─── PROFIL : CHANGER MOT DE PASSE ────────────────────────────────
app.put('/auth/change-password', authMiddleware, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: "Les deux mots de passe sont requis." });
    if (newPassword.length < 6) return res.status(400).json({ error: "Le nouveau mot de passe doit faire au moins 6 caractères." });
    db.get("SELECT * FROM users WHERE id = ?", [req.user.id], async (err, user) => {
        if (err || !user) return res.status(404).json({ error: "Utilisateur introuvable." });
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) return res.status(400).json({ error: "Mot de passe actuel incorrect." });
        const hash = await bcrypt.hash(newPassword, 10);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hash, req.user.id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: "Mot de passe mis à jour." });
        });
    });
});

// ─── STRIPE ───────────────────────────────────────────────────────
app.post('/stripe/create-checkout', authMiddleware, async (req, res) => {
    if (!stripe) return res.status(503).json({ error: "Paiement non disponible pour l'instant." });
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'subscription',
            line_items: [{
                price_data: {
                    currency: 'eur',
                    product_data: { name: 'InsightEngine Premium', description: 'Analyses illimitées (500 pages) + historique + support 24/7' },
                    unit_amount: 999,
                    recurring: { interval: 'month' },
                },
                quantity: 1,
            }],
            customer_email: req.user.email,
            success_url: `${process.env.APP_URL || 'http://localhost:3000'}/?payment=success`,
            cancel_url: `${process.env.APP_URL || 'http://localhost:3000'}/`,
            metadata: { user_id: req.user.id },
        });
        res.json({ url: session.url });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
    if (!stripe) return res.status(503).json({ error: "Stripe non configuré." });
    const sig = req.headers['stripe-signature'];
    let event;
    try { event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET); }
    catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        if (session.mode === 'subscription' && session.metadata.user_id) {
            db.run("UPDATE users SET plan = 'premium', stripe_subscription_id = ? WHERE id = ?",
                [session.subscription, session.metadata.user_id]);
        }
    }
    if (event.type === 'customer.subscription.deleted') {
        const sub = event.data.object;
        db.run("UPDATE users SET plan = 'free' WHERE stripe_subscription_id = ?", [sub.id]);
    }
    res.json({ received: true });
});

// ─── ANALYSE ──────────────────────────────────────────────────────
app.post('/analyze', optionalAuth, async (req, res) => {
    console.log("📥 Requête d'analyse reçue...");
    try {
        if (!req.body || !req.body.text) return res.status(400).json({ error: "Champ 'text' manquant." });
        if (!activeModel) return res.status(503).json({ error: "Aucun modèle IA n'est prêt." });

        if (req.user) {
            const user = await new Promise((resolve, reject) =>
                db.get("SELECT * FROM users WHERE id = ?", [req.user.id], (err, row) => err ? reject(err) : resolve(row)));
            await new Promise((resolve) => checkAndResetMonthlyCounter(user, resolve));
            const freshUser = await new Promise((resolve, reject) =>
                db.get("SELECT * FROM users WHERE id = ?", [req.user.id], (err, row) => err ? reject(err) : resolve(row)));
            const limit = LIMITS[freshUser.plan] || LIMITS.free;
            if (freshUser.plan !== 'premium' && freshUser.analyses_this_month >= limit.analyses) {
                return res.status(403).json({
                    error: "quota_exceeded",
                    message: `Vous avez atteint votre limite de ${limit.analyses} analyses gratuites ce mois-ci.`,
                    analyses_used: freshUser.analyses_this_month,
                    analyses_limit: limit.analyses
                });
            }
        }

        const prompt = `Réponds UNIQUEMENT en JSON pur, sans balises markdown, sans blocs de code :
{"resume": "...", "points_cles": ["..."], "recommandation": "..."}
Texte: ${req.body.text.substring(0, 50000)}`;

        const result = await activeModel.generateContent(prompt);
        const textResponse = result.response.text();
        const cleaned = textResponse.replace(/```json|```/g, "").trim();
        const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
        if (!jsonMatch) throw new Error("L'IA n'a pas renvoyé de JSON valide.");
        const parsed = JSON.parse(jsonMatch[0]);

        if (req.user) {
            db.run("UPDATE users SET analyses_this_month = analyses_this_month + 1 WHERE id = ?", [req.user.id]);
            db.get("SELECT plan FROM users WHERE id = ?", [req.user.id], (err, u) => {
                if (u?.plan === 'premium') {
                    db.run("INSERT INTO analyses (user_id, filename, resume, points_cles, recommandation) VALUES (?, ?, ?, ?, ?)",
                        [req.user.id, req.body.filename || 'document.pdf', parsed.resume,
                         JSON.stringify(parsed.points_cles), parsed.recommandation]);
                }
            });
        }

        console.log("✨ Analyse réussie.");
        res.json({ analysis: JSON.stringify(parsed) });
    } catch (error) {
        console.error("❌ Erreur:", error.message);
        res.status(500).json({ error: error.message });
    }
});

// ─── HISTORIQUE ───────────────────────────────────────────────────
app.get('/history', authMiddleware, (req, res) => {
    db.get("SELECT plan FROM users WHERE id = ?", [req.user.id], (err, user) => {
        if (user?.plan !== 'premium') return res.status(403).json({ error: "Fonctionnalité Premium uniquement." });
        db.all("SELECT id, filename, resume, points_cles, recommandation, created_at FROM analyses WHERE user_id = ? ORDER BY created_at DESC",
            [req.user.id], (err, rows) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json(rows.map(r => ({ ...r, points_cles: JSON.parse(r.points_cles) })));
            }
        );
    });
});

app.get('/models', async (req, res) => {
    try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${API_KEY}`);
        const data = await response.json();
        res.json(data.models.map(m => m.name));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

process.on('SIGINT', () => {
    db.close(() => { console.log("🛑 DB fermée."); process.exit(0); });
});

app.listen(3000, () => console.log("🚀 Serveur : http://localhost:3000"));