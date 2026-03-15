require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ─── STRIPE INITIALISÉ EN PREMIER ────────────────────────────────
let stripe = null;
const stripeKey = process.env.STRIPE_SECRET_KEY;
if (stripeKey && !stripeKey.includes('placeholder')) {
    try { stripe = require('stripe')(stripeKey); console.log("✅ Stripe activé."); }
    catch(e) { console.log("⚠️ Stripe non disponible:", e.message); }
} else {
    console.log("⚠️ Stripe non configuré — paiements désactivés.");
}

// ⚠️ WEBHOOK AVANT express.json() ET APRÈS init Stripe
app.post('/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    console.log("📨 Webhook reçu !");

    if (!stripe) {
        console.error("❌ Stripe non initialisé.");
        return res.status(500).send("Stripe non initialisé.");
    }

    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
        );
        console.log("✅ Signature OK — Type:", event.type);
    } catch (err) {
        console.error("❌ Signature invalide:", err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            console.log("💳 Session complète:", JSON.stringify(session.metadata));
            if (session.metadata?.user_id) {
                await pool.query(
                    "UPDATE users SET plan = 'premium', stripe_subscription_id = $1 WHERE id = $2",
                    [session.subscription, session.metadata.user_id]
                );
                console.log("⭐ Premium activé pour user:", session.metadata.user_id);
            }
        }

        if (event.type === 'customer.subscription.deleted') {
            const sub = event.data.object;
            await pool.query(
                "UPDATE users SET plan = 'free' WHERE stripe_subscription_id = $1",
                [sub.id]
            );
            console.log("⬇️ Abonnement annulé.");
        }

        res.json({ received: true });
    } catch(err) {
        console.error("❌ Erreur webhook:", err.message);
        res.status(400).send("Erreur: " + err.message);
    }
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

const JWT_SECRET = process.env.JWT_SECRET || 'insightengine_secret_key';

async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS analyses (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                filename TEXT,
                resume TEXT,
                points_cles TEXT,
                recommandation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Tables PostgreSQL prêtes.");
    } catch (err) {
        console.error("❌ Erreur init DB:", err.message);
    }
}
initDB();

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

async function checkAndResetMonthlyCounter(user) {
    const currentMonth = new Date().toISOString().slice(0, 7);
    if (user.last_reset_month !== currentMonth) {
        await pool.query(
            "UPDATE users SET analyses_this_month = 0, last_reset_month = $1 WHERE id = $2",
            [currentMonth, user.id]
        );
        return { ...user, analyses_this_month: 0, last_reset_month: currentMonth };
    }
    return user;
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
        const result = await pool.query(
            "INSERT INTO users (email, password, last_reset_month) VALUES ($1, $2, $3) RETURNING id",
            [email, hash, currentMonth]
        );
        const token = jwt.sign({ id: result.rows[0].id, email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: result.rows[0].id, email, plan: 'free', analyses_this_month: 0 } });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Cet email est déjà utilisé." });
        res.status(500).json({ error: err.message });
    }
});

// ─── AUTH : CONNEXION ──────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];
        if (!user) return res.status(400).json({ error: "Email ou mot de passe incorrect." });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: "Email ou mot de passe incorrect." });
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.id, email: user.email, plan: user.plan, analyses_this_month: user.analyses_this_month } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── AUTH : PROFIL ─────────────────────────────────────────────────
app.get('/auth/me', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, email, nom, prenom, adresse, ville, code_postal, pays, plan, analyses_this_month, last_reset_month FROM users WHERE id = $1",
            [req.user.id]
        );
        if (!result.rows[0]) return res.status(404).json({ error: "Utilisateur introuvable." });
        const user = await checkAndResetMonthlyCounter(result.rows[0]);
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── PROFIL : MODIFIER INFOS ───────────────────────────────────────
app.put('/auth/profile', authMiddleware, async (req, res) => {
    const { nom, prenom, adresse, ville, code_postal, pays } = req.body;
    try {
        await pool.query(
            "UPDATE users SET nom=$1, prenom=$2, adresse=$3, ville=$4, code_postal=$5, pays=$6 WHERE id=$7",
            [nom||'', prenom||'', adresse||'', ville||'', code_postal||'', pays||'', req.user.id]
        );
        res.json({ success: true, message: "Profil mis à jour." });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── PROFIL : CHANGER EMAIL ────────────────────────────────────────
app.put('/auth/change-email', authMiddleware, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis." });
    try {
        const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: "Utilisateur introuvable." });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: "Mot de passe incorrect." });
        await pool.query("UPDATE users SET email = $1 WHERE id = $2", [email, req.user.id]);
        const token = jwt.sign({ id: req.user.id, email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, message: "Email mis à jour." });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Cet email est déjà utilisé." });
        res.status(500).json({ error: err.message });
    }
});

// ─── PROFIL : CHANGER MOT DE PASSE ────────────────────────────────
app.put('/auth/change-password', authMiddleware, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: "Les deux mots de passe sont requis." });
    if (newPassword.length < 6) return res.status(400).json({ error: "Le nouveau mot de passe doit faire au moins 6 caractères." });
    try {
        const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: "Utilisateur introuvable." });
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) return res.status(400).json({ error: "Mot de passe actuel incorrect." });
        const hash = await bcrypt.hash(newPassword, 10);
        await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hash, req.user.id]);
        res.json({ success: true, message: "Mot de passe mis à jour." });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── STRIPE : CHECKOUT ────────────────────────────────────────────
app.post('/stripe/create-checkout', authMiddleware, async (req, res) => {
    if (!stripe) return res.status(503).json({ error: "Paiement non disponible pour l'instant." });
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'subscription',
            line_items: [{
                price_data: {
                    currency: 'eur',
                    product_data: {
                        name: 'InsightEngine Premium',
                        description: 'Analyses illimitées (500 pages) + historique + support 24/7'
                    },
                    unit_amount: 999,
                    recurring: { interval: 'month' },
                },
                quantity: 1,
            }],
            customer_email: req.user.email,
            success_url: `${process.env.APP_URL}/?payment=success`,
            cancel_url: `${process.env.APP_URL}/`,
            metadata: { user_id: String(req.user.id) },
        });
        console.log("💳 Session créée pour user:", req.user.id);
        res.json({ url: session.url });
    } catch (err) {
        console.error("❌ Stripe error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─── ANALYSE ──────────────────────────────────────────────────────
app.post('/analyze', optionalAuth, async (req, res) => {
    console.log("📥 Requête d'analyse reçue...");
    try {
        if (!req.body || !req.body.text) return res.status(400).json({ error: "Champ 'text' manquant." });
        if (!activeModel) return res.status(503).json({ error: "Aucun modèle IA n'est prêt." });

        if (req.user) {
            const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
            await checkAndResetMonthlyCounter(result.rows[0]);
            const freshResult = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
            const freshUser = freshResult.rows[0];
            const limit = LIMITS[freshUser.plan] || LIMITS.free;
            if (freshUser.plan !== 'premium' && freshUser.analyses_this_month >= limit.analyses) {
                return res.status(403).json({
                    error: "quota_exceeded",
                    message: `Vous avez atteint votre limite de ${limit.analyses} analyses gratuites ce mois-ci.`,
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
            await pool.query("UPDATE users SET analyses_this_month = analyses_this_month + 1 WHERE id = $1", [req.user.id]);
            const userResult = await pool.query("SELECT plan FROM users WHERE id = $1", [req.user.id]);
            if (userResult.rows[0]?.plan === 'premium') {
                await pool.query(
                    "INSERT INTO analyses (user_id, filename, resume, points_cles, recommandation) VALUES ($1, $2, $3, $4, $5)",
                    [req.user.id, req.body.filename || 'document.pdf', parsed.resume,
                     JSON.stringify(parsed.points_cles), parsed.recommandation]
                );
            }
        }

        console.log("✨ Analyse réussie.");
        res.json({ analysis: JSON.stringify(parsed) });
    } catch (error) {
        console.error("❌ Erreur:", error.message);
        res.status(500).json({ error: error.message });
    }
});

// ─── HISTORIQUE ───────────────────────────────────────────────────
app.get('/history', authMiddleware, async (req, res) => {
    try {
        const userResult = await pool.query("SELECT plan FROM users WHERE id = $1", [req.user.id]);
        if (userResult.rows[0]?.plan !== 'premium') return res.status(403).json({ error: "Fonctionnalité Premium uniquement." });
        const result = await pool.query(
            "SELECT id, filename, resume, points_cles, recommandation, created_at FROM analyses WHERE user_id = $1 ORDER BY created_at DESC",
            [req.user.id]
        );
        res.json(result.rows.map(r => ({ ...r, points_cles: JSON.parse(r.points_cles) })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── ROUTE /models ────────────────────────────────────────────────
app.get('/models', async (req, res) => {
    try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${API_KEY}`);
        const data = await response.json();
        res.json(data.models.map(m => m.name));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

process.on('SIGINT', () => { pool.end(); process.exit(0); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur : http://localhost:${PORT}`));