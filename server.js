require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
const PORT = process.env.PORT || 3000;
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ── API KEY pentru comunicare inter-servicii ──
// Adaugă în .env: INTERNAL_API_KEY=un_string_random_lung_32+_caractere
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY;

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Conectat la MongoDB!'))
    .catch(err => console.error('❌ Eroare MongoDB:', err));

const UserSchema = new mongoose.Schema({
    googleId:           { type: String, required: true, unique: true },
    email:              { type: String, required: true },
    name:               String,
    picture:            String,
    credits:            { type: Number, default: 10 },
    voice_characters:   { type: Number, default: 3000 },
    stripeCustomerId:   { type: String, default: null },
    subscriptionId:     { type: String, default: null },
    subscriptionPlan:   { type: String, enum: ['none','starter','creator','agency'], default: 'none' },
    subscriptionStatus: { type: String, default: 'inactive' },
    currentPeriodEnd:   { type: Date, default: null },
    referralCode:       { type: String, unique: true, sparse: true },
    referredBy:         { type: String, default: null },
    referralCount:      { type: Number, default: 0 },
    referralCreditsEarned: { type: Number, default: 0 },
    referralTier:       { type: Number, default: 0 },
    referralBonusesClaimed: [{ type: Number }],  // tier indexes already claimed
    registrationIp:     { type: String, default: null },
    createdAt:          { type: Date, default: Date.now },
    earlyAccess:        { type: Boolean, default: false }
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

const WaitlistSchema = new mongoose.Schema({
    email: String, name: String, date: { type: Date, default: Date.now }
});
const Waitlist = mongoose.models.Waitlist || mongoose.model('Waitlist', WaitlistSchema);

const PLANS = {
    [process.env.STRIPE_PRICE_STARTER]:        { plan: 'starter', credits: 150,  chars: 50000  },
    [process.env.STRIPE_PRICE_CREATOR]:        { plan: 'creator', credits: 400,  chars: 150000 },
    [process.env.STRIPE_PRICE_AGENCY]:         { plan: 'agency',  credits: 1500, chars: 500000 },
    [process.env.STRIPE_PRICE_STARTER_YEARLY]: { plan: 'starter', credits: 150,  chars: 50000  },
    [process.env.STRIPE_PRICE_CREATOR_YEARLY]: { plan: 'creator', credits: 400,  chars: 150000 },
    [process.env.STRIPE_PRICE_AGENCY_YEARLY]:  { plan: 'agency',  credits: 1500, chars: 500000 },
};

const TOPUP = {
    [process.env.STRIPE_PRICE_TOPUP_50]:  50,
    [process.env.STRIPE_PRICE_TOPUP_150]: 150,
    [process.env.STRIPE_PRICE_TOPUP_400]: 400,
};

// ══════════════════════════════════════════════════════════════
// ██ REFERRAL TIER SYSTEM — 8 niveluri, bonusuri progresive
// ══════════════════════════════════════════════════════════════
const REFERRAL_TIERS = [
    // tier 0: start — fiecare invitație = 5 credite
    { minReferrals: 0,   name: 'Începător',      icon: '🌱', perReferral: 5,  bonus: 0,    bonusVoice: 0,      badge: null },
    // tier 1: 3 invitații — bonus 10 credite
    { minReferrals: 3,   name: 'Promoter',        icon: '⚡', perReferral: 5,  bonus: 10,   bonusVoice: 2000,   badge: 'Promoter' },
    // tier 2: 10 invitații — bonus 30 credite + 5k voice
    { minReferrals: 10,  name: 'Influencer',      icon: '🔥', perReferral: 7,  bonus: 30,   bonusVoice: 5000,   badge: 'Influencer' },
    // tier 3: 25 invitații — bonus 75 credite + 15k voice
    { minReferrals: 25,  name: 'Ambassador',      icon: '💎', perReferral: 7,  bonus: 75,   bonusVoice: 15000,  badge: 'Ambassador' },
    // tier 4: 50 invitații — bonus 150 credite + 30k voice
    { minReferrals: 50,  name: 'Elite',           icon: '👑', perReferral: 10, bonus: 150,  bonusVoice: 30000,  badge: 'Elite' },
    // tier 5: 100 invitații — bonus 400 credite + 80k voice
    { minReferrals: 100, name: 'Legend',           icon: '🏆', perReferral: 10, bonus: 400,  bonusVoice: 80000,  badge: 'Legend' },
    // tier 6: 250 invitații — bonus 1000 credite + 200k voice
    { minReferrals: 250, name: 'Titan',            icon: '🚀', perReferral: 12, bonus: 1000, bonusVoice: 200000, badge: 'Titan' },
    // tier 7: 500 invitații — bonus 2500 credite + 500k voice + badge permanent
    { minReferrals: 500, name: 'Viralio Partner',  icon: '🌟', perReferral: 15, bonus: 2500, bonusVoice: 500000, badge: 'Partner' },
];

function getCurrentTier(count) {
    let tier = 0;
    for (let i = REFERRAL_TIERS.length - 1; i >= 0; i--) {
        if (count >= REFERRAL_TIERS[i].minReferrals) { tier = i; break; }
    }
    return tier;
}

function getPerReferralCredits(count) {
    return REFERRAL_TIERS[getCurrentTier(count)].perReferral;
}

// Anti-fraud: max referrals per IP in 24h
const REFERRAL_IP_LIMIT = 3;
const REFERRAL_IP_WINDOW_MS = 24 * 60 * 60 * 1000; // 24h

console.log('📋 PLANS:', JSON.stringify(PLANS));
console.log('📋 TOPUP:', JSON.stringify(TOPUP));
console.log('📋 WEBHOOK_SECRET:', endpointSecret ? endpointSecret.substring(0, 12) + '...' : 'LIPSESTE!');

// ══════════════════════════════════════════════════════════════
// ██ WEBHOOK STRIPE (trebuie ÎNAINTE de express.json!)
// ══════════════════════════════════════════════════════════════
app.post('/api/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    } catch (err) {
        console.error('❌ WEBHOOK SIGNATURE ERROR:', err.message);
        return res.status(400).send('Webhook Error: ' + err.message);
    }

    console.log('📨 WEBHOOK PRIMIT:', event.type);

    try {
        if (event.type === 'invoice.payment_succeeded') {
            const invoice = event.data.object;
            const subId = invoice.subscription
                || invoice.parent?.subscription_details?.subscription
                || invoice.lines?.data?.[0]?.subscription;

            console.log('💳 amount_paid=' + invoice.amount_paid + ' | subId=' + subId);

            if (invoice.amount_paid === 0) { console.log('⏭️ Skip: amount=0'); return res.sendStatus(200); }
            if (!subId) { console.log('⏭️ Skip: nu e subscription'); return res.sendStatus(200); }

            const sub = await stripe.subscriptions.retrieve(subId);
            const priceId = sub.items.data[0]?.price?.id;
            const planCfg = PLANS[priceId];
            if (!planCfg) { console.error('❌ PRICE ID NECUNOSCUT: ' + priceId); return res.sendStatus(200); }

            const customer = await stripe.customers.retrieve(invoice.customer);
            const email = customer.email;

            const user = await User.findOneAndUpdate(
                { email },
                {
                    credits: planCfg.credits, voice_characters: planCfg.chars,
                    stripeCustomerId: invoice.customer, subscriptionId: subId,
                    subscriptionPlan: planCfg.plan, subscriptionStatus: 'active',
                    currentPeriodEnd: new Date(sub.current_period_end * 1000),
                },
                { new: true }
            );
            if (user) console.log('✅ SUCCES: ' + email + ' plan=' + planCfg.plan);
            else console.error('❌ USER NEGASIT pentru: ' + email);
        }

        else if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            if (session.mode !== 'payment') { return res.sendStatus(200); }

            const topupPriceId = session.metadata?.topup_price_id;
            const creditsToAdd = topupPriceId ? TOPUP[topupPriceId] : null;
            if (!creditsToAdd) { console.error('❌ TOPUP metadata lipsa'); return res.sendStatus(200); }

            const email = session.customer_details?.email;
            if (!email) { console.error('❌ TOPUP email lipsa'); return res.sendStatus(200); }

            const user = await User.findOneAndUpdate(
                { email }, { $inc: { credits: creditsToAdd } }, { new: true }
            );
            if (user) console.log('✅ TOPUP +' + creditsToAdd + ' pentru ' + email + ' total=' + user.credits);
            else console.error('❌ TOPUP negasit: ' + email);
        }

        else if (event.type === 'customer.subscription.deleted') {
            const sub = event.data.object;
            const customer = await stripe.customers.retrieve(sub.customer);
            await User.findOneAndUpdate(
                { email: customer.email },
                { subscriptionId: null, subscriptionPlan: 'none', subscriptionStatus: 'canceled', currentPeriodEnd: null }
            );
            console.log('❌ SUB CANCELED: ' + customer.email);
        }

        else if (event.type === 'invoice.payment_failed') {
            const invoice = event.data.object;
            if (invoice.subscription) {
                const customer = await stripe.customers.retrieve(invoice.customer);
                await User.findOneAndUpdate({ email: customer.email }, { subscriptionStatus: 'past_due' });
                console.warn('⚠️ PAYMENT FAILED: ' + customer.email);
            }
        }
    } catch (err) {
        console.error('❌ EROARE WEBHOOK:', err.message);
    }

    res.sendStatus(200);
});

// ── MIDDLEWARE ───────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());
app.get('/open-in-browser', (req, res) => {
    res.sendFile(path.join(__dirname, 'tiktok-redirect.html'));
});
app.use(express.static(path.join(__dirname, 'public')));

const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Trebuie să fii logat!' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Sesiune expirată.' });
    }
};

// Middleware pentru apeluri interne (de la celelalte app-uri)
const authenticateInternal = (req, res, next) => {
    const apiKey = req.headers['x-internal-key'];
    if (!apiKey || apiKey !== INTERNAL_API_KEY) {
        return res.status(403).json({ error: 'Acces interzis.' });
    }
    next();
};

// ══════════════════════════════════════════════════════════════
// ██ AUTH — GOOGLE LOGIN (SINGURA SURSĂ!)
// ══════════════════════════════════════════════════════════════
app.post('/api/auth/google', async (req, res) => {
    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: req.body.credential,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        const payload = ticket.getPayload();
        let user = await User.findOne({ googleId: payload.sub });
        let isNewUser = false;

        if (!user) {
            const userCount = await User.countDocuments();
            if (userCount >= 800) {
                const dejaInLista = await Waitlist.findOne({ email: payload.email });
                if (!dejaInLista) await Waitlist.create({ email: payload.email, name: payload.name });
                return res.status(403).json({
                    error: 'BETA_FULL',
                    message: 'Locurile limitate pentru Beta s-au epuizat! Te-am adăugat pe lista de așteptare.',
                    discordLink: 'https://discord.gg/h8Ah6VKDzm'
                });
            }

            // Generează cod referral unic
            const referralCode = payload.name
                ? payload.name.split(' ')[0].toLowerCase().replace(/[^a-z0-9]/g, '') + crypto.randomBytes(3).toString('hex')
                : 'viralio' + crypto.randomBytes(4).toString('hex');

            // ── ANTI-FRAUD: captează IP-ul real ──
            const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
                || req.headers['x-real-ip']
                || req.connection?.remoteAddress
                || 'unknown';

            // Bonusuri de bază
            let bonusCredits = 0;
            let referredByCode = req.body.referralCode || null;
            let referralValid = false;

            // Verifică dacă codul de referral există + anti-fraud
            if (referredByCode) {
                const referrer = await User.findOne({ referralCode: referredByCode });
                if (!referrer || referrer.email === payload.email) {
                    referredByCode = null; // cod invalid sau auto-referral
                } else {
                    // ── ANTI-FRAUD CHECK 1: Același IP ──
                    // Câți useri cu referral de la ORICINE s-au înregistrat de pe acest IP în ultimele 24h?
                    const recentFromSameIp = await User.countDocuments({
                        registrationIp: clientIp,
                        referredBy: { $ne: null },
                        createdAt: { $gte: new Date(Date.now() - REFERRAL_IP_WINDOW_MS) }
                    });
                    if (clientIp !== 'unknown' && recentFromSameIp >= REFERRAL_IP_LIMIT) {
                        console.warn('🚫 ANTI-FRAUD: IP ' + clientIp + ' a depășit limita de referral (' + recentFromSameIp + ')');
                        referredByCode = null; // nu mai acordă bonus, dar lasă contul să se creeze
                    }

                    // ── ANTI-FRAUD CHECK 2: Același domeniu email ──
                    if (referredByCode) {
                        const refDomain = referrer.email.split('@')[1];
                        const newDomain = payload.email.split('@')[1];
                        // Blochează doar domenii custom (nu gmail/yahoo/hotmail etc.)
                        const commonDomains = ['gmail.com','googlemail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','protonmail.com','live.com','mail.com','aol.com','proton.me'];
                        if (refDomain === newDomain && !commonDomains.includes(refDomain)) {
                            console.warn('🚫 ANTI-FRAUD: Același domeniu custom ' + refDomain);
                            referredByCode = null;
                        }
                    }

                    // ── ANTI-FRAUD CHECK 3: Referrerul își invită propriul IP ──
                    if (referredByCode && referrer.registrationIp === clientIp && clientIp !== 'unknown') {
                        console.warn('🚫 ANTI-FRAUD: Referrer IP identic cu noul user (' + clientIp + ')');
                        referredByCode = null;
                    }

                    if (referredByCode) {
                        bonusCredits = 3;
                        referralValid = true;
                    }
                }
            }

            user = new User({
                googleId: payload.sub, email: payload.email,
                name: payload.name, picture: payload.picture,
                credits: 10 + bonusCredits, voice_characters: 3000,
                referralCode: referralCode,
                referredBy: referredByCode,
                registrationIp: clientIp,
            });
            await user.save();
            isNewUser = true;

            // Acordă credite referrerului — TIER-AWARE
            if (referralValid && referredByCode) {
                const referrer = await User.findOne({ referralCode: referredByCode });
                if (referrer) {
                    const newCount = (referrer.referralCount || 0) + 1;
                    const creditsForThis = getPerReferralCredits(newCount);
                    const newTier = getCurrentTier(newCount);

                    // Calculează bonus de tier dacă tocmai a avansat
                    let tierBonus = 0;
                    let tierBonusVoice = 0;
                    const claimed = referrer.referralBonusesClaimed || [];
                    if (newTier > 0 && !claimed.includes(newTier)) {
                        tierBonus = REFERRAL_TIERS[newTier].bonus;
                        tierBonusVoice = REFERRAL_TIERS[newTier].bonusVoice;
                    }

                    const updateOps = {
                        $inc: {
                            credits: creditsForThis + tierBonus,
                            referralCount: 1,
                            referralCreditsEarned: creditsForThis + tierBonus,
                            voice_characters: tierBonusVoice,
                        },
                        referralTier: newTier,
                    };
                    if (tierBonus > 0) {
                        updateOps.$addToSet = { referralBonusesClaimed: newTier };
                    }

                    await User.findOneAndUpdate({ referralCode: referredByCode }, updateOps);
                    console.log('🎁 REFERRAL: ' + payload.email + ' invitat de ' + referredByCode
                        + ' | +' + creditsForThis + 'cr'
                        + (tierBonus ? ' + TIER BONUS +' + tierBonus + 'cr +' + tierBonusVoice + 'voice' : '')
                        + ' | tier=' + newTier + ' count=' + newCount);
                }
            }
        }

        // Dacă userul existent nu are referralCode, generează-i unul
        if (!user.referralCode) {
            for (let attempt = 0; attempt < 3; attempt++) {
                try {
                    const referralCode = user.name
                        ? user.name.split(' ')[0].toLowerCase().replace(/[^a-z0-9]/g, '') + crypto.randomBytes(3).toString('hex')
                        : 'viralio' + crypto.randomBytes(4).toString('hex');
                    user.referralCode = referralCode;
                    await user.save();
                    break;
                } catch (e) {
                    if (e.code === 11000 && attempt < 2) continue;
                    console.error('⚠️ Eroare generare referralCode:', e.message);
                    break;
                }
            }
        }

        // ── EARLY ACCESS CHECK ──
        if (!user.earlyAccess) {
            return res.status(403).json({
                error: 'EARLY_ACCESS',
                message: 'Nu ai primit încă acces early. Vei fi notificat când contul tău este activat.',
                email: user.email,
                name: user.name,
                picture: user.picture,
            });
        }

        const sessionToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({
            token: sessionToken,
            isNewUser,
            user: {
                name: user.name, picture: user.picture,
                credits: user.credits, voice_characters: user.voice_characters,
                email: user.email, subscriptionPlan: user.subscriptionPlan,
                subscriptionStatus: user.subscriptionStatus,
                referralCode: user.referralCode,
            }
        });
    } catch (error) {
        console.error(error);
        res.status(400).json({ error: 'Eroare Google' });
    }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User inexistent.' });
    if (!user.earlyAccess) return res.status(403).json({ error: 'EARLY_ACCESS' });
    res.json({
        user: {
            name: user.name, picture: user.picture,
            credits: user.credits, voice_characters: user.voice_characters,
            email: user.email, subscriptionPlan: user.subscriptionPlan,
            subscriptionStatus: user.subscriptionStatus,
            currentPeriodEnd: user.currentPeriodEnd,
            referralCode: user.referralCode,
        }
    });
});

// ══════════════════════════════════════════════════════════════
// ██ ENDPOINTURI INTER-SERVICII (apelate de celelalte app-uri)
// ══════════════════════════════════════════════════════════════

// 1. Verificare token — celelalte app-uri trimit JWT-ul userului, HUB-ul îl validează
app.post('/api/internal/verify-token', authenticateInternal, async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token lipsă.' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(404).json({ error: 'User inexistent.' });

        res.json({
            userId: user._id,
            user: {
                name: user.name, picture: user.picture,
                credits: user.credits, voice_characters: user.voice_characters,
                email: user.email, subscriptionPlan: user.subscriptionPlan,
                subscriptionStatus: user.subscriptionStatus,
            }
        });
    } catch (e) {
        return res.status(401).json({ error: 'Token invalid sau expirat.' });
    }
});

// 2. Scade credite — atomic, cu verificare $gte
app.post('/api/internal/use-credits', authenticateInternal, async (req, res) => {
    const { userId, amount } = req.body;
    if (!userId || !amount || amount <= 0) return res.status(400).json({ error: 'userId și amount sunt obligatorii.' });

    const user = await User.findOneAndUpdate(
        { _id: userId, credits: { $gte: amount } },
        { $inc: { credits: -amount } },
        { new: true }
    );

    if (!user) {
        // Verificăm dacă nu exista sau nu avea credite
        const exists = await User.findById(userId);
        if (!exists) return res.status(404).json({ error: 'User inexistent.' });
        return res.status(403).json({ error: 'Credite insuficiente.', credits: exists.credits });
    }

    res.json({ credits: user.credits });
});

// 3. Scade voice_characters — atomic
app.post('/api/internal/use-voice-chars', authenticateInternal, async (req, res) => {
    const { userId, amount } = req.body;
    if (!userId || !amount || amount <= 0) return res.status(400).json({ error: 'userId și amount sunt obligatorii.' });

    const user = await User.findOneAndUpdate(
        { _id: userId, voice_characters: { $gte: amount } },
        { $inc: { voice_characters: -amount } },
        { new: true }
    );

    if (!user) {
        const exists = await User.findById(userId);
        if (!exists) return res.status(404).json({ error: 'User inexistent.' });
        return res.status(403).json({ error: 'Caractere voce insuficiente.', voice_characters: exists.voice_characters });
    }

    res.json({ voice_characters: user.voice_characters });
});

// 4. Verifică credite (fără a le scădea)
app.post('/api/internal/check-credits', authenticateInternal, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId obligatoriu.' });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User inexistent.' });

    res.json({ credits: user.credits, voice_characters: user.voice_characters });
});

// 5. Returnează info user complet (pentru /api/auth/me pe sub-app-uri)
app.post('/api/internal/user-info', authenticateInternal, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId obligatoriu.' });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User inexistent.' });

    res.json({
        user: {
            name: user.name, picture: user.picture,
            credits: user.credits, voice_characters: user.voice_characters,
            email: user.email, subscriptionPlan: user.subscriptionPlan,
            subscriptionStatus: user.subscriptionStatus,
            currentPeriodEnd: user.currentPeriodEnd,
            referralCode: user.referralCode,
        }
    });
});

// ══════════════════════════════════════════════════════════════
// ██ REFERRAL SYSTEM
// ══════════════════════════════════════════════════════════════

// Migration: generează referralCode pentru toți userii existenți care nu au
// Apelează o singură dată: POST /api/internal/migrate-referral-codes
app.post('/api/internal/migrate-referral-codes', authenticateInternal, async (req, res) => {
    try {
        const usersWithout = await User.find({ $or: [{ referralCode: null }, { referralCode: { $exists: false } }] });
        let updated = 0;
        for (const u of usersWithout) {
            for (let attempt = 0; attempt < 3; attempt++) {
                try {
                    const code = u.name
                        ? u.name.split(' ')[0].toLowerCase().replace(/[^a-z0-9]/g, '') + crypto.randomBytes(3).toString('hex')
                        : 'viralio' + crypto.randomBytes(4).toString('hex');
                    u.referralCode = code;
                    await u.save();
                    updated++;
                    break;
                } catch (e) {
                    if (e.code === 11000 && attempt < 2) continue;
                    console.error('⚠️ Migration skip ' + u.email + ':', e.message);
                    break;
                }
            }
        }
        res.json({ message: `Migration completă. ${updated}/${usersWithout.length} useri actualizați.` });
    } catch (e) {
        console.error('❌ Migration error:', e);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/referral/info', authenticate, async (req, res) => {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User inexistent.' });

    // Dacă userul nu are referralCode, generează-i unul acum
    if (!user.referralCode) {
        const code = user.name
            ? user.name.split(' ')[0].toLowerCase().replace(/[^a-z0-9]/g, '') + crypto.randomBytes(3).toString('hex')
            : 'viralio' + crypto.randomBytes(4).toString('hex');
        user.referralCode = code;
        await user.save();
    }

    const count = user.referralCount || 0;
    const currentTier = getCurrentTier(count);
    const nextTierIdx = currentTier < REFERRAL_TIERS.length - 1 ? currentTier + 1 : null;
    const claimed = user.referralBonusesClaimed || [];

    // IMPORTANT: doar caută invitații dacă referralCode e valid
    let referredUsers = [];
    if (user.referralCode) {
        referredUsers = await User.find({ referredBy: user.referralCode })
            .select('name picture createdAt')
            .sort({ createdAt: -1 })
            .limit(20)
            .lean();
    }

    res.json({
        referralCode: user.referralCode,
        referralLink: process.env.APP_URL + '/?ref=' + user.referralCode,
        referralCount: count,
        referralCreditsEarned: user.referralCreditsEarned || 0,
        // Tier system
        currentTier,
        currentTierData: REFERRAL_TIERS[currentTier],
        nextTier: nextTierIdx !== null ? REFERRAL_TIERS[nextTierIdx] : null,
        nextTierIndex: nextTierIdx,
        remainingForNext: nextTierIdx !== null ? REFERRAL_TIERS[nextTierIdx].minReferrals - count : 0,
        allTiers: REFERRAL_TIERS.map((t, i) => ({
            ...t,
            index: i,
            reached: count >= t.minReferrals,
            bonusClaimed: claimed.includes(i),
            current: i === currentTier,
        })),
        recentReferrals: referredUsers.map(u => ({
            name: u.name,
            picture: u.picture,
            date: u.createdAt,
        })),
    });
});

// ══════════════════════════════════════════════════════════════
// ██ STRIPE ROUTES
// ══════════════════════════════════════════════════════════════
app.post('/api/stripe/subscribe', authenticate, async (req, res) => {
    const { plan } = req.body;
    const interval = req.body.interval || 'monthly';
    const priceMap = {
        starter: interval === 'yearly' ? process.env.STRIPE_PRICE_STARTER_YEARLY : process.env.STRIPE_PRICE_STARTER,
        creator: interval === 'yearly' ? process.env.STRIPE_PRICE_CREATOR_YEARLY : process.env.STRIPE_PRICE_CREATOR,
        agency:  interval === 'yearly' ? process.env.STRIPE_PRICE_AGENCY_YEARLY  : process.env.STRIPE_PRICE_AGENCY,
    };
    const priceId = priceMap[plan];
    if (!priceId) return res.status(400).json({ error: 'Plan invalid' });

    const user = await User.findById(req.userId);
    try {
        const sessionParams = {
            mode: 'subscription',
            line_items: [{ price: priceId, quantity: 1 }],
            success_url: process.env.APP_URL + '/?subscribed=1',
            cancel_url:  process.env.APP_URL + '/#pricing',
            metadata: { userId: user._id.toString() },
            subscription_data: { metadata: { userId: user._id.toString() } },
        };
        if (user.stripeCustomerId) sessionParams.customer = user.stripeCustomerId;
        else sessionParams.customer_email = user.email;

        const session = await stripe.checkout.sessions.create(sessionParams);
        res.json({ url: session.url });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Eroare Stripe' });
    }
});

app.post('/api/stripe/topup', authenticate, async (req, res) => {
    const { package: pkg } = req.body;
    const topupMap = {
        micro:    { priceId: process.env.STRIPE_PRICE_TOPUP_50,  credits: 50  },
        standard: { priceId: process.env.STRIPE_PRICE_TOPUP_150, credits: 150 },
        pro:      { priceId: process.env.STRIPE_PRICE_TOPUP_400, credits: 400 },
    };
    const topup = topupMap[pkg];
    if (!topup) return res.status(400).json({ error: 'Pachet invalid' });

    const user = await User.findById(req.userId);
    const isSubscriber = user.subscriptionStatus === 'active';
    try {
        const sessionParams = {
            mode: 'payment',
            line_items: [{ price: topup.priceId, quantity: 1 }],
            success_url: process.env.APP_URL + '/?topup=1',
            cancel_url:  process.env.APP_URL + '/',
            metadata: { topup_price_id: topup.priceId, userId: user._id.toString() },
            payment_intent_data: { metadata: { topup_price_id: topup.priceId } },
        };
        if (user.stripeCustomerId) sessionParams.customer = user.stripeCustomerId;
        else sessionParams.customer_email = user.email;
        if (isSubscriber) sessionParams.discounts = [{ coupon: process.env.STRIPE_COUPON_SUBSCRIBER_10 }];

        const session = await stripe.checkout.sessions.create(sessionParams);
        res.json({ url: session.url, discount: isSubscriber });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Eroare Stripe' });
    }
});

app.use((req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log('🚀 HUB rulează pe portul ' + PORT));