require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');

const app = express();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

const PORT = process.env.PORT || 3000;
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ─────────────────────────────────────────────
// 1. BAZĂ DE DATE & MODELE
// ─────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Conectat la MongoDB! (HUB CENTRAL)'))
    .catch(err => console.error('❌ Eroare MongoDB:', err));

const UserSchema = new mongoose.Schema({
    googleId:         { type: String, required: true, unique: true },
    email:            { type: String, required: true },
    name:             String,
    picture:          String,
    credits:          { type: Number, default: 10 },
    voice_characters: { type: Number, default: 3000 },
    // Subscription info
    stripeCustomerId:   { type: String, default: null },
    subscriptionId:     { type: String, default: null },
    subscriptionPlan:   { type: String, enum: ['none','starter','creator','agency'], default: 'none' },
    subscriptionStatus: { type: String, default: 'inactive' }, // active | past_due | canceled | inactive
    currentPeriodEnd:   { type: Date, default: null },
    createdAt:          { type: Date, default: Date.now }
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

const WaitlistSchema = new mongoose.Schema({
    email: String, name: String, date: { type: Date, default: Date.now }
});
const Waitlist = mongoose.model('Waitlist', WaitlistSchema);


// ─────────────────────────────────────────────
// PLAN CONFIG  (sursa unică de adevăr)
// ─────────────────────────────────────────────
const PLANS = {
    // price_id → { plan, credits, chars }
    [process.env.STRIPE_PRICE_STARTER]:  { plan: 'starter',  credits: 150,  chars: 50000  },
    [process.env.STRIPE_PRICE_CREATOR]:  { plan: 'creator',  credits: 400,  chars: 150000 },
    [process.env.STRIPE_PRICE_AGENCY]:   { plan: 'agency',   credits: 1500, chars: 500000 },
};

// Top-up pachete (price_id → credite extra)
const TOPUP = {
    [process.env.STRIPE_PRICE_TOPUP_50]:  50,
    [process.env.STRIPE_PRICE_TOPUP_150]: 150,
    [process.env.STRIPE_PRICE_TOPUP_400]: 400,
};


// ─────────────────────────────────────────────
// 2. STRIPE WEBHOOK  (înainte de express.json!)
// ─────────────────────────────────────────────
app.post('/api/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    } catch (err) {
        console.error(`❌ Webhook signature error: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
        switch (event.type) {

            // ── Abonament nou activat (prima plată) sau reînnoire lunară ──────
case 'invoice.payment_succeeded': {
    const invoice = event.data.object;
    
    // LOG TEMPORAR - șterge după debug
    const fs = require('fs');
    fs.appendFileSync('/root/webhook-debug.txt', 
        `\n--- ${new Date().toISOString()} ---\n` +
        `amount_paid: ${invoice.amount_paid}\n` +
        `subscription: ${invoice.subscription}\n` +
        `customer: ${invoice.customer}\n` +
        `PLANS keys: ${JSON.stringify(Object.keys(PLANS))}\n`
    );
    
    if (invoice.amount_paid === 0) break;
    if (!invoice.subscription) break;

    const sub = await stripe.subscriptions.retrieve(invoice.subscription);
    const priceId = sub.items.data[0]?.price?.id;
    
    fs.appendFileSync('/root/webhook-debug.txt', 
        `priceId din Stripe: ${priceId}\n` +
        `planCfg găsit: ${JSON.stringify(PLANS[priceId])}\n`
    );
    
    // ... restul codului rămâne la fel
                if (invoice.amount_paid === 0) break;
                // Funcționează doar pentru subscriptions, nu one-time
                if (!invoice.subscription) break;

                const sub = await stripe.subscriptions.retrieve(invoice.subscription);
                const priceId = sub.items.data[0]?.price?.id;
                const planCfg = PLANS[priceId];
                if (!planCfg) {
                    console.warn(`⚠️ Price ID necunoscut în subscription: ${priceId}`);
                    break;
                }

                const customerId = invoice.customer;
                const customer = await stripe.customers.retrieve(customerId);
                const email = customer.email;

                // RESET credite la valoarea planului + setare chars
                const user = await User.findOneAndUpdate(
                    { email },
                    {
                        credits: planCfg.credits,          // RESET, nu increment
                        voice_characters: planCfg.chars,   // RESET
                        stripeCustomerId:   customerId,
                        subscriptionId:     invoice.subscription,
                        subscriptionPlan:   planCfg.plan,
                        subscriptionStatus: 'active',
                        currentPeriodEnd:   new Date(sub.current_period_end * 1000),
                    },
                    { new: true }
                );

                if (user) {
                    console.log(`🔄 [SUB RENEWED] ${email} → plan=${planCfg.plan} | cr=${planCfg.credits} | chars=${planCfg.chars}`);
                } else {
                    console.warn(`⚠️ [SUB] Email ${email} nu există în DB`);
                }
                break;
            }

            // ── Top-up one-time (Stripe Checkout Session) ────────────────────
            case 'checkout.session.completed': {
                const session = event.data.object;
                // Procesăm DOAR sesiunile de tip 'payment' (one-time top-up)
                // Sesiunile de tip 'subscription' sunt gestionate de invoice.payment_succeeded
                if (session.mode !== 'payment') break;

                const topupPriceId = session.metadata?.topup_price_id;
                const creditsToAdd = topupPriceId ? TOPUP[topupPriceId] : null;

                if (!creditsToAdd) {
                    console.warn(`⚠️ [TOPUP] metadata.topup_price_id lipsă sau necunoscut`);
                    break;
                }

                const email = session.customer_details?.email;
                if (!email) break;

                const user = await User.findOneAndUpdate(
                    { email },
                    { $inc: { credits: creditsToAdd } },
                    { new: true }
                );

                if (user) {
                    console.log(`💰 [TOPUP] +${creditsToAdd} credite pentru ${email} (total: ${user.credits})`);
                } else {
                    console.warn(`⚠️ [TOPUP] Email ${email} nu există în DB`);
                }
                break;
            }

            // ── Abonament anulat / expirat ────────────────────────────────────
            case 'customer.subscription.deleted': {
                const sub = event.data.object;
                const customerId = sub.customer;
                const customer = await stripe.customers.retrieve(customerId);

                await User.findOneAndUpdate(
                    { email: customer.email },
                    {
                        subscriptionId:     null,
                        subscriptionPlan:   'none',
                        subscriptionStatus: 'canceled',
                        currentPeriodEnd:   null,
                    }
                );
                console.log(`❌ [SUB CANCELED] ${customer.email}`);
                break;
            }

            // ── Plată eșuată (card expirat etc.) ─────────────────────────────
            case 'invoice.payment_failed': {
                const invoice = event.data.object;
                if (!invoice.subscription) break;
                const customer = await stripe.customers.retrieve(invoice.customer);
                await User.findOneAndUpdate(
                    { email: customer.email },
                    { subscriptionStatus: 'past_due' }
                );
                console.warn(`⚠️ [PAYMENT FAILED] ${customer.email}`);
                break;
            }

            default:
                // Ignorăm celelalte events
                break;
        }
    } catch (err) {
        console.error('❌ Eroare procesare webhook:', err);
        // Returnăm 200 oricum ca Stripe să nu retrimită
    }

    res.sendStatus(200);
});


// ─────────────────────────────────────────────
// 3. MIDDLEWARE GENERALE
// ─────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());
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


// ─────────────────────────────────────────────
// 4. RUTE AUTENTIFICARE
// ─────────────────────────────────────────────
app.post('/api/auth/google', async (req, res) => {
    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: req.body.credential,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        const payload = ticket.getPayload();

        let user = await User.findOne({ googleId: payload.sub });

        if (!user) {
            const userCount = await User.countDocuments();
            if (userCount >= 380) {
                const dejaInLista = await Waitlist.findOne({ email: payload.email });
                if (!dejaInLista) {
                    await Waitlist.create({ email: payload.email, name: payload.name });
                }
                return res.status(403).json({
                    error: 'BETA_FULL',
                    message: 'Locurile limitate pentru Beta s-au epuizat! Te-am adăugat pe lista de așteptare.',
                    discordLink: 'https://discord.gg/h8Ah6VKDzm'
                });
            }

            user = new User({
                googleId: payload.sub,
                email: payload.email,
                name: payload.name,
                picture: payload.picture,
                credits: 10,
                voice_characters: 3000
            });
            await user.save();
        }

        const sessionToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({
            token: sessionToken,
            user: {
                name:             user.name,
                picture:          user.picture,
                credits:          user.credits,
                voice_characters: user.voice_characters,
                email:            user.email,
                subscriptionPlan:   user.subscriptionPlan,
                subscriptionStatus: user.subscriptionStatus,
            }
        });
    } catch (error) {
        console.error(error);
        res.status(400).json({ error: 'Eroare Google' });
    }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
    const user = await User.findById(req.userId);
    res.json({
        user: {
            name:             user.name,
            picture:          user.picture,
            credits:          user.credits,
            voice_characters: user.voice_characters,
            email:            user.email,
            subscriptionPlan:   user.subscriptionPlan,
            subscriptionStatus: user.subscriptionStatus,
            currentPeriodEnd:   user.currentPeriodEnd,
        }
    });
});


// ─────────────────────────────────────────────
// 5. RUTE STRIPE – creare sesiuni Checkout
// ─────────────────────────────────────────────

// Abonament (subscription)
app.post('/api/stripe/subscribe', authenticate, async (req, res) => {
    const { plan } = req.body;
    const priceMap = {
        starter: process.env.STRIPE_PRICE_STARTER,
        creator: process.env.STRIPE_PRICE_CREATOR,
        agency:  process.env.STRIPE_PRICE_AGENCY,
    };
    const priceId = priceMap[plan];
    if (!priceId) return res.status(400).json({ error: 'Plan invalid' });

    const user = await User.findById(req.userId);

    try {
        const sessionParams = {
            mode: 'subscription',
            line_items: [{ price: priceId, quantity: 1 }],
            success_url: `${process.env.APP_URL}/?subscribed=1`,
            cancel_url:  `${process.env.APP_URL}/#pricing`,
            metadata: { userId: user._id.toString() },
            subscription_data: {
                metadata: { userId: user._id.toString() }
            },
        };

        // Dacă userul are deja un customer Stripe, îl reutilizăm
        if (user.stripeCustomerId) {
            sessionParams.customer = user.stripeCustomerId;
        } else {
            sessionParams.customer_email = user.email;
        }

        const session = await stripe.checkout.sessions.create(sessionParams);
        res.json({ url: session.url });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Eroare Stripe' });
    }
});

// Top-up (one-time payment)
app.post('/api/stripe/topup', authenticate, async (req, res) => {
    const { package: pkg } = req.body; // 'micro' | 'standard' | 'pro'

    const topupMap = {
        micro:    { priceId: process.env.STRIPE_PRICE_TOPUP_50,  credits: 50,  label: '50 Credite Top-up'  },
        standard: { priceId: process.env.STRIPE_PRICE_TOPUP_150, credits: 150, label: '150 Credite Top-up' },
        pro:      { priceId: process.env.STRIPE_PRICE_TOPUP_400, credits: 400, label: '400 Credite Top-up' },
    };

    const topup = topupMap[pkg];
    if (!topup) return res.status(400).json({ error: 'Pachet invalid' });

    const user = await User.findById(req.userId);
    const isSubscriber = user.subscriptionStatus === 'active';

    try {
        // Dacă e abonat, aplicăm 10% reducere prin discount Stripe
        const discounts = isSubscriber
            ? [{ coupon: process.env.STRIPE_COUPON_SUBSCRIBER_10 }]
            : [];

        const sessionParams = {
            mode: 'payment',
            line_items: [{ price: topup.priceId, quantity: 1 }],
            success_url: `${process.env.APP_URL}/?topup=1`,
            cancel_url:  `${process.env.APP_URL}/`,
            metadata: {
                topup_price_id: topup.priceId,
                userId: user._id.toString()
            },
            payment_intent_data: {
                metadata: { topup_price_id: topup.priceId }
            },
        };

        if (user.stripeCustomerId) {
            sessionParams.customer = user.stripeCustomerId;
        } else {
            sessionParams.customer_email = user.email;
        }

        if (discounts.length > 0) {
            sessionParams.discounts = discounts;
        }

        const session = await stripe.checkout.sessions.create(sessionParams);
        res.json({ url: session.url, discount: isSubscriber });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Eroare Stripe' });
    }
});


// ─────────────────────────────────────────────
// 6. CATCH-ALL FRONTEND
// ─────────────────────────────────────────────
app.use((req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`🚀 HUB rulează pe portul ${PORT}`));