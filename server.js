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

// 🚨 TREBUIE SĂ FIE ÎNAINTE DE app.use(express.json()) !!!
app.post('/api/webhook/stripe', express.raw({type: 'application/json'}), async (request, response) => {
    const sig = request.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(request.body, sig, endpointSecret);
    } catch (err) {
        console.error(`❌ Eroare Stripe Webhook: ${err.message}`);
        return response.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const customerEmail = session.customer_details.email;
        const amountPaid = session.amount_total; 

        let creditsToAdd = 0;
        let charsToAdd = 0;
        
        // Pachet Starter (49.90 RON) -> 150 credite / 50k caractere
        if (amountPaid === 4990) { creditsToAdd = 150; charsToAdd = 50000; }
        // Pachet Creator PRO (99.90 RON) -> 400 credite / 150k caractere
        else if (amountPaid === 9990) { creditsToAdd = 400; charsToAdd = 150000; }
        // Pachet Agency (249.90 RON) -> 1500 credite / 500k caractere
        else if (amountPaid === 24990) { creditsToAdd = 1500; charsToAdd = 500000; }

        if (creditsToAdd > 0 && customerEmail) {
            try {
                await User.findOneAndUpdate(
                    { email: customerEmail },
                    { 
                        $inc: { 
                            credits: creditsToAdd,
                            voice_characters: charsToAdd 
                        } 
                    }
                );
                console.log(`💰 [STRIPE SUCCES] Am adăugat ${creditsToAdd} cr / ${charsToAdd} litere pentru ${customerEmail}`);
            } catch (err) {
                console.error("Eroare la adaugarea creditelor:", err);
            }
        }
    }

    response.send();
});

const PORT = process.env.PORT || 3000;
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// BAZA DE DATE
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Conectat la MongoDB! (HUB CENTRAL)'))
    .catch(err => console.error('❌ Eroare MongoDB:', err));

// 1. Schema unică, completă și identică pe toate aplicațiile
const UserSchema = new mongoose.Schema({
    googleId: { type: String, required: true, unique: true },
    email: { type: String, required: true },
    name: String,
    picture: String,
    credits: { type: Number, default: 10 }, // Universal: 10 credite
    voice_characters: { type: Number, default: 3000 }, // Universal: 3000 caractere
    createdAt: { type: Date, default: Date.now }
});

// 2. Crearea modelului (Atenție la o eroare comună în Mongoose unde re-definirea aruncă eroare)
const User = mongoose.models.User || mongoose.model('User', UserSchema);

const WaitlistSchema = new mongoose.Schema({
    email: String, name: String, date: { type: Date, default: Date.now }
});
const Waitlist = mongoose.model('Waitlist', WaitlistSchema);

const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Trebuie să fii logat!" });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (e) { return res.status(401).json({ error: "Sesiune expirată." }); }
};

// RUTE AUTH (Folosite de index.html-ul de pe HUB)
app.post('/api/auth/google', async (req, res) => {
    try {
        const ticket = await googleClient.verifyIdToken({ idToken: req.body.credential, audience: process.env.GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        
        let user = await User.findOne({ googleId: payload.sub });
        
        if (!user) {
            const userCount = await User.countDocuments();
            if (userCount >= 12) {
                const dejaInLista = await Waitlist.findOne({ email: payload.email });
                if (!dejaInLista) {
                    await Waitlist.create({ email: payload.email, name: payload.name });
                }
                return res.status(403).json({ error: 'BETA_FULL', message: 'Locurile sunt epuizate!' });
            }

            user = new User({ 
                googleId: payload.sub, email: payload.email, name: payload.name, picture: payload.picture, 
                credits: 10, voice_characters: 3000 
            });
            await user.save();
        }
        
        const sessionToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token: sessionToken, user: { name: user.name, picture: user.picture, credits: user.credits, voice_characters: user.voice_characters, email: user.email } });
    } catch (error) { 
        console.error(error);
        res.status(400).json({ error: "Eroare Google" }); 
    }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
    const user = await User.findById(req.userId);
    res.json({ user: { name: user.name, picture: user.picture, credits: user.credits, voice_characters: user.voice_characters, email: user.email } });
});

// AICI SE RETURNEAZA FRONTEND-UL (HUB)
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`🚀 HUB rulează pe portul ${PORT}`));