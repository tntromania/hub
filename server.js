require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const OpenAI = require('openai');
const mongoose = require('mongoose');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// SETĂRI PENTRU VPS COOLIFY
const YTDLP_PATH = '/usr/local/bin/yt-dlp';
const DOWNLOAD_DIR = path.join(__dirname, 'downloads');
if (!fs.existsSync(DOWNLOAD_DIR)) fs.mkdirSync(DOWNLOAD_DIR);

// FIX CORS: Permitem orice domeniu, pentru ca oricum securitatea sta in JWT (Token)
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// BAZA DE DATE & SCHEME (USER + CACHE)
// ==========================================
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Conectat la MongoDB!'))
    .catch(err => console.error('❌ Eroare MongoDB:', err));

const UserSchema = new mongoose.Schema({
    googleId: String,
    email: String,
    name: String,
    picture: String,
    credits: { type: Number, default: 3 },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// NOU: Schema pentru Cache (Se sterge singura dupa 24h)
const CacheSchema = new mongoose.Schema({
    videoId: String,
    originalText: String,
    translatedText: String,
    createdAt: { type: Date, expires: 86400, default: Date.now }
});
const VideoCache = mongoose.model('VideoCache', CacheSchema);

// ==========================================
// PROXY DATAIMPULSE & BYPASS
// ==========================================
const PROXY_URL = `http://7e96441a0204cbbea090:31a09abfc490dcd7@gw.dataimpulse.com:823`;
const proxyArg = `--proxy "${PROXY_URL}"`;
const bypassArgs = `--force-ipv4 --extractor-args "youtube:player_client=android,web" --no-warnings`;

// ==========================================
// MIDDLEWARE AUTENTIFICARE
// ==========================================
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Trebuie să fii logat!" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (e) {
        return res.status(401).json({ error: "Sesiune expirată. Te rog loghează-te din nou." });
    }
};

// ==========================================
// RUTELE DE API
// ==========================================

// EXEMPLU LOGICĂ PE SERVER (Node.js)
app.post('/api/auth/google', async (req, res) => {
    // ... verifici tokenul google (ticket-ul) ...
    const { email, name, picture } = payload;

    // 1. Verifici daca userul exista deja
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

    if (user) {
        // Userul e vechi (unul din primii 5). Il lasi sa intre.
        const token = generateJWT(user);
        return res.json({ token, user });
    } else {
        // E un user NOU. Verifici cati useri exista in total.
        const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get().count;

        if (userCount >= 5) {
            // S-AU UMPLUT LOCURILE!
            return res.status(403).json({ error: 'BETA_FULL', message: 'Locurile pentru Early Access s-au epuizat!' });
        }

        // Daca sunt sub 5, il adaugi in baza de date (cu 5 credite)
        db.prepare("INSERT INTO users (email, name, picture, credits) VALUES (?, ?, ?, 5)").run(email, name, picture);
        // ... generezi token si returnezi ...
    }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
    const user = await User.findById(req.userId);
    res.json({ user: { name: user.name, picture: user.picture, credits: user.credits } });
});

// FUNCTIE: Descarcare Video
const downloadVideo = (url, outputPath) => {
    return new Promise((resolve, reject) => {
        const command = `"${YTDLP_PATH}" ${proxyArg} ${bypassArgs} -f "b[ext=mp4]/best" -o "${outputPath}" --no-check-certificates --no-playlist "${url}"`;
        exec(command, { maxBuffer: 1024 * 1024 * 10, timeout: 180000 }, (error, stdout, stderr) => {
            if (error) reject(new Error("Serverul YouTube a refuzat conexiunea video."));
            else resolve();
        });
    });
};

// FUNCTIE: Transcript & GPT
const getTranscriptAndTranslation = async (url) => {
    return new Promise((resolve) => {
        const command = `"${YTDLP_PATH}" ${proxyArg} ${bypassArgs} --write-auto-sub --skip-download --sub-lang en,ro --convert-subs vtt --output "${path.join(DOWNLOAD_DIR, 'temp_%(id)s')}" "${url}"`;
        
        exec(command, { maxBuffer: 1024 * 1024 * 10, timeout: 60000 }, async (err) => {
            const files = fs.readdirSync(DOWNLOAD_DIR).filter(f => f.startsWith('temp_') && f.endsWith('.vtt'));
            let originalText = "";
            
            if (files.length === 0) {
                return resolve({ original: "Nu s-a găsit subtitrare.", translated: "Nu există text de tradus." });
            }
            
            const vttPath = path.join(DOWNLOAD_DIR, files[0]);
            let content = fs.readFileSync(vttPath, 'utf8');
            
            content = content.replace(/WEBVTT/gi, '').replace(/Kind:[^\n]+/gi, '').replace(/Language:[^\n]+/gi, '')
                .replace(/align:[^\n]+/gi, '').replace(/position:[^\n]+/gi, '')
                .replace(/(\d{2}:\d{2}:\d{2}\.\d{3}\s*-->\s*\d{2}:\d{2}:\d{2}\.\d{3}.*)/g, '')
                .replace(/<[^>]*>/g, '').replace(/\[Music\]/gi, '').replace(/\[Muzică\]/gi, '');

            originalText = [...new Set(content.split('\n').map(l => l.trim()).filter(l => l.length > 2))].join(' ');
            fs.unlinkSync(vttPath);

            try {
                const completion = await openai.chat.completions.create({
                    messages: [
                        { role: "system", content: "Ești un traducător profesionist. Tradu textul în limba română. Returnează DOAR traducerea textului, fără absolut nicio altă explicație." },
                        { role: "user", content: originalText.substring(0, 10000) }
                    ],
                    model: "gpt-4o-mini", 
                });
                resolve({ original: originalText, translated: completion.choices[0].message.content });
            } catch (e) {
                resolve({ original: originalText, translated: "Eroare AI la traducere: " + e.message });
            }
        });
    });
};

// ENDPOINT PRINCIPAL PROCESARE
app.post('/api/process-yt', authenticate, async (req, res) => {
    let { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL lipsă' });

    const user = await User.findById(req.userId);
    if (user.credits <= 0) return res.status(403).json({ error: "Nu mai ai credite! Cumpără un pachet." });

    if (url.includes('/shorts/')) url = url.replace('/shorts/', '/watch?v=').split('&')[0].split('?feature')[0];
    
    // Extragem ID-ul real al videoclipului pentru Cache
    const videoIdMatch = url.match(/(?:v=|youtu\.be\/|shorts\/)([^&?]+)/);
    if (!videoIdMatch) return res.status(400).json({ error: "Link-ul de YouTube nu este valid." });
    const videoId = videoIdMatch[1];
    
    const outputPath = path.join(DOWNLOAD_DIR, `${videoId}.mp4`);

    try {
        // 1. VERIFICARE CACHE (ULTRA SPEED)
        const cachedData = await VideoCache.findOne({ videoId });
        if (cachedData && fs.existsSync(outputPath)) {
            console.log(`⚡ CACHE HIT pentru video: ${videoId}`);
            user.credits -= 1; // Taxam oricum, a primit rezultatul
            await user.save();
            return res.json({
                status: 'ok',
                downloadUrl: `/download/${videoId}.mp4`,
                originalText: cachedData.originalText,
                translatedText: cachedData.translatedText,
                creditsLeft: user.credits 
            });
        }

        console.log(`⏳ PROCESARE NOUA pentru video: ${videoId}`);

        // 2. PROCESARE PARALELA (Descarca Video si Cere GPT in acelasi timp)
        const [aiData] = await Promise.all([
            getTranscriptAndTranslation(url),
            downloadVideo(url, outputPath)
        ]);

        // 3. SALVARE IN CACHE
        await VideoCache.create({
            videoId,
            originalText: aiData.original,
            translatedText: aiData.translated
        });

        // 4. TAXARE CREDIT
        user.credits -= 1;
        await user.save();

        res.json({
            status: 'ok',
            downloadUrl: `/download/${videoId}.mp4`,
            originalText: aiData.original,
            translatedText: aiData.translated,
            creditsLeft: user.credits 
        });

    } catch (e) {
        console.error("Eroare Procesare:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// ENDPOINT DESCARCARE (NU MAI STERGEM INSTANT)
app.get('/download/:filename', (req, res) => {
    const file = path.join(DOWNLOAD_DIR, req.params.filename);
    if (fs.existsSync(file)) {
        res.download(file);
    } else {
        res.status(404).send('Fișierul nu mai există sau a expirat.');
    }
});

// CRON JOB: Curăță video-urile vechi de pe server la fiecare oră
setInterval(() => {
    const files = fs.readdirSync(DOWNLOAD_DIR);
    const now = Date.now();
    files.forEach(file => {
        if (file.endsWith('.mp4') || file.endsWith('.vtt')) {
            const filePath = path.join(DOWNLOAD_DIR, file);
            const stats = fs.statSync(filePath);
            // Sterge fisiere mai vechi de 24 de ore
            if (now - stats.mtimeMs > 24 * 60 * 60 * 1000) {
                fs.unlinkSync(filePath);
            }
        }
    });
}, 3600000); // 1 Ora

app.listen(PORT, () => console.log(`🚀 VIRALIO SaaS rulează Ultra-Fast.`));