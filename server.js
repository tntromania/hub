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

const YTDLP_PATH = '/usr/local/bin/yt-dlp';
const DOWNLOAD_DIR = path.join(__dirname, 'downloads');
if (!fs.existsSync(DOWNLOAD_DIR)) fs.mkdirSync(DOWNLOAD_DIR);

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// BAZA DE DATE
// ==========================================
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Conectat la MongoDB! (Aplicația YT)'))
    .catch(err => console.error('❌ Eroare MongoDB:', err));

const UserSchema = new mongoose.Schema({
    googleId: String, email: String, name: String, picture: String, 
    credits: { type: Number, default: 10 }, 
    voice_characters: { type: Number, default: 3000 }, 
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const WaitlistSchema = new mongoose.Schema({
    email: String, name: String, date: { type: Date, default: Date.now }
});
const Waitlist = mongoose.model('Waitlist', WaitlistSchema);

const CacheSchema = new mongoose.Schema({
    videoId: String, originalText: String, translatedText: String,
    createdAt: { type: Date, expires: 86400, default: Date.now }
});
const VideoCache = mongoose.model('VideoCache', CacheSchema);

const PROXY_URL = process.env.PROXY_URL; 
const proxyArg = PROXY_URL ? `--proxy "${PROXY_URL}"` : ""; 
const bypassArgs = '--no-warnings --geo-bypass';

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

const downloadVideo = (url, outputPath, resolution = "1080") => {
    return new Promise((resolve, reject) => {
        const formatArg = `-f "bestvideo[height<=${resolution}][ext=mp4]+bestaudio[ext=m4a]/bestvideo[height<=${resolution}]+bestaudio/best" --merge-output-format mp4`;
        const command = `"${YTDLP_PATH}" ${proxyArg} ${bypassArgs} ${formatArg} -o "${outputPath}" --no-check-certificates --no-playlist "${url}"`;
        exec(command, { maxBuffer: 1024 * 1024 * 50, timeout: 300000 }, (error) => { 
            if (error) reject(new Error("Serverul YouTube a refuzat conexiunea video."));
            else resolve();
        });
    });
};

const getTranscriptAndTranslation = async (url) => {
    return new Promise((resolve) => {
        const command = `"${YTDLP_PATH}" ${proxyArg} ${bypassArgs} --write-auto-sub --skip-download --sub-lang en,ro --convert-subs vtt --output "${path.join(DOWNLOAD_DIR, 'temp_%(id)s')}" "${url}"`;
        exec(command, { maxBuffer: 1024 * 1024 * 10, timeout: 60000 }, async (err) => {
            const files = fs.readdirSync(DOWNLOAD_DIR).filter(f => f.startsWith('temp_') && f.endsWith('.vtt'));
            let originalText = "";
            if (files.length === 0) return resolve({ original: "Nu s-a găsit subtitrare.", translated: "Nu există text de tradus." });
            
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
                        { role: "system", content: "Ești un traducător profesionist. Tradu textul în limba română. Returnează DOAR traducerea textului." },
                        { role: "user", content: originalText.substring(0, 10000) }
                    ],
                    model: "gpt-4o-mini", 
                });
                resolve({ original: originalText, translated: completion.choices[0].message.content });
            } catch (e) {
                resolve({ original: originalText, translated: "Eroare AI: " + e.message });
            }
        });
    });
};

app.post('/api/process-yt', authenticate, async (req, res) => {
    let { url, resolution } = req.body;
    if (!url) return res.status(400).json({ error: 'URL lipsă' });
    if (!resolution) resolution = "1080"; 

    const user = await User.findById(req.userId);
    if (url.includes('/shorts/')) url = url.replace('/shorts/', '/watch?v=').split('&')[0].split('?feature')[0];
    
    const videoIdMatch = url.match(/(?:v=|youtu\.be\/|shorts\/)([^&?]+)/);
    if (!videoIdMatch) return res.status(400).json({ error: "Link-ul de YouTube nu este valid." });
    const videoId = videoIdMatch[1];
    
    const outputPath = path.join(DOWNLOAD_DIR, `${videoId}.mp4`);

    try {
        const cachedData = await VideoCache.findOne({ videoId });
        if (cachedData && fs.existsSync(outputPath)) {
            return res.json({
                status: 'ok', downloadUrl: `/download/${videoId}.mp4`,
                originalText: cachedData.originalText, translatedText: cachedData.translatedText, creditsLeft: user.credits 
            });
        }

        if (user.credits < 2) return res.status(403).json({ error: "Nu mai ai credite! Cumpără un pachet." });

        const [aiData] = await Promise.all([
            getTranscriptAndTranslation(url),
            downloadVideo(url, outputPath, resolution)
        ]);

        await VideoCache.create({ videoId, originalText: aiData.original, translatedText: aiData.translated });

        user.credits -= 2;
        await user.save();

        res.json({
            status: 'ok', downloadUrl: `/download/${videoId}.mp4`,
            originalText: aiData.original, translatedText: aiData.translated, creditsLeft: user.credits 
        });

    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/download/:filename', (req, res) => {
    const file = path.join(DOWNLOAD_DIR, req.params.filename);
    if (fs.existsSync(file)) res.download(file); else res.status(404).send('Fișierul nu mai există sau a expirat.');
});

setInterval(() => {
    const files = fs.readdirSync(DOWNLOAD_DIR);
    const now = Date.now();
    files.forEach(file => {
        if (file.endsWith('.mp4') || file.endsWith('.vtt')) {
            const filePath = path.join(DOWNLOAD_DIR, file);
            if (now - fs.statSync(filePath).mtimeMs > 24 * 60 * 60 * 1000) fs.unlinkSync(filePath);
        }
    });
}, 3600000); 

app.listen(PORT, () => console.log(`🚀 YT Downloader rulează pe portul ${PORT}`));