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
    googleId: { type: String, required: true, unique: true },
    email: { type: String, required: true },
    name: String,
    picture: String,
    credits: { type: Number, default: 10 },
    voice_characters: { type: Number, default: 3000 },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

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

const bypassArgs = '--no-warnings --geo-bypass --extractor-args "youtube:player_client=web,default"';

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
                if (!dejaInLista) await Waitlist.create({ email: payload.email, name: payload.name });
                return res.status(403).json({ error: 'BETA_FULL', message: 'Locurile limitate pentru Beta s-au epuizat! Te-am adăugat pe lista de așteptare. Pentru acces prioritar, intră pe Discord: https://discord.gg/h8Ah6VKDzm' });
            }
            user = new User({ googleId: payload.sub, email: payload.email, name: payload.name, picture: payload.picture, credits: 10, voice_characters: 3000 });
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

// ==========================================
// downloadVideo — calitate maximă, fără filtre
// ==========================================
// bestvideo+bestaudio = yt-dlp alege cel mai bun stream video + cel mai bun audio disponibil.
// Niciun filtru de height/width/res — funcționează corect atât pe Shorts (verticale) cât și pe video normale.
// ffmpeg face merge-ul în mp4 la final.

const downloadVideo = (url, outputPath, resolution = "1080") => {
    return new Promise((resolve, reject) => {

        const command = [
            `"${YTDLP_PATH}"`,
            proxyArg,
            `--no-warnings --geo-bypass`,
            `--extractor-args "youtube:player_client=web,default"`,  // web = full quality formats, no login needed
            `--rm-cache-dir`,
            `--no-cache-dir`,
            `--retries 5`,
            `--fragment-retries 5`,
            `-f "bv*+ba/b"`,
            `--merge-output-format mp4`,
            `-o "${outputPath}"`,
            `--no-check-certificates`,
            `--no-playlist`,
            `--print "after_move:%(width)sx%(height)s | vcodec=%(vcodec).10s | acodec=%(acodec).8s | ~%(filesize,filesize_approx)s bytes"`,
            `"${url}"`
        ].join(' ');

        console.log(`⬇️  START download: ${url} (calitate maxima disponibila)`);

        exec(command, { maxBuffer: 1024 * 1024 * 200, timeout: 600000 }, (error, stdout, stderr) => {
            if (stdout && stdout.trim()) console.log(`📊 Format ales: ${stdout.trim()}`);

            if (error) {
                console.error("❌ Eroare yt-dlp:", stderr?.slice(0, 600));
                reject(new Error("Descărcarea a eșuat: " + (stderr?.slice(0, 200) || "eroare necunoscută")));
                return;
            }

            try {
                const stat = fs.statSync(outputPath);
                const sizeMB = (stat.size / 1024 / 1024).toFixed(2);
                console.log(`✅ Video descărcat cu succes: ${sizeMB} MB`);
                if (stat.size < 50 * 1024) {
                    reject(new Error(`Fișierul e suspect de mic (${sizeMB} MB). Posibil format greșit.`));
                } else {
                    resolve();
                }
            } catch (e) {
                reject(new Error("Fișierul video nu a fost găsit pe disk după download."));
            }
        });
    });
};

// ==========================================
// MOTOR DIRECT PE WHISPER
// ==========================================
const getTranscriptAndTranslation = async (url, videoId) => {
    return new Promise(async (resolve) => {
        let originalText = "";
        const audioPath = path.join(DOWNLOAD_DIR, `audio_${videoId}.mp3`);

        try {
            console.log(`🎙️ Extragem audio pentru Whisper: ${videoId}`);
            
            const audioCmd = `"${YTDLP_PATH}" ${proxyArg} ${bypassArgs} --quiet --rm-cache-dir --no-cache-dir --retries 5 --fragment-retries 5 -f "ba/bestaudio/best" --extract-audio --audio-format mp3 --audio-quality 0 --output "${audioPath}" "${url}"`;
            
            await new Promise((res, rej) => {
                exec(audioCmd, { maxBuffer: 1024 * 1024 * 50, timeout: 300000 }, (aErr, stdout, stderr) => {
                    if (aErr) { console.error("DEBUG Audio Stderr:", stderr); rej(aErr); }
                    else res();
                });
            });

            if (!fs.existsSync(audioPath) || fs.statSync(audioPath).size < 1000) {
                throw new Error("Fișier audio corupt sau blocat de YouTube.");
            }

            console.log(`🧠 Trimitem la Whisper pentru transcriere: ${videoId}`);
            const transcription = await openai.audio.transcriptions.create({
                file: fs.createReadStream(audioPath),
                model: "whisper-1",
            });

            originalText = transcription.text;
            console.log(`✅ Whisper a transcris cu succes.`);
            try { fs.unlinkSync(audioPath); } catch (e) {}

        } catch (err) {
            console.error("❌ Eroare Whisper / yt-dlp Audio:", err.message);
            if (fs.existsSync(audioPath)) try { fs.unlinkSync(audioPath); } catch (e) {}
            return resolve({ original: "Eroare la extragerea audio (YouTube Anti-Bot).", translated: "Eroare tehnică." });
        }

        try {
            const completion = await openai.chat.completions.create({
                messages: [
                    { role: "system", content: "Ești un traducător profesionist. Urmează un text transcris dintr-un video. Poate fi în orice limbă. Te rog să îl traduci perfect, natural și cursiv în limba ROMÂNĂ. Returnează DOAR textul tradus, fără alte comentarii." },
                    { role: "user", content: originalText.substring(0, 10000) }
                ],
                model: "gpt-4o-mini",
            });
            resolve({ original: originalText, translated: completion.choices[0].message.content });
        } catch (e) {
            resolve({ original: originalText, translated: "Eroare la traducere AI: " + e.message });
        }
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
            // Verifică și cache-ul că are fișier valid
            const stat = fs.statSync(outputPath);
            if (stat.size > 100 * 1024) {
                console.log(`⚡ CACHE HIT (Gratuit) pentru video: ${videoId}`);
                return res.json({
                    status: 'ok', downloadUrl: `/download/${videoId}.mp4`,
                    originalText: cachedData.originalText, translatedText: cachedData.translatedText, creditsLeft: user.credits
                });
            }
            // Dacă fișierul e corupt/mic, șterge-l și reprocessează
            console.warn(`⚠️  Cache hit dar fișier suspect (${stat.size} bytes). Reprocessăm.`);
            fs.unlinkSync(outputPath);
        }

        if (user.credits < 2) return res.status(403).json({ error: "Nu mai ai credite! Cumpără un pachet." });

        console.log(`⏳ PROCESARE NOUA pentru video: ${url} la ${resolution}p`);

        const [aiData] = await Promise.all([
            getTranscriptAndTranslation(url, videoId),
            downloadVideo(url, outputPath, resolution)
        ]);

        await VideoCache.create({ videoId, originalText: aiData.original, translatedText: aiData.translated });

        user.credits -= 2;
        await user.save();

        res.json({
            status: 'ok', downloadUrl: `/download/${videoId}.mp4`,
            originalText: aiData.original, translatedText: aiData.translated, creditsLeft: user.credits
        });

    } catch (e) {
        console.error("Eroare Procesare:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.get('/download/:filename', (req, res) => {
    const file = path.join(DOWNLOAD_DIR, req.params.filename);
    if (fs.existsSync(file)) res.download(file);
    else res.status(404).send('Fișierul nu mai există sau a expirat.');
});

setInterval(() => {
    const files = fs.readdirSync(DOWNLOAD_DIR);
    const now = Date.now();
    files.forEach(file => {
        if (file.endsWith('.mp4') || file.endsWith('.mp3')) {
            const filePath = path.join(DOWNLOAD_DIR, file);
            if (now - fs.statSync(filePath).mtimeMs > 24 * 60 * 60 * 1000) fs.unlinkSync(filePath);
        }
    });
}, 3600000);

app.listen(PORT, () => console.log(`🚀 YT Downloader rulează pe portul ${PORT}`));