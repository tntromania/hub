const express = require('express');
const cors = require('cors');
const multer = require('multer');
const ffmpeg = require('fluent-ffmpeg');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Upload & Folders
const upload = multer({ dest: 'uploads/' });
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('processed')) fs.mkdirSync('processed');

// Servim fișierele statice DIRECT (fără prefix, Traefik îl strip-uiește)
app.use(express.static(path.join(__dirname, 'public')));

// API endpoint pentru procesare audio
app.post('/api/smart-cut', upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Fisier lipsa' });

    const inputFile = req.file.path;
    const outputFile = path.join('processed', `cut_${Date.now()}.mp3`);
    const threshold = req.body.threshold || '-30dB'; 
    const minSilence = req.body.minSilence || '0.3';

    console.log(`[CUT] Processing: ${req.file.originalname}`);

    ffmpeg(inputFile)
        .audioFilters(`silenceremove=stop_periods=-1:stop_duration=${minSilence}:stop_threshold=${threshold}`)
        .on('end', () => {
            res.download(outputFile, 'tight_audio.mp3', (err) => {
                try {
                    fs.unlinkSync(inputFile);
                    setTimeout(() => { 
                        if(fs.existsSync(outputFile)) fs.unlinkSync(outputFile); 
                    }, 10000);
                } catch(e){ console.error(e); }
            });
        })
        .on('error', (err) => {
            console.error('[FFmpeg Error]:', err);
            res.status(500).json({ error: 'Eroare procesare audio.' });
        })
        .save(outputFile);
});

// Fallback pentru toate rutele - trimite index.html
app.get('*', (req, res) => {
    console.log(`[REQUEST] ${req.method} ${req.path}`);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✂️ AudioCut running on port ${PORT}`);
    console.log(`📁 Static files from: ${path.join(__dirname, 'public')}`);
});