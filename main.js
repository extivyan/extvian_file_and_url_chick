const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const multer = require('multer');
const crypto = require('crypto');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ storage: multer.memoryStorage() });

// ---------------------------------------------------------
// 1. Endpoint لفحص الروابط (URL Scan)
// ---------------------------------------------------------
app.get('/api/scan-url', async (req, res) => {
    const targetUrl = req.query.url;

    if (!targetUrl) {
        return res.status(400).json({ error: 'من فضلك قم بتمرير الرابط: ?url=...' });
    }

    try {
        const parsedUrl = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
        const domain = parsedUrl.hostname.replace('www.', '');

        const response = await axios.get(`https://www.urlvoid.com/scan/${domain}/`, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        });

        const $ = cheerio.load(response.data);
        const scoreText = $('span.label-danger, span.label-success').first().text().trim();
        const isBlacklisted = $('table.table-striped').text().includes('POSSIBLE INFECTION') || (scoreText && !scoreText.startsWith('0/'));

        return res.json({
            status: 'success',
            type: 'url',
            target: domain,
            detections: scoreText || 'غير معروف',
            is_safe: !isBlacklisted,
            provider: 'URLVoid'
        });

    } catch (error) {
        console.error("Error Scanning Domain:", error.message);
        return res.status(500).json({
            error: 'فشل فحص الرابط من المصدر',
            details: error.message
        });
    }
});

// ---------------------------------------------------------
// 2. Endpoint لفحص الملفات (File Scan) - بدون API Key
// ---------------------------------------------------------
app.post('/api/scan-file', upload.single('file'), async (req, res) => {
    const file = req.file;

    if (!file) {
        return res.status(400).json({ error: 'يرجى إرفاق ملف للعملية في الحقل file' });
    }

    try {
        // حساب الـ SHA256 Hash للملف
        const fileHash = crypto.createHash('sha256').update(file.buffer).digest('hex');

        // الاستعلام عن الـ Hash عبر AlienVault OTX (مفتوح وبدون API Key)
        const response = await axios.get(`https://otx.alienvault.com/api/v1/indicators/file/${fileHash}/general`, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        });

        const data = response.data;
        const pulsesCount = data.pulse_info ? data.pulse_info.count : 0;
        const isMalicious = pulsesCount > 0;

        return res.json({
            status: 'success',
            type: 'file',
            filename: file.originalname,
            sha256: fileHash,
            is_safe: !isMalicious,
            threat_indicators: pulsesCount,
            details_url: `https://otx.alienvault.com/indicator/file/${fileHash}`,
            provider: 'AlienVault OTX'
        });

    } catch (error) {
        // إذا كان الـ Hash غير موجود في السجلات (الملف سليم أو غير مسجل كتهديد)
        if (error.response && error.response.status === 404) {
            const fileHash = crypto.createHash('sha256').update(file.buffer).digest('hex');
            return res.json({
                status: 'success',
                type: 'file',
                filename: file.originalname,
                sha256: fileHash,
                is_safe: true,
                note: 'لم يتم التسجيل كتهديد في قواعد بيانات AlienVault OTX',
                provider: 'AlienVault OTX'
            });
        }

        console.error("Error Scanning File:", error.message);
        return res.status(500).json({
            error: 'فشل فحص الملف',
            details: error.message
        });
    }
});

module.exports = app;

if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`🚀 Scraper API running on http://localhost:${PORT}`);
    });
}