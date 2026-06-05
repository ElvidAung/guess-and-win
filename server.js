const crypto = require('crypto');

const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;

function verifySignature(req, bodyBuffer) {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) return false;
    
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const digest = 'sha256=' + hmac.update(bodyBuffer).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

// Vercel Serverless Function Handler
module.exports = async (req, res) => {
    // CRITICAL: Force it to only allow POST requests from GitHub
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).send(`Method ${req.method} Not Allowed. Use POST.`);
    }

    // Capture raw body for signature verification
    let rawBody = '';
    req.on('data', chunk => { rawBody += chunk; });
    
    await new Promise(resolve => req.on('end', resolve));

    if (!verifySignature(req, rawBody)) {
        return res.status(401).send('Mismatched or invalid HMAC token signature.');
    }

    const payload = JSON.parse(rawBody || '{}');
    const githubEvent = req.headers['x-github-event'];
    
    let logMessage = `GitHub Event [${githubEvent}]: Action triggered by ${payload.sender?.login}`;
    console.log("Saved Event:", logMessage); 

    return res.status(200).send('Webhook captured successfully.');
};
