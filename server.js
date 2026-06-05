const crypto = require('crypto');

const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;

function verifySignature(req, bodyBuffer) {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) return false;
    
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const digest = 'sha256=' + hmac.update(bodyBuffer).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

module.exports = async (req, res) => {
    // Only accept POST requests from GitHub Webhooks
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).send(`Method ${req.method} Not Allowed. Use POST.`);
    }

    // Read the incoming data stream body
    let rawBody = '';
    req.on('data', chunk => { rawBody += chunk; });
    await new Promise(resolve => req.on('end', resolve));

    // Verify the webhook secret password matches
    if (!verifySignature(req, rawBody)) {
        return res.status(401).send('Mismatched or invalid HMAC token signature.');
    }

    try {
        const payload = JSON.parse(rawBody || '{}');
        const githubEvent = req.headers['x-hub-signature-256'] ? req.headers['x-github-event'] : 'unknown';
        
        console.log(`Successfully received ${githubEvent} event from GitHub!`);
        
        // Return a successful response status back to GitHub
        return res.status(200).json({ success: true, message: "Webhook captured successfully." });
    } catch (error) {
        return res.status(500).json({ error: "Failed to parse webhook payload data." });
    }
};
