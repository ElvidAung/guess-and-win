const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;

function verifySignature(req) {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) return false;
    
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const digest = 'sha256=' + hmac.update(JSON.stringify(req.body)).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

// Main Webhook Route Handler
app.post('/api/github-webhook', (req, res) => {
    if (!verifySignature(req)) {
        return res.status(401).send('Mismatched or invalid HMAC token signature.');
    }

    const githubEvent = req.headers['x-github-event'];
    const payload = req.body;
    let logMessage = `GitHub Event [${githubEvent}]: Action triggered by ${payload.sender?.login}`;
    
    if (githubEvent === 'push') {
        logMessage = `Push to branch ${payload.ref.split('/').pop()} by ${payload.pusher?.name}: "${payload.head_commit?.message}"`;
    } else if (githubEvent === 'issues') {
        logMessage = `Issue #${payload.issue?.number} ${payload.action}: ${payload.issue?.title}`;
    }

    // NOTE: Because localStorage doesn't exist on a server, you should pipe this log 
    // to an external micro-database (like a free Supabase, Firebase, or Kv Redis instance)
    // so your admin.js dashboard can fetch it.
    console.log("Saved Event:", logMessage); 

    return res.status(200).send('Webhook captured successfully.');
});

// EXPORT FOR VERCEL (Instead of app.listen)
module.exports = app;