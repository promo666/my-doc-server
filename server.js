const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SCOPES = [
  'https://www.googleapis.com/auth/drive.file',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile'
].join(' ');

app.use(cors({ origin: true, credentials: true }));

// In-memory session store: sessionId -> { refreshToken }
// Note: this resets if the server restarts/redeploys. Fine for a small personal app.
const sessions = new Map();

function backendUrl(req){
  return `${req.protocol}://${req.get('host')}`;
}

// Step 1: send the browser to Google's consent screen
app.get('/auth/google', (req, res) => {
  const redirectUri = `${backendUrl(req)}/auth/google/callback`;
  if(req.query.debug){
    return res.send('Computed redirect_uri: [' + redirectUri + ']');
  }
  const state = crypto.randomBytes(16).toString('hex');
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: SCOPES,
    access_type: 'offline',
    prompt: 'consent',
    state
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

// Step 2: Google redirects back here with a one-time code
app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  if(!code) return res.status(400).send('Missing code');
  const redirectUri = `${backendUrl(req)}/auth/google/callback`;

  try{
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      })
    });
    const tokens = await tokenRes.json();
    if(!tokens.refresh_token){
      // Happens if the user had already granted access before without prompt=consent.
      // Our /auth/google route always forces prompt=consent, so this should be rare.
      return res.status(400).send('No refresh token returned. Try signing out of this app in your Google Account permissions and try again.');
    }

    const sessionId = crypto.randomBytes(24).toString('hex');
    sessions.set(sessionId, { refreshToken: tokens.refresh_token });

    res.cookie('sid', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
    });
    res.redirect('/');
  }catch(e){
    res.status(500).send('Sign-in failed: ' + e.message);
  }
});

// Frontend calls this to get a short-lived access token using the stored refresh token
app.get('/auth/token', async (req, res) => {
  const sessionId = req.cookies.sid;
  const session = sessionId && sessions.get(sessionId);
  if(!session) return res.status(401).json({ error: 'not_signed_in' });

  try{
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: session.refreshToken,
        grant_type: 'refresh_token'
      })
    });
    const data = await tokenRes.json();
    if(!data.access_token) return res.status(401).json({ error: 'refresh_failed' });
    res.json({ access_token: data.access_token, expires_in: data.expires_in });
  }catch(e){
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/auth/status', (req, res) => {
  const sessionId = req.cookies.sid;
  res.json({ signedIn: !!(sessionId && sessions.has(sessionId)) });
});

app.post('/auth/logout', (req, res) => {
  const sessionId = req.cookies.sid;
  if(sessionId) sessions.delete(sessionId);
  res.clearCookie('sid');
  res.json({ ok: true });
});

app.get('/privacy', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>My Doc — Privacy Policy</title>
  <style>body{font-family:sans-serif;max-width:700px;margin:40px auto;padding:0 20px;line-height:1.6;color:#1D2B33;}h1{font-size:24px;}h2{font-size:18px;margin-top:28px;}</style>
  </head><body>
  <h1>Privacy Policy — My Doc</h1>
  <p>Last updated: ${new Date().toISOString().slice(0,10)}</p>
  <p>My Doc is a simple document storage app. This page explains what data we access and how it's used.</p>
  <h2>What we access</h2>
  <p>When you sign in with Google, My Doc requests permission to create, view, and manage <strong>only the files and folders that My Doc itself creates</strong> in your Google Drive (using Google's "drive.file" scope). My Doc cannot see, read, or modify any other files in your Drive.</p>
  <p>We also access your basic Google account email and name, solely to identify your account within the app.</p>
  <h2>What we store</h2>
  <p>Your files are stored directly in your own Google Drive — not on our servers. A small technical token (used to keep you signed in) is stored securely on our server and is never shared with third parties.</p>
  <h2>What we don't do</h2>
  <p>We do not sell, share, or use your data for advertising. We do not access any files other than the ones created by this app.</p>
  <h2>Contact</h2>
  <p>Questions about this policy can be sent to jouriali57@gmail.com.</p>
  </body></html>`);
});

app.get('/', (req, res) => res.send('My Doc backend is running.'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('My Doc backend listening on ' + PORT));
