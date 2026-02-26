/**
 * SnopDesk WhatsApp Bridge
 * - GET /qr?connection_id=xxx  → PNG QR code (poll until ready)
 * - POST /send                 → send message (body: connection_id, to, body)
 * - POST /send-audio           → send voice message (body: connection_id, to, media_base64, mimetype)
 * - Calls PHP: POST phpBaseUrl/api/whatsapp/connected when ready
 * - Calls PHP: POST phpBaseUrl/api/whatsapp/incoming when message received
 *
 * Env: PHP_BASE_URL, WEBHOOK_SECRET (same as WHATSAPP_WEBHOOK_SECRET or APP_KEY in PHP), PORT
 */

// Always load .env from bridge directory (so it works even when run from project root)
const path = require('path');
const fs = require('fs');
const envPath = path.join(__dirname, '.env');
const parentEnvPath = path.join(__dirname, '..', '.env');

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  let content = fs.readFileSync(filePath, 'utf8');
  content = content.replace(/^\uFEFF/, ''); // strip BOM if present
  content.split(/\r?\n/).forEach((line) => {
    const m = line.match(/^\s*([^#=]+)=(.*)$/);
    if (m) {
      const key = m[1].trim();
      const val = m[2].trim().replace(/\r$/, '').replace(/^["']|["']$/g, '');
      if (!process.env[key]) process.env[key] = val;
    }
  });
}

try {
  require('dotenv').config({ path: envPath });
} catch (_) {}
loadEnvFile(envPath);
if (!process.env.WEBHOOK_SECRET) {
  loadEnvFile(parentEnvPath);
  process.env.WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || process.env.WHATSAPP_WEBHOOK_SECRET || process.env.APP_KEY || '';
}

const express = require('express');
const QRCode = require('qrcode');
const { Client, LocalAuth } = require('whatsapp-web.js');

const app = express();
// Must be large enough for /send-audio (base64 MP3 ≈ 1.33× file size; allow 15mb so voice replies never hit 413)
app.use(express.json({ limit: '15mb' }));

const PHP_BASE_URL = (process.env.PHP_BASE_URL || 'http://localhost:8000').trim().replace(/\/$/, '');
const WEBHOOK_SECRET = (process.env.WEBHOOK_SECRET || process.env.APP_KEY || '').trim();
const AUTH_DATA_PATH = (process.env.AUTH_DATA_PATH || '').trim();

/** Try to find Chrome or Edge on Windows so we don't require puppeteer's Chromium download. */
function getChromePath() {
  if (process.env.PUPPETEER_EXECUTABLE_PATH) {
    return process.env.PUPPETEER_EXECUTABLE_PATH;
  }
  if (process.platform !== 'win32') return null;
  const candidates = [
    path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
  ].filter(Boolean);
  for (const exe of candidates) {
    try {
      if (fs.existsSync(exe)) return exe;
    } catch (_) {}
  }
  return null;
}

const chromePath = getChromePath();
const puppeteerOpts = {
  headless: true,
  args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
};
if (chromePath) {
  puppeteerOpts.executablePath = chromePath;
}

const sessions = new Map(); // connection_id -> { client, qrPayload, phone }
const connectionIdByClient = new Map(); // client -> connection_id

/** Session dir for a connection (same as LocalAuth). Used to clear stale Chrome lock. */
function getSessionDir(connectionId) {
  const base = AUTH_DATA_PATH || path.join(__dirname, '.wwebjs_auth');
  return path.join(base, 'session-' + connectionId);
}

/** If Chrome left a lock file (e.g. after crash), remove it so a new browser can start. */
function clearStaleChromeLock(connectionId) {
  const dir = getSessionDir(connectionId);
  const lockFiles = ['SingletonLock', 'SingletonCookie', 'SingletonSocket'];
  let cleared = 0;
  for (const name of lockFiles) {
    const f = path.join(dir, name);
    try {
      if (fs.existsSync(f)) {
        fs.unlinkSync(f);
        cleared++;
      }
    } catch (_) {}
  }
  return cleared;
}

function getConnectionId(client) {
  return connectionIdByClient.get(client);
}

function notifyPhpConnected(connectionId, phoneNumber) {
  if (!WEBHOOK_SECRET) {
    console.warn('WEBHOOK_SECRET not set; skipping PHP notify. Set it in .env to match APP_KEY in SnopDesk.');
    return;
  }
  const url = PHP_BASE_URL + '/api/whatsapp/connected';
  const body = JSON.stringify({ connection_id: connectionId, phone_number: phoneNumber });
  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Webhook-Secret': WEBHOOK_SECRET,
    },
    body,
  })
    .then((r) => {
      const status = r.status;
      return r.text().then((text) => {
        let data;
        try {
          data = JSON.parse(text);
        } catch (_) {
          data = { raw: text.slice(0, 200) };
        }
        if (status >= 200 && status < 300) {
          console.log('PHP connected OK:', status, data);
        } else {
          console.error('PHP connected FAIL:', status, url, data);
        }
        return data;
      });
    })
    .catch((err) => console.error('PHP connected error (network?):', err.message, url));
}

function notifyPhpDisconnected(connectionId) {
  if (!WEBHOOK_SECRET) return;
  const url = PHP_BASE_URL + '/api/whatsapp/disconnected';
  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Webhook-Secret': WEBHOOK_SECRET,
    },
    body: JSON.stringify({ connection_id: connectionId }),
  })
    .then((r) => r.text().then((text) => ({ status: r.status, text })))
    .then(({ status, text }) => {
      if (status >= 200 && status < 300) {
        console.log('PHP disconnected OK:', connectionId);
      } else {
        console.error('PHP disconnected FAIL:', status, text?.slice(0, 100));
      }
    })
    .catch((err) => console.error('PHP disconnected error:', err.message));
}

function notifyPhpIncoming(connectionId, from, messageId, body, extra = {}) {
  if (!WEBHOOK_SECRET) {
    console.warn('WEBHOOK_SECRET not set; skipping PHP incoming');
    return;
  }
  const url = PHP_BASE_URL + '/api/whatsapp/incoming';
  const payload = { connection_id: connectionId, from, message_id: messageId, body: body || '', ...extra };
  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Webhook-Secret': WEBHOOK_SECRET,
    },
    body: JSON.stringify(payload),
  })
    .then((r) => {
      const status = r.status;
      return r.text().then((text) => {
        let data;
        try {
          data = JSON.parse(text);
        } catch (_) {
          data = { raw: text.slice(0, 200) };
        }
        if (status >= 200 && status < 300) {
          console.log('PHP incoming OK:', status, data);
        } else {
          console.error('PHP incoming FAIL:', status, url, data);
        }
        return data;
      });
    })
    .catch((err) => console.error('PHP incoming error (network?):', err.message, url));
}

function createClient(connectionId) {
  if (sessions.has(connectionId)) {
    return sessions.get(connectionId).client;
  }
  const authOpts = { clientId: connectionId };
  if (AUTH_DATA_PATH) authOpts.dataPath = AUTH_DATA_PATH;
  const client = new Client({
    authStrategy: new LocalAuth(authOpts),
    puppeteer: puppeteerOpts,
  });
  const state = { client, qrPayload: null, phone: null };
  sessions.set(connectionId, state);
  connectionIdByClient.set(client, connectionId);

  client.on('qr', (qr) => {
    state.qrPayload = qr;
    console.log('QR received for', connectionId);
  });

  client.on('ready', () => {
    state.qrPayload = null;
    console.log('Client ready for', connectionId);
    Promise.resolve()
      .then(() => client.info)
      .then((info) => {
        const phone = (info && info.wid && info.wid.user)
          ? info.wid.user + (info.wid.server ? '@' + info.wid.server : '')
          : '';
        state.phone = phone;
        return phone;
      })
      .catch((err) => {
        console.warn('client.info failed for', connectionId, err.message);
        return '';
      })
      .then((phone) => {
        notifyPhpConnected(connectionId, phone);
      })
      .catch((err) => {
        console.error('notifyPhpConnected failed for', connectionId, err);
      });
  });

  client.on('message', async (msg) => {
    const cid = getConnectionId(client);
    if (!cid) return;
    if (msg.fromMe) return;
    const from = msg.from;
    const messageId = msg.id._serialized || msg.id;
    let body = msg.body || '';
    const extra = {};
    if (msg.hasMedia && (msg.type === 'ptt' || msg.type === 'audio')) {
      extra.media_type = msg.type;
      try {
        const media = await msg.downloadMedia();
        if (media && media.data) {
          extra.media_base64 = media.data;
          extra.mimetype = media.mimetype || 'audio/ogg';
          if (!body) body = '';
        }
      } catch (e) {
        console.warn('WhatsApp audio download failed for', messageId, e.message);
      }
    }
    notifyPhpIncoming(cid, from, messageId, body, extra);
  });

  client.on('disconnected', (reason) => {
    const cid = connectionIdByClient.get(client);
    if (cid) {
      notifyPhpDisconnected(cid);
      sessions.delete(cid);
    }
    connectionIdByClient.delete(client);
  });

  function doInit() {
    return state.client.initialize().catch((err) => {
      const msg = (err && err.message) || String(err);
      const isAlreadyRunning = /already running|userDataDir/i.test(msg);
      if (isAlreadyRunning) {
        const removed = clearStaleChromeLock(connectionId);
        if (removed > 0) {
          console.log('Cleared stale Chrome lock for', connectionId, '(retrying once)');
          return state.client.initialize().catch((e) => {
            console.error('Init retry failed for', connectionId, e.message || e);
            sessions.delete(connectionId);
            connectionIdByClient.delete(state.client);
            notifyPhpDisconnected(connectionId);
          });
        }
      }
      console.error('Init error for', connectionId, err);
      sessions.delete(connectionId);
      connectionIdByClient.delete(state.client);
      notifyPhpDisconnected(connectionId);
    });
  }
  doInit();
  return client;
}

// GET /qr?connection_id=xxx → PNG or 204
app.get('/qr', async (req, res) => {
  const connectionId = (req.query.connection_id || '').trim();
  if (!connectionId) {
    return res.status(400).send('connection_id required');
  }
  let state = sessions.get(connectionId);
  if (!state) {
    createClient(connectionId);
    state = sessions.get(connectionId);
  }
  if (state && state.qrPayload) {
    try {
      const png = await QRCode.toBuffer(state.qrPayload, { type: 'png', margin: 2, width: 280 });
      res.set('Cache-Control', 'no-store');
      res.type('png').send(png);
    } catch (e) {
      res.status(500).send('QR error');
    }
    return;
  }
  // Return a small placeholder PNG so <img> doesn't break while waiting for QR (browser will poll again).
  const placeholderPng = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
    'base64'
  );
  res.set('Cache-Control', 'no-store');
  res.type('png').send(placeholderPng);
});

// GET /status?connection_id=xxx — so PHP can sync "connected" state; checks real client state (not just in-memory)
app.get('/status', async (req, res) => {
  const connectionId = (req.query.connection_id || '').trim();
  if (!connectionId) {
    return res.status(400).json({ ok: false, error: 'connection_id required' });
  }
  const state = sessions.get(connectionId);
  if (!state || !state.client) {
    return res.json({ ok: true, connected: false, phone_number: null });
  }
  const page = state.client.pupPage;
  if (page && typeof page.isClosed === 'function' && page.isClosed()) {
    console.log('GET /status: Puppeteer page closed for', connectionId);
    sessions.delete(connectionId);
    connectionIdByClient.delete(state.client);
    notifyPhpDisconnected(connectionId);
    return res.json({ ok: true, connected: false, phone_number: null });
  }
  let actualState = null;
  try {
    actualState = await state.client.getState();
  } catch (err) {
    // Client destroyed, page closed, or detached frame → treat as disconnected
    console.log('GET /status: getState() failed for', connectionId, err.message || err);
    sessions.delete(connectionId);
    connectionIdByClient.delete(state.client);
    notifyPhpDisconnected(connectionId);
    return res.json({ ok: true, connected: false, phone_number: null });
  }
  const connected = actualState === 'CONNECTED' && !!state.phone;
  if (!connected) {
    console.log('GET /status: not CONNECTED for', connectionId, 'actualState=', actualState);
    if (actualState === 'UNPAIRED' || actualState === 'UNPAIRED_IDLE' || actualState === 'LOGOUT' || actualState === 'CONFLICT') {
      sessions.delete(connectionId);
      connectionIdByClient.delete(state.client);
      notifyPhpDisconnected(connectionId);
    }
  }
  res.json({
    ok: true,
    connected,
    phone_number: connected ? state.phone : null,
  });
});

// POST /send — send message
app.post('/send', async (req, res) => {
  const secret = req.headers['x-webhook-secret'];
  if (WEBHOOK_SECRET && secret !== WEBHOOK_SECRET) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
  const { connection_id: connectionId, to, body } = req.body || {};
  if (!connectionId || !to || body === undefined) {
    return res.status(400).json({ ok: false, error: 'connection_id, to, body required' });
  }
  const state = sessions.get(connectionId.trim());
  if (!state || !state.client) {
    return res.status(404).json({ ok: false, error: 'Connection not found or not ready' });
  }
  try {
    const chatId = to.includes('@') ? to : to + '@c.us';
    // sendSeen: false avoids "getLastMsgKeyForAction is not a function" when WhatsApp Web updates their client
    await state.client.sendMessage(chatId, body, { sendSeen: false });
    res.json({ ok: true });
  } catch (e) {
    console.error('Send error', e);
    const msg = e.message || 'Send failed';
    const isDeadClient = /detached|not found|Connection not found|destroyed/i.test(msg);
    if (isDeadClient) {
      sessions.delete(connectionId.trim());
      connectionIdByClient.delete(state.client);
      notifyPhpDisconnected(connectionId.trim());
    }
    res.status(500).json({ ok: false, error: msg });
  }
});

// POST /send-audio — send voice message (base64 audio, sent as PTT)
app.post('/send-audio', async (req, res) => {
  const secret = req.headers['x-webhook-secret'];
  if (WEBHOOK_SECRET && secret !== WEBHOOK_SECRET) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
  const { connection_id: connectionId, to, media_base64: mediaBase64, mimetype } = req.body || {};
  if (!connectionId || !to || !mediaBase64) {
    return res.status(400).json({ ok: false, error: 'connection_id, to, media_base64 required' });
  }
  const state = sessions.get(connectionId.trim());
  if (!state || !state.client) {
    return res.status(404).json({ ok: false, error: 'Connection not found or not ready' });
  }
  try {
    const { MessageMedia } = require('whatsapp-web.js');
    const mime = mimetype || 'audio/mpeg';
    const media = new MessageMedia(mime, mediaBase64, 'voice.mp3');
    const chatId = to.includes('@') ? to : to + '@c.us';
    await state.client.sendMessage(chatId, media, { sendAudioAsVoice: true, sendSeen: false });
    res.json({ ok: true });
  } catch (e) {
    console.error('Send-audio error', e);
    const msg = e.message || 'Send failed';
    const isDeadClient = /detached|not found|Connection not found|destroyed/i.test(msg);
    if (isDeadClient) {
      sessions.delete(connectionId.trim());
      connectionIdByClient.delete(state.client);
      notifyPhpDisconnected(connectionId.trim());
    }
    res.status(500).json({ ok: false, error: msg });
  }
});

/** Restore all known connections from PHP so sessions load from disk (no QR needed after restart). */
function restoreSessionsFromPhp() {
  if (!WEBHOOK_SECRET) {
    console.warn('WEBHOOK_SECRET not set; skipping session restore.');
    return;
  }
  const url = PHP_BASE_URL + '/api/whatsapp/connection-ids';
  fetch(url, {
    method: 'GET',
    headers: { 'X-Webhook-Secret': WEBHOOK_SECRET },
  })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(r.status + ' ' + r.statusText))))
    .then(async (data) => {
      const ids = data.connection_ids || [];
      if (ids.length === 0) {
        console.log('No WhatsApp connections to restore.');
        return;
      }
      console.log('Restoring', ids.length, 'WhatsApp connection(s) from saved session...');
      const RESTORE_DELAY_MS = 4000;
      for (let i = 0; i < ids.length; i++) {
        if (i > 0) await new Promise((r) => setTimeout(r, RESTORE_DELAY_MS));
        createClient(ids[i]);
      }
    })
    .catch((err) => console.warn('Session restore failed (PHP unreachable?):', err.message));
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('SnopDesk WhatsApp bridge listening on', PORT);
  console.log('Notify PHP at:', PHP_BASE_URL);
  console.log('WEBHOOK_SECRET:', WEBHOOK_SECRET ? 'set' : 'NOT SET (PHP will reject webhooks)');
  if (AUTH_DATA_PATH) console.log('Session data path:', AUTH_DATA_PATH);
  if (chromePath) {
    console.log('Using browser:', chromePath);
  } else {
    console.log('Chrome/Edge not found. Set PUPPETEER_EXECUTABLE_PATH or run: npx puppeteer browsers install chrome');
  }
  restoreSessionsFromPhp();
});
