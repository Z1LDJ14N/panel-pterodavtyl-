const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));

// Database setup
const dbPath = path.join(__dirname, '../database/panel.db');
const db = new Database(dbPath);

// Create tables if not exists
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT DEFAULT 'stopped',
    port INTEGER,
    script_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    size INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(server_id) REFERENCES servers(id)
  );
`);

// Insert default user if not exists
try {
  const hash = bcrypt.hashSync('123', 10);
  db.prepare('INSERT OR IGNORE INTO users (username, password, email) VALUES (?, ?, ?)').run('xyz', hash, 'xyz@panel.com');
} catch (e) {
  console.log('Default user already exists');
}

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Upload configuration
const upload = multer({
  dest: path.join(__dirname, '../uploads/'),
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB limit
});

// Helper function to verify JWT
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ============ AUTH ROUTES ============

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(401).json({ error: 'User not found' });

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;

  try {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)').run(username, hash, email);
    res.json({ message: 'User created successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ SERVER MANAGEMENT ROUTES ============

app.get('/api/servers', verifyToken, (req, res) => {
  try {
    const servers = db.prepare('SELECT * FROM servers WHERE user_id = ?').all(req.user.id);
    res.json(servers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/servers', verifyToken, (req, res) => {
  const { name, type } = req.body;

  try {
    const result = db.prepare('INSERT INTO servers (user_id, name, type, port) VALUES (?, ?, ?, ?)').run(
      req.user.id,
      name,
      type,
      3000 + Math.floor(Math.random() * 60000)
    );

    const uploadDir = path.join(__dirname, `../uploads/server_${result.lastInsertRowid}`);
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

    res.json({ id: result.lastInsertRowid, message: 'Server created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ FILE MANAGEMENT ROUTES ============

app.post('/api/servers/:serverId/upload', verifyToken, upload.single('file'), (req, res) => {
  const { serverId } = req.params;

  try {
    const server = db.prepare('SELECT * FROM servers WHERE id = ? AND user_id = ?').get(serverId, req.user.id);
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const uploadDir = path.join(__dirname, `../uploads/server_${serverId}`);
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

    const newPath = path.join(uploadDir, req.file.originalname);
    fs.renameSync(req.file.path, newPath);

    db.prepare('INSERT INTO files (server_id, filename, filepath, size) VALUES (?, ?, ?, ?)').run(
      serverId,
      req.file.originalname,
      newPath,
      req.file.size
    );

    res.json({ message: 'File uploaded', filename: req.file.originalname });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/servers/:serverId/files', verifyToken, (req, res) => {
  const { serverId } = req.params;

  try {
    const server = db.prepare('SELECT * FROM servers WHERE id = ? AND user_id = ?').get(serverId, req.user.id);
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const files = db.prepare('SELECT * FROM files WHERE server_id = ?').all(serverId);
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/servers/:serverId/files/:fileId', verifyToken, (req, res) => {
  const { serverId, fileId } = req.params;

  try {
    const file = db.prepare('SELECT f.* FROM files f JOIN servers s ON f.server_id = s.id WHERE f.id = ? AND s.user_id = ?').get(fileId, req.user.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    if (fs.existsSync(file.filepath)) fs.unlinkSync(file.filepath);
    db.prepare('DELETE FROM files WHERE id = ?').run(fileId);

    res.json({ message: 'File deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ SERVER CONTROL ROUTES ============

const runningProcesses = {};

app.post('/api/servers/:serverId/start', verifyToken, (req, res) => {
  const { serverId } = req.params;
  const { scriptPath } = req.body;

  try {
    const server = db.prepare('SELECT * FROM servers WHERE id = ? AND user_id = ?').get(serverId, req.user.id);
    if (!server) return res.status(404).json({ error: 'Server not found' });

    if (runningProcesses[serverId]) {
      return res.status(400).json({ error: 'Server already running' });
    }

    // Get uploaded file or use default
    let execPath = scriptPath;
    if (!execPath) {
      const files = db.prepare('SELECT filepath FROM files WHERE server_id = ? LIMIT 1').get(serverId);
      execPath = files ? files.filepath : null;
    }

    if (!execPath) {
      return res.status(400).json({ error: 'No script provided' });
    }

    const child = spawn('node', [execPath], {
      cwd: path.dirname(execPath),
      stdio: 'pipe',
      detached: false
    });

    runningProcesses[serverId] = { process: child, logs: [] };

    child.stdout.on('data', (data) => {
      const log = data.toString();
      runningProcesses[serverId].logs.push(log);
      if (runningProcesses[serverId].logs.length > 1000) {
        runningProcesses[serverId].logs.shift();
      }
    });

    child.stderr.on('data', (data) => {
      const log = `[ERROR] ${data.toString()}`;
      runningProcesses[serverId].logs.push(log);
    });

    child.on('close', (code) => {
      db.prepare('UPDATE servers SET status = ? WHERE id = ?').run('stopped', serverId);
      delete runningProcesses[serverId];
    });

    db.prepare('UPDATE servers SET status = ?, script_path = ? WHERE id = ?').run('running', execPath, serverId);
    res.json({ message: 'Server started', pid: child.pid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/servers/:serverId/stop', verifyToken, (req, res) => {
  const { serverId } = req.params;

  try {
    if (runningProcesses[serverId]) {
      runningProcesses[serverId].process.kill();
      delete runningProcesses[serverId];
      db.prepare('UPDATE servers SET status = ? WHERE id = ?').run('stopped', serverId);
      res.json({ message: 'Server stopped' });
    } else {
      res.status(400).json({ error: 'Server not running' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/servers/:serverId/logs', verifyToken, (req, res) => {
  const { serverId } = req.params;

  try {
    const server = db.prepare('SELECT * FROM servers WHERE id = ? AND user_id = ?').get(serverId, req.user.id);
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const logs = runningProcesses[serverId]?.logs || [];
    res.json({ logs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ EGGS (TEMPLATES) ============

app.get('/api/eggs', verifyToken, (req, res) => {
  const eggs = [
    {
      id: 1,
      name: 'WhatsApp Bot',
      description: 'WhatsApp Bot using Baileys',
      image: '🤖',
      script: `const { default: makeWASocket, useMultiFileAuthState } = require('@whiskeysockets/baileys');
const fs = require('fs');

async function startBot() {
  const { state, saveCreds } = await useMultiFileAuthState('auth_info');
  
  const sock = makeWASocket({
    auth: state,
    printQRInTerminal: true
  });

  sock.ev.on('creds.update', saveCreds);
  sock.ev.on('messages.upsert', async (m) => {
    const message = m.messages[0];
    if (!message.message) return;
    
    console.log('[MESSAGE]', message.pushName, ':', message.message.conversation);
    
    // Reply logic here
    await sock.sendMessage(message.key.remoteJid, { text: 'Pong!' });
  });
}

startBot().catch(console.error);`
    },
    {
      id: 2,
      name: 'Node.js 20',
      description: 'Basic Node.js 20 server',
      image: '⚙️',
      script: `const http = require('http');

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Node.js 20 Server Running!\\n');
});

server.listen(3000, () => {
  console.log('Server running on port 3000');
});`
    },
    {
      id: 3,
      name: 'Discord Bot',
      description: 'Discord.js bot template',
      image: '🎮',
      script: `const { Client, GatewayIntentBits } = require('discord.js');
const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });

client.on('ready', () => {
  console.log('Bot is online!');
});

client.on('messageCreate', (message) => {
  if (message.author.bot) return;
  if (message.content === '!ping') {
    message.reply('Pong!');
  }
});

client.login(process.env.DISCORD_TOKEN);`
    }
  ];

  res.json(eggs);
});

// ============ SERVER STATUS ============

app.get('/api/status', (req, res) => {
  res.json({ status: 'Panel is running', timestamp: new Date().toISOString() });
});

// Export untuk Vercel
module.exports = app;

// Local development
if (require.main === module) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
        }
