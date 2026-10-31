const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const MAX_PEERS = 2; // a couple
const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

const server = http.createServer((req, res) => {
  const urlPath = req.url.split('?')[0];
  const file = path.join(PUBLIC_DIR, urlPath === '/' ? 'index.html' : urlPath);
  if (!file.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
});

const wss = new WebSocketServer({ server });
const rooms = new Map();

function send(ws, obj) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

function broadcast(room, sender, obj) {
  for (const peer of room) if (peer !== sender) send(peer, obj);
}

function leave(ws) {
  const room = rooms.get(ws.roomCode);
  if (!room) return;
  room.delete(ws);
  broadcast(room, ws, { type: 'peer-left' });
  if (room.size === 0) rooms.delete(ws.roomCode);
  ws.roomCode = null;
}

wss.on('connection', (ws) => {
  ws.roomCode = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'join') {
      const code = String(msg.room || '').trim().toUpperCase();
      if (!/^[A-Z0-9]{4,12}$/.test(code)) {
        return send(ws, { type: 'error', message: 'Room code must be 4-12 letters or digits.' });
      }
      if (ws.roomCode) leave(ws);
      const room = rooms.get(code) || new Set();
      if (room.size >= MAX_PEERS) {
        return send(ws, { type: 'error', message: 'This room is already full.' });
      }
      rooms.set(code, room);
      room.add(ws);
      ws.roomCode = code;
      send(ws, { type: 'joined', room: code, others: room.size - 1 });
      broadcast(room, ws, { type: 'peer-joined' });
      return;
    }

    const room = rooms.get(ws.roomCode);
    if (room) broadcast(room, ws, msg);
  });

  ws.on('close', () => leave(ws));
});

server.listen(PORT, () => console.log(`Signaling server on http://localhost:${PORT}`));