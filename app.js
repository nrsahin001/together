// Client: signaling over WebSocket, one WebRTC peer connection, and a data channel.
// Either person can start a stream (screen or video file). The stream is always the
// main screen, and both people can control it: the person who owns the video file
// applies the commands, and everyone else sends commands to them.

const $ = (id) => document.getElementById(id);
const stage = $('stage');
const main = $('main');
const els = {
  room: $('room'), connect: $('connect'), dot: $('dot'), statusText: $('statusText'),
  empty: $('empty'), sharing: $('sharing'), stopShare: $('stopShare'), chip: $('chip'),
  tiles: $('tiles'), seek: $('seek'), back: $('back'), toggle: $('toggle'), fwd: $('fwd'),
  vol: $('vol'), time: $('time'), mic: $('mic'), cam: $('cam'), screen: $('screen'),
  fileBtn: $('fileBtn'), fs: $('fs'), file: $('file'), log: $('log'),
};

const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];
// For devices on strict networks, add a TURN server here:
// { urls: 'turn:your.server:3478', username: '...', credential: '...' }

let ws = null, pc = null, channel = null;
let polite = false, makingOffer = false, ignoreOffer = false;
let stateTimer = null, blobUrl = null;
let needsTap = false, scrubbing = false;

const localStreams = new Map();   // 'mic' | 'cam' | 'screen' | 'file' -> MediaStream we send
const remoteStreams = new Map();  // stream.id -> MediaStream we receive
let activeStream = null;          // { owner: 'me' | 'partner', kind: 'file' | 'screen', name, id }
let playerState = { position: 0, duration: 0, paused: true, at: 0 }; // last state from the owner

const clamp = (n, lo, hi) => Math.min(Math.max(n, lo), hi);
const fmt = (s) => {
  s = Math.max(0, Math.floor(s || 0));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h ? `${h}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}` : `${m}:${String(sec).padStart(2, '0')}`;
};
const log = (text) => { els.log.textContent = text; };
const isMine = () => activeStream?.owner === 'me';
const isMyFile = () => isMine() && activeStream.kind === 'file';

// ---------- Signaling ----------

function randomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function setStatus(connected, text) {
  els.dot.classList.toggle('on', connected);
  els.statusText.textContent = text;
}

function setShareEnabled(on) {
  for (const b of [els.mic, els.cam, els.screen, els.fileBtn]) b.disabled = !on;
}

function connect() {
  const code = (els.room.value.trim() || randomCode()).toUpperCase();
  els.room.value = code;
  els.connect.disabled = true;

  ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`);
  ws.onopen = () => ws.send(JSON.stringify({ type: 'join', room: code }));
  ws.onclose = () => {
    setStatus(false, 'Disconnected');
    setShareEnabled(false);
    els.connect.disabled = false;
    teardownPeer();
  };
  ws.onmessage = async (e) => {
    const msg = JSON.parse(e.data);
    switch (msg.type) {
      case 'joined':
        polite = msg.others > 0;          // someone was already here, so we yield on collisions
        setupPeer();
        setStatus(true, msg.others ? `Room ${msg.room}: partner is here` : `Room ${msg.room}: waiting for partner`);
        setShareEnabled(true);
        break;
      case 'peer-joined':
        setStatus(true, `Room ${els.room.value}: partner joined`);
        if (!polite) openChannel(pc.createDataChannel('sync'));   // the first joiner opens the channel
        break;
      case 'peer-left':
        setStatus(true, `Room ${els.room.value}: partner left`);
        clearRemote();
        setupPeer();                       // fresh connection for whoever joins next
        break;
      case 'signal':
        await handleSignal(msg);
        break;
      case 'error':
        log(msg.message);
        els.connect.disabled = false;
        break;
    }
  };
}

function signal(payload) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'signal', ...payload }));
}

// ---------- Peer connection (perfect negotiation) ----------

function setupPeer() {
  teardownPeer();
  pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  makingOffer = false;
  ignoreOffer = false;

  pc.onicecandidate = ({ candidate }) => { if (candidate) signal({ candidate }); };

  // Fires whenever tracks are added, so starting a call or stream mid-session just works
  pc.onnegotiationneeded = async () => {
    try {
      makingOffer = true;
      await pc.setLocalDescription();
      signal({ description: pc.localDescription });
    } catch (err) { console.error(err); }
    finally { makingOffer = false; }
  };

  pc.ontrack = ({ track, streams }) => {
    const stream = streams[0] || new MediaStream([track]);
    if (!remoteStreams.has(stream.id)) {
      remoteStreams.set(stream.id, stream);
      stream.onremovetrack = () => {
        if (!stream.getTracks().length) { remoteStreams.delete(stream.id); renderTiles(); }
      };
    }
    attachRemoteMain();
    renderTiles();
  };
  pc.ondatachannel = ({ channel: ch }) => openChannel(ch);
  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'connected') log('Connected to your partner.');
    if (pc.connectionState === 'failed') log('Connection failed. A TURN server may be needed on this network.');
  };

  // Re-attach anything we were already sending (after a partner reconnects)
  for (const stream of localStreams.values()) {
    for (const track of stream.getTracks()) pc.addTrack(track, stream);
  }
}

function teardownPeer() {
  clearInterval(stateTimer);
  if (channel) { channel.onmessage = null; channel.close(); channel = null; }
  if (pc) { pc.close(); pc = null; }
}

async function handleSignal({ description, candidate }) {
  if (!pc) return;
  try {
    if (description) {
      const collision = description.type === 'offer' && (makingOffer || pc.signalingState !== 'stable');
      ignoreOffer = !polite && collision;
      if (ignoreOffer) return;
      await pc.setRemoteDescription(description);
      if (description.type === 'offer') {
        await pc.setLocalDescription();
        signal({ description: pc.localDescription });
      }
    } else if (candidate) {
      try { await pc.addIceCandidate(candidate); }
      catch (err) { if (!ignoreOffer) throw err; }
    }
  } catch (err) { console.error(err); }
}

// ---------- Data channel ----------

function openChannel(ch) {
  channel = ch;
  ch.onopen = () => {
    log('Connected to your partner.');
    clearInterval(stateTimer);
    stateTimer = setInterval(sendState, 1000);
    if (isMine()) {            // tell a newly joined partner what is on the stage
      announceStream();
      sendState();
    }
  };
  ch.onclose = () => clearInterval(stateTimer);
  ch.onmessage = (e) => onData(JSON.parse(e.data));
}

function sendData(msg) {
  if (channel && channel.readyState === 'open') channel.send(JSON.stringify(msg));
}

function announceStream() {
  sendData({ t: 'stream-start', kind: activeStream.kind, id: activeStream.id, name: activeStream.name });
}

function sendState() {
  if (!isMyFile()) return;
  sendData({ t: 'state', position: main.currentTime, duration: main.duration || 0, paused: main.paused });
}

function onData(m) {
  switch (m.t) {
    case 'stream-start':               // partner took the stage
      takeStageFor('partner');
      activeStream = { owner: 'partner', kind: m.kind, name: m.name, id: m.id };
      playerState = { position: 0, duration: 0, paused: true, at: performance.now() };
      attachRemoteMain();
      renderTiles(); renderStage(); renderControls();
      log(m.kind === 'screen' ? 'Your partner is sharing their screen.' : `Your partner is streaming ${m.name}.`);
      break;
    case 'stream-stop':
      if (activeStream?.owner === 'partner') {
        remoteStreams.delete(activeStream.id);
        activeStream = null;
        resetMain();
        renderTiles(); renderStage(); renderControls();
      }
      break;
    case 'state':
      playerState = { position: m.position, duration: m.duration, paused: m.paused, at: performance.now() };
      renderControls();
      break;
    case 'cmd':
      if (isMyFile()) applyCommand(m.action, m.value);
      break;
  }
}

// ---------- Playback control (shared) ----------

// Whoever clicks, the owner of the file performs the action; the other side asks for it.
function command(action, value) {
  if (activeStream?.kind !== 'file') return;
  if (isMyFile()) return applyCommand(action, value);

  sendData({ t: 'cmd', action, value });
  // Update our own controls right away; the owner's next state message corrects them if needed
  const p = playerState, pos = currentPos();
  if (action === 'toggle') playerState = { ...p, position: pos, paused: !p.paused, at: performance.now() };
  if (action === 'seek-rel') playerState = { ...p, position: clamp(pos + value, 0, p.duration || 0), at: performance.now() };
  if (action === 'seek-abs') playerState = { ...p, position: value, at: performance.now() };
  renderControls();
}

function applyCommand(action, value) {
  const dur = main.duration || 0;
  if (action === 'toggle') { main.paused ? main.play().catch(() => {}) : main.pause(); }
  if (action === 'seek-rel') main.currentTime = clamp(main.currentTime + value, 0, dur);
  if (action === 'seek-abs') main.currentTime = clamp(value, 0, dur);
}

function currentPaused() { return isMyFile() ? main.paused : playerState.paused; }
function currentDur() { return isMyFile() ? (main.duration || 0) : playerState.duration; }
function currentPos() {
  if (isMyFile()) return main.currentTime;
  if (activeStream?.kind !== 'file') return 0;
  const p = playerState;
  if (p.paused) return p.position;
  return Math.min(p.duration || Infinity, p.position + (performance.now() - p.at) / 1000);
}

for (const ev of ['play', 'pause', 'seeked', 'ended', 'loadedmetadata']) {
  main.addEventListener(ev, () => { if (isMyFile()) { renderControls(); sendState(); } });
}
main.addEventListener('timeupdate', () => { if (isMyFile()) renderTime(); });

// ---------- Stage ownership ----------

function resetMain() {
  main.pause();
  main.srcObject = null;
  main.removeAttribute('src');
  main.load();
  if (blobUrl) { URL.revokeObjectURL(blobUrl); blobUrl = null; }
  needsTap = false;
}

// Before a new stream takes the stage, clear whatever was there.
function takeStageFor(who) {
  if (isMine()) stopMyStream(false);                 // yield quietly; the new start message replaces it
  else if (activeStream?.owner === 'partner') remoteStreams.delete(activeStream.id);
  if (who === 'me') activeStream = null;
  resetMain();
}

function stopMyStream(announce = true) {
  if (!isMine()) return;
  removeStream(activeStream.kind);
  activeStream = null;
  resetMain();
  if (announce) sendData({ t: 'stream-stop' });
  renderStage(); renderControls();
}

function attachRemoteMain() {
  if (activeStream?.owner !== 'partner') return;
  const s = remoteStreams.get(activeStream.id);
  if (!s || main.srcObject === s) return;
  main.removeAttribute('src');
  main.srcObject = s;
  main.muted = false;
  main.play().then(() => { needsTap = false; })
    .catch(() => { needsTap = true; log('Tap the video once to start playback.'); });
}

async function startFileStream(file) {
  takeStageFor('me');
  blobUrl = URL.createObjectURL(file);
  main.muted = false;
  main.src = blobUrl;
  await new Promise((resolve, reject) => {
    main.onloadedmetadata = resolve;
    main.onerror = () => reject(new Error('This file cannot be played in your browser.'));
  });
  main.onloadedmetadata = main.onerror = null;

  const capture = main.captureStream || main.mozCaptureStream;
  if (!capture) throw new Error('Streaming a video file needs Chrome, Edge or Firefox on a computer or Android.');
  const stream = capture.call(main);
  activeStream = { owner: 'me', kind: 'file', name: file.name, id: stream.id };
  addStream('file', stream);
  announceStream();
  await main.play().catch(() => {});
  renderTiles(); renderStage(); renderControls(); sendState();
}

async function startScreenShare() {
  if (!navigator.mediaDevices?.getDisplayMedia) {
    throw new Error('Screen sharing is not available in this browser. Phones usually cannot share their screen.');
  }
  const stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true });
  takeStageFor('me');
  activeStream = { owner: 'me', kind: 'screen', name: 'Screen share', id: stream.id };
  addStream('screen', stream);
  announceStream();
  renderTiles(); renderStage(); renderControls();
}

// ---------- Local media tracks ----------

function addStream(name, stream) {
  localStreams.set(name, stream);
  for (const track of stream.getTracks()) {
    pc.addTrack(track, stream);
    if (name !== 'file') track.onended = () => stopLocal(name);   // e.g. browser "Stop sharing"
  }
  // captureStream can add tracks after the first frame
  stream.onaddtrack = (e) => { if (pc) pc.addTrack(e.track, stream); };
}

function removeStream(name) {
  const stream = localStreams.get(name);
  if (!stream) return;
  stream.onaddtrack = null;
  const tracks = stream.getTracks();
  tracks.forEach((t) => { t.onended = null; t.stop(); });
  localStreams.delete(name);
  if (pc) for (const sender of pc.getSenders()) if (sender.track && tracks.includes(sender.track)) pc.removeTrack(sender);
  if (name === 'cam') renderTiles();
}

function stopLocal(name) {
  if (name === 'screen' || name === 'file') { if (isMine() && activeStream.kind === name) stopMyStream(); }
  else removeStream(name);
  renderTiles(); renderControls();
}

async function toggleDevice(name, constraints) {
  if (localStreams.has(name)) return stopLocal(name);
  addStream(name, await navigator.mediaDevices.getUserMedia(constraints));
  renderTiles(); renderControls();
}

// ---------- Rendering ----------

function clearRemote() {
  remoteStreams.clear();
  if (activeStream?.owner === 'partner') { activeStream = null; resetMain(); }
  renderTiles(); renderStage(); renderControls();
}

function renderTiles() {
  const want = new Map();
  for (const [id, s] of remoteStreams) {
    if (activeStream?.owner === 'partner' && activeStream.id === id) continue;   // that one is the main screen
    want.set(`r-${id}`, s);
  }
  if (localStreams.has('cam')) want.set('local-cam', localStreams.get('cam'));

  for (const el of [...els.tiles.children]) {
    if (!want.has(el.dataset.key)) { el.srcObject = null; el.remove(); }
  }
  for (const [key, s] of want) {
    let el = [...els.tiles.children].find((c) => c.dataset.key === key);
    if (!el) {
      el = document.createElement('video');
      el.dataset.key = key;
      el.autoplay = true;
      el.playsInline = true;
      if (key === 'local-cam') { el.muted = true; el.classList.add('mirror'); }
      els.tiles.appendChild(el);
    }
    if (el.srcObject !== s) el.srcObject = s;
    el.classList.toggle('audio-only', s.getVideoTracks().length === 0);
  }
}

function renderStage() {
  const sharingScreen = isMine() && activeStream.kind === 'screen';
  main.hidden = !activeStream || sharingScreen;
  els.empty.hidden = !!activeStream;
  els.sharing.hidden = !sharingScreen;
  els.chip.hidden = !activeStream;
  if (activeStream) {
    els.chip.textContent = isMine()
      ? `You are streaming: ${activeStream.name}`
      : (activeStream.kind === 'screen' ? 'Your partner is sharing their screen' : `Your partner is streaming: ${activeStream.name}`);
  }
  wake();
}

function renderControls() {
  const file = activeStream?.kind === 'file';
  for (const b of [els.back, els.toggle, els.fwd]) b.disabled = !file;
  els.seek.disabled = !file;
  els.toggle.classList.toggle('flip', file && !currentPaused());
  els.vol.disabled = !activeStream || isMine();      // you hear your own file through your device volume
  els.vol.classList.toggle('flip', main.muted);
  els.mic.classList.toggle('active', localStreams.has('mic'));
  els.cam.classList.toggle('active', localStreams.has('cam'));
  els.screen.classList.toggle('active', isMine() && activeStream.kind === 'screen');
  els.fileBtn.classList.toggle('active', isMyFile());
  renderTime();
}

function renderTime() {
  const pos = currentPos(), dur = currentDur();
  els.time.textContent = activeStream?.kind === 'file' ? `${fmt(pos)} / ${fmt(dur)}` : (activeStream ? 'Live' : '');
  if (!scrubbing) {
    const v = dur ? clamp((pos / dur) * 1000, 0, 1000) : 0;
    els.seek.value = v;
    els.seek.style.setProperty('--pct', `${v / 10}%`);
  }
}
setInterval(renderTime, 250);

// ---------- Fullscreen / maximize ----------

const fsElement = () => document.fullscreenElement || document.webkitFullscreenElement;

function renderFs() {
  els.fs.classList.toggle('flip', !!fsElement() || stage.classList.contains('maximized'));
}

function toggleFullscreen() {
  if (stage.classList.contains('maximized')) { stage.classList.remove('maximized'); return renderFs(); }
  if (fsElement()) { (document.exitFullscreen || document.webkitExitFullscreen).call(document); return; }
  const request = stage.requestFullscreen || stage.webkitRequestFullscreen;
  if (!request) { stage.classList.add('maximized'); return renderFs(); }   // e.g. iPhone: fill the page instead
  const p = request.call(stage);
  if (p && p.catch) p.catch(() => { stage.classList.add('maximized'); renderFs(); });
}
document.addEventListener('fullscreenchange', renderFs);
document.addEventListener('webkitfullscreenchange', renderFs);

// ---------- Auto-hide controls ----------

let idleTimer = null;
function wake() {
  stage.classList.remove('idle');
  clearTimeout(idleTimer);
  if (activeStream) idleTimer = setTimeout(() => stage.classList.add('idle'), 3000);
}
for (const ev of ['mousemove', 'pointerdown', 'touchstart']) stage.addEventListener(ev, wake);

// ---------- Wire up the UI ----------

function guard(fn) {
  return async (...args) => { try { await fn(...args); } catch (err) { log(err.message); if (!activeStream) resetMain(); } };
}

els.connect.onclick = connect;
els.room.onkeydown = (e) => { if (e.key === 'Enter') connect(); };

els.toggle.onclick = () => command('toggle');
els.back.onclick = () => command('seek-rel', -10);
els.fwd.onclick = () => command('seek-rel', 10);
els.vol.onclick = () => { main.muted = !main.muted; renderControls(); };
els.fs.onclick = toggleFullscreen;
els.stopShare.onclick = () => stopMyStream();

els.seek.addEventListener('input', () => {
  scrubbing = true;
  els.seek.style.setProperty('--pct', `${els.seek.value / 10}%`);
});
els.seek.addEventListener('change', () => {
  command('seek-abs', (els.seek.value / 1000) * currentDur());
  setTimeout(() => { scrubbing = false; }, 150);
});

els.mic.onclick = guard(() => toggleDevice('mic', { audio: { echoCancellation: true, noiseSuppression: true } }));
els.cam.onclick = guard(() => toggleDevice('cam', { video: true }));
els.screen.onclick = guard(() => (isMine() && activeStream.kind === 'screen') ? stopMyStream() : startScreenShare());
els.fileBtn.onclick = () => { if (isMyFile()) stopMyStream(); else els.file.click(); };
els.file.onchange = guard(async () => {
  const f = els.file.files[0];
  els.file.value = '';
  if (f) await startFileStream(f);
});

// Click the picture to play/pause, double-click for fullscreen (like YouTube)
let clickTimer = null;
main.addEventListener('click', () => {
  if (needsTap) { main.play().then(() => { needsTap = false; }).catch(() => {}); return; }
  clearTimeout(clickTimer);
  clickTimer = setTimeout(() => command('toggle'), 250);
});
main.addEventListener('dblclick', () => { clearTimeout(clickTimer); toggleFullscreen(); });

document.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT') return;
  if (e.target.closest('button') && (e.key === ' ' || e.key === 'Enter')) return;
  const k = e.key.toLowerCase();
  if (k === ' ' || k === 'k') { e.preventDefault(); command('toggle'); }
  else if (k === 'arrowleft' || k === 'j') command('seek-rel', -10);
  else if (k === 'arrowright' || k === 'l') command('seek-rel', 10);
  else if (k === 'f') toggleFullscreen();
  else if (k === 'm' && !els.vol.disabled) els.vol.click();
  else if (k === 'escape' && stage.classList.contains('maximized')) toggleFullscreen();
  wake();
});

setShareEnabled(false);
renderStage();
renderControls();
renderFs();
