// Shows who is signed in (name from the server's signed session) and bounces to /login if the session ended.
(async () => {
  try {
    const r = await fetch('/api/me', { credentials: 'same-origin' });
    if (r.status === 401) { location.replace('/login'); return; }
    const me = await r.json();
    const el = document.getElementById('who');
    el.textContent = me.name;
    el.hidden = false;
  } catch (e) { /* offline: leave the header as is */ }
})();
