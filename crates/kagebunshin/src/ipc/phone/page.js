// The approval page of a paired phone. It shows what the daemon says is
// waiting, and answers with the phone's passkey. Nothing here is trusted
// by the daemon: it checks the passkey's signature itself.
//
// Its service worker (sw.js) shows the notification the daemon sends when
// a request starts waiting. An iPhone lets a page be notified only once
// it is on the home screen and opened from there.
'use strict';

const $ = (id) => document.getElementById(id);
// Everything the daemon sends goes through this before it is shown.
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const bytes = (text) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

const icon = {
  face: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8V6a3 3 0 0 1 3-3h2M16 3h2a3 3 0 0 1 3 3v2M21 16v2a3 3 0 0 1-3 3h-2M8 21H6a3 3 0 0 1-3-3v-2"/><path d="M8.5 9v1.5M15.5 9v1.5M12 9v4h-1M8.800 15.600a4.500 4.500 0 0 0 6.400 0"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.500l4.500 4.500L19 7.500"/></svg>',
  cross: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  calm: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5.500c0 4.200-2.900 7.600-7 9.500-4.100-1.900-7-5.300-7-9.500V6z"/><path d="M9 12l2.200 2.200L15.200 10"/></svg>',
  away: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5h16v11H4zM9 20h6M12 16v4M9.500 8.500l5 5M14.500 8.500l-5 5"/></svg>',
  share: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3M8 7l4-4 4 4M6 11H5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-8a1 1 0 0 0-1-1h-1"/></svg>',
  bell: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M6 10a6 6 0 0 1 12 0c0 5 2 6 2 7H4c0-1 2-2 2-7M10 20a2 2 0 0 0 4 0"/></svg>',
};

// Whether this was opened from the home screen, and whether the browser
// lets it be notified here.
const standalone = navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
const pushes = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
// The request a tapped notification was for, until it has been shown.
let wanted = Number(new URLSearchParams(location.search).get('req')) || null;
if (location.search) history.replaceState(null, '', '/');

// A refusal, in the daemon's words where it gave any.
class Refused extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// How long one request to the daemon may take. The state is held back
// for up to 25 seconds while nothing changes.
const PATIENCE = 40000;

async function post(path, body = {}, signal) {
  const limit = AbortSignal.timeout(PATIENCE);
  const reply = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    cache: 'no-store',
    signal: signal ? AbortSignal.any([signal, limit]) : limit,
  });
  let said = null;
  try { said = await reply.json(); } catch { /* not JSON: said below */ }
  if (!reply.ok) throw new Refused(reply.status, (said && said.error) || `The computer answered ${reply.status}.`);
  if (!said) throw new Error('the computer sent something this page cannot read');
  return said;
}

// What the daemon last said, which screen shows, and when each waiting
// request is denied unanswered (by this phone's clock).
let state = null;
let shown = '';
let busy = false;
let tick = null;
let timer = null;
const deadlines = new Map();

function show(name, html) {
  shown = name;
  clearInterval(tick);
  clearTimeout(timer);
  const main = $('main');
  main.innerHTML = html;
  main.classList.remove('in');
  void main.offsetWidth;
  main.classList.add('in');
}

const clock = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
const ago = (s) => s < 90 ? 'just now'
  : s < 5400 ? `${Math.round(s / 60)} min ago`
  : s < 129600 ? `${Math.round(s / 3600)} h ago`
  : `${Math.round(s / 86400)} d ago`;
const outcomes = { approved: 'Approved', denied: 'Denied', timed_out: 'Timed out', ended: 'Ended' };
const places = { desk: 'at the desk', phone: 'on this phone' };
const cancelled = (e) => e.name === 'NotAllowedError' || e.name === 'AbortError';

// The computer does not answer: locked, asleep, or off the tailnet.
function away(why) {
  if (shown === 'away') return;
  show('away', `<div class="center"><div class="ring">${icon.away}</div>
    <h1>Cannot reach your computer</h1>
    <p class="dim">${esc(why)}</p>
    <p class="dim">This page answers only while kagebunshin is unlocked there and both are on the tailnet. It keeps trying.</p></div>`);
}

function unpaired() {
  if (shown === 'unpaired') return;
  show('unpaired', `<div class="center"><div class="ring">${icon.away}</div>
    <h1>This phone is not paired</h1>
    <p class="dim">In the kagebunshin app on your computer, open <span class="strong">Phone</span> and pick this phone. It then shows a code to scan.</p></div>`);
}

// The phone being paired makes its passkey.
function pair() {
  let left = state.pairing;
  show('pair', `<div class="scroll">
    <span class="pill" id="left"></span>
    <h1>Pair this phone</h1>
    <p class="dim">One tap, once. After that, approving a request here asks for Face ID.</p>
    <div class="card">
      <div class="row"><div class="grow"><div class="t">Approval key</div>
        <div class="s">A passkey kept on this phone. ${esc(state.machine)} keeps only its public half.</div></div>
        <button class="small" id="make">Create</button></div>
    </div>
    <div class="err spaced" id="err"></div></div>`);
  const paint = () => {
    const pill = $('left');
    if (pill) pill.textContent = `pairing ends in ${clock(Math.max(left, 0))}`;
    left -= 1;
  };
  paint();
  tick = setInterval(paint, 1000);
  $('make').onclick = async () => {
    $('make').disabled = true;
    $('err').textContent = '';
    busy = true;
    try {
      const begin = await post('/pair/begin');
      const made = await navigator.credentials.create({ publicKey: {
        rp: { id: location.hostname, name: 'kagebunshin' },
        // The same for every pairing with this computer, so a new passkey
        // replaces the old one where the phone keeps them.
        user: { id: new TextEncoder().encode('kagebunshin'), name: begin.name, displayName: begin.name },
        challenge: bytes(begin.challenge),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        attestation: 'none',
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required', authenticatorAttachment: 'platform' },
        timeout: 120000,
      } });
      await post('/pair/finish', {
        client_data: b64(made.response.clientDataJSON),
        auth_data: b64(made.response.getAuthenticatorData()),
      });
      busy = false;
      state = await post('/state');
      shown = '';
      route();
    } catch (e) {
      busy = false;
      if ($('err')) $('err').textContent = cancelled(e) ? 'Cancelled. Try again when you are ready.' : e.message;
      if ($('make')) $('make').disabled = false;
    }
  };
}

// Has this phone told of each request that waits: `ask` asks the person
// to allow notifications first, which only a tap may do.
async function notify(ask) {
  if (ask && await Notification.requestPermission() !== 'granted') {
    throw new Error('Notifications were not allowed. Allow them for Kagebunshin in this phone\u2019s settings.');
  }
  const worker = await navigator.serviceWorker.ready;
  const { key } = await post('/push/key');
  // What the browser gave for another key is of no use with this one.
  let held = await worker.pushManager.getSubscription();
  if (held && (!held.options.applicationServerKey || b64(held.options.applicationServerKey) !== key)) {
    await held.unsubscribe();
    held = null;
  }
  if (!held) held = await worker.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: bytes(key) });
  const said = held.toJSON();
  await post('/push/subscribe', { endpoint: said.endpoint, p256dh: said.keys.p256dh, auth: said.keys.auth });
}

// What stands between this phone and being notified, if anything does.
function notices() {
  if (state.notified) return '';
  const card = (mark, title, text, button) => `<div class="card notice"><div class="row">${mark}
    <div class="grow"><div class="t">${title}</div><div class="s">${text}</div></div>${button || ''}</div></div>`;
  if (!pushes) {
    return standalone ? '' : card(icon.share, 'Add to Home Screen',
      'To be told here when a command asks: in Safari, tap Share, then Add to Home Screen, and open Kagebunshin from there.');
  }
  if (Notification.permission === 'denied') {
    return card(icon.bell, 'Notifications are off', 'Allow them for Kagebunshin in this phone\u2019s settings to be told here when a command asks.');
  }
  return `${card(icon.bell, 'Notifications', 'Be told here when a command asks, wherever you are.', '<button class="small" id="notify">Turn on</button>')}
    <div class="err spaced" id="err"></div>`;
}

// Takes down the notifications of requests that no longer wait.
async function tidy() {
  try {
    const worker = await navigator.serviceWorker.getRegistration();
    for (const shown of await worker.getNotifications()) {
      const id = shown.data && shown.data.id;
      if (!state.prompts.some((p) => p.id === id)) shown.close();
    }
  } catch { /* a browser that does not list them keeps them */ }
}

function idle() {
  const rows = state.recent.map((r) => `<div class="row"><span class="dot ${r.outcome === 'approved' ? '' : r.outcome === 'denied' ? 'no' : 'none'}"></span>
    <div class="grow"><div class="t">${esc(r.project)}/${esc(r.env)}</div><div class="s mono">${esc(r.command)}</div></div>
    <div class="s right">${esc((outcomes[r.outcome] || r.outcome).toLowerCase())}<br>${ago(Math.max(state.now - r.time, 0))}${r.by ? ` · ${r.by === 'phone' ? 'phone' : 'desk'}` : ''}</div></div>`).join('');
  show('idle', `<div class="scroll column">${notices()}
    <div class="center top"><div class="ring">${icon.calm}</div>
      <h1>Nothing is waiting</h1>
      <p class="dim">A command that asks for sensitive values on <span class="strong">${esc(state.machine)}</span> shows up here.</p></div>
    ${rows ? `<div class="label">Recent</div><div class="card flush">${rows}</div>` : ''}</div>`);
  const on = $('notify');
  if (!on) return;
  on.onclick = async () => {
    on.disabled = true;
    $('err').textContent = '';
    busy = true;
    try {
      await notify(true);
      busy = false;
      state = await post('/state');
      shown = '';
      route();
    } catch (e) {
      busy = false;
      if (shown !== 'idle') return route();
      if ($('err')) $('err').textContent = e.message;
      if ($('notify')) $('notify').disabled = false;
    }
  };
}

// One waiting request, in the words the app on the computer uses: who
// asks, the question, the command and one line of what it gets. How it
// got here, why it waits and what approving does are a tap away.
function request(p, more) {
  const w = p.words;
  const keys = p.keys.map((k) => `<span class="chip">${esc(k)}</span>`).join('');
  const line = p.here ? w.summary : 'This one takes the passphrase: answer it in the app on your computer. You can deny it here.';
  show(`request:${p.id}`, `<div class="scroll">
    <div class="who"><b>${esc(w.who)}</b><span class="place">${esc(w.place)}</span><span class="left" id="left"></span></div>
    <h1>${esc(w.question)}</h1>
    ${w.command_plain ? '' : `<div class="label">${esc(w.command_label)}</div>`}<div class="cmd">${esc(w.command)}</div>
    <div class="line">${esc(line)} <button class="link" id="more">Details</button></div>
    ${more ? `<div class="line">${more} more waiting after this one</div>` : ''}
    <div class="details" id="details" hidden>
      ${p.here && keys ? `<div class="label">${esc(w.wants)}</div><div class="chips">${keys}</div>` : ''}
      <div class="label">${esc(w.asked_label)}</div><div class="chain">${esc(w.detail)}</div>
      ${w.why ? `<div class="label">Why it asks</div><div>${esc(w.why)}</div>` : ''}
      <div class="label">Approving</div><div>${esc(w.trust)}</div>
    </div>
  </div>
  <div class="err" id="err"></div>
  <div class="bar"><button class="deny" id="deny">Deny</button>${p.here ? `<button class="approve" id="approve">${icon.face} Approve</button>` : ''}</div>`);
  $('more').onclick = () => {
    const open = $('details').hidden;
    $('details').hidden = !open;
    $('more').textContent = open ? 'Hide details' : 'Details';
  };
  const paint = () => {
    const pill = $('left');
    if (!pill) return;
    const left = Math.max(Math.round((deadlines.get(p.id) - Date.now()) / 1000), 0);
    pill.textContent = `denied in ${clock(left)}`;
    pill.classList.toggle('soon', left < 60);
  };
  paint();
  tick = setInterval(paint, 1000);
  const answer = async (button, work, outcome) => {
    button.disabled = true;
    $('err').textContent = '';
    busy = true;
    try {
      await work();
      busy = false;
      if (wanted === p.id) wanted = null;
      result({ ...p, command: w.command, outcome, by: 'phone' });
    } catch (e) {
      busy = false;
      // Answered elsewhere meanwhile, say: what is true now is shown.
      if (shown !== `request:${p.id}`) return;
      if (!state.prompts.some((x) => x.id === p.id)) return route();
      $('err').textContent = cancelled(e) ? 'Face ID was cancelled. Nothing was approved.' : e.message;
      button.disabled = false;
    }
  };
  if (p.here) {
    $('approve').onclick = () => answer($('approve'), async () => {
      const begin = await post('/approve/begin', { id: p.id });
      const signed = await navigator.credentials.get({ publicKey: {
        challenge: bytes(begin.challenge),
        rpId: location.hostname,
        allowCredentials: [{ type: 'public-key', id: bytes(begin.credential) }],
        userVerification: 'required',
        timeout: 120000,
      } });
      await post('/approve/finish', {
        id: p.id,
        client_data: b64(signed.response.clientDataJSON),
        auth_data: b64(signed.response.authenticatorData),
        signature: b64(signed.response.signature),
      });
    }, 'approved');
  }
  $('deny').onclick = () => answer($('deny'), () => post('/deny', { id: p.id }), 'denied');
}

// How a request ended: here, or wherever it was answered.
function result(r) {
  const ok = r.outcome === 'approved';
  const short = r.command.length > 48 ? `${r.command.slice(0, 47)}…` : r.command;
  const text = ok ? `<span class="strong">${esc(short)}</span> has the values of ${esc(r.project)}/${esc(r.env)}.`
    : r.outcome === 'ended' ? 'The command stopped waiting. Nothing was handed out.'
    : 'Nothing was handed out.';
  const where = r.by && r.by !== 'phone' ? `<br>Answered ${places[r.by] || ''}.` : '';
  show('result', `<div class="center"><div class="ring ${ok ? 'ok' : 'no'}">${ok ? icon.check : icon.cross}</div>
    <h1>${esc(outcomes[r.outcome] || 'Answered')}</h1><p class="dim">${text}${where}</p></div>
    <div class="bar"><button class="plain" id="ok">Done</button></div>`);
  const back = () => { shown = ''; route(); };
  $('ok').onclick = back;
  timer = setTimeout(back, 4000);
}

// Shows what `state` calls for, unless a person is in the middle of
// something: Face ID, or reading how the last request ended.
function route() {
  $('where').textContent = state.machine;
  $('where').hidden = false;
  const now = Date.now();
  deadlines.clear();
  for (const p of state.prompts) deadlines.set(p.id, now + p.left * 1000);
  if (busy || shown === 'result') return;
  if (state.pairing !== null) { if (shown !== 'pair') pair(); return; }
  if (!state.paired) return unpaired();
  tidy();
  // Allowed before, but what that gave is not kept there: after pairing
  // again, say. Given again, once, without asking.
  if (pushes && !state.notified && !notify.again && Notification.permission === 'granted') {
    notify.again = true;
    notify(false).catch(() => {});
  }
  // A notification's request comes first; one that no longer waits is
  // shown as it ended.
  const asked = wanted && state.prompts.find((p) => p.id === wanted);
  if (wanted && !asked) {
    const r = state.recent.find((x) => x.id === wanted);
    wanted = null;
    if (r) return result(r);
  }
  const next = asked || state.prompts[0];
  if (next) {
    if (shown !== `request:${next.id}`) request(next, state.prompts.length - 1);
    return;
  }
  if (shown.startsWith('request:')) {
    const id = Number(shown.slice(8));
    const r = state.recent.find((x) => x.id === id);
    if (r) return result(r);
  }
  idle.listed = idle.listed || '';
  const listed = JSON.stringify([state.notified, pushes && Notification.permission, state.recent.map((r) => [r.id, r.outcome])]);
  if (shown !== 'idle' || idle.listed !== listed) { idle.listed = listed; idle(); }
}

// Asks for the state again and again; the daemon holds each answer back
// until something changed. Coming back to the page asks afresh, at once.
let asking = null;
let fresh = true;
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') { fresh = true; if (asking) asking.abort(); }
});

(async () => {
  for (;;) {
    asking = new AbortController();
    const seen = fresh || !state ? null : state.version;
    fresh = false;
    try {
      state = await post('/state', { seen }, asking.signal);
      if (shown === 'away' || shown === 'unpaired') shown = '';
      route();
    } catch (e) {
      if (asking.signal.aborted) continue;
      if (!busy) {
        // 403 is what a phone that is not paired gets for everything.
        if (e instanceof Refused && e.status === 403) unpaired();
        else away(e instanceof Refused ? e.message : 'It did not answer.');
      }
      fresh = true;
      await sleep(3000);
    }
  }
})();
