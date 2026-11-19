// The approval page of a paired phone. It shows what the daemon says is
// waiting, and answers with the phone's passkey. Nothing here is trusted
// by the daemon: it checks the passkey's signature itself.
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
};

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

function idle() {
  const rows = state.recent.map((r) => `<div class="row"><span class="dot ${r.outcome === 'approved' ? '' : r.outcome === 'denied' ? 'no' : 'none'}"></span>
    <div class="grow"><div class="t">${esc(r.project)}/${esc(r.env)}</div><div class="s mono">${esc(r.command)}</div></div>
    <div class="s right">${esc((outcomes[r.outcome] || r.outcome).toLowerCase())}<br>${ago(Math.max(state.now - r.time, 0))}${r.by ? ` · ${r.by === 'phone' ? 'phone' : 'desk'}` : ''}</div></div>`).join('');
  show('idle', `<div class="scroll column">
    <div class="center top"><div class="ring">${icon.calm}</div>
      <h1>Nothing is waiting</h1>
      <p class="dim">A command that asks for sensitive values on <span class="strong">${esc(state.machine)}</span> shows up here.</p></div>
    ${rows ? `<div class="label">Recent</div><div class="card flush">${rows}</div>` : ''}</div>`);
}

// One waiting request, in the words the app on the computer uses.
function request(p, more) {
  const w = p.words;
  const keys = p.keys.map((k) => `<span class="chip">${esc(k)}</span>`).join('');
  show(`request:${p.id}`, `<div class="scroll">
    <span class="pill" id="left"></span>${more ? ` <span class="pill">${more} more waiting</span>` : ''}
    <h1>${esc(w.title)}</h1>
    <div class="label">${esc(w.command_label)}</div><div class="cmd">${esc(w.command)}</div>
    <div class="label">${esc(w.wants)}</div>${keys ? `<div class="chips">${keys}</div>` : ''}
    <div class="label">${esc(w.asked_label)}</div>
    <div><b>${esc(w.who)}</b>${esc(w.place)}</div><div class="chain">${esc(w.detail)}</div>
    ${w.why ? `<div class="label">Why it asks</div><div>${esc(w.why)}</div>` : ''}
    <div class="warn">${p.here ? esc(w.trust) : 'This one takes the passphrase: answer it in the app on your computer. You can deny it here.'}</div>
  </div>
  <div class="err" id="err"></div>
  <div class="bar"><button class="deny" id="deny">Deny</button>${p.here ? `<button class="approve" id="approve">${icon.face} Approve</button>` : ''}</div>`);
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
  const next = state.prompts[0];
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
  const listed = JSON.stringify(state.recent.map((r) => [r.id, r.outcome]));
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
