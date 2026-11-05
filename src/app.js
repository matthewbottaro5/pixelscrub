import { inspect, reencode, sha256, detectFormat, cleanVideo, VIDEO_FORMATS } from './scrub.js';
import { zip } from './zip.js';
import { CATEGORIES, CATEGORY_ORDER } from './categories.js';

const $ = (s, el = document) => el.querySelector(s);
const MAX_FILES = 30;
const MAX_VIDEO_BYTES = 750 * 1024 * 1024;
const VIDEO_EXT = /\.(mp4|m4v|mov|3gp)$/i;
const CONCURRENCY = 2;
const cleaned = [];
let pending = [];
let active = 0;

const SENSITIVE = new Set(['location', 'people', 'identity', 'tracking']);
const RISK_TEXT = { none: 'No hidden data', low: 'Low privacy risk', medium: 'Medium privacy risk', high: 'High privacy risk' };
const totals = { files: 0, fields: 0, bytes: 0, location: 0, ai: 0 };

function track(event, detail, level = 'info') {
  const body = JSON.stringify({ event, detail, level });
  if (navigator.sendBeacon) navigator.sendBeacon('/api/events', new Blob([body], { type: 'application/json' }));
  else fetch('/api/events', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, keepalive: true }).catch(() => {});
}

window.addEventListener('error', (e) => track('js.error', { message: e.message, src: e.filename, line: e.lineno }, 'error'));
window.addEventListener('unhandledrejection', (e) => track('js.error', { message: String(e.reason?.message || e.reason) }, 'error'));

const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);
const short = (h) => `${h.slice(0, 10)}…${h.slice(-6)}`;

function cleanName(name, ext) {
  const base = name.replace(/\.[^.]+$/, '').replace(/[^\w.-]+/g, '_').slice(0, 80) || 'image';
  return `${base}-clean.${ext}`;
}

function uniqueName(name) {
  const taken = new Set(cleaned.map((c) => c.name));
  if (!taken.has(name)) return name;
  const [, base, ext] = /^(.*?)(\.[^.]+)$/.exec(name);
  let i = 2;
  while (taken.has(`${base}-${i}${ext}`)) i++;
  return `${base}-${i}${ext}`;
}

function download(blob, name) {
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
}

function badge(text, cls = '') {
  return Object.assign(document.createElement('span'), { className: `badge ${cls}`, textContent: text });
}

function renderReport(card, report, format) {
  const cats = Object.keys(report.categories);
  const n = report.fields.length;

  if (format && n) {
    const risk = $('.risk', card);
    risk.hidden = false;
    risk.dataset.level = report.risk.level;
    $('.meter i', risk).style.width = `${Math.max(4, report.risk.score)}%`;
    $('.risk-label', risk).textContent = `${RISK_TEXT[report.risk.level]} · ${report.risk.score}/100`;
  }
  $('.summary', card).textContent = !format
    ? 'Format not inspected; the image is still re-encoded.'
    : n ? `Found ${n} item${n === 1 ? '' : 's'} in ${cats.length} categor${cats.length === 1 ? 'y' : 'ies'} · ${fmtBytes(report.metaBytes)} of hidden data`
      : 'No metadata found.';

  const badges = $('.badges', card);
  for (const c of cats) {
    const meta = CATEGORIES[c];
    const b = badge(`${meta.icon} ${meta.label} · ${report.categories[c]}`, SENSITIVE.has(c) ? 'warn' : c === 'ai' || c === 'provenance' ? 'ai' : '');
    b.title = meta.desc;
    badges.append(b);
  }
  if (format && !n) badges.append(badge('Nothing hidden', 'ok'));

  if (report.gps) {
    const gps = $('.gps', card);
    gps.hidden = false;
    gps.textContent = `📍 This photo contained its location: ${report.gps.lat.toFixed(5)}, ${report.gps.lon.toFixed(5)} (removed)`;
  }
  if (report.watermark) {
    const note = Object.assign(document.createElement('div'), { className: 'gps' });
    note.textContent = '⚠ The generator says it also embedded an invisible watermark in the pixels (e.g. SynthID). The label is removed, but the watermark itself may still be detectable.';
    $('.gps', card).after(note);
  }
  if (report.thumbnails.length) {
    const box = $('.hidden-thumbs', card);
    box.hidden = false;
    for (const t of report.thumbnails.slice(0, 3)) {
      const img = document.createElement('img');
      img.alt = 'Embedded thumbnail';
      img.src = URL.createObjectURL(new Blob([t], { type: 'image/jpeg' }));
      $('div', box).append(img);
    }
  }

  // Full breakdown, one group per category, most sensitive first.
  const groups = $('.groups', card);
  for (const c of CATEGORY_ORDER.filter((k) => report.categories[k])) {
    const sec = document.createElement('section');
    sec.className = `group${SENSITIVE.has(c) ? ' sensitive' : ''}`;
    const h = document.createElement('h4');
    h.textContent = `${CATEGORIES[c].icon} ${CATEGORIES[c].label}`;
    const count = Object.assign(document.createElement('span'), { textContent: ` ${report.categories[c]}` });
    h.append(count);
    const dl = document.createElement('dl');
    for (const f of report.fields.filter((x) => x.cat === c)) {
      const dt = Object.assign(document.createElement('dt'), { textContent: f.name });
      const dd = Object.assign(document.createElement('dd'), { textContent: f.value });
      dd.append(Object.assign(document.createElement('small'), { textContent: f.src }));
      dl.append(dt, dd);
    }
    sec.append(h, dl);
    groups.append(sec);
  }
  if (report.blocks.length) {
    $('.blocks', card).textContent = `Stripped containers: ${report.blocks.map((b) => `${b.label} (${fmtBytes(b.bytes)})`).join(', ')}`;
  }
  $('.found summary', card).textContent = `See all ${n} removed item${n === 1 ? '' : 's'}`;
  $('.found', card).hidden = !n;
}

function addTotals(report) {
  totals.files++;
  totals.fields += report.fields.length;
  totals.bytes += report.metaBytes;
  if (report.categories.location) totals.location++;
  if (report.categories.ai || report.ai.length) totals.ai++;
  const parts = [`${totals.fields} items removed`, `${fmtBytes(totals.bytes)} of hidden data`];
  if (totals.location) parts.push(`${totals.location} with location`);
  if (totals.ai) parts.push(`${totals.ai} with AI data`);
  $('#totals').textContent = parts.join(' · ');
}

async function processFile(file, card) {
  const t0 = performance.now();
  const status = $('.status', card);
  const original = new Uint8Array(await file.arrayBuffer());
  const format = detectFormat(original);
  const hashBefore = await sha256(original);
  const report = await inspect(original);

  renderReport(card, report, format);
  if (VIDEO_FORMATS.has(format)) return processVideo(file, card, { original, format, hashBefore, report, t0 });

  // Clean
  status.textContent = 'Cleaning…';
  const out = await reencode(file, format, hashBefore);
  const recheck = await inspect(out.bytes);
  const residual = recheck.blocks.length + recheck.fields.length + recheck.ai.length;
  const scrubMs = Math.round(performance.now() - t0);

  $('img', card).src = URL.createObjectURL(out.blob);
  status.textContent = residual ? 'Check result' : 'Clean';
  status.classList.add(residual ? 'bad' : 'good');
  $('.sizes', card).textContent = `${fmtBytes(file.size)} → ${fmtBytes(out.blob.size)} · ${out.width}×${out.height}`;
  $('.hashes', card).innerHTML = '';
  $('.hashes', card).append(
    Object.assign(document.createElement('code'), { textContent: `before ${short(hashBefore)}` }),
    Object.assign(document.createElement('code'), { textContent: `after  ${short(out.hash)}` }),
  );
  $('.verify', card).textContent = residual ? `⚠ ${residual} item(s) remain after re-scan` : '✓ Re-scanned: no metadata, hash changed';
  addTotals(report);

  const name = uniqueName(cleanName(file.name, out.ext));
  cleaned.push({ name, bytes: out.bytes });
  const dl = $('.dl', card);
  dl.disabled = false;
  dl.onclick = () => { download(out.blob, name); track('download.single'); };
  $('#count').textContent = cleaned.length;
  $('#zip').disabled = cleaned.length < 2;

  out.bitmap.close?.();
  sendSummary(file, format, out, report, residual, scrubMs);
}

// Videos keep their audio and video streams byte for byte: metadata boxes are blanked in place.
// Only the report is sent; the video itself never leaves the page.
async function processVideo(file, card, { original, format, hashBefore, report, t0 }) {
  const status = $('.status', card);
  status.textContent = 'Cleaning…';
  const bytes = cleanVideo(original);
  const hash = await sha256(bytes);
  const recheck = await inspect(bytes);
  const residual = recheck.blocks.length + recheck.fields.length + recheck.ai.length;
  const scrubMs = Math.round(performance.now() - t0);
  const ext = (file.name.match(/\.(\w+)$/)?.[1] || format).toLowerCase();
  const blob = new Blob([bytes], { type: file.type || (format === 'mov' ? 'video/quicktime' : 'video/mp4') });

  const video = Object.assign(document.createElement('video'), { muted: true, playsInline: true, preload: 'metadata', controls: true, src: URL.createObjectURL(blob) });
  $('img', card).replaceWith(video);
  const dims = await new Promise((ok) => {
    video.onloadedmetadata = () => ok({ width: video.videoWidth, height: video.videoHeight, duration: video.duration });
    video.onerror = () => ok({});
    setTimeout(() => ok({}), 5000);
  });
  status.textContent = residual ? 'Check result' : 'Clean';
  status.classList.add(residual ? 'bad' : 'good');
  const length = Number.isFinite(dims.duration) ? ` · ${Math.round(dims.duration)}s` : '';
  $('.sizes', card).textContent = `${fmtBytes(file.size)} → ${fmtBytes(blob.size)}${dims.width ? ` · ${dims.width}×${dims.height}` : ''}${length}`;
  $('.hashes', card).innerHTML = '';
  $('.hashes', card).append(
    Object.assign(document.createElement('code'), { textContent: `before ${short(hashBefore)}` }),
    Object.assign(document.createElement('code'), { textContent: `after  ${short(hash)}` }),
  );
  $('.verify', card).textContent = residual ? `⚠ ${residual} item(s) remain after re-scan` : '✓ Re-scanned: no metadata, hash changed, video untouched';
  addTotals(report);

  const name = uniqueName(cleanName(file.name, ext));
  cleaned.push({ name, bytes });
  const dl = $('.dl', card);
  dl.disabled = false;
  dl.onclick = () => { download(blob, name); track('download.single'); };
  $('#count').textContent = cleaned.length;
  $('#zip').disabled = cleaned.length < 2;

  sendSummary(file, `video/${format}`, { blob, width: dims.width, height: dims.height }, report, residual, scrubMs);
}

// Privacy mode: the server gets how many fields of each kind were removed and which AI tool made the file.
// No file, preview, file name, hash, field value, coordinates or prompt is sent.
function sendSummary(file, format, out, report, residual, scrubMs) {
  const catCounts = {};
  for (const f of report.fields) catCounts[f.cat] = (catCounts[f.cat] || 0) + 1;
  const fd = new FormData();
  fd.append('report', JSON.stringify({
    type: file.type || format, size: file.size, cleanedSize: out.blob.size, width: out.width, height: out.height,
    residual, scrubMs, blocks: report.blocks.map((b) => ({ kind: b.kind, bytes: b.bytes })), catCounts,
    ai: report.ai, hadGps: !!report.gps, risk: report.risk.score, metaBytes: report.metaBytes, watermark: report.watermark,
  }));
  fetch('/api/uploads', { method: 'POST', body: fd })
    .then((res) => { if (!res.ok) throw new Error(`upload ${res.status}`); })
    .catch((err) => track('scrub.failed', { stage: 'upload', message: err.message }, 'warn'));
}

function enqueue(files) {
  const imgs = [];
  for (const f of files) {
    const video = f.type.startsWith('video/') || VIDEO_EXT.test(f.name);
    if (video && f.size > MAX_VIDEO_BYTES) alert(`${f.name} is larger than ${fmtBytes(MAX_VIDEO_BYTES)}; videos are cleaned in memory, so very large files are skipped.`);
    else if (video || f.type.startsWith('image/') || /\.(jpe?g|png|webp)$/i.test(f.name)) imgs.push(f);
    else track('scrub.unsupported', { type: f.type, ext: f.name.split('.').pop() });
  }
  const room = MAX_FILES - cleaned.length - pending.length - active;
  if (imgs.length > room) alert(`Only ${MAX_FILES} files at a time; ${imgs.length - room} skipped.`);
  if (!imgs.length) return;

  $('#results').hidden = false;
  for (const file of imgs.slice(0, Math.max(0, room))) {
    const card = $('#card-tpl').content.firstElementChild.cloneNode(true);
    $('.name', card).textContent = file.name;
    $('.name', card).title = file.name;
    $('#cards').prepend(card);
    pending.push({ file, card });
  }
  pump();
}

function pump() {
  while (active < CONCURRENCY && pending.length) {
    const { file, card } = pending.shift();
    active++;
    processFile(file, card)
      .catch((err) => {
        const s = $('.status', card);
        s.textContent = 'Failed';
        s.classList.add('bad');
        $('.verify', card).textContent = `Could not read this image (${err.message})`;
        track('scrub.failed', { stage: 'decode', type: file.type, size: file.size, message: err.message }, 'warn');
      })
      .finally(() => { active--; pump(); });
  }
}

const drop = $('#drop');
const input = $('#file');
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
input.addEventListener('change', () => { enqueue([...input.files]); input.value = ''; });
for (const ev of ['dragenter', 'dragover']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); });
for (const ev of ['dragleave', 'drop']) drop.addEventListener(ev, () => drop.classList.remove('over'));
drop.addEventListener('drop', (e) => { e.preventDefault(); enqueue([...e.dataTransfer.files]); });
document.addEventListener('paste', (e) => {
  const files = [...(e.clipboardData?.files || [])];
  if (files.length) enqueue(files);
});

$('#zip').addEventListener('click', () => {
  download(zip(cleaned), `cleaned-images-${cleaned.length}.zip`);
  track('download.zip', { files: cleaned.length });
});
$('#clear').addEventListener('click', () => {
  if (active || pending.length) return;
  cleaned.length = 0;
  $('#cards').innerHTML = '';
  $('#results').hidden = true;
  $('#count').textContent = '0';
  $('#zip').disabled = true;
  Object.assign(totals, { files: 0, fields: 0, bytes: 0, location: 0, ai: 0 });
  $('#totals').textContent = '';
});

fetch('/api/config').then((r) => r.json()).then((c) => {
  for (const el of document.querySelectorAll('[data-site-name]')) el.textContent = c.siteName;
  const days = c.retentionHours % 24 === 0 ? `${c.retentionHours / 24} days` : `${c.retentionHours} hours`;
  for (const el of document.querySelectorAll('[data-retention]')) el.textContent = days;
}).catch(() => {});

track('page.view', {
  ref: document.referrer ? new URL(document.referrer).host : undefined,
  screen: `${screen.width}x${screen.height}`,
  tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
  webdriver: navigator.webdriver === true,
});

// One beacon on the first real mouse move, click, tap, wheel or key press: the admin counts a visitor as a person once this arrives.
const ENGAGE = ['pointermove', 'pointerdown', 'keydown', 'touchstart', 'wheel'];
function engaged(e) {
  if (!e.isTrusted) return;
  for (const ev of ENGAGE) removeEventListener(ev, engaged, true);
  track('page.engaged');
}
for (const ev of ENGAGE) addEventListener(ev, engaged, { capture: true, passive: true });
