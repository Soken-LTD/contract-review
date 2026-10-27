// render.mjs (08 3.2): print.html -> report.pdf with headless Chrome over CDP, no network.
// Usage: node render.mjs <job_dir> <in_html> <out_pdf>
// Exit codes: 0 ok, 10 timeout, 11 layout_overflow, 12 empty_page, 14 chrome_start, 15 net_request.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const [jobDir, inHtml, outPdf] = process.argv.slice(2).map((p) => path.resolve(p));
const CHROME = process.env.CHROME_BIN;
const T_LOAD = 15000, T_PAGED = 30000, T_PRINT = 30000, T_PROC = 90000;
const PROFILE = fs.mkdtempSync(path.join(process.env.TMPDIR || '/tmp', 'chrome-prof-'));
let proc = null;

function fail(code, msg) {
  process.stderr.write(`render: ${msg}\n`);
  try { proc && proc.kill('SIGKILL'); } catch {}
  process.exit(code);
}
setTimeout(() => fail(10, 'process timeout'), T_PROC).unref();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function within(ms, p, what) {
  let t;
  const timer = new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`timeout ${what}`)), ms); });
  try { return await Promise.race([p, timer]); } finally { clearTimeout(t); }
}

async function main() {
  if (!CHROME || !fs.existsSync(CHROME)) fail(14, 'CHROME_BIN not set or missing');
  proc = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--hide-scrollbars', '--disable-dev-shm-usage',
    '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-sync',
    '--disable-extensions', '--disable-component-update', '--disable-domain-reliability',
    '--remote-debugging-port=0', `--user-data-dir=${PROFILE}`, 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  proc.stderr.on('data', () => {});
  proc.on('exit', (c) => { if (!done) fail(14, `chrome exited ${c}`); });

  // Port from DevToolsActivePort in the per-job profile (08 3.2).
  let port = null, wsPath = null;
  for (let i = 0; i < 100 && !port; i++) {
    try {
      const [p, w] = fs.readFileSync(path.join(PROFILE, 'DevToolsActivePort'), 'utf8').split('\n');
      if (p && w) { port = p.trim(); wsPath = w.trim(); }
    } catch {}
    if (!port) await sleep(100);
  }
  if (!port) fail(14, 'no DevToolsActivePort');
  const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
  await within(5000, new Promise((r, j) => { ws.addEventListener('open', r, { once: true }); ws.addEventListener('error', j, { once: true }); }), 'ws').catch(() => fail(14, 'devtools connect'));

  let id = 0; const pend = new Map(); let sessionId = null; let loaded = false;
  const blocked = [], consoleLog = [];  // page console (paged.js warnings), for the debug record only
  const call = (method, params = {}, sess = sessionId) => new Promise((res, rej) => {
    const myid = ++id; pend.set(myid, { res, rej });
    const m = { id: myid, method, params }; if (sess) m.sessionId = sess;
    ws.send(JSON.stringify(m));
  });
  const jobUrl = 'file://' + jobDir + '/';
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pend.has(m.id)) { const p = pend.get(m.id); pend.delete(m.id); m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result); return; }
    if (m.method === 'Page.loadEventFired') loaded = true;
    if (m.method === 'Runtime.consoleAPICalled' && consoleLog.length < 60) {
      consoleLog.push(m.params.type + ': ' + m.params.args.map((a) => String(a.value ?? a.description ?? '')).join(' ').slice(0, 240));
    }
    if (m.method === 'Fetch.requestPaused') {
      const url = m.params.request.url;
      // Network layer 1: only file:// inside the job dir and data: continue; all else fails, recorded.
      if (url.startsWith(jobUrl) || url.startsWith('data:')) {
        call('Fetch.continueRequest', { requestId: m.params.requestId }).catch(() => {});
      } else {
        blocked.push(url.slice(0, 200));
        call('Fetch.failRequest', { requestId: m.params.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
      }
    }
  });

  const { targetId } = await call('Target.createTarget', { url: 'about:blank' }, null);
  sessionId = (await call('Target.attachToTarget', { targetId, flatten: true }, null)).sessionId;
  await call('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  await call('Page.enable');
  await call('Runtime.enable');
  await call('Page.navigate', { url: 'file://' + inHtml });
  const t0 = Date.now();
  while (!loaded) { if (Date.now() - t0 > T_LOAD) fail(10, 'load timeout'); await sleep(100); }

  const evaluate = async (expression) => (await call('Runtime.evaluate', { expression, returnByValue: true })).result.value;
  let prev = -1, stable = 0; const t1 = Date.now();
  for (;;) {
    if (Date.now() - t1 > T_PAGED) fail(10, 'paged.js not stable');
    await sleep(250);
    const n = await evaluate("document.querySelectorAll('.pagedjs_page').length");
    if (n > 0 && n === prev) { if (++stable >= 3) break; } else stable = 0;
    prev = n;
  }
  await sleep(300);

  // DOM checks (08 3.2): (b) element right edge beyond its page content box; (c) near-empty non-last page.
  // Both failures name the elements involved so the cause is visible from the log: for (b) the
  // innermost overflowing element and the block it sits in, for (c) the last block on the near-empty
  // page and the first block on the page after it. Structure only (tag, class, id, data-section,
  // data-block): the detail reaches worker logs and error_detail, and report text is client content.
  const dom = await evaluate(`(() => {
    const pages = [...document.querySelectorAll('.pagedjs_page')];
    const out = { pages: pages.length, overflow: null, empty: null };
    const cls = (el) => String(el.className && el.className.baseVal !== undefined ? el.className.baseVal : el.className || '');
    const skip = (el) => (el.closest('svg') && el.tagName.toLowerCase() !== 'svg') || (el.tagName === 'DIV' && !cls(el));
    const ident = (s) => String(s || '').replace(/[^A-Za-z0-9_. -]/g, '').slice(0, 40);
    const describe = (el) => {
      if (!el) return null;
      const d = { tag: el.tagName, cls: ident(cls(el)) };
      if (el.id) d.id = ident(el.id);
      const sec = el.closest && el.closest('[data-section]');
      if (sec) d.sec = ident(sec.dataset.section);
      const blk = el.closest && el.closest('[data-block]');
      if (blk) d.blk = ident(blk.dataset.block);
      return d;
    };
    // Visible elements of a page in document order, paged.js wrappers and SVG internals left out.
    const content = (pg) => {
      const area = pg.querySelector('.pagedjs_page_content');
      if (!area) return [];
      return [...area.querySelectorAll('*')].filter((el) => {
        if (skip(el)) return false;
        const r = el.getBoundingClientRect();
        return r.width !== 0 || r.height !== 0;
      });
    };
    // The outermost block an element belongs to (section, card, figure, table, list), else itself.
    const block = (el) => (el && el.closest && el.closest('.finding, figure, table, ul, ol, .keep, .codegrp, section')) || el;
    pages.forEach((pg, i) => {
      const area = pg.querySelector('.pagedjs_page_content');
      if (!area) return;
      const box = area.getBoundingClientRect();
      const els = content(pg);
      let bottom = box.top;
      const over = [];
      for (const el of els) {
        const r = el.getBoundingClientRect();
        if (r.right > box.right + 1) over.push(el);
        if (r.bottom > bottom) bottom = r.bottom;
      }
      if (!out.overflow && over.length) {
        const inner = over.find((a) => !over.some((b) => b !== a && a.contains(b))) || over[0];
        const r = inner.getBoundingClientRect();
        out.overflow = { page: i + 1, excess_px: Math.round(r.right - box.right), el: describe(inner), in: describe(block(inner)) };
      }
      const used = (Math.min(bottom, box.bottom) - box.top) / box.height;
      if (!out.empty && i < pages.length - 1 && used < 0.12) {
        const next = content(pages[i + 1]);
        out.empty = { page: i + 1, used: Math.round(used * 1000) / 1000,
          last: describe(block(els[els.length - 1])), next: describe(block(next[0])) };
      }
    });
    return out;
  })()`);
  if (blocked.length) fail(15, 'blocked requests: ' + JSON.stringify(blocked.slice(0, 5)));
  if (!dom.pages) fail(10, 'no pages');
  if (dom.overflow || dom.empty) {
    // Debug record with page text, for a developer reading the sandbox out/ dir by hand. The
    // supervisor reads only result.json and report.pdf from out/ and never logs or stores this file.
    const bad = (dom.overflow || dom.empty).page;
    try { fs.writeFileSync(path.join(path.dirname(outPdf), 'layout.json'), JSON.stringify({ check: dom, console: consoleLog, handlers: await evaluate('window.__kitLog || []'), pages: await evaluate(`(() =>
      [...document.querySelectorAll('.pagedjs_page')].map((pg, i) => {
        const area = pg.querySelector('.pagedjs_page_content');
        const box = area ? area.getBoundingClientRect() : { top: 0, left: 0 };
        const text = (el) => el ? el.tagName + '.' + String(el.className || '').slice(0, 30) + ' ' + String(el.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 80) : null;
        const rect = (el) => { const r = el.getBoundingClientRect(); return [Math.round(r.left - box.left), Math.round(r.top - box.top), Math.round(r.right - box.left), Math.round(r.bottom - box.top)]; };
        const kids = area ? [...area.querySelectorAll('section > *, .pagedjs_page_content > div > *')] : [];
        const out = { page: i + 1, first: text(kids[0]), last: text(kids[kids.length - 1]), blocks: kids.length };
        if (i + 1 === ${bad}) out.detail = kids.map((el) => [text(el), rect(el), el.tagName === 'TABLE' ? [...el.querySelectorAll('tr')].map((tr) => [rect(tr), String(tr.textContent || '').trim().slice(0, 40)]) : undefined]);
        return out;
      }))()`) }, null, 1)); } catch {}
  }
  if (dom.overflow) fail(11, 'layout_overflow ' + JSON.stringify(dom.overflow));
  if (dom.empty) fail(12, 'empty_page ' + JSON.stringify(dom.empty));

  const { data } = await within(T_PRINT, call('Page.printToPDF', {
    printBackground: true, displayHeaderFooter: false, paperWidth: 8.27, paperHeight: 11.69,
    marginTop: 0, marginBottom: 0, marginLeft: 0, marginRight: 0, preferCSSPageSize: false, scale: 1,
  }), 'print').catch(() => fail(10, 'print timeout'));
  if (blocked.length) fail(15, 'blocked requests: ' + JSON.stringify(blocked.slice(0, 5)));
  fs.writeFileSync(outPdf, Buffer.from(data, 'base64'));
  done = true;
  try { ws.close(); } catch {}
  proc.kill('SIGKILL');
  try { fs.rmSync(PROFILE, { recursive: true, force: true }); } catch {}
  process.stdout.write(JSON.stringify({ pages: dom.pages, bytes: fs.statSync(outPdf).size }) + '\n');
  process.exit(0);
}
let done = false;
main().catch((e) => fail(14, String(e && e.message || e)));
