// Kit paged.js handlers, inlined after pagedjs.js in print.html (build()). No network, no DOM text.
//
// RepeatTableHead: paged.js 0.4 splits a long table between rows and rebuilds the <table> on the
// next page without its <thead>. The kit's pagination contract (report.css) is thead + tbody with
// the header row on every page a table continues on, so this handler inserts a copy of the source
// table's <thead> into each continuation fragment. renderNode fires for the first row placed on
// the continuation page, before paged.js measures that page, so the repeated header counts toward
// the page height like any other row.
class RepeatTableHead extends Paged.Handler {
  renderNode(clone, node) {
    if (!node || node.nodeName !== 'TR' || !clone || !clone.closest) return;
    const table = clone.closest('table');
    if (!table || !table.hasAttribute('data-split-from') || table.querySelector(':scope > thead')) return;
    const source = node.closest('table');
    const head = source && source.querySelector(':scope > thead');
    if (!head) return;
    const copy = head.cloneNode(true);
    for (const el of [copy, ...copy.querySelectorAll('[data-ref]')]) el.removeAttribute('data-ref');
    copy.setAttribute('data-repeated', '');
    table.insertBefore(copy, table.firstChild);
  }
}
Paged.registerHandlers(RepeatTableHead);

// RowFitGuard: paged.js detects overflow by elements and text lines that START below the page
// bottom, so a table row (break-inside:avoid) whose last line ENDS within a fraction of a pixel of
// the bottom counts as fitting while it is measured; once the rows after it are extracted, its
// collapsed bottom border becomes the table edge, it grows by that fraction and Chrome's
// fragmentation moves the whole row into an overflow column (x86 render of the Solana Scope table,
// 2026-10-27: row measured 907 to 952 on a 952 px page, rendered in the overflow column; the
// Mac and arm64 engines round the other way). Any row ending inside the last BAND px of the page
// starts the next page instead: the break token moves back to it, never forward.
const BAND = 2;
class RowFitGuard extends Paged.Handler {
  onBreakToken(breakToken, overflow, rendered, layout) {
    // Decision log for the developer record (render.mjs copies window.__kitLog into out/layout.json).
    const log = (window.__kitLog = window.__kitLog || []);
    const note = (what, extra) => { if (log.length < 80) log.push({ hook: 'onBreakToken', what, ...extra }); };
    if (!overflow || !breakToken || !breakToken.node || !rendered || !rendered.querySelectorAll) return note('skip', { overflow: !!overflow, token: !!(breakToken && breakToken.node) });
    const bounds = layout && layout.bounds;
    const source = this.chunker && this.chunker.source;
    if (!bounds || !source) return note('no_bounds_or_source', { bounds: !!bounds, source: !!source, chunker: !!this.chunker });
    const tokenRef = breakToken.node.dataset ? breakToken.node.dataset.ref : null;
    for (const tr of rendered.querySelectorAll('tbody > tr')) {
      const r = tr.getBoundingClientRect();
      if (!r.height || r.top >= bounds.bottom || r.bottom <= bounds.bottom - BAND) continue;
      note('row_in_band', { ref: tr.dataset.ref, top: r.top - bounds.top, bottom: r.bottom - bounds.top, page_h: bounds.height, token: tokenRef });
      if (r.top <= bounds.top) return;  // the row starts the page: nothing earlier to break at
      const src = tr.dataset.ref && source.querySelector(`[data-ref="${tr.dataset.ref}"]`);
      if (!src) return note('no_source_row', { ref: tr.dataset.ref });
      // Only move the token back: when it already sits at or before this row, keep it.
      if (src !== breakToken.node && !(src.compareDocumentPosition(breakToken.node) & Node.DOCUMENT_POSITION_FOLLOWING)) return note('token_before_row', {});
      breakToken.node = src;
      breakToken.offset = 0;
      // paged.js extracts the page overflow with this Range, not with the token: start it at the row
      // too, so the row leaves this page and is not printed twice.
      try { overflow.setStartBefore(tr); } catch (e) { return note('range_not_moved', { ref: tr.dataset.ref, err: String(e).slice(0, 80) }); }
      return note('moved', { ref: tr.dataset.ref });
    }
    // Last rows of the page, for the record even when none is in the band.
    const rows = [...rendered.querySelectorAll('tbody > tr')].filter((tr) => tr.getBoundingClientRect().height);
    note('no_row_in_band', { token: tokenRef, page_h: bounds.height, last_rows: rows.slice(-3).map((tr) => { const r = tr.getBoundingClientRect(); return [tr.dataset.ref, Math.round((r.top - bounds.top) * 100) / 100, Math.round((r.bottom - bounds.top) * 100) / 100]; }) });
  }
}
Paged.registerHandlers(RowFitGuard);
