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
