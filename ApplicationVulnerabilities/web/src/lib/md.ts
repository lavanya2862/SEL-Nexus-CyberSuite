// Minimal, safe Markdown → HTML for reports and assistant answers. The input is escaped first, so the only tags in the
// output are the ones made here; links are limited to http(s).

export const esc = (v: unknown) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)

export function md(text: string): string {
  const blocks: string[] = []
  let src = String(text || '').replace(/```(\w*)\n([\s\S]*?)```/g, (_, _lang, code: string) => {
    blocks.push(`<pre><code>${esc(code.replace(/\n$/, ''))}</code></pre>`)
    return `\u0000${blocks.length - 1}\u0000`
  })
  src = esc(src)
  const inline = (s: string) => s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/(^|[\s(])\*([^*\n]+)\*/g, '$1<i>$2</i>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
    .replace(/(^|\s)(https?:\/\/[^\s<]+)/g, '$1<a href="$2" target="_blank" rel="noopener noreferrer">$2</a>')
  const out: string[] = []
  let list: { t: 'ul' | 'ol'; items: string[] } | null = null
  let para: string[] = []
  let table: string[] | null = null
  const flushPara = () => { if (para.length) { out.push(`<p>${inline(para.join(' '))}</p>`); para = [] } }
  const flushList = () => { if (list) { out.push(`<${list.t}>${list.items.map((i) => `<li>${inline(i)}</li>`).join('')}</${list.t}>`); list = null } }
  const flushTable = () => {
    if (!table) return
    const rows = table.filter((r) => !/^\|?\s*:?-{2,}/.test(r))
      .map((r) => r.replace(/^\||\|$/g, '').split(/(?<!\\)\|/).map((c) => inline(c.trim().replace(/\\\|/g, '|'))))
    const [head, ...body] = rows
    out.push(`<div class="md-table"><table><thead><tr>${head.map((c) => `<th>${c}</th>`).join('')}</tr></thead><tbody>${body.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`)
    table = null
  }
  for (const raw of src.split('\n')) {
    const line = raw.trimEnd()
    let m: RegExpMatchArray | null
    if (/^\u0000\d+\u0000$/.test(line.trim())) { flushPara(); flushList(); flushTable(); out.push(line.trim()); continue }
    if (line.startsWith('|')) { flushPara(); flushList(); (table = table ?? []).push(line); continue }
    flushTable()
    if (!line.trim()) { flushPara(); flushList(); continue }
    if ((m = line.match(/^(#{1,4})\s+(.*)$/))) { flushPara(); flushList(); const l = Math.min(4, m[1].length + 1); out.push(`<h${l}>${inline(m[2])}</h${l}>`); continue }
    if ((m = line.match(/^\s*[-*]\s+(.*)$/))) { flushPara(); if (!list || list.t !== 'ul') { flushList(); list = { t: 'ul', items: [] } } list.items.push(m[1]); continue }
    if ((m = line.match(/^\s*\d+[.)]\s+(.*)$/))) { flushPara(); if (!list || list.t !== 'ol') { flushList(); list = { t: 'ol', items: [] } } list.items.push(m[1]); continue }
    if ((m = line.match(/^&gt;\s?(.*)$/))) { flushPara(); flushList(); out.push(`<blockquote>${inline(m[1])}</blockquote>`); continue }
    if (/^-{3,}$/.test(line)) { flushPara(); flushList(); out.push('<hr>'); continue }
    if (list && /^\s{2,}/.test(raw)) { list.items[list.items.length - 1] += ' ' + line.trim(); continue }
    para.push(line)
  }
  flushPara(); flushList(); flushTable()
  return out.join('\n').replace(/\u0000(\d+)\u0000/g, (_, i) => blocks[Number(i)])
}
