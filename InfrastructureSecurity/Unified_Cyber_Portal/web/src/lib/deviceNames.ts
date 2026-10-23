// Friendly computer names: the screen says "VM 1" where the data says opca-wks-01, and hovering the name shows the real
// one. OpCo labels are swapped the same way (OpCo A -> VM 1). The list comes from the portal's config/device_names.csv
// (/api/device-names, see src/portal/devicenames.py).
//
// Only the text on screen changes: the data, Defender and every action (fix, isolate, links, copy buttons) keep the real
// name. It works on the page text itself, so every screen, table, chart, chat answer and AI explanation is covered
// without each page knowing about it. Text nodes are never added or removed (React keeps owning them), only their text
// is swapped; the hover tooltip is one element outside the React app.
import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '@/lib/auth'

type Names = Record<string, string> // real name (lower case) -> name shown

interface Spot { start: number; end: number; real: string }

const ATTRS = ['title', 'aria-label', 'placeholder']
const SKIP = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'NOSCRIPT'])

export function DeviceNames() {
  const { user } = useAuth()
  const { data } = useQuery({
    queryKey: ['device-names'],
    queryFn: async (): Promise<Names> => {
      const res = await fetch('/api/device-names')
      return res.ok ? res.json() : {}
    },
    enabled: !!user,
    staleTime: Infinity,
  })
  useEffect(() => (data && Object.keys(data).length ? rename(data) : undefined), [data])
  return null
}

/** Swap the names everywhere under <body> from now on; returns the stop function. */
function rename(names: Names): () => void {
  const escaped = Object.keys(names).sort((a, b) => b.length - a.length).map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  // the name, plus a domain if Defender gives the full one (opca-wks-01.contoso.local)
  const pattern = new RegExp(`(?<![\\w-])(?:${escaped.join('|')})(?:\\.[a-z0-9][a-z0-9-]*)*(?![\\w-])`, 'gi')
  const shownFor = (real: string) => names[real.toLowerCase().split('.')[0]] ?? real

  const texts = new WeakMap<Text, { shown: string; spots: Spot[] }>()
  const attrs = new WeakMap<Element, Record<string, string>>()

  // the hover tooltip; its own text is the real name, so it is never swapped
  const tip = document.createElement('div')
  tip.setAttribute('role', 'tooltip')
  tip.className = 'pointer-events-none fixed z-[100] hidden -translate-x-1/2 -translate-y-full rounded-md bg-foreground px-2.5 py-1 text-xs text-background shadow-md'

  function swapText(node: Text) {
    const parent = node.parentElement
    if (!parent || parent === tip || SKIP.has(parent.tagName) || parent.isContentEditable) return
    const value = node.nodeValue ?? ''
    if (texts.get(node)?.shown === value) return
    const spots: Spot[] = []
    let shown = ''
    let last = 0
    for (const m of value.matchAll(pattern)) {
      shown += value.slice(last, m.index)
      const name = shownFor(m[0])
      spots.push({ start: shown.length, end: shown.length + name.length, real: m[0] })
      shown += name
      last = m.index + m[0].length
    }
    if (!spots.length) return void texts.delete(node)
    shown += value.slice(last)
    texts.set(node, { shown, spots })
    node.nodeValue = shown
  }

  function swapAttrs(el: Element) {
    for (const attr of ATTRS) {
      const value = el.getAttribute(attr)
      if (!value || attrs.get(el)?.[attr] === value) continue
      // a native tooltip keeps the real name next to the friendly one
      const shown = value.replace(pattern, (real) => (attr === 'title' ? `${shownFor(real)} (${real})` : shownFor(real)))
      if (shown === value) continue
      attrs.set(el, { ...attrs.get(el), [attr]: shown })
      el.setAttribute(attr, shown)
    }
  }

  function swapAll(root: Node) {
    if (root.nodeType === Node.TEXT_NODE) return swapText(root as Text)
    if (!(root instanceof Element)) return
    swapAttrs(root)
    root.querySelectorAll(ATTRS.map((a) => `[${a}]`).join(',')).forEach(swapAttrs)
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
    for (let n = walker.nextNode(); n; n = walker.nextNode()) swapText(n as Text)
  }

  const observer = new MutationObserver((records) => {
    for (const r of records) {
      if (r.type === 'characterData') swapText(r.target as Text)
      else if (r.type === 'attributes') swapAttrs(r.target as Element)
      else r.addedNodes.forEach(swapAll)
    }
  })
  swapAll(document.body)
  observer.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS })

  // Hover: find the swapped name under the pointer and show its real name just above it.
  document.body.appendChild(tip)
  const range = document.createRange()

  function hit(target: Element, x: number, y: number): { real: string; rect: DOMRect } | null {
    for (const child of target.childNodes) {
      const info = child.nodeType === Node.TEXT_NODE ? texts.get(child as Text) : undefined
      if (!info || child.nodeValue !== info.shown) continue
      for (const spot of info.spots) {
        range.setStart(child, spot.start)
        range.setEnd(child, spot.end)
        for (const rect of range.getClientRects()) {
          if (x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom) return { real: spot.real, rect }
        }
      }
    }
    return null
  }

  function onMove(e: MouseEvent) {
    const found = e.target instanceof Element ? hit(e.target, e.clientX, e.clientY) : null
    if (!found) return void tip.classList.add('hidden')
    tip.textContent = `Real name: ${found.real}`
    tip.style.left = `${found.rect.left + found.rect.width / 2}px`
    tip.style.top = `${found.rect.top - 6}px`
    tip.classList.remove('hidden')
  }
  const hide = () => tip.classList.add('hidden')

  document.addEventListener('mousemove', onMove, { passive: true })
  document.addEventListener('scroll', hide, { capture: true, passive: true })
  document.documentElement.addEventListener('mouseleave', hide)
  return () => {
    observer.disconnect()
    document.removeEventListener('mousemove', onMove)
    document.removeEventListener('scroll', hide, { capture: true })
    document.documentElement.removeEventListener('mouseleave', hide)
    tip.remove()
  }
}
