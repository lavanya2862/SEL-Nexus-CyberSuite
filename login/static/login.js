// SEL Nexus CyberSuite sign-in page. People pick a security domain (Infrastructure Security, Application Security) from
// a dropdown on the sign-in form and go straight there; at sign-up they choose the domain access their account needs
// (one domain or both). A domain that finds nobody signed in sends people here with ?next=<its address>; after
// sign-in they go straight back. ?switch shows the signed-in person their domains to move between.
(() => {
  const $ = (sel) => document.querySelector(sel)
  const ICONS = { infrastructure_security: 'i-server', application_security: 'i-code' }
  const RENAMED = { defender_infra: 'infrastructure_security', infrastructure_vulnerabilities: 'infrastructure_security', application_vulnerabilities: 'application_security' } // ids before the rename
  const LAST = 'cybersuite-domain' // the domain picked last time on this browser, picked again by default
  const ALL = 'all' // the sign-up choice "Both domains"
  let config = null

  async function api(path, body) {
    const res = await fetch(`/api/${path}`, body === undefined ? {} : {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CyberSuite': 'auth' },
      body: JSON.stringify(body),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `Something went wrong (error ${res.status}). Please try again.`)
    return data
  }

  const store = {
    get() { try { const v = localStorage.getItem(LAST); return RENAMED[v] || v } catch { return null } },
    set(v) { try { localStorage.setItem(LAST, v) } catch { /* not essential */ } },
  }

  const moduleById = (id) => config.modules.find((m) => m.id === id)
  const moduleOf = (href) => {
    try {
      const origin = new URL(href).origin
      return config.modules.find((m) => m.url && new URL(m.url).origin === origin) || null
    } catch { return null }
  }
  const tileClass = (id) => (id === 'application_security' ? 'tile tile-violet' : 'tile')
  const iconOf = (id) => ICONS[id] || 'i-shield'

  /** Only go back to one of our own domains, never another website. */
  function safeNext() {
    const next = new URLSearchParams(location.search).get('next')
    if (!next || !config) return null
    return moduleOf(next) ? new URL(next).href : null
  }

  function showError(box, message) {
    box.hidden = !message
    box.replaceChildren()
    if (!message) return
    box.insertAdjacentHTML('afterbegin', '<svg class="ico"><use href="#i-alert"/></svg>')
    box.append(document.createTextNode(message))
  }

  const option = (value, text, disabled = false) => Object.assign(document.createElement('option'), { value, textContent: text, disabled })

  /** The icon in a dropdown and the line under it follow the choice, so people see what each domain covers. */
  function describe(select, note, choice) {
    const icon = select.parentElement.querySelector('.select-ico')
    const m = moduleById(choice)
    icon.className = `select-ico ${m ? tileClass(m.id) : choice === ALL ? 'tile tile-mix' : 'tile tile-idle'}`
    icon.querySelector('use').setAttribute('href', m ? `#${iconOf(m.id)}` : choice === ALL ? '#i-layers' : '#i-shield')
    note.textContent = m ? (m.url ? m.description : `${m.description} Not yet available on this server.`)
      : choice === ALL ? `Access to ${config.modules.map((x) => x.name).join(' and ')}. Switch between them at any time from inside the suite.`
        : select.id === 'signup-domain' ? 'Choose the domain you work in. Select both if you work across infrastructure and application security.'
          : 'Choose where you want to start. You can switch domains at any time.'
  }

  /** Sign-in: one domain to open now. Sign-up: the domain access the account needs (one domain or both). */
  function renderPickers() {
    const back = moduleOf(safeNext() || '')?.id
    const wanted = back || store.get() || config.modules.find((m) => m.url)?.id

    const login = $('#login-domain')
    login.replaceChildren(...config.modules.map((m) => option(m.id, m.url ? m.name : `${m.name} (not yet available)`, !m.url)))
    login.value = moduleById(wanted)?.url ? wanted : config.modules.find((m) => m.url)?.id || ''
    const loginNote = $('#login-domain-note')
    login.onchange = () => describe(login, loginNote, login.value)
    describe(login, loginNote, login.value)

    const signup = $('#signup-domain')
    signup.replaceChildren(option('', 'Select the access you need', true), ...config.modules.map((m) => option(m.id, m.name)),
      ...(config.modules.length > 1 ? [option(ALL, 'Both domains')] : []))
    signup.value = back || ''
    const signupNote = $('#signup-domain-note')
    signup.onchange = () => describe(signup, signupNote, signup.value)
    describe(signup, signupNote, signup.value)
  }

  /** The two domains under the headline, from the same descriptions the dropdowns use. */
  function renderAreas() {
    $('#areas').replaceChildren(...config.modules.map((m) => {
      const li = document.createElement('li')
      li.innerHTML = `<span class="${tileClass(m.id)} tile-lg"><svg class="ico"><use href="#${iconOf(m.id)}"/></svg></span><span><b></b><small></small></span>`
      li.querySelector('b').textContent = m.name
      li.querySelector('small').textContent = m.description
      return li
    }))
  }

  /** The slowly turning security backdrop behind the card: a dial, signal arcs, a node network, shield rings, a sweep. */
  function buildOrbit() {
    const svg = $('#orbit')
    if (svg.childElementCount) return
    const at = (r, deg) => { const a = (deg - 90) * Math.PI / 180; return [+(r * Math.cos(a)).toFixed(1), +(r * Math.sin(a)).toFixed(1)] }
    const arc = (r, from, to) => { const [x1, y1] = at(r, from); const [x2, y2] = at(r, to); return `M${x1} ${y1}A${r} ${r} 0 ${to - from > 180 ? 1 : 0} 1 ${x2} ${y2}` }
    const hexagon = (r, turn) => Array.from({ length: 6 }, (_, i) => at(r, i * 60 + turn).join(',')).join(' ')
    const ticks = Array.from({ length: 120 }, (_, i) => {
      const major = i % 10 === 0
      const [x1, y1] = at(major ? 360 : 368, i * 3)
      const [x2, y2] = at(380, i * 3)
      return `<line class="${major ? 'o-tick-major' : 'o-tick'}" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`
    }).join('')
    const angles = [8, 40, 77, 112, 151, 186, 222, 259, 296, 333]
    const nodes = angles.map((d) => at(270, d))
    const links = nodes.map(([x, y], i) => {
      const [a, b] = nodes[(i + 3) % nodes.length]
      const [c, d] = nodes[(i + 1) % nodes.length]
      return `<line x1="${x}" y1="${y}" x2="${a}" y2="${b}"/><line x1="${x}" y1="${y}" x2="${c}" y2="${d}"/>`
    }).join('')
    const dots = nodes.map(([x, y], i) => `<circle class="o-node" style="animation-delay:${(i * 0.7).toFixed(1)}s" cx="${x}" cy="${y}" r="3.6"/>`).join('')
    const [sx, sy] = at(385, 0)
    const [ex, ey] = at(385, 42)
    svg.innerHTML = `
      <defs>
        <radialGradient id="o-glow"><stop offset="0" stop-color="#1d5cff" stop-opacity=".34"/><stop offset=".55" stop-color="#1d5cff" stop-opacity=".08"/><stop offset="1" stop-color="#1d5cff" stop-opacity="0"/></radialGradient>
        <linearGradient id="o-sweep" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#6b97ff" stop-opacity="0"/><stop offset="1" stop-color="#6b97ff" stop-opacity=".28"/></linearGradient>
        <filter id="o-blur" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="3"/></filter>
      </defs>
      <circle class="o-halo" r="330" fill="url(#o-glow)"/>
      <g class="o-layer o-spin-slow"><circle class="o-ring" r="380"/>${ticks}</g>
      <g class="o-layer o-spin-rev">
        <circle class="o-ring o-dash" r="330"/>
        <g class="o-arcs" filter="url(#o-blur)"><path class="o-arc-blue" d="${arc(330, 12, 64)}"/><path class="o-arc-violet" d="${arc(330, 150, 182)}"/><path class="o-arc-teal" d="${arc(330, 238, 300)}"/></g>
        <path class="o-arc-blue" d="${arc(330, 12, 64)}"/><path class="o-arc-violet" d="${arc(330, 150, 182)}"/><path class="o-arc-teal" d="${arc(330, 238, 300)}"/>
      </g>
      <g class="o-layer o-spin-mid"><circle class="o-ring o-faint" r="270"/><g class="o-links">${links}</g>${dots}</g>
      <g class="o-layer o-spin-rev-slow"><circle class="o-ring o-none" r="215"/><polygon class="o-hex" points="${hexagon(215, 0)}"/><polygon class="o-hex o-dash" points="${hexagon(188, 30)}"/></g>
      <g class="o-layer o-sweep"><circle class="o-ring o-none" r="385"/><path d="M0 0L${sx} ${sy}A385 385 0 0 1 ${ex} ${ey}Z" fill="url(#o-sweep)"/></g>`
  }

  function showForm() {
    const signup = location.hash === '#signup' && config?.signup_open
    $('#form-login').hidden = signup
    $('#form-signup').hidden = !signup
    document.title = `${signup ? 'Create your account' : 'Sign in'} · SEL Nexus CyberSuite`
    const form = signup ? $('#form-signup') : $('#form-login')
    showError(form.querySelector('.error'), null)
    form.querySelector('input')?.focus()
  }

  function showSignedOut() {
    $('#who').hidden = true
    $('#view-choose').hidden = true
    $('#view-auth').hidden = false
    buildOrbit()
    showForm()
  }

  /** Into the chosen domain: back to the page that sent the person here when it belongs to that domain. */
  function enter(user) {
    const m = moduleById(user.domain)
    store.set(user.domain)
    if (!m?.url) return showChooser(user, `${m?.name || 'That domain'} isn’t available on this server yet.`)
    const next = safeNext()
    location.replace(next && moduleOf(next)?.id === m.id ? next : m.url)
  }

  async function switchTo(user, id) {
    try {
      const { user: moved } = await api('switch', { domain: id })
      enter(moved)
    } catch (err) {
      showChooser(user, err.message)
    }
  }

  /** Signed in: the person's own domains, to move between them (no password needed). */
  function showChooser(user, message) {
    const mine = user.domains || config.modules.map((m) => m.id)
    $('#who-name').textContent = `${user.name} · ${user.email}`
    $('#who').hidden = false
    $('#view-auth').hidden = true
    document.title = 'Switch domain · SEL Nexus CyberSuite'
    $('#welcome').textContent = 'Switch domain'
    $('#choose-lead').textContent = `Signed in as ${user.name.split(' ')[0]}. Select a domain to continue.`
    showError($('#choose-error'), message || null)
    $('#modules').replaceChildren(...config.modules.filter((m) => mine.includes(m.id)).map((m) => {
      const here = m.id === user.domain
      const card = document.createElement(m.url ? 'button' : 'div')
      card.className = m.url ? 'module' : 'module off'
      if (m.url) { card.type = 'button'; card.addEventListener('click', () => (here ? enter(user) : switchTo(user, m.id))) }
      card.innerHTML = `<span class="${tileClass(m.id)}"><svg class="ico"><use href="#${iconOf(m.id)}"/></svg></span><h2></h2><p></p>` +
        (!m.url ? '<span class="soon">Not yet available</span>'
          : here ? '<span class="here">Current domain · Open</span>' : '<span class="go">Open <svg class="ico"><use href="#i-arrow"/></svg></span>')
      card.querySelector('h2').textContent = m.name
      card.querySelector('p').textContent = m.description
      return card
    }))
    $('#view-choose').hidden = false
  }

  /** Arriving here already signed in: straight on to the right domain, or the switcher when that is what was asked. */
  function signedInArrival(user) {
    const mine = user.domains || config.modules.map((m) => m.id)
    const target = moduleOf(safeNext() || '')
    if (new URLSearchParams(location.search).has('switch')) return showChooser(user)
    if (target) {
      if (!mine.includes(target.id)) return showChooser(user, `Your account doesn’t have access to ${target.name}. Contact your CyberSuite administrator to request access, or select one of your domains.`)
      return target.id === user.domain ? enter(user) : switchTo(user, target.id)
    }
    if (user.domain && mine.includes(user.domain)) return enter(user)
    return showChooser(user)
  }

  async function submit(form, action) {
    const box = form.querySelector('.error')
    const button = form.querySelector('button[type=submit]')
    const label = button.innerHTML
    const fd = new FormData(form)
    const data = { email: String(fd.get('email') || '').trim(), password: fd.get('password') }
    if (action === 'signup') {
      const access = String(fd.get('access') || '')
      data.name = String(fd.get('name') || '').trim()
      data.domains = access === ALL ? config.modules.map((m) => m.id) : access ? [access] : []
      const back = moduleOf(safeNext() || '')?.id
      if (back && data.domains.includes(back)) data.domain = back
    } else {
      data.domain = fd.get('domain')
    }
    showError(box, null)
    if (action === 'signup' && !data.domains.length) return showError(box, 'Select the domain access you need.')
    if (action === 'login' && !data.domain) return showError(box, 'Select a domain to continue.')
    const fields = form.querySelectorAll('input, select')
    fields.forEach((i) => { i.disabled = true; i.removeAttribute('aria-invalid') })
    button.disabled = true
    button.textContent = button.dataset.busy
    try {
      const { user } = await api(action, data)
      form.reset()
      enter(user)
    } catch (err) {
      showError(box, err.message)
      if (!/domain|access/i.test(err.message)) form.querySelectorAll('input').forEach((i) => i.setAttribute('aria-invalid', 'true'))
      form.querySelector('input[name=password]').value = ''
    } finally {
      fields.forEach((i) => { i.disabled = false })
      button.disabled = false
      button.innerHTML = label
    }
  }

  $('#form-login').addEventListener('submit', (e) => { e.preventDefault(); submit(e.target, 'login') })
  $('#form-signup').addEventListener('submit', (e) => { e.preventDefault(); submit(e.target, 'signup') })
  $('#form-signup .switch a').addEventListener('click', (e) => { e.preventDefault(); history.pushState(null, '', location.pathname + location.search); showForm() })
  window.addEventListener('hashchange', showForm)
  window.addEventListener('popstate', () => { if (!$('#view-auth').hidden) showForm() })

  document.querySelectorAll('.pw-toggle').forEach((btn) => btn.addEventListener('click', () => {
    const input = btn.parentElement.querySelector('input')
    const shown = input.type === 'password'
    input.type = shown ? 'text' : 'password'
    btn.setAttribute('aria-pressed', String(shown))
    btn.setAttribute('aria-label', shown ? 'Hide password' : 'Show password')
    btn.querySelector('use').setAttribute('href', shown ? '#i-eye-off' : '#i-eye')
  }))

  $('#signout').addEventListener('click', async () => {
    await api('logout', {}).catch(() => undefined)
    history.replaceState(null, '', '/')
    showSignedOut()
  })

  Promise.all([api('config'), api('me')])
    .then(([cfg, me]) => {
      config = cfg
      $('#pw-rule').textContent = cfg.password_rule
      document.querySelectorAll('[data-signup-only]').forEach((el) => { el.hidden = !cfg.signup_open })
      document.querySelectorAll('[data-signup-closed]').forEach((el) => { el.hidden = cfg.signup_open })
      renderAreas()
      renderPickers()
      if (me.user) signedInArrival(me.user)
      else showSignedOut()
    })
    .catch(() => showError($('#page-error'), 'The sign-in service is unavailable right now. Please try again in a moment.'))
})()
