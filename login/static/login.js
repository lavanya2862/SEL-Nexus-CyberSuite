// SEL Nexus CyberSuite sign-in page. People pick a domain (Infrastructure Security, Application Security) on
// the sign-in form and go straight there; at sign-up they tick which domains their account needs.
// A domain that finds nobody signed in sends people here with ?next=<its address>; after sign-in they go straight back.
// ?switch shows the signed-in person their domains to move between (the "Switch domain" button in each domain).
(() => {
  const $ = (sel) => document.querySelector(sel)
  const ICONS = { infrastructure_security: 'i-server', application_security: 'i-code' }
  const RENAMED = { defender_infra: 'infrastructure_security', infrastructure_vulnerabilities: 'infrastructure_security', application_vulnerabilities: 'application_security' } // ids before the rename
  const LAST = 'cybersuite-domain' // the domain picked last time on this browser, picked again by default
  let config = null

  async function api(path, body) {
    const res = await fetch(`/api/${path}`, body === undefined ? {} : {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CyberSuite': 'auth' },
      body: JSON.stringify(body),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `The sign-in page answered ${res.status}`)
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

  /** The domain cards inside a form: radio buttons on sign-in (one domain now), tick boxes on sign-up (all you need). */
  function renderDomains() {
    const wanted = moduleOf(safeNext() || '')?.id || store.get() || config.modules[0]?.id
    document.querySelectorAll('[data-domains]').forEach((list) => {
      const kind = list.dataset.domains
      list.replaceChildren(...config.modules.map((m) => {
        const label = document.createElement('label')
        label.className = 'domain'
        const tile = m.id === 'application_security' ? 'tile tile-violet' : 'tile'
        label.innerHTML = `<input type="${kind}" name="${kind === 'radio' ? 'domain' : 'domains'}">` +
          `<span class="${tile}"><svg class="ico"><use href="#${ICONS[m.id] || 'i-shield'}"/></svg></span>` +
          '<span><b></b><small></small></span><span class="mark"><svg class="ico"><use href="#i-check"/></svg></span>'
        const input = label.querySelector('input')
        input.value = m.id
        input.checked = m.id === wanted
        label.querySelector('b').textContent = m.name
        label.querySelector('small').textContent = m.url ? m.description : 'Not connected yet'
        return label
      }))
    })
  }

  function showForm() {
    const signup = location.hash === '#signup' && config?.signup_open
    $('#form-login').hidden = signup
    $('#form-signup').hidden = !signup
    const form = signup ? $('#form-signup') : $('#form-login')
    showError(form.querySelector('.error'), null)
    form.querySelector('input')?.focus()
  }

  function showSignedOut() {
    $('#who').hidden = true
    $('#view-choose').hidden = true
    $('#view-auth').hidden = false
    showForm()
  }

  /** Into the chosen domain: back to the page that sent the person here when it belongs to that domain. */
  function enter(user) {
    const m = moduleById(user.domain)
    store.set(user.domain)
    if (!m?.url) return showChooser(user, `${m?.name || 'That domain'} is not connected yet.`)
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
    $('#welcome').textContent = 'Switch domain'
    $('#choose-lead').textContent = `Signed in as ${user.name.split(' ')[0]}. Choose where you want to work.`
    showError($('#choose-error'), message || null)
    $('#modules').replaceChildren(...config.modules.filter((m) => mine.includes(m.id)).map((m) => {
      const here = m.id === user.domain
      const card = document.createElement(m.url ? 'button' : 'div')
      card.className = m.url ? 'module' : 'module off'
      if (m.url) { card.type = 'button'; card.addEventListener('click', () => (here ? enter(user) : switchTo(user, m.id))) }
      const tile = m.id === 'application_security' ? 'tile tile-violet' : 'tile'
      card.innerHTML = `<span class="${tile}"><svg class="ico"><use href="#${ICONS[m.id] || 'i-shield'}"/></svg></span><h2></h2><p></p>` +
        (!m.url ? '<span class="soon">Not connected yet</span>'
          : here ? '<span class="here">You are here · Open</span>' : '<span class="go">Open <svg class="ico"><use href="#i-arrow"/></svg></span>')
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
      if (!mine.includes(target.id)) return showChooser(user, `Your account does not include ${target.name}. Ask the CyberSuite owner for access, or choose one of your domains.`)
      return target.id === user.domain ? enter(user) : switchTo(user, target.id)
    }
    if (user.domain && mine.includes(user.domain)) return enter(user)
    return showChooser(user)
  }

  async function submit(form, action) {
    const box = form.querySelector('.error')
    const button = form.querySelector('button[type=submit]')
    const label = button.textContent
    const fd = new FormData(form)
    const data = { email: String(fd.get('email') || '').trim(), password: fd.get('password') }
    if (action === 'signup') {
      data.name = fd.get('name')
      data.domains = fd.getAll('domains')
      const back = moduleOf(safeNext() || '')?.id
      if (back && data.domains.includes(back)) data.domain = back
    } else {
      data.domain = fd.get('domain')
    }
    showError(box, null)
    if (action === 'signup' && !data.domains.length) return showError(box, 'Tick at least one domain you need access to.')
    if (action === 'login' && !data.domain) return showError(box, 'Choose the domain you want to open.')
    form.querySelectorAll('input').forEach((i) => { i.disabled = true; i.removeAttribute('aria-invalid') })
    button.disabled = true
    button.textContent = button.dataset.busy
    try {
      const { user } = await api(action, data)
      form.reset()
      enter(user)
    } catch (err) {
      showError(box, err.message)
      if (!/domain/i.test(err.message)) form.querySelectorAll('input:not([name^=domain])').forEach((i) => i.setAttribute('aria-invalid', 'true'))
      form.querySelector('input[name=password]').value = ''
    } finally {
      form.querySelectorAll('input').forEach((i) => { i.disabled = false })
      button.disabled = false
      button.textContent = label
    }
  }

  $('#form-login').addEventListener('submit', (e) => { e.preventDefault(); submit(e.target, 'login') })
  $('#form-signup').addEventListener('submit', (e) => { e.preventDefault(); submit(e.target, 'signup') })
  $('#form-signup a').addEventListener('click', (e) => { e.preventDefault(); history.pushState(null, '', location.pathname + location.search); showForm() })
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
      renderDomains()
      if (me.user) signedInArrival(me.user)
      else showSignedOut()
    })
    .catch(() => showError($('#page-error'), 'The sign-in service is not answering. Check that it is running, then reload this page.'))
})()
