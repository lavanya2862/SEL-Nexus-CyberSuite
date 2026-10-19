// SEL Nexus CyberSuite sign-in page: sign in (or create an account), then pick a module.
// A module that finds nobody signed in sends people here with ?next=<its address>; after sign-in they go straight back.
(() => {
  const $ = (sel) => document.querySelector(sel)
  const ICONS = { defender_infra: 'i-server', application_vulnerabilities: 'i-code' }
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

  /** Only go back to one of our own modules, never another website. */
  function safeNext() {
    const next = new URLSearchParams(location.search).get('next')
    if (!next || !config) return null
    try {
      const url = new URL(next)
      return config.modules.some((m) => m.url && new URL(m.url).origin === url.origin) ? url.href : null
    } catch { return null }
  }

  function showError(box, message) {
    box.hidden = !message
    box.replaceChildren()
    if (!message) return
    box.insertAdjacentHTML('afterbegin', '<svg class="ico"><use href="#i-alert"/></svg>')
    box.append(document.createTextNode(message))
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

  function moduleCard(m) {
    const card = document.createElement(m.url ? 'a' : 'div')
    card.className = m.url ? 'module' : 'module off'
    if (m.url) card.href = m.url
    else card.setAttribute('aria-disabled', 'true')
    const tile = m.id === 'application_vulnerabilities' ? 'tile tile-violet' : 'tile'
    card.innerHTML = `<span class="${tile}"><svg class="ico"><use href="#${ICONS[m.id] || 'i-shield'}"/></svg></span><h2></h2><p></p>` +
      (m.url ? '<span class="go">Open <svg class="ico"><use href="#i-arrow"/></svg></span>' : '<span class="soon">Not connected yet</span>')
    card.querySelector('h2').textContent = m.name
    card.querySelector('p').textContent = m.description
    return card
  }

  function showSignedIn(user) {
    const next = safeNext()
    if (next) { location.replace(next); return }
    $('#who-name').textContent = `${user.name} · ${user.email}`
    $('#who').hidden = false
    $('#view-auth').hidden = true
    $('#welcome').textContent = `Welcome, ${user.name.split(' ')[0]}`
    $('#modules').replaceChildren(...config.modules.map(moduleCard))
    $('#view-choose').hidden = false
    history.replaceState(null, '', '/')
  }

  async function submit(form, action) {
    const box = form.querySelector('.error')
    const button = form.querySelector('button[type=submit]')
    const label = button.textContent
    const data = Object.fromEntries(new FormData(form))
    data.email = String(data.email || '').trim()
    showError(box, null)
    form.querySelectorAll('input').forEach((i) => { i.disabled = true; i.removeAttribute('aria-invalid') })
    button.disabled = true
    button.textContent = button.dataset.busy
    try {
      const { user } = await api(action, data)
      form.reset()
      showSignedIn(user)
    } catch (err) {
      showError(box, err.message)
      form.querySelectorAll('input').forEach((i) => i.setAttribute('aria-invalid', 'true'))
      form.querySelector('input[type=password], input[name=password]').value = ''
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
    showSignedOut()
  })

  Promise.all([api('config'), api('me')])
    .then(([cfg, me]) => {
      config = cfg
      $('#pw-rule').textContent = cfg.password_rule
      document.querySelectorAll('[data-signup-only]').forEach((el) => { el.hidden = !cfg.signup_open })
      document.querySelectorAll('[data-signup-closed]').forEach((el) => { el.hidden = cfg.signup_open })
      if (me.user) showSignedIn(me.user)
      else showSignedOut()
    })
    .catch(() => showError($('#page-error'), 'The sign-in service is not answering. Check that it is running, then reload this page.'))
})()
