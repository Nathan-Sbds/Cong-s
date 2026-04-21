const http = require('http');
const https = require('https');
const fs = require('fs');
const { URL } = require('url');
const db = require('./database');

const PORT = Number(process.env.PORT || 80);
const HTTPS_KEY_PATH = process.env.HTTPS_KEY_PATH || '';
const HTTPS_CERT_PATH = process.env.HTTPS_CERT_PATH || '';

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseCookies(header) {
  const out = {};
  String(header || '')
    .split(';')
    .map(part => part.trim())
    .filter(Boolean)
    .forEach(part => {
      const index = part.indexOf('=');
      if (index === -1) return;
      const key = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      out[key] = decodeURIComponent(value);
    });
  return out;
}

function normalizePrefix(prefix) {
  let value = String(prefix || '').trim();
  if (!value) return '';
  if (!value.startsWith('/')) value = `/${value}`;
  value = value.replace(/\/+$/g, '');
  return value || '/';
}

function normalizeTargetUrl(targetUrl) {
  const value = String(targetUrl || '').trim();
  if (!value) return '';
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol)) return '';
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return '';
  }
}

function buildTargetUrl({ protocol, host, port }) {
  const cleanProtocol = String(protocol || 'http').trim().toLowerCase() === 'https' ? 'https' : 'http';
  const cleanHost = String(host || '127.0.0.1').trim() || '127.0.0.1';
  const cleanPort = Number(port);
  if (!Number.isInteger(cleanPort) || cleanPort < 1 || cleanPort > 65535) return '';
  return `${cleanProtocol}://${cleanHost}:${cleanPort}`;
}

function splitTargetUrl(targetUrl) {
  try {
    const parsed = new URL(targetUrl);
    return {
      protocol: parsed.protocol === 'https:' ? 'https' : 'http',
      host: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
    };
  } catch {
    return { protocol: 'http', host: '127.0.0.1', port: '80' };
  }
}

function getRoutes() {
  return db.prepare(`
    SELECT id, name, path_prefix, target_url, strip_prefix, enabled, created_at, updated_at
    FROM routes
    ORDER BY LENGTH(path_prefix) DESC, path_prefix ASC
  `).all();
}

function getSettings() {
  return db.prepare('SELECT * FROM settings WHERE id = 1').get();
}

function setRouteCookie(res, prefix) {
  const cookie = `gw_route=${encodeURIComponent(prefix)}; Path=/; SameSite=Lax`;
  const existing = res.getHeader('Set-Cookie');
  if (!existing) {
    res.setHeader('Set-Cookie', cookie);
    return;
  }

  const next = Array.isArray(existing) ? [...existing, cookie] : [existing, cookie];
  res.setHeader('Set-Cookie', next);
}

function routeMatches(prefix, pathname) {
  if (!prefix || prefix === '/') return false;
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

function chooseRoute(req, routes) {
  const requestUrl = new URL(req.url, 'http://127.0.0.1');
  const pathname = requestUrl.pathname;

  const exact = routes.find(route => routeMatches(route.path_prefix, pathname));
  if (exact) return exact;

  const cookies = parseCookies(req.headers.cookie);
  if (cookies.gw_route) {
    const cookieRoute = routes.find(route => route.path_prefix === cookies.gw_route && route.enabled);
    if (cookieRoute) return cookieRoute;
  }

  const referer = req.headers.referer || req.headers.referrer || '';
  if (referer) {
    try {
      const refPath = new URL(referer).pathname;
      const refRoute = routes.find(route => routeMatches(route.path_prefix, refPath));
      if (refRoute) return refRoute;
    } catch {
      // Ignore invalid referer.
    }
  }

  return null;
}

function stripPrefixFromPath(pathname, prefix) {
  if (!prefix || prefix === '/') return pathname || '/';
  if (pathname === prefix) return '/';
  if (pathname.startsWith(`${prefix}/`)) return pathname.slice(prefix.length) || '/';
  return pathname || '/';
}

function proxyRequest(req, res, route) {
  const target = new URL(route.target_url);
  const incoming = new URL(req.url, 'http://127.0.0.1');
  const pathname = route.strip_prefix ? stripPrefixFromPath(incoming.pathname, route.path_prefix) : incoming.pathname;
  const forwardPath = `${pathname}${incoming.search}` || '/';
  const transport = target.protocol === 'https:' ? https : http;

  const headers = {
    ...req.headers,
    host: target.host,
    connection: 'close',
    'x-forwarded-for': req.socket.remoteAddress || '',
    'x-forwarded-host': req.headers.host || '',
    'x-forwarded-proto': req.socket.encrypted ? 'https' : 'http',
    'x-forwarded-prefix': route.path_prefix,
    'x-gateway-route': route.path_prefix,
  };

  delete headers['content-length'];
  delete headers['transfer-encoding'];

  const upstream = transport.request(
    {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      method: req.method,
      path: forwardPath,
      headers,
    },
    upstreamRes => {
      const responseHeaders = { ...upstreamRes.headers };
      if (responseHeaders.location && typeof responseHeaders.location === 'string') {
        if (responseHeaders.location.startsWith('/')) {
          responseHeaders.location = route.strip_prefix
            ? `${route.path_prefix}${responseHeaders.location}`.replace(/\/+/g, '/')
            : responseHeaders.location;
        }
      }

      res.statusCode = upstreamRes.statusCode || 502;
      for (const [key, value] of Object.entries(responseHeaders)) {
        if (typeof value === 'undefined') continue;
        if (key.toLowerCase() === 'content-length') continue;
        if (key.toLowerCase() === 'connection') continue;
        res.setHeader(key, value);
      }

      setRouteCookie(res, route.path_prefix);
      upstreamRes.pipe(res);
    }
  );

  upstream.on('error', err => {
    res.statusCode = 502;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Gateway</title><style>body{font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:32px} .card{max-width:720px;margin:auto;background:#1a1d2e;border:1px solid #2d3148;border-radius:16px;padding:24px} code{background:#232641;padding:2px 6px;border-radius:6px}</style></head><body><div class="card"><h1>Service indisponible</h1><p>Impossible d'atteindre <code>${escapeHtml(route.target_url)}</code>.</p><p>${escapeHtml(err.message)}</p></div></body></html>`);
  });

  req.pipe(upstream);
}

function renderRootPage() {
  const settings = getSettings();
  const routes = getRoutes().filter(route => route.enabled);

  const cards = routes.length
    ? routes.map(route => `
      <a class="app-card" href="${escapeHtml(route.path_prefix)}">
        <div class="app-card-top">
          <strong>${escapeHtml(route.name)}</strong>
          <span>${escapeHtml(route.path_prefix)}</span>
        </div>
        <small>${escapeHtml(route.target_url)}</small>
      </a>
    `).join('')
    : '<div class="empty-state">Aucune route active. Ajoute une application via <code>/admin</code>.</div>';

  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(settings.title)}</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, Segoe UI, sans-serif;
      background: radial-gradient(circle at top, #1b1f34, #0f1117 60%);
      color: #e2e8f0;
    }
    main {
      max-width: 960px;
      margin: 0 auto;
      padding: 40px 20px 56px;
    }
    .hero {
      display: grid;
      gap: 14px;
      margin-bottom: 26px;
    }
    h1 { margin: 0; font-size: clamp(2rem, 4vw, 3.2rem); }
    p { margin: 0; color: #94a3b8; line-height: 1.55; }
    .toolbar { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 10px; }
    .toolbar a {
      color: white; text-decoration: none; padding: 10px 14px; border-radius: 999px;
      background: #6c63ff; font-weight: 700;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      margin-top: 24px;
    }
    .app-card {
      display: grid;
      gap: 10px;
      text-decoration: none;
      color: inherit;
      background: rgba(35, 38, 65, 0.88);
      border: 1px solid #2d3148;
      border-radius: 18px;
      padding: 18px;
      transition: transform .15s ease, border-color .15s ease, background .15s ease;
    }
    .app-card:hover { transform: translateY(-2px); border-color: #6c63ff; background: rgba(38, 42, 73, 0.95); }
    .app-card-top { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; }
    .app-card-top span { color: #94a3b8; font-size: .9rem; }
    small { color: #a8b0ca; }
    .empty-state {
      padding: 20px;
      border: 1px dashed #2d3148;
      border-radius: 14px;
      color: #94a3b8;
      background: rgba(26, 29, 46, 0.7);
    }
    code { background: #232641; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>${escapeHtml(settings.title)}</h1>
      <p>${escapeHtml(settings.public_root_message)}</p>
      <div class="toolbar">
        <a href="/admin">Administrer les routes</a>
      </div>
    </section>
    <section class="grid">
      ${cards}
    </section>
  </main>
</body>
</html>`;
}

function renderAdminPage() {
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Administration Gateway</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, Segoe UI, sans-serif;
      background: #0f1117;
      color: #e2e8f0;
    }
    main { max-width: 1180px; margin: 0 auto; padding: 30px 18px 48px; }
    h1, h2 { margin: 0 0 14px; }
    .panel {
      background: #1a1d2e;
      border: 1px solid #2d3148;
      border-radius: 16px;
      padding: 18px;
      margin-top: 16px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 12px;
    }
    label { display: grid; gap: 6px; font-size: .88rem; color: #94a3b8; }
    input, select {
      background: #232641;
      border: 1px solid #2d3148;
      color: #e2e8f0;
      border-radius: 10px;
      padding: 11px 12px;
      width: 100%;
    }
    button {
      background: #6c63ff;
      color: #fff;
      border: none;
      border-radius: 10px;
      padding: 11px 14px;
      cursor: pointer;
      font-weight: 700;
    }
    button.secondary { background: #232641; border: 1px solid #2d3148; }
    .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
    .routes { display: grid; gap: 10px; margin-top: 14px; }
    .route {
      display: grid;
      grid-template-columns: 1.3fr 1.5fr 1fr auto auto;
      gap: 10px;
      align-items: center;
      padding: 12px;
      background: #232641;
      border: 1px solid #2d3148;
      border-radius: 12px;
    }
    .route small { color: #94a3b8; }
    .pill { display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px; font-size:.78rem; background:#1f2937; }
    .muted { color: #94a3b8; }
    .actions { display:flex; gap:8px; justify-content:flex-end; }
    .topbar { display:flex; justify-content:space-between; gap:16px; align-items:center; flex-wrap:wrap; }
    .status { font-size:.9rem; color:#94a3b8; }
    @media (max-width: 860px) {
      .route { grid-template-columns: 1fr; }
      .actions { justify-content:flex-start; }
    }
  </style>
</head>
<body>
  <main>
    <div class="topbar">
      <div>
        <h1>Gateway routes</h1>
        <div class="status">Gestion du routage par base SQLite</div>
      </div>
      <div class="row">
        <a href="/" style="color:#e2e8f0;text-decoration:none;padding:10px 14px;border:1px solid #2d3148;border-radius:10px;background:#1a1d2e">Retour accueil</a>
      </div>
    </div>

    <div class="panel">
      <h2>Nouvelle route</h2>
      <div class="grid">
        <label>Nom
          <input id="name" placeholder="Congés" />
        </label>
        <label>Préfixe public
          <input id="path_prefix" placeholder="/conges" />
        </label>
        <label>Protocole
          <select id="target_protocol">
            <option value="http">http</option>
            <option value="https">https</option>
          </select>
        </label>
        <label>Hôte cible
          <input id="target_host" value="127.0.0.1" placeholder="127.0.0.1" />
        </label>
        <label>Port cible
          <input id="target_port" type="number" min="1" max="65535" placeholder="5001" />
        </label>
        <label>Strip prefix
          <select id="strip_prefix">
            <option value="1">Oui</option>
            <option value="0">Non</option>
          </select>
        </label>
      </div>
      <div class="row" style="margin-top:12px;">
        <button id="createBtn" onclick="createRoute()">Créer la route</button>
        <button class="secondary" onclick="loadRoutes()">Rafraîchir</button>
      </div>
      <div id="message" class="muted" style="margin-top:10px"></div>
    </div>

    <div class="panel">
      <h2>Routes actives</h2>
      <div id="routes" class="routes"></div>
    </div>
  </main>
  <script src="/admin.js"></script>
</body>
</html>`;
}

function renderAdminJs() {
  return [
    "const $ = function(id) { return document.getElementById(id); };",
    "function escapeHtml(value) {",
    "  return String(value == null ? '' : value)",
    "    .replace(/&/g, '&amp;')",
    "    .replace(/</g, '&lt;')",
    "    .replace(/>/g, '&gt;')",
    "    .replace(/\"/g, '&quot;')",
    "    .replace(/'/g, '&#39;');",
    "}",
    "async function api(path, options) {",
    "  const res = await fetch(path, {",
    "    ...(options || {}),",
    "    headers: { 'Content-Type': 'application/json', ...((options && options.headers) || {}) },",
    "  });",
    "  const data = await res.json().catch(function() { return {}; });",
    "  if (!res.ok) throw new Error(data.error || 'Erreur');",
    "  return data;",
    "}",
    "function setMessage(text, isError) {",
    "  const el = $('message');",
    "  if (!el) return;",
    "  el.textContent = text;",
    "  el.style.color = isError ? '#f87171' : '#94a3b8';",
    "}",
    "async function loadRoutes() {",
    "  const data = await api('/api/routes');",
    "  const container = $('routes');",
    "  if (!container) return;",
    "  if (!data.routes.length) {",
    "    container.innerHTML = '<div class=\"muted\">Aucune route définie.</div>';",
    "    return;",
    "  }",
    "  container.innerHTML = data.routes.map(function(route) {",
    "    return '<div class=\"route\">' +",
    "      '<div><strong>' + escapeHtml(route.name) + '</strong><br><small>' + escapeHtml(route.path_prefix) + '</small></div>' +",
    "      '<div><small>' + escapeHtml(route.target_url) + '</small></div>' +",
    "      '<div>' +",
    "        '<span class=\"pill\">strip_prefix: ' + (route.strip_prefix ? 'oui' : 'non') + '</span>' +",
    "        '<span class=\"pill\">' + (route.enabled ? 'actif' : 'inactif') + '</span>' +",
    "      '</div>' +",
    "      '<div class=\"actions\">' +",
    "        '<button class=\"secondary\" onclick=\"toggleRoute(' + route.id + ', ' + (route.enabled ? 0 : 1) + ')\">' + (route.enabled ? 'Désactiver' : 'Activer') + '</button>' +",
    "        '<button class=\"secondary\" onclick=\"deleteRoute(' + route.id + ')\">Supprimer</button>' +",
    "      '</div>' +",
    "      '<div></div>' +",
    "    '</div>';",
    "  }).join('');",
    "}",
    "function getTargetUrlFromForm() {",
    "  const protocol = $('target_protocol').value === 'https' ? 'https' : 'http';",
    "  const host = ($('target_host').value || '').trim() || '127.0.0.1';",
    "  const port = Number($('target_port').value);",
    "  if (!Number.isInteger(port) || port < 1 || port > 65535) {",
    "    throw new Error('Port cible invalide.');",
    "  }",
    "  return protocol + '://' + host + ':' + port;",
    "}",
    "async function createRoute() {",
    "  try {",
    "    await api('/admin/routes', {",
    "      method: 'POST',",
    "      body: JSON.stringify({",
    "        name: $('name').value,",
    "        path_prefix: $('path_prefix').value,",
    "        target_url: getTargetUrlFromForm(),",
    "        strip_prefix: $('strip_prefix').value,",
    "      }),",
    "    });",
    "    $('name').value = '';",
    "    $('path_prefix').value = '';",
    "    $('target_protocol').value = 'http';",
    "    $('target_host').value = '127.0.0.1';",
    "    $('target_port').value = '';",
    "    $('strip_prefix').value = '1';",
    "    setMessage('Route créée.');",
    "    await loadRoutes();",
    "  } catch (err) {",
    "    setMessage(err.message, true);",
    "  }",
    "}",
    "async function toggleRoute(id, enabled) {",
    "  try {",
    "    await api('/admin/routes/' + id, {",
    "      method: 'PUT',",
    "      body: JSON.stringify({ enabled: enabled }),",
    "    });",
    "    await loadRoutes();",
    "  } catch (err) {",
    "    setMessage(err.message, true);",
    "  }",
    "}",
    "async function deleteRoute(id) {",
    "  if (!confirm('Supprimer cette route ?')) return;",
    "  try {",
    "    await api('/admin/routes/' + id, { method: 'DELETE' });",
    "    await loadRoutes();",
    "  } catch (err) {",
    "    setMessage(err.message, true);",
    "  }",
    "}",
    "loadRoutes().catch(function(err) { setMessage(err.message, true); });",
  ].join('\n');
}

function json(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(new Error('JSON invalide'));
      }
    });
    req.on('error', reject);
  });
}

function setCommonHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'same-origin');
}

async function handleRequest(req, res) {
  setCommonHeaders(res);
  const routes = getRoutes();
  const requestUrl = new URL(req.url, 'http://127.0.0.1');

  if (req.method === 'GET' && requestUrl.pathname === '/health') {
    return json(res, 200, { ok: true, routes: routes.length });
  }

  if (req.method === 'GET' && requestUrl.pathname === '/') {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.end(renderRootPage());
  }

  if (req.method === 'GET' && requestUrl.pathname === '/admin') {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.end(renderAdminPage());
  }

  if (req.method === 'GET' && requestUrl.pathname === '/admin.js') {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
    return res.end(renderAdminJs());
  }

  if (requestUrl.pathname === '/api/routes' && req.method === 'GET') {
    return json(res, 200, { routes });
  }

  if (requestUrl.pathname === '/admin/routes' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const name = String(body.name || '').trim();
      const pathPrefix = normalizePrefix(body.path_prefix);
      const targetUrl = normalizeTargetUrl(body.target_url);
      const stripPrefix = Number(body.strip_prefix) ? 1 : 0;

      if (!name) return json(res, 400, { error: 'Nom requis.' });
      if (!pathPrefix || pathPrefix === '/') return json(res, 400, { error: 'Préfixe invalide.' });
      if (!targetUrl) return json(res, 400, { error: 'URL cible invalide.' });

      db.prepare(`
        INSERT INTO routes (name, path_prefix, target_url, strip_prefix)
        VALUES (?, ?, ?, ?)
      `).run(name, pathPrefix, targetUrl, stripPrefix);

      return json(res, 201, { success: true });
    } catch (err) {
      return json(res, 400, { error: err.message || 'Création impossible.' });
    }
  }

  const routeMatch = requestUrl.pathname.startsWith('/admin/routes/') ? requestUrl.pathname.split('/').filter(Boolean) : null;
  if (routeMatch && routeMatch[0] === 'admin' && routeMatch[1] === 'routes' && routeMatch[2]) {
    const id = Number(routeMatch[2]);
    if (!Number.isInteger(id)) return json(res, 400, { error: 'ID invalide.' });

    if (req.method === 'PUT') {
      try {
        const body = await readBody(req);
        const current = db.prepare('SELECT * FROM routes WHERE id = ?').get(id);
        if (!current) return json(res, 404, { error: 'Route introuvable.' });

        const nextName = String(body.name ?? current.name).trim();
        const nextPrefix = normalizePrefix(body.path_prefix ?? current.path_prefix);
        const nextTargetUrl = normalizeTargetUrl(body.target_url ?? current.target_url);
        const nextStripPrefix = body.strip_prefix === undefined ? current.strip_prefix : Number(body.strip_prefix) ? 1 : 0;
        const nextEnabled = body.enabled === undefined ? current.enabled : Number(body.enabled) ? 1 : 0;

        if (!nextName) return json(res, 400, { error: 'Nom requis.' });
        if (!nextPrefix || nextPrefix === '/') return json(res, 400, { error: 'Préfixe invalide.' });
        if (!nextTargetUrl) return json(res, 400, { error: 'URL cible invalide.' });

        db.prepare(`
          UPDATE routes
          SET name = ?, path_prefix = ?, target_url = ?, strip_prefix = ?, enabled = ?, updated_at = datetime('now')
          WHERE id = ?
        `).run(nextName, nextPrefix, nextTargetUrl, nextStripPrefix, nextEnabled, id);

        return json(res, 200, { success: true });
      } catch (err) {
        return json(res, 400, { error: err.message || 'Mise à jour impossible.' });
      }
    }

    if (req.method === 'DELETE') {
      db.prepare('DELETE FROM routes WHERE id = ?').run(id);
      return json(res, 200, { success: true });
    }
  }

  if (req.method === 'POST' && requestUrl.pathname === '/admin/routes/seed') {
    const count = db.prepare('SELECT COUNT(*) AS count FROM routes').get().count;
    if (!count) {
      db.prepare(`
        INSERT INTO routes (name, path_prefix, target_url, strip_prefix)
        VALUES (?, ?, ?, ?)
      `).run('Congés', '/conges', 'http://127.0.0.1:5001', 1);
    }
    return json(res, 200, { success: true });
  }

  const route = chooseRoute(req, routes);
  if (route) {
    return proxyRequest(req, res, route);
  }

  if (requestUrl.pathname.startsWith('/api/')) {
    return json(res, 404, { error: 'Aucune route ne correspond à cette API.' });
  }

  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>404</title><style>body{font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:32px} .card{max-width:680px;margin:auto;background:#1a1d2e;border:1px solid #2d3148;border-radius:16px;padding:24px}</style></head><body><div class="card"><h1>Page introuvable</h1><p>Cette URL ne correspond à aucune route.</p><p>Ouvre <a href="/">l’accueil</a> ou <a href="/admin">l’administration</a>.</p></div></body></html>`);
}

let server;
if (HTTPS_KEY_PATH && HTTPS_CERT_PATH) {
  try {
    const key = fs.readFileSync(HTTPS_KEY_PATH);
    const cert = fs.readFileSync(HTTPS_CERT_PATH);
    server = https.createServer({ key, cert }, handleRequest);
    console.log('🔒 HTTPS activé');
  } catch (err) {
    console.warn(`⚠️ HTTPS désactivé: ${err.message}`);
  }
}

if (!server) {
  server = http.createServer(handleRequest);
}

server.listen(PORT, () => {
  console.log(`✅ Gateway démarrée sur ${HTTPS_KEY_PATH && HTTPS_CERT_PATH ? 'https' : 'http'}://localhost:${PORT}`);
  console.log('ℹ️ Ouvre / pour la sélection des applications, /admin pour gérer les routes');
});
