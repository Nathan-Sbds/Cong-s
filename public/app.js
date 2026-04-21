const API = '';
const AUTH_TOKEN_KEY = 'conges_auth_token';

let calendar;
let coursCalendar;
let allAbsences = [];
let prefs = {};
let FERIES_JS = [];
let ferieDates = new Set();
let fullDayAbsenceDates = new Set();
let morningAbsenceDates = new Set();
let afternoonAbsenceDates = new Set();
let coursWeekdays = new Set();
let coursDates = new Set();
let editingAbsenceId = null;
let selectedAbsenceId = null;
let pendingDatePrefill = null;
let suppressNextDateClick = false;
let authToken = localStorage.getItem(AUTH_TOKEN_KEY) || '';
let currentUsername = 'admin';
let pendingTwoFactorChallenge = null;
let coursPrefsSaveTimer = null;
const rqSoldePreviewCache = new Map();

// ─── INIT ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  bindAuthUI();
  initModalLivePreview();

  const status = await fetchAuthStatus();
  if (status.authenticated) {
    currentUsername = status.username || 'admin';
    showApp();
    await initAppData();
    return;
  }

  showLogin(status.username || 'admin');
});

async function initAppData() {
  initCalendar();
  initCoursCalendar();
  await loadFeries();
  await loadPrefs();
  await loadAbsences();
  await refreshSolde();
}

function bindAuthUI() {
  const form = document.getElementById('login-form');
  if (form) form.addEventListener('submit', onLoginSubmit);

  const registerForm = document.getElementById('register-form');
  if (registerForm) registerForm.addEventListener('submit', onRegisterSubmit);

  document.querySelectorAll('[data-auth-tab]').forEach(btn => {
    btn.addEventListener('click', () => showAuthTab(btn.dataset.authTab));
  });

  const logoutBtn = document.getElementById('btn-logout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      try {
        await apiFetch('/api/auth/logout', { method: 'POST' });
      } catch {
        // Ignore backend logout error; local cleanup still logs out the session.
      }
      authToken = '';
      localStorage.removeItem(AUTH_TOKEN_KEY);
      location.reload();
    });
  }
}

async function onLoginSubmit(event) {
  event.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const remember = document.getElementById('login-remember').checked;

  const msg = document.getElementById('login-error');
  msg.textContent = '';

  try {
    const res = await fetch(`${API}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, remember }),
    });
    const data = await res.json();

    if (!res.ok || !data.token) {
      if (data.requiresTwoFactor && data.challengeToken) {
        pendingTwoFactorChallenge = data.challengeToken;
        currentUsername = data.username || username;
        showTwoFactorLoginPanel();
        return;
      }
      msg.textContent = data.error || 'Connexion impossible.';
      return;
    }

    authToken = data.token;
    currentUsername = data.username || username;
    pendingTwoFactorChallenge = null;
    localStorage.setItem(AUTH_TOKEN_KEY, authToken);
    showApp();
    await initAppData();
  } catch {
    msg.textContent = 'Erreur réseau. Réessayez.';
  }
}

async function onRegisterSubmit(event) {
  event.preventDefault();
  const username = document.getElementById('register-username').value.trim();
  const password = document.getElementById('register-password').value;
  const confirm = document.getElementById('register-password-confirm').value;
  const msg = document.getElementById('register-error');
  msg.textContent = '';

  if (password !== confirm) {
    msg.textContent = 'Les mots de passe ne correspondent pas.';
    return;
  }

  try {
    const res = await fetch(`${API}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (!res.ok || !data.token) {
      msg.textContent = data.error || 'Création impossible.';
      return;
    }

    authToken = data.token;
    currentUsername = data.username || username;
    pendingTwoFactorChallenge = null;
    localStorage.setItem(AUTH_TOKEN_KEY, authToken);
    showApp();
    await initAppData();
  } catch {
    msg.textContent = 'Erreur réseau. Réessayez.';
  }
}

async function fetchAuthStatus() {
  try {
    const res = await fetch(`${API}/api/auth/status`, {
      headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
    });
    if (!res.ok) return { authenticated: false, username: 'admin' };
    return await res.json();
  } catch {
    return { authenticated: false, username: 'admin' };
  }
}

function showLogin(defaultUsername) {
  document.getElementById('auth-screen').classList.remove('hidden');
  document.getElementById('app').classList.add('hidden');
  document.getElementById('login-username').value = defaultUsername || 'admin';
  document.getElementById('login-password').value = '';
  document.getElementById('register-username').value = '';
  document.getElementById('register-password').value = '';
  document.getElementById('register-password-confirm').value = '';
  document.getElementById('twofactor-code').value = '';
  hideForgotPasswordPanel();
  hideTwoFactorLoginPanel();
  setAuthMessage('login-error', '');
  setAuthMessage('register-error', '');
  setAuthMessage('forgot-error', '');
  setAuthMessage('forgot-success', '');
  setAuthMessage('twofactor-login-error', '');
  showAuthTab('login');
}

function showApp() {
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');
  syncCurrentUsernameUI();
}

function syncCurrentUsernameUI() {
  const currentUsernameInput = document.getElementById('current-username');
  if (currentUsernameInput) currentUsernameInput.value = currentUsername || '';
}

function showAuthTab(tab) {
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const loginTab = document.querySelector('[data-auth-tab="login"]');
  const registerTab = document.querySelector('[data-auth-tab="register"]');
  if (!loginForm || !registerForm || !loginTab || !registerTab) return;

  const isLogin = tab !== 'register';
  loginForm.classList.toggle('hidden', !isLogin);
  registerForm.classList.toggle('hidden', isLogin);
  loginTab.classList.toggle('active', isLogin);
  registerTab.classList.toggle('active', !isLogin);
  if (isLogin) hideForgotPasswordPanel();
}

function showTwoFactorLoginPanel() {
  document.getElementById('twofactor-login-panel').classList.remove('hidden');
  setAuthMessage('twofactor-login-error', '');
  setAuthMessage('login-error', '');
}

function hideTwoFactorLoginPanel() {
  const panel = document.getElementById('twofactor-login-panel');
  if (panel) panel.classList.add('hidden');
}

async function verifyTwoFactorLogin() {
  const code = document.getElementById('twofactor-code').value.trim();
  if (!pendingTwoFactorChallenge) {
    setAuthMessage('twofactor-login-error', 'Aucun challenge actif.');
    return;
  }
  if (!code) {
    setAuthMessage('twofactor-login-error', 'Saisissez le code 2FA.');
    return;
  }

  try {
    const res = await fetch(`${API}/api/auth/2fa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeToken: pendingTwoFactorChallenge, code }),
    });
    const data = await res.json();
    if (!res.ok || !data.token) {
      setAuthMessage('twofactor-login-error', data.error || 'Code invalide.');
      return;
    }

    authToken = data.token;
    currentUsername = data.username || currentUsername;
    pendingTwoFactorChallenge = null;
    localStorage.setItem(AUTH_TOKEN_KEY, authToken);
    hideTwoFactorLoginPanel();
    showApp();
    await initAppData();
  } catch {
    setAuthMessage('twofactor-login-error', 'Erreur réseau. Réessayez.');
  }
}

function cancelTwoFactorLogin() {
  pendingTwoFactorChallenge = null;
  document.getElementById('twofactor-code').value = '';
  hideTwoFactorLoginPanel();
}

function setAuthMessage(id, message) {
  const el = document.getElementById(id);
  if (el) el.textContent = message || '';
}

function showForgotPasswordPanel() {
  document.getElementById('forgot-password-panel').classList.remove('hidden');
  setAuthMessage('forgot-error', '');
  setAuthMessage('forgot-success', '');
  document.getElementById('forgot-username').value = document.getElementById('login-username').value.trim();
}

function hideForgotPasswordPanel() {
  const panel = document.getElementById('forgot-password-panel');
  if (panel) panel.classList.add('hidden');
}

async function resetForgotPassword() {
  const username = document.getElementById('forgot-username').value.trim();
  const code = document.getElementById('forgot-code').value.trim();
  const newPassword = document.getElementById('forgot-new-password').value;
  const confirm = document.getElementById('forgot-new-password-confirm').value;
  setAuthMessage('forgot-error', '');
  setAuthMessage('forgot-success', '');

  if (!username || !code || !newPassword) {
    setAuthMessage('forgot-error', 'Tous les champs sont requis.');
    return;
  }
  if (newPassword !== confirm) {
    setAuthMessage('forgot-error', 'Les mots de passe ne correspondent pas.');
    return;
  }

  try {
    const res = await fetch(`${API}/api/auth/forgot-password/reset`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, code, newPassword }),
    });
    const data = await res.json();
    if (!res.ok) {
      setAuthMessage('forgot-error', data.error || 'Réinitialisation impossible.');
      return;
    }

    setAuthMessage('forgot-success', 'Mot de passe réinitialisé. Vous pouvez vous connecter.');
    document.getElementById('login-username').value = username;
    document.getElementById('login-password').value = '';
    hideForgotPasswordPanel();
    showAuthTab('login');
  } catch {
    setAuthMessage('forgot-error', 'Erreur réseau. Réessayez.');
  }
}

async function apiFetch(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;

  const response = await fetch(`${API}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    authToken = '';
    localStorage.removeItem(AUTH_TOKEN_KEY);
    showLogin('admin');
    throw new Error('Session expirée');
  }

  return response;
}

// ─── FERIES ───────────────────────────────────────────────────────────────────

async function loadFeries() {
  try {
    const res = await apiFetch('/api/feries');
    const data = await res.json();
    FERIES_JS = Object.values(data).flat();
  } catch {
    FERIES_JS = [];
  }
  syncCalendarEvents();
}

// ─── VIEWS ────────────────────────────────────────────────────────────────────

function showView(name, btn) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(`view-${name}`).classList.add('active');
  btn.classList.add('active');
  if (name === 'list') renderList();
  if (name === 'calendar' && calendar) calendar.updateSize();
  if (name === 'settings' && coursCalendar) coursCalendar.updateSize();
}

function absencesToEvents(absences) {
  return absences.map(a => {
    const isConge = a.type === 'conge';
    let title = isConge ? '🟣 Congé' : '🟡 RQ';
    if (a.demi_journee === 'matin') title += ' (matin)';
    else if (a.demi_journee === 'apres-midi') title += ' (après-midi)';
    if (a.note) title += ` — ${a.note}`;
    const endDate = new Date(a.date_fin);
    endDate.setDate(endDate.getDate() + 1);

    if (a.demi_journee !== 'journee') {
      return {
        id: a.id,
        title,
        start: a.date_debut,
        end: addDays(a.date_debut, 1),
        allDay: true,
        display: 'auto',
        backgroundColor: 'transparent',
        borderColor: 'transparent',
        textColor: '#cbd5e1',
        classNames: [a.demi_journee === 'matin' ? 'absence-half-label-am' : 'absence-half-label-pm'],
        extendedProps: { absenceId: a.id },
      };
    }

    return {
      id: a.id,
      title,
      start: a.date_debut,
      end: endDate.toISOString().split('T')[0],
      allDay: true,
      display: 'background',
      backgroundColor: isConge ? '#6c63ff' : '#f59e0b',
      classNames: [isConge ? 'absence-full-conge' : 'absence-full-rq'],
      extendedProps: { absenceId: a.id },
    };
  });
}

function getEventAbsenceId(event) {
  return event.extendedProps?.absenceId || event.id;
}

function isFerieEvent(event) {
  return String(event.id || '').startsWith('ferie-');
}

function onCalendarEventClick(info) {
  suppressNextDateClick = true;
  info.jsEvent?.preventDefault();
  info.jsEvent?.stopPropagation();
  if (isFerieEvent(info.event)) return;
  const absenceId = getEventAbsenceId(info.event);
  if (!absenceId) return;
  openAbsenceInfo(absenceId);
}

function findAbsenceInRange(startDate, endDate) {
  return allAbsences.find(a => a.date_debut <= endDate && a.date_fin >= startDate) || null;
}

function initCalendar() {
  calendar = new FullCalendar.Calendar(document.getElementById('calendar'), {
    initialView: 'dayGridMonth',
    locale: 'fr',
    firstDay: 1,
    selectable: true,
    selectMirror: true,
    headerToolbar: {
      left: 'prev,next today',
      center: 'title',
      right: 'dayGridMonth,timeGridWeek,listMonth',
    },
    height: 'auto',
    events: [],
    datesSet() {
      applyDayCellHighlights();
    },
    dayCellDidMount(arg) {
      if (ferieDates.has(arg.dateStr)) arg.el.classList.add('fc-day-ferie');
      if (fullDayAbsenceDates.has(arg.dateStr)) arg.el.classList.add('fc-day-conge-full');
      if (morningAbsenceDates.has(arg.dateStr)) arg.el.classList.add('fc-day-conge-am');
      if (afternoonAbsenceDates.has(arg.dateStr)) arg.el.classList.add('fc-day-conge-pm');
      if (isCoursDay(arg.dateStr)) arg.el.classList.add('fc-day-cours');
    },
    eventClick: onCalendarEventClick,
    select(info) {
      suppressNextDateClick = true;
      // FullCalendar returns an exclusive end date for selections.
      const endInclusive = addDays(info.endStr, -1);

      const coursDays = getCoursDaysInRange(info.startStr, endInclusive);
      if (coursDays.length) {
        toast(`Jour de cours détecté (${coursDays[0]}), sélection impossible.`, true);
        calendar.unselect();
        return;
      }

      const existing = findAbsenceInRange(info.startStr, endInclusive);
      if (existing) {
        openAbsenceInfo(existing.id);
        calendar.unselect();
        return;
      }

      prefillModalDates(info.startStr, endInclusive);
      openModal();
      calendar.unselect();
    },
    dateClick(info) {
      if (suppressNextDateClick) {
        suppressNextDateClick = false;
        return;
      }

      if (isCoursDay(info.dateStr)) {
        toast('Impossible de poser une absence sur un jour de cours.', true);
        return;
      }

      const existing = findAbsenceByDate(info.dateStr);
      if (existing) {
        openAbsenceInfo(existing.id);
        return;
      }
      prefillModalDates(info.dateStr, info.dateStr);
      openModal();
    },
  });
  calendar.render();
}

function prefillModalDates(dateDebut, dateFin) {
  pendingDatePrefill = {
    date_debut: dateDebut,
    date_fin: dateFin,
  };
}

function feriesToEvents(feries) {
  return feries.map(date => ({
    id: `ferie-${date}`,
    start: date,
    end: addDays(date, 1),
    allDay: true,
    display: 'background',
    backgroundColor: '#64748b',
    classNames: ['ferie-full'],
  }));
}

function syncCalendarEvents() {
  if (!calendar) return;
  ferieDates = new Set(FERIES_JS);
  fullDayAbsenceDates = new Set();
  morningAbsenceDates = new Set();
  afternoonAbsenceDates = new Set();

  for (const a of allAbsences) {
    if (a.demi_journee === 'journee') {
      let cur = a.date_debut;
      while (cur <= a.date_fin) {
        fullDayAbsenceDates.add(cur);
        cur = addDays(cur, 1);
      }
      continue;
    }

    if (a.demi_journee === 'matin') morningAbsenceDates.add(a.date_debut);
    if (a.demi_journee === 'apres-midi') afternoonAbsenceDates.add(a.date_debut);
  }

  calendar.removeAllEvents();
  calendar.addEventSource(absencesToEvents(allAbsences));
  calendar.addEventSource(feriesToEvents(FERIES_JS));
  applyDayCellHighlights();
}

function applyDayCellHighlights() {
  const cells = document.querySelectorAll('.fc-daygrid-day[data-date]');
  for (const cell of cells) {
    cell.classList.remove('fc-day-ferie', 'fc-day-conge-full', 'fc-day-conge-am', 'fc-day-conge-pm', 'fc-day-cours');
    const date = cell.getAttribute('data-date');
    if (!date) continue;
    if (ferieDates.has(date)) cell.classList.add('fc-day-ferie');
    if (fullDayAbsenceDates.has(date)) cell.classList.add('fc-day-conge-full');
    if (morningAbsenceDates.has(date)) cell.classList.add('fc-day-conge-am');
    if (afternoonAbsenceDates.has(date)) cell.classList.add('fc-day-conge-pm');
    if (isCoursDay(date)) cell.classList.add('fc-day-cours');
  }
}

function parseCoursJours(csv) {
  if (!csv) return new Set();
  return new Set(
    String(csv)
      .split(',')
      .map(s => Number(s.trim()))
      .filter(n => Number.isInteger(n) && n >= 0 && n <= 6)
  );
}

function isCoursDay(dateStr) {
  if (coursDates.has(dateStr)) return true;
  if (!coursWeekdays.size) return false;
  const d = new Date(`${dateStr}T00:00:00Z`);
  return coursWeekdays.has(d.getUTCDay());
}

function getCoursDaysInRange(dateDebut, dateFin) {
  const out = [];
  let cur = dateDebut;
  while (cur <= dateFin) {
    if (isCoursDay(cur)) out.push(cur);
    cur = addDays(cur, 1);
  }
  return out;
}

function setCoursCheckboxesFromPrefs(csv) {
  const values = parseCoursJours(csv);
  coursWeekdays = values;
  document.querySelectorAll('#set-cours-days input[type="checkbox"]').forEach(cb => {
    cb.checked = values.has(Number(cb.value));
  });
}

function bindCoursCheckboxesAutoSave() {
  document.querySelectorAll('#set-cours-days input[type="checkbox"]').forEach(cb => {
    if (cb.dataset.coursBound === '1') return;
    cb.dataset.coursBound = '1';
    cb.addEventListener('change', () => {
      coursWeekdays = parseCoursJours(readCoursCheckboxesToCsv());
      applyDayCellHighlights();
      queueSaveCoursPrefs();
    });
  });
}

function parseCoursDates(csv) {
  if (!csv) return new Set();
  return new Set(
    String(csv)
      .split(',')
      .map(s => s.trim())
      .filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d))
  );
}

function renderCoursDatesList() {
  const container = document.getElementById('set-cours-dates-list');
  if (!container) return;

  const dates = Array.from(coursDates).sort();
  if (!dates.length) {
    container.innerHTML = '<span class="muted-text">Aucune date manuelle ajoutée.</span>';
    return;
  }

  const readable = dates.map(d => new Date(`${d}T00:00:00Z`).toLocaleDateString('fr-FR', {
    weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric'
  }));

  container.innerHTML = `
    <div class="cours-dates-summary">${dates.length} date(s) manuelle(s) enregistrée(s)</div>
    <textarea class="cours-dates-text" readonly>${readable.join('\n')}</textarea>
  `;
}

function coursDatesToEvents() {
  return Array.from(coursDates).map(d => ({
    id: `cours-${d}`,
    start: d,
    end: addDays(d, 1),
    allDay: true,
    display: 'background',
    classNames: ['cours-manual-event'],
  }));
}

function syncCoursCalendarEvents() {
  if (!coursCalendar) return;
  coursCalendar.removeAllEvents();
  coursCalendar.addEventSource(coursDatesToEvents());
}

function eachDateInRange(start, end, cb) {
  let cur = start;
  while (cur <= end) {
    cb(cur);
    cur = addDays(cur, 1);
  }
}

function toggleCoursDate(dateStr) {
  if (coursDates.has(dateStr)) {
    coursDates.delete(dateStr);
  } else {
    coursDates.add(dateStr);
  }
  renderCoursDatesList();
  syncCoursCalendarEvents();
  applyDayCellHighlights();
  queueSaveCoursPrefs();
}

function initCoursCalendar() {
  const el = document.getElementById('cours-calendar');
  if (!el || coursCalendar) return;

  coursCalendar = new FullCalendar.Calendar(el, {
    initialView: 'dayGridMonth',
    locale: 'fr',
    firstDay: 1,
    selectable: true,
    selectMirror: true,
    height: 'auto',
    headerToolbar: {
      left: 'prev,next today',
      center: 'title',
      right: '',
    },
    dateClick(info) {
      toggleCoursDate(info.dateStr);
    },
    select(info) {
      const endInclusive = addDays(info.endStr, -1);
      eachDateInRange(info.startStr, endInclusive, d => coursDates.add(d));
      renderCoursDatesList();
      syncCoursCalendarEvents();
      applyDayCellHighlights();
      queueSaveCoursPrefs();
      coursCalendar.unselect();
    },
    events: coursDatesToEvents(),
  });

  coursCalendar.render();
}

function setCoursDatesFromPrefs(csv) {
  coursDates = parseCoursDates(csv);
  renderCoursDatesList();
  syncCoursCalendarEvents();
}

function readCoursDatesToCsv() {
  return Array.from(coursDates).sort().join(',');
}

function addCoursDate() {
  const input = document.getElementById('set-cours-date-input');
  if (!input?.value) {
    toast('Sélectionnez une date de cours.', true);
    return;
  }
  coursDates.add(input.value);
  input.value = '';
  renderCoursDatesList();
  syncCoursCalendarEvents();
  applyDayCellHighlights();
  queueSaveCoursPrefs();
}

function removeCoursDate(date) {
  coursDates.delete(date);
  renderCoursDatesList();
  syncCoursCalendarEvents();
  applyDayCellHighlights();
  queueSaveCoursPrefs();
}

function queueSaveCoursPrefs() {
  clearTimeout(coursPrefsSaveTimer);
  coursPrefsSaveTimer = setTimeout(() => {
    void saveCoursPrefs();
  }, 250);
}

async function saveCoursPrefs() {
  const body = {
    cours_jours: readCoursCheckboxesToCsv(),
    cours_dates: readCoursDatesToCsv(),
  };

  try {
    const res = await apiFetch('/api/preferences/cours', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error('save-cours-failed');
    prefs = { ...prefs, ...body };
  } catch {
    toast('Erreur de sauvegarde des jours de cours', true);
  }
}

function readCoursCheckboxesToCsv() {
  const values = Array.from(document.querySelectorAll('#set-cours-days input[type="checkbox"]'))
    .filter(cb => cb.checked)
    .map(cb => Number(cb.value))
    .filter(v => Number.isInteger(v) && v >= 0 && v <= 6)
    .sort((a, b) => a - b);
  return values.join(',');
}

function getAbsenceById(id) {
  return allAbsences.find(a => a.id === id) || null;
}

function getAbsenceDisplayMode(absence) {
  return absence.demi_journee === 'matin' ? 'Matin uniquement'
    : absence.demi_journee === 'apres-midi' ? 'Après-midi uniquement'
    : 'Journée complète';
}

function getAbsenceDuration(absence) {
  const jours = countJoursOuvresJS(absence.date_debut, absence.date_fin);
  return absence.type === 'rq' ? jours : (absence.demi_journee !== 'journee' ? 0.5 : jours);
}

function findAbsenceByDate(dateStr) {
  const fullDay = allAbsences.find(a =>
    a.demi_journee === 'journee' &&
    a.date_debut <= dateStr &&
    a.date_fin >= dateStr
  );
  if (fullDay) return fullDay;

  const morning = allAbsences.find(a => a.demi_journee === 'matin' && a.date_debut === dateStr);
  if (morning) return morning;

  const afternoon = allAbsences.find(a => a.demi_journee === 'apres-midi' && a.date_debut === dateStr);
  if (afternoon) return afternoon;

  return allAbsences.find(a =>
    a.date_debut <= dateStr &&
    a.date_fin >= dateStr
  ) || null;
}

function openAbsenceInfo(id) {
  const absence = getAbsenceById(id);
  if (!absence) return;

  selectedAbsenceId = id;
  const info = document.getElementById('absence-info-content');
  const typeLabel = absence.type === 'conge' ? 'Congé payé' : 'RQ (repos compensateur)';
  const duration = getAbsenceDuration(absence);

  info.innerHTML = `
    <div class="absence-info-grid">
      <div><span>Type</span><strong>${typeLabel}</strong></div>
      <div><span>Début</span><strong>${formatDate(absence.date_debut)}</strong></div>
      <div><span>Fin</span><strong>${formatDate(absence.date_fin)}</strong></div>
      <div><span>Mode</span><strong>${getAbsenceDisplayMode(absence)}</strong></div>
      <div><span>Note</span><strong>${absence.note || '—'}</strong></div>
      <div><span>Jours décomptés</span><strong>${duration}j</strong></div>
    </div>
  `;

  document.getElementById('absence-info-overlay').classList.remove('hidden');
}

function closeAbsenceInfo() {
  document.getElementById('absence-info-overlay').classList.add('hidden');
  selectedAbsenceId = null;
}

function editSelectedAbsence() {
  const absence = getAbsenceById(selectedAbsenceId);
  if (!absence) return;
  closeAbsenceInfo();
  openModal(absence);
}

// ─── DATA ─────────────────────────────────────────────────────────────────────

async function loadAbsences() {
  const res = await apiFetch('/api/absences');
  allAbsences = await res.json();
  syncCalendarEvents();
  renderList();
}

async function refreshSolde() {
  try {
    const res = await apiFetch('/api/solde');
    const { conges, rq } = await res.json();

    document.getElementById('sb-conges').textContent =
      `${conges.disponible}j / ${conges.initial}j`;

    const debutFmt = conges.debut ? formatDate(conges.debut) : '—';
    const finFmt   = conges.fin   ? formatDate(conges.fin)   : '—';
    document.getElementById('sb-conges-periode').textContent =
      `${debutFmt} → ${finFmt}`;

    document.getElementById('sb-rq').textContent = `${rq.acquis}j`;
    document.getElementById('sb-rq-dispo').textContent = `${rq.disponible}j`;

    window._solde = { conges, rq };
  } catch (e) {
    console.error('Erreur refreshSolde', e);
  }
}

// ─── MODAL ────────────────────────────────────────────────────────────────────

function openModal(absence = null) {
  editingAbsenceId = absence?.id || null;
  document.getElementById('modal-title').textContent = editingAbsenceId ? 'Modifier une absence' : 'Poser une absence';

  if (absence) {
    document.getElementById('m-type').value = absence.type;
    document.getElementById('m-debut').value = absence.date_debut;
    document.getElementById('m-fin').value = absence.date_fin;
    document.getElementById('m-demi').value = absence.demi_journee;
    document.getElementById('m-note').value = absence.note || '';
  } else {
    document.getElementById('m-type').value = 'conge';
    document.getElementById('m-debut').value = pendingDatePrefill?.date_debut || '';
    document.getElementById('m-fin').value = pendingDatePrefill?.date_fin || '';
    document.getElementById('m-demi').value = 'journee';
    document.getElementById('m-note').value = '';
    pendingDatePrefill = null;
  }

  onTypeChange();
  updateModalSoldeInfo();
  void refreshSolde().then(() => updateModalSoldeInfo());
  document.getElementById('modal-overlay').classList.remove('hidden');
}

function closeModal() {
  document.getElementById('modal-overlay').classList.add('hidden');
  editingAbsenceId = null;
  pendingDatePrefill = null;
}

function closeModalOutside(e) {
  if (e.target.id === 'modal-overlay') closeModal();
}

function onTypeChange() {
  const type = document.getElementById('m-type').value;
  const demiSel = document.getElementById('m-demi');
  const demiLabel = document.getElementById('m-demi-label');
  if (type === 'rq') {
    demiSel.value = 'journee';
    demiSel.disabled = true;
    demiLabel.style.opacity = '0.45';
  } else {
    demiSel.disabled = false;
    demiLabel.style.opacity = '1';
  }
  updateModalSoldeInfo();
}

async function updateModalSoldeInfo() {
  const info = document.getElementById('modal-solde-info');
  if (!window._solde) return;
  const type = document.getElementById('m-type').value;
  const dateDebut = document.getElementById('m-debut').value;
  const dateFin = document.getElementById('m-fin').value;
  const demi = document.getElementById('m-demi').value;
  const { conges } = window._solde;

  let rq = window._solde.rq;
  if (type === 'rq' && dateDebut) {
    rq = await getRqSoldeAtDate(dateDebut);
  }

  const requested = calculateRequestedDays(type, dateDebut, dateFin, demi);

  let congesBase = Number(conges.disponible || 0);
  let rqBase = Number(rq.disponible || 0);

  if (editingAbsenceId) {
    const existing = getAbsenceById(editingAbsenceId);
    if (existing) {
      const previous = getAbsenceDuration(existing);
      if (existing.type === 'conge') congesBase += previous;
      if (existing.type === 'rq') rqBase += previous;
    }
  }

  if (type === 'conge') {
    const remaining = Math.max(0, Math.round((congesBase - requested) * 2) / 2);
    info.innerHTML =
      `💼 Congés disponibles : <strong style="color:var(--accent)">${congesBase}j</strong> sur ${conges.initial}j<br>
       <span style="font-size:.78rem">Cette pose : ${requested}j • Restera : <strong style="color:var(--success)">${remaining}j</strong></span><br>
       <span style="font-size:.78rem">Période : ${formatDate(conges.debut)} → ${formatDate(conges.fin)}</span>`;
  } else {
    const remaining = Math.max(0, Math.round((rqBase - requested) * 2) / 2);
    info.innerHTML =
      `⏱️ RQ disponibles : <strong style="color:var(--accent2)">${rqBase}j</strong> (acquis : ${rq.acquis}j, posés : ${rq.pose}j)<br>
       <span style="font-size:.78rem">Cette pose : ${requested}j • Restera : <strong style="color:var(--success)">${remaining}j</strong></span><br>
       <span style="font-size:.78rem">Depuis : ${formatDate(rq.date_debut_periode)}</span>`;
  }
  info.classList.add('visible');
}

async function getRqSoldeAtDate(targetDate) {
  if (!targetDate) return window._solde?.rq;
  if (rqSoldePreviewCache.has(targetDate)) return rqSoldePreviewCache.get(targetDate);

  try {
    const res = await apiFetch(`/api/solde?targetDate=${encodeURIComponent(targetDate)}`);
    if (!res.ok) throw new Error('preview-failed');
    const data = await res.json();
    const rq = data?.rq || window._solde?.rq;
    rqSoldePreviewCache.set(targetDate, rq);
    return rq;
  } catch {
    return window._solde?.rq;
  }
}

function calculateRequestedDays(type, dateDebut, dateFin, demi) {
  if (!dateDebut || !dateFin || dateFin < dateDebut) return 0;
  const jours = countJoursOuvresJS(dateDebut, dateFin);
  if (type === 'rq') return jours;
  return demi !== 'journee' ? 0.5 : jours;
}

function initModalLivePreview() {
  const ids = ['m-type', 'm-debut', 'm-fin', 'm-demi'];
  for (const id of ids) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.addEventListener('input', () => { void updateModalSoldeInfo(); });
    el.addEventListener('change', () => { void updateModalSoldeInfo(); });
  }
}

async function submitAbsence() {
  const body = {
    type: document.getElementById('m-type').value,
    date_debut: document.getElementById('m-debut').value,
    date_fin: document.getElementById('m-fin').value,
    demi_journee: document.getElementById('m-demi').value,
    note: document.getElementById('m-note').value,
  };

  if (!body.date_debut || !body.date_fin)
    return toast('Veuillez renseigner les dates', true);
  if (body.date_fin < body.date_debut)
    return toast('La date de fin doit être après le début', true);

  const path = editingAbsenceId ? `/api/absences/${editingAbsenceId}` : '/api/absences';
  const method = editingAbsenceId ? 'PUT' : 'POST';

  const res = await apiFetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (res.ok) {
    const wasEditing = Boolean(editingAbsenceId);
    await loadAbsences();
    await refreshSolde();
    closeModal();
    toast(wasEditing ? 'Absence modifiée ✓' : 'Absence posée ✓');
    document.getElementById('m-note').value = '';
  } else {
    const err = await res.json();
    toast(err.error || 'Erreur serveur', true);
  }
}

async function deleteAbsence(id) {
  await apiFetch(`/api/absences/${id}`, { method: 'DELETE' });
  allAbsences = allAbsences.filter(a => a.id !== id);
  syncCalendarEvents();
  await refreshSolde();
  renderList();
  if (selectedAbsenceId === id) closeAbsenceInfo();
  toast('Absence supprimée');
}

// ─── LIST ─────────────────────────────────────────────────────────────────────

function renderList() {
  const tbody = document.getElementById('list-body');
  tbody.innerHTML = '';

  if (!allAbsences.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:30px">
      Aucune absence enregistrée</td></tr>`;
    return;
  }

  for (const a of allAbsences) {
    const jours = countJoursOuvresJS(a.date_debut, a.date_fin);
    const decompte = a.type === 'rq' ? jours : (a.demi_journee !== 'journee' ? 0.5 : jours);
    const modeLabel = { matin: 'Matin', 'apres-midi': 'Après-midi', journee: 'Journée' }[a.demi_journee] || 'Journée';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="tag tag-${a.type}">${a.type === 'conge' ? 'Congé' : 'RQ'}</span></td>
      <td>${formatDate(a.date_debut)}</td>
      <td>${formatDate(a.date_fin)}</td>
      <td>${modeLabel}</td>
      <td>${a.note || '—'}</td>
      <td><strong>${decompte}j</strong></td>
      <td><button class="btn-del" onclick="deleteAbsence('${a.id}')">Supprimer</button></td>
    `;
    tbody.appendChild(tr);
  }
}

// ─── EXPORT EXCEL ─────────────────────────────────────────────────────────────

function exportExcel() {
  const data = allAbsences.map(a => {
    const jours = countJoursOuvresJS(a.date_debut, a.date_fin);
    const decompte = a.type === 'rq' ? jours : (a.demi_journee !== 'journee' ? 0.5 : jours);
    return {
      Type: a.type === 'conge' ? 'Congé payé' : 'RQ',
      'Date début': a.date_debut,
      'Date fin': a.date_fin,
      Mode: a.demi_journee === 'matin' ? 'Matin'
          : a.demi_journee === 'apres-midi' ? 'Après-midi'
          : 'Journée complète',
      Note: a.note || '',
      'Jours décomptés': decompte,
    };
  });

  const ws = XLSX.utils.json_to_sheet(data);
  ws['!cols'] = [{ wch: 14 }, { wch: 13 }, { wch: 13 }, { wch: 18 }, { wch: 24 }, { wch: 18 }];
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Absences');

  if (window._solde) {
    const { conges, rq } = window._solde;
    const recap = [
      { Catégorie: '── CONGÉS PAYÉS ──', Valeur: '' },
      { Catégorie: `Période`, Valeur: `${conges.debut} → ${conges.fin}` },
      { Catégorie: 'Solde initial', Valeur: `${conges.initial}j` },
      { Catégorie: 'Congés posés', Valeur: `${conges.pose}j` },
      { Catégorie: 'Congés restants', Valeur: `${conges.disponible}j` },
      { Catégorie: '' },
      { Catégorie: '── RQ (indépendant) ──', Valeur: '' },
      { Catégorie: 'Depuis', Valeur: rq.date_debut_periode },
      { Catégorie: 'Mode acquisition', Valeur: rq.mode },
      { Catégorie: 'RQ acquis', Valeur: `${rq.acquis}j` },
      { Catégorie: 'RQ posés', Valeur: `${rq.pose}j` },
      { Catégorie: 'RQ disponibles', Valeur: `${rq.disponible}j` },
    ];
    const wsR = XLSX.utils.json_to_sheet(recap);
    wsR['!cols'] = [{ wch: 25 }, { wch: 22 }];
    XLSX.utils.book_append_sheet(wb, wsR, 'Récapitulatif');
  }

  XLSX.writeFile(wb, `conges_${new Date().toISOString().split('T')[0]}.xlsx`);
  toast('Export Excel généré ✓');
}

// ─── SUGGESTIONS IA ───────────────────────────────────────────────────────────

function addPeriode() {
  const container = document.getElementById('periodes-container');
  const div = document.createElement('div');
  div.className = 'periode-row';
  div.innerHTML = `
    <input type="date" class="p-debut" />
    <input type="date" class="p-fin" />
    <button onclick="removePeriode(this)">✕</button>
  `;
  container.appendChild(div);
}

function removePeriode(btn) {
  const container = document.getElementById('periodes-container');
  if (container.children.length > 1) btn.parentElement.remove();
}

async function getSuggestions() {
  const rows = document.querySelectorAll('.periode-row');
  const periodes = [];
  rows.forEach(r => {
    const d = r.querySelector('.p-debut').value;
    const f = r.querySelector('.p-fin').value;
    if (d && f) periodes.push({ debut: d, fin: f });
  });

  const res = await apiFetch('/api/suggestions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ periodes_souhaitees: periodes }),
  });

  const { suggestions } = await res.json();
  const container = document.getElementById('suggestions-result');
  container.innerHTML = '';

  if (!suggestions.length) {
    container.innerHTML = '<p style="color:var(--text-muted);margin-top:16px">Aucune suggestion pour ces périodes.</p>';
    return;
  }

  const icons  = { pont: '🌉', vacances: '🏖️', semaine_riche: '⭐' };
  const labels = { pont: 'Pont optimal', vacances: 'Bloc vacances optimal', semaine_riche: 'Semaine chargée en fériés' };

  for (const s of suggestions) {
    const card = document.createElement('div');
    card.className = `suggestion-card ${s.type}`;
    card.innerHTML = `
      <div>
        <h4>${icons[s.type] || '📌'} ${labels[s.type] || s.type}</h4>
        <p>${s.description}</p>
      </div>
      <span class="suggestion-badge">${s.jours_poses}j posés → ${s.jours_gagnes}j repos</span>
    `;
    container.appendChild(card);
  }
}

// ─── PREFERENCES ─────────────────────────────────────────────────────────────

async function loadPrefs() {
  const res = await apiFetch('/api/preferences');
  prefs = await res.json();

  document.getElementById('set-conges').value        = prefs.solde_conges ?? 25;
  document.getElementById('set-conges-debut').value  = prefs.conges_date_debut_periode ?? '';
  document.getElementById('set-conges-fin').value    = prefs.conges_date_fin_periode ?? '';
  document.getElementById('set-rq-mode').value       = prefs.rq_mode ?? 'forfaitaire';
  document.getElementById('set-rq-debut').value      = prefs.rq_date_debut_periode ?? '';
  document.getElementById('set-rq-forfait').value    = prefs.rq_forfait_annuel ?? 12;
  document.getElementById('set-rq-cycle').value      = prefs.rq_cycle_jours_travailles ?? 20;
  document.getElementById('set-rq-par-acq').value    = prefs.rq_jours_par_acquisition ?? 1;
  setCoursCheckboxesFromPrefs(prefs.cours_jours || '');
  bindCoursCheckboxesAutoSave();
  setCoursDatesFromPrefs(prefs.cours_dates || '');
  applyDayCellHighlights();
  onRqModeChange();
  await loadTwoFactorStatus();
}

function onRqModeChange() {
  const mode = document.getElementById('set-rq-mode').value;
  document.getElementById('rq-forfaitaire-block').style.display = mode === 'forfaitaire' ? 'block' : 'none';
  document.getElementById('rq-reel-block').style.display        = mode === 'reel'        ? 'block' : 'none';
}

async function savePrefs() {
  const body = {
    solde_conges:               parseFloat(document.getElementById('set-conges').value),
    conges_date_debut_periode:  document.getElementById('set-conges-debut').value,
    conges_date_fin_periode:    document.getElementById('set-conges-fin').value,
    rq_mode:                    document.getElementById('set-rq-mode').value,
    rq_date_debut_periode:      document.getElementById('set-rq-debut').value,
    rq_forfait_annuel:          parseFloat(document.getElementById('set-rq-forfait').value),
    rq_cycle_jours_travailles:  parseInt(document.getElementById('set-rq-cycle').value),
    rq_jours_par_acquisition:   parseFloat(document.getElementById('set-rq-par-acq').value),
    cours_jours:                readCoursCheckboxesToCsv(),
    cours_dates:                readCoursDatesToCsv(),
  };

  const res = await apiFetch('/api/preferences', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (res.ok) {
    prefs = { ...prefs, ...body };
    coursWeekdays = parseCoursJours(body.cours_jours);
    coursDates = parseCoursDates(body.cours_dates);
    renderCoursDatesList();
    syncCoursCalendarEvents();
    applyDayCellHighlights();
    await refreshSolde();
    toast('Préférences enregistrées ✓');
  } else {
    toast('Erreur lors de la sauvegarde', true);
  }
}

async function loadTwoFactorStatus() {
  const statusEl = document.getElementById('twofactor-status');
  if (!statusEl) return;

  try {
    const res = await apiFetch('/api/auth/2fa/status');
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'status');

    const remaining = Number(data.backupCodesRemaining || 0);
    statusEl.textContent = data.enabled
      ? `2FA activé • ${remaining} code(s) de secours restant(s)`
      : '2FA désactivé';
    statusEl.classList.toggle('enabled', Boolean(data.enabled));
    statusEl.classList.toggle('disabled', !data.enabled);
  } catch {
    statusEl.textContent = 'Impossible de charger le statut';
    statusEl.classList.remove('enabled', 'disabled');
  }
}

async function startTwoFactorSetup() {
  setAuthMessage('twofactor-setup-error', '');
  setAuthMessage('twofactor-setup-success', '');

  try {
    const res = await apiFetch('/api/auth/2fa/setup/start', { method: 'POST' });
    const data = await res.json();
    if (!res.ok || !data.qrDataUrl) {
      setAuthMessage('twofactor-setup-error', data.error || 'Impossible de générer le QR code.');
      return;
    }

    const panel = document.getElementById('twofactor-setup-panel');
    const qr = document.getElementById('twofactor-qr');
    if (panel) panel.classList.remove('hidden');
    if (qr) qr.src = data.qrDataUrl;
    setAuthMessage('twofactor-setup-success', 'Scannez le QR code puis confirmez le code à 6 chiffres.');
  } catch {
    setAuthMessage('twofactor-setup-error', 'Erreur réseau. Réessayez.');
  }
}

async function confirmTwoFactorSetup() {
  const password = document.getElementById('twofactor-password').value;
  const code = document.getElementById('twofactor-confirm-code').value.trim();
  setAuthMessage('twofactor-setup-error', '');
  setAuthMessage('twofactor-setup-success', '');

  if (!password || !code) {
    setAuthMessage('twofactor-setup-error', 'Le mot de passe et le code sont requis.');
    return;
  }

  try {
    const res = await apiFetch('/api/auth/2fa/setup/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, code }),
    });
    const data = await res.json();
    if (!res.ok) {
      setAuthMessage('twofactor-setup-error', data.error || 'Activation impossible.');
      return;
    }

    document.getElementById('twofactor-password').value = '';
    document.getElementById('twofactor-confirm-code').value = '';
    setAuthMessage('twofactor-setup-success', '2FA activé avec succès.');
    await loadTwoFactorStatus();
  } catch {
    setAuthMessage('twofactor-setup-error', 'Erreur réseau. Réessayez.');
  }
}

async function disableTwoFactor() {
  const password = window.prompt('Entrez votre mot de passe actuel pour désactiver le 2FA');
  if (!password) return;

  setAuthMessage('twofactor-disable-error', '');
  setAuthMessage('twofactor-disable-success', '');

  try {
    const res = await apiFetch('/api/auth/2fa/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    const data = await res.json();
    if (!res.ok) {
      setAuthMessage('twofactor-disable-error', data.error || 'Désactivation impossible.');
      return;
    }

    setAuthMessage('twofactor-disable-success', '2FA désactivé.');
    await loadTwoFactorStatus();
  } catch {
    setAuthMessage('twofactor-disable-error', 'Erreur réseau. Réessayez.');
  }
}

function toggleBackupCodesPanel() {
  const panel = document.getElementById('twofactor-backup-panel');
  if (!panel) return;
  panel.classList.toggle('hidden');
  setAuthMessage('backup-codes-error', '');
  setAuthMessage('backup-codes-success', '');
}

function hideBackupCodesPanel() {
  const panel = document.getElementById('twofactor-backup-panel');
  if (panel) panel.classList.add('hidden');
}

async function generateBackupCodes() {
  const password = document.getElementById('backup-codes-password').value;
  setAuthMessage('backup-codes-error', '');
  setAuthMessage('backup-codes-success', '');

  if (!password) {
    setAuthMessage('backup-codes-error', 'Entrez votre mot de passe actuel.');
    return;
  }

  try {
    const res = await apiFetch('/api/auth/2fa/backup-codes/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    const data = await res.json();
    if (!res.ok || !Array.isArray(data.codes)) {
      setAuthMessage('backup-codes-error', data.error || 'Impossible de générer les codes.');
      return;
    }

    const list = document.getElementById('backup-codes-list');
    const status = document.getElementById('backup-codes-status');
    if (list) {
      list.innerHTML = data.codes.map(code => `<div class="backup-code-item">${code}</div>`).join('');
    }
    if (status) {
      status.textContent = `${data.remaining} code(s) disponible(s)`;
    }
    document.getElementById('backup-codes-password').value = '';
    setAuthMessage('backup-codes-success', 'Codes générés. Copiez-les maintenant, ils ne seront plus réaffichés.');
    await loadTwoFactorStatus();
  } catch {
    setAuthMessage('backup-codes-error', 'Erreur réseau. Réessayez.');
  }
}

async function changePassword() {
  const currentPassword = document.getElementById('current-password').value;
  const newPassword = document.getElementById('new-password').value;
  const confirm = document.getElementById('new-password-confirm').value;
  setAuthMessage('change-password-error', '');
  setAuthMessage('change-password-success', '');

  if (!currentPassword || !newPassword) {
    setAuthMessage('change-password-error', 'Tous les champs sont requis.');
    return;
  }
  if (newPassword !== confirm) {
    setAuthMessage('change-password-error', 'Les mots de passe ne correspondent pas.');
    return;
  }

  try {
    const res = await apiFetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword, newPassword }),
    });
    const data = await res.json();
    if (!res.ok) {
      setAuthMessage('change-password-error', data.error || 'Modification impossible.');
      return;
    }

    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('new-password-confirm').value = '';
    setAuthMessage('change-password-success', 'Mot de passe mis à jour.');
  } catch {
    setAuthMessage('change-password-error', 'Erreur réseau. Réessayez.');
  }
}

async function changeUsername() {
  const newUsername = document.getElementById('new-username').value.trim();
  const currentPassword = document.getElementById('change-username-password').value;
  setAuthMessage('change-username-error', '');
  setAuthMessage('change-username-success', '');

  if (!newUsername || !currentPassword) {
    setAuthMessage('change-username-error', 'Tous les champs sont requis.');
    return;
  }

  try {
    const res = await apiFetch('/api/auth/change-username', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword, newUsername }),
    });
    const data = await res.json();
    if (!res.ok) {
      setAuthMessage('change-username-error', data.error || 'Modification impossible.');
      return;
    }

    currentUsername = data.username || newUsername;
    syncCurrentUsernameUI();
    document.getElementById('new-username').value = '';
    document.getElementById('change-username-password').value = '';
    setAuthMessage('change-username-success', `Identifiant mis à jour : ${currentUsername}`);
    await loadTwoFactorStatus();
  } catch {
    setAuthMessage('change-username-error', 'Erreur réseau. Réessayez.');
  }
}

// ─── SIMULATION RQ ────────────────────────────────────────────────────────────

async function loadSimulation() {
  const container = document.getElementById('simulation-chart-container');
  container.innerHTML = '';

  try {
    const res = await apiFetch('/api/rq/simulation');
    let payload = null;
    try {
      payload = await res.json();
    } catch {
      throw new Error('Réponse serveur invalide pour la simulation RQ.');
    }

    if (!res.ok) {
      throw new Error(payload?.error || 'La simulation RQ a échoué.');
    }

    const mode = payload?.mode || 'forfaitaire';
    const points = Array.isArray(payload?.points) ? payload.points : [];

    if (!points.length) {
      container.innerHTML = '<p class="muted-text">Configurez une date de début RQ dans les paramètres.</p>';
      return;
    }

    const normalized = points
      .map(p => ({
        date: p.date,
        acquis: Number(p.acquis),
        pose: Number(p.pose),
        disponible: Number(p.disponible),
      }))
      .filter(p => p.date && Number.isFinite(p.acquis) && Number.isFinite(p.pose) && Number.isFinite(p.disponible));

    if (!normalized.length) {
      throw new Error('Données de simulation invalides.');
    }

    const maxVal = Math.max(...normalized.map(p => p.acquis), 1);
    const W = 560, H = 200, PL = 44, PR = 16, PT = 24, PB = 28;
    const chartW = W - PL - PR;
    const chartH = H - PT - PB;
    const xStep  = chartW / Math.max(normalized.length - 1, 1);
    const toX = i => PL + i * xStep;
    const toY = v => PT + chartH - (v / maxVal) * chartH;

    const mkPath = key =>
      normalized.map((p, i) => `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(p[key]).toFixed(1)}`).join(' ');

    const mkDots = (key, color) =>
      normalized.map((p, i) =>
        `<circle cx="${toX(i).toFixed(1)}" cy="${toY(p[key]).toFixed(1)}" r="3" fill="${color}"/>`
      ).join('');

    const monthLabels = normalized.map((p, i) => {
      if (i % 2 !== 0 && i !== normalized.length - 1) return '';
      const label = new Date(p.date).toLocaleDateString('fr-FR', { month: 'short' });
      return `<text x="${toX(i).toFixed(1)}" y="${H - 4}" text-anchor="middle" font-size="9" fill="#94a3b8">${label}</text>`;
    }).join('');

    const yLines = [0, 0.25, 0.5, 0.75, 1].map(ratio => {
      const v = (maxVal * ratio).toFixed(1);
      const y = toY(maxVal * ratio).toFixed(1);
      return `
      <line x1="${PL}" y1="${y}" x2="${W - PR}" y2="${y}" stroke="#2d3148" stroke-width="1"/>
      <text x="${PL - 4}" y="${parseFloat(y) + 4}" text-anchor="end" font-size="9" fill="#94a3b8">${v}</text>`;
    }).join('');

    container.innerHTML = `
    <svg width="100%" viewBox="0 0 ${W} ${H}" style="background:var(--surface2);border-radius:10px;display:block">
      ${yLines}${monthLabels}
      <path d="${mkPath('acquis')}"    fill="none" stroke="#6c63ff" stroke-width="2.5"/>
      ${mkDots('acquis', '#6c63ff')}
      <path d="${mkPath('pose')}"      fill="none" stroke="#ef4444" stroke-width="2" stroke-dasharray="5,3"/>
      ${mkDots('pose', '#ef4444')}
      <path d="${mkPath('disponible')}" fill="none" stroke="#22c55e" stroke-width="2"/>
      ${mkDots('disponible', '#22c55e')}
      <circle cx="52"  cy="13" r="4" fill="#6c63ff"/>
      <text   x="60"   y="17" font-size="10" fill="#e2e8f0">Acquis</text>
      <circle cx="112" cy="13" r="4" fill="#ef4444"/>
      <text   x="120"  y="17" font-size="10" fill="#e2e8f0">Posés</text>
      <circle cx="168" cy="13" r="4" fill="#22c55e"/>
      <text   x="176"  y="17" font-size="10" fill="#e2e8f0">Disponibles</text>
      <text x="${W - PR}" y="13" text-anchor="end" font-size="9" fill="#94a3b8">Mode : ${mode}</text>
    </svg>
    <div style="overflow-x:auto;margin-top:14px">
      <table style="width:100%;font-size:.82rem;border-collapse:collapse">
        <thead>
          <tr>
            <th style="padding:7px 12px;text-align:left;color:var(--text-muted);background:var(--surface2)">Mois</th>
            <th style="padding:7px 12px;text-align:right;color:#6c63ff;background:var(--surface2)">Acquis</th>
            <th style="padding:7px 12px;text-align:right;color:#ef4444;background:var(--surface2)">Posés</th>
            <th style="padding:7px 12px;text-align:right;color:#22c55e;background:var(--surface2)">Disponibles</th>
          </tr>
        </thead>
        <tbody>
          ${normalized.map((p, i) => `
            <tr style="border-bottom:1px solid var(--border);${i % 2 ? 'background:var(--surface2)' : ''}">
              <td style="padding:6px 12px">${new Date(p.date).toLocaleDateString('fr-FR', { month: 'long', year: 'numeric' })}</td>
              <td style="padding:6px 12px;text-align:right;color:#6c63ff">${p.acquis}j</td>
              <td style="padding:6px 12px;text-align:right;color:#ef4444">${p.pose}j</td>
              <td style="padding:6px 12px;text-align:right;color:#22c55e">${p.disponible}j</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>
  `;
  } catch (e) {
    container.innerHTML = `<p class="muted-text">Simulation indisponible pour le moment.</p>`;
    toast(e.message || 'Erreur simulation RQ', true);
    console.error('Erreur loadSimulation', e);
  }
}

// ─── UTILS ────────────────────────────────────────────────────────────────────

function countJoursOuvresJS(debut, fin) {
  let count = 0;
  let cur = new Date(debut);
  const end = new Date(fin);
  while (cur <= end) {
    const dow = cur.getDay();
    const ds  = cur.toISOString().split('T')[0];
    if (dow !== 0 && dow !== 6 && !FERIES_JS.includes(ds)) count++;
    cur.setDate(cur.getDate() + 1);
  }
  return count;
}

function addDays(dateStr, days) {
  const date = new Date(`${dateStr}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().split('T')[0];
}

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' });
}

function toast(msg, isError = false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = isError ? 'show error' : 'show';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = ''; }, 3200);
}
