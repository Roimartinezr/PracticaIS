

// Persistencia de tema
    const root = document.documentElement;
    const savedTheme = localStorage.getItem('phishguard-theme');
    if (savedTheme) root.setAttribute('data-theme', savedTheme);

    document.getElementById('toggleTheme').addEventListener('click', () => {
      const now = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', now);
      localStorage.setItem('phishguard-theme', now);
    });

    // Sidebar en móvil
    const sidebar = document.getElementById('appSidebar');
    document.getElementById('openSidebar').addEventListener('click', () => sidebar.classList.add('open'));
    document.getElementById('closeSidebar').addEventListener('click', () => sidebar.classList.remove('open'));

    // Utilidades UI
    const showLoading = (on = true) => document.getElementById('loading').style.display = on ? 'grid' : 'none';
    function toast(msg, type = 'info') {
      const t = document.getElementById('toast');
      const el = document.createElement('div');
      el.className = 'item';
      el.textContent = msg;
      if (type === 'error') el.style.borderColor = 'rgba(231, 76, 60, .45)';
      if (type === 'success') el.style.borderColor = 'rgba(46, 204, 113, .45)';
      t.appendChild(el);
      setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateY(6px)'; }, 2600);
      setTimeout(() => el.remove(), 3000);
    }

    // Colorear fondo según porcentaje
    function getGradientColor(percentage) {
      let r, g;
      if (percentage <= 50) { r = Math.round((percentage / 50) * 255); g = 255; }
      else { r = 255; g = Math.round(255 - ((percentage - 50) / 50) * 255); }
      return `rgb(${r}, ${g}, 0)`;
    }

  // Relleno demo rápido
  const API = window.location.origin;
    document.getElementById('prefillDemo').addEventListener('click', () => {
      document.getElementById('textInput').value = "[ALERTA] Su cuenta bancaria será bloqueada. Verifique sus datos en https://seguro-banco-validacion.com de inmediato.";
      document.getElementById('urlInput').value = "http://sospechoso.com/login";
      toast('Ejemplo cargado', 'success');
    });
    document.getElementById('resetForm').addEventListener('click', () => {
      document.getElementById('textInput').value = '';
      document.getElementById('urlInput').value = '';
      document.getElementById('result').innerHTML = '';
      document.getElementById('riskBarContainer').style.display = 'none';
      toast('Campos limpios');
    });

    // Auth UI
    const loginModal = document.getElementById('loginModal');
    const authUsername = document.getElementById('authUsername');
    const authPassword = document.getElementById('authPassword');
    const authClose = document.getElementById('authClose');
    const authLogin = document.getElementById('authLogin');
    const authSignup = document.getElementById('authSignup');
    const btnLoginOpen = document.getElementById('btnLoginOpen');
    const loggedUser = document.getElementById('loggedUser');
    const btnResetStats = document.getElementById('btnResetStats');

    function setLoggedUser(name) {
      if (name) {
        loggedUser.textContent = name;
        btnLoginOpen.textContent = 'Logout';
      } else {
        loggedUser.textContent = '';
        btnLoginOpen.textContent = 'Login';
      }
    }

    btnLoginOpen.addEventListener('click', async () => {
      const token = localStorage.getItem('phishguard_token');
      if (token) {
        // logout
        try {
          await fetch(`${API}/logout`, { method: 'POST', headers: { 'Authorization': `Bearer ${token}` } });
        } catch (e) { /* ignore */ }
        localStorage.removeItem('phishguard_token');
        setLoggedUser(null);
        toast('Sesión cerrada', 'success');
        return;
      }
      loginModal.style.display = 'grid';
    });

    authClose.addEventListener('click', () => { loginModal.style.display = 'none'; });

    authSignup.addEventListener('click', async () => {
      const u = authUsername.value.trim(); const p = authPassword.value;
      if (!u || !p) { toast('Usuario y contraseña requeridos','error'); return; }
      try {
        const r = await fetch(`${API}/signup`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username: u, password: p }) });
        if (!r.ok) throw new Error(await r.text());
        toast('Usuario creado. Haz login.', 'success');
      } catch (e) { toast('Error al crear usuario','error'); }
    });

    authLogin.addEventListener('click', async () => {
      const u = authUsername.value.trim(); const p = authPassword.value;
      if (!u || !p) { toast('Usuario y contraseña requeridos','error'); return; }
      try {
        const r = await fetch(`${API}/login`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username: u, password: p }) });
        if (!r.ok) throw new Error(await r.text());
  const data = await r.json();
  localStorage.setItem('phishguard_token', data.token);
  localStorage.setItem('phishguard_user', data.username);
  setLoggedUser(data.username);
        loginModal.style.display = 'none';
        toast('Login correcto', 'success');
      } catch (e) { toast('Error al iniciar sesión','error'); }
    });

    btnResetStats.addEventListener('click', async () => {
      const token = localStorage.getItem('phishguard_token');
      if (!token) { toast('Debes iniciar sesión para resetear', 'error'); return; }
      try {
        const r = await fetch(`${API}/reset_stats`, { method: 'POST', headers: { 'Authorization': `Bearer ${token}` } });
        if (!r.ok) throw new Error(await r.text());
        toast('Estadísticas reseteadas', 'success');
        await updateHistory({});
        await updateStats();
      } catch (e) { toast('Error al resetear estadísticas', 'error'); }
    });

    // On load, restore username if token present
    (function restoreAuth(){
      const token = localStorage.getItem('phishguard_token');
      if (!token) return;
      // attempt to fetch stats to validate token (not strictly necessary)
      // no introspection endpoint, so just show username from login stored localStorage? We saved username earlier, but if not, show 'usuario'.
      const storedUser = localStorage.getItem('phishguard_user');
      setLoggedUser(storedUser || 'usuario');
    })();

    // Limpiar historial (si tu API lo soporta: DELETE /history)
    document.getElementById('clearHistory').addEventListener('click', async () => {
      try {
        await fetch(`${API}/history`, { method: 'DELETE' });
      } catch (e) { /* si no existe, solo vaciamos UI */ }
      renderHistory([]);
      toast('Historial limpiado', 'success');
    });

    async function analyzeText() {
      const text = document.getElementById('textInput').value.trim();
      const resultDiv = document.getElementById('result');
      const riskBar = document.getElementById('riskBarContainer');
      const riskArrow = document.getElementById('riskArrow');
      const riskPercentage = document.getElementById('riskPercentage');

      if (!text) {
        resultDiv.innerHTML = 'Por favor, ingresa un texto para analizar.';
        resultDiv.style.backgroundColor = '';
        riskBar.style.display = 'none';
        return;
      }

      showLoading(true);
      resultDiv.innerHTML = '';
      resultDiv.style.backgroundColor = '';
      riskBar.style.display = 'none';

      try {
        const headers = { 'Content-Type': 'application/json' };
        const token = localStorage.getItem('phishguard_token');
        if (!token) { throw new Error('Debes iniciar sesión para analizar'); }
        headers['Authorization'] = `Bearer ${token}`;
        const response = await fetch(`${API}/analyze`, { method: 'POST', headers, body: JSON.stringify({ text }) });
        if (!response.ok) throw new Error('Error en la conexión con la API');

        const data = await response.json();
        let html = `<p style="margin:0 0 6px; font-weight:700;">${data.combined_verdict} <span style="opacity:.8; font-weight:600;">(${data.percentage}% riesgo)</span></p>`;
        if (data.url_results && data.url_results.length > 0) {
          html += `<div style="margin-top:10px"><h3 style="margin:0 0 6px; font-size:14px;">Análisis de URLs detectadas</h3><ul style="margin:0; padding-left:18px">`;
          data.url_results.forEach(u => { html += `<li><strong>${u.url}</strong>: ${u.verdict} <span style="color:var(--muted)">(${u.reason})</span></li>`; });
          html += `</ul></div>`;
        }
        resultDiv.innerHTML = html;
        resultDiv.style.backgroundColor = getGradientColor(data.percentage);
        resultDiv.style.color = '#000';

        // Barra de riesgo
        const percentage = Number(data.percentage) || 0;
        riskBar.style.display = 'block';
        const barWidth = document.getElementById('riskBar').offsetWidth;
        const arrowPosition = (percentage / 100) * barWidth - 8; // centrado
        riskArrow.style.left = `${Math.max(0, Math.min(arrowPosition, barWidth-8))}px`;
        riskPercentage.innerText = `${percentage}% de riesgo`;
        riskArrow.style.borderTopColor = percentage > 66 ? 'var(--danger)' : percentage > 33 ? 'var(--warning)' : 'var(--success)';

        await updateHistory({ type: 'texto', input: text, verdict: data.combined_verdict, percentage: data.percentage });
        await updateStats();
        toast('Análisis de texto completado', 'success');
      } catch (error) {
        resultDiv.innerHTML = 'Error al analizar: ' + error.message;
        resultDiv.style.backgroundColor = 'rgba(231, 76, 60, .15)';
        toast('Error al analizar texto', 'error');
      } finally {
        showLoading(false);
      }
    }

    async function analyzeUrl() {
      const url = document.getElementById('urlInput').value.trim();
      const resultDiv = document.getElementById('result');
      const riskBar = document.getElementById('riskBarContainer');

      if (!url) {
        resultDiv.innerHTML = 'Por favor, ingresa una URL para analizar.';
        resultDiv.style.backgroundColor = '';
        riskBar.style.display = 'none';
        return;
      }

      showLoading(true);
      resultDiv.innerHTML = '';
      resultDiv.style.backgroundColor = '';
      riskBar.style.display = 'none';

      try {
        const headers = { 'Content-Type': 'application/json' };
        const token = localStorage.getItem('phishguard_token');
        if (!token) { throw new Error('Debes iniciar sesión para analizar'); }
        headers['Authorization'] = `Bearer ${token}`;
        const response = await fetch(`${API}/analyze_url`, { method: 'POST', headers, body: JSON.stringify({ url }) });
        if (!response.ok) throw new Error('Error en la conexión con la API');

        const data = await response.json();
        resultDiv.innerHTML = `<p style="margin:0; font-weight:700;">URL: ${data.verdict} <span style="color:var(--muted); font-weight:600;">(${data.reason})</span></p>`;
        resultDiv.style.backgroundColor = data.verdict === 'Maliciosa' ? 'rgba(231, 76, 60, .15)' : 'rgba(46, 204, 113, .15)';
        resultDiv.style.color = 'inherit';

        await updateHistory({ type: 'url', input: url, verdict: data.verdict });
        await updateStats();
        toast('Análisis de URL completado', 'success');
      } catch (error) {
        resultDiv.innerHTML = 'Error al analizar: ' + error.message;
        resultDiv.style.backgroundColor = 'rgba(231, 76, 60, .15)';
        toast('Error al analizar URL', 'error');
      } finally {
        showLoading(false);
      }
    }

    async function updateHistory(entry) {
      try {
        // Solo guarda si viene con input
        if (entry && entry.input) {
          const headers = { 'Content-Type': 'application/json' };
          const token = localStorage.getItem('phishguard_token');
          if (token) headers['Authorization'] = `Bearer ${token}`;
          await fetch(`${API}/history`, { method: 'POST', headers, body: JSON.stringify(entry) });
        }
      } catch (e) {
        console.warn('No se pudo guardar en historial:', e);
      }
      try {
  const headers = {};
  const token = localStorage.getItem('phishguard_token');
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${API}/history`, { headers });
        if (!res.ok) throw new Error('Error al obtener historial');
        const history = await res.json();
        renderHistory(history);
      } catch (error) {
        console.error('Error al actualizar historial:', error);
      }
    }

    function renderHistory(history = []) {
      const list = document.getElementById('historyList');
      if (!Array.isArray(history)) { list.innerHTML = ''; return; }
      list.innerHTML = history.slice().reverse().map(h => {
        const type = h.type === 'texto' ? 'Texto' : 'URL';
        const badge = `<span class="badge">${type}</span>`;
        const pct = h.percentage ? ` <span class="meta">(${h.percentage}%)</span>` : '';
        const ts = `<div class="meta">${h.timestamp || ''}</div>`;
        return `<li class="history-item">${badge}<div><div><strong>${h.verdict || '—'}</strong>${pct}</div><div class="meta">${(h.input || '').toString().replace(/</g,'&lt;').slice(0, 90)}${(h.input||'').length>90?'…':''}</div>${ts}</li>`;
      }).join('');
    }

    async function updateStats() {
      try {
  const headers = {};
  const token = localStorage.getItem('phishguard_token');
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${API}/stats`, { headers });
        if (!res.ok) throw new Error('Error al obtener estadísticas');
        const s = await res.json();
        // KPIs
        document.getElementById('kpi-total').textContent = s.total ?? 0;
        document.getElementById('kpi-avg').textContent = `${s.avg_risk ?? 0}%`;
        document.getElementById('kpi-safe').textContent = `${s.safe ?? 0}%`;
        document.getElementById('kpi-suspicious').textContent = `${s.suspicious ?? 0}%`;
        document.getElementById('kpi-phishing').textContent = `${s.phishing ?? 0}%`;
        // Gauges
        document.getElementById('g-safe').style.width = `${s.safe ?? 0}%`;
        document.getElementById('g-suspicious').style.width = `${s.suspicious ?? 0}%`;
        document.getElementById('g-phishing').style.width = `${s.phishing ?? 0}%`;
      } catch (error) {
        console.error('Error al actualizar estadísticas:', error);
      }
    }

    // Carga inicial
    window.addEventListener('DOMContentLoaded', async () => {
      await updateHistory({});
      await updateStats();
    });
