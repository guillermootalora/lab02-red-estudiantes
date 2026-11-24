/* Laboratorio 01 - Memoria RAM | Ing. Guillermo Otálora Luna | Digital Forensics 203028123 UNAD */
{
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- índice: resaltar la sección visible ---------- */
  const links = $$('.nav a');
  const secs = links.map(a => $(a.getAttribute('href'))).filter(Boolean);
  const navObs = new IntersectionObserver(es => {
    es.forEach(e => {
      if (e.isIntersecting) {
        links.forEach(a => a.classList.toggle('on', a.getAttribute('href') === '#' + e.target.id));
      }
    });
  }, { rootMargin: '-40% 0px -55% 0px' });
  secs.forEach(s => navObs.observe(s));

  /* ---------- visor de imágenes ---------- */
  const lb = $('#lb'), lbImg = $('#lb img'), lbTxt = $('#lb p');
  $$('figure img').forEach(img => img.addEventListener('click', () => {
    lbImg.src = img.src;
    lbImg.alt = img.alt;
    const cap = img.closest('figure').querySelector('figcaption');
    lbTxt.textContent = cap ? cap.textContent : '';
    lb.classList.add('on');
  }));
  const closeLb = () => lb.classList.remove('on');
  lb.addEventListener('click', closeLb);
  addEventListener('keydown', e => { if (e.key === 'Escape') closeLb(); });

  /* ---------- botones Copiar ---------- */
  $$('.code').forEach(box => {
    const pre = $('pre', box);
    const b = document.createElement('button');
    b.className = 'cp'; b.type = 'button'; b.textContent = 'Copiar';
    b.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(pre.innerText); b.textContent = 'Copiado ✓'; }
      catch (e) { b.textContent = 'Seleccione y copie'; }
      setTimeout(() => (b.textContent = 'Copiar'), 1800);
    });
    box.appendChild(b);
  });

  /* ---------- SHA-256 en el navegador ---------- */
  const hex = buf => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
  const sha = async data => {
    if (!(window.crypto && crypto.subtle)) return null;
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    return hex(await crypto.subtle.digest('SHA-256', bytes));
  };
  const diffMark = (a, b) => [...b].map((ch, i) => (a && a[i] !== ch ? '<i>' + ch + '</i>' : ch)).join('');

  const tA = $('#hA'), tB = $('#hB'), oA = $('#oA'), oB = $('#oB'), cnt = $('#hcount');
  const runHash = async () => {
    if (!tA) return;
    const [a, b] = await Promise.all([sha(tA.value), sha(tB.value)]);
    if (!a) { oA.textContent = 'Este navegador no permite calcular SHA-256 aquí.'; return; }
    oA.textContent = a;
    oB.innerHTML = diffMark(a, b);
    let d = 0; for (let i = 0; i < 64; i++) if (a[i] !== b[i]) d++;
    cnt.textContent = a === b ? 'Huellas idénticas: los dos textos son exactamente iguales.' : d + ' de 64 caracteres hexadecimales cambiaron.';
  };
  if (tA) { tA.addEventListener('input', runHash); tB.addEventListener('input', runHash); runHash(); }

  const fIn = $('#hfile'), fOut = $('#hfileout');
  if (fIn) fIn.addEventListener('change', async () => {
    const f = fIn.files[0]; if (!f) return;
    if (f.size > 400 * 1024 * 1024) { fOut.textContent = 'Archivo muy grande para el navegador: use Get-FileHash o certutil.'; return; }
    fOut.textContent = 'Calculando…';
    const h = await sha(await f.arrayBuffer());
    fOut.textContent = h ? f.name + '  (' + f.size.toLocaleString('es-CO') + ' bytes)\nSHA-256: ' + h.toUpperCase() : 'No disponible.';
  });

  /* ---------- RAM vs disco: la RAM cambia, el disco no ---------- */
  const ramG = $('#ramgrid'), diskG = $('#diskgrid'), ramH = $('#ramhash'), diskH = $('#diskhash');
  if (ramG) {
    const N = 128;
    const cells = g => { g.innerHTML = Array.from({ length: N }, () => '<i></i>').join(''); return $$('i', g); };
    const rc = cells(ramG), dc = cells(diskG);
    let seed = 7;
    const rnd = () => (seed = seed * 16807 % 2147483647) / 2147483647;
    const state = rc.map(() => rnd() > .5 ? 1 : 0);
    const dstate = dc.map(() => rnd() > .5 ? 1 : 0);
    const paint = (els, st) => els.forEach((e, i) => e.classList.toggle('on', !!st[i]));
    paint(rc, state); paint(dc, dstate);
    sha(dstate.join('')).then(h => { if (h) diskH.textContent = 'SHA-256 = ' + h.slice(0, 32) + '…  (siempre igual)'; });
    const tick = async () => {
      for (let k = 0; k < 9; k++) { const i = Math.floor(rnd() * N); state[i] ^= 1; }
      paint(rc, state);
      const h = await sha(state.join(''));
      if (h) ramH.textContent = 'SHA-256 = ' + h.slice(0, 32) + '…';
    };
    tick();
    if (!reduce) setInterval(tick, 900);
  }

  /* ---------- mapa de memoria física (rangos reales reportados por WinPmem) ---------- */
  const mm = $('#mmap');
  if (mm) {
    const MAX = 0x280000000;
    const R = [[0x1000, 0x9E000], [0x100000, 0x6FA45000], [0x6FB46000, 0x27000], [0x6FB6E000, 0x1E7000], [0x71EFF000, 0x1000], [0x100000000, 0x180000000]];
    let pos = 0, html = '', ram = 0;
    R.forEach(([s, l]) => {
      if (s > pos) html += `<div class="gap" style="width:${(s - pos) / MAX * 100}%" title="Relleno con ceros: ${((s - pos) / 2 ** 20).toFixed(1)} MiB"></div>`;
      html += `<div class="ram" style="width:${Math.max(l / MAX * 100, .25)}%" title="RAM 0x${s.toString(16)} - ${(l / 2 ** 20).toFixed(1)} MiB"></div>`;
      pos = s + l; ram += l;
    });
    mm.innerHTML = html;
    const gib = x => (x / 2 ** 30).toLocaleString('es-CO', { maximumFractionDigits: 2 });
    $('#mram').textContent = gib(ram) + ' GiB';
    $('#mgap').textContent = gib(MAX - ram) + ' GiB';
    $('#mtot').textContent = gib(MAX) + ' GiB';
  }

  /* ---------- descargas: capacidad del visor de Claude o enlace normal ---------- */
  let dl = null;
  const status = $('#dlstatus');
  (async () => {
    try { if (window.claude && claude.use) dl = await claude.use('downloads'); } catch (e) { dl = null; }
  })();
  $$('a.dl').forEach(a => a.addEventListener('click', async ev => {
    if (!dl) return; // copia local o navegador normal: el enlace descarga el archivo
    ev.preventDefault();
    try {
      const r = await fetch(a.getAttribute('href'));
      if (!r.ok) throw new Error('No se encontró el archivo');
      await dl.save({ filename: a.dataset.name || a.getAttribute('href').split('/').pop(), data: await r.blob() });
      if (status) status.textContent = 'Archivo entregado: ' + (a.dataset.name || '');
    } catch (e) {
      if (status) status.textContent = (e && e.code === 'declined') ? 'Descarga cancelada.' : 'No se pudo descargar desde este visor; abra la copia local del sitio.';
    }
  }));
}

/* =================== v3: tema, progreso, pasos, glosario =================== */
{
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  };
  const root = document.documentElement;

  /* tema claro / oscuro */
  const tbtn = $('#themebtn');
  const current = () => root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const applyTheme = t => {
    root.dataset.theme = t;
    if (tbtn) { tbtn.setAttribute('aria-label', t === 'dark' ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro'); tbtn.title = tbtn.getAttribute('aria-label'); }
  };
  applyTheme(store.get('lab02-tema') || current());
  if (tbtn) tbtn.addEventListener('click', () => { const t = current() === 'dark' ? 'light' : 'dark'; applyTheme(t); store.set('lab02-tema', t); });

  /* barra de lectura e ir arriba */
  const bar = $('.readbar'), up = $('.totop');
  const onScroll = () => {
    const h = document.documentElement.scrollHeight - innerHeight;
    if (bar) bar.style.width = (h > 0 ? scrollY / h * 100 : 0) + '%';
    if (up) up.classList.toggle('on', scrollY > 900);
  };
  addEventListener('scroll', onScroll, { passive: true }); onScroll();
  if (up) up.addEventListener('click', () => scrollTo({ top: 0, behavior: 'smooth' }));

  /* marcar pasos completados (solo en este navegador) */
  const steps = $$('#caso ~ section .step, #caso .step').filter(s => s.closest('#verificar,#instalar,#volatility,#resultados,#informe'));
  const prog = $('#prog');
  let done = new Set(JSON.parse(store.get('lab02-pasos') || '[]'));
  const paintProg = () => { if (prog) prog.innerHTML = 'Avance <b>' + done.size + '</b>/' + steps.length; };
  steps.forEach(st => {
    const id = st.querySelector('.n')?.textContent.trim();
    const h = st.querySelector('h3'); if (!id || !h) return;
    const lab = document.createElement('label'); lab.className = 'done';
    lab.innerHTML = '<input type="checkbox"> Hecho';
    const cb = lab.querySelector('input');
    cb.checked = done.has(id); st.classList.toggle('ok', cb.checked);
    cb.addEventListener('change', () => {
      cb.checked ? done.add(id) : done.delete(id);
      st.classList.toggle('ok', cb.checked);
      store.set('lab02-pasos', JSON.stringify([...done])); paintProg();
    });
    h.appendChild(lab);
  });
  paintProg();

  /* glosario */
  const cards = $$('.gcard');
  cards.forEach(c => c.addEventListener('click', () => { c.classList.toggle('flip'); c.setAttribute('aria-pressed', c.classList.contains('flip')); }));
  const q = $('#gq'), chips = $$('.gtools .chip[data-t]'), cnt = $('#gcount'), all = $('#gall');
  let topic = 'todos';
  const norm = s => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  const filter = () => {
    const term = norm(q ? q.value : '');
    let n = 0;
    $$('.gtopic').forEach(t => {
      let vis = 0;
      $$('.gcard', t).forEach(c => {
        const ok = (topic === 'todos' || t.dataset.t === topic) && (!term || norm(c.textContent).includes(term));
        c.hidden = !ok; if (ok) vis++;
      });
      t.hidden = vis === 0; n += vis;
    });
    if (cnt) cnt.textContent = n + (n === 1 ? ' término' : ' términos');
  };
  if (q) q.addEventListener('input', filter);
  chips.forEach(ch => ch.addEventListener('click', () => {
    topic = ch.dataset.t;
    chips.forEach(c => c.setAttribute('aria-pressed', c === ch));
    filter();
  }));
  if (all) all.addEventListener('click', () => {
    const vis = cards.filter(c => !c.hidden);
    const flip = !vis.every(c => c.classList.contains('flip'));
    vis.forEach(c => { c.classList.toggle('flip', flip); c.setAttribute('aria-pressed', flip); });
    all.textContent = flip ? 'Mostrar conceptos' : 'Voltear todas';
  });
  filter();
}

/* =================== Lab 02: pestañas Estudiante / Docente =================== */
(() => {
  const tabs = [...document.querySelectorAll('.ptab')];
  if (!tabs.length) return;
  const secs = [...document.querySelectorAll('section[data-tab]')];
  const store = { get: k => { try { return localStorage.getItem(k); } catch (e) { return null; } },
                  set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) {} } };
  const show = t => {
    secs.forEach(s => { s.hidden = s.dataset.tab !== t; });
    tabs.forEach(b => b.setAttribute('aria-selected', String(b.dataset.t === t)));
    document.body.dataset.tab = t; store.set('lab02-pestana', t);
  };
  const reveal = id => {
    const el = id && document.getElementById(id); if (!el) return false;
    const s = el.closest('section[data-tab]');
    if (s && s.hidden) { show(s.dataset.tab); requestAnimationFrame(() => el.scrollIntoView()); return true; }
    return false;
  };
  tabs.forEach(b => b.addEventListener('click', () => {
    show(b.dataset.t);
    const first = document.getElementById(b.dataset.t === 'doc' ? 'docente' : 'estudiante');
    if (first) first.scrollIntoView();
  }));
  document.addEventListener('click', e => {
    const a = e.target.closest('a[href^="#"]'); if (!a) return;
    reveal(a.getAttribute('href').slice(1));
  }, true);
  window.addEventListener('hashchange', () => reveal(location.hash.slice(1)));
  show(store.get('lab02-pestana') || 'est');
  reveal(location.hash.slice(1));
})();
