/* An editorial index and a small, deliberately illustrative register experiment. */
(() => {
  const archive = document.querySelector('#world-archive');
  if (!archive) return;
  const nav = archive.querySelector('.archive-tabs');
  const side = document.createElement('aside');
  side.className = 'archive-index';
  side.innerHTML = `<p class="index-kicker">A PERSONAL COLLECTION</p><p class="index-title">Field<br><i>notes.</i><span>by Jieyu Zheng</span></p>`;
  nav.before(side);
  side.append(nav);
  nav.querySelectorAll('button').forEach((button, i) => {
    const number = document.createElement('span');
    number.className = 'index-number';
    number.textContent = String(i).padStart(2, '0');
    button.prepend(number);
    button.insertAdjacentHTML('beforeend', '<span class="index-arrow" aria-hidden="true">↗</span>');
  });
  const postcard = document.createElement('figure');
  postcard.className = 'index-postcard';
  postcard.innerHTML = `<img src="images/photographs/table.jpg" alt="Sunlight on the sea, seen from a boat's wooden table"><figcaption>A little light, between the lines.</figcaption>`;
  side.append(postcard);
  const theme = document.createElement('button');
  theme.className = 'archive-light';
  theme.setAttribute('aria-label', 'Switch day and night');
  theme.onclick = () => document.querySelector('#world-theme').click();
  archive.querySelector('.archive-toolbar [data-dismiss]').before(theme);
  const syncTheme = () => { theme.textContent = document.documentElement.dataset.theme === 'dark' ? '☼ Daylight' : '☾ After hours'; };
  syncTheme();
  new MutationObserver(syncTheme).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  const footer = document.createElement('footer');
  footer.className = 'archive-colophon';
  footer.innerHTML = '<span>JZ / FIELD NOTES</span><span>Code, curiosity & collected light.</span>';
  archive.querySelector('.archive-pages').append(footer);

  const skills = archive.querySelector('#skills');
  skills.querySelector('.section-heading h2').innerHTML = 'Closer to<br>the <i>metal.</i>';
  skills.querySelector('.section-heading p').textContent = 'Assembly implementation, from wide vectors to small devices. A few tools at my workbench.';
  const workbench = document.createElement('div');
  workbench.className = 'workbench';
  const architectures = [
    { name: 'AVX2', family: 'x86', bits: 256, lanes: 8, register: 'YMM', detail: '256-bit vector example' },
    { name: 'AVX-512', family: 'x86', bits: 512, lanes: 16, register: 'ZMM', detail: '512-bit vector example' },
    { name: 'ARMv8-A', family: 'Arm', bits: 128, lanes: 4, register: 'V', detail: '128-bit NEON example' },
    { name: 'ARMv7-M', family: 'Arm', bits: 32, lanes: 1, register: 'R', detail: '32-bit scalar example' }
  ];
  workbench.innerHTML = `<div class="architecture-selector" role="group" aria-label="Choose an architecture">${architectures.map((a, i) => `<button data-architecture="${i}" aria-pressed="${i === 0}"><span class="architecture-number">0${i+1} / ${a.family}</span><strong>${a.name}</strong><span class="architecture-led" aria-hidden="true"></span></button>`).join('')}</div>
    <div class="bench-topline"><span><i aria-hidden="true"></i> IMPLEMENTATION WORKBENCH</span><span>EXP. 01 / ADDITION</span></div>
    <div class="bench-interior"><div class="chip-study"><span class="bench-micro">REGISTER STUDY</span><div class="register-chip" aria-hidden="true"><span id="chip-register">YMM</span><strong id="chip-width">256</strong><span>BITS</span></div><p id="chip-detail">256-bit vector example</p></div>
    <div class="register-study"><div class="register-intro"><h3>One operation.<br><i id="lane-title">Eight little journeys.</i></h3><span class="bench-micro">32-BIT<br>ELEMENTS</span></div>
    <div id="register-rows" class="register-rows" aria-label="Addition inputs and result"></div>
    <div class="bench-actions"><button id="run-register">Run addition <span aria-hidden="true">↵</span></button><button id="new-register">New inputs ↻</button><output id="register-status" role="status">Ready when you are.</output></div></div></div>
    <div class="bench-footnote"><span>SIMULATION, NOT A BENCHMARK</span><p>A visual model of independent 32-bit additions. JavaScript only; no native assembly or hardware detection.</p></div>`;
  skills.querySelector('.skills-grid').replaceWith(workbench);
  const annotation = document.createElement('p');
  annotation.className = 'bench-annotation';
  annotation.innerHTML = '<span aria-hidden="true">↖</span> Pick an architecture. Follow the numbers.';
  workbench.before(annotation);
  let selected = 0;
  let generation = 0;
  let complete = false;
  const words = ['Eight little journeys.', 'Sixteen little journeys.', 'Four little journeys.', 'One small step.'];
  const rows = workbench.querySelector('#register-rows');
  function values() {
    return Array.from({ length: architectures[selected].lanes }, (_, i) => [(i * 7 + generation * 3 + 5) % 23, (i * 3 + generation * 5 + 2) % 17]);
  }
  function render() {
    const arch = architectures[selected];
    workbench.querySelectorAll('[data-architecture]').forEach((button, i) => button.setAttribute('aria-pressed', String(i === selected)));
    document.querySelector('#chip-register').textContent = arch.register;
    document.querySelector('#chip-width').textContent = arch.bits;
    document.querySelector('#chip-detail').textContent = arch.detail;
    document.querySelector('#lane-title').textContent = words[selected];
    rows.style.setProperty('--lanes', Math.min(arch.lanes, 8));
    rows.dataset.complete = String(complete);
    const pairs = values();
    rows.innerHTML = ['a', 'b', 'a + b'].map((label, r) => `<div class="register-row"><span class="row-label">${label}</span><div class="register-lanes">${pairs.map(([a, b], i) => `<span class="register-lane ${r === 2 ? 'result-lane' : ''}" style="--lane:${i}" aria-label="${label}, element ${i + 1}: ${r === 0 ? a : r === 1 ? b : complete ? a+b : 'not computed'}">${r === 0 ? a : r === 1 ? b : complete ? a+b : '·'}</span>`).join('')}</div></div>`).join('');
    document.querySelector('#register-status').textContent = complete ? `${arch.lanes} ${arch.lanes === 1 ? 'result' : 'results'}. All lanes added independently.` : 'Ready when you are.';
    document.querySelector('#run-register').disabled = complete;
  }
  workbench.querySelectorAll('[data-architecture]').forEach(button => {
    button.onclick = () => { selected = Number(button.dataset.architecture); complete = false; render(); };
  });
  document.querySelector('#run-register').onclick = () => { complete = true; render(); };
  document.querySelector('#new-register').onclick = () => { generation++; complete = false; render(); };
  render();
  // The archive may already be open via a URL hash before this layout is built.
  if (archive.open) requestAnimationFrame(() => { archive.scrollTop = 0; });
  // Native fragment scrolling runs after layout; keep deep-linked archive views
  // at their toolbar rather than scrolling the section underneath it.
  window.addEventListener('load', () => {
    if (archive.open && location.hash) requestAnimationFrame(() => { archive.scrollTop = 0; });
  }, { once: true });
})();
