// Blog: post list, post rendering, and EN/中文 switching
(function() {
    const LANGS = ['en', 'zh'];
    const UI = {
        en: { toggle: '中文', toggleLabel: 'Switch to Chinese', back: '← All posts', blog: 'Blog', empty: 'No posts yet.', error: 'Sorry, unable to load this post.' },
        zh: { toggle: 'EN', toggleLabel: '切换到英文', back: '← 全部文章', blog: '博客', empty: '暂无文章。', error: '抱歉，文章加载失败。' }
    };

    function readLang() {
        const param = new URLSearchParams(window.location.search).get('lang');
        if (LANGS.includes(param)) return param;
        try {
            const saved = localStorage.getItem('lang');
            if (LANGS.includes(saved)) return saved;
        } catch (e) { /* storage unavailable */ }
        return 'en';
    }

    let lang = readLang();

    function formatDate(iso, l) {
        const d = new Date(iso + 'T00:00:00');
        return l === 'zh'
            ? `${d.getFullYear()} 年 ${d.getMonth() + 1} 月 ${d.getDate()} 日`
            : d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    }

    function escapeHtml(s) {
        return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    async function loadPosts(base) {
        const res = await fetch(`${base}posts.json`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const posts = await res.json();
        return posts.sort((a, b) => b.date.localeCompare(a.date));
    }

    function renderList(el, posts, base) {
        if (!posts.length) {
            el.innerHTML = `<p class="post-empty">${UI[lang].empty}</p>`;
            return;
        }
        const query = lang === 'en' ? '' : `?lang=${lang}`;
        el.innerHTML = `<ul class="post-list">${posts.map(p => `
            <li class="post-item">
                <time class="post-date" datetime="${p.date}">${formatDate(p.date, lang)}</time>
                <a class="post-link" href="${base}${p.slug}/${query}">${escapeHtml(p.title[lang] || p.title.en)}</a>
                <p class="post-summary">${escapeHtml(p.summary[lang] || p.summary.en)}</p>
            </li>`).join('')}
        </ul>`;
    }

    async function renderPost(el) {
        const res = await fetch(`${lang}.md`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const markdown = await res.text();
        el.innerHTML = window.marked.parse(markdown);

        // Stable heading anchors shared by both languages
        el.querySelectorAll('h2, h3').forEach((h, i) => { h.id = `s${i + 1}`; });

        // Wide tables scroll inside their own box on small screens
        el.querySelectorAll('table').forEach(t => {
            const wrap = document.createElement('div');
            wrap.className = 'table-wrap';
            t.parentNode.insertBefore(wrap, t);
            wrap.appendChild(t);
        });

        el.querySelectorAll('a[href^="http"]').forEach(a => {
            a.target = '_blank';
            a.rel = 'noopener';
        });

        const h1 = el.querySelector('h1');
        if (h1) document.title = `${h1.textContent} — Jieyu Zheng`;

        if (window.location.hash) {
            const target = document.getElementById(window.location.hash.slice(1));
            if (target) document.fonts.ready.then(() => target.scrollIntoView());
        }
    }

    async function render() {
        document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';

        const toggle = document.getElementById('lang-toggle');
        if (toggle) {
            toggle.textContent = UI[lang].toggle;
            toggle.setAttribute('aria-label', UI[lang].toggleLabel);
        }
        document.querySelectorAll('[data-i18n]').forEach(n => {
            n.textContent = UI[lang][n.dataset.i18n];
        });

        const root = document.getElementById('blog-root');
        if (!root) return;
        const base = root.dataset.base || '';
        try {
            if (root.dataset.view === 'post') {
                await renderPost(root);
            } else {
                renderList(root, await loadPosts(base), base);
            }
        } catch (err) {
            console.error('Blog load failed:', err);
            root.innerHTML = `<div class="error-message"><p>${UI[lang].error}</p></div>`;
        }
        if (typeof window.applyBHoverEffect === 'function') {
            window.applyBHoverEffect(root);
        }
    }

    function setLang(next) {
        lang = next;
        try { localStorage.setItem('lang', lang); } catch (e) { /* storage unavailable */ }
        const url = new URL(window.location.href);
        if (lang === 'en') url.searchParams.delete('lang');
        else url.searchParams.set('lang', lang);
        url.hash = '';
        history.replaceState(null, '', url);
        render().then(() => window.scrollTo(0, 0));
    }

    document.addEventListener('DOMContentLoaded', () => {
        const toggle = document.getElementById('lang-toggle');
        if (toggle) {
            toggle.addEventListener('click', () => setLang(lang === 'en' ? 'zh' : 'en'));
        }
        render();
    });
})();
