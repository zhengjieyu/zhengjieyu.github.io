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

    function localized(value) {
        return value[lang] || value.zh || value.en || '';
    }

    async function loadPosts(base) {
        if (window.blogData?.posts) {
            return [...window.blogData.posts].sort((a, b) => b.date.localeCompare(a.date));
        }
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
                <div class="post-meta"><time class="post-date" datetime="${p.date}">${formatDate(p.date, lang)}</time>${p.readTime ? `<span aria-hidden="true">·</span><span>${lang === 'zh' ? `约 ${p.readTime} 分钟阅读` : `${p.readTime} min read`}</span>` : ''}</div>
                <a class="post-link" href="${base}${p.slug}/${query}">${escapeHtml(localized(p.title))}</a>
                <p class="post-summary">${escapeHtml(localized(p.summary))}</p>
            </li>`).join('')}
        </ul>`;
    }

    async function renderPost(el) {
        const postLang = el.dataset.lang || lang;
        const bundled = window.blogData?.content?.[el.dataset.slug]?.[postLang];
        let markdown = bundled;
        if (!markdown) {
            const res = await fetch(`${postLang}.md`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            markdown = await res.text();
        }
        el.innerHTML = window.marked.parse(markdown);

        // Stable heading anchors shared by both languages
        el.querySelectorAll('h2, h3').forEach((h, i) => { h.id = `s${i + 1}`; });

        const sections = [...el.querySelectorAll('h2')];
        if (sections.length > 8) {
            const contents = document.createElement('details');
            contents.className = 'post-contents';
            const summary = document.createElement('summary');
            summary.textContent = document.documentElement.lang === 'zh-CN' ? '目录' : 'Contents';
            contents.appendChild(summary);
            const list = document.createElement('ol');
            sections.forEach(h => {
                const item = document.createElement('li');
                const link = document.createElement('a');
                link.href = `#${h.id}`;
                link.textContent = h.textContent;
                item.appendChild(link);
                list.appendChild(item);
            });
            contents.appendChild(list);
            const firstHeading = sections[0];
            firstHeading.parentNode.insertBefore(contents, firstHeading);
        }

        // Wide tables scroll inside their own box on small screens
        el.querySelectorAll('table').forEach(t => {
            const wrap = document.createElement('div');
            wrap.className = 'table-wrap';
            const hint = document.createElement('p');
            hint.className = 'table-scroll-hint';
            hint.textContent = postLang === 'zh' ? '表格可左右滑动 →' : 'Swipe to see more columns →';
            hint.hidden = true;
            t.parentNode.insertBefore(hint, t);
            t.parentNode.insertBefore(wrap, t);
            wrap.appendChild(t);
            const update = () => { hint.hidden = wrap.scrollWidth <= wrap.clientWidth + 1; };
            requestAnimationFrame(update);
            document.fonts.ready.then(update);
            new ResizeObserver(update).observe(wrap);
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
        const root = document.getElementById('blog-root');
        const displayLang = root?.dataset.lang || lang;
        document.documentElement.lang = displayLang === 'zh' ? 'zh-CN' : 'en';

        const toggle = document.getElementById('lang-toggle');
        if (toggle) {
            toggle.hidden = Boolean(root?.dataset.lang);
            toggle.textContent = UI[lang].toggle;
            toggle.setAttribute('aria-label', UI[lang].toggleLabel);
        }
        document.querySelectorAll('[data-i18n]').forEach(n => {
            n.textContent = UI[displayLang][n.dataset.i18n];
        });

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
