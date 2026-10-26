// Reapply personal-site presentation after each upstream Explorer build.
// Deliberately leaves Svelte's hydration markup, JS bundles and benchmark data intact.
const fs = require('node:fs');
const path = require('node:path');

const START = '<!-- personal-site-branding:start -->';
const END = '<!-- personal-site-branding:end -->';
function integrate(html) {
  if (!html.includes('</head>') || !/<body\b/.test(html)) throw new Error('Invalid Explorer HTML');
  const old = new RegExp(`${START}[\\s\\S]*?${END}\\n?`, 'g');
  html = html.replace(old, '').replace(/<link\b[^>]*rel="icon"[^>]*href="data:,"[^>]*>/g, '');
  const head = `${START}\n<link rel="icon" href="/images/jz-favicon.ico" sizes="16x16 32x32 48x48 64x64">\n<link rel="icon" type="image/svg+xml" href="/images/jz-mark.svg">\n<link rel="apple-touch-icon" href="/images/jz-touch.png">\n<link rel="stylesheet" href="/site-surfaces.css">\n<link rel="stylesheet" href="/explorer-theme.css">\n${END}\n`;
  html = html.replace('</head>', head + '</head>');
  html = html.replace(/<body\b([^>]*)>/, (_, attrs) => {
    const existing = attrs.match(/\bclass="([^"]*)"/);
    const classes = new Set((existing?.[1] || '').split(/\s+/).filter(Boolean));
    classes.add('sea-subpage');
    classes.add('explorer-page');
    const value = `class="${[...classes].join(' ')}"`;
    return `<body${existing ? attrs.replace(existing[0], value) : attrs + ' ' + value}>`;
  });
  return html;
}

if (require.main === module) {
  const directory = path.resolve(__dirname, '../ngcc-explorer');
  for (const name of ['index.html', '200.html']) {
    const file = path.join(directory, name);
    const original = fs.readFileSync(file, 'utf8');
    const branded = integrate(original);
    if (branded !== original) fs.writeFileSync(file, branded);
    console.log(`Branded ${name}`);
  }
}
module.exports = { integrate };
