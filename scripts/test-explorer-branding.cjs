const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { integrate } = require('./integrate-explorer-branding.cjs');
const fixture = '<html><head><link rel="icon" href="data:," /></head><body data-sveltekit-preload-data="hover"><main>Benchmark data</main><script>/* hydration */</script></body></html>';
const branded = integrate(fixture);
assert.equal(integrate(branded), branded, 'branding must be idempotent');
assert.ok(branded.includes('<main>Benchmark data</main><script>/* hydration */</script>'));
assert.ok(!branded.includes('href="data:,"'));
assert.ok(branded.includes('data-sveltekit-preload-data="hover"'));
assert.ok(integrate(fixture.replace('<body ', '<body class="existing" ')).includes('class="existing sea-subpage explorer-page"'));
assert.throws(() => integrate('<p>not a document</p>'));
for (const name of ['index.html', '200.html']) {
  const html = fs.readFileSync(path.resolve(__dirname, '../ngcc-explorer', name), 'utf8');
  assert.equal(integrate(html), html, `${name} must be branded`);
  assert.equal((html.match(/personal-site-branding:start/g) || []).length, 1);
}
console.log('PASS: branding is repeatable, preserves app markup, and covers both Explorer entry points.');
