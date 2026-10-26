// Rebuild raster fallbacks from the editable SVG. Requires sharp.
const fs = require('node:fs/promises');
const path = require('node:path');
const sharp = require('sharp');

async function build() {
  const images = path.resolve(__dirname, '../images');
  const source = path.join(images, 'jz-mark.svg');
  for (const [name, size] of [['jz-mark.png', 256], ['jz-touch.png', 180], ['jz-favicon.png', 32]]) {
    await sharp(source).resize(size, size).png().toFile(path.join(images, name));
  }
  const sizes = [16, 32, 48, 64];
  const frames = await Promise.all(sizes.map(size => sharp(source).resize(size, size).png().toBuffer()));
  const directory = Buffer.alloc(6 + 16 * sizes.length);
  directory.writeUInt16LE(1, 2);
  directory.writeUInt16LE(sizes.length, 4);
  let offset = directory.length;
  sizes.forEach((size, i) => {
    const entry = 6 + 16 * i;
    directory[entry] = size;
    directory[entry + 1] = size;
    directory.writeUInt16LE(1, entry + 4);
    directory.writeUInt16LE(32, entry + 6);
    directory.writeUInt32LE(frames[i].length, entry + 8);
    directory.writeUInt32LE(offset, entry + 12);
    offset += frames[i].length;
  });
  await fs.writeFile(path.join(images, 'jz-favicon.ico'), Buffer.concat([directory, ...frames]));
}

build().catch(error => { console.error(error); process.exitCode = 1; });
