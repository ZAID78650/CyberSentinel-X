import puppeteer from 'puppeteer-core';
import { resolve } from 'path';
import { mkdirSync } from 'fs';

const htmlPath = resolve(import.meta.dirname, 'og-image-gen.html');
const outputPath = resolve(import.meta.dirname, '..', 'frontend', 'public', 'og-image.png');

mkdirSync(resolve(import.meta.dirname, '..', 'frontend', 'public'), { recursive: true });

const browser = await puppeteer.launch({
  executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  headless: 'new',
  args: ['--no-sandbox', '--disable-setuid-sandbox'],
});

const page = await browser.newPage();
await page.setViewport({ width: 1200, height: 630, deviceScaleFactor: 2 });
await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle0' });
await page.waitForFunction(() => document.title === 'CANVAS_READY');

// Screenshot at exact 1200x630
await page.screenshot({
  path: outputPath,
  clip: { x: 0, y: 0, width: 1200, height: 630 },
});

console.log(`✅ OG image saved: ${outputPath}`);
console.log(`   Resolution: 2400×1260 (2x retina for crisp sharing)`);

await browser.close();
