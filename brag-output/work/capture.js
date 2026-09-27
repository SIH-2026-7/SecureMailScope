/**
 * Frame-by-frame capture of the SecureMailScope brag video using Puppeteer.
 * Produces 600 PNG frames (30fps × 20s) in work/frames/.
 */
const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

const FPS = 30;
const DURATION = 20;   // seconds
const TOTAL_FRAMES = FPS * DURATION;
const WIDTH = 1920;
const HEIGHT = 1080;
const FRAMES_DIR = path.join(__dirname, 'frames');

(async () => {
  // Clean & create output dir
  if (fs.existsSync(FRAMES_DIR)) fs.rmSync(FRAMES_DIR, { recursive: true });
  fs.mkdirSync(FRAMES_DIR, { recursive: true });

  console.log(`Capturing ${TOTAL_FRAMES} frames at ${WIDTH}x${HEIGHT} @ ${FPS}fps...`);

  const browser = await puppeteer.launch({
    headless: 'new',
    args: [`--window-size=${WIDTH},${HEIGHT}`, '--no-sandbox', '--disable-gpu'],
    defaultViewport: { width: WIDTH, height: HEIGHT },
  });

  const page = await browser.newPage();
  await page.goto(
    `file:///${path.resolve(__dirname, 'video.html').replace(/\\/g, '/')}?capture=1`,
    { waitUntil: 'domcontentloaded' }
  );

  // Give fonts/layout a moment to settle
  await new Promise(r => setTimeout(r, 500));

  for (let i = 0; i < TOTAL_FRAMES; i++) {
    const t = i / FPS;

    await page.evaluate((time) => {
      window.seekTo(time);
    }, t);

    // One rAF to let the browser paint the new state
    await page.evaluate(() => new Promise(r => requestAnimationFrame(r)));

    const frameNum = String(i).padStart(4, '0');
    await page.screenshot({
      path: path.join(FRAMES_DIR, `frame_${frameNum}.png`),
      type: 'png',
    });

    if (i % 60 === 0) {
      console.log(`  Frame ${i}/${TOTAL_FRAMES} (${t.toFixed(1)}s)`);
    }
  }

  console.log(`Done. ${TOTAL_FRAMES} frames saved to ${FRAMES_DIR}`);
  await browser.close();
})();
