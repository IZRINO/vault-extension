const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const { mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { evaluateNativePopup, waitForBuiltInFilters } = require('./browser-fixtures.cjs');

const executables = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
const now = () => performance.timeOrigin + performance.now();
const ms = value => Math.round(value * 100) / 100;
const prefix = 'vault-popup-floor-';
const actionUrl = 'about:blank#vault-popup-floor';

async function fixture(dir) {
  await mkdir(dir);
  await Promise.all([
    writeFile(path.join(dir, 'manifest.json'), JSON.stringify({
      manifest_version: 3, name: 'Vault timing control', version: '1.0.0',
      action: { default_popup: 'popup.html' },
      content_security_policy: { extension_pages: "script-src 'self'; object-src 'self';" },
    })),
    writeFile(path.join(dir, 'popup.html'), '<!doctype html><meta charset="utf-8"><title>Timing control</title><script src="boot.js"></script><button type="button">Counter</button>'),
    writeFile(path.join(dir, 'boot.js'), `performance.mark('probe:script');
      document.addEventListener('DOMContentLoaded', () => {
        document.querySelector('button').addEventListener('click', event => { event.currentTarget.textContent = 'Clicked'; });
        performance.mark('probe:button');
      });`),
  ]);
}

async function measure(name, dir) {
  const extension = path.join(dir, 'control');
  const context = await chromium.launchPersistentContext(path.join(dir, name), {
    executablePath: executables[name], headless: false, viewport: null,
    args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension, '--enable-unsafe-extension-debugging'],
  });
  try {
    const cdp = await context.browser().newBrowserCDPSession();
    const { extensions } = await cdp.send('Extensions.getExtensions');
    const installed = extensions.find(entry => entry.name === 'Vault timing control' && entry.enabled);
    assert(installed, 'The control extension must be loaded and enabled');
    const { id } = installed;
    await waitForBuiltInFilters(context, name);
    const tab = context.pages()[0] || await context.newPage();
    await tab.goto(actionUrl);
    await tab.bringToFront();
    const { targetInfos } = await cdp.send('Target.getTargets', { filter: [{ type: 'tab' }] });
    const target = targetInfos.find(info => info.url === actionUrl);
    assert(target, 'Probe needs an active browser tab');
    const popupUrl = `chrome-extension://${id}/popup.html`;
    const seen = new Map();
    const record = ({ targetInfo }) => {
      if (targetInfo.url.startsWith(`chrome-extension://${id}/`)) seen.set(targetInfo.targetId, { type: targetInfo.type, url: targetInfo.url });
    };
    cdp.on('Target.targetCreated', record);
    cdp.on('Target.targetInfoChanged', record);
    cdp.on('Target.targetDestroyed', ({ targetId }) => {
      if (seen.has(targetId)) seen.get(targetId).closed = true;
    });
    await cdp.send('Target.setDiscoverTargets', { discover: true, filter: [{ exclude: false }] });
    const samples = [];
    for (let i = 0; i < 10; i++) {
      for (const open of seen.values()) assert(open.closed, 'A prior Popup did not close');
      seen.clear();
      await tab.bringToFront();
      await delay(250);
      const start = now();
      await cdp.send('Extensions.triggerAction', { id, targetId: target.targetId });
      await delay(1000);
      const entry = [...seen].find(([, info]) => info.url === popupUrl && !info.closed);
      assert(entry, `${name} sample ${i + 1}: no live native Popup; observed targets ${JSON.stringify([...seen.values()])}`);
      const [popupId] = entry;
      const result = await evaluateNativePopup(cdp, popupId, `(() => {
        const mark = name => performance.getEntriesByName(name, 'mark')[0]?.startTime;
        const nav = performance.getEntriesByType('navigation')[0];
        const button = document.querySelector('button');
        button.click();
        return { navigationAt: performance.timeOrigin, documentResponseMs: nav?.responseEnd,
          scriptMs: mark('probe:script'), buttonMs: mark('probe:button'),
          operable: !button.disabled && button.getBoundingClientRect().height > 0 && button.textContent === 'Clicked' };
      })()`);
      assert(result?.operable && Number.isFinite(result.buttonMs));
      assert(result.navigationAt >= start && result.buttonMs >= result.scriptMs);
      const nav = result.navigationAt - start;
      samples.push({ navigationMs: ms(nav), documentResponseFromNavigationMs: ms(result.documentResponseMs),
        scriptMs: ms(nav + result.scriptMs), buttonMs: ms(nav + result.buttonMs) });
      await cdp.send('Target.closeTarget', { targetId: popupId });
      await expect.poll(() => seen.get(popupId)?.closed).toBe(true);
    }
    assert(!context.serviceWorkers().some(worker => worker.url().startsWith(`chrome-extension://${id}/`)));
    return { browser: name, version: context.browser().version(), controlOnly: true, samples };
  } finally { await context.close(); }
}

(async () => {
  const temp = path.resolve(os.tmpdir());
  const dir = await mkdtemp(path.join(temp, prefix));
  try {
    await fixture(path.join(dir, 'control'));
    const results = [];
    for (const name of Object.keys(executables)) {
      const result = await measure(name, dir);
      results.push(result);
      console.log(JSON.stringify(result));
    }
    const output = path.resolve(__dirname, '..', 'test-results');
    await mkdir(output, { recursive: true });
    await writeFile(path.join(output, `wakeup-popup-floor-${Date.now()}.json`), JSON.stringify(results, null, 2) + '\n');
  } finally {
    assert(path.dirname(dir) === temp && path.basename(dir).startsWith(prefix));
    await rm(dir, { recursive: true, maxRetries: 3, retryDelay: 200 });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
