const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { waitForBuiltInFilters } = require('./browser-fixtures.cjs');

const root = path.resolve(__dirname, '..');
const extension = path.resolve(root, process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const executables = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
const sampleCount = Number(process.env.VAULT_WAKE_SAMPLES ?? 10);
const fixtureCount = Number(process.env.VAULT_WAKE_ITEMS ?? 1);
const title = 'Vault Wake Fixture';
const tabUrl = 'about:blank#vault-wakeup';
const fixture = {
  id: '', title, data: { kind: 'login', username: 'fixture', password: 'Fixture-Only#2026', uris: [] },
  note: '', customFields: [], tags: [], pinned: true, requireReprompt: true, trashed: false,
};

const now = () => performance.timeOrigin + performance.now();
const ms = value => Math.round(value * 100) / 100;

function stats(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return {
    min: ms(sorted[0]),
    median: ms(sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2),
    max: ms(sorted.at(-1)),
  };
}

async function addFixture(page) {
  await page.evaluate(async ({ item, count }) => {
    const send = async message => {
      const reply = await chrome.runtime.sendMessage({ target: 'vault', ...message });
      if (!reply?.ok) throw new Error(reply?.error || 'Vault did not reply');
      return reply.value;
    };
    const masterPassword = 'Wake-Fixture-Master#2026';
    await send({ type: 'create', masterPassword });
    if (count > 1) {
      const csv = 'url,username,password,name\r\n' + Array.from({ length: count - 1 }, (_, i) =>
        `https://w${i}.example.net,fixture${i},Test-Only-${i},Wake setup ${i}`).join('\r\n');
      const bytes = Array.from(new TextEncoder().encode(csv));
      const preview = await send({ type: 'preview-browser-csv', bytes });
      await send({ type: 'import-browser-csv', bytes, stamp: preview.stamp, proof: { method: 'master', secret: masterPassword } });
    }
    await send({ type: 'upsert', itemJson: JSON.stringify(item) });
    const opened = await send({ type: 'open' });
    if (opened.items.length !== count) throw new Error(`Fixture count mismatch: ${opened.items.length}`);
  }, { item: fixture, count: fixtureCount });
}

async function readPopup(cdp, targetId) {
  // The native extension Popup has a CDP target that Playwright does not expose as a Page.
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: false });
  let listener, timer;
  try {
    const expression = `(() => {
      const ready = performance.getEntriesByName('vault:list-ready', 'mark')[0];
      const row = [...document.querySelectorAll('.row-main')].find(button => button.textContent.includes(${JSON.stringify(title)}));
      const rowUsable = !!row && !row.disabled && row.getBoundingClientRect().height > 0
        && getComputedStyle(row).visibility === 'visible';
      return {
        readyAt: ready && performance.timeOrigin + ready.startTime,
        navigationAt: performance.timeOrigin,
        requestMs: performance.getEntriesByName('vault:popup-request', 'mark')[0]?.startTime,
        rowUsable, heading: document.querySelector('h1')?.textContent,
      };
    })()`;
    const result = new Promise((resolve, reject) => {
      listener = event => {
        if (event.sessionId !== sessionId) return;
        const message = JSON.parse(event.message);
        if (message.id !== 1) return;
        if (message.error || message.result.exceptionDetails) reject(new Error('Could not read the native Popup'));
        else resolve(message.result.result.value);
      };
      cdp.on('Target.receivedMessageFromTarget', listener);
      timer = setTimeout(() => reject(new Error('Native Popup did not respond')), 4000);
    });
    const [, popup] = await Promise.all([
      cdp.send('Target.sendMessageToTarget', {
        sessionId, message: JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression, returnByValue: true } }),
      }),
      result,
    ]);
    assert(popup?.rowUsable, `The native Popup must have a rendered, enabled fixture row: ${JSON.stringify(popup)}`);
    assert(Number.isFinite(popup.readyAt), 'Missing first-list render mark');
    return popup;
  } finally {
    clearTimeout(timer);
    if (listener) cdp.off('Target.receivedMessageFromTarget', listener);
    await cdp.send('Target.detachFromTarget', { sessionId }).catch(() => undefined);
  }
}

async function run(name, artifact) {
  const executablePath = process.env.VAULT_BROWSER_PATH || executables[name];
  await fs.access(executablePath);
  const temp = path.resolve(os.tmpdir());
  const profile = await fs.mkdtemp(path.join(temp, 'vault-wakeup-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, {
      executablePath, headless: false, viewport: null,
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension, '--enable-unsafe-extension-debugging'],
    });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 20000 });
    const id = new URL(worker.url()).host;
    await waitForBuiltInFilters(context, name);
    const setup = await context.newPage();
    await setup.goto(`chrome-extension://${id}/sidepanel.html`);
    await addFixture(setup);
    await setup.close();

    const tab = context.pages()[0] || await context.newPage();
    await tab.goto(tabUrl);
    await tab.bringToFront();
    const browserCdp = await context.browser().newBrowserCDPSession();
    const { targetInfos } = await browserCdp.send('Target.getTargets', { filter: [{ type: 'tab' }] });
    const actionTab = targetInfos.find(target => target.url === tabUrl);
    assert(actionTab, 'Native action needs a real browser tab');
    const cdp = await context.newCDPSession(tab);
    let version;
    cdp.on('ServiceWorker.workerVersionUpdated', ({ versions }) => {
      version = versions.find(entry => entry.scriptURL === worker.url()) ?? version;
    });
    await cdp.send('ServiceWorker.enable');
    await expect.poll(() => version?.runningStatus).toBe('running');

    const samples = [];
    for (let index = 0; index < sampleCount; index++) {
      await cdp.send('ServiceWorker.stopWorker', { versionId: version.versionId });
      await expect.poll(() => version?.runningStatus).toBe('stopped');
      const startedAt = now();
      await browserCdp.send('Extensions.triggerAction', { id, targetId: actionTab.targetId });
      // Read marks after the deadline; hidden Popup timers may be throttled by Chromium.
      await delay(1000);
      let popupTarget;
      await expect.poll(async () => {
        const { targetInfos } = await browserCdp.send('Target.getTargets', { filter: [{ type: 'page' }] });
        popupTarget = targetInfos.find(target => target.url === `chrome-extension://${id}/popup.html`);
        return !!popupTarget;
      }, { timeout: 2500 }).toBe(true);
      const { readyAt, navigationAt, requestMs } = await readPopup(browserCdp, popupTarget.targetId);
      const started = context.serviceWorkers().find(entry => entry.url() === worker.url());
      assert(started, 'Popup should wake the Vault service worker');
      const restored = await started.evaluate(() => {
        const mark = name => performance.getEntriesByName(name, 'mark')[0]?.startTime;
        return {
          workerAt: performance.timeOrigin, restoreMs: mark('vault:session-restored'),
          backgroundEntryMs: mark('vault:background-entry'), prepareMs: mark('vault:prepare'), wasmLoadedMs: mark('vault:wasm-loaded'),
        };
      });
      assert(Number.isFinite(restored.restoreMs), 'Missing WASM session restore mark');
      assert(restored.workerAt >= startedAt && readyAt >= restored.workerAt + restored.restoreMs,
        'Expected cold worker start and authenticated restore after the toolbar action and before the list');
      samples.push({ restoreMs: restored.restoreMs, popupMs: readyAt - startedAt,
        workerStartMs: restored.workerAt - startedAt, popupNavigationMs: navigationAt - startedAt, popupRequestMs: requestMs,
        backgroundEntryMs: restored.backgroundEntryMs, prepareMs: restored.prepareMs, wasmLoadedMs: restored.wasmLoadedMs });
      await browserCdp.send('Target.closeTarget', { targetId: popupTarget.targetId }).catch(error => {
        // Chromium already dismisses the toolbar Popup when it loses focus.
        if (!error.message.includes('No target with given id found')) throw error;
      });
    }
    const result = {
      browser: name, version: context.browser().version(), extension: path.relative(root, extension), artifact, fixtureCount,
      samples: samples.map(sample => Object.fromEntries(Object.entries(sample)
        .filter(([, value]) => Number.isFinite(value)).map(([key, value]) => [key, ms(value)]))),
      restoreMs: stats(samples.map(sample => sample.restoreMs)), popupMs: stats(samples.map(sample => sample.popupMs)),
      restorePassed: samples.every(sample => sample.restoreMs < 5), popupPassed: samples.every(sample => sample.popupMs < 50),
      passed: samples.every(sample => sample.restoreMs < 5 && sample.popupMs < 50),
    };
    console.log(JSON.stringify(result));
    return result;
  } finally {
    await context?.close();
    assert(path.dirname(path.resolve(profile)) === temp && path.basename(profile).startsWith('vault-wakeup-'));
    await fs.rm(profile, { recursive: true, maxRetries: 3, retryDelay: 200 });
  }
}

async function buildHash() {
  const entries = await fs.readdir(extension, { recursive: true, withFileTypes: true });
  const files = entries.filter(entry => entry.isFile()).map(entry => path.join(entry.parentPath, entry.name)).sort();
  const digest = createHash('sha256');
  for (const file of files) {
    digest.update(path.relative(extension, file).replaceAll('\\', '/') + '\0');
    digest.update(createHash('sha256').update(await fs.readFile(file)).digest());
  }
  return digest.digest('hex');
}

(async () => {
  assert(Number.isInteger(sampleCount) && sampleCount >= 2, 'At least two cold samples are required');
  assert(Number.isInteger(fixtureCount) && fixtureCount >= 1 && fixtureCount <= 5000, 'Fixture count must be 1–5000');
  const names = process.argv.slice(2).length ? process.argv.slice(2) : ['edge', 'helium'];
  const artifact = await buildHash();
  const results = [];
  for (const name of names) results.push(await run(name, artifact));
  assert.equal(await buildHash(), artifact, 'The production build changed during measurement');
  const output = path.join(root, 'test-results');
  await fs.mkdir(output, { recursive: true });
  const filename = fixtureCount === 1 ? 'wakeup.json' : `wakeup-${fixtureCount}.json`;
  await fs.writeFile(path.join(output, filename), JSON.stringify(results, null, 2) + '\n');
  assert(results.every(result => result.passed), 'Cold-wake limits: WASM restore < 5 ms and native Popup list < 50 ms on every sample');
})().catch(error => { console.error(error); process.exitCode = 1; });
