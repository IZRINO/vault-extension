const { expect } = require('@playwright/test');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

class BrowserTargetTimeout extends Error {}

async function extensionBuildHash(directory) {
  const entries = await fs.readdir(directory, { recursive: true, withFileTypes: true });
  const files = entries.filter(entry => entry.isFile()).map(entry => path.join(entry.parentPath, entry.name)).sort();
  const digest = createHash('sha256');
  for (const file of files) {
    digest.update(path.relative(directory, file).replaceAll('\\', '/') + '\0');
    digest.update(createHash('sha256').update(await fs.readFile(file)).digest());
  }
  return digest.digest('hex');
}

async function waitForSetupTab(context, workerUrl) {
  const url = new URL('/sidepanel.html?view=setup', workerUrl).href;
  const matches = () => context.pages().filter(page => page.url() === url);
  await expect.poll(() => matches().length, { timeout: 15000, message: 'Fresh installation must open one Vault setup tab' }).toBe(1);
  return matches()[0];
}

async function waitForBuiltInFilters(context, name) {
  if (name !== 'helium') return;
  const cdp = await context.browser().newBrowserCDPSession();
  try {
    // Helium can replace the background target during initial startup.
    await expect.poll(async () => {
      const { targetInfos } = await cdp.send('Target.getTargets');
      const target = targetInfos.find(target => target.type === 'background_page' && target.title === 'uBlock Origin');
      if (!target) return 'no background page';
      try {
        const ready = await evaluateBrowserTarget(cdp, target.targetId,
          `globalThis.µBlock?.readyToFilter === true && globalThis.µBlock?.supportStats?.allReadyAfter !== '?' &&
           globalThis.vAPI?.net?.suspendDepth === 0`);
        return ready ? 'ready' : 'initializing';
      } catch (error) {
        if (error instanceof BrowserTargetTimeout || /(?:No target|Session) with given id (?:not )?found|Target closed/.test(String(error)))
          return 'background page unresponsive';
        throw error;
      }
    }, { timeout: 60000, message: 'Wait for the Helium content blocker to finish initializing' }).toBe('ready');
    console.log('Helium built-in filters ready');
  } finally { await cdp.detach(); }
}
// Toolbar Popups and the built-in filter background page are not exposed as Playwright Pages.
async function evaluateBrowserTarget(cdp, targetId, expression) {
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: false });
  let listener, timer;
  try {
    const result = new Promise((resolve, reject) => {
      listener = event => {
        if (event.sessionId !== sessionId) return;
        const message = JSON.parse(event.message);
        if (message.id !== 1) return;
        const error = message.error?.message ?? message.result?.exceptionDetails?.exception?.description ?? message.result?.exceptionDetails?.text;
        if (error) reject(new Error(`Could not evaluate the browser target: ${error}`));
        else resolve(message.result.result.value);
      };
      cdp.on('Target.receivedMessageFromTarget', listener);
      timer = setTimeout(() => reject(new BrowserTargetTimeout('Browser target did not respond')), 4000);
    });
    const [, value] = await Promise.all([
      cdp.send('Target.sendMessageToTarget', {
        sessionId, message: JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression, returnByValue: true } }),
      }),
      result,
    ]);
    return value;
  } finally {
    clearTimeout(timer);
    if (listener) cdp.off('Target.receivedMessageFromTarget', listener);
    await cdp.send('Target.detachFromTarget', { sessionId }).catch(() => undefined);
  }
}
module.exports = { extensionBuildHash, waitForBuiltInFilters, waitForSetupTab, evaluateNativePopup: evaluateBrowserTarget };
