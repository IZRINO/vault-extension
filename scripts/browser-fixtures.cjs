const { expect } = require('@playwright/test');
async function waitForBuiltInFilters(context, name) {
  if (name !== 'helium') return;
  const cdp = await context.browser().newBrowserCDPSession();
  let target;
  try {
    await expect.poll(async () => {
      const { targetInfos } = await cdp.send('Target.getTargets');
      target = targetInfos.find(target => target.type === 'background_page' && target.title === 'uBlock Origin');
      return !!target;
    }, { timeout: 20000, message: 'Wait for Helium built-in content blocker to start' }).toBe(true);
    // Helium's first-run UI can replace tabs while the built-in background page is already alive.
    await expect.poll(() => evaluateBrowserTarget(cdp, target.targetId,
      `globalThis.µBlock?.readyToFilter === true && globalThis.µBlock?.supportStats?.allReadyAfter !== '?' &&
       globalThis.vAPI?.net?.suspendDepth === 0`),
    { timeout: 60000, message: 'Wait for the Helium content blocker to finish initializing' }).toBe(true);
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
      timer = setTimeout(() => reject(new Error('Browser target did not respond')), 4000);
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
module.exports = { waitForBuiltInFilters, evaluateNativePopup: evaluateBrowserTarget };
