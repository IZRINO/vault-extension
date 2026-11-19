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
  } finally { await cdp.detach(); }
  if (!target) return;
  const dashboard = await context.newPage();
  try {
    await dashboard.goto(new URL('/dashboard.html', target.url).href);
    await dashboard.waitForFunction(() => new Promise(resolve => chrome.runtime.getBackgroundPage(background =>
      resolve(background.µBlock?.readyToFilter === true && background.µBlock?.supportStats?.allReadyAfter !== '?' && background.vAPI?.net?.suspendDepth === 0))),
    undefined, { timeout: 60000 });
    console.log('Helium built-in filters ready');
  } finally { await dashboard.close(); }
}
// Toolbar Popups have CDP targets but are not exposed as Playwright Pages.
async function evaluateNativePopup(cdp, targetId, expression) {
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: false });
  let listener, timer;
  try {
    const result = new Promise((resolve, reject) => {
      listener = event => {
        if (event.sessionId !== sessionId) return;
        const message = JSON.parse(event.message);
        if (message.id !== 1) return;
        const error = message.error?.message ?? message.result?.exceptionDetails?.exception?.description ?? message.result?.exceptionDetails?.text;
        if (error) reject(new Error(`Could not read the native Popup: ${error}`));
        else resolve(message.result.result.value);
      };
      cdp.on('Target.receivedMessageFromTarget', listener);
      timer = setTimeout(() => reject(new Error('Native Popup did not respond')), 4000);
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
module.exports = { waitForBuiltInFilters, evaluateNativePopup };
