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
module.exports = { waitForBuiltInFilters };
