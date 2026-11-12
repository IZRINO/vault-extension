export interface MessageSender {
  id?: string; url?: string; origin?: string; tab?: { url?: string };
}
export function isVaultPage(sender: MessageSender, extensionId: string): boolean {
  if (sender.id !== extensionId || !sender.url) return false;
  try {
    const url = new URL(sender.url);
    const origin = 'chrome-extension://' + extensionId;
    if (url.protocol !== 'chrome-extension:' || url.host !== extensionId ||
      !['/popup.html', '/sidepanel.html'].includes(url.pathname)) return false;
    if (sender.origin && sender.origin !== origin) return false;
    // An extension tab is allowed. A web page/content script is never a vault UI.
    if (sender.tab && (!sender.tab.url || new URL(sender.tab.url).protocol !== 'chrome-extension:' ||
      new URL(sender.tab.url).host !== extensionId)) return false;
    return true;
  } catch { return false; }
}
