(() => {
  const runtime = globalThis.chrome?.runtime;
  if (!runtime?.id) return;

  let reply;
  const recordLock = message => {
    if (message?.target === 'vault-event' && message.type === 'locked') reply = undefined;
  };
  runtime.onMessage.addListener(recordLock);
  // Start only when the popup document opens, in parallel with loading React.
  performance.mark('vault:popup-request');
  reply = runtime.sendMessage({ target: 'vault', type: 'open' }).then(result => {
    performance.mark('vault:popup-reply');
    return result;
  }).catch(() => undefined);
  window.readVaultOpening = async () => {
    const pending = reply;
    const result = await pending;
    const valid = reply === pending;
    reply = undefined;
    runtime.onMessage.removeListener(recordLock);
    return valid && result?.ok ? result.value : undefined;
  };
})();
