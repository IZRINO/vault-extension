type PlatformHints = { platform?: string; platformVersion?: string; brands?: { brand: string; version: string }[] };

export async function deviceProfile() {
  const ua = navigator.userAgent;
  const hints = (navigator as Navigator & { userAgentData?: PlatformHints & {
    getHighEntropyValues?(values: string[]): Promise<PlatformHints>;
  } }).userAgentData;
  const [platform, detail] = await Promise.all([
    browser.runtime.getPlatformInfo().catch(() => undefined),
    hints?.getHighEntropyValues?.(['platformVersion']).catch(() => undefined),
  ]);
  const os = platform?.os ?? (/Windows/.test(ua) ? 'win' : /Macintosh/.test(ua) ? 'mac' : 'linux');
  const major = Number(detail?.platformVersion?.split('.')[0]);
  const displayOs = os === 'win' ? (major >= 13 ? 'Windows 11' : major > 0 ? 'Windows 10' : 'Windows')
    : os === 'mac' ? 'macOS' : os === 'linux' ? 'Linux' : os;
  const arch = platform?.arch === 'x86-64' ? 'x86_64' : platform?.arch;
  const brand = hints?.brands?.find(entry => /helium/i.test(entry.brand));
  const edgeVersion = /\bEdg\/(\d+)/.exec(ua)?.[1], heliumVersion = /\bHelium\/(\d+)/.exec(ua)?.[1];
  const name = edgeVersion ? 'Microsoft Edge' : brand || heliumVersion ? 'Helium' : 'Chromium';
  const version = edgeVersion ?? heliumVersion ?? brand?.version.split('.')[0] ?? /\bChrome\/(\d+)/.exec(ua)?.[1];
  return {
    system: arch ? `${os}-${arch}` : os,
    browser: name,
    browserLabel: version ? `${name} ${version}` : name,
    suggestedName: `${displayOs}${arch ? ` (${arch === 'x86_64' ? 'x64' : arch})` : ''} · ${name}`,
  };
}
