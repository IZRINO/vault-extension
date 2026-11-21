export async function clipboardDigest(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  try { return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join(''); }
  finally { bytes.fill(0); }
}
