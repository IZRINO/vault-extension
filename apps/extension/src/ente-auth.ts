import type { EnteMerge, EntePreview, VaultItem } from './vault-messages';

export interface EnteRow {
  setupKey: string; issuer: string; account: string; note: string;
  tags: string[]; pinned: boolean; trashed: boolean;
}
export interface EnteBatch { rows: EnteRow[]; invalid: number; skipped: number }

// Suggestions only: these brands never create or broaden website matching rules.
const domains: Record<string, readonly string[]> = {
  github: ['github.com'], gitlab: ['gitlab.com'], cloudflare: ['cloudflare.com'],
  google: ['google.com', 'accounts.google.com'], microsoft: ['microsoft.com', 'live.com', 'office.com'],
  steam: ['steampowered.com', 'steamcommunity.com'], dropbox: ['dropbox.com'], discord: ['discord.com'],
  amazon: ['amazon.com'],
};

function matches(row: EnteRow, item: VaultItem): boolean {
  if (row.trashed || item.trashed || item.data.kind !== 'login' || item.data.totpUri ||
      item.data.username !== row.account || !row.account) return false;
  const issuer = row.issuer.toLowerCase().trim();
  const known = domains[issuer] ?? (/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(issuer) ? [issuer] : []);
  const uris = item.data.uris as { uri: string }[] | undefined;
  return !!uris?.some(({ uri }) => {
    try {
      const url = new URL(uri);
      return ['https:', 'http:'].includes(url.protocol) &&
        known.some(domain => url.hostname === domain || url.hostname.endsWith('.' + domain));
    } catch { return false; }
  });
}

export function planEnteImport(batch: EnteBatch, existing: VaultItem[], merges: EnteMerge[] = []) {
  const possible = batch.rows.map((row, index) => {
    const matching = existing.filter(item => matches(row, item));
    return matching.length === 1 ? { row: index, id: matching[0]!.id, title: matching[0]!.title, account: row.account } : undefined;
  });
  const counts = new Map<string, number>();
  for (const match of possible) if (match) counts.set(match.id, (counts.get(match.id) ?? 0) + 1);
  const suggestions = possible.filter((match): match is NonNullable<typeof match> => !!match && counts.get(match.id) === 1);
  if (!Array.isArray(merges) || merges.length > suggestions.length ||
      new Set(merges.map(merge => merge.row)).size !== merges.length ||
      merges.some(merge => !suggestions.some(suggestion => suggestion.row === merge.row && suggestion.id === merge.id))) {
    throw new Error('合并选择已失效，请重新预览。');
  }
  const items: VaultItem[] = batch.rows.map((row, index) => {
    const choice = merges.find(merge => merge.row === index);
    if (choice) {
      const old = existing.find(item => item.id === choice.id)!;
      return { ...old, data: { ...old.data, totpUri: row.setupKey },
        note: !row.note || row.note === old.note ? old.note : [old.note, row.note].filter(Boolean).join('\n\n'),
        tags: [...new Set([...old.tags, ...row.tags])], pinned: old.pinned || row.pinned,
        updatedAtMs: Date.now() };
    }
    return { id: '', title: row.issuer || row.account || '两步验证码',
      data: { kind: 'login', username: row.account, password: '', uris: [], totpUri: row.setupKey },
      note: row.note, tags: row.tags, pinned: row.pinned, trashed: row.trashed,
      trashedAtMs: row.trashed ? Date.now() : undefined,
      customFields: [], requireReprompt: false, createdAtMs: Date.now(), updatedAtMs: Date.now(), revision: 1 };
  });
  const preview: Omit<EntePreview, 'stamp'> = {
    ready: items.length, skipped: batch.skipped, invalid: batch.invalid,
    trashed: batch.rows.filter(row => row.trashed).length, suggestions,
    sample: batch.rows.slice(0, 12).map(row => ({
      title: row.issuer || row.account || '两步验证码', account: row.account, kind: new URL(row.setupKey).hostname,
    })),
  };
  return { items, preview };
}
