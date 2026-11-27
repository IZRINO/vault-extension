import { expect, it, vi } from 'vitest';
import type { SessionState } from '../vault-storage';
import { combinePacks, type PackView } from './pack-sync';
import type { PackVersion } from './pack-transport';

const bytes = new Uint8Array([1]);
const encode = (value: Record<string, string>) => new TextEncoder().encode(JSON.stringify(value));
const decode = (value: Uint8Array) => JSON.parse(new TextDecoder().decode(value)) as Record<string, string>;

vi.mock('../bridge', () => ({ derive: async (operation: string, args: Uint8Array[]) => {
  if (operation === 'open-preferences') return '{"sites":{},"equivalentDomains":[]}';
  if (operation !== 'sync:pack-merge') throw new Error(`Unexpected operation ${operation}`);
  const [base, local, remote] = [decode(args[3]!), decode(args[5]!), decode(args[7]!)];
  const result: Record<string, string> = {};
  for (const field of Object.keys(base)) {
    if (local[field] !== base[field] && remote[field] !== base[field] && local[field] !== remote[field])
      throw new Error(`Unexpected fixture conflict for ${field}`);
    result[field] = (local[field] === base[field] ? remote[field] : local[field])!;
  }
  return { head: Array.from(bytes), snap: Array.from(encode(result)), conflicts: [], count: 1, conflictCount: 0, draftCount: 0 };
} }));

it('keeps an edit back to an old value after two devices independently merge the same branches', async () => {
  const version = (id: string, ...parents: PackVersion[]): PackVersion => ({
    id, vaultId: 'fixture', parents: parents.map(value => value.id), bytes: 1, createdAt: 1, keyEpoch: 1, sha256: '',
  });
  const root = version('root'), title = version('a', root), notes = version('b', root);
  const first = version('merge1', title, notes), second = version('merge2', title, notes);
  const view = (title: string, notes: string): PackView => ({
    head: bytes, snap: encode({ title, notes }), rules: bytes, conflicts: new Uint8Array(),
    count: 1, conflictCount: 0, draftCount: 0,
  });
  const content = new Map([
    [root.id, view('before', 'old')], [title.id, view('after', 'old')], [notes.id, view('before', 'new')],
    [first.id, view('after', 'new')], [second.id, view('after', 'new')],
  ]);
  const listing = { root, versions: [root, title, notes, first, second], tips: [first, second], offsetSeconds: null };
  const session: SessionState = { key: bytes, wrap: bytes, unlockedAtMs: 0, lastActivityMs: 0 };
  const result = await combinePacks(listing, view('after', 'old'), first.id, listing.tips,
    async version => content.get(version.id)!, session, () => {});
  expect(decode(result.snap)).toEqual({ title: 'after', notes: 'old' });
});
