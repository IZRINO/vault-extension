import { MAX_HISTORY_BYTES, MAX_REMOTE_WAL_BYTES, MAX_REMOTE_WALS, type RemoteWal } from './bootstrap';
import { davSnapshotName, davWalName, type WebDavClient } from './webdav';

const name = 'wal-budget.bin';
const magic = [0x56, 0x42, 1, 0], header = 20, row = 85;
const invalid = () => new Error('无法验证网盘增量容量登记。本机编辑仍在，未追加增量。');
const retry = () => new Error('另一台设备正在同步。本机进度已保留，请稍后重试。');
export const MAX_APPEND_BYTES = MAX_REMOTE_WAL_BYTES / 2;
// Leave headroom for one older writer that doesn't participate in admission.
export const fitsAppend = (count: number, total: number, bytes: number) =>
  count + 2 <= MAX_REMOTE_WALS && total + bytes + MAX_APPEND_BYTES <= MAX_REMOTE_WAL_BYTES;

type Claim = { size: number; base: string; baseSize: number; helped: boolean; payload?: Uint8Array<ArrayBuffer> };
type Reservations = Map<string, Claim>;
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, i) => value === b[i]);

async function read(client: WebDavClient) {
  const object = await client.get(name, header + MAX_REMOTE_WALS * row + MAX_REMOTE_WAL_BYTES);
  const reservations: Reservations = new Map();
  if (!object) return { reservations, tag: undefined };
  if (object === 'unchanged' || !object.etag) throw invalid();
  const { bytes } = object;
  if (bytes.length < header || magic.some((value, i) => bytes[i] !== value)) throw invalid();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const decoder = new TextDecoder();
  let total = 0;
  for (let i = header; i < bytes.length;) {
    if (i + row > bytes.length || reservations.size >= MAX_REMOTE_WALS) throw invalid();
    const id = decoder.decode(bytes.subarray(i, i + 38)), size = view.getUint32(i + 38, true);
    const base = `snap_${decoder.decode(bytes.subarray(i + 42, i + 80))}`, baseSize = view.getUint32(i + 80, true), state = bytes[i + 84]!;
    i += row;
    total += size;
    if (!davWalName.test(`${id}.bin`) || !davSnapshotName.test(`${base}.bin`) || !size || size > MAX_APPEND_BYTES ||
        !baseSize || baseSize > MAX_HISTORY_BYTES || state > 2 || reservations.has(id) || total > MAX_REMOTE_WAL_BYTES) throw invalid();
    const payload = state < 2 ? bytes.subarray(i, i + size) : undefined;
    if (payload && payload.length !== size) throw invalid();
    reservations.set(id, { size, base, baseSize, helped: state > 0, payload });
    i += payload?.length ?? 0;
  }
  return { reservations, tag: object.etag };
}

function save(client: WebDavClient, reservations: Reservations, tag: string | undefined) {
  const payloadBytes = Array.from(reservations.values()).reduce((sum, claim) => sum + (claim.payload?.length ?? 0), 0);
  const bytes = new Uint8Array(header + reservations.size * row + payloadBytes), view = new DataView(bytes.buffer);
  bytes.set(magic);
  // A content-derived ETag must not repeat when the same set of reservations recurs.
  crypto.getRandomValues(bytes.subarray(4, header));
  const encoder = new TextEncoder();
  let i = header;
  for (const [id, { size, base, baseSize, helped, payload }] of reservations) {
    encoder.encodeInto(id, bytes.subarray(i, i + 38));
    view.setUint32(i + 38, size, true);
    encoder.encodeInto(base.slice(5), bytes.subarray(i + 42, i + 80));
    view.setUint32(i + 80, baseSize, true);
    bytes[i + 84] = !payload ? 2 : helped ? 1 : 0;
    i += row;
    if (payload) { bytes.set(payload, i); i += payload.length; }
  }
  return client.put(name, bytes, tag ? { match: tag } : { absent: true });
}

function forgetPresent(reservations: Reservations, objects: readonly RemoteWal[], retire: boolean, cancelled = false) {
  let changed = false;
  for (const { id, bytes } of objects) {
    const reservation = reservations.get(id);
    if (!reservation) continue;
    if (reservation.size !== bytes.length || reservation.payload && !sameBytes(reservation.payload, bytes)) throw invalid();
    if (retire && reservation.helped) {
      if (cancelled || !reservation.payload) continue;
      // Two conditional PUTs may still arrive on opposite sides of a DELETE. Keep one slot
      // charged for this name, even after its contents are safely absorbed.
      reservation.payload = undefined;
    } else reservations.delete(id);
    changed = true;
  }
  return changed;
}

export async function reserveAppend(client: WebDavClient, objects: readonly RemoteWal[], candidate: RemoteWal, base: string, baseSize: number,
  included: readonly string[],
  listingStillMatches: () => Promise<boolean>): Promise<'granted' | 'snapshot' | 'retry'> {
  const total = objects.reduce((sum, object) => sum + object.bytes.length, 0);
  for (let attempt = 0; attempt < 4; attempt++) {
    // Read the register BEFORE the directory. A concurrent grant/retirement invalidates this CAS.
    const { reservations, tag } = await read(client);
    if (!await listingStillMatches()) return 'retry';
    // A visible WAL is charged by the directory, but keep its base pinned until an authenticated
    // snapshot absorbs it. A compactor may still be working from a listing taken before it arrived.
    const unseen = new Map(reservations);
    forgetPresent(unseen, objects, false);
    // Never issue the same grant twice: the first PUT may still be in flight after a lost response.
    if (reservations.has(candidate.id)) return 'snapshot';
    const pending = Array.from(unseen.values()).reduce((sum, claim) => sum + claim.size, 0);
    if (!fitsAppend(objects.length + unseen.size, total + pending, candidate.bytes.length)) return 'snapshot';
    const absorbed = new Set(included), bases = new Map([[base, baseSize]]);
    for (const [id, claim] of reservations) if (!absorbed.has(id)) bases.set(claim.base, claim.baseSize);
    if (Array.from(bases.values()).reduce((sum, n) => sum + n, 0) > MAX_HISTORY_BYTES) return 'snapshot';
    reservations.set(candidate.id, { size: candidate.bytes.length, base, baseSize, helped: false, payload: new Uint8Array(candidate.bytes) });
    if (await save(client, reservations, tag)) return 'granted';
  }
  return 'retry';
}

export async function retireReservations(client: WebDavClient, objects: readonly RemoteWal[], cancelled = false) {
  if (!objects.length) return;
  for (let attempt = 0; attempt < 4; attempt++) {
    const { reservations, tag } = await read(client);
    if (!forgetPresent(reservations, objects, true, cancelled) || await save(client, reservations, tag)) return;
  }
  throw retry();
}

export async function blockingReservation(client: WebDavClient, prior: readonly string[], included: readonly string[]): Promise<RemoteWal | undefined> {
  if (prior.length < 5) return;
  const { reservations } = await read(client);
  const absorbed = new Set(included), retained = new Set(prior.slice(0, 4));
  for (const [id, claim] of reservations) {
    if (absorbed.has(id) || retained.has(claim.base)) continue;
    if (!claim.payload) throw invalid();
    return { id, bytes: claim.payload };
  }
}

// Never trust the register as a source of credentials: the caller must authenticate and replay
// the staged bytes against the active vault before offering exactly this immutable WAL.
export async function assistReservation(client: WebDavClient, object: RemoteWal) {
  const { reservations, tag } = await read(client), claim = reservations.get(object.id);
  if (!claim?.payload || !sameBytes(claim.payload, object.bytes)) return;
  if (!claim.helped) {
    claim.helped = true;
    if (!await save(client, reservations, tag)) return;
  }
  await client.put(`wal/${object.id}.bin`, new Uint8Array(object.bytes), { absent: true });
}
