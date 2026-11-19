export interface JournalClock { deviceId: string; tag: string; time: number; sequence: number }

export function adoptDevice(deviceId: string, previous: JournalClock | undefined, now: number) {
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(deviceId)) throw new Error('设备身份无效。');
  const { state } = nextJournalVersion(undefined, now, previous?.time);
  return { ...state, deviceId };
}

export function nextJournalVersion(previous: JournalClock | undefined, now: number, observed = -1) {
  if (previous && (!/^[0-9a-f-]{36}$/.test(previous.deviceId) || !/^[0-9a-f]{8}$/.test(previous.tag) ||
      !Number.isSafeInteger(previous.time) || previous.time < 0 || !Number.isSafeInteger(previous.sequence) || previous.sequence < 0)) {
    throw new Error('本机同步日志身份已损坏。');
  }
  const state: JournalClock = {
    deviceId: previous?.deviceId ?? crypto.randomUUID(),
    tag: previous?.tag ?? Array.from(crypto.getRandomValues(new Uint8Array(4)), value => value.toString(16).padStart(2, '0')).join(''),
    time: Math.max(0, now, (previous?.time ?? -1) + 1, observed + 1),
    sequence: (previous?.sequence ?? 0) + 1,
  };
  if (!Number.isSafeInteger(state.time) || !Number.isSafeInteger(state.sequence)) throw new Error('本机同步日志时钟不可用。');
  const hex = (value: number) => value.toString(16).padStart(14, '0');
  return { id: `${hex(state.time)}_${state.tag}_${hex(state.sequence)}`, state };
}
