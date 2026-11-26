import init, { wasm_make_local_wal, wasm_verify_local_wal, wasm_sync_authenticate_head, wasm_sync_create_genesis,
  wasm_sync_history_metadata, wasm_sync_unlock_head, wasm_sync_verify_recovery, wasm_sync_verify_snapshot, wasm_sync_replay, wasm_sync_make_batch,
  wasm_sync_reconcile, wasm_sync_adopt, wasm_sync_write_guard, wasm_sync_conflicts, wasm_sync_conflict_stamp, wasm_sync_preview_resolutions,
  wasm_sync_resolve, wasm_sync_guard_staged,
  wasm_sync_compact, wasm_sync_publish_wrap, wasm_sync_rebase_wrap, wasm_sync_same_wrap, wasm_sync_restore_content, wasm_sync_devices, wasm_sync_device_change, wasm_sync_import_pack,
  type Genesis, type Replayed, type RemoteHead } from '../../../crates/vault-sync/pkg/vault_sync.js';

function headOutput(head: RemoteHead) {
  try {
    const history = Array.from({ length: 5 }, (_, index) => head.history_id(index)).filter((value): value is string => !!value);
    return { localHead: Array.from(head.local_head), wrap: Array.from(head.session_wrap), vaultId: head.vault_id, keyEpoch: head.key_epoch,
      snapshotId: head.snapshot_id, snapshotEpoch: head.snapshot_epoch, root: Array.from(head.root), history };
  } finally { head.free(); }
}

function replayOutput(replay: Replayed) {
  try {
    const included = replay.included;
    const compacted = replay.compacted;
    return { head: Array.from(replay.head), snap: Array.from(replay.snap), hlc: replay.hlc, count: replay.count,
      included: included ? included.split('\n') : [], conflicts: Array.from(replay.conflicts), conflictCount: replay.conflict_count,
      draftCount: replay.draft_count,
      receipts: Array.from(replay.receipts), compacted: compacted ? compacted.split('\n') : [] };
  } finally { replay.free(); }
}

function genesisOutput(genesis: Genesis) {
  try { return { head: Array.from(genesis.head), snap: Array.from(genesis.snap), root: Array.from(genesis.root) }; }
  finally { genesis.free(); }
}

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ operation: string; args: unknown[] }>) => {
    try {
      await init();
      let value: unknown;
      if (data.operation === 'sync:local-wal') {
        const args = data.args as [Uint8Array, Uint8Array, string, string, Uint8Array, Uint8Array, Uint8Array, Uint8Array, boolean];
        value = Array.from(wasm_make_local_wal(...args));
      } else if (data.operation === 'sync:verify-local-wal') {
        const args = data.args as [Uint8Array, Uint8Array, string, Uint8Array];
        value = wasm_verify_local_wal(...args);
      } else if (data.operation === 'sync:unlock-head') {
        value = headOutput(wasm_sync_unlock_head(...data.args as Parameters<typeof wasm_sync_unlock_head>));
      } else if (data.operation === 'sync:verify-recovery') {
        value = wasm_sync_verify_recovery(...data.args as Parameters<typeof wasm_sync_verify_recovery>);
      } else if (data.operation === 'sync:authenticate-head') {
        value = headOutput(wasm_sync_authenticate_head(...data.args as Parameters<typeof wasm_sync_authenticate_head>));
      } else if (data.operation === 'sync:genesis') {
        value = genesisOutput(wasm_sync_create_genesis(...data.args as Parameters<typeof wasm_sync_create_genesis>));
      } else if (data.operation === 'sync:compact') {
        value = genesisOutput(wasm_sync_compact(...data.args as Parameters<typeof wasm_sync_compact>));
      } else if (data.operation === 'sync:restore-content') {
        value = replayOutput(wasm_sync_restore_content(...data.args as Parameters<typeof wasm_sync_restore_content>));
      } else if (data.operation === 'sync:import-pack') {
        const result = wasm_sync_import_pack(...data.args as Parameters<typeof wasm_sync_import_pack>);
        try { value = { head: Array.from(result.head), snap: Array.from(result.snap),
          added: result.added, updated: result.updated, skipped: result.skipped }; }
        finally { result.free(); }
      } else if (data.operation === 'sync:devices') {
        value = wasm_sync_devices(...data.args as Parameters<typeof wasm_sync_devices>);
      } else if (data.operation === 'sync:device-change') {
        value = replayOutput(wasm_sync_device_change(...data.args as Parameters<typeof wasm_sync_device_change>));
      } else if (data.operation === 'sync:rebase-wrap') {
        value = Array.from(wasm_sync_rebase_wrap(...data.args as Parameters<typeof wasm_sync_rebase_wrap>));
      } else if (data.operation === 'sync:publish-wrap') {
        value = Array.from(wasm_sync_publish_wrap(...data.args as Parameters<typeof wasm_sync_publish_wrap>));
      } else if (data.operation === 'sync:same-wrap') {
        value = wasm_sync_same_wrap(...data.args as Parameters<typeof wasm_sync_same_wrap>);
      } else if (data.operation === 'sync:verify-snapshot') {
        value = wasm_sync_verify_snapshot(...data.args as Parameters<typeof wasm_sync_verify_snapshot>);
      } else if (data.operation === 'sync:replay') {
        value = replayOutput(wasm_sync_replay(...data.args as Parameters<typeof wasm_sync_replay>));
      } else if (data.operation === 'sync:reconcile') {
        value = replayOutput(wasm_sync_reconcile(...data.args as Parameters<typeof wasm_sync_reconcile>));
      } else if (data.operation === 'sync:adopt') {
        value = replayOutput(wasm_sync_adopt(...data.args as Parameters<typeof wasm_sync_adopt>));
      } else if (data.operation === 'sync:conflicts') {
        value = wasm_sync_conflicts(...data.args as Parameters<typeof wasm_sync_conflicts>);
      } else if (data.operation === 'sync:conflict-stamp') {
        value = wasm_sync_conflict_stamp(...data.args as Parameters<typeof wasm_sync_conflict_stamp>);
      } else if (data.operation === 'sync:resolve-preview') {
        value = wasm_sync_preview_resolutions(...data.args as Parameters<typeof wasm_sync_preview_resolutions>);
      } else if (data.operation === 'sync:resolve') {
        value = replayOutput(wasm_sync_resolve(...data.args as Parameters<typeof wasm_sync_resolve>));
      } else if (data.operation === 'sync:guard-staged') {
        value = wasm_sync_guard_staged(...data.args as Parameters<typeof wasm_sync_guard_staged>);
      } else if (data.operation === 'sync:write-guard') {
        const guard = wasm_sync_write_guard(...data.args as Parameters<typeof wasm_sync_write_guard>);
        try { value = { stamp: guard.stamp, before: guard.before, after: guard.after, removed: guard.removed, blocked: guard.blocked }; }
        finally { guard.free(); }
      } else if (data.operation === 'sync:make-batch') {
        value = Array.from(wasm_sync_make_batch(...data.args as Parameters<typeof wasm_sync_make_batch>));
      } else if (data.operation === 'sync:history-metadata') {
        value = Array.from(wasm_sync_history_metadata(...data.args as Parameters<typeof wasm_sync_history_metadata>));
      } else throw new Error('invalid sync operation');
      self.postMessage({ ok: true, value });
    } catch (error) {
      const conflict = typeof error === 'string' && error.includes('SyncConflict');
      const ancestor = typeof error === 'string' && error.match(/\bSyncAncestorRequired:[1-9]\d{0,15}\b/)?.[0];
      const message = data.operation === 'sync:unlock-head' ? '无法验证网盘密码库，请核对该库自己的主密码或恢复码。' :
        data.operation === 'sync:import-pack' ? '无法读取此备份，请核对文件密码和 .vaultpack 文件是否完整。' :
        data.operation === 'sync:local-wal' ? '同步日志无法保存，本次操作未完成。' :
        typeof error === 'string' && error.includes('InvalidResolutionAdjustment') ? '请填写有效的名称，并缩短超出长度限制的字段。' :
        ancestor ? `缺少可验证的共同快照（${ancestor}）。本机编辑仍在。` :
        conflict ? '此条目正在等待同步裁决，未保存此次修改。请先到网盘设置处理冲突。' : '网盘对象无法验证或版本不受支持。';
      self.postMessage({ ok: false, error: typeof error === 'string' && error.startsWith('COMPACT_OBJECT_TOO_LARGE: ') ? error : message });
    } finally {
      for (const arg of data.args) if (arg instanceof Uint8Array) arg.fill(0);
      data.args.length = 0;
      self.close();
    }
  };
});
