import { EventEmitter } from 'node:events';
import { ReplayWindow } from './replay-window.js';

/** 路径验证未确认前，旧路径上延迟到达的包仍被容忍的宽限期（ms）。 */
const DEFAULT_OLD_PATH_GRACE_MS = 1000;
/** PATH_CHALLENGE 发出后等待 PATH_RESPONSE 的超时时间（ms）。 */
const DEFAULT_VALIDATION_TIMEOUT_MS = 3000;
const DEFAULT_REPLAY_WINDOW_SIZE = 128;

export const ErrorCode = Object.freeze({
  HANDSHAKE_INCOMPLETE: 'handshake_incomplete',
  HANDSHAKE_FAILED: 'handshake_failed',
  CHALLENGE_MISMATCH: 'challenge_mismatch',
  RESPONSE_WRONG_PATH: 'response_wrong_path',
  UNEXPECTED_PATH_RESPONSE: 'unexpected_path_response',
  UNKNOWN_CONNECTION_ID: 'unknown_connection_id',
  PACKET_NUMBER_REGRESSION: 'packet_number_regression',
  ACK_FOR_UNSENT_PACKET: 'ack_for_unsent_packet',
  STALE_PATH_PACKET: 'stale_path_packet',
  VALIDATION_TIMEOUT: 'validation_timeout',
});

/**
 * 规范化地址：接受 "host:port" 字符串或 { host, port } 对象。
 * 返回 { host, port, key }。
 */
function normalizeAddress(addr, field) {
  if (typeof addr === 'string') {
    const idx = addr.lastIndexOf(':');
    if (idx <= 0) throw new TypeError(`invalid ${field} address: ${addr}`);
    return { host: addr.slice(0, idx), port: Number(addr.slice(idx + 1)), key: addr };
  }
  if (addr && typeof addr === 'object' && typeof addr.host === 'string') {
    const port = Number(addr.port);
    return { host: addr.host, port, key: `${addr.host}:${port}` };
  }
  throw new TypeError(`invalid ${field} address`);
}

function normalizePath(src, dst) {
  const s = normalizeAddress(src, 'source');
  const d = normalizeAddress(dst, 'destination');
  return { src: s, dst: d, key: `${s.key}->${d.key}` };
}

/**
 * 事件驱动的 QUIC 连接迁移校验器。
 *
 * 不处理真实网络包，只消费外部投递的事件序列并维护：
 *  - 当前活跃路径（activePath）
 *  - 是否可恢复正常发送（canSend）
 *  - 待验证路径列表（pendingPaths）
 *  - 错误原因列表（errors）
 *
 * 支持的事件（handleEvent / 别名 feed）：
 *  - { type: 'handshake', state: 'started'|'completed'|'failed', connectionId? }
 *  - { type: 'connection_id', action: 'issue'|'retire', connectionId }
 *  - { type: 'packet', packetNumber, src, dst, connectionId, now? }
 *  - { type: 'path_challenge', src, dst, data, packetNumber?, now? }
 *  - { type: 'path_response', src, dst, data, packetNumber?, now? }
 *  - { type: 'window_update', size?, highest? }
 *  - { type: 'ack', ranges: [[lo, hi], ...] } 或 { type: 'ack', packetNumbers: [...] }
 *  - { type: 'clock', now }
 */
export class MigrationValidator extends EventEmitter {
  constructor(options = {}) {
    super();
    this.validationTimeoutMs = options.validationTimeoutMs ?? DEFAULT_VALIDATION_TIMEOUT_MS;
    this.oldPathGraceMs = options.oldPathGraceMs ?? DEFAULT_OLD_PATH_GRACE_MS;
    this.replayWindow = new ReplayWindow(options.replayWindowSize ?? DEFAULT_REPLAY_WINDOW_SIZE);

    this.now = 0;
    this.handshakeState = 'idle'; // idle | started | completed | failed
    this.connectionIds = new Set();
    this.activePath = null; // { src, dst, key, validatedAt }
    this.previousPaths = []; // 最近废弃的路径，宽限期内容忍延迟包
    this.pendingPaths = new Map(); // pathKey -> { path, kind, challenges:Set, detectedAt }
    this.errors = []; // { code, message, at, event? }
    this.notes = []; // 被容忍的异常：重复包、乱序 ACK、旧路径延迟包等
    this.acked = new Set(); // 已被 ACK 的包号
    this.maxPacketSeen = -1;
  }

  /** 事件入口。返回当前状态快照，便于链式断言。 */
  handleEvent(event) {
    if (!event || typeof event.type !== 'string') {
      throw new TypeError('event must have a string type');
    }
    if (typeof event.now === 'number') this.now = event.now;
    switch (event.type) {
      case 'handshake': return this.#onHandshake(event);
      case 'connection_id': return this.#onConnectionId(event);
      case 'packet': return this.#onPacket(event);
      case 'path_challenge': return this.#onPathChallenge(event);
      case 'path_response': return this.#onPathResponse(event);
      case 'window_update': return this.#onWindowUpdate(event);
      case 'ack': return this.#onAck(event);
      case 'clock': return this.#onClock(event);
      default:
        throw new TypeError(`unknown event type: ${event.type}`);
    }
  }

  feed(events) {
    let snapshot;
    for (const event of events) snapshot = this.handleEvent(event);
    return snapshot ?? this.getState();
  }

  /** 当前状态快照：活跃路径、可发送状态、待验证路径、错误原因。 */
  getState() {
    return {
      now: this.now,
      handshakeState: this.handshakeState,
      activePath: this.activePath ? structuredClone(this.activePath) : null,
      canSend: this.#computeCanSend(),
      pendingPaths: [...this.pendingPaths.values()].map((p) => ({
        key: p.path.key,
        src: p.path.src.key,
        dst: p.path.dst.key,
        kind: p.kind,
        detectedAt: p.detectedAt,
        challenges: [...p.challenges],
      })),
      errors: this.errors.map((e) => ({ ...e })),
      notes: this.notes.map((n) => ({ ...n })),
      replayWindow: { size: this.replayWindow.size, highest: this.replayWindow.highest },
    };
  }

  // ---- 事件处理 ----

  #onHandshake(event) {
    const { state, connectionId } = event;
    if (!['started', 'completed', 'failed'].includes(state)) {
      throw new TypeError(`invalid handshake state: ${state}`);
    }
    this.handshakeState = state;
    if (connectionId !== undefined) this.connectionIds.add(connectionId);
    if (state === 'failed') {
      // 迁移进行中握手失败：所有待验证路径作废，禁止发送。
      for (const pending of this.pendingPaths.values()) {
        this.#error(ErrorCode.HANDSHAKE_FAILED,
          `握手失败，作废待验证路径 ${pending.path.key}`, event);
      }
      this.pendingPaths.clear();
      this.emit('handshake_failed');
    }
    return this.getState();
  }

  #onConnectionId(event) {
    if (event.action === 'issue') this.connectionIds.add(event.connectionId);
    else if (event.action === 'retire') this.connectionIds.delete(event.connectionId);
    else throw new TypeError(`invalid connection_id action: ${event.action}`);
    return this.getState();
  }

  #onPacket(event) {
    const { packetNumber, connectionId } = event;
    const path = normalizePath(event.src, event.dst);

    if (connectionId !== undefined && !this.connectionIds.has(connectionId)) {
      this.#error(ErrorCode.UNKNOWN_CONNECTION_ID,
        `未知连接 ID: ${connectionId}`, event);
      return this.getState();
    }

    const replay = this.replayWindow.check(packetNumber);
    this.maxPacketSeen = Math.max(this.maxPacketSeen, packetNumber);
    if (replay.status === 'too_old') {
      this.#error(ErrorCode.PACKET_NUMBER_REGRESSION,
        `包号 ${packetNumber} 低于重放窗口下界 ${this.replayWindow.floor}，疑似重放`, event);
      return this.getState();
    }
    if (replay.status === 'duplicate') {
      this.#note('duplicate_packet', `重复包号 ${packetNumber}，已忽略`, event);
      return this.getState();
    }

    if (!this.activePath) {
      // 初始路径：握手完成前不允许正常发送。
      this.activePath = { ...path, validatedAt: null };
      this.emit('path_established', this.getState().activePath);
      return this.getState();
    }

    if (path.key === this.activePath.key) return this.getState();

    // 旧路径上延迟到达的包：宽限期内容忍，不触发迁移。
    const previous = this.previousPaths.find((p) => p.key === path.key);
    if (previous) {
      if (this.now - previous.retiredAt <= this.oldPathGraceMs) {
        this.#note('late_old_path_packet',
          `旧路径 ${path.key} 上的延迟包 ${packetNumber}，已容忍`, event);
      } else {
        this.#error(ErrorCode.STALE_PATH_PACKET,
          `旧路径 ${path.key} 已超出宽限期，包 ${packetNumber} 被拒绝`, event);
      }
      return this.getState();
    }

    // 新路径：进入待验证状态。握手未完成时不能确认迁移。
    if (this.handshakeState !== 'completed') {
      this.#error(ErrorCode.HANDSHAKE_INCOMPLETE,
        `握手未完成（${this.handshakeState}），路径 ${path.key} 的迁移不能确认`, event);
      return this.getState();
    }

    const kind = this.#classifyMigration(path);
    if (!this.pendingPaths.has(path.key)) {
      this.pendingPaths.set(path.key, {
        path,
        kind,
        challenges: new Set(),
        detectedAt: this.now,
      });
      this.emit('migration_detected', { path: path.key, kind });
    }
    return this.getState();
  }

  #onPathChallenge(event) {
    const path = normalizePath(event.src, event.dst);
    const pending = this.pendingPaths.get(path.key);
    if (!pending) {
      this.#note('challenge_without_pending',
        `路径 ${path.key} 没有待验证迁移，PATH_CHALLENGE 仅作记录`, event);
      return this.getState();
    }
    pending.challenges.add(String(event.data));
    pending.challengedAt = this.now;
    return this.getState();
  }

  #onPathResponse(event) {
    const path = normalizePath(event.src, event.dst);
    const data = String(event.data);

    // 响应必须落在某条待验证路径上。
    const pending = this.pendingPaths.get(path.key);
    if (!pending) {
      // 数据是否匹配其他路径的挑战？若是，则属于“来自错误路径的响应”。
      for (const p of this.pendingPaths.values()) {
        if (p.challenges.has(data)) {
          this.#error(ErrorCode.RESPONSE_WRONG_PATH,
            `PATH_RESPONSE 来自错误路径 ${path.key}，挑战发往 ${p.path.key}`, event);
          return this.getState();
        }
      }
      this.#error(ErrorCode.UNEXPECTED_PATH_RESPONSE,
        `没有待验证路径匹配 ${path.key}，PATH_RESPONSE 被拒绝`, event);
      return this.getState();
    }

    if (!pending.challenges.has(data)) {
      this.#error(ErrorCode.CHALLENGE_MISMATCH,
        `PATH_RESPONSE 数据 ${data} 与路径 ${path.key} 上的挑战不匹配`, event);
      return this.getState();
    }

    // 验证通过：确认迁移。
    if (this.handshakeState !== 'completed') {
      this.#error(ErrorCode.HANDSHAKE_INCOMPLETE,
        `握手未完成，路径 ${path.key} 的迁移不能确认`, event);
      return this.getState();
    }
    this.#confirmMigration(pending, event);
    return this.getState();
  }

  #onWindowUpdate(event) {
    this.replayWindow.update({ size: event.size, highest: event.highest });
    return this.getState();
  }

  #onAck(event) {
    const numbers = [];
    if (Array.isArray(event.ranges)) {
      for (const [lo, hi] of event.ranges) {
        for (let pn = lo; pn <= hi; pn++) numbers.push(pn);
      }
    }
    if (Array.isArray(event.packetNumbers)) numbers.push(...event.packetNumbers);

    // 乱序 ACK 是常态：集合并集天然容忍乱序与重复。
    for (const pn of numbers) {
      if (pn > this.maxPacketSeen) {
        this.#error(ErrorCode.ACK_FOR_UNSENT_PACKET,
          `ACK 确认了未出现过的包号 ${pn}`, event);
        continue;
      }
      if (!this.acked.has(pn)) {
        this.acked.add(pn);
      } else {
        this.#note('duplicate_ack', `包号 ${pn} 被重复 ACK`, event);
      }
    }
    return this.getState();
  }

  #onClock(event) {
    this.now = event.now;
    // 检查待验证路径是否超时。
    for (const [key, pending] of this.pendingPaths) {
      const since = pending.challengedAt ?? pending.detectedAt;
      if (this.now - since > this.validationTimeoutMs) {
        this.pendingPaths.delete(key);
        this.#error(ErrorCode.VALIDATION_TIMEOUT,
          `路径 ${key} 验证超时，保持原活跃路径`, event);
        this.emit('validation_timeout', { path: key });
      }
    }
    return this.getState();
  }

  // ---- 内部逻辑 ----

  /** 区分主动迁移与 NAT 重绑定：源主机相同、仅端口变化视为 NAT 重绑定。 */
  #classifyMigration(path) {
    const active = this.activePath;
    if (
      active &&
      path.src.host === active.src.host &&
      path.dst.key === active.dst.key &&
      path.src.port !== active.src.port
    ) {
      return 'nat_rebinding';
    }
    return 'migration';
  }

  #confirmMigration(pending, event) {
    // 旧活跃路径进入宽限期，容忍延迟到达的包。
    if (this.activePath) {
      this.previousPaths.push({ ...this.activePath, retiredAt: this.now });
    }
    this.activePath = { ...pending.path, validatedAt: this.now, kind: pending.kind };

    // 多路径竞争：其余待验证路径被取代。
    for (const [key, p] of this.pendingPaths) {
      if (key !== pending.path.key) {
        this.#note('superseded_path',
          `待验证路径 ${key} 被 ${pending.path.key} 取代`, event);
      }
    }
    this.pendingPaths.clear();
    this.emit('migration_confirmed', this.getState().activePath);
  }

  #computeCanSend() {
    if (this.handshakeState !== 'completed') return false;
    if (!this.activePath) return false;
    // 有待验证路径时，代理不得过早恢复正常发送。
    if (this.pendingPaths.size > 0) return false;
    return this.activePath.validatedAt !== null || this.previousPaths.length === 0;
  }

  #error(code, message, event) {
    const entry = { code, message, at: this.now };
    this.errors.push(entry);
    this.emit('error_recorded', entry);
    return entry;
  }

  #note(kind, message, event) {
    const entry = { kind, message, at: this.now };
    this.notes.push(entry);
    this.emit('note', entry);
    return entry;
  }
}
