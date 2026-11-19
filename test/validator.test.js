import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MigrationValidator, ErrorCode } from '../src/validator.js';

const CLIENT_A = '203.0.113.10:5000';
const CLIENT_A_REBIND = '203.0.113.10:6000';
const CLIENT_B = '198.51.100.20:5000';
const CLIENT_C = '192.0.2.30:5000';
const SERVER = '192.0.2.1:4433';
const CID = 'cid-initial';

function established() {
  const v = new MigrationValidator();
  v.feed([
    { type: 'handshake', state: 'started', connectionId: CID },
    { type: 'handshake', state: 'completed' },
    { type: 'packet', packetNumber: 0, src: CLIENT_A, dst: SERVER, connectionId: CID },
  ]);
  return v;
}

function startMigration(v, src, pn, challenge) {
  v.handleEvent({ type: 'packet', packetNumber: pn, src, dst: SERVER, connectionId: CID });
  v.handleEvent({ type: 'path_challenge', src, dst: SERVER, data: challenge });
}

test('正常迁移：挑战匹配且响应来自同一路径后确认', () => {
  const v = established();
  assert.equal(v.getState().activePath.src.key, CLIENT_A);
  assert.equal(v.getState().canSend, true);

  startMigration(v, CLIENT_B, 1, 'challenge-1');
  let state = v.getState();
  assert.equal(state.canSend, false);
  assert.equal(state.pendingPaths.length, 1);
  assert.equal(state.pendingPaths[0].kind, 'migration');
  assert.equal(state.activePath.src.key, CLIENT_A);

  state = v.handleEvent({
    type: 'path_response', src: CLIENT_B, dst: SERVER, data: 'challenge-1',
  });
  assert.equal(state.activePath.src.key, CLIENT_B);
  assert.equal(state.canSend, true);
  assert.equal(state.pendingPaths.length, 0);
  assert.equal(state.errors.length, 0);
});

test('伪造响应：挑战数据不匹配时拒绝确认', () => {
  const v = established();
  startMigration(v, CLIENT_B, 1, 'real-challenge');

  const state = v.handleEvent({
    type: 'path_response', src: CLIENT_B, dst: SERVER, data: 'forged-data',
  });
  assert.equal(state.activePath.src.key, CLIENT_A);
  assert.equal(state.canSend, false);
  assert.equal(state.errors.at(-1).code, ErrorCode.CHALLENGE_MISMATCH);
  assert.equal(state.pendingPaths.length, 1);
});

test('伪造响应：响应来自错误路径时拒绝确认', () => {
  const v = established();
  startMigration(v, CLIENT_B, 1, 'challenge-x');

  const state = v.handleEvent({
    type: 'path_response', src: CLIENT_C, dst: SERVER, data: 'challenge-x',
  });
  assert.equal(state.activePath.src.key, CLIENT_A);
  assert.equal(state.canSend, false);
  assert.equal(state.errors.at(-1).code, ErrorCode.RESPONSE_WRONG_PATH);
});

test('无待验证路径时的意外 PATH_RESPONSE 被拒绝', () => {
  const v = established();
  const state = v.handleEvent({
    type: 'path_response', src: CLIENT_B, dst: SERVER, data: 'whatever',
  });
  assert.equal(state.errors.at(-1).code, ErrorCode.UNEXPECTED_PATH_RESPONSE);
  assert.equal(state.activePath.src.key, CLIENT_A);
});

test('包号回退：低于重放窗口下界的包被拒绝', () => {
  const v = new MigrationValidator({ replayWindowSize: 8 });
  v.feed([
    { type: 'handshake', state: 'completed', connectionId: CID },
    { type: 'packet', packetNumber: 100, src: CLIENT_A, dst: SERVER, connectionId: CID },
  ]);
  const state = v.handleEvent({
    type: 'packet', packetNumber: 90, src: CLIENT_A, dst: SERVER, connectionId: CID,
  });
  assert.equal(state.errors.at(-1).code, ErrorCode.PACKET_NUMBER_REGRESSION);
});

test('重复包与窗口滑动：重复包被容忍并记录', () => {
  const v = established();
  v.handleEvent({
    type: 'packet', packetNumber: 1, src: CLIENT_A, dst: SERVER, connectionId: CID,
  });
  let state = v.handleEvent({
    type: 'packet', packetNumber: 1, src: CLIENT_A, dst: SERVER, connectionId: CID,
  });
  assert.equal(state.errors.length, 0);
  assert.equal(state.notes.at(-1).kind, 'duplicate_packet');

  v.handleEvent({ type: 'window_update', size: 2 });
  v.handleEvent({
    type: 'packet', packetNumber: 10, src: CLIENT_A, dst: SERVER, connectionId: CID,
  });
  state = v.handleEvent({
    type: 'packet', packetNumber: 8, src: CLIENT_A, dst: SERVER, connectionId: CID,
  });
  assert.equal(state.errors.at(-1).code, ErrorCode.PACKET_NUMBER_REGRESSION);
});

test('迁移中握手失败：待验证路径作废且不可发送', () => {
  const v = established();
  startMigration(v, CLIENT_B, 1, 'challenge-1');

  const state = v.handleEvent({ type: 'handshake', state: 'failed' });
  assert.equal(state.canSend, false);
  assert.equal(state.pendingPaths.length, 0);
  assert.ok(state.errors.some((e) => e.code === ErrorCode.HANDSHAKE_FAILED));

  const after = v.handleEvent({
    type: 'path_response', src: CLIENT_B, dst: SERVER, data: 'challenge-1',
  });
  assert.equal(after.activePath.src.key, CLIENT_A);
  assert.equal(after.canSend, false);
});

test('握手未完成时迁移不能确认', () => {
  const v = new MigrationValidator();
  v.feed([
    { type: 'handshake', state: 'started', connectionId: CID },
    { type: 'packet', packetNumber: 0, src: CLIENT_A, dst: SERVER, connectionId: CID },
  ]);
  assert.equal(v.getState().canSend, false);

  const state = v.handleEvent({
    type: 'packet', packetNumber: 1, src: CLIENT_B, dst: SERVER, connectionId: CID,
  });
  assert.equal(state.errors.at(-1).code, ErrorCode.HANDSHAKE_INCOMPLETE);
  assert.equal(state.activePath.src.key, CLIENT_A);
  assert.equal(state.pendingPaths.length, 0);
});

test('同地址 NAT 重绑定：源端口变化被识别且仍需验证', () => {
  const v = established();
  startMigration(v, CLIENT_A_REBIND, 1, 'rebind-challenge');
  let state = v.getState();
  assert.equal(state.pendingPaths[0].kind, 'nat_rebinding');
  assert.equal(state.canSend, false);

  state = v.handleEvent({
    type: 'path_response', src: CLIENT_A_REBIND, dst: SERVER, data: 'rebind-challenge',
  });
  assert.equal(state.activePath.src.key, CLIENT_A_REBIND);
  assert.equal(state.canSend, true);
});

test('连续多次迁移：每次都需要独立验证', () => {
  const v = established();
  startMigration(v, CLIENT_B, 1, 'c1');
  v.handleEvent({ type: 'path_response', src: CLIENT_B, dst: SERVER, data: 'c1' });
  assert.equal(v.getState().activePath.src.key, CLIENT_B);

  startMigration(v, CLIENT_C, 2, 'c2');
  assert.equal(v.getState().canSend, false);
  const state = v.handleEvent({
    type: 'path_response', src: CLIENT_C, dst: SERVER, data: 'c2',
  });
  assert.equal(state.activePath.src.key, CLIENT_C);
  assert.equal(state.canSend, true);
  assert.equal(state.errors.length, 0);
});

test('多路径竞争：先完成验证的路径胜出，其余被取代', () => {
  const v = established();
  startMigration(v, CLIENT_B, 1, 'cb');
  startMigration(v, CLIENT_C, 2, 'cc');
  assert.equal(v.getState().pendingPaths.length, 2);
  assert.equal(v.getState().canSend, false);

  const state = v.handleEvent({
    type: 'path_response', src: CLIENT_C, dst: SERVER, data: 'cc',
  });
  assert.equal(state.activePath.src.key, CLIENT_C);
  assert.equal(state.pendingPaths.length, 0);
  assert.ok(state.notes.some((n) => n.kind === 'superseded_path'));

  const late = v.handleEvent({
    type: 'path_response', src: CLIENT_B, dst: SERVER, data: 'cb',
  });
  assert.equal(late.errors.at(-1).code, ErrorCode.UNEXPECTED_PATH_RESPONSE);
  assert.equal(late.activePath.src.key, CLIENT_C);
});

test('乱序 ACK 被合并，确认未发送包号报错', () => {
  const v = established();
  v.feed([
    { type: 'packet', packetNumber: 1, src: CLIENT_A, dst: SERVER, connectionId: CID },
    { type: 'packet', packetNumber: 2, src: CLIENT_A, dst: SERVER, connectionId: CID },
    { type: 'packet', packetNumber: 3, src: CLIENT_A, dst: SERVER, connectionId: CID },
  ]);
  v.handleEvent({ type: 'ack', ranges: [[2, 3]] });
  let state = v.handleEvent({ type: 'ack', ranges: [[0, 1]] });
  assert.equal(state.errors.length, 0);

  state = v.handleEvent({ type: 'ack', packetNumbers: [99] });
  assert.equal(state.errors.at(-1).code, ErrorCode.ACK_FOR_UNSENT_PACKET);
});

test('旧路径延迟到达：宽限期内容忍，超期拒绝', () => {
  const v = new MigrationValidator({ oldPathGraceMs: 1000 });
  v.feed([
    { type: 'handshake', state: 'completed', connectionId: CID },
    { type: 'packet', packetNumber: 0, src: CLIENT_A, dst: SERVER, connectionId: CID, now: 0 },
  ]);
  v.handleEvent({ type: 'packet', packetNumber: 1, src: CLIENT_B, dst: SERVER, connectionId: CID, now: 100 });
  v.handleEvent({ type: 'path_challenge', src: CLIENT_B, dst: SERVER, data: 'c1', now: 100 });
  v.handleEvent({ type: 'path_response', src: CLIENT_B, dst: SERVER, data: 'c1', now: 200 });

  let state = v.handleEvent({
    type: 'packet', packetNumber: 2, src: CLIENT_A, dst: SERVER, connectionId: CID, now: 500,
  });
  assert.equal(state.errors.length, 0);
  assert.equal(state.notes.at(-1).kind, 'late_old_path_packet');
  assert.equal(state.activePath.src.key, CLIENT_B);

  state = v.handleEvent({
    type: 'packet', packetNumber: 3, src: CLIENT_A, dst: SERVER, connectionId: CID, now: 5000,
  });
  assert.equal(state.errors.at(-1).code, ErrorCode.STALE_PATH_PACKET);
});

test('验证超时：时钟事件使待验证路径过期，保持原路径可发送', () => {
  const v = new MigrationValidator({ validationTimeoutMs: 3000 });
  v.feed([
    { type: 'handshake', state: 'completed', connectionId: CID },
    { type: 'packet', packetNumber: 0, src: CLIENT_A, dst: SERVER, connectionId: CID, now: 0 },
    { type: 'packet', packetNumber: 1, src: CLIENT_B, dst: SERVER, connectionId: CID, now: 100 },
    { type: 'path_challenge', src: CLIENT_B, dst: SERVER, data: 'c1', now: 100 },
  ]);
  assert.equal(v.getState().canSend, false);

  const state = v.handleEvent({ type: 'clock', now: 5000 });
  assert.equal(state.pendingPaths.length, 0);
  assert.ok(state.errors.some((e) => e.code === ErrorCode.VALIDATION_TIMEOUT));
  assert.equal(state.activePath.src.key, CLIENT_A);
  assert.equal(state.canSend, true);
});

test('未知连接 ID 的包被拒绝', () => {
  const v = established();
  const state = v.handleEvent({
    type: 'packet', packetNumber: 1, src: CLIENT_A, dst: SERVER, connectionId: 'cid-unknown',
  });
  assert.equal(state.errors.at(-1).code, ErrorCode.UNKNOWN_CONNECTION_ID);
});
