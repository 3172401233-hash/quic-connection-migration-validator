# quic-connection-migration-validator

事件驱动的 QUIC 连接迁移校验器（Node.js 24.16.0）。

> **重要：本库只验证事件序列，不处理真实网络包。**
> 它不解析 UDP 数据报、不执行 QUIC 加密、不与任何套接字交互。
> 调用方（如代理、中间盒或测试框架）负责把观测到的握手状态、包号、
> 地址与控制帧抽象成事件投递进来，本库只对这组事件序列做一致性校验，
> 回答"当前连接迁移到哪条路径、现在能不能恢复正常发送"。

## 校验内容

- 迁移前后的源/目标地址变化，区分主动迁移与同地址 NAT 重绑定（源端口变化）
- 路径验证状态机：PATH_CHALLENGE / PATH_RESPONSE 配对，响应必须来自挑战所在路径
- 防重放滑动窗口：重复包、包号回退（重放）、WINDOW_UPDATE 窗口滑动
- 乱序与重复 ACK 的合并，以及 ACK 确认未发送包号的检测
- 旧路径上延迟到达的包（宽限期内容忍，超期拒绝）
- 连续多次迁移与多路径竞争（先完成验证者胜出，其余被取代）
- 验证超时（通过时钟事件驱动）

以下情况一律不确认迁移：

- 握手未完成或握手失败
- PATH_RESPONSE 数据与挑战不匹配（伪造响应）
- PATH_RESPONSE 来自错误的路径（跨路径回放）

## 使用

```js
import { MigrationValidator } from './src/validator.js';

const v = new MigrationValidator({
  validationTimeoutMs: 3000,  // PATH_CHALLENGE 超时
  oldPathGraceMs: 1000,       // 旧路径延迟包宽限期
  replayWindowSize: 128,      // 防重放窗口大小
});

v.handleEvent({ type: 'handshake', state: 'completed', connectionId: 'cid-1' });
v.handleEvent({ type: 'packet', packetNumber: 0, src: '203.0.113.10:5000', dst: '192.0.2.1:4433', connectionId: 'cid-1' });

// 客户端切换到新网络：新路径出现，进入待验证状态，canSend 变为 false
v.handleEvent({ type: 'packet', packetNumber: 1, src: '198.51.100.20:5000', dst: '192.0.2.1:4433', connectionId: 'cid-1' });
v.handleEvent({ type: 'path_challenge', src: '198.51.100.20:5000', dst: '192.0.2.1:4433', data: 'abc' });
v.handleEvent({ type: 'path_response', src: '198.51.100.20:5000', dst: '192.0.2.1:4433', data: 'abc' });

console.log(v.getState());
// { activePath: ..., canSend: true, pendingPaths: [], errors: [], ... }
```

### 事件类型

| type | 字段 | 说明 |
| --- | --- | --- |
| `handshake` | `state: started\|completed\|failed`, `connectionId?` | 握手状态迁移 |
| `connection_id` | `action: issue\|retire`, `connectionId` | 连接 ID 注册/退役 |
| `packet` | `packetNumber`, `src`, `dst`, `connectionId`, `now?` | 观测到的包（触发迁移检测与重放检查） |
| `path_challenge` | `src`, `dst`, `data`, `now?` | 在某条待验证路径上发出的挑战 |
| `path_response` | `src`, `dst`, `data`, `now?` | 路径验证响应 |
| `window_update` | `size?`, `highest?` | 调整防重放窗口 |
| `ack` | `ranges: [[lo, hi]]` 或 `packetNumbers: [...]` | ACK，可乱序 |
| `clock` | `now` | 时钟推进，驱动验证超时 |

地址可以是 `"host:port"` 字符串或 `{ host, port }` 对象。

### 状态输出

`getState()` 返回：

- `activePath`：当前活跃路径（含 `validatedAt` 与 `kind: migration | nat_rebinding`）
- `canSend`：是否可恢复正常发送（握手完成且无待验证路径时才为 `true`，避免代理过早恢复发送）
- `pendingPaths`：待验证路径及其待匹配的挑战数据
- `errors`：错误原因列表（`handshake_incomplete`、`challenge_mismatch`、`response_wrong_path`、`packet_number_regression`、`stale_path_packet`、`validation_timeout` 等）
- `notes`：被容忍的异常（重复包、重复 ACK、旧路径延迟包、被取代路径）

同时继承 `EventEmitter`，可监听 `migration_detected`、`migration_confirmed`、`validation_timeout`、`error_recorded` 等事件。

## 测试

```sh
node --test
```

覆盖：正常迁移、伪造响应（数据不匹配 / 错误路径）、包号回退、重复包、
迁移中握手失败、握手未完成迁移、同地址 NAT 重绑定、连续多次迁移、
多路径竞争、乱序 ACK、旧路径延迟到达、验证超时、未知连接 ID。
