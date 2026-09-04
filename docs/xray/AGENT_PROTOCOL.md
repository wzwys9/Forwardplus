# Xray Agent 协议

状态：Xray v1 合同已实施；UDP 使用 v1 envelope 的可选能力扩展；managed services v1 合同已批准并首先实施 MTProto；TASK057 快速配置复用既有探测/规则合同，并为隧道派生端口回收增加可选运行观测字段。与 `SPEC.md` 0.21 配套。

## 1. 传输原则

- 复用 Agent 主动连接面板的现有 HTTPS、加密 envelope、心跳和 SSE 通道，不在 Agent 主机开放管理端口。
- Xray 字段作为现有载荷的可选扩展；旧 Agent 忽略未知字段，面板根据 capability 禁止对旧 Agent 创建节点。
- 配置同步使用 desired state；端口、扫描、安装和显式重启使用带 `taskId` 的 typed task。
- 所有时间使用 UTC RFC3339 或现有协议约定的 Unix 时间；同一字段不得混用。
- 所有列表、字符串、JSON 和输出都有明确上限，禁止无界 payload。

## 2. Capability

在注册、完整/压缩心跳和加密 SSE 握手中，Agent 与现有 `agentVersion` 一起发送以下向后兼容字段：

```json
{
  "agentVersion": "2.3.0",
  "agentDistribution": "forwardplus",
  "agentBuildId": "0123456789ab"
}
```

- `agentVersion` 始终是真实语义版本，不能为迁移临时抬高。
- Forwardplus 官方构建固定发送 `agentDistribution=forwardplus`；`agentBuildId` 最大 64 字符，只用于诊断和发布追踪。
- 旧 Agent 缺少来源时仍能注册和保持现有数据面，但面板把它标为来源未确认并列入迁移候选。
- Forwardplus 专有 desired state、typed task 和能力判断除原版本/capability 条件外，还必须要求发行来源为 `forwardplus`。来源不匹配时只允许既有兼容心跳、升级命令和安全迁移，不把更高版本号当作专有能力证明。
- 升级请求可携带可选 `targetDistribution`；Agent 可忽略该加法字段。面板必须等后续报告同时满足来源和版本才清除升级请求。

Agent 在心跳静态信息发生变化或周期刷新时上报：

```json
{
  "xrayCapability": {
    "schemaVersion": 1,
    "supported": true,
    "supervisor": "AGENT_CHILD",
    "supportsPortProbe": true,
    "supportsUdpPortProbe": true,
    "supportsUdpListenerReadiness": true,
    "supportsRealityScan": true,
    "supportsArtifactInstall": true,
    "supportedOS": "linux",
    "supportedArch": "amd64"
  }
}
```

约束：

- `schemaVersion` 当前只允许 `1`。
- `supportsUdpPortProbe` 与 `supportsUdpListenerReadiness` 是可选加法字段；缺失或非 `true` 均按不支持。面板只有在两项均为 `true` 时才向该主机创建或下发 UDP profile。
- `supervisor` 第一版固定为 `AGENT_CHILD`；未知值按 capability 不兼容处理。
- `supportedArch` 从 Agent 的 Go runtime/受信本机信息自动识别，第一版只允许 `amd64` 或 `arm64`。
- `supported=false` 时可以附带短错误码，但不得附带任意命令输出。
- 面板只持久化通过 schema 校验的 capability OS/arch、功能布尔值和稳定错误码；非法报告清空能力投影，禁止从 `osInfo`/`cpuInfo` 展示文本补全。
- 面板创建选择器必须同时检查在线状态、心跳新鲜度、schemaVersion、OS/arch 制品可用性。

## 3. Desired state

面板在现有 desired state 中增加可选 `xray` 字段：

```json
{
  "schemaVersion": 1,
  "generation": 12,
  "issuedAt": "2026-09-01T08:00:00Z",
  "targetVersion": "v26.3.27",
  "configHash": "64-char-lowercase-sha256",
  "configEncoding": "JSON_UTF8",
  "configJson": "{...panel-generated Xray config...}",
  "expectedListeners": [
    {
      "inboundId": 101,
      "runtimeTag": "forwardx-inbound-01J...",
      "network": "tcp",
      "listenAddress": "0.0.0.0",
      "port": 23456
    }
  ]
}
```

字段语义：

- `generation`：该主机 Xray 期望状态的单调递增整数。
- `configHash`：对 `configJson` 的精确 UTF-8 字节计算 SHA-256。面板必须先用稳定生成器产生规范化 JSON；Agent 不重新序列化后比较。
- `configJson`：面板生成的完整 Xray 配置，可能含运行所需的私钥和 UUID。只能存在于加密通道和权限 `0600` 的本地文件，不得进入日志/operation 元数据。
- `expectedListeners`：不含密钥的就绪检查清单，Agent 无需从任意 JSON 推断控制信息。
- 空 `expectedListeners` 表示期望没有受管 inbound；具体是停止但保留安装，还是保持空配置运行，由运行生命周期文档决定。

一次完整 reconciliation 只构建一次 Xray desired state；SSE 即时推送和 heartbeat 响应回退必须复用完全相同的 `generation`、`configHash` 和 `configJson` 字节，不能分别生成。

Agent 必须以 `(schemaVersion, generation, configHash)` 为幂等身份。generation 相同但 hash 不同是 `GENERATION_HASH_CONFLICT`，不得静默覆盖。

heartbeat fallback 与 SSE 推送进入同一个有界串行应用队列：最多保留一个正在应用和一个最新的待应用快照；同时到达的相同 identity 共享一次应用结果。入队前 Agent 必须验证 schema、固定版本、精确 config bytes/hash 和 expected listeners；已接收的最高 generation 不能被更低 generation 或同 generation 的不同 hash 替换。队列使用独立本地运行 context，不绑定 heartbeat/SSE 请求取消。

## 4. Observed state

Agent 每次心跳发送 `xrayStateSignature`。完整状态只在签名变化、面板请求或周期审计时发送，沿用现有 local runtime state 压缩模式。

面板必须在 heartbeat 的 busy/coalesced 提前返回之前处理 capability 和 observed 摘要。capability 兼容但面板没有对应完整状态缓存、签名变化、完整 payload/schema/signature 校验失败或数据库缓存重新校验失败时，响应返回 `requestXrayState: true`；旧 Agent 缺少这些可选字段时继续按不支持处理，不返回强制 Xray 字段。

```json
{
  "xrayStateSignature": "64-char-lowercase-sha256",
  "xrayState": {
    "schemaVersion": 1,
    "isInstalled": true,
    "installedVersion": "v26.3.27",
    "runningVersion": "v26.3.27",
    "serviceStatus": "RUNNING",
    "processId": 2145,
    "binarySha256": "64-char-lowercase-sha256",
    "appliedGeneration": 12,
    "appliedConfigHash": "64-char-lowercase-sha256",
    "listeners": [
      {
        "runtimeTag": "forwardx-inbound-01J...",
        "network": "tcp",
        "port": 23456,
        "status": "READY"
      }
    ],
    "lastError": null,
    "observedAt": "2026-09-01T08:00:05Z"
  }
}
```

允许的 `serviceStatus`：`RUNNING`、`STOPPED`、`ERROR`、`UNKNOWN`。

listener `status`：`READY`、`MISSING`、`WRONG_PROCESS`、`UNKNOWN`。

observed state 禁止包含：

- `configJson` 或磁盘配置内容。
- Reality 私钥。
- 客户端 UUID、shortId、名称或分享链接。
- Agent Token。
- 无界 stdout/stderr。

`lastError` 结构固定为 `{ code, message, generation, occurredAt }`，message 先脱敏并限制长度。

desired 应用失败时 Agent 只把稳定错误码、目标 generation 和本地固定通用摘要合并到下一次完整 observed state；不得放入 config、命令输出或底层错误文本。一次成功应用（包括真实 runtime 一致时的幂等复用）清除该临时失败。

面板按 v1 固定字段顺序重新计算签名，计算前把 `observedAt` 和 `lastError.occurredAt` 置空，再对 UTF-8 JSON 计算 SHA-256。只有完整状态通过递归 schema、禁用字段、大小和签名校验后才能更新缓存；仅签名上报复用缓存时还必须重新验证数据库字段和 `listenersJson`。

## 5. 任务 envelope

```json
{
  "schemaVersion": 1,
  "taskId": "uuid-or-random-id",
  "type": "PORT_PROBE",
  "createdAt": "2026-09-01T08:00:00Z",
  "expiresAt": "2026-09-01T08:00:30Z",
  "payload": {}
}
```

通用规则：

- 面板可在受鉴权 heartbeat 响应的可选 `xrayTasks` 数组中下发 task envelope；旧 Agent 忽略该未知字段，新 Agent 必须在任何 local-state 提前返回前接收任务。
- Agent 在 heartbeat 请求的可选 `xrayTaskResults` 数组中批量上报本地终态结果；面板只在结果通过 schema、host 和 operation 校验并已持久化后，才把对应 taskId 放入响应的 `acceptedXrayTaskResults`。
- `taskId` 在面板中唯一，Agent 必须持久化终态结果，重复任务返回相同结果或明确 `TASK_ALREADY_COMPLETED`。
- 过期任务不执行，返回 `TASK_EXPIRED`。
- Agent 对改变 Xray 的任务串行化；只读端口/Reality 探测采用有界并发。
- 制品安装/升级使用独立的单 worker、有界队列（第一版容量 16）；端口与 Reality 探测继续使用独立的 4 worker、有界队列（第一版容量 64）。长时间下载不得占满交互探测 worker，队列满时由面板重试，不在日志中写入任务载荷或认证信息。
- task result 上报失败时写入 `/var/lib/forwardx-agent/xray/task-results/` 下权限 `0600` 的结果队列，恢复通信后重试；Agent 只能删除本次已提交且被 `acceptedXrayTaskResults` 明确确认的文件。
- 任务类型和 payload 使用判别联合，禁止把 Shell command 作为 payload。

## 6. `PORT_PROBE`

请求：

```json
{
  "network": "tcp",
  "listenAddress": "0.0.0.0",
  "ports": [23456, 23501, 25123]
}
```

结果：

```json
{
  "ports": [
    { "port": 23456, "available": true, "errorCode": null },
    { "port": 23501, "available": false, "errorCode": "PORT_IN_USE" }
  ],
  "observedAt": "2026-09-01T08:00:02Z"
}
```

约束：

- 第一版只允许 TCP、`1000–65535`、每任务最多 32 个候选。
- Agent 使用真实 bind/close 检测，不通过解析 `ss` 文本猜测可用性。
- 结果短期有效，不能保证 bind 后没有其他进程抢占；最终应用仍需处理 `EADDRINUSE`。
- 不返回占用端口的进程命令行，避免泄露主机信息。

## 7. `REALITY_SCAN`

请求：

```json
{
  "targets": ["www.cloudflare.com:443", "www.amazon.com:443"],
  "timeoutMs": 10000,
  "maxConcurrency": 16
}
```

单项结果字段：

```json
{
  "target": "www.amazon.com:443",
  "host": "www.amazon.com",
  "resolvedIp": "203.0.113.10",
  "port": 443,
  "feasible": true,
  "tls13": true,
  "h2": true,
  "x25519": true,
  "certificateValid": true,
  "serverNames": ["www.amazon.com"],
  "latencyMs": 83,
  "reasonCode": null
}
```

约束：

- 第一版最多 64 个公网域名目标；不接受 CIDR、URL path、认证信息或私网 IP。
- Agent 必须解析全部 A/AAAA 结果并拒绝任何被安全策略禁止的地址；连接使用已经验证并固定的地址，避免 DNS rebinding。
- 每个目标最多接受 16 个去重后的 A/AAAA 地址；超过上限或公网/禁止地址混合时整体拒绝。策略拒绝不回传被禁止地址，`resolvedIp` 使用 `redacted`；尚未得到安全地址的解析失败使用 `unresolved`。
- TLS 诊断始终连接同一个已验证固定 IP 并保留原域名 SNI：普通握手判断 TLS 1.3、ALPN h2 和证书链/主机名，第二次强制 TLS 1.3 + X25519 握手判断 X25519。扫描不发送 HTTP 请求数据。
- 不跟随应用层重定向。
- 结果按 feasible 优先、延迟升序返回；失败使用稳定 reasonCode 和简短脱敏消息。

## 8. `INSTALL` 与 `UPGRADE`

创建首个 inbound 的按需安装复用该创建请求的顶层 `SYNC operationId` 作为 `INSTALL taskId`；数据库 operation 类型仍为 `SYNC`，安全 `requestMetaJson` 只记录安装阶段和固定 artifact 元数据。Agent 必须按 taskId 从 `0600` 终态 spool 幂等重放，同一任务不能重复下载。面板明确接受安装成功结果后才投递对应 generation 的 desired；失败只保存稳定错误码和通用摘要。

管理员显式安装使用 `INSTALL operation/task`，制品验证成功即可结束安装 operation；显式升级使用 `UPGRADE operation/task`，制品 task 只把新版本写入独立目录。升级 operation 随后保持非终态并投递现有结构化 desired，只有 Agent 原子应用新 binary/config 且 observed 精确收敛后才成功。普通 `SYNC` 不生成 `UPGRADE` task，已装版本低于目标时返回版本不匹配；已装版本高于目标时拒绝降级。

请求只引用面板制品，不接受任意 URL：

```json
{
  "artifactId": 7,
  "version": "v26.3.27",
  "os": "linux",
  "arch": "amd64",
  "size": 17234567,
  "sha256": "64-char-lowercase-sha256",
  "downloadPath": "/api/agent/artifacts/xray/7"
}
```

Agent 必须：

1. 使用当前 Agent 认证访问相同面板 origin 下的固定 path；GET 请求必须发送从 Go runtime/capability 得到的 `X-ForwardX-Xray-OS` 和 `X-ForwardX-Xray-Arch`，面板只在 Token 已映射到 host 后使用这两个受限值做制品匹配，不从 `osInfo`/`cpuInfo` 展示文本猜测平台。
2. 限制响应大小和下载时间。
3. 校验 size、SHA-256、归档路径和二进制版本。
4. 写入新版本目录，不覆盖 current 正在使用的文件。
5. 只有验证和运行测试成功才原子切换 current。
6. 升级失败恢复旧版本并上报终态。

## 9. `RESTART`

- 只接受 `{ "reason": "ADMIN_REQUEST" }` 等固定枚举，不接受命令。
- 重启前检查已提交的 current config/state（本地 last-good 运行快照）存在、hash/路径有效，并用 current binary 执行 config test。
- 结果报告重启前后版本、服务状态和就绪监听数量，不返回日志全文。
- 重启启动失败时先尝试恢复同一已提交 binary/config；恢复成功仍把管理员 operation 标为失败，恢复也失败则上报 `ROLLBACK_FAILED`。

配置正常同步不依赖 `RESTART` task；desired state apply 自己管理所需的重载或重启。

## 10. 任务结果

```json
{
  "schemaVersion": 1,
  "taskId": "same-as-request",
  "type": "PORT_PROBE",
  "status": "SUCCESS",
  "startedAt": "2026-09-01T08:00:01Z",
  "finishedAt": "2026-09-01T08:00:02Z",
  "result": {},
  "error": null
}
```

状态：`SUCCESS`、`FAILED`、`TIMEOUT`、`REJECTED`。

错误结构：`{ code, message, retryable }`。message 不作为程序判断依据。

## 11. 稳定错误码

第一版至少定义：

- `CAPABILITY_UNSUPPORTED`
- `TASK_EXPIRED`
- `TASK_ALREADY_COMPLETED`
- `INVALID_PAYLOAD`
- `HOST_PLATFORM_UNSUPPORTED`
- `PORT_IN_USE`
- `PORT_BIND_DENIED`
- `REALITY_TARGET_BLOCKED`
- `REALITY_TLS_UNSUPPORTED`
- `ARTIFACT_NOT_FOUND`
- `ARTIFACT_SIZE_MISMATCH`
- `ARTIFACT_HASH_MISMATCH`
- `ARTIFACT_ARCH_MISMATCH`
- `XRAY_VERSION_MISMATCH`
- `CONFIG_INVALID`
- `GENERATION_HASH_CONFLICT`
- `RUNTIME_START_FAILED`
- `RUNTIME_NOT_READY`
- `ROLLBACK_FAILED`
- `INTERNAL_ERROR`

新增错误码是向后兼容操作；不得改变已发布错误码含义。

## 12. 限制和超时基线

具体值可以在实现测试后收紧，但不得无界：

- desired `configJson`：最大 1 MiB。
- expected listeners：最大 256。
- PORT_PROBE 候选：最大 32，任务 15 秒。
- REALITY_SCAN 候选：最大 64，并发最大 16，单目标最大 10 秒，总任务最大 60 秒。
- task result：最大 256 KiB。
- 错误消息：最大 2 KiB。
- taskId/runtimeTag：最大 128 字符且符合固定字符集。

## 13. 合同测试

- TypeScript 和 Go 使用同一组 `docs/xray/examples/*.json` 验证解码和必填字段。
- 旧 Agent payload 缺少 `xrayCapability` 时，面板视为不支持，不报解析错误。
- 新 payload 增加未知可选字段时，旧实现不得失败。
- 非法枚举、超限数组、私钥出现在 observed state、generation/hash 冲突都必须被测试拒绝。

## 14. 多协议扩展

### 14.1 Xray-native TCP profile

- VLESS、Trojan、VMess、Shadowsocks 等 TCP profile 不改变 desired 应用协议；面板仍下发完整 `configJson`、`generation`、`configHash` 和 `expectedListeners`。
- `TUNNEL_TCP_LOCAL_NONE` 同样不新增 Agent task 或 capability；面板下发的 expected TCP listener 地址必须精确为 `127.0.0.1`。Agent 只能按既有受管 PID/socket 规则确认该地址就绪，不得把回环 listener 与 `0.0.0.0`/`::` wildcard 互相等价，也不解析 Tunnel 目标或回传目标流量。
- Agent 不增加协议解析器，不从磁盘读取配置内容回传面板，也不执行局部 JSON patch。
- profile 是否可用由面板固定版本目录决定；Agent 继续用真实 Xray config test 作为独立校验边界。

### 14.2 UDP 可选扩展（v1 envelope 上的 capability 门控）

- listener 和 `PORT_PROBE` 的 `network` 扩展为 `tcp | udp`，需要双协议的 profile 由面板明确声明两个 expected listener，而不是使用模糊的 `both`。
- Agent 分别使用真实 TCP/UDP bind 探测，并读取 `/proc/net/tcp*`、`/proc/net/udp*` 验证受管 PID/inode/端口。
- capability 以可选布尔字段 `supportsUdpPortProbe`、`supportsUdpListenerReadiness` 声明 UDP probe/readiness 支持；缺失按 `false`。旧面板忽略新增字段并继续只发送 TCP；旧 Agent 收到误发的 UDP task/desired 时按 `INVALID_PAYLOAD` 安全拒绝。
- UDP `PORT_PROBE` 每个 task 的 `ports` 必须恰好一项；仍限制 `1000–65535`、固定 `0.0.0.0`、15 秒超时，且不返回占用进程信息。TCP 合同继续允许最多 32 个候选。
- TCP 和 UDP 在同一主机可以使用相同端口；任务、operation metadata、短期 reservation、创建消费与 listener 对齐均携带明确 network，并按 `host + network + port` 比较。
- 在 TypeScript/Go 合同、持久 observed 缓存和端口 reservation 全部升级前，不得只修改前端开放 Hysteria/WireGuard。
- `WIREGUARD_UDP_NONE` 不新增 Agent action、managed service 或 WireGuard 专用载荷；它仍是面板完整 `configJson` 中的 Xray-native inbound，只声明一个 `{ runtimeTag, network: "udp", port }` expected listener。Agent 不解析 peer/key/address，继续用固定 Xray 二进制 config test、原子切换和 UDP procfs/PID readiness 验证整份配置。
- WireGuard inbound 固定 gVisor/`noKernelTun=true` 是配置生成器责任，不成为 Agent capability 字段；Agent 不打开 `/dev/net/tun`、不请求 `CAP_NET_ADMIN`、不配置系统 WireGuard 或防火墙。desired 中包含运行所需 server key、peer public key 和 PSK，但 Agent 只能把精确配置写入 ForwardX 专属 `0600` current/last-good，observed/task result/日志不得回传或摘录这些字段。

实现依据：Go `net.ListenConfig.ListenPacket` 用于有 context 的 UDP bind；Linux `/proc/<pid>/fd` 的 `socket:[inode]` 与 `/proc/net/{tcp,tcp6,udp,udp6}` inode 交叉验证受管进程所有权。

- https://pkg.go.dev/net#ListenConfig.ListenPacket
- https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html
- https://man7.org/linux/man-pages/man5/proc_pid_net.5.html

### 14.3 独立受管服务 v1

心跳静态报告增加可选 `managedServicesCapability`：

```json
{
  "schemaVersion": 1,
  "supportedKinds": ["MTPROTO_FAKE_TLS"],
  "supervisor": "AGENT_CHILD",
  "supportsArtifactInstall": true,
  "runsAsDedicatedUser": true,
  "supportedOS": "linux",
  "supportedArch": "amd64"
}
```

AmneziaWG 使用向后兼容的可选 per-kind 扩展；legacy `supportedKinds` 继续只报告旧面板认识的 MTProto，避免升级 Agent 后让旧面板丢失 MTProto capability：

```json
{
  "schemaVersion": 1,
  "supportedKinds": ["MTPROTO_FAKE_TLS"],
  "kindCapabilities": [
    { "kind": "MTPROTO_FAKE_TLS", "supervisor": "AGENT_CHILD", "supportsArtifactInstall": true, "runsAsDedicatedUser": true, "network": "tcp" },
    { "kind": "AMNEZIAWG", "supervisor": "AGENT_CHILD", "supportsArtifactInstall": false, "runsAsDedicatedUser": true, "network": "udp" }
  ],
  "supervisor": "AGENT_CHILD",
  "supportsArtifactInstall": true,
  "runsAsDedicatedUser": true,
  "supportedOS": "linux",
  "supportedArch": "amd64"
}
```

缺失整个字段表示完全不支持；缺失 `kindCapabilities` 表示只按 legacy MTProto 字段解释。两个数组均去重且最多 8 项。只有 Agent 能确认对应专用 UID/GID、私有目录和支持平台时才声明该 kind；AWG 不需要 artifact install。

`desiredState.managedServices` 是独立完整快照：

```json
{
  "schemaVersion": 1,
  "generation": 4,
  "issuedAt": "2026-09-03T08:00:00.000Z",
  "configHash": "<64 lowercase hex>",
  "services": [{
    "kind": "MTPROTO_FAKE_TLS",
    "serviceId": 12,
    "serviceTag": "forwardx-mtproto-<uuid>",
    "targetVersion": "v1.15.0",
    "artifact": {
      "artifactId": 7,
      "packageFormat": "tar.gz",
      "sha256": "<64 lowercase hex>",
      "fileSize": 5307638
    },
    "listenAddress": "0.0.0.0",
    "listenPort": 8443,
    "fakeTlsDomain": "www.cloudflare.com",
    "accounts": [{
      "accountTag": "forwardx-mtproto-account-<uuid>",
      "secret": "ee<32 hex><lowercase domain utf8 hex>"
    }]
  }]
}
```

- `services` 最多 32 项、每服务账户最多 64 项；服务、账户 tag 必须唯一并匹配固定前缀。
- `configHash` 对不含 `generation/issuedAt` 的规范服务数组计算 SHA-256；同 generation 不同 hash 必须拒绝。
- Agent 只根据上述字段生成固定 TOML：`bind-to` 后直接进入最后的 `[secrets]`；不接收 config text、命令、参数、路径、环境变量或 service 名。
- sidecar 只允许固定 binary、固定 `run` 子命令与 Agent 推导出的受管 config path。配置先用固定 `access` 子命令且丢弃输出验证，再原子切换并确认受管 PID 的 TCP listener；失败恢复该服务 last-good。
- 一个服务失败时整个新 generation 不提交；已成功切换的同批服务必须恢复旧 last-good。空快照停止并清理全部 MTProto 进程和含 secret 的配置，但可保留已验证版本制品。
- Agent 在首次面板认证前根据本地 last-good 恢复；Token 无效、面板不可达或 SSE 断开均不停止现有 sidecar。Agent 显式卸载才停止进程并删除 MTProto config、last-good、state 和 binary。

心跳可选报告 `managedServicesStateSignature` 与 `managedServicesState`。完整状态只允许 schemaVersion、applied generation/hash、每服务 kind/id/tag/version、进程与 TCP listener 状态、稳定错误码和 observedAt；不得出现 secret、FakeTLS 域名、TOML、命令、路径或环境。签名压缩、忙时接受和 SSE/heartbeat 去重规则与 Xray section 相同，但两个 generation 空间互不替代。

`AMNEZIAWG` 分支固定为 `targetVersion=v3.1.20260814`、`forwardx-amneziawg-<uuid>`、单 UDP listener、固定 subnet/MTU/DNS、规范化 `publicAddress`、server private key、严格 AWG 3.1 obfuscation 和至少一个 peer。peer 只含 `accountTag/address/publicKey/preSharedKey`，不得包含客户端 private key。`publicAddress` 只用于 helper 禁止隧道回连该服务公开端点；Agent 还在本地包装配置中加入当前 panel URL 的 hostname。panel URL 变更时使用带 revision 的 `TRANSITION`/`STABLE` 本地 deny policy：helper 先保留旧解析 IP、解析新 hostname 并以严格权限 ACK 回执，Agent 只在成功后切换 runtime URL，再用 `STABLE` 清理旧 IP；失败恢复旧策略或继续 fail closed。panel URL、deny hostname、解析结果和 ACK 均不写入 observed。它没有 artifact；Agent 只把当前自身 executable 作为固定 helper。observed 使用相同 service id/tag、helper PID、Agent binary hash、固定版本和 `network=udp` listener，不得出现 key、PSK、obfuscation、deny 数据或配置。

MTProto 与 AWG 服务数组共同参与同一个规范 hash；端口在首版跨 kind 仍不复用。Agent 必须先逐 kind 完成严格验证，再切换整批；旧 Agent 收到未知 AWG kind 必须拒绝整个 generation 并保留 last-good。TUN 仍无合同分支。Agent 之间没有管理通道。

## 15. 快速配置的 Agent 合同复用（TASK057）

TASK057 不新增 Agent task type、DNS payload、快速配置 desired section 或 Agent 间通信。DNSPod account、zone、line、FQDN、recordId、冲突快照、quickConfigId、外部代理 secret 和派生分享材料都不得发送给 Agent。

### 15.1 全局数字端口检查

面板为一个 quick-config port check 在每个去重且实际需要创建 Realm listener 的 `FORWARD` host 上分别编排现有 `PORT_PROBE`：

- TCP 请求保持 `{ network:"tcp", listenAddress:"0.0.0.0", ports:[candidate] }`；虽然现有合同允许最多 32 个候选，快速配置每 host/port 只消费所选 candidate 的结果。
- UDP 请求保持 `{ network:"udp", listenAddress:"0.0.0.0", ports:[candidate] }` 且每 task 恰好一个端口。
- UDP fan-out 继续要求 capability 同时明确 `supportsUdpPortProbe=true` 和 `supportsUdpListenerReadiness=true`，与现有 `xray.portProbes.create` 门禁一致；不为快速配置放宽或推断能力。
- `taskId/operationId`、幂等、队列容量、超时、过期、本地结果持久化和 accepted result 语义全部沿用第 5、6、10、12 节。

面板只有收到每个预期 `hostId + network + port` 的 schema-valid、未过期 `available=true` 结果才把业务检查标为成功。受管 Xray 使用原端口且选择其落地主机时，该 route 是既有 listener 的 `LANDING/DIRECT`，不创建 Realm listener，也不向 Agent 询问“该端口是否空闲”；面板改为核对账本 alias 和 Xray runtime READY。其他 host、改写端口及所有外部目标入口仍按本节探测。host 错配、网络错配、candidate 缺失、重复/额外结果、离线、队列满、timeout、能力下降或未知错误都 fail closed。Agent 仍不返回 PID、进程、socket、命令、占用地址或错误原文。

面板的 `global_port_allocations` 是控制面更严格的业务真相；Agent 不保存、解释或回报 allocation/owner/domain 信息。一次 probe 成功不构成占位，最终规则仍必须处理 `EADDRINUSE` 并由既有 applied/runtime state 证明 listener READY。

### 15.2 IPv4/IPv6 与 Realm readiness

运营商 route 的 IPv4/IPv6 选择只决定 DNS A/AAAA 值，不改变 Agent payload。TASK057 的 Realm 规则继续由既有普通 rule desired 生成 `[::]:port`、`ipv6_only=false` 的单 TCP 双栈 listener；同 host 的 IPv4 与 IPv6 route 不产生两条规则或两个服务。

`PORT_PROBE.listenAddress` 继续固定 `0.0.0.0`，本任务不批准任意 address 或地址族扩展，也不把 TCP probe 结果声称为独立 IPv6 bind 证明。DNS 切流前必须等待既有 Realm service 与实际 listener readiness；如果双栈 bind、服务身份或 listener 检查失败，规则 operation 失败并由面板 saga 补偿，Agent 不修改 DNS。

### 15.3 规则应用、删除与回收

快速配置生成项是普通 `forward_rules`，Agent 接收的仍是既有规则 action：固定 `forwardType=realm`、`protocol=tcp`、`proxyProtocol*=false`、数值 source/target port 和规范 target address。payload 不增加 quick config、线路或 DNS 字段；同一 host 被多个线路/地址族选择时面板只下发一条规则。

apply/edit 必须先由现有 rule runtime report 明确确认所有新规则 READY，面板随后才写 DNS。remove 必须先由面板完成 DNS 阶段，再发送既有 rule remove；只有 Agent 回报受管服务/listener 已清理，面板才把端口从 `RELEASING` 转为 `PENDING_SCAN`。Agent 离线、Token 无效或 SSE 断开继续保持现有数据面，不因 quick-config operation 主动停止规则。

12 小时端口回收仍只复用第 15.1 节双网络单端口 task。面板给每轮保存固定 host cohort；Agent 不感知扫描租约。任一 host/network 不能确认空闲时面板不得释放，且不会要求 Agent kill、删除文件或报告占用者。

### 15.4 隧道派生端口的运行确认

全局端口账本管理 tunnel 主监听、附加出口、hop、规则 tunnel exit 和 ForwardX v2 mimic UDP 端口。面板仅在心跳请求实际携带一份完整 `localState` 时根据运行监听促进 staged ownership 或释放旧引用；只有 `localStateSignature`、面板缓存投影或局部报告不得触发释放。

`localState.tunnels[]` 在既有 `port/tunnelId/forwardType/transportVersion` 外增加可选 `udpPort` 正整数。该值由 Agent 从已生效或本地持久的 FXP 规格推导，只表示当前隧道的 mimic UDP 运行监听；它不进入 desired state，不是快速配置/DNS payload，也不含隧道凭据、路径或配置文本。无法唯一推导时 Agent 必须省略该字段，不得猜测端口。

旧 Agent 或新 Agent 在某个仍被报告的 tunnel 上缺少 `udpPort` 时，面板必须把 mimic 运行状态视为未知，保留旧公开引用和 staged ownership，不促进、不释放。只有完整快照已不再包含该 tunnel，或明确报告新 `udpPort` 且旧端口已消失时，才能确认清理/切换。普通 TCP/UDP 隧道监听同样必须在完整快照中缺失后才释放对应引用。

## 16. 六引擎快速配置复用（TASK058）

TASK058 不增加 Agent task、desired section、快速配置字段或 DNS 字段。面板只把经服务端批准的一种 engine 映射到既有普通 rule action 的 `forwardType=iptables|nftables|realm|socat|gost|nginx`；payload 继续固定 TCP、关闭上下游 PROXY Protocol，并只包含既有数值端口和规范公开目标地址。Agent 不接收 FQDN、运营商线路、DNS record、quick-config token、外部代理凭据或共同可用目录。

六引擎目录首版的能力基线固定为 Agent `2.2.192`，同时要求现有 Xray capability schema v1 明确声明 TCP port probe、UDP port probe 和 UDP listener readiness；缺版本、旧版本、缺字段或 false 全部按不支持。这个基线只证明当前 Agent 已实现六种既有 rule action 与所需探测/readiness 合同，不从 `osInfo`、命令输出、运行中规则或二进制路径猜测能力，也不向管理员返回原始 capability。以后若某引擎形成不同能力边界，必须以向后兼容的可选 capability 扩展并对旧 Agent 取 false。

IPv4/IPv6 是 DNS 入口选择身份；当前六种 action 都继续使用既有双栈或内核规则生成路径，不增加任意 listen address。iptables/nftables 的 READY 只由 Agent 已确认的受管规则存在性和签名证明，不能伪造 socket listener；Realm、socat、GOST、Nginx 继续使用各自现有 service/process/listener readiness。任一 apply/remove 结果缺失、身份不符或 readiness 不成立时，面板 saga 不得推进 DNS 或宣称切换完成。
