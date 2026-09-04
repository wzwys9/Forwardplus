# Xray 数据模型

状态：第一版、多协议增量模型与独立 managed-services 模型已实施；DNSPod + Realm 快速配置模型已批准，与 `SPEC.md` 0.20 配套。

## 1. 设计原则

- 面板数据库只保存结构化期望状态、加密凭据、制品清单、最后一次实际状态和操作记录。
- 完整 Xray JSON 由面板根据结构化数据生成，不作为第二份数据库真相长期保存。
- desired 字段由面板写，observed 字段只由受鉴权 Agent 报告更新。
- 第一版兼容 SQLite、MySQL、PostgreSQL；使用项目现有 `table()`、`int()`、`bigint()`、`varchar()`、`text()`、`boolean()` 和 `epoch()` 抽象。
- 不依赖数据库原生 enum 或 JSON 类型；JSON 快照使用有大小限制的 `text`，读取时用 Zod 验证。
- 现有 schema 主要使用逻辑关联而非数据库外键。新增表遵循项目模式，但 repository 删除流程必须维护引用完整性。

## 2. 关系

```text
hosts 1 ─── N xray_inbounds 1 ─── N xray_clients
  │                    │
  ├── 1 xray_host_deployments
  ├── 1 xray_runtime_reports
  └── N xray_operations

xray_artifacts 独立保存按 version/os/arch 区分的面板制品
```

独立服务追加以下关系，不与 `xray_inbounds` 建立伪关联：

```text
hosts 1 ─── N xray_managed_services 1 ─── N xray_managed_service_accounts
  │                         │                       │
  ├── 1 xray_managed_service_deployments           └── 1 xray_managed_service_secrets
  └── 1 xray_managed_service_runtime_reports

xray_managed_service_artifacts 按 kind/version/os/arch 保存固定 sidecar 制品
```

## 3. `xray_inbounds`

保存一个受管 Xray listener 的期望配置。

| 字段 | 类型 | 约束/默认 | 所有者 | 说明 |
|---|---|---|---|---|
| `id` | serial | PK | 面板 | 内部主键 |
| `hostId` | int | not null, index | 面板 | 逻辑关联 `hosts.id` |
| `name` | text | not null | 面板 | 管理员可见名称，1–128 字符 |
| `runtimeTag` | varchar(128) | not null, unique | 面板 | 稳定 Xray inbound tag，不由名称派生 |
| `publicAddress` | text | not null | 面板 | 分享链接地址，初始取 Agent 公网 IPv4 |
| `listenAddress` | varchar(64) | not null, default `0.0.0.0` | 面板 | Xray 本地监听地址 |
| `listenPort` | int | not null | 面板 | `1000–65535` |
| `protocol` | varchar(32) | not null, default `vless` | 面板 | 第一版只允许 `vless` |
| `transport` | varchar(32) | not null, default `tcp` | 面板 | 第一版 `tcp`，配置生成器可映射目标版本的 raw/tcp 名称 |
| `security` | varchar(32) | not null, default `reality` | 面板 | 第一版只允许 `reality` |
| `tlsCertificateId` | int | nullable, index | 面板 | 逻辑关联同一 `hostId` 的 `xray_tls_certificates.id`；非 TLS profile 必须为空 |
| `realityTargetHost` | text | not null | 面板 | 已规范化的公网域名 |
| `realityTargetPort` | int | not null, default `443` | 面板 | Reality dest 端口 |
| `realityServerName` | text | not null | 面板 | 兼容列；Reality/TLS profile 的客户端 SNI，必须来自验证结果或所选证书 DNS SAN |
| `realityPublicKey` | text | not null | 面板 | 可进入分享链接 |
| `realityPrivateKeyEncrypted` | text | not null | 面板 | 版本化 AEAD 密文，不进入 DTO |
| `secretKeyVersion` | int | not null, default `1` | 面板 | 加密密钥/封装版本 |
| `fingerprint` | varchar(32) | not null, default `chrome` | 面板 | 分享链接默认 fingerprint |
| `spiderX` | varchar(256) | not null, default `/` | 面板 | 有长度上限的客户端参数；使用 varchar 保证 MySQL 保留默认值 |
| `isEnabled` | boolean | not null, default true | 面板 | 期望是否包含在配置中 |
| `pendingDelete` | boolean | not null, default false | 面板 | 等待新 generation 应用后清理 |
| `desiredGeneration` | bigint(number) | not null, default 0 | 面板 | 最近一次影响该 inbound 的主机 generation |
| `createdByUserId` | int | not null | 面板 | 管理员审计身份 |
| `createdAt` | epoch | not null, now | 面板 | 创建时间 |
| `updatedAt` | epoch | not null, now | 面板 | 更新时间 |

索引和约束：

- unique `runtimeTag`。
- unique `(hostId, transport, listenPort)`，防止 Xray inbound 之间重复。
- index `(hostId, pendingDelete, isEnabled)`，用于生成主机完整配置。
- index `(hostId, desiredGeneration)`，用于状态汇总。
- index `(createdByUserId, createdAt)`，用于管理员审计。

该表唯一约束只保留为同主机 Xray 物理防线，不能阻止与 `forward_rules`、隧道、其他 host 或服务器进程冲突。TASK057 后所有新建/复制/改端口路径必须先取得第 16.4 节持久全局 allocation，再复用主机级端口锁、短期 reservation 和 Agent bind 探测。

MySQL 升级路径必须把旧版 `TEXT NOT NULL` 的 `spiderX` 显式修改为 `VARCHAR(256) NOT NULL DEFAULT '/'`；不能只修正新建表 DDL。

## 4. `xray_clients`

保存 inbound 下的 VLESS 客户端。一个 inbound 可以有多个客户端。

| 字段 | 类型 | 约束/默认 | 所有者 | 说明 |
|---|---|---|---|---|
| `id` | serial | PK | 面板 | 客户端主键 |
| `inboundId` | int | not null, index | 面板 | 逻辑关联 `xray_inbounds.id` |
| `name` | text | not null | 面板 | 1–128 字符 |
| `uuidEncrypted` | text | not null | 面板 | VLESS UUID 的版本化 AEAD 密文 |
| `uuidFingerprint` | varchar(64) | not null, unique | 面板 | HMAC-SHA-256 判重值，不可还原 UUID |
| `shortIdEncrypted` | text | not null | 面板 | shortId 的版本化 AEAD 密文 |
| `shortIdFingerprint` | varchar(64) | not null | 面板 | 同一 inbound 内判重 |
| `statsKey` | varchar(128) | not null, unique | 面板 | 稳定且不含敏感数据的 Xray email/stats 身份；创建后不可修改 |
| `flow` | varchar(64) | not null, default `xtls-rprx-vision` | 面板 | 第一版只允许规定值 |
| `ownerUserId` | int | nullable, index | 面板 | 为后续用户管理预留；第一版不授权普通用户 |
| `isEnabled` | boolean | not null, default true | 面板 | 是否写入期望配置 |
| `pendingDelete` | boolean | not null, default false | 面板 | 删除正在等待运行时确认 |
| `desiredGeneration` | bigint(number) | not null, default 0 | 面板 | 最近一次影响客户端的主机 generation |
| `sortOrder` | int | not null, default 0 | 面板 | 显示顺序 |
| `createdAt` | epoch | not null, now | 面板 | 创建时间 |
| `updatedAt` | epoch | not null, now | 面板 | 更新时间 |

索引和约束：

- unique `uuidFingerprint`。
- unique `statsKey`。
- unique `(inboundId, shortIdFingerprint)`。
- index `(inboundId, pendingDelete, isEnabled, sortOrder)`。
- index `(ownerUserId, createdAt)` 为后续用户管理预留。

普通列表只返回 UUID/shortId 的掩码或是否已配置。只有管理员请求分享材料时，服务端才按最小字段解密并生成 URI；不返回数据库密文。

旧版本曾把单条记录身份混入 fingerprint，导致跨记录判重失效。schema 初始化、结构化导入结束以及首个 Xray 写操作会在持有进程级迁移锁时解密旧记录并重算版本 2 fingerprint；占位值与最终值在同一数据库事务中两阶段写入，完成后记录 `xraySecretFingerprintVersion=2`。若旧数据已包含全局重复 UUID 或同一 inbound 重复 shortId，迁移必须显式失败且不写入部分 fingerprint，不能静默选择一条记录。

## 5. `xray_host_deployments`

保存每台主机由面板拥有的期望部署游标。

| 字段 | 类型 | 约束/默认 | 所有者 | 说明 |
|---|---|---|---|---|
| `id` | serial | PK | 面板 | 记录主键 |
| `hostId` | int | not null, unique | 面板 | 一台主机一条 |
| `targetVersion` | varchar(64) | nullable | 面板 | 期望受管 Xray 版本；无 inbound 时可为空 |
| `desiredGeneration` | bigint(number) | not null, default 0 | 面板 | 单调递增，禁止回退 |
| `desiredConfigHash` | varchar(64) | nullable | 面板 | 规范化配置 SHA-256 |
| `lastOperationId` | varchar(64) | nullable, index | 面板 | 最近一次相关操作 |
| `createdAt` | epoch | not null, now | 面板 | 创建时间 |
| `updatedAt` | epoch | not null, now | 面板 | 更新时间 |

创建、编辑、启停、删除 inbound/client 时，在同一数据库事务和主机级互斥锁中：

1. 修改结构化记录。
2. 递增 `desiredGeneration`。
3. 生成包含非删除、按启用状态处理的完整主机配置。
4. 计算规范化 `desiredConfigHash`。
5. 创建或关联一次 `SYNC` operation。

不得从 observed state 修改这些字段。

## 6. `xray_runtime_reports`

保存 Agent 最近一次受鉴权上报的实际状态缓存。它不是配置来源。

| 字段 | 类型 | 约束/默认 | 所有者 | 说明 |
|---|---|---|---|---|
| `id` | serial | PK | Agent 报告 | 记录主键 |
| `hostId` | int | not null, unique | Agent 报告 | 一台主机一条 |
| `capabilitySchemaVersion` | int | not null, default 0 | Agent 报告 | 支持的 Xray 协议版本 |
| `supportedOS` | varchar(32) | nullable | Agent 报告 | 通过 capability 合同验证的 Go runtime OS；不得从展示文本推断 |
| `supportedArch` | varchar(32) | nullable | Agent 报告 | 通过 capability 合同验证的 Go runtime arch |
| `supportsArtifactInstall` | boolean | not null, default false | Agent 报告 | typed artifact install 能力 |
| `supportsPortProbe` | boolean | not null, default false | Agent 报告 | typed TCP 端口探测能力 |
| `supportsUdpPortProbe` | boolean | not null, default false | Agent 报告 | 可选 typed UDP 单端口 bind 探测能力；旧 Agent 缺失时为 false |
| `supportsUdpListenerReadiness` | boolean | not null, default false | Agent 报告 | 可选 UDP procfs PID/inode readiness 能力；旧 Agent 缺失时为 false |
| `supportsRealityScan` | boolean | not null, default false | Agent 报告 | typed Reality 扫描能力 |
| `capabilityErrorCode` | varchar(64) | nullable | Agent 报告 | 不支持时的稳定脱敏原因码 |
| `isInstalled` | boolean | not null, default false | Agent 报告 | ForwardX 专属路径是否安装 |
| `installedVersion` | varchar(64) | nullable | Agent 报告 | 已安装 current 版本 |
| `runningVersion` | varchar(64) | nullable | Agent 报告 | 实际进程版本 |
| `serviceStatus` | varchar(32) | not null, default `UNKNOWN` | Agent 报告 | `RUNNING/STOPPED/ERROR/UNKNOWN` |
| `processId` | int | nullable | Agent 报告 | Xray PID |
| `appliedGeneration` | bigint(number) | not null, default 0 | Agent 报告 | 最后成功配置 generation |
| `appliedConfigHash` | varchar(64) | nullable | Agent 报告 | 最后成功配置 hash |
| `binarySha256` | varchar(64) | nullable | Agent 报告 | 运行二进制哈希 |
| `listenersJson` | text | nullable | Agent 报告 | 有界的受管 listener 摘要，不含密钥/客户端 |
| `reportSignature` | varchar(64) | nullable | Agent 报告 | observed payload 签名，用于压缩上报 |
| `lastErrorCode` | varchar(64) | nullable | Agent 报告 | 稳定机器错误码 |
| `lastErrorMessage` | text | nullable | Agent 报告 | 长度受限、已脱敏消息 |
| `reportedAt` | epoch | nullable, index | Agent 报告 | 实际采集时间 |
| `updatedAt` | epoch | not null, now | 面板 | 入库时间 |

`listenersJson` 读取时必须校验 schema、条数和字符串长度。内容只允许 inbound runtimeTag、端口、网络、就绪状态和错误码。

只有完整通过 schemaVersion 1 capability 校验且明确 `supported=true` 的报告，才把 `capabilitySchemaVersion` 记为 `1`；旧 Agent、不支持或非法报告记为 `0`。通过校验但 `supported=false` 的报告可以保留受限 OS/arch、false 功能位和稳定 `capabilityErrorCode`，供选择器区分旧 Agent 与平台不支持；非法报告清空这些字段。两个 UDP 功能位是独立、默认 false 的可选列，只有 capability 明确上报 `true` 才持久化为 true，不从 schemaVersion、OS/arch 或 TCP 能力推断。`reportSignature` 仅在完整 observed payload 通过递归 schema、禁用字段、大小和签名校验后更新。读取缓存时必须重新校验所有列和 `listenersJson`，数据库篡改或旧脏数据不得作为签名压缩命中。未知 Agent 错误码统一保存为 `INTERNAL_ERROR`，不得持久化 Agent 原始错误文本。

## 7. `xray_artifacts`

保存面板缓存的受管 Xray 制品。

| 字段 | 类型 | 约束/默认 | 说明 |
|---|---|---|---|
| `id` | serial | PK | 制品主键 |
| `version` | varchar(64) | not null | 规范化 Xray 版本 |
| `os` | varchar(32) | not null | 第一版 `linux` |
| `arch` | varchar(32) | not null | 例如 `amd64`、`arm64` |
| `packageFormat` | varchar(16) | not null | 允许的归档格式 |
| `storageKey` | text | not null | 面板数据目录下相对键，不接受用户路径 |
| `sha256` | varchar(64) | not null | 归档或发布二进制校验值，语义必须固定 |
| `fileSize` | bigint(number) | not null | 下载长度验证 |
| `status` | varchar(32) | not null, default `CACHED` | `CACHED/VERIFIED/INVALID` |
| `source` | text | nullable | 受限来源描述，不作为 Agent 下载 URL |
| `verifiedAt` | epoch | nullable | 最近校验时间 |
| `createdAt` | epoch | not null, now | 创建时间 |
| `updatedAt` | epoch | not null, now | 更新时间 |

约束和索引：

- unique `(version, os, arch)`。
- index `(version, status)`。
- `storageKey` 只由服务端生成，下载接口通过 artifact id 查询，不接收任意文件路径。

## 8. `xray_operations`

持久记录跨心跳的异步操作。

| 字段 | 类型 | 约束/默认 | 说明 |
|---|---|---|---|
| `id` | serial | PK | 内部主键 |
| `operationId` | varchar(64) | not null, unique | UUID/随机稳定任务 id |
| `hostId` | int | not null, index | 目标主机 |
| `inboundId` | int | nullable, index | 可选关联 inbound |
| `type` | varchar(32) | not null | `PORT_PROBE/REALITY_SCAN/INSTALL/UPGRADE/SYNC/RESTART` |
| `requestedGeneration` | bigint(number) | nullable | SYNC 目标 generation |
| `status` | varchar(32) | not null, default `QUEUED` | `QUEUED/RUNNING/SUCCESS/FAILED/TIMEOUT/CANCELLED` |
| `requestMetaJson` | text | nullable | 无密钥、有界、已校验的请求摘要 |
| `resultJson` | text | nullable | 有界、已校验的探测/安装结果 |
| `errorCode` | varchar(64) | nullable | 稳定机器错误码 |
| `errorMessage` | text | nullable | 已脱敏消息 |
| `attemptCount` | int | not null, default 0 | 尝试次数 |
| `createdByUserId` | int | not null | 管理员审计身份 |
| `createdAt` | epoch | not null, now | 创建时间 |
| `startedAt` | epoch | nullable | Agent 接受时间 |
| `finishedAt` | epoch | nullable | 终态时间 |
| `expiresAt` | epoch | nullable, index | 交互任务过期时间 |
| `updatedAt` | epoch | not null, now | 更新时间 |

约束和索引：

- index `(hostId, status, createdAt)`。
- index `(type, status, createdAt)`。
- index `(inboundId, createdAt)`。
- 同一主机一次只允许一个改变 Xray 安装或配置的写操作；扫描和端口探测可以有界并发。
- `requestMetaJson` 禁止保存 configJson、私钥、UUID、shortId、Agent Token 和完整分享链接。
- 创建首个 inbound 的 `SYNC` operation 可在 `requestMetaJson` 保存 schemaVersion、`INSTALL/INSTALL_COMPLETE` 阶段、task 有效期和固定 artifact id/version/os/arch/size/hash/downloadPath；读取接口只投影阶段，不返回原始 JSON。
- 手动 `INSTALL`/`UPGRADE` 复用同样的固定 artifact metadata；`RESTART` 只保存 `RESTART` 阶段、有效期和固定 `ADMIN_REQUEST` reason；纯 `SYNC` 只保存 `SYNC_ONLY` 阶段。四类 metadata 都不得包含配置、命令或凭据。
- `xray_host_deployments.lastOperationId` 指向该主机最后一个运行时写 operation；`QUEUED/RUNNING` 的 `INSTALL/UPGRADE/SYNC/RESTART` 对同一主机互斥。`RESTART` 不改写 `targetVersion`。

## 9. 主机探测预留与全局端口授权

现有进程内预留继续表达一次 Agent 探测后的短期主机事实；UDP 扩展后该 reservation 身份固定为 `hostId + network + port`：

- 预留包含 hostId、network、port、reservationId、过期时间；Xray network 只允许 `tcp | udp`，不保存 `both`。
- 同主机 TCP 与 UDP 可以预留相同端口；相同 network/port 冲突。ForwardX 既有 `both` 规则在共享预留层分别占用 TCP 与 UDP，不能绕过冲突。
- Agent 探测成功后立即预留，创建 mutation 必须携带 reservationId。
- operation request/result 和 reservation 消费必须重复校验 network；旧调用省略时只默认 `tcp`，不得因此消费 UDP reservation。
- 面板进程重启导致预留丢失时，提交失败并重新探测，不写半成品。
- 成功插入资源后释放短期预留；它不能单独证明该端口满足跨主机业务唯一性。

TASK057 实施后，所有新建、复制和改端口的 Xray inbound、普通规则及独立服务还必须先取得第 16.4 节的持久全局端口授权。全局账本解决多请求、多进程和跨 host 的数字端口唯一性；本节短期预留只保留为 Agent 技术探测与竞态缩窄机制，不能覆盖或替代账本。

## 10. 删除和清理

- API 受理删除前必须确认 Agent 在线且心跳新鲜；第一版不允许管理员在离线主机上新建 tombstone 或排队删除。
- 删除 inbound/client 先设置 `pendingDelete=true`，递增 generation，并在新配置中排除该记录。
- Agent 确认 applied generation/hash 后，repository 在事务中先删除待清理 inbound 的全部客户端密文，再删除 inbound tombstone；独立客户端 tombstone 在同一事务中清理。
- inbound/client tombstone 只在 observed 精确匹配该主机当前 desired generation/hash、固定版本、进程和全部 listener 后清理；空 listener 目标还必须报告已安装且 `STOPPED`。较旧 applied generation 或失败应用即使随后重连上报也不得提前删除。清理后配置字节不变，因为生成器早已排除 `pendingDelete` 记录。
- 已受理操作在执行中途遇到 Agent 离线时保留 tombstone，并在 UI 显示“待删除/待同步”，不能声称凭据已失效；这不是离线状态下接受新修改。
- 删除主机时必须在主机删除事务内按 client、operation/deployment/report、inbound 顺序清理面板拥有的 Xray 记录，并保留共享 artifact；该动作不向远端 Agent 下发停止命令。Agent 离线或未先显式卸载时远端 Xray 可能继续运行，UI 和确认文案必须说明。
- terminal operation 保留 30 天；`QUEUED`/`RUNNING` 和仍被 deployment 的 `lastOperationId` 引用的 operation 不清理。超时扫描结果不作为永久运行状态。
- artifact 保留固定默认版本、deployment 目标版本、runtime report 的 installed/running 版本、活动 operation metadata 引用版本，并按每个 OS/arch 至少保留最新两个版本；只有超过 30 天且不在保护集合中的记录和受管普通文件才清理。

## 11. 加密和迁移

- `realityPrivateKeyEncrypted`、`uuidEncrypted`、`shortIdEncrypted` 使用 `SECURITY.md` 定义的版本化 AEAD envelope。
- 密文列不建立可搜索索引；需要判重时使用 HMAC fingerprint。fingerprint 范围为 envelope 版本、资源类型和字段类型，不包含单条记录的 runtimeTag/statsKey，因此同类字段可跨记录判重；密文 AEAD AAD 仍包含稳定资源身份。
- 新表必须同时加入 `drizzle/schema.ts` 和 `server/dbSchema.ts`，并添加 schema 一致性/迁移测试。
- 初始化和升级必须幂等，不改变已有 ForwardX 表的现有字段语义。
- 导入/导出面板备份时必须包含 Xray 表密文。密码加密完整备份按 `SECURITY.md` 包装主密钥；原始数据库迁移不包含主密钥，导入在任何数据库写入前必须用目标端密钥验证全部 Xray envelope，缺失或不匹配时返回 `SENSITIVE_DATA_UNAVAILABLE`。

## 12. 多协议增量模型

现有 `xray_inbounds` 和 `xray_clients` 的 Reality/UUID/shortId 列均为非空。为了保持 SQLite、MySQL、PostgreSQL 可重复迁移和现有节点可回滚，多协议扩展不先把这些列批量改为 nullable，也不为其他协议写入虚假 UUID/shortId。显式非 Reality profile 在既有 Reality-only 非空列写固定中性兼容值：`realityTargetHost/realityPublicKey/realityPrivateKeyEncrypted=""`、`realityTargetPort=443`、`fingerprint="chrome"`、`spiderX="/"`；TLS 的真实 SNI 写入现有 `realityServerName`。这些值不构成 secret 或配置来源，所有读取、备份预检和 fingerprint 迁移必须先按已验证 profile/security 分支，不能用“字段非空”推断存在 Reality 凭据。

实施顺序：

1. 为 `xray_inbounds` 增加可选 `profileId`、`specVersion` 和有界 `specJson`；旧记录读取时映射为 `VLESS_RAW_REALITY_VISION`，迁移完成前继续保留原列。
2. 新增通用访问账户和 secret 表，迁移现有客户端后由编译器在受控过渡期双读；验证完成后才能停止从旧凭据列读取。
3. Agent 探测和 listener readiness 的技术身份从 `(hostId, transport, listenPort)` 迁移为实际 `(hostId, network, listenPort)`；TASK057 后的新业务写入还必须通过第 16.4 节不区分 host/network 的全局数字端口账本。UDP Agent 合同落地前不得创建 UDP profile。

旧 VLESS 回填先在事务外验证全部 profile、旧 envelope 和当前 fingerprint，再在单一事务中写入。access entry 通过唯一 `legacyClientId` 幂等定位，UUID/shortId/Reality envelope 原样复制并保留现有 AAD；任一既有通用记录与旧表不一致或任一密文损坏时，整批不写。D2 完成后，旧 inbound/client mutation 在原主机事务内双写通用表；配置编译和分享逐字段双读比对，再以通用表的 envelope、账户设置与状态为来源。缺失映射或任一侧漂移都拒绝生成，不做读取时静默回填。

`XRAY-TASK-039` 的存储合同固定如下：三列同时为 `NULL` 的旧记录使用原 `protocol/transport/security` 列映射 profile，不回填、不重建密钥；三列只要有一列存在就必须全部存在并互相一致。`VLESS_RAW_REALITY_VISION` 只接受 `specVersion=1` 和语义为严格空对象的 `specJson`；`VLESS_GRPC_REALITY` 只接受 v1 严格 `{ serviceName }`；`VLESS_XHTTP_REALITY` 只接受 v1 严格 `{ path }`，具体字符规则见 `SPEC.md`。现有 Reality 目标等结构化值仍由原列承载。`specJson` UTF-8 上限为 4096 字节，读取进入配置生成器前按 profile/version 的 Zod allowlist 重验；部分 envelope、未知 profile/version、未知字段和完整 Xray JSON 均使生成失败。

### 12.1 `xray_access_entries`

保存协议无关的账户、用户或 peer 身份：

| 字段 | 说明 |
|---|---|
| `id`, `inboundId`, `name` | 稳定资源身份和显示名称 |
| `legacyClientId` | 可空且唯一，只用于把旧 `xray_clients.id` 映射到通用账户；新协议不得写入 |
| `credentialType` | `UUID`、`PASSWORD`、`SHADOWSOCKS_KEY`、`HYSTERIA_AUTH`、`WIREGUARD_PEER`、`HTTP_BASIC` 等固定枚举 |
| `settingsJson` | 非空、非敏感、有界、按 `credentialType` 验证的判别设置；不是 Xray JSON |
| `statsKey` | 不含凭据的稳定内部身份，保留现有审计/统计兼容性但当前不采集流量 |
| `ownerUserId` | 可空的现有 ForwardX 用户关联，语义与旧 client 一致 |
| `isEnabled`, `pendingDelete`, `desiredGeneration`, `sortOrder`, 时间戳 | 沿用当前收敛与删除语义 |

`legacyClientId` 解决双写过渡期的身份映射问题，不能假定旧表和新表的自增 id 永远同步。`statsKey` 全局唯一；`legacyClientId` 非空时唯一。`VLESS_GRPC_REALITY`、`VLESS_XHTTP_REALITY` 与旧 profile 使用完全相同且真实的 UUID/shortId/Reality 凭据列，因此 VLESS 过渡期继续原子双写 `xray_clients` 与通用表，flow 分别精确保存为空字符串和 `NONE`；Trojan、VMess 等非 VLESS profile 不得这样做，也不得伪造 legacy UUID/shortId。`settingsJson` 必须在 repository 写入和编译读取两个边界按版本化 Zod schema 重验。

`settingsJson` 最多 4096 UTF-8 字节并按 credentialType + schemaVersion 判别：`UUID_AND_SHORT_ID` v1 只保存 `schemaVersion/flow`；`UUID` v1 专用于 VMess，严格保存 `schemaVersion=1/flow=NONE/security=AUTO`，v2 专用于 VLESS TLS，严格保存 `schemaVersion=2/protocol=VLESS/encryption=NONE/flow=NONE|XTLS_RPRX_VISION`；`SHADOWSOCKS_KEY` v1 与 `HTTP_BASIC` v1 只保存 `schemaVersion=1`，method/HTTP 行为由 inbound profile 固定，不在每账户重复。其余凭据类型 v1 当前只保存 `schemaVersion`。协议尚需的非敏感字段必须在对应 profile 验证后增加新版本，不能提前以任意键透传。

WireGuard 实施时新增 `WIREGUARD_PEER` v2，严格只保存 `{ "schemaVersion": 2, "address": "10.0.0.N/32" }`；v1 空设置继续可解析以保持已发布合同稳定，但不得作为启用 `WIREGUARD_UDP_NONE` 的有效 peer 编译。`address` 只接受固定 `10.0.0.0/24` 中的 canonical IPv4 `/32`，`.0/.1/.255` 禁用，同一 inbound 的全部行（包括待删除 tombstone）不得重复。

### 12.2 `xray_access_secrets` 与 `xray_inbound_secrets`

一个账户或入站可以拥有多个命名 secret：

| 字段 | 说明 |
|---|---|
| `accessEntryId` 或 `inboundId` | 逻辑关联资源 |
| `kind` | 固定枚举，如 `UUID`、`PASSWORD`、`SHORT_ID`、`PRIVATE_KEY`、`PRE_SHARED_KEY` |
| `encryptedValue` | 版本化 AEAD envelope |
| `fingerprint` | 按 secret 类别定义作用域的 HMAC 判重值 |
| `keyVersion` | envelope/keyring 版本 |

每个资源的 `kind` 唯一；fingerprint 建普通索引但不全局唯一，由服务层按 secret 类别及安全范围判重。access secret 的 AEAD AAD 绑定稳定 `statsKey`，inbound secret 绑定稳定 `runtimeTag`；`keyVersion` 来自已验证 envelope，不能由 API 自由指定。

access secret kind 固定为 `UUID`、`SHORT_ID`、`USERNAME`、`PASSWORD`、`SHADOWSOCKS_KEY`、`HYSTERIA_AUTH`、`PRIVATE_KEY`、`PRE_SHARED_KEY`；inbound secret kind 固定为 `REALITY_PRIVATE_KEY`、`TLS_PRIVATE_KEY`、`SHADOWSOCKS_SERVER_KEY`、`PRIVATE_KEY`、`PRE_SHARED_KEY`。现有 UUID/shortId/Reality context 必须与通用 context 字节一致，迁移时不重加密；其他类别使用类别隔离的 field。HTTP username/password 分别使用 `username`/`password` 类别隔离 context；Shadowsocks server/user PSK 分别使用 `shadowsocks-server-key` 和 `shadowsocks-key` field，不得与 password/private-key context 复用。

通用 access repository 只接受 plaintext secret 输入并在事务内加密，不能接受调用方预制 envelope/fingerprint/keyVersion。创建和轮换必须同时满足 credential secret 策略；普通 DTO 只返回 `requiredConfigured/configuredKinds`，不返回 plaintext、envelope、fingerprint 或 key id。数据库读取再次验证 settings、kind、fingerprint 形状和 envelope version，损坏记录不能被静默投影为正常账户。

`specJson`、`settingsJson` 和 secret 表都必须有 Zod allowlist、大小上限、备份注册、删除清理、fingerprint 迁移和日志/支持包脱敏测试。完整 Xray JSON 仍不落库。

### 12.3 VMess/Shadowsocks 投影

- `VMESS_RAW_TLS` 使用严格空 v1 `specJson`、同主机 `tlsCertificateId`、`realityServerName` SNI 和 generic-only `UUID` v1。`legacyClientId=NULL`，不写 `xray_clients`、shortId、Reality 或 inbound secret；其他 Reality-only 旧列写 TLS profile 的固定中性值。
- `SHADOWSOCKS_2022_RAW_NONE` 使用严格空 v1 `specJson`、`tlsCertificateId=NULL`、全部 Reality-only 旧列的固定中性值，以单一 `xray_inbound_secrets.SHADOWSOCKS_SERVER_KEY` 保存 32-byte canonical base64 server PSK。每账户只写 generic `SHADOWSOCKS_KEY` v1 和单一同名 access secret，不写 legacy client 或任何 TLS/Reality secret。
- `SHADOWSOCKS_2022_RAW_TCP_UDP_NONE` 复用完全相同且逐资源独立生成的 server/user PSK 存储、空 spec 和旧列中性值；`profileId` 是它与 TCP-only profile 的规范判别，`transport` 仍保存 RAW 的 `tcp`，不得把 listener 集合塞进 transport 或任意 `specJson`。配置加载时由 profile 固定恢复 `settings.network=tcp,udp` 和两个 expected listener。
- TCP/UDP reservation 仍是带 60 秒 TTL 的进程内短期主机事实。双网络创建同时持有两条相同 host/user/port、不同 network 的 reservation；TASK057 后还须先取得同一数字端口的全局 allocation。数据库事务成功或失败后都释放短期占用，不能只消费其中一条后留下半状态。
- 生成配置前必须重验 profile/spec、server/user PSK 的 base64 解码长度、envelope、fingerprint 和账户集合。启用的 Shadowsocks inbound 若没有启用且非待删除账户必须拒绝编译，repository 也必须在修改 generation 前拒绝会造成该状态的停用/删除。

### 12.4 Hysteria 2 投影

- `HYSTERIA2_TLS` 使用严格空 v1 `specJson`、同主机 `tlsCertificateId`、规范化 `realityServerName` SNI 和 TLS profile 的固定中性 Reality-only 列；不写 `xray_clients`、Reality secret、shortId 或 inbound 级 auth。
- 每个账户只写 `xray_access_entries.credentialType=HYSTERIA_AUTH`、严格 `settingsJson={"schemaVersion":1}`、`legacyClientId=NULL` 和唯一 `xray_access_secrets.HYSTERIA_AUTH`。明文必须解码为 32 字节且重新编码后精确等于 43 字符 canonical base64url；使用既有 `hysteria-auth` 类别隔离的 AEAD/HMAC context。
- 写入和生成配置前都必须重验 profile/spec、证书主机归属、SNI/SAN、auth envelope/fingerprint/规范形式和账户集合。启用的 Hysteria 2 inbound 至少需要一个启用且非待删除账户；修改层在主机写锁和 generation 事务内拒绝产生空 `clients`，避免保存一个无法认证且没有产品语义的监听。
- 该 profile 的 Agent 技术身份固定为 `(hostId, UDP, listenPort)`；创建只消费同主机、同端口的 UDP reservation，不能消费 TCP reservation，并在 TASK057 后额外取得全局数字端口 allocation。缺少任一 UDP capability 时不得写入 inbound/access/secret/operation 或增加 generation。

### 12.5 WireGuard 投影

- `WIREGUARD_UDP_NONE` 使用严格空 v1 `specJson`、`tlsCertificateId=NULL` 和全部 Reality-only 旧列的固定中性值；inbound 的 32-byte canonical base64 WireGuard private key 只写 `xray_inbound_secrets.PRIVATE_KEY`，不把 server public/private key 写进 `specJson` 或普通 inbound 行。server public key在配置/分享时从已解密私钥派生并验证，数据库不建立第二份可漂移真相。
- 每个 peer 只写 generic `xray_access_entries.credentialType=WIREGUARD_PEER`、严格 v2 address settings、`legacyClientId=NULL`，以及 `xray_access_secrets.PRIVATE_KEY` 和 `PRE_SHARED_KEY` 两个必需 secret。两项分别使用同一 statsKey 下类别隔离的 AEAD/HMAC context；private key 解密后派生 public key，PSK 只用于 server peer 和按需客户端配置。两项都必须是解码 32 字节且重新编码后精确相同的 44 字符 standard base64。
- 新 peer 在主机写锁和同一数据库事务内读取该 inbound 的全部现存地址，选择最低空闲 `.2/32` 并连同 secret、generation 和 operation 一次写入；并发创建不能获得同一地址。启用 inbound 若没有启用且非待删除的 v2 peer 必须在修改 generation 前拒绝。删除 tombstone 被 applied generation 清理前地址不复用。
- 编译固定输出 `protocol=wireguard`、`settings.address=["10.0.0.1/32"]`、`mtu=1420`、`noKernelTun=true`，并按 sortOrder/id 输出启用 peer 的 `{ publicKey, preSharedKey, allowedIPs:[address] }`；不输出 access name/email、privateKey、endpoint、keepAlive 或未批准字段。Agent 技术身份为 `(hostId, UDP, listenPort)`，创建消费单个 UDP reservation；TASK057 后还须取得全局数字端口 allocation。

### 12.6 HTTP Basic 管理代理投影

- `HTTP_RAW_NONE` 使用严格空 v1 `specJson`、`tlsCertificateId=NULL` 和全部 TLS/Reality-only 列的固定中性值，不建立 inbound secret。
- 每个账户只写 generic `xray_access_entries.credentialType=HTTP_BASIC`、严格 `settingsJson={"schemaVersion":1}`、`legacyClientId=NULL`，以及 `xray_access_secrets.USERNAME` 和 `xray_access_secrets.PASSWORD` 两个必需 secret；缺少、重复或无法解密任一项都使完整主机配置生成失败。
- username/password 均由 CSPRNG 生成规范 base64url token，username 为 16 随机字节、password 为 32 随机字节；不得从显示名称、邮箱、statsKey 或自增 id 派生。普通账户 DTO 只返回两项 `requiredConfigured/configuredKinds` 的配置状态，不返回明文、密文、fingerprint、envelope version 或可推导用户名的字段。

### 12.7 Mixed 管理代理投影

- `MIXED_RAW_NONE` 使用严格空 v1 `specJson`、`tlsCertificateId=NULL` 和全部 TLS/Reality-only 列的固定中性值，不建立 inbound secret。存储 `transport=tcp` 只表达 RAW/TCP；同一 Xray listener 内部支持 SOCKS5 与 HTTP 由 profile 决定，不拆成两条 reservation 或两个 observed listener。
- 每个账户只写 generic `xray_access_entries.credentialType=MIXED_USER_PASSWORD`、严格 `settingsJson={"schemaVersion":1}`、`legacyClientId=NULL`，以及 `xray_access_secrets.USERNAME` 和 `xray_access_secrets.PASSWORD` 两个必需 secret。两项沿用按独立 access `statsKey` 与 secret kind 绑定的 AEAD AAD/HMAC context，并由 Mixed credential/profile 双重判别；不得复用 HTTP 账户记录或把显示名称作为用户名。
- username/password 分别由 16/32 个 CSPRNG 随机字节生成并规范化为 22/43 字符 canonical base64url，满足 RFC 1929 单字段最多 255 octets 的边界。写入和编译前重验规范形式、envelope、fingerprint、profile/settings 和至少一个有效账户；任一失败都不能生成 `auth=noauth` 或空 accounts。
- 配置固定输出 `protocol=mixed` 与 `{ auth:"password", accounts:[{ user, pass }], udp:false, userLevel:0 }`；不持久化 `udp/ip`，也不生成 UDP listener/reservation。分享只临时组合两份已验证 secret 和安全 endpoint，不新增可漂移的 URL/订阅存储列。

### 12.8 Tunnel 固定目标投影

- `TUNNEL_TCP_LOCAL_NONE` 使用严格 v1 `specJson={"targetAddress":"...","targetPort":...}` 保存唯一目标；对象 key 顺序由 profile 解析结果规范化。`targetAddress` 只允许 canonical IPv4/IPv6 literal 或小写 ASCII FQDN，`targetPort` 只允许 `1..65535`，不得把 port map、路由、outbound、透明代理或完整配置存入 spec。
- 既有 inbound 非空兼容列使用中性值：`publicAddress=127.0.0.1`、`listenAddress=127.0.0.1`、`transport=none`、`security=none`、`tlsCertificateId=NULL`、`realityTargetHost/realityServerName/realityPublicKey/realityPrivateKeyEncrypted` 为空、`realityTargetPort=443`、`fingerprint=chrome`、`spiderX=/`。目标只存在于受 profile/version 严格重验的 spec，不复用 Reality 列，避免字段所有权歧义。
- 该 profile 必须精确保持零 `xray_clients`、零 `xray_access_entries`、零 `xray_access_secrets` 和零 `xray_inbound_secrets`。repository 创建的通用“至少一个账户”约束只对此 profile 放宽为零，并禁止任何账户或 secret；其他 profile 的账户下限不变。
- Agent 技术身份固定为 `(hostId, TCP, listenPort)`，继续消费一份 TCP reservation；TASK057 后还须取得全局数字端口 allocation。完整快照和 expected listener 保存 `127.0.0.1`，不得在生成器中归一成 `0.0.0.0`；同网络同端口继续按主机保守唯一，即使监听地址不同也不允许复用。

## 13. 受管 TLS 证书

### 13.1 `xray_tls_certificates`

证书是主机级面板资源；一份证书可以被同一主机的多个 TLS inbound 引用，但不能跨主机引用：

| 字段 | 类型 | 约束/默认 | 说明 |
|---|---|---|---|
| `id` | serial | PK | 证书内部主键 |
| `hostId` | int | not null, index | 逻辑关联 `hosts.id` |
| `name` | text | not null | 管理员可见名称，1–128 字符，同主机大小写不敏感唯一 |
| `certificateTag` | varchar(128) | not null, unique | 服务端生成且不可修改的稳定资源身份，用于 AEAD AAD |
| `certificateChainPem` | text | not null | 规范化后的公开 PEM 完整链，UTF-8 最大 16 KiB、最多四张证书 |
| `privateKeyEncrypted` | text | not null | 未加密 PEM 私钥的版本化 AEAD envelope，不进入普通 DTO |
| `privateKeyFingerprint` | varchar(64) | not null, index | 类别隔离的 HMAC-SHA-256 判重值 |
| `keyVersion` | int | not null | 从 envelope 验证得到，API 不得指定 |
| `leafFingerprintSha256` | varchar(64) | not null, index | 叶证书公开 SHA-256 fingerprint |
| `dnsNamesJson` | text | not null | 规范化、去重、有界 DNS SAN 数组；读取时再次验证 |
| `subject`, `issuer` | text | not null | 有界公开元数据，只用于列表和确认 |
| `serialNumber` | varchar(128) | not null | 规范化公开序列号 |
| `notBefore`, `notAfter` | epoch | not null, index | 叶证书有效期 |
| `keyAlgorithm` | varchar(32) | not null | `RSA_2048_4096` 或 `ECDSA_P256_P384` |
| `createdByUserId` | int | not null | 管理员审计身份 |
| `createdAt`, `updatedAt` | epoch | not null | 时间戳 |

私钥 AAD 固定绑定 `certificateTag` 和 `tls-private-key` field；fingerprint context 绑定 envelope 版本、`xray-tls-certificate` 资源类型和字段类型，但不包含单条记录 id。普通 DTO 只返回公开证书元数据、引用数量和 `privateKeyConfigured=true`，不返回 PEM、envelope、fingerprint 或 keyVersion。

### 13.2 引用、轮换和清理

- `xray_inbounds.tlsCertificateId` 只能引用同一主机证书；非 TLS profile 必须为 `NULL`，TLS profile 必须非空。repository 和配置加载器都重复校验。
- 导入未被引用的证书不改变 generation。轮换未被引用的证书只更新证书记录；轮换被引用证书必须持有主机锁、复核主机在线和无活动写 operation，在同一事务更新证书、递增 generation、重建完整 config hash 并创建 `SYNC` operation。
- 轮换应用失败时 Agent 继续使用含旧证书的 last-good；面板保持新 desired 并显示未同步，可通过既有同步流程重试，不从 Agent 回读旧证书。
- 有任一非 `pendingDelete` inbound 引用时拒绝删除并返回 `CERTIFICATE_IN_USE`。无引用证书可在单一数据库事务中物理删除；删除主机时必须在删除 inbound 后清理该主机全部证书密文。
- 加密完整备份包含证书表和包装后的面板主密钥；恢复写数据库前必须预检每个私钥 envelope。原始数据库迁移仍不携带主密钥。

### 13.3 TLS inbound 投影

- 13 个 TLS profile 都要求 `tlsCertificateId` 指向同一 `hostId` 的有效证书；`realityServerName` 保存经规范化且被证书 DNS SAN 覆盖的 TLS `serverName`。transport 专属 v1 `specJson` 只保存空对象、`path` 或 `serviceName`，不保存证书 PEM、私钥、Agent 文件路径或任意 TLS JSON。
- TLS inbound 的 Reality-only 兼容列使用第 12 节固定中性值，不创建 `xray_inbound_secrets.REALITY_PRIVATE_KEY`。配置生成只从证书表最小解密所引用私钥；轮换仍只有证书记录一份面板真相。
- VLESS TLS 账户只写 `xray_access_entries` + `UUID` secret，`legacyClientId=NULL` 且没有 `xray_clients`/`SHORT_ID`；RAW 标准/Vision 的差异由 UUID v2 settings 与 profile 双重校验。Trojan TLS 复用现有 generic-only `PASSWORD` v1。
- 分享查询可以在管理员 `private, no-store` 响应中使用证书表的公开 `leafFingerprintSha256` 生成 `pcs`，但不得把私钥 envelope、HMAC fingerprint 或 PEM 带入普通 inbound/account DTO。

## 14. 独立受管服务表（TASK053）

- `xray_managed_services`：`hostId/name/serviceTag/kind/publicAddress/listenAddress/listenPort/specVersion/specJson/targetVersion/isEnabled/pendingDelete/desiredGeneration/createdByUserId/timestamps`。首版 kind 仅 `MTPROTO_FAKE_TLS`，listenAddress 固定 `0.0.0.0`，strict v1 spec 只有 `{ "fakeTlsDomain": "lowercase-fqdn" }`。
- `xray_managed_service_accounts`：`serviceId/name/accountTag/settingsVersion/settingsJson/isEnabled/pendingDelete/desiredGeneration/sortOrder/timestamps`。账户 tag 是 AEAD AAD 的稳定资源身份，不由显示名推导。MTProto 固定 `settingsVersion=1/settingsJson={}`；AWG peer 的 strict v1 settings 只保存 `{ "address":"10.8.1.N/32", "publicKey":"<canonical base64>" }`。
- `xray_managed_service_secrets`：MTProto 每账户一个 `MTPROTO_SECRET`；AWG peer 每账户分别保存 `AMNEZIAWG_PRIVATE_KEY` 和 `AMNEZIAWG_PRE_SHARED_KEY`。字段为 `encryptedValue/fingerprint/keyVersion/timestamps`，唯一键为 `accountId + kind`，同类 fingerprint 用于判重；private key 只用于面板按需分享，desired 只发送派生 public key。
- `xray_managed_service_instance_secrets`：服务级 secret，字段为 `serviceId/kind/encryptedValue/fingerprint/keyVersion/timestamps`，唯一键 `serviceId + kind`。AWG 固定包含 `AMNEZIAWG_SERVER_PRIVATE_KEY` 与 `AMNEZIAWG_HEADER_PROTECTION_KEY`；MTProto 不写该表。
- `xray_managed_service_deployments`：每主机独立 `desiredGeneration/desiredConfigHash/targetVersion/timestamps`，不复用 Xray generation。
- `xray_managed_service_runtime_reports`：只保存验证后的 capability 与 observed allowlist JSON、签名、reportedAt；不保存 desired、secret、TOML 或路径。
- `xray_managed_service_artifacts`：`kind/version/os/arch/packageFormat/storageKey/sha256/fileSize/status/source/verifiedAt/timestamps`；唯一键 `kind + version + os + arch`。

删除服务先 `pendingDelete=true` 并增加 managed-service generation；只有 observed 确认新 generation 且服务已从状态中消失后才能清理账户、account secret、instance secret 和服务记录。删除主机只清理面板记录，不等价于远端卸载；Agent 显式卸载负责删除远端运行材料。新表和新列必须同步进入 SQLite/MySQL/PostgreSQL、加密备份/恢复预检、fingerprint 迁移、host 删除和支持包 allowlist。

## 15. 外部出口节点（TASK055）

`xray_external_proxy_nodes` 保存全局公开定义：`id/name/nodeTag/protocol/address/port/specVersion/specJson/createdByUserId/createdAt/updatedAt`。`nodeTag` 是唯一、不可变的配置身份；`protocol` 仅允许 `VLESS_REALITY_VISION | SHADOWSOCKS | SOCKS5`；`specJson` 最大 4096 字节并按协议/version 严格重验，不保存 URI、UUID、shortId、密码、用户名、secret envelope、secret fingerprint 或任意 Xray JSON。VLESS v1 的公开 spec 固定为 `serverName/fingerprint/publicKey/spiderX`，其中 `fingerprint` 只允许 `chrome|random` 并在导入、加载、编译和分享时保持原值；这不是密文表使用的 HMAC fingerprint。

`xray_external_proxy_secrets` 保存 `externalProxyNodeId/kind/encryptedValue/fingerprint/keyVersion/timestamps`，唯一键为 `externalProxyNodeId + kind`。kind 仅允许 `VLESS_UUID`、`VLESS_SHORT_ID`、`SHADOWSOCKS_PASSWORD`、`SOCKS_USERNAME`、`SOCKS_PASSWORD`；AAD 绑定不可变 `nodeTag + kind`，HMAC fingerprint 绑定 envelope version、资源类型和 kind。

`xray_inbounds.externalProxyNodeId` 与 `forward_rules.targetExternalProxyNodeId` 是可空引用并建立索引。两列都为空时保持旧行为；规则引用时 `targetIp/targetPort` 继续保存公开 endpoint 的物化副本供旧 Agent 使用，但面板展示和编辑以稳定引用 id 为身份。出口节点被引用时禁止删除和除名称外的修改；解除引用不删除全局资源。

加密完整备份包含两个新表和两列引用，并在写库前预检全部 secret envelope；结构化备份不导出明文。主机删除会删除其 inbound/规则引用，但不删除仍可被其他主机使用的全局出口节点。普通 DTO 只投影安全 spec、`credentialsConfigured` 和 inbound/rule 引用数量。

## 16. DNS provider 与出口快速配置（TASK057）

本节新增的所有表和列都必须使用项目现有跨数据库类型抽象，同时进入 SQLite、MySQL、PostgreSQL 的幂等初始化、schema 对照、结构化备份、加密备份预检和删除清理。表内状态使用受版本控制的字符串 allowlist，不使用数据库原生 enum、JSON、partial index 或仅单一数据库支持的约束。

本节所有 `revision/version/fence` bigint 在 TypeScript 中只允许正安全整数并通过数据库 CAS 单调递增；下一值超过 `Number.MAX_SAFE_INTEGER` 时 fail closed，不做浮点舍入、回绕或重置。

### 16.1 DNS provider account、secret、zone 与 line

`dns_provider_accounts` 保存可扩展的账号公开部分：

| 字段 | 类型 | 约束/默认 | 说明 |
|---|---|---|---|
| `id` | serial | PK | 内部主键 |
| `accountTag` | varchar(128) | not null, unique | 服务端生成且不可变的 AEAD 资源身份 |
| `provider` | varchar(32) | not null, index | 首版只允许 `DNSPOD` |
| `name` | text | not null | 管理员可见名称，1–128 字符 |
| `revision` | bigint(number) | not null, default 1 | 乐观并发版本，只增不减 |
| `isDisabled` | boolean | not null, default false | 管理员是否禁用保存的账号；“全局启用”只由固定 scope binding 定义 |
| `verificationStatus` | varchar(32) | not null, default `UNVERIFIED` | `UNVERIFIED/VALID/INVALID/ERROR/EXPIRED` |
| `lastErrorCode` | varchar(64) | nullable | 稳定脱敏错误码，不保存 provider 原文 |
| `lastValidationAttemptAt` | epoch | nullable | 最近一次验证尝试时间 |
| `verifiedAt` | epoch | nullable | 最近一次成功验证时间；失败不覆盖 |
| `verificationExpiresAt` | epoch | nullable, index | 验证有效期；过期后使用方 fail closed |
| `createdByUserId` | int | not null | 管理员审计身份 |
| `createdAt`, `updatedAt` | epoch | not null | 时间戳 |

`dns_provider_account_secrets` 保存 `accountId/kind/encryptedValue/fingerprint/keyVersion/createdAt/updatedAt`，唯一键为 `accountId + kind`。DNSPod 必须同时且仅有 `DNSPOD_SECRET_ID` 与 `DNSPOD_SECRET_KEY` 两项；AAD 绑定稳定 `accountTag + kind`，HMAC fingerprint 绑定 envelope version、`dns-provider-account` 资源类型和 kind。普通 DTO、审计、operation 和错误不得返回密文、fingerprint 或 keyVersion。

新建或轮换只有在远端验证和 zone 同步成功后才提交；`verifiedAt` 只记录成功，`verificationExpiresAt=verifiedAt+24h`。候选凭据验证失败时整个 mutation 不写库，旧密文、`VALID` 状态和原有效期保持不变；仅对已保存凭据执行显式 revalidate 时，失败才更新该账号的稳定状态/尝试时间。到期或已保存凭据认证失败的账号不能发起新的快速配置写操作。

`dns_provider_global_bindings` 保存 `id/scopeKey/accountId/revision/createdAt/updatedAt`，其中 `scopeKey` 唯一、`accountId` 可空，`revision` 固定为 `bigint(number) NOT NULL DEFAULT 1`。schema 初始化必须保证首版固定 `scopeKey=XRAY_QUICK_CONFIG` 行存在；“未配置”用该行 `accountId=NULL` 表达，删除账号只清空引用并递增 binding revision，不删除 scope 行，避免未配置状态的并发 ABA。交互上因此只有一个全局启用账号；account 表本身允许保存多行，未来可增加 scope 或选择策略而不重建 account/secret 表。非空 binding 只可指向未禁用、凭据完整且 `VALID`/未过期的账号；替换 binding 不删除旧账号。现有 DDNS `system_settings` 明文字段不迁移、不双写，也不能成为快速配置的隐式凭据来源。

固定空 binding 是 schema seed，不计入“目标库已有业务数据”。直接 SQLite 和结构化恢复必须专门处理：只有备份的 provider account/secret/catalog、quick config、managed DNS 和相关 operation 全部为空时，缺固定 scope 才可保留目标空 seed；否则视为部分损坏并在写库前拒绝。备份存在恰好一行时，空目标可用 scope key 更新 seed 的 `accountId/revision/timestamps`、记录旧 id 到 seed id 的映射，再恢复引用；重复或未知 scope 一律预检拒绝。

incremental restore 不能只复用 seed 而跳过安全判定：目标 binding 为空且没有非 `REMOVED` quick config、managed record 或活动 operation 时才可按上段绑定来源账号；目标 binding 非空时，只有来源账号映射到相同稳定 `accountTag` 才可复用现有 binding，并保留目标 accountId/revision 而只记录 id 映射，其他情况整次导入预检失败。相关空库检测、导入顺序和回滚都必须显式忽略或恢复 seed，不能依赖通用表计数/通用 insert。

`dns_provider_zones` 保存 `accountId/providerZoneId/name/status/catalogRevision/refreshedAt/expiresAt/lastSeenAt/createdAt/updatedAt`；唯一键为 `accountId + providerZoneId` 和 `accountId + name`。`dns_provider_record_lines` 保存 `zoneId/providerLineId/name/category/status/catalogRevision/refreshedAt/expiresAt/lastSeenAt/createdAt/updatedAt`；唯一键为 `zoneId + providerLineId`。两表的 `catalogRevision` 都是 `varchar(64)`；status 均闭合为 `AVAILABLE/STALE/REMOVED/ERROR`；`providerZoneId/providerLineId/name` 使用有界 varchar 而非不可完整索引的 text。zone/line 只是最多 6 小时的有界缓存；到期只用于显示 stale 状态，任何 DNS write 前必须实时读取并重新确认账号、zone、lineId、状态和 catalog revision。

运营商 `category` 只允许 `DEFAULT/TELECOM/UNICOM/MOBILE/EDUCATION/OTHER`。首版映射只在 DNSPod 实时返回的当前 catalog 内，对规范化后的完整展示名做版本化精确匹配：`默认 -> DEFAULT`、`电信 -> TELECOM`、`联通 -> UNICOM`、`移动 -> MOBILE`、`教育网 -> EDUCATION`；lineId 始终采用 provider 动态返回值，禁止硬编码、子串猜测或从 line group 位置推断。repository 必须为每个 zone 计算五个 category 的 `AVAILABLE/MISSING/AMBIGUOUS/STALE` 安全投影；只有恰好一个当前候选时为 `AVAILABLE`。缺失或歧义时 fail closed，不能让用户用 `OTHER` 冒充四条必选运营商线路。

`catalogRevision` 的规范算法固定为：前缀 `dnspod-catalog:v1`、映射版本 `dnspod-carrier-map:v1`，加按 `providerZoneId` 排序的完整 zone `{providerZoneId,name,status,lines}`，其中 lines 按 `providerLineId` 排序并固定为 `{providerLineId,name,status,category}`；使用固定 key 顺序 UTF-8 JSON 编码后取小写十六进制 SHA-256，同一次同步的 zone/line 行保存同一个 account catalog hash。刷新和读取都必须用同一个共享 helper 重算；映射版本变化会使旧缓存 stale，不能继续把旧 category 报为可用。

### 16.2 快速配置、线路、普通规则与 DNS 记录

`xray_quick_configs` 保存一个 FQDN 到一个已选落地的编排身份：

| 字段 | 类型 | 约束/默认 | 说明 |
|---|---|---|---|
| `id` | serial | PK | 内部主键 |
| `configTag` | varchar(128) | not null, unique | 服务端生成且不可变的稳定身份 |
| `targetType` | varchar(32) | not null | `XRAY_INBOUND/EXTERNAL_PROXY_NODE` |
| `xrayInboundId` | int | nullable, index | 受管 Xray 落地引用 |
| `externalProxyNodeId` | int | nullable, index | 外部 VLESS/SS/SOCKS5 落地引用 |
| `targetVersion` | varchar(64) | not null | 创建时服务端计算的目标安全版本；每次编排重算比对 |
| `dnsAccountId`, `zoneId` | int | not null, index | 应用时使用的账号与 zone |
| `relativeName`, `fqdn` | text | not null | 已规范化相对多级主机记录和完整域名 |
| `state` | varchar(32) | not null | `APPLYING/ACTIVE/UPDATING/DELETING/COMPENSATING/PARTIAL_FAILURE/FAILED/REMOVED` |
| `revision` | bigint(number) | not null, default 1 | 乐观并发版本，只增不减 |
| `activeTopologyRevisionId` | int | nullable, index | 当前已验证生效的不可变拓扑版本 |
| `desiredTopologyRevisionId` | int | nullable, index | 当前 operation 正在应用的拓扑版本 |
| `currentOperationId` | int | nullable, index | 仅当前活动的持久 operation，终态清空 |
| `createdByUserId` | int | not null | 管理员审计身份 |
| `createdAt`, `updatedAt` | epoch | not null | 时间戳 |

`targetType` 与两个引用必须形成严格判别联合：`XRAY_INBOUND` 只允许 `xrayInboundId`，`EXTERNAL_PROXY_NODE` 只允许 `externalProxyNodeId`。repository 每次读取和写入都重验；快速配置创建后目标引用不可原地替换，换落地使用 remove 后重新创建。目标被快速配置引用时不得绕过编排直接删除或改变 endpoint。

`targetVersion` 的规范算法固定为 `quick-config-target:v1` 前缀加类型分支的固定 key 顺序 UTF-8 JSON，再取小写十六进制 SHA-256。Xray 分支字段依次为类型/id/runtimeTag/hostId/规范 publicAddress/listenPort/protocol/transport/security/profileId/specVersion/严格解析后的规范 secret-free profile spec hash/isEnabled/pendingDelete；外部分支依次为类型/id/nodeTag/protocol/规范 address/port/specVersion/规范 secret-free spec hash。缺失值显式编码为 `null`，IP/域名复用公共地址规范化 helper，数字用无前导零十进制；显示名、时间戳、host generation 和客户端不参与。签发/消费 token 与持久化必须调用同一共享 helper，不能各自拼字符串。

`xray_quick_config_domain_claims` 保存 `claimKey/dnsAccountId/zoneId/normalizedRelativeName/quickConfigId/revision/createdAt/updatedAt`；`claimKey` 是服务端由 provider、稳定 accountTag、providerZoneId 和规范 FQDN 计算的 SHA-256，唯一且不可由浏览器提交，`quickConfigId` 也唯一。每次取得 claim 都必须重算并比对完整 tuple，哈希碰撞按冲突拒绝。该表为多进程提供跨三数据库一致的 FQDN 所有权；删除后的再次创建必须在事务内显式转移或复用 `REMOVED` 配置的 claim，不依赖 partial unique index 或仅服务层预查。

`xray_quick_config_topology_revisions` 保存 `quickConfigId/revisionNumber/engine/targetAddress/targetPort/publicPort/portAllocationId/state/activeSlot/createdByUserId/createdAt/updatedAt`。唯一键为 `quickConfigId + revisionNumber`；TASK057 的 engine 固定 `realm`。状态闭合为 `STAGED/APPLYING/APPLIED/RETIRING/RETIRED/ROLLBACK_PENDING/ABANDONED`；只有 `APPLIED` 可设置 `activeSlot=1`，其他状态为 `NULL`，唯一键 `quickConfigId + activeSlot` 保证最多一个 active topology。旧/新 topology 在 edit 完成或补偿前必须同时保留，各自引用自己的 allocation，不能依赖 operation 摘要恢复。

`xray_quick_config_routes` 保存逐 DNS 线路的入口选择：`routeTag/quickConfigId/topologyRevisionId/lineCategory/providerLineId/sourceType/hostId/addressFamily/address/routeMode/sortOrder/state/timestamps`。`routeTag` 全局唯一；`lineCategory` 允许 `DEFAULT/TELECOM/UNICOM/MOBILE/EDUCATION`，`sourceType` 允许 `MANAGED_HOST/LANDING`，`addressFamily` 只允许 `IPV4/IPV6`，`routeMode` 只允许 `DIRECT/FORWARD`，state 闭合为 `PLANNED/APPLYING/APPLIED/RETIRING/RETIRED/FAILED`。`FORWARD` 必须引用 host 并通过 rule binding 关联普通规则；`DIRECT` 不关联规则，外部落地直连时允许 `hostId=NULL`。地址必须是该 host 或落地当次验证的规范公开地址快照；同一 host 被多个线路选择时可由多条 route 共同引用一条实际 `forward_rules`。repository 在事务内保证同一 topology 的规范 `lineCategory + sourceType + host/addressFamily/address` 不重复，避免依赖各数据库对 nullable unique 的不同语义。

`forward_rules` 增加可空 `xrayQuickConfigId`、可空 `portResourceGroupId` 及各自索引。前者表示编排所有权，后者只表示链路管理端口资源归属；二者都不改变普通规则作为唯一运行时真相的地位。`portResourceGroupId` 不得写入 `forwardGroupId`，不得参与模板/子规则派生、Agent desired、计费资源选择或规则分类。只有未待删除且 `xrayQuickConfigId` 非空的规则计入归属资源的快速配置引用。

`forward_groups` 增加可空 `systemManagedKind` 和可空、唯一 `systemManagedKey`。快速配置自动资源固定 `systemManagedKind=XRAY_QUICK_CONFIG_PORT`；key 由服务端按版本、owner、host、engine 生成有界稳定 identity，浏览器不能提交。自动资源是正常 `groupMode=port`、单 host member 的真实目录资源，但没有模板规则时不自行生成数据面。历史收敛逐条验证 owner/host/engine；已有有效归属保持，唯一已启用人工候选复用，无/多候选时通过 key 幂等取得自动资源。重复启动不会增加资源，engine 变化会迁移归属而不改规则数据面。

`xray_quick_config_rule_bindings` 保存 `bindingTag/quickConfigId/topologyRevisionId/forwardRuleId/state/createdAt/updatedAt`；`bindingTag` 唯一，唯一键为 `topologyRevisionId + forwardRuleId`，state 闭合为 `PLANNED/APPLYING/READY/RETIRING/REMOVED/FAILED`。相同、无需变更的普通规则可被连续两个 topology revision 同时引用；最后一个 binding 清理前不得删除规则。这张表只保存关联和阶段，不复制 Realm 配置。

`xray_quick_config_dns_records` 保存面板实际管理的 provider 记录：`quickConfigId/routeId/dnsAccountId/zoneId/recordTag/providerRecordId/providerLineId/fqdn/recordType/value/ttl/status/appliedRevision/remoteTupleHash/lastVerifiedAt/timestamps`。`recordTag` 唯一且不可变；`providerRecordId` 在 `DESIRED` 时允许为空，取得后受数据库唯一键 `dnsAccountId + providerRecordId` 约束，三种数据库都允许多条 `NULL` 待创建记录。长期托管的 `recordType` 只允许 `A/AAAA`，`status` 只允许 `DESIRED/APPLIED/DELETE_PENDING/REMOVED/DRIFTED/UNKNOWN`。面板只有同时持有 provider recordId、zone、规范 tuple（FQDN/type/line/value/TTL）及其 hash 和所属 quick config 时才声称拥有记录；只凭同名或同值不得删除或覆盖。

`remoteTupleHash` 的规范算法固定为对 UTF-8 JSON `{"schema":"quick-config-dns-tuple:v1","fqdn":...,"recordType":...,"providerLineId":...,"value":...,"ttl":...}` 取小写十六进制 SHA-256；key 顺序如示例固定，输入必须是已规范化的持久 tuple。托管记录、替换快照、写后验证、CAS 删除和备份预检必须调用同一 helper 重算，不能只检查 hash 外形。

`xray_quick_config_dns_record_backups` 保存显式替换 A/AAAA 或删除 CNAME 前的有界恢复材料：`operationId/dnsAccountId/zoneId/providerRecordId/fqdn/recordType/providerLineId/value/ttl/remoteTupleHash/snapshotOrder/state/timestamps`。唯一键为 `operationId + dnsAccountId + providerRecordId`，并另有 `operationId + snapshotOrder` 唯一键；state 闭合为 `CAPTURED/RESTORING/RESTORED/SKIPPED_DRIFTED/FAILED`。只接受 DNSPod 返回的固定字段、每次 operation 最多 64 条、字符串和数值均有上限；不保存任意响应 JSON。这些快照只用于同一次 apply/edit 的失败补偿，不是配置日后删除时的长期恢复基线；正常 remove 只 CAS 删除当前面板拥有的 A/AAAA，不复活历史第三方记录。TXT/MX/CAA 及其他未批准类型只用于冲突摘要，永不进入替换快照或变更集合。

### 16.3 持久 operation 与补偿步骤

`xray_quick_config_operations` 保存 `operationTag/quickConfigId/type/status/phase/activeSlot/revision/expectedRevision/fromTopologyRevisionId/toTopologyRevisionId/requestSummaryJson/retryOfOperationId/executionOwnerId/executionLeaseUntil/executionFence/errorCode/errorMessage/createdByUserId/startedAt/finishedAt/createdAt/updatedAt`。`revision` 与 `executionFence` 都是 `bigint(number) NOT NULL DEFAULT 1`；`expectedRevision` 是 `bigint(number) NOT NULL`，保存发起时 quick-config revision。revision 每次 phase/status/lease ownership 变化都递增，fence 每次取得或接管执行权都递增；`executionOwnerId` 是 `varchar(128)` 可空的面板进程随机实例 id，`executionLeaseUntil` 是可空 epoch。所有 bigint revision/fence 输入输出必须是正安全整数，递增将超过 `Number.MAX_SAFE_INTEGER` 时 fail closed，不截断。`type` 只允许 `APPLY/EDIT/REMOVE/RETRY`；`status` 闭合为 `QUEUED/RUNNING/COMPENSATING/SUCCESS/FAILED/PARTIAL_FAILURE/CANCELLED`；`phase` 闭合为 `RECHECKING_DOMAIN/RESERVING_PORT/CREATING_RULES/WAITING_RULES_READY/APPLYING_DNS/VERIFYING_DNS/FINALIZING/DNS_REMOVING/DNS_REMOVED/RULES_REMOVING/RULES_REMOVED/PORT_RELEASING/RESTORING_DNS/REMOVING_NEW_RULES/RELEASING_REFERENCES/COMPLETED`。非终态 `activeSlot=1`、终态为 `NULL`，唯一键 `quickConfigId + activeSlot` 跨数据库保证同一配置只有一个活动 operation；`CANCELLED` 只允许尚无外部副作用的 `QUEUED`。`expectedRevision` 防止旧向导提交覆盖新状态；from/to topology 是 edit/rollback 的持久权威，不能只写进 JSON 摘要。

worker 只有用 `operationId + revision + executionFence` CAS 取得/续租后才可执行一步；lease 必须长于单次 provider/Agent 最大超时加持久化余量，接管只能在 lease 到期且该余量也经过后递增 fence。旧 worker 的 outcome 按旧 fence 拒绝写入。新 owner 在任何外部动作前先按 step intent/idempotencyKey 读取远端事实，处理旧请求可能已成功但结果尚未落库的情形，不能直接重复 create/delete。

`xray_quick_configs.currentOperationId` 只指向活动 operation；创建 operation 时以 quick-config revision/CAS 同时设置，进入任一终态时同时清空。历史 operation 进入终态后不可重新打开；retry 必须创建新的 `type=RETRY` 行，以 `retryOfOperationId` 指向失败/部分失败的终态 operation，并用 quick-config revision 与唯一 active slot CAS 取得执行权。retry lineage 可只读使用最初失败 apply/edit operation 的不可变 backup 行继续同一补偿，但必须重新执行 record tuple/CAS 和 fence 校验；不得复制、改写或把快照用于正常 remove。历史和 retry 关系只从 operation 表查询，不能让终态 current pointer 阻塞后续重试。

`xray_quick_config_operation_steps` 保存 `operationId/stepKey/kind/subjectType/subjectId/status/attemptCount/idempotencyKey/requestSummaryJson/resultSummaryJson/errorCode/startedAt/finishedAt/updatedAt`；唯一键为 `operationId + stepKey`，`idempotencyKey` 全局唯一。kind 闭合为 `DOMAIN_RECHECK/PORT_RESERVE/RULE_CREATE/RULE_VERIFY/DNS_CREATE/DNS_REPLACE/DNS_DELETE/DNS_VERIFY/DNS_RESTORE/RULE_DELETE/RULE_VERIFY_REMOVED/REFERENCE_RELEASE`，status 闭合为 `PENDING/RUNNING/SUCCESS/FAILED/SKIPPED/COMPENSATED`。步骤只保存经过 schema 校验、无凭据、无完整 provider 响应和无完整分享链接的有界摘要。进程退出后必须从持久 topology/phase/step 恢复，不以浏览器请求生命周期或内存 Promise 作为成功事实。

在 saga worker 尚未实现的 057D 基础模型阶段，operation/step 摘要的唯一合法值是空对象 `{}`，备份导入拒绝任何未知字段。057K 引入 worker 时必须先为每种 operation/step kind 定义带版本的字段白名单，再允许写入非空摘要；不得退回敏感键名黑名单。

`subjectType` 闭合为 `DOMAIN/PORT/RULE/DNS_RECORD/ALLOCATION/TOPOLOGY`。`RULE/DNS_RECORD/ALLOCATION/TOPOLOGY` 的非空 `subjectId` 是对应内部主键的规范十进制字符串，结构化迁移必须按目标库 ID 重映射；`DOMAIN` 保存当前规范 FQDN，`PORT` 保存 `1..65535` 的规范十进制端口。普通 DTO 只投影为 `subjectSafeId`，不得借此返回 provider 原始标识或其他敏感材料。

跨数据库事务只保护本地状态转换。规则 Agent 收敛、DNSPod 写入与验证必须是可重试的外部步骤；禁止把本地事务提交描述成跨系统原子成功。应用顺序固定为重新检查与占位、创建并确认普通规则、写入 DNS、读取验证后激活。正常移除顺序固定为先 CAS 删除当前面板拥有的 A/AAAA，再删除并等待 Agent 确认规则，最后删除引用并把端口从 `RELEASING` 转为 `PENDING_SCAN`；只有 apply/edit 尚未完成时的同次失败补偿可使用该 operation 的替换前快照。补偿只能基于步骤记录、精确 recordId/tuple 和替换前快照执行；检测到第三方修改时转为 `PARTIAL_FAILURE`，不得猜测覆盖。

存在非 `REMOVED` 快速配置或活动 operation 引用时，host、目标 inbound、外部出口节点、DNS account、固定 global binding 和 zone 均禁止直接删除、禁用或改变 endpoint/归属；必须先通过 quick-config edit/remove saga 收敛。QC020 的在线门禁同样适用于删除主机和替换账号绑定，不能用级联清理绕过远端 DNS/规则补偿。

### 16.4 不区分网络的持久全局端口账本

`global_port_allocations` 保存 `allocationTag/port/status/primaryOwnerType/primaryOwnerTag/reservationTokenHash/reservedUntil/scanNotBefore/lastScanStartedAt/lastScanFinishedAt/lastErrorCode/version/createdAt/updatedAt`。`allocationTag` 和 `port` 分别唯一，存储范围为 `1..65535` 以容纳历史 listener，新候选只允许 `1000..65535`；`status` 只允许 `RESERVED/ACTIVE/RELEASING/PENDING_SCAN/FREE/EXTERNAL_OCCUPIED/LEGACY_CONFLICT`。`port` 是面板全局逻辑身份，不区分 TCP/UDP，也不区分 host；底层 Agent `host + network + port` 仍只是探测和监听事实。`primaryOwnerType/Tag` 由分配服务设置，`FREE/PENDING_SCAN/EXTERNAL_OCCUPIED/LEGACY_CONFLICT` 时为空。

`global_port_allocation_references` 保存 `referenceKey/allocationId/resourceType/resourceId/ownerGroupTag/hostId/network/role/isOwning/createdAt/updatedAt`；服务端生成的 `referenceKey` 全局唯一，索引 `allocationId + ownerGroupTag`、`resourceType + resourceId` 和 host。`resourceType` 闭合为 `XRAY_INBOUND/FORWARD_RULE/MANAGED_SERVICE/TUNNEL/TUNNEL_EXIT_NODE/TUNNEL_HOP/FORWARD_RULE_TUNNEL_EXIT/QUICK_CONFIG`；`network` 允许 `TCP/UDP/BOTH/NONE`，`role` 允许 `TARGET/PUBLIC_LISTENER/OWNERSHIP/MIMIC`。`referenceKey` 规范包含资源类型、资源 id、实际 host、network、role，避免 nullable unique 和不同资源 id 空间碰撞。`ownerGroupTag` 由服务端生成，普通资源绑定自己的稳定 tag，快速配置必须精确等于其 `configTag`，API 不接受调用者提供。

一个 allocation 只有 `primaryOwnerType/Tag` 对应的 owning group。快速配置引用目标 Xray 原端口时，`TARGET` 是经 `xrayInboundId` 和 allocation source reference 双重校验的 `isOwning=false` alias，不改变 Xray inbound 的 primary owner；该配置在端口未改写时建立的 `PUBLIC_LISTENER` references 也是同一目标关系授权的非 owning aliases。端口改写时则新建以 `QUICK_CONFIG/configTag` 为 primary owner 的 allocation，其所有普通规则 references 属于同一 owning group。其他跨 group 附着一律拒绝。删除目标前必须先移除快速配置及全部 alias；移除配置先清理普通规则和 alias，目标 allocation 仍由 inbound 持有。

`global_port_probe_runs` 保存一次候选或回收检查的 `probeTag/allocationId/allocationVersion/candidatePort/purpose/status/hostSetHash/expectedHostCount/createdByUserId/startedAt/finishedAt/expiresAt/errorCode`；`probeTag` 唯一，purpose 闭合为 `CANDIDATE/RECLAIM`，status 闭合为 `QUEUED/RUNNING/SUCCESS/FAILED/EXPIRED`。preview 前的候选检查允许 `allocationId=NULL`，它不是持久端口占用。`hostSetHash` 是开始时按 host id 排序的 cohort 摘要。`global_port_probe_results` 保存 `probeRunId/hostId/network/xrayOperationId/status/probedAt/expiresAt`，唯一键为 `probeRunId + hostId + network`；`xrayOperationId` 对应既有 `xray_operations.operationId` 的稳定字符串，network 只允许 `tcp/udp`，status 只允许 `FREE/OCCUPIED/OFFLINE/UNSUPPORTED/ERROR/EXPIRED`。不得保存占用进程、命令输出或远端任意文本。

`global_port_scan_leases` 保存固定 `scopeKey=GLOBAL_PORT_RECLAIM`、`leaseOwnerHash/leaseUntil/lastStartedAt/lastFinishedAt/updatedAt`，`scopeKey` 唯一。调度器必须以数据库 CAS 取得有界租约，确保多面板进程和上次未结束扫描不会重叠；lease owner 只存随机实例标识摘要，不存主机凭据。

分配与回收规则：

- 新 Xray listener、普通转发 listener 和独立受管 listener 在业务写入前必须通过同一数据库分配服务；短期进程内 reservation 只能作为并发优化，不能覆盖持久账本。
- 端口检查允许创建有时效的 Agent probe operation 和短期 host reservation，但 preview 只消费这些结果，不建立 `global_port_allocations` 或业务引用；apply 必须重新校验后事务性创建/取得 `RESERVED` allocation，并处理检查后竞态。
- 候选端口只有在所需 host 上 TCP、UDP 都得到未过期 `FREE` 结果后才可从 `RESERVED` 变为 `ACTIVE`；旧 Agent 缺少 UDP probe、任一 host 离线或结果过期均 fail closed。
- 删除最后引用时先转为 `RELEASING`；只有 Agent 确认所有关联 listener 已清理后才转为 `PENDING_SCAN`，不得立即复用。每 12 小时一次的非重叠扫描只处理没有任何类型有效引用的记录，并对开始时的全部在管 host cohort 并行检查 TCP 与 UDP；发现占用转为 `EXTERNAL_OCCUPIED`，`OFFLINE/UNSUPPORTED/ERROR/EXPIRED` 保持原不可用状态。转为 `FREE` 的事务必须再次确认全部类型引用为零、allocation version 未变、当前 host set 与 `hostSetHash/expectedHostCount` 一致且每个 host 的双网络结果齐全、未过期；否则丢弃本轮结论。后续扫描会重新检查 `PENDING_SCAN/EXTERNAL_OCCUPIED`。
- schema 初始化回填所有仍会产生 listener 的既有 Xray、普通规则、managed service、tunnel 主 listener/mimic、exit node、hop 和 mapped exit 记录。相同端口只有一个既有逻辑所有者时建立 `ACTIVE` allocation；同一 owner 部署到多 host 保存多条 reference 但仍算一个所有者；同一端口已有多个无共同 owner 的资源时建立一条 `LEGACY_CONFLICT` allocation 和全部引用，不修改或停止旧运行时，但禁止新增引用、端口迁入或把它当作候选。管理员消除冲突后，仍有一个 owner 时转为 `ACTIVE`，零引用时转为 `PENDING_SCAN`，绝不直接 `FREE`。
- `FREE` allocation 行可以保留并由事务安全地重新占用；reservation token 只保存摘要且有 TTL，进程崩溃后的过期 `RESERVED` 也必须先进入保守扫描，不能直接假定远端未监听。

状态转移闭合为：新分配 `FREE -> RESERVED -> ACTIVE`；未消费或崩溃过期的 `RESERVED -> PENDING_SCAN`；删除 `ACTIVE -> RELEASING -> PENDING_SCAN -> FREE`；扫描发现未知占用 `PENDING_SCAN/EXTERNAL_OCCUPIED -> EXTERNAL_OCCUPIED`，后续全空闲才到 `FREE`；历史回填进入 `ACTIVE` 或 `LEGACY_CONFLICT`，冲突消除后按是否仍有 owner 转为 `ACTIVE` 或 `PENDING_SCAN`。除明确重试当前 reservation 外，不允许跳过中间状态。
