# Xray 测试计划

状态：已批准。测试名称和命令在实施任务中补充，但验收场景不得删除或弱化；TASK057 采用风险聚焦的精简矩阵。与 `SPEC.md` 0.21 配套。

TASK057 端口资源归属补充只跑聚焦矩阵：一个 SQLite repository 目标覆盖 A 唯一资源复用、B 自动资源、引用数、重复收敛和停用拒绝；schema 目标检查新增列/索引及 MySQL/PostgreSQL 描述；前端以 TypeScript 和一次相关页面构建验证移除主机投影、计数和开关锁定。Agent payload 未变化，不因此运行 Go 全量或 Xray 协议矩阵。

## 1. 测试层级

| 层级 | 目标 | 主要位置 |
|---|---|---|
| 共享合同 | DTO、Zod、枚举、示例 JSON、分享 URI | `shared/`、`client/src/lib/` |
| 数据库 | 三方 schema、repository、generation 事务、密文排除 | `server/*.test.ts` |
| Agent 单元 | task 校验、端口 bind、扫描安全、持久化、安装/回滚 | `agent/*_test.go` |
| 服务端集成 | tRPC、operation、Agent result、权限、并发 | `server/*.test.ts` |
| 前端组件 | 状态、离线禁用、表单、进度和分享 | `client/src/**/*.test.tsx` |
| 端到端/故障 | 面板—Agent—Xray 完整路径和异常恢复 | 隔离测试环境/真实浏览器 |

## 2. 合同与配置生成

- `XRAY-SYNC-001..005` TypeScript 和 Go 能解析 `examples/desired-state.v1.json`、`observed-state.v1.json`、`agent-task.v1.json`。
- 缺少可选 Xray 字段的旧 Agent heartbeat 正常解析并视为 capability 不支持。
- 未知可选字段不破坏旧 schemaVersion 1 解析。
- 非法枚举、超限 payload、generation/hash 冲突被拒绝。
- 同一结构化数据库输入生成字节稳定的 configJson 和相同 SHA-256。
- 客户端排序、shortIds、启用/删除状态产生确定配置。
- 配置生成输出符合目标 Xray 版本并通过真实 Xray config test。
- observed state 不允许私钥、UUID、shortId 或 configJson 字段。

## 3. 数据库与密钥

- `XRAY-REQ-002..004` 一个 inbound 可关联多个客户端，删除一个不会删除其他客户端。
- schema 在 SQLite、MySQL、PostgreSQL 描述中具有一致字段、默认、唯一和索引语义。
- migration 可重复执行，不改变已有 ForwardX 数据。
- `(hostId, transport, listenPort)`、UUID fingerprint、shortId fingerprint 约束生效。
- inbound/client mutation 在一个事务中递增 host generation 并写入 hash/operation。
- 并发 expectedGeneration 只有一个成功，另一个返回 conflict。
- AEAD 加解密成功；nonce 不复用；错误 key/AAD/篡改密文失败。
- DTO、备份日志、配置审计和普通 repository 返回不含密文字段。
- pendingDelete 在旧 generation、失败应用和重连期间保留；只有当前 generation/hash/version/listener 精确确认后才在事务中清理 inbound/client 密文，且不误删同主机其他记录。

## 4. 主机选择与端口

- `XRAY-HOST-001..003` 在线、新鲜、兼容、有制品和 IPv4 的主机可选。
- 离线、心跳过期、旧 Agent、不支持架构、缺制品和缺 IPv4 主机灰显且原因正确。
- 绕过前端直接创建仍返回对应服务端错误。
- `XRAY-PORT-001` 999、65536 被拒绝，1000、65535 合法。
- 面板候选排除 forward rules、隧道、Xray inbound 和当前 reservation。
- Agent bind 探测能区分可用、占用和权限错误，不返回进程信息。
- 两个并发创建不会取得同一 reservation/端口。
- reservation 过期、host 不匹配、管理员不匹配被拒绝。
- probe 成功后端口被抢占时，应用失败为 `PORT_IN_USE`，旧配置继续。

## 5. Reality 扫描

- `XRAY-SCAN-001..004` 扫描任务在选定 Agent 执行并返回结构化排序结果。
- 空/默认候选使用面板版本化列表。
- 默认候选 `v2` 精确包含 Cloudflare、Amazon/AWS、Samsung、NVIDIA、AMD、Intel、Sony 和 Google 下载站 9 项，且不含 `www.microsoft.com`；候选升级不会把历史 `v1` operation 当作当前结果。
- 发布候选前除 TLS 结构化扫描外，使用真实固定 Xray 做一次完整 Reality 握手和代理请求，避免证书链/握手记录过大却被基础 TLS 扫描误判为可用。
- TLS 1.3、H2、X25519、证书和 serverNames 判定有固定夹具。
- NXDOMAIN、超时、TLS 1.2、无 H2、证书无效给稳定 reasonCode。
- IPv4/IPv6 loopback、RFC1918、CGNAT、link-local、ULA、metadata、multicast、reserved 被拒绝。
- DNS 同时返回公网和私网时整体拒绝。
- DNS rebinding 测试证明连接使用已验证固定 IP。
- CIDR、URL、userinfo、超限候选和超限并发被拒绝。
- 扫描任务超时取消 goroutine/连接，不泄漏资源。

## 6. 制品安装和升级

- 同版本或更高版本但缺少/不是 `forwardplus` 来源的 Agent 仍列入迁移候选。
- `forwardplus` 来源但真实版本落后的 Agent 仍列入升级候选；来源和版本都满足才清除升级状态。
- 注册、完整/压缩心跳和 SSE 握手都能持久化同一真实版本、来源和 build id；非法/超长 identity 不进入数据库。
- 来源未知的旧 Agent 保持既有数据面和升级通道，但不能接收 Forwardplus 专有 Xray desired/task。
- 主机卡片、表格和确认框显示真实版本及来源，不显示人为虚高版本。

- `XRAY-RUN-001..006` 未安装主机按需下载匹配 os/arch 制品。
- `XRAY-RUN-015` 生产面板启动初始化按清单顺序覆盖 amd64/arm64，且仅在两项都成功后设置默认版本；任一项失败时不设置默认版本、不阻止面板启动，也不存在 Agent 公网下载分支。
- 制品清单只接受固定 `v26.3.27`，Agent 自动识别 `amd64`/`arm64`；其他架构报告 `PLATFORM_UNSUPPORTED`，不能错误回退到 amd64。
- 非同源/任意 path 下载请求被拒绝。
- size/hash/版本/架构不匹配禁止安装。
- 归档绝对路径、`..`、符号链接逃逸和设备文件被拒绝。
- 已验证同版本安装幂等，不覆盖 current。
- 面板更高版本显示 upgrade；普通 sync 不强制升级。
- Agent 更高版本不自动降级。
- 新版本验证和启动成功才切换 current。
- 新版本启动失败回到旧二进制和 last-good。
- 面板/Agent 重启后 operation 和本地 task result 可恢复。
- install/upgrade/restart/sync 均要求危险确认；运行环境 operationId 刷新后可恢复，关闭 Dialog 后焦点回到原动作。

## 7. 配置应用和运行生命周期

- `XRAY-RUN-007..009` 无效 config 不替换 current。
- 首次部署成功写 config/hash/state，所有 expected listeners READY。
- 更新一个 inbound 生成完整主机配置，其他 inbound 保持存在。
- 更新/删除一个客户端不影响其他客户端认证配置。
- 相同 generation/hash 重复下发幂等跳过。
- generation 相同/hash 不同拒绝并报告冲突。
- SSE 与 heartbeat 同时下发同一 identity 只执行一次；串行队列只保留一个运行中和一个最新 pending，旧快照不能覆盖新 generation。
- 文件或 listener 漂移被检测并恢复/报告。
- 启动后 listener 缺失触发 rollback 或明确 `RUNTIME_NOT_READY`。
- 删除最后 inbound 以空 listener desired 停止受管 Xray但保留受管二进制和面板 deployment/runtime report。
- 显式 Agent 卸载只终止 ForwardX 私有版本目录下的 Xray 并删除私有状态；Token 撤销、401、SSE/面板离线和删除面板主机记录均不触发远端清理。
- 删除主机清理该主机所有面板 Xray 记录但保留共享 artifact，确认文案说明远端可能继续运行。
- Agent 启动在 register/heartbeat 失败前能检查并恢复 last-good。

## 8. Token、离线和进程故障

- `XRAY-RUN-008` Agent Token 改错后心跳/SSE失败，但不会调用 Xray stop/remove。
- 控制面停止或 context 取消后现有 Xray listener 和客户端连接继续；自动化测试直接证明控制面取消/无效 Token 不触发 stop/remove，不用真实等待 10 分钟。发布前可按需做长时 soak，但它不是替代该因果断言的必需步骤。
- 网络隔离恢复后 desired/observed generation/hash 收敛。
- Token/register/heartbeat/SSE context 取消与 Xray 运行 context 相互独立。
- Agent 进程崩溃/重启时允许 Xray 短暂中断，必须证明恢复发生在面板认证之前且不存在重复实例或 PID 复用误杀。
- Agent 服务升级不删除 config、last-good 或 current。
- Agent 离线时面板显示状态未知，不错误显示 Xray stopped。
- Agent 离线或心跳过期时，所有 Xray 写接口均返回稳定 API 错误码 `HOST_OFFLINE`，数据库 generation、节点、客户端和 tombstone 不变化；只读查询仍可用。

## 9. API 与权限

- `XRAY-AUTH-001` 普通用户对每个 query/mutation/artifact route 均被拒绝。
- 管理员 list/detail DTO 不含密文、私钥和完整分享 URI。
- share 仅返回请求客户端的 URI，响应 no-store，日志无 URI。
- create 在主机提交前离线时不写半成品。
- operation id 不能越权查询；重复 Agent result 幂等。
- 请求大小、字符串、客户端数量、分页和扫描速率上限生效。
- 删除、重启、升级和密钥轮换（若实现）具有确认输入和审计记录。
- 错误响应不含堆栈、磁盘路径、Token、config 和命令输出。

## 10. 前端

- 管理员能看到 Xray 菜单，普通用户不能。
- 节点/运行环境 tabs 可通过 URL 状态恢复。
- 列表 loading skeleton、空状态、错误重试和分页正常。
- 离线/不兼容主机显示但禁选，并有可见原因。
- 创建四步骤键盘可操作，提交失败保留输入。
- operation 页面刷新后继续显示真实阶段，终态停止轮询。
- Agent offline 显示“状态未知”而非“已停止”。
- 多客户端增删、启停、分享和二维码交互正确。
- 节点删除成功回调关闭详情、清除 URL `inboundId` 并刷新列表；即使节点已被 observed 清理也不重新查询详情或显示加载失败。
- 客户端 service/API 测试证明单个客户端创建、编辑、停启和删除不改写其他客户端的密文或稳定身份；旧 applied generation 保留 tombstone，精确当前 generation/hash 才清理。
- VLESS URI 纯函数覆盖固定 Reality/Vision 字段顺序、UTF-8 保留字符编码、裸 IPv6 authority 方括号、非法持久字段拒绝和私钥缺失；分享响应覆盖管理员鉴权与 `private, no-store`。
- `VLESS_GRPC_REALITY` 覆盖严格 serviceName、无隐藏 Vision、RAW+gRPC 混合快照、固定 `v26.3.27` config test，并通过真实 Xray 客户端经 SOCKS 发出 HTTPS 请求。
- `VLESS_XHTTP_REALITY` 覆盖严格 path、固定 auto、无高级字段/隐藏 Vision、RAW+gRPC+XHTTP 混合快照、固定 `v26.3.27` config test，并通过真实 Xray 客户端经 SOCKS 发出 HTTPS 请求。
- `TROJAN_RAW_REALITY` 覆盖严格空 spec、generic-only PASSWORD/shortId 加密、无伪 legacy client、账户 CRUD/tombstone、Trojan URI/no-store、安全 DTO、VLESS+Trojan 混合快照，并通过固定 `v26.3.27` 的真实 Trojan 客户端经 SOCKS 发出 HTTPS 请求。
- 分享 Dialog 关闭后不把 URI留在 URL/localStorage。
- 320、768、1024、1440 宽度无阻塞主流程的溢出。
- 使用真实浏览器验证 DOM、console、network、焦点和响应式行为。

## 11. 安全回归

- 使用唯一测试 secret 扫描面板日志、Agent 日志、API fixture、operation、支持包和构建产物，结果为零。
- `server/xraySecretLeak.test.ts` 在隔离日志目录和 SQLite 中注入唯一 Token、UUID、Reality 私钥、shortId、完整 config 与 VLESS URI，并联合扫描结构化面板日志、配置审计、普通 operation DTO/API 投影和实际生成的支持包；Agent 对应测试覆盖嵌套 JSON、命令输出、错误与敏感文件名。
- SSRF、命令注入、路径遍历、归档炸弹、超限任务和重放 task 有测试。
- artifact route 不能读取任意本地文件。
- config generator 不接受客户端传入 JSON。
- Agent task 不存在 command/script 任意执行字段。
- SQLite/MySQL/PostgreSQL 迁移描述保持六张 Xray 表、密文和逻辑关联；原始数据库导出不含主密钥。
- 密码加密完整备份 round-trip 验证 Xray envelope 可由恢复后的包装密钥解密，备份明文中找不到主密钥；错误密码、篡改、非法 KDF、缺失/不匹配密钥均显式失败且不覆盖已有有效密钥。
- 历史清理验证活动/被引用 operation 保留，并保护 current、last-good、deployment、runtime report 和活动 operation 所需制品。

## 12. 检查点命令

按任务运行目标测试；阶段检查点运行：

```bash
pnpm exec tsc --noEmit
pnpm build
pnpm test:server
(cd agent && go test ./...)
pnpm docs:build
```

如果完整 `pnpm test:server` 受既有无关失败阻塞，必须记录精确失败、证明与本任务无关，并运行所有 Xray 目标测试；不得删除测试或把失败标成通过。

## 13. 完成交付门槛

- `SPEC.md` 的 `XRAY-AC-001..010` 均有至少一个自动测试或明确人工验证。
- 所有高风险故障测试通过。
- 功能开关默认策略和升级说明完成。
- 支持的数据库、OS、arch 和 Xray 版本写入发布说明。
- 未决问题全部关闭或明确移出第一版范围。

## 13.1 多协议阶段验收矩阵

每个 profile 必须作为独立垂直切片满足以下条件后才能从 `NOT_IMPLEMENTED` 改为可创建：

- profile 目录拒绝未批准组合，并锁定协议、传输、安全、flow、监听网络、凭据类型、分享格式和 `v26.3.27`。
- 结构化输入生成确定字节和稳定 hash，使用真实固定 Xray 执行 config test；需要监听的 profile 完成真实 listener/readiness 验证。
- 创建、启停、账户 CRUD、删除和完整主机快照证明不会丢失同主机其他 profile。
- 分享材料语义正确、`no-store` 且 secret leak 测试覆盖对应 URI/config 格式。
- UDP profile（包括 mKCP）额外覆盖 TCP/UDP 同端口、真实 UDP bind、`/proc/net/udp*`、旧 Agent capability 拒绝和回滚；单独的 Xray config test 不得作为 listener readiness 证据。
- HTTP/SOCKS/Mixed 覆盖无认证公网配置拒绝；TUN/sidecar 覆盖权限、专属路径、固定命令参数和卸载清理。

TLS profile 额外要求：

- 13 个 profileId、storage transport、flow、credential、spec schema 和 listener network 与 `SPEC.md` 3.9 精确一致；处于 `IMPLEMENTING` 时 catalog/create/UI 均不可用。
- RAW 标准/Vision 分别测试；所有非 RAW VLESS 和全部 Trojan profile 拒绝 flow。VLESS TLS 只生成 generic UUID，不生成 shortId、旧 client 或 Reality secret；Trojan 只生成 password。
- 服务端配置只包含内联 `certificate`/`key`，gRPC 固定 ALPN `h2`；WS/HTTPUpgrade 拒绝 early data/Host/headers，XHTTP 固定 auto，mKCP 不接受 seed/header/FinalMask 或调优参数。
- VLESS/Trojan 分享 URI 都含正确 `type/security=tls/sni/fp/pcs`，仅 Vision URI 含 flow；自签证书客户端使用 pin 能真实连接，错误 pin 必须失败，证书轮换后旧 URI 失败且新 URI 成功。
- mKCP 两项在 TASK049 前保持不可用；之后分别完成 UDP readiness、混合快照回滚和真实客户端连接才能开放。

多协议阶段继续只运行与当前增量风险相称的目标测试；阶段检查点才运行 TypeScript、构建、Agent 和文档完整命令。仓库既有 `LatencyTimeRangeSelect.test.ts` 缺失阻断仍不得伪报为通过。

## 14. TASK033 端到端验收记录（2026-09-01）

环境：WSL2 Linux x86_64、Node.js 20.20.2、pnpm 10.34.4、Go 1.23.1、固定 Xray 26.7.28；真实 Xray 二进制 SHA-256 为 `8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40`。浏览器为 Chrome for Testing 151.0.7922.34（Playwright Chromium）。

| 验收项 | 可复现证据 | 结果 |
|---|---|---|
| `XRAY-AC-001` | `server/xrayInboundCreate.test.ts` 生成真实 desired，并调用 `agent/TestXrayAPIToAgentListenerE2E` 启动固定 Xray、确认 listener 可连接 | 通过 |
| `XRAY-AC-002` | `server/xrayClientService.test.ts` 的三客户端独立 CRUD、启停和 applied 后删除 | 通过 |
| `XRAY-AC-003` | `shared/xrayShare.test.ts` 与 TASK027 真实浏览器分享/二维码/no-store/关闭清除检查 | 通过 |
| `XRAY-AC-004` | Agent desired 串行、重复 identity 幂等、drift 重应用和恢复测试 | 通过 |
| `XRAY-AC-005` | Agent invalid Token、控制面 context 取消、无面板恢复和离线 task-result 持久化测试 | 通过 |
| `XRAY-AC-006` | Agent 无效配置不改 current、listener 抢占/缺失回滚、启动失败恢复旧版本和损坏制品拒绝测试；错误 DTO/UI 只显示稳定码 | 通过 |
| `XRAY-AC-007` | 面板 Reality operation 与 Agent 公网地址策略、固定 IP TLS 扫描测试 | 通过 |
| `XRAY-AC-008` | 普通用户 mutation/query/artifact 拒绝、菜单门控、DTO/secret leak 测试 | 通过 |
| `XRAY-AC-009` | TASK032 的 TypeScript/文档构建、TASK033 的服务端目标集与 Agent 故障集；最终发布命令见 TASK034 | 通过 |
| `XRAY-AC-010` | `server/xraySchema.test.ts` 的 SQLite 实际 DDL，以及 MySQL/PostgreSQL Drizzle/runtime 描述 | 通过 |

本轮真实 Xray/服务端目标命令（10/10 通过，内部真实 listener E2E 通过）：

```bash
XRAY_TEST_BINARY=/tmp/forwardx-xray-v26.7.28/xray JWT_SECRET=xray-task033-e2e \
  node --import tsx --test \
  server/xrayInboundCreate.test.ts server/xrayClientService.test.ts \
  server/xrayInboundLifecycle.test.ts server/xrayRealityOperations.test.ts \
  server/xrayQueries.test.ts shared/xrayShare.test.ts \
  client/src/components/xray/XrayRuntimeOperationDialog.test.tsx \
  client/src/components/xray/XrayInboundRemoveDialog.test.tsx
```

Agent 故障目标命令通过，直接覆盖真实 heartbeat Token 401 不停止受管数据面、控制面离线、认证前恢复、应用中断在提交点前回滚/提交点后收尾、禁止自动降级、desired/SSE 幂等与 generation/hash 保序、无效配置、端口监听失败回滚、升级启动失败回滚、损坏 Zip 和 Reality 公网策略：

```bash
cd agent
GOTOOLCHAIN=local FORWARDX_XRAY_TEST_BINARY=/tmp/forwardx-xray-v26.7.28/xray \
  /tmp/forwardx-go1.23.1/go/bin/go test ./... -run '^(TestXray(HeartbeatInvalidTokenDoesNotStopManagedRuntime|ManagedSupervisor(ControlPlaneCancellationDoesNotStop|InvalidTokenDoesNotStop|RecoveryAdoptsOrStartsWithoutPanel)|RecoveryValidatesLocalStateBeforeStartingWithoutPanel|Recover(RestoresLastGoodAfterInterruptedApply|FinalizesCommittedApplyWithStaleMarker)|Desired(SSEAndHeartbeatShareOneSerializedApply|ReappliesDriftAndReportsConflictWithoutLosingLastGood)|ConfigHashOrConfigTestFailureDoesNotTouchCurrent|Apply(RejectsAutomaticDowngrade|StartFailureRestoresOldConfigAndBinary|ListenerFailureRollsBackOnlyAfterReadinessExhausted|SameGenerationAndHashIsIdempotent)|Artifact(RejectsUnsafeAndMalformedArchives|TaskResultPersistsWhenPanelIsUnavailable)|PortProbeUsesRealBindAndPersistsSafeResult|Reality(AddressPolicyRejectsNonPublicRanges|ScanPinsValidatedAddressAndReportsTLSFeatures))|TestDesiredStatePushScheduler(DoesNotReplaceNewerXrayGeneration|RejectsSameGenerationXrayHashConflict))$'
```

最终审计只重跑受影响目标：上述 Agent 新增/变更的 5 个用例通过；`xraySchema`、旧 fingerprint 迁移、备份/结构化迁移、client/inbound 服务和删除确认共 21/21 通过，覆盖 MySQL 旧 `spiderX` 改型、版本 2 fingerprint 重算和部分导入语义。随后 `corepack pnpm exec tsc --noEmit` 通过；未重复全量构建、文档构建或浏览器烟测。

仓库提交了可复现的真实浏览器基线 `tests/xray-browser-smoke.spec.ts` 与 `tests/xray.playwright.config.ts`。执行 `corepack pnpm test:xray-browser` 会启动使用隔离 SQLite/主密钥目录且开启功能开关的真实开发面板，并用 Playwright Chromium 验证 320/768/1440 无水平溢出、创建 Dialog 焦点、同 pathname 查询参数更新后打开详情、客户端分享/QR、Reality/运行时信息、主机级同步确认、`private, no-store`、URI 不进入 URL/localStorage/sessionStorage，以及无 console/page/request/HTTP 5xx 错误；2026-09-01 实测 1/1 通过。首次运行若本机没有浏览器，只需先执行 `corepack pnpm exec playwright install chromium`。

TASK024/026/027/028/029/030 的既有隔离 Chromium 记录继续补充 1024 视口、完整创建/删除、普通用户入口隐藏和操作刷新恢复；这些历史记录不替代上述仓库内可复现基线。Chrome DevTools MCP 未配置，因此验收使用真实 Playwright Chromium，不把组件模拟当作浏览器结果。

## 15. TASK036 固定版本替换与测试环境记录（2026-09-01）

- 官方 `v26.3.27` linux/amd64 归档大小为 21,136,402，SHA-256 为 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`；linux/arm64 归档大小为 19,716,427，SHA-256 为 `4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c`。release API digest、本地计算值和官方 `.dgst` 的 SHA2-256 一致。
- `XRAY_TEST_BINARY=<v26.3.27 binary> node --import tsx --test server/xrayArtifacts.test.ts server/xrayConfigGenerator.test.ts`：10/10 通过，真实二进制配置校验已执行；Agent 的 `Xray.*(Artifact|Desired|Config|Apply)` 目标测试通过。
- `corepack pnpm exec tsc --noEmit`、`corepack pnpm build:server`、`corepack pnpm build:client` 和 `corepack pnpm docs:build` 通过；按用户要求未重复运行已知因缺失 `LatencyTimeRangeSelect.test.ts` 而在收集前阻断的仓库级 `pnpm test:server`。
- 面板 A 的 `xrayDefaultVersion` 为 `v26.3.27`，amd64/arm64 两项制品均为 `VERIFIED`。A/B 运行时分别保留原 generation 3/1 和原 configHash，最终 installed/running version 均为 `v26.3.27`、serviceStatus 均为 `RUNNING` 且无错误。
- 用户使用现有客户端和节点完成 Reality 实际连接，确认替换后可用；节点结构、UUID、Reality 凭据和 Xray 配置未重建。

## 16. TASK037 Reality 默认候选 v2 验证记录（2026-09-01）

- 参考本地 `3x-ui/` 的默认域名数据但未修改或复制其实现；移除 `www.microsoft.com:443` 后，`v2` 精确保留 Cloudflare、Amazon/AWS、Samsung、NVIDIA、AMD、Intel、Sony 和 Google 下载站 9 项。
- A/B 两台目标 Agent 所在服务器对全部 9 项完成 TLS 1.3、H2、X25519 和证书验证；固定 Xray `v26.3.27` 对每项完成 Reality 握手，并通过本地 SOCKS 代理访问测试端点得到 HTTP 204。
- `corepack pnpm exec node --import tsx --test server/xrayRealityOperations.test.ts`：1/1 通过，覆盖精确候选列表、旧 `v1` operation 拒绝、结果安全投影和既有自定义目标校验。
- `corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过；按用户要求未运行仓库级 `pnpm test:server` 或重复构建、Agent 全量测试和浏览器烟测。本任务尚未部署到线上。

## 17. TASK039 inbound profile/spec 存储验证记录（2026-09-01）

- `node --import tsx --test shared/xrayProfiles.test.ts server/xraySchema.test.ts server/xrayConfigGenerator.test.ts`：15/15 通过，1 项未配置 `XRAY_TEST_BINARY` 的既有真实核心测试按条件跳过；覆盖三数据库描述、SQLite 旧表重复迁移、旧行/显式 profile 配置字节与 hash 一致，以及部分 envelope、未知字段、完整 Xray JSON 和超限 spec 拒绝。
- `corepack pnpm exec tsc --noEmit`、生产 `corepack pnpm build` 和 `git diff --check` 通过；按用户要求未运行已知缺失 `LatencyTimeRangeSelect.test.ts` 阻断的仓库级 `pnpm test:server`，也未重复 Agent/浏览器测试。
- A 面板部署前 SQLite 在线备份 `integrity_check=ok`；部署后 `quick_check=ok`，`profileId/specVersion/specJson` 已增加且 3 条旧 inbound 均保持 legacy 空值。用户/主机/inbound/client 数量保持 1/2/3/4，A/B generation 3/1 与原 configHash 不变，两个 runtime 均为 `RUNNING`、无错误，域名 HTTPS 返回 200。

## 18. TASK045 Trojan RAW Reality 验证与部署记录（2026-09-02）

- `server/xrayTrojanRealityE2e.test.ts` 使用 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的固定 Xray `v26.3.27`，启动真实 Trojan RAW Reality server/client，经本地 SOCKS 请求 Cloudflare HTTPS 成功，1/1 通过。
- profile、access policy、分享、配置生成、createV2、generic-only 持久化/CRUD/tombstone、查询 DTO、旧 VLESS client 回归和三项前端目标共执行 43 项通过；组合命令中 1 项既有 config test 因未传 `XRAY_TEST_BINARY` 条件跳过，真实 Trojan 测试已单独传入同一固定二进制通过。secret leak/observability 4/4、TypeScript、生产构建和 `git diff --check` 通过；构建只有既有大 chunk 提示。
- 按用户要求未运行已知由缺失 `client/src/components/LatencyTimeRangeSelect.test.ts` 阻断的仓库级 `pnpm test:server`，未重复无改动的 Agent/浏览器全量测试。
- A 面板部署备份位于 `/opt/forwardx-panel/backups/deploy-20260902-8d3012c`。线上程序 SHA-256 为 `5b87bd83502533df5278f5b9023ca82e9865083b22b35c2c9785020c4bc59282`，与本地一致；SQLite `quick_check=ok`，原有用户/主机/inbound/client `1/2/3/4` 和 access/access-secret/inbound-secret `4/8/3` 均未变化。A/B runtime generation 3/1 均已应用且为 `RUNNING`、无错误；systemd active、重启 0、近 5 分钟 warning 0，HTTPS 首页和包含 Trojan profile 的新 asset 均为 200。B 无 Agent 改动。

## 19. TASK046F 受管内联 TLS 真实连接记录（2026-09-02）

- `server/xrayTlsE2e.test.ts` 使用 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的固定 Xray `v26.3.27`，为带 DNS SAN 的短期自签证书生成现有受管内联 `certificate`/`key` 配置，并对服务端和客户端分别执行 `xray run -test`。
- 测试启动完全本地的 HTTP origin、VLESS RAW TLS 服务端和 SOCKS+VLESS TLS 客户端；客户端使用叶证书 DER SHA-256 pin 覆盖自签证书校验且配置中不含 `allowInsecure`，真实请求成功返回预期响应。服务端配置断言不含 `certificateFile`、`keyFile`、临时目录或其他 Agent 证书路径。
- `XRAY_TEST_BINARY=<v26.3.27 binary> node --import tsx --test server/xrayInlineTlsCompiler.test.ts server/xrayTlsCertificate.test.ts server/xrayTlsE2e.test.ts`：4/4 通过；`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。此次只增加固定版本验证，未开放 TLS profile，未运行无改动的 Agent、浏览器、生产构建或仓库级 `pnpm test:server`，尚未部署。

## 20. TASK047A TLS profile 合同探测记录（2026-09-02）

- 依据 Xray 官方 VLESS/Trojan、RAW、WebSocket、gRPC、HTTPUpgrade、XHTTP、mKCP 和 TLS 配置语义锁定 13 个 profile；参考 3x-ui 当前代码只用于确认其界面 flow 与分享参数覆盖，不复制其任意字段或组合模型。
- 使用 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的固定 Xray `v26.3.27`，对 VLESS RAW 标准/Vision、Trojan RAW 以及两个协议的 WS/gRPC/HTTPUpgrade/XHTTP/mKCP TLS 最小服务端配置逐项执行 `run -test`，13/13 通过。该结果只证明固定语法；全部 profile 继续不可用，等待各垂直切片真实连接。
- 官方 mKCP 语义确认其使用 UDP 模拟 TCP，因此两个 mKCP profile 明确依赖 TASK049 的 Agent v2 UDP 合同。TLS 分享固定使用叶证书 `pcs` 而不使用 `allowInsecure`；证书轮换要求重新分发 URI。

## 21. TASK047B1 TCP TLS 共享合同记录（2026-09-02）

- 服务端 profile 目录新增 11 个 TCP TLS profile，严格区分 RAW 标准/Vision、WebSocket、gRPC、HTTPUpgrade 和 XHTTP；全部保持 `IMPLEMENTING`，`listAvailableXrayProfiles` 与 profile catalog 输出不变。
- RAW 只接受 `{}`，WebSocket/HTTPUpgrade/XHTTP 只接受严格 `{ path }`，gRPC 只接受严格 `{ serviceName }`。VLESS RAW TLS 两 profile 共享存储列时，组合查找缺少 flow 会因歧义失败，显式 profileId 解析稳定。
- `UUID` access settings 新增 VLESS TLS 专用 v2，只允许 `protocol=VLESS/encryption=NONE/flow=NONE|XTLS_RPRX_VISION`。联合执行 shared profile/access、catalog、config generator、access repository/migration 和 backup 测试：26 项中 25 通过，1 项因未配置 `XRAY_TEST_BINARY` 按既有条件跳过；`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。

## 22. TASK047B2 VLESS RAW TLS 编译/分享记录（2026-09-02）

- `XrayConfigInboundInput` 和账户投影使用显式 Reality/TLS、UUID+shortId/generic UUID 判别联合。TLS 输入拒绝 Reality 材料和 shortId，且配置安全编译再次校验证书、私钥与 SAN/SNI；损坏材料统一转为 `INVALID_CONFIG_INPUT`。
- VLESS RAW 标准 TLS 生成无 flow 的 generic UUID client，Vision 生成固定 `xtls-rprx-vision`；两者都只生成 RAW TCP + 内联 TLS 证书/私钥。固定 `v26.3.27` 的新测试与现有配置回归联合 25/25 通过，实际执行了新旧配置 `run -test`。
- VLESS TLS URI 按 RAW 标准/Vision profileId 固定生成 `type=tcp/security=tls/sni/fp=chrome/pcs/encryption=none`，只有 Vision 带 flow，且拒绝错误 endpoint、IP/通配符 SNI、非规范 pin 和其他 profile。分享回归 8/8、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。

## 23. TASK047B3A VLESS RAW TLS 主机快照记录（2026-09-02）

- 新增只选择 `VLESS_RAW_TLS`/`VLESS_RAW_TLS_VISION` 的 generic UUID 投影；验证 UUID v2 settings 与 profile flow 一致、只存在一个 UUID secret、envelope version 和 context-bound HMAC fingerprint，且不会被 Trojan generic password 投影误读。
- 主机快照先读取证书非敏感位置并复核 `hostId`，通过后才解密受管私钥；测试故意损坏另一主机的私钥密文，跨主机引用仍在解密前稳定返回 `INVALID_CONFIG_INPUT`。TLS 输入不携带 Reality target/private key/shortId，证书/SNI 继续由纯编译器复核。
- `XRAY_TEST_BINARY=<v26.3.27 binary> node --import tsx --test server/xrayRawTlsHostConfig.test.ts server/xrayRawTlsProfileCompiler.test.ts server/xrayConfigGenerator.test.ts server/xrayTlsCertificateRepository.test.ts server/xrayAccessRepository.test.ts server/xrayAccessMigration.test.ts`：15/15 通过，并实际执行 RAW TLS 配置 `run -test`；`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。
- 全量 `server/xray*.test.ts` 中 70 项有 69 项通过；唯一失败 `server/xrayHeartbeatState.test.ts` 已在干净 `HEAD 3821290` 同样复现，根因是既有夹具在迁移后只直写 legacy client 而未创建严格投影要求的 generic 镜像，不属于本次回归。未运行无改动的 Agent、浏览器或生产构建，未部署。

## 24. TASK047B3B VLESS RAW TLS 创建持久化记录（2026-09-02）

- `createXrayInboundConfiguration` 只为 `VLESS_RAW_TLS`/`VLESS_RAW_TLS_VISION` 注册 RAW TCP TLS 存储，写入前按 profile 复核 generic `UUID`、v2 settings 与固定 flow，并要求 `tlsCertificateId` 属于同一主机。
- TLS inbound 强制使用规格中性 Reality-only 列，只写 `xray_access_entries` 与唯一 `UUID` secret；测试断言没有 `xray_clients`、`SHORT_ID` 或 `xray_inbound_secrets`。跨主机证书创建以 `OPERATION_CONFLICT` 原子回滚，inbound/access/secret/operation 数量和 deployment generation 均不变化。
- `XRAY_TEST_BINARY=<v26.3.27 binary> node --import tsx --test server/xrayRawTlsPersistence.test.ts server/xrayRawTlsHostConfig.test.ts server/xrayRepository.test.ts server/xrayGrpcPersistence.test.ts server/xrayTrojanPersistence.test.ts server/xrayConfigGenerator.test.ts`：14/14 通过，并实际执行持久化后标准/Vision TLS 混合配置 `run -test`；`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。未运行无改动的 Agent、浏览器或生产构建，未部署，profile 保持 `IMPLEMENTING`。

## 25. TASK047B3C VLESS RAW TLS 账户生命周期记录（2026-09-02）

- `xray.accessEntries` 按关联 profile 生成 Trojan PASSWORD+shortId 或 VLESS TLS UUID-only；VLESS 标准/Vision 分别固定 UUID v2 `NONE`/`XTLS_RPRX_VISION` flow。改名、停启、pending delete 和 observed 后精确清理继续复用主机 generation/hash 事务，TLS 路径始终没有 legacy client、shortId 或 Reality secret。
- 分享路由接受 `TROJAN_URI|VLESS_URI`，服务层拒绝与 profile 不一致的格式。TLS VLESS URI 生成前重验 UUID envelope/fingerprint、证书同主机、SNI/SAN，并从证书链重新计算叶 SHA-256 与存储元数据匹配后输出 `pcs`；不含 `sid/pbk/allowInsecure`，响应继续 `private, no-store`。
- 证书链/SAN/主机或 pin 元数据损坏映射为 `INVALID_CONFIG_INPUT`，UUID secret 损坏映射为 `SENSITIVE_DATA_UNAVAILABLE`。联合账户/分享/持久化/证书/配置回归 25/25，查询安全投影、secret-leak 与垂直账户补充目标 3/3，`corepack pnpm exec tsc --noEmit` 和 `git diff --check` 通过。未运行无改动的 Agent、浏览器或生产构建，未部署，profile 保持 `IMPLEMENTING`。

## 26. TASK047B4A VLESS RAW TLS createV2 服务记录（2026-09-02）

- `createV2` 的严格判别联合已注册 `VLESS_RAW_TLS`/`VLESS_RAW_TLS_VISION`，只接受证书 id、规范化 ASCII DNS SNI、空 spec 和账户名称；Reality 对象、额外 TLS 字段和两类安全材料混用在 API 边界或服务层拒绝。生产 profile 状态门控保持不变，catalog 不返回两个 `IMPLEMENTING` profile。
- 目标测试用仅限内部测试的显式 profile 门控创建标准/Vision 两个 inbound，验证 generic-only UUID v2、固定 flow、中性 Reality 列、无 legacy client/shortId/inbound secret，以及公开详情只含 profile/security 和证书 id/name/configured。证书跨主机、SNI/SAN 不匹配或私钥材料损坏在 reservation 消费前失败；跨主机路径使用已损坏的他主机私钥证明归属检查先于解密。
- `XRAY_TEST_BINARY=<v26.3.27 binary> node --import tsx --test server/xrayInboundCreate.test.ts server/xrayProfileCatalog.test.ts server/xrayRawTlsAccess.test.ts server/xrayRawTlsCreate.test.ts server/xrayRawTlsHostConfig.test.ts server/xrayRawTlsPersistence.test.ts server/xraySecretLeak.test.ts`：7/7 通过，并实际执行新 TLS 配置 `run -test`。查询与证书 repository/service 回归 3/3、`corepack pnpm exec tsc --noEmit` 和 `git diff --check` 通过；未运行生产构建、Agent 或浏览器测试，未部署，profile 继续保持 `IMPLEMENTING`。

## 27. TASK047B4B VLESS RAW TLS 创建 UI 记录（2026-09-02）

- VLESS/RAW 的同传输组合选择明确展示 Reality Vision、TLS 标准和 TLS Vision 三个独立 profile。安全分区按所选 profile 显示 Reality 扫描或同主机证书/SNI；证书查询不在非 TLS profile 或未选主机时启用，过期证书不可选，ASCII DNS SNI 必须被所选 SAN 覆盖。
- TLS 请求构造只输出 `tlsCertificateId/serverName/spec={}/initialAccessEntries`，SNI 规范化为小写；不输出 Reality 对象、UUID、shortId、flow、PEM、私钥、`allowInsecure` 或任意 TLS JSON。切换主机/profile 统一重置安全、账户和传输专属草稿，避免隐藏值跨 profile 继承。
- `node --import tsx --test client/src/components/xray/xrayCreateDeployment.test.tsx client/src/components/xray/xrayCreateFlow.test.tsx client/src/components/xray/xrayCreateSections.test.ts`：14/14 通过；`corepack pnpm exec tsc --noEmit` 和 `git diff --check` 通过。生产 catalog 仍不含 TLS profile；生产构建和隔离真实浏览器验证留给 047B4C，未部署。

## 28. TASK047B4C VLESS RAW TLS 服务/UI/浏览器检查点（2026-09-02）

- 服务/createV2/UI/查询/证书/secret-leak 目标联合执行 24/24 通过；包含固定 `v26.3.27` 对新 TLS 持久化配置的真实 `run -test`。`corepack pnpm exec tsc --noEmit`、生产 `corepack pnpm build` 和 `git diff --check` 通过，构建仅保留既有大 chunk 警告。
- 仓库隔离 Playwright 在网络层注入仅供测试的 `isAvailable=true` RAW TLS 标准/Vision profile、同主机证书、端口结果和成功 operation；生产共享目录与服务状态门控均未修改。真实 Chromium 从基础配置走到 TLS Standard，验证错误 SAN 阻断后返回传输切换 Vision，确认证书/SNI 草稿清空，再重新填写账户并提交。
- 浏览器核验实际 `createV2` 载荷只含 profile/空 spec/证书 id/SNI/账户名称，无 Reality/UUID/shortId/flow/PEM/privateKey/`allowInsecure`；320/768/1440 均无水平溢出，原有证书管理、详情、分享 no-store、URI 不进 URL/localStorage/sessionStorage 与零 console/page/request/HTTP 5xx 回归保留，`corepack pnpm test:xray-browser` 1/1 通过。两个 profile 仍为 `IMPLEMENTING`，未部署。

## 29. TASK047B5 VLESS RAW TLS 真实连接与开放记录（2026-09-02）

- `server/xrayRawTlsE2e.test.ts` 校验测试二进制 SHA-256 为固定 `v26.3.27` 的 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`。标准与 Vision 各自使用生产配置生成器和生产分享 URI 启动真实 Xray server/client，经 SOCKS 成功访问完全本地的 HTTP origin；服务端使用内联证书/私钥且客户端不含 `allowInsecure`。
- 两个 profile 均验证正确 `pcs` 成功、格式正确但值错误的 `pcs` 失败；服务端替换为同 SAN 的新受管证书并重启后，旧分享 URI 失败、新 pin URI 成功。新 E2E 两个 profile 子测试 2/2 通过，与既有受管 TLS E2E 联合为 4/4。
- 真实证据完成后只将 `VLESS_RAW_TLS` 和 `VLESS_RAW_TLS_VISION` 标为 `AVAILABLE`，其他九个 TCP TLS profile 保持 `IMPLEMENTING`。生产 catalog/createV2/UI 不再依赖浏览器 profile 注入；开放后 profile/create/config/share/security/UI 联合回归 47/47、`corepack pnpm exec tsc --noEmit`、生产构建、`git diff --check` 和隔离 Playwright 1/1 通过，构建仅有既有大 chunk 警告。本任务未部署。

## 30. TASK047C1 Trojan RAW TLS 编译与分享记录（2026-09-02）

- PASSWORD 配置客户端的 shortId 改为由 profile 安全层判定：Trojan RAW Reality 继续严格要求合法 shortId，Trojan RAW TLS 严格拒绝 shortId；password 客户端携带 UUID 或 flow 也在运行时拒绝。`TROJAN_RAW_TLS` 只新增到 Trojan 协议和 RAW 内联 TLS 安全编译的显式分支。
- Trojan RAW TLS 配置只生成 `{ password, email }` client 与内联证书/私钥；分享 URI 固定带 `type=tcp/security=tls/sni/fp=chrome/pcs`，不含 flow、shortId、Reality 参数、`encryption` 或 `allowInsecure`。错误 profile 和交叉字段均拒绝。
- 固定 `v26.3.27` 实际执行新服务端配置 `run -test`；新配置/分享与既有 Reality/VLESS 相邻回归 22/22、`corepack pnpm exec tsc --noEmit` 和 `git diff --check` 通过。`TROJAN_RAW_TLS` 仍为 `IMPLEMENTING`，未部署。

## 31. TASK047C2 Trojan RAW TLS 持久化与账户记录（2026-09-02）

- 底层创建事务和主机快照支持 `TROJAN_RAW_TLS` 的同主机受管证书与 generic-only PASSWORD。Repository 按 profile/security 要求 Reality PASSWORD 必须有 SHORT_ID、TLS PASSWORD 必须没有 SHORT_ID；TLS 发现 shortId secret、跨主机证书或非中性 Reality 列时原子拒绝，不改变 generation/operation/业务行。
- generic password 投影按 profile 返回判别联合，主机配置只为 Reality 解密/校验 shortId。Trojan TLS 账户新增、改名、停启、待删除和 observed 后清理只处理 PASSWORD；分享重验密码、证书归属、SAN/SNI 和叶 pin，固定输出 Trojan TLS URI，错误格式拒绝且响应保持 `private, no-store`。
- 持久化/主机快照相邻回归 13/13、账户/分享相邻回归 12/12，固定 `v26.3.27` 对数据库生成配置实际 `run -test`、`corepack pnpm exec tsc --noEmit` 和 `git diff --check` 通过。`TROJAN_RAW_TLS` 仍为 `IMPLEMENTING`，未部署。

## 32. TASK047C3 Trojan RAW TLS createV2 与 UI 记录（2026-09-02）

- `createV2` 增加严格 Trojan RAW TLS 判别分支，只接收空 spec、受管证书 id、DNS SNI 和账户名称；Reality 对象或额外字段在 API/服务边界拒绝。生产服务继续只接受 `AVAILABLE`，目标测试通过显式内部门控创建 `IMPLEMENTING` profile。
- 初始账户只生成 43 位 canonical password 与 PASSWORD secret，不创建 UUID、flow、shortId、legacy client 或 Reality/inbound secret。公开详情沿用证书 id/name/configured 与通用 PASSWORD configured 状态，不返回凭据或证书材料。
- 创建 Dialog 可由目录派生 Trojan/RAW/TLS，复用证书/SNI 安全页且确认无 Flow；请求只含 profile、空 spec、证书 id、SNI 和账户名。服务相邻回归 4/4、UI 相邻回归 14/14、固定核心 `run -test`、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过；未构建、未跑浏览器、未部署，profile 仍为 `IMPLEMENTING`。

## 33. TASK047C4 Trojan RAW TLS 真实连接与开放记录（2026-09-02）

- `server/xrayTrojanRawTlsE2e.test.ts` 校验测试二进制 SHA-256 为固定 `v26.3.27` 的 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`。测试使用生产配置生成器和生产 Trojan TLS 分享 URI 启动真实 Xray server/client，经 SOCKS 成功访问完全本地的 HTTP origin；服务端使用内联证书/私钥，客户端不含 `allowInsecure`、Reality、flow 或 shortId。
- 测试验证正确 `pcs` 成功、格式正确但值错误的 `pcs` 失败；服务端替换为同 SAN 的新受管证书并重启后，旧分享 URI 失败、新 pin URI 成功。Trojan 新 E2E 1/1 通过，与 VLESS 标准/Vision 和既有受管 TLS E2E 联合为 5/5。
- 真实证据完成后只将 `TROJAN_RAW_TLS` 标为 `AVAILABLE`，其他八个 TCP TLS profile 继续 `IMPLEMENTING`。生产 catalog/createV2/UI 直接开放；隔离 Chromium 使用生产目录完成 Trojan TLS 创建并验证实际载荷无 password、UUID、flow、shortId、Reality、PEM、privateKey 或 `allowInsecure`。开放后服务回归 36/36、UI 回归 14/14、`corepack pnpm exec tsc --noEmit`、生产构建、`git diff --check` 和 Playwright 1/1 通过；构建仅有既有大 chunk 警告。本任务未部署。

## 34. TASK047D1 WebSocket TLS 编译与分享记录（2026-09-02）

- `VLESS_WEBSOCKET_TLS` 与 `TROJAN_WEBSOCKET_TLS` 只在协议编译器和 TLS 传输安全编译器的显式分支中注册；两者生成 `network=ws`、严格 `wsSettings: { path }` 和内联证书/私钥。VLESS 只编译无 flow generic UUID，Trojan 只编译无 shortId/flow generic PASSWORD。
- VLESS/Trojan 分享 URI 固定包含 `type=ws/security=tls/sni/fp=chrome/pcs/path`，VLESS 另含 `encryption=none`；不生成 flow、Host、early data、Reality 参数或 `allowInsecure`。RAW profile 误带 path、非法/扩展 path spec 和交叉安全字段均拒绝。
- 新 WS 编译/分享测试与 RAW/共享 URI 相邻回归 14/14，固定 `v26.3.27` 对混合 VLESS/Trojan WS TLS 配置实际执行 `run -test`；`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。两个 WebSocket TLS profile 仍为 `IMPLEMENTING`，未部署。

## 35. TASK047D2 WebSocket TLS 持久化与账户记录（2026-09-02）

- 创建事务显式映射 VLESS/Trojan `transport=ws/security=tls`，严格保存规范化 `{ path }` spec、同主机受管证书和中性 Reality 列。VLESS 只写 generic UUID v2，Trojan 只写 generic PASSWORD；均不写 legacy client、shortId、Reality/inbound secret。跨主机证书、扩展 spec、Vision flow 或 Trojan shortId 失败时业务行、operation 和 generation 整体不变。
- generic UUID/password 安全投影和完整主机快照覆盖两个 WS profile，固定核心实际验证混合配置。账户新增、改名、停启、待删除和 observed 后清理继续复用 generation/hash 事务；分享从严格 profile spec 读取 path，重验凭据 envelope/fingerprint、证书归属、SAN/SNI 和叶 pin，格式错配拒绝且响应保持 `private, no-store`。
- 持久化/快照相邻回归 14/14、账户/分享相邻回归 13/13，`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。两个 WebSocket TLS profile 仍为 `IMPLEMENTING`，未部署。

## 36. TASK047D3 WebSocket TLS createV2 与创建 UI 记录（2026-09-02）

- `createV2` 增加 VLESS/Trojan WebSocket TLS 严格判别分支，只接收规范化 path、受管证书 id、DNS SNI 和账户名称；公开服务继续拒绝 `IMPLEMENTING` profile，内部目标门控覆盖两类持久化。VLESS 初始账户只生成 generic UUID v2，Trojan 只生成 canonical password，均不创建 shortId、flow、legacy client 或 Reality/inbound secret。
- 创建 Dialog 由服务端目录派生 WebSocket 传输，只显示严格路径和既有证书/SNI/账户分区；WebSocket 与 XHTTP 路径草稿隔离，切换主机/profile 时清理。请求只含 profile、`spec.path`、证书 id、SNI 和账户名称，不含浏览器生成的凭据、Host/headers/early data、任意 TLS/WS JSON 或证书材料。
- 服务目标测试 4/4、创建 UI 既有小回归 14/14、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。为减少重复覆盖，没有新增独立 UI 测试文件，也未提前运行生产构建、浏览器或无关全量套件；这些只在 047D4 开放检查点执行一次。两个 profile 仍为 `IMPLEMENTING`，未部署。

## 37. TASK047D4 WebSocket TLS 真实连接与开放记录（2026-09-02）

- `server/xrayWebSocketTlsE2e.test.ts` 校验测试二进制 SHA-256 为固定 `v26.3.27` 的 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`。单个测试循环 VLESS/Trojan 两协议，使用生产配置生成器和生产分享 URI 启动真实 WebSocket TLS server/client，经 SOCKS 成功访问完全本地的 HTTP origin。
- 两协议均验证正确 `pcs` 成功、格式正确但值错误的 `pcs` 失败；服务端替换同 SAN 受管证书后，旧 URI 失败、新 pin URI 成功。客户端配置不含 `allowInsecure`、flow、shortId、Reality、Host/headers 或 early data。合并 E2E 1/1 通过。
- 真实证据完成后只将 `VLESS_WEBSOCKET_TLS` 与 `TROJAN_WEBSOCKET_TLS` 标为 `AVAILABLE`，其他六个 TCP TLS profile 保持 `IMPLEMENTING`。profile/catalog/create 小回归 12/12、创建 UI 既有回归 14/14、`corepack pnpm exec tsc --noEmit`、生产构建、`git diff --check` 和隔离 Playwright 1/1 通过；构建仅有既有大 chunk 警告。浏览器用既有第二条创建流程替换验证 Trojan WebSocket TLS，没有新增重复浏览器用例；未重复运行持久化/账户/Agent/仓库全量套件，本任务未部署。

## 38. TASK047E1 gRPC TLS 编译与分享记录（2026-09-02）

- `VLESS_GRPC_TLS`/`TROJAN_GRPC_TLS` 只在协议和 TLS 传输安全编译器的显式分支中注册；两者严格生成 `network=grpc`、`grpcSettings={serviceName,multiMode:false}`、内联证书/私钥和固定 `tlsSettings.alpn=[h2]`。VLESS 只编译无 flow generic UUID，Trojan 只编译无 shortId/flow generic PASSWORD。
- VLESS/Trojan 分享 URI 固定包含 `type=grpc/security=tls/sni/fp/pcs/serviceName/alpn=h2`，VLESS 另含 `encryption=none`；不生成 flow、authority、multiMode、Reality 参数或 `allowInsecure`。RAW/WS 误带 serviceName、gRPC 误带 path、非法/扩展 spec 和交叉安全字段均拒绝。
- 一个合并 gRPC TLS 编译/分享测试与 RAW/WS/共享分享相邻回归 13/13，固定 `v26.3.27` 对 VLESS/Trojan 混合配置实际执行 `run -test`；`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。两个 profile 仍为 `IMPLEMENTING`，未运行持久化、Agent、构建或浏览器，未部署。

## 39. TASK047E2 gRPC TLS 持久化与账户记录（2026-09-02）

- 创建事务显式映射 VLESS/Trojan `transport=grpc/security=tls`，严格保存规范化 `{ serviceName }`、同主机受管证书和中性 Reality 列。VLESS 只写 generic UUID v2，Trojan 只写 generic PASSWORD；均不写 legacy client、shortId、Reality/inbound secret。跨主机证书或 authority 扩展 spec 失败时业务行、operation 和 generation 整体不变。
- generic UUID/password 安全投影和完整主机快照覆盖两个 gRPC profile；单个既有持久化目标同时生成 WebSocket+gRPC 四入站配置，并由固定核心实际验证。gRPC 账户新增、改名、停启、待删除和 observed 后清理继续复用 generation/hash 事务；分享从严格 spec 读取 serviceName，重验凭据、证书归属、SAN/SNI 和叶 pin 后固定输出 `alpn=h2`，格式错配拒绝且响应保持 `private, no-store`。
- 持久化/快照相邻回归 3/3、账户相邻回归 2/2，`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。没有新增独立持久化或账户测试文件，未运行 Agent、构建或浏览器；两个 profile 仍为 `IMPLEMENTING`，未部署。

## 40. TASK047E3 gRPC TLS createV2 与创建 UI 记录（2026-09-02）

- `createV2` 增加 VLESS/Trojan gRPC TLS 严格判别分支，只接受 `{ serviceName }`、受管证书 id、DNS SNI 和账户名称。生产状态门控继续拒绝 `IMPLEMENTING` profile；内部目标门控创建两类入站，公开拒绝后端口 reservation 保持可用。
- 创建 Dialog 由服务端目录派生 gRPC TLS，只显示严格 serviceName 和既有证书/SNI/账户分区；切换主机/profile 清理草稿。请求不含浏览器凭据、authority、multiMode、Reality、任意 TLS JSON 或证书材料。
- 服务创建/目录目标 2/2、复用既有 UI 测试文件的小回归 13/13、固定 `v26.3.27` 对创建后混合配置的 `run -test`、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。没有新增测试文件，未运行 Agent、生产构建、浏览器或无关全量套件；两个 profile 仍为 `IMPLEMENTING`，未部署。

## 41. TASK047E4 gRPC TLS 真实连接与开放记录（2026-09-02）

- 既有 `server/xrayWebSocketTlsE2e.test.ts` 扩展为单个 WebSocket+gRPC 四 profile 循环，没有新增 E2E 文件。测试校验固定 `v26.3.27` 二进制 SHA-256，VLESS/Trojan gRPC 均使用生产配置生成器和分享 URI 启动真实 server/client，经 SOCKS 访问本地 origin。
- 两协议均验证正确 `pcs` 成功、格式正确但值错误的 `pcs` 失败；同 SAN 受管证书轮换后旧 URI 失败、新 URI 成功。gRPC 服务端固定 `multiMode=false` 和 ALPN `h2`，客户端不含 `allowInsecure`、flow、shortId、Reality、authority、headers 或 early data；合并 E2E 1/1 通过。
- 真实证据完成后只将 `VLESS_GRPC_TLS` 与 `TROJAN_GRPC_TLS` 标为 `AVAILABLE`，其他四个 TCP TLS profile 保持 `IMPLEMENTING`。profile/catalog/create 小回归 12/12、创建 UI 既有回归 13/13、`corepack pnpm exec tsc --noEmit`、一次生产构建、`git diff --check` 和既有 Playwright 1/1 通过；浏览器将 Trojan WebSocket 代表流程替换为 Trojan gRPC，未增加用例。本任务未部署。

## 42. TASK047F1 HTTPUpgrade TLS 编译与分享记录（2026-09-02）

- `VLESS_HTTP_UPGRADE_TLS`/`TROJAN_HTTP_UPGRADE_TLS` 只在协议和 TLS 传输安全编译器的显式分支中注册；两者严格生成 `network=httpupgrade`、`httpupgradeSettings={path}` 和内联证书/私钥。VLESS 只编译无 flow generic UUID，Trojan 只编译无 shortId/flow generic PASSWORD。
- VLESS/Trojan 分享 URI 固定包含 `type=httpupgrade/security=tls/sni/fp/pcs/path`，VLESS 另含 `encryption=none`；不生成 Host、headers、acceptProxyProtocol、early data、flow、Reality 参数或 `allowInsecure`。非法/扩展 path spec 和交叉字段均拒绝。
- 既有 gRPC 合并测试扩展为 gRPC+HTTPUpgrade 四入站并由固定 `v26.3.27` 实际执行一次 `run -test`；目标 1/1、RAW/WS/共享分享相邻回归 12/12、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。没有新增测试文件，两个 profile 仍为 `IMPLEMENTING`，未运行持久化、Agent、构建或浏览器，未部署。

## 43. TASK047F2 HTTPUpgrade TLS 持久化与账户记录（2026-09-02）

- 创建事务显式映射 VLESS/Trojan `transport=httpupgrade/security=tls`，严格保存 `{ path }`、同主机受管证书和中性 Reality 列。VLESS 只写 generic UUID v2，Trojan 只写 generic PASSWORD；均不写 legacy client、shortId、Reality/inbound secret。跨主机证书或 Host 扩展 spec 失败时业务行、operation 和 generation 整体不变。
- generic UUID/password 投影和完整主机快照覆盖两个 HTTPUpgrade profile；既有目标同时生成 WebSocket+gRPC+HTTPUpgrade 六入站配置，并由固定核心实际验证。HTTPUpgrade 账户 CRUD、分享和 observed tombstone 继续复用 generation/hash 事务；分享严格读取 path 并重验凭据、证书与 pin，响应保持 `private, no-store`。
- 综合持久化/账户目标 1/1、RAW TLS 相邻账户目标 1/1、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。没有新增测试文件，未运行 Agent、构建或浏览器；两个 profile 仍为 `IMPLEMENTING`，未部署。

## 44. TASK047F3 HTTPUpgrade TLS createV2 与创建 UI 记录（2026-09-02）

- `createV2` 增加 VLESS/Trojan HTTPUpgrade TLS 严格判别分支，只接受 `{ path }`、受管证书 id、DNS SNI 和账户名称。生产状态门控继续拒绝 `IMPLEMENTING` profile；内部目标门控创建两类入站，公开拒绝后端口 reservation 保持可用。
- 创建 Dialog 由服务端目录派生 HTTPUpgrade TLS，只显示独立严格 path 和既有证书/SNI/账户分区；切换主机/profile 清理草稿。请求不含浏览器凭据、Host、headers、acceptProxyProtocol、early data、任意 TLS JSON 或证书材料。
- 服务 create/catalog 目标 2/2、复用既有 UI 测试文件的小回归 13/13、固定 `v26.3.27` 对创建配置的 `run -test`、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。没有新增测试文件，未运行 Agent、生产构建、浏览器或无关全量套件；两个 profile 仍为 `IMPLEMENTING`，未部署。

## 45. TASK047F4 HTTPUpgrade TLS 真实连接与开放记录（2026-09-02）

- 既有 `server/xrayWebSocketTlsE2e.test.ts` 扩展为单个 WebSocket+gRPC+HTTPUpgrade 六 profile 循环，没有新增 E2E 文件。测试校验固定 `v26.3.27` 二进制 SHA-256，VLESS/Trojan HTTPUpgrade 均使用生产配置生成器和分享 URI 启动真实 server/client，经 SOCKS 访问本地 origin。
- 两协议均验证正确 `pcs` 成功、格式正确但值错误的 `pcs` 失败；同 SAN 受管证书轮换后旧 URI 失败、新 URI 成功。HTTPUpgrade 服务端和客户端只含严格 path，不含 `allowInsecure`、flow、shortId、Reality、Host、headers、acceptProxyProtocol 或 early data；合并 E2E 1/1 约 27.4 秒。
- 真实证据完成后只将 `VLESS_HTTP_UPGRADE_TLS` 与 `TROJAN_HTTP_UPGRADE_TLS` 标为 `AVAILABLE`，XHTTP TLS 两项保持 `IMPLEMENTING`。profile/catalog/create 小回归 12/12、创建 UI 既有回归 13/13、`corepack pnpm exec tsc --noEmit`、一次生产构建、`git diff --check` 和既有 Playwright 1/1 通过；浏览器将 Trojan gRPC 代表流程替换为 Trojan HTTPUpgrade，未增加用例，构建仅有既有大 chunk 提示。本任务未部署。

## 46. TASK047G1 XHTTP TLS 编译与分享记录（2026-09-02）

- `VLESS_XHTTP_TLS`/`TROJAN_XHTTP_TLS` 只在协议和 TLS 传输安全编译器的显式分支中注册；两者严格生成 `network=xhttp`、`xhttpSettings={path,mode:auto}` 和内联证书/私钥。VLESS 只编译无 flow generic UUID，Trojan 只编译无 shortId/flow generic PASSWORD。
- VLESS/Trojan 分享 URI 固定包含 `type=xhttp/security=tls/sni/fp/pcs/path/mode=auto`，VLESS 另含 `encryption=none`；不生成 Host、headers、padding、xmux、downloadSettings、flow、Reality 参数或 `allowInsecure`。非法/扩展 path spec 和交叉字段均拒绝。
- 既有合并测试扩展为 gRPC+HTTPUpgrade+XHTTP 六入站并由固定 `v26.3.27` 实际执行一次 `run -test`；目标 1/1、RAW/WS/共享分享相邻回归 12/12、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。没有新增测试文件，两个 profile 仍为 `IMPLEMENTING`，未运行持久化、Agent、构建或浏览器，未部署。

## 47. TASK047G2 XHTTP TLS 持久化与账户记录（2026-09-02）

- 创建事务显式映射 VLESS/Trojan `transport=xhttp/security=tls`，严格保存 `{ path }`、同主机受管证书和中性 Reality 列。VLESS 只写 generic UUID v2，Trojan 只写 generic PASSWORD；均不写 legacy client、shortId、Reality/inbound secret。跨主机证书或自定义 mode 扩展 spec 失败时业务行、operation 和 generation 整体不变。
- generic UUID/password 投影和完整主机快照覆盖两个 XHTTP profile；既有目标同时生成 WebSocket+gRPC+HTTPUpgrade+XHTTP 八入站配置，并由固定核心实际验证。XHTTP 账户 CRUD、分享和 observed tombstone 继续复用 generation/hash 事务；分享严格读取 path 并重验凭据、证书与 pin，固定输出 `mode=auto` 且响应保持 `private, no-store`。
- 综合持久化/账户目标 1/1、RAW TLS 相邻账户目标 1/1、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。没有新增测试文件，未运行 Agent、UI、构建或浏览器；两个 profile 仍为 `IMPLEMENTING`，未部署。

## 48. TASK047G3 XHTTP TLS createV2 与创建 UI 记录（2026-09-02）

- `createV2` 增加 VLESS/Trojan XHTTP TLS 严格判别分支，只接受 `{ path }`、受管证书 id、DNS SNI 和账户名称。生产状态门控继续拒绝 `IMPLEMENTING` profile；内部目标门控创建两类入站，公开拒绝后端口 reservation 保持可用。
- 创建 Dialog 由服务端目录派生 XHTTP TLS，复用独立 XHTTP path 草稿和既有证书/SNI/账户分区；切换主机/profile 清理草稿。请求不含浏览器凭据、mode、Host、headers、padding、xmux、downloadSettings、任意 TLS JSON 或证书材料。
- 服务 create/catalog 目标 2/2、复用既有 UI 测试文件的小回归 13/13、固定 `v26.3.27` 对创建配置的 `run -test`、`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。没有新增测试文件，未运行 Agent、生产构建、浏览器或无关全量套件；两个 profile 仍为 `IMPLEMENTING`，未部署。

## 49. TASK047G4 XHTTP TLS 真实连接与开放记录（2026-09-02）

- 既有 `server/xrayWebSocketTlsE2e.test.ts` 扩展为单个 WebSocket+gRPC+HTTPUpgrade+XHTTP 八 profile 循环，没有新增 E2E 文件。测试校验固定 `v26.3.27` 二进制 SHA-256，VLESS/Trojan XHTTP 均使用生产配置生成器和分享 URI 启动真实 server/client，经 SOCKS 访问本地 origin。
- 两协议均验证正确 `pcs` 成功、格式正确但值错误的 `pcs` 失败；同 SAN 受管证书轮换后旧 URI 失败、新 URI 成功。XHTTP 服务端和客户端固定 `mode=auto`，不含 `allowInsecure`、flow、shortId、Reality、Host、headers、padding、xmux 或 downloadSettings；合并 E2E 1/1 约 30.3 秒。
- 真实证据完成后只将 `VLESS_XHTTP_TLS` 与 `TROJAN_XHTTP_TLS` 标为 `AVAILABLE`；11 个 TCP TLS profile 至此全部开放，mKCP 两项仍等待 TASK049。profile/catalog/create 小回归 12/12、创建 UI 既有回归 13/13、`corepack pnpm exec tsc --noEmit`、一次生产构建、`git diff --check` 和既有 Playwright 1/1 通过；浏览器将 Trojan HTTPUpgrade 代表流程替换为 Trojan XHTTP，未增加用例，构建仅有既有大 chunk 提示。本任务未部署。

## 50. TASK048A VMess/Shadowsocks 规格核验记录（2026-09-02）

- 固定 SHA-256 为 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的 `v26.3.27` 对同一份 `VMESS_RAW_TLS` + `SHADOWSOCKS_2022_RAW_NONE` 最小多用户服务端配置执行 `run -test`，结果为 `Configuration OK`；同时观察到核心对 VMess/Shadowsocks 的 deprecated 警告，因此锁定 catalog/UI 显式告警。参考为 [Xray VMess inbound](https://xtls.github.io/en/config/inbounds/vmess.html)、[Xray Shadowsocks inbound](https://xtls.github.io/en/config/inbounds/shadowsocks.html)、[固定版本 Shadowsocks 构建源码](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/shadowsocks.go) 和 [SIP002 URI](https://github.com/shadowsocks/shadowsocks-org/wiki/SIP002-URI-Scheme)。
- 3x-ui 只读对照确认 VMess 默认 UUID/AEAD auto、Shadowsocks 默认 SS2022 和双 PSK 分享；ForwardX 未复制其任意组合或高级 JSON。VMess 首版只做 RAW+TLS+pin，Shadowsocks 只做标准可导入的 SS2022 RAW+none TCP，UDP 仍等 TASK051。
- 本规格任务没有新增测试文件，也未运行无关全量套件。后续 048B/C/E 只扩展现有 profile/access/持久化/UI 合并目标；真实连接分别集中在 048D/048F，生产构建和一个既有浏览器代表流程只在开放/总检查点运行。

## 51. TASK048B VMess/Shadowsocks 共享合同记录（2026-09-02）

- `shared/xrayProfiles.test.ts` 以一个表驱动目标覆盖 `VMESS_RAW_TLS` 与 `SHADOWSOCKS_2022_RAW_NONE`：严格空 spec、精确存储组合、固定 `v26.3.27`、`CORE_DEPRECATED` advisory，并确认两者保持 `IMPLEMENTING` 且不会进入生产可用目录。与既有 catalog 回归合计 12/12。
- `shared/xrayAccess.test.ts` 与 `server/xraySecretCrypto.test.ts` 复核既有 VMess UUID v1、Shadowsocks 用户 `SHADOWSOCKS_KEY` 策略，以及新增入站 `SHADOWSOCKS_SERVER_KEY` 独立 AAD 字段；access/secret 合并回归 15/15。
- 为减少重复覆盖，本任务只修改三个既有测试文件，没有新增测试文件；`corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。未运行 Agent、生产构建、浏览器、真实连接或仓库级全量套件，真实 VMess/SS 连接分别留到 048D/048F。

## 52. TASK048C VMess RAW TLS 垂直切片记录（2026-09-02）

- `VMESS_RAW_TLS` 已贯通生产配置编译、受管 TLS/SNI/叶证书 pin、UUID v1 安全持久化、完整主机快照、账户 CRUD/tombstone、VMess base64 JSON 分享、严格 createV2、创建 Dialog 和详情账户 UI。服务端固定 `security=auto`，拒绝 flow、`aid/alterId`、shortId、Reality 字段和未知 spec。
- 兼容性告警只使用服务端 profile 投影的 `CORE_DEPRECATED` advisory，在协议选择、创建确认和节点详情保持一致；详情与分享只展示凭据已配置状态，不回传 UUID、envelope、fingerprint 或完整配置。
- 为减少重复测试，本任务只扩展既有测试文件，没有新建测试文件。配置/分享目标 11/11、持久化 1/1、账户/分享 1/1、createV2 1/1、创建 UI 7/7、详情 UI 4/4、详情查询 1/1 和 `corepack pnpm exec tsc --noEmit` 通过；固定 `v26.3.27` 对生成配置的 `run -test` 通过。
- 未运行 Agent、仓库级全量套件、生产构建或浏览器测试；真实连接、错误 pin、证书轮换、一次构建和一个既有浏览器代表流程集中留到 048D。profile 继续保持 `IMPLEMENTING`，未部署。

## 53. TASK048D VMess RAW TLS 真实连接与开放记录（2026-09-02）

- 既有 `server/xrayWebSocketTlsE2e.test.ts` 增加一个 VMess 分支，没有新建 E2E 文件。测试校验固定 `v26.3.27` 二进制 SHA-256，使用生产配置生成器和 VMess URI 启动真实 server/client，经 SOCKS 访问本地 origin。
- VMess 正确 `pcs` 成功、错误 `pcs` 失败；同 SAN 受管证书轮换后旧 URI 失败、新 URI 成功。服务端客户对象精确为 `id/email/security=auto`，分享载荷字段集合固定，客户端不含 `aid/alterId`、flow、shortId、Reality 或 `allowInsecure`；合并 E2E 1/1 约 35.7 秒。
- 真实证据完成后只将 `VMESS_RAW_TLS` 标为 `AVAILABLE`，Shadowsocks 仍保持 `IMPLEMENTING`。profile/create 小回归 13/13、`corepack pnpm exec tsc --noEmit`、一次生产构建、`git diff --check` 和既有隔离 Playwright 1/1 通过；浏览器用 VMess 替换 Trojan XHTTP 代表流程，没有增加用例，构建仅有既有大 chunk 提示。
- 按用户要求未重复配置、持久化、账户、Agent 或仓库全量套件，本任务未部署。

## 54. TASK048E Shadowsocks 2022 RAW TCP 垂直切片记录（2026-09-03）

- `SHADOWSOCKS_2022_RAW_NONE` 已贯通严格空 spec、固定 `2022-blake3-aes-256-gcm`、RAW TCP、无 TLS/Reality 的生产配置编译；每个入站 server PSK 与每账户 user PSK 均为独立 32-byte canonical base64，分别使用资源绑定的 `SHADOWSOCKS_SERVER_KEY` 与 `SHADOWSOCKS_KEY` 加密上下文、fingerprint 和持久化投影。
- 账户新增、改名、停启、tombstone、SIP002/SIP022 明文 userinfo 分享和完整主机快照已贯通。启用中的节点拒绝停用或删除最后一个启用且非待删除账户，返回 `LAST_ACTIVE_ACCESS_REQUIRED` 且 generation 不变；禁用节点后允许清理。分享固定为 `ss://2022-blake3-aes-256-gcm:<server-psk>:<user-psk>@endpoint#name`，不写查询参数或整段 base64 userinfo。
- `createV2` 使用严格判别输入，仅接收基础字段、空 spec 和账户名称；普通服务继续拒绝 `IMPLEMENTING` profile，内部目标门控证明创建不暴露或复用密钥。创建与详情 UI 显示固定 method、“协议层加密（无 TLS/Reality）”、服务端生成密钥状态、`CORE_DEPRECATED` 告警和最后账户中文提示，不提供 method、PSK 或任意 JSON 输入。
- 为减少重复测试，只扩展既有合并测试文件。分享 10/10、配置 3/3、持久化 1/1、账户/分享 1/1、createV2 1/1、创建 UI 7/7、详情 UI 4/4 和 `corepack pnpm exec tsc --noEmit` 均通过；固定 `v26.3.27` 对生成配置的 `run -test` 已通过。未运行 Agent、仓库全量、生产构建、浏览器或真实连接；profile 继续保持 `IMPLEMENTING`，这些开放检查集中留到 048F。本任务未部署。

## 55. TASK048F Shadowsocks 2022 真实连接与开放记录（2026-09-03）

- 既有 `server/xrayWebSocketTlsE2e.test.ts` 增加一个独立 Shadowsocks 目标，没有新建 E2E 文件。测试校验固定 `v26.3.27` 二进制 SHA-256，使用生产配置生成器和生产 `ss://` 分享 URI 启动真实 server/client，经 SOCKS 访问完全本地 origin。
- 同一服务端配置包含两个独立 user PSK；两名用户均连接成功，格式正确但错配的 server PSK 与 user PSK 分别连接失败。服务端精确为固定 method、server password、`network=tcp` 和两项 client password；客户端从 SIP002/SIP022 明文 userinfo 构建 `server-psk:user-psk`，不含查询参数、TLS、Reality、flow、shortId 或 UDP 设置。按测试名过滤后真实目标 1/1 通过，TLS 大矩阵 1 项被跳过，总耗时约 14 秒。
- 真实证据通过后只将 `SHADOWSOCKS_2022_RAW_NONE` 标为 `AVAILABLE`；profile/catalog/create 定向回归 13/13、`corepack pnpm exec tsc --noEmit`、一次生产构建和既有隔离 Playwright 1/1 通过。浏览器把上次 VMess 兼容协议代表流程替换为 Shadowsocks，没有增加用例，覆盖三种视口、固定 method、无 TLS/Reality、安全告警和无密钥提交载荷；首次运行仅因两张兼容卡有相同警告导致严格选择器歧义，限定到 Shadowsocks 卡后重跑通过。构建只有既有大 chunk 提示。
- 按用户要求未重复配置、持久化、账户、Agent、TLS 真实矩阵或仓库全量套件。本任务未部署。

## 56. TASK048G VMess/Shadowsocks 总检查点记录（2026-09-03）

- 总检查直接复用现有混合目标，没有新增或修改业务测试。固定 `v26.3.27` 下的 VMess TLS + Shadowsocks 2022 RAW 配置、完整主机快照、通用账户事务、最后 Shadowsocks 账户保护，以及 VMess/SS 两种严格分享格式合计 15/15 通过。
- 现有可观测性和密钥泄漏目标 4/4 通过，覆盖嵌套 JSON、命令输出、VMess/Shadowsocks URI、UUID/PSK 类敏感值、结构化日志、审计/支持包 allowlist 和 API 错误边界。两协议均保持 `CORE_DEPRECATED` 告警，只有已真实验证的 `VMESS_RAW_TLS` 与 `SHADOWSOCKS_2022_RAW_NONE` 组合为 `AVAILABLE`。
- 048F 已完成生产构建、浏览器和单协议真实连接，因此本总检查按用户要求没有重复这些项目，也未运行 Agent 或仓库全量套件。TASK048 全部验收项完成，本任务未部署。

## 57. TASK049 UDP 基础设施精简验证计划（2026-09-03）

- 合同只扩展既有 `shared/xrayTypes.test.ts` 与 `agent/xray_types_test.go`：同一组 UDP capability/desired/observed/task 夹具两端均通过；省略 UDP capability 的旧 payload 解析为 false，`both`、UDP 多端口和非法 network 拒绝；既有 v1 TCP examples 不改字节并继续通过。
- Agent 只扩展既有 port probe/runtime 目标：真实 UDP bind 区分可用/占用且结果不含进程信息；`/proc/net/udp`/`udp6` 只在 network、地址、端口和受管 PID socket inode 同时匹配时 READY；同 runtimeTag 的 TCP/UDP listener 不能互相覆盖。
- 面板只扩展既有 schema、heartbeat 和 port reservation 目标：旧 capability 两项 UDP 列落 false；UDP operation 无能力时零写入；task/result/reservation/消费复核 network；同 host+port 的 TCP/UDP 可并存，相同 network 冲突，`both` 占用两个网络。
- 按用户要求不重复浏览器、生产构建、真实 Xray 客户端矩阵或仓库全量套件。TASK049 总检查只运行上述目标、一个既有 TCP reservation 回归、TypeScript 检查、Go vet 和文档构建；047H/050/051 各自承担 profile 真实 UDP 连接证据。
- 049B 结果：单个共享 UDP 夹具由 TypeScript/Go 两端通过；旧 v1 TCP examples 原样通过，旧 capability 缺失 UDP 字段为 false，`both` 和 UDP 多端口均拒绝。`shared/xrayTypes.test.ts` 13/13、Go v1 合同目标与 `corepack pnpm exec tsc --noEmit` 通过；未运行无关套件。
- 049C 结果：真实 socket 目标证明 TCP 已占用的同端口仍可 UDP bind、UDP 已占用返回 `PORT_IN_USE`；真实 procfs 目标证明 UDP-only 时同 tag TCP 为 MISSING/UDP 为 READY，补齐 TCP 后二者分别 READY。相邻 Agent port probe/readiness 目标与 Go vet 通过；未运行 Agent 全量、race、浏览器、生产构建或真实 Xray profile。
- 049D 结果：三数据库 schema 目标 7/7、UDP capability/listener 心跳目标 1/1、DTO 3/3、共享 reservation 3/3、SQLite+tRPC port operation 1/1 和 TypeScript 检查通过。覆盖旧 capability 默认 false、UDP listener network 持久化、无双能力零 operation、派发前能力降级不下发 UDP、UDP AUTO 单端口、operation/result/reservation/消费 network 复核、同端口 TCP/UDP 并存、同网络冲突及 `both` 双网络冲突。
- TASK049 总检查复用上述新鲜结果，只补跑跨语言合同、Agent UDP bind/readiness、Go vet 和文档构建；按用户要求未重复浏览器、生产构建、真实 Xray 客户端矩阵、Agent 全量/race 或仓库全量套件。

## 58. TASK047H mKCP TLS 精简验证计划（2026-09-03）

- H1 只扩展既有 profile、TLS transport compiler 和分享表驱动目标：两个 profile 保持 `IMPLEMENTING`，严格 `{}` 生成 `network=kcp` 与 `kcpSettings={}`；URI 固定 `type=kcp/security=tls/sni/fp/pcs`，VLESS 另含 `encryption=none`，且不含调优、seed/header、FinalMask、flow 或 `allowInsecure`。
- H2/H3 只扩展既有混合持久化、heartbeat、createV2 和 reservation 目标：expected listener 为 UDP，TCP/UDP 同端口不冲突；旧 Agent 或缺任一 UDP capability 时 catalog/create/desired 均安全门控，reservation 不被错误消费，持久化和 generation 不变化。
- H4 复用既有创建/详情 UI 目标，证明 mKCP 只在具备双 UDP capability 的选定主机可选，升级原因可见，切换主机/profile 清理不兼容草稿，提交载荷无凭据、mKCP 参数、证书材料或任意 JSON。
- H5 才运行一次固定 `v26.3.27` 两协议真实客户端、错误 pin、证书轮换、真实 UDP readiness/混合回滚、生产构建和一个既有浏览器代表流程；证据通过前不改为 `AVAILABLE`。不运行仓库级 `pnpm test:server`、Agent 全量/race 或重复 TCP TLS E2E。
- H1 结果：profile 目标 12/12 通过，覆盖 UDP listener、`IMPLEMENTING` 状态、严格空 spec 和所有额外 mKCP 字段拒绝；合并 TLS transport 目标 1/1 通过，并使用固定 SHA-256 对应的 `v26.3.27` 实际执行配置测试。配置只含空 `kcpSettings`，分享只含固定 kcp/TLS/pin 参数；TypeScript 与 `git diff --check` 通过。
- H2 结果：主机编译目标 10 项通过，证明 expected listener 从 profile 推导为 UDP 且 TCP/UDP 端口空间独立；heartbeat UDP 子目标 1/1 通过，TCP 同端口不能冒充 UDP readiness。desired 在读取并生成含密钥的完整快照前复核两项 UDP capability，缺任一项返回空 desired。
- H3 结果：固定核心持久化目标 1/1 通过，两个 profile 均只落 generic access/secret 并生成空 `kcpSettings`；聚合 create/capability/account 目标 1/1 通过，覆盖两项能力分别缺失、零业务写入、generation 不变、UDP reservation 保留复用、TCP reservation 拒绝、VLESS/Trojan 创建、账户增改删与严格 kcp/TLS/pin 分享。TypeScript 与 `git diff --check` 通过，按精简计划未运行 UI、构建、浏览器、Agent 行为、真实客户端或仓库全量套件。
- H4 结果：host-aware catalog/create 聚合目标 2/2、创建 UI 14/14、严格请求 7/7、详情 UI 5/5 与 TypeScript 通过。catalog 对双 UDP capability 缺失返回 `UDP_CAPABILITY_REQUIRED`，具备能力但未开放时返回 `NOT_IMPLEMENTED`；UI 只消费可用项，显示升级诊断，并在 TCP/UDP profile 切换时清除 reservation 和隐藏传输/安全草稿后回到正确网络探测。mKCP 不渲染调优输入；详情按 UDP readiness 判定 RUNNING，只展示安全证书 DTO/SNI。两个 profile 继续为 `IMPLEMENTING`，H5 前未运行构建、浏览器、Agent 或真实连接。
- H5 结果：固定 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的 `v26.3.27` 合并 TLS 目标增加两个 mKCP 分支，生产生成器输出空 `kcpSettings`，生产 URI 构建真实 client；两协议均经 UDP mKCP + SOCKS 成功访问本地 origin，错误 `pcs` 拒绝，证书轮换后旧 URI 拒绝、新 URI 成功，按名过滤 1/1 通过、约 39.4 秒。Agent 定向 2 项通过，证明 PID-owned TCP/UDP readiness 不互相冒充，含 TCP+UDP 的新快照在 readiness 耗尽后恢复同样的 last-good 混合监听。
- 真实证据完成后 `VLESS_MKCP_TLS`/`TROJAN_MKCP_TLS` 标为 `AVAILABLE`。profile/catalog/create 14/14、创建/请求/详情 UI 19/19、`corepack pnpm exec tsc --noEmit`、一次 `corepack pnpm build`、`git diff --check` 和既有隔离 Playwright 1/1 通过；浏览器不新增用例，只把 RAW TLS 代表创建替换为 mKCP，验证 TCP→UDP 切换清理 reservation、UDP 再探测、固定默认值文案和严格无高级字段载荷。构建只有既有大 chunk 提示。按用户要求未运行仓库级 `pnpm test:server`、Agent 全量/race 或重复 E2E；本任务未部署。

## 59. TASK047I TLS profile 总检查点记录（2026-09-03）

- 总目录目标先按红绿循环复现两个已开放 mKCP profile 未进入旧断言的问题，修正后 `server/xrayRawTlsCreate.test.ts` 在固定 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的 Xray `v26.3.27` 下 1/1 通过。
- 复用现有 TLS transport 持久化目标建立单一 13 profile 快照：VLESS RAW 标准/Vision、Trojan RAW，以及两个协议的 WS/gRPC/HTTPUpgrade/XHTTP/mKCP 同时持久化和生成。测试证明只使用 generic UUID/password、无 legacy client/Reality secret，generation 单调，RAW/应用层传输为 TCP、mKCP 为 UDP；生成的完整配置经固定 `v26.3.27` `run -test`，目标 1/1 通过。
- `shared/xrayShare.test.ts` 新增一张 13 profile 表，逐项验证 URI scheme/凭据及允许的完整 query 集合；整个文件 11/11 通过。现有 `server/xrayObservability.test.ts` 与 `server/xraySecretLeak.test.ts` 4/4 通过，覆盖 VLESS/Trojan URI、UUID、密码、私钥、证书字段、嵌套配置和日志/审计/API/支持包边界。
- `corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。047H 已执行真实 mKCP 客户端、错误 pin、证书轮换、Agent、构建和浏览器，本总检查按用户要求不重复这些项目，也未运行仓库全量套件；TASK047 全部完成，本任务未部署。

## 60. TASK050 Hysteria 2 精简验证计划（2026-09-03）

- 050A 依据 [Xray Hysteria inbound](https://xtls.github.io/en/config/inbounds/hysteria.html)、[Xray Hysteria transport](https://xtls.github.io/en/config/transports/hysteria.html)、[固定 v26.3.27 Hysteria 配置源码](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/hysteria.go) 和 [Hysteria 2 URI 规范](https://v2.hysteria.network/docs/developers/URI-Scheme/) 锁定 `settings.clients`、Hysteria v2、TLS-only、auth 和 `pinSHA256` 语义；固定 tag 源码优先于可能随新版本变化的网页字段名。
- 独立风险探针先对服务端/客户端各执行一次 `run -test`，再用 SHA-256 为 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的 Xray `v26.3.27` 启动真实 UDP server/client，经本地 SOCKS 访问本地 HTTP origin，结果通过。客户端只设置 SNI、h3 和叶证书 `pinnedPeerCertSha256`，没有 `allowInsecure`；临时探针和证书均已删除，没有新增业务测试文件。
- 050B–D 只扩展既有 profile/config/share、持久化/create/account 和创建/详情 UI 的表驱动目标；每段先红后绿，只运行受影响目标和必要的 TypeScript 检查。已有 TLS 证书 CRUD、通用 UDP schema/probe/readiness 和其余协议矩阵不重复。
- 050E 复用一个真实 E2E 目标集中证明生产生成器/分享 URI、正确 auth 成功、错误 auth 失败、叶 pin 校验、Agent UDP readiness、TCP+UDP 混合快照 last-good、一次生产构建和一个代表浏览器流程，证据完成后才把 profile 改为 `AVAILABLE`。不运行仓库级 `pnpm test:server`、Agent 全量/race 或重复完整 TLS 矩阵。
- `pinSHA256` 只能来自受管叶证书；不得使用 CA hash。该边界同时遵循 [Xray TLS pin 语义](https://xtls.github.io/en/config/transports/tls.html) 与 [Xray CA pin 安全公告 GHSA-5wf9-h793-w73c](https://github.com/XTLS/Xray-core/security/advisories/GHSA-5wf9-h793-w73c)。
- 050B 结果：profile 测试先以未知 `HYSTERIA2_TLS` 红灯，随后注册 UDP/Hysteria/TLS、`HYSTERIA_AUTH`、严格空 spec 且保持 `IMPLEMENTING`；`shared/xrayProfiles.test.ts` 13/13 通过。配置目标先因未支持 auth 归一化红灯，随后生产生成器输出 `settings.version=2/clients.auth`、`network=hysteria`、h3、固定 60 秒和内联证书，拒绝空账户、非 canonical auth、非 TLS 与扩展 spec；固定 `v26.3.27` `run -test` 通过，文件内 2/2 通过。
- 分享目标先因构建器不存在红灯，随后严格生成只有 `sni/pinSHA256` 的标准 URI；`shared/xrayShare.test.ts` 12/12 与 `corepack pnpm exec tsc --noEmit` 通过。050B 只扩展三个既有测试文件，未运行持久化、Agent、UI、构建、浏览器、真实连接或仓库全量套件；profile 继续保持 `IMPLEMENTING`，未部署。
- 050C 先扩展既有 RAW TLS 持久化目标，证明 Hysteria auth 只进入 generic access/secret、混合快照可编译且固定核心 config test 通过；`server/xrayRawTlsPersistence.test.ts` 1/1 通过。随后只扩展既有 UDP TLS create 目标，覆盖 UDP reservation、创建/账号/入站修改双 capability 零写入、32-byte canonical auth、受管证书分享、最后有效账户保护、desired UDP listener 与收敛；`server/xrayMkcpTlsCreate.test.ts` 1/1 和 TypeScript 通过。未重复 profile/config/share 单测、TLS CRUD、Agent、UI、构建、浏览器或仓库全量套件；profile 继续保持 `IMPLEMENTING`，未部署。
- 050D 复用 host-aware UDP catalog 规则：缺少任一 UDP capability 时 Hysteria 2 返回 `UDP_CAPABILITY_REQUIRED`，能力齐备但开放验收未完成时返回 `NOT_IMPLEMENTED`。创建请求、传输只读摘要、受管 TLS/SNI、账户隐藏状态、详情/列表与分享入口均已接入；4 个既有目标联合 15/15 和 TypeScript 通过。未运行服务端配置/持久化、Agent、构建、浏览器或真实客户端；profile 继续保持 `IMPLEMENTING`，未部署。
- 050E 新增一个可按名称单独运行的 Hysteria 2 真实目标，并只执行该目标：生产生成器生成固定 v2/h3/60 秒 UDP 服务端，生产分享函数生成仅含 `sni/pinSHA256` 的 URI；正确 auth + 叶 pin 经 SOCKS 访问本地 HTTP 成功，错误 auth 和错误 pin 均失败，固定核心目标 1/1 通过，其余 11 个 TLS profile 与 Shadowsocks 目标按名称过滤跳过。
- Agent 只运行 `TestXrayApplyListenerProbeSeparatesTCPAndUDPWithSameRuntimeTag` 与 `TestXrayApplyListenerFailureRollsBackOnlyAfterReadinessExhausted`，2/2 通过，分别证明受管 PID 的 UDP readiness 和 TCP+UDP 混合监听失败后恢复 last-good。profile/catalog/UDP create 红绿回归 15/15、一次生产构建和既有 Playwright smoke 1/1 通过；浏览器将原 mKCP 代表创建段替换为 Hysteria 2，没有新增用例，并验证 TCP reservation 清除、UDP 重探测、固定项、受管 TLS/SNI、pin 提示及无 auth/高级字段的 createV2 载荷。
- 证据完成后 `HYSTERIA2_TLS` 已标记为 `AVAILABLE`。按精简计划未运行仓库级 `pnpm test:server`、Agent 全量/race、完整 TLS 矩阵、TLS 证书 CRUD 或重复 TypeScript 全量检查；050D 已通过 TypeScript，本轮新增测试由真实执行覆盖，生产代码只变更已验证 profile 状态。构建仅有既有大 chunk 提示，任务未部署。

## 61. TASK051 Shadowsocks UDP 精简验证计划（2026-09-03）

- 051A 依据 [Xray Shadowsocks inbound](https://xtls.github.io/en/config/inbounds/shadowsocks.html) 和 [固定 v26.3.27 Shadowsocks 配置源码](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/shadowsocks.go) 锁定原生 listener 语义：`network=tcp` 仍可能承载 XUDP，但只有 `network=tcp,udp` 才能作为 TCP+UDP 双 listener 验收。3x-ui 当前表单默认同样为 `tcp,udp`，只用于只读核对产品入口，不复制其 method、ivCheck 或任意组合。
- 固定 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的 Xray `v26.3.27` 已完成一次无仓库文件的风险探针：`run -test` 通过并保留核心 deprecated 告警，实际启动后同一 runtimeTag/port 同时出现受管 PID 的 TCP LISTEN 与 UDP UNCONN socket。探针只证明配置与 socket 事实，不替代 051E 的生产路径、原生 UDP 流量和回滚证据。
- 051B–D 只扩展既有 profile/config、host/heartbeat/create/reservation、创建/详情 UI 的聚合目标；每段先红后绿，只执行受影响目标和必要 TypeScript 检查。既有 SS TCP 多用户、通用 UDP bind/procfs、TLS、数据库全量和其他协议矩阵不重复。
- 双网络端口继续使用两个既有 `PORT_PROBE`：同一端口分别探测 TCP 与 UDP，创建 API 以规范 `portReservations` 精确接收两份 reservation；不向 Agent 发送 `both`。测试必须证明只提供一份、网络重复、host/user/port 不同、能力降级或竞态失败时零业务写入且两个 reservation 不被部分消费。
- 051B 结果：profile 定向目标 13/13、RAW/SS 编译目标 3/3（含固定 SHA-256 对应 `v26.3.27` 的 `run -test`）、heartbeat UDP 子目标 1/1 与 TypeScript 通过。新 profile 保持 `IMPLEMENTING`；配置只增加 `network=tcp,udp`，同一入站展开 TCP/UDP 两个 expected listener，存储 heartbeat 也要求两项同时 READY。未运行仓库全量、Agent、构建、浏览器或真实 UDP 客户端。
- 051C 结果：端口操作聚合目标 1/1 证明双 reservation 先全部校验再同时消费，重复 ID/网络不匹配后两项仍有效；专用 Shadowsocks UDP 创建目标 1/1 覆盖严格 createV2 形状、能力降级零写入、单双字段混用拒绝、双 PSK 持久化/投影、账户新增/分享/最后账户保护、普通修改和 TCP+UDP 全量 readiness。TypeScript 与 diff 检查通过；双网络端口更新因旧 API 只有单 reservation 而按 ADR-066 安全拒绝。未运行无关 RAW/TLS 大矩阵、生产构建、浏览器、Agent 或真实客户端。
- 051D 结果：创建页把 Shadowsocks 的“仅 TCP”和“TCP + UDP”作为两个明确 profile 展示；选择双网络会清空单网络预留，先按当前 AUTO/MANUAL 策略探测 TCP，再对同一端口自动发起 UDP MANUAL 探测。状态机分别展示两项结果，只有端口一致且均未过期才开放后续分区；createV2 只提交 `{ tcp, udp }` reservation ID，确认与详情显示 `TCP + UDP`，运行时显示两个 listener。仅运行三个受影响前端目标 23/23、TypeScript 和 diff 检查；未运行生产构建、浏览器、Agent、真实客户端或其他协议矩阵，均集中留到 051E。
- 051E 结果：复用既有 Shadowsocks 真实目标并按名称只运行双网络目标 1/1，固定 SHA-256 对应的 Xray `v26.3.27` 由生产生成器启动 `network=tcp,udp`，两个用户 TCP 与经客户端原生 UDP outbound 的本地 UDP 请求/响应均成功，错误 server/user PSK 均失败；其余两个目标过滤跳过。Agent 只运行同 runtimeTag/port 的 TCP/UDP 受管 PID 探测与混合 listener readiness 失败恢复 last-good 两个目标，2/2 通过。
- profile/catalog/create 开放回归 15/15、TypeScript、diff、一次生产构建和既有 Playwright smoke 1/1 通过；浏览器没有新增用例，改用双网络 Shadowsocks 代表流程，验证 TCP/UDP 同端口双探测、两份独立 reservation、确认文案和无密钥 createV2 载荷。首次浏览器执行暴露测试桩把第五次探测送入真实后端并触发活动任务上限，改为在浏览器桩内闭环 operation/result 后复跑通过；生产逻辑未因此修改。证据齐全后 `SHADOWSOCKS_2022_RAW_TCP_UDP_NONE` 已标记 `AVAILABLE`。按精简计划未运行仓库级 `pnpm test:server`、Agent 全量/race、完整 TLS 矩阵、重复 SS TCP-only E2E 或其他协议矩阵；构建只有既有大 chunk 提示，任务未部署。

## 62. TASK051 WireGuard 精简验证计划（2026-09-03）

- 051F 依据 [Xray WireGuard inbound](https://xtls.github.io/en/config/inbounds/wireguard.html)、[固定 v26.3.27 WireGuard 配置源码](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/wireguard.go)、[固定版本 server 实现](https://github.com/XTLS/Xray-core/blob/v26.3.27/proxy/wireguard/server.go) 和本地 3x-ui 只读代码锁定 `WIREGUARD_UDP_NONE`。profile 固定 UDP/NONE/none、gVisor、MTU 1420、`10.0.0.0/24`、服务端生成 key/PSK 和标准 IPv4 全隧道 `.conf`；不复制 kernel TUN、workers、reserved、domainStrategy、IPv6、自定义 subnet/MTU/DNS/route 或任意 JSON。
- 固定 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的 Xray `v26.3.27` 已完成一次无仓库文件的双 peer 风险探针：server 与两个 client 配置均先通过 `run -test`，同一 gVisor WireGuard inbound 分配唯一 `10.0.0.2/32`、`10.0.0.3/32` 后，两个独立客户端都完成握手并经 SOCKS 访问完全本地 TCP origin。临时脚本/config 已清理；该探针只消除多 peer/gVisor 可行性风险，不替代 051J 的生产生成器、UDP、错误 key/PSK、Agent 回滚或泄漏验收。
- 051G–I 每段只扩展一个受影响聚合目标并执行必要 TypeScript：G 覆盖隐藏 profile、canonical key/PSK、peer 编译与标准配置；H 覆盖 UDP reservation/capability、唯一地址事务、createV2 和 peer CRUD；I 覆盖创建/详情/分享 UI 与浏览器持久层禁密。固定核心、Agent、secret 总检查、构建和浏览器只在 051J 各执行一次，不运行仓库全量、TLS/Reality/SS/Hysteria 重复矩阵或 Agent race。
- 051G 聚合目标已按红绿顺序完成：隐藏 `IMPLEMENTING` profile、严格 v2 `/32` settings、CSPRNG/clamped private key、PSK、RFC 7748 公钥派生、资源隔离加密、固定两 peer server 配置、单 UDP listener 和标准 `.conf` 均通过；另运行既有 access schema 目标，合计 4/4，TypeScript 与 diff 检查通过。未提前运行 051J 保留的固定核心、Agent、构建或浏览器检查。
- 051H 聚合目标先红后绿，最终 1/1 通过：覆盖能力降级时零写入且 UDP reservation 保留、严格 createV2、server/peer 双类 secret、事务内 `.2/.3/.4/.5` 分配、tombstone 不提前复用、peer CRUD/最后有效 peer 保护、标准 `.conf` 的 no-store API、普通 DTO 禁密、desired hash 与单 UDP observed listener 收敛。`corepack pnpm exec tsc --noEmit` 与 diff 检查通过；未运行固定核心、Agent、secret 总检查、构建、浏览器、仓库全量或其他协议矩阵。
- 051I 已完成 WireGuard 单 UDP 创建请求、固定 profile/风险摘要、只含名称的初始 peer、详情地址/启停/待同步状态、最后 peer 错误文案，以及标准 `.conf` 文本/同内容二维码/复制/下载界面。分享关闭、失败与下载会清除组件内存和对应 React Query cache，不写 URL 或浏览器持久存储；普通详情不渲染 key/PSK/fingerprint/keyVersion。首次聚焦运行 20 个受影响目标时 19 个通过并发现一处既有账户按钮空格回归，修复后相关详情目标 2/2、最终 WireGuard UI 目标 3/3 和 TypeScript 均通过；未运行 051J 保留的固定核心、Agent、secret 总检查、构建、浏览器、仓库全量或其他协议矩阵。
- 051J 使用固定 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 的 Xray `v26.3.27`，从生产生成器构建单 UDP server 配置，并从生产标准 `.conf` 反解析两个独立 client：两个 peer 的 TCP、第二个 peer 的原生 UDP 均通过，错误 peer private key 与错误 PSK 均无法建立连接。首次真实请求命中 gVisor 对 loopback destination 的 martian 丢弃，测试 origin 改为同机非回环 IPv4 后通过；生产配置未因此改变。
- Agent 只运行 UDP/TCP 同 runtimeTag readiness 分离与监听失败耗尽重试后恢复 last-good 两个既有目标，2/2 通过；统一 secret-leak 目标加入 WireGuard private key、PSK、整份 `.conf` 和 support bundle 驼峰诊断键，发现并修复 `wireGuardPrivateKey`/`wireGuardPsk`/`wireGuardConfig` 结构化键脱敏后 1/1 通过。
- 真实证据完成后 `WIREGUARD_UDP_NONE` 已标记 `AVAILABLE`。profile/catalog/compiler 定向回归 15/15、TypeScript、一次生产构建、`git diff --check` 和既有隔离 Playwright smoke 1/1 通过；浏览器没有增加用例，而是用 WireGuard 替换旧 Hysteria 2 与 Shadowsocks 创建段，覆盖 TCP→UDP reservation 清理、固定安全边界、双 peer 无密钥载荷、详情地址、标准 `.conf`、二维码、关闭后重新取数、下载同内容文件及 URL/localStorage/sessionStorage 禁密。两次浏览器首跑只修正复合文本定位，生产行为未变。按精简计划未运行仓库全量、Agent 全量/race 或其他协议真实矩阵；代码提交为 `49f0451`，未部署。

## 63. TASK052 HTTP 管理代理精简验证计划（2026-09-03）

- 052A 依据固定 [Xray v26.3.27 HTTP 配置源码](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/http.go)、[HTTP server 实现](https://github.com/XTLS/Xray-core/blob/v26.3.27/proxy/http/server.go) 和本地 3x-ui 只读实现锁定 `HTTP_RAW_NONE`。固定核心在 accounts 非空时校验 Proxy-Authorization Basic，accounts 为空时不强制认证，因此 ForwardX 必须拒绝零有效账户并固定 `allowTransparent=false`。
- 052B–D 先连续完成 profile/credential/compiler/share、持久化/create/CRUD 和创建/详情/分享 UI，不在每个文件或小改动后重复执行测试。复用现有 profile、通用 access、RAW 持久化/create、详情 UI 与浏览器 smoke 文件，不为相同层级创建重复测试套件。
- 052E 再集中运行：一个固定核心生产路径目标覆盖正确认证的普通 HTTP 和 CONNECT、缺失/错误 username/password 拒绝；一个现有服务端聚合目标覆盖严格输入、两份资源绑定 secret、原子事务、最后账户保护、分享/no-store 和 DTO 禁密；Agent 只复用 TCP readiness 与失败恢复 last-good 目标；另运行统一 secret-leak、TypeScript、一次生产构建和一个代表浏览器流程。
- `HTTP_RAW_NONE` 只有在上述真实证据完成后才从 `IMPLEMENTING` 改为 `AVAILABLE`。不运行仓库级全量、Agent 全量/race、TLS/Reality/UDP/WireGuard 真实矩阵或无关 UI 用例。
- 052B–D 已连续完成共享合同、生产编译/分享、资源绑定双 secret 投影、持久化/createV2/账户 CRUD、创建/详情/分享 UI，并在 052E 集中验证。固定 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 对应的 Xray `v26.3.27` 真实目标 1/1 通过：正确 Basic 认证的普通 HTTP 与 CONNECT 成功，缺失认证、错误用户名和错误密码均返回 `407`。
- 服务端 HTTP 创建/持久化/CRUD/分享聚合目标 1/1、共享 profile/access/share/observability 33/33、catalog 1/1、secret-leak 1/1 通过；Agent 生产 desired listener 1/1、TCP readiness/失败恢复 last-good 2/2 通过；TypeScript、一次生产构建和隔离 Chromium 代表流程 1/1 通过。构建只有既有大 chunk 提示；按精简计划未运行仓库全量、Agent 全量/race、其他协议真实矩阵或无关 UI 用例。`HTTP_RAW_NONE` 已标记为 `AVAILABLE`，本任务未部署。

## 64. TASK052 SOCKS/Mixed 管理代理精简验证计划（2026-09-03）

- 052F 依据 [Xray SOCKS/Mixed 官方文档](https://xtls.github.io/en/config/inbounds/socks.html)、固定 [protocol 到配置映射](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/xray.go)、[SocksServerConfig](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/socks.go)、[server 分流实现](https://github.com/XTLS/Xray-core/blob/v26.3.27/proxy/socks/server.go)、[SOCKS4/5 认证实现](https://github.com/XTLS/Xray-core/blob/v26.3.27/proxy/socks/protocol.go)、[UDP filter](https://github.com/XTLS/Xray-core/blob/v26.3.27/proxy/socks/udpfilter.go) 与本地 3x-ui 只读行为锁定 `MIXED_RAW_NONE`。固定核心的 `mixed`/`socks` 使用同一配置和 listener，密码模式支持认证 SOCKS5 与内嵌 HTTP 并拒绝 SOCKS4；ForwardX 固定 TCP-only，避免 UDP 按来源 IP 放行造成共享 NAT 认证缺口。
- username/password 长度同时满足 [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) 的 255 octet 上限；协议也明确其口令可被链路观察者读取。3x-ui 不为 Mixed 生成订阅链接，因此 ForwardX 只返回结构化双代理地址，不进入订阅。
- 052G 连续完成隐藏 profile/credential/compiler/share、持久化/createV2/CRUD/最后账户保护和 TCP desired/observed，不在每个文件后跑测试。052H 随后完成 UI，再集中只运行：一个固定核心生产路径目标覆盖同一端口/凭据的 SOCKS5 TCP、HTTP 和 CONNECT，缺失/错误凭据及 SOCKS4 失败且无 UDP socket；一个现有服务端聚合目标覆盖严格输入、双 secret、事务、分享/no-store 和 DTO 禁密；Agent 只复用 TCP readiness/last-good；另运行统一 secret-leak、TypeScript、一次生产构建和一个代表浏览器流程。
- `MIXED_RAW_NONE` 只有在 052H 上述证据完成后才从 `IMPLEMENTING` 改为 `AVAILABLE`。不运行仓库级全量、Agent 全量/race、既有 HTTP/TLS/Reality/UDP/WireGuard 真实矩阵或无关 UI 用例。
- 052G 已完成隐藏 profile、凭据/分享合同、生产编译、通用持久化/createV2/CRUD、最后账户保护、单 TCP desired/observed 和 `socks5://` 泄漏 scrubber。按用户明确的“代码写完再测”要求，本阶段没有运行任何测试、TypeScript、构建、Agent 或浏览器检查；profile 继续保持 `IMPLEMENTING`，验证没有被标记为通过。
- 052H 已完成创建、详情、账户和双地址分享 UI。浏览器只提交账户备注；详情只显示 USERNAME/PASSWORD 已配置状态；分享 Dialog 同时按需展示 `socks5://` 与 `http://`、各自二维码和复制入口，关闭或失败同时清理两项内存与 React Query cache，不写订阅、URL 或浏览器持久存储。
- 固定 SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` 对应的 Xray `v26.3.27` 真实 Mixed 目标 1/1 通过：同一账户/端口的认证 SOCKS5 TCP、普通 HTTP 和 CONNECT 均成功；匿名/错误凭据、SOCKS4 均失败，且同端口 UDP 可独立 bind，证明没有 UDP listener。服务端创建/持久化/CRUD/desired/DTO/双分享/no-store 聚合目标 1/1，开放后的 profile/catalog 小回归 5/5，access 与统一 secret-leak 4/4，Mixed UI/内存/observability 聚焦目标均通过。
- Agent 只用经官方 SHA-256 校验的临时 Go 1.23.1 工具链运行 TCP PID ownership readiness 与 readiness 耗尽后恢复 last-good 两个既有目标，2/2 通过；TypeScript、一次生产构建和隔离 Chromium 代表流程 1/1 通过。构建只有既有大 chunk 提示；浏览器证明只发起 TCP probe、createV2 无 username/password/UDP、双地址响应 `private, no-store` 且凭据不进入 URL/localStorage/sessionStorage。`MIXED_RAW_NONE` 已标记 `AVAILABLE`，代码提交为 `7ea3ab0`、`34b19e7`、`ac56325`；按精简计划未运行仓库全量、Agent 全量/race、既有 HTTP/TLS/Reality/UDP/WireGuard 真实矩阵或无关 UI 用例，本任务未部署。

## 65. TASK052 Tunnel 精简验证计划（2026-09-03）

- 052I 依据 [Xray Tunnel 官方文档](https://xtls.github.io/en/config/inbounds/tunnel.html)、固定 [v26.3.27 protocol 映射](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/xray.go)、[Dokodemo 配置源码](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/dokodemo.go)、[运行实现](https://github.com/XTLS/Xray-core/blob/v26.3.27/proxy/dokodemo/dokodemo.go) 和本地 3x-ui 只读实现锁定 `TUNNEL_TCP_LOCAL_NONE`。固定 tag 使用 `address/port/network` 旧字段，不能照抄更新核心的 `rewriteAddress/rewritePort/allowedNetwork`。
- Xray Tunnel 没有认证模型，因此不做“公网强认证 Tunnel”的虚假抽象；首版以服务端固定 `127.0.0.1` 监听满足 MP007。只接收一个规范目标，不开放 3x-ui 的任意 `portMap`、followRedirect/TProxy 或路由；零账户、零 secret、零分享是应验证的合同，不是缺少测试数据。
- 052J 先连续完成隐藏 profile、严格 spec、生产编译、零账户持久化/createV2、详情投影和创建/详情 UI；按用户要求代码闭环前不运行测试、TypeScript、构建、Agent 或浏览器检查。
- 052K 再集中运行：一个固定核心生产路径目标覆盖回环入口到唯一 TCP 目标的双向转发、目标未监听失败且同端口 UDP 可绑定；一个服务端聚合目标覆盖 strict input、非回环 fail closed、零账户/secret、原子 reservation/generation、deterministic config 和详情投影；Agent 只复用 TCP PID readiness 与 last-good 目标；另运行 TypeScript、一次生产构建和一个代表浏览器流程。
- `TUNNEL_TCP_LOCAL_NONE` 只有在上述证据完成后才从 `IMPLEMENTING` 改为 `AVAILABLE`。不运行仓库级全量、Agent 全量/race、HTTP/Mixed/TLS/Reality/UDP/WireGuard 真实矩阵、账户/share/secret-leak 套件或无关 UI 用例。
- 052K 结果：固定 Xray `v26.3.27` 真实目标 1/1 通过，覆盖配置预检、回环 TCP 请求双向转发、目标关闭后新请求失败和同端口 UDP 可绑定；服务端纵向聚合 1/1 通过，覆盖 strict input、reservation/generation 原子性、规范 spec、零账户/secret、deterministic config、desired/DTO 和 public/listen address 篡改 fail closed。
- 共享 profile 与面板 catalog 直接受影响合同 17/17、既有 Agent `TestXrayApplyListenerProbeRequiresManagedPIDOwnership` 与 `TestXrayApplyListenerFailureRollsBackOnlyAfterReadinessExhausted` 2/2 通过；TypeScript、一次生产构建和隔离 Chromium Tunnel 创建/详情代表流程 1/1 通过。构建只有既有大 chunk 提示；按计划未运行无关全量和其他协议矩阵，profile 已标记 `AVAILABLE`。

## 66. TASK053 MTProto 独立服务精简验证计划（2026-09-03）

- 053A 只依据官方 `mtg-multi v1.15.0` release/README、Telegram MTProxy 链接格式和本地 3x-ui 只读实现锁定最小 sidecar；amd64 archive 固定 size `5307638`、SHA-256 `f1f8763504753fb863a0ddff83eab19c856747289c376275c44b717f1747908e`，arm64 固定 size `4767178`、SHA-256 `9ed776b2052b95e8344896d43fbe01250014f36d7cfdd7f29f7903179bce4bed`，checksums 固定 size `1013`、SHA-256 `90ba733fefcadb0de8c3fe82d3ac5165deacfe96d4feaad7891256b5e32d3740`。
- 053B–D 连续完成共享合同/三数据库/制品、面板 CRUD/分享/desired/observed、Agent 安装/降权/supervisor/last-good/卸载和前端完整流程。按用户要求，代码闭环前不运行测试、TypeScript、构建、Agent 或浏览器检查。
- 053E 最后只集中运行：一个共享跨语言合同目标；一个服务端纵向聚合目标覆盖 strict input、资源绑定 secret、reservation/generation 原子性、no-store 分享与 DTO 禁密；一个 Agent 聚合目标覆盖 tar 安全、版本/架构/hash、专用 UID、固定 argv、listener、回滚、离线恢复与卸载；TypeScript、一次生产构建和一个代表浏览器流程。
- 不运行仓库级全量、Agent 全量/race、既有 Xray profile/真实核心矩阵或无关 UI 用例。只有上述证据完成后才把 MTProto catalog 从 `IMPLEMENTING` 改为 `AVAILABLE`；TUN/AmneziaWG 保持 `NOT_IMPLEMENTED`。
- 053E 结果：共享跨语言合同目标 1/1、服务端纵向聚合目标 1/1、Agent 合同与运行时安全聚合目标 1/1、`corepack pnpm exec tsc --noEmit`、一次生产构建和隔离 Chromium 创建页代表流程 1/1 均通过。构建只有既有大 chunk 提示。
- 固定 amd64 官方 archive 重新校验 size/SHA-256 后，实际执行 `mtg-multi --version` 得到 `v1.15.0`；无管理 API 的最小配置通过 `access --ipv4 192.0.2.1` 预检，实际 `run` 后 TCP listener 可连接。验证过程发现官方二进制版本参数为 `--version` 而非 `version`，生产 Agent 已按实测修正。
- MTProto catalog 已改为 `AVAILABLE`；TUN 与 AmneziaWG 继续为 `NOT_IMPLEMENTED`。按精简计划未运行仓库级全量、Agent 全量/race、既有 Xray profile/真实核心矩阵或无关 UI 用例，本任务未部署。

## 67. TASK054 AmneziaWG userspace 精简验证计划（2026-09-03）

- 054A 依据[官方 amneziawg-go 仓库](https://github.com/amnezia-vpn/amneziawg-go)、[固定 v3.1.20260814 go.mod](https://raw.githubusercontent.com/amnezia-vpn/amneziawg-go/v3.1.20260814/go.mod)、[官方参数文档](https://docs.amnezia.org/documentation/amnezia-wg/)与本地 3x-ui 只读代码锁定低权限 Agent helper。官方模块要求 Go 1.25；首片不使用内核 TUN、DKMS、awg-quick、防火墙或 `CAP_NET_ADMIN`。
- 054B–E 连续完成共享合同/三数据库/secret、服务端 CRUD/分享/desired、Agent helper/supervisor/离线恢复和前端完整流程。按用户要求，代码闭环前不运行测试、TypeScript、构建、Agent 或浏览器检查，仅做 diff/格式静态收口。
- 054F 最后只集中运行：一个跨语言合同目标；一个三数据库/服务端纵向聚合目标；一个 Agent 聚合目标覆盖固定 helper argv/UID、真实 AWG peer TCP/UDP、公网允许与私网/metadata 拒绝、错误 key/PSK/obfuscation、UDP readiness、混合 MTProto/AWG rollback 和离线恢复；统一 secret leak；TypeScript；一次生产构建；一个隔离 Chromium 创建/详情/分享流程。
- 不运行仓库级全量、Agent 全量/race、既有 Xray profile/真实核心矩阵或无关 UI 用例。上述证据全部通过后才把 `AMNEZIAWG` 从 `IMPLEMENTING` 改为 `AVAILABLE`；TUN 继续 `NOT_IMPLEMENTED`。
- 054F 结果：跨语言 mixed MTProto/AWG 合同 1/1、SQLite 真实表与 MySQL/PostgreSQL schema 渲染的服务端纵向聚合 1/1、Agent 合同/真实 userspace AWG TCP+UDP/公网策略/回滚聚合 1/1通过；`corepack pnpm exec tsc --noEmit`、`corepack pnpm build` 和隔离 Playwright Chromium AWG 代表流程 1/1 通过。浏览器覆盖严格 UDP 创建、peer 详情、`.conf`/`vpn://`/二维码、no-store、缓存清理、TUN 无创建入口与零 console/page/request/HTTP 5xx。
- Agent 聚合目标使用官方 Go 1.25.0 便携工具链并关闭 `vet`；不关闭时会先命中与 TASK054 无关的既有 `main.go` 非常量 format string 告警，因此未扩大范围修复。最终 Agent 生产编译通过。
- 最终静态审查额外覆盖备份恢复全零 HeaderProtectionKey 拒绝，以及面板 URL 变更的串行事务、durable revision pin、文件/父目录 `fsync`、两次 ACK、进程重启持有、失败回滚顺序和 generation 提交后清理；对应小回归通过，独立最终审查结论为 `critical: none; required: none`。按精简计划未运行仓库级全量、Agent 全量/race、既有 Xray profile/真实核心矩阵或无关 UI 用例；`AMNEZIAWG` 已标记 `AVAILABLE`，TUN 继续 `NOT_IMPLEMENTED`。提交 `698f896` 随后已直接部署到两台 Debian amd64 服务器，面板与 Agent 重新安装、数据迁移、AWG capability、原 Xray `v26.3.27` generation/hash/listener 恢复、外网资源和服务日志关键检查均通过。

## 68. 创建 Dialog 滚动与回退维护回归（2026-09-03）

- 逻辑目标先复现端口 reservation 失效后已完成 TRANSPORT 被禁用，新增选择集后 2/2 通过；选择集只放开当前及之前分区，ACCOUNT/CONFIRM 等后续分区仍使用原前置条件。
- 原 Playwright smoke 增加可控时钟：进入 SECURITY 后推进 61 秒使 reservation 确定失效，验证 TRANSPORT 仍可返回、后续分区禁用、节点/公网地址/profile 草稿保留，并重新执行 UDP 探测后提交 replacement reservation；不依赖墙钟等待。
- 创建 Dialog 改为受限高度 flex，标题/分区固定，表单和 operation 进度使用 `min-h-0 flex-1 overflow-y-auto`。直接启动真实本地面板后，Chromium 在 320×500 下测得表单 `clientHeight=224`、`scrollHeight=280`，滚动后到达精确底部且底部按钮可见，console/page error 为 0。
- `corepack pnpm exec tsc --noEmit` 与 `git diff --check` 通过。仓库 Playwright runner 本轮在执行断言前卡于 webServer 启动阶段并终止，因此不记为通过；未运行生产构建、仓库/Agent 全量或协议真实矩阵。
- 用户随后授权更新；提交 `a07e1fe` 经一次 `corepack pnpm build` 后只替换面板 `dist` 与 `client/dist`。实际 `9810` 本机与既有公网入口的首页/新 JS 资产均为 HTTP 200，线上资产哈希与本地一致，SQLite `quick_check=ok`，面板 systemd active/enabled、重启数 0、当前 invocation 错误 0，Agent 未更新且保持 active；成功后删除旧构建回滚副本和全部临时发布包。

## 69. TASK055 出口节点精简验证计划（2026-09-03）

- 055A–E 先完成生产代码；每个行为增量先增加对应目标测试，但按用户要求不提前反复运行无关矩阵。实现阶段只做 `git diff --check` 等快速静态收口。
- 最终只集中运行：URI parser/normalizer 目标；一个 SQLite CRUD/引用/加密/no-store 聚合目标并检查 MySQL/PostgreSQL schema 描述；一个 Xray generator/binding 聚合目标且用固定 `v26.3.27` 执行 `run -test`；一个 Realm/GOST 规则物化/PROXY Protocol/派生链接聚合目标；受影响 UI 组件目标；TypeScript；一次生产构建；一个隔离真实 Chromium 代表流程。
- 浏览器代表流程覆盖出口导入/清理、Xray 详情绑定/标注、规则目标切换/锁定、中转链接、创建前返回修改、移动端滚动、焦点、no-store 和零 console/page/request/HTTP 5xx。
- 不运行仓库级全量、Agent 全量/race、既有 Xray profile 真实矩阵、AWG/MTProto 或无关 UI 用例。只有上述证据通过后才勾选 055F；未部署前不在交接中表述线上已支持。

## 70. TASK056 六种本地转发方式出口引用精简验证计划（2026-09-03）

- 先扩充现有外部出口规则纵向目标，证明 iptables、nftables、socat、Nginx 在旧兼容矩阵下被拒绝，再实现共享六种方式 allowlist。
- 服务端聚焦目标覆盖六种方式创建、任意两种兼容方式间更新、TCP/管理员/PROXY Protocol 负向边界、endpoint 物化与中转链接；不重复 URI、数据库、Xray generator 或 Agent 全量矩阵。
- UI 聚焦检查六种工具均可在“出口节点”模式选择、切换时不再回退手动目标、提示文案准确，并保留 TCP/只读 endpoint/隐藏字段清理；运行 TypeScript、一次生产构建和一个隔离 Chromium 代表流程。
- TASK056 不修改数据库、Agent payload 或 Agent 运行时；因此不运行三数据库迁移、Agent Go、固定 Xray 真实矩阵、AWG/MTProto 或无关 UI 测试。
- 验证结果：服务端六种方式纵向目标 1/1、TypeScript、VitePress 文档构建、一次生产构建和隔离 Chromium 代表流程 1/1 通过；生产构建只有既有大 chunk 提示。Playwright 自动 webServer 首次停在启动阶段并人工终止，随后手动启动同一隔离开发面板执行相同测试通过，不计首次运行成功。

## 71. MAINT003 外部 VLESS 链接兼容性验证计划（2026-09-03）

- 先以脱敏固定样例建立 `fp=chrome|random × authority 空路径|单个 / × 两种查询参数顺序` 的表驱动 RED 矩阵；每项都检查解析结果、规范 URI 重建和指纹不被改写，不把用户提供的真实 UUID、地址、公钥、shortId 或完整链接写入测试和日志。
- 负向矩阵保留重复参数、未知参数、非 TCP、非 Reality、非 Vision、非根路径、点段/编码点段、非法 percent/UTF-8 和未批准指纹拒绝；`randomized`、浏览器名称及任意 uTLS 变量不因本修复顺带开放。
- 服务层目标使用 SQLite 实际建表与主密钥文件，证明 `random` 只作为公开设置保存、UUID/shortId 仍以资源绑定密文保存，加载和原节点链接重建保持 `random`；不修改三数据库 schema、Agent 合同或 secret 格式。
- 配置层目标把加载后的定义绑定到 inbound，检查完整主机配置中的 Reality outbound 为 `fingerprint=random`，并由固定 SHA-256 对应的 Xray `v26.3.27` 执行 `run -test`。最后只运行上述兼容目标、TypeScript、文档构建、一次生产构建和部署后在线导入链路；不运行仓库级全量、Agent Go、无关协议真实矩阵或浏览器全量。
- 实施结果：三轮 RED 分别证明旧实现拒绝根斜杠/`random`、会放过归一后的点段路径、会接受 VLESS `spx` 非法 percent；最小修复后共享/SQLite/绑定/编译聚合 12/12、中转链接 `random` 保留 1/1、TypeScript、文档构建和生产构建通过。官方 archive 与二进制 SHA-256 分别为 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`、`8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`，固定 `v26.3.27 run -test` 通过；fresh-context 审查为 Critical 0、Required 0。
- 部署结果：提交 `9990d14` 的后端 `dist` 已原子部署服务器 A，SHA-256 为 `9443a7b30966b571cdc1b1f71d8f747454ca4a8f21e6dace763e6910cef3445f`；前端树未变化，服务器 B 与 Agent 未改动。部署前 SQLite 离线 checkpoint、完整性检查、backup API 复验和主密钥配套备份通过；部署后 SQLite `quick_check`、数据库驱动的 publicInfo/setup、health、静态资源一致性及 14 秒稳定观察通过，独立复查确认 PID 稳定、重启数为 0。回滚材料位于 `/opt/forwardx-panel/backups/deploy-20260903T101507Z-9990d14`；为避免把真实凭据写入生产数据，未创建用户样例节点。

## 72. TASK057 DNSPod + Realm 快速配置精简验证计划（2026-09-03）

实现仍遵守行为变更先建立失败目标，但每个增量只运行直接相关测试；不在 account、schema、allocator、saga、UI 每一片后重复仓库/Agent/协议全量。057R 只集中运行下面九组关键证据：

1. **共享 DTO/API 边界**：strict Zod、管理员权限、未知字段拒绝、稳定错误码、token 不进 URL、普通 DTO 禁 secret/envelope/fingerprint/operation JSON，所有 secret/share/token 响应 `private, no-store`；targetVersion 允许重命名/无关 generation，endpoint/profile/spec/eligibility 改变必须失效，并验证规范 hash 跨调用复现。
2. **DNS account/repository/client**：候选凭据远端验证成功才提交；轮换必须继续访问全部在用 zone/recordId，失败时旧密文不变；未配置/已配置 binding 与 account 双 revision CAS；24 小时账号失效、6 小时 catalog 自动刷新/stale 门禁、无 zone、动态 lineId、五个 category 的 `AVAILABLE/MISSING/AMBIGUOUS/STALE`、TC3 固定 endpoint/action、超时/分页/响应上限、错误映射、资源绑定 AEAD 和统一 secret-leak。
3. **三数据库与备份**：SQLite 幂等实际迁移，MySQL/PostgreSQL schema descriptor 对照；global binding/domain claim/active operation/port 的唯一约束；固定空 binding 不计业务数据，fresh 恢复能更新 seed/映射 id，缺 binding 但有 provider 数据、重复/未知 scope 必须拒绝，incremental 仅允许空目标或相同 accountTag 复用；旧库恢复、DNS secret envelope 预检和既有 DDNS 字节不变。
4. **域名检查**：`dfd`/`hk.dfd` 规范化，`@`/通配符/URL/非法 label 拒绝；check/confirm token 绑定与过期，action 互换和 CNAME 删除授权复用被拒绝；A/AAAA/CNAME 显式替换，TXT/MX/CAA 保留且冲突时只允许换名；最终 apply 发现远端竞态时零规则/DNS 写入，正常 remove 不恢复历史第三方记录。
5. **线路/端口/default preview**：四运营商各多 host、IPv4/IPv6、跨 carrier 相同 endpoint 保留 DNS route 且物理规则去重；受管原端口 landing/direct 不误探测自身 listener，原端口与改写端口、受管手工端口、外部推荐 token 绑定、实际 bind 占用映射 `GLOBAL_PORT_EXTERNAL_OCCUPIED`、异步失败/过期终态、外部 FQDN 同族多公网地址用 candidateId 唯一选择、默认 direct/managed 入口；preview 纯计算且无业务写入。
6. **全局端口账本**：跨 host、TCP/UDP、并发申请、同 quick-config 多 host alias、目标 Xray 原端口 alias、低端口历史回填、tunnel/mimic/exit/hop/managed service 覆盖、`LEGACY_CONFLICT`、崩溃恢复和 12 小时 lease/cohort 保守回收。
7. **Agent fan-out/规则 readiness**：每个 host 的现有 TCP+UDP `PORT_PROBE`、错 host/network/port、缺失/额外/过期结果、能力下降、离线和超时 fail closed；Realm 一条双栈规则复用与实际 readiness，DNS 绝不先切流。只有 Agent 合同实现实际变化时才增加 Go 目标；TASK057 预计复用现有合同，不跑 Agent 全量/race。
8. **持久 saga**：在每个 phase 注入进程退出/第 N 条 DNS 失败/第 N 台 Agent 失败；同一计划即使以 carrier-first 持久化，create/edit/retry 的真实 provider 调用也必须先完成全部默认线路 A/AAAA，再处理运营商线路；CreateRecord 后模拟记录在有界轮询内由不可见变为可见并保存 recordId，超时不重复写；模拟前序已尝试写入但保存前中断，retry 只接管唯一精确 tuple 且无其他 owner 的记录，前序 step 为 `PENDING/COMPENSATED`、不同 quick config、多匹配或已有 owner 均继续报漂移；apply 同次快照补偿、edit 新旧 topology、DNS CAS 漂移、remove 顺序、清理失败、重启恢复、lease 超时接管与旧 fence 结果拒绝、历史 operation 不可变且 retry 新建关联 operation 并沿 lineage 只读使用原快照、retry 幂等和 active operation 并发门禁。普通 rule 直接 edit/disable/remove 必须返回 `QUICK_CONFIG_MANAGED_RULE`。
9. **UI reducer + 单个 Chromium 主流程**：系统设置保存/掩码/失效，目标禁用原因，六步全部回退与依赖失效，320×500 滚动，刷新恢复 operation，Rules 徽标/跳转，多账户分享和 no-store 清理，零 console/page/request/HTTP 5xx。

链路管理维护目标以 MAINT-006 为准：主列表只展示真实 `port` 资源；A 的 `dfaf` 合并模板与快速配置引用为 2，B 的三条快速配置规则幂等归属同一张“快速配置默认生成”资源卡片。存在快速配置引用时停用、删除和 identity/成员变更由服务端拒绝；历史收敛和重复启动不得重复建资源，待删除规则不计数，且不得规则不进入 `forwardGroupId` 模板/子规则链路。只运行 schema/repository、相关分页/开关、TypeScript 和一次生产构建，不扩展到六引擎真实 Agent 或 DNSPod 写入。

链路管理维护已以提交 `258b2cd`、`59e1c06`、`01490a0` 部署到服务器 A 面板；只替换 `dist/index.js`、对应 source map 和 `client/dist`，未覆盖 `dist/agent`、其他服务端入口、两台 Agent、服务器 B 或运行中转发规则。离线 SQLite backup API、源库/备份库 `quick_check`/`integrity_check`、前后规则计数及独立规则计数一致，生产按真实主机解析到服务器 B 的独立规则为 3 条，活动快速配置/Xray operation 均为 0。线上后端 SHA-256 为 `36be0241b1bade3262dbc518c35c1989ad919a76956e4d06cfddc71395078637`，前端树 SHA-256 为 `6cc7bef64a8bc7e832e80e6c43f8bad5c9db58ce3bb512cfd1d66de5d9ed7dcb`；受保护新 procedure 返回预期未授权而非未注册，实际 JS 资产 content-type/字节哈希一致。稳定窗口与独立复核均为 HTTP 200、PID 稳定、`NRestarts=0`、当前 invocation error/warning 0，回滚材料位于 `/opt/forwardx-panel/backups/deploy-01490a0-20260904T025726Z`。

MAINT-005 纠偏后，链路页不再渲染下方规则明细区，而是以主列表同级主机项展示独立规则。RED→GREEN 服务端聚合 4/4、卡片/表格静态渲染 1/1、TypeScript 与生产构建通过。提交 `c4e6c47`、`2208b42`、`05a2331`、`0cb4c1e` 已部署服务器 A；数据库前后均为 6 条规则/2 台主机，生产主机汇总确认服务器 B 为 3 条规则且全部运行。线上后端/前端树 SHA-256 为 `a79bc2b31b3f50debba3734a4c470ec477ed69772522d77933432d2251fe254c` / `7f7a38f62c8e4ccafc72d6619f18205a3f119a627558931795c1d40b6cbd4374`；新 procedure 注册、实际 JS 资产、SQLite `quick_check`、PID 稳定、重启 0 和 warning 0 通过，回滚包位于 `/opt/forwardx-panel/backups/deploy-0cb4c1e-20260904T033742Z`。当前工具未配置 Chrome DevTools MCP，按精简范围未运行全量浏览器或无关集中套件。

MAINT-006 已以提交 `d2af667`、`281e0e8`、`e61ef7a`（交接提交 `bca83c9`）部署服务器 A 面板，只替换后端主 bundle/source map 与前端静态树，未替换 `dist/agent`、其他服务端入口、两台 Agent 或服务器 B。停服态 WAL checkpoint、源库/SQLite backup API 副本的 `quick_check`/`integrity_check`、Xray 主密钥和 Agent 资产哈希均通过；6 条规则、2 台主机以及规则运行字段、Agent revision/hash、Xray desired/applied generation/configHash 前后不变。历史收敛后共有 2 个真实端口资源，4/4 活动快速配置规则归属有效：A `dfaf` 为 2 条总引用，B 默认资源为 3 条快速配置引用。线上后端/前端树 SHA-256 为 `e5b53d11297cd71504272154fccc5d27eacb8b19944725a5187b9b66d7063438` / `8de5f5020e8ddc9e1ec8c70bf166fbe09da8e7064cda9ed014f845f0b622e5b2`；公网 index/JS 与本地构建逐字节一致，服务 PID `78552`、`NRestarts=0`、当前 invocation warning 0。回滚材料位于 `/opt/forwardx-panel/backups/deploy-bca83c9-20260904T051958Z`。

最终检查只额外运行 `corepack pnpm exec tsc --noEmit`、一次 `corepack pnpm docs:build`、一次 `corepack pnpm build` 和上述单个浏览器流程。按用户要求不运行仓库级全量、全部既有 Xray profile 真实连接矩阵、AWG/MTProto、无关 DDNS/规则/UI 套件或 Agent 全量；若聚焦失败证明公共基础被改变，再只扩展到对应受影响目标。

## 73. TASK058 快速配置六引擎精简验证计划（2026-09-04）

1. **共享/目录合同：** 固定六项顺序与 Realm 默认值；系统逐项关闭、两个 host 能力取交集、同 host IPv4/IPv6 去重、缺地址族、离线、低于 `2.2.192`、缺 TCP/UDP probe 或 UDP readiness 都返回稳定禁用码，响应快照不得出现 Agent 版本、原始 capability、地址、命令或运行时原文。
2. **创建矩阵：** 六种 engine 各完成一条受管或外部目标 create；后端在 port check、preview、apply 三处拒绝过期能力、全局关闭、混合 engine、UDP/PROXY Protocol 和浏览器伪造可用性。iptables/nftables 以规则存在性确认，四种进程型 engine 以既有 readiness 确认，全部 READY 前 DNS 保持不变。
3. **切换/恢复：** Realm 与其余五种 engine 各一条成功互切；至少一条第 N 台失败、Agent 断线、面板重启和全局开关中途关闭注入，证明同端口不会出现两个 owner、DNS/endpoint/线路不变、恢复成功回旧 ACTIVE，恢复失败保留引用并进入 `PARTIAL_FAILURE`。
4. **UI：** reducer/组件检查 Realm 默认、六项禁用原因、入口变化清除下游、全局单选、切换短暂中断提示、返回修改和实际 engine 展示；单个 320×500 Chromium 主流程覆盖创建与一次失败恢复。

058A–E 只运行当前增量直接相关目标和 `git diff --check`；058F 集中运行上述目标、`corepack pnpm exec tsc --noEmit`、一次 `corepack pnpm docs:build`、一次生产构建和一个浏览器流程。由于合同复用现有 Agent payload，本阶段不新增 Go 合同测试或运行 Agent 全量；只有 Agent capability/payload 实际变化时才增加对应聚焦 Go 目标。
