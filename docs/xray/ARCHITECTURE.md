# Xray 集成架构

状态：第一版、Xray-native 多协议、独立受管服务与 DNSPod + Realm 快速配置架构均已批准，与 `SPEC.md` 0.21 配套。

## 1. 系统边界

```text
┌───────────────────────────────────────────────────────────┐
│ ForwardX 面板                                             │
│ DB desired state + secret store + artifact cache + tRPC  │
└─────────────────────────┬─────────────────────────────────┘
                          │ 现有受鉴权、加密的 Agent 通道
                          │ desired state / task / artifact
┌─────────────────────────▼─────────────────────────────────┐
│ ForwardX Agent                                            │
│ capability + probe + validate + apply + observed report  │
└─────────────────────────┬─────────────────────────────────┘
                          │ 本地受控文件和进程操作
┌─────────────────────────▼─────────────────────────────────┐
│ 受管数据面                                                │
│ Xray + 独立 sidecar，各自 last-good/binary/listeners       │
└───────────────────────────────────────────────────────────┘
```

面板是控制面，Agent 是执行器和节点现场传感器，Xray 与批准的独立 sidecar 是数据面。控制面故障不能自动转化为数据面故障。

Agent 发行身份采用独立的真实 `agentVersion`、规范 `agentDistribution` 和诊断 `agentBuildId`。语义版本只回答新旧关系，不能证明二次开发能力来源；Forwardplus 专有控制面必须同时要求受鉴权 Agent 明确报告 `agentDistribution=forwardplus`。旧 Agent 缺字段时维持既有数据面，只开放兼容心跳与升级路径。

## 2. 所有权

| 数据 | 权威来源 | 允许的副本 |
|---|---|---|
| inbound、客户端、端口、目标、期望版本 | 面板数据库 | Agent 只接收完整快照 |
| Reality 私钥、客户端 UUID | 面板加密存储 | Agent 的 `0600` 运行配置必须含工作副本 |
| 公网 IP、端口 bind、Reality 探测 | 目标 Agent | 面板缓存最近报告 |
| 安装/运行版本、PID、监听器、错误 | 目标 Agent | 面板保存 observed report |
| Xray 制品 | 面板缓存和清单 | Agent 专属版本目录 |
| 独立服务、账户、期望版本和 generation | 面板数据库 | Agent 只接收独立完整快照 |
| MTProto secret | 面板资源绑定加密存储 | Agent 的组只读运行配置必须含工作副本 |
| 独立服务制品 | 面板固定版本缓存和清单 | Agent 专属 root-owned 版本目录 |
| 分享链接 | 面板按结构化字段生成 | 不作为独立数据库真相 |

Agent 不从本地 Xray 配置反向覆盖面板数据库。面板也不要求 Agent 回传完整配置进行合并。

## 3. 期望状态收敛

每台主机维护一个单调递增 generation：

```text
DB transaction changes inbound/client
            ↓
desiredGeneration += 1
            ↓
normalize full host config → configHash
            ↓
SSE immediate push + heartbeat fallback
            ↓
Agent validates and applies atomically
            ↓
Agent reports appliedGeneration/configHash/listeners
```

规则：

- 相同 generation/hash 已成功应用且运行一致：幂等跳过。
- 相同 generation/hash 但监听器或文件漂移：重新验证并应用，或上报 `RUNTIME_DRIFT`。
- Agent 报告更旧 generation：面板再次下发当前完整快照。
- Agent 报告未知的更高 generation：面板不采纳本地配置，记录异常并重新声明面板期望状态。
- 配置失败：Agent 保持上一个成功 generation，报告失败；面板不得把失败 generation 显示为运行中。

该模型复用 ForwardX 当前 desired state、config revision/hash、SSE 和心跳兜底机制，不建立第二套双向同步协议。

## 4. 交互任务与期望状态分离

以下是短生命周期、位置相关的交互任务，不属于配置真相：

- 端口候选 bind 探测。
- Reality 目标 TLS 探测。
- Xray 制品安装/升级。
- 显式服务重启和诊断。

任务使用 `taskId`/`operationId`，具有超时和结构化结果。端口或扫描结果会过期，不能永久当作实际状态。节点配置仍然通过下一代完整 desired state 下发。

## 5. 节点创建事务

推荐流程：

1. 前端选择在线且具备 Xray v1 capability 的主机。
2. 面板从 `1000–65535` 生成候选端口，先排除持久全局端口账本、数据库已知 listener 和进程内短期预留。
3. Agent 对候选端口执行所需网络 bind 探测；TASK057 后还必须获得同一 host 另一网络的单端口空闲证据，才能满足不区分 TCP/UDP 的业务唯一性。
4. 面板建立短期 host reservation；最终 mutation 在数据库事务中取得唯一数字端口的持久 `RESERVED` allocation，二者任一失效都重新检查。
5. 在同一数据库事务中插入 inbound、初始客户端、加密密钥和 allocation reference，递增 host generation。
6. 创建 `SYNC` 操作，生成完整配置并推送。
7. 若 Xray 未安装，Agent 先执行所需制品安装，再验证配置。
8. Agent 切换配置，等待进程和监听器就绪，报告 applied state；面板随后把 allocation 转为 `ACTIVE`。
9. 面板只有在 observed state 确认后显示“运行中”。

若第 5 步前主机离线或短期预留过期，不创建 inbound；已经取得但未消费的持久 allocation 转为 `PENDING_SCAN`，不能直接复用。第 5 步后失败则保留明确的期望状态、allocation 引用和失败操作，便于重试、补偿和审计。

## 6. 运行时托管

`XRAY-ADR-014` 已确定采用 Agent 直接子进程：

- Agent 用固定二进制、参数数组和受管配置启动 Xray，不经 shell，也不创建独立 `forwardx-xray.service`。
- Xray 的生命周期 context 独立于 register、heartbeat、SSE 和单次 task context；Token 无效或网络请求取消不能传导为进程终止。
- Agent 内的本地 supervisor 持有进程句柄，执行就绪检查，并在 Xray 意外退出时根据 last-good 有界退避重启。
- PID 只是线索；接管或终止前同时校验进程启动时间、可执行文件路径和受管配置标识，避免 PID 复用误杀其他进程。
- Agent 启动先恢复或接管本地 Xray，再尝试面板认证；两个 Agent/Xray 实例不得同时绑定。
- 显式停止、删除最后一个 inbound 和卸载使用单独的受控路径，不能由 Token 错误触发。

第一版保留 systemd 默认 cgroup 清理语义：Agent service 停止/崩溃/升级时 Xray 可以短暂中断，新 Agent 必须在面板认证前从 last-good 恢复。不得用 `KillMode=process` 遗留孤儿 Xray，也不得依赖偶然的孤儿进程行为。

## 7. 模块边界

建议模块按职责组织，最终文件名以实施任务和现有仓库模式为准：

- `shared/`：版本化 DTO、Zod schema、状态枚举和分享链接纯函数。
- `server/`：密钥加密、repository、配置生成、制品缓存、operation 协调和 tRPC router。
- `agent/`：capability、任务执行、制品安装、配置持久化、supervisor 和 observed report。
- `client/src/`：Xray 页面、创建流程、节点/客户端详情和运行环境。

Agent 不接收由用户拼接的命令字符串；面板下发有版本的 typed payload，Agent 映射到固定的本地操作。

## 8. 故障语义

| 故障 | 期望行为 |
|---|---|
| Agent Token 错误 | 主机最终离线；现有 Xray 继续；不接受新配置 |
| 面板不可达 | 使用 last-good 继续；任务结果本地持久化后重试上报 |
| Agent 重启 | 允许短暂中断；在面板认证前恢复 last-good，禁止重复实例 |
| Xray 配置无效 | 不替换当前配置；报告 `CONFIG_INVALID` |
| 新端口被抢占 | 旧配置继续；报告 `PORT_IN_USE`，面板允许重试分配 |
| Xray 启动失败 | 回滚 last-good 和旧二进制；报告结构化错误 |
| 升级制品损坏 | SHA-256 校验失败，禁止切换 |
| 面板 desired 比 Agent 新 | 重发当前快照 |
| Agent observed 比面板未知地新 | 不反向采纳，记录漂移并重申 desired |

## 9. 可演进性

- 协议通过 `schemaVersion` 和 capability 增量扩展。
- 客户端从第一版保留 `statsKey` 与可选 `ownerUserId`，但不启用流量采集。
- 新协议、新传输和用户授权必须新增规格和测试，不通过泛化 JSON 绕过边界。
- 配置生成器可以随目标 Xray 版本选择兼容模板，但一个 Agent 一次只运行一个受管目标版本。

## 10. 多协议编译边界

多协议扩展仍使用单向声明式收敛：

```text
管理员输入
  -> tRPC 严格 schema
  -> 服务端 profile 目录验证组合
  -> 面板数据库结构化期望状态和加密 secret
  -> 按主机确定性编译完整 Xray config
  -> generation/configHash desired
  -> 目标 Agent 校验、原子切换、last-good 回滚
  -> 脱敏 observed state
```

- `profileId` 是产品支持单位，包含协议、传输、安全、flow、监听网络、凭据类型、分享格式和固定核心版本要求；不是任意字段的笛卡尔积。
- 配置编译器按协议、传输和安全模块组合，但只有 profile 目录列出的组合可进入编译器。
- Reality 扫描只服务于 Reality profile；TLS profile 使用独立的受控证书引用；UDP profile 使用网络感知的端口探测和 listener readiness。
- Agent 对 Xray-native profile 仍把 `configJson` 视为不透明的完整快照，不需要理解每个协议。只有 UDP listener、额外 capability 或独立 sidecar 才扩展 Agent 合同。
- MTProto 与 AmneziaWG 都不写入 Xray inbound 表，通过已批准的独立 `managedServices` desired section、专用低权限子进程和 kind-aware supervisor 实现；TUN 在特权方案批准前保持未实现。

## 11. 独立受管服务边界

独立服务沿用同一认证通道、SSE 唤醒和 heartbeat 兜底，但不复用 Xray 的表、配置、generation 或进程：

```text
managed service transaction
  -> 独立 host generation/configHash
  -> desiredState.managedServices 完整快照
  -> Agent 串行预检与整批切换
  -> 独立 sidecar supervisor
  -> 脱敏 managedServices observed
```

- 已批准分支为 `MTPROTO_FAKE_TLS` 与 `AMNEZIAWG`。前者固定 `mtg-multi v1.15.0` 制品，后者固定当前 Agent binary helper 与 `amneziawg-go/v3 v3.1.20260814`；都只支持 linux/amd64 或 linux/arm64，不接受任意 JSON、TOML/UAPI、shell、argv、路径或 service 名。
- Agent 仍以 root 执行受控安装和状态切换，但 mtg/AWG helper 分别降权到安装器维护的 `forwardx-mtproto`/`forwardx-amneziawg` no-login 身份，且不授予额外 Linux capability。
- MTProto/AWG 的配置、current/last-good 和 watchdog 与 Xray 隔离；kind 分派共享一个 managed-services generation，任一新服务失败使整批回滚，不影响已运行的 Xray generation。
- 面板失联或认证失败只停止新的控制面收敛，不停止最后成功的 Xray、MTProto 或 AWG 数据面。显式 Agent 卸载才按固定 executable 路径与进程启动身份停止子进程并清理专属文件。

## 12. 外部出口节点边界

外部出口是面板全局资源，不属于 Agent observed state，也不是新的 sidecar。公开 endpoint/spec 与加密 secret 分离；Xray 消费方由主机配置生成器把它编译进完整快照，iptables、nftables、Realm、socat、GOST、Nginx 六种本地转发消费方只使用物化 endpoint。两条路径共享稳定资源 id 和引用完整性，但不共享运行状态或错误语义。

```text
导入 URI -> 严格解析 -> 公开定义 + 加密 secret
                         |-> Xray inbound 引用 -> outbound + inboundTag routing -> 完整主机 generation
                         `-> Forward rule 引用 -> endpoint 物化 -> 既有六种本地转发 desired
```

原节点分享和中转链接都由服务端按需从结构化字段重建；中转只替换 authority。Agent 永远不接收六种本地转发路径不需要的代理凭据，外部节点缺失或损坏时 Xray 路径 fail-closed，引用中的资源不得被原地替换或删除。

## 13. DNSPod + Realm 快速配置边界

快速配置是面板持久编排，不是新的 Agent 运行时，也不是隐藏规则生成器。DNS provider 凭据和远端记录所有权只在面板；入口 listener 仍由既有普通 `forward_rules` 与 Agent 收敛；Xray 落地仍由完整 generation/configHash 收敛；外部出口节点仍只是面板全局资源。

```text
管理员向导草稿
  -> 面板验证 DNSPod 全局账号、zone、相对主机名与冲突
  -> 选择四运营商的 host + IPv4/IPv6
  -> 全局端口账本 + 对所需 Agent 并行 TCP/UDP PORT_PROBE
  -> 只读 preview 与最终确认
  -> 持久 quick-config operation
       -> 预留端口并创建普通 Realm forward_rules
       -> 等待各 Agent 确认规则生效
       -> DNSPod 创建/替换 A/AAAA 并读取验证
       -> 标记 ACTIVE
```

所有权固定如下：

| 事实 | 权威来源 | 其他组件行为 |
|---|---|---|
| DNSPod 账号选择、加密凭据、zone/line 缓存 | 面板数据库 | 浏览器只见状态；Agent 永不接收 |
| 域名冲突与 DNS recordId/tuple | DNSPod 实时读取 + 面板所有权记录 | 缓存不可单独授权覆盖/删除 |
| 快速配置意图、线路、默认线路、operation phase | 面板数据库 | 浏览器可恢复/重试，不决定成功 |
| 全局端口分配与逻辑引用 | 面板持久账本 | Agent probe 是有时效的占用证据 |
| Realm listener 期望与运行状态 | `forward_rules` + Agent observed | 快速配置只持关联 id，不复制配置 |
| Xray 落地配置 | 既有 Xray desired/last-good | 快速配置不生成增量 Xray JSON |
| 外部落地 endpoint/secret | 既有 external proxy 表 | DNS/Realm 只消费公开 endpoint，不接收 secret |

### 13.1 只读向导与提交边界

域名检查、拓扑选择、端口检测和 preview 在最终确认前不得创建 DNS 记录、普通规则、全局 allocation 或持久 active 引用。端口检测可以创建有界 Agent task 与短期 host reservation；preview 本身只消费有效检查结果并纯计算规则/DNS 差异。域名检查返回绑定账号、zone、FQDN、远端记录版本摘要和短期确认 token；任何输入、账号绑定、远端记录集或 quick-config revision 变化都会使 token 失效。提交必须重新读取 DNSPod 和数据库、事务性取得全局 allocation，不能信任旧 preview。

线路选择精确到 `host + addressFamily`。面板只从 host 的已验证公开 IPv4/IPv6 生成候选，不接受浏览器提交任意 IP。四条运营商线路分别可多选；相同 host/address 可被多个线路复用。默认线路在统一 `publicPort` 确定后计算：端口未改写时可直达落地的有效 IPv4/IPv6；端口改写时只能选择会运行相同 Realm listener 的受管入口，不能把外部落地原 IP 伪装成可直达。

### 13.2 全局端口与 Agent 探测

全局端口账本是比现有 `host + network + port` reservation 更严格的面板业务层。一个端口数字一次只属于一个逻辑 owner group；同一快速配置可让多个入口 host 绑定该端口，但其他 Xray、规则或服务不能复用。创建新的 Xray/规则/服务必须在原有主机锁之外进入端口分配事务，防止多面板请求在不同 host 上竞态。

面板复用现有单端口 `PORT_PROBE` typed task，对所需 host 的 TCP 与 UDP 并行派发并设置并发、超时和结果 TTL。它不扩展为端口范围、任意地址或进程查询。由于业务唯一性不区分网络，候选端口只有 TCP/UDP 都确认空闲才可使用；旧 Agent 缺少 UDP probe、离线或返回不完整时禁用创建或要求更换可验证 host，不做乐观分配。Realm 规则继续使用既有 `[::]:port`、`ipv6_only=false` 双栈 listener 和受管进程 readiness；`0.0.0.0` TCP probe 不被夸大为单独的 IPv6 bind 证明，最终双栈 bind/readiness 失败必须在修改 DNS 前触发规则补偿。

回收任务每 12 小时通过数据库租约取得单实例资格，先在数据库重验零逻辑引用，再对固定的全部在管 host cohort 执行相同双网络检查。任一无法证明空闲的结果都保持该 allocation 当前不可用状态；实际占用进入或保持 `EXTERNAL_OCCUPIED`，离线/不支持/超时不把它降级为 `FREE`。提交释放时还要重验 allocation version、全部引用和当前 host cohort。扫描不停止进程、不修改远端规则，也不根据 observed listener 列表缺失推断空闲。

### 13.3 持久 saga、补偿与删除

数据库事务、多个 Agent 和 DNSPod 之间不存在原子提交。每个 apply/edit/remove/retry 都先持久化 operation 与幂等 step，再按以下边界推进：

1. 重新检查账号、域名冲突、目标、主机能力、地址和端口 revision，并持久占位。
2. 创建或更新普通 Realm 规则，等待所有相关 Agent 明确确认；任一失败时删除已创建部分并等待清理，DNS 保持不变。
3. 按 recordId/lineId 创建或显式替换 DNS，逐条读取验证；失败时只撤销本 operation 精确拥有且未漂移的记录，并从有界快照恢复被替换项。
4. 全部规则和 DNS 验证后才置 `ACTIVE`。补偿无法安全完成时置 `PARTIAL_FAILURE` 并保留端口/规则/记录引用，管理员可从同一 operation 重试。

编辑不覆盖唯一一套当前字段，而是持久创建 `fromTopology -> toTopology`：

1. 保留 active topology、旧 DNS/规则 binding 与旧 allocation，同时创建不可变 staged topology；快速配置绑定的落地目标不可在原配置内替换，换目标使用 remove 后重新创建。
2. 为新 topology 建立新规则或引用完全相同的现有规则，等待所有新增 listener READY。改端口时旧/新端口并存；只改线路或地址族时相同 host/port/target 复用一条规则，不在同 host 上重复 bind。
3. 以旧/新 recordId 和 tuple 快照切换 DNS 并验证，然后原子切换 active topology pointer。
4. DNS 切换前失败时清理 staged-only 规则/allocation，旧 topology 保持 ACTIVE；切换中失败时仅按 CAS 恢复未漂移记录，恢复成功后回旧 topology，无法恢复则保留两套引用并进入 `PARTIAL_FAILURE`。
5. DNS 已完整验证后即以新 topology 为 active；清理旧规则失败只保留旧 topology 为 `RETIRING/ROLLBACK_PENDING` 和端口引用供重试，不盲目回切 DNS。旧 Agent 清理确认后才释放旧 allocation。

移除先让 DNS 不再指向入口并验证，再删除普通规则并等待 Agent 确认，最后释放逻辑引用。端口只进入 `PENDING_SCAN`，不会立即成为候选。直接编辑、停用或删除带 `xrayQuickConfigId` 的普通规则会破坏 DNS 一致性，因此既有规则 API 必须拒绝并返回快速配置入口；列表、详情、状态和日志仍按普通规则显示。

面板进程重启后调度器从持久 phase/step 继续；浏览器断开不取消已提交 operation。DNSPod 不可达时已运行的 Realm/Xray 数据面不被主动停止；是否补偿取决于已持久化阶段，绝不从异常文本或猜测的远端状态决定破坏性动作。
