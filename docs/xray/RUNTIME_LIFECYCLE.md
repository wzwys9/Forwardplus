# Xray 运行生命周期

状态：已批准。Supervisor 为 Agent 直接子进程；Agent service 重启允许短暂中断并在认证前恢复；TASK057 快速配置使用面板持久 saga。与 `SPEC.md` 0.21 配套。

## 1. 目标

- Xray 按需安装，不污染系统已有 Xray。
- Agent Token、面板网络或 Agent 控制循环故障时，最后一次成功的数据面继续运行。
- 配置和二进制升级是可验证、原子、可回滚的。
- Agent 重启后可以仅凭本地状态恢复管理，不要求先成功连接面板。
- 显式 `migrate-forwardx` 开启来源迁移后，来源不匹配的 Agent 在受鉴权心跳中加入持久升级队列；升级失败或面板不可达时保留旧 Agent 与其数据面，后续重连重试。只有新进程回报真实目标版本和 `forwardplus` 来源后才完成。

## 2. 受管路径

建议 Linux 路径：

```text
/var/lib/forwardx-agent/xray/
├── versions/
│   └── <version>/<os>-<arch>/xray
├── current -> versions/<version>/<os>-<arch>
├── state.json
├── apply-pending.json
├── task-results/
└── downloads/

/etc/forwardx/xray/
├── config.json
├── config.json.sha256
├── last-good.json
├── last-good.json.sha256
└── pending/

/var/log/forwardx-agent/
└── xray-runtime.log       # 有界、脱敏；默认不记录访问流量
```

要求：

- 目录 `0700`，含密钥配置文件 `0600`，root 所有。
- `current` 只指向 Agent 受管目录，不能指向 `/usr/local/bin/xray` 等系统路径。
- 临时文件在目标目录内创建、fsync 后 rename，避免跨文件系统非原子替换。
- `state.json` 只保存版本、generation/hash、路径和安全摘要；不得复制密钥。
- `apply-pending.json` 只保存切换前的非敏感运行快照，用作跨进程崩溃恢复事务标记；`state.json` 的原子写入是提交点，marker 删除只是最终清理。成功提交或完成回滚后删除 marker。

Windows 或非 systemd 平台只有在 capability 明确实现同等语义后才启用，第一版可以安全报告不支持。

## 3. 面板制品初始化

生产面板在数据库初始化成功后异步确保固定 `v26.3.27` 的 `linux-amd64` 和 `linux-arm64` 制品均位于面板持久数据目录：已有文件先按固定大小和 SHA-256 幂等复核；缺失或损坏时仅从批准的官方归档及 `.dgst` 来源重新获取，并沿用临时文件、校验和原子切换流程。只有两个架构均成为 `VERIFIED` 后才能设置默认版本。

制品初始化不阻塞面板监听和登录。单次启动填充失败时保持缺失/无效状态并记录稳定错误码，后续面板重启会再次尝试；Agent 不得因此改为直连 GitHub 或其他公网来源。

## 4. 发现已有 Xray

Agent 可以检测 PATH、常见服务和进程用于提示，但必须遵循：

- 不停止、不覆盖、不复用已有 Xray。
- 不读取或上传已有配置。
- 不把已有版本报告为 ForwardX `isInstalled=true`。
- 受管 Xray 端口与已有进程冲突时按 `PORT_IN_USE` 处理。

面板可以显示“检测到系统 Xray，ForwardX 将使用独立路径”，不提供接管按钮。

## 5. 安装流程

1. Agent 校验 task schema、目标 OS/arch、版本和面板 origin。
2. 下载到 `downloads/<taskId>.part`，限制大小、超时和低速连接。
3. 校验声明的文件大小和 SHA-256。
4. 在临时目录安全解包：拒绝绝对路径、`..`、符号链接逃逸、设备文件和额外可执行入口。
5. 验证 Xray 二进制格式、执行权限和自报版本。
6. 移动到全新版本目录；同版本已验证存在时幂等复用。
7. 若没有配置，只完成安装，不启动空白代理。
8. 创建首个 inbound 时，面板在同一顶层 `SYNC` operation 内先投递 `INSTALL` task，并在明确接受其成功结果前暂缓 desired；成功后进入配置应用流程。
9. 成功后持久化 installed/current 状态并上报。

安装不得覆盖 current 版本目录中的文件。

## 6. 配置应用流程

面板配置生成器对启用且非 `pendingDelete` 的 inbound 按 `runtimeTag`/id 排序，对其启用且非 `pendingDelete` 的 client 按 `sortOrder`/id 排序，使用固定字段顺序、两个空格缩进和单个末尾换行生成 UTF-8 JSON；`configHash` 对这些精确字节计算 SHA-256。当前固定模板为 `v26.3.27` 的 VLESS + TCP + Reality + Vision。若 inbound 暂无启用客户端，`clients` 为空且 `shortIds` 使用 Xray 要求的单个空 sentinel；没有 UUID，因此不会产生可认证客户端。

WireGuard profile 仍由同一个 Xray 配置生成器和 supervisor 管理，不复用 Agent 已有的 `forwardx-wireguard` 隧道 runtime，也不创建第二个进程或系统接口。固定核心在 Xray 进程内运行 gVisor userspace TUN；应用成功只以完整 generation/hash、受管 Xray PID 和单个 UDP listener READY 为准。peer CRUD 失败、配置测试失败或 UDP readiness 缺失沿用相同 last-good 回滚，不能只局部修改运行中 peer。

Tunnel profile 也由同一完整 Xray 快照和 supervisor 管理，不建立单独 sidecar。目标地址/端口只属于面板 desired config，Agent 不探测、不改写也不回传；应用成功仍只确认固定版本、generation/hash、受管 PID 和 `127.0.0.1` TCP expected listener。配置测试、启动或回环 readiness 失败时恢复整份 last-good，不能保留半应用的 Tunnel inbound。

SSE 和 heartbeat 的 Xray desired 先进入同一个有界串行队列；相同 identity 合并，较新 generation 最多保留一个 pending。入队和运行时两层都验证 payload/hash；应用完成后强制下一次 heartbeat 上传完整 observed state。队列及 Xray 子进程均不使用控制面请求的可取消 context。

1. 验证 desired `schemaVersion`、generation、hash、大小和 expected listeners。
2. 对收到的精确 `configJson` 字节计算 SHA-256。
3. 写入 `pending/<generation>-<hash>.json`，权限 `0600`。
4. 使用目标受管 Xray 二进制执行配置测试，设置严格超时并捕获有界输出。
5. 测试成功后保存当前 `config.json` 为 `last-good.json`；首次部署没有 last-good，并在修改 current/config 前原子写入 `apply-pending.json`。
6. 原子替换 `config.json` 和 hash 文件。
7. 启动或重启受管 Xray。
8. 校验进程/服务状态、运行版本和所有 expected listeners。
9. 成功后更新 `state.json` 的 applied generation/hash，清理 pending 文件和事务标记。
10. 失败则恢复 last-good 和旧 current 版本，重新启动并验证；完成回滚后删除事务标记并报告原始错误和 rollback 状态。

不得在第 4 步失败后触碰当前运行配置。首次部署失败时保持未运行状态，不伪造 last-good。

相同 generation/hash 在 runtime 文件、进程和 listeners 仍一致时直接复用；发现 drift 时执行完整验证和重应用。同 generation/different hash 或倒退 generation 在写 pending/config/current 前拒绝，最后一次成功 runtime 保持不变。

面板只在 observed state 同时确认目标 generation/hash、固定运行版本、受管进程状态以及 expected listeners 全部精确就绪后，把对应 `SYNC` operation 标记成功；当前 generation 的失败只保存稳定错误码和通用摘要。空主机 desired state 不含运行密钥，生成它不得要求面板主密钥；其收敛状态为保留安装且受管进程停止。

## 7. Agent 子进程 Supervisor

第一版由 Agent 直接启动和监管 Xray，不创建独立 Xray service：

1. 使用固定受管路径和参数数组启动，长生命周期进程不得绑定到网络请求或任务的可取消 context。
2. 进程启动后保存 PID、启动时间、二进制路径、版本和 generation/hash 的非敏感身份信息。
3. 本地 watchdog 监听退出状态；非显式停止导致的退出按有界退避恢复 last-good，连续失败后进入 `ERROR`，避免高速重启循环。
4. 配置切换由 supervisor 串行执行；旧进程完全退出并确认端口释放后才能启动新进程。
5. 接管、停止或清理前同时核验 PID、启动时间和 executable，不能只信任可能复用的 PID。
6. Token、register、heartbeat、SSE 或面板网络错误只影响控制面连接，不调用 stop，也不取消 Xray 运行 context。

保留现有 systemd 默认 `KillMode=control-group`：Agent service 停止、崩溃或升级时连同 Xray 子进程一起清理，允许一次短暂中断。新 Agent 启动后必须在 register/heartbeat/SSE 之前恢复 last-good；不设置 `KillMode=process`，不让旧 Xray 跨 service 重启存活。

## 8. 启动和恢复

Agent 启动顺序必须与面板认证解耦：

1. 读取并验证本地 `state.json`、current 二进制、config hash 和可选的 `apply-pending.json`。
2. 若存在有效事务标记且 `state.json` 仍是切换前快照，停止与旧快照不一致的受管进程，再恢复旧 current/state 和 last-good；若 `state.json` 已原子提交为另一份有效状态，必须用 current/config/hash 完整复核该快照后按已提交状态继续，只清理滞留 marker。任何不一致或损坏都安全失败。
3. 检查受管 Xray 实际进程状态和持久身份信息。
4. 已有受管进程仍运行且与已提交 state 一致时安全接管，不重复启动。
5. Xray 未运行但 last-good 有效且期望启用时，在不等待 register/heartbeat 成功的情况下恢复。
6. 启动心跳/SSE 后上报 observed state，等待面板纠偏。

Token 错误时 Agent 保持重试通信，但本地 runtime supervisor 不执行停止命令。

## 9. 升级流程

- 升级只由管理员显式 operation 或新配置的最低版本门槛触发。
- 面板比较结构化版本，不做简单字符串字典序比较。
- 安装新版本到独立目录并验证，不覆盖旧版本。
- 使用新版本测试当前配置和目标配置。
- 原子切换 `current` 后重启并检查版本、进程和监听器。
- 失败时切回旧 symlink、恢复 last-good、重启旧版本。
- Agent 已安装/运行版本高于面板目标时拒绝自动切换并报告 `XRAY_VERSION_MISMATCH`/`NEWER_THAN_TARGET`，不自动降级；只有本地事务回滚可以恢复已验证的旧快照。
- 普通配置 `SYNC` 不承担升级职责；旧版本必须由管理员显式创建 `UPGRADE` operation，新制品 task 成功后仍要等待 desired 的配置测试、原子切换和 observed 收敛。
- 手动 `RESTART` 不改写目标版本，只验证并重启已提交的 current config/state；失败时尝试恢复该快照并向 operation 报告稳定错误码。
- 清理旧版本必须保留固定默认版本、所有 deployment 目标、runtime report 的 installed/running 版本和活动 operation 引用版本，并按每个 OS/arch 至少保留最新两个版本；只有超过 30 天且不在保护集合中的受管制品才可清理。

## 10. 停用、删除与卸载

- 停用单个 inbound：新完整配置排除该 inbound，其他 inbound 继续运行。
- 删除客户端：新完整配置排除该 UUID/shortId；在 applied generation 确认前，面板必须显示旧客户端可能仍可用。
- 删除 WireGuard peer：新完整配置排除其 public key/PSK；在 applied generation 精确确认并清理 tombstone 前，旧客户端配置可能仍可握手，UI 必须沿用“应用完成前可能继续有效”的说明。
- 删除最后一个 inbound：停止受管 Xray，但保留受管二进制，便于后续按需启用；该默认需要在 UI 文案说明。
- 卸载 Agent：默认停止并删除 ForwardX 受管 Xray 进程、配置和二进制；卸载脚本只按真实 executable 路径匹配 `/var/lib/forwardx-agent/xray/versions/*/xray`，不得使用宽泛进程名匹配或影响系统 Xray。普通 Token 撤销或主机离线不等于卸载，不触发清理。
- 删除本地数据只允许固定 ForwardX Xray 路径，并在停止受管服务和核对路径后执行。

## 11. 日志和诊断

- Xray 默认关闭访问日志；错误日志使用有界轮转和最少级别。
- Agent 只报告结构化错误码和脱敏摘要，不上传完整 config 或命令环境。
- 本地诊断可以记录 generation、hash 前缀、版本、PID、runtimeTag 和端口。
- 禁止记录 privateKey、UUID、shortId、Agent Token、完整 VLESS URI。
- 支持包只有在 `SECURITY.md` 定义的 scrubber 后才能收集 Xray 状态。

## 12. 防火墙和公网可达性

第一版不修改防火墙。就绪定义为：

- 配置有效。
- Xray 进程/服务运行。
- 本机每个 expected TCP/UDP listener 都由正确的受管 Xray 进程持有；双网络 inbound 必须分别确认，不能按 runtimeTag 合并。

固定 Xray `v26.3.27` 在 Linux 上可能把配置中的 IPv4 wildcard `0.0.0.0` 表示为同 PID 所有的双栈 IPv6 unspecified socket `::`。Agent listener 探测把这两个 procfs 表示视为同一 wildcard，但仍必须匹配同端口和受管 PID 的 socket inode；其他地址或其他进程不得因此变为 READY。

TCP readiness 读取 `/proc/net/tcp`/`tcp6` 的 LISTEN 状态，UDP readiness 读取 `/proc/net/udp`/`udp6` 的未连接 bind 状态；两者都与 `/proc/<pid>/fd` 的 `socket:[inode]` 交叉验证，并把 `runtimeTag + network + port` 作为 observed listener 身份。

它不保证云安全组、NAT 或外部防火墙允许公网访问。面板应明确区分“本机监听正常”和“公网已验证”；第一版不强制提供外部连通性探测。

## 13. MTProto 独立服务生命周期

MTProto 不复用 Xray 二进制、配置或 generation。首版固定使用以下路径：

```text
/opt/forwardx-agent/managed-services/mtproto/v1.15.0/<arch>/
├── mtg-multi             # root:root 0755
└── artifact.json         # root:root 0600

/etc/forwardx/managed-services/mtproto/<serviceTag>/
└── config.toml           # root:forwardx-mtproto 0640；目录 0750

/var/lib/forwardx-agent/managed-services/
├── current.json          # root:root 0600
├── last-good.json        # root:root 0600
└── apply-in-progress     # root:root 0600；只保存非敏感 hash marker
```

- 安装器创建或复核无登录 `forwardx-mtproto` 用户/同名主组；只有安装器实际创建的用户或组才写 root marker 并在显式卸载时删除。Agent 缺少该身份、不是 root、平台不符或任一路径/owner/mode 不安全时不声明 capability。
- 面板缓存固定官方归档和 checksums；Agent 只从受鉴权面板 route 下载，限制响应大小和超时，拒绝 redirect、range、错误平台、额外 executable、symlink/hardlink、设备文件与路径穿越。解包后以专用 UID 执行固定 `version` 检查，替换 binary/manifest 时暂存旧文件，任一步失败恢复旧文件。
- Agent 从 typed desired 生成最小 TOML，先在 root 持有、专用组只读的 staging 目录用专用 UID 执行固定 `access` 预检。整批服务验证完成后写 marker、停止旧批次、切换全部目录、以固定 `run <config>` 启动，并用 PID/socket inode 复核每个 TCP listener。任一服务失败都停止新批次并恢复旧 last-good；`last-good.json` 的原子替换是该批次恢复提交点，marker 删除只是最终清理。
- SSE 和 heartbeat 共用一个 managed-services 串行队列；相同 generation/hash 合并等待者，active 之外只保留最新且更高 generation 的一个 pending。控制面请求 context 取消不终止应用或运行进程。
- sidecar 非显式退出后，watchdog 每次先重建并复核固定配置，再按 1/2/4 秒最多重启三次；仍失败则保持结构化 `ERROR`，不高速循环。普通 Token、register、heartbeat、SSE 或面板网络故障不调用 stop。
- Agent service 重启允许短暂中断；在首次面板认证前只读取 root 所有且严格验证的 last-good，重新生成组只读配置并恢复进程。空 desired 停止全部 sidecar并删除含 secret 的服务配置，但保留固定制品；显式 Agent 卸载才按 PID 启动时间和真实 executable 路径停止进程并删除这些固定目录。

## 14. AmneziaWG helper 生命周期

AmneziaWG 与 MTProto 共用 managed-services generation/state 文件，但配置和 UID 隔离：

```text
/etc/forwardx/managed-services/amneziawg/<serviceTag>/config.json  # root:forwardx-amneziawg 0640
/usr/local/bin/forwardx-agent __forwardx-amneziawg validate <derived-path>
/usr/local/bin/forwardx-agent __forwardx-amneziawg run <derived-path>
```

- 安装/升级脚本创建或复核无登录 `forwardx-amneziawg` 用户/组；只对实际创建的身份写独立 root marker。helper executable 必须是当前 Agent 自身的 canonical executable，argv 和配置路径全部由 Agent 推导，控制面不能覆盖。
- 预检以低权限 helper 的固定 `validate` 模式构造 AWG device/UAPI 但不占目标端口；全部服务通过后才写 apply marker、停旧批次、原子切换目录并启动固定 `run`。每个 helper 必须由 PID/starttime/executable/argv 和 UDP socket inode共同确认 READY；失败停止新批次并恢复全部旧 MTProto/AWG last-good。
- helper 只创建内存 gVisor TUN 和普通 UDP socket，不打开 `/dev/net/tun`，不修改 OS 网络状态。Agent 从 desired `publicAddress` 与当前 panel URL hostname 生成仅本地 wrapper；helper 周期刷新 deny hostname 的 IPv4 A 记录和本机接口地址，任一配置 hostname 未解析时保持 listener/device 存活但全部出口 fail closed。panel URL 变更时，Agent 先原子写入 `TRANSITION` policy，在 AWG kind root 写入 root 所有的 durable revision pin，并等待 helper 保留旧 IP、解析新 hostname 后的同步 ACK；再切换 runtime URL，用 `STABLE` policy 清理旧 IP，并在第二次 ACK 后清理 pin。wrapper、panel 配置、pin 及其父目录都必须完成 `fsync`；panel URL 同步与迁移在同一全局事务锁内串行。ACK/解析/写入失败时先持久化旧 URL/策略再解除 hold；无法安全恢复则保留 pin，让 helper 在重启和周期刷新后仍持续 fail closed。generation 的 current/state/last-good 全部提交后才可清理失效 pin，回滚期间必须保留。未变更 revision 的 30 秒重读必须真 no-op，不中断已有 TCP/UDP session。TCP/UDP 出站走该 public-only policy 和有界 flow manager；退出时关闭所有 device/socket/session。watchdog 三次有界退避、控制面失联保持与 MTProto 相同。
- Agent 自身升级会短暂终止同 executable 的 helper；新 Agent 在首次面板认证前从严格 last-good 恢复。显式卸载按 PID identity 停止 helper，删除 AWG 配置/state 和仅由 ForwardX 创建的专用用户/组；不会删除系统网络接口，因为首版从不创建它们。

## 15. 外部出口应用生命周期

Xray 出口绑定不增加 Agent 命令或第二套运行时。面板在主机锁内加载全部有效 inbound 和所引用出口，最小解密所需 secret，确定性生成 direct + 去重外部 outbounds + inboundTag routing 的完整配置，再递增现有 generation/hash。Agent 仍先 `run -test`、原子切换并在失败时恢复 last-good；引用损坏在面板编译阶段 fail-closed，不能生成 direct fallback。

iptables、nftables、Realm、socat、GOST、Nginx 六种本地转发引用只在规则期望配置中使用公开 `address:port` 物化结果，Agent 不接收 URI 或代理 secret。iptables/nftables 继续使用既有 DNS 物化和目标变化重建，其余方式沿用既有用户态地址处理。出口定义不参与规则运行状态判断；规则的启动、重启、回滚和离线保持沿用现有生命周期。解除规则引用后才可删除/替换出口定义，避免远端仍运行旧 endpoint 时误清理资源。

## 16. DNSPod + Realm 快速配置生命周期

### 16.1 检查与 preview

- DNS 账号 upsert 在写库前使用候选凭据完成远端验证和 zone/line 同步；轮换时还确认全部在用 zone/recordId 仍可访问，失败不覆盖旧凭据。已保存账号每次成功验证有效 24 小时，zone/line catalog 最多缓存 6 小时；catalog 到期先自动做一次有界刷新，失败返回 stale 投影并阻止新操作。任一过期不撤销已有 DNS。
- 域名 check 只实时读取 DNSPod 并签发 5 分钟 token；管理员 confirm 后签发最长 10 分钟 confirmed token。任一输入、目标/account revision 或远端 record set 变化都会失效。
- port check 可以持久创建既有 Agent probe operation 和短期 host reservation，但不创建 global allocation、quick config、普通规则或 DNS。对最终需新建 Realm listener 的 `FORWARD` host 集合并行检查 TCP/UDP，全部结果齐全才成功；受管 Xray 原端口在落地主机上的 `LANDING/DIRECT` route 不探测自身已占用 listener，改为核对合法账本 alias 与 Xray runtime READY。
- preview 只消费 confirmed domain/probe token 并纯计算 immutable topology、去重规则、A/AAAA 和 default route；不创建 Agent task 或任何业务记录。preview token 最长 5 分钟。

### 16.2 Apply saga

最终 `apply` 先重验全部 token 和外部事实，再在单一数据库事务中取得 domain claim、`RESERVED` allocation、quick config、staged topology、operation 和第一批幂等 steps。worker 必须用 operation revision/lease/fence CAS 取得执行权；lease 长于单次外部请求最大超时与落库余量，旧 fence 的结果拒绝写入，接管者先读取远端事实再决定是否执行。之后按持久 phase 推进：

1. `RECHECKING_DOMAIN`：重新读取 DNS record set、账号/zone/line 和目标/host revision；不一致在外部写入前失败。
2. `RESERVING_PORT`：确认 global allocation 与全部 host reservation 仍有效；过期 reservation 进入保守释放路径。
3. `CREATING_RULES -> WAITING_RULES_READY`：创建正式 Realm `forward_rules` 并等待每个受管 Agent 的规则/service/listener READY；任何失败先进入 `COMPENSATING/REMOVING_NEW_RULES`，DNS 不变。
4. `APPLYING_DNS -> VERIFYING_DNS`：每个 DNS 动作先记录 intent，再按稳定 step/idempotency key 创建或替换，随后读取 recordId/tuple 验证。CreateRecord 成功或结果不明确后的新记录允许最多 30 秒索引可见性窗口，期间以有界退避重复读取同一 tuple，不重复写入。执行层根据持久 route 的动态 category 先处理并验证全部 `DEFAULT` A/AAAA，再处理电信、联通、移动和教育网记录；preview、用户提交顺序和持久 step 身份不变。第 N 条失败时只补偿本 operation 未漂移的前 N-1 条及替换快照。
5. `RETRY` 对远端存在但本地尚无 provider recordId 的记录默认视为漂移；只有 source operation 属于同一 quick config、对应 `DNS_CREATE` 状态为 `RUNNING/SUCCESS/FAILED`、远端 tuple 唯一精确匹配且 recordId 未被其他记录拥有时，才把它视为前序不明确写入并接管。已确认撤销的 `COMPENSATED` 不构成接管证明；仅有相同值或相同域名也不足以建立所有权。
6. `FINALIZING -> COMPLETED`：全部 DNS 验证后把 topology/config/allocation 置 active 并清空 current operation pointer；此时 UI 才显示 `ACTIVE`。

完全补偿成功的创建进入 `FAILED` 并把未消费 allocation 送入 `PENDING_SCAN`。记录漂移、DNS 恢复失败或规则清理未确认时进入 `PARTIAL_FAILURE`，保留两侧对象、端口引用和 operation；不得显示 active 或释放端口。

### 16.3 Edit saga

编辑创建新的 immutable `toTopology`，保留 `fromTopology`、两套 rule/DNS binding 和可能的双 allocation：

1. 新规则 make-before-break；完全相同的 host/port/target 只复用已有普通规则。改端口时旧 listener 持续运行，直到新 listener 全部 READY。
2. 新规则 READY 后切换并验证 DNS；切换前失败只清理 staged-only 对象，旧 topology 不变。
3. DNS 切换中失败时按精确 tuple 恢复旧记录；恢复成功后回旧 topology，失败则保留两套引用并进入 `PARTIAL_FAILURE`。
4. DNS 全部验证后原子切换 active topology，再进入 `RULES_REMOVING/RULES_REMOVED/PORT_RELEASING` 清理旧-only 规则和 allocation。清理失败保持新 topology active、旧 topology retiring，并从相同 operation 重试，不盲目回切 DNS。

落地 target 引用不可在 edit 中替换；换 target 必须先 remove 再新建，避免同时迁移凭据、规则和 DNS 所有权。

### 16.4 Remove 与 retry

remove 先持久化 `DNS_REMOVING` intent，只 CAS 删除自身当前 managed A/AAAA；创建前或历史 edit 已被管理员明确替换的 A/AAAA/CNAME 不作为长期恢复基线，不能在正常删除时复活。每项必须比对 account/zone/recordId/tuple；漂移停止并进入 `PARTIAL_FAILURE`。`DNS_REMOVED` 后才进入 `RULES_REMOVING`，等待所有 Agent 确认 listener 消失；随后删除 binding/route/domain claim，allocation 经 `RELEASING` 到 `PENDING_SCAN`，quick config 才成为 `REMOVED`。

retry 不重新打开历史终态行；它校验原 operation revision 后，通过 quick-config revision/CAS 取得活动 slot 并创建新的 `RETRY` operation，引用原行且只接续非成功步骤。retry 可沿 lineage 只读使用最初 apply/edit 的不可变替换快照继续失败补偿，但每项仍须重读 record tuple、通过 CAS/fence，不能复制快照或用于正常删除。每个外部动作前先读取当前远端事实，不能盲目重复 create/delete。浏览器断开或面板进程退出不取消已提交 operation；调度器重启后从 topology、phase、step、recordId 和 ruleId 恢复。只有尚无外部副作用的 `QUEUED` operation 可取消。

### 16.5 端口回收

每 12 小时调度器以数据库 CAS 获取 `GLOBAL_PORT_RECLAIM` 租约，按有界批次处理 `PENDING_SCAN/EXTERNAL_OCCUPIED`。每个 run 固定当时全部在管 host cohort，对每台 host 并行、整体限流地执行 TCP/UDP 单端口 probe。任一占用转为 `EXTERNAL_OCCUPIED`，任一离线、不支持、错误、超时或过期都保持当前不可用状态。

只有全部结果为空闲时，单一事务再次确认 lease、allocation version、当前 host cohort hash/数量、所有资源类型引用为零和结果未过期，才转为 `FREE`。扫描不停止远端进程、不修改规则；新 host、引用或 allocation revision 在扫描期间变化会丢弃本轮结果。

## 17. 六引擎创建与切换生命周期（TASK058）

创建在端口检查前冻结一个全局 engine，并对全部去重的 `hostId + addressFamily` 重新计算能力交集；任一全局开关、Agent 版本/capability、在线状态或地址族失效都在创建规则前终止。通过后仍沿用 16.2 的规则先行顺序，只是正式规则的 `forwardType` 使用所选 engine。iptables/nftables 等待受管规则存在性确认；Realm、socat、GOST、Nginx 等待既有 service/process/listener readiness。全部 host 成功前不写 DNS，任一失败只补偿本 operation 新建的规则。

engine 修改保持 FQDN、目标 endpoint、公开端口、DNS record 和线路集合不变。因为同一 host 的同一端口不能同时由两个 engine 拥有，切换不能伪装成 make-before-break：worker 先持久保存旧规则安全快照并预检全部 host，再按受控顺序确认旧 engine 清理、应用新 engine、验证对应 readiness。切换期间 UI 明确短暂中断；DNS 保持不变。任一 host 失败时停止后续切换并按快照恢复所有已触及 host 的旧 engine；全部恢复成功则旧 topology 继续 ACTIVE，无法确认恢复时保留引用与端口并进入 `PARTIAL_FAILURE`。

面板重启或 Agent 断线后只从持久 operation/step/fence 和实际规则状态恢复，不重复创建第二个 engine 抢占端口。全局协议开关在 operation 中途关闭时不强杀已运行数据面，但阻止新步骤并进入同一恢复流程；不得静默回退 Realm 或为不同 host 选不同 engine。
