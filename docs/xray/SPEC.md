# 规格：ForwardX 受管 Xray

状态：已批准  
版本：0.26
日期：2026-09-04

实现状态：第一版 `XRAY-TASK-001..037`、多协议基础 `XRAY-TASK-038..042`、Xray-native profile `XRAY-TASK-043..052`、MTProto 独立服务首片 `XRAY-TASK-053`、AmneziaWG userspace 独立服务 `XRAY-TASK-054`、出口节点/中转联动 `XRAY-TASK-055` 与六种本地转发方式出口引用 `XRAY-TASK-056` 已完成；DNSPod 快速配置 `XRAY-TASK-057` 与六引擎创建/切换 `XRAY-TASK-058` 的可体验主流程已实现，集中运行验证待补；TUN 保持 `NOT_IMPLEMENTED`。Reality 默认候选为 `v2`，固定 Xray 默认版本仍为 `v26.3.27`。

## 1. 目标

在 ForwardX 现有多主机面板和子 Agent 架构中加入受管 Xray，使管理员能够从面板为远程服务器安装、配置和升级 Xray，并创建可分享的 VLESS + Reality 节点。

第一版成功标准是：管理员能在一台在线 Agent 主机上创建一个 inbound、添加多个客户端、获得各自分享链接，并在 Agent 重连、面板短暂离线或配置应用失败后保持可解释、可恢复的运行状态。

多协议扩展的目标是在不改变上述控制面和故障语义的前提下，以类型化 profile 逐步支持更多 Xray 协议、传输和安全组合。协议支持至少包含创建、确定性配置生成、部署、监听确认、凭据管理和客户端分享材料；不以“能保存一段任意 JSON”作为支持完成。

出口节点扩展的目标是把管理员导入的外部代理节点保存为一个全局、类型化且可复用的资源。首版支持 VLESS RAW/TCP + Reality + Vision、Shadowsocks 和 SOCKS5 链接；同一资源既可作为受管 Xray inbound 的 outbound，也可作为现有 iptables、nftables、Realm、socat、GOST、Nginx TCP 端口转发规则的目标端点。两种使用方式相互独立，不把任何 L4 转发器误表述为能够解析代理协议。

独立服务扩展继续使用同一面板—Agent 单向控制原则，但不伪装成 Xray inbound。`MTPROTO_FAKE_TLS` 由固定 sidecar 承载；`AMNEZIAWG` 由同一 Agent 二进制的固定低权限 helper 子命令承载。TUN 在特权方案获批前不开放。

## 2. 使用者

- 第一版唯一使用者是 ForwardX 管理员。
- 普通用户不显示 Xray 菜单，也不能读取或修改 Xray 资源。
- 后续可以把客户端关联 ForwardX 用户，但不属于第一版交付范围。

## 3. 已确认需求

### 3.1 节点与客户端

- `XRAY-REQ-001` 第一版只支持 VLESS + Reality + TCP/RAW + XTLS Vision。
- `XRAY-REQ-002` 一个节点定义为一个 Xray inbound/listener，一个 inbound 允许多个客户端。
- `XRAY-REQ-003` 每个客户端拥有独立 UUID、名称、启用状态和分享链接。
- `XRAY-REQ-004` 每个 inbound 使用独立 Reality 密钥对；客户端可使用独立 shortId。
- `XRAY-REQ-005` 第一版不提供任意 Xray JSON 编辑器，不开放未列入规格的协议和传输方式。

### 3.2 主机、地址和端口

- `XRAY-HOST-001` 创建节点时只允许选择 Agent 在线、心跳新鲜且声明支持 Xray v1 能力的主机。
- `XRAY-HOST-002` 离线或能力不足的主机在选择器中灰显并禁用，同时显示不可用原因；后端必须重复校验，不能只依赖前端。
- `XRAY-HOST-003` 分享链接默认使用 Agent 上报的公网 IPv4；inbound 保存独立的 `publicAddress`，不把监听地址当作分享地址。
- `XRAY-HOST-004` Agent 离线或心跳过期时，第一版拒绝该主机的全部 Xray 写操作，包括节点、客户端、启停、删除、同步、扫描、端口探测、安装、升级和重启；已有数据仍可只读查看，最后一次运行状态必须标记为历史状态。
- `XRAY-PORT-001` 自动端口范围固定为 `1000–65535`。
- `XRAY-PORT-002` 面板先排除 ForwardX、隧道和 Xray 数据库已知端口，再让目标 Agent 对候选 TCP 端口执行实际 bind 探测。
- `XRAY-PORT-003` 面板对候选端口使用短期预留；Xray 最终绑定仍冲突时，操作必须失败并可安全重试，不得覆盖其他监听程序。
- `XRAY-PORT-004` 创建向导对仍有效的结果重新探测时，必须显式携带当前向导持有的旧 reservation；服务端只允许受控替换同一管理员、同一主机和同一端口的最多一项 TCP 与一项 UDP 预留。旧 reservation 缺失或已过期按已经释放处理；仍有效但 owner、host、port、网络唯一性或数量不匹配时拒绝请求。释放后必须重新执行端口策略、数据库、全局账本与 Agent bind 检查，不能把“替换自己的预留”作为绕过其他占用的例外。

### 3.3 Reality 目标扫描

- `XRAY-SCAN-001` Reality 扫描在目标子 Agent 上执行，因为 DNS、路由、网络限制和延迟取决于节点位置。
- `XRAY-SCAN-002` 面板可以提供版本化的内置公网候选列表，也允许管理员输入受限的公网域名目标。
- `XRAY-SCAN-003` 扫描结果至少返回目标、解析 IP、TLS 1.3、H2、X25519、证书有效性、可用 serverName、延迟和失败原因。
- `XRAY-SCAN-004` 第一版不提供任意 CIDR 批量扫描，不允许私网、回环、链路本地、保留地址或云元数据目标。
- `XRAY-SCAN-005` 默认候选列表版本为 `v2`：保留 `www.cloudflare.com:443`，加入经过真实 Reality 握手验证的 Amazon/AWS、Samsung、NVIDIA、AMD、Intel、Sony 和 Google 下载站候选；移除会在现有环境触发 Reality 握手校验失败的 `www.microsoft.com:443`。默认候选仍必须经过目标 Agent 的完整安全与 TLS 扫描才能选择。

### 3.4 安装、升级和运行

- `XRAY-RUN-000` Agent 的真实语义版本与发行来源是两个独立身份。新 Forwardplus Agent 必须上报 `agentDistribution=forwardplus` 和有界 `agentBuildId`；旧 Agent 缺失来源时按 `unknown` 处理，不能因其版本号较高而推断包含 Forwardplus 能力。面板在来源不匹配或真实版本落后任一条件成立时提示/执行迁移，且只有来源匹配并满足目标版本才把升级标记完成。界面始终显示 Agent 上报的真实版本，不生成临时虚高版本。
- `XRAY-RUN-001` Xray 按需安装；没有任何 inbound 的主机不要求预装 Xray。
- `XRAY-RUN-002` Agent 从面板的受鉴权制品接口下载 Xray，不直接依赖目标服务器访问 GitHub。
- `XRAY-RUN-003` 面板按版本、操作系统和 CPU 架构缓存并校验制品；Agent 必须在安装前校验 SHA-256。
- `XRAY-RUN-004` ForwardX 使用专属二进制和配置路径，不覆盖、不复用服务器已有的系统 Xray。
- `XRAY-RUN-005` 面板目标版本高于 Agent 受管版本时显示升级选项，不在普通配置同步中强制升级。
- `XRAY-RUN-006` Agent 版本高于面板目标版本时不得自动降级。
- `XRAY-RUN-007` 新配置必须先在临时文件中通过 Xray 配置测试，再原子切换；失败时保留或恢复最后一次成功配置和二进制。
- `XRAY-RUN-008` Agent Token 无效、面板不可达、心跳失败或 SSE 断开时，不得主动停止已经运行的 Xray。
- `XRAY-RUN-009` Agent 恢复通信后，面板通过 generation/hash 重新对齐期望状态和实际状态。
- `XRAY-RUN-010` 第一版由 ForwardX Agent 直接持有并监管 Xray OS 子进程，不创建独立 `forwardx-xray.service`；控制面认证或网络错误不能取消该运行上下文或触发 stop。
- `XRAY-RUN-011` 当前目标版本固定为 Xray-core `v26.3.27`；不得使用 `latest` 作为隐式版本。
- `XRAY-RUN-012` Agent 自动识别 Linux CPU 架构，第一版只声明现有 ForwardX Agent 发布链已经覆盖的 `amd64` 和 `arm64`；其他架构明确报告不支持，不回退下载错误制品。
- `XRAY-RUN-013` Agent service 停止、崩溃或升级时允许 Xray 短暂中断；新 Agent 必须在尝试面板注册前从本地 last-good 恢复，保留默认 cgroup 清理语义，不遗留孤儿 Xray。
- `XRAY-RUN-014` 删除最后一个 inbound 时停止受管 Xray 子进程但保留已验证二进制；显式卸载 Agent 时停止并删除 ForwardX 受管 Xray 进程、配置和二进制。
- `XRAY-RUN-015` 生产面板在数据库就绪后自动将固定 `v26.3.27` 的 `linux-amd64`、`linux-arm64` 制品填充到面板持久数据目录；只有两项均通过固定清单校验后才设置默认版本。Agent 始终只从面板下载，自动填充失败时不得回退为 Agent 直连公网，也不得阻止面板提供管理界面。

### 3.5 状态同步

- `XRAY-SYNC-001` 面板数据库是节点、客户端、密钥、目标版本和期望配置的唯一权威来源。
- `XRAY-SYNC-002` 面板按主机生成完整 Xray 配置快照，不向 Agent 发送会形成第二套配置真相的零散 Shell 命令。
- `XRAY-SYNC-003` 每台主机使用单调递增的 `generation` 和规范化配置 `configHash`。
- `XRAY-SYNC-004` Agent 上报安装版本、运行版本、进程/服务状态、已应用 generation/hash、受管监听器和脱敏错误；不回传私钥、UUID或完整配置。
- `XRAY-SYNC-005` 同一 generation/hash 已成功应用且本地运行一致时必须幂等跳过；发现运行漂移时必须重新应用或报告明确错误。

### 3.6 面板和权限

- `XRAY-UI-001` 管理员侧边栏增加“Xray 节点”，页面包含“节点管理”和“运行环境”。
- `XRAY-UI-002` 创建流程展示服务器、端口、Reality、初始客户端和部署确认；异步部署必须显示阶段和最终结果。
- `XRAY-UI-003` 节点详情支持多个客户端的新增、启停、删除、VLESS URI 复制和二维码展示。
- `XRAY-UI-004` Reality 私钥不在常规页面显示；分享链接只包含公钥和客户端所需字段。
- `XRAY-UI-005` 节点删除请求受理后必须关闭该节点详情并清除 URL 中的详情身份，再刷新节点列表；不得重新查询可能已在 observed 收敛后物理清理的节点并把 `NOT_FOUND` 呈现为删除失败。
- `XRAY-UI-006` 管理员 Xray 界面默认开启。为修复早期 ForwardX 迁移脚本留下 `FORWARDX_XRAY_ENABLED=0`、缺失开关或缺失迁移标记后永久隐藏入口的问题，安装器和面板运行时使用 `FORWARDPLUS_XRAY_UI_POLICY_VERSION=1` 区分当前策略与历史状态：策略标记缺失时，历史开关值不具备“管理员主动关闭”的可证明来源，首次启动及升级必须显示 Xray，并由新版安装器把开关和策略标记持久化为 `1`；策略标记为当前版本后，`FORWARDX_XRAY_ENABLED=0`、`false`、`off` 等显式关闭值必须在后续升级中保留。公共设置读取失败仍须隐藏入口，功能开关不得替代后端管理员鉴权。
- `XRAY-AUTH-001` 所有 Xray 查询、变更、扫描、安装和升级接口只允许管理员调用。

### 3.7 暂不实现

- `XRAY-NON-001` 当前多协议阶段不做客户端或 inbound 流量统计、流量限额或流量重置。
- `XRAY-NON-002` 第一版不管理 iptables、nftables、ufw、firewalld 或云安全组。
- `XRAY-NON-003` 当前多协议阶段不做到期时间、订阅、fallback、sniffing、任意路由或负载均衡；唯一批准的路由能力是 `3.9` 定义的按受管 inboundTag 精确绑定一个类型化出口节点。
- `XRAY-NON-004` 第一版不向普通 ForwardX 用户开放节点创建和客户端自助管理。
- `XRAY-NON-005` 第一版不自动扫描任意互联网网段。
- `XRAY-NON-006` 不开放任意 Xray JSON、任意文件路径或任意 Shell 命令入口。

### 3.8 多协议扩展

- `XRAY-MP-001` 面板数据库继续是全部协议期望配置和密钥的唯一权威；新增、编辑、启停或删除任一入站/账户后，面板按主机生成包含全部有效记录的完整配置快照。
- `XRAY-MP-002` Agent 不读取、解析或回传现有配置供面板合并；Agent 只校验并原子应用面板快照，上报脱敏 observed state。Agent 本地旧配置只用于幂等、漂移检查和 last-good 回滚。
- `XRAY-MP-003` 使用服务端拥有的类型化 profile 目录定义协议、传输、安全、flow、监听网络和目标 Xray 版本兼容性；未列入且未验证的组合必须拒绝，前端不得独立维护另一份兼容矩阵。
- `XRAY-MP-004` 第一批 Xray 原生节点按顺序覆盖 VLESS、Trojan、VMess、Shadowsocks；传输按 profile 开放 RAW、gRPC、WebSocket、HTTPUpgrade、XHTTP 和 mKCP，安全层按组合开放 Reality、TLS 或 none。mKCP 的产品名称不改变其 UDP 监听事实，不能按 TCP profile 验收。
- `XRAY-MP-005` Reality 只开放给批准的 VLESS/Trojan profile；Vision 只允许 RAW TCP + Reality/TLS；Hysteria 2 必须使用 TLS。VLESS/Trojan 公网明文 profile 默认不开放。
- `XRAY-MP-006` mKCP、Hysteria 2、WireGuard 和 Shadowsocks UDP 在 Agent 合同增加 UDP 探测和监听确认后实施；端口身份使用 `host + network + port`，不能继续用 transport 代替网络。mKCP TLS 可以先锁定 profile 合同并通过配置测试，但在 `XRAY-TASK-049` 完成前不得创建或标记可用。
- `XRAY-MP-007` HTTP、SOCKS/Mixed、Tunnel 属于后续本地/管理代理能力；公网监听必须有认证且不能产生默认开放代理。TUN、MTProto、AmneziaWG 使用独立受管服务契约和显式能力/权限门控，不混入 Xray inbound config。
- `XRAY-MP-008` 默认核心版本保持 `v26.3.27`；profile 只有通过该固定版本的配置测试和运行验证后才能标记可用。当前不因增加协议引入多版本自动选择或隐式升级。
- `XRAY-MP-009` 现有 VLESS Reality API、数据库记录和分享行为必须向后兼容；迁移采用可重复的增量结构，不用伪造 UUID/shortId 填充其他协议。
- `XRAY-MP-010` 未完成 profile 不出现在可创建列表；已有管理员功能开关继续保护整个 Xray UI。
- `XRAY-MP-011` inbound 的 `profileId/specVersion/specJson` 采用可空增量存储；旧记录继续由原结构化列映射到现有 profile。显式 spec 必须限长并按 profile/version 严格重验，不能保存或接收完整 Xray JSON。
- `XRAY-MP-012` 3x-ui 对照目标固定为其当前后端接受的 VLESS、VMess、Trojan、Shadowsocks、Hysteria、WireGuard、HTTP、Mixed、Tunnel、MTProto 和 AmneziaWG，以及 RAW、mKCP、WebSocket、gRPC、HTTPUpgrade、XHTTP 传输。TUN 仅保留为独立特权能力评估项，因为参考实现当前前端只为旧数据保留渲染兼容、后端不再把它作为普通 inbound 接受。ForwardX 不复制任意组合：每个协议/传输/安全组合必须成为独立的已验证 profile；MTProto、AmneziaWG 和未来 TUN 使用独立 `managedServices` 合同。
- `XRAY-MP-013` “多协议支持完成”不能以数据库底座、可保存 profile 或生成配置为准。普通节点协议必须同时完成创建/编辑、凭据、确定性完整快照、Agent 应用与监听、分享材料和真实连接验证；管理代理与独立服务必须分别通过检查点 J。`XRAY-TASK-038..042` 仅属于检查点 F 的基础，不得在 UI、交接或发布说明中表述为已支持全部协议。
- `XRAY-MP-014` 首个新增 profile 固定为 `VLESS_GRPC_REALITY`：只允许非空、最长 128 字节且由 ASCII 字母、数字、点、下划线、波浪号或连字符组成的 `serviceName`，`multiMode=false`，不设置 `authority`，客户端 flow 必须为 `NONE`。服务端配置和 VLESS URI 都由该判别 spec 生成，不能携带隐藏的 Vision 值。
- `XRAY-MP-015` `VLESS_XHTTP_REALITY` v1 只接收 `{ path }`：路径总长 1–128 位，必须以 `/` 开头，其余只允许 ASCII 字母、数字、`._~/-`；传输固定 `mode=auto`、空 host、空 headers，不开放 padding、xmux、downloadSettings 或其他高级字段。客户端 flow 必须为 `NONE`，分享 URI 固定包含 `type=xhttp`、编码后的 `path` 和 `mode=auto`。
- `XRAY-MP-016` `TROJAN_RAW_REALITY` v1 使用严格空 spec、RAW TCP、Reality 和 `NONE` flow；每个账户由服务端生成 32-byte 随机值并以 43 位 canonical base64url password 保存到 generic access secret，`legacyClientId` 必须为 `NULL`，不得创建或伪造 `xray_clients` 行。分享 URI 固定为 `trojan://<encoded-password>@<endpoint>?type=tcp&security=reality...` 且不含 flow/fallback。
- `XRAY-MP-017` TLS 第一版只接受管理员在浏览器中粘贴或选择的 PEM 完整证书链与未加密 PEM 私钥；浏览器读取为文本后调用受鉴权接口，不上传或保存原文件名。证书按主机托管并可被同一主机的多个 inbound 引用，不接受 Agent 文件路径、PFX/PKCS#12、JKS、压缩包、加密私钥、任意 TLS JSON 或跨主机引用。证书链最大 16 KiB、最多四张证书，私钥最大 8 KiB；服务端必须验证 PEM 结构、有效期、DNS SAN、叶证书与私钥匹配及批准的 RSA/ECDSA 算法。
- `XRAY-MP-018` TLS 私钥在面板数据库中使用证书稳定身份绑定的 AEAD 加密；面板为固定 `v26.3.27` 生成内联 `certificate`/`key` 配置，不生成 `certificateFile`/`keyFile`。轮换复用主机 generation、完整快照、Agent 配置测试、原子切换和 last-good；被 inbound 引用的证书不得删除。第一版不做 ACME、自动续期、多证书 SNI、明文私钥导出、OCSP/ECH 或自定义密码套件。
- `XRAY-MP-019` 创建界面采用由服务端可用 profile 驱动的“基础配置 / 协议 / 传输 / 端口 / 安全 / 账户 / 确认”分区。基础配置只收集主机、名称和公网地址；只有协议与传输已归一化为明确 profile 后才允许进入端口分区，并按该 profile 的 `listenerNetworks` 直接执行 TCP、UDP 或同端口 TCP+UDP 探测，不先做默认 TCP 探测。改变主机或 listener network 必须使旧结果失效，但保留其他表单草稿且不自动跳回基础配置。协议、传输或安全变化仍必须清除不兼容的隐藏字段；未完成 profile、嗅探、fallback、高级 JSON 和路由不显示。该交互只借鉴 3x-ui 的信息分组，不复制其任意组合或配置透传模型。
- `XRAY-MP-020` VLESS/Trojan TLS 使用下表 13 个独立 profile；VLESS RAW 同时提供标准 TLS 和 Vision 两种明确 profile，对应参考界面的 flow 开关。其余传输和全部 Trojan profile 固定 `NONE` flow，不接受隐藏 flow。
- `XRAY-MP-021` TLS profile 的 `serverName` 是 profile 外的共同必填字段：只接受 1–253 字节的规范化 ASCII DNS 名称，不接受 IP、通配符或任意 SNI，并且必须被所选同主机证书的 DNS SAN 覆盖。RAW/mKCP 使用严格空 v1 spec；WebSocket、HTTPUpgrade、XHTTP 只接受严格 `{ path }`；gRPC 只接受严格 `{ serviceName }`。path 和 serviceName 沿用现有已验证的 1–128 字节字符集；所有额外 Host、headers、early data、authority、multiMode、XHTTP extra、mKCP 参数、FinalMask、PROXY protocol 和 TLS 高级字段均拒绝。
- `XRAY-MP-022` 所有 TLS 分享材料固定包含 `security=tls`、规范化 `sni`、`fp=chrome` 和所选证书叶证书 SHA-256 的 `pcs`；VLESS 另含 `encryption=none`，只有 `VLESS_RAW_TLS_VISION` 含 `flow=xtls-rprx-vision`。这使受管自签证书无需 `allowInsecure` 也可验证；证书轮换会改变 `pcs`，应用新 generation 后管理员必须重新分发分享材料。
- `XRAY-MP-023` TLS VLESS 账户使用 generic-only `UUID` secret，不生成无意义 shortId 或旧 `xray_clients` 行；其账户设置使用版本 2 严格 `{ schemaVersion: 2, protocol: "VLESS", encryption: "NONE", flow }`。TLS Trojan 继续使用 generic-only `PASSWORD`。非 Reality TLS inbound 不生成 Reality 私钥或 `REALITY_PRIVATE_KEY` secret。
- `XRAY-MP-024` VMess/Shadowsocks 在固定 `v26.3.27` 中均能构建和运行，但核心会输出 deprecated 警告并建议迁移到 VLESS Encryption。ForwardX 只把它们作为兼容现有客户端的显式 profile；catalog 必须返回 `CORE_DEPRECATED` 告警，创建入口当前可见或以后恢复时必须提示优先使用 VLESS/Trojan，不将其作为新建默认协议。VMess 的当前创建可见性以 `XRAY-MP-064` 为准。
- `XRAY-MP-025` VMess 首版只开放 `VMESS_RAW_TLS`：TCP 监听、严格空 spec、受管 TLS 证书/SNI/pin，每账户使用服务端生成的 generic-only UUID v1，设置固定 `flow=NONE/security=AUTO`。服务端和分享都不写 `alterId/aid`，不接受用户自选 VMess 密码算法、flow、Reality 或 none。WebSocket/gRPC/HTTPUpgrade/XHTTP/mKCP 和其他安全组合不在本切片中暗中开放。
- `XRAY-MP-026` Shadowsocks 首版只开放 `SHADOWSOCKS_2022_RAW_NONE`：RAW TCP、严格空 spec、无传输层 TLS/Reality，method 固定 `2022-blake3-aes-256-gcm`。每个 inbound 生成独立 32-byte 服务端 PSK，每账户生成独立 32-byte 用户 PSK，两者都使用带单个 `=` 填充的 44 字符 canonical base64。启用中的 inbound 必须始终至少有一个启用且非待删除账户；禁用或删除最后一个有效账户必须返回 `LAST_ACTIVE_ACCESS_REQUIRED`，否则 Xray 会把空 clients 退化为可使用服务端 PSK 登录的单用户模式。
- `XRAY-MP-027` `VMESS_RAW_TLS` 分享使用 `vmess://<standard-base64(compact UTF-8 JSON)>`，JSON 只包含 `v=2/ps/add/port/id/scy=auto/net=tcp/type=none/tls=tls/sni/fp=chrome/pcs`，不包含 `aid/alterId/host/path/allowInsecure`。`SHADOWSOCKS_2022_RAW_NONE` 使用 SIP002/SIP022 明文 userinfo 格式 `ss://method:<percent-encoded-server-psk>:<percent-encoded-user-psk>@endpoint#name`，不使用 base64 userinfo，不写非标准 `type/security` 查询参数。两种分享都是凭据，只能在管理员 `private, no-store` 响应中按需生成。
- `XRAY-MP-028` UDP 以 v1 envelope 的向后兼容可选能力扩展交付：capability 新增 `supportsUdpPortProbe` 和 `supportsUdpListenerReadiness`，缺失一律按 `false`；desired、observed 和 `PORT_PROBE` 的 listener `network` 只扩展为明确的 `tcp | udp`，不接受 `both`。面板只有在两项 UDP 能力均为 `true` 时才允许创建或下发 UDP profile；旧 Agent 收到 UDP task/desired 必须以既有 `INVALID_PAYLOAD` 安全拒绝，TCP payload 字节和行为保持不变。UDP probe 每个 task 只允许一个端口；Agent 探测、短期预留和 listener 收敛继续以 `host + network + port` 为技术身份，但 `XRAY-QC-011..012` 在面板增加不区分 TCP/UDP 的更严格全局逻辑分配层，不能再把底层可绑定等同于面板允许复用。
- `XRAY-MP-029` Hysteria 2 首版只开放 `HYSTERIA2_TLS`：UDP 监听、Hysteria transport、TLS、`NONE` flow、严格空 v1 spec 和固定 version 2。服务端配置固定为 `protocol=hysteria`、`settings.clients=[{ auth, email }]`、`streamSettings.network=hysteria`、`hysteriaSettings.version=2/udpIdleTimeout=60`、TLS ALPN `h3`，并复用同主机受管证书、规范化 SNI 和内联密钥。第一版不开放无 TLS、带宽、拥塞控制、端口跳跃、masquerade、Salamander/其他 obfs、FinalMask、ECH、自定义 ALPN/idle timeout 或任意 Hysteria JSON。
- `XRAY-MP-030` 每个 Hysteria 2 账户使用服务端生成的 32-byte 随机值并规范化为 43 位 canonical base64url auth；只写 generic `HYSTERIA_AUTH` access secret 和严格 `{"schemaVersion":1}` settings，不创建 legacy client 或 inbound 级 auth。分享固定为 `hysteria2://<percent-encoded-auth>@<endpoint>?sni=<encoded-sni>&pinSHA256=<lowercase-leaf-sha256>#<encoded-name>`，不生成 `insecure`、`allowInsecure` 或 `pcs`；Hysteria URI 的 `pinSHA256` 与通用 TLS URI 的 `pcs` 是同一受管叶证书指纹的协议专用字段。创建、修改和 desired 下发前必须同时确认主机两项 UDP capability，能力不足不得产生业务写入。
- `XRAY-MP-031` Shadowsocks 原生 UDP 作为独立 `SHADOWSOCKS_2022_RAW_TCP_UDP_NONE` profile 实施；不得修改已开放 `SHADOWSOCKS_2022_RAW_NONE` 的 TCP-only 含义。新 profile 继续固定 RAW、none、严格空 v1 spec、`2022-blake3-aes-256-gcm`、同一套 inbound/user 双 PSK、最后有效账户保护、SIP002/SIP022 分享和 `CORE_DEPRECATED` 告警，但服务端 `settings.network` 固定为 `tcp,udp`，同一 runtimeTag/port 必须声明并收敛 TCP、UDP 两个 expected listener。
- `XRAY-MP-032` 双网络 profile 不扩展 Agent `PORT_PROBE.network` 为 `both`。创建时必须对同一 host/user/port 分别取得 TCP 与 UDP 两份短期预留，API 以 additive 严格对象 `portReservations: { tcp, udp }` 接收精确的双 reservation，在任何业务写入前同时验证，并由同一创建事务作用域消费；既有单网络 profile 继续使用 `portReservationId`，两种字段不得混用。主机缺少任一 UDP capability 时 catalog、探测后的创建、修改和 desired 下发全部安全拒绝。第一版不使用旧单 reservation 更新双网络入站端口；名称、公网地址、启停、删除和账户写操作继续可用并受双 UDP capability 门控，端口迁移等待独立双 reservation 更新合同。
- `XRAY-MP-033` WireGuard 首版只开放 `WIREGUARD_UDP_NONE`：Xray 原生 WireGuard inbound、UDP listener、`transport=NONE`、`security=NONE`、`flow=NONE` 和严格空 v1 inbound spec。服务端配置固定使用 gVisor userspace TUN、`noKernelTun=true`、MTU 1420、隧道服务端地址 `10.0.0.1/32`；只生成 `secretKey/peers/mtu/noKernelTun/address`，不开放 kernel TUN、workers、reserved、domainStrategy、IPv6、自定义 subnet/MTU/DNS/路由、TLS/Reality 或任意 WireGuard JSON。该 profile 必须显示 WireGuard 外层特征可能被识别或封锁的风险提示，不作为默认推荐。
- `XRAY-MP-034` 每个 WireGuard peer 由服务端生成独立 X25519/WireGuard 私钥和 32-byte pre-shared key，均规范化为带单个 `=` 的 44 字符 standard base64；peer 公钥从私钥派生，不接受浏览器输入，也不进入普通 DTO。启用 peer 的唯一 IPv4 地址从固定 `10.0.0.0/24` 按最低空闲 `.2/32` 分配，`.1` 保留给服务端，单 inbound 仍受 32 个账户上限；分配与写入在主机锁/数据库事务内完成，重复地址、密钥不匹配、地址耗尽或能力降级必须零业务写入且不增加 generation。Xray server peer 只含派生公钥、PSK 与该 `/32` allowed source，不写客户端私钥、endpoint、email 或 keepAlive；启用 inbound 至少保留一个启用且非待删除 peer。
- `XRAY-MP-035` WireGuard 分享只返回标准 `.conf` 文本：`[Interface]` 固定包含 peer 私钥、分配地址、`DNS = 1.1.1.1, 1.0.0.1` 和 `MTU = 1420`；`[Peer]` 固定包含派生的 server 公钥、peer PSK、`AllowedIPs = 0.0.0.0/0`、规范 endpoint 和 `PersistentKeepalive = 25`。首版为 IPv4 全隧道配置，不生成非标准 `wireguard://` URL；文本与其二维码整体按凭据处理，只能由管理员 `private, no-store` 按需获取，不能写数据库、日志、operation、URL 或浏览器持久存储。固定核心真实 TCP/UDP、错误 peer key/PSK、Agent UDP readiness/last-good 和泄漏验收完成前 profile 保持 `IMPLEMENTING`。

### 3.9 VLESS/Trojan TLS profile 矩阵

| profile | transport/spec v1 | flow | credential | listener | 开放门槛 |
|---|---|---|---|---|---|
| `VLESS_RAW_TLS` | RAW / `{}` | `NONE` | `UUID` | TCP | 047B 独立真实连接 |
| `VLESS_RAW_TLS_VISION` | RAW / `{}` | `XTLS_RPRX_VISION` | `UUID` | TCP | 047B 独立真实连接 |
| `TROJAN_RAW_TLS` | RAW / `{}` | `NONE` | `PASSWORD` | TCP | 047C 独立真实连接 |
| `VLESS_WEBSOCKET_TLS`, `TROJAN_WEBSOCKET_TLS` | WebSocket / `{ path }` | `NONE` | UUID / password | TCP | 047D 每项独立真实连接 |
| `VLESS_GRPC_TLS`, `TROJAN_GRPC_TLS` | gRPC / `{ serviceName }`，固定 `multiMode=false`、TLS ALPN `h2` | `NONE` | UUID / password | TCP | 047E 每项独立真实连接 |
| `VLESS_HTTP_UPGRADE_TLS`, `TROJAN_HTTP_UPGRADE_TLS` | HTTPUpgrade / `{ path }` | `NONE` | UUID / password | TCP | 047F 每项独立真实连接 |
| `VLESS_XHTTP_TLS`, `TROJAN_XHTTP_TLS` | XHTTP / `{ path }`，固定 `mode=auto` | `NONE` | UUID / password | TCP | 047G 每项独立真实连接 |
| `VLESS_MKCP_TLS`, `TROJAN_MKCP_TLS` | mKCP / `{}`，固定核心默认值 | `NONE` | UUID / password | UDP | 047H 且依赖 TASK049 |

表中的 UUID/password 均指服务端生成并加密保存的 generic access secret。固定 `v26.3.27` 已对 13 个最小服务端配置完成 `run -test`，但配置语法通过不等于 profile 可用；仍须逐项完成创建、快照、监听、分享和真实客户端连接。

### 3.10 VMess/Shadowsocks 首版 profile 矩阵

| profile | transport/security/spec v1 | 凭据 | listener | 分享 | 开放门槛 |
|---|---|---|---|---|---|
| `VMESS_RAW_TLS` | RAW / TLS / `{}` | generic-only UUID v1，固定 AEAD `AUTO` | TCP | VMess v2 base64 JSON + `pcs` | 048D 真实 pin/轮换连接 |
| `SHADOWSOCKS_2022_RAW_NONE` | RAW / none / `{}`，固定 `2022-blake3-aes-256-gcm` | inbound server PSK + generic-only user PSK | TCP | SIP002/SIP022 `ss://` | 048F 真实多用户连接 |
| `SHADOWSOCKS_2022_RAW_TCP_UDP_NONE` | RAW / none / `{}`，固定 `2022-blake3-aes-256-gcm` | 复用同类但逐节点/账户独立生成的 inbound server PSK + generic-only user PSK | TCP + UDP | 同一 SIP002/SIP022 `ss://` | 051E 真实 TCP/UDP、多用户和双 listener 收敛 |

这些 profile 只代表协议的可互操兼容切片，不代表复制 3x-ui 的任意组合。固定 `v26.3.27` 对同一份 VMess TLS + Shadowsocks 2022 RAW 合并服务端配置 `run -test` 通过，并同时输出两协议 deprecated 警告；`SHADOWSOCKS_2022_RAW_NONE` 的 `network=tcp` 即使可转发 XUDP 也仍是 TCP-only listener。TASK051 新 profile 必须在 051E 真实证明 TCP/UDP socket、原生 UDP 客户端流量和双 listener 收敛后才能由 `IMPLEMENTING` 改为 `AVAILABLE`。

### 3.11 Hysteria 2 首版 profile

| profile | transport/security/spec v1 | 凭据 | listener | 分享 | 开放门槛 |
|---|---|---|---|---|---|
| `HYSTERIA2_TLS` | Hysteria v2 / TLS / `{}`，固定 ALPN `h3`、`udpIdleTimeout=60` | generic-only `HYSTERIA_AUTH`，32-byte canonical base64url | UDP | 标准 `hysteria2://` + `sni` + `pinSHA256` | 050E 真实 auth、pin、UDP readiness 和客户端连接 |

固定 `v26.3.27` 已通过生产生成器和分享函数驱动的真实 `UDP/Hysteria2 -> SOCKS -> HTTP` 验收：正确 auth 与受管叶证书 pin 成功，错误 auth 或错误 pin 失败，且不使用 `allowInsecure`。Agent 的受管 PID UDP readiness 与 TCP+UDP 混合快照 last-good 回滚、生产构建和代表浏览器创建流程也已通过；`HYSTERIA2_TLS` 因此标记为 `AVAILABLE`，但仍按主机双 UDP capability 动态门控。

### 3.12 认证型 HTTP 管理代理首版 profile

- `XRAY-MP-036` 首个管理代理切片固定为 `HTTP_RAW_NONE`：Xray inbound `protocol=http`、RAW/TCP、`security=none`、`flow=NONE`、严格空 `spec`，只生成 `settings.accounts`、`allowTransparent=false` 和 `userLevel=0`。不开放透明代理、TLS、Unix socket、fallback、sniffing、路由、任意 headers 或 Xray JSON。
- `XRAY-MP-037` `HTTP_RAW_NONE` 必须至少有一个启用且未待删除的账户；服务端为每个账户独立生成 Basic 用户名和密码，两者均作为 secret 加密保存。显示名称只用于管理和分享展示，改名不能改变用户名；创建/编辑 API 不接受浏览器提交用户名或密码，启用中的 inbound 禁止移除最后一个有效账户。
- `XRAY-MP-038` HTTP 代理是管理员明确创建的管理代理，不是普通代理订阅节点，也不作为创建页默认推荐。因为 Basic 凭据在无 TLS 的代理连接上可被路径观察者读取，创建确认、详情和分享必须显示高可见风险提示；公网监听若没有有效认证账户必须由服务端拒绝，不能静默生成开放代理。
- `XRAY-MP-039` 分享固定为标准 `http://<percent-encoded-user>:<percent-encoded-password>@<endpoint>`，仅在管理员按需请求时解密并返回，响应为 `private, no-store`。完整代理 URL、用户名和密码不得进入普通 DTO、日志、operation、地址栏或浏览器持久存储。profile 只有在固定 `v26.3.27` 的配置验证、正确认证 HTTP/CONNECT、缺失/错误认证拒绝、Agent TCP readiness/last-good、secret-leak、构建和代表浏览器验收全部完成后才能标记为 `AVAILABLE`。

| profile | transport/security/spec v1 | 凭据 | listener | 分享 | 开放门槛 |
|---|---|---|---|---|---|
| `HTTP_RAW_NONE` | RAW / none / `{}`，固定非透明代理 | generic-only `HTTP_BASIC`，服务端生成 username + password | TCP | 标准认证型 `http://` proxy URL | 052E 正确/缺失/错误认证、CONNECT、Agent 与泄漏验收 |

052E 已使用固定 SHA-256 对应的 Xray `v26.3.27` 完成生产生成器驱动的真实 HTTP/CONNECT 验收：正确 Basic 认证可用，缺失认证、错误用户名和错误密码均返回 `407`。持久化、Agent TCP readiness/last-good、secret-leak、生产构建和代表浏览器流程也已通过，因此 `HTTP_RAW_NONE` 已标记为 `AVAILABLE`。

### 3.13 认证型 Mixed 管理代理首版 profile

- `XRAY-MP-040` 首个 SOCKS/Mixed 切片固定为 `MIXED_RAW_NONE`：Xray inbound `protocol=mixed`、RAW/TCP、`security=none`、`flow=NONE` 和严格空 `spec`。固定核心 `v26.3.27` 将 `mixed` 与 `socks` 都解析为同一 `SocksServerConfig`，单个 listener 按首字节分流 SOCKS 或内嵌 HTTP；ForwardX 对外名称因此固定为“Mixed（SOCKS5 + HTTP）管理代理”，不伪装成两个独立 listener。
- `XRAY-MP-041` 配置必须精确生成 `settings.auth=password`、一个或多个 `{ user, pass }` accounts、`udp=false` 和 `userLevel=0`。密码模式下固定核心拒绝 SOCKS4/4a，因此产品只承诺认证 SOCKS5、HTTP 和 HTTP CONNECT；不开放 `noauth`、SOCKS4/4a、透明代理、TLS、fallback、sniffing、路由、任意 headers 或 Xray JSON。
- `XRAY-MP-042` 每个账户使用独立 `MIXED_USER_PASSWORD` credential，服务端分别生成 16-byte canonical base64url username 和 32-byte canonical base64url password，并作为两个资源绑定 secret 加密保存；创建/编辑 API 只接收显示名称。启用中的 inbound 必须至少保留一个启用且未待删除的账户，缺失任一 secret 或零有效账户必须在 generation/config 生成前失败。
- `XRAY-MP-043` 首版明确固定 TCP-only。固定核心的 SOCKS UDP 过滤只在一次认证 TCP UDP ASSOCIATE 后按来源 IP 放行，且没有与 TCP association 同生命周期的可靠清理；共享 NAT 下不能满足“公网 listener 的每个请求均已认证”边界。因此 API、profile、配置和 UI 都拒绝 `udp/ip` 与双网络 reservation；以后只有在核心/runtime 提供可验证的逐会话 UDP 认证，或另行批准仅回环/受信 LAN 产品边界后才能增加独立 UDP profile。
- `XRAY-MP-044` 3x-ui 不为 Mixed 生成订阅链接，ForwardX 同样不得把它放入普通订阅。管理员按需分享返回结构化 `MIXED_PROXY_ENDPOINTS`，包含同一账户和 endpoint 的 `socks5Uri` 与 `httpUri`；前者是常见客户端导入形式而不是 Xray 标准订阅。两项 URI 都必须 percent-encode userinfo，只存在于 `private, no-store` 响应和短生命周期 Dialog 内存；创建确认、详情和分享同时显示明文链路认证风险。

| profile | transport/security/spec v1 | 凭据 | listener | 分享 | 开放门槛 |
|---|---|---|---|---|---|
| `MIXED_RAW_NONE` | RAW / none / `{}`，固定 `auth=password`、`udp=false` | generic-only `MIXED_USER_PASSWORD`，服务端生成 username + password | TCP | `MIXED_PROXY_ENDPOINTS`：认证型 `socks5://` + `http://` | 052H SOCKS5/HTTP/CONNECT 正确与错误认证、无 SOCKS4/UDP、Agent 与泄漏验收 |

052H 已使用固定 SHA-256 对应的 Xray `v26.3.27` 完成生产生成器驱动的真实 Mixed 验收：同一端口和账户的 SOCKS5 TCP、HTTP 与 CONNECT 均可用，缺失/错误认证和 SOCKS4 均失败，且没有 UDP listener。持久化、Agent TCP readiness/last-good、secret-leak、生产构建和代表浏览器流程也已通过，因此 `MIXED_RAW_NONE` 已标记为 `AVAILABLE`。

### 3.14 回环固定目标 Tunnel 首版 profile

- `XRAY-MP-045` 首个 Tunnel 切片固定为 `TUNNEL_TCP_LOCAL_NONE`：Xray inbound `protocol=tunnel`、无独立传输层、`security=none`、`flow=NONE`、单 TCP listener。`specVersion=1` 只允许严格 `{ targetAddress, targetPort }`，地址必须规范化为 canonical IPv4/IPv6 literal 或小写 ASCII FQDN，端口为 `1..65535`；不得省略目标端口以借用监听端口语义。
- `XRAY-MP-046` 固定核心 `v26.3.27` 仍使用旧 Tunnel/Dokodemo 字段名，生产配置必须精确生成 `settings={ address, port, network:"tcp", followRedirect:false, userLevel:0 }`。不得依据较新在线文档输出 `rewriteAddress/rewritePort/allowedNetwork`；profile 不接受 `portMap`、`followRedirect`、TProxy、透明转发、UDP、sniffing、fallback、出站/路由选择或任意 Xray JSON。
- `XRAY-MP-047` Xray Tunnel 没有客户端认证模型，因此服务端必须把 `listenAddress` 与用于显示的 endpoint 都固定为 `127.0.0.1`，创建 API 不接受 `publicAddress/listenAddress`。任何持久记录或编译输入若把该 profile 绑定到 wildcard、LAN 或公网地址都必须在生成配置前拒绝；不得用 UI 警告替代这一拒绝。它只允许目标主机上的本地进程连接，不承诺公网或面板浏览器可直连。
- `XRAY-MP-048` Tunnel 不建立 client、generic access 或 inbound secret，不生成分享材料，也不进入订阅。创建合同必须显式要求空 `initialAccessEntries`，repository 只对该 profile 允许零账户；详情显示本地 listener、固定目标和“无客户端凭据（由回环边界隔离）”，不出现账户增删或分享入口。
- `XRAY-MP-049` Tunnel 流量只使用完整快照中固定的默认 `freedom` direct outbound；首版不提供“通过某节点转发”、自定义 outbound、路由规则或负载均衡。目标地址由管理员明确配置，面板不主动发起 DNS、HTTP 或端口探测；实际解析/连接只发生在受管 Xray 运行时。目标、listener 或 generation 变更继续走既有完整快照、配置预检、原子切换、expected TCP listener 和 last-good 回滚。

| profile | transport/security/spec v1 | 凭据 | listener | 分享 | 开放门槛 |
|---|---|---|---|---|---|
| `TUNNEL_TCP_LOCAL_NONE` | NONE / none / `{ targetAddress, targetPort }`，固定 direct TCP | `NONE`，零账户/零 secret | `127.0.0.1` TCP | `NONE`，无分享/订阅 | 052K 固定目标转发、非回环拒绝、Agent 与浏览器验收已通过 |

`TUNNEL_TCP_LOCAL_NONE` 已在 052K 完成真实证据并标记 `AVAILABLE`：固定核心证明通过 `127.0.0.1:<listenPort>` 可到达唯一配置目标、目标未监听时失败且同端口 UDP 未被占用；服务端、Agent、构建和浏览器代表流程同时通过。管理代理类 profile 不进入普通订阅聚合。

### 3.15 MTProto 独立服务首版

- `XRAY-MP-050` MTProto 不进入 `xray_inbounds` 或 Xray `configJson`。首版 kind 固定为 `MTPROTO_FAKE_TLS`，由 Agent 监管一服务一进程的 `mtg-multi v1.15.0` sidecar；只支持 `linux/amd64` 和 `linux/arm64`，制品从面板固定清单下载并在面板、Agent 两侧校验版本、大小、架构与 SHA-256。
- `XRAY-MP-051` 服务只接受名称、在线兼容主机、公开地址、TCP reservation、`0.0.0.0:<1000..65535>` listener、规范小写 FakeTLS FQDN 和账户显示名。每账户 secret 由服务端生成 `ee + 16 random bytes + domain UTF-8 hex`，使用独立稳定 account tag 绑定的 AEAD/HMAC context 加密；启用服务必须至少保留一个有效账户。
- `XRAY-MP-052` Agent 只用固定 binary、固定 `run <managed-config>` 和固定 `access --ipv4 192.0.2.1 <managed-config>`。子进程使用安装器维护的无登录 `forwardx-mtproto` UID/GID、无额外 Linux capability；配置目录和文件由 root 持有、专用组只读，sidecar 不得修改自己的期望配置。不得接受任意 shell、argv、path、service、TOML、环境变量或 mtg 管理 API。
- `XRAY-MP-053` MTProto 使用独立的每主机 generation/configHash 和完整 `managedServices` desired/observed。新快照必须整批预检、停旧、原子切换、确认受管 PID 的 TCP listener 后提交；失败整批恢复 last-good。相同 identity 幂等合并，最多保留一个较新 pending；意外退出只做三次有界退避重启。Agent 认证失败、面板不可达或 SSE 断开不得主动停止最后成功 sidecar，Agent 重启在面板认证前从本地 last-good 恢复。
- `XRAY-MP-054` 管理界面使用独立服务列表/创建/详情/账户 CRUD；分享只按需返回管理员可见的 `tg://proxy`、二维码和复制内容，并设置 `private, no-store`。普通 DTO、observed、日志、审计、operation、支持包和浏览器持久存储不得包含 secret、完整 URI、envelope、TOML、命令或路径。
- `XRAY-MP-055` MTProto 只有在跨语言合同、服务端事务与 secret、Agent 制品/supervisor/回滚/离线恢复、TypeScript、构建和一个代表浏览器流程全部通过后才从 `IMPLEMENTING` 改为 `AVAILABLE`。MTProto 门禁已通过；AmneziaWG 由 `XRAY-MP-056..063` 与 TASK054 独立门禁约束；只有 TUN 继续为 `NOT_IMPLEMENTED`，等待最小 `CAP_NET_ADMIN` 方案批准。

### 3.16 AmneziaWG userspace 独立服务首版

- `XRAY-MP-056` AmneziaWG 不进入 `xray_inbounds`、Xray `configJson` 或系统 WireGuard/TUN。kind 固定为 `AMNEZIAWG`，协议实现固定为官方 `github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814`，只支持 `linux/amd64` 与 `linux/arm64`。Agent 升级到该模块要求的 Go 1.25 基线；依赖和许可证必须固定并记录，不跟随 `latest`。
- `XRAY-MP-057` 一服务一 helper 子进程；可执行文件只能是当前受管 ForwardX Agent 自身，argv 只能是 Agent 定义的隐藏 helper 子命令和 Agent 推导的配置路径。子进程必须使用独立无登录 `forwardx-amneziawg` UID/GID，不继承 root，不请求 `CAP_NET_ADMIN`，不创建 OS TUN，不写 iptables/nftables、系统路由或网络接口，也不接受 shell、环境、path、argv、UAPI 或配置文本输入。
- `XRAY-MP-058` 首版固定单个 `0.0.0.0:<1000..65535>/udp` listener、IPv4 `10.8.1.0/24`、server `.1/24`、peer 从 `.2/32` 起按最低空闲分配、MTU 1420、DNS `1.1.1.1, 1.0.0.1`、客户端 `AllowedIPs=0.0.0.0/0` 与 keepalive 25。每服务最多 32 个 peer；不开放 IPv6、custom subnet/MTU/DNS/allowedIPs、external interface、forwarded ports、内核路由、Xray proxy chain、流量/到期/订阅或任意高级字段。
- `XRAY-MP-059` server/peer Curve25519 key、每 peer PSK 和 HeaderProtectionKey 只能由面板 CSPRNG 生成并以 service/account 稳定 tag 绑定的独立 AEAD/HMAC context 保存；Agent desired 只含运行必需的 server private key、peer public key/PSK/address 和严格混淆参数，绝不含 peer private key。普通 DTO、observed、日志、审计、operation、支持包和错误响应不得包含任何 key、PSK、完整配置或 `vpn://`。
- `XRAY-MP-060` 混淆参数由服务端生成一次并版本化持久化：固定支持 Jc/Jmin/Jmax、S1–S4、互不重叠 H1–H4、I1、HeaderProtectionKey、content padding、rekey/reject/keepalive/handshake ranges、RandomTrailers 与 DisableCookies；API/UI 不提供逐字段编辑或重新随机。服务端和 Agent 都必须重验范围、H 区间不重叠、`S1+56 != S2`、header protection 所需 `S1..S4 >= 12` 及 key 配对。
- `XRAY-MP-061` helper 在 gVisor userspace 栈中终止隧道并直接代理 TCP/UDP 到公网。所有目的地址在拨号前拒绝 loopback、link-local、multicast、unspecified、RFC1918、CGNAT、benchmark/documentation/metadata 等非公网范围、本机接口地址、该服务公开端点以及当前面板主机地址；不允许通过 VPN 访问 Agent、面板或宿主私网。本机地址与 deny hostname 的 IPv4 结果必须周期刷新；任一配置 deny hostname 暂时无法解析时，helper 保持运行但全部公网出口 fail closed，解析恢复后自动放行。面板 URL 变更必须先让 helper 以 transition policy 保留旧解析地址、解析并拒绝新面板且同步回执，Agent 才能切换 runtime URL；随后 stable policy 清理旧地址，任一回执失败都回退旧 URL/策略或保持 fail closed。每服务 TCP 并发、UDP flow 数量、队列、包长、空闲时间和拨号时间均有固定上限，错误只输出稳定脱敏类别。
- `XRAY-MP-062` AmneziaWG 与 MTProto 共用每主机 `managedServices` generation/configHash 完整快照，但按 kind 分别预检、启动和确认 listener。任一新服务失败必须整批恢复上一个 last-good；相同 identity 幂等，旧 Agent 缺少 AWG per-kind capability 时面板不得下发。Agent 失联、Token 无效或 SSE 断开不得停止最后成功 helper，Agent 重启在面板认证前恢复。
- `XRAY-MP-063` 分享只对在线兼容主机上的启用 peer 按需返回 `private, no-store` 的标准 `.conf` 与 `vpn://` + base64url-no-padding(`.conf`)；关闭/失败/下载后清除 React Query 和组件内存。创建 UI 只提交名称、主机、公开地址、UDP reservation 和 peer 显示名；详情只显示地址、配置状态和运行状态。TUN 继续为 `NOT_IMPLEMENTED`。
- `XRAY-MP-064` 当前 Xray 节点创建向导的协议卡片只展示 VLESS、Trojan、Shadowsocks、HTTP 和 Mixed。VMess、Hysteria 2、WireGuard 与 Tunnel 暂时仅从创建面板隐藏；服务端 profile catalog、创建/API 校验、配置生成、持久化和 Agent 能力不得删除，已有这些 profile 的节点仍可在列表和详情中正常管理。该可见性限制只属于前端产品入口，不得改写 profile 的 `AVAILABLE` 状态或把隐藏项误报为未实现。

### 3.9 出口节点与中转联动

- `XRAY-EGRESS-001` 出口节点是面板全局资源，第一版仅管理员可查询或修改。普通用户、普通规则列表、日志、审计摘要和 operation metadata 不得返回其凭据、原始导入链接或可还原凭据的完整配置。
- `XRAY-EGRESS-002` 首版导入只接受单条、最大 4096 UTF-8 字节的 `vless://`、`ss://` 或 `socks5://` 链接。服务端必须自行识别协议、严格校验、规范化并拆分公开设置与 secret；原始链接不得持久化。
- `XRAY-EGRESS-003` VLESS 仅接受 RAW/TCP + Reality + `xtls-rprx-vision`、合法 UUID、缺省或显式 `encryption=none`、规范 SNI、`fp=chrome|random`、X25519 公钥和合法 shortId；RAW authority 后的空路径与单个 `/` 视为等价且不进入公开定义，任何其他原始路径（包括会被 URL 解析器折叠的点段或编码点段）仍拒绝。解析、公开定义、Xray outbound 编译和按需原节点/中转链接必须保留输入指纹，不得静默改写；不接受 TLS、其他 transport、其他 flow、ECH、任意 header、未批准指纹或未知行为参数。
- `XRAY-EGRESS-004` Shadowsocks 接受 SIP002 的 AEAD/SS2022 单服务器链接，不接受 plugin、outline 参数或任意查询扩展；SOCKS5 接受无认证或用户名+密码认证的单服务器链接，不接受路径、查询或缺少一半的认证字段。方法和字段必须由版本化 allowlist 决定。
- `XRAY-EGRESS-005` UUID、shortId、Shadowsocks 密码、SOCKS5 用户名/密码使用资源稳定身份绑定的 AEAD secret envelope；普通列表/详情只返回协议、规范地址、端口、非敏感参数、凭据已配置状态和引用计数。
- `XRAY-EGRESS-006` 一个受管 Xray inbound 最多绑定一个出口节点。首版只允许监听网络为 TCP 且不是 `TUNNEL_TCP_LOCAL_NONE` 的 inbound 绑定；绑定、解绑与现有 Xray mutation 一样要求在线兼容主机、expected generation 和主机级写锁。
- `XRAY-EGRESS-007` 面板继续为主机生成完整确定性 Xray 配置快照。未绑定时配置字节保持既有 direct-only 行为；有绑定时按稳定 tag 去重生成类型化 outbound，并增加只按该 inbound `runtimeTag` 匹配的 routing rule。不得按端口匹配，不得接受任意路由 JSON。
- `XRAY-EGRESS-008` 被引用的出口节点缺失、密文损坏、字段不合法或固定核心不支持时，整次配置生成和 mutation 必须失败并保留 last-good，不得静默改走 `direct`。
- `XRAY-EGRESS-009` 添加或修改 Xray 出口绑定只下发该主机的完整新 generation/configHash；Agent 合同不增加增量 outbound 命令，也不回传出口凭据或完整配置。
- `XRAY-EGRESS-010` 出口节点可被现有 iptables、nftables、Realm、socat、GOST、Nginx 六种本地转发规则引用为目标。该模式只把规则运行时目标物化为出口节点的规范 `address:port`；六种方式均只做 TCP 原始字节转发，不解析 VLESS、Shadowsocks 或 SOCKS5 协议。iptables/nftables 沿用既有 Agent DNS 解析和目标变化重建路径，其余用户态运行时沿用既有目标地址处理。
- `XRAY-EGRESS-011` 引用出口节点的转发规则只允许 TCP 和上述六种本地转发方式；必须关闭向上游发送 PROXY Protocol 及其他会在代理握手前注入字节的选项。规则配置继续通过现有 Agent 期望配置下发，不新增代理凭据载荷；经过现有隧道或转发组时仍由既有最终出口执行路径连接同一物化 endpoint。
- `XRAY-EGRESS-012` 管理员可按需为引用出口节点的转发规则生成“中转链接”。生成器只把原节点链接的连接地址和端口替换为入口服务器的公网地址和规则监听端口，并保留原协议凭据、安全参数、SNI 和公钥；响应必须 `private, no-store`，材料不得写入 URL、缓存、日志或数据库。
- `XRAY-EGRESS-013` 外部出口定义不宣称“在线”。Xray 绑定的应用状态来自主机 generation/hash；六种本地转发规则的运行状态沿用现有规则状态；两者不得用一次 TCP 探测伪装成端到端代理可用性。
- `XRAY-EGRESS-014` 出口节点被任一 inbound 或转发规则引用时禁止删除；除显示名称外，协议、地址、端口或凭据更新也必须先解除全部引用。删除或更新失败不得修改引用方或 generation。
- `XRAY-EGRESS-015` 管理界面增加“出口节点”页，支持链接导入预览、列表、详情、引用统计和删除；Xray 节点详情可配置/解除出口并在列表与详情显示当前出口；规则表单可在“手动目标/出口节点”间切换，选中出口后锁定地址端口并显示协议约束，规则列表/详情显示引用名称。
- `XRAY-EGRESS-016` 页面联动必须以稳定资源 id 为身份。删除被引用资源显示精确引用入口；关闭导入或中转分享 Dialog 后清除原始链接和派生链接内存；切换目标类型时清除不兼容的隐藏字段，不能把旧地址、凭据或 PROXY Protocol 选项暗中提交。

- `XRAY-AC-011` 三种批准链接均能严格导入、无密文泄漏地查询；VLESS 至少覆盖 `chrome|random × 空路径|单个 / × 参数顺序变化` 的兼容矩阵，并逐层证明规范重建、加密持久化/加载和固定核心 outbound 编译保留指纹。重复参数、未知行为字段、非根路径、未批准指纹、非法方法、语法错误和超长输入继续拒绝。
- `XRAY-AC-012` 同一出口节点可分别完成 Xray inboundTag 路由绑定和 iptables、nftables、Realm、socat、GOST、Nginx TCP 原始转发；固定 Xray `v26.3.27` 配置测试通过，未绑定主机的旧配置字节/hash 不变。
- `XRAY-AC-013` 删除/更新引用完整性、主机 generation/hash、离线零写入、损坏密文 fail-closed、PROXY Protocol 禁止和 no-store 中转链接均有服务端目标测试。
- `XRAY-AC-014` 出口管理、Xray 节点绑定和规则目标选择在桌面/移动界面可完成，加载、空、错误、引用中、应用中和操作失败状态可解释，创建最终提交前可返回修改。

### 3.17 DNSPod 全局账号与出口快速配置

- `XRAY-QC-001` 快速配置只允许管理员使用。系统设置新增独立 DNS 服务商账户；首版 provider 固定为 DNSPod 且全局只允许一个启用账户，但账户、zone、line 和 secret 数据模型不得把“一个账号”编码成不可扩展的单例结构。
- `XRAY-QC-002` DNSPod `SecretId` 与 `SecretKey` 都按凭据处理，使用稳定账户身份绑定的版本化 AEAD envelope 保存；普通设置 DTO 只返回已配置/验证状态和掩码。既有 DDNS 的明文 `system_settings` 凭据不得成为快速配置的权威来源，也不得在迁移时静默复制后继续保留第二份明文。
- `XRAY-QC-003` DNSPod 客户端复用用户提供的 `~/dnspod_test` 已验证 TC3 行为作为只读参考，固定官方 endpoint/service/version、超时、有限重试、响应大小和稳定错误映射；域名、记录类型及运营商 line/lineId 必须从 API 动态获取并缓存，不硬编码套餐相关 lineId，不增加生产依赖。
- `XRAY-QC-004` DNSPod 账户保存前必须完成凭据验证和域名同步。未配置、验证失败、验证过期或没有可用 zone 时，Xray“快速配置”页签可见但不可创建，并给出系统设置入口。
- `XRAY-QC-005` 一个快速配置绑定一个既有落地资源：受管 Xray inbound，或 `VLESS_REALITY_VISION | SHADOWSOCKS | SOCKS5` 外部出口节点。首版继续只编排现有 TCP 原始转发能力，不把 L4 中转器描述为代理协议客户端。
- `XRAY-QC-006` 点击某落地资源“配置”后，向导第一步固定为域名。管理员从当前 DNSPod 账户的可用 zone 下拉选择主域名，只填写相对主机记录；允许 `dfd`、`hk.dfd` 等多级记录，不接受 `@`、通配符、URL、端口、路径或非法 DNS label。系统规范化并预览 FQDN，只有实时检查通过且管理员再次确认后才能继续；修改 zone/主机记录立即作废旧检查。
- `XRAY-QC-007` 同名检查覆盖面板快速配置归属和 DNSPod 远端记录。存在同名记录时只能“替换现有解析”或更换域名；替换 A/AAAA，CNAME 经明确提示后删除，TXT/MX/CAA 保留。检查只生成有时效的冲突快照，最终提交前必须再次读取；在最终确认前不得修改远端记录。
- `XRAY-QC-008` 电信、联通、移动、教育网分别选择一个或多个受管入口，身份精确到 `hostId + IPv4|IPv6`；主机没有有效地址或 Agent/运行时不兼容时禁选。同一 host 被多个线路或两个地址族引用时只创建一个实际监听规则，多条 DNS 记录引用它。
- `XRAY-QC-009` 对外端口未改写时，默认线路自动解析到落地节点经验证的 IPv4/IPv6，有两种地址就同时创建 A/AAAA。外部 endpoint 为 FQDN 时必须展示并确认本次解析出的公网地址；无法得到稳定公网地址时不能选择直接默认线路。
- `XRAY-QC-010` TASK057 的转发引擎固定为 Realm，不显示伪选择器；TASK058 才允许一次快速配置从 iptables、nftables、Realm、socat、GOST、Nginx 中统一选择一种，默认推荐 Realm。所选全部 host 必须共同支持该引擎和地址族，不允许同一快速配置按 host 混用引擎。
- `XRAY-QC-011` 面板增加持久化全局端口分配账本，端口号本身是唯一逻辑身份，不区分 TCP/UDP。一个分配可以由同一快速配置在多台入口 host 上建立绑定，也可以合法引用其目标 Xray inbound 已持有的原端口；无关联的节点、规则或配置不能取得同一端口。账本状态至少覆盖 `RESERVED/ACTIVE/RELEASING/PENDING_SCAN/FREE/EXTERNAL_OCCUPIED/LEGACY_CONFLICT`，创建必须先持久预留再下发，不能只依赖进程内 Map。
- `XRAY-QC-012` 所有新建或修改的 Xray inbound 端口在全部受管主机间全局唯一，且 TCP/UDP 不区分；创建、编辑、复制和批量路径必须共用同一事务化分配服务。历史重复端口只标记 `LEGACY_CONFLICT` 并阻止新引用，不自动停止或删除运行数据面；待管理员消除后收敛为普通分配。
- `XRAY-QC-013` 快速配置先尝试目标原端口，并先查全局账本、再对最终选中的 host 并行执行受限实际探测。受管 Xray 目标冲突时由管理员选择新的统一对外端口；外部目标冲突时系统推荐一个全局可用端口并等待确认。改写只改变入口监听和派生分享 endpoint，最终目标仍是原地址/原端口。
- `XRAY-QC-014` 端口确定后才计算默认线路。未改写端口时沿用 `XRAY-QC-009`；改写端口时管理员必须从兼容、在线且端口可用的受管 host/address family 中选择一个或多个默认入口。外部节点不得把改写后的端口直接解析到不可管理的原始 IP；受管 Xray 的落地主机只有在创建 `新端口 -> 本机原端口` 规则后才可成为默认入口。
- `XRAY-QC-015` 快速配置生成的每个唯一 `host + engine + listenPort + targetAddress + targetPort` 都必须是现有 `forward_rules` 中的正式规则并在普通规则列表/详情显示“快速配置”、FQDN、出口和线路引用。多线路复用一条规则；规则详情可查看/重试，任何会改变 DNS 拓扑的编辑、停用或删除必须进入快速配置编排并显示影响，不能产生隐藏运行时。
- `XRAY-QC-016` 创建、修改、切换引擎和删除使用持久多阶段 operation/saga：重新检查域名、预留端口、创建并确认全部规则、提交 DNS、验证并标记 ACTIVE。数据库事务不得伪装成能原子覆盖 DNSPod 与多个 Agent；部分失败必须保存脱敏阶段、执行补偿或进入可重试的 `PARTIAL_FAILURE`，不得显示成功。
- `XRAY-QC-017` DNS 记录必须保存 provider recordId、zone、FQDN、type、lineId、value 和快速配置归属。替换前保存有界快照用于同次 operation 补偿；修改/删除只操作自己管理或管理员明确选择替换的记录，不删除保留的 TXT/MX/CAA。
- `XRAY-QC-018` 删除规则只有在 Agent 确认运行时清理且没有 Xray/转发/快速配置引用后才把端口置为 `PENDING_SCAN`。每 12 小时运行一次不重叠的有界校准，只扫描没有有效规则和 Xray 引用的端口；在全部受管 host 上检查实际占用，任一占用则保持不可用，任一必要 host 离线或缺少所需探测能力也不得释放，全部确认空闲才置为 `FREE`。
- `XRAY-QC-019` 快速配置产生的 VLESS/SS 派生链接只替换连接地址和对外端口，保留批准的凭据、安全、SNI、公钥和指纹；SOCKS5 返回等价新 endpoint。分享继续使用 `private, no-store`，不把 URI、密码、UUID、shortId 或 DNSPod secret 写入数据库普通列、operation、日志、URL 或浏览器持久存储。
- `XRAY-QC-020` Agent 离线或能力不足时禁止新增、修改、删除涉及该 host 的快速配置；已经运行的 Xray 和转发数据面保持既有离线语义。DNS 不得在入口规则尚未确认运行时先切流。
- `XRAY-QC-021` 用户仍在现有向导中一次性确认默认线路与四类运营商线路；后台执行 DNSPod create/replace 时必须先完成并验证本 topology 的全部默认线路 A/AAAA，再处理电信、联通、移动和教育网记录。不得要求用户改变选择或提交顺序，也不得用前端数组顺序决定 provider 写入顺序。
- `XRAY-QC-022` DNSPod CreateRecord 返回成功或结果不明确后，新记录允许在最多 30 秒的有界窗口内暂时不可查询；worker 必须用相同 FQDN/type/动态 lineId/value/TTL 和 provider recordId 轮询对账，不能立即报告失败。RETRY 只有在前序同 quick config 的 DNS_CREATE step 已实际进入尝试状态、远端 tuple 完全一致且 recordId 无其他面板归属时才可接管该记录；缺任一证明继续按 `DNS_RECORD_DRIFT` fail closed。
- `XRAY-QC-023` 链路管理的“端口转发”主列表只展示真实 `port` 资源卡片，不追加规则级或主机级投影。快速配置创建的每条普通规则必须通过独立的 `portResourceGroupId` 归属一个同 owner、同 host、同 engine 的真实 `port` 资源：若恰有一个已启用候选则复用；若没有候选、候选不唯一或已存在同 identity 的系统资源则幂等使用/创建名称为“快速配置默认生成”的系统资源。该归属只服务资源目录与控制联动，不得复用 `forwardGroupId`、生成模板/子规则或改变 Agent desired。
- `XRAY-QC-024` `port` 资源的引用数必须等于未待删除的用户模板规则数加快速配置规则数。快速配置引用大于零时，服务端必须拒绝停用、删除或改变资源 identity/runtime 字段，界面至少禁用关闭开关并说明原因；名称等纯展示字段是否可改由接口显式限制。面板启动时必须幂等收敛历史未归属或 engine 已变化的快速配置规则，不能重建数据面或重复下发 Agent。
- `XRAY-QC-025` 受管 Xray 使用目标原端口时，其他入口主机的实际探测只能通过服务端内部派生的精确 `inboundId + port` target-alias 授权忽略该 inbound 自身的全局占用；授权在探测创建、Agent 任务派发和结果接受时都必须用单次一致性查询重新验证 ACTIVE allocation、稳定 runtimeTag、同主机公开 owning reference，不能由浏览器或 Agent 构造。快速配置重新检测或切换引擎时，可以提交上一轮服务端签名的 probe result token；服务端必须拒绝非规范编码，并先完整验证管理员、域名、目标和其中全部 host/network reservation，再一次性释放，任何错配不得部分释放。
- `XRAY-QC-026` 普通转发规则的新建表单在把源端口标记为“可用”前，必须同时通过套餐/主机范围、本机数据库监听、不区分 TCP/UDP 的全局端口账本，以及服务端派生的全部实际入口主机 Agent bind 探测。`both` 必须分别取得 TCP、UDP 结果；任一入口占用、离线、能力不足、失败、超时或过期都不得提交。编辑已有规则允许全局账本识别同一稳定 `FORWARD_RULE` owner，但不得对自身正在运行的 listener 做空闲 bind 探测。最终创建仍须事务化取得全局 allocation 并处理探测后的竞态。
- `XRAY-QC-027` 系统设置的 DNS 服务商页在账号卡片下增加管理员专用的“DNS 管理”。域名下拉来自当前已验证 DNSPod 账号的 zone 目录，记录列表实时从 DNSPod 读取，不在面板建立第二份通用 DNS 记录副本。第一版只允许创建、修改和删除 `A | AAAA | CNAME`，线路必须从当前 zone 的动态目录选择。选中 zone 被任一未删除快速配置、未清理托管 DNS 记录或活动编排引用时，仍可读取和刷新，但整个 zone 必须只读；服务端在每次写入前重新检查并返回稳定冲突错误，不得只依赖前端禁用。
- `XRAY-QC-028` ACTIVE 快速配置详情提供显式“同步配置”。同步以当前 active topology、对应 rule binding 和托管 DNS 行为唯一期望状态，通过持久 operation 先收敛正式 `forward_rules` 并确认 Agent 运行，再实时读取 DNSPod：缺失的托管 A/AAAA 记录补建，同一 locally-owned provider recordId 在同一相对域名下发生 type/line/value/TTL 漂移时恢复为期望 tuple，完全一致时只验证不写。额外的非托管记录不得删除；provider recordId 已移动到其他相对域名、同值记录无法证明属于本 operation，或出现重复/跨配置归属时必须 fail closed。同步部分失败保留已完成修复和当前 active topology，不回滚、删除既有可用规则或 DNS，并允许管理员再次同步。

- `XRAY-AC-015` 一个加密保存并验证通过的 DNSPod 账户可列出多个可用 zone 和动态线路；无账号、错误凭据和失效验证会禁用创建且不泄露 SecretId/SecretKey。
- `XRAY-AC-016` `dfd` 与 `hk.dfd` 能在所选 zone 下完成检查/确认；`@`、通配符和非法输入被拒绝。同名 A/AAAA/CNAME 必须显式确认替换，TXT/MX/CAA 保留，检查后竞态会在提交前被发现。
- `XRAY-AC-017` 四类运营商可各选多个 IPv4/IPv6入口；原端口可用时默认直达落地，端口改写时必须选择受管默认入口，所有 DNS A/AAAA/lineId 与规则引用可从详情追踪。
- `XRAY-AC-018` 全局端口账本在并发、删除、重试、历史冲突和面板重启后保持唯一；新 Xray 端口跨 host、跨 TCP/UDP 均不能重复，孤立端口只有 12 小时校准确认全部 host 空闲后才回收。
- `XRAY-AC-019` 多 zone 账号可在 DNS 管理中通过下拉切换，每个 zone 能列出 DNSPod 实时记录并对未占用 zone 完成 A/AAAA/CNAME 增改删；已占用 zone 仍可查看，但前端写按钮禁用且任意直接 API 写请求均被服务端拒绝。
- `XRAY-AC-019` TASK057 的 Realm 规则全部出现在普通转发规则列表且多线路不重复监听；创建/修改/删除的 Agent、DNS 与端口部分失败可解释、可补偿、可重试。
- `XRAY-AC-020` TASK058 的六种引擎都复用同一快速配置、端口和 DNS 合同；只显示全部所选 host 共同支持的引擎，切换失败恢复旧引擎且不提前修改 DNS。
- `XRAY-AC-021` 同一 preview 同时包含默认及运营商记录时，create/edit/retry 的 provider 写入均先完成默认线路，运营商记录随后执行；preview 内容、用户步骤和最终拓扑保持不变。
- `XRAY-AC-022` provider 新建成功但记录短时不可见时，operation 在有界窗口内完成对账并保存 recordId；进程/网络在保存前中断后，新 RETRY 可以且只能凭前序写 intent 接管唯一精确匹配记录，不重复创建、不误接管第三方记录。
- `XRAY-AC-023` 服务器 A 只有一个符合条件的 `port` 资源 `dfaf`，且一条用户模板规则和一条快速配置规则使用 A 时，`dfaf` 显示引用数 2，关闭开关不可用；服务器 B 没有符合条件的资源而存在快速配置规则时，同一列表出现真实的“快速配置默认生成”资源卡片，不显示“实际规则”主机汇总项或下方明细区。
- `XRAY-AC-024` 历史规则收敛、创建、编辑新增 host、失败重试和 engine 切换后，每条活动快速配置规则都归属正确端口资源；重复启动/重试不重复创建系统资源，待删除规则不再计数，任何锁定绕过都由服务端拒绝。
- `XRAY-AC-025` 已运行的受管 Xray 原端口可在其他入口主机完成 TCP/UDP 快速配置探测并生成 `TARGET_ALIAS`；切换引擎或立即重检不会撞到同一向导上一轮预留，而其他 Xray、规则、隧道、受管服务、跨管理员 token 和探测期间 owner 变化仍被拒绝。
- `XRAY-AC-026` 普通端口转发的新建表单对直连主机和转发组的完整入口集合执行真实单端口探测；跨主机全局占用、任一实际 bind 占用和删减/篡改检查身份都不会显示绿色，随机候选也不能绕过同一门禁。
- `XRAY-AC-027` ACTIVE 快速配置点击“同步配置”后，正确规则和 DNS 不产生 provider 写；缺失规则会作为正式规则恢复并等待 Agent running，缺失托管记录会补建，同一已归属 recordId 的同名 tuple 漂移会恢复。同步不接管或删除第三方同名记录，失败后 active topology 与已运行数据面仍保留，operation 展示具体失败步骤并可再次同步。

| kind | runtime/version | listener | 分享 | 开放门槛 |
|---|---|---|---|---|
| `AMNEZIAWG` | 低权限 Agent helper / `amneziawg-go v3.1.20260814` | 单 UDP | `.conf` + `vpn://` | `AVAILABLE`；054F 合同、三数据库、helper TCP/UDP、公网阻断、last-good、泄漏、构建和浏览器验收已通过 |

## 4. 技术栈和代码位置

- 面板：TypeScript、Express、tRPC、Zod、Drizzle ORM。
- 前端：React、React Query、wouter、现有 UI 组件和 Tailwind。
- Agent：Go，沿用现有心跳、SSE、任务队列、状态持久化和进程管理模式。
- 数据库：SQLite、MySQL、PostgreSQL。
- Xray：固定并经过制品清单验证的 Xray-core 版本。
- 参考实现：`3x-ui/` 只用于理解 Xray 安装、配置、Reality 扫描和统计方式；直接复用代码前必须核对 GPLv3 与本项目 AGPLv3 的许可及通知要求。

预期新增代码区域在实施计划中确定，合同类型优先放在 `shared/`，服务端模块放在 `server/`，页面放在 `client/src/`，Agent 运行时放在 `agent/`。

## 5. 常用命令

```bash
# 面板开发
pnpm dev

# TypeScript、构建和服务端测试
pnpm exec tsc --noEmit
pnpm build
pnpm test:server

# Agent 测试
(cd agent && go test ./...)

# 文档构建
pnpm docs:build
```

新增测试应尽量提供可单独运行的命令，并在 `tasks/todo.md` 中记录。

## 6. 代码和接口风格

- tRPC 输入在路由边界用 Zod 校验，内部服务使用已经验证的类型。
- 使用明确的判别联合描述任务和状态，不使用随意的 `Record<string, any>` 作为长期协议。
- 协议枚举值使用稳定的大写名称，例如 `PORT_PROBE`、`RUNNING`、`CONFIG_INVALID`。
- API 输入、数据库记录和输出 DTO 分离；敏感数据库字段不进入列表 DTO。
- 新能力通过 `schemaVersion` 和 capability 进行可选扩展，不改变已发布字段的类型或含义。

## 7. 测试策略

- 共享类型、配置规范化、配置哈希、端口选择和密钥封装使用单元测试。
- 数据库 schema 和 repository 使用 SQLite 集成测试，并验证三数据库 schema 描述一致。
- Agent 安装、配置校验、服务恢复、Token 错误和结果持久化使用 Go 测试与可替换命令执行器。
- 面板与 Agent 的 desired/observed state 使用合同测试。
- 创建节点、多客户端、升级和失败回滚使用服务端集成测试。
- 前端验证加载、空、错误、离线禁用和异步状态；完成后用真实浏览器做管理员主流程测试。
- 详细矩阵见 `TEST_PLAN.md`。

## 8. 边界

### 始终执行

- 保持现有转发、隧道、插件、Agent 安装和心跳行为兼容。
- 所有管理员输入在边界验证并设置长度、数量、端口和超时上限。
- 私钥、UUID 和任务载荷按 `SECURITY.md` 处理。
- 变更协议、数据库或运行生命周期时同步文档和测试。

### 实现前确认

- 改变本文已批准的多协议范围或兼容矩阵。
- 改变 Agent 离线时现有 Xray 的持续运行策略。
- 增加新的生产依赖、外部服务或文件上传接口。
- 修改认证、Agent Token，或超出 `SECURITY.md` 已批准主密钥包装方案改变其他数据库备份语义。
- 从 3x-ui 直接复制而不是独立实现代码。
- 增加 TLS 私钥上传/托管、TUN 特权、MTProto/AmneziaWG 独立进程或新的生产依赖时，必须先完成对应安全设计并取得明确确认。

### 禁止

- 把私钥、UUID、Agent Token 写入日志或普通接口响应。
- 对用户输入的地址执行未受 SSRF 保护的扫描。
- 通过拼接用户输入生成 Shell 命令。
- 未验证二进制哈希就安装或升级。
- 配置验证失败后覆盖当前可用配置。
- 因面板或 Agent 鉴权故障自动停止已有 Xray。

## 9. 第一版完成标准

- `XRAY-AC-001` 在线兼容主机可以完成自动端口探测、按需安装、单 inbound 创建和运行确认。
- `XRAY-AC-002` 同一 inbound 至少可创建、启停和删除三个客户端，其他客户端不受单个客户端变更影响。
- `XRAY-AC-003` 每个客户端可生成语义正确的 VLESS Reality URI 和二维码，URI 不包含服务端私钥。
- `XRAY-AC-004` Agent 重连后 desired/observed generation/hash 收敛，重复下发不重复破坏运行时。
- `XRAY-AC-005` Token 错误和面板离线期间，最后一次成功的 Xray 配置继续工作。
- `XRAY-AC-006` 无效配置、端口冲突和升级失败不会破坏最后一次成功运行环境，并在面板显示脱敏原因。
- `XRAY-AC-007` Reality 扫描只能访问允许的公网目标并返回结构化结果。
- `XRAY-AC-008` Xray 页面、接口和密钥材料仅管理员可访问，普通用户不存在可绕过入口。
- `XRAY-AC-009` TypeScript 构建、Agent 测试、服务端相关测试和文档构建通过。
- `XRAY-AC-010` SQLite、MySQL、PostgreSQL 的新增表、列、默认值、唯一约束和索引语义一致。

## 10. 已关闭问题

- `XRAY-OPEN-001..007` 已全部关闭，结果记录在 `XRAY-ADR-014..023`。
- 面板主密钥生命周期按 `SECURITY.md` 执行。
- 第一版没有阻塞业务代码实施的产品或架构开放问题；实现中若发现规格冲突，必须先新增 ADR，不能自行扩大范围。
- 多协议架构、排除的运营功能、固定 `v26.3.27` 和分阶段实施顺序由用户确认，记录为 `XRAY-ADR-043..045`。
