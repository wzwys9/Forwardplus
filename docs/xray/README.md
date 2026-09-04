# ForwardX Xray 二次开发文档

状态：第一版、Xray-native 多协议、MTProto、AmneziaWG userspace、出口节点与六种本地转发联动已完成；DNSPod 快速配置与六引擎创建/切换主流程已实现、集中验证待补；TUN 仍待单独特权设计
规格版本：0.26
最后更新：2026-09-05

本目录定义 ForwardX 集成受管 Xray 的第一版需求和工程契约。任何实现工作都应先以这里的文档为准，不再依赖聊天上下文猜测需求。

## 阅读顺序

1. `SPEC.md`：第一版范围和验收标准。
2. `DECISIONS.md`：已确认和已废弃的关键决定。
3. `ARCHITECTURE.md`：控制面、Agent 和 Xray 数据面的职责。
4. `DATA_MODEL.md`：面板数据库模型。
5. `AGENT_PROTOCOL.md`：desired/observed state 与异步任务格式。
6. `RUNTIME_LIFECYCLE.md`：安装、启动、升级、回滚和故障行为。
7. `API_CONTRACT.md`：管理员 tRPC 接口。
8. `UI_DESIGN.md`：页面、创建流程和状态展示。
9. `SECURITY.md`：密钥、制品、扫描和权限边界。
10. `TEST_PLAN.md`：单元、集成、端到端和故障测试。
11. `../../tasks/plan.md`、`../../tasks/todo.md`：实施顺序和可执行任务。

## 第一版摘要

- 管理员在面板上为在线子 Agent 创建 VLESS + Reality 节点。
- 一个 inbound 可以包含多个独立客户端。
- 每个 inbound 使用独立 Reality 密钥对，面板保存加密后的私钥。
- 默认自动端口范围为 `1000–65535`，面板记录与 Agent 实际 bind 探测共同判定可用性。
- 普通转发规则的新建表单也使用同一全局账本与 Agent bind 探测；任一实际入口主机未确认空闲时不得显示“可用”或提交。
- Xray 按需从面板下载安装，使用 ForwardX 专属路径，支持有提示的手动升级。
- Xray 由 Agent 直接作为 OS 子进程监管；当前固定 `v26.3.27`，自动识别 `linux-amd64`/`linux-arm64`。
- Agent 执行 Reality 目标扫描、配置验证和运行状态检查。
- 第一版仅管理员可见，不做流量统计和防火墙管理。

## 多协议扩展摘要

- 保持面板数据库为唯一配置权威；面板始终分别控制每台 Agent，Agent 之间不建立控制关系。
- 面板按主机从数据库重新生成完整 Xray 配置快照，不从 Agent 拉取配置做双向合并。
- 按类型化 profile 逐步增加 VLESS、Trojan、VMess、Shadowsocks、Hysteria 2 和 WireGuard；认证型 HTTP、Mixed 管理代理与 `TUNNEL_TCP_LOCAL_NONE` 均已完成固定核心、安全和浏览器验收并开放。Tunnel 固定回环 TCP 与唯一目标，不开放公网、透明代理、路由或任意 JSON。
- MTProto 已作为独立 `managedServices` sidecar 完成合同、面板、Agent、安全与真实运行验收；AmneziaWG 已作为不需要 `CAP_NET_ADMIN` 的 userspace 低权限 helper 完成 `XRAY-TASK-054` 验收；两者均不伪装成普通 Xray inbound。TUN 仍等待单独特权方案。
- 本阶段不实现流量限额、到期时间、订阅、fallback、sniffing、任意路由或负载均衡，也不开放任意 Xray JSON；TASK055 只开放按 inboundTag 精确绑定一个类型化外部出口。
- TASK055 增加全局 VLESS Reality Vision、Shadowsocks、SOCKS5 出口节点；TASK056 将公开 endpoint 的 TCP 原始中转目标扩展到 iptables、nftables、Realm、socat、GOST、Nginx 六种本地转发方式。
- TASK057 已增加一个可扩展但首版单账号的全局 DNSPod 账户、运营商线路快速配置、持久化全局端口分配和可恢复编排；TASK058 已在同一快速配置内统一选择六种现有本地转发方式之一，并支持保持域名、端口和落地不变的引擎切换。
- 外部 VLESS 导入兼容 `fp=chrome|random`，RAW authority 后的空路径与单个 `/` 视为等价输入；保存、编译与重新分享都保留原指纹，其他路径和未批准指纹继续拒绝。
- 默认 Xray-core 继续固定为 `v26.3.27`；每个 profile 必须通过该版本的确定性配置测试和真实运行/客户端连接验证后才能在界面开放；mKCP 按 UDP listener 处理，必须等待 Agent v2 UDP capability 完成。
- `XRAY-TASK-038..039` 只完成 profile 目录和入站存储底座，不代表多协议已交付；3x-ui 对照目标、完成定义和实施顺序以 `SPEC.md` 3.8、`tasks/plan.md` 5.1 及 `tasks/todo.md` 阶段 6–10 为准。
- VMess/Shadowsocks 首个兼容切片固定为 `VMESS_RAW_TLS` 与 `SHADOWSOCKS_2022_RAW_NONE`；固定核心对两种协议都会输出 deprecated 警告，因此只用于兼容现有客户端，不取代 VLESS/Trojan 推荐项。
- TASK049 UDP 基础设施已完成：Agent capability/bind/procfs readiness 与面板 operation/reservation 均使用明确的 `host + network + port` 身份；mKCP、Hysteria 2、Shadowsocks TCP+UDP 与 WireGuard 均已完成固定核心真实连接和 Agent 收敛验收并开放。

## 决定状态

第一版产品、运行时、密钥、版本和架构问题均已确认，详见 `DECISIONS.md`。`XRAY-TASK-001..056` 已完成；`XRAY-TASK-057..058` 的可体验主流程已实现，真实 DNSPod、六引擎运行、故障恢复和浏览器矩阵仍保留在集中检查点；MTProto 与 AmneziaWG 均已开放，TUN 保持未实现，记录见 `../../tasks/todo.md`、`../../tasks/handoff.md` 与 `TEST_PLAN.md`。
