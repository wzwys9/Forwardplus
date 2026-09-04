# Xray 面板设计

状态：第一版界面已实施；多协议创建流程已批准并按 profile 垂直切片增量开放；DNSPod + Realm 快速配置界面已批准。与 `SPEC.md` 0.24 配套。

## 1. 导航

主机列表和升级确认始终显示 Agent 上报的真实版本，并在旁边显示发行来源：`Forwardplus`、`ForwardX` 或“来源未确认”。来源不是 Forwardplus 时显示“待切换到 Forwardplus”，即使版本号高于当前目标也不能显示为最新；升级进行中只有在后续心跳同时报告 `forwardplus` 和满足目标的真实版本后才结束。

管理员侧边栏主功能区增加：

```text
仪表盘
主机管理
链路管理
转发规则
Xray 节点
```

- 路由建议 `/xray`。
- 使用 admin route，普通用户既不显示菜单也不能访问路由。
- 管理员 Xray UI 受 `FORWARDX_XRAY_ENABLED` 控制并默认开启。`FORWARDPLUS_XRAY_UI_POLICY_VERSION=1` 表示部署已经完成默认开启策略迁移；标记缺失的历史部署在首次启动和安装器升级时都按开启处理，不依赖早期迁移是否留下 `FORWARDPLUS_MIGRATE_AGENTS`。
- 当前策略下，`FORWARDX_XRAY_ENABLED` 的 `1`、`true`、`on`（忽略大小写和首尾空白）表示开启，其他字符串值表示管理员显式关闭；字段缺失仍默认开启。策略标记写入前的历史 `0` 无法证明是管理员设置，会在一次性迁移中改为 `1`。公共设置查询失败仍保持关闭。
- `system.publicInfo.xrayEnabled` 只公开上述布尔结果，侧边栏和 `/xray` 路由共用该结果；开关不替代后端各 Xray procedure 的管理员鉴权。

## 2. 页面结构

```text
┌────────────────────────────────────────────────────────────┐
│ Xray 节点                                  [＋ 创建节点]    │
│ [节点管理] [运行环境]                                      │
├────────────────────────────────────────────────────────────┤
│ 搜索  主机  状态  协议                         [刷新]       │
├────────────────────────────────────────────────────────────┤
│ 节点名称 │ 主机 │ 公网地址 │ 客户端 │ 状态 │ 更新时间 │操作│
└────────────────────────────────────────────────────────────┘
```

不要新增脱离项目设计系统的渐变、超大卡片或独立配色。状态使用现有语义 token、图标和文字，不只依赖颜色。

## 3. 节点管理

桌面表格列：

- 节点名称。
- 所属主机和 Agent 在线状态。
- 公网地址与端口。
- 协议/安全：`VLESS · Reality`。
- 客户端数量。
- 部署状态。
- 最后同步/更新时间。
- 操作菜单。

操作：

- 查看详情。
- 管理客户端。
- 复制客户端分享链接（一个客户端时可以快捷展示；多个时进入客户端列表）。
- 编辑节点。
- 启用/停用。
- 重新同步。
- 删除。

Xray 服务重启属于主机级操作，不放在单个 inbound 操作中。

移动端使用信息密度较高的纵向列表/卡片，不强制横向滚动所有列。主要操作保持可触达，次要操作放入菜单。

## 4. 状态展示

| 状态 | 文案 | 行为 |
|---|---|---|
| `WAITING_SYNC` | 待同步 | 可查看 operation |
| `INSTALLING` | 正在安装 Xray | 显示阶段，不允许重复安装 |
| `APPLYING` | 正在应用 | 显示 generation 和阶段 |
| `RUNNING` | 运行中 | 分享操作可用 |
| `DISABLED` | 已停用 | 允许只读查看当前分享材料，并提示远端旧配置仍可能有效；写操作禁用 |
| `PENDING_DELETE` | 待删除 | 说明旧配置可能仍有效 |
| `ERROR` | 应用失败 | 展示脱敏原因和重试入口 |
| `HOST_OFFLINE` | Agent 离线 | 不声称 Xray 已停止；显示“运行状态未知” |
| `UNKNOWN` | 状态未知 | 提供刷新/诊断入口 |

“Agent 离线”和“Xray 已停止”必须分开。Agent 离线期间最后一次 observed state 可以作为历史信息展示，但需要标注报告时间。

Agent 离线或心跳过期时，节点、客户端和运行环境的全部写按钮禁用，包括编辑、启停、删除、同步、扫描、端口探测、安装、升级和重启。只读详情和已有分享材料可以查看，但必须提示无法确认远端当前状态；后端仍需独立拒绝写请求。

删除节点必须输入当前节点名精确确认，并说明它会先进入待删除、应用完成前旧节点和分享凭据可能继续有效。删除最后一个节点时还要说明受管 Xray 会停止但二进制保留。删除主机的确认文案必须区分面板记录清理和远端卸载：删除面板记录不会下发停止命令，Agent 离线或未先显式卸载时远端 Xray 可能继续运行。

## 5. 创建节点流程

使用宽 Dialog 或与现有页面一致的分步对话框。移动端占满可用宽度。分四步：

创建配置和部署进度 Dialog 不得因点击遮罩自动关闭，避免未提交草稿或当前进度被意外隐藏；管理员仍可使用右上角关闭按钮等明确操作退出。

### 步骤一：主机和基本信息

字段：

- 节点名称。
- 所属主机。
- 公网地址，默认取 Agent IPv4，可由管理员确认/修改。

主机选项保留离线/不兼容主机并灰显：

```text
香港-01     可用 · Xray v26.3.27
日本-02     Agent 离线，无法检测端口或部署
美国-01     Agent 版本过低，请先升级 Agent
新加坡-01   缺少 linux-arm64 Xray 制品
```

禁用选项必须有可见原因，不能只有 tooltip。提交时若主机变离线，保留表单内容并显示 `HOST_OFFLINE`，不生成半成品节点。

### 步骤二：端口和 Reality

端口：

- 默认“自动分配”。
- 固定提示范围 `1000–65535`。
- 可切换“手动端口”，仍必须实时探测。
- 显示“等待检测/检测中/可用/已占用/预留过期”。
- 已取得预留后点击“重新探测”时，先捕获当前主/次 reservation ID 并由同一次新请求受控替换；不能先清空浏览器状态再发起一个与旧预留无关的请求。TCP+UDP profile 必须同时交回两项，避免新 TCP 成功后被遗留 UDP 预留误报占用。

Reality：

- “扫描目标站点”触发目标 Agent 扫描。
- “默认候选”使用版本化 `v2` 的 9 个公网域名，不展示已知会导致 Reality 校验失败的 `www.microsoft.com`；实际可选项仍以本次目标 Agent 扫描结果为准。
- 结果表显示目标、serverName、TLS 1.3、H2、X25519、证书、延迟和失败原因。
- 只允许选择 feasible 项作为默认；手工输入仍需验证并遵守安全策略。
- 面板自动生成密钥，页面只显示公钥和“私钥已安全生成”，不显示私钥。

### 步骤三：初始客户端

- 至少一个客户端，允许一次添加多个。
- 字段只有名称和第一版固定/default flow。
- UUID、shortId、statsKey 由服务端生成，表单不要求管理员手工输入。
- 名称重复、数量上限和长度在前后端同时提示。

### 步骤四：确认并部署

摘要至少包含：

- 节点、主机、公网 endpoint。
- 协议和 Reality 目标/serverName。
- 客户端数量。
- 当前/目标 Xray 版本。
- 未安装时提示“部署将先安装受管 Xray”。

按钮：在线且校验完成时显示“创建并部署”。离线主机不能进入可提交状态。提交后关闭或切换为非阻塞 operation 进度，不让用户在一个长 HTTP 请求中等待。

## 6. Operation 进度

用真实阶段展示：

```text
检测端口 ✓
下载并验证 Xray ✓
验证配置 ✓
切换配置 …
检查监听器
```

- 页面刷新后通过持久 operation 恢复进度。
- 终态成功跳转节点详情或刷新列表。
- 失败保留具体阶段、错误码对应中文说明、重试和查看运行环境入口。
- 不展示原始 Shell、私钥或完整 config。

## 7. 节点详情

使用 Tabs：

### 概览

- endpoint、协议、安全、主机。
- desired/applied generation 与同步状态。
- Reality 目标、serverName、公钥。
- 最后 Agent 报告时间和 listener 状态。

### 客户端

| 名称 | UUID 掩码 | shortId 掩码 | Flow | 状态 | 操作 |
|---|---|---|---|---|---|

操作包括：复制 VLESS URI、显示二维码、编辑名称、启停、删除。分享 Dialog 关闭后清除内存中的 URI；响应 no-store。

### Reality

- 目标、serverName、TLS 探测摘要、公钥。
- 重新扫描。
- 重新生成密钥属于危险操作，需要解释所有现有链接将失效，并等待新 generation 应用后才显示完成。
- 第一版如未实现密钥轮换，不显示占位按钮。

### 运行状态

- 主机、受管 Xray 版本、PID/服务状态。
- desired/applied generation/hash 前缀。
- 受管 listener。
- 最后脱敏错误。

### 操作记录

- 分页显示与该 inbound 相关的 operation、阶段、耗时和结果。

删除请求受理后立即关闭确认框和节点详情，清除 URL 的 `inboundId` 并刷新节点列表；列表可继续展示尚未收敛的待删除状态。不得在成功回调中重新查询该节点详情，因为 Agent 可能已完成新 generation 并物理清理记录，此时正常的 `NOT_FOUND` 不能显示为删除失败。

## 8. 运行环境页签

一行代表一个子 Agent，而不是 inbound：

| 主机 | Agent | 已装版本 | 目标版本 | Xray 状态 | 节点数 | 配置 | 操作 |
|---|---|---|---|---|---:|---|---|

操作：

- 安装。
- 升级。
- 重启受管 Xray。
- 重新同步配置。
- 查看错误/operation。

安装、升级、重启和重新同步都先打开危险确认 Dialog，并要求逐字输入主机名；关闭后焦点返回触发按钮。操作创建后把 operationId 和运行环境作用域保存在 URL，刷新页面继续从数据库轮询真实进度。已有活动运行时 operation 时只显示“查看进度”，不允许并发写。普通同步文案必须明确不会安装新版本或降级。

版本状态：

- 未安装。
- 当前版本。
- 可升级。
- Agent 版本高于目标，显示“不自动降级”。
- 架构缺少制品。

顶部显示面板默认版本和已验证的 os/arch 制品矩阵。

## 9. 主机页面集成

主机卡片只增加简要状态，例如：

```text
Xray：v26.3.27 · 运行中 · 4 个节点
```

点击跳转 `/xray?tab=runtime&hostId=<id>`。不要在主机页复制完整节点/客户端管理逻辑。

## 10. 可访问性和交互质量

- 每个 input 有可见 label；错误用 `aria-describedby` 关联。
- Dialog 打开管理焦点，关闭回到触发按钮；危险确认可键盘操作。
- 状态 badge 同时包含文字/图标，不只用红绿颜色。
- 异步区域使用 `aria-live` 有节制地宣布阶段变化。
- 表格有空、加载 skeleton、错误和重试状态。
- 在 320、768、1024、1440 宽度验证。
- 尊重 reduced motion；不为 operation 进度添加持续干扰动画。

## 11. 文案原则

- 使用“Agent 离线，Xray 运行状态未知”，不用“节点已停止”。
- 使用“已在本机监听”，不用“公网一定可用”。
- 删除客户端时说明“应用完成前旧链接可能继续有效”。
- 端口探测说明结果是短期事实，最终绑定仍可能冲突。
- 错误面向管理员给出下一步，不展示堆栈和内部路径。

## 12. 多协议创建流程

多协议阶段把现有四步 Dialog 演进为 profile 驱动的宽 Dialog。信息架构借鉴 3X-UI 创建入站时的分区方式，但保留 ForwardX 的服务端 profile 权威和部署状态机。顶部固定为七个分区：

1. `基础配置`：主机、节点名称和公网地址。
2. `协议`：先按 catalog 的可用 profile 判定，再应用当前产品可见性列表；只显示 VLESS、Trojan、Shadowsocks、HTTP 和 Mixed。VMess、Hysteria 2、WireGuard 与 Tunnel 暂时不提供新建入口，但已有节点仍在列表和详情中正常显示和管理。
3. `传输`：从当前协议的可用 profile 派生 RAW/gRPC/XHTTP 等选择，并仅显示对应严格字段。
4. `端口`：只在协议与传输已确定一个 profile 后可用；按 `listenerNetworks` 直接探测 TCP、UDP 或同端口 TCP+UDP。Hysteria 2 直接进入 UDP 探测，不先创建 TCP 探测。
5. `安全`：从当前协议+传输的可用 profile 派生；Reality 显示目标扫描，TLS 显示受管证书选择，none 不显示伪安全字段。
6. `账户`：协议专属账户/peer 名称；UUID、password、auth、key 等仍由服务端生成或按严格表单处理。
7. `确认`：完整摘要、目标核心版本和部署 operation。

分区允许返回已完成步骤；依赖未满足的后续分区禁用并显示原因。协议/传输/安全切换必须通过 catalog 选择一个确定 profile，清除不属于该 profile 的 `serviceName/path/serverName/certificateId/flow` 等字段；不得保留不可见旧值。若返回更改 profile 导致 listener network 变化，旧端口结果失效，但界面留在当前协议/传输分区；管理员主动进入端口分区后再按新网络检测。界面不提供高级 JSON、嗅探、fallback 或路由。Vision 只在兼容 profile 中出现；协议变更不在编辑页原地转换，使用“创建替代节点”操作。

当前已开放 `VLESS_RAW_REALITY_VISION`、`VLESS_GRPC_REALITY`、`VLESS_XHTTP_REALITY` 与 `TROJAN_RAW_REALITY`。选择 gRPC 时只增加严格 `serviceName` 输入；选择 XHTTP 时只增加严格 `path` 输入并说明固定 auto、无高级字段；选择 Trojan 时不显示 password、shortId 或 flow 输入。Trojan 详情只展示 generic-only 账户及凭据“已配置（隐藏）”状态，CRUD/分享使用 generic access id；现有 Reality VLESS 仍使用旧客户端 id。

TLS profile 逐项开放后，安全分区要求先选主机级证书，再从其 DNS SAN 中选择或输入匹配的 `serverName`；界面不接受 IP、通配符 SNI、证书路径或关闭校验。VLESS RAW 同时显示“标准 TLS”和“Vision”两个服务端 profile 选项，不使用反向含义的“禁用 flow”开关；其他 TLS 传输不显示 flow。WebSocket/HTTPUpgrade/XHTTP 只显示严格 path，gRPC 只显示 serviceName，mKCP 在 Agent UDP capability 完成前不出现在可创建项，若查看 catalog 诊断则显示“需要升级 Agent 以支持 UDP 监听确认”。

TLS VLESS 也使用 generic access id 管理账户，详情不显示 UUID；分享 Dialog 可以在内存中展示带证书 pin 的 URI。Dialog 应说明该 URI 不使用 `allowInsecure`，关闭时沿用现有清理；证书轮换确认必须明确“新配置应用后，现有 TLS 分享链接的证书 pin 将失效，需要重新分享给客户端”。

Shadowsocks 在当前协议卡片、确认摘要和详情中显示“兼容协议，固定 Xray 核心已标记 deprecated；新节点优先使用 VLESS/Trojan”，并且不作为打开 Dialog 时的默认 profile。VMess 当前不显示创建卡片，但已有节点的摘要和详情仍保留同一告警；以后恢复创建入口时也必须显示。告警来自 catalog `advisoryCode=CORE_DEPRECATED`，前端不通过 profile id 自行猜测。

`VMESS_RAW_TLS` 只显示 RAW 和受管 TLS 证书/SNI，账户分区只填名称；确认页显示“VMess AEAD · AUTO”，不显示 `alterId/aid`、密码算法、flow 或明文 UUID 输入。`SHADOWSOCKS_2022_RAW_NONE` 只显示 RAW/TCP、固定 `2022-blake3-aes-256-gcm` 和“协议层加密（无 TLS/Reality）”，不显示 method 下拉、服务端 PSK 或用户 PSK 输入。尝试停用/删除最后一个有效 Shadowsocks 账户时显示“启用中的 Shadowsocks 2022 节点至少需要一个账户；请先停用节点”。

`HYSTERIA2_TLS` 只在所选主机同时支持 UDP 探测和 UDP 监听确认时可创建；否则 catalog 诊断显示“需要升级 Agent 以支持 UDP”，且不提供可绕过入口。选择后协议/传输/安全固定显示为“Hysteria 2 / Hysteria / TLS”，监听网络显示 UDP，并复用同主机证书和 SNI 选择；账户分区只输入名称，auth 不在浏览器生成、输入或显示。

Hysteria 2 传输区只展示只读摘要“版本 2 · ALPN h3 · UDP 空闲 60 秒”，不提供带宽、拥塞、跳端口、masquerade、obfs、FinalMask/ECH 或高级 JSON 控件。确认和详情明确分享使用叶证书 `pinSHA256` 且不关闭证书校验；停用/删除最后一个有效账户时沿用“请先停用节点”的保护文案。切换回 TCP profile 时必须清除 UDP reservation，切换主机/profile 时继续清除证书、SNI 和账户草稿。

Shadowsocks 的协议分区提供两个明确选项：“TCP”对应既有 `SHADOWSOCKS_2022_RAW_NONE`，“TCP + UDP”对应 `SHADOWSOCKS_2022_RAW_TCP_UDP_NONE`；不能用一个会改变已部署节点含义的隐式开关。两者都继续显示固定 RAW/none/method 和 deprecated 告警。选择双网络时端口区为同一端口分别显示 TCP、UDP 的“等待检测/检测中/可用/失败”状态，自动流程先取得一个网络的端口，再以 MANUAL 对同一端口探测另一网络；只有两项 reservation 都有效才能确认创建。

在 TCP 与 TCP+UDP 之间切换必须清除浏览器内已有 reservation 引用并重新探测；不得把单个 TCP 或 UDP reservation 伪装为双网络成功。确认页和详情明确显示“监听：TCP + UDP”，运行状态必须同时看到同一 runtimeTag/port 的两个 READY listener 才显示运行中。浏览器提交 `portReservations` 只含两个 reservation id，不含 PSK、method、network JSON 或其他高级字段。

第一版编辑页不得为 TCP+UDP 入站提供端口修改入口，因为既有更新 API 只有一个 reservation；名称、公网地址、启停、删除和账户管理保留，并在 UDP capability 降级时统一禁用写操作和显示升级原因。需要改端口时先创建替代节点，直到双预留更新合同单独批准。

`WIREGUARD_UDP_NONE` 只在主机同时支持 UDP 探测和 UDP listener readiness 时显示为可创建协议；选择后传输/安全固定显示“Xray 内置 / UDP / 无 TLS”，端口只执行一份 UDP 探测。页面必须醒目提示“WireGuard 外层特征明显，可能被识别或封锁”，且不把它设为默认推荐。固定配置摘要显示“gVisor · IPv4 · MTU 1420 · 10.0.0.0/24”，不提供 kernel TUN、workers、reserved、domain strategy、IPv6、subnet、MTU、DNS、路由、key、PSK、allowedIPs、keepAlive 或高级 JSON 控件。

创建和新增 peer 时账户区只输入名称；服务端生成密钥并分配地址。详情 peer 列表只显示名称、`10.0.0.N/32`、启用/待同步状态和“凭据已配置（隐藏）”，不显示 server/peer public key、private key、PSK、fingerprint 或 keyVersion。尝试停用/删除最后一个有效 peer 时显示“启用中的 WireGuard 节点至少需要一个 peer；请先停用节点”。

WireGuard 分享 Dialog 展示可复制、可下载的 `.conf` 文本及同内容二维码，不能沿用“URI”标签；文件名由服务端提供并禁止路径字符。关闭、失败或下载后清除组件内存与 React Query 缓存，浏览器不得把配置写入 URL、localStorage、sessionStorage 或 IndexedDB。确认页和详情明确显示单 UDP listener；切换到其他 profile 时清除 UDP reservation 和全部 WireGuard peer 草稿。

### 12.5 HTTP 管理代理

`HTTP_RAW_NONE` 在协议选择中标记为“管理代理”，不作为默认项，也不进入普通订阅提示。传输和安全只读显示“RAW / TCP / 无 TLS / 强制 Basic 认证”；创建页只收集账户显示名称，不能输入、回显或预设 username/password，也不显示 transparent、headers、fallback、sniffing、路由或高级 JSON。

创建确认、详情和分享 Dialog 必须显示 `PLAINTEXT_PROXY_AUTH_RISK`：“该 HTTP 代理未使用 TLS，Basic 用户名和密码可能被链路观察者读取；仅在受信网络或额外加密隧道中使用。”详情账户沿用通用 CRUD 和“凭据已配置（隐藏）”，启用中的节点禁止停用/删除最后一个有效账户。

分享 Dialog 将材料标记为“HTTP 代理地址”，按需展示/复制/二维码呈现标准认证型 `http://` URL；不得称为订阅链接。关闭或失败后清除组件内存和对应查询缓存，禁止写入 URL、localStorage、sessionStorage 或 IndexedDB。

### 12.6 Mixed（SOCKS5 + HTTP）管理代理

`MIXED_RAW_NONE` 在协议选择中显示为“Mixed（SOCKS5 + HTTP）”，归类为管理代理且不作为默认推荐。传输和安全只读显示“RAW / TCP / 无 TLS / 强制密码认证 / UDP 关闭”；界面不提供单独 SOCKS4、SOCKS5、HTTP、UDP、IP 或认证方式开关，因为它们会改变已批准 profile 的安全语义。

创建页只收集一个或多个账户显示名称，不能输入或回显 username/password。确认、详情和分享显示 `PLAINTEXT_MIXED_AUTH_RISK`：“该 Mixed 代理未使用 TLS，SOCKS5 用户名/密码和 HTTP Basic 凭据可能被链路观察者读取；仅在受信网络或额外加密隧道中使用。”同时说明同一端口可用于认证 SOCKS5、HTTP 和 CONNECT，不支持 SOCKS4/4a 与 UDP。

分享 Dialog 标题为“Mixed 管理代理地址”，分别展示“SOCKS5 地址”和“HTTP 地址”的复制项与按需二维码，不使用“订阅”字样。关闭或失败时必须同时清除两个 URI、二维码和对应 React Query cache；两项都不得进入地址栏、localStorage、sessionStorage 或 IndexedDB。详情账户继续只显示名称、状态和两项凭据已配置，不泄露或推导 username。

### 12.7 Tunnel（本机固定目标转发）

`TUNNEL_TCP_LOCAL_NONE` 在协议选择中显示为“Tunnel（本机端口转发）”，不作为默认推荐。传输和安全只读显示“本机回环 / TCP / 无客户端认证”；目标表单只提供“目标地址”和“目标端口”，接受规范 IP/FQDN 与 `1..65535`。页面明确说明入口恒为 `127.0.0.1:<listenPort>`，只有目标主机上的本地进程可连接，所选主机公网地址不会用于该 profile。

界面不显示或提交 public/listen address、账户、凭据、分享、订阅、UDP、portMap、followRedirect/TProxy、transparent、sniffing、fallback、route/outbound 或高级 JSON。安全分区展示固定回环边界和默认 direct outbound；账户分区改为“访问边界”只读确认，不能用伪造的默认客户端通过既有表单。

确认页用“本机 endpoint”替代“公网 endpoint”，显示唯一目标和“0 个凭据”；详情概览显示本地入口、目标、TCP-only、无认证但仅回环，不渲染账户页签或分享按钮。列表中的地址仍显示 `127.0.0.1:<listenPort>`，列标题/移动端标签使用中性“监听地址”，避免把回环地址标为公网可达。

## 13. TLS 证书管理

`Xray 节点` 页面新增 `TLS 证书` 页签，按主机筛选显示证书名称、DNS SAN、签发者、有效期、算法、状态和引用节点数；不显示完整证书 PEM 或任何私钥字段。到期状态使用“有效 / 30 天内到期 / 14 天内到期 / 7 天内到期 / 已过期”文字和图标，不能只依赖颜色。

导入和轮换 Dialog 提供两个等价入口：粘贴 PEM，或选择本地 `.pem/.crt/.key` 后由浏览器读取文本。UI 不显示或提交本地路径，不记住文件名，不写 localStorage/sessionStorage；提交成功、关闭或失败后都清空私钥表单值。前端显示 16 KiB/8 KiB 限制并预检长度，但服务端校验为权威。

删除要求逐字输入证书名称；存在引用时禁用删除并列出安全的节点名称/数量。轮换被引用证书时，确认区列出受影响节点和主机，明确应用完成前 Agent 可能仍运行旧证书，并且应用后所有引用节点都必须重新分发带新 `pcs` 的分享链接。创建 TLS 节点时只显示同一主机、当前有效且 serverName 可匹配的证书；没有证书时提供“先导入证书”入口，不允许填写 Agent 文件路径。

## 14. 独立服务

`Xray 管理` 增加“独立服务”页签，与“节点管理/运行环境/TLS 证书”并列。列表显示名称、类型、主机、公开 endpoint、账户数、desired/applied 状态和更新时间；不能将 MTProto 标成 Xray inbound。

“创建独立服务”按 catalog kind 提供独立入口。MTProto 表单保持基础配置、TCP 监听、FakeTLS、安全边界和账户；AmneziaWG 表单只提供名称、在线兼容主机、publicAddress、单 UDP 自动/手工探测和初始 peer 显示名，并只读展示固定 IPv4 subnet/MTU/DNS、userspace helper 与公网 allow policy。浏览器不得输入或生成任何 key/PSK、地址、混淆、route、interface 或高级配置。

确认页按 kind 显示运行时边界：MTProto 为固定 mtg sidecar/TCP，AWG 为固定 Agent helper/UDP/gVisor userspace；两者均为专用低权限用户且无额外 Linux capability。AWG 通过 054F 后按 catalog 显示可创建入口；TUN 继续显示待设计且没有可提交控件。

详情按 kind 提供启停、删除和账户/peer CRUD。MTProto 分享保持 `tg://`；AWG peer分享展示 `.conf` 二维码、复制/下载和独立 `vpn://` 复制。关闭、失败或下载后清理组件内存与 React Query cache，不写 URL、localStorage、sessionStorage 或 IndexedDB。Agent 离线时全部写操作和新分享均禁用，最后 observed 只标为历史状态。

## 15. 出口节点与界面联动（TASK055）

`Xray 管理` 增加“出口节点”页签。列表显示名称、协议、公开 endpoint、Xray 引用数、转发规则引用数和更新时间；不显示“在线”徽标。导入 Dialog 接受单条链接并先显示无凭据预览；批准的 VLESS `chrome|random` 以及 authority 后有无单个 `/` 使用相同流程，界面不得因兼容写法改写指纹。原始输入只留在表单内存，关闭、成功或失败后立即清空。详情支持重命名、无引用时替换链接、查看引用入口和精确名称确认删除。

Xray 节点列表与详情显示“出口：直连/节点名称（协议）”。详情提供“配置出口”按钮和可搜索选择器；只列出当前 profile 可绑定的资源，提交前显示该主机将生成新 generation。解绑明确恢复 direct；应用中、失败和 observed 未收敛沿用现有 operation 状态，不把外部定义标成已连通。

规则创建/编辑在目标区提供“手动目标/出口节点”切换。选择出口节点后地址端口只读显示、协议固定 TCP，并允许 iptables、nftables、Realm、socat、GOST、Nginx 六种本地转发方式；“只转发原始 TCP、不得发送 PROXY Protocol”提示同步生效，所有不兼容隐藏选项在 reducer 中清除。切回手动目标时不携带旧引用 id；切换页面分区或返回上一步时保留当前合法草稿，但最终提交前仍可修改。

引用出口的规则在列表/详情显示“出口节点：名称（协议）”和物化 endpoint。管理员可打开“中转链接” Dialog，确认入口主机公网地址与监听端口后按需获取链接；关闭/失败/复制后清除链接与 React Query cache，不进入 URL、localStorage、sessionStorage 或 IndexedDB。移动端卡片、桌面表格和所有 Dialog 必须能滚到底、键盘操作并恢复焦点。

普通转发规则创建 Dialog 的“源端口”在输入稳定后自动执行全局账本与全部实际入口 Agent 探测；检测中显示等待状态，只有本次 host/转发组、协议和端口均取得 `AVAILABLE` 才显示绿色并允许创建。随机分配只选择候选，仍须走相同探测。任一入口占用、离线、能力不足或超时显示不可用及脱敏原因；修改任一相关字段立即作废旧结果。编辑已有规则不对自身监听做 bind 探测。

## 16. DNSPod 设置与快速配置（TASK057）

### 16.1 系统设置

系统设置新增“DNS 服务商”卡片，首版固定 DNSPod，只显示一个全局账号。未配置时提供名称、SecretId、SecretKey；已配置时只显示掩码、验证状态、有效期、zone 数量和“重新验证/更换凭据/删除”。保存按钮明确先验证后保存；验证中禁用重复提交，失败保留用户当前输入供修改但不得写浏览器持久存储，关闭/成功后清空两项 secret。

账号失效或 24 小时验证过期显示稳定原因和重新验证入口，不展示 provider 原文。6 小时 catalog 到期且自动刷新失败时显示“线路目录已过期”、允许手动刷新，但快速配置创建保持禁用。存在快速配置引用时禁用删除/换绑并显示配置数、记录数和可筛选的引用列表；更换同一稳定账号的凭据仍可尝试，但只有新凭据能继续访问全部在用 zone/recordId 时才保存。既有 DDNS 设置保持原卡片和行为，不显示“已自动迁移”等误导文案。

### 16.2 快速配置入口与目标列表

`Xray 管理` 增加“快速配置”页签。没有有效 DNSPod global binding、无 zone 或验证过期时页签仍可见，内容区显示原因和“前往系统设置”，创建按钮不可用。

可用时列表统一显示受管 TCP Xray 落地和外部 VLESS/SS/SOCKS5 节点：名称、类型/协议、原 endpoint、已配置 FQDN/对外端口、状态和“配置/查看”。UDP-only、回环 Tunnel、pending delete、未同步或 endpoint 不稳定的目标保留可见但禁用，并展示服务端 reasonCode。受管 profile 如果不能产生 QC019 的 VLESS/SS/SOCKS 分享材料，仍可作为合格 TCP 落地，但标注“需手动更新客户端地址”且不显示伪分享按钮。

### 16.3 六步可回退向导

Dialog 使用受限高度 flex 布局，标题/步骤固定，内容 `min-h-0` 独立滚动；桌面和 320×500 下都必须能到达底部按钮。最终 apply 前六步均可返回：

1. **域名**：zone 下拉 + 相对记录输入。点击“检查域名”后显示规范 FQDN、A/AAAA/CNAME 替换项与 TXT/MX/CAA 保留项；另一个“确认此域名”动作成功后才能下一步。若保留类型与地址记录不能共存则只允许换名称，不能用“替换”删除它。修改 zone/记录会清除 domain token 及全部下游。
2. **运营商入口**：电信、联通、移动、教育网各自多选 `服务器 · IPv4/IPv6 · 地址`。只显示服务端返回的有效地址；同 host 双地址族说明只建立一个 listener。修改任一选择会清除 probe、端口、默认线路和 preview。
3. **端口检测**：先自动检测落地原端口，并逐 host 展示 TCP/UDP 检查状态。受管 Xray 冲突后显示手工统一端口；外部目标显示服务器推荐端口并要求确认。检测异步但可恢复，不能让用户编辑 Agent 列表。
4. **默认线路**：只有端口检测成功后出现。未改写端口时预选落地已验证 IPv4/IPv6，二者都有则同时选择；改写端口时要求从已建立相同 Realm listener 的受管入口中至少选择一个地址族。修改端口清除本步和 preview。
5. **预览**：显示最终 FQDN、统一端口、四线路 A/AAAA、默认线路、按 host 去重的正式 Realm 规则、将替换/保留的 DNS 记录和全部警告。修改默认线路只清除此 preview。页面必须明确“此时尚未创建规则或修改 DNS”。
6. **执行状态**：点击最终确认后冻结表单，显示持久 operation 的真实 phase、逐 host 规则和逐 record 状态；刷新页面可通过非敏感 quickConfigId/operationId 恢复，但 token、secret 和 URI 不进入 URL。

token、probe reservation 或 preview 过期时保留仍合法的上游草稿，禁用前进并在对应步骤提供“重新检查”，不强制从头填写。向前按钮只按当前依赖启用；已完成步骤始终可返回。成功端口检测后返回更换 engine、入口选择或端口时，前端只在内存保留上一轮 `probeResultToken + expiresAt` 作为下一次检测的替换凭证；新检测被服务端受理后立即清除，不能把 reservation ID 暴露为表单字段或写入 URL/浏览器持久存储。关闭未提交向导只停止轮询，最长 60 秒的短期 reservation 由服务端自动到期；已提交 operation 不因关闭 Dialog 或浏览器断开而取消。

### 16.4 详情、编辑、删除与部分失败

详情显示 active topology、若存在则显示 staged/retiring topology，线路到 DNS recordId 安全摘要、普通规则和端口 allocation 的可追踪关系。`APPLYING/UPDATING/DELETING/COMPENSATING/PARTIAL_FAILURE` 都显示真实阶段和稳定下一步，不能把“规则 ready、DNS 部分失败”显示为 ACTIVE。

编辑复用六步向导并预填 active topology；用户可以返回任一步，目标落地不可更换。确认页明确新规则先 ready、再切 DNS、最后清旧规则。删除先展示将删除的当前托管 A/AAAA、规则和端口，明确不会恢复创建前或历史 edit 的第三方记录，并要求输入完整 FQDN；Agent 离线或 DNS 漂移时禁用提交并提供重试/处理说明，不提供“只删数据库”的绕过按钮。

`PARTIAL_FAILURE` 保留“重试当前操作”入口和逐步结果；不能把“清理干净”作为会覆盖第三方 DNS 或释放未确认端口的动作。operation 进行中阻止第二次编辑/删除。

### 16.5 普通规则与分享联动

快速配置生成的规则在既有 Rules 桌面表格和移动卡片显示“快速配置”徽标、FQDN、目标和线路标签，详情显示真实 engine/source/target/运行日志及 quick-config 链接。直接编辑、停用、删除改为说明影响并跳转 quick-config 编排；查看运行状态和日志保持普通规则体验。

链路管理“端口转发”只显示真实 `port` 资源，不显示下方规则明细，也不追加“实际规则”主机汇总。快速配置规则在创建或历史收敛时归属到真实资源；服务器 B 没有唯一可复用资源时，列表自动出现名称“快速配置默认生成”的正常资源卡片/表格行。已有服务器 A 资源 `dfaf` 被唯一复用时保持原卡片和名称。

卡片、移动列表和桌面表格的“引用规则”统一显示用户模板与快速配置规则总和；存在快速配置引用时增加“快速配置 N”说明，关闭开关禁用且 title/辅助文本明确“请先在快速配置中移除相关入口”。服务端仍必须拒绝伪造请求。锁定期间不得通过删除或改变 host/engine 绕过归属；最后一个活动引用进入待删除后资源解锁，系统生成资源首版保留供用户查看或手动清理。

详情只有服务端 `shareCapability` 支持时显示“获取新连接信息”。受管多账户先选择账户；外部节点不显示账户选择。VLESS/SS URI 与 SOCKS5 endpoint 只存在于按需 Dialog 内存，关闭、失败或复制后清除组件和 React Query cache，禁止 URL、localStorage、sessionStorage、IndexedDB。其他 TCP profile 显示手动修改 endpoint 的明确说明。

## 17. 快速配置六引擎交互（TASK058）

第二步完成四类运营商入口选择后，在同一步显示一个全局“转发引擎”选择器，候选固定为 iptables、nftables、Realm、socat、GOST、Nginx，顺序与服务端目录一致。初始推荐 Realm；Realm 不可用时保留禁用状态和原因，不自动选择第一项。每项只显示稳定原因文案，例如全局关闭、主机离线、Agent 需升级、缺双网络探测能力或所选 IPv4/IPv6 不可用，不显示版本号、原始 capability、命令或运行时错误。

一个向导只能选择一种 engine，选择作用于全部物理入口 host；修改 carrier endpoint 后立即重新读取交集并清除已失效 engine、port check、默认线路和 preview。只有目录返回 eligible 且后端再次校验通过才能进入端口检测。预览和详情逐条显示实际 engine，但不提供按 host 单独修改入口。

编辑已有配置时预填当前 engine。改选 engine 后确认页展示受影响 host、同端口逐台切换和可能短暂中断，允许返回修改；不声称零中断。执行状态区显示旧规则清理、新规则应用和失败恢复阶段。失败且旧 engine 已全部恢复时继续显示旧配置 ACTIVE；恢复不完整时显示 `PARTIAL_FAILURE` 和重试入口，禁止把某些 host 已切换误报为完成。
