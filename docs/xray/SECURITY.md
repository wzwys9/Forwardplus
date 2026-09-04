# Xray 安全设计

状态：已批准。本文是实现的最低安全边界，不能为了调试方便临时绕过。

## 1. 资产和信任边界

重要资产：

- Reality 私钥。
- VLESS UUID 和 shortId。
- Agent Token 和 Agent 加密通道。
- 面板 Xray 制品与哈希。
- 受管 Xray 配置和 last-good。
- 管理员操作权限。

信任边界：

```text
管理员浏览器 → tRPC/API → 面板服务 → 数据库/制品存储
                                  ↓
                         加密 Agent 通道
                                  ↓
                         Agent → 文件/进程/网络探测
```

浏览器输入、Agent 上报、扫描目标、制品响应、磁盘已有文件和 Xray 命令输出都按不可信数据处理。

## 2. 权限

- 所有 Xray 页面、query、mutation、artifact 管理和 operation 查询仅管理员。
- 前端路由保护不能替代服务端角色检查。
- Agent artifact route 使用现有 Agent 认证，并把受限 OS/arch 请求头与该主机最近一次已验证、已持久化的 capability 报告逐项匹配；只允许下载相符的已验证制品，不能仅信任请求头。
- 不提供普通用户读取客户端 UUID、分享链接、Reality 公钥列表或运行错误的接口。
- 后续开放用户管理时必须新增资源所有权规格，不能仅把管理员接口换成 protectedProcedure。

## 3. 面板静态加密

Reality 私钥、UUID 和 shortId 使用版本化 AES-256-GCM 或等强度 AEAD envelope。建议逻辑格式：

```text
fwdx-secret:v1:<keyId>:<base64url nonce+ciphertext+tag>
```

要求：

- 独立 32 字节面板主密钥，不复用 Agent Token、会话 secret、数据库密码或备份密码。
- 每次加密使用随机 96-bit nonce，禁止 nonce 重用。
- Associated Data 绑定资源类型、稳定资源 id 和字段类型，防止在记录之间搬运密文。
- AAD 的稳定资源身份固定为 inbound `runtimeTag` 和 client `statsKey`；字段名分别为 `reality-private-key`、`uuid`、`short-id`。这些服务端生成身份创建后不可修改，避免数据库自增 id 尚未分配时无法加密，也避免后续重命名使既有密文不可解。
- 解密失败返回 `SENSITIVE_DATA_UNAVAILABLE`，不得退回明文或空凭据继续部署。
- 判重使用独立派生的 HMAC key 和 HMAC-SHA-256 fingerprint，不对密文做唯一判断。fingerprint 绑定 envelope 版本、资源类型和字段类型，但不绑定单条记录 id，使相同字段的同一明文能跨记录判重；AEAD AAD 仍绑定稳定资源 id，防止搬运密文。
- 密文字段永不进入普通 DTO、日志、审计 diff、operation metadata 和错误响应。

这里的“面板主密钥”是只供 ForwardX 面板静态加密数据库敏感字段使用的 256-bit 应用密钥，不是 Reality 密钥、Xray 密钥、Agent Token、登录会话 secret、数据库密码或备份密码。

`XRAY-ADR-015` 确定以下生命周期：

- 首次生成：安装器使用密码学安全随机源自动生成，不让管理员手工编一个字符串；已存在有效文件时必须复用，禁止升级时覆盖。
- 持久化：Docker 默认 `/data/xray-master.key`，位于现有 `forwardx-data` 持久卷；本地安装默认 `/opt/forwardx-panel/data/xray-master.key`；开发环境默认 `data/xray-master.key`。允许用 `XRAY_MASTER_KEY_PATH` 指向等价的持久 secret 文件。
- 文件安全：原子创建，root/面板服务用户所有，权限 `0600`；拒绝目录、符号链接和组/其他用户可写文件。密钥不能放进数据库、镜像层或命令行参数。
- 备份恢复：原始数据库备份必须同时独立备份密钥文件；第一版“密码加密完整备份”使用备份密码派生的包装密钥加密一份面板主密钥，从而一次恢复，但明文备份和日志中绝不包含密钥。
- 轮换：第一版实现带 `keyId` 的 envelope 和读取 keyring/写当前 key 的内部结构，不做轮换 UI；后续轮换使用后台逐条重加密。
- 丢失处理：只恢复数据库而没有正确密钥时明确报告 `SENSITIVE_DATA_UNAVAILABLE`，禁止自动生成新密钥后把旧节点伪装成可用。

没有配置主密钥时 Xray 功能应安全不可用，不能明文降级。

## 4. Agent 传输和本地存储

- desired config 通过现有 HTTPS 和加密 envelope 传输，服务端和 Agent 均不得打印 payload。
- Agent 只在受管配置工作副本中保存运行所需的明文私钥/UUID，目录 `0700`、文件 `0600`、root 所有。
- Agent observed state、task result 和支持包禁止回传完整 config。
- `agentDistribution` 是受鉴权 Agent 的有界声明，不是远程证明；只接受已知规范值，并继续要求对应版本、capability、制品和 observed 校验。缺失或未知来源 fail closed，不因高版本号开放 Forwardplus 专有 desired/task。
- Agent 本地 pending task result 不含 configJson 或凭据。
- Agent 对受管目录、版本、manifest、二进制、配置、hash、state、事务标记和 current symlink 逐级执行所有者、类型、权限、边界与大小检查；所有最终受管对象必须属于运行 Agent 的有效用户，拒绝符号链接和不受信所有者。
- config 临时文件和 last-good 使用同样权限；失败/删除时清理固定路径，不使用宽泛 glob 删除。
- Xray desired 串行队列内存最多保留一个运行中和一个待处理 config；不得把队列 payload 写入日志、action record 或普通 task-result spool。
- 面板对完整 observed state 做递归 schema、禁用字段、大小和签名校验；压缩上报命中数据库缓存前还要重新验证缓存内容。
- Agent 错误只按允许的稳定错误码和面板生成的通用摘要入库，不保存或回显 Agent 提供的任意错误文本。

## 5. 分享材料

- 分享 URI 是凭据，按 secret 响应处理。
- `xray.clients.share` 仅管理员、`Cache-Control: no-store`，不在服务端日志记录响应。
- 前端不写 localStorage/sessionStorage，不把 URI 放进 URL query/hash。
- 二维码在内存生成；关闭 Dialog 后释放引用。
- UI 日志、错误上报和分析事件不得携带完整 URI。
- 分享链接只含 Reality 公钥，不含服务端私钥。

## 6. Reality 扫描和 SSRF

Reality 扫描可能被滥用为远程主机内网扫描器，必须：

- 第一版仅允许域名和显式公网 host:port，不允许 CIDR、URL path、userinfo、Unix socket 或任意协议。
- 解析全部 A/AAAA 记录；任何一个结果属于 loopback、RFC1918、CGNAT、link-local、multicast、reserved、documentation、IPv6 ULA 或云元数据范围时拒绝目标。除通用地址分类外，面板和 Agent 都显式拒绝已知云平台特殊端点（包括 Azure `168.63.129.16`）。
- 连接使用验证过的固定 IP，同时保留正确 SNI，避免 DNS rebinding 再解析。
- 策略拒绝和混合 DNS 结果只返回脱敏状态，不把私网、metadata 或其他被禁止地址写入 task result。
- 不跟随 HTTP 重定向，不使用系统代理环境变量。
- 限制候选数量、并发、单目标超时、总超时和返回大小。
- 默认候选列表版本化并由面板提供；当前 `v2` 只包含固定的 9 个域名目标，不包含 `www.microsoft.com`。候选来源不能替代 Agent 独立执行的地址安全和 TLS 检查。
- 面板创建 operation 前也执行有界 DNS/地址预筛；接收结果时重新校验 target/host/port、公网地址、serverNames 和稳定 reasonCode，不信任 Agent 回传绕过面板策略。
- reason message 不返回内部路由、进程或敏感 DNS 配置。

第一版禁止管理员通过“确认风险”绕过私网保护。

## 7. 端口探测

- 面板生成候选，浏览器不能提交任意大列表。
- Agent 只执行 bind/close，不读取或返回占用进程命令行。
- 绑定地址固定在协议允许集合内，不能由管理员传入任意本地地址。
- 探测任务短期、限速、过期即拒绝。
- 面板预留和最终 Xray bind 都要处理竞态；不能把 probe 成功当永久锁。
- 重复探测只能携带最多两项互异 UUID 形式的旧 reservation ID；服务端按当前管理员、主机、共同端口和 TCP/UDP 唯一性一次性验证，任一有效项错配都不得释放任何项。旧项释放后仍须重新检查数据库和全局账本，禁止通过替换参数释放其他 owner 的预留或隐藏真实占用。

## 8. 制品供应链

- 面板只缓存明确版本、OS、arch 和受支持格式的 Xray 制品。
- 当前只获取 Xray-core `v26.3.27` 的官方 `linux-amd64`/`linux-arm64` 归档与 `.dgst`，核对固定 SHA-256 后写入面板清单；版本变更必须新增 ADR 和制品清单，不跟随 `latest`。
- 生产面板启动时自动填充这两个固定制品；已有缓存也必须重新验证，两个架构未全部验证前不得设置默认版本。初始化失败只保留缺失/无效状态，不能允许 Agent 直连公网兜底。
- artifact 数据库存储 SHA-256 和大小，Agent 二次校验。
- 安全解包防止 Zip Slip/Tar path traversal、绝对路径、符号链接逃逸和设备文件。
- Agent 验证二进制自报版本、架构和执行结果。
- 不执行归档中的安装脚本，不信任文件名决定版本。
- 升级只写全新目录并原子切换，可回滚旧版本。
- 下载 route 不接受任意路径/URL，避免目录遍历和 SSRF。

## 9. 命令和配置注入

- Agent 只接受判别联合 typed tasks，不接受 `command`/`script` 字段。
- 本地命令使用 `exec.Command` 参数数组或固定 systemctl unit 名，不经 shell 拼接用户输入。
- runtimeTag、taskId、版本和文件名使用字符 allowlist。
- `configJson` 只由面板生成器产生，管理员不能直接提交；Agent 仍使用 Xray 配置测试作为独立安全边界。
- Xray 错误输出先截断和脱敏再存储/上报。

## 10. 日志、审计和支持包

允许记录：

- 管理员 id、hostId、inboundId、clientId。
- operationId、task type、状态、耗时。
- generation、hash 前 8–12 位。
- Xray 版本、artifact id、端口、runtimeTag。
- 稳定错误码和脱敏摘要。

禁止记录：

- Agent Token、Authorization、加密 envelope。
- privateKey、UUID、shortId。
- 完整 configJson、分享 URI、二维码数据。
- HTTP Basic 用户名、密码及完整认证型代理 URL。
- 数据库密文和面板主密钥。

支持包增加 Xray 信息前必须有专用 scrubber 和测试夹具，证明嵌套 JSON、命令输出和文件名都不会泄密。

认证型 HTTP 管理代理额外遵守：公网监听不得在零有效账户时生成配置；username/password 必须由服务端 CSPRNG 生成并分别使用资源绑定 AEAD/HMAC context，显示名称不得充当登录名；无 TLS 的 Basic 认证风险必须由服务端 advisory 驱动并在创建、详情、分享三处展示。首版不提供无认证开关、透明代理或浏览器自定义凭据输入。

认证型 Mixed 管理代理额外遵守：固定使用密码认证且只承诺 SOCKS5、HTTP 和 CONNECT；不得开放会绕过密码模式的 SOCKS4/4a 兼容入口或 `noauth`。username/password 使用独立 `MIXED_USER_PASSWORD` credential 的资源绑定双 secret，不能复用 HTTP 账户或由显示名称派生。RFC 1929 用户名/密码与 HTTP Basic 都是链路明文认证，服务端 advisory 必须在创建、详情和双地址分享三处提示仅用于受信网络或额外加密隧道。

Mixed 首版必须固定 `udp=false`。固定核心的 UDP filter 在一次 TCP UDP ASSOCIATE 后只按来源 IP 放行、没有可靠按 association 回收；共享 NAT 下其他进程或设备可能利用已放行来源，不能满足公网每次访问已认证的边界。不得用 UI 警告替代安全拒绝，也不得发送 UDP reservation/listener；未来 UDP 需要新的已批准 profile 和能证明逐会话授权/回收的运行证据。

Tunnel 没有客户端认证协议，首版必须把 listener 和展示 endpoint 双重固定为 `127.0.0.1`。服务端不接受 public/listen address，repository 与配置生成器重新验证 profile/address/零账户/零 secret；任一非回环记录 fail closed，不能因为 UI 隐藏字段而信任请求。回环边界只限制连接来源，不加密转发内容，也不代表目标安全。

Tunnel 目标是管理员授予受管 Xray 的持久出站连接能力。输入只允许规范 IP/FQDN 和单端口，面板不解析、不探测、不回传目标内容；配置固定 `followRedirect=false` 和默认 direct outbound。任意 port map、原始目的地址恢复、TProxy/iptables、路由/outbound 选择、URL、协议探测或 Xray JSON 都会扩大 SSRF/横向移动与透明劫持面，必须通过新 profile 和安全评审另行批准。

实现约束：

- 面板 Xray mutation 日志和配置审计必须先经过同一个字段 allowlist；未知字段直接丢弃，完整 hash 只输出 12 位前缀。
- 审计的脱敏展示与变更检测分离：展示值删除 secret，比较值对 secret 原文做单向 SHA-256，凭据轮换仍必须产生审计修订。
- Agent 支持包中的 `xrayRuntime` 是独立 allowlist 投影，只允许 installed/running version、service/listener status、config/binary hash 前缀，以及 listener 的 runtimeTag/port；不得包含 PID、generation、network、完整 observed state 或 config。
- 面板收到支持包后必须再次执行同一 Xray 投影和递归 scrubber，不能只信任 Agent 已脱敏；命令错误与输出都必须先脱敏再截断。
- 普通 runtime/operation DTO 和 API 错误不得复制数据库或底层异常文本，只返回稳定错误码与通用摘要。

## 11. 备份和密钥恢复

- 面板数据库备份包含 Xray 密文和结构化记录。
- 原始数据库备份必须通过独立安全渠道配套备份面板主密钥；只恢复数据库而没有主密钥时，面板应明确报告不可解密，不重新生成并静默破坏现有节点。
- “密码加密完整备份”格式版本 2 在同一个 AES-256-GCM 认证加密载荷内保存数据库快照和版本化主密钥包装；备份头作为 AAD，恢复时严格验证格式版本、固定 scrypt 参数和认证标签。普通数据库导出仍不包含主密钥。
- 恢复到没有 Xray 密文的面板时可以采用备份中的主密钥；目标面板已有 Xray 密文时只接受完全相同的密钥，密钥不同或旧格式备份缺少包装时返回 `SENSITIVE_DATA_UNAVAILABLE`。
- 导入必须先在内存中解析候选 keyring，并在修改磁盘密钥或数据库前验证快照中全部 Xray envelope；通过基本快照/重复检查后才提交密钥。只有目标库原先没有 Xray 密文时才允许采用不同的候选密钥；一旦数据库导入开始就保留该已验证密钥，因为结构化导入允许部分写入，回滚密钥会使已写入的备份密文不可解密。
- 格式版本 1 备份继续可读取；它若包含 Xray 密文但没有独立恢复正确主密钥，必须显式失败。
- 加密备份密码不直接替代长期主密钥。
- 密钥轮换使用 keyId：新写入使用新 key，后台逐条重加密，旧 key 在确认完成后退役。
- 导出、导入和迁移测试必须验证敏感字段不变成明文。

## 12. 可用性与撤销语义

- Agent Token 撤销是控制面认证撤销，不自动停止数据面。
- Agent/面板离线时旧客户端仍可能有效；UI 必须明确，删除只有 applied generation 确认后才算远端生效。
- 如未来需要“失联自动停机租约”，必须作为独立高风险需求设计，第一版禁止隐式加入。
- 紧急情况下远端 Agent 无法认证时，管理员需要通过 SSH 或恢复有效 Agent Token 管理 Xray。

## 13. 安全验收

- 普通用户对所有 Xray procedure 返回拒绝。
- 搜索日志、operation、API 快照和支持包找不到测试私钥/UUID/Token。
- 修改密文、AAD 或 keyId 会安全失败。
- 私网、metadata、DNS rebinding 和超限扫描被拒绝。
- 损坏、错误架构、路径穿越制品不安装。
- 配置测试失败不替换 current/last-good。
- Token 错误不调用停止 Xray 的本地操作。

## 14. 多协议新增威胁与边界

- **配置注入：** `profileId`、`spec` 和账户输入使用严格判别联合并拒绝未知字段；数据库中的 `specJson/settingsJson` 读取时再次验证。管理员也不能提交完整 Xray JSON。
- **凭据泄漏：** password、Hysteria auth、WireGuard private/pre-shared key、TLS private key 与现有 UUID/Reality key 一样使用资源绑定 AEAD；普通 DTO、observed state、operation、审计、日志、支持包均只做 allowlist 投影。
- **开放代理：** HTTP/SOCKS/Mixed 公网监听必须强制认证且默认不开放；Tunnel 无认证能力，只允许固定回环 listener。不得生成无认证公网默认 profile。
- **UDP 滥用：** mKCP、Hysteria 2、WireGuard 和 Shadowsocks UDP 只探测单个受限端口，不接受端口范围；Agent v2 有界执行并且不返回占用进程信息。mKCP 不能因名称含 “TCP” 或配置测试通过而绕过 UDP capability、reservation 和 readiness。
- **特权提升：** TUN 需要显式 capability 和最小 `CAP_NET_ADMIN` 设计；MTProto 只允许固定制品，AmneziaWG 只允许当前 Agent executable 的固定 helper 子命令。两者都使用独立 no-login UID、固定参数和专属路径，不接受 shell、任意 service/path/argv/env；AWG 不得打开 OS TUN、系统路由、防火墙或请求 `CAP_NET_ADMIN`。
- **MTProto 最小权限：** `mtg-multi v1.15.0` 只允许面板固定清单中的 linux/amd64 或 linux/arm64 制品。Agent 启动任何 mtg 命令前必须解析安装器维护的 `forwardx-mtproto` 专用 UID/GID，并设置 child credential；root 专属 state/current/last-good 为 `0700/0600`，服务配置目录为 root:`forwardx-mtproto` `0750`、配置为 `0640`，专用账户只能读取；binary/manifest 为 root 所有且不可由该账户写。任何缺少专用账户、所有者不符、symlink、group/world 可写或架构/version/hash 不符都 fail closed，不回退以 root 启动。卸载只删除由 ForwardX 创建且有 root marker 的用户/组，不删除预先存在的兼容系统账户。
- **MTProto 输入与 secret：** API 只接收服务名、主机、端口 reservation、publicAddress、规范小写 DNS FakeTLS 域名和账户显示名；secret 只能由服务端 CSPRNG 生成，使用独立 managed-service account AAD/HMAC context 加密。普通 DTO、operation、审计、日志、observed、支持包和 config validator 输出不得出现 secret、完整 `tg://` URI 或加密 envelope。
- **MTProto 网络面：** 首版只监听一个显式 TCP `0.0.0.0:<1000..65535>`，不打开 mtg 管理 API，不启用 ad-tag/remote blocklist/domain-fronting override/proxy chain/PROXY protocol。分享按需 `private, no-store` 生成，关闭后清理浏览器内存和查询缓存。
- **AmneziaWG 密钥隔离：** server/peer private key、每 peer PSK 和 HeaderProtectionKey 只由服务端 CSPRNG 生成并使用不同 service/account context 加密；server/peer public key必须由相应 private key派生和复核。Agent desired 不得含 peer private key，observed/log/error/support bundle 不得含任一 key、PSK、混淆对象、`.conf` 或 `vpn://`。
- **AmneziaWG helper 隔离：** 安装器维护独立 `forwardx-amneziawg` no-login UID/GID 和 root marker。配置目录为 root:专用组 `0750/0640`，state/current/last-good 为 root `0700/0600`；helper executable 必须解析为当前受管 Agent binary 且 PID/starttime/argv 与 desired 相符。身份、owner/mode、symlink、版本或 hash 任何一项异常均 fail closed，绝不回退到 root helper。
- **AmneziaWG 网络出口：** helper 只代理来自已配置 peer 地址的 IPv4 TCP/UDP。拨号前拒绝 loopback、link-local、multicast、unspecified、private、CGNAT、benchmark/documentation、cloud metadata、本机接口地址、service `publicAddress` 和当前 panel URL hostname 的 IPv4 结果；本机地址与 DNS A 结果周期刷新，任一配置 hostname 无法解析时保持 helper 存活但全部出口 fail closed。panel URL 变更前必须先由 helper 回执带 revision 的 `TRANSITION` policy，保留旧地址并拒绝新地址；切换后再以 `STABLE` 清理旧地址。root 所有的 revision pin 必须位于不被 service 目录替换的 AWG kind root，且 wrapper/panel/pin 文件和父目录都必须持久化；只有第二 ACK 或完整 generation 提交后才可清理。所有 panel URL 同步/迁移必须串行，失败时先持久化回滚再解除 hold；未收到 ACK 、重启后仍有 pin 或恢复失败时不得保留新 runtime URL，并持续 fail closed。deny 输入、结果、pin 和 ACK 只存在于 Agent 受管本地路径，不进入 observed、日志或支持包。固定限制并发 TCP、UDP flow、每 flow 队列、包长、idle 和 dial timeout，防止资源耗尽及横向访问。首版不允许域名目的、IPv6、LAN route、port forward 或 proxy chain。
- **AmneziaWG 输入与分享：** API 只接受服务名、主机、公开地址、单 UDP reservation 和 peer 显示名；subnet/MTU/DNS/AllowedIPs/keepalive/AWG 参数全部由服务端固定或生成。管理员分享响应才可包含 private key/PSK/header key 和完整配置，必须 `private, no-store`，关闭、失败或下载后清除组件/React Query 内存并禁止 URL/localStorage/sessionStorage/IndexedDB。
- **分享泄漏：** scrubber 扩展识别 `trojan://`、`vmess://`、`ss://`、`hysteria2://` 和 WireGuard 配置材料；响应保持 `private, no-store`。
- **证书托管：** 已批准的第一版只接受管理员提交的 PEM 文本：证书链最多四张且不超过 16 KiB，未加密私钥不超过 8 KiB。浏览器文件选择只调用 `File.text()`，服务端不接收或保存文件名、Content-Type、临时上传文件、压缩包、PFX/JKS、密码或 Agent 路径；请求体和解析错误不得进入日志。
- **证书内容验证：** 边界必须规范化 CRLF、拒绝 NUL/非 PEM/额外私钥块，解析叶证书和链，验证当前有效期、至少一个 DNS SAN、叶证书与私钥公钥一致，并只允许 RSA 2048–4096 或 ECDSA P-256/P-384。绑定 TLS inbound 时用相同主机证书并再次验证 1–253 字节规范化 DNS `serverName` 被 DNS SAN 覆盖；不接受 IP、通配符输入或 `allowInsecure`。
- **私钥生命周期：** 私钥使用证书不可变 `certificateTag` 绑定的版本化 AEAD；普通 DTO、日志、审计、operation、observed state、支持包和错误响应均不得出现私钥、完整 PEM、envelope、fingerprint 或 key id。轮换沿用主机 generation/last-good，引用中的证书禁止删除；备份恢复在写库前验证全部 envelope。
- **Agent 边界：** 面板仅在生成 desired 时解密私钥，固定 Xray `v26.3.27` 使用内联 `certificate`/`key`；Agent 只在 ForwardX 专属、`0600` 的 current/last-good 配置中保存运行副本，不建立证书目录、文件路径 API 或第二套证书真相，也不回传证书、私钥或完整配置。
- **TLS 分享验证：** 管理员专用 `private, no-store` 分享响应从所选证书的公开叶证书指纹生成 `pcs`，同时携带规范化 `sni` 和固定 `fp=chrome`；服务端不得生成关闭验证的链接。证书轮换应用后旧 pin 必须失效，UI 明确要求重新分发；普通 DTO、日志、operation 和浏览器持久存储仍不得保存完整 URI。
- **旧列兼容：** 显式 TLS profile 的 Reality-only 非空旧列只能写规格固定的中性值。解密、备份预检、fingerprint 迁移和 secret-leak 检查必须先验证 profile/security，不能尝试把中性空值当作 envelope，也不能因列存在而生成 `REALITY_PRIVATE_KEY` secret。
- **VMess 兼容：** 只开放受管 TLS/pin 的 RAW profile，固定 VMess AEAD `AUTO` 且不写已废弃 `alterId/aid`。UUID 使用既有资源绑定 AEAD/HMAC；核心 deprecated 告警必须在 catalog/UI 保留，不得作为默认推荐。
- **Shadowsocks 双 PSK：** SS2022 server/user PSK 都是 32 随机字节的 canonical base64，分别使用 inbound `SHADOWSOCKS_SERVER_KEY` 与 access `SHADOWSOCKS_KEY` 类别隔离的 AEAD AAD/HMAC context。普通 DTO、日志、审计、operation、observed 和支持包不得出现任一 PSK；分享响应因同时包含两个 PSK，必须整体按 secret 处理。
- **Shadowsocks 空账户退化：** 不得为启用 inbound 编译空 `clients`；修改层在 generation 之前拒绝停用或删除最后一个有效账户，防止固定核心切换到仅 server PSK 可登录的单用户语义。该竞态检查必须在主机写锁/数据库事务内完成。
- **Hysteria 2 auth 与证书 pin：** auth 必须由服务端生成 32 随机字节的 canonical base64url，并使用 access `HYSTERIA_AUTH` 独立 AEAD/HMAC context；不得接受管理员自定义值、复用 password context、写入 inbound 级 transport auth 或进入普通 DTO/日志。分享使用 Hysteria 标准 `pinSHA256` 保存受管叶证书的小写 SHA-256，不生成 `insecure`/`allowInsecure`；不得把 CA 证书 hash 当作 leaf pin，以免把信任范围扩大到该 CA 签发的其他证书。
- **WireGuard key 隔离：** server/peer private key 与每 peer PSK 均由服务端 CSPRNG 生成，规范化为 32-byte standard base64；server key 使用 inbound `PRIVATE_KEY` context，peer key/PSK 使用 access `PRIVATE_KEY`/`PRE_SHARED_KEY` context。peer public key每次由解密后的私钥派生，不能由浏览器提交或以第二份持久值覆盖；普通 DTO、observed、operation、审计、日志、支持包和错误都不得包含任一 key、PSK、envelope、fingerprint 或 keyVersion。
- **WireGuard 地址与权限：** peer 地址只能由事务内最低空闲分配器从固定 IPv4 `/24` 产生，API 不接收 `allowedIPs` 或路由，防止重复源地址、跨 peer 冒用和任意路由注入。Xray inbound 固定 `noKernelTun=true` 的 gVisor userspace 实现，不请求 `/dev/net/tun`、`CAP_NET_ADMIN`、iptables/nftables 或系统 WireGuard 配置；任何启用 kernel TUN 的提议都必须重新做特权设计和确认。
- **WireGuard 分享边界：** `.conf` 和二维码包含 peer private key 与 PSK，整体按最高敏感级别处理；只在管理员 `private, no-store` 响应中临时生成，文件名不含路径，关闭 Dialog 后清除 React Query 和组件内存，不写 URL/localStorage/sessionStorage/IndexedDB。Agent desired 中因运行需要出现 server private key、peer public key与 PSK，但只落 ForwardX 专属 `0600` current/last-good 配置，Agent 不解析回传或记录完整配置。
- **WireGuard 网络风险：** UI 必须展示官方文档所述的外层特征识别/封锁风险。首版固定 IPv4 全隧道，仅认证 peer 可经服务器出站；不得宣传为抗封锁协议，也不得在未验证的情况下开放 IPv6、自定义 DNS/MTU/subnet/route、workers/reserved/domainStrategy 或 3x-ui 任意设置透传。
- **Hysteria 2 UDP 边界：** 只有 capability 中 `supportsUdpPortProbe` 和 `supportsUdpListenerReadiness` 同时为 true 才允许 catalog 可选、单端口探测、创建、修改或下发；reservation 和 observed listener 始终携带 `network=udp`。第一版拒绝端口范围/跳跃、masquerade URL、obfs 密码、带宽/拥塞控制和可改变连接目标或流量形态的任意 transport 字段。
- **Shadowsocks 双网络边界：** TCP-only profile 不得在升级后静默获得 UDP listener。TCP+UDP profile 必须在业务写入前同时校验同 host/user/port 的两份不同 network reservation，并在同一作用域消费/释放；任何一份失效、能力降级或并发冲突都不能留下 inbound、secret、operation、generation 或部分消费。Agent 仍只接收逐 listener 的 `tcp|udp`，不接受 `both`。
- **Shadowsocks 原生 UDP：** profile 只固定 `settings.network=tcp,udp`，不开放 UDP 端口范围、XUDP/UoT、ivCheck、插件、FinalMask 或自定义 transport。双 PSK、最后账户保护和全部 secret 泄漏边界与 TCP-only profile 相同；分享链接不添加可被客户端误解的非标准 UDP 参数。
- **明确排除：** 第一版不实现 ACME 自动化所需 DNS 凭据、自动续期、明文私钥导出、多证书 SNI、OCSP/ECH、自定义 cipher/minVersion、Agent 本地证书管理或密码保护私钥。TASK057 的 DNSPod 凭据只能用于受管解析编排，不能被证书模块或 Agent 复用。到期只做 30/14/7 天提示，不自动停止现有数据面。

## 15. 外部出口节点安全边界

- **不信任导入链接：** URI 限制为 4096 UTF-8 字节和一个批准 scheme，拒绝控制字符、重复/未知行为参数、userinfo 缺失、非法 percent/base64、plugin、非根路径或额外服务器。VLESS RAW 只把 authority 后的空路径与单个 `/` 视为等价，并只允许 `fp=chrome|random`；`randomized`、其他浏览器名和任意 uTLS 名称仍拒绝。前端预览不能替代服务端重验。
- **凭据最小暴露：** 原始 URI 永不持久化；UUID、shortId、SS 密码和 SOCKS 认证分别使用资源绑定 AEAD context。普通 DTO、引用摘要、审计、operation、错误、日志和支持包只用 allowlist；按需原节点/中转链接整体视为 secret，必须 `private, no-store` 并清理浏览器内存。
- **配置注入：** `specJson` 是版本化严格对象，不接收 outbound/routing JSON。Xray 编译只用固定字段和稳定 tag，routing 只匹配面板拥有的 inboundTag；任何缺失、篡改或解密失败都中止新 generation，Agent 保留 last-good。
- **L4 中转边界：** iptables、nftables、Realm、socat、GOST、Nginx 六种本地转发方式只连接公开 endpoint，不接收代理凭据。引用规则固定 TCP，禁止向上游发送 PROXY Protocol 或其他前置字节；iptables/nftables 只使用既有受控 DNS 物化结果，不接收凭据或任意命令。派生链接只替换规范 authority，不能改写 SNI、公钥、flow、method 或认证信息。
- **引用完整性：** 被引用定义不可删除或替换端点/凭据。规则/Xray 绑定 mutation 在相同锁和事务内再次校验引用；不能依赖前端禁用。普通用户无出口节点查询权限，也不能通过规则 mutation 猜测 id 获得存在性差异。

## 16. DNSPod 与快速配置安全边界

- **账号密钥：** DNSPod SecretId/SecretKey 只能由管理员提交到独立 provider account mutation，使用不可变 `accountTag + secret kind` 绑定的版本化 AEAD envelope 保存；HMAC fingerprint 只绑定 envelope version、资源类型和 kind，不修改既有通用 fingerprint 算法。不得写入既有 DDNS 明文设置、环境回显、普通 DTO、审计 diff、operation metadata、日志、错误、支持包、浏览器缓存或 Agent payload；未配置面板主密钥时功能 fail closed。
- **验证后提交：** 新账号或凭据轮换必须先在内存中调用固定 DNSPod 验证与 zone 同步，成功后才在单一数据库事务中写密文和 global binding；失败不得留下半个账号或替换现有有效凭据。成功验证最多有效 24 小时，过期或随后 provider 认证失败时禁止新的 check/preview/apply；已有 DNS 与数据面不被主动删除。账号、binding 或 zone 被活动快速配置引用时禁止直接删除、禁用或换绑。
- **固定外连面：** provider client 只允许 TLS 连接固定 DNSPod API host、service、version 和批准 action，不接受管理员 URL、region、代理、header、path、重定向或任意请求 JSON。设置连接/总超时、有界重试与退避、请求/响应体上限、分页条数和总页数；严格校验状态码、Content-Type、JSON schema、RequestId 长度和 provider 错误码，原始响应及签名 canonical request 不进入日志。
- **TC3 签名与时钟：** SecretKey 只在单次服务端请求内解密并尽快丢弃；签名使用固定算法和 header allowlist，拒绝超出允许时钟偏差的重放。不得把签名、Authorization、SecretId、派生 signing key 或完整响应附入错误、追踪或测试快照。
- **域名与记录输入：** zone 必须来自当前全局账号的实时列表；相对主机名只允许规范 DNS labels 和受限总长度，拒绝 `@`、通配符、URL、端口、路径、控制字符、Unicode 混淆和越界 punycode。记录值只由已验证的受管 host 公网 IPv4/IPv6 或已批准的落地地址生成，浏览器不能提交任意地址；TTL、线路、record type 和其他 provider 字段使用服务端 allowlist。
- **同名冲突确认：** 检查与提交分离。短期确认 token 必须绑定管理员、账号、zone、FQDN、规范远端记录摘要、quick-config revision 和过期时间，并以服务端 MAC 防篡改；输入或远端记录变化后拒绝。最终 apply 必须以持久、唯一的 domain claim 防止多进程同时取得相同 FQDN。A/AAAA 只有在最终确认和提交时按展示集合替换，CNAME 只可经明确确认删除并进入补偿快照，TXT/MX/CAA 及未知类型绝不修改。
- **记录所有权：** 面板只可修改/删除本地持有的 provider recordId 且远端 zone/FQDN/type/line/value/TTL 与最近确认 tuple 一致的记录。recordId 缺失、已被第三方改写或响应不一致时标记 `DRIFTED/PARTIAL_FAILURE` 并停止破坏性补偿；禁止按同名批量删除。替换快照只保存恢复所需的固定非敏感字段、数量有上限，并在恢复前再次比对远端状态。
- **IP 与 SSRF 边界：** host 地址候选必须从服务端数据库读取、规范化并确认是可公开解析的单播 IPv4/IPv6；拒绝 loopback、private/ULA、link-local、multicast、unspecified、documentation/benchmark、CGNAT、metadata 和面板内部地址。DNSPod 响应中的域名、记录值或错误内容不得驱动面板向任意地址发起 HTTP/TCP 请求；端口探测只发送给已鉴权的在管 Agent。
- **双网络端口门禁：** 面板全局唯一性不区分 TCP/UDP，因此候选和回收都必须分别获得 TCP 与 UDP 单端口探测的有效 `FREE` 结果。离线、旧 Agent 不支持、超时、结果过期或 schema 不完整都按不空闲处理。结果只含 host/network/port/稳定状态，不暴露 PID、进程名、socket、命令输出或远端错误文本。
- **目标别名与重检：** 受管 Xray 原端口的 probe 豁免只能由服务端根据当前目标 inbound 派生，必须同时绑定精确端口、ACTIVE `XRAY_INBOUND` owner 和同主机公开 owning reference，并在创建、派发前与结果接受时以单条关联查询重验；浏览器和 Agent 均不能声明 owner 或 allocation。重检只接受上一轮规范 Base64URL 编码的签名 probe result token，不接受裸 reservation ID 或解码后字节相同的变体；先验证管理员、confirmed domain、目标版本及全部 host/network reservation，再批量释放，任一错配零释放。token 只在组件内存存在并继承 no-store 边界。
- **并发与租约：** 端口唯一性由数据库唯一键、乐观 version 和持久引用共同保证，不依赖单进程 Map。reservation token 只存不可逆摘要并有短 TTL；过期、进程崩溃或补偿中断后进入 `PENDING_SCAN`。`FREE` 到 `RESERVED`、引用增删和状态转换都必须在同一数据库事务内重验，禁止 ABA 重用。12 小时扫描用数据库 CAS 租约防重叠，并在释放事务中重验全部引用、allocation version、受管 host cohort 和每台 host 的双网络结果；扫描期间新增 host 或引用会使本轮结论失效。
- **编排补偿：** apply 必须先确认所有 Realm 规则，再发布 DNS；remove 必须先撤销/恢复 DNS，再停止规则。每个外部动作使用稳定幂等键和持久步骤，数据库事务不得宣称包含 Agent 或 DNSPod。补偿只撤销本 operation 明确拥有且未漂移的对象；无法证明安全时保留规则和端口引用、返回稳定 `PARTIAL_FAILURE` 与具体脱敏错误码，不能为了“清理干净”覆盖第三方 DNS 或提前复用端口。
- **普通规则联动：** 快速配置生成的 Realm listener 是正式 `forward_rules`，继续受现有管理员鉴权、Agent allowlist、命令生成和审计约束。直接规则 mutation 必须拒绝会造成 DNS 漂移的编辑、停用或删除；不得通过去掉 UI 按钮、伪造普通规则或隐藏第二套配置绕过编排。
- **派生连接材料：** 受管 Xray 分享、外部 VLESS/SS 链接和 SOCKS endpoint 只在管理员按需响应中重建，整体设置 `private, no-store`；只替换 authority，保留原 SNI/public key/flow/method/凭据。快速配置表、DNS 记录、operation、规则备注和浏览器持久存储不得保存完整材料。
- **备份与轮换：** 三类 provider/quick-config/port 表全部进入结构化备份；provider secret envelope 进入加密备份预检和主密钥轮换。原始数据库备份仍需独立主密钥，结构化普通导出不含 secret。恢复后在任何 DNS 写入前重验 envelope、账号绑定、operation phase、记录所有权和端口引用；无法解密时返回 `SENSITIVE_DATA_UNAVAILABLE`，不得生成新凭据或继续补偿。

## 17. 六引擎快速配置安全边界（TASK058）

- **能力交集：** engine 只来自共享 `FORWARD_TYPES` 六项 allowlist。服务端在目录、port check、preview 和 apply/edit 消费点都按全部 `hostId + addressFamily` 重算系统开关、公开地址和 Agent 版本/capability；旧 Agent 或缺字段取 false。浏览器不能提交 capability、命令、配置文本、二进制路径、运行时探测结果或“可用”布尔值。
- **最小披露：** 目录只返回 engine、固定 label、默认标记、eligible 和稳定禁用码；不返回 Agent 版本、原始 capability、主机内部地址、安装路径、服务状态原文或探测输出。缺能力和未知 host 不得产生可用于枚举运行时细节的差异错误。
- **固定规则面：** 六种 engine 都只能创建普通 TCP `forward_rules`，目标由服务端从已绑定落地资源解析，PROXY Protocol 双向固定关闭。iptables/nftables 不接受任意规则片段，进程型 engine 不接受任意 argv/unit/config；Agent 继续只执行现有受控生成路径。
- **单引擎与回滚：** 同一 topology 和端口只允许一种 engine。切换先持久化旧安全快照和步骤，再确认旧 owner 清理后应用新 owner；失败恢复旧 engine。无法证明任一 host 已清理或恢复时保持端口与规则引用并进入部分失败，禁止并存抢占、释放端口、切换 DNS或静默回退 Realm。
