# 受管 Xray 节点

ForwardX 第一版受管 Xray 供管理员在已连接的 Agent 主机上创建 VLESS + Reality 节点、管理多个客户端，并由 Agent 安装和监管独立的 Xray 运行时。

## 支持范围

| 项目 | 第一版支持 |
| --- | --- |
| 协议 | VLESS + Reality + TCP/RAW + XTLS Vision |
| Xray | 固定 Xray-core `v26.3.27`，不跟随 `latest` |
| Agent 主机 | Linux `amd64`、Linux `arm64`，需 systemd 或等价的受管服务生命周期 |
| 数据库 | SQLite、MySQL、PostgreSQL |
| 权限 | 仅管理员；普通用户看不到入口，接口也会拒绝访问 |
| 监听地址 | Agent 上的 `0.0.0.0` TCP；分享地址使用主机公网 IPv4 |

第一版不支持任意 Xray JSON、其他代理协议或传输、客户端流量统计、普通用户自助管理，也不管理主机防火墙或云安全组。

## 启用功能

Xray 管理界面由 `FORWARDX_XRAY_ENABLED` 保护。新安装和普通升级默认关闭；使用 `migrate-forwardx` 从原版迁移时，如果原部署没有显式设置该变量，安装器会自动写入 `1`，后续升级继续保留。已有显式设置优先，不会把管理员主动关闭改为开启。只有字符串 `1`、`true` 或 `on`（忽略大小写和首尾空白）会启用；未配置、拼写错误或公共设置读取失败都保持关闭。

Docker 部署在部署目录 `.env` 中加入：

```dotenv
FORWARDX_XRAY_ENABLED=1
```

本地 systemd 部署在 `/opt/forwardx-panel/.env` 加入同一行，然后重启面板。开关只控制管理员 UI 入口，不替代服务端管理员鉴权。

升级旧面板时该开关不会自动打开，也不会改写已有转发配置。旧 Agent 没有 Xray v1 capability 时会显示“需要升级 Agent”，不会收到 Xray 安装或配置；新 Agent 对旧面板保持向后兼容。建议先升级面板，再逐台升级 Agent，确认能力和制品状态后启用开关。

生产面板在数据库就绪后会自动把固定 `v26.3.27` 的 Linux `amd64`、`arm64` 制品缓存到面板持久数据目录并完成校验。Agent 安装 Xray 时只从面板的受鉴权接口下载，不需要也不会改为直连 GitHub；若上游暂时不可用，面板本身仍可登录，制品保持缺失状态并在下次面板启动时重试。

## 创建节点

启用后，管理员进入“Xray 节点 → 节点管理”，按页面步骤完成：

1. 选择 Agent 在线、心跳新鲜、平台受支持且制品可用的主机。
2. 使用自动探测或手动候选端口。自动范围固定为 `1000–65535`；探测只表示当时可以 bind，不能消除提交后的端口竞态。
3. 选择经目标 Agent 检查的公网 Reality 目标和 serverName。私网、回环、链路本地、保留地址和云元数据地址会被拒绝。
4. 添加一个或多个初始客户端，核对部署摘要后提交。
5. 等待按需安装、配置校验、运行时启动和 listener 检查完成。页面刷新后仍可通过 operation 继续查看进度。

如果端口在探测后被其他程序抢占，部署会以稳定错误码失败；ForwardX 不会终止占用端口的进程。请选择新端口重试。

## 防火墙和公网访问

ForwardX 不修改 iptables、nftables、ufw、firewalld 或云安全组。创建成功只证明受管 Xray 已在 Agent 主机监听，管理员仍需自行放行对应 TCP 端口，并确认 NAT、云防火墙和运营商网络允许外部访问。

排查时先在主机确认 listener，再从真正的外部网络测试。不要把“Agent bind 成功”当作公网一定可达。

## 客户端和分享

节点详情可以新增、重命名、启停和删除多个独立客户端。单个客户端变更不会轮换其他客户端的 UUID 或 shortId。

分享 URI 和二维码只在管理员主动打开分享对话框时生成；响应禁止缓存，关闭后会从页面内存清除。分享材料属于凭据，不要放进工单、日志、URL、浏览器存储或公开聊天。Reality 服务端私钥不会出现在 URI 或普通页面。

删除或停用在新的 generation 被 Agent 成功应用前仍可能在远端有效。页面显示“待同步/待删除”时，不应向使用者声称凭据已经失效。

## 运行环境、升级和回滚

“Xray 节点 → 运行环境”展示主机的已装/运行版本、配置同步状态、制品状态和持久 operation。安装、升级、重启、同步都要求逐字输入主机名确认。

- 普通“同步”只重新生成配置，不承担版本升级，也不会降级更高版本。
- 升级先把新二进制写入独立目录，校验制品和目标配置后才原子切换。
- 新版本启动、配置测试或 listener 检查失败时，Agent 保留或恢复 last-good 配置和旧二进制。
- 删除最后一个 inbound 会停止受管 Xray，但保留已验证二进制，便于后续重新启用。

受管文件使用 ForwardX 专属路径，不覆盖系统已经安装的 Xray：

| 用途 | 路径 |
| --- | --- |
| Agent Xray 状态和版本 | `/var/lib/forwardx-agent/xray/` |
| 当前配置和 last-good | `/etc/forwardx/xray/` |
| 面板 Xray 主密钥（Docker） | `/data/xray-master.key` |
| 面板 Xray 主密钥（本地） | `/opt/forwardx-panel/data/xray-master.key` |

显式卸载 Agent 会停止并删除 ForwardX 私有目录内的受管 Xray；只删除面板中的主机记录不会远程卸载，远端数据面可能继续运行。

## 离线和 Token 语义

Agent Token 错误、面板不可达、SSE 断开或 Agent 被面板判定离线时，ForwardX 不会主动停止最后一次成功运行的 Xray 数据面。此时页面显示历史/未知状态，并拒绝该主机的所有 Xray 写操作；只读信息仍可查看。

Agent service 自身重启、崩溃或升级时，systemd 默认 cgroup 生命周期允许 Xray 短暂中断。新 Agent 会在联系面板前验证并恢复本地 last-good，避免依赖控制面在线才能恢复。需要在失联时紧急停机，应通过 SSH 停止受管进程或先恢复有效 Agent Token。

## 备份和恢复

推荐使用“系统设置 → 备份与恢复 → 加密数据导出”。密码加密完整备份会在同一个认证加密容器内保存数据库快照、Xray 密文和被安全包装的面板 Xray 主密钥；文件中没有明文密钥或明文客户端凭据。必须同时保管备份文件和备份密码。

只导出原始 SQLite/MySQL/PostgreSQL 数据库时，主密钥不在数据库内，必须通过独立安全渠道备份对应的 `xray-master.key`。只恢复数据库而缺少正确密钥会返回 `SENSITIVE_DATA_UNAVAILABLE`，不会自动生成新凭据冒充恢复成功。

恢复到已有 Xray 密文的面板时，导入只接受完全相同的主密钥；密钥冲突会停止导入且不会覆盖当前密钥。详细步骤见[升级和备份](./upgrade-backup.md)。

## 已知限制

- 只支持固定版本和两种 Linux 架构，不提供自定义制品版本或自动降级。
- 不自动配置防火墙、NAT、域名、证书或云安全组。
- 不提供任意扫描目标网段、任意 Shell 命令或任意 Xray JSON 编辑器。
- 不统计 Xray inbound/client 流量，也不向普通用户开放。
- 面板/Agent 离线不会自动撤销已经下发的客户端凭据；删除必须等待 applied generation 确认。
- 第一版没有主密钥轮换 UI；丢失主密钥后无法恢复既有 Xray 密文。

## 常见故障

| 现象 | 处理 |
| --- | --- |
| 页面没有 Xray 入口 | 确认开关值、重启面板并以管理员登录 |
| 主机灰显 | 升级 Agent，检查心跳、Linux 架构和制品状态 |
| `PORT_IN_USE` | 查明占用者或选择其他端口，不要反复覆盖 |
| `CONFIG_INVALID` / `RUNTIME_NOT_READY` | 查看 operation 的稳定错误阶段；last-good 应仍保留 |
| 分享地址不可达 | 检查主机公网 IPv4、NAT、防火墙和云安全组 |
| `SENSITIVE_DATA_UNAVAILABLE` | 恢复与数据库匹配的 Xray 主密钥，不要重新创建空密钥 |
