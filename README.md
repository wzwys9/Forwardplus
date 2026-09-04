# Forwardplus 转发与 Xray 管理面板

[![CI](https://github.com/wzwys9/Forwardplus/actions/workflows/ci.yml/badge.svg)](https://github.com/wzwys9/Forwardplus/actions/workflows/ci.yml)
[![Docs](https://github.com/wzwys9/Forwardplus/actions/workflows/docs.yml/badge.svg)](https://wzwys9.github.io/Forwardplus/)
[![License](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Forwardplus 基于 [ForwardX](https://github.com/poouo/Forwardx) 二次开发，通过轻量 Agent 集中管理多台 Linux 服务器上的端口转发、加密隧道、转发链、故障转移和受管 Xray 服务。项目包含 React 管理面板、Express/tRPC 服务端、Go Agent 与 Go FXP 隧道运行时。

面板不保存主机 SSH 密钥。Xray、DNSPod 和外部出口节点的敏感材料由服务端加密保存，不会通过普通列表接口返回。

## 链接

- [使用文档](https://wzwys9.github.io/Forwardplus/)
- [GitHub Releases](https://github.com/wzwys9/Forwardplus/releases)
- [更新日志](CHANGELOG.md)
- [问题反馈](https://github.com/wzwys9/Forwardplus/issues)

## 主要功能

- 创建 TCP、UDP 或 TCP+UDP 转发规则，支持 `iptables`、`nftables`、`Realm`、`Socat`、`GOST` 和 `Nginx`。
- 管理 GOST、ForwardX V1/V2 和 Nginx Stream 隧道，支持多跳、入口组、出口组和多出口。
- 使用转发链组织固定入口、中转与出口路径，使用转发组实现多入口复用和故障转移。
- 管理主机状态、规则流量、延迟趋势、链路图、自测结果、系统日志和批量任务。
- 管理用户权限、端口与流量额度、套餐、余额、兑换码、折扣码及支付通道。
- 提供邮件、Telegram 通知、插件系统、Android 客户端和面板/Agent 更新。
- 集中管理受管 Xray 节点、客户端、TLS 证书、运行环境及独立代理服务。
- 支持导入 VLESS Reality Vision、Shadowsocks、SOCKS5 外部出口，并绑定到 Xray 节点或六种 TCP 转发引擎。
- 支持 DNSPod 全局账号、运营商线路解析、IPv4/IPv6 入口选择、全局端口分配和出口快速配置。

## 资源模型

链路资源在「链路管理」中创建，业务入口端口与目标在「转发规则」中配置；Xray 相关资源统一在「Xray 管理」中维护。

| 资源 | 典型路径 | 适用场景 |
| --- | --- | --- |
| 端口转发 | 用户 → 单台主机 → 目标 | 单台入口可以直接访问目标 |
| 隧道 | 用户 → 入口 → 隧道 → 出口 → 目标 | 入口与出口不同，或需要加密传输 |
| 转发链 | 用户 → 入口 → 多级中转 → 出口 → 目标 | 固定多跳路径 |
| 转发组 | 多个入口 → 同一目标 | 多入口复用、故障转移和 DDNS |
| Xray 节点 | 客户端 → 受管 Xray inbound → direct/外部出口 | 类型化代理节点与出口路由 |
| 快速配置 | 运营商 DNS → 多入口规则 → Xray/外部落地 | 自动编排 DNS、端口和转发规则 |

入口组用于复用多台入口主机，出口组用于复用多个隧道出口。同一链路资源可以被多条规则引用；快速配置创建的规则也会出现在原有链路与转发规则界面中。

## 快速部署

面板默认访问端口为 `9810`。以下命令请使用 `root` 执行；普通用户可在管道后的 `bash` 前增加 `sudo`。

### Docker Compose

安装：

```bash
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-docker.sh" | bash -s -- install'
```

升级：

```bash
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-docker.sh" | bash -s -- upgrade'
```

卸载：

```bash
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-docker.sh" | bash -s -- uninstall'
```

Docker 默认拉取 `ghcr.io/wzwys9/forwardplus:latest`。数据库配置和 SQLite 数据保存在数据卷中；升级会保留 `.env`、数据卷和业务数据，卸载只有在用户明确确认后才会清理持久数据。

### 从原版 ForwardX 迁移

原版 ForwardX 已经安装并保留现有数据库时，执行专用迁移动作；脚本会先显示检测到的原面板镜像/版本，再切换到 Forwardplus，并在旧 Agent 后续心跳时自动下发 Forwardplus Agent：

```bash
# Docker Compose
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-docker.sh" | bash -s -- migrate-forwardx'

# 本地 systemd
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-local.sh" | sudo bash -s -- migrate-forwardx'
```

迁移不伪造版本号：面板和主机页仍显示 Agent 的真实版本，并额外显示发行来源。来源不是 `Forwardplus` 的 Agent 即使版本更高也会被识别为待迁移；完成迁移后，面板、Agent 安装脚本、Release 和容器镜像均只使用 `wzwys9/Forwardplus` 更新源。原部署没有显式配置 Xray 功能开关时，迁移会自动启用 Xray 管理入口；已有开关设置会保留原有启停语义。迁移前仍建议备份数据库和 Xray 主密钥。

### 本地 systemd

安装：

```bash
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-local.sh" | sudo bash -s -- install'
```

升级与卸载：

```bash
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-local.sh" | sudo bash -s -- upgrade'
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-local.sh" | sudo bash -s -- uninstall'
```

默认安装目录为 `/opt/forwardx-panel`，服务名为 `forwardx-panel.service`，数据目录为 `/opt/forwardx-panel/data`。

详细部署、反向代理和数据库配置参见[部署面板](https://wzwys9.github.io/Forwardplus/guide/deploy-panel.html)。

## 首次使用

1. 打开 `http://服务器IP:9810`。
2. 选择 SQLite、MySQL 或 PostgreSQL 并完成初始化。
3. 创建首个管理员，或使用已有数据库中的管理员登录。
4. 在「系统设置」中填写面板公开地址。
5. 在「主机管理 → Token 管理」创建一次性 Agent Token。
6. 复制面板生成的安装命令到目标 Linux 主机执行。
7. 确认 Agent 在线后，创建链路资源、转发规则或 Xray 节点。

Agent 安装命令由面板按照当前公开地址和 Token 生成，形式如下：

```bash
curl -fsSL https://你的面板地址/api/agent/install.sh | bash -s -- install YOUR_AGENT_TOKEN
```

不要把真实 Agent Token 放进 README、工单、截图或公开日志。安装完成后可以在面板中撤销对应 Token。

## Xray 管理

Forwardplus 使用服务端控制的类型化 profile 生成完整 Xray 配置，不开放任意 JSON 或任意 Shell。当前已实现的范围包括：

- VLESS、Trojan、VMess、Shadowsocks、Hysteria 2、WireGuard、认证 HTTP、Mixed 和固定目标 Tunnel profile。
- RAW、mKCP、WebSocket、gRPC、HTTPUpgrade、XHTTP 等已经验证并由 profile 开放的传输组合。
- Reality、TLS、Vision、客户端凭据、证书和分享链接管理。
- MTProto 与 AmneziaWG userspace 独立受管服务。
- VLESS Reality Vision、Shadowsocks、SOCKS5 外部出口节点导入与引用。
- DNSPod 快速配置：域名检查、默认/电信/联通/移动/教育网线路、IPv4/IPv6 入口、端口冲突检查及规则编排。

Xray 配置以面板数据库为唯一权威来源。每次变更按主机生成带 `generation` 和 `configHash` 的完整快照，Agent 验证成功后原子切换；失败时保留最近一次可用配置。当前不支持 TUN，也不提供任意路由、fallback、sniffing、订阅或 Xray 节点流量限额。

## 隧道类型

| 类型 | 说明 |
| --- | --- |
| GOST | TLS、WSS、TCP、MTLS、MWSS、MTCP 等传输模式 |
| ForwardX V1 | FXP 加密传输，兼容既有部署 |
| ForwardX V2 | Agent 内置 userspace WireGuard 外层 UDP，内层继续使用 FXP |
| Nginx Stream | 独立 `forwardx-nginx` 四层 TCP/UDP 转发，TCP 可配置 TLS |

ForwardX V2 不要求系统安装 `wg`，不会创建系统 WireGuard 网卡或修改主机路由。使用 UDP 隧道时仍需在防火墙与安全组中放行对应端口。

## GitHub 下载加速

访问 GitHub 不稳定时，可以给安装脚本添加加速地址：

```bash
curl -fsSL "https://mirror.example.com/https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-docker.sh" \
  | bash -s -- install --github-accelerator "https://mirror.example.com"
```

安装器会把加速地址保存到部署 `.env`，后续升级继续使用；失败时自动回退 GitHub 直连。该设置不代理 `ghcr.io`，Docker 镜像源需通过 `FORWARDX_IMAGE` 或 `FORWARDX_IMAGE_REPO` 单独配置。

公开仓库无需 GitHub Token。请求频率较高时，可在服务端配置最小只读权限的 `FORWARDPLUS_GITHUB_TOKEN`，仅用于提高 GitHub API 限额。

## 数据库

Forwardplus 支持 SQLite、MySQL 和 PostgreSQL：

- SQLite 适合单机部署，默认文件为 `/data/forwardx.db`。
- MySQL 和 PostgreSQL 适合已有独立数据库运维的环境。
- 原地升级会保留数据库配置和业务数据。
- Xray 与 DNSPod 敏感数据备份需要同时保存面板主密钥，推荐使用面板的密码加密完整备份。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `9810` | 面板访问端口 |
| `DATABASE_CONFIG_PATH` | `/data/database.json` | 数据库连接配置文件 |
| `SQLITE_PATH` | `/data/forwardx.db` | SQLite 数据文件 |
| `DATABASE_TYPE` / `DB_TYPE` | 空 | 指定 `sqlite`、`mysql` 或 `postgresql` |
| `JWT_SECRET` | 自动生成 | 登录签名密钥，生产环境应固定配置 |
| `TELEGRAM_BOT_TOKEN` | 空 | Telegram 机器人 Token |
| `FORWARDX_IMAGE` | `ghcr.io/wzwys9/forwardplus:latest` | Docker 镜像 |
| `FORWARDPLUS_GITHUB_TOKEN` | 空 | 可选，只读 GitHub Token |
| `FORWARDPLUS_MIGRATE_AGENTS` | `false` | 仅由 `migrate-forwardx` 写入；让来源不匹配的 Agent 重连后自动迁移 |
| `FORWARDX_XRAY_ENABLED` | `1` | Xray 管理入口开关；旧迁移部署首次升级到当前策略时自动开启，之后显式设置为关闭值会在升级中保留 |
| `FORWARDPLUS_XRAY_UI_POLICY_VERSION` | `1` | Xray UI 默认开启策略的内部迁移标记，通常无需手工修改 |

更多变量见[环境变量文档](https://wzwys9.github.io/Forwardplus/guide/env-vars.html)。

## 本地开发

环境要求：Node.js 22、pnpm 10；构建 Agent 和 FXP 时还需要 Go 1.25。

```bash
git clone https://github.com/wzwys9/Forwardplus.git
cd Forwardplus
corepack enable
corepack pnpm install --frozen-lockfile
cp .env.example .env
corepack pnpm dev:panel
```

关键检查：

```bash
corepack pnpm check:versions
corepack pnpm exec tsc --noEmit
corepack pnpm test:server
corepack pnpm build
corepack pnpm docs:build
(cd agent && go test ./... && go vet ./...)
(cd forwardx-fxp && go test ./... && go vet ./...)
```

仓库没有总入口 `pnpm test`。开发与贡献约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 安全建议

- 固定配置随机 `JWT_SECRET`，使用强管理员密码和 HTTPS。
- 不需要公开注册时，在系统设置中关闭注册入口。
- MySQL/PostgreSQL 使用独立账号并授予最小权限。
- 妥善保存 Agent Token、DNSPod Secret 和 Xray 密钥，泄露后立即撤销或轮换。
- `.env`、`vps*.txt`、数据库、日志、API Key、私钥和签名文件不得提交。
- 定期备份数据库、面板数据目录和 Xray 面板主密钥。

## License 与来源

Forwardplus 基于 ForwardX 修改，继续使用 [GNU Affero General Public License v3.0 only](LICENSE)。通过网络向用户提供修改后的服务时，请遵守 AGPL 对应源代码提供义务。

第三方组件、许可证和数据来源见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。ForwardX Agent 中的第三方 userspace WireGuard 实现按其 MIT License 使用。
