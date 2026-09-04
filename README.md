# Forwardplus

Forwardplus 是基于 [ForwardX](https://github.com/poouo/Forwardx) 二次开发的多主机端口转发、隧道和 Xray 节点管理面板。项目包含 React 管理界面、Express/tRPC 服务端、Go Agent，以及 Go FXP 隧道运行时。

本仓库公开发布，安装脚本和 Release 可匿名访问。Agent 安装仍优先使用面板自带接口，以便安装来源与当前面板版本保持一致。

## 主要功能

- 多主机 Agent 管理、在线状态、流量统计和批量操作
- Realm、Gost 等端口转发与链路管理
- FXP 隧道、转发组、入口组和出口组
- Xray 入站、外部出口节点、快速配置和 DNSPod 联动
- SQLite、MySQL、PostgreSQL 数据库支持
- Docker、Linux systemd 和 Android 客户端构建

## 环境要求

- Node.js 22
- pnpm 10（建议通过 Corepack 使用）
- Go 1.25（构建 Agent 和 FXP 时需要）
- Linux 生产服务器建议使用 root 或 sudo

## 获取代码

直接克隆公开仓库：

```bash
git clone https://github.com/wzwys9/Forwardplus.git
cd Forwardplus
```

## 本地开发

```bash
corepack enable
corepack pnpm install --frozen-lockfile
cp .env.example .env
corepack pnpm dev:panel
```

开发面板默认使用 `http://localhost:5173`，后端默认使用 `http://localhost:3000`。首次打开面板后按向导创建管理员账号。

生产环境必须把 `.env` 中的 `JWT_SECRET` 改为足够长的随机值，例如：

```bash
openssl rand -hex 32
```

## 生产部署

### 使用本地安装脚本

发布版本及面板构建产物后，可直接运行公开安装脚本：

```bash
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-local.sh" | sudo bash -s -- install'
```

升级和卸载：

```bash
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-local.sh" | sudo bash -s -- upgrade'
bash -o pipefail -c 'curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-panel-local.sh" | sudo bash -s -- uninstall'
```

### Docker

当 `ghcr.io/wzwys9/forwardplus` 包设置为 Public 后，可以匿名拉取：

```bash
cp .env.example .env
docker compose up -d
```

默认镜像为 `ghcr.io/wzwys9/forwardplus:latest`。首次发布镜像后，还需在 GitHub Packages 中确认该包的可见性为 Public。请在 `.env` 中设置随机 `JWT_SECRET`。

## 添加主机 Agent

先在面板的“主机管理/安装 Token”中生成一次性 Token。Forwardplus 会生成面板优先的安装命令，形式如下：

```bash
bash -c 'set -o pipefail; curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 60 "https://YOUR_PANEL/api/agent/install.sh" | PANEL_URL='\''https://YOUR_PANEL'\'' FORWARDX_AGENT_PANEL_FIRST=true bash -s -- install YOUR_AGENT_TOKEN'
```

不要把真实 Agent Token 写进 README、工单或公开日志。安装完成后可在面板中撤销安装 Token。

代码中的 GitHub 备用地址已改为：

```text
https://raw.githubusercontent.com/wzwys9/Forwardplus/main/scripts/install-agent.sh
```

该 Raw 地址可匿名访问，但正常安装仍优先使用面板的 `/api/agent/install.sh`，Raw 地址作为面板安装接口不可用时的备用来源。

## 更新检查

面板的仓库地址、Release、Tag、主分支版本检查和默认镜像已切换到 `wzwys9/Forwardplus`。公开仓库无需 Token；如检查频率较高，可在生产面板的 `.env` 中配置只读 Token，以提高 GitHub API 限额：

```bash
FORWARDPLUS_GITHUB_TOKEN=github_pat_replace_me
```

Token 只配置在服务端，建议限制到 `wzwys9/Forwardplus` 且仅授予 `Contents: read`。修改 `.env` 后重启面板。未配置 Token 时，面板使用 GitHub 匿名 API 限额，现有 Agent 数据面不受影响。

每次发布新版本时应同步更新版本常量、创建 `vX.Y.Z` Release，并由 GitHub Actions 构建面板、Agent、FXP、Android 和 Docker 资产。

## 关键检查

```bash
corepack pnpm check:versions
corepack pnpm exec tsc --noEmit
corepack pnpm build
(cd agent && go test ./... && go vet ./...)
(cd forwardx-fxp && go test ./... && go vet ./...)
```

仓库没有总入口 `pnpm test`。服务端测试使用：

```bash
corepack pnpm test:server
```

## 安全说明

- `.env`、`vps*.txt`、数据库、日志、API Key、私钥和签名文件均不应提交。
- Android Release 必须通过 GitHub Secrets 注入签名材料；仓库不提供签名私钥兜底。
- 可选的 `FORWARDPLUS_GITHUB_TOKEN` 只应配置在服务端，并使用最小只读权限。
- 推送前建议检查 `git status`，并执行一次敏感信息扫描。

## 许可证与来源

本项目基于 ForwardX 修改，继续遵循 [GNU Affero General Public License v3.0](LICENSE)。第三方组件和数据来源见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 及各插件目录中的说明。
