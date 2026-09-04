# Forwardplus

Forwardplus 是基于 [ForwardX](https://github.com/poouo/Forwardx) 二次开发的多主机端口转发、隧道和 Xray 节点管理面板。项目包含 React 管理界面、Express/tRPC 服务端、Go Agent，以及 Go FXP 隧道运行时。

本仓库为私有仓库：GitHub Raw、Releases 和 GHCR 镜像默认都不能匿名访问。生产部署应配置最小权限的 GitHub Token，Agent 安装则优先使用面板自带的安装接口。

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

先安装并登录 GitHub CLI，然后克隆私有仓库：

```bash
gh auth login
gh repo clone wzwys9/Forwardplus
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

创建 GitHub Release 并上传面板构建产物后，可使用仅有本仓库 `Contents: read` 权限的 [fine-grained token](https://docs.github.com/rest/releases/assets#get-a-release-asset) 安装：

```bash
export FORWARDPLUS_GITHUB_TOKEN="YOUR_FINE_GRAINED_CONTENTS_READ_TOKEN"
sudo --preserve-env=FORWARDPLUS_GITHUB_TOKEN \
  bash scripts/install-panel-local.sh install
unset FORWARDPLUS_GITHUB_TOKEN
```

升级和卸载：

```bash
export FORWARDPLUS_GITHUB_TOKEN="YOUR_FINE_GRAINED_CONTENTS_READ_TOKEN"
sudo --preserve-env=FORWARDPLUS_GITHUB_TOKEN bash scripts/install-panel-local.sh upgrade
unset FORWARDPLUS_GITHUB_TOKEN
sudo bash scripts/install-panel-local.sh uninstall
```

### Docker

私有 GHCR 镜像需要先使用带 `read:packages` 权限的 [classic personal access token](https://docs.github.com/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-to-the-container-registry) 登录：

```bash
export GHCR_TOKEN="YOUR_CLASSIC_PAT_WITH_READ_PACKAGES"
echo "$GHCR_TOKEN" | docker login ghcr.io -u wzwys9 --password-stdin
unset GHCR_TOKEN

cp .env.example .env
docker compose up -d
```

默认镜像为 `ghcr.io/wzwys9/forwardplus:latest`。请在 `.env` 中设置随机 `JWT_SECRET`；若需要面板检查私有仓库更新，再设置 `FORWARDPLUS_GITHUB_TOKEN`。

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

由于 `Forwardplus` 是私有仓库，该 Raw 地址不能匿名访问，所以它只作为备用来源。正常安装应优先使用面板的 `/api/agent/install.sh`。

## 私有仓库更新检查

面板的仓库地址、Release、Tag、主分支版本检查和默认镜像已切换到 `wzwys9/Forwardplus`。在生产面板的 `.env` 中配置：

```bash
FORWARDPLUS_GITHUB_TOKEN=github_pat_replace_me
```

建议创建仅允许访问 `wzwys9/Forwardplus`、且只有 `Contents: read` 权限的 fine-grained token。修改 `.env` 后重启面板。没有 Token 时，私有仓库的更新检查和 Release 资产回退下载会失败，但面板与现有 Agent 数据面不会因此停止。

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
- `FORWARDPLUS_GITHUB_TOKEN` 只应配置在服务端，并使用最小只读权限。
- 推送前建议检查 `git status`，并执行一次敏感信息扫描。

## 许可证与来源

本项目基于 ForwardX 修改，继续遵循 [GNU Affero General Public License v3.0](LICENSE)。第三方组件和数据来源见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 及各插件目录中的说明。
