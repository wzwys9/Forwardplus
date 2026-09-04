# Xray 面板 API 契约

状态：第一版契约已实施；多协议 additive 契约已批准并按任务增量落地；DNSPod 快速配置、同步与通用记录管理契约已批准。与 `SPEC.md` 0.26 配套。ForwardX 使用 tRPC，本文件描述 procedure、输入输出和错误语义；实现以共享 Zod schema 和类型测试固化。

主机列表、状态摘要和 Agent 升级接口将真实 `agentVersion` 与可空 `agentDistribution`、`agentBuildId` 分开返回。升级候选定义为“来源不是 `forwardplus` 或版本低于面板目标”；单台/批量升级请求写入 `targetDistribution=forwardplus`，只有后续报告同时满足来源和版本才返回完成。来源未知的旧 Agent 不能因为版本较高而绕过 Forwardplus 专有功能门控。

## 1. 通用规则

- 所有 `xray.*` procedure 使用 `protectedProcedure` 并在服务端断言 `ctx.user.role === "admin"`。
- 前端禁用按钮不是权限边界；普通用户直接调用必须返回 `FORBIDDEN`。
- mutation 输入使用 Zod 严格对象、长度/数量/枚举/端口上限和 `.trim()` 规范化。
- 列表输出使用专用 DTO，不 spread 数据库行，避免密文字段泄露。
- 所有需要等待 Agent 或可能超过单次有界 provider 请求的异步操作立即返回 `operationId`，前端查询状态；长任务不保持 HTTP 请求等待 Agent。DNS account 的验证/zone catalog 与 domain check 是首版明确批准的有界同步例外，必须使用固定总超时、分页/响应上限和无重试风暴策略。
- 列表支持分页、搜索和稳定排序；新增字段采用可选扩展，不改变已发布字段类型。
- 机器判断使用 `code`/枚举，中文 `message` 只用于展示。
- Xray mutation 失败沿用 tRPC 标准错误 `data.code`，并在 `data.xrayCode` 返回本文定义的稳定领域错误码；不得让前端解析自由文本。为兼容现有调用，错误 `message` 同时使用同一稳定码，不包含底层错误。

## 2. 通用 DTO

### `XrayInboundSummary`

```ts
type XrayInboundSummary = {
  id: number;
  name: string;
  host: {
    id: number;
    name: string;
    isOnline: boolean;
    lastHeartbeat: Date | null;
  };
  publicAddress?: string; // Tunnel 必须省略；其他 profile 必填
  listenPort: number;
  protocol: "VLESS";
  security: "REALITY";
  clientCount: number;
  desiredEnabled: boolean;
  pendingDelete: boolean;
  deploymentStatus: XrayDeploymentStatus;
  lastErrorCode?: string | null;
  updatedAt: Date;
};
```

`deploymentStatus` 是服务端根据 desired、observed、host liveness 和最近 operation 推导的 DTO，不直接信任单个数据库 `status` 字段：

- `WAITING_SYNC`
- `INSTALLING`
- `APPLYING`
- `RUNNING`
- `DISABLED`
- `PENDING_DELETE`
- `ERROR`
- `HOST_OFFLINE`
- `UNKNOWN`

### `XrayRuntimeSummary`

```ts
type XrayRuntimeSummary = {
  hostId: number;
  hostName: string;
  isAgentOnline: boolean;
  capabilityVersion: number;
  canManageXray: boolean;
  unavailableReasonCode?: string | null;
  installedVersion?: string | null;
  runningVersion?: string | null;
  targetVersion?: string | null;
  serviceStatus: "RUNNING" | "STOPPED" | "ERROR" | "UNKNOWN";
  desiredGeneration: number;
  appliedGeneration: number;
  configInSync: boolean;
  inboundCount: number;
  hasUpgrade: boolean;
  isNewerThanTarget: boolean;
  lastReportedAt?: Date | null;
  lastErrorCode?: string | null;
  lastErrorMessage?: string | null;
};
```

## 3. 主机选择

### `xray.hosts.options`

查询管理员可见主机的 Xray 可用性。返回离线主机，不隐藏，以便 UI 灰显。

输出项：

```ts
type XrayHostOption = {
  id: number;
  name: string;
  publicIpv4?: string | null;
  isOnline: boolean;
  lastHeartbeat?: Date | null;
  capabilityVersion: number;
  os?: string | null;
  arch?: string | null;
  canCreateXrayInbound: boolean;
  unavailableReasonCode?:
    | "AGENT_OFFLINE"
    | "HEARTBEAT_STALE"
    | "AGENT_UPGRADE_REQUIRED"
    | "PLATFORM_UNSUPPORTED"
    | "ARTIFACT_UNAVAILABLE"
    | "PUBLIC_IPV4_MISSING"
    | null;
};
```

所有针对主机运行状态的 Xray mutation 必须重新计算在线、心跳新鲜度和 capability 规则。选择器中曾经可用不代表提交时仍可用；离线时 create/update/setEnabled/remove、客户端写操作、sync、scan、probe、install、upgrade、restart 均返回稳定 API 错误码 `HOST_OFFLINE`，不创建新的排队 desired。`XrayHostOption.unavailableReasonCode` 中的 `AGENT_OFFLINE` 仅为选择器不可用原因，不是 mutation 错误码。

## 4. Inbound procedures

### `xray.inbounds.list`

输入：`page`、`pageSize`、`search`、`hostId?`、`status?`、`isEnabled?`、`sortBy`、`sortOrder`。

输出：`{ items: XrayInboundSummary[], pagination }`。默认按 `updatedAt desc, id desc`，最大 pageSize 100。

### `xray.inbounds.detail`

输入：`{ id: positiveInt }`。

输出包含：

- inbound 非敏感配置。
- Reality 公钥和密钥存在状态，不包含私钥密文。
- 客户端摘要，不包含 UUID/shortId 密文。
- host desired/observed generation/hash。
- 最近相关 operations。

### `xray.inbounds.create`

推荐输入：

```ts
{
  hostId: number;
  name: string;
  publicAddress: string;
  portReservationId: string;
  listenPort: number;
  reality: {
    targetHost: string;
    targetPort: number;
    serverName: string;
    fingerprint: "chrome";
    spiderX: string;
  };
  initialClients: Array<{
    name: string;
    flow: "xtls-rprx-vision";
  }>;
}
```

服务端负责生成 runtimeTag、Reality keypair、UUID、shortId、statsKey；客户端不能提交私钥。

节点名和客户端名均为 trim 后 `1–128` 字符；`initialClients` 必须有 `1–32` 项、名称大小写不敏感去重，第一版 flow 只能为 `xtls-rprx-vision`。`spiderX` 必须以 `/` 开头且最多 256 字符。Reality 目标必须来自同一管理员、同一主机、仍在有效期内且结果重新校验通过的成功 scan，create 不接受仅凭浏览器字段绕过扫描。

流程：校验在线/capability/制品、验证 scan 与 reservation、数据库事务写入全部初始客户端、递增 generation、生成精确 config hash 并创建一个顶层 `SYNC` operation。未安装时同一 operation 先投递 typed `INSTALL` task，状态阶段显示 `INSTALLING`；安装成功前不下发 desired，安装失败则该 operation 以稳定脱敏错误终止。返回 `{ inboundId, operationId, desiredGeneration }`，只有后续 observed 精确确认 generation/hash/version/listener 才进入 `RUNNING/SUCCESS`。

### `xray.inbounds.update`

输入包含 `id`、可变字段和 `expectedUpdatedAt` 或 `expectedGeneration`。只修改提供字段；端口变化需要新的 reservation。

冲突返回 `CONFIG_GENERATION_CONFLICT`，不覆盖另一管理员刚完成的修改。

### `xray.inbounds.setEnabled`

输入 `{ id, isEnabled, expectedGeneration }`，创建新的完整配置 generation。

### `xray.inbounds.remove`

输入 `{ id, expectedGeneration, confirmName }`，`confirmName` 必须逐字匹配当前节点名。先设置 pendingDelete 并下发不含该 inbound 的配置；响应包含 `{ operationId, desiredGeneration, pendingDelete: true, mayRemainActive: true, lastInbound }`，明确说明旧节点在应用完成前可能继续可用。只有 observed 精确确认当前 generation/hash/version/listener 后才清理记录；最后一个 inbound 的目标状态为已安装且 `STOPPED`。

### `xray.inbounds.sync`

输入 `{ id }` 或 hostId 形式的专用 runtime sync。不得接受 configJson；服务端从数据库重新生成当前主机快照。

## 5. Client procedures

### `xray.clients.list`

输入 `{ inboundId }`，输出名称、启用状态、flow、statsKey、凭据掩码、pending 状态和更新时间。

### `xray.clients.create`

输入 `{ inboundId, name, flow, expectedGeneration }`。服务端生成 UUID/shortId/statsKey，递增主机 generation，原子保存新 config hash，返回 `{ clientId, operationId, desiredGeneration }`，不默认在响应体返回 UUID。每个 inbound 最多保留 32 个非 `pendingDelete` 客户端；名称 trim 后 1–128 字符并在同一 inbound 内大小写不敏感去重。

### `xray.clients.update`

输入 `{ id, expectedGeneration, name?, flow?, isEnabled? }`，至少提供一个可变字段。允许修改名称、flow、ownerUserId（第一版 API 不暴露）和启用状态；第一版 flow 固定为 `xtls-rprx-vision`。所有编辑都按数据模型在主机锁和单事务中递增 generation、重算完整 config hash 并创建 `SYNC` operation，客户端 UUID/shortId/statsKey 保持不变。

### `xray.clients.remove`

输入 `{ id, expectedGeneration }`。先标记 `pendingDelete` 并创建排除该客户端的新 generation；响应包含 `pendingDelete: true` 和 `mayRemainActive: true`，不能在未确认前声称客户端已经失效。只有 observed 精确确认当前 desired generation/hash 后才物理删除记录和密文。

### `xray.clients.share`

输入 `{ clientId, format: "VLESS_URI" }`。

输出：

```ts
{
  uri: string;
  displayName: string;
  generatedAt: Date;
  deploymentStatus: XrayDeploymentStatus;
}
```

只允许管理员，设置 `Cache-Control: no-store`，不得写日志。二维码由前端根据 URI 在内存生成，或使用同样 no-store 的专用响应；数据库不保存完整 URI。

第一版 URI 固定为 `vless://<uuid>@<address>:<port>?type=tcp&security=reality&sni=<serverName>&fp=chrome&pbk=<publicKey>&sid=<shortId>&spx=<spiderX>&flow=xtls-rprx-vision#<displayName>`。所有动态 query/fragment 值使用 UTF-8 percent-encoding，裸 IPv6 address 在 authority 中加方括号；只包含 Reality 公钥，不包含服务端私钥。`displayName` 使用该客户端名称。客户端或 inbound 为停用/待删除时仍只读返回当前材料及相应 `DISABLED/PENDING_DELETE` 状态，提醒旧配置是否仍可能有效；应用确认并清理后返回 `CLIENT_NOT_FOUND`。

### `xray.clients.rotateCredentials`

第一版可以推迟；如实现，必须生成新 UUID/shortId、递增 generation，并明确旧链接在应用确认前仍可能有效。

## 6. Port probe procedures

### `xray.portProbes.create`

输入：

```ts
{
  hostId: number;
  mode: "AUTO" | "MANUAL";
  manualPort?: number;
  network?: "TCP" | "UDP";
  replaceReservationIds?: string[];
}
```

`network` 省略时保持兼容并固定为 `TCP`。TCP AUTO 由面板从 `1000–65535` 生成最多 32 个候选；MANUAL 只探测指定端口。UDP 的 AUTO/MANUAL 每个 task 都只发送一个候选，失败后由管理员或有界服务流程重新发起，不能把端口范围交给 Agent。前端不能上传任意候选数组绕过端口策略。

`replaceReservationIds` 是向后兼容的可选数组，只供同一创建向导重新探测时交回当前主/次 reservation，最多两项、必须是互异 UUID。仍有效的每项必须属于当前管理员和 `hostId`，最多各含一项 TCP/UDP，且全部端口相同；MANUAL 时还必须等于 `manualPort`。缺失或过期 ID 按已释放处理，其他错配返回 `PORT_RESERVATION_MISMATCH`，并且任何错配都不能部分释放。全部验证通过后，服务端先释放这些短期预留，再重新执行主机策略、数据库、全局账本和 Agent bind 探测；不携带该字段的既有调用保持原行为。

UDP 请求要求主机最近一次有效 capability 同时明确 `supportsUdpPortProbe=true` 和 `supportsUdpListenerReadiness=true`，否则返回 `UDP_CAPABILITY_REQUIRED` 且不创建 operation。operation metadata、结果和 reservation 都返回规范化 `network`。

返回 `{ operationId }`。

### `xray.portProbes.result`

输入 `{ operationId }`。成功返回 `{ network, selectedPort, reservationId, expiresAt }`。reservation 只供同一管理员/host/network 的 create/update mutation 使用；既有调用省略 network 时只可消费 TCP reservation。

## 7. Reality scan procedures

### `xray.realityScans.create`

输入：

```ts
{
  hostId: number;
  source: "DEFAULT_CANDIDATES" | "ADMIN_DOMAINS";
  targets?: string[];
}
```

服务端规范化并执行 SSRF 策略后创建 Agent task。ADMIN_DOMAINS 数量、长度和端口有上限，不接受 URL/CIDR。

默认候选列表 `v2` 固定为 `www.cloudflare.com:443`、`www.amazon.com:443`、`aws.amazon.com:443`、`www.samsung.com:443`、`www.nvidia.com:443`、`www.amd.com:443`、`www.intel.com:443`、`www.sony.com:443`、`dl.google.com:443`；不再包含 `www.microsoft.com:443`。ADMIN_DOMAINS 统一转为小写、去重，最多 64 项；面板先对每个唯一 host 做有界 A/AAAA 解析并按与 Agent 相同的公网策略预筛，任一禁止/混合地址或每 host 超过 16 个地址均拒绝，Agent 仍必须独立重复安全检查。每台主机最多同时保留 2 个活动扫描 operation。

### `xray.realityScans.result`

返回 operation 状态和结构化候选结果，不返回原始 TLS 数据包或证书全文。
面板只接受与原 operation target 集合完全一致的结果；`resolvedIp` 必须是公网地址或协议规定的 `redacted`/`unresolved`，serverNames 只能包含该 target 的 host。Agent reasonMessage 不持久化，未知 error code 规范化为 `INTERNAL_ERROR`。

## 8. Runtime procedures

### `xray.runtimes.list`

支持分页和 host/status/version 筛选，返回 `XrayRuntimeSummary`。主机页可使用向后兼容的可选 `hostIds`（1–100 个唯一正整数）批量读取当前页简要状态；`hostId` 与 `hostIds` 不得同时提交。

### `xray.runtimes.install`

输入 `{ hostId, targetVersion? }`。检查在线、capability 和对应 artifact，返回 operationId。

### `xray.runtimes.upgrade`

输入 `{ hostId, targetVersion, expectedInstalledVersion }`。如果 Agent 版本更高，默认返回 `DOWNGRADE_NOT_ALLOWED`；第一版不提供 force downgrade。

### `xray.runtimes.restart`

输入 `{ hostId, confirmHostName }`，返回 operationId。只重启受管 Xray，不重启 Agent。

### `xray.runtimes.sync`

输入 `{ hostId }`。重新生成当前 desired snapshot；不允许调用者提交 JSON。

该 procedure 只接受已安装版本与面板固定目标完全一致的主机；旧版本返回 `XRAY_VERSION_MISMATCH` 并要求管理员显式 upgrade，更高版本返回 `DOWNGRADE_NOT_ALLOWED`。因此普通 sync 不会隐式安装、升级或降级。

## 9. Artifact procedures

管理员面板查询：

- `xray.artifacts.list`
- `xray.artifacts.refresh` 或后续确定的受限缓存入口
- `xray.artifacts.setDefaultVersion`

Agent 下载使用单独受 Agent 鉴权的固定 Express route，例如 `/api/agent/artifacts/xray/:artifactId`。该 route：

- 从 authenticated host 的受鉴权下载请求读取 `X-ForwardX-Xray-OS`/`X-ForwardX-Xray-Arch`，只接受 capability 合同允许的平台值，并据此匹配制品；不从展示用的 `osInfo`/`cpuInfo` 文本猜测平台。
- 不接受文件路径或任意 URL。
- 返回精确 Content-Length、ETag/sha256 元数据和 no-store/private 缓存策略。
- 记录 artifactId、hostId、结果和字节数，不记录 Agent Token。

当前清单固定 Xray-core `v26.3.27` 的 `linux-amd64`、`linux-arm64` 制品；面板获取并校验官方归档和 `.dgst`/固定 SHA-256 后再缓存，Agent 不直接访问 GitHub。

## 10. Operation procedures

### `xray.operations.get`

输入 `{ operationId }`，输出状态、阶段、时间、脱敏结果和错误。

阶段示例：

- `QUEUED`
- `PROBING_PORT`
- `DOWNLOADING_ARTIFACT`
- `VERIFYING_ARTIFACT`
- `VALIDATING_CONFIG`
- `SWITCHING_CONFIG`
- `RESTARTING_RUNTIME`
- `CHECKING_LISTENERS`
- `ROLLING_BACK`
- `COMPLETE`

### `xray.operations.list`

按 host、inbound、type、status 分页查询，默认只展示近期记录。

## 11. 稳定 API 错误码

- `FORBIDDEN`
- `HOST_NOT_FOUND`
- `HOST_OFFLINE`
- `HEARTBEAT_STALE`
- `AGENT_CAPABILITY_MISSING`
- `PLATFORM_UNSUPPORTED`
- `ARTIFACT_UNAVAILABLE`
- `PUBLIC_ADDRESS_REQUIRED`
- `PORT_OUT_OF_RANGE`
- `PORT_IN_USE`
- `PORT_RESERVATION_EXPIRED`
- `PORT_RESERVATION_MISMATCH`
- `REALITY_TARGET_INVALID`
- `REALITY_TARGET_BLOCKED`
- `INBOUND_NOT_FOUND`
- `CLIENT_NOT_FOUND`
- `CONFIG_GENERATION_CONFLICT`
- `OPERATION_CONFLICT`
- `XRAY_VERSION_MISMATCH`
- `DOWNGRADE_NOT_ALLOWED`
- `SENSITIVE_DATA_UNAVAILABLE`
- `CERTIFICATE_INVALID`
- `PRIVATE_KEY_INVALID`
- `CERTIFICATE_KEY_MISMATCH`
- `CERTIFICATE_EXPIRED`
- `CERTIFICATE_NOT_YET_VALID`
- `CERTIFICATE_SERVER_NAME_MISMATCH`
- `CERTIFICATE_IN_USE`

tRPC 映射建议：鉴权 `FORBIDDEN`；不存在 `NOT_FOUND`；版本/端口/操作冲突 `CONFLICT`；语义校验 `BAD_REQUEST`；内部错误只返回通用消息并在脱敏日志记录追踪 id。

## 12. 版本和并发

- 同一 host 的配置写入通过 keyed lock 串行化，并在事务中校验 expectedGeneration。
- Agent 任务具有唯一 taskId；重复结果幂等更新同一 operation。
- 页面轮询 operation 时使用退避和 visibility-aware interval，终态停止轮询。
- 删除和密钥轮换不做前端乐观“已生效”展示，必须等待 applied generation。

## 13. 多协议 additive 契约

### `xray.profiles.catalog`

管理员只读查询。输入 `{ hostId?: positiveInt }`，输出由服务端 profile 目录投影的安全描述：

```ts
type XrayProfileSummary = {
  id: string;
  protocol: "VLESS" | "TROJAN" | "VMESS" | "SHADOWSOCKS" | "HYSTERIA2" | "WIREGUARD" | "HTTP" | "MIXED";
  transport: "RAW" | "GRPC" | "WEBSOCKET" | "HTTP_UPGRADE" | "XHTTP" | "MKCP" | "HYSTERIA" | "NONE";
  security: "NONE" | "TLS" | "REALITY";
  clientFlow: "XTLS_RPRX_VISION" | "NONE";
  listenerNetworks: Array<"TCP" | "UDP">;
  clientCredentialType: string;
  shareFormat: string;
  testedCoreVersion: "v26.3.27";
  isAvailable: boolean;
  advisoryCode?: "CORE_DEPRECATED" | "WIREGUARD_BLOCKING_RISK" | "PLAINTEXT_PROXY_AUTH_RISK" | "PLAINTEXT_MIXED_AUTH_RISK" | null;
  unavailableReasonCode?: "NOT_IMPLEMENTED" | "AGENT_UPGRADE_REQUIRED" | "TLS_CERTIFICATE_REQUIRED" | "UDP_CAPABILITY_REQUIRED" | null;
};
```

前端只能显示 `isAvailable=true` 的创建选项；服务端 create 仍独立按 profileId、主机 capability 和固定版本复核，不信任客户端回传的 protocol/transport/security 展示字段。

### `xray.inbounds.createV2`

在旧 `xray.inbounds.create` 保持兼容期间，以 additive procedure 接收：

```ts
{
  hostId: number;
  name: string;
  publicAddress: string;
  portReservationId?: string;
  portReservations?: {
    tcp: string;
    udp: string;
  };
  listenPort: number;
  profileId: string;
  spec: StrictDiscriminatedInboundSpec;
  tlsCertificateId?: number;
  serverName?: string;
  initialAccessEntries: StrictDiscriminatedAccessEntryInput[]; // Tunnel 精确为空
}
```

- 当前接收 `VLESS_RAW_REALITY_VISION + spec={}`、`VLESS_GRPC_REALITY + spec={ serviceName }`、`VLESS_XHTTP_REALITY + spec={ path }` 或 `TROJAN_RAW_REALITY + spec={}`；`profileId` 决定允许的严格 `spec` 变体，未知字段和跨 profile 字段必须拒绝。处于 `IMPLEMENTING` 的 profile 即使输入合同已注册，服务层仍必须拒绝创建，直到固定版本真实连接验收后才进入目录。
- `initialAccessEntries` 当前每项只接受 `{ name }`；UUID/shortId 和 Reality key pair 全由服务端生成。gRPC/XHTTP flow 由 profile 固定为 `NONE`，API 不接收客户端传入的隐藏 flow。
- `TROJAN_RAW_REALITY` 同样只接收账户名称；password 由服务端生成且不在 create 响应返回。后续账户 CRUD/分享使用 additive `xray.accessEntries.*` procedure 和 generic access id，不能把 generic id 当作旧 `xray.clients.*` id。
- TLS profile 必须同时提交 `tlsCertificateId` 和 `serverName`；非 TLS profile 必须省略二者。服务端在端口 reservation 前后分别复核证书同主机、未过期、私钥可解密且 serverName 被 DNS SAN 覆盖。VLESS TLS 与 Trojan TLS 的初始账户仍只接收 `{ name }`，分别由服务端生成 generic-only UUID/password；浏览器不提交 UUID、shortId、password 或 flow。
- TASK048 的 `VMESS_RAW_TLS` 同样只接收空 spec、`tlsCertificateId/serverName` 和 `{ name }` 账户；服务端生成 generic-only UUID v1，不接收 `alterId/aid/security/flow`。`SHADOWSOCKS_2022_RAW_NONE` 只接收空 spec 和 `{ name }`，必须省略 TLS/Reality 字段；服务端生成 inbound PSK 和每账户 PSK，API 不接收 method/key。两项在真实连接验收前都由服务层拒绝创建。
- `HYSTERIA2_TLS` 只接收空 spec、`tlsCertificateId/serverName` 和一个或多个 `{ name }` 账户；服务端生成 generic-only `HYSTERIA_AUTH`，API 不接收 auth、version、ALPN、idle timeout、带宽、obfs、masquerade 或端口范围。端口 reservation 必须是 UDP；profile 已在 050E 真实验收后开放，但 catalog、创建和 desired 下发仍要求主机两项 UDP capability。
- `SHADOWSOCKS_2022_RAW_TCP_UDP_NONE` 与 TCP-only profile 使用相同的严格空 spec、服务端生成双 PSK、无 TLS/Reality 和账户输入，但只接受严格 `portReservations: { tcp, udp }`。两项必须属于同一管理员/主机/端口且分别匹配 TCP、UDP，在业务写入前同时有效；缺项、重复使用同一 reservation、网络/端口不匹配、与 `portReservationId` 混用或能力降级都返回稳定端口/能力错误并保持 generation、业务行和两份 reservation 不变。单网络 profile 必须继续只提交 `portReservationId`。
- `WIREGUARD_UDP_NONE` 只接收严格空 spec、单个 UDP `portReservationId` 和一个或多个 `{ name }` peer；必须省略 TLS/Reality、key、PSK、publicKey、allowedIPs、MTU、DNS、keepAlive、subnet、route 和任意 settings 字段。服务端为 inbound 生成 server private key，为每个 peer 生成 private key/PSK 并在固定 `10.0.0.0/24` 中分配唯一 `/32`；profile 在 051J 真实验收前保持 `IMPLEMENTING`，catalog、create、peer CRUD 与 desired 下发都要求主机两项 UDP capability。
- `HTTP_RAW_NONE` 只接收严格空 spec、单个 TCP `portReservationId` 和一个或多个 `{ name }` 账户；必须省略 TLS/Reality、username、password、transparent、headers、fallback、sniffing、route 和任意 settings 字段。服务端为每项生成独立 username/password，创建失败不得消费 reservation 或留下部分 secret；052E 真实验收已完成，profile 当前为 `AVAILABLE`。
- `MIXED_RAW_NONE` 只接收严格空 spec、单个 TCP `portReservationId` 和一个或多个 `{ name }` 账户；必须省略 TLS/Reality、username、password、auth、udp、ip、transparent、headers、fallback、sniffing、route 和任意 settings 字段。服务端为每项生成独立 username/password，固定 `auth=password/udp=false`；不得接受双网络 reservation。052H 真实验收已完成，profile 当前为 `AVAILABLE`。
- `TUNNEL_TCP_LOCAL_NONE` 只接收 `hostId/name/listenPort/portReservationId`、严格 `spec:{ targetAddress, targetPort }` 和精确空数组 `initialAccessEntries:[]`。必须省略 `publicAddress/listenAddress`、TLS/Reality、账户/凭据、network、portMap、followRedirect、TProxy、sniffing、fallback、route、outbound 和任意 settings；服务端规范化目标并固定保存 `publicAddress/listenAddress=127.0.0.1`。非空账户、未知字段、非 canonical 目标、非 TCP reservation 或尝试双网络 reservation 必须在业务写入前拒绝，且不消费 reservation、不增加 generation。
- 现有 `xray.inbounds.update` 只有单个 `portReservationId`，不得用于修改双网络入站端口；此类请求返回 `INVALID_CONFIG_INPUT` 且不消费预留、不改变 generation。双网络入站的名称、公网地址、启停、删除及账户 CRUD 继续沿用现有接口，但每次写入和事务内 precondition 都必须复核两项 UDP capability。端口迁移待后续增加与 createV2 对称的双预留更新合同。
- 对启用中的 `SHADOWSOCKS_2022_RAW_NONE` 或 `SHADOWSOCKS_2022_RAW_TCP_UDP_NONE`，`xray.accessEntries.setEnabled/remove` 若会使启用且非待删除账户降为零，返回 `LAST_ACTIVE_ACCESS_REQUIRED`且不增加 generation。管理员可先停用 inbound，再整理账户。
- 对启用中的 `HYSTERIA2_TLS` 使用同一 `LAST_ACTIVE_ACCESS_REQUIRED` 语义，防止生成空 `settings.clients`；管理员可先停用 inbound 再清理账户。
- 对启用中的 `WIREGUARD_UDP_NONE` 同样禁止停用或删除最后一个有效 peer。`xray.accessEntries.create` 仍只接收 `{ inboundId, name, expectedGeneration }`，由服务端在主机锁和事务内分配地址/生成密钥；普通 list/detail DTO 只返回名称、状态、`settings.address` 和 `requiredConfigured/configuredKinds`，不得返回 server/peer public key、private key、PSK、fingerprint、envelope 或 keyVersion。
- Reality/TLS/普通安全字段互斥；客户端不能提交服务端私钥。
- 返回形状、operation 收敛、离线门控和 expectedGeneration 语义沿用现有接口。
- profile 的协议/传输/安全变更第一阶段不做原地转换；管理员创建替代入站后再删除旧入站。

### 分享材料

分享接口按账户关联 profile 由服务端选择格式；当前 RAW Reality URI 保持原字节顺序，gRPC Reality URI 使用 `type=grpc&serviceName=<validated>` 且不含 `flow`，XHTTP Reality URI 使用 `type=xhttp&path=<validated>&mode=auto` 且不含 `flow`。客户端不能要求与 profile 不一致的格式；所有响应继续 `private, no-store`，不写数据库、日志、URL 或浏览器持久存储。

TLS VLESS/Trojan URI 固定包含传输对应的 `type`、`security=tls`、`sni=<serverName>`、`fp=chrome` 和所选证书小写 64 hex `pcs=<leafFingerprintSha256>`；VLESS 另含 `encryption=none`，仅 `VLESS_RAW_TLS_VISION` 含 `flow=xtls-rprx-vision`。WebSocket/HTTPUpgrade/XHTTP 写严格 path，gRPC 写 `serviceName` 和 `alpn=h2`，XHTTP 另写 `mode=auto`，mKCP 使用 `type=kcp` 且不写已移除的 seed/header。服务端不得生成 `allowInsecure`，也不得因证书由公开 CA 签发而省略 pin；证书轮换应用后旧 URI 的 `pcs` 失效，重新分享返回新 URI。

VMess 分享使用 `vmess://` + standard base64 编码的紧凑 UTF-8 JSON；解码后必须精确为 `v=2`、安全 endpoint/显示名、`id`、`scy=auto`、`net=tcp`、`type=none`、`tls=tls`、`sni`、`fp=chrome` 和小写 64 hex `pcs`，不得写 `aid/alterId/allowInsecure`。两个 Shadowsocks 2022 profile 都按 SIP002/SIP022 直接生成 `ss://2022-blake3-aes-256-gcm:<server-psk>:<user-psk>@endpoint#name`，两段 PSK 分别 percent-encode，userinfo 不做 base64，RAW+none 不附加 Xray 私有 transport/security/network 参数；是否具备原生 UDP listener 由服务端 profile 决定，不把非标准开关塞入分享链接。

Hysteria 2 分享固定为 `hysteria2://<percent-encoded-auth>@<endpoint>?sni=<encoded-sni>&pinSHA256=<lowercase-64-hex>#<encoded-name>`。scheme 已隐含 Hysteria v2 + TLS，不增加 `security`、`fp`、`alpn` 或 Xray 私有参数；不生成 `insecure`/`allowInsecure`，也不误用其他 TLS URI 的 `pcs` 字段。URI 只在管理员按需分享响应中生成并保持 `private, no-store`。

WireGuard 扩展 `xray.accessEntries.share` 的 input format 为 `WIREGUARD_CONFIG`，只允许关联 `WIREGUARD_UDP_NONE` 的 peer。响应使用 `{ format: "WIREGUARD_CONFIG", content, fileName, displayName, deploymentStatus }`，其中 `content` 是 `SPEC.md` 固定的标准 `.conf`，`fileName` 是服务端规范化的无路径安全名称；不把配置伪装进 `uri` 字段。响应继续设置 `Cache-Control: private, no-store, max-age=0` 和 `Pragma: no-cache`，不得进入查询缓存持久化、URL 或审计参数。

HTTP 扩展 `xray.accessEntries.share` 的 input format 为 `HTTP_PROXY_URI`，只允许关联 `HTTP_RAW_NONE` 的账户。响应复用 URI 形状 `{ format: "HTTP_PROXY_URI", uri, displayName, deploymentStatus }`；`uri` 固定为 `http://<encoded-username>:<encoded-password>@<endpoint>`，不添加 fragment、订阅参数或 Xray 私有参数。接口必须逐项重验两份 secret、profile 和 endpoint，并使用与其他分享相同的 `private, no-store` 响应头。

Mixed 扩展 `xray.accessEntries.share` 的 input format 为 `MIXED_PROXY_ENDPOINTS`，只允许关联 `MIXED_RAW_NONE` 的账户。响应形状固定为 `{ format: "MIXED_PROXY_ENDPOINTS", socks5Uri, httpUri, displayName, deploymentStatus }`；两项使用相同的 percent-encoded username/password 与规范 endpoint，分别固定 `socks5://` 和 `http://` scheme，不添加 fragment、UDP、订阅或 Xray 私有参数。`socks5Uri` 只是客户端常见导入地址，不得命名为标准 Xray 分享链接；接口必须逐项重验两份 secret、profile 和 endpoint，并设置 `Cache-Control: private, no-store, max-age=0` 与 `Pragma: no-cache`。

Tunnel 不注册 client/access share format，也不进入订阅聚合。详情由已验证的 profile spec 投影 `tunnelTargetAddress/tunnelTargetPort` 与本地 endpoint；普通响应不得伪造账户、凭据状态或公网地址。账户 CRUD/share procedure 对该 inbound 必须返回 `INVALID_CONFIG_INPUT`。

## 14. 受管 TLS 证书接口

所有接口仅管理员可用，并在服务层复核目标主机存在、在线、心跳新鲜和 Xray capability。输入使用严格 Zod 对象并拒绝未知字段；普通响应不包含证书 PEM、私钥、envelope、fingerprint 或 keyVersion。

### `xray.certificates.list`

输入 `{ hostId?: positiveInt, search?: string, page, pageSize }`。返回证书 id、hostId/name、证书名称、DNS SAN、有界 subject/issuer、序列号、有效期、算法、叶证书 fingerprint、引用 inbound 数量、到期状态和 `privateKeyConfigured: true`。

### `xray.certificates.import`

输入：

```ts
{
  hostId: number;
  name: string;
  certificatePem: string; // UTF-8 <= 16 KiB, 1..4 certificates
  privateKeyPem: string;  // UTF-8 <= 8 KiB, exactly one unencrypted key
}
```

浏览器可以提供粘贴和本地文件选择，但只提交文本，不提交文件名或路径。服务端完成格式、有效期、DNS SAN、算法和 key match 校验后，在 repository 内加密私钥并创建主机级资源；返回安全证书 DTO。

### `xray.certificates.rotate`

输入 `{ id, certificatePem, privateKeyPem, expectedGeneration }`。如果证书被 inbound 引用，必须持有主机配置锁、复核无活动写 operation，并在同一事务更新证书、递增 generation、生成完整快照/hash 和创建 `SYNC` operation；响应 `{ certificate, operationId?, desiredGeneration? }`。未被引用时不创建 operation。

### `xray.certificates.remove`

输入 `{ id, confirmName }`。名称必须逐字匹配；存在引用时返回 `CERTIFICATE_IN_USE` 并附安全的引用数量，不返回配置或凭据。无引用时物理删除证书及密文。

### TLS inbound 引用

TLS profile 的 `xray.inbounds.createV2` 使用严格 `tlsCertificateId` 和 `serverName` 字段；服务端验证证书属于目标主机、仍在有效期且 `serverName` 被 DNS SAN 覆盖。RAW/mKCP spec 必须为 `{}`；WebSocket、HTTPUpgrade、XHTTP 只接受严格 `{ path }`；gRPC 只接受严格 `{ serviceName }`。API 不接受 `certificateFile`、`keyFile`、Agent path、证书/私钥内联 Xray JSON、Host/headers/early data/authority/multiMode/XHTTP extra/mKCP 参数或 `allowInsecure`。

profileId 固定为 `VLESS_RAW_TLS`、`VLESS_RAW_TLS_VISION`、`TROJAN_RAW_TLS`、`VLESS_WEBSOCKET_TLS`、`TROJAN_WEBSOCKET_TLS`、`VLESS_GRPC_TLS`、`TROJAN_GRPC_TLS`、`VLESS_HTTP_UPGRADE_TLS`、`TROJAN_HTTP_UPGRADE_TLS`、`VLESS_XHTTP_TLS`、`TROJAN_XHTTP_TLS`、`VLESS_MKCP_TLS`、`TROJAN_MKCP_TLS`。前 11 项必须逐项完成 TCP 垂直验收才设置 `isAvailable=true`；两个 mKCP profile 还必须在 Agent v2 UDP 能力完成后逐项验收，旧 Agent 返回 `UDP_CAPABILITY_REQUIRED`。

## 15. 独立受管服务 API（TASK053）

独立服务位于 `xray.managedServices.*`，不进入 `xray.inbounds.*`、profile catalog 或 Xray config generator。

- `catalog()`：返回固定 kind 的实施状态、版本、网络/权限 advisory；AmneziaWG 在 054F 验收后返回 `AVAILABLE`，TUN 只能返回 `NOT_IMPLEMENTED` 且没有 create mutation。
- `list({ page, pageSize, search?, hostId?, status? })` / `detail({ id })`：只返回按 kind 的安全投影。账户/peer 只含名称、状态、配置状态；AWG peer可额外返回分配 address。不得返回 fake secret、任何 key/PSK、混淆对象、envelope、fingerprint、keyVersion、TOML/config、命令或路径。
- `createMtproto({ hostId, name, publicAddress, listenPort, portReservationId, fakeTlsDomain, initialAccounts:[{name}] })`：严格对象；至少 1、最多 32 个唯一账户名。服务端检查在线、managedServices capability、专用用户、固定平台制品和 TCP reservation，再原子创建服务/账户/secrets/deployment generation。
- `createAmneziawg({ hostId, name, publicAddress, listenPort, portReservationId, initialPeers:[{name}] })`：严格对象；至少 1、最多 32 个唯一 peer 名。服务端检查在线、per-kind capability 和单 UDP reservation，再生成服务/peer keys、PSK、地址和 AWG 3.1 参数并原子创建数据与 generation；输入不得带任何 key、subnet、route、DNS、MTU 或混淆字段。
- `setEnabled/update/remove` 与 `accounts.create/update/remove`：携带 `expectedGeneration`；启用服务不得有零个有效账户，删除最后有效账户必须拒绝。离线或能力降级时全部写操作拒绝。
- `share({ accountId })`：管理员专用、`private, no-store` 的判别联合。MTProto 返回 `{ kind:"MTPROTO_PROXY", uri, server, port, secret }`；AWG 返回 `{ kind:"AMNEZIAWG_CONFIG", content, fileName, vpnUri }`，其中 `vpnUri="vpn://" + base64url-no-padding(content)`。普通列表和详情不含这些材料。

稳定错误码增加 `MANAGED_SERVICE_NOT_FOUND`、`MANAGED_SERVICE_ACCOUNT_NOT_FOUND`、`MANAGED_SERVICE_CAPABILITY_MISSING`、`MANAGED_SERVICE_ARTIFACT_UNAVAILABLE`、`MANAGED_SERVICE_GENERATION_CONFLICT`、`LAST_ACTIVE_ACCOUNT_REQUIRED`、`INVALID_MANAGED_SERVICE_INPUT`；通用 `HOST_OFFLINE`、`PORT_*`、`SENSITIVE_DATA_UNAVAILABLE` 保持原含义。

## 16. 外部出口节点 API（TASK055）

全部 procedure 位于 `xray.externalProxyNodes.*` 并复用管理员鉴权。普通响应禁止返回原始 URI、secret、envelope、fingerprint、keyVersion 或完整 Xray outbound。

- `previewImport({ uri })`：只解析并返回短期安全预览 `{ protocol, suggestedName, address, port, publicSettings, credentialsConfigured }`，响应 `private, no-store`；不写数据库。VLESS 的 `publicSettings.fingerprint` 只可能为 `chrome|random`，authority 空路径和单个 `/` 不作为业务字段返回。
- `create({ name, uri })`：服务端重新解析 URI，生成不可变 `nodeTag`，在一个事务写公开定义和资源绑定 secret；返回安全详情。VLESS 导入、后续 `detail/share` 和 Xray 配置编译必须保留批准的 fingerprint，不能在边界间默认回 `chrome`。
- `list({ search?, protocol?, page?, pageSize? })` / `detail({ id })`：返回安全投影及 `{ inboundCount, ruleCount }`。详情可以返回引用资源的 id/name/host 安全摘要，不能返回账户或配置材料。
- `rename({ id, name })`：只修改显示名称；`replace({ id, uri })` 仅在引用计数为零时允许，并原子替换公开定义和 secret。
- `remove({ id, confirmName })`：名称必须逐字匹配且两个引用计数均为零；否则返回 `EXTERNAL_PROXY_IN_USE` 和安全引用数量。
- `share({ id, relayRuleId? })`：按需重建标准原节点链接；携带 `relayRuleId` 时验证该规则引用此节点、入口主机有规范公网地址且监听端口有效，只替换 authority。响应 `private, no-store`。

`xray.inbounds.setExternalProxy({ inboundId, externalProxyNodeId|null, expectedGeneration })` 在主机锁内复核在线/capability、TCP profile、非 Tunnel、引用完整性和 generation，提交完整配置 hash 与 `SYNC` operation。解绑使用 `null`；缺失/损坏出口必须零写入，不回退 direct。

规则 create/update 增加可选 `targetExternalProxyNodeId`。存在时只允许管理员、`protocol=tcp` 与 iptables、nftables、Realm、socat、GOST、Nginx 六种本地转发执行路径，服务端忽略客户端提交的目标地址并物化资源 endpoint，且拒绝任何向上游发送 PROXY Protocol 的选项；经过既有隧道/转发组时仍按其最终出口执行路径处理。为空时保持既有手动目标合同。稳定错误码增加 `EXTERNAL_PROXY_NOT_FOUND`、`EXTERNAL_PROXY_IN_USE`、`EXTERNAL_PROXY_INVALID_LINK`、`EXTERNAL_PROXY_UNSUPPORTED`、`EXTERNAL_PROXY_REFERENCE_INVALID`。

`rules.checkPort` 与 `rules.randomPort` 必须把所有非 `FREE` 全局端口 allocation 合并到既有主机/隧道/转发组、套餐和数据库监听判断；`excludeRuleId` 只允许同一稳定 `FORWARD_RULE` owner 在编辑时保留自身端口。新建表单随后调用 `rules.portProbeStart({ hostId|forwardGroupId, tunnelId?, sourcePort, protocol, replacePortCheckId? })`。服务端重新鉴权并派生完整入口 host 集合，按明确的 TCP/UDP 网络创建既有单端口 `PORT_PROBE`，返回 `{ status:"RUNNING", portCheckId }` 或稳定的 `USED/FAILED` 结果；浏览器不得提交 host、候选、operation 或 reservation 数组。

`rules.portProbeResult({ portCheckId })` 返回 `{status:"RUNNING", completed, total}`、`{status:"AVAILABLE", checkedAt}`、`{status:"USED", reasonCode, reason}`、`{status:"FAILED", reasonCode, reason}` 或 `{status:"EXPIRED", reasonCode, reason}`。`portCheckId` 是从持久 cookie secret 派生的用途隔离 HMAC token，严格绑定管理员、端口、协议、完整 `host + network + operationId` 集合和期限；未知字段、非规范编码、跨管理员、删减、篡改或过期 fail closed。全部成功后释放短期 host reservation，最终 `rules.create` 的进程内预留和事务化全局 allocation 继续作为竞态防线。输入变化或 Dialog 关闭可调用 `rules.portProbeDiscard({ portCheckId })`，它只取消该签名集合中属于当前管理员的未完成 operation，并释放匹配的短期预留。

## 17. DNS provider account API（TASK057）

全部 procedure 位于 `xray.dnsProviderAccounts.*`，只允许管理员。首版 UI 只管理固定 `XRAY_QUICK_CONFIG` global binding；底层 DTO 保留稳定 account id/tag 以便未来增加 scope。任何携带 secret 或短期授权 token 的请求/响应都必须设置 `Cache-Control: private, no-store, max-age=0` 和 `Pragma: no-cache`。

### `xray.dnsProviderAccounts.getGlobal`

无输入。固定 scope 未绑定时返回 `{ configured:false, provider:"DNSPOD", bindingRevision:number }`；存在时只返回：

```ts
{
  configured: true;
  accountId: number;
  provider: "DNSPOD";
  name: string;
  accountRevision: number;
  bindingRevision: number;
  credentialsConfigured: true;
  secretIdMask: string;        // 固定安全掩码，不可还原
  secretKeyMask: string;
  validationStatus: "UNVERIFIED" | "VALID" | "INVALID" | "ERROR" | "EXPIRED";
  verifiedAt: string | null;
  verificationExpiresAt: string | null;
  zonesSyncedAt: string | null;
  zoneCount: number;
  quickConfigReferenceCount: number;
  managedRecordCount: number;
  canRotateCredentials: boolean;
  canRebind: boolean;
  canRemove: boolean;
  lastErrorCode: string | null;
}
```

普通响应不得返回 `accountTag`、secret、envelope、fingerprint、keyVersion、provider 原始错误或完整请求摘要。

### `xray.dnsProviderAccounts.upsertGlobal`

输入是严格对象 `{ expectedBindingRevision, expectedAccountRevision:null|positiveInt, name, secretId, secretKey }`，name 为 1–128 字符，两项凭据使用有界非空字符串。创建要求 `expectedAccountRevision=null` 且固定未绑定 scope 的 binding revision 精确匹配；轮换要求两项 revision 均精确匹配。服务端先在内存中用候选凭据调用固定 DNSPod 验证并同步至少一个 zone/line catalog；若稳定 account 已被快速配置引用，还必须用候选凭据确认全部被引用 provider zone 和面板拥有的 recordId 仍可见。任一步失败时零数据库写入，现有账号/binding 不变。成功后单事务创建或轮换同一稳定 account、两项密文、catalog 和 binding，递增所有发生持久变化的 revision，返回 `getGlobal` 安全 DTO。请求体、候选值和 provider 响应不得进入审计或错误。

### `xray.dnsProviderAccounts.revalidateGlobal`

输入 `{ expectedAccountRevision, expectedBindingRevision }`。最小解密已保存的两项凭据，重新验证并同步 catalog；成功把验证有效期固定延长到 24 小时并增加 account revision，失败只保存稳定状态/时间/错误码且同样增加 account revision。binding 未改变时其 revision 不增加，但仍用于确认请求操作的是当前 global account。存在活动快速配置时，认证失败不删除 DNS 或停止数据面。

### `xray.dnsProviderAccounts.removeGlobal`

输入 `{ expectedAccountRevision, expectedBindingRevision, confirmName }`，名称逐字匹配。存在任何非 `REMOVED` quick config、活动 operation 或 managed DNS record 时返回 `DNS_PROVIDER_IN_USE`；否则同事务把固定 binding 的 `accountId` 置空并增加 binding revision，再删除 catalog、secret 和 account。它不读取、修改或清空既有 DDNS 设置。

### `xray.dnsProviderAccounts.zones`

输入 `{ refresh?: boolean }`。只有账号验证未过期时可用；catalog 最多缓存 6 小时。`refresh=true` 强制有界实时同步；`refresh=false` 遇到过期缓存也自动尝试一次同步，失败时返回 stale 安全投影而不是旧 catalog 可写能力。zone 返回 `{ zoneId, providerZoneId, name, status, catalogRevision, expiresAt, catalogUsable, catalogReasonCode, inUse, quickConfigReferenceCount, managedRecordCount, activeOperationCount, lines[], carrierLines[] }`，line 只含 `{ lineId, providerLineId, name, category, status }`；`carrierLines` 恰好投影 `DEFAULT + TELECOM + UNICOM + MOBILE + EDUCATION` 五类，每类为 `{ category, status:"AVAILABLE", lineId, providerLineId, name } | { category, status:"MISSING"|"AMBIGUOUS"|"STALE", reasonCode }`，`OTHER` 只保留在原始安全 `lines` 数组。`inUse` 在未删除快速配置、未清理托管记录或活动 operation 任一计数非零时为 true。服务端仅对本次 DNSPod catalog 返回的完整规范名称按版本化精确表 `默认/电信/联通/移动/教育网` 分类，lineId 必须取动态响应，禁止硬编码、子串或顺序推断。只有 `AVAILABLE` 可提交；客户端提交面板 line id，后端在每次 DNS write 前再次实时核对。

## 18. DNS 记录管理 API（MAINT-019）

全部 procedure 位于 `xray.dnsRecords.*`、只允许管理员，并设置 `private, no-store`。账号必须验证有效，zone 必须是当前 global binding 目录中的 `AVAILABLE` 项；所有 provider 响应都继续通过严格解析器，不暴露 RequestId 或原始错误。

- `list({ zoneId, search?, recordType?, page=1, pageSize=20 })` 实时读取 DNSPod 记录，服务端稳定排序、筛选并分页，返回 `{ items, total, page, pageSize, zone:{ zoneId,name,inUse,...counts } }`。每条记录只返回 providerRecordId、subdomain、recordType、lineId/lineName、value、ttl、status 和基于规范 tuple 的 `recordRevision`。
- `create({ zoneId, subdomain, recordType, lineId, value, ttl })` 只允许 A/AAAA/CNAME。`lineId` 是面板目录 id，服务端解析并复核 providerLineId/name；成功后只返回 `{ providerRecordId }`，界面再实时重读列表。
- `update({ zoneId, providerRecordId, expectedRecordRevision, subdomain, recordType, lineId, value, ttl })` 在写入前用 `DescribeRecord` 回读并比对 revision，远端已变更时返回 `DNS_RECORD_CHANGED`，不覆盖。
- `remove({ zoneId, providerRecordId, expectedRecordRevision })` 同样先回读并比对 revision，仅删除该精确 recordId。

三个 mutation 均必须在 provider 写入前从数据库重新计算 zone 占用；占用时返回 `DNS_ZONE_IN_USE` 冲突。账号/catalog revision 变化、记录被第三方改写、recordId 不属于选定 zone 都必须 fail closed。写请求出现结果不明时返回 `DNS_WRITE_UNCERTAIN`，界面要求刷新而不自动重试。

## 19. 快速配置 API（TASK057）

全部 procedure 位于 `xray.quickConfigs.*`，只允许管理员。输入均为 strict Zod object，拒绝浏览器提交任意 Agent task、候选数组、DNS record、Realm 命令、规则 payload、ownerGroupTag 或分享材料。所有包含 domain/probe/recommendation/preview/remove token 或派生分享材料的响应统一设置 `Cache-Control: private, no-store, max-age=0` 与 `Pragma: no-cache`；token 不进入普通 list/detail/operation DTO。

### 19.1 目标目录与列表

`xray.quickConfigs.targetsList({ search?, targetType?, page?, pageSize? })` 的 `items` 使用以下判别联合：

```ts
type QuickConfigTarget =
  | {
      targetType: "XRAY_INBOUND";
      targetId: number;
      targetVersion: string;
      name: string;
      protocol: string;
      profileId: string;
      host: { id: number; name: string };
      endpoint: { address: string; port: number };
      eligible: boolean;
      disabledReasonCode: string | null;
      shareCapability: "VLESS_URI" | "SHADOWSOCKS_URI" | "SOCKS5_ENDPOINT" | "NONE";
    }
  | {
      targetType: "EXTERNAL_PROXY_NODE";
      targetId: number;
      targetVersion: string;
      name: string;
      protocol: "VLESS_REALITY_VISION" | "SHADOWSOCKS" | "SOCKS5";
      endpoint: { address: string; port: number };
      eligible: boolean;
      disabledReasonCode: string | null;
      shareCapability: "VLESS_URI" | "SHADOWSOCKS_URI" | "SOCKS5_ENDPOINT";
    };
```

受管 Xray 目录包括能作为 TCP 落地的既有 inbound；UDP-only、回环 Tunnel、pending delete、未同步或无法生成稳定公开 endpoint 的记录不可选。QC019 的一键派生只开放现有服务端 builder 已批准的 VLESS、Shadowsocks 和 Mixed/SOCKS5 材料；其他可作为 TCP 落地的 profile 返回 `shareCapability=NONE`，不伪造链接。多账户 inbound 的分享由后续 `accessRef` 明确选择，不默认泄露第一条凭据。

`targetVersion` 是服务端对会改变落地能力的安全字段计算出的 SHA-256：Xray 分支绑定类型/id/runtimeTag/hostId/publicAddress/listenPort/protocol/transport/security/profileId/specVersion 及严格解析后的规范 secret-free profile spec hash/enabled/pending，外部节点分支绑定类型/id/nodeTag/protocol/address/port/specVersion 及规范 secret-free spec hash。它明确排除显示名称、`updatedAt`、无关 host generation 和客户端列表；允许的重命名或同主机其他配置变化不得让快速配置失效，endpoint/profile/公开 profile spec/eligibility 改变必须失效。它不是数据库自增 id，也不包含 secret。服务端在每个 token 签发与消费点重新计算，不一致返回 `QUICK_CONFIG_TARGET_CHANGED`。

`xray.quickConfigs.targetsList({ search?, targetType?, page=1, pageSize=20 })` 返回 `{ items:QuickConfigTarget[], total:number, page:number, pageSize:number }`，`pageSize` 只允许 1–100。

目录固定先按 `targetType`、显示名、`targetId` 做稳定升序，再分页；`search` 只匹配安全显示名、主机名和公开 endpoint，不搜索 profile spec 或任何凭据。`targetsList` 本身允许在 DNS 账号未配置时读取，以便页面展示落地资源和明确的账号门禁；真正开始域名步骤的 `domainChecksCreate` 必须重新验证当前 global binding、24 小时账号验证有效期和所选 zone catalog。不可选项保留在目录并仅使用以下稳定原因：`TARGET_DISABLED`、`TARGET_PENDING_DELETE`、`TARGET_PROFILE_INVALID`、`TARGET_TCP_UNSUPPORTED`、`TARGET_ENDPOINT_INVALID`、`TARGET_NOT_SYNCED`、`TARGET_HOST_OFFLINE`。

运营商线路入口候选由独立只读查询返回：

```ts
type QuickConfigEntryHost = {
  hostId: number;
  name: string;
  eligible: boolean;
  disabledReasonCode:
    | "HOST_OFFLINE"
    | "AGENT_CAPABILITY_MISSING"
    | "UDP_CAPABILITY_REQUIRED"
    | "QUICK_CONFIG_HOST_UNAVAILABLE"
    | null;
  endpoints: Array<{
    addressFamily: "IPV4" | "IPV6";
    address: string;
  }>;
};
```

`xray.quickConfigs.entryHostsList()` 返回 `{ items:QuickConfigEntryHost[] }`，按主机名、hostId 稳定排序；`endpoints` 固定先 IPv4 后 IPv6，且只含服务端从受管主机记录读取并通过公网单播策略的地址。它不返回 `ip`/`entryIp`/`tunnelEntryIp` 原始列、Agent Token、userId、心跳时间、Agent 版本、原始 capability 或运行时错误文本。

候选资格以服务端实时状态为准：主机必须保持新鲜在线、具备 schema v1 的 TCP/UDP 单端口探测和 UDP listener readiness capability、系统设置中的 Realm 必须启用，并且至少有一个有效公网 IPv4/IPv6 endpoint。禁用原因按 `HOST_OFFLINE` → `AGENT_CAPABILITY_MISSING` → `UDP_CAPABILITY_REQUIRED` → `QUICK_CONFIG_HOST_UNAVAILABLE` 的顺序取第一个；后者只表示 Realm 被禁用或主机没有有效公网 endpoint。该目录只提供向导选择提示，`portChecksCreate`、preview 与 apply 仍必须重新读取并验证同一 host/address family，不能信任浏览器回传的地址。

列表与详情 DTO 固定为：

```ts
type QuickConfigSummary = {
  id: number;
  revision: number;
  dnsAccountId: number;
  fqdn: string;
  targetType: "XRAY_INBOUND" | "EXTERNAL_PROXY_NODE";
  targetId: number;
  targetName: string;
  publicPort: number;
  engine: "realm";
  state: "APPLYING" | "ACTIVE" | "UPDATING" | "DELETING" | "COMPENSATING" | "PARTIAL_FAILURE" | "FAILED" | "REMOVED";
  currentOperationId: number | null;
  createdAt: string;
  updatedAt: string;
};

type QuickConfigTopologyDto = {
  topologyRevisionId: number;
  revisionNumber: number;
  state: "STAGED" | "APPLYING" | "APPLIED" | "RETIRING" | "RETIRED" | "ROLLBACK_PENDING" | "ABANDONED";
  publicPort: number;
  targetAddress: string;
  targetPort: number;
  routes: Array<{ routeId: number; lineCategory: "DEFAULT" | "TELECOM" | "UNICOM" | "MOBILE" | "EDUCATION"; providerLineId: string; sourceType: "MANAGED_HOST" | "LANDING"; hostId: number | null; addressFamily: "IPV4" | "IPV6"; address: string; routeMode: "DIRECT" | "FORWARD"; state: "PLANNED" | "APPLYING" | "APPLIED" | "RETIRING" | "RETIRED" | "FAILED" }>;
};

type QuickConfigDetail = QuickConfigSummary & {
  target: { targetVersion: string; protocol: string; endpoint: { address: string; port: number }; shareCapability: "VLESS_URI" | "SHADOWSOCKS_URI" | "SOCKS5_ENDPOINT" | "NONE" };
  activeTopology: QuickConfigTopologyDto | null;
  desiredTopology: QuickConfigTopologyDto | null;
  rules: Array<{ ruleId: number; hostId: number; name: string; bindingState: "PLANNED" | "APPLYING" | "READY" | "RETIRING" | "REMOVED" | "FAILED"; runtimeStatus: "running" | "degraded" | "pending" | "disabled" | "unknown"; lineCategories: Array<"DEFAULT" | "TELECOM" | "UNICOM" | "MOBILE" | "EDUCATION"> }>;
  dnsRecords: Array<{ recordRef: string; routeId: number; recordType: "A" | "AAAA"; providerLineId: string; value: string; ttl: number; status: "DESIRED" | "APPLIED" | "DELETE_PENDING" | "REMOVED" | "DRIFTED" | "UNKNOWN"; lastVerifiedAt: string | null }>;
  currentOperation: QuickConfigOperationDto | null;
  lastOperation: QuickConfigOperationDto | null;
};
```

`xray.quickConfigs.list({ search?, state?, targetType?, accountId?, page=1, pageSize=20 })` 返回 `{ items:QuickConfigSummary[], total:number, page:number, pageSize:number }`，其中 `pageSize` 为 1–100。`xray.quickConfigs.detail({ id })` 返回 `QuickConfigDetail`。不得返回 DNSPod secret、出口凭据、完整 URI、token、原始 provider 响应或 operation JSON。

### 19.2 域名检查与确认

`xray.quickConfigs.domainChecksCreate` 输入：

```ts
{
  targetRef: { targetType: "XRAY_INBOUND" | "EXTERNAL_PROXY_NODE"; targetId: number; targetVersion: string };
  accountId: number;
  zoneId: number;
  relativeName: string;
}
```

返回严格结构：

```ts
type DomainRecordProjection = {
  recordRef: string; // 不可猜测摘要，不是 provider recordId
  recordType: "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "CAA" | "OTHER";
  providerLineId: string;
  lineName: string;
  value: string;
  ttl: number;
};

type DomainCheckDto = {
  fqdn: string;
  conflicts: DomainRecordProjection[]; // 仅 A/AAAA/CNAME
  preservedRecords: DomainRecordProjection[];
  allowedActions: Array<"USE_UNUSED_NAME" | "REPLACE_CONFLICTING_RECORDS">;
  confirmationHash: string;
  domainCheckToken: string;
  expiresAt: string;
};
```

服务端规范化 `dfd`、`hk.dfd` 等相对记录并实时读取同名远端记录并返回 `DomainCheckDto`。`confirmationHash` 只绑定本次规范化展示集合，不预先绑定尚未选择的 action。A/AAAA 允许显式 replace，CNAME 允许显式 delete-and-replace，TXT/MX/CAA 和未知类型只进入 preserved 摘要。此过程不修改 DNS、规则、global allocation 或 quick config。

`recordRef` 是服务端以独立用途 MAC 从 `account + zone + provider recordId + 精确 record tuple` 派生的固定不透明引用；响应和 token 明文载荷都不返回 provider recordId。远端集合先按 provider recordId 和规范 tuple 做稳定排序，`confirmationHash` 绑定管理员实际看到的两个投影数组，内部 `record-set hash` 额外绑定 provider recordId、status、规范相对记录名及完整 tuple。单次同名检查最多接受 512 条远端记录，超过上限 fail closed。

`xray.quickConfigs.domainChecksConfirm` 输入 `{ domainCheckToken, action:"USE_UNUSED_NAME"|"REPLACE_CONFLICTING_RECORDS", confirmationHash }`。即使无冲突也必须由用户调用确认；存在 A/AAAA/CNAME 冲突时只能使用 `REPLACE_CONFLICTING_RECORDS`，confirmationHash 必须匹配展示集合。TXT/MX/CAA 或未知类型不被删除，若其语义阻止地址记录共存则必须换相对名称。成功返回 `{ confirmedDomainToken, expiresAt }`，有效期最长 10 分钟；其 MAC 额外绑定本次 `action + confirmationHash + 精确 record-set hash`，不能把未冲突授权、地址替换授权或 CNAME 删除授权互换复用。原 check token 最长 5 分钟；两种 token 都绑定管理员、account/credential revision、zone、FQDN、targetVersion 和到期时间，不进入 URL。输入、账号、目标或远端集合变化返回稳定竞态错误。

`domainChecksConfirm` 必须再次实时读取同名记录后才签发 confirmed token，而不是只验浏览器回传的 hash；面板同名非 `REMOVED` 快速配置也在 create 与 confirm 两处重查。两类 token 使用紧凑的版本化 payload、随机 nonce 和 purpose-separated HMAC-SHA256；签名密钥从面板持久 cookie secret 以固定 quick-config context 派生，因此服务重启后仍可验证，而 cookie secret 轮换会安全地使全部短期 token 失效。签名比较使用 constant-time，解析前限制整体长度，未知字段、版本、用途、管理员、revision 或过期时间一律拒绝。

### 19.3 线路与端口检查

四运营商输入固定为：

```ts
type CarrierRoutesInput = Array<{
  carrier: "TELECOM" | "UNICOM" | "MOBILE" | "EDUCATION";
  providerLineId: string;
  endpoints: Array<{ hostId: number; addressFamily: "IPV4" | "IPV6" }>;
}>;
```

四种 carrier 必须各出现一次且每项至少一个 endpoint；同一 carrier 内的重复 endpoint 拒绝，跨 carrier 的相同 endpoint 必须保留为不同 DNS route，只在物理 Realm rule 计划层按 host 去重。服务端从 host 数据读取对应公开地址，检查在线、Agent capability、Realm runtime 和动态 line 归属，不接受任意 IP。

`xray.quickConfigs.portChecksCreate` 输入 `{ confirmedDomainToken, carrierRoutes, engine, choice:{ mode:"TARGET_ORIGINAL" } | { mode:"MANUAL", port:number } | { mode:"RECOMMENDED", recommendationToken:string }, replaceProbeResultToken?:string }`。`replaceProbeResultToken` 只用于同一向导交回上一轮服务端签名的成功结果；服务端必须验证 token 未过期并绑定当前管理员、confirmed domain 和同一 target/version，再完整验证其中数量受限、互异的全部 `host + network + selectedPort` reservation，全部通过后一次性释放。engine、carrier routes 和新 choice 允许改变；篡改、跨管理员、跨域名、跨目标或任一 reservation 错配都返回 `QUICK_CONFIG_PREVIEW_INVALID` 且零释放。服务端随后先查 global ledger，再对最终去重的物理 `FORWARD` host 并行创建既有 TCP/UDP `PORT_PROBE` operation；浏览器不能提供候选数组或 reservation ID。返回严格判别联合：

```ts
type PortCheckStart =
  | { status: "RUNNING"; portCheckId: string }
  | { status: "CONFLICT"; resolution: "MANUAL"; reasonCode: "GLOBAL_PORT_CONFLICT" | "GLOBAL_PORT_LEGACY_CONFLICT" | "GLOBAL_PORT_SCAN_PENDING" | "GLOBAL_PORT_EXTERNAL_OCCUPIED"; requestedPort: number }
  | { status: "CONFLICT"; resolution: "RECOMMENDED"; reasonCode: "GLOBAL_PORT_CONFLICT" | "GLOBAL_PORT_LEGACY_CONFLICT" | "GLOBAL_PORT_SCAN_PENDING" | "GLOBAL_PORT_EXTERNAL_OCCUPIED"; requestedPort: number; recommendation: { port: number; recommendationToken: string; expiresAt: string } };
```

受管 Xray 目标的任何冲突使用 `MANUAL`；外部目标的任何冲突使用 `RECOMMENDED`，用户确认后再次发起。recommendation token 绑定管理员、targetVersion、规范 host cohort、推荐端口、原冲突原因和期限。冲突响应不创建 Agent task 或 allocation。

`xray.quickConfigs.portChecksResult({ portCheckId })` 返回以下严格判别联合：

```ts
type PortCheckResult =
  | { status: "RUNNING"; completedHosts: number; totalHosts: number }
  | { status: "SUCCESS"; selectedPort: number; rewritten: boolean; probeResultToken: string; expiresAt: string; defaultRouteCandidates: DefaultRouteCandidate[] }
  | { status: "CONFLICT"; resolution: "MANUAL"; reasonCode: "GLOBAL_PORT_CONFLICT" | "GLOBAL_PORT_LEGACY_CONFLICT" | "GLOBAL_PORT_SCAN_PENDING" | "GLOBAL_PORT_EXTERNAL_OCCUPIED"; requestedPort: number }
  | { status: "CONFLICT"; resolution: "RECOMMENDED"; reasonCode: "GLOBAL_PORT_CONFLICT" | "GLOBAL_PORT_LEGACY_CONFLICT" | "GLOBAL_PORT_SCAN_PENDING" | "GLOBAL_PORT_EXTERNAL_OCCUPIED"; requestedPort: number; recommendation: { port: number; recommendationToken: string; expiresAt: string } }
  | { status: "FAILED"; reasonCode: "HOST_OFFLINE" | "UDP_CAPABILITY_REQUIRED" | "GLOBAL_PORT_PROBE_FAILED" }
  | { status: "EXPIRED"; reasonCode: "GLOBAL_PORT_PROBE_EXPIRED" };
```

只有全部预期 `FORWARD` host 的 TCP/UDP 结果都匹配 host/network/port 且未过期才成功；异步探测发现占用时也按目标类型进入唯一的 `MANUAL/RECOMMENDED` 分支。operation 可以创建最长 60 秒、绑定当前管理员/host/network/port 的短期 reservation，但不会创建 global allocation。关闭向导无需发送 cancel；前端停止轮询，reservation 自动到期，apply 必须复核 TTL。

受管 Xray 使用目标原端口时，目标 inbound 所在 host/address family 规划为 `LANDING/DIRECT`，不创建转发规则，也不对已由该 inbound 合法持有的 listener 做空闲探测；它只通过账本的非 owning target alias 与实际 Xray runtime READY 复核。其他入口 host 仍规划为 `FORWARD` 并做 TCP/UDP 空闲检查。面板为这些内部 probe 派生不可由 tRPC 输入构造的 target-alias 授权，只允许精确 MANUAL 原端口忽略目标 inbound 自身的 ACTIVE 全局 allocation；operation metadata 只保存 `inboundId + port`，Agent payload 不变，创建、派发和结果接受均以单次一致性查询验证稳定 owner、同主机公开 owning reference 和 inbound 状态。端口改写时包括落地主机在内的每个入口都必须建立 `新端口 -> 原端口` 规则并参与探测。外部目标没有受管 landing host，全部选择的入口都属于 `FORWARD`。

Realm 继续监听既有 `[::]:port` 且 `ipv6_only=false`，同 host 的 IPv4/IPv6 route 共用一条规则。现有 `PORT_PROBE` 不接受任意 IPv6 bind 地址；最终 apply 必须等 Realm 的实际双栈 listener readiness 后才能写 DNS，双栈 bind 失败返回 `RULE_APPLY_FAILED` 并补偿。

### 19.4 Preview 与 apply

默认线路输入固定为：

```ts
type DefaultRoutesInput = Array<{ candidateId: string }>;

type DefaultRouteCandidate = {
  candidateId: string;
  sourceType: "LANDING" | "MANAGED_HOST";
  hostId: number | null;
  addressFamily: "IPV4" | "IPV6";
  address: string;
  label: string;
  recommended: boolean;
};
```

`candidateId` 是当前 probeResultToken 内对 `sourceType/host/addressFamily/精确地址` 的有时效 opaque MAC 身份，因此外部 FQDN 同一地址族解析出多个公网地址时也能唯一选择；它不能跨 port check 复用。`xray.quickConfigs.preview` 输入严格为 `{ confirmedDomainToken, carrierRoutes, probeResultToken, defaultRoutes:DefaultRoutesInput }`，create 路径拒绝 quickConfigId/expectedRevision。每项只能从 port check 返回的候选中选择，至少一项且 candidateId 不重复；服务端从 token 重建地址，不接受浏览器提交 IP。未改写端口时允许已确认的落地公网 IPv4/IPv6 direct，且有两种地址族时默认候选同时包含两项；改写端口时只允许具有相同 Realm listener 的受管 host/address family。外部 FQDN direct 必须展示并绑定本次解析出的每个稳定公网地址。

preview 是纯计算：不创建 Agent task、普通规则、DNS record、global allocation、domain claim 或 quick-config 行。它返回严格 `QuickConfigPreviewDto`：

```ts
type QuickConfigPreviewDto = {
  fqdn: string;
  publicPort: number;
  target: { targetType: "XRAY_INBOUND" | "EXTERNAL_PROXY_NODE"; targetId: number; targetName: string; address: string; port: number };
  rules: Array<{ ruleKey: string; action: "CREATE" | "REUSE"; hostId: number; hostName: string; engine: "realm"; listenPort: number; targetAddress: string; targetPort: number }>;
  dnsRecords: Array<(
    | { routeKind: "CARRIER"; carrier: "TELECOM" | "UNICOM" | "MOBILE" | "EDUCATION" }
    | { routeKind: "DEFAULT"; carrier: null }
  ) & { providerLineId: string; recordType: "A" | "AAAA"; value: string; ttl: number; action: "CREATE" | "REPLACE" }>;
  conflictingRecords: Array<
    | (DomainRecordProjection & { recordType: "A" | "AAAA"; action: "REPLACE" })
    | (DomainRecordProjection & { recordType: "CNAME"; action: "DELETE" })
  >;
  preservedRecords: DomainRecordProjection[];
  allocation: { port: number; mode: "TARGET_ALIAS" | "RESERVE_NEW"; rewritten: boolean };
  warnings: Array<{ code: string; message: string }>;
  previewToken: string;
  expiresAt: string;
};
```

token 最长 5 分钟并绑定上述全部规范输入、目标/account/catalog/record-set revision、probe results 和管理员。

`xray.quickConfigs.createApply({ previewToken })` 在重新验证 token、账号有效期、targetVersion、domain record-set、host/capability、probe TTL 和端口账本后，事务性取得 domain claim/global allocation，建立 immutable topology 和持久 operation。任何检查后竞态均零外部写入失败；响应 `{ quickConfigId, operationId, state:"APPLYING" }`。浏览器不能在 apply 时重传或覆盖 DNS/rule 计划。`apply` 是 tRPC 路由保留字，不得作为 procedure 名称。

`dnsRecords` 的 DTO/preview 顺序不代表 provider 写入顺序。create/edit/retry 的 DNS 执行层必须按持久 route category 将全部 `DEFAULT` A/AAAA create/replace 并验证完成后，才处理运营商线路记录；不得依赖浏览器排序或硬编码 DNSPod lineId。

CreateRecord 成功或网络结果不明确后的验证允许最多 30 秒 provider 索引延迟，轮询只做读取和精确 tuple/recordId 对账，不再次调用 CreateRecord。RETRY 若发现无本地 providerRecordId 的唯一远端精确匹配，只能在 `retryOfOperationId` 指向同一 quick config 的终态 operation、且该 recordId 对应 `DNS_CREATE` step 状态为 `RUNNING/SUCCESS/FAILED` 时接管；`PENDING/COMPENSATED` 均不构成证明，浏览器也不提交或确认该所有权证明。

`xray.quickConfigs.editPreview` 输入 `{ quickConfigId, expectedRevision, confirmedDomainToken, carrierRoutes, probeResultToken, defaultRoutes:DefaultRoutesInput }`，返回 `QuickConfigPreviewDto` 和绑定 edit 身份/revision 的 previewToken；目标引用不可更换。`xray.quickConfigs.editApply({ previewToken })` 只消费该 token，不允许浏览器重传规划字段，服务端持久保存 from/to topology 并按 make-before-break saga 切换，返回 `{ quickConfigId, operationId, state:"UPDATING" }`。

`xray.quickConfigs.removePreview({ id, expectedRevision })` 返回 `{ quickConfigId, revision, fqdn, dnsRecords:[{ recordRef, recordType, providerLineId, value, action:"DELETE" }], rules:[{ ruleId, hostId, name, action:"REMOVE"|"KEEP_SHARED" }], allocation:{ port, nextState:"RELEASING"|"ACTIVE" }, warnings:[{ code, message }], removeToken, expiresAt }`；只列将 CAS 删除的当前 managed A/AAAA，不承诺恢复创建前或历史 edit 的第三方记录。`xray.quickConfigs.removeApply({ removeToken, confirmFqdn })` 创建持久 remove operation 并返回 `{ quickConfigId, operationId, state:"DELETING" }`。Agent 离线或能力不足时拒绝，不能只删数据库行。

`xray.quickConfigs.retry({ operationId, expectedOperationRevision })` 只接受失败/部分失败的终态 operation；原行不可变，服务端以 quick-config revision 与 active-slot CAS 新建 `type=RETRY/retryOfOperationId=原 id` 的 operation，只复制仍需执行的安全 step identity，不重放已确认成功步骤，返回 `{ operationId:newId, operationRevision:1 }`。活动 operation 存在时返回冲突。`xray.quickConfigs.operation({ operationId })` 返回：

`xray.quickConfigs.sync({ id, expectedRevision })` 只接受 `ACTIVE`、存在唯一 active topology 且没有 current operation 的快速配置，返回 `{ quickConfigId, operationId, state:"UPDATING" }`。它创建 `type=EDIT`、`requestSummaryJson={kind:"CONFIG_SYNC",schemaVersion:1}` 的持久 operation；浏览器不能提交规则、DNS tuple、host、recordId 或 provider payload。服务端从 active topology 重建期望规则，缺失时创建、字段漂移时恢复并等待 Agent running；随后实时读取 DNSPod，对 locally-owned 同名 recordId 做 keep/repair，对确实缺失的托管记录 create。已严格验证为正整数的旧 recordId 在 `DescribeRecord` 返回精确 `InvalidParameter.RecordIdInvalid` 时视为远端缺失，但仍需借助当前完整列表完成同值冲突和所有权判定；其他 `InvalidParameter.*` 保持请求拒绝。每次 DNS 写前会持久化当时已存在的同值 recordId，进程接管只允许认领此集合之外的唯一记录。provider recordId 已移动到其他相对名称、未归属的同值记录、重复记录或跨配置占用均返回稳定漂移错误，不接管、不删除。终态无论成功或部分失败都恢复 quick config 的 `ACTIVE` 状态并清除 current operation；已完成的增量修复不做破坏性补偿，管理员可用新 revision 再次同步。

```ts
type QuickConfigOperationDto = {
  operationId: number;
  quickConfigId: number;
  type: "APPLY" | "EDIT" | "REMOVE" | "RETRY";
  status: "QUEUED" | "RUNNING" | "COMPENSATING" | "SUCCESS" | "FAILED" | "PARTIAL_FAILURE" | "CANCELLED";
  phase: "RECHECKING_DOMAIN" | "RESERVING_PORT" | "CREATING_RULES" | "WAITING_RULES_READY" | "APPLYING_DNS" | "VERIFYING_DNS" | "FINALIZING" | "DNS_REMOVING" | "DNS_REMOVED" | "RULES_REMOVING" | "RULES_REMOVED" | "PORT_RELEASING" | "RESTORING_DNS" | "REMOVING_NEW_RULES" | "RELEASING_REFERENCES" | "COMPLETED";
  operationRevision: number;
  retryOfOperationId: number | null;
  startedAt: string | null;
  finishedAt: string | null;
  errorCode: string | null;
  steps: Array<{ stepKey: string; kind: "DOMAIN_RECHECK" | "PORT_RESERVE" | "RULE_CREATE" | "RULE_VERIFY" | "DNS_CREATE" | "DNS_REPLACE" | "DNS_DELETE" | "DNS_VERIFY" | "DNS_RESTORE" | "RULE_DELETE" | "RULE_VERIFY_REMOVED" | "REFERENCE_RELEASE"; subjectType: "DOMAIN" | "PORT" | "RULE" | "DNS_RECORD" | "ALLOCATION" | "TOPOLOGY"; subjectSafeId: string | null; status: "PENDING" | "RUNNING" | "SUCCESS" | "FAILED" | "SKIPPED" | "COMPENSATED"; attemptCount: number; errorCode: string | null }>;
};
```

DTO 不返回 request/result JSON、provider/Agent 原文、execution owner/lease/fence 或 token，页面可据此刷新恢复。

### 19.5 分享与普通规则联动

`xray.quickConfigs.share({ id, accessRef? })` 只对 `shareCapability != NONE` 可用。`accessRef` 严格判别为 `{ type:"LEGACY_CLIENT", legacyClientId:number } | { type:"ACCESS_ENTRY", accessEntryId:number }`；外部节点禁止携带，受管 Xray 多账户必须携带并在服务端复核归属。返回判别联合 `{ format:"VLESS_URI"|"SHADOWSOCKS_URI", uri:string }` 或 `{ format:"SOCKS5_ENDPOINT", endpoint:{ host:string, port:number, username?:string, password?:string } }`，只替换 authority，响应 `private, no-store`；关闭、失败或复制后前端清理内存。

普通规则 list/detail 增加可选安全字段 `{ quickConfigRef:{ id, fqdn, targetName, lineCategories, operationState } }`。带该字段的规则仍使用既有运行状态/日志；直接 update/setEnabled/remove 必须返回 `QUICK_CONFIG_MANAGED_RULE` 和 quickConfigId，界面跳转 quick-config edit/remove，而不是修改规则。

`forwardGroups.listPage({ groupMode:"port", ... })` 是链路管理“端口转发”的唯一主列表接口。每个 item 在既有安全 DTO 上增加 `{ templateRuleCount, quickConfigRuleCount, referenceRuleCount, quickConfigLocked, systemManagedKind? }`；`referenceRuleCount = templateRuleCount + quickConfigRuleCount`，计数只包含未待删除规则。普通用户仍按既有资源权限过滤，不能因快速配置归属看到无权资源或规则详情。

快速配置创建/编辑/重试在数据库事务内由服务端解析 `portResourceGroupId`，浏览器不得提交该字段。匹配范围固定为同 owner、同 host member、`groupMode=port`、同 engine 的已启用资源；存在稳定 `systemManagedKey` 的资源优先保持，恰有一个候选时复用，否则幂等创建 `systemManagedKind=XRAY_QUICK_CONFIG_PORT` 的资源。`forwardGroups.toggle(false)`、`delete` 和会改变 host/engine/mode 的 `update` 在 `quickConfigRuleCount > 0` 时返回 `QUICK_CONFIG_PORT_RESOURCE_IN_USE`；列表中的禁用只是体验层，服务端检查不可省略。已废弃的 `rules.portLinksPage` 与 `rules.portLinkHostsPage` 不再用于链路管理并从公开 router 删除。

### 19.6 稳定错误码

- 账号：`DNS_PROVIDER_NOT_CONFIGURED`、`DNS_PROVIDER_INVALID`、`DNS_PROVIDER_VALIDATION_STALE`、`DNS_PROVIDER_CATALOG_STALE`、`DNS_PROVIDER_LINE_MISSING`、`DNS_PROVIDER_LINE_AMBIGUOUS`、`DNS_PROVIDER_NO_ZONES`、`DNS_PROVIDER_IN_USE`、`DNS_PROVIDER_CONFLICT`。
- 通用 DNS 管理：`DNS_ZONE_NOT_FOUND`、`DNS_ZONE_IN_USE`、`DNS_RECORD_NOT_FOUND`、`DNS_RECORD_CHANGED`、`DNS_WRITE_UNCERTAIN`、`DNS_PROVIDER_UNAVAILABLE`、`DNS_PROVIDER_REQUEST_REJECTED`、`DNS_PROVIDER_INVALID_RESPONSE`。
- 域名：`DOMAIN_INVALID`、`DOMAIN_CHECK_INVALID`、`DOMAIN_CHECK_EXPIRED`、`DOMAIN_CONFIRMATION_INVALID`、`DOMAIN_CONFIRMATION_EXPIRED`、`DOMAIN_CONFIRMATION_REQUIRED`、`DOMAIN_CONFLICT_CHANGED`、`DOMAIN_ALREADY_MANAGED`、`DNS_RECORD_DRIFT`。
- 目标/主机：`QUICK_CONFIG_NOT_FOUND`、`QUICK_CONFIG_TARGET_UNSUPPORTED`、`QUICK_CONFIG_TARGET_CHANGED`、`QUICK_CONFIG_HOST_UNAVAILABLE`、`QUICK_CONFIG_MANAGED_RULE`、`QUICK_CONFIG_PORT_RESOURCE_IN_USE`；主机离线继续统一使用通用 `HOST_OFFLINE`，UDP 能力不足统一使用 `UDP_CAPABILITY_REQUIRED`，`QUICK_CONFIG_HOST_UNAVAILABLE` 只表示在线主机缺有效公开地址或 Realm runtime 前置条件。
- 端口：`GLOBAL_PORT_CONFLICT`、`GLOBAL_PORT_LEGACY_CONFLICT`、`GLOBAL_PORT_RESERVATION_EXPIRED`、`GLOBAL_PORT_SCAN_PENDING`、`GLOBAL_PORT_EXTERNAL_OCCUPIED`、`GLOBAL_PORT_PROBE_INVALID`、`GLOBAL_PORT_PROBE_EXPIRED`、`GLOBAL_PORT_PROBE_FAILED`、`GLOBAL_PORT_RECOMMENDATION_INVALID`、`GLOBAL_PORT_RECOMMENDATION_EXPIRED`。
- 编排：`QUICK_CONFIG_PREVIEW_INVALID`、`QUICK_CONFIG_PREVIEW_EXPIRED`、`QUICK_CONFIG_REMOVE_TOKEN_INVALID`、`QUICK_CONFIG_REMOVE_TOKEN_EXPIRED`、`QUICK_CONFIG_OPERATION_CONFLICT`、`QUICK_CONFIG_REVISION_CONFLICT`、`QUICK_CONFIG_PARTIAL_FAILURE`、`DNS_COMPENSATION_FAILED`、`RULE_APPLY_FAILED`、`RULE_CLEANUP_FAILED`。

所有错误只携带稳定 code、通用 message 和完成下一步所需的安全 id/revision；不返回 provider 原始错误、Agent 原文、DNSPod RequestId、secret、record ownership hash、reservation token 摘要或完整拓扑 JSON。

## 20. 快速配置六引擎扩展（TASK058）

TASK058 对第 18 节做向后兼容扩展：`QuickConfigSummary.engine`、`QuickConfigPreviewDto.rules[].engine` 和 topology 对应规则引擎从固定 `"realm"` 扩展为 `"iptables" | "nftables" | "realm" | "socat" | "gost" | "nginx"`。同一 topology 只能保存一种 engine；不同 host 不得混用。既有 TASK057 数据仍按 `realm` 读取。

`xray.quickConfigs.forwardEngines({ entries })` 是管理员只读目录，其中 `entries` 为 1–128 个 `{ hostId:number; addressFamily:"IPV4"|"IPV6" }`，重复项按同一选择去重。返回：

```ts
type QuickConfigForwardEngineCatalog = {
  defaultEngine: "realm";
  items: Array<{
    engine: "iptables" | "nftables" | "realm" | "socat" | "gost" | "nginx";
    label: string;
    isDefault: boolean;
    eligible: boolean;
    disabledReasonCode:
      | "FORWARD_PROTOCOL_DISABLED"
      | "HOST_OFFLINE"
      | "AGENT_CAPABILITY_MISSING"
      | "UDP_CAPABILITY_REQUIRED"
      | "QUICK_CONFIG_HOST_UNAVAILABLE"
      | "QUICK_CONFIG_ADDRESS_UNAVAILABLE"
      | null;
  }>;
};
```

候选顺序固定与共享 `FORWARD_TYPES` 一致；`defaultEngine="realm"` 只表示默认推荐，不会在 Realm 不可用时静默改选其他引擎。目录按全部已选 `hostId + addressFamily` 对共享引擎矩阵取交集，并叠加系统 `forwardProtocols` 全局开关、在线/公开地址、现有 TCP/UDP probe 与 UDP listener readiness capability，以及每项固定最低 Agent 版本。旧 Agent、缺失 capability、任一 host/address family 不兼容或全局关闭时返回禁用项，不猜测可用。响应不返回主机地址、Agent 版本、原始 capability、二进制路径或探测原文。

TASK058 起 `xray.quickConfigs.portChecksCreate` 输入增加必填 `engine`；服务端把 engine 与规范 host/address-family cohort 一并绑定到 probe token 和 preview token。`preview`、`createApply`、`editPreview`、`editApply` 在各自消费点重新计算共同可用目录；浏览器提交的 `eligible`、label 或 capability 一律忽略。创建和修改始终生成正式 `forward_rules`，固定 `protocol=tcp`、`proxyProtocolReceive=false`、`proxyProtocolSend=false`。不支持或被关闭的 engine 返回 `FORWARD_PROTOCOL_DISABLED` 或上述主机稳定错误，不回退 Realm，也不按 host 拆成混合 engine。
