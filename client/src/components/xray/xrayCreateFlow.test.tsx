import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { XrayHostPortSteps } from "./XrayHostPortSteps";
import { XrayProfileSteps } from "./XrayProfileSteps";
import {
  availableXrayCreateProfiles,
  currentXrayPortReplacementIds,
  initialXrayCreateState,
  listenerNetworkForXrayProfile,
  listenerNetworksMatch,
  nextSecondaryPortProbeInput,
  portReservationsReady,
  portProbePresentation,
  reduceXrayCreateState,
  type XrayHostOption,
} from "./xrayCreateFlow";

const profileStepProps = {
  section: "TRANSPORT" as const,
  profilesLoading: false,
  profilesError: false,
  onSelectProfile: () => undefined,
  onGrpcServiceNameChange: () => undefined,
  onXhttpPathChange: () => undefined,
  onRetry: () => undefined,
  onBack: () => undefined,
  onNext: () => undefined,
};

const hosts: XrayHostOption[] = [
  { id: 1, name: "香港-01", publicIpv4: "8.8.8.8", isOnline: true, canCreateXrayInbound: true, unavailableReasonCode: null, os: "linux", arch: "amd64" },
  { id: 2, name: "日本-02", publicIpv4: "1.1.1.1", isOnline: false, canCreateXrayInbound: false, unavailableReasonCode: "AGENT_OFFLINE", os: "linux", arch: "amd64" },
  { id: 3, name: "美国-01", publicIpv4: "9.9.9.9", isOnline: true, canCreateXrayInbound: false, unavailableReasonCode: "AGENT_UPGRADE_REQUIRED", os: "linux", arch: "arm64" },
];

test("create flow only exposes server profiles marked available", () => {
  const profiles = availableXrayCreateProfiles([
    { id: "VLESS_RAW_REALITY_VISION", protocol: "VLESS", transport: "RAW", security: "REALITY", clientFlow: "XTLS_RPRX_VISION", listenerNetworks: ["TCP"], clientCredentialType: "UUID_AND_SHORT_ID", shareFormat: "VLESS_URI", testedCoreVersion: "v26.3.27", isAvailable: true, unavailableReasonCode: null },
    { id: "TROJAN_RAW_REALITY", protocol: "TROJAN", transport: "RAW", security: "REALITY", clientFlow: "NONE", listenerNetworks: ["TCP"], clientCredentialType: "PASSWORD", shareFormat: "TROJAN_URI", testedCoreVersion: "v26.3.27", isAvailable: false, unavailableReasonCode: "NOT_IMPLEMENTED" },
  ]);
  assert.deepEqual(profiles.map((profile) => profile.id), ["VLESS_RAW_REALITY_VISION"]);
});

test("mKCP UI identifies UDP, exposes no tuning fields, and explains an Agent capability gate", () => {
  const mkcpProfile = {
    id: "VLESS_MKCP_TLS", protocol: "VLESS", transport: "MKCP", security: "TLS", clientFlow: "NONE",
    listenerNetworks: ["UDP"] as const, clientCredentialType: "UUID", shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
  } as const;
  assert.equal(listenerNetworkForXrayProfile(mkcpProfile), "UDP");
  const mkcpMarkup = renderToStaticMarkup(<XrayProfileSteps
    {...profileStepProps}
    profiles={[mkcpProfile]}
    selectedProfileId={mkcpProfile.id}
    grpcServiceName=""
    xhttpPath=""
  />);
  assert.match(mkcpMarkup, /mKCP/);
  assert.match(mkcpMarkup, /UDP 监听/);
  assert.match(mkcpMarkup, /固定 Xray 核心默认值/);
  assert.doesNotMatch(mkcpMarkup, /<input|MTU|TTI|上行带宽|下行带宽|拥塞控制/);

  const gatedMarkup = renderToStaticMarkup(<XrayProfileSteps
    {...profileStepProps}
    profiles={[mkcpProfile]}
    selectedProfileId={mkcpProfile.id}
    grpcServiceName=""
    xhttpPath=""
    udpCapabilityRequired
  />);
  assert.match(gatedMarkup, /需要升级 Agent 以支持 UDP 端口探测和监听确认/);

  let state = reduceXrayCreateState(initialXrayCreateState(), { type: "SELECT_HOST", host: hosts[0] });
  const portMarkup = renderToStaticMarkup(<XrayHostPortSteps
    section="PORT"
    state={state}
    hosts={hosts}
    hostsLoading={false}
    now={Date.now()}
    listenerNetwork="UDP"
    onAction={() => undefined}
    onProbe={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  assert.match(portMarkup, /UDP 端口检测与短期预留/);
});

test("Hysteria 2 reaches its first port check as UDP after profile selection", () => {
  const hysteriaProfile = {
    id: "HYSTERIA2_TLS", protocol: "HYSTERIA2", transport: "HYSTERIA", security: "TLS", clientFlow: "NONE",
    listenerNetworks: ["UDP"] as const, clientCredentialType: "HYSTERIA_AUTH", shareFormat: "HYSTERIA2_URI",
    testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
  } as const;
  const state = reduceXrayCreateState(initialXrayCreateState(), { type: "SELECT_HOST", host: hosts[0] });
  const markup = renderToStaticMarkup(<XrayHostPortSteps
    section="PORT"
    state={state}
    hosts={hosts}
    hostsLoading={false}
    now={Date.now()}
    listenerNetworks={hysteriaProfile.listenerNetworks}
    onAction={() => undefined}
    onProbe={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);

  assert.equal(listenerNetworkForXrayProfile(hysteriaProfile), "UDP");
  assert.match(markup, /UDP 端口检测与短期预留/);
  assert.match(markup, /返回传输/);
  assert.doesNotMatch(markup, /TCP 端口检测/);
});

test("Shadowsocks dual-network UI distinguishes TCP from same-port TCP plus UDP", () => {
  const tcpProfile = {
    id: "SHADOWSOCKS_2022_RAW_NONE", protocol: "SHADOWSOCKS", transport: "RAW", security: "NONE", clientFlow: "NONE",
    listenerNetworks: ["TCP"] as const, clientCredentialType: "SHADOWSOCKS_KEY", shareFormat: "SHADOWSOCKS_URI",
    testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
  } as const;
  const dualProfile = {
    ...tcpProfile,
    id: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
    listenerNetworks: ["TCP", "UDP"] as const,
  } as const;
  assert.equal(listenerNetworkForXrayProfile(dualProfile), "TCP");
  assert.equal(listenerNetworksMatch(tcpProfile, dualProfile), false);

  const profileMarkup = renderToStaticMarkup(<XrayProfileSteps
    {...profileStepProps}
    profiles={[tcpProfile, dualProfile]}
    selectedProfileId={dualProfile.id}
    grpcServiceName=""
    xhttpPath=""
  />);
  assert.match(profileMarkup, /监听网络/);
  assert.match(profileMarkup, /仅 TCP/);
  assert.match(profileMarkup, /TCP \+ UDP/);

  let state = reduceXrayCreateState(initialXrayCreateState(), { type: "SELECT_HOST", host: hosts[0] });
  state = reduceXrayCreateState(state, { type: "PROBE_QUEUED", operationId: "probe-tcp" });
  state = reduceXrayCreateState(state, { type: "PROBE_RESERVED", selectedPort: 24443, reservationId: "reservation-tcp", expiresAt: "2026-09-01T00:10:00Z" });
  assert.deepEqual(nextSecondaryPortProbeInput(state, dualProfile.listenerNetworks, Date.parse("2026-09-01T00:05:00Z")), {
    hostId: 1,
    mode: "MANUAL",
    network: "UDP",
    manualPort: 24443,
  });
  assert.equal(nextSecondaryPortProbeInput(state, tcpProfile.listenerNetworks, Date.parse("2026-09-01T00:05:00Z")), null);
  state = reduceXrayCreateState(state, { type: "PROBE_QUEUED", slot: "SECONDARY", operationId: "probe-udp" });
  assert.equal(nextSecondaryPortProbeInput(state, dualProfile.listenerNetworks, Date.parse("2026-09-01T00:05:00Z")), null);
  assert.equal(portReservationsReady(state, dualProfile.listenerNetworks, Date.parse("2026-09-01T00:05:00Z")), false);
  state = reduceXrayCreateState(state, { type: "PROBE_RESERVED", slot: "SECONDARY", selectedPort: 24443, reservationId: "reservation-udp", expiresAt: "2026-09-01T00:09:00Z" });
  assert.equal(portReservationsReady(state, dualProfile.listenerNetworks, Date.parse("2026-09-01T00:05:00Z")), true);
  assert.deepEqual(currentXrayPortReplacementIds(state), ["reservation-tcp", "reservation-udp"]);

  const portMarkup = renderToStaticMarkup(<XrayHostPortSteps
    section="PORT"
    state={state}
    hosts={hosts}
    hostsLoading={false}
    now={Date.parse("2026-09-01T00:05:00Z")}
    listenerNetworks={dualProfile.listenerNetworks}
    onAction={() => undefined}
    onProbe={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  assert.match(portMarkup, /TCP \+ UDP 同端口检测与短期预留/);
  assert.match(portMarkup, /TCP[^<]*已预留|TCP[\s\S]*端口可用/);
  assert.match(portMarkup, /UDP[^<]*已预留|UDP[\s\S]*端口可用/);
  assert.match(portMarkup, /下一步：配置安全/);

  const reset = reduceXrayCreateState(state, { type: "RESET_PROBE" });
  assert.equal(reset.probe.phase, "IDLE");
  assert.equal(reset.secondaryProbe.phase, "IDLE");
  assert.deepEqual(currentXrayPortReplacementIds(reset), ["reservation-tcp", "reservation-udp"]);
});

test("create flow preserves draft through offline failure and reservation expiry", () => {
  let state = initialXrayCreateState();
  state = reduceXrayCreateState(state, { type: "SELECT_HOST", host: hosts[0] });
  state = reduceXrayCreateState(state, { type: "SET_NAME", value: "香港 Reality" });
  state = reduceXrayCreateState(state, { type: "SET_PORT_MODE", mode: "MANUAL" });
  state = reduceXrayCreateState(state, { type: "SET_MANUAL_PORT", value: "24443" });
  state = reduceXrayCreateState(state, { type: "PROBE_QUEUED", operationId: "probe-1" });
  state = reduceXrayCreateState(state, { type: "PROBE_RESERVED", selectedPort: 24443, reservationId: "reservation-1", expiresAt: "2026-09-01T00:01:00Z" });
  assert.equal(portProbePresentation(state, Date.parse("2026-09-01T00:02:00Z")).phase, "EXPIRED");
  state = reduceXrayCreateState(state, { type: "PROBE_FAILED", errorCode: "HOST_OFFLINE" });
  assert.deepEqual({ hostId: state.hostId, name: state.name, publicAddress: state.publicAddress, manualPort: state.manualPort }, {
    hostId: 1, name: "香港 Reality", publicAddress: "8.8.8.8", manualPort: "24443",
  });
  assert.equal(portProbePresentation(state, Date.parse("2026-09-01T00:02:00Z")).message, "Agent 离线，已保留表单，请恢复连接后重新探测。");
});

test("gRPC profile shows strict serviceName input and no Vision flow", () => {
  const grpcProfile = {
    id: "VLESS_GRPC_REALITY", protocol: "VLESS", transport: "GRPC", security: "REALITY", clientFlow: "NONE",
    listenerNetworks: ["TCP"] as const, clientCredentialType: "UUID_AND_SHORT_ID", shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
  } as const;
  const markup = renderToStaticMarkup(
    <XrayProfileSteps
      {...profileStepProps}
      profiles={[grpcProfile]}
      selectedProfileId={grpcProfile.id}
      grpcServiceName="forwardx-grpc"
      xhttpPath=""
    />,
  );
  assert.match(markup, /gRPC 服务名/);
  assert.match(markup, /value="forwardx-grpc"/);
  assert.match(markup, /无 Flow/);
  assert.doesNotMatch(markup, />Vision</);
});

test("XHTTP profile shows only its strict path input and no advanced settings", () => {
  const xhttpProfile = {
    id: "VLESS_XHTTP_REALITY", protocol: "VLESS", transport: "XHTTP", security: "REALITY", clientFlow: "NONE",
    listenerNetworks: ["TCP"] as const, clientCredentialType: "UUID_AND_SHORT_ID", shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
  } as const;
  const markup = renderToStaticMarkup(
    <XrayProfileSteps
      {...profileStepProps}
      profiles={[xhttpProfile]}
      selectedProfileId={xhttpProfile.id}
      grpcServiceName=""
      xhttpPath="/forwardx/xhttp-v1"
    />,
  );
  assert.match(markup, /XHTTP 路径/);
  assert.match(markup, /value="\/forwardx\/xhttp-v1"/);
  assert.match(markup, /固定使用 auto/);
  assert.doesNotMatch(markup, /xmux|padding|headers/i);
  assert.doesNotMatch(markup, />Vision</);
});

test("Trojan Reality profile needs no browser-side credential fields", () => {
  const trojanProfile = {
    id: "TROJAN_RAW_REALITY", protocol: "TROJAN", transport: "RAW", security: "REALITY", clientFlow: "NONE",
    listenerNetworks: ["TCP"] as const, clientCredentialType: "PASSWORD", shareFormat: "TROJAN_URI",
    testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
  } as const;
  const markup = renderToStaticMarkup(
    <XrayProfileSteps
      {...profileStepProps}
      profiles={[trojanProfile]}
      selectedProfileId={trojanProfile.id}
      grpcServiceName=""
      xhttpPath=""
    />,
  );
  assert.match(markup, /TROJAN · RAW \/ TCP · Reality/);
  assert.match(markup, /无 Flow/);
  assert.doesNotMatch(markup, /Password|密码|shortId|UUID|gRPC 服务名|XHTTP 路径/);
});

test("host and port steps keep unavailable hosts visible with reasons and waiting state", () => {
  let state = reduceXrayCreateState(initialXrayCreateState(), { type: "SELECT_HOST", host: hosts[0] });
  state = reduceXrayCreateState(state, { type: "SET_NAME", value: "香港 Reality" });
  const hostMarkup = renderToStaticMarkup(
    <XrayHostPortSteps section="BASIC" state={state} hosts={hosts} hostsLoading={false} now={Date.now()} onAction={() => undefined} onProbe={() => undefined} onNext={() => undefined} />,
  );
  state = reduceXrayCreateState(state, { type: "PROBE_QUEUED", operationId: "probe-1" });
  const portMarkup = renderToStaticMarkup(
    <XrayHostPortSteps section="PORT" state={state} hosts={hosts} hostsLoading={false} now={Date.now()} onAction={() => undefined} onProbe={() => undefined} onBack={() => undefined} onNext={() => undefined} />,
  );
  assert.match(hostMarkup, /日本-02/);
  assert.match(hostMarkup, /Agent 离线，无法检测端口或部署/);
  assert.match(hostMarkup, /美国-01/);
  assert.match(hostMarkup, /Agent 版本过低，请先升级 Agent/);
  assert.match(hostMarkup, /disabled/);
  assert.match(hostMarkup, /香港 Reality/);
  assert.doesNotMatch(hostMarkup, /协议配置|VLESS · RAW · Reality/);
  assert.match(hostMarkup, /下一步：选择协议/);
  assert.doesNotMatch(hostMarkup, /自动分配|手动端口|检测并预留端口/);
  assert.match(portMarkup, /等待 Agent 探测端口/);

  const offlineHosts = hosts.map((host) => host.id === 1 ? { ...host, isOnline: false, canCreateXrayInbound: false, unavailableReasonCode: "AGENT_OFFLINE" as const } : host);
  const offlineMarkup = renderToStaticMarkup(
    <XrayHostPortSteps section="BASIC" state={state} hosts={offlineHosts} hostsLoading={false} now={Date.now()} onAction={() => undefined} onProbe={() => undefined} onNext={() => undefined} />,
  );
  assert.match(offlineMarkup, /Agent 离线，无法检测端口或部署；已填写内容会保留/);
  assert.match(offlineMarkup, /value="香港 Reality"/);
});
