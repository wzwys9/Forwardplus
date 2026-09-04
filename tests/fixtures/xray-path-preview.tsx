import { useState } from "react";
import { createRoot } from "react-dom/client";
import "../../client/src/index.css";
import { XrayQuickConfigPathDesigner } from "../../client/src/components/xray/XrayQuickConfigPathDesigner";
import type { XrayQuickConfigEntryHost, XrayQuickConfigTarget } from "../../client/src/components/xray/xrayQuickConfigFlow";
import { emptyQuickConfigPaths } from "../../client/src/components/xray/xrayQuickConfigPaths";

const names = ["香港 B · 电信入口", "日本 C · 中转", "新加坡 D · 中转", "备用 E（离线）"];
const hosts: XrayQuickConfigEntryHost[] = names.map((name, index) => ({
  hostId: index + 1, name, eligible: index !== 3, disabledReasonCode: index === 3 ? "HOST_OFFLINE" : null,
  endpoints: [{ addressFamily: "IPV4", address: `192.0.2.${index + 1}` },
    { addressFamily: "IPV6", address: `2001:db8:1234:5678:aaaa:bbbb:cccc:${index + 1}` }],
}));
const target: XrayQuickConfigTarget = {
  targetType: "EXTERNAL_PROXY_NODE", targetId: 1, targetVersion: "fixture", name: "美国落地 A",
  protocol: "VLESS", endpoint: { address: "landing.example.com", port: 33333 },
  eligible: true, disabledReasonCode: null, shareCapability: "VLESS_URI",
};
const initial = emptyQuickConfigPaths();
if (new URLSearchParams(window.location.search).has("sample")) {
  initial.TELECOM = [{ id: "t", hops: ["1:IPV4", "2:IPV6", "3:IPV4"] }];
  initial.UNICOM = [{ id: "u", hops: ["1:IPV4", "2:IPV6", "3:IPV4"] }];
  initial.MOBILE = [{ id: "m", hops: ["3:IPV4"] }];
  initial.EDUCATION = [{ id: "e", hops: ["3:IPV6"] }];
}
if (new URLSearchParams(window.location.search).has("direct")) {
  target.targetType = "XRAY_INBOUND";
  target.host = { id: 1, name: hosts[0].name };
  initial.TELECOM = [{ id: "direct", hops: ["1:IPV4"] }];
}
function Fixture() {
  const [open, setOpen] = useState(true);
  return <main><p className="p-4">隔离 UI 夹具 · 所有地址均为示例，不连接真实服务器</p>
    {open ? <XrayQuickConfigPathDesigner target={target} hosts={hosts} loading={false} error={false}
      onRetry={() => {}} onClose={() => setOpen(false)} initialPaths={initial} /> : <p>预览已关闭</p>}
  </main>;
}
createRoot(document.getElementById("root")!).render(<Fixture />);
