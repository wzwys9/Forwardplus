import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { httpLink } from "@trpc/client";
import superjson from "superjson";
import { trpc } from "../../client/src/lib/trpc";
import { XrayQuickConfigDialog } from "../../client/src/components/xray/XrayQuickConfigDialog";

// Every request is fulfilled by Playwright. This mounts the real wizard without
// a panel, account credentials, Agent, provider, or external network access.
const client = trpc.createClient({ links: [httpLink({ url: "/fixture-trpc", transformer: superjson })] });
const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
const carrierLines = (["TELECOM", "UNICOM", "MOBILE", "EDUCATION"] as const).map((category, index) => ({
  category, lineId: index + 2, providerLineId: `10=${index}`, name: category, status: "AVAILABLE" as const,
}));

export function QuickConfigDialogFixture() {
  const [open, setOpen] = useState(true);
  return <trpc.Provider client={client} queryClient={queryClient}><QueryClientProvider client={queryClient}>
    {open ? <XrayQuickConfigDialog onClose={() => setOpen(false)}
      target={{ targetType: "EXTERNAL_PROXY_NODE", targetId: 1, targetVersion: "a".repeat(64), name: "IPv6 落地",
        protocol: "VLESS", endpoint: { address: "2606:4700::1111", port: 33333 },
        eligible: true, disabledReasonCode: null, shareCapability: "VLESS_URI" }}
      account={{ configured: true, provider: "DNSPOD", accountId: 1, name: "Fixture DNSPod", accountRevision: 1,
        bindingRevision: 1, credentialsConfigured: true, secretIdMask: "fixture", secretKeyMask: "fixture",
        validationStatus: "VALID", verifiedAt: null, verificationExpiresAt: null, zonesSyncedAt: null,
        zoneCount: 1, quickConfigReferenceCount: 0, managedRecordCount: 0, canRotateCredentials: true,
        canRebind: true, canRemove: true, lastErrorCode: null }}
      zones={[{ zoneId: 1, providerZoneId: "42", name: "example.com", status: "AVAILABLE", catalogRevision: "fixture",
        expiresAt: "2099-01-01T00:00:00.000Z", catalogUsable: true, catalogReasonCode: null, inUse: false,
        quickConfigReferenceCount: 0, managedRecordCount: 0, activeOperationCount: 0, lines: carrierLines, carrierLines }]} />
      : <p>隔离向导已关闭</p>}
  </QueryClientProvider></trpc.Provider>;
}
