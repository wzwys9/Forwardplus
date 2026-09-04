import { trpc } from "@/lib/trpc";
import type { XrayQuickConfigTarget } from "./xrayQuickConfigFlow";
import { XrayQuickConfigPathDesigner } from "./XrayQuickConfigPathDesigner";

// Only the existing read-only, admin-scoped host projection is available here.
export function XrayQuickConfigPathPreview(props: { target: XrayQuickConfigTarget; onClose: () => void }) {
  const hosts = trpc.xray.quickConfigs.entryHostsList.useQuery(undefined, {
    retry: false, refetchInterval: 15_000, refetchOnWindowFocus: true,
  });
  return <XrayQuickConfigPathDesigner target={props.target} hosts={hosts.data?.items ?? []}
    loading={hosts.isLoading} error={hosts.isError}
    onRetry={() => { void hosts.refetch(); }} onClose={props.onClose} />;
}
