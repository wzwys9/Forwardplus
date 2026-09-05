import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { httpLink } from "@trpc/client";
import superjson from "superjson";
import { trpc } from "../../client/src/lib/trpc";
import { XrayQuickConfigPanel } from "../../client/src/components/xray/XrayQuickConfigPanel";

// Mock transport only; invalidation simulates a background refresh without DNS writes.
const client = trpc.createClient({ links: [httpLink({ url: "/fixture-trpc", transformer: superjson })] });
const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });

export function QuickConfigListFixture() {
  return <trpc.Provider client={client} queryClient={queryClient}><QueryClientProvider client={queryClient}>
    <main className="mx-auto max-w-3xl p-3">
      <button type="button" onClick={() => { void queryClient.invalidateQueries(); }}>模拟后台刷新</button>
      <XrayQuickConfigPanel account={{ configured: false, provider: "DNSPOD", bindingRevision: 1 }}
        zones={[]} onOpenSettings={() => {}} />
    </main>
  </QueryClientProvider></trpc.Provider>;
}
