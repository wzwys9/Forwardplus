import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { httpLink } from "@trpc/client";
import superjson from "superjson";
import { trpc } from "../../client/src/lib/trpc";
import DnsRecordManagementCard from "../../client/src/components/DnsRecordManagementCard";
import "../../client/src/index.css";

// Playwright intercepts this path. No panel, DNS credentials or Agent is used.
const client = trpc.createClient({ links: [httpLink({ url: "/fixture-trpc", transformer: superjson })] });
const queryClient = new QueryClient();
createRoot(document.getElementById("root")!).render(
  <trpc.Provider client={client} queryClient={queryClient}>
    <QueryClientProvider client={queryClient}>
      <main className="mx-auto max-w-5xl p-3"><DnsRecordManagementCard accountValid zones={[{
        zoneId: 1, name: "example.com", status: "AVAILABLE", inUse: false,
        quickConfigReferenceCount: 0, managedRecordCount: 0, activeOperationCount: 0,
        lines: [{ lineId: 1, providerLineId: "0", name: "默认", status: "AVAILABLE" }],
      }]} /></main>
    </QueryClientProvider>
  </trpc.Provider>,
);
