import { adminProcedure } from "../_core/trpc";
import { listXrayQuickConfigEntryHosts } from "../xrayQuickConfigEntryHosts";

export const xrayQuickConfigEntryHostsListProcedure = adminProcedure.query(async ({ ctx }) => {
  ctx.res.setHeader("Cache-Control", "private, no-store, max-age=0");
  ctx.res.setHeader("Pragma", "no-cache");
  return listXrayQuickConfigEntryHosts();
});
