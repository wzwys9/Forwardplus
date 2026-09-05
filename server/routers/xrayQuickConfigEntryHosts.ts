import { adminProcedure } from "../_core/trpc";
import { listXrayQuickConfigEntryHosts } from "../xrayQuickConfigEntryHosts";
import { z } from "zod";
import { FORWARD_TYPES } from "../../shared/forwardTypes";

export const xrayQuickConfigEntryHostsListProcedure = adminProcedure
  .input(z.object({ engine: z.enum(FORWARD_TYPES).optional() }).strict().optional())
  .query(async ({ ctx, input }) => {
  ctx.res.setHeader("Cache-Control", "private, no-store, max-age=0");
  ctx.res.setHeader("Pragma", "no-cache");
  return listXrayQuickConfigEntryHosts(input?.engine);
});
