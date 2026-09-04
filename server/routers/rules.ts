import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { crudRulesRouter } from "./rules.crud";
import { portsRulesRouter } from "./rules.ports";
import { selfTestRulesRouter } from "./rules.selfTest";
import { trafficRulesRouter } from "./rules.traffic";
import { canUseForwardRuleResource, getLinkAccessScope } from "../linkAccessView";
import { isManagedForwardGroupChildRule } from "../forwardRuleVisibility";
import { getXrayExternalProxyNodeSummaries } from "../xrayExternalProxyService";
import { inList, quoteIdentifier } from "../dbCompat";
import { queryRaw } from "../dbRuntime";

const QUICK_CONFIG_LINE_CATEGORIES = ["DEFAULT", "TELECOM", "UNICOM", "MOBILE", "EDUCATION"] as const;
const QUICK_CONFIG_STATES = new Set([
  "APPLYING", "ACTIVE", "UPDATING", "DELETING", "COMPENSATING", "PARTIAL_FAILURE", "FAILED", "REMOVED",
]);

type QuickConfigLineCategory = typeof QUICK_CONFIG_LINE_CATEGORIES[number];
type QuickConfigRef = {
  id: number;
  fqdn: string;
  targetName: string;
  lineCategories: QuickConfigLineCategory[];
  operationState: string;
};

async function withQuickConfigRefs<T extends any>(value: T): Promise<T> {
  const rules: any[] = Array.isArray(value)
    ? value
    : value && Array.isArray((value as any).items)
      ? (value as any).items
      : value ? [value] : [];
  const ruleIds = [...new Set(rules
    .filter((rule) => Number(rule?.xrayQuickConfigId || 0) > 0)
    .map((rule) => Number(rule?.id || 0))
    .filter((id) => Number.isSafeInteger(id) && id > 0))];
  if (ruleIds.length === 0) return value;

  const q = quoteIdentifier;
  const byRuleId = new Map<number, QuickConfigRef>();
  const lineSets = new Map<number, Set<QuickConfigLineCategory>>();
  for (let offset = 0; offset < ruleIds.length; offset += 400) {
    const ids = inList(ruleIds.slice(offset, offset + 400));
    const rows = await queryRaw<Record<string, unknown>>(
      `SELECT fr.${q("id")} AS ${q("ruleId")}, qc.${q("id")} AS ${q("quickConfigId")},
              qc.${q("fqdn")} AS ${q("fqdn")}, qc.${q("state")} AS ${q("operationState")},
              CASE WHEN qc.${q("targetType")} = 'XRAY_INBOUND' THEN xi.${q("name")}
                   ELSE ep.${q("name")} END AS ${q("targetName")},
              qr.${q("lineCategory")} AS ${q("lineCategory")}
         FROM ${q("forward_rules")} fr
         JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = fr.${q("xrayQuickConfigId")}
         LEFT JOIN ${q("xray_inbounds")} xi ON xi.${q("id")} = qc.${q("xrayInboundId")}
         LEFT JOIN ${q("xray_external_proxy_nodes")} ep ON ep.${q("id")} = qc.${q("externalProxyNodeId")}
         LEFT JOIN ${q("xray_quick_config_rule_bindings")} qb
           ON qb.${q("quickConfigId")} = qc.${q("id")}
          AND qb.${q("forwardRuleId")} = fr.${q("id")}
          AND qb.${q("state")} <> 'REMOVED'
         LEFT JOIN ${q("xray_quick_config_routes")} qr
           ON qr.${q("quickConfigId")} = qc.${q("id")}
          AND qr.${q("topologyRevisionId")} = qb.${q("topologyRevisionId")}
          AND qr.${q("hostId")} = fr.${q("hostId")}
          AND qr.${q("routeMode")} = 'FORWARD'
          AND qr.${q("state")} <> 'RETIRED'
        WHERE fr.${q("id")} IN ${ids.sql}`,
      ids.params,
    );
    for (const row of rows) {
      const ruleId = Number(row.ruleId || 0);
      const quickConfigId = Number(row.quickConfigId || 0);
      if (!Number.isSafeInteger(ruleId) || ruleId <= 0 || !Number.isSafeInteger(quickConfigId) || quickConfigId <= 0) continue;
      if (!byRuleId.has(ruleId)) {
        const rawState = String(row.operationState || "");
        byRuleId.set(ruleId, {
          id: quickConfigId,
          fqdn: String(row.fqdn || ""),
          targetName: String(row.targetName || ""),
          lineCategories: [],
          operationState: QUICK_CONFIG_STATES.has(rawState) ? rawState : "FAILED",
        });
        lineSets.set(ruleId, new Set());
      }
      const lineCategory = String(row.lineCategory || "") as QuickConfigLineCategory;
      if ((QUICK_CONFIG_LINE_CATEGORIES as readonly string[]).includes(lineCategory)) {
        lineSets.get(ruleId)?.add(lineCategory);
      }
    }
  }
  for (const [ruleId, ref] of byRuleId) {
    const lines = lineSets.get(ruleId) || new Set<QuickConfigLineCategory>();
    ref.lineCategories = QUICK_CONFIG_LINE_CATEGORIES.filter((line) => lines.has(line));
  }

  const decorate = (rule: any) => {
    if (!rule || typeof rule !== "object") return rule;
    const ref = byRuleId.get(Number(rule.id || 0));
    return ref ? { ...rule, quickConfigRef: ref } : rule;
  };
  if (Array.isArray(value)) return rules.map(decorate) as T;
  if (value && Array.isArray((value as any).items)) return { ...value, items: rules.map(decorate) } as T;
  return decorate(value) as T;
}

async function withRuleResourceAccess<T extends any>(value: T, user: { id: number; role: string }): Promise<T> {
  if (user.role === "admin") return value;
  const scope = await getLinkAccessScope(user);
  const decorate = (rule: any) => ({
    ...rule,
    resourceAccessAllowed: canUseForwardRuleResource(rule, scope),
  });
  if (Array.isArray(value)) return value.map(decorate) as T;
  if (value && Array.isArray((value as any).items)) {
    return { ...value, items: (value as any).items.map(decorate) } as T;
  }
  return (value ? decorate(value) : value) as T;
}

async function withExternalProxySummaries<T extends any>(value: T, user: { role: string }): Promise<T> {
  const rules: any[] = Array.isArray(value)
    ? value
    : value && Array.isArray((value as any).items)
      ? (value as any).items
      : value ? [value] : [];
  if (user.role !== "admin") {
    const strip = (rule: any) => {
      if (!rule || typeof rule !== "object") return rule;
      const { targetExternalProxyNodeId: _hidden, ...safe } = rule;
      return safe;
    };
    if (Array.isArray(value)) return rules.map(strip) as T;
    if (value && Array.isArray((value as any).items)) return { ...value, items: rules.map(strip) } as T;
    return strip(value) as T;
  }
  const ids = [...new Set(rules.map((rule) => Number(rule?.targetExternalProxyNodeId || 0)).filter((id) => id > 0))];
  const nodes = await getXrayExternalProxyNodeSummaries(ids);
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const decorate = (rule: any) => {
    const id = Number(rule?.targetExternalProxyNodeId || 0);
    const node = byId.get(id);
    return {
      ...rule,
      externalProxy: node ? {
        id: node.id,
        name: node.name,
        protocol: node.protocol,
        address: node.address,
        port: node.port,
      } : null,
    };
  };
  if (Array.isArray(value)) return rules.map(decorate) as T;
  if (value && Array.isArray((value as any).items)) return { ...value, items: rules.map(decorate) } as T;
  return decorate(value) as T;
}


type RuleListCategory = "all" | "local" | "tunnel" | "chain" | "group";
type RuleListFilters = {
  userId?: number;
  scope?: "self" | "all";
  entryHostId?: number | null;
  category: RuleListCategory;
  search: string;
};

async function getRuleListRepositoryInput(
  input: RuleListFilters,
  user: { id: number; role: string },
) {
  const isAdmin = user.role === "admin";
  const accessScope = isAdmin ? null : await getLinkAccessScope(user);
  const ownerUserId = isAdmin
    ? input.scope === "all"
      ? undefined
      : input.userId ?? user.id
    : user.id;
  return {
    ownerUserId,
    searchVisibleHostIds: accessScope
      ? Array.from(accessScope.useHostIds || accessScope.hostIds)
      : undefined,
    searchVisibleTunnelIds: accessScope
      ? Array.from(accessScope.useTunnelIds || accessScope.tunnelIds)
      : undefined,
    searchVisibleForwardGroupIds: accessScope
      ? Array.from(accessScope.useGroupIds || accessScope.groupIds)
      : undefined,
    entryHostId: input.entryHostId,
    category: input.category,
    search: input.search,
  };
}

export const rulesRouter = router({
  list: protectedProcedure
    .input(z.object({
      hostId: z.number().optional(),
      userId: z.number().optional(),
      scope: z.enum(["self", "all"]).optional(),
      tunnelId: z.number().nullable().optional(),
    }).optional())
    .query(async ({ input, ctx }) => {
      const isAdmin = ctx.user.role === "admin";
      const requestedUserId = isAdmin
        ? input?.scope === "all"
          ? undefined
          : input?.userId ?? ctx.user.id
        : ctx.user.id;
      const rules = await db.getForwardRules(requestedUserId, input?.hostId);
      const filtered = input?.tunnelId === undefined
        ? rules
        : input.tunnelId === null
          ? rules.filter((rule: any) => !rule.tunnelId)
          : rules.filter((rule: any) => Number(rule.tunnelId || 0) === Number(input.tunnelId));
      return withQuickConfigRefs(await withExternalProxySummaries(await withRuleResourceAccess(filtered, ctx.user), ctx.user));
    }),
  listPage: protectedProcedure
    .input(z.object({
      page: z.number().int().positive().default(1),
      pageSize: z.number().int().min(1).max(100).default(12),
      userId: z.number().optional(),
      scope: z.enum(["self", "all"]).optional(),
      entryHostId: z.number().int().positive().nullable().optional(),
      category: z.enum(["all", "local", "tunnel", "chain", "group"]).default("all"),
      search: z.string().trim().max(200).optional().default(""),
    }))
    .query(async ({ input, ctx }) => {
      const repositoryInput = await getRuleListRepositoryInput(input, ctx.user);
      const page = await db.getForwardRulesPage({ ...repositoryInput, page: input.page, pageSize: input.pageSize });
      return withQuickConfigRefs(await withExternalProxySummaries(await withRuleResourceAccess(page, ctx.user), ctx.user));
    }),
  mapItems: protectedProcedure
    .input(z.object({
      cursor: z.number().int().min(0).optional(),
      limit: z.number().int().min(20).max(250).default(100),
      userId: z.number().optional(),
      scope: z.enum(["self", "all"]).optional(),
      entryHostId: z.number().int().positive().nullable().optional(),
      category: z.enum(["all", "local", "tunnel", "chain", "group"]).default("all"),
      search: z.string().trim().max(200).optional().default(""),
    }))
    .query(async ({ input, ctx }) => {
      const repositoryInput = await getRuleListRepositoryInput(input, ctx.user);
      const batch = await db.getForwardRuleMapBatch(repositoryInput, input.cursor || 0, input.limit);
      return withQuickConfigRefs(await withExternalProxySummaries(await withRuleResourceAccess(batch, ctx.user), ctx.user));
    }),
  listSummary: protectedProcedure
    .input(z.object({
      userId: z.number().optional(),
      scope: z.enum(["self", "all"]).optional(),
      entryHostId: z.number().int().positive().nullable().optional(),
      category: z.enum(["all", "local", "tunnel", "chain", "group"]).default("all"),
      search: z.string().trim().max(200).optional().default(""),
    }))
    .query(async ({ input, ctx }) => {
      const repositoryInput = await getRuleListRepositoryInput(input, ctx.user);
      const selection = await db.getForwardRuleSummarySelection(repositoryInput);
      const [totalRows, dailyRows] = selection.ruleIds.length > 0
        ? await Promise.all([
          db.getTrafficCounterSummaryByRule({
            userId: ctx.user.role === "admin" ? undefined : ctx.user.id,
            ruleIds: selection.ruleIds,
          }),
          db.getTrafficSummaryByRule({
            userId: ctx.user.role === "admin" ? undefined : ctx.user.id,
            ruleIds: selection.ruleIds,
            since: new Date(Date.now() - 24 * 60 * 60 * 1000),
          }),
        ])
        : [[], []];
      const sumRows = (rows: any[]) => rows.reduce((total, row) => ({
        bytesIn: total.bytesIn + Math.max(0, Number(row?.bytesIn) || 0),
        bytesOut: total.bytesOut + Math.max(0, Number(row?.bytesOut) || 0),
        connections: total.connections + Math.max(0, Number(row?.connections) || 0),
      }), { bytesIn: 0, bytesOut: 0, connections: 0 });
      return {
        totalItems: selection.totalItems,
        activeItems: selection.activeItems,
        totalTraffic: sumRows(totalRows as any[]),
        dailyTraffic: sumRows(dailyRows as any[]),
      };
    }),
  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input, ctx }) => {
      const rule = await db.getForwardRuleById(input.id);
      if (!rule) return null;
      if (ctx.user.role !== "admin" && rule.userId !== ctx.user.id) return null;
      if (ctx.user.role !== "admin" && isManagedForwardGroupChildRule(rule)) return null;
      return withQuickConfigRefs(await withExternalProxySummaries(await withRuleResourceAccess(rule, ctx.user), ctx.user));
    }),
  reorder: protectedProcedure
    .input(z.object({
      category: z.enum(["local", "tunnel", "chain", "group"]),
      ids: z.array(z.number().int().positive()).min(1),
      startIndex: z.number().int().min(0).max(1_000_000).optional().default(0),
    }))
    .mutation(async ({ input, ctx }) => {
      await db.reorderForwardRules(input.category, input.ids, ctx.user.role === "admin" ? undefined : ctx.user.id, input.startIndex);
      return { success: true };
    }),
  ...portsRulesRouter._def.procedures,
  ...crudRulesRouter._def.procedures,
  ...trafficRulesRouter._def.procedures,
  ...selfTestRulesRouter._def.procedures,
});
