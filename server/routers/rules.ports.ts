import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import {
  requireHostUseAccess,
  requireRuleAccess,
  requireTrafficBillingAccessIfConfigured,
  requireTunnelUseOrTrafficBillingAccess,
} from "./helpers";
import { combinePortPolicies, isPortAllowedByPolicy, portPolicyErrorMessage, portPolicyFrom } from "../portPolicy";
import {
  assertGlobalPortAvailable,
  collectUnavailableGlobalPorts,
  GlobalPortAllocationError,
  type GlobalPortOwner,
} from "../globalPortAllocationService";
import { createRulePortCheck, discardRulePortCheck, getRulePortCheckResult } from "../rulePortProbeService";
import { XrayPortOperationError } from "../xrayPortOperations";

const randomPortInputSchema = z.object({
  hostId: z.number().optional(),
  tunnelId: z.number().nullable().optional(),
  forwardGroupId: z.number().optional(),
  excludeRuleId: z.number().optional(),
  protocol: z.enum(["tcp", "udp", "both"]).optional().default("both"),
});

async function requireForwardGroupPortAccess(ctx: { user: { id: number; role: string } }, forwardGroupId: number) {
  if (ctx.user.role === "admin") return;
  const isTrafficBillingResource = await requireTrafficBillingAccessIfConfigured(
    ctx,
    "forward_group",
    forwardGroupId,
  );
  if (isTrafficBillingResource) return;
  const hasPermission = await db.checkUserForwardGroupPermission(ctx.user.id, forwardGroupId);
  if (!hasPermission) throw new Error("无权使用该转发组");
}

type PortCheckInput = {
  hostId?: number;
  forwardGroupId?: number;
  tunnelId?: number | null;
  sourcePort: number;
  excludeRuleId?: number;
  protocol: "tcp" | "udp" | "both";
};

type PortCheckContext = { user: { id: number; role: string } };

function globalPortReason(error: GlobalPortAllocationError) {
  if (error.code === "GLOBAL_PORT_INVALID") return "新建规则源端口必须在 1000-65535 之间";
  if (error.code === "GLOBAL_PORT_LEGACY_CONFLICT") return "端口存在历史冲突，暂不可使用";
  if (error.code === "GLOBAL_PORT_SCAN_PENDING") return "端口正在等待全局空闲确认";
  if (error.code === "GLOBAL_PORT_EXTERNAL_OCCUPIED") return "端口已被服务器上的其他服务占用";
  return "端口已被全局占用";
}

async function editedRuleOwner(excludeRuleId?: number): Promise<GlobalPortOwner | undefined> {
  if (!excludeRuleId) return undefined;
  const rule = await db.getForwardRuleById(excludeRuleId) as any;
  if (!rule || rule.xrayQuickConfigId != null) return undefined;
  const ownerId = Number(rule.forwardGroupRuleId || rule.id || 0);
  return Number.isSafeInteger(ownerId) && ownerId > 0
    ? { type: "FORWARD_RULE", stableIdentity: ownerId }
    : undefined;
}

async function evaluateRulePort(input: PortCheckInput, ctx: PortCheckContext): Promise<{
  used: boolean;
  reason?: string;
  reasonCode?: string;
  hostIds: number[];
}> {
  if (input.excludeRuleId) await requireRuleAccess(ctx, input.excludeRuleId);
  const allowedOwner = await editedRuleOwner(input.excludeRuleId);
  if (!input.excludeRuleId && input.sourcePort < 1_000) {
    return {
      used: true,
      reason: "新建规则源端口必须在 1000-65535 之间",
      reasonCode: "PORT_OUT_OF_RANGE",
      hostIds: [],
    };
  }

  let hostIds: number[];
  if (input.forwardGroupId) {
    if (ctx.user.role !== "admin") {
      await requireForwardGroupPortAccess(ctx, input.forwardGroupId);
      const planRange = await db.getUserForwardGroupPlanPortRange(ctx.user.id, input.forwardGroupId);
      if (planRange && !db.isPortAllowedByUserPlanRange(input.sourcePort, planRange)) {
        const ranges = planRange.ranges.map((range) => `${range.start}-${range.end}`).join(",");
        return { used: true, reason: `套餐端口必须在 ${ranges} 范围内`, reasonCode: "PORT_OUT_OF_RANGE", hostIds: [] };
      }
    }
    try {
      await db.validateForwardGroupRuleConfig(input.forwardGroupId, {
        sourcePort: input.sourcePort,
        protocol: input.protocol,
        excludeTemplateRuleId: input.excludeRuleId,
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : "";
      const isRangeError = /必须在.*(?:范围|区间)|must be.*range/i.test(reason);
      return {
        used: true,
        ...(isRangeError ? { reason } : {}),
        reasonCode: isRangeError ? "PORT_OUT_OF_RANGE" : "PORT_IN_USE",
        hostIds: [],
      };
    }
    hostIds = await db.getForwardGroupRuleEntryHostIds(input.forwardGroupId);
  } else {
    const hostId = Number(input.hostId);
    let policy = portPolicyFrom(null);
    if (input.tunnelId) {
      const { tunnel } = await requireTunnelUseOrTrafficBillingAccess(ctx, input.tunnelId);
      if (tunnel.entryHostId !== hostId) throw new Error("隧道入口主机与规则主机不一致");
      const host = await db.getHostById(hostId);
      policy = combinePortPolicies(
        portPolicyFrom(host as any),
        portPolicyFrom({
          portRangeStart: (tunnel as any).portRangeStart,
          portRangeEnd: (tunnel as any).portRangeEnd,
        }),
      );
    } else {
      const { host } = await requireHostUseAccess(ctx, hostId);
      policy = portPolicyFrom(host as any);
    }
    if (!isPortAllowedByPolicy(input.sourcePort, policy)) {
      return { used: true, reason: portPolicyErrorMessage(policy), reasonCode: "PORT_OUT_OF_RANGE", hostIds: [] };
    }
    if (ctx.user.role !== "admin") {
      const planRange = await db.getUserPlanPortRange(ctx.user.id, hostId, input.tunnelId ?? undefined);
      if (planRange) {
        policy = combinePortPolicies(policy, portPolicyFrom({ portRanges: planRange.ranges }));
      }
      if (planRange && !isPortAllowedByPolicy(input.sourcePort, policy)) {
        return { used: true, reason: portPolicyErrorMessage(policy, "套餐端口"), reasonCode: "PORT_OUT_OF_RANGE", hostIds: [] };
      }
    }
    const excludeRuleIds = input.excludeRuleId
      ? [
          input.excludeRuleId,
          ...((await db.getForwardGroupChildRulesForTemplate(input.excludeRuleId)) as any[]).map((rule: any) => Number(rule.id)),
        ]
      : [];
    const used = await db.isPortUsedOnHost(hostId, input.sourcePort, excludeRuleIds, input.protocol, undefined, false);
    if (used) return { used: true, reasonCode: "PORT_IN_USE", hostIds: [] };
    hostIds = [hostId];
  }

  if (!input.excludeRuleId || input.sourcePort >= 1_000) {
    try {
      await assertGlobalPortAvailable(input.sourcePort, allowedOwner);
    } catch (error) {
      if (!(error instanceof GlobalPortAllocationError)) throw error;
      return { used: true, reason: globalPortReason(error), reasonCode: error.code, hostIds: [] };
    }
  }
  return { used: false, hostIds: Array.from(new Set(hostIds)).sort((left, right) => left - right) };
}

const portTargetFields = {
  hostId: z.number().int().positive().optional(),
  forwardGroupId: z.number().int().positive().optional(),
  tunnelId: z.number().nullable().optional(),
  sourcePort: z.number().int().min(1).max(65535),
  protocol: z.enum(["tcp", "udp", "both"]).optional().default("both"),
};

function failedProbeStart(error: unknown) {
  if (error instanceof XrayPortOperationError) {
    if (error.code === "PORT_IN_USE") {
      return { status: "USED" as const, reasonCode: error.code, reason: "端口已被入口服务器占用" };
    }
    const reason = error.code === "HOST_OFFLINE"
      ? "入口服务器已离线"
      : error.code === "AGENT_CAPABILITY_MISSING" || error.code === "UDP_CAPABILITY_REQUIRED"
        ? "入口服务器 Agent 不支持所需端口检测"
        : "入口服务器端口检测无法启动，请重试";
    return { status: "FAILED" as const, reasonCode: error.code, reason };
  }
  throw error;
}

export const portsRulesRouter = router({
  checkPort: protectedProcedure
    .input(z.object({
      hostId: z.number().int().positive().optional(),
      forwardGroupId: z.number().int().positive().optional(),
      tunnelId: z.number().nullable().optional(),
      sourcePort: z.number().min(1).max(65535),
      excludeRuleId: z.number().optional(),
      protocol: z.enum(["tcp", "udp", "both"]).optional().default("both"),
    }).refine(
      (input) => !!input.hostId !== !!input.forwardGroupId,
      { message: "请选择一个主机、隧道或转发组" },
    ))
    .query(async ({ input, ctx }) => {
      const result = await evaluateRulePort(input, ctx);
      return { used: result.used, ...(result.reason ? { reason: result.reason } : {}) };
    }),
  portProbeStart: protectedProcedure
    .input(z.object({ ...portTargetFields, replacePortCheckId: z.string().max(16_384).optional() }).refine(
      (input) => !!input.hostId !== !!input.forwardGroupId,
      { message: "请选择一个主机、隧道或转发组" },
    ))
    .mutation(async ({ input, ctx }) => {
      if (input.replacePortCheckId) await discardRulePortCheck(input.replacePortCheckId, ctx.user.id);
      const availability = await evaluateRulePort(input, ctx);
      if (availability.used) {
        return {
          status: "USED" as const,
          reasonCode: availability.reasonCode || "PORT_IN_USE",
          reason: availability.reason || "端口已被占用",
        };
      }
      try {
        return await createRulePortCheck({
          userId: ctx.user.id,
          hostIds: availability.hostIds,
          sourcePort: input.sourcePort,
          protocol: input.protocol,
        });
      } catch (error) {
        return failedProbeStart(error);
      }
    }),
  portProbeResult: protectedProcedure
    .input(z.object({ portCheckId: z.string().min(1).max(16_384) }).strict())
    .query(async ({ input, ctx }) => getRulePortCheckResult({
      userId: ctx.user.id,
      portCheckId: input.portCheckId,
    })),
  portProbeDiscard: protectedProcedure
    .input(z.object({ portCheckId: z.string().min(1).max(16_384) }).strict())
    .mutation(async ({ input, ctx }) => {
      await discardRulePortCheck(input.portCheckId, ctx.user.id);
      return { success: true as const };
    }),
  randomPort: protectedProcedure
    .input(randomPortInputSchema)
    .query(async ({ input, ctx }) => {
      if (input.excludeRuleId) {
        await requireRuleAccess(ctx, input.excludeRuleId);
      }
      if (input.forwardGroupId) {
        let planRange: Awaited<ReturnType<typeof db.getUserForwardGroupPlanPortRange>> = null;
        if (ctx.user.role !== "admin") {
          await requireForwardGroupPortAccess(ctx, input.forwardGroupId);
          planRange = await db.getUserForwardGroupPlanPortRange(ctx.user.id, input.forwardGroupId);
        }
        const unavailablePorts = await collectUnavailableGlobalPorts();
        const port = await db.findAvailableForwardGroupPort(
          input.forwardGroupId,
          input.excludeRuleId,
          planRange,
          input.protocol,
          unavailablePorts,
        );
        if (!port) throw new Error("转发组入口端口区间内已无可用端口");
        return { port };
      }
      if (!input.hostId) throw new Error("请选择主机");
      let rangeStart: number | null | undefined;
      let rangeEnd: number | null | undefined;
      let planRange: Awaited<ReturnType<typeof db.getUserPlanPortRange>> = null;
      if (input.tunnelId) {
        const { tunnel } = await requireTunnelUseOrTrafficBillingAccess(ctx, input.tunnelId);
        if (tunnel.entryHostId !== input.hostId) throw new Error("隧道入口主机与规则主机不一致");
        rangeStart = (tunnel as any).portRangeStart;
        rangeEnd = (tunnel as any).portRangeEnd;
      } else {
        await requireHostUseAccess(ctx, input.hostId);
      }
      if (ctx.user.role !== "admin") {
        planRange = await db.getUserPlanPortRange(ctx.user.id, input.hostId, input.tunnelId ?? undefined);
        // Keep the subscription's disjoint ranges intact. The repository
        // intersects them with the host/tunnel policy when selecting a port.
      }
      const excludeRuleIds = input.excludeRuleId
        ? [
            input.excludeRuleId,
            ...((await db.getForwardGroupChildRulesForTemplate(input.excludeRuleId)) as any[]).map((rule: any) => Number(rule.id)),
          ]
        : [];
      const port = await db.findAvailablePort(
        input.hostId,
        rangeStart,
        rangeEnd,
        input.protocol,
        [],
        excludeRuleIds,
        planRange?.ranges || [],
      );
      if (!port) throw new Error("该主机端口区间内已无可用端口");
      return { port };
    }),
});
