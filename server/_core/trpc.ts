import { ACCOUNT_DISABLED_ERR_MSG, COOKIE_NAME, NOT_ADMIN_ERR_MSG, SESSION_REPLACED_ERR_MSG, UNAUTHED_ERR_MSG } from '../../shared/const';
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { TrpcContext } from "./context";
import { getSessionCookieOptions } from "./cookies";
import { runWithConfigAuditContext } from "../configAudit";

const t = initTRPC.context<TrpcContext>().create({
  transformer: superjson,
  errorFormatter({ shape, error }) {
    const cause = error.cause as { name?: unknown; code?: unknown; quickConfigId?: unknown } | undefined;
    const xrayCode = String(cause?.name ?? "").startsWith("Xray")
      && /^[A-Z][A-Z0-9_]{0,63}$/.test(String(cause?.code ?? ""))
      ? String(cause!.code)
      : undefined;
    const quickConfigId = xrayCode === "QUICK_CONFIG_MANAGED_RULE"
      && Number.isSafeInteger(Number(cause?.quickConfigId))
      && Number(cause?.quickConfigId) > 0
      ? Number(cause!.quickConfigId)
      : undefined;
    return xrayCode
      ? { ...shape, data: { ...shape.data, xrayCode, ...(quickConfigId ? { quickConfigId } : {}) } }
      : shape;
  },
});

export const router = t.router;
export const publicProcedure = t.procedure;

const requireUser = t.middleware(async opts => {
  const { ctx, next } = opts;

  if (!ctx.user) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: ctx.authFailureReason === "session_replaced"
        ? SESSION_REPLACED_ERR_MSG
        : ctx.authFailureReason === "account_disabled" ? ACCOUNT_DISABLED_ERR_MSG : UNAUTHED_ERR_MSG,
    });
  }
  if ((ctx.user as any).accountEnabled === false) {
    ctx.res.clearCookie(COOKIE_NAME, { ...getSessionCookieOptions(ctx.req), maxAge: -1 });
    throw new TRPCError({ code: "UNAUTHORIZED", message: ACCOUNT_DISABLED_ERR_MSG });
  }

  return runWithConfigAuditContext({
    actorUserId: Number(ctx.user.id),
    actorName: String(ctx.user.username || ctx.user.name || ""),
    source: "panel:trpc",
    requestId: String(ctx.req.headers["x-request-id"] || "") || undefined,
    requestPath: opts.path,
  }, () => next({ ctx: { ...ctx, user: ctx.user } }));
});

export const protectedProcedure = t.procedure.use(requireUser);

export const adminProcedure = t.procedure.use(
  t.middleware(async opts => {
    const { ctx, next } = opts;

    if (!ctx.user) {
      throw new TRPCError({
        code: "UNAUTHORIZED",
        message: ctx.authFailureReason === "session_replaced"
          ? SESSION_REPLACED_ERR_MSG
          : ctx.authFailureReason === "account_disabled" ? ACCOUNT_DISABLED_ERR_MSG : UNAUTHED_ERR_MSG,
      });
    }
    if ((ctx.user as any).accountEnabled === false) {
      ctx.res.clearCookie(COOKIE_NAME, { ...getSessionCookieOptions(ctx.req), maxAge: -1 });
      throw new TRPCError({ code: "UNAUTHORIZED", message: ACCOUNT_DISABLED_ERR_MSG });
    }
    if (ctx.user.role !== 'admin') {
      throw new TRPCError({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }

    return runWithConfigAuditContext({
      actorUserId: Number(ctx.user.id),
      actorName: String(ctx.user.username || ctx.user.name || ""),
      source: "panel:trpc",
      requestId: String(ctx.req.headers["x-request-id"] || "") || undefined,
      requestPath: opts.path,
    }, () => next({ ctx: { ...ctx, user: ctx.user } }));
  }),
);
