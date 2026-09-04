import { boolValue, quoteIdentifier } from "./dbCompat";
import {
  executeRaw,
  getDatabaseKind,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "./dbRuntime";
import { withKeyedTaskLock } from "./keyedTaskLock";
import {
  XRAY_QUICK_CONFIG_FORWARD_ENGINES,
  type XrayQuickConfigForwardEngine,
} from "../shared/xrayQuickConfigForwardEngines";

export const QUICK_CONFIG_PORT_RESOURCE_KIND = "XRAY_QUICK_CONFIG_PORT";
export const QUICK_CONFIG_PORT_RESOURCE_NAME = "快速配置默认生成";

type Row = Record<string, unknown>;

export type QuickConfigPortResourceResult = {
  groupId: number;
  created: boolean;
};

function positiveInteger(value: unknown, field: string): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error(`Invalid ${field}`);
  return number;
}

function normalizeEngine(value: unknown): XrayQuickConfigForwardEngine {
  const engine = String(value || "").trim().toLowerCase();
  if (!(XRAY_QUICK_CONFIG_FORWARD_ENGINES as readonly string[]).includes(engine)) {
    throw new Error("Invalid quick config forward engine");
  }
  return engine as XrayQuickConfigForwardEngine;
}

function managedKey(userId: number, hostId: number, engine: XrayQuickConfigForwardEngine) {
  return `quick-config-port:v1:${userId}:${hostId}:${engine}`;
}

async function matchingResources(input: {
  userId: number;
  hostId: number;
  engine: XrayQuickConfigForwardEngine;
}) {
  const q = quoteIdentifier;
  return queryRaw<Row>(
    `SELECT g.${q("id")}, g.${q("systemManagedKind")}, g.${q("systemManagedKey")}, g.${q("isEnabled")}
       FROM ${q("forward_groups")} g
       INNER JOIN ${q("forward_group_members")} m ON m.${q("groupId")} = g.${q("id")}
      WHERE g.${q("userId")} = ?
        AND g.${q("groupMode")} = 'port'
        AND g.${q("forwardType")} = ?
        AND g.${q("isEnabled")} = ?
        AND m.${q("memberType")} = 'host'
        AND m.${q("hostId")} = ?
        AND m.${q("isEnabled")} = ?
      GROUP BY g.${q("id")}, g.${q("systemManagedKind")}, g.${q("systemManagedKey")}, g.${q("isEnabled")}
      ORDER BY g.${q("id")} ASC`,
    [input.userId, input.engine, boolValue(true), input.hostId, boolValue(true)],
  );
}

async function currentManagedResource(key: string) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("isEnabled")} FROM ${q("forward_groups")}
      WHERE ${q("systemManagedKey")} = ? AND ${q("systemManagedKind")} = ? LIMIT 1`,
    [key, QUICK_CONFIG_PORT_RESOURCE_KIND],
  );
  return rows[0] || null;
}

async function insertManagedResource(input: {
  userId: number;
  hostId: number;
  engine: XrayQuickConfigForwardEngine;
  key: string;
}): Promise<QuickConfigPortResourceResult> {
  const q = quoteIdentifier;
  const now = nowDate();
  const [sort] = await queryRaw<Row>(
    `SELECT COALESCE(MAX(${q("sortOrder")}), -1) + 1 AS ${q("nextSortOrder")}
       FROM ${q("forward_groups")} WHERE ${q("userId")} = ? AND ${q("groupMode")} = 'port'`,
    [input.userId],
  );
  const values = [
    QUICK_CONFIG_PORT_RESOURCE_NAME,
    "host",
    "port",
    input.engine,
    "tcp",
    1,
    "0.0.0.0",
    1,
    boolValue(true),
    QUICK_CONFIG_PORT_RESOURCE_KIND,
    input.key,
    Math.max(0, Number(sort?.nextSortOrder || 0)),
    input.userId,
    now,
    now,
  ];
  const columns = [
    "name", "groupType", "groupMode", "forwardType", "protocol", "sourcePort", "targetIp",
    "targetPort", "isEnabled", "systemManagedKind", "systemManagedKey", "sortOrder", "userId",
    "createdAt", "updatedAt",
  ];
  const quotedColumns = columns.map(q).join(", ");
  const placeholders = columns.map(() => "?").join(", ");
  let created = false;

  if (getDatabaseKind() === "mysql") {
    const result = await executeRaw(
      `INSERT INTO ${q("forward_groups")} (${quotedColumns}) VALUES (${placeholders})
       ON DUPLICATE KEY UPDATE ${q("id")} = LAST_INSERT_ID(${q("id")})`,
      values,
    );
    created = rawAffectedRows(result) === 1;
  } else if (getDatabaseKind() === "postgresql") {
    const result: any = await executeRaw(
      `INSERT INTO ${q("forward_groups")} (${quotedColumns}) VALUES (${placeholders})
       ON CONFLICT (${q("systemManagedKey")}) DO NOTHING RETURNING ${q("id")}`,
      values,
    );
    created = Array.isArray(result?.rows) && result.rows.length === 1;
  } else {
    const result = await executeRaw(
      `INSERT OR IGNORE INTO ${q("forward_groups")} (${quotedColumns}) VALUES (${placeholders})`,
      values,
    );
    created = rawAffectedRows(result) === 1;
  }

  const group = await currentManagedResource(input.key);
  const groupId = positiveInteger(group?.id, "managed port resource id");
  const [member] = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("forward_group_members")}
      WHERE ${q("groupId")} = ? AND ${q("memberType")} = 'host' AND ${q("hostId")} = ? LIMIT 1`,
    [groupId, input.hostId],
  );
  if (!member) {
    await executeRaw(
      `INSERT INTO ${q("forward_group_members")} (${q("groupId")}, ${q("memberType")}, ${q("hostId")}, ${q("priority")}, ${q("isEnabled")}, ${q("createdAt")}, ${q("updatedAt")})
       VALUES (?, 'host', ?, 0, ?, ?, ?)`,
      [groupId, input.hostId, boolValue(true), now, now],
    );
  }
  if (!group?.isEnabled) {
    await executeRaw(
      `UPDATE ${q("forward_groups")} SET ${q("isEnabled")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
      [boolValue(true), now, groupId],
    );
  }
  return { groupId, created };
}

export async function ensureQuickConfigPortResource(input: {
  userId: number;
  hostId: number;
  engine: XrayQuickConfigForwardEngine | string;
}): Promise<QuickConfigPortResourceResult> {
  const userId = positiveInteger(input.userId, "user id");
  const hostId = positiveInteger(input.hostId, "host id");
  const engine = normalizeEngine(input.engine);
  const key = managedKey(userId, hostId, engine);

  return withKeyedTaskLock(key, async () => withDatabaseTransaction(async () => {
    const managed = await currentManagedResource(key);
    if (managed) {
      if (!managed.isEnabled) {
        const q = quoteIdentifier;
        await executeRaw(
          `UPDATE ${q("forward_groups")} SET ${q("isEnabled")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
          [boolValue(true), nowDate(), positiveInteger(managed.id, "managed port resource id")],
        );
      }
      return { groupId: positiveInteger(managed.id, "managed port resource id"), created: false };
    }
    const candidates = await matchingResources({ userId, hostId, engine });
    if (candidates.length === 1) {
      return { groupId: positiveInteger(candidates[0].id, "port resource id"), created: false };
    }
    return insertManagedResource({ userId, hostId, engine, key });
  }));
}

export async function assignQuickConfigRulePortResource(ruleIdValue: number) {
  const ruleId = positiveInteger(ruleIdValue, "rule id");
  return withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    const [rule] = await queryRaw<Row>(
      `SELECT ${q("id")}, ${q("hostId")}, ${q("userId")}, ${q("forwardType")}, ${q("portResourceGroupId")}
         FROM ${q("forward_rules")}
        WHERE ${q("id")} = ? AND ${q("xrayQuickConfigId")} IS NOT NULL
          AND ${q("xrayQuickConfigId")} > 0 AND ${q("pendingDelete")} = ? LIMIT 1`,
      [ruleId, boolValue(false)],
    );
    if (!rule) return { assigned: false, created: false, groupId: null as number | null };
    const currentGroupId = Number(rule.portResourceGroupId || 0);
    if (currentGroupId > 0) {
      const [current] = await queryRaw<Row>(
        `SELECT g.${q("id")} FROM ${q("forward_groups")} g
          WHERE g.${q("id")} = ? AND g.${q("userId")} = ? AND g.${q("groupMode")} = 'port'
            AND g.${q("forwardType")} = ? AND g.${q("isEnabled")} = ?
            AND EXISTS (
              SELECT 1 FROM ${q("forward_group_members")} m
               WHERE m.${q("groupId")} = g.${q("id")} AND m.${q("memberType")} = 'host'
                 AND m.${q("hostId")} = ? AND m.${q("isEnabled")} = ?
            ) LIMIT 1`,
        [currentGroupId, rule.userId, normalizeEngine(rule.forwardType), boolValue(true), rule.hostId, boolValue(true)],
      );
      if (current) return { assigned: false, created: false, groupId: currentGroupId };
    }
    const resource = await ensureQuickConfigPortResource({
      userId: positiveInteger(rule.userId, "rule owner id"),
      hostId: positiveInteger(rule.hostId, "rule host id"),
      engine: normalizeEngine(rule.forwardType),
    });
    if (Number(rule.portResourceGroupId || 0) !== resource.groupId) {
      await executeRaw(
        `UPDATE ${q("forward_rules")} SET ${q("portResourceGroupId")} = ?, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("xrayQuickConfigId")} IS NOT NULL AND ${q("pendingDelete")} = ?`,
        [resource.groupId, nowDate(), ruleId, boolValue(false)],
      );
      return { assigned: true, created: resource.created, groupId: resource.groupId };
    }
    return { assigned: false, created: resource.created, groupId: resource.groupId };
  });
}

export async function reconcileQuickConfigPortResources() {
  const q = quoteIdentifier;
  const rules = await queryRaw<Row>(
    `SELECT r.${q("id")} FROM ${q("forward_rules")} r
       LEFT JOIN ${q("forward_groups")} g ON g.${q("id")} = r.${q("portResourceGroupId")}
      WHERE r.${q("xrayQuickConfigId")} IS NOT NULL AND r.${q("xrayQuickConfigId")} > 0
        AND r.${q("pendingDelete")} = ?
        AND (
          g.${q("id")} IS NULL OR g.${q("userId")} <> r.${q("userId")} OR g.${q("groupMode")} <> 'port'
          OR g.${q("forwardType")} <> r.${q("forwardType")} OR g.${q("isEnabled")} <> ?
          OR NOT EXISTS (
            SELECT 1 FROM ${q("forward_group_members")} m
             WHERE m.${q("groupId")} = g.${q("id")} AND m.${q("memberType")} = 'host'
               AND m.${q("hostId")} = r.${q("hostId")} AND m.${q("isEnabled")} = ?
          )
        )
      ORDER BY r.${q("id")} ASC`,
    [boolValue(false), boolValue(true), boolValue(true)],
  );
  let rulesAssigned = 0;
  let groupsCreated = 0;
  for (const rule of rules) {
    const result = await assignQuickConfigRulePortResource(positiveInteger(rule.id, "rule id"));
    if (result.assigned) rulesAssigned += 1;
    if (result.created) groupsCreated += 1;
  }
  return { rulesAssigned, groupsCreated };
}
