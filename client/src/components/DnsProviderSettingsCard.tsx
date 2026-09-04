import { useId, useRef, useState, type FormEvent } from "react";
import {
  AlertTriangle,
  Cloud,
  KeyRound,
  Loader2,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type GlobalDnsAccount =
  | { configured: false; provider: "DNSPOD"; bindingRevision: number }
  | {
      configured: true;
      accountId: number;
      provider: "DNSPOD";
      name: string;
      accountRevision: number;
      bindingRevision: number;
      credentialsConfigured: true;
      secretIdMask: string;
      secretKeyMask: string;
      validationStatus: "UNVERIFIED" | "VALID" | "INVALID" | "ERROR" | "EXPIRED";
      verifiedAt: string | null;
      verificationExpiresAt: string | null;
      zonesSyncedAt: string | null;
      zoneCount: number;
      quickConfigReferenceCount: number;
      managedRecordCount: number;
      canRotateCredentials: boolean;
      canRebind: boolean;
      canRemove: boolean;
      lastErrorCode: string | null;
    };

type DnsZone = {
  zoneId: number;
  name: string;
  status: "AVAILABLE" | "STALE" | "REMOVED" | "ERROR";
  expiresAt: string;
  catalogUsable: boolean;
  catalogReasonCode: string | null;
  carrierLines: ReadonlyArray<{
    category: "DEFAULT" | "TELECOM" | "UNICOM" | "MOBILE" | "EDUCATION";
    status: "AVAILABLE" | "MISSING" | "AMBIGUOUS" | "STALE";
  }>;
};

const errorMessages: Record<string, string> = {
  DNS_PROVIDER_NOT_CONFIGURED: "尚未配置 DNSPod 账号。",
  DNS_PROVIDER_INVALID: "DNSPod 凭据无效，请检查后重试。",
  DNS_PROVIDER_VALIDATION_STALE: "账号验证已过期，请重新验证。",
  DNS_PROVIDER_CATALOG_STALE: "线路目录已过期，请手动刷新。",
  DNS_PROVIDER_LINE_MISSING: "DNSPod 缺少快速配置所需的运营商线路。",
  DNS_PROVIDER_LINE_AMBIGUOUS: "DNSPod 返回了重复的运营商线路，请稍后重试。",
  DNS_PROVIDER_NO_ZONES: "该账号下没有可用域名。",
  DNS_PROVIDER_IN_USE: "账号正在被快速配置使用，暂时不能删除。",
  DNS_PROVIDER_CONFLICT: "账号已被其他操作更新，请刷新后重试。",
  SENSITIVE_DATA_UNAVAILABLE: "保存的凭据暂时不可用，请更换凭据。",
};

const statusCopy = {
  UNVERIFIED: { label: "未验证", className: "border-amber-500/40 text-amber-700 dark:text-amber-300" },
  VALID: { label: "验证有效", className: "border-emerald-500/40 text-emerald-700 dark:text-emerald-300" },
  INVALID: { label: "凭据无效", className: "border-destructive/40 text-destructive" },
  ERROR: { label: "验证失败", className: "border-destructive/40 text-destructive" },
  EXPIRED: { label: "验证已过期", className: "border-amber-500/40 text-amber-700 dark:text-amber-300" },
} as const;

const carrierLabels = {
  DEFAULT: "默认",
  TELECOM: "电信",
  UNICOM: "联通",
  MOBILE: "移动",
  EDUCATION: "教育网",
} as const;

function safeErrorCode(error: unknown): string | null {
  if (!error || typeof error !== "object") return null;
  const candidate = error as {
    message?: unknown;
    data?: { xrayCode?: unknown; reasonCode?: unknown; causeCode?: unknown };
  };
  for (const value of [candidate.data?.xrayCode, candidate.data?.reasonCode, candidate.data?.causeCode, candidate.message]) {
    if (typeof value === "string" && Object.hasOwn(errorMessages, value)) return value;
  }
  return null;
}

function safeErrorMessage(error: unknown, fallback: string) {
  const code = safeErrorCode(error);
  return code ? errorMessages[code] : fallback;
}

function formatDate(value: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function CredentialFields({ defaultName }: { defaultName?: string }) {
  const id = useId();
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor={`${id}-name`}>账号名称</Label>
        <Input
          id={`${id}-name`}
          name="name"
          defaultValue={defaultName}
          maxLength={128}
          autoComplete="off"
          placeholder="例如：主账号"
          required
        />
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor={`${id}-secret-id`}>SecretId</Label>
          <Input
            id={`${id}-secret-id`}
            name="secretId"
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            placeholder="输入 DNSPod SecretId"
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor={`${id}-secret-key`}>SecretKey</Label>
          <Input
            id={`${id}-secret-key`}
            name="secretKey"
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            placeholder="输入 DNSPod SecretKey"
            required
          />
        </div>
      </div>
      <p className="text-xs leading-5 text-muted-foreground">
        凭据只用于服务端验证和加密保存，不会显示在页面、URL 或浏览器存储中。
      </p>
    </div>
  );
}

function ZoneSummary({ zones, refreshing, onRefresh }: {
  zones: readonly DnsZone[];
  refreshing: boolean;
  onRefresh: () => void;
}) {
  const unavailableCount = zones.filter((zone) => !zone.catalogUsable).length;
  return (
    <section className="space-y-3 border-t pt-5" aria-labelledby="dns-zone-summary-title">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 id="dns-zone-summary-title" className="font-medium">域名与线路目录</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            {zones.length} 个域名{unavailableCount > 0 ? `，${unavailableCount} 个目录暂不可用于快速配置` : "，运营商线路目录可用"}
          </p>
        </div>
        <Button type="button" variant="outline" size="sm" onClick={onRefresh} disabled={refreshing}>
          {refreshing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
          刷新目录
        </Button>
      </div>

      {zones.length === 0 ? (
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>没有可用域名</AlertTitle>
          <AlertDescription>请先在 DNSPod 账号中添加一个域名，然后重新验证。</AlertDescription>
        </Alert>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {zones.map((zone) => (
            <div key={zone.zoneId} className="min-w-0 rounded-lg border bg-muted/15 p-4">
              <div className="flex items-start justify-between gap-3">
                <p className="min-w-0 truncate font-medium" title={zone.name}>{zone.name}</p>
                <Badge variant="outline" className={zone.catalogUsable
                  ? "shrink-0 border-emerald-500/40 text-emerald-700 dark:text-emerald-300"
                  : "shrink-0 border-amber-500/40 text-amber-700 dark:text-amber-300"}
                >
                  {zone.catalogUsable ? "可用" : "目录异常"}
                </Badge>
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5" aria-label={`${zone.name} 线路状态`}>
                {zone.carrierLines.map((line) => (
                  <span
                    key={line.category}
                    className={line.status === "AVAILABLE"
                      ? "rounded border border-border bg-background px-2 py-1 text-xs"
                      : "rounded border border-amber-500/30 bg-amber-500/5 px-2 py-1 text-xs text-amber-700 dark:text-amber-300"}
                    title={line.status === "AVAILABLE" ? "线路可用" : "线路不可用"}
                  >
                    {carrierLabels[line.category]} · {line.status === "AVAILABLE" ? "可用" : "异常"}
                  </span>
                ))}
              </div>
              <p className="mt-3 text-xs text-muted-foreground">目录有效期：{formatDate(zone.expiresAt)}</p>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export default function DnsProviderSettingsCard() {
  const dnsApi = trpc.xray.dnsProviderAccounts;
  const accountQuery = dnsApi.getGlobal.useQuery(undefined, { retry: false });
  const account = accountQuery.data as GlobalDnsAccount | undefined;
  const zonesQuery = dnsApi.zones.useQuery({ refresh: false }, {
    enabled: account?.configured === true,
    retry: false,
  });
  const refreshZonesQuery = dnsApi.zones.useQuery({ refresh: true }, { enabled: false, retry: false });
  const upsertMutation = dnsApi.upsertGlobal.useMutation({ gcTime: 0 });
  const revalidateMutation = dnsApi.revalidateGlobal.useMutation({ gcTime: 0 });
  const removeMutation = dnsApi.removeGlobal.useMutation({ gcTime: 0 });
  const [rotationOpen, setRotationOpen] = useState(false);
  const [removeOpen, setRemoveOpen] = useState(false);
  const rotationFormRef = useRef<HTMLFormElement>(null);
  const removeFormRef = useRef<HTMLFormElement>(null);

  const submitCredentials = async (event: FormEvent<HTMLFormElement>, current: GlobalDnsAccount) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    try {
      await upsertMutation.mutateAsync({
        expectedBindingRevision: current.bindingRevision,
        expectedAccountRevision: current.configured ? current.accountRevision : null,
        name: String(values.get("name") ?? "").trim(),
        secretId: String(values.get("secretId") ?? "").trim(),
        secretKey: String(values.get("secretKey") ?? "").trim(),
      });
      form.reset();
      setRotationOpen(false);
      toast.success(current.configured ? "DNSPod 凭据已更换并通过验证" : "DNSPod 账号已验证并保存");
      await accountQuery.refetch();
      if (current.configured) await zonesQuery.refetch();
    } catch (error) {
      toast.error(safeErrorMessage(error, "DNSPod 验证失败，请检查凭据后重试。"));
    } finally {
      // tRPC mutation variables 含 secret，完成请求后立即从 mutation state 清除。
      upsertMutation.reset();
    }
  };

  const revalidate = async () => {
    if (!account?.configured) return;
    try {
      await revalidateMutation.mutateAsync({
        expectedAccountRevision: account.accountRevision,
        expectedBindingRevision: account.bindingRevision,
      });
      toast.success("DNSPod 账号和线路目录已重新验证");
      await accountQuery.refetch();
      await zonesQuery.refetch();
    } catch (error) {
      toast.error(safeErrorMessage(error, "重新验证失败，请稍后重试。"));
      await accountQuery.refetch();
    } finally {
      revalidateMutation.reset();
    }
  };

  const refreshZones = async () => {
    const result = await refreshZonesQuery.refetch();
    if (result.error) {
      toast.error(safeErrorMessage(result.error, "线路目录刷新失败，请稍后重试。"));
      return;
    }
    toast.success("线路目录已刷新");
    await accountQuery.refetch();
    await zonesQuery.refetch();
  };

  const removeAccount = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!account?.configured) return;
    const values = new FormData(event.currentTarget);
    const confirmName = String(values.get("confirmName") ?? "");
    if (confirmName !== account.name) {
      toast.error("请输入完整账号名称后再删除");
      return;
    }
    try {
      await removeMutation.mutateAsync({
        expectedAccountRevision: account.accountRevision,
        expectedBindingRevision: account.bindingRevision,
        confirmName,
      });
      removeFormRef.current?.reset();
      setRemoveOpen(false);
      toast.success("DNSPod 账号已删除");
      await accountQuery.refetch();
    } catch (error) {
      toast.error(safeErrorMessage(error, "DNSPod 账号删除失败，请稍后重试。"));
    } finally {
      removeMutation.reset();
    }
  };

  const changeRotationOpen = (open: boolean) => {
    if (!open) rotationFormRef.current?.reset();
    setRotationOpen(open);
  };

  const changeRemoveOpen = (open: boolean) => {
    if (!open) removeFormRef.current?.reset();
    setRemoveOpen(open);
  };

  if (accountQuery.isLoading) {
    return (
      <Card>
        <CardContent className="flex min-h-52 items-center justify-center text-sm text-muted-foreground">
          <Loader2 className="mr-2 h-4 w-4 animate-spin text-primary" />
          正在读取 DNS 服务商配置
        </CardContent>
      </Card>
    );
  }

  if (accountQuery.error || !account) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>DNS 服务商</CardTitle>
          <CardDescription>用于 Xray 快速配置的全局 DNSPod 账号。</CardDescription>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>配置加载失败</AlertTitle>
            <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
              <span>{safeErrorMessage(accountQuery.error, "暂时无法读取 DNS 服务商配置。")}</span>
              <Button type="button" size="sm" variant="outline" onClick={() => accountQuery.refetch()}>
                重新加载
              </Button>
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (!account.configured) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Cloud className="h-5 w-5" />
            </div>
            <div>
              <CardTitle>DNS 服务商</CardTitle>
              <CardDescription className="mt-1.5">配置一个全局 DNSPod 账号，启用 Xray 快速配置。</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <form className="space-y-5" onSubmit={(event) => submitCredentials(event, account)}>
            <CredentialFields />
            <div className="flex justify-end">
              <Button type="submit" disabled={upsertMutation.isPending}>
                {upsertMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                验证并保存
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    );
  }

  const validation = statusCopy[account.validationStatus];
  const visibleZones = (zonesQuery.data || []) as DnsZone[];
  const catalogError = refreshZonesQuery.error || zonesQuery.error;
  const referenced = account.quickConfigReferenceCount > 0 || account.managedRecordCount > 0;

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <Cloud className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <CardTitle>DNS 服务商</CardTitle>
                  <Badge variant="outline" className={validation.className}>{validation.label}</Badge>
                </div>
                <CardDescription className="mt-1.5">全局 DNSPod 账号 · {account.name}</CardDescription>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 sm:justify-end">
              <Button type="button" variant="outline" onClick={revalidate} disabled={revalidateMutation.isPending}>
                {revalidateMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                重新验证
              </Button>
              <Button type="button" variant="outline" onClick={() => changeRotationOpen(true)} disabled={!account.canRotateCredentials}>
                <KeyRound className="mr-2 h-4 w-4" />
                更换凭据
              </Button>
              <Button type="button" variant="destructive" onClick={() => changeRemoveOpen(true)} disabled={!account.canRemove}>
                <Trash2 className="mr-2 h-4 w-4" />
                删除
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          {account.validationStatus !== "VALID" && (
            <Alert variant={account.validationStatus === "INVALID" || account.validationStatus === "ERROR" ? "destructive" : "default"}>
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>{validation.label}</AlertTitle>
              <AlertDescription>{account.lastErrorCode && errorMessages[account.lastErrorCode]
                ? errorMessages[account.lastErrorCode]
                : "快速配置暂不可用，请重新验证账号。"}</AlertDescription>
            </Alert>
          )}

          <dl className="grid gap-x-8 gap-y-4 rounded-lg border bg-muted/10 p-4 sm:grid-cols-2 lg:grid-cols-3">
            <div>
              <dt className="text-xs text-muted-foreground">SecretId</dt>
              <dd className="mt-1 font-mono text-sm">{account.secretIdMask}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">SecretKey</dt>
              <dd className="mt-1 font-mono text-sm">{account.secretKeyMask}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">域名数量</dt>
              <dd className="mt-1 text-sm font-medium">{account.zoneCount}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">上次验证</dt>
              <dd className="mt-1 text-sm">{formatDate(account.verifiedAt)}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">验证有效期</dt>
              <dd className="mt-1 text-sm">{formatDate(account.verificationExpiresAt)}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">目录同步时间</dt>
              <dd className="mt-1 text-sm">{formatDate(account.zonesSyncedAt)}</dd>
            </div>
          </dl>

          {referenced && (
            <Alert>
              <ShieldCheck className="h-4 w-4" />
              <AlertTitle>账号正在使用</AlertTitle>
              <AlertDescription>
                当前有 {account.quickConfigReferenceCount} 个快速配置、{account.managedRecordCount} 条托管 DNS 记录引用此账号。
                删除或换绑会被阻止；完整的在用记录验证接入前，更换凭据也会保持禁用。
              </AlertDescription>
            </Alert>
          )}

          {zonesQuery.isLoading ? (
            <div className="flex min-h-32 items-center justify-center rounded-lg border text-sm text-muted-foreground">
              <Loader2 className="mr-2 h-4 w-4 animate-spin text-primary" />
              正在读取域名与线路目录
            </div>
          ) : catalogError && visibleZones.length === 0 ? (
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>线路目录暂不可用</AlertTitle>
              <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
                <span>{safeErrorMessage(catalogError, "请手动刷新目录；恢复前快速配置保持禁用。")}</span>
                <Button type="button" size="sm" variant="outline" onClick={refreshZones} disabled={refreshZonesQuery.isFetching}>
                  重新刷新
                </Button>
              </AlertDescription>
            </Alert>
          ) : (
            <ZoneSummary zones={visibleZones} refreshing={refreshZonesQuery.isFetching} onRefresh={refreshZones} />
          )}
        </CardContent>
      </Card>

      <Dialog open={rotationOpen} onOpenChange={changeRotationOpen}>
        <DialogContent className="flex max-h-[92svh] max-w-xl flex-col gap-0 p-0">
          <DialogHeader className="shrink-0 border-b p-5 pr-12 sm:p-6 sm:pr-12">
            <DialogTitle>更换 DNSPod 凭据</DialogTitle>
            <DialogDescription>新凭据通过验证前，现有账号和线路目录不会被修改。</DialogDescription>
          </DialogHeader>
          <form ref={rotationFormRef} className="flex min-h-0 flex-1 flex-col" onSubmit={(event) => submitCredentials(event, account)}>
            <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-5 sm:p-6">
              <CredentialFields defaultName={account.name} />
            </div>
            <DialogFooter className="shrink-0 gap-2 border-t p-4 sm:p-5">
              <Button type="button" variant="outline" onClick={() => changeRotationOpen(false)}>取消</Button>
              <Button type="submit" disabled={upsertMutation.isPending}>
                {upsertMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                验证并更换
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={removeOpen} onOpenChange={changeRemoveOpen}>
        <DialogContent className="flex max-h-[92svh] max-w-md flex-col gap-0 p-0">
          <DialogHeader className="shrink-0 border-b p-5 pr-12 sm:p-6 sm:pr-12">
            <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-md bg-destructive/10 text-destructive">
              <AlertTriangle className="h-5 w-5" />
            </div>
            <DialogTitle>删除 DNSPod 账号</DialogTitle>
            <DialogDescription>此操作会删除已保存的加密凭据和线路目录，不会修改已有 DDNS 配置。</DialogDescription>
          </DialogHeader>
          <form ref={removeFormRef} className="flex min-h-0 flex-1 flex-col" onSubmit={removeAccount}>
            <div className="min-h-0 flex-1 space-y-3 overflow-y-auto overscroll-contain p-5 sm:p-6">
              <Label htmlFor="dns-provider-confirm-name">输入账号名称“{account.name}”确认删除</Label>
              <Input id="dns-provider-confirm-name" name="confirmName" autoComplete="off" required />
            </div>
            <DialogFooter className="shrink-0 gap-2 border-t p-4 sm:p-5">
              <Button type="button" variant="outline" onClick={() => changeRemoveOpen(false)}>取消</Button>
              <Button type="submit" variant="destructive" disabled={removeMutation.isPending}>
                {removeMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                删除账号
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
