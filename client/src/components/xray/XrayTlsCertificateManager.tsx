import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./XrayDialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import type { AppRouterOutputs } from "@/lib/trpc";
import { trpc } from "@/lib/trpc";
import {
  AlertTriangle,
  CalendarClock,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  FileKey2,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { useEffect, useState } from "react";

import type { XrayHostOption } from "./xrayCreateFlow";
import {
  certificateDraftError,
  certificateStatusPresentation,
} from "./xrayTlsCertificatePresentation";

type Certificate = AppRouterOutputs["xray"]["certificates"]["list"]["items"][number];

type Props = {
  items: Certificate[];
  hosts: XrayHostOption[];
  page: number;
  totalPages: number;
  totalItems: number;
  importOpen: boolean;
  onImportOpenChange: (open: boolean) => void;
  onPageChange: (page: number) => void;
  onChanged: () => void;
  onOperationStarted: (operationId: string) => void;
};

function mutationError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error ?? "");
  return /^[A-Z][A-Z0-9_]{1,63}$/.test(message) ? message : "INTERNAL_ERROR";
}

function canManageCertificate(host: XrayHostOption): boolean {
  return host.canCreateXrayInbound
    || host.unavailableReasonCode === "ARTIFACT_UNAVAILABLE"
    || host.unavailableReasonCode === "PUBLIC_IPV4_MISSING";
}

function certificateDate(value: number): string {
  const date = new Date(value * 1000);
  if (!Number.isFinite(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" }).format(date);
}

function CertificateStatus({ certificate }: { certificate: Certificate }) {
  const view = certificateStatusPresentation(certificate.status);
  const Icon = view.tone === "success" ? CheckCircle2 : view.tone === "warning" ? CalendarClock : AlertTriangle;
  return (
    <Badge variant={view.tone === "danger" ? "destructive" : view.tone === "success" ? "outline" : "secondary"} className="gap-1.5 whitespace-nowrap">
      <Icon className="h-3.5 w-3.5" aria-hidden={true} />{view.label}
    </Badge>
  );
}

function PemFields(props: {
  certificatePem: string;
  privateKeyPem: string;
  onCertificatePemChange: (value: string) => void;
  onPrivateKeyPemChange: (value: string) => void;
  onReadError: () => void;
}) {
  const readFile = async (file: File | undefined, setter: (value: string) => void, input: HTMLInputElement) => {
    try {
      if (file) setter(await file.text());
    } catch {
      setter("");
      props.onReadError();
    } finally {
      input.value = "";
    }
  };
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="space-y-2">
        <Label htmlFor="xray-certificate-pem">完整证书链 PEM</Label>
        <Textarea id="xray-certificate-pem" className="min-h-44 resize-y font-mono text-xs" value={props.certificatePem} onChange={(event) => props.onCertificatePemChange(event.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">最多 16 KiB、四张证书</p>
          <Input aria-label="从本地读取证书 PEM" className="h-8 max-w-52 text-xs" type="file" accept=".pem,.crt,.cer,text/plain" onChange={(event) => void readFile(event.currentTarget.files?.[0], props.onCertificatePemChange, event.currentTarget)} />
        </div>
      </div>
      <div className="space-y-2">
        <Label htmlFor="xray-private-key-pem">未加密私钥 PEM</Label>
        <Textarea id="xray-private-key-pem" className="min-h-44 resize-y font-mono text-xs" value={props.privateKeyPem} onChange={(event) => props.onPrivateKeyPemChange(event.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" />
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">最多 8 KiB，不支持加密私钥</p>
          <Input aria-label="从本地读取私钥 PEM" className="h-8 max-w-52 text-xs" type="file" accept=".pem,.key,text/plain" onChange={(event) => void readFile(event.currentTarget.files?.[0], props.onPrivateKeyPemChange, event.currentTarget)} />
        </div>
      </div>
    </div>
  );
}

function MobileRow({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-xs text-muted-foreground">{label}</span><div className="min-w-0 max-w-[72%] break-words text-right text-sm">{children}</div></div>;
}

export function XrayTlsCertificateManager({
  items,
  hosts,
  page,
  totalPages,
  totalItems,
  importOpen,
  onImportOpenChange,
  onPageChange,
  onChanged,
  onOperationStarted,
}: Props) {
  const [selected, setSelected] = useState<Certificate | null>(null);
  const [dialogMode, setDialogMode] = useState<"ROTATE" | "REMOVE" | null>(null);
  const [hostId, setHostId] = useState<number | null>(null);
  const [name, setName] = useState("");
  const [certificatePem, setCertificatePem] = useState("");
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [confirmName, setConfirmName] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const selectedRuntime = trpc.xray.runtimes.list.useQuery(
    { page: 1, pageSize: 1, ...(selected ? { hostId: selected.hostId } : {}) },
    { enabled: dialogMode === "ROTATE" && !!selected, retry: false },
  );

  const clearSensitiveFields = () => {
    setCertificatePem("");
    setPrivateKeyPem("");
  };
  const closeEditor = () => {
    clearSensitiveFields();
    setName("");
    setHostId(null);
    setConfirmName("");
    setFormError(null);
    setDialogMode(null);
    setSelected(null);
    onImportOpenChange(false);
  };

  useEffect(() => {
    if (!importOpen) return;
    setSelected(null);
    setDialogMode(null);
    setHostId((current) => current ?? hosts.find(canManageCertificate)?.id ?? null);
    setFormError(null);
  }, [hosts, importOpen]);

  const importCertificate = trpc.xray.certificates.import.useMutation({
    onSuccess: () => {
      closeEditor();
      onChanged();
    },
    onError: (error) => {
      setFormError(mutationError(error));
      clearSensitiveFields();
    },
  });
  const rotateCertificate = trpc.xray.certificates.rotate.useMutation({
    onSuccess: (result) => {
      const operationId = result.operationId;
      closeEditor();
      onChanged();
      if (operationId) onOperationStarted(operationId);
    },
    onError: (error) => {
      setFormError(mutationError(error));
      clearSensitiveFields();
    },
  });
  const removeCertificate = trpc.xray.certificates.remove.useMutation({
    onSuccess: () => {
      closeEditor();
      if (items.length === 1 && page > 1) onPageChange(page - 1);
      else onChanged();
    },
    onError: (error) => setFormError(mutationError(error)),
  });

  const submitPem = () => {
    const pemError = certificateDraftError({ certificatePem, privateKeyPem });
    if (pemError) return setFormError(pemError);
    setFormError(null);
    if (importOpen) {
      if (!hostId || !name.trim()) return setFormError("请选择主机并填写证书名称");
      importCertificate.mutate({ hostId, name: name.trim(), certificatePem, privateKeyPem });
      return;
    }
    if (!selected || dialogMode !== "ROTATE") return;
    const expectedGeneration = selectedRuntime.data?.items[0]?.desiredGeneration;
    if (expectedGeneration === undefined) return setFormError("无法读取主机 generation，请重试");
    rotateCertificate.mutate({ id: selected.id, certificatePem, privateKeyPem, expectedGeneration });
  };

  const openRotate = (certificate: Certificate) => {
    clearSensitiveFields();
    setSelected(certificate);
    setDialogMode("ROTATE");
    setFormError(null);
  };
  const openRemove = (certificate: Certificate) => {
    setSelected(certificate);
    setDialogMode("REMOVE");
    setConfirmName("");
    setFormError(null);
  };
  const hostName = (id: number) => hosts.find((host) => host.id === id)?.name ?? `主机 #${id}`;
  const pending = importCertificate.isPending || rotateCertificate.isPending || removeCertificate.isPending;

  return (
    <>
      {items.length > 0 && <Card>
        <CardContent className="p-0">
          <div className="grid gap-3 p-3 xl:hidden">
            {items.map((certificate) => (
              <article key={certificate.id} className="rounded-lg border border-border/60 bg-background/40 p-4">
                <div className="flex items-start justify-between gap-3"><div className="min-w-0"><h2 className="truncate font-semibold">{certificate.name}</h2><p className="mt-1 text-xs text-muted-foreground">{hostName(certificate.hostId)}</p></div><CertificateStatus certificate={certificate} /></div>
                <div className="mt-4 space-y-2.5 border-t border-border/50 pt-3">
                  <MobileRow label="DNS SAN"><span className="break-all">{certificate.dnsNames.join("、")}</span></MobileRow>
                  <MobileRow label="有效期">{certificateDate(certificate.notBefore)} – {certificateDate(certificate.notAfter)}</MobileRow>
                  <MobileRow label="算法">{certificate.keyAlgorithm === "RSA_2048_4096" ? "RSA 2048–4096" : "ECDSA P-256/P-384"}</MobileRow>
                  <MobileRow label="引用节点">{certificate.referenceCount} 个</MobileRow>
                </div>
                <div className="mt-4 flex gap-2"><Button type="button" size="sm" variant="outline" className="flex-1" onClick={() => openRotate(certificate)}><RefreshCw className="mr-1.5 h-4 w-4" />轮换</Button><Button type="button" size="sm" variant="destructive" className="flex-1" disabled={certificate.referenceCount > 0} title={certificate.referenceCount > 0 ? "请先移除节点引用" : undefined} onClick={() => openRemove(certificate)}><Trash2 className="mr-1.5 h-4 w-4" />删除</Button></div>
              </article>
            ))}
          </div>
          <div className="hidden overflow-x-auto xl:block">
            <Table className="min-w-[1120px]">
              <TableHeader><TableRow><TableHead>证书</TableHead><TableHead>主机</TableHead><TableHead>DNS SAN</TableHead><TableHead>签发者</TableHead><TableHead>有效期</TableHead><TableHead>算法</TableHead><TableHead>状态</TableHead><TableHead>引用</TableHead><TableHead className="text-right">操作</TableHead></TableRow></TableHeader>
              <TableBody>{items.map((certificate) => (
                <TableRow key={certificate.id}>
                  <TableCell><p className="font-medium">{certificate.name}</p><p className="mt-1 font-mono text-[11px] text-muted-foreground">{certificate.leafFingerprintSha256.slice(0, 16)}…</p></TableCell>
                  <TableCell>{hostName(certificate.hostId)}</TableCell>
                  <TableCell className="max-w-64"><p className="line-clamp-2 break-all text-xs">{certificate.dnsNames.join("、")}</p></TableCell>
                  <TableCell className="max-w-48 truncate text-xs" title={certificate.issuer}>{certificate.issuer}</TableCell>
                  <TableCell className="whitespace-nowrap text-xs">{certificateDate(certificate.notBefore)}<br /><span className="text-muted-foreground">至 {certificateDate(certificate.notAfter)}</span></TableCell>
                  <TableCell className="text-xs">{certificate.keyAlgorithm === "RSA_2048_4096" ? "RSA 2048–4096" : "ECDSA P-256/P-384"}</TableCell>
                  <TableCell><CertificateStatus certificate={certificate} /></TableCell>
                  <TableCell>{certificate.referenceCount} 个节点</TableCell>
                  <TableCell><div className="flex justify-end gap-2"><Button type="button" size="sm" variant="outline" onClick={() => openRotate(certificate)}>轮换</Button><Button type="button" size="sm" variant="destructive" disabled={certificate.referenceCount > 0} title={certificate.referenceCount > 0 ? "请先移除节点引用" : undefined} onClick={() => openRemove(certificate)}>删除</Button></div></TableCell>
                </TableRow>
              ))}</TableBody>
            </Table>
          </div>
          <nav aria-label="TLS 证书分页" className="flex flex-col gap-3 border-t border-border/60 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-sm text-muted-foreground">共 {totalItems} 张证书 · 第 {page} / {totalPages} 页</p>
            <div className="flex gap-2"><Button type="button" size="sm" variant="outline" disabled={page <= 1} onClick={() => onPageChange(page - 1)}><ChevronLeft className="mr-1 h-4 w-4" />上一页</Button><Button type="button" size="sm" variant="outline" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>下一页<ChevronRight className="ml-1 h-4 w-4" /></Button></div>
          </nav>
        </CardContent>
      </Card>}

      <Dialog open={importOpen} onOpenChange={(open) => { if (!open) closeEditor(); }}>
        <DialogContent className="max-w-4xl">
          <DialogHeader><DialogTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5" />导入 TLS 证书</DialogTitle><DialogDescription>证书按主机托管；浏览器只读取文本，不提交文件名或本地路径。</DialogDescription></DialogHeader>
          <div className="max-h-[70svh] space-y-5 overflow-y-auto pr-1">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="xray-certificate-host">目标主机</Label>
                <Select value={hostId ? String(hostId) : undefined} onValueChange={(value) => setHostId(Number(value) || null)}>
                  <SelectTrigger id="xray-certificate-host"><SelectValue placeholder="请选择主机" /></SelectTrigger>
                  <SelectContent>{hosts.map((host) => {
                    const writable = canManageCertificate(host);
                    const suffix = writable ? host.canCreateXrayInbound ? "" : "（可导入，暂不可部署）" : "（当前不可写）";
                    return <SelectItem key={host.id} value={String(host.id)} disabled={!writable}>{host.name}{suffix}</SelectItem>;
                  })}</SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5"><Label htmlFor="xray-certificate-name">证书名称</Label><Input id="xray-certificate-name" maxLength={128} value={name} onChange={(event) => setName(event.target.value)} placeholder="例如：example.com 生产证书" /></div>
            </div>
            <PemFields certificatePem={certificatePem} privateKeyPem={privateKeyPem} onCertificatePemChange={setCertificatePem} onPrivateKeyPemChange={setPrivateKeyPem} onReadError={() => setFormError("本地文件读取失败")} />
            {formError && <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{formError}</p>}
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end"><Button type="button" variant="outline" disabled={pending} onClick={closeEditor}>取消</Button><Button type="button" disabled={pending} onClick={submitPem}><FileKey2 className="mr-2 h-4 w-4" />{pending ? "正在验证" : "验证并导入"}</Button></div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={dialogMode === "ROTATE" && !!selected} onOpenChange={(open) => { if (!open) closeEditor(); }}>
        <DialogContent className="max-w-4xl">
          <DialogHeader><DialogTitle>轮换 TLS 证书</DialogTitle><DialogDescription>{selected ? `${selected.name} · ${hostName(selected.hostId)} · 影响 ${selected.referenceCount} 个引用节点` : ""}</DialogDescription></DialogHeader>
          <div className="max-h-[70svh] space-y-5 overflow-y-auto pr-1">
            {selected && selected.referenceCount > 0 && <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">提交后会创建新的主机 generation。应用完成前，Agent 可能继续运行旧证书；失败时保留 last-good。</p>}
            <PemFields certificatePem={certificatePem} privateKeyPem={privateKeyPem} onCertificatePemChange={setCertificatePem} onPrivateKeyPemChange={setPrivateKeyPem} onReadError={() => setFormError("本地文件读取失败")} />
            {selectedRuntime.isError && <p role="alert" className="text-sm text-destructive">主机 generation 加载失败，请重试。</p>}
            {formError && <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{formError}</p>}
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end"><Button type="button" variant="outline" disabled={pending} onClick={closeEditor}>取消</Button><Button type="button" disabled={pending || selectedRuntime.isLoading || selectedRuntime.isError} onClick={submitPem}>{pending ? "正在验证" : "验证并轮换"}</Button></div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={dialogMode === "REMOVE" && !!selected} onOpenChange={(open) => { if (!open) closeEditor(); }}>
        <DialogContent>
          <DialogHeader><DialogTitle>删除 TLS 证书</DialogTitle><DialogDescription>此操作会删除面板保存的公开证书链和加密私钥，无法撤销。</DialogDescription></DialogHeader>
          {selected && <div className="space-y-4"><div className="rounded-lg border border-border/60 p-3"><p className="font-medium">{selected.name}</p><p className="mt-1 text-xs text-muted-foreground">{hostName(selected.hostId)} · {selected.referenceCount} 个引用节点</p></div><div className="space-y-1.5"><Label htmlFor="xray-certificate-confirm">逐字输入证书名称</Label><Input id="xray-certificate-confirm" autoComplete="off" value={confirmName} onChange={(event) => setConfirmName(event.target.value)} /></div>{formError && <p role="alert" className="text-sm text-destructive">{formError}</p>}<div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end"><Button type="button" variant="outline" disabled={pending} onClick={closeEditor}>取消</Button><Button type="button" variant="destructive" disabled={pending || confirmName !== selected.name || selected.referenceCount > 0} onClick={() => removeCertificate.mutate({ id: selected.id, confirmName })}>{pending ? "正在删除" : "确认删除"}</Button></div></div>}
        </DialogContent>
      </Dialog>
    </>
  );
}
