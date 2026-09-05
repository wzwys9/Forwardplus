import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { XrayQuickConfigPathDesigner } from "./XrayQuickConfigPathDesigner";
import { XrayQuickConfigPathFlow } from "./XrayQuickConfigPathCard";
import { quickConfigPathsFromEntries, QUICK_CONFIG_CARRIER_LABELS, type QuickConfigPaths } from "./xrayQuickConfigPaths";
import { inspectQuickConfigPathDraft } from "./xrayQuickConfigPathAvailability";
import { XRAY_QUICK_CONFIG_CARRIERS, type XrayQuickConfigFlowState, type XrayQuickConfigEntryHost, type XrayQuickConfigTarget } from "./xrayQuickConfigFlow";

export function XrayQuickConfigCarrierPaths(props: {
  state: XrayQuickConfigFlowState; target: XrayQuickConfigTarget; hosts: XrayQuickConfigEntryHost[];
  loading: boolean; error: boolean; confirmedValid: boolean; linesAvailable: boolean;
  onChange: (paths: QuickConfigPaths) => void; onBack: () => void; onNext: () => void; onRetry: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const paths = props.state.carrierPaths ?? quickConfigPathsFromEntries(props.state.carrierEndpoints);
  const inspection = inspectQuickConfigPathDraft(paths, props.hosts, props.target, props.state.engine);
  return <div className="min-w-0 space-y-5">
    <div><h3 className="font-semibold">为四类运营商配置访问路径</h3><p className="mt-1 text-sm text-muted-foreground">入口 → 可选的多台中转 → 固定落地。DNS 只指向入口；相同服务器共用监听，下一跳必须一致。</p></div>
    {!props.confirmedValid && <Alert variant="destructive"><AlertTitle>请先确认域名</AlertTitle><AlertDescription>已有路径草稿保留。</AlertDescription></Alert>}
    {!props.linesAvailable && <Alert variant="destructive"><AlertTitle>运营商线路目录不可用</AlertTitle><AlertDescription>请返回域名步骤刷新目录。</AlertDescription></Alert>}
    {props.loading ? <div aria-busy="true" aria-label="读取路径服务器"><Skeleton className="h-24" /><Skeleton className="mt-3 h-24" /></div>
      : props.error ? <Alert variant="destructive"><AlertTitle>服务器列表加载失败</AlertTitle><AlertDescription><Button variant="outline" className="mt-3 h-11" onClick={props.onRetry}>重新加载</Button></AlertDescription></Alert>
      : <>
        <Button type="button" className="h-11 w-full sm:w-auto" onClick={() => setEditing(true)}>编辑运营商路径</Button>
        <div className="grid min-w-0 gap-3 sm:grid-cols-2">{XRAY_QUICK_CONFIG_CARRIERS.map(carrier => <section key={carrier} className="min-w-0 space-y-3 rounded-lg border p-3">
          <h4 className="font-medium">{QUICK_CONFIG_CARRIER_LABELS[carrier]} · {paths[carrier].length} 条路径</h4>
          {!paths[carrier].length && <p className="text-sm text-muted-foreground">尚未配置</p>}
          {paths[carrier].map(path => <XrayQuickConfigPathFlow key={path.id} path={path} hosts={props.hosts} targetName={props.target.name} targetHostId={props.target.host?.id} />)}
        </section>)}</div>
        {inspection.issues.length > 0 && <p role="status" className="text-sm text-destructive">路径未完成或存在冲突，请进入编辑查看提示。</p>}
      </>}
    <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between">
      <Button type="button" variant="outline" className="h-11" onClick={props.onBack}>返回：转发引擎</Button>
      <Button type="button" className="h-11" disabled={props.loading || props.error || !props.confirmedValid || !props.linesAvailable || inspection.issues.length > 0} onClick={props.onNext}>下一步：端口检测</Button>
    </div>
    {editing && <XrayQuickConfigPathDesigner target={props.target} hosts={props.hosts} loading={props.loading} error={props.error}
      engine={props.state.engine}
      initialPaths={paths} onRetry={props.onRetry} onClose={() => setEditing(false)} onAccept={next => { props.onChange(next); setEditing(false); }} />}
  </div>;
}
