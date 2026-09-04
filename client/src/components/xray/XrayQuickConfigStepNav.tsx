import { Check } from "lucide-react";

import {
  XRAY_QUICK_CONFIG_STEPS,
  type XrayQuickConfigStep,
} from "./xrayQuickConfigFlow";

const stepLabels: Record<XrayQuickConfigStep, string> = {
  DOMAIN: "域名",
  CARRIERS: "运营商入口",
  ENGINE: "转发引擎",
  PORT: "端口检测",
  DEFAULT: "默认线路",
  PREVIEW: "预览",
  APPLY: "执行",
};

export function XrayQuickConfigStepNav(props: {
  active: XrayQuickConfigStep;
  furthestStepIndex: number;
  completed: ReadonlySet<XrayQuickConfigStep>;
  onSelect: (step: XrayQuickConfigStep) => void;
}) {
  return (
    <nav aria-label="快速配置步骤" className="-mx-1 overflow-x-auto px-1">
      <ol className="flex min-w-[720px] border-b border-border/70">
        {XRAY_QUICK_CONFIG_STEPS.map((step, index) => {
          const enabled = index <= props.furthestStepIndex;
          const completed = props.completed.has(step);
          return (
            <li key={step} className="flex-1">
              <button
                type="button"
                disabled={!enabled}
                aria-current={step === props.active ? "step" : undefined}
                onClick={() => props.onSelect(step)}
                className="group flex w-full items-center justify-center gap-2 border-b-2 border-transparent px-3 py-3 text-sm text-muted-foreground transition-colors enabled:hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40 aria-[current=step]:border-primary aria-[current=step]:font-medium aria-[current=step]:text-primary"
              >
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-current text-[11px]">
                  {completed ? <Check className="h-3 w-3" aria-hidden="true" /> : index + 1}
                </span>
                <span>{stepLabels[step]}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
