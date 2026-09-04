import { Check } from "lucide-react";

export const XRAY_CREATE_SECTIONS = ["BASIC", "PROTOCOL", "TRANSPORT", "PORT", "SECURITY", "ACCOUNT", "CONFIRM"] as const;
export type XrayCreateSection = typeof XRAY_CREATE_SECTIONS[number];

const labels: Record<XrayCreateSection, string> = {
  BASIC: "基础配置",
  PROTOCOL: "协议",
  TRANSPORT: "传输",
  PORT: "端口",
  SECURITY: "安全",
  ACCOUNT: "账户",
  CONFIRM: "确认",
};

export function selectableXrayCreateSections(
  active: XrayCreateSection,
  forwardEnabled: ReadonlySet<XrayCreateSection>,
): ReadonlySet<XrayCreateSection> {
  const activeIndex = XRAY_CREATE_SECTIONS.indexOf(active);
  return new Set(XRAY_CREATE_SECTIONS.filter((section, index) => (
    index <= activeIndex || forwardEnabled.has(section)
  )));
}

export function XrayCreateSectionNav(props: {
  active: XrayCreateSection;
  enabled: ReadonlySet<XrayCreateSection>;
  onSelect: (section: XrayCreateSection) => void;
}) {
  const activeIndex = XRAY_CREATE_SECTIONS.indexOf(props.active);
  return (
    <nav aria-label="创建节点配置分区" className="-mx-1 overflow-x-auto px-1">
      <ol className="flex min-w-[780px] border-b border-border/70">
        {XRAY_CREATE_SECTIONS.map((section, index) => {
          const enabled = props.enabled.has(section);
          const completed = index < activeIndex && enabled;
          return (
            <li key={section} className="flex-1">
              <button
                type="button"
                disabled={!enabled}
                aria-current={section === props.active ? "step" : undefined}
                onClick={() => props.onSelect(section)}
                className="group flex w-full items-center justify-center gap-2 border-b-2 border-transparent px-3 py-3 text-sm text-muted-foreground transition-colors enabled:hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40 aria-[current=step]:border-primary aria-[current=step]:font-medium aria-[current=step]:text-primary"
              >
                <span className="flex h-5 w-5 items-center justify-center rounded-full border border-current text-[11px]">{completed ? <Check className="h-3 w-3" aria-hidden={true} /> : index + 1}</span>
                <span>{labels[section]}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
