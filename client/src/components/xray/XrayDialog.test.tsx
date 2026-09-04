import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";
import { Dialog as BaseDialog, DialogContent as BaseDialogContent } from "../ui/dialog";
import { Dialog, DialogContent } from "./XrayDialog";

test("Xray dialogs prevent outside dismissal while retaining callbacks, refs and explicit close behavior", () => {
  let outsideCalls = 0;
  const escape = () => undefined;
  const ref = { current: null };
  const content = DialogContent({
    children: "Details", className: "max-w-4xl", ref,
    onInteractOutside: () => { outsideCalls += 1; },
    onEscapeKeyDown: escape,
  });
  const outside = new Event("interactOutside", { cancelable: true });
  content.props.onInteractOutside(outside);
  assert.equal(outside.defaultPrevented, true);
  assert.equal(outsideCalls, 1);
  const defaultOutside = new Event("interactOutside", { cancelable: true });
  DialogContent({}).props.onInteractOutside(defaultOutside);
  assert.equal(defaultOutside.defaultPrevented, true);
  assert.equal(content.type, BaseDialogContent);
  assert.equal(content.props.ref, ref);
  assert.equal(content.props.children, "Details");
  assert.equal(content.props.className, "max-w-4xl");
  assert.equal(content.props.onEscapeKeyDown, escape);
  assert.equal(Dialog, BaseDialog);
});

test("every Xray modal uses the scoped dialog instead of the globally dismissible dialog", () => {
  const directory = new URL("./", import.meta.url);
  let count = 0;
  for (const name of readdirSync(directory)) {
    if (!name.endsWith(".tsx") || name.includes(".test.") || name === "XrayDialog.tsx") continue;
    const source = readFileSync(new URL(name, directory), "utf8");
    assert.doesNotMatch(source, /from\s+["'](?:@\/components\/ui\/dialog|@radix-ui\/react-dialog)["']/, name);
    if (/<DialogContent\b/.test(source)) {
      assert.match(source, /from\s+["']\.\/XrayDialog["']/, name);
      count += 1;
    }
  }
  assert.ok(count >= 13, "all existing Xray dialog consumers must be covered");
});
