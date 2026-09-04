import type { ComponentProps } from "react";
import { DialogContent as BaseDialogContent } from "../ui/dialog";

export {
  Dialog,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog";

// Keep the policy local to Xray, including dialogs nested in other dialogs.
export function DialogContent({ onInteractOutside, ...props }: ComponentProps<typeof BaseDialogContent>) {
  return (
    <BaseDialogContent
      {...props}
      onInteractOutside={(event) => {
        event.preventDefault();
        onInteractOutside?.(event);
      }}
    />
  );
}
