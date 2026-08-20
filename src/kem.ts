import { XWing } from "@hpke/hybridkem-x-wing";

let cached: XWing | null = null;

export function getXWingKem(): XWing {
  if (!cached) cached = new XWing();
  return cached;
}
