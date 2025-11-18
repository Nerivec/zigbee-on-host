import type { APSHandler } from "./aps-handler.js";
import type { MACHandler } from "./mac-handler.js";
import type { NWKGPHandler } from "./nwk-gp-handler.js";
import type { NWKHandler } from "./nwk-handler.js";
import type { StackContext } from "./stack-context.js";
/**
 * 05-3474-23 (Zigbee PRO) multi-layer processing pipeline
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Decodes MAC CMD/DATA frames and dispatches according to IEEE 802.15.4 frame type
 * - ✅ Validates PAN ID and destination addressing before NWK processing
 * - ✅ Routes Green Power (GP) frames per Zigbee GP spec (14-0563-19) when protocol version indicates GP
 * - ✅ Applies duplicate checks via respective handlers (MAC/NWK/APS/GP)
 * - ⚠️  INTERPAN frame type not supported (throws) - optional for coordinator
 * - ⚠️  Beacon/Other MAC frame types ignored (logged at debug level)
 * DEVICE SCOPE: Centralized trust center
 */
export declare function processFrame(payload: Buffer, context: StackContext, macHandler: MACHandler, nwkHandler: NWKHandler, nwkGPHandler: NWKGPHandler, apsHandler: APSHandler, rssi?: number): Promise<void>;
