import type { MACHeader } from "../zigbee/mac.js";
import { type ZigbeeNWKGPHeader } from "../zigbee/zigbee-nwkgp.js";
import type { StackCallbacks } from "../zigbee-stack/stack-context.js";
/**
 * Callbacks for NWK GP handler to communicate with driver
 */
export interface NWKGPHandlerCallbacks {
    onGPFrame: StackCallbacks["onGPFrame"];
}
/**
 * NWK GP Handler - Zigbee Green Power Network Layer
 */
export declare class NWKGPHandler {
    #private;
    constructor(callbacks: NWKGPHandlerCallbacks);
    start(): Promise<void>;
    stop(): void;
    /**
     * 14-0563-19 #A.3.8.2 (Commissioning mode control)
     *
     * Put the coordinator in Green Power commissioning mode.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Enables commissioning for bounded window (defaults to 180 s, clamped to 0xfe)
     * - ✅ Clears existing timer before starting new session to avoid overlap
     * - ✅ Logs entry for diagnostics; required commands are gated on this flag elsewhere
     * - ⚠️  Does not broadcast commissioning state to sinks; assumes host-only coordination
     *
     * @param commissioningWindow Defaults to 180 if unspecified. Max 254. 0 means exit.
     */
    enterCommissioningMode(commissioningWindow?: number): void;
    /**
     * 14-0563-19 #A.3.8.2 (Commissioning mode control)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Cancels active commissioning timer and resets state flag
     * - ✅ Logs exit for diagnostics, matching spec recommendation for operator visibility
     * - ✅ Clears duplicate tables only when stop() invoked to preserve replay protection during window
     * - ⚠️  Additional cleanup (e.g., pending key distribution) not yet triggered here
     */
    exitCommissioningMode(): void;
    /**
     * 14-0563-19 #A.3.5.2 (Duplicate filtering)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Maintains per-source security frame counter as primary replay protection metric
     * - ✅ Falls back to MAC sequence number when security not in use, per spec guidance
     * - ✅ Applies timeout window to age entries out of duplicate tables
     * - ✅ Handles both source ID and IEEE/endpoint addressing forms
     * - ⚠️  Does not persist counters across restarts; relies on runtime tables only
     */
    isDuplicateFrame(macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, now?: number): boolean;
    /**
     * 14-0563-19 (Green Power) #A.3.8.2
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Parses NWK GP command identifier and forwards payload to Stack callbacks
     * - ✅ Enforces commissioning-mode requirement for commissioning/success/channel request commands
     * - ✅ Applies duplicate filtering prior to forwarding (isDuplicateFrame)
     * - ⚠️  Does not validate security parameters beyond duplicate table (future enhancement)
     * - ⚠️  TLV decoding delegated to consumer (payload forwarded raw)
     *
     * @param data
     * @param macHeader
     * @param nwkHeader
     * @param rssi
     * @returns
     */
    processFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, lqa: number): void;
}
