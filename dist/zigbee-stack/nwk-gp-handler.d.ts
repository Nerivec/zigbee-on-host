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
     * Put the coordinator in Green Power commissioning mode.
     * @param commissioningWindow Defaults to 180 if unspecified. Max 254. 0 means exit.
     */
    enterCommissioningMode(commissioningWindow?: number): void;
    exitCommissioningMode(): void;
    checkDuplicate(macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader): boolean;
    /**
     * See 14-0563-19 #A.3.8.2
     * @param data
     * @param macHeader
     * @param nwkHeader
     * @param rssi
     * @returns
     */
    processFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, lqa: number): void;
}
