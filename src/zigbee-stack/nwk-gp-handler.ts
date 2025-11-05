import { logger } from "../utils/logger.js";
import type { MACHeader } from "../zigbee/mac.js";
import { ZigbeeNWKGPCommandId, type ZigbeeNWKGPHeader } from "../zigbee/zigbee-nwkgp.js";
import type { StackCallbacks } from "../zigbee-stack/stack-context.js";

const NS = "nwk-gp-handler";

type DuplicateTrackerEntry = {
    securityFrameCounter?: number;
    macSequenceNumber?: number;
    expiresAt: number;
};

/**
 * Callbacks for NWK GP handler to communicate with driver
 */
export interface NWKGPHandlerCallbacks {
    onGPFrame: StackCallbacks["onGPFrame"];
}

/** Duration while duplicate table entries remain valid (milliseconds). */
const CONFIG_NWK_GP_DUPLICATE_TIMEOUT_MS = 60000;

/**
 * NWK GP Handler - Zigbee Green Power Network Layer
 */
export class NWKGPHandler {
    readonly #callbacks: NWKGPHandlerCallbacks;

    #commissioningMode = false;
    #commissioningWindowTimeout: NodeJS.Timeout | undefined;
    readonly #duplicateTable = new Map<string, DuplicateTrackerEntry>();

    constructor(callbacks: NWKGPHandlerCallbacks) {
        this.#callbacks = callbacks;
    }

    async start() {}

    stop() {
        this.exitCommissioningMode();
        this.#duplicateTable.clear();
    }

    /**
     * Put the coordinator in Green Power commissioning mode.
     * @param commissioningWindow Defaults to 180 if unspecified. Max 254. 0 means exit.
     */
    public enterCommissioningMode(commissioningWindow = 180): void {
        if (commissioningWindow > 0) {
            clearTimeout(this.#commissioningWindowTimeout);

            this.#commissioningMode = true;
            this.#commissioningWindowTimeout = setTimeout(this.exitCommissioningMode.bind(this), Math.min(commissioningWindow, 0xfe) * 1000);

            logger.info(`Entered Green Power commissioning mode for ${commissioningWindow} seconds`, NS);
        } else {
            this.exitCommissioningMode();
        }
    }

    public exitCommissioningMode(): void {
        clearTimeout(this.#commissioningWindowTimeout);
        this.#commissioningWindowTimeout = undefined;
        this.#commissioningMode = false;

        logger.info("Exited Green Power commissioning mode", NS);
    }

    public isDuplicateFrame(macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader): boolean {
        const key = this.#makeDuplicateKey(macHeader, nwkHeader);

        if (key === undefined) {
            return false;
        }

        const now = Date.now();
        this.#pruneExpiredDuplicateEntries(now);

        const entry = this.#duplicateTable.get(key);

        if (nwkHeader.securityFrameCounter !== undefined) {
            const counter = nwkHeader.securityFrameCounter >>> 0;

            if (entry?.securityFrameCounter !== undefined && counter <= entry.securityFrameCounter) {
                return true;
            }

            this.#duplicateTable.set(key, {
                securityFrameCounter: counter,
                macSequenceNumber: macHeader.sequenceNumber,
                expiresAt: now + CONFIG_NWK_GP_DUPLICATE_TIMEOUT_MS,
            });

            return false;
        }

        if (macHeader.sequenceNumber === undefined) {
            return false;
        }

        const sequenceNumber = macHeader.sequenceNumber & 0xff;

        if (entry?.macSequenceNumber !== undefined && sequenceNumber === entry.macSequenceNumber) {
            return true;
        }

        this.#duplicateTable.set(key, {
            macSequenceNumber: sequenceNumber,
            expiresAt: now + CONFIG_NWK_GP_DUPLICATE_TIMEOUT_MS,
        });

        return false;
    }

    // Zigbee Green Power 14-0563-19 §A.1.4.1 requires sinks to track the latest GPD security frame counter per device.
    #makeDuplicateKey(macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader): string | undefined {
        if (nwkHeader.sourceId !== undefined) {
            return `gpd32:${nwkHeader.sourceId}`;
        }

        if (nwkHeader.source64 !== undefined) {
            const endpoint = nwkHeader.endpoint ?? 0;

            return `gpd64:${nwkHeader.source64}:${endpoint}`;
        }

        if (macHeader.source64 !== undefined) {
            return `mac64:${macHeader.source64}`;
        }

        if (macHeader.source16 !== undefined) {
            return `mac16:${macHeader.source16}`;
        }

        if (macHeader.sequenceNumber !== undefined) {
            const fcs = macHeader.fcs ?? 0;

            return `macseq:${macHeader.sequenceNumber}:${fcs}`;
        }

        return undefined;
    }

    #pruneExpiredDuplicateEntries(now: number): void {
        for (const [key, entry] of this.#duplicateTable) {
            if (entry.expiresAt <= now) {
                this.#duplicateTable.delete(key);
            }
        }
    }

    /**
     * See 14-0563-19 #A.3.8.2
     * @param data
     * @param macHeader
     * @param nwkHeader
     * @param rssi
     * @returns
     */
    public processFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, lqa: number): void {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;
        const framePayload = data.subarray(offset);

        if (
            !this.#commissioningMode &&
            (cmdId === ZigbeeNWKGPCommandId.COMMISSIONING || cmdId === ZigbeeNWKGPCommandId.SUCCESS || cmdId === ZigbeeNWKGPCommandId.CHANNEL_REQUEST)
        ) {
            logger.debug(() => `<=~= NWKGP[cmdId=${cmdId} src=${nwkHeader.sourceId}:${macHeader.source64}] Not in commissioning mode`, NS);

            return;
        }

        logger.debug(() => `<=== NWKGP[cmdId=${cmdId} src=${nwkHeader.sourceId}:${macHeader.source64}]`, NS);

        setImmediate(() => {
            this.#callbacks.onGPFrame(cmdId, framePayload, macHeader, nwkHeader, lqa);
        });
    }
}
