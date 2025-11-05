import { logger } from "../utils/logger.js";
import type { MACHeader } from "../zigbee/mac.js";
import { ZigbeeNWKGPCommandId, type ZigbeeNWKGPHeader } from "../zigbee/zigbee-nwkgp.js";
import type { StackCallbacks } from "../zigbee-stack/stack-context.js";

const NS = "nwk-gp-handler";

type DuplicateEntry = {
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
const CONFIG_NWK_GP_DUPLICATE_TIMEOUT_MS = 2000;

/**
 * NWK GP Handler - Zigbee Green Power Network Layer
 */
export class NWKGPHandler {
    readonly #callbacks: NWKGPHandlerCallbacks;

    #commissioningMode = false;
    #commissioningWindowTimeout: NodeJS.Timeout | undefined;
    /** Recently seen frames for duplicate rejection by source ID */
    readonly #duplicateTableId = new Map<number, DuplicateEntry>();
    /** Recently seen frames for duplicate rejection by source 64 + endpoint */
    readonly #duplicateTable64 = new Map<string, DuplicateEntry>();

    constructor(callbacks: NWKGPHandlerCallbacks) {
        this.#callbacks = callbacks;
    }

    async start() {}

    stop() {
        this.exitCommissioningMode();
        this.#duplicateTableId.clear();
        this.#duplicateTable64.clear();
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

    public isDuplicateFrame(macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, now = Date.now()): boolean {
        const hasSourceId = nwkHeader.sourceId !== undefined;

        if (!hasSourceId && nwkHeader.source64 === undefined) {
            // skip check if no identifier
            return false;
        }

        // prune expired duplicates, only for relevant table to avoid pointless looping for current frame
        if (hasSourceId) {
            for (const [key, entry] of this.#duplicateTableId) {
                if (entry.expiresAt <= now) {
                    this.#duplicateTableId.delete(key);
                }
            }
        } else {
            for (const [key, entry] of this.#duplicateTable64) {
                if (entry.expiresAt <= now) {
                    this.#duplicateTable64.delete(key);
                }
            }
        }

        const entry = hasSourceId
            ? this.#duplicateTableId.get(nwkHeader.sourceId!)
            : this.#duplicateTable64.get(`${nwkHeader.source64!}-${nwkHeader.endpoint ?? 0xff}`);

        if (nwkHeader.securityFrameCounter !== undefined) {
            if (entry?.securityFrameCounter !== undefined && nwkHeader.securityFrameCounter <= entry.securityFrameCounter) {
                return true;
            }

            const newEntry: DuplicateEntry = {
                securityFrameCounter: nwkHeader.securityFrameCounter,
                macSequenceNumber: macHeader.sequenceNumber,
                expiresAt: now + CONFIG_NWK_GP_DUPLICATE_TIMEOUT_MS,
            };

            if (hasSourceId) {
                this.#duplicateTableId.set(nwkHeader.sourceId!, newEntry);
            } else {
                this.#duplicateTable64.set(`${nwkHeader.source64!}-${nwkHeader.endpoint ?? 0xff}`, newEntry);
            }

            return false;
        }

        if (macHeader.sequenceNumber === undefined) {
            return false;
        }

        if (entry?.macSequenceNumber !== undefined && macHeader.sequenceNumber === entry.macSequenceNumber) {
            return true;
        }

        const newEntry: DuplicateEntry = {
            macSequenceNumber: macHeader.sequenceNumber,
            expiresAt: now + CONFIG_NWK_GP_DUPLICATE_TIMEOUT_MS,
        };

        if (hasSourceId) {
            this.#duplicateTableId.set(nwkHeader.sourceId!, newEntry);
        } else {
            this.#duplicateTable64.set(`${nwkHeader.source64!}-${nwkHeader.endpoint ?? 0xff}`, newEntry);
        }

        return false;
    }

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
