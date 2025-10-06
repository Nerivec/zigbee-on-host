import { logger } from "../utils/logger.js";
import type { MACHeader } from "../zigbee/mac.js";
import { ZigbeeNWKGPCommandId, type ZigbeeNWKGPHeader } from "../zigbee/zigbee-nwkgp.js";
import type { StackCallbacks } from "../zigbee-stack/stack-context.js";

const NS = "nwk-gp-handler";

/**
 * Callbacks for NWK GP handler to communicate with driver
 */
export interface NWKGPHandlerCallbacks {
    onGPFrame: StackCallbacks["onGPFrame"];
}

/**
 * NWK GP Handler - Zigbee Green Power Network Layer
 */
export class NWKGPHandler {
    readonly #callbacks: NWKGPHandlerCallbacks;

    #commissioningMode = false;
    #commissioningWindowTimeout: NodeJS.Timeout | undefined;
    #lastSecurityFrameCounter = 0;
    #lastMACSequenceNumber = 0;

    constructor(callbacks: NWKGPHandlerCallbacks) {
        this.#callbacks = callbacks;
    }

    async start() {}

    stop() {
        this.exitCommissioningMode();
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

    public checkDuplicate(macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader): boolean {
        let duplicate = false;

        if (nwkHeader.securityFrameCounter !== undefined) {
            if (nwkHeader.securityFrameCounter === this.#lastSecurityFrameCounter) {
                duplicate = true;
            }

            this.#lastSecurityFrameCounter = nwkHeader.securityFrameCounter;
        } else if (macHeader.sequenceNumber !== undefined) {
            if (macHeader.sequenceNumber === this.#lastMACSequenceNumber) {
                duplicate = true;
            }

            this.#lastMACSequenceNumber = macHeader.sequenceNumber;
        }

        return duplicate;
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
