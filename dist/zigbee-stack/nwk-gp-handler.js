"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NWKGPHandler = void 0;
const logger_js_1 = require("../utils/logger.js");
const NS = "nwk-gp-handler";
/**
 * NWK GP Handler - Zigbee Green Power Network Layer
 */
class NWKGPHandler {
    #callbacks;
    #commissioningMode = false;
    #commissioningWindowTimeout;
    #lastSecurityFrameCounter = 0;
    #lastMACSequenceNumber = 0;
    constructor(callbacks) {
        this.#callbacks = callbacks;
    }
    async start() { }
    stop() {
        this.exitCommissioningMode();
    }
    /**
     * Put the coordinator in Green Power commissioning mode.
     * @param commissioningWindow Defaults to 180 if unspecified. Max 254. 0 means exit.
     */
    enterCommissioningMode(commissioningWindow = 180) {
        if (commissioningWindow > 0) {
            clearTimeout(this.#commissioningWindowTimeout);
            this.#commissioningMode = true;
            this.#commissioningWindowTimeout = setTimeout(this.exitCommissioningMode.bind(this), Math.min(commissioningWindow, 0xfe) * 1000);
            logger_js_1.logger.info(`Entered Green Power commissioning mode for ${commissioningWindow} seconds`, NS);
        }
        else {
            this.exitCommissioningMode();
        }
    }
    exitCommissioningMode() {
        clearTimeout(this.#commissioningWindowTimeout);
        this.#commissioningWindowTimeout = undefined;
        this.#commissioningMode = false;
        logger_js_1.logger.info("Exited Green Power commissioning mode", NS);
    }
    checkDuplicate(macHeader, nwkHeader) {
        let duplicate = false;
        if (nwkHeader.securityFrameCounter !== undefined) {
            if (nwkHeader.securityFrameCounter === this.#lastSecurityFrameCounter) {
                duplicate = true;
            }
            this.#lastSecurityFrameCounter = nwkHeader.securityFrameCounter;
        }
        else if (macHeader.sequenceNumber !== undefined) {
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
    processFrame(data, macHeader, nwkHeader, lqa) {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;
        const framePayload = data.subarray(offset);
        if (!this.#commissioningMode &&
            (cmdId === 224 /* ZigbeeNWKGPCommandId.COMMISSIONING */ || cmdId === 226 /* ZigbeeNWKGPCommandId.SUCCESS */ || cmdId === 227 /* ZigbeeNWKGPCommandId.CHANNEL_REQUEST */)) {
            logger_js_1.logger.debug(() => `<=~= NWKGP[cmdId=${cmdId} src=${nwkHeader.sourceId}:${macHeader.source64}] Not in commissioning mode`, NS);
            return;
        }
        logger_js_1.logger.debug(() => `<=== NWKGP[cmdId=${cmdId} src=${nwkHeader.sourceId}:${macHeader.source64}]`, NS);
        setImmediate(() => {
            this.#callbacks.onGPFrame(cmdId, framePayload, macHeader, nwkHeader, lqa);
        });
    }
}
exports.NWKGPHandler = NWKGPHandler;
//# sourceMappingURL=nwk-gp-handler.js.map