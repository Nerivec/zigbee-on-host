"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NWKGPHandler = void 0;
const logger_js_1 = require("../utils/logger.js");
const NS = "nwk-gp-handler";
/** Duration while duplicate table entries remain valid (milliseconds). */
const CONFIG_NWK_GP_DUPLICATE_TIMEOUT_MS = 2000;
/**
 * NWK GP Handler - Zigbee Green Power Network Layer
 */
class NWKGPHandler {
    #callbacks;
    #commissioningMode = false;
    #commissioningWindowTimeout;
    /** Recently seen frames for duplicate rejection by source ID */
    #duplicateTableId = new Map();
    /** Recently seen frames for duplicate rejection by source 64 + endpoint */
    #duplicateTable64 = new Map();
    constructor(callbacks) {
        this.#callbacks = callbacks;
    }
    async start() { }
    stop() {
        this.exitCommissioningMode();
        this.#duplicateTableId.clear();
        this.#duplicateTable64.clear();
    }
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
    /**
     * 14-0563-19 #A.3.8.2 (Commissioning mode control)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Cancels active commissioning timer and resets state flag
     * - ✅ Logs exit for diagnostics, matching spec recommendation for operator visibility
     * - ✅ Clears duplicate tables only when stop() invoked to preserve replay protection during window
     * - ⚠️  Additional cleanup (e.g., pending key distribution) not yet triggered here
     */
    exitCommissioningMode() {
        clearTimeout(this.#commissioningWindowTimeout);
        this.#commissioningWindowTimeout = undefined;
        this.#commissioningMode = false;
        logger_js_1.logger.info("Exited Green Power commissioning mode", NS);
    }
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
    isDuplicateFrame(macHeader, nwkHeader, now = Date.now()) {
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
        }
        else {
            for (const [key, entry] of this.#duplicateTable64) {
                if (entry.expiresAt <= now) {
                    this.#duplicateTable64.delete(key);
                }
            }
        }
        const entry = hasSourceId
            ? this.#duplicateTableId.get(nwkHeader.sourceId)
            : this.#duplicateTable64.get(`${nwkHeader.source64}-${nwkHeader.endpoint ?? 0xff}`);
        if (nwkHeader.securityFrameCounter !== undefined) {
            if (entry?.securityFrameCounter !== undefined && nwkHeader.securityFrameCounter <= entry.securityFrameCounter) {
                return true;
            }
            const newEntry = {
                securityFrameCounter: nwkHeader.securityFrameCounter,
                macSequenceNumber: macHeader.sequenceNumber,
                expiresAt: now + CONFIG_NWK_GP_DUPLICATE_TIMEOUT_MS,
            };
            if (hasSourceId) {
                this.#duplicateTableId.set(nwkHeader.sourceId, newEntry);
            }
            else {
                this.#duplicateTable64.set(`${nwkHeader.source64}-${nwkHeader.endpoint ?? 0xff}`, newEntry);
            }
            return false;
        }
        if (macHeader.sequenceNumber === undefined) {
            return false;
        }
        if (entry?.macSequenceNumber !== undefined && macHeader.sequenceNumber === entry.macSequenceNumber) {
            return true;
        }
        const newEntry = {
            macSequenceNumber: macHeader.sequenceNumber,
            expiresAt: now + CONFIG_NWK_GP_DUPLICATE_TIMEOUT_MS,
        };
        if (hasSourceId) {
            this.#duplicateTableId.set(nwkHeader.sourceId, newEntry);
        }
        else {
            this.#duplicateTable64.set(`${nwkHeader.source64}-${nwkHeader.endpoint ?? 0xff}`, newEntry);
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