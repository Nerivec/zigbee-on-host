"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.processFrame = processFrame;
const logger_js_1 = require("../utils/logger.js");
const mac_js_1 = require("../zigbee/mac.js");
const zigbee_aps_js_1 = require("../zigbee/zigbee-aps.js");
const zigbee_nwk_js_1 = require("../zigbee/zigbee-nwk.js");
const zigbee_nwkgp_js_1 = require("../zigbee/zigbee-nwkgp.js");
const NS = "frame-handler";
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
/* @__INLINE__ */
async function processFrame(payload, context, macHandler, nwkHandler, nwkGPHandler, apsHandler, rssi = context.rssiMin) {
    const [macFCF, macFCFOutOffset] = (0, mac_js_1.decodeMACFrameControl)(payload, 0);
    // TODO: process BEACON for PAN ID conflict detection?
    if (macFCF.frameType !== 3 /* MACFrameType.CMD */ && macFCF.frameType !== 1 /* MACFrameType.DATA */) {
        logger_js_1.logger.debug(() => `<-~- MAC Ignoring frame with type not CMD/DATA (${macFCF.frameType})`, NS);
        return;
    }
    const [macHeader, macHOutOffset] = (0, mac_js_1.decodeMACHeader)(payload, macFCFOutOffset, macFCF);
    const macPayload = (0, mac_js_1.decodeMACPayload)(payload, macHOutOffset, macFCF, macHeader);
    if (macFCF.frameType === 3 /* MACFrameType.CMD */) {
        await macHandler.processCommand(macPayload, macHeader);
        // done
        return;
    }
    if (macHeader.destinationPANId !== 65535 /* ZigbeeMACConsts.BCAST_PAN */ && macHeader.destinationPANId !== context.netParams.panId) {
        logger_js_1.logger.debug(() => `<-~- MAC Ignoring frame with mismatching PAN Id ${macHeader.destinationPANId}`, NS);
        return;
    }
    if (macFCF.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
        macHeader.destination16 !== 65535 /* ZigbeeMACConsts.BCAST_ADDR */ &&
        macHeader.destination16 !== 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */) {
        logger_js_1.logger.debug(() => `<-~- MAC Ignoring frame intended for device ${macHeader.destination16}`, NS);
        return;
    }
    if (macPayload.byteLength > 0) {
        const protocolVersion = (macPayload.readUInt8(0) & 60 /* ZigbeeNWKConsts.FCF_VERSION */) >> 2;
        if (protocolVersion === 3 /* ZigbeeNWKConsts.VERSION_GREEN_POWER */) {
            if ((macFCF.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ && macHeader.destination16 === 65535 /* ZigbeeMACConsts.BCAST_ADDR */) ||
                macFCF.destAddrMode === 3 /* MACFrameAddressMode.EXT */) {
                const [nwkGPFCF, nwkGPFCFOutOffset] = (0, zigbee_nwkgp_js_1.decodeZigbeeNWKGPFrameControl)(macPayload, 0);
                const [nwkGPHeader, nwkGPHOutOffset] = (0, zigbee_nwkgp_js_1.decodeZigbeeNWKGPHeader)(macPayload, nwkGPFCFOutOffset, nwkGPFCF);
                if (nwkGPHeader.frameControl.frameType !== 0 /* ZigbeeNWKGPFrameType.DATA */ &&
                    nwkGPHeader.frameControl.frameType !== 1 /* ZigbeeNWKGPFrameType.MAINTENANCE */) {
                    logger_js_1.logger.debug(() => `<-~- NWKGP Ignoring frame with type ${nwkGPHeader.frameControl.frameType}`, NS);
                    return;
                }
                // Delegate GP duplicate check to NWK GP handler
                if (nwkGPHeader.frameControl.frameType !== 1 /* ZigbeeNWKGPFrameType.MAINTENANCE */ &&
                    nwkGPHandler.isDuplicateFrame(macHeader, nwkGPHeader)) {
                    logger_js_1.logger.debug(() => `<-~- NWKGP Ignoring duplicate frame macSeqNum=${macHeader.sequenceNumber} nwkGPFC=${nwkGPHeader.securityFrameCounter}`, NS);
                    return;
                }
                const nwkGPPayload = (0, zigbee_nwkgp_js_1.decodeZigbeeNWKGPPayload)(macPayload, nwkGPHOutOffset, context.netParams.networkKey, macHeader.source64, nwkGPFCF, nwkGPHeader);
                // Delegate GP frame processing to NWK GP handler
                nwkGPHandler.processFrame(nwkGPPayload, macHeader, nwkGPHeader, context.computeLQA(rssi));
            }
            else {
                logger_js_1.logger.debug(() => `<-x- NWKGP Invalid frame addressing ${macFCF.destAddrMode} (${macHeader.destination16})`, NS);
                return;
            }
        }
        else {
            const [nwkFCF, nwkFCFOutOffset] = (0, zigbee_nwk_js_1.decodeZigbeeNWKFrameControl)(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = (0, zigbee_nwk_js_1.decodeZigbeeNWKHeader)(macPayload, nwkFCFOutOffset, nwkFCF);
            if (macHeader.destination16 !== undefined &&
                macHeader.destination16 >= 65528 /* ZigbeeConsts.BCAST_MIN */ &&
                nwkHeader.source16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */) {
                logger_js_1.logger.debug(() => "<-~- NWK Ignoring frame from coordinator (broadcast loopback)", NS);
                return;
            }
            const resolvedSource64 = nwkHeader.source64 ?? (nwkHeader.source16 !== undefined ? context.address16ToAddress64.get(nwkHeader.source16) : undefined);
            const sourceLQA = context.computeDeviceLQA(nwkHeader.source16, nwkHeader.source64, rssi);
            const nwkPayload = (0, zigbee_nwk_js_1.decodeZigbeeNWKPayload)(macPayload, nwkHOutOffset, undefined, // use pre-hashed this.context.netParams.networkKey,
            resolvedSource64, nwkFCF, nwkHeader);
            if (nwkFCF.security && nwkHeader.securityHeader) {
                const accepted = context.updateIncomingNWKFrameCounter(nwkHeader.securityHeader.source64, nwkHeader.securityHeader.frameCounter);
                if (!accepted) {
                    logger_js_1.logger.warning(() => `<-x- NWK Rejecting replay frame src16=${nwkHeader.source16}:${nwkHeader.securityHeader.source64} counter=${nwkHeader.securityHeader?.frameCounter}`, NS);
                    return;
                }
            }
            if (nwkFCF.frameType === 0 /* ZigbeeNWKFrameType.DATA */) {
                const [apsFCF, apsFCFOutOffset] = (0, zigbee_aps_js_1.decodeZigbeeAPSFrameControl)(nwkPayload, 0);
                const [apsHeader, apsHOutOffset] = (0, zigbee_aps_js_1.decodeZigbeeAPSHeader)(nwkPayload, apsFCFOutOffset, apsFCF);
                if (nwkHeader.source16 === undefined && nwkHeader.source64 === undefined) {
                    logger_js_1.logger.debug(() => `<-~- APS Ignoring frame with no sender info nwkSeqNum=${nwkHeader.seqNum}`, NS);
                    return;
                }
                if (apsHeader.frameControl.ackRequest && nwkHeader.source16 !== 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */) {
                    await apsHandler.sendACK(macHeader, nwkHeader, apsHeader);
                }
                // Delegate APS duplicate check to APS handler
                if (apsHeader.frameControl.frameType !== 2 /* ZigbeeAPSFrameType.ACK */ && apsHandler.isDuplicateFrame(nwkHeader, apsHeader)) {
                    logger_js_1.logger.debug(() => `<=~= APS Ignoring duplicate frame nwkSeqNum=${nwkHeader.seqNum} counter=${apsHeader.counter}`, NS);
                    return;
                }
                const apsPayload = (0, zigbee_aps_js_1.decodeZigbeeAPSPayload)(nwkPayload, apsHOutOffset, undefined, // use pre-hashed this.context.netParams.tcKey,
                /* nwkHeader.frameControl.extendedSource ? nwkHeader.source64 : this.context.address16ToAddress64.get(nwkHeader.source16!) */
                nwkHeader.source64 ?? context.address16ToAddress64.get(nwkHeader.source16), apsFCF, apsHeader);
                // Delegate APS frame processing to APS handler
                await apsHandler.processFrame(apsPayload, macHeader, nwkHeader, apsHeader, sourceLQA);
            }
            else if (nwkFCF.frameType === 1 /* ZigbeeNWKFrameType.CMD */) {
                // Delegate NWK command processing to NWK handler
                await nwkHandler.processCommand(nwkPayload, macHeader, nwkHeader);
            }
            else if (nwkFCF.frameType === 3 /* ZigbeeNWKFrameType.INTERPAN */) {
                throw new Error("INTERPAN not supported");
            }
        }
    }
}
//# sourceMappingURL=frame.js.map