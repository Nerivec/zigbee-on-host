import { logger } from "../utils/logger.js";
import { decodeMACFrameControl, decodeMACHeader, decodeMACPayload, MACFrameAddressMode, MACFrameType, ZigbeeMACConsts } from "../zigbee/mac.js";
import { ZigbeeConsts } from "../zigbee/zigbee.js";
import { decodeZigbeeAPSFrameControl, decodeZigbeeAPSHeader, decodeZigbeeAPSPayload, ZigbeeAPSFrameType } from "../zigbee/zigbee-aps.js";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
} from "../zigbee/zigbee-nwk.js";
import { decodeZigbeeNWKGPFrameControl, decodeZigbeeNWKGPHeader, decodeZigbeeNWKGPPayload, ZigbeeNWKGPFrameType } from "../zigbee/zigbee-nwkgp.js";
import type { APSHandler } from "./aps-handler.js";
import type { MACHandler } from "./mac-handler.js";
import type { NWKGPHandler } from "./nwk-gp-handler.js";
import type { NWKHandler } from "./nwk-handler.js";
import type { StackContext } from "./stack-context.js";

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
 */
/* @__INLINE__ */
export async function processFrame(
    payload: Buffer,
    context: StackContext,
    macHandler: MACHandler,
    nwkHandler: NWKHandler,
    nwkGPHandler: NWKGPHandler,
    apsHandler: APSHandler,
    rssi = context.rssiMin,
): Promise<void> {
    const [macFCF, macFCFOutOffset] = decodeMACFrameControl(payload, 0);

    // TODO: process BEACON for PAN ID conflict detection?
    if (macFCF.frameType !== MACFrameType.CMD && macFCF.frameType !== MACFrameType.DATA) {
        logger.debug(() => `<-~- MAC Ignoring frame with type not CMD/DATA (${macFCF.frameType})`, NS);
        return;
    }

    const [macHeader, macHOutOffset] = decodeMACHeader(payload, macFCFOutOffset, macFCF);

    const macPayload = decodeMACPayload(payload, macHOutOffset, macFCF, macHeader);

    if (macFCF.frameType === MACFrameType.CMD) {
        await macHandler.processCommand(macPayload, macHeader);

        // done
        return;
    }

    if (macHeader.destinationPANId !== ZigbeeMACConsts.BCAST_PAN && macHeader.destinationPANId !== context.netParams.panId) {
        logger.debug(() => `<-~- MAC Ignoring frame with mismatching PAN Id ${macHeader.destinationPANId}`, NS);
        return;
    }

    if (
        macFCF.destAddrMode === MACFrameAddressMode.SHORT &&
        macHeader.destination16! !== ZigbeeMACConsts.BCAST_ADDR &&
        macHeader.destination16! !== ZigbeeConsts.COORDINATOR_ADDRESS
    ) {
        logger.debug(() => `<-~- MAC Ignoring frame intended for device ${macHeader.destination16}`, NS);
        return;
    }

    if (macPayload.byteLength > 0) {
        const protocolVersion = (macPayload.readUInt8(0) & ZigbeeNWKConsts.FCF_VERSION) >> 2;

        if (protocolVersion === ZigbeeNWKConsts.VERSION_GREEN_POWER) {
            if (
                (macFCF.destAddrMode === MACFrameAddressMode.SHORT && macHeader.destination16 === ZigbeeMACConsts.BCAST_ADDR) ||
                macFCF.destAddrMode === MACFrameAddressMode.EXT
            ) {
                const [nwkGPFCF, nwkGPFCFOutOffset] = decodeZigbeeNWKGPFrameControl(macPayload, 0);
                const [nwkGPHeader, nwkGPHOutOffset] = decodeZigbeeNWKGPHeader(macPayload, nwkGPFCFOutOffset, nwkGPFCF);

                if (
                    nwkGPHeader.frameControl.frameType !== ZigbeeNWKGPFrameType.DATA &&
                    nwkGPHeader.frameControl.frameType !== ZigbeeNWKGPFrameType.MAINTENANCE
                ) {
                    logger.debug(() => `<-~- NWKGP Ignoring frame with type ${nwkGPHeader.frameControl.frameType}`, NS);
                    return;
                }

                // Delegate GP duplicate check to NWK GP handler
                if (
                    nwkGPHeader.frameControl.frameType !== ZigbeeNWKGPFrameType.MAINTENANCE &&
                    nwkGPHandler.isDuplicateFrame(macHeader, nwkGPHeader)
                ) {
                    logger.debug(
                        () => `<-~- NWKGP Ignoring duplicate frame macSeqNum=${macHeader.sequenceNumber} nwkGPFC=${nwkGPHeader.securityFrameCounter}`,
                        NS,
                    );
                    return;
                }

                const nwkGPPayload = decodeZigbeeNWKGPPayload(
                    macPayload,
                    nwkGPHOutOffset,
                    context.netParams.networkKey,
                    macHeader.source64,
                    nwkGPFCF,
                    nwkGPHeader,
                );

                // Delegate GP frame processing to NWK GP handler
                nwkGPHandler.processFrame(nwkGPPayload, macHeader, nwkGPHeader, context.computeLQA(rssi));
            } else {
                logger.debug(() => `<-x- NWKGP Invalid frame addressing ${macFCF.destAddrMode} (${macHeader.destination16})`, NS);
                return;
            }
        } else {
            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);

            if (
                macHeader.destination16 !== undefined &&
                macHeader.destination16 >= ZigbeeConsts.BCAST_MIN &&
                nwkHeader.source16 === ZigbeeConsts.COORDINATOR_ADDRESS
            ) {
                logger.debug(() => "<-~- NWK Ignoring frame from coordinator (broadcast loopback)", NS);
                return;
            }

            const resolvedSource64 =
                nwkHeader.source64 ?? (nwkHeader.source16 !== undefined ? context.address16ToAddress64.get(nwkHeader.source16) : undefined);
            const sourceLQA = context.computeDeviceLQA(nwkHeader.source16, nwkHeader.source64, rssi);
            const nwkPayload = decodeZigbeeNWKPayload(
                macPayload,
                nwkHOutOffset,
                undefined, // use pre-hashed this.context.netParams.networkKey,
                resolvedSource64,
                nwkFCF,
                nwkHeader,
            );

            if (nwkFCF.security && nwkHeader.securityHeader) {
                const accepted = context.updateIncomingNWKFrameCounter(resolvedSource64, nwkHeader.securityHeader.frameCounter);

                if (!accepted) {
                    logger.warning(
                        () =>
                            `<-x- NWK Rejecting replay frame src16=${nwkHeader.source16}:${resolvedSource64} counter=${nwkHeader.securityHeader?.frameCounter}`,
                        NS,
                    );

                    return;
                }
            }

            if (nwkFCF.frameType === ZigbeeNWKFrameType.DATA) {
                const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
                const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);

                if (nwkHeader.source16 === undefined && nwkHeader.source64 === undefined) {
                    logger.debug(() => `<-~- APS Ignoring frame with no sender info seqNum=${nwkHeader.seqNum}`, NS);
                    return;
                }

                if (apsHeader.frameControl.ackRequest && nwkHeader.source16 !== ZigbeeConsts.COORDINATOR_ADDRESS) {
                    await apsHandler.sendACK(macHeader, nwkHeader, apsHeader);
                }

                // Delegate APS duplicate check to APS handler
                if (apsHeader.frameControl.frameType !== ZigbeeAPSFrameType.ACK && apsHandler.isDuplicateFrame(nwkHeader, apsHeader)) {
                    logger.debug(() => `<=~= APS Ignoring duplicate frame seqNum=${nwkHeader.seqNum} counter=${apsHeader.counter}`, NS);
                    return;
                }

                const apsPayload = decodeZigbeeAPSPayload(
                    nwkPayload,
                    apsHOutOffset,
                    undefined, // use pre-hashed this.context.netParams.tcKey,
                    /* nwkHeader.frameControl.extendedSource ? nwkHeader.source64 : this.context.address16ToAddress64.get(nwkHeader.source16!) */
                    nwkHeader.source64 ?? context.address16ToAddress64.get(nwkHeader.source16!),
                    apsFCF,
                    apsHeader,
                );

                // Delegate APS frame processing to APS handler
                await apsHandler.processFrame(apsPayload, macHeader, nwkHeader, apsHeader, sourceLQA);
            } else if (nwkFCF.frameType === ZigbeeNWKFrameType.CMD) {
                // Delegate NWK command processing to NWK handler
                await nwkHandler.processCommand(nwkPayload, macHeader, nwkHeader);
            } else if (nwkFCF.frameType === ZigbeeNWKFrameType.INTERPAN) {
                throw new Error("INTERPAN not supported");
            }
        }
    }
}
