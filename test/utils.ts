import { MACFrameAddressMode, type MACFrameControl, MACFrameType, MACFrameVersion, type MACHeader } from "../src/zigbee/mac.js";
import type { ZigbeeNWKGPHeader } from "../src/zigbee/zigbee-nwkgp.js";
import type { DeviceTableEntry } from "../src/zigbee-stack/stack-context.js";

export function defaultDeviceTableEntry(): DeviceTableEntry {
    return {
        address16: 0x0001,
        capabilities: undefined,
        authorized: false,
        neighbor: false,
        lastTransportedNetworkKeySeq: undefined,
        recentLQAs: [],
        lastReceivedRssi: undefined,
        incomingNWKFrameCounter: undefined,
        endDeviceTimeout: undefined,
        linkStatusMisses: 0,
    };
}

/** Helper to create minimal MAC frame control */
export function createMACFrameControl(
    frameType = MACFrameType.CMD,
    destAddrMode = MACFrameAddressMode.SHORT,
    sourceAddrMode = MACFrameAddressMode.SHORT,
): MACFrameControl {
    return {
        frameType,
        securityEnabled: false,
        framePending: false,
        ackRequest: false,
        panIdCompression: false,
        seqNumSuppress: false,
        iePresent: false,
        destAddrMode,
        frameVersion: MACFrameVersion.V2003,
        sourceAddrMode,
    };
}

/** Helper to create minimal MAC header for GP testing */
export function createMACHeader(
    frameType = MACFrameType.CMD,
    destAddrMode = MACFrameAddressMode.SHORT,
    sourceAddrMode = MACFrameAddressMode.SHORT,
): MACHeader {
    return {
        frameControl: createMACFrameControl(frameType, destAddrMode, sourceAddrMode),
        sequenceNumber: 1,
        destinationPANId: 0x1a62,
        destination16: 0x0000,
        source64: 0x00124b0012345678n,
        fcs: 0,
    };
}

/** Helper to create minimal NWK GP header */
export function createNWKGPHeader(): ZigbeeNWKGPHeader {
    return {
        frameControl: {
            frameType: 0,
            protocolVersion: 3,
            autoCommissioning: false,
            nwkFrameControlExtension: false,
        },
        sourceId: 0x12345678,
        securityFrameCounter: 100,
        micSize: 0,
        payloadLength: 10,
    };
}
