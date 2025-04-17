"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MACAssociationStatus = void 0;
exports.getMICLength = getMICLength;
exports.decodeMACFrameControl = decodeMACFrameControl;
exports.decodeMACCapabilities = decodeMACCapabilities;
exports.encodeMACCapabilities = encodeMACCapabilities;
exports.decodeMACHeader = decodeMACHeader;
exports.decodeMACPayload = decodeMACPayload;
exports.encodeMACFrame = encodeMACFrame;
exports.encodeMACFrameZigbee = encodeMACFrameZigbee;
exports.decodeMACZigbeeBeacon = decodeMACZigbeeBeacon;
exports.encodeMACZigbeeBeacon = encodeMACZigbeeBeacon;
/** Definitions for Association Response Command */
var MACAssociationStatus;
(function (MACAssociationStatus) {
    MACAssociationStatus[MACAssociationStatus["SUCCESS"] = 0] = "SUCCESS";
    MACAssociationStatus[MACAssociationStatus["PAN_FULL"] = 1] = "PAN_FULL";
    MACAssociationStatus[MACAssociationStatus["PAN_ACCESS_DENIED"] = 2] = "PAN_ACCESS_DENIED";
})(MACAssociationStatus || (exports.MACAssociationStatus = MACAssociationStatus = {}));
/* Compute the MIC length. */
function getMICLength(securityLevel) {
    return (0x2 << (securityLevel & 0x3)) & ~0x3;
}
function decodeMACFrameControl(data, offset) {
    const fcf = data.readUInt16LE(offset);
    offset += 2;
    const frameType = fcf & 7 /* ZigbeeMACConsts.FCF_TYPE_MASK */;
    if (frameType === 5 /* MACFrameType.MULTIPURPOSE */) {
        throw new Error(`Unsupported MAC frame type MULTIPURPOSE (${frameType})`);
    }
    return [
        {
            frameType,
            securityEnabled: Boolean((fcf & 8 /* ZigbeeMACConsts.FCF_SEC_EN */) >> 3),
            framePending: Boolean((fcf & 16 /* ZigbeeMACConsts.FCF_FRAME_PND */) >> 4),
            ackRequest: Boolean((fcf & 32 /* ZigbeeMACConsts.FCF_ACK_REQ */) >> 5),
            panIdCompression: Boolean((fcf & 64 /* ZigbeeMACConsts.FCF_PAN_ID_COMPRESSION */) >> 6),
            /* bit 7 reserved */
            seqNumSuppress: Boolean((fcf & 256 /* ZigbeeMACConsts.FCF_SEQNO_SUPPRESSION */) >> 8),
            iePresent: Boolean((fcf & 512 /* ZigbeeMACConsts.FCF_IE_PRESENT */) >> 9),
            destAddrMode: (fcf & 3072 /* ZigbeeMACConsts.FCF_DADDR_MASK */) >> 10,
            frameVersion: (fcf & 12288 /* ZigbeeMACConsts.FCF_VERSION */) >> 12,
            sourceAddrMode: (fcf & 49152 /* ZigbeeMACConsts.FCF_SADDR_MASK */) >> 14,
        },
        offset,
    ];
}
function encodeMACFrameControl(data, offset, fcf) {
    if (fcf.frameType === 5 /* MACFrameType.MULTIPURPOSE */) {
        throw new Error(`Unsupported MAC frame type MULTIPURPOSE (${fcf.frameType})`);
    }
    data.writeUInt16LE((fcf.frameType & 7 /* ZigbeeMACConsts.FCF_TYPE_MASK */) |
        (((fcf.securityEnabled ? 1 : 0) << 3) & 8 /* ZigbeeMACConsts.FCF_SEC_EN */) |
        (((fcf.framePending ? 1 : 0) << 4) & 16 /* ZigbeeMACConsts.FCF_FRAME_PND */) |
        (((fcf.ackRequest ? 1 : 0) << 5) & 32 /* ZigbeeMACConsts.FCF_ACK_REQ */) |
        (((fcf.panIdCompression ? 1 : 0) << 6) & 64 /* ZigbeeMACConsts.FCF_PAN_ID_COMPRESSION */) |
        /* bit 7 reserved */
        (((fcf.seqNumSuppress ? 1 : 0) << 8) & 256 /* ZigbeeMACConsts.FCF_SEQNO_SUPPRESSION */) |
        (((fcf.iePresent ? 1 : 0) << 9) & 512 /* ZigbeeMACConsts.FCF_IE_PRESENT */) |
        ((fcf.destAddrMode << 10) & 3072 /* ZigbeeMACConsts.FCF_DADDR_MASK */) |
        ((fcf.frameVersion << 12) & 12288 /* ZigbeeMACConsts.FCF_VERSION */) |
        ((fcf.sourceAddrMode << 14) & 49152 /* ZigbeeMACConsts.FCF_SADDR_MASK */), offset);
    offset += 2;
    return offset;
}
function decodeMACAuxSecHeader(data, offset, frameControl) {
    let frameCounterSuppression = false;
    let asn;
    let frameCounter;
    let keySourceAddr32;
    let keySourceAddr64;
    let keyIndex;
    const securityControl = data.readUInt8(offset);
    offset += 1;
    const securityLevel = securityControl & 7 /* ZigbeeMACConsts.AUX_SEC_LEVEL_MASK */;
    const keyIdMode = (securityControl & 24 /* ZigbeeMACConsts.AUX_KEY_ID_MODE_MASK */) >> 3 /* ZigbeeMACConsts.AUX_KEY_ID_MODE_SHIFT */;
    if (frameControl.frameVersion === 2 /* MACFrameVersion.V2015 */) {
        frameCounterSuppression = Boolean(securityControl & 32 /* ZigbeeMACConsts.AUX_FRAME_COUNTER_SUPPRESSION_MASK */);
        // TODO: correct??
        asn = (securityControl & 64 /* ZigbeeMACConsts.AUX_ASN_IN_NONCE_MASK */) >> 6;
    }
    if (!frameCounterSuppression) {
        frameCounter = data.readUInt32LE(offset);
        offset += 4;
    }
    if (keyIdMode !== 0 /* MACSecurityKeyIdMode.IMPLICIT */) {
        if (keyIdMode === 2 /* MACSecurityKeyIdMode.EXPLICIT_4 */) {
            keySourceAddr32 = data.readUInt32LE(offset);
            offset += 4;
        }
        else if (keyIdMode === 3 /* MACSecurityKeyIdMode.EXPLICIT_8 */) {
            keySourceAddr64 = data.readBigUInt64LE(offset);
            offset += 8;
        }
        keyIndex = data.readUInt8(offset);
        offset += 1;
    }
    return [
        {
            securityLevel,
            keyIdMode,
            frameCounterSuppression,
            asn,
            frameCounter,
            keySourceAddr32,
            keySourceAddr64,
            keyIndex,
        },
        offset,
    ];
}
// function encodeMACAuxSecHeader(data: Buffer, offset: number): number {}
function decodeMACSuperframeSpec(data, offset) {
    const spec = data.readUInt16LE(offset);
    offset += 2;
    const beaconOrder = spec & 15 /* ZigbeeMACConsts.SUPERFRAME_BEACON_ORDER_MASK */;
    const superframeOrder = (spec & 240 /* ZigbeeMACConsts.SUPERFRAME_ORDER_MASK */) >> 4 /* ZigbeeMACConsts.SUPERFRAME_ORDER_SHIFT */;
    const finalCAPSlot = (spec & 3840 /* ZigbeeMACConsts.SUPERFRAME_CAP_MASK */) >> 8 /* ZigbeeMACConsts.SUPERFRAME_CAP_SHIFT */;
    const batteryExtension = Boolean((spec & 4096 /* ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_MASK */) >> 12 /* ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_SHIFT */);
    const panCoordinator = Boolean((spec & 16384 /* ZigbeeMACConsts.SUPERFRAME_COORD_MASK */) >> 14 /* ZigbeeMACConsts.SUPERFRAME_COORD_SHIFT */);
    const associationPermit = Boolean((spec & 32768 /* ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_MASK */) >> 15 /* ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_SHIFT */);
    return [
        {
            beaconOrder,
            superframeOrder,
            finalCAPSlot,
            batteryExtension,
            panCoordinator,
            associationPermit,
        },
        offset,
    ];
}
function encodeMACSuperframeSpec(data, offset, header) {
    const spec = header.superframeSpec;
    data.writeUInt16LE((spec.beaconOrder & 15 /* ZigbeeMACConsts.SUPERFRAME_BEACON_ORDER_MASK */) |
        ((spec.superframeOrder << 4 /* ZigbeeMACConsts.SUPERFRAME_ORDER_SHIFT */) & 240 /* ZigbeeMACConsts.SUPERFRAME_ORDER_MASK */) |
        ((spec.finalCAPSlot << 8 /* ZigbeeMACConsts.SUPERFRAME_CAP_SHIFT */) & 3840 /* ZigbeeMACConsts.SUPERFRAME_CAP_MASK */) |
        (((spec.batteryExtension ? 1 : 0) << 12 /* ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_SHIFT */) & 4096 /* ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_MASK */) |
        (((spec.panCoordinator ? 1 : 0) << 14 /* ZigbeeMACConsts.SUPERFRAME_COORD_SHIFT */) & 16384 /* ZigbeeMACConsts.SUPERFRAME_COORD_MASK */) |
        (((spec.associationPermit ? 1 : 0) << 15 /* ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_SHIFT */) & 32768 /* ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_MASK */), offset);
    offset += 2;
    return offset;
}
function decodeMACGtsInfo(data, offset) {
    let directionByte;
    let directions;
    let addresses;
    let timeLengths;
    let slots;
    const spec = data.readUInt8(offset);
    offset += 1;
    const count = spec & 7 /* ZigbeeMACConsts.GTS_COUNT_MASK */;
    const permit = Boolean(spec & 128 /* ZigbeeMACConsts.GTS_PERMIT_MASK */);
    if (count > 0) {
        directionByte = data.readUInt8(offset);
        offset += 1;
        directions = [];
        addresses = [];
        timeLengths = [];
        slots = [];
        for (let i = 0; i < count; i++) {
            directions.push(directionByte & (0x01 << i));
            const addr = data.readUInt16LE(offset);
            offset += 2;
            const slotByte = data.readUInt8(offset);
            offset += 1;
            const timeLength = (slotByte & 240 /* ZigbeeMACConsts.GTS_LENGTH_MASK */) >> 4 /* ZigbeeMACConsts.GTS_LENGTH_SHIFT */;
            const slot = slotByte & 15 /* ZigbeeMACConsts.GTS_SLOT_MASK */;
            addresses.push(addr);
            timeLengths.push(timeLength);
            slots.push(slot);
        }
    }
    return [
        {
            permit,
            directionByte,
            directions,
            addresses,
            timeLengths,
            slots,
        },
        offset,
    ];
}
function encodeMACGtsInfo(data, offset, header) {
    const info = header.gtsInfo;
    const count = info.directions ? info.directions.length : 0;
    data.writeUInt8((count & 7 /* ZigbeeMACConsts.GTS_COUNT_MASK */) | ((info.permit ? 1 : 0) & 128 /* ZigbeeMACConsts.GTS_PERMIT_MASK */), offset);
    offset += 1;
    if (count > 0) {
        // assert(info.directionByte !== undefined);
        data.writeUInt8(info.directionByte, offset);
        offset += 1;
        for (let i = 0; i < count; i++) {
            data.writeUInt16LE(info.addresses[i], offset);
            offset += 2;
            const timeLength = info.timeLengths[i];
            const slot = info.slots[i];
            data.writeUInt8(((timeLength << 4 /* ZigbeeMACConsts.GTS_LENGTH_SHIFT */) & 240 /* ZigbeeMACConsts.GTS_LENGTH_MASK */) | (slot & 15 /* ZigbeeMACConsts.GTS_SLOT_MASK */), offset);
            offset += 1;
        }
    }
    return offset;
}
function decodeMACPendAddr(data, offset) {
    const spec = data.readUInt8(offset);
    offset += 1;
    const num16 = spec & 7 /* ZigbeeMACConsts.PENDADDR_SHORT_MASK */;
    const num64 = (spec & 112 /* ZigbeeMACConsts.PENDADDR_LONG_MASK */) >> 4 /* ZigbeeMACConsts.PENDADDR_LONG_SHIFT */;
    let addr16List;
    let addr64List;
    if (num16 > 0) {
        addr16List = [];
        for (let i = 0; i < num16; i++) {
            addr16List.push(data.readUInt16LE(offset));
            offset += 2;
        }
    }
    if (num64 > 0) {
        addr64List = [];
        for (let i = 0; i < num64; i++) {
            addr64List.push(data.readBigUInt64LE(offset));
            offset += 8;
        }
    }
    return [
        {
            addr16List,
            addr64List,
        },
        offset,
    ];
}
function encodeMACPendAddr(data, offset, header) {
    const pendAddr = header.pendAddr;
    const num16 = pendAddr.addr16List ? pendAddr.addr16List.length : 0;
    const num64 = pendAddr.addr64List ? pendAddr.addr64List.length : 0;
    data.writeUInt8((num16 & 7 /* ZigbeeMACConsts.PENDADDR_SHORT_MASK */) | ((num64 << 4 /* ZigbeeMACConsts.PENDADDR_LONG_SHIFT */) & 112 /* ZigbeeMACConsts.PENDADDR_LONG_MASK */), offset);
    offset += 1;
    for (let i = 0; i < num16; i++) {
        data.writeUInt16LE(pendAddr.addr16List[i], offset);
        offset += 2;
    }
    for (let i = 0; i < num64; i++) {
        data.writeBigUInt64LE(pendAddr.addr64List[i], offset);
        offset += 8;
    }
    return offset;
}
function decodeMACHeaderIEs(data, offset, auxSecHeader) {
    let remaining = data.byteLength - offset - getMICLength(auxSecHeader?.securityLevel ?? 0);
    let payloadIEPresent = false;
    const ies = [];
    do {
        const header = data.readUInt16LE(offset);
        offset += 2;
        const id = (header & 32640 /* ZigbeeMACConsts.HEADER_IE_ID_MASK */) >> 7;
        const length = header & 127 /* ZigbeeMACConsts.HEADER_IE_LENGTH_MASK */;
        ies.push({ id, length });
        offset += 2 + length;
        remaining -= 2 + length;
        if (id === 126 /* ZigbeeMACConsts.HEADER_IE_HT1 */ || id === 127 /* ZigbeeMACConsts.HEADER_IE_HT2 */) {
            payloadIEPresent = id === 126 /* ZigbeeMACConsts.HEADER_IE_HT1 */;
            break;
        }
    } while (remaining > 0);
    return [
        {
            ies,
            payloadIEPresent,
        },
        offset,
    ];
}
// function encodeMACHeaderIEs(data: Buffer, offset: number): number {}
// export type MACHeaderPayloadIE = {
// }
// /**
//  * TODO: proper support for all IE stuff
//  *
//  * The Zigbee Payload IE is a Vendor Specific Payload IE (Group ID = 0x2) using the Zigbee OUI value of 0x4A191B.
//  *   - Bits: 0-5     6-15    Octets: Variable
//  *   -       Length  Sub-ID  Content
//  *
//  * REJOIN:
//  *   - Octets: 8                        2
//  *   -         Network Extended PAN ID  Sender Short Address
//  *
//  * TX_POWER:
//  *   - Octets: 1
//  *   -         TX Power (in dBm - used to send the frame)
//  *
//  * EB_PAYLOAD:
//  *   - Octets: 15              2                         2
//  *   -         Beacon Payload  Superframe Specification  Sender Short Address
//  */
// function decodeMACHeaderPayloadIEs(data: Buffer, offset: number, headerIE: MACHeaderIE): [MACHeaderPayloadIE[], offset: number] {
//     return [[], offset];
// }
function decodeMACCapabilities(capabilities) {
    return {
        alternatePANCoordinator: Boolean(capabilities & 0x01),
        deviceType: (capabilities & 0x02) >> 1,
        powerSource: (capabilities & 0x04) >> 2,
        rxOnWhenIdle: Boolean((capabilities & 0x08) >> 3),
        // reserved1: (capabilities & 0x10) >> 4,
        // reserved2: (capabilities & 0x20) >> 5,
        securityCapability: Boolean((capabilities & 0x40) >> 6),
        allocateAddress: Boolean((capabilities & 0x80) >> 7),
    };
}
function encodeMACCapabilities(capabilities) {
    return (((capabilities.alternatePANCoordinator ? 1 : 0) & 0x01) |
        ((capabilities.deviceType << 1) & 0x02) |
        ((capabilities.powerSource << 2) & 0x04) |
        (((capabilities.rxOnWhenIdle ? 1 : 0) << 3) & 0x08) |
        // (capabilities.reserved1 << 4) & 0x10) |
        // (capabilities.reserved2 << 5) & 0x20) |
        (((capabilities.securityCapability ? 1 : 0) << 6) & 0x40) |
        (((capabilities.allocateAddress ? 1 : 0) << 7) & 0x80));
}
function decodeMACHeader(data, offset, frameControl) {
    let sequenceNumber;
    let destinationPANId;
    let sourcePANId;
    if (!frameControl.seqNumSuppress) {
        sequenceNumber = data.readUInt8(offset);
        offset += 1;
    }
    if (frameControl.destAddrMode === 1 /* MACFrameAddressMode.RESERVED */) {
        throw new Error(`Invalid MAC frame: destination address mode ${frameControl.destAddrMode}`);
    }
    if (frameControl.sourceAddrMode === 1 /* MACFrameAddressMode.RESERVED */) {
        throw new Error(`Invalid MAC frame: source address mode ${frameControl.sourceAddrMode}`);
    }
    let destPANPresent = false;
    let sourcePANPresent = false;
    if (frameControl.frameType === 5 /* MACFrameType.MULTIPURPOSE */) {
        throw new Error("Unsupported MAC frame: MULTIPURPOSE");
    }
    if (frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */ || frameControl.frameVersion === 1 /* MACFrameVersion.V2006 */) {
        if (frameControl.destAddrMode !== 0 /* MACFrameAddressMode.NONE */ && frameControl.sourceAddrMode !== 0 /* MACFrameAddressMode.NONE */) {
            // addressing information is present
            if (frameControl.panIdCompression) {
                // PAN IDs are identical
                destPANPresent = true;
                sourcePANPresent = false;
            }
            else {
                // PAN IDs are different, both shall be included in the frame
                destPANPresent = true;
                sourcePANPresent = true;
            }
        }
        else {
            if (frameControl.panIdCompression) {
                throw new Error("Invalid MAC frame: unexpected PAN ID compression");
            }
            // only either the destination or the source addressing information is present
            if (frameControl.destAddrMode !== 0 /* MACFrameAddressMode.NONE */ && frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */) {
                destPANPresent = true;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ && frameControl.sourceAddrMode !== 0 /* MACFrameAddressMode.NONE */) {
                destPANPresent = false;
                sourcePANPresent = true;
            }
            else if (frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ && frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */) {
                destPANPresent = false;
                sourcePANPresent = false;
            }
            else {
                throw new Error("Invalid MAC frame: invalid addressing");
            }
        }
    }
    else if (frameControl.frameVersion === 2 /* MACFrameVersion.V2015 */) {
        if (frameControl.frameType === 0 /* MACFrameType.BEACON */ ||
            frameControl.frameType === 1 /* MACFrameType.DATA */ ||
            frameControl.frameType === 2 /* MACFrameType.ACK */ ||
            frameControl.frameType === 3 /* MACFrameType.CMD */) {
            if (frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                !frameControl.panIdCompression) {
                destPANPresent = false;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                frameControl.panIdCompression) {
                destPANPresent = true;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode !== 0 /* MACFrameAddressMode.NONE */ &&
                frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                !frameControl.panIdCompression) {
                destPANPresent = true;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode !== 0 /* MACFrameAddressMode.NONE */ &&
                frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                frameControl.panIdCompression) {
                destPANPresent = false;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                frameControl.sourceAddrMode !== 0 /* MACFrameAddressMode.NONE */ &&
                !frameControl.panIdCompression) {
                destPANPresent = false;
                sourcePANPresent = true;
            }
            else if (frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                frameControl.sourceAddrMode !== 0 /* MACFrameAddressMode.NONE */ &&
                frameControl.panIdCompression) {
                destPANPresent = false;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                !frameControl.panIdCompression) {
                destPANPresent = true;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                frameControl.panIdCompression) {
                destPANPresent = false;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                !frameControl.panIdCompression) {
                destPANPresent = true;
                sourcePANPresent = true;
            }
            else if (frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                !frameControl.panIdCompression) {
                destPANPresent = true;
                sourcePANPresent = true;
            }
            else if (frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                !frameControl.panIdCompression) {
                destPANPresent = true;
                sourcePANPresent = true;
            }
            else if (frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                frameControl.panIdCompression) {
                destPANPresent = true;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                frameControl.panIdCompression) {
                destPANPresent = true;
                sourcePANPresent = false;
            }
            else if (frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                frameControl.panIdCompression) {
                destPANPresent = true;
                sourcePANPresent = false;
            }
            else {
                throw new Error("Invalid MAC frame: unexpected PAN ID compression");
            }
        }
        else {
            // PAN ID Compression is not used
            destPANPresent = false;
            sourcePANPresent = false;
        }
    }
    else {
        throw new Error("Invalid MAC frame: invalid version");
    }
    let destination16;
    let destination64;
    let source16;
    let source64;
    if (destPANPresent) {
        destinationPANId = data.readUInt16LE(offset);
        offset += 2;
    }
    if (frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */) {
        destination16 = data.readUInt16LE(offset);
        offset += 2;
    }
    else if (frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */) {
        destination64 = data.readBigUInt64LE(offset);
        offset += 8;
    }
    if (sourcePANPresent) {
        sourcePANId = data.readUInt16LE(offset);
        offset += 2;
    }
    else {
        sourcePANId = destPANPresent ? destinationPANId : 65535 /* ZigbeeMACConsts.BCAST_PAN */;
    }
    if (frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */) {
        source16 = data.readUInt16LE(offset);
        offset += 2;
    }
    else if (frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */) {
        source64 = data.readBigUInt64LE(offset);
        offset += 8;
    }
    let auxSecHeader;
    if (frameControl.securityEnabled &&
        /*(frameControl.frameType === MACFrameType.MULTIPURPOSE || */ frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */) {
        [auxSecHeader, offset] = decodeMACAuxSecHeader(data, offset, frameControl);
    }
    let superframeSpec;
    let gtsInfo;
    let pendAddr;
    let commandId;
    let headerIE;
    if (
    /*frameControl.frameType !== MACFrameType.MULTIPURPOSE && */
    frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */ ||
        frameControl.frameVersion === 1 /* MACFrameVersion.V2006 */) {
        if (frameControl.frameType === 0 /* MACFrameType.BEACON */) {
            [superframeSpec, offset] = decodeMACSuperframeSpec(data, offset);
            [gtsInfo, offset] = decodeMACGtsInfo(data, offset);
            [pendAddr, offset] = decodeMACPendAddr(data, offset);
        }
        else if (frameControl.frameType === 3 /* MACFrameType.CMD */) {
            commandId = data.readUInt8(offset);
            offset += 1;
        }
    }
    else {
        if (frameControl.iePresent) {
            [headerIE, offset] = decodeMACHeaderIEs(data, offset, auxSecHeader);
            // TODO: headerIE.payloadIEPresent === true, Zigbee OUI?
        }
    }
    let frameCounter;
    let keySeqCounter;
    if (frameControl.securityEnabled &&
        /*frameControl.frameType !== MACFrameType.MULTIPURPOSE && */
        frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */) {
        // auxSecHeader?.securityLevel = ???;
        const isEncrypted = auxSecHeader.securityLevel & 0x04;
        if (isEncrypted) {
            frameCounter = data.readUInt32LE(offset);
            offset += 4;
            keySeqCounter = data.readUInt8(offset);
            offset += 1;
        }
    }
    if (offset >= data.byteLength) {
        throw new Error("Invalid MAC frame: no payload");
    }
    return [
        {
            frameControl,
            sequenceNumber,
            destinationPANId,
            destination16,
            destination64,
            sourcePANId,
            source16,
            source64,
            auxSecHeader,
            superframeSpec,
            gtsInfo,
            pendAddr,
            commandId,
            headerIE,
            frameCounter,
            keySeqCounter,
            fcs: 0, // set after decoded payload
        },
        offset,
    ];
}
function encodeMACHeader(data, offset, header, zigbee) {
    offset = encodeMACFrameControl(data, offset, header.frameControl);
    if (zigbee) {
        data.writeUInt8(header.sequenceNumber, offset);
        offset += 1;
        data.writeUInt16LE(header.destinationPANId, offset);
        offset += 2;
        data.writeUInt16LE(header.destination16, offset);
        offset += 2;
        if (header.sourcePANId !== undefined) {
            data.writeUInt16LE(header.sourcePANId, offset);
            offset += 2;
        }
        // NWK GP can be NONE
        if (header.frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */) {
            data.writeUInt16LE(header.source16, offset);
            offset += 2;
        }
    }
    else {
        if (!header.frameControl.seqNumSuppress) {
            data.writeUInt8(header.sequenceNumber, offset);
            offset += 1;
        }
        if (header.frameControl.destAddrMode === 1 /* MACFrameAddressMode.RESERVED */) {
            throw new Error(`Invalid MAC frame: destination address mode ${header.frameControl.destAddrMode}`);
        }
        if (header.frameControl.sourceAddrMode === 1 /* MACFrameAddressMode.RESERVED */) {
            throw new Error(`Invalid MAC frame: source address mode ${header.frameControl.sourceAddrMode}`);
        }
        let destPANPresent = false;
        let sourcePANPresent = false;
        if (header.frameControl.frameType === 5 /* MACFrameType.MULTIPURPOSE */) {
            throw new Error("Unsupported MAC frame: MULTIPURPOSE");
        }
        if (header.frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */ || header.frameControl.frameVersion === 1 /* MACFrameVersion.V2006 */) {
            if (header.frameControl.destAddrMode !== 0 /* MACFrameAddressMode.NONE */ && header.frameControl.sourceAddrMode !== 0 /* MACFrameAddressMode.NONE */) {
                // addressing information is present
                if (header.frameControl.panIdCompression) {
                    // PAN IDs are identical
                    destPANPresent = true;
                    sourcePANPresent = false;
                }
                else {
                    // PAN IDs are different, both shall be included in the frame
                    destPANPresent = true;
                    sourcePANPresent = true;
                }
            }
            else {
                if (header.frameControl.panIdCompression) {
                    throw new Error("Invalid MAC frame: unexpected PAN ID compression");
                }
                // only either the destination or the source addressing information is present
                if (header.frameControl.destAddrMode !== 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.sourceAddrMode !== 0 /* MACFrameAddressMode.NONE */) {
                    destPANPresent = false;
                    sourcePANPresent = true;
                }
                else if (header.frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                }
                else {
                    throw new Error("Invalid MAC frame: invalid addressing");
                }
            }
        }
        else if (header.frameControl.frameVersion === 2 /* MACFrameVersion.V2015 */) {
            if (header.frameControl.frameType === 0 /* MACFrameType.BEACON */ ||
                header.frameControl.frameType === 1 /* MACFrameType.DATA */ ||
                header.frameControl.frameType === 2 /* MACFrameType.ACK */ ||
                header.frameControl.frameType === 3 /* MACFrameType.CMD */) {
                if (header.frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    !header.frameControl.panIdCompression) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.panIdCompression) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode !== 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    !header.frameControl.panIdCompression) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode !== 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.sourceAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.panIdCompression) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.sourceAddrMode !== 0 /* MACFrameAddressMode.NONE */ &&
                    !header.frameControl.panIdCompression) {
                    destPANPresent = false;
                    sourcePANPresent = true;
                }
                else if (header.frameControl.destAddrMode === 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.sourceAddrMode !== 0 /* MACFrameAddressMode.NONE */ &&
                    header.frameControl.panIdCompression) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                    header.frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                    !header.frameControl.panIdCompression) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                    header.frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                    header.frameControl.panIdCompression) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                    header.frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                    !header.frameControl.panIdCompression) {
                    destPANPresent = true;
                    sourcePANPresent = true;
                }
                else if (header.frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                    header.frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                    !header.frameControl.panIdCompression) {
                    destPANPresent = true;
                    sourcePANPresent = true;
                }
                else if (header.frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                    header.frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                    !header.frameControl.panIdCompression) {
                    destPANPresent = true;
                    sourcePANPresent = true;
                }
                else if (header.frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                    header.frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                    header.frameControl.panIdCompression) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */ &&
                    header.frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                    header.frameControl.panIdCompression) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                }
                else if (header.frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                    header.frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                    header.frameControl.panIdCompression) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                }
                else {
                    throw new Error("Invalid MAC frame: unexpected PAN ID compression");
                }
            }
            else {
                // PAN ID Compression is not used
                destPANPresent = false;
                sourcePANPresent = false;
            }
        }
        else {
            throw new Error("Invalid MAC frame: invalid version");
        }
        if (destPANPresent) {
            data.writeUInt16LE(header.destinationPANId, offset);
            offset += 2;
        }
        if (header.frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */) {
            data.writeUInt16LE(header.destination16, offset);
            offset += 2;
        }
        else if (header.frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */) {
            data.writeBigUInt64LE(header.destination64, offset);
            offset += 8;
        }
        if (sourcePANPresent) {
            data.writeUInt16LE(header.sourcePANId, offset);
            offset += 2;
        }
        if (header.frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */) {
            data.writeUInt16LE(header.source16, offset);
            offset += 2;
        }
        else if (header.frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */) {
            data.writeBigUInt64LE(header.source64, offset);
            offset += 8;
        }
        let auxSecHeader;
        if (header.frameControl.securityEnabled &&
            /*(header.frameControl.frameType === MACFrameType.MULTIPURPOSE || */ header.frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */) {
            throw new Error("Unsupported: securityEnabled");
            // [auxSecHeader, offset] = encodeMACAuxSecHeader(data, offset, header.frameControl);
        }
        if (
        /*header.frameControl.frameType !== MACFrameType.MULTIPURPOSE && */
        header.frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */ ||
            header.frameControl.frameVersion === 1 /* MACFrameVersion.V2006 */) {
            if (header.frameControl.frameType === 0 /* MACFrameType.BEACON */) {
                offset = encodeMACSuperframeSpec(data, offset, header);
                offset = encodeMACGtsInfo(data, offset, header);
                offset = encodeMACPendAddr(data, offset, header);
            }
            else if (header.frameControl.frameType === 3 /* MACFrameType.CMD */) {
                data.writeUInt8(header.commandId, offset);
                offset += 1;
            }
        }
        else {
            if (header.frameControl.iePresent) {
                throw new Error("Unsupported iePresent");
                // offset = encodeMACHeaderIEs(data, offset, auxSecHeader);
            }
        }
        if (header.frameControl.securityEnabled &&
            /*header.frameControl.frameType !== MACFrameType.MULTIPURPOSE && */
            header.frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */) {
            // auxSecHeader?.securityLevel = ???;
            const isEncrypted = auxSecHeader.securityLevel & 0x04;
            if (isEncrypted) {
                data.writeUInt32LE(header.frameCounter, offset);
                offset += 4;
                data.writeUInt8(header.keySeqCounter, offset);
                offset += 1;
            }
        }
    }
    return offset;
}
function crc16CCITT(data) {
    let fcs = 0x0000;
    for (const aByte of data) {
        let q = (fcs ^ aByte) & 0x0f;
        fcs = (fcs >> 4) ^ (q * 0x1081);
        q = (fcs ^ (aByte >> 4)) & 0x0f;
        fcs = (fcs >> 4) ^ (q * 0x1081);
    }
    return fcs;
}
function decryptPayload(data, offset, frameControl) {
    if (frameControl.securityEnabled) {
        // XXX: not needed for ZigBee
        throw new Error("Unsupported MAC: security enabled");
    }
    const endOffset = data.byteLength - 2 /* ZigbeeMACConsts.FCS_LEN */;
    return [data.subarray(offset, endOffset), endOffset];
}
// function encryptPayload(data: Buffer, offset: number): number {}
function decodeMACPayload(data, offset, frameControl, header) {
    const [payload, pOutOffset] = decryptPayload(data, offset, frameControl);
    if (pOutOffset >= data.byteLength) {
        throw new Error("Invalid MAC frame: no FCS");
    }
    header.fcs = data.readUInt16LE(pOutOffset);
    return payload;
}
function encodeMACFrame(header, payload) {
    let offset = 0;
    const data = Buffer.alloc(102 /* ZigbeeMACConsts.PAYLOAD_MAX_SAFE_SIZE */);
    offset = encodeMACHeader(data, offset, header, false);
    data.set(payload, offset);
    offset += payload.byteLength;
    data.writeUInt16LE(crc16CCITT(data.subarray(0, offset)), offset);
    offset += 2;
    return data.subarray(0, offset);
}
/** Encode MAC frame with hotpath for Zigbee NWK/APS payload */
function encodeMACFrameZigbee(header, payload) {
    let offset = 0;
    const data = Buffer.alloc(102 /* ZigbeeMACConsts.PAYLOAD_MAX_SAFE_SIZE */); // TODO: optimize with max ZigBee header length
    // always transmit with v2003 (0) frame version @see D.6 Frame Version Value of 05-3474-23
    header.frameControl.frameVersion = 0 /* MACFrameVersion.V2003 */;
    offset = encodeMACHeader(data, offset, header, true); // zigbee hotpath
    data.set(payload, offset);
    offset += payload.byteLength;
    data.writeUInt16LE(crc16CCITT(data.subarray(0, offset)), offset);
    offset += 2;
    return data.subarray(0, offset);
}
function decodeMACZigbeeBeacon(data, offset) {
    const protocolId = data.readUInt8(offset);
    offset += 1;
    const beacon = data.readUInt16LE(offset);
    offset += 2;
    const profile = beacon & 15 /* ZigbeeMACConsts.ZIGBEE_BEACON_STACK_PROFILE_MASK */;
    const version = (beacon & 240 /* ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_MASK */) >> 4 /* ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_SHIFT */;
    const routerCapacity = Boolean((beacon & 1024 /* ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_MASK */) >> 10 /* ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_SHIFT */);
    const deviceDepth = (beacon & 30720 /* ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_MASK */) >> 11 /* ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_SHIFT */;
    const endDeviceCapacity = Boolean((beacon & 32768 /* ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_MASK */) >> 15 /* ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_SHIFT */);
    const extendedPANId = data.readBigUInt64LE(offset);
    offset += 8;
    const endBytes = data.readUInt32LE(offset);
    const txOffset = endBytes & 16777215 /* ZigbeeMACConsts.ZIGBEE_BEACON_TX_OFFSET_MASK */;
    const updateId = (endBytes & 255 /* ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_MASK */) >> 24 /* ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_SHIFT */;
    return {
        protocolId,
        profile,
        version,
        routerCapacity,
        deviceDepth,
        endDeviceCapacity,
        extendedPANId,
        txOffset,
        updateId,
    };
}
function encodeMACZigbeeBeacon(beacon) {
    const payload = Buffer.alloc(15 /* ZigbeeMACConsts.ZIGBEE_BEACON_LENGTH */);
    let offset = 0;
    payload.writeUInt8(0, offset); // protocol ID always 0 on Zigbee beacons
    offset += 1;
    payload.writeUInt16LE((beacon.profile & 15 /* ZigbeeMACConsts.ZIGBEE_BEACON_STACK_PROFILE_MASK */) |
        ((beacon.version << 4 /* ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_SHIFT */) & 240 /* ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_MASK */) |
        (((beacon.routerCapacity ? 1 : 0) << 10 /* ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_SHIFT */) &
            1024 /* ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_MASK */) |
        ((beacon.deviceDepth << 11 /* ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_SHIFT */) & 30720 /* ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_MASK */) |
        (((beacon.endDeviceCapacity ? 1 : 0) << 15 /* ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_SHIFT */) &
            32768 /* ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_MASK */), offset);
    offset += 2;
    payload.writeBigUInt64LE(beacon.extendedPANId, offset);
    offset += 8;
    payload.writeUInt32LE((beacon.txOffset & 16777215 /* ZigbeeMACConsts.ZIGBEE_BEACON_TX_OFFSET_MASK */) |
        ((beacon.updateId << 24 /* ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_SHIFT */) & 255 /* ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_MASK */), offset);
    return payload;
}
// #endregion
//# sourceMappingURL=mac.js.map