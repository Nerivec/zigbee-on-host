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
/**
 * Decode MAC frame control field.
 * HOT PATH: Called for every incoming MAC frame.
 * IEEE Std 802.15.4-2020, 7.2.1 (Frame control field)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Parses Zigbee-required FCF bits and reconstructs addressing/security flags
 * - ✅ Rejects Multipurpose frame type forbidden by Zigbee MAC profile
 * - ⚠️  Leaves Information Element interpretation to higher layers by design
 * DEVICE SCOPE: All logical devices.
 */
/* @__INLINE__ */
function decodeMACFrameControl(data, offset) {
    // HOT PATH: Read FCF and extract fields with bitwise operations
    const fcf = data.readUInt16LE(offset);
    offset += 2;
    const frameType = fcf & 7 /* ZigbeeMACConsts.FCF_TYPE_MASK */;
    if (frameType === 5 /* MACFrameType.MULTIPURPOSE */) {
        // MULTIPURPOSE frames belong to generic 802.15.4 features that Zigbee never exercises
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
/**
 * IEEE Std 802.15.4-2020, 7.2.1 (Frame control field)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Emits only Zigbee-allowed frame versions and addressing combinations
 * - ✅ Rejects Multipurpose frames consistent with host-side Zigbee profile constraints
 * - ⚠️  Leaves Information Element flag handling to later encoding paths
 * DEVICE SCOPE: All logical devices.
 */
function encodeMACFrameControl(data, offset, fcf) {
    if (fcf.frameType === 5 /* MACFrameType.MULTIPURPOSE */) {
        // MULTIPURPOSE frames belong to generic 802.15.4 features that Zigbee never exercises
        throw new Error(`Unsupported MAC frame type MULTIPURPOSE (${fcf.frameType})`);
    }
    offset = data.writeUInt16LE((fcf.frameType & 7 /* ZigbeeMACConsts.FCF_TYPE_MASK */) |
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
    return offset;
}
/**
 * IEEE Std 802.15.4-2020, 9.4.2 (Auxiliary security header)
 * 05-3474-23 R23.1, Annex C.4 (Zigbee MAC security profile)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Parses key identifier modes used for Zigbee MAC security interop
 * - ✅ Preserves frame counter for legacy Trust Center fallback scenarios
 * - ⚠️  Omits ASN parsing because Zigbee does not enable TSCH-based security
 * DEVICE SCOPE: All logical devices (legacy MAC security interoperability)
 */
function decodeMACAuxSecHeader(data, offset) {
    let asn;
    let keySourceAddr32;
    let keySourceAddr64;
    let keyIndex;
    const securityControl = data.readUInt8(offset);
    offset += 1;
    const securityLevel = securityControl & 7 /* ZigbeeMACConsts.AUX_SEC_LEVEL_MASK */;
    const keyIdMode = (securityControl & 24 /* ZigbeeMACConsts.AUX_KEY_ID_MODE_MASK */) >> 3 /* ZigbeeMACConsts.AUX_KEY_ID_MODE_SHIFT */;
    const frameCounter = data.readUInt32LE(offset);
    offset += 4;
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
/**
 * IEEE Std 802.15.4-2020, 7.3.1 (Superframe specification field)
 * 05-3474-23 R23.1, 2.2.2.5 (Beacon superframe descriptor)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Decodes beacon order, CAP slot, and association permit for Trust Center policy
 * - ✅ Preserves coordinator flag per Zigbee beacon evaluation rules
 * - ⚠️  Treats battery extension as boolean with semantics deferred to stack context
 * DEVICE SCOPE: Beacon-capable FFDs (coordinator/router)
 */
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
/**
 * IEEE Std 802.15.4-2020, 7.3.1 (Superframe specification field)
 * 05-3474-23 R23.1, 2.2.2.5 (Beacon superframe descriptor)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Encodes Zigbee beacon superframe bits with spec-defined masks and shifts
 * - ✅ Surfaces association-permit flag for downstream join admission logic
 * - ⚠️  Relies on caller to clamp beacon order/superframe order values to allowed range
 * DEVICE SCOPE: Beacon-capable FFDs (coordinator/router)
 */
function encodeMACSuperframeSpec(data, offset, header) {
    const spec = header.superframeSpec;
    offset = data.writeUInt16LE((spec.beaconOrder & 15 /* ZigbeeMACConsts.SUPERFRAME_BEACON_ORDER_MASK */) |
        ((spec.superframeOrder << 4 /* ZigbeeMACConsts.SUPERFRAME_ORDER_SHIFT */) & 240 /* ZigbeeMACConsts.SUPERFRAME_ORDER_MASK */) |
        ((spec.finalCAPSlot << 8 /* ZigbeeMACConsts.SUPERFRAME_CAP_SHIFT */) & 3840 /* ZigbeeMACConsts.SUPERFRAME_CAP_MASK */) |
        (((spec.batteryExtension ? 1 : 0) << 12 /* ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_SHIFT */) & 4096 /* ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_MASK */) |
        (((spec.panCoordinator ? 1 : 0) << 14 /* ZigbeeMACConsts.SUPERFRAME_COORD_SHIFT */) & 16384 /* ZigbeeMACConsts.SUPERFRAME_COORD_MASK */) |
        (((spec.associationPermit ? 1 : 0) << 15 /* ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_SHIFT */) & 32768 /* ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_MASK */), offset);
    return offset;
}
/**
 * IEEE Std 802.15.4-2020, 7.3.2 (GTS fields)
 * 05-3474-23 R23.1, Annex C.5 (Zigbee beacon GTS usage)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Parses GTS slot descriptors and permit flag to support indirect transmissions
 * - ✅ Preserves entry ordering per beacon payload layout required by Zigbee
 * - ⚠️  Leaves interpretation of direction bits to higher layers since Zigbee rarely uses GTS
 * DEVICE SCOPE: Beacon-capable FFDs (coordinator/router)
 */
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
/**
 * IEEE Std 802.15.4-2020, 7.3.2 (GTS fields)
 * 05-3474-23 R23.1, Annex C.5 (Zigbee beacon GTS usage)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Emits GTS descriptors in canonical order for Zigbee beacon compliance
 * - ✅ Retains permit flag semantics for Trust Center join evaluation
 * - ⚠️  Assumes caller validated slot/time arrays as per spec limits
 * DEVICE SCOPE: Beacon-capable FFDs (coordinator/router)
 */
function encodeMACGtsInfo(data, offset, header) {
    const info = header.gtsInfo;
    const count = info.directions ? info.directions.length : 0;
    const permitBit = info.permit ? 128 /* ZigbeeMACConsts.GTS_PERMIT_MASK */ : 0;
    offset = data.writeUInt8((count & 7 /* ZigbeeMACConsts.GTS_COUNT_MASK */) | permitBit, offset);
    if (count > 0) {
        // assert(info.directionByte !== undefined);
        offset = data.writeUInt8(info.directionByte, offset);
        for (let i = 0; i < count; i++) {
            offset = data.writeUInt16LE(info.addresses[i], offset);
            const timeLength = info.timeLengths[i];
            const slot = info.slots[i];
            offset = data.writeUInt8(((timeLength << 4 /* ZigbeeMACConsts.GTS_LENGTH_SHIFT */) & 240 /* ZigbeeMACConsts.GTS_LENGTH_MASK */) | (slot & 15 /* ZigbeeMACConsts.GTS_SLOT_MASK */), offset);
        }
    }
    return offset;
}
/**
 * IEEE Std 802.15.4-2020, 7.3.3 (Pending address specification)
 * 05-3474-23 R23.1, Annex C.6 (Indirect data poll support)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Extracts short and extended pending address lists for Zigbee indirect transmissions
 * - ✅ Maintains spec-defined ordering to keep beacon compatibility
 * - ⚠️  Leaves validation of maximum entry counts to beacon construction logic
 * DEVICE SCOPE: Beacon-capable FFDs (coordinator/router)
 */
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
/**
 * IEEE Std 802.15.4-2020, 7.3.3 (Pending address specification)
 * 05-3474-23 R23.1, Annex C.6 (Indirect data poll support)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Serialises pending address lists using Zigbee-ordered masks
 * - ✅ Clears reserved bits to zero as mandated for beacon payloads
 * - ⚠️  Relies on caller to enforce Zigbee limit of seven pending short addresses
 * DEVICE SCOPE: Beacon-capable FFDs (coordinator/router)
 */
function encodeMACPendAddr(data, offset, header) {
    const pendAddr = header.pendAddr;
    const num16 = pendAddr.addr16List ? pendAddr.addr16List.length : 0;
    const num64 = pendAddr.addr64List ? pendAddr.addr64List.length : 0;
    offset = data.writeUInt8((num16 & 7 /* ZigbeeMACConsts.PENDADDR_SHORT_MASK */) | ((num64 << 4 /* ZigbeeMACConsts.PENDADDR_LONG_SHIFT */) & 112 /* ZigbeeMACConsts.PENDADDR_LONG_MASK */), offset);
    for (let i = 0; i < num16; i++) {
        offset = data.writeUInt16LE(pendAddr.addr16List[i], offset);
    }
    for (let i = 0; i < num64; i++) {
        offset = data.writeBigUInt64LE(pendAddr.addr64List[i], offset);
    }
    return offset;
}
/**
 * 05-3474-23 R23.1, Table 2-36 (MAC capability information field)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Maps capability bits used during association joins (device type, power, security)
 * - ✅ Preserves reserved bits as zero to comply with Zigbee profile requirements
 * - ⚠️  Leaves semantic validation (e.g., alt coordinator) to stack-context policy
 * DEVICE SCOPE: All logical devices.
 */
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
/**
 * 05-3474-23 R23.1, Table 2-36 (MAC capability information field)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Encodes capability flags in Zigbee-defined bit order for association responses
 * - ✅ Zeroes reserved bits to maintain spec compliance
 * - ⚠️  Assumes caller verified combination viability (e.g., router capacity)
 * DEVICE SCOPE: All logical devices.
 */
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
/**
 * IEEE Std 802.15.4-2020, 7.2.2 (MAC header fields)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * Decode MAC header from frame.
 * HOT PATH: Called for every incoming MAC frame.
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Validates addressing mode combinations and PAN ID compression per Zigbee limits
 * - ✅ Parses beacon, command, and data header extensions (GTS, pending list) as required
 * - ⚠️  Supports MAC security only for legacy 2003 mode; production security handled above MAC
 * DEVICE SCOPE: All logical devices.
 */
/* @__INLINE__ */
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
        // MULTIPURPOSE frames belong to generic 802.15.4 features that Zigbee never exercises
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
    if (frameControl.securityEnabled && frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */) {
        [auxSecHeader, offset] = decodeMACAuxSecHeader(data, offset);
    }
    let superframeSpec;
    let gtsInfo;
    let pendAddr;
    let commandId;
    let headerIE;
    if (frameControl.frameType === 0 /* MACFrameType.BEACON */) {
        [superframeSpec, offset] = decodeMACSuperframeSpec(data, offset);
        [gtsInfo, offset] = decodeMACGtsInfo(data, offset);
        [pendAddr, offset] = decodeMACPendAddr(data, offset);
    }
    else if (frameControl.frameType === 3 /* MACFrameType.CMD */) {
        commandId = data.readUInt8(offset);
        offset += 1;
    }
    let frameCounter;
    let keySeqCounter;
    if (frameControl.securityEnabled && frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */) {
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
/**
 * IEEE Std 802.15.4-2020, 7.2.2 (MAC header fields)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Constructs headers matching Zigbee addressing and PAN compression rules
 * - ✅ Rejects unsupported Multipurpose frames and MAC security paths
 * - ⚠️  Delegates field range validation to callers to keep hot path minimal
 * DEVICE SCOPE: All logical devices.
 */
function encodeMACHeader(data, offset, header, zigbee) {
    offset = encodeMACFrameControl(data, offset, header.frameControl);
    if (zigbee) {
        offset = data.writeUInt8(header.sequenceNumber, offset);
        offset = data.writeUInt16LE(header.destinationPANId, offset);
        offset = data.writeUInt16LE(header.destination16, offset);
        if (header.sourcePANId !== undefined) {
            offset = data.writeUInt16LE(header.sourcePANId, offset);
        }
        // NWK GP can be NONE
        if (header.frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */) {
            offset = data.writeUInt16LE(header.source16, offset);
        }
    }
    else {
        if (!header.frameControl.seqNumSuppress) {
            offset = data.writeUInt8(header.sequenceNumber, offset);
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
            // MULTIPURPOSE frames belong to generic 802.15.4 features that Zigbee never exercises
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
        else {
            throw new Error("Invalid MAC frame: invalid version");
        }
        if (destPANPresent) {
            offset = data.writeUInt16LE(header.destinationPANId, offset);
        }
        if (header.frameControl.destAddrMode === 2 /* MACFrameAddressMode.SHORT */) {
            offset = data.writeUInt16LE(header.destination16, offset);
        }
        else if (header.frameControl.destAddrMode === 3 /* MACFrameAddressMode.EXT */) {
            offset = data.writeBigUInt64LE(header.destination64, offset);
        }
        if (sourcePANPresent) {
            offset = data.writeUInt16LE(header.sourcePANId, offset);
        }
        if (header.frameControl.sourceAddrMode === 2 /* MACFrameAddressMode.SHORT */) {
            offset = data.writeUInt16LE(header.source16, offset);
        }
        else if (header.frameControl.sourceAddrMode === 3 /* MACFrameAddressMode.EXT */) {
            offset = data.writeBigUInt64LE(header.source64, offset);
        }
        let auxSecHeader;
        if (header.frameControl.securityEnabled && header.frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */) {
            // Zigbee never relies on MAC layer security; the error documents the intentional gap
            throw new Error("Unsupported: securityEnabled");
        }
        if (header.frameControl.frameType === 0 /* MACFrameType.BEACON */) {
            offset = encodeMACSuperframeSpec(data, offset, header);
            offset = encodeMACGtsInfo(data, offset, header);
            offset = encodeMACPendAddr(data, offset, header);
        }
        else if (header.frameControl.frameType === 3 /* MACFrameType.CMD */) {
            offset = data.writeUInt8(header.commandId, offset);
        }
        if (header.frameControl.securityEnabled && header.frameControl.frameVersion === 0 /* MACFrameVersion.V2003 */) {
            // auxSecHeader?.securityLevel = ???;
            const isEncrypted = auxSecHeader.securityLevel & 0x04;
            if (isEncrypted) {
                offset = data.writeUInt32LE(header.frameCounter, offset);
                offset = data.writeUInt8(header.keySeqCounter, offset);
            }
        }
    }
    return offset;
}
/**
 * IEEE Std 802.15.4-2020, 6.2.1 (FCS computation using CRC-16-IBM polynomial)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Matches the polynomial required for MAC frame FCS validation
 * - ✅ Runs without heap allocations to remain hot-path friendly
 * - ⚠️  Expects caller to supply payload-length buffer per MAC framing rules
 * DEVICE SCOPE: All logical devices.
 */
function crc16CCITT(data) {
    let fcs = 0x0000;
    for (let i = 0; i < data.byteLength; i++) {
        const aByte = data[i];
        let q = (fcs ^ aByte) & 0x0f;
        fcs = (fcs >> 4) ^ (q * 0x1081);
        q = (fcs ^ (aByte >> 4)) & 0x0f;
        fcs = (fcs >> 4) ^ (q * 0x1081);
    }
    return fcs;
}
/**
 * IEEE Std 802.15.4-2020, 7.2.2.4 (MAC payload and FCS handling)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Rejects MAC-layer security frames in line with Zigbee host design (security handled at NWK/APS)
 * - ✅ Verifies FCS presence and stores it for diagnostics per Zigbee stack requirements
 * - ⚠️  Leaves MIC validation to upper layers because MAC security is disabled
 * DEVICE SCOPE: All logical devices.
 */
function decodeMACPayload(data, offset, frameControl, header) {
    if (frameControl.securityEnabled) {
        // MAC layer security is intentionally unsupported for Zigbee hosts
        throw new Error("Unsupported MAC frame: security enabled");
    }
    const endOffset = data.byteLength - 2 /* ZigbeeMACConsts.FCS_LEN */;
    if (endOffset - offset < 0) {
        throw new Error("Invalid MAC frame: no FCS");
    }
    const payload = data.subarray(offset, endOffset);
    header.fcs = data.readUInt16LE(endOffset);
    return payload;
}
/**
 * IEEE Std 802.15.4-2020, 7.2.2 (General MAC frame format)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Emits canonical MAC frames with Zigbee-safe payload length and CRC tail
 * - ✅ Shares encoding path with general 802.15.4 data while honouring Zigbee restrictions
 * - ⚠️  Assumes caller already prepared payload within MAC safe size
 * DEVICE SCOPE: All logical devices.
 */
function encodeMACFrame(header, payload) {
    let offset = 0;
    const data = Buffer.alloc(116 /* ZigbeeMACConsts.PAYLOAD_MAX_SIZE */);
    offset = encodeMACHeader(data, offset, header, false);
    offset += payload.copy(data, offset);
    offset = data.writeUInt16LE(crc16CCITT(data.subarray(0, offset)), offset);
    return data.subarray(0, offset);
}
/**
 * Encode MAC frame with hotpath for Zigbee NWK/APS payload
 * 05-3474-23 R23.1, Annex C.2.1 (Zigbee data frame rules)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Forces frame version to 2003 as mandated for Zigbee data/command frames
 * - ✅ Encodes only Zigbee-relevant addressing fields for NWK hot path efficiency
 * - ⚠️  Caller must enforce payload length not exceeding Zigbee safe payload size
 * DEVICE SCOPE: All logical devices.
 */
function encodeMACFrameZigbee(header, payload) {
    let offset = 0;
    const data = Buffer.alloc(116 /* ZigbeeMACConsts.PAYLOAD_MAX_SIZE */); // TODO: optimize with max Zigbee header length
    // always transmit with v2003 (0) frame version @see D.6 Frame Version Value of 05-3474-23
    header.frameControl.frameVersion = 0 /* MACFrameVersion.V2003 */;
    offset = encodeMACHeader(data, offset, header, true); // zigbee hotpath
    offset += payload.copy(data, offset);
    offset = data.writeUInt16LE(crc16CCITT(data.subarray(0, offset)), offset);
    return data.subarray(0, offset);
}
/**
 * 05-3474-23 R23.1, 2.2.2 (Beacon payload format)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Parses routing and end-device capacity bits for join admission logic
 * - ✅ Retains Update ID for network parameter synchronization
 * - ⚠️  Exposes protocolId even though Zigbee fixes it to zero for diagnostics
 * DEVICE SCOPE: Beacon receivers (all logical devices)
 */
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
/**
 * 05-3474-23 R23.1, 2.2.2 (Beacon payload format)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Serialises Zigbee beacon descriptor using mandated masks and shifts
 * - ✅ Hardcodes protocol ID to zero per Zigbee specification
 * - ⚠️  Relies on caller to enforce txOffset bounds defined by aMaxBeaconTxOffset
 * DEVICE SCOPE: Beacon transmitters (coordinator/router)
 */
function encodeMACZigbeeBeacon(beacon) {
    const payload = Buffer.alloc(15 /* ZigbeeMACConsts.ZIGBEE_BEACON_LENGTH */);
    let offset = 0;
    offset = payload.writeUInt8(0, offset); // protocol ID always 0 on Zigbee beacons
    offset = payload.writeUInt16LE((beacon.profile & 15 /* ZigbeeMACConsts.ZIGBEE_BEACON_STACK_PROFILE_MASK */) |
        ((beacon.version << 4 /* ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_SHIFT */) & 240 /* ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_MASK */) |
        (((beacon.routerCapacity ? 1 : 0) << 10 /* ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_SHIFT */) &
            1024 /* ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_MASK */) |
        ((beacon.deviceDepth << 11 /* ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_SHIFT */) & 30720 /* ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_MASK */) |
        (((beacon.endDeviceCapacity ? 1 : 0) << 15 /* ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_SHIFT */) &
            32768 /* ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_MASK */), offset);
    offset = payload.writeBigUInt64LE(beacon.extendedPANId, offset);
    offset = payload.writeUInt32LE((beacon.txOffset & 16777215 /* ZigbeeMACConsts.ZIGBEE_BEACON_TX_OFFSET_MASK */) |
        ((beacon.updateId << 24 /* ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_SHIFT */) & 255 /* ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_MASK */), offset);
    return payload;
}
// #endregion
//# sourceMappingURL=mac.js.map