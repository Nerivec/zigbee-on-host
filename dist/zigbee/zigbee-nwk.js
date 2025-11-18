"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZigbeeNWKStatus = void 0;
exports.decodeZigbeeNWKFrameControl = decodeZigbeeNWKFrameControl;
exports.decodeZigbeeNWKHeader = decodeZigbeeNWKHeader;
exports.decodeZigbeeNWKPayload = decodeZigbeeNWKPayload;
exports.encodeZigbeeNWKFrame = encodeZigbeeNWKFrame;
const zigbee_js_1 = require("./zigbee.js");
/** Network Status Code Definitions. */
var ZigbeeNWKStatus;
(function (ZigbeeNWKStatus) {
    /** @deprecated in R23, should no longer be sent, but still processed (same as @see LINK_FAILURE ) */
    ZigbeeNWKStatus[ZigbeeNWKStatus["LEGACY_NO_ROUTE_AVAILABLE"] = 0] = "LEGACY_NO_ROUTE_AVAILABLE";
    /** @deprecated in R23, should no longer be sent, but still processed (same as @see LINK_FAILURE ) */
    ZigbeeNWKStatus[ZigbeeNWKStatus["LEGACY_LINK_FAILURE"] = 1] = "LEGACY_LINK_FAILURE";
    /** This link code indicates a failure to route across a link. */
    ZigbeeNWKStatus[ZigbeeNWKStatus["LINK_FAILURE"] = 2] = "LINK_FAILURE";
    // LOW_BATTERY = 0x03, // deprecated
    // NO_ROUTING = 0x04, // deprecated
    // NO_INDIRECT = 0x05, // deprecated
    // INDIRECT_EXPIRE = 0x06, // deprecated
    // DEVICE_UNAVAIL = 0x07, // deprecated
    // ADDR_UNAVAIL = 0x08, // deprecated
    /**
     * The failure occurred as a result of a failure in the RF link to the device’s parent.
     * This status is only used locally on a device to indicate loss of communication with the parent.
     */
    ZigbeeNWKStatus[ZigbeeNWKStatus["PARENT_LINK_FAILURE"] = 9] = "PARENT_LINK_FAILURE";
    // VALIDATE_ROUTE = 0x0a, // deprecated
    /** Source routing has failed, probably indicating a link failure in one of the source route’s links. */
    ZigbeeNWKStatus[ZigbeeNWKStatus["SOURCE_ROUTE_FAILURE"] = 11] = "SOURCE_ROUTE_FAILURE";
    /** A route established as a result of a many-to-one route request has failed. */
    ZigbeeNWKStatus[ZigbeeNWKStatus["MANY_TO_ONE_ROUTE_FAILURE"] = 12] = "MANY_TO_ONE_ROUTE_FAILURE";
    /** The address in the destination address field has been determined to be in use by two or more devices. */
    ZigbeeNWKStatus[ZigbeeNWKStatus["ADDRESS_CONFLICT"] = 13] = "ADDRESS_CONFLICT";
    // VERIFY_ADDRESS = 0x0e, // deprecated
    /** The operational network PAN identifier of the device has been updated. */
    ZigbeeNWKStatus[ZigbeeNWKStatus["PANID_UPDATE"] = 15] = "PANID_UPDATE";
    /** The network address of the local device has been updated. */
    ZigbeeNWKStatus[ZigbeeNWKStatus["NETWORK_ADDRESS_UPDATE"] = 16] = "NETWORK_ADDRESS_UPDATE";
    // BAD_FRAME_COUNTER = 0x11, // XXX: not in spec
    // BAD_KEY_SEQNO = 0x12, // XXX: not in spec
    /** The NWK command ID is not known to the device. */
    ZigbeeNWKStatus[ZigbeeNWKStatus["UNKNOWN_COMMAND"] = 19] = "UNKNOWN_COMMAND";
    /** Notification to the local application that a PAN ID Conflict Report has been received by the local Network Manager. */
    ZigbeeNWKStatus[ZigbeeNWKStatus["PANID_CONFLICT_REPORT"] = 20] = "PANID_CONFLICT_REPORT";
    // RESERVED = 0x15-0xff,
})(ZigbeeNWKStatus || (exports.ZigbeeNWKStatus = ZigbeeNWKStatus = {}));
/**
 * Decode Zigbee NWK frame control field.
 * HOT PATH: Called for every incoming Zigbee NWK frame.
 * 05-3474-23 R23.1, Table 3-19 (NWK frame control field)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Extracts protocol version, discover route, source route, and security bits per Zigbee PRO
 * - ✅ Surfaces end-device initiator bit introduced in r21 for parent-loss detection
 * - ⚠️  Leaves multicast control parsing to later stages since Zigbee seldom uses legacy flag
 * DEVICE SCOPE: All logical devices
 */
/* @__INLINE__ */
function decodeZigbeeNWKFrameControl(data, offset) {
    // HOT PATH: Extract NWK FCF fields with bitwise operations
    const fcf = data.readUInt16LE(offset);
    offset += 2;
    return [
        {
            frameType: fcf & 3 /* ZigbeeNWKConsts.FCF_FRAME_TYPE */,
            protocolVersion: (fcf & 60 /* ZigbeeNWKConsts.FCF_VERSION */) >> 2,
            discoverRoute: (fcf & 192 /* ZigbeeNWKConsts.FCF_DISCOVER_ROUTE */) >> 6,
            multicast: Boolean((fcf & 256 /* ZigbeeNWKConsts.FCF_MULTICAST */) >> 8),
            security: Boolean((fcf & 512 /* ZigbeeNWKConsts.FCF_SECURITY */) >> 9),
            sourceRoute: Boolean((fcf & 1024 /* ZigbeeNWKConsts.FCF_SOURCE_ROUTE */) >> 10),
            extendedDestination: Boolean((fcf & 2048 /* ZigbeeNWKConsts.FCF_EXT_DEST */) >> 11),
            extendedSource: Boolean((fcf & 4096 /* ZigbeeNWKConsts.FCF_EXT_SOURCE */) >> 12),
            endDeviceInitiator: Boolean((fcf & 8192 /* ZigbeeNWKConsts.FCF_END_DEVICE_INITIATOR */) >> 13),
        },
        offset,
    ];
}
/**
 * 05-3474-23 R23.1, Table 3-19 (NWK frame control field)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Encodes NWK FCF bits honouring Zigbee PRO versioning and source route flags
 * - ✅ Keeps multicast flag optional but off by default to match Zigbee routing profile
 * - ⚠️  Requires caller to pre-validate discover route bits against frame type
 * DEVICE SCOPE: All logical devices
 */
function encodeZigbeeNWKFrameControl(view, offset, fcf) {
    offset = view.writeUInt16LE((fcf.frameType & 3 /* ZigbeeNWKConsts.FCF_FRAME_TYPE */) |
        ((fcf.protocolVersion << 2) & 60 /* ZigbeeNWKConsts.FCF_VERSION */) |
        ((fcf.discoverRoute << 6) & 192 /* ZigbeeNWKConsts.FCF_DISCOVER_ROUTE */) |
        (((fcf.multicast ? 1 : 0) << 8) & 256 /* ZigbeeNWKConsts.FCF_MULTICAST */) |
        (((fcf.security ? 1 : 0) << 9) & 512 /* ZigbeeNWKConsts.FCF_SECURITY */) |
        (((fcf.sourceRoute ? 1 : 0) << 10) & 1024 /* ZigbeeNWKConsts.FCF_SOURCE_ROUTE */) |
        (((fcf.extendedDestination ? 1 : 0) << 11) & 2048 /* ZigbeeNWKConsts.FCF_EXT_DEST */) |
        (((fcf.extendedSource ? 1 : 0) << 12) & 4096 /* ZigbeeNWKConsts.FCF_EXT_SOURCE */) |
        (((fcf.endDeviceInitiator ? 1 : 0) << 13) & 8192 /* ZigbeeNWKConsts.FCF_END_DEVICE_INITIATOR */), offset);
    return offset;
}
/**
 * 05-3474-23 R23.1, Tables 3-20/3-21 (NWK frame formats)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Applies frame-type specific field presence rules (extended addressing, source routes)
 * - ✅ Tracks radius/sequence to support routing loops and replay protection per spec
 * - ⚠️  Skips multicast control field body since Zigbee host does not emit legacy multicast frames
 * DEVICE SCOPE: All logical devices
 */
function decodeZigbeeNWKHeader(data, offset, frameControl) {
    let destination16;
    let source16;
    let radius;
    let seqNum;
    let destination64;
    let source64;
    let relayIndex;
    let relayAddresses;
    if (frameControl.frameType !== 3 /* ZigbeeNWKFrameType.INTERPAN */) {
        destination16 = data.readUInt16LE(offset);
        offset += 2;
        source16 = data.readUInt16LE(offset);
        offset += 2;
        radius = data.readUInt8(offset);
        offset += 1;
        seqNum = data.readUInt8(offset);
        offset += 1;
        if (frameControl.extendedDestination) {
            destination64 = data.readBigUInt64LE(offset);
            offset += 8;
        }
        if (frameControl.extendedSource) {
            source64 = data.readBigUInt64LE(offset);
            offset += 8;
        }
        if (frameControl.multicast) {
            offset += 1;
        }
        if (frameControl.sourceRoute) {
            const relayCount = data.readUInt8(offset);
            offset += 1;
            relayIndex = data.readUInt8(offset);
            offset += 1;
            relayAddresses = [];
            for (let i = 0; i < relayCount; i++) {
                relayAddresses.push(data.readUInt16LE(offset));
                offset += 2;
            }
        }
    }
    if (offset >= data.byteLength) {
        throw new Error("Invalid NWK frame: no payload");
    }
    return [
        {
            frameControl,
            destination16,
            source16,
            radius,
            seqNum,
            destination64,
            source64,
            relayIndex,
            relayAddresses,
            securityHeader: undefined, // set later, or not
        },
        offset,
    ];
}
/**
 * 05-3474-23 R23.1, Tables 3-20/3-21 (NWK frame formats)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Serialises mandatory radius, sequence, and addressing fields for NWK data/command frames
 * - ✅ Encodes source routing list per Zigbee PRO requirements when enabled
 * - ⚠️  Expects caller to populate relay list indices already bounds-checked
 * DEVICE SCOPE: All logical devices
 */
function encodeZigbeeNWKHeader(data, offset, header) {
    offset = encodeZigbeeNWKFrameControl(data, offset, header.frameControl);
    if (header.frameControl.frameType !== 3 /* ZigbeeNWKFrameType.INTERPAN */) {
        offset = data.writeUInt16LE(header.destination16, offset);
        offset = data.writeUInt16LE(header.source16, offset);
        offset = data.writeUInt8(header.radius, offset);
        offset = data.writeUInt8(header.seqNum, offset);
        if (header.frameControl.extendedDestination) {
            offset = data.writeBigUInt64LE(header.destination64, offset);
        }
        if (header.frameControl.extendedSource) {
            offset = data.writeBigUInt64LE(header.source64, offset);
        }
        if (header.frameControl.sourceRoute) {
            offset = data.writeUInt8(header.relayAddresses.length, offset);
            offset = data.writeUInt8(header.relayIndex, offset);
            for (const relayAddress of header.relayAddresses) {
                offset = data.writeUInt16LE(relayAddress, offset);
            }
        }
    }
    return offset;
}
/**
 *
 * @param data
 * @param offset
 * @param decryptKey If undefined, use default pre-hashed
 * @param macSource64
 * @param frameControl
 * @param header
 */
/**
 * 05-3474-23 R23.1, Annex A (NWK security)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Invokes CCM* decrypt when security bit set, storing auxiliary header for Trust Center use
 * - ✅ Supports fallback to default hashed NWK keys when dedicated key not supplied
 * - ⚠️  Defers key selection policy (global vs. unique) to higher stack layers
 * DEVICE SCOPE: All logical devices
 */
function decodeZigbeeNWKPayload(data, offset, decryptKey, macSource64, frameControl, header) {
    if (frameControl.security) {
        const [payload, securityHeader, dOutOffset] = (0, zigbee_js_1.decryptZigbeePayload)(data, offset, decryptKey, macSource64);
        offset = dOutOffset;
        header.securityHeader = securityHeader;
        return payload;
    }
    return data.subarray(offset);
}
/**
 * @param header
 * @param payload
 * @param securityHeader
 * @param encryptKey If undefined, and security=true, use default pre-hashed
 */
/**
 * 05-3474-23 R23.1, Table 3-20 (NWK data frame format) & Annex A (NWK security)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Constructs NWK frame then encrypts/authenticates payload per Zigbee security flag
 * - ✅ Copies authentication tag trailing bytes as mandated by CCM*
 * - ⚠️  Caller must ensure payload length respects NWK/APS combined MTU when security enabled
 * DEVICE SCOPE: All logical devices
 */
function encodeZigbeeNWKFrame(header, payload, securityHeader, encryptKey) {
    let offset = 0;
    const data = Buffer.alloc(116 /* ZigbeeNWKConsts.FRAME_MAX_SIZE */);
    offset = encodeZigbeeNWKHeader(data, offset, header);
    if (header.frameControl.security) {
        const [cryptedPayload, authTag, eOutOffset] = (0, zigbee_js_1.encryptZigbeePayload)(data, offset, payload, securityHeader, encryptKey);
        offset = eOutOffset;
        offset += cryptedPayload.copy(data, offset);
        offset += authTag.copy(data, offset);
        return data.subarray(0, offset);
    }
    offset += payload.copy(data, offset);
    return data.subarray(0, offset);
}
//# sourceMappingURL=zigbee-nwk.js.map