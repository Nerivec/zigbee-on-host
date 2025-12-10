"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeZigbeeAPSFrameControl = decodeZigbeeAPSFrameControl;
exports.decodeZigbeeAPSHeader = decodeZigbeeAPSHeader;
exports.encodeZigbeeAPSHeader = encodeZigbeeAPSHeader;
exports.decodeZigbeeAPSPayload = decodeZigbeeAPSPayload;
exports.encodeZigbeeAPSFrame = encodeZigbeeAPSFrame;
const zigbee_js_1 = require("./zigbee.js");
/**
 * Decode Zigbee APS frame control field.
 * HOT PATH: Called for every incoming Zigbee APS frame.
 * 05-3474-23 R23.1, Table 2-69 (APS frame control fields)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Extracts frame type, delivery, security, and extended header bits per Zigbee 3.0 profile
 * - ✅ Treats deprecated indirect bit as reserved, matching Zigbee 2007+ behaviour
 * - ⚠️  Defers extended header parsing to caller since fragmentation format varies by frame type
 * DEVICE SCOPE: All logical devices
 */
/* @__INLINE__ */
function decodeZigbeeAPSFrameControl(data, offset) {
    // HOT PATH: Extract APS FCF fields with bitwise operations
    const fcf = data.readUInt8(offset);
    offset += 1;
    return [
        {
            frameType: fcf & 3 /* ZigbeeAPSConsts.FCF_FRAME_TYPE */,
            deliveryMode: (fcf & 12 /* ZigbeeAPSConsts.FCF_DELIVERY_MODE */) >> 2,
            // indirectMode = (fcf & ZigbeeAPSConsts.FCF_INDIRECT_MODE) >> 4,
            ackFormat: Boolean((fcf & 16 /* ZigbeeAPSConsts.FCF_ACK_FORMAT */) >> 4),
            security: Boolean((fcf & 32 /* ZigbeeAPSConsts.FCF_SECURITY */) >> 5),
            ackRequest: Boolean((fcf & 64 /* ZigbeeAPSConsts.FCF_ACK_REQ */) >> 6),
            extendedHeader: Boolean((fcf & 128 /* ZigbeeAPSConsts.FCF_EXT_HEADER */) >> 7),
        },
        offset,
    ];
}
/**
 * 05-3474-23 R23.1, Table 2-69 (APS frame control fields)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Encodes frame control bits according to Zigbee APS data/command frame requirements
 * - ✅ Leaves deprecated indirect addressing bit cleared per Zigbee 2007+ specification
 * - ⚠️  Assumes caller validated delivery mode compatibility with frame type
 * DEVICE SCOPE: All logical devices
 */
function encodeZigbeeAPSFrameControl(data, offset, fcf) {
    offset = data.writeUInt8((fcf.frameType & 3 /* ZigbeeAPSConsts.FCF_FRAME_TYPE */) |
        ((fcf.deliveryMode << 2) & 12 /* ZigbeeAPSConsts.FCF_DELIVERY_MODE */) |
        // ((fcf.indirectMode << 4) & ZigbeeAPSConsts.FCF_INDIRECT_MODE) |
        (((fcf.ackFormat ? 1 : 0) << 4) & 16 /* ZigbeeAPSConsts.FCF_ACK_FORMAT */) |
        (((fcf.security ? 1 : 0) << 5) & 32 /* ZigbeeAPSConsts.FCF_SECURITY */) |
        (((fcf.ackRequest ? 1 : 0) << 6) & 64 /* ZigbeeAPSConsts.FCF_ACK_REQ */) |
        (((fcf.extendedHeader ? 1 : 0) << 7) & 128 /* ZigbeeAPSConsts.FCF_EXT_HEADER */), offset);
    return offset;
}
/**
 * 05-3474-23 R23.1, Tables 2-69/2-70 (APS data and command frame formats)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Applies delivery-mode driven presence rules for endpoints, groups, cluster/profile IDs
 * - ✅ Handles extended header fragmentation bits as defined for Zigbee fragmentation sublayer
 * - ⚠️  Assumes caller already validated NWK header to supply addressing context
 * DEVICE SCOPE: All logical devices
 */
function decodeZigbeeAPSHeader(data, offset, frameControl) {
    let hasEndpointAddressing = true;
    let destPresent = false;
    let sourcePresent = false;
    let destEndpoint;
    let group;
    let clusterId;
    let profileId;
    let sourceEndpoint;
    switch (frameControl.frameType) {
        case 0 /* ZigbeeAPSFrameType.DATA */: {
            break;
        }
        case 2 /* ZigbeeAPSFrameType.ACK */: {
            if (frameControl.ackFormat) {
                hasEndpointAddressing = false;
            }
            break;
        }
        case 3 /* ZigbeeAPSFrameType.INTERPAN */: {
            destPresent = false;
            sourcePresent = false;
            break;
        }
        case 1 /* ZigbeeAPSFrameType.CMD */: {
            hasEndpointAddressing = false;
            break;
        }
    }
    if (hasEndpointAddressing) {
        if (frameControl.frameType !== 3 /* ZigbeeAPSFrameType.INTERPAN */) {
            if (frameControl.deliveryMode === 0 /* ZigbeeAPSDeliveryMode.UNICAST */ || frameControl.deliveryMode === 2 /* ZigbeeAPSDeliveryMode.BCAST */) {
                destPresent = true;
                sourcePresent = true;
            }
            else if (frameControl.deliveryMode === 3 /* ZigbeeAPSDeliveryMode.GROUP */) {
                destPresent = false;
                sourcePresent = true;
            }
            else {
                throw new Error(`Invalid APS delivery mode ${frameControl.deliveryMode}`);
            }
            if (destPresent) {
                destEndpoint = data.readUInt8(offset);
                offset += 1;
            }
        }
        if (frameControl.deliveryMode === 3 /* ZigbeeAPSDeliveryMode.GROUP */) {
            group = data.readUInt16LE(offset);
            offset += 2;
        }
        clusterId = data.readUInt16LE(offset);
        offset += 2;
        profileId = data.readUInt16LE(offset);
        offset += 2;
        if (sourcePresent) {
            sourceEndpoint = data.readUInt8(offset);
            offset += 1;
        }
    }
    let counter;
    if (frameControl.frameType !== 3 /* ZigbeeAPSFrameType.INTERPAN */) {
        counter = data.readUInt8(offset);
        offset += 1;
    }
    let fragmentation;
    let fragBlockNumber;
    let fragACKBitfield;
    if (frameControl.extendedHeader) {
        const fcf = data.readUInt8(offset);
        offset += 1;
        fragmentation = fcf & 3 /* ZigbeeAPSConsts.EXT_FCF_FRAGMENT */;
        if (fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */) {
            fragBlockNumber = data.readUInt8(offset);
            offset += 1;
        }
        if (fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */ && frameControl.frameType === 2 /* ZigbeeAPSFrameType.ACK */) {
            fragACKBitfield = data.readUInt8(offset);
            offset += 1;
        }
    }
    return [
        {
            frameControl,
            destEndpoint: destEndpoint,
            group,
            clusterId,
            profileId,
            sourceEndpoint: sourceEndpoint,
            counter,
            fragmentation,
            fragBlockNumber,
            fragACKBitfield,
            securityHeader: undefined, // set later, or not
        },
        offset,
    ];
}
/**
 * 05-3474-23 R23.1, Tables 2-69/2-70 (APS data and command frame formats)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Serialises endpoint/group fields following delivery-mode matrix mandated by spec
 * - ✅ Emits fragmentation header only when requested, matching Zigbee fragmentation rules
 * - ⚠️  Relies on caller to provide consistent fragmentation settings (block numbers, ACK bitmap)
 * DEVICE SCOPE: All logical devices
 */
function encodeZigbeeAPSHeader(data, offset, header) {
    offset = encodeZigbeeAPSFrameControl(data, offset, header.frameControl);
    let hasEndpointAddressing = true;
    let destPresent = false;
    let sourcePresent = false;
    switch (header.frameControl.frameType) {
        case 0 /* ZigbeeAPSFrameType.DATA */: {
            break;
        }
        case 2 /* ZigbeeAPSFrameType.ACK */: {
            if (header.frameControl.ackFormat) {
                hasEndpointAddressing = false;
            }
            break;
        }
        case 3 /* ZigbeeAPSFrameType.INTERPAN */: {
            destPresent = false;
            sourcePresent = false;
            break;
        }
        case 1 /* ZigbeeAPSFrameType.CMD */: {
            hasEndpointAddressing = false;
            break;
        }
    }
    if (hasEndpointAddressing) {
        if (header.frameControl.frameType !== 3 /* ZigbeeAPSFrameType.INTERPAN */) {
            if (header.frameControl.deliveryMode === 0 /* ZigbeeAPSDeliveryMode.UNICAST */ ||
                header.frameControl.deliveryMode === 2 /* ZigbeeAPSDeliveryMode.BCAST */) {
                destPresent = true;
                sourcePresent = true;
            }
            else if (header.frameControl.deliveryMode === 3 /* ZigbeeAPSDeliveryMode.GROUP */) {
                destPresent = false;
                sourcePresent = true;
            }
            else {
                throw new Error(`Invalid APS delivery mode ${header.frameControl.deliveryMode}`);
            }
            if (destPresent) {
                offset = data.writeUInt8(header.destEndpoint, offset);
            }
        }
        if (header.frameControl.deliveryMode === 3 /* ZigbeeAPSDeliveryMode.GROUP */) {
            offset = data.writeUInt16LE(header.group, offset);
        }
        offset = data.writeUInt16LE(header.clusterId, offset);
        offset = data.writeUInt16LE(header.profileId, offset);
        if (sourcePresent) {
            offset = data.writeUInt8(header.sourceEndpoint, offset);
        }
    }
    if (header.frameControl.frameType !== 3 /* ZigbeeAPSFrameType.INTERPAN */) {
        offset = data.writeUInt8(header.counter, offset);
    }
    if (header.frameControl.extendedHeader) {
        const fragmentation = header.fragmentation ?? 0 /* ZigbeeAPSFragmentation.NONE */;
        const fcf = fragmentation & 3 /* ZigbeeAPSConsts.EXT_FCF_FRAGMENT */;
        offset = data.writeUInt8(fcf, offset);
        if (fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */) {
            offset = data.writeUInt8(header.fragBlockNumber, offset);
        }
        if (fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */ && header.frameControl.frameType === 2 /* ZigbeeAPSFrameType.ACK */) {
            offset = data.writeUInt8(header.fragACKBitfield, offset);
        }
    }
    return offset;
}
/**
 * 05-3474-23 R23.1, Annex B (APS security processing)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Invokes APS encryption/decryption helpers when security bit is asserted, per spec flow
 * - ✅ Preserves resulting security header for NWK/Trust Center auditing
 * - ⚠️  Leaves key selection policy to caller (default hashed keys vs per-device link keys)
 * DEVICE SCOPE: All logical devices
 *
 * @param data
 * @param offset
 * @param decryptKey If undefined, use default pre-hashed
 * @param nwkSource64
 * @param frameControl
 * @param header
 */
function decodeZigbeeAPSPayload(data, offset, decryptKey, nwkSource64, frameControl, header) {
    if (frameControl.security) {
        const [payload, securityHeader, dOutOffset] = (0, zigbee_js_1.decryptZigbeePayload)(data, offset, decryptKey, nwkSource64);
        offset = dOutOffset;
        header.securityHeader = securityHeader;
        return payload;
    }
    return data.subarray(offset);
}
/**
 * 05-3474-23 R23.1, Table 2-70 (APS data frame format) & Annex B (APS security)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Builds full APS frame, invoking security helper when security flag set
 * - ✅ Copies authentication tag per CCM* requirements when encryption enabled
 * - ⚠️  Expects caller to enforce payload length vs. APS fragmentation strategy
 * DEVICE SCOPE: All logical devices
 *
 * @param header
 * @param payload
 * @param securityHeader
 * @param encryptKey If undefined, and security=true, use default pre-hashed
 */
function encodeZigbeeAPSFrame(header, payload, securityHeader, encryptKey) {
    let offset = 0;
    const data = Buffer.alloc(108 /* ZigbeeAPSConsts.FRAME_MAX_SIZE */);
    offset = encodeZigbeeAPSHeader(data, offset, header);
    if (header.frameControl.security) {
        // the octet string `a` SHALL be the string ApsHeader || Auxiliary-Header and the octet string `m` SHALL be the string Payload
        const [cryptedPayload, authTag, eOutOffset] = (0, zigbee_js_1.encryptZigbeePayload)(data, offset, payload, securityHeader, encryptKey);
        offset = eOutOffset;
        offset += cryptedPayload.copy(data, offset);
        offset += authTag.copy(data, offset);
        return data.subarray(0, offset);
    }
    offset += payload.copy(data, offset);
    // TODO: auth tag?
    //       the octet string `a` SHALL be the string ApsHeader || AuxiliaryHeader || Payload and the octet string `m` SHALL be a string of length zero
    return data.subarray(0, offset);
}
//# sourceMappingURL=zigbee-aps.js.map