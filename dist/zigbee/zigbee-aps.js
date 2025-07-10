"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeZigbeeAPSFrameControl = decodeZigbeeAPSFrameControl;
exports.decodeZigbeeAPSHeader = decodeZigbeeAPSHeader;
exports.encodeZigbeeAPSHeader = encodeZigbeeAPSHeader;
exports.decodeZigbeeAPSPayload = decodeZigbeeAPSPayload;
exports.encodeZigbeeAPSFrame = encodeZigbeeAPSFrame;
const zigbee_js_1 = require("./zigbee.js");
function decodeZigbeeAPSFrameControl(data, offset) {
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
function encodeZigbeeAPSFrameControl(data, offset, fcf) {
    data.writeUInt8((fcf.frameType & 3 /* ZigbeeAPSConsts.FCF_FRAME_TYPE */) |
        ((fcf.deliveryMode << 2) & 12 /* ZigbeeAPSConsts.FCF_DELIVERY_MODE */) |
        // ((fcf.indirectMode << 4) & ZigbeeAPSConsts.FCF_INDIRECT_MODE) |
        (((fcf.ackFormat ? 1 : 0) << 4) & 16 /* ZigbeeAPSConsts.FCF_ACK_FORMAT */) |
        (((fcf.security ? 1 : 0) << 5) & 32 /* ZigbeeAPSConsts.FCF_SECURITY */) |
        (((fcf.ackRequest ? 1 : 0) << 6) & 64 /* ZigbeeAPSConsts.FCF_ACK_REQ */) |
        (((fcf.extendedHeader ? 1 : 0) << 7) & 128 /* ZigbeeAPSConsts.FCF_EXT_HEADER */), offset);
    offset += 1;
    return offset;
}
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
    if (fragmentation !== undefined && fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */) {
        // TODO
        throw new Error("APS fragmentation not supported");
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
                data.writeUInt8(header.destEndpoint, offset);
                offset += 1;
            }
        }
        if (header.frameControl.deliveryMode === 3 /* ZigbeeAPSDeliveryMode.GROUP */) {
            data.writeUInt16LE(header.group, offset);
            offset += 2;
        }
        data.writeUInt16LE(header.clusterId, offset);
        offset += 2;
        data.writeUInt16LE(header.profileId, offset);
        offset += 2;
        if (sourcePresent) {
            data.writeUInt8(header.sourceEndpoint, offset);
            offset += 1;
        }
    }
    if (header.frameControl.frameType !== 3 /* ZigbeeAPSFrameType.INTERPAN */) {
        data.writeUInt8(header.counter, offset);
        offset += 1;
    }
    if (header.frameControl.extendedHeader) {
        const fcf = header.fragmentation & 3 /* ZigbeeAPSConsts.EXT_FCF_FRAGMENT */;
        data.writeUInt8(fcf, offset);
        offset += 1;
        if (header.fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */) {
            data.writeUInt8(header.fragBlockNumber, offset);
            offset += 1;
        }
        if (header.fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */ && header.frameControl.frameType === 2 /* ZigbeeAPSFrameType.ACK */) {
            data.writeUInt8(header.fragACKBitfield, offset);
            offset += 1;
        }
    }
    return offset;
}
/**
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
        data.set(cryptedPayload, offset);
        offset += cryptedPayload.byteLength;
        data.set(authTag, offset);
        offset += authTag.byteLength;
        return data.subarray(0, offset);
    }
    data.set(payload, offset);
    offset += payload.byteLength;
    // TODO: auth tag?
    //       the octet string `a` SHALL be the string ApsHeader || AuxiliaryHeader || Payload and the octet string `m` SHALL be a string of length zero
    return data.subarray(0, offset);
}
//# sourceMappingURL=zigbee-aps.js.map