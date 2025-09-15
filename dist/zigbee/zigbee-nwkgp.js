"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeZigbeeNWKGPFrameControl = decodeZigbeeNWKGPFrameControl;
exports.decodeZigbeeNWKGPHeader = decodeZigbeeNWKGPHeader;
exports.decodeZigbeeNWKGPPayload = decodeZigbeeNWKGPPayload;
exports.encodeZigbeeNWKGPFrame = encodeZigbeeNWKGPFrame;
const zigbee_js_1 = require("./zigbee.js");
function decodeZigbeeNWKGPFrameControl(data, offset) {
    const fcf = data.readUInt8(offset);
    offset += 1;
    return [
        {
            frameType: fcf & 3 /* ZigbeeNWKGPConsts.FCF_FRAME_TYPE */,
            protocolVersion: (fcf & 60 /* ZigbeeNWKGPConsts.FCF_VERSION */) >> 2,
            autoCommissioning: Boolean((fcf & 64 /* ZigbeeNWKGPConsts.FCF_AUTO_COMMISSIONING */) >> 6),
            nwkFrameControlExtension: Boolean((fcf & 128 /* ZigbeeNWKGPConsts.FCF_CONTROL_EXTENSION */) >> 7),
        },
        offset,
    ];
}
function encodeZigbeeNWKGPFrameControl(data, offset, fcf) {
    data.writeUInt8((fcf.frameType & 3 /* ZigbeeNWKGPConsts.FCF_FRAME_TYPE */) |
        ((fcf.protocolVersion << 2) & 60 /* ZigbeeNWKGPConsts.FCF_VERSION */) |
        (((fcf.autoCommissioning ? 1 : 0) << 6) & 64 /* ZigbeeNWKGPConsts.FCF_AUTO_COMMISSIONING */) |
        (((fcf.nwkFrameControlExtension ? 1 : 0) << 7) & 128 /* ZigbeeNWKGPConsts.FCF_CONTROL_EXTENSION */), offset);
    offset += 1;
    return offset;
}
function decodeZigbeeNWKGPFrameControlExt(data, offset) {
    const fcf = data.readUInt8(offset);
    offset += 1;
    return [
        {
            appId: fcf & 7 /* ZigbeeNWKGPConsts.FCF_EXT_APP_ID */,
            securityLevel: (fcf & 24 /* ZigbeeNWKGPConsts.FCF_EXT_SECURITY_LEVEL */) >> 3,
            securityKey: Boolean((fcf & 32 /* ZigbeeNWKGPConsts.FCF_EXT_SECURITY_KEY */) >> 5),
            rxAfterTx: Boolean((fcf & 64 /* ZigbeeNWKGPConsts.FCF_EXT_RX_AFTER_TX */) >> 6),
            direction: (fcf & 128 /* ZigbeeNWKGPConsts.FCF_EXT_DIRECTION */) >> 7,
        },
        offset,
    ];
}
function encodeZigbeeNWKGPFrameControlExt(data, offset, fcExt) {
    data.writeUInt8((fcExt.appId & 7 /* ZigbeeNWKGPConsts.FCF_EXT_APP_ID */) |
        ((fcExt.securityLevel << 3) & 24 /* ZigbeeNWKGPConsts.FCF_EXT_SECURITY_LEVEL */) |
        (((fcExt.securityKey ? 1 : 0) << 5) & 32 /* ZigbeeNWKGPConsts.FCF_EXT_SECURITY_KEY */) |
        (((fcExt.rxAfterTx ? 1 : 0) << 6) & 64 /* ZigbeeNWKGPConsts.FCF_EXT_RX_AFTER_TX */) |
        ((fcExt.direction << 7) & 128 /* ZigbeeNWKGPConsts.FCF_EXT_DIRECTION */), offset);
    offset += 1;
    return offset;
}
function decodeZigbeeNWKGPHeader(data, offset, frameControl) {
    let frameControlExt;
    if (frameControl.nwkFrameControlExtension) {
        [frameControlExt, offset] = decodeZigbeeNWKGPFrameControlExt(data, offset);
    }
    let sourceId;
    let endpoint;
    let micSize = 0;
    let securityFrameCounter;
    let mic;
    if ((frameControl.frameType === 0 /* ZigbeeNWKGPFrameType.DATA */ && !frameControl.nwkFrameControlExtension) ||
        (frameControl.frameType === 0 /* ZigbeeNWKGPFrameType.DATA */ &&
            frameControl.nwkFrameControlExtension &&
            frameControlExt.appId === 0 /* ZigbeeNWKGPAppId.DEFAULT */) ||
        (frameControl.frameType === 1 /* ZigbeeNWKGPFrameType.MAINTENANCE */ &&
            frameControl.nwkFrameControlExtension &&
            frameControlExt.appId === 0 /* ZigbeeNWKGPAppId.DEFAULT */ &&
            data.readUInt8(offset) !== 243 /* ZigbeeNWKGPCommandId.CHANNEL_CONFIGURATION */)) {
        sourceId = data.readUInt32LE(offset);
        offset += 4;
    }
    if (frameControl.nwkFrameControlExtension && frameControlExt.appId === 2 /* ZigbeeNWKGPAppId.ZGP */) {
        endpoint = data.readUInt8(offset);
        offset += 1;
    }
    if (frameControl.nwkFrameControlExtension &&
        (frameControlExt.appId === 0 /* ZigbeeNWKGPAppId.DEFAULT */ ||
            frameControlExt.appId === 2 /* ZigbeeNWKGPAppId.ZGP */ ||
            frameControlExt.appId === 1 /* ZigbeeNWKGPAppId.LPED */)) {
        if (frameControlExt.securityLevel === 1 /* ZigbeeNWKGPSecurityLevel.ONELSB */ && frameControlExt.appId !== 1 /* ZigbeeNWKGPAppId.LPED */) {
            micSize = 2;
        }
        else if (frameControlExt.securityLevel === 2 /* ZigbeeNWKGPSecurityLevel.FULL */ ||
            frameControlExt.securityLevel === 3 /* ZigbeeNWKGPSecurityLevel.FULLENCR */) {
            micSize = 4;
            securityFrameCounter = data.readUInt32LE(offset);
            offset += 4;
        }
    }
    //-- here `offset` is "start of payload"
    const payloadLength = data.byteLength - offset - micSize;
    if (payloadLength <= 0) {
        throw new Error("Zigbee NWK GP frame without payload");
    }
    if (micSize === 2) {
        mic = data.readUInt16LE(offset + payloadLength); // at end
    }
    else if (micSize === 4) {
        mic = data.readUInt32LE(offset + payloadLength); // at end
    }
    return [
        {
            frameControl,
            frameControlExt,
            sourceId,
            endpoint,
            micSize,
            securityFrameCounter,
            payloadLength,
            mic,
        },
        offset,
    ];
}
function encodeZigbeeNWKGPHeader(data, offset, header) {
    offset = encodeZigbeeNWKGPFrameControl(data, offset, header.frameControl);
    if (header.frameControl.nwkFrameControlExtension) {
        offset = encodeZigbeeNWKGPFrameControlExt(data, offset, header.frameControlExt);
    }
    if ((header.frameControl.frameType === 0 /* ZigbeeNWKGPFrameType.DATA */ && !header.frameControl.nwkFrameControlExtension) ||
        (header.frameControl.frameType === 0 /* ZigbeeNWKGPFrameType.DATA */ &&
            header.frameControl.nwkFrameControlExtension &&
            header.frameControlExt.appId === 0 /* ZigbeeNWKGPAppId.DEFAULT */) ||
        (header.frameControl.frameType === 1 /* ZigbeeNWKGPFrameType.MAINTENANCE */ &&
            header.frameControl.nwkFrameControlExtension &&
            header.frameControlExt.appId === 0 /* ZigbeeNWKGPAppId.DEFAULT */ &&
            data.readUInt8(offset) !== 243 /* ZigbeeNWKGPCommandId.CHANNEL_CONFIGURATION */)) {
        data.writeUInt32LE(header.sourceId, offset);
        offset += 4;
    }
    if (header.frameControl.nwkFrameControlExtension && header.frameControlExt.appId === 2 /* ZigbeeNWKGPAppId.ZGP */) {
        data.writeUInt8(header.endpoint, offset);
        offset += 1;
    }
    if (header.frameControl.nwkFrameControlExtension &&
        (header.frameControlExt.appId === 0 /* ZigbeeNWKGPAppId.DEFAULT */ ||
            header.frameControlExt.appId === 2 /* ZigbeeNWKGPAppId.ZGP */ ||
            header.frameControlExt.appId === 1 /* ZigbeeNWKGPAppId.LPED */)) {
        if (header.frameControlExt.securityLevel === 2 /* ZigbeeNWKGPSecurityLevel.FULL */ ||
            header.frameControlExt.securityLevel === 3 /* ZigbeeNWKGPSecurityLevel.FULLENCR */) {
            data.writeUInt32LE(header.securityFrameCounter, offset);
            offset += 4;
        }
    }
    //-- here `offset` is "start of payload"
    return offset;
}
function makeGPNonce(header, macSource64) {
    const nonce = Buffer.alloc(13 /* ZigbeeConsts.SEC_NONCE_LEN */);
    let offset = 0;
    if (header.frameControlExt.appId === 0 /* ZigbeeNWKGPAppId.DEFAULT */) {
        if (header.frameControlExt.direction === 0 /* ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD */) {
            nonce.writeUInt32LE(header.sourceId, offset);
            offset += 4;
        }
        nonce.writeUInt32LE(header.sourceId, offset);
        offset += 4;
    }
    else if (header.frameControlExt.appId === 2 /* ZigbeeNWKGPAppId.ZGP */) {
        nonce.writeBigUInt64LE(macSource64, offset);
        offset += 8;
    }
    nonce.writeUInt32LE(header.securityFrameCounter, offset);
    offset += 4;
    if (header.frameControlExt.appId === 2 /* ZigbeeNWKGPAppId.ZGP */ && header.frameControlExt.direction === 0 /* ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD */) {
        // Security level = 0b101, Key Identifier = 0x00, Extended nonce = 0b0, Reserved = 0b00
        nonce.writeUInt8(0xc5, offset);
        offset += 1;
    }
    else {
        // Security level = 0b101, Key Identifier = 0x00, Extended nonce = 0b0, Reserved = 0b11
        nonce.writeUInt8(0x05, offset);
        offset += 1;
    }
    return nonce;
}
function decodeZigbeeNWKGPPayload(data, offset, decryptKey, macSource64, _frameControl, header) {
    let authTag;
    let decryptedPayload;
    if (header.frameControlExt?.securityLevel === 3 /* ZigbeeNWKGPSecurityLevel.FULLENCR */) {
        const nonce = makeGPNonce(header, macSource64);
        [authTag, decryptedPayload] = (0, zigbee_js_1.aes128CcmStar)(header.micSize, decryptKey, nonce, data.subarray(offset));
        const computedAuthTag = (0, zigbee_js_1.computeAuthTag)(data.subarray(0, offset), header.micSize, decryptKey, nonce, decryptedPayload);
        if (!computedAuthTag.equals(authTag)) {
            throw new Error("Auth tag mismatch while decrypting Zigbee NWK GP payload with FULLENCR security level");
        }
    }
    else if (header.frameControlExt?.securityLevel === 2 /* ZigbeeNWKGPSecurityLevel.FULL */) {
        // TODO: Works against spec test vectors but not actual sniffed frame...
        // const nonce = makeGPNonce(header, macSource64);
        // [authTag] = aes128CcmStar(header.micSize, decryptKey, nonce, data.subarray(offset));
        // const computedAuthTag = computeAuthTag(data.subarray(0, offset + header.payloadLength), header.micSize!, decryptKey, nonce, Buffer.alloc(0));
        // if (!computedAuthTag.equals(authTag)) {
        //     throw new Error("Auth tag mismatch while decrypting Zigbee NWK GP payload with FULL security level");
        // }
        decryptedPayload = data.subarray(offset, offset + header.payloadLength); // no MIC
    }
    else {
        decryptedPayload = data.subarray(offset, offset + header.payloadLength); // no MIC
        // TODO mic/authTag?
    }
    if (!decryptedPayload) {
        throw new Error("Unable to decrypt Zigbee NWK GP payload");
    }
    return decryptedPayload;
}
function encodeZigbeeNWKGPFrame(header, payload, decryptKey, macSource64) {
    let offset = 0;
    const data = Buffer.alloc(116 /* ZigbeeNWKGPConsts.FRAME_MAX_SIZE */);
    offset = encodeZigbeeNWKGPHeader(data, offset, header);
    if (header.frameControlExt?.securityLevel === 3 /* ZigbeeNWKGPSecurityLevel.FULLENCR */) {
        const nonce = makeGPNonce(header, macSource64);
        const decryptedData = Buffer.alloc(payload.byteLength + header.micSize); // payload + auth tag
        decryptedData.set(payload, 0);
        const computedAuthTag = (0, zigbee_js_1.computeAuthTag)(data.subarray(0, offset), header.micSize, decryptKey, nonce, payload);
        decryptedData.set(computedAuthTag, payload.byteLength);
        const [authTag, encryptedPayload] = (0, zigbee_js_1.aes128CcmStar)(header.micSize, decryptKey, nonce, decryptedData);
        data.set(encryptedPayload, offset);
        offset += encryptedPayload.byteLength;
        data.set(authTag, offset); // at end
        offset += header.micSize;
    }
    else if (header.frameControlExt?.securityLevel === 2 /* ZigbeeNWKGPSecurityLevel.FULL */) {
        const nonce = makeGPNonce(header, macSource64);
        const decryptedData = Buffer.alloc(payload.byteLength + header.micSize); // payload + auth tag
        decryptedData.set(payload, 0);
        data.set(payload, offset);
        offset += payload.byteLength;
        const computedAuthTag = (0, zigbee_js_1.computeAuthTag)(data.subarray(0, offset), header.micSize, decryptKey, nonce, Buffer.alloc(0));
        decryptedData.set(computedAuthTag, payload.byteLength);
        const [authTag] = (0, zigbee_js_1.aes128CcmStar)(header.micSize, decryptKey, nonce, decryptedData);
        data.set(authTag, offset); // at end
        offset += header.micSize;
    }
    else {
        data.set(payload, offset);
        offset += payload.byteLength;
    }
    return data.subarray(0, offset);
}
//# sourceMappingURL=zigbee-nwkgp.js.map