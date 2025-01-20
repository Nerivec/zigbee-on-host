import { ZigbeeConsts, aes128CcmStar } from "./zigbee.js";

/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export const enum ZigbeeNWKGPConsts {
    // TODO: get actual values, these are just copied from NWK
    FRAME_MAX_SIZE = 116,
    /** no security */
    HEADER_MIN_SIZE = 8,
    HEADER_MAX_SIZE = 30,
    PAYLOAD_MIN_SIZE = 86,
    PAYLOAD_MAX_SIZE = 108,

    //---- ZigBee NWK GP FCF fields
    FCF_AUTO_COMMISSIONING = 0x40,
    FCF_CONTROL_EXTENSION = 0x80,
    FCF_FRAME_TYPE = 0x03,
    FCF_VERSION = 0x3c,

    //---- Extended NWK Frame Control field
    FCF_EXT_APP_ID = 0x07, // 0 - 2 b.
    FCF_EXT_SECURITY_LEVEL = 0x18, // 3 - 4 b.
    FCF_EXT_SECURITY_KEY = 0x20, // 5 b.
    FCF_EXT_RX_AFTER_TX = 0x40, // 6 b.
    FCF_EXT_DIRECTION = 0x80, // 7 b.
}

/** ZigBee NWK GP FCF frame types. */
export const enum ZigbeeNWKGPFrameType {
    DATA = 0x00,
    MAINTENANCE = 0x01,
}

/** Definitions for application IDs. */
export const enum ZigbeeNWKGPAppId {
    DEFAULT = 0x00,
    LPED = 0x01,
    ZGP = 0x02,
}

/** Definitions for GP directions. */
export const enum ZigbeeNWKGPDirection {
    // DIRECTION_DEFAULT = 0x00,
    DIRECTION_FROM_ZGPD = 0x00,
    DIRECTION_FROM_ZGPP = 0x01,
}

/** Security level values. */
export const enum ZigbeeNWKGPSecurityLevel {
    NO = 0x00,
    ONELSB = 0x01,
    FULL = 0x02,
    FULLENCR = 0x03,
}

/** GP Security key types. */
export const enum ZigbeeNWKGPSecurityKeyType {
    NO_KEY = 0x00,
    ZB_NWK_KEY = 0x01,
    GPD_GROUP_KEY = 0x02,
    NWK_KEY_DERIVED_GPD_KEY_GROUP_KEY = 0x03,
    PRECONFIGURED_INDIVIDUAL_GPD_KEY = 0x04,
    DERIVED_INDIVIDUAL_GPD_KEY = 0x07,
}

export const enum ZigbeeNWKGPCommandId {
    IDENTIFY = 0x00,
    RECALL_SCENE0 = 0x10,
    RECALL_SCENE1 = 0x11,
    RECALL_SCENE2 = 0x12,
    RECALL_SCENE3 = 0x13,
    RECALL_SCENE4 = 0x14,
    RECALL_SCENE5 = 0x15,
    RECALL_SCENE6 = 0x16,
    RECALL_SCENE7 = 0x17,
    STORE_SCENE0 = 0x18,
    STORE_SCENE1 = 0x19,
    STORE_SCENE2 = 0x1a,
    STORE_SCENE3 = 0x1b,
    STORE_SCENE4 = 0x1c,
    STORE_SCENE5 = 0x1d,
    STORE_SCENE6 = 0x1e,
    STORE_SCENE7 = 0x1f,
    OFF = 0x20,
    ON = 0x21,
    TOGGLE = 0x22,
    RELEASE = 0x23,
    MOVE_UP = 0x30,
    MOVE_DOWN = 0x31,
    STEP_UP = 0x32,
    STEP_DOWN = 0x33,
    LEVEL_CONTROL_STOP = 0x34,
    MOVE_UP_WITH_ON_OFF = 0x35,
    MOVE_DOWN_WITH_ON_OFF = 0x36,
    STEP_UP_WITH_ON_OFF = 0x37,
    STEP_DOWN_WITH_ON_OFF = 0x38,
    MOVE_HUE_STOP = 0x40,
    MOVE_HUE_UP = 0x41,
    MOVE_HUE_DOWN = 0x42,
    STEP_HUE_UP = 0x43,
    STEP_HUW_DOWN = 0x44,
    MOVE_SATURATION_STOP = 0x45,
    MOVE_SATURATION_UP = 0x46,
    MOVE_SATURATION_DOWN = 0x47,
    STEP_SATURATION_UP = 0x48,
    STEP_SATURATION_DOWN = 0x49,
    MOVE_COLOR = 0x4a,
    STEP_COLOR = 0x4b,
    LOCK_DOOR = 0x50,
    UNLOCK_DOOR = 0x51,
    PRESS11 = 0x60,
    RELEASE11 = 0x61,
    PRESS12 = 0x62,
    RELEASE12 = 0x63,
    PRESS22 = 0x64,
    RELEASE22 = 0x65,
    SHORT_PRESS11 = 0x66,
    SHORT_PRESS12 = 0x67,
    SHORT_PRESS22 = 0x68,
    ATTRIBUTE_REPORTING = 0xa0,
    MANUFACTURE_SPECIFIC_ATTR_REPORTING = 0xa1,
    MULTI_CLUSTER_REPORTING = 0xa2,
    MANUFACTURER_SPECIFIC_MCLUSTER_REPORTING = 0xa3,
    REQUEST_ATTRIBUTES = 0xa4,
    READ_ATTRIBUTES_RESPONSE = 0xa5,
    ANY_SENSOR_COMMAND_A0_A3 = 0xaf,
    COMMISSIONING = 0xe0,
    DECOMMISSIONING = 0xe1,
    SUCCESS = 0xe2,
    CHANNEL_REQUEST = 0xe3,
    COMMISSIONING_REPLY = 0xf0,
    WRITE_ATTRIBUTES = 0xf1,
    READ_ATTRIBUTES = 0xf2,
    CHANNEL_CONFIGURATION = 0xf3,
}

/**
 * Frame Control Field: 0x8c, Frame Type: Data, NWK Frame Extension Data
 *     .... ..00 = Frame Type: Data (0x0)
 *     ..00 11.. = Protocol Version: 3
 *     .0.. .... = Auto Commissioning: False
 *     1... .... = NWK Frame Extension: True
 */
export type ZigbeeNWKGPFrameControl = {
    frameType: number;
    protocolVersion: number;
    autoCommissioning: boolean;
    nwkFrameControlExtension: boolean;
};

/**
 * Extended NWK Frame Control Field: 0x30, Application ID: Unknown, Security Level: Full frame counter and full MIC only, Security Key, Direction: From ZGPD
 *     .... .000 = Application ID: Unknown (0x0)
 *     ...1 0... = Security Level: Full frame counter and full MIC only (0x2)
 *     ..1. .... = Security Key: True
 *     .0.. .... = Rx After Tx: False
 *     0... .... = Direction: From ZGPD (0x0)
 */
export type ZigbeeNWKGPFrameControlExt = {
    appId: ZigbeeNWKGPAppId;
    securityLevel: ZigbeeNWKGPSecurityLevel;
    securityKey: boolean;
    rxAfterTx: boolean;
    direction: ZigbeeNWKGPDirection;
};

export type ZigbeeNWKGPHeader = {
    frameControl: ZigbeeNWKGPFrameControl;
    frameControlExt?: ZigbeeNWKGPFrameControlExt;
    sourceId?: number;
    endpoint?: number;
    micSize: 0 | 2 | 4;
    securityFrameCounter?: number;
    payloadLength: number;
    mic?: number;
};

export type ZigbeeNWKGPPayload = Buffer;

export function decodeZigbeeNWKGPFrameControl(data: Buffer, offset: number): [ZigbeeNWKGPFrameControl, offset: number] {
    const fcf = data.readUInt8(offset);
    offset += 1;

    return [
        {
            frameType: fcf & ZigbeeNWKGPConsts.FCF_FRAME_TYPE,
            protocolVersion: (fcf & ZigbeeNWKGPConsts.FCF_VERSION) >> 2,
            autoCommissioning: Boolean((fcf & ZigbeeNWKGPConsts.FCF_AUTO_COMMISSIONING) >> 6),
            nwkFrameControlExtension: Boolean((fcf & ZigbeeNWKGPConsts.FCF_CONTROL_EXTENSION) >> 7),
        },
        offset,
    ];
}

function encodeZigbeeNWKGPFrameControl(data: Buffer, offset: number, fcf: ZigbeeNWKGPFrameControl): number {
    data.writeUInt8(
        (fcf.frameType & ZigbeeNWKGPConsts.FCF_FRAME_TYPE) |
            ((fcf.protocolVersion << 2) & ZigbeeNWKGPConsts.FCF_VERSION) |
            (((fcf.autoCommissioning ? 1 : 0) << 6) & ZigbeeNWKGPConsts.FCF_AUTO_COMMISSIONING) |
            (((fcf.nwkFrameControlExtension ? 1 : 0) << 7) & ZigbeeNWKGPConsts.FCF_CONTROL_EXTENSION),
        offset,
    );
    offset += 1;

    return offset;
}

function decodeZigbeeNWKGPFrameControlExt(data: Buffer, offset: number): [ZigbeeNWKGPFrameControlExt, offset: number] {
    const fcf = data.readUInt8(offset);
    offset += 1;

    return [
        {
            appId: fcf & ZigbeeNWKGPConsts.FCF_EXT_APP_ID,
            securityLevel: (fcf & ZigbeeNWKGPConsts.FCF_EXT_SECURITY_LEVEL) >> 3,
            securityKey: Boolean((fcf & ZigbeeNWKGPConsts.FCF_EXT_SECURITY_KEY) >> 5),
            rxAfterTx: Boolean((fcf & ZigbeeNWKGPConsts.FCF_EXT_RX_AFTER_TX) >> 6),
            direction: (fcf & ZigbeeNWKGPConsts.FCF_EXT_DIRECTION) >> 7,
        },
        offset,
    ];
}

function encodeZigbeeNWKGPFrameControlExt(data: Buffer, offset: number, fcExt: ZigbeeNWKGPFrameControlExt): number {
    data.writeUInt8(
        (fcExt.appId & ZigbeeNWKGPConsts.FCF_EXT_APP_ID) |
            ((fcExt.securityLevel << 3) & ZigbeeNWKGPConsts.FCF_EXT_SECURITY_LEVEL) |
            (((fcExt.securityKey ? 1 : 0) << 5) & ZigbeeNWKGPConsts.FCF_EXT_SECURITY_KEY) |
            (((fcExt.rxAfterTx ? 1 : 0) << 6) & ZigbeeNWKGPConsts.FCF_EXT_RX_AFTER_TX) |
            ((fcExt.direction << 7) & ZigbeeNWKGPConsts.FCF_EXT_DIRECTION),
        offset,
    );
    offset += 1;

    return offset;
}

export function decodeZigbeeNWKGPHeader(data: Buffer, offset: number, frameControl: ZigbeeNWKGPFrameControl): [ZigbeeNWKGPHeader, offset: number] {
    let frameControlExt: ZigbeeNWKGPFrameControlExt | undefined;

    if (frameControl.nwkFrameControlExtension) {
        [frameControlExt, offset] = decodeZigbeeNWKGPFrameControlExt(data, offset);
    }

    let sourceId: number | undefined;
    let endpoint: number | undefined;
    let micSize: ZigbeeNWKGPHeader["micSize"] = 0;
    let securityFrameCounter: number | undefined;
    let mic: number | undefined;

    if (
        (frameControl.frameType === ZigbeeNWKGPFrameType.DATA && !frameControl.nwkFrameControlExtension) ||
        (frameControl.frameType === ZigbeeNWKGPFrameType.DATA &&
            frameControl.nwkFrameControlExtension &&
            frameControlExt!.appId === ZigbeeNWKGPAppId.DEFAULT) ||
        (frameControl.frameType === ZigbeeNWKGPFrameType.MAINTENANCE &&
            frameControl.nwkFrameControlExtension &&
            frameControlExt!.appId === ZigbeeNWKGPAppId.DEFAULT &&
            data.readUInt8(offset) !== ZigbeeNWKGPCommandId.CHANNEL_CONFIGURATION)
    ) {
        sourceId = data.readUInt32LE(offset);
        offset += 4;
    }

    if (frameControl.nwkFrameControlExtension && frameControlExt!.appId === ZigbeeNWKGPAppId.ZGP) {
        endpoint = data.readUInt8(offset);
        offset += 1;
    }

    if (
        frameControl.nwkFrameControlExtension &&
        (frameControlExt!.appId === ZigbeeNWKGPAppId.DEFAULT ||
            frameControlExt!.appId === ZigbeeNWKGPAppId.ZGP ||
            frameControlExt!.appId === ZigbeeNWKGPAppId.LPED)
    ) {
        if (frameControlExt!.securityLevel === ZigbeeNWKGPSecurityLevel.ONELSB && frameControlExt!.appId !== ZigbeeNWKGPAppId.LPED) {
            micSize = 2;
        } else if (
            frameControlExt!.securityLevel === ZigbeeNWKGPSecurityLevel.FULL ||
            frameControlExt!.securityLevel === ZigbeeNWKGPSecurityLevel.FULLENCR
        ) {
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
    } else if (micSize === 4) {
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

function encodeZigbeeNWKGPHeader(data: Buffer, offset: number, header: ZigbeeNWKGPHeader): number {
    offset = encodeZigbeeNWKGPFrameControl(data, offset, header.frameControl);

    if (header.frameControl.nwkFrameControlExtension) {
        offset = encodeZigbeeNWKGPFrameControlExt(data, offset, header.frameControlExt!);
    }

    if (
        (header.frameControl.frameType === ZigbeeNWKGPFrameType.DATA && !header.frameControl.nwkFrameControlExtension) ||
        (header.frameControl.frameType === ZigbeeNWKGPFrameType.DATA &&
            header.frameControl.nwkFrameControlExtension &&
            header.frameControlExt!.appId === ZigbeeNWKGPAppId.DEFAULT) ||
        (header.frameControl.frameType === ZigbeeNWKGPFrameType.MAINTENANCE &&
            header.frameControl.nwkFrameControlExtension &&
            header.frameControlExt!.appId === ZigbeeNWKGPAppId.DEFAULT &&
            data.readUInt8(offset) !== ZigbeeNWKGPCommandId.CHANNEL_CONFIGURATION)
    ) {
        data.writeUInt32LE(header.sourceId!, offset);
        offset += 4;
    }

    if (header.frameControl.nwkFrameControlExtension && header.frameControlExt!.appId === ZigbeeNWKGPAppId.ZGP) {
        data.writeUInt8(header.endpoint!, offset);
        offset += 1;
    }

    if (
        header.frameControl.nwkFrameControlExtension &&
        (header.frameControlExt!.appId === ZigbeeNWKGPAppId.DEFAULT ||
            header.frameControlExt!.appId === ZigbeeNWKGPAppId.ZGP ||
            header.frameControlExt!.appId === ZigbeeNWKGPAppId.LPED)
    ) {
        if (
            header.frameControlExt!.securityLevel === ZigbeeNWKGPSecurityLevel.FULL ||
            header.frameControlExt!.securityLevel === ZigbeeNWKGPSecurityLevel.FULLENCR
        ) {
            data.writeUInt32LE(header.securityFrameCounter!, offset);
            offset += 4;
        }
    }

    //-- here `offset` is "start of payload"

    return offset;
}

function makeGPNonce(header: ZigbeeNWKGPHeader, macSource64: bigint | undefined): Buffer {
    const nonce = Buffer.alloc(ZigbeeConsts.SEC_NONCE_LEN);
    let offset = 0;

    if (header.frameControlExt!.appId === ZigbeeNWKGPAppId.DEFAULT) {
        if (header.frameControlExt!.direction === ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD) {
            nonce.writeUInt32LE(header.sourceId!, offset);
            offset += 4;
        }

        nonce.writeUInt32LE(header.sourceId!, offset);
        offset += 4;
    } else if (header.frameControlExt!.appId === ZigbeeNWKGPAppId.ZGP) {
        nonce.writeBigUInt64LE(macSource64!, offset);
        offset += 8;
    }

    nonce.writeUInt32LE(header.securityFrameCounter!, offset);
    offset += 4;

    if (header.frameControlExt!.appId === ZigbeeNWKGPAppId.ZGP && header.frameControlExt!.direction === ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD) {
        // Security level = 0b101, Key Identifier = 0x00, Extended nonce = 0b0, Reserved = 0b00
        nonce.writeUInt8(0xc5, offset);
        offset += 1;
    } else {
        // Security level = 0b101, Key Identifier = 0x00, Extended nonce = 0b0, Reserved = 0b11
        nonce.writeUInt8(0x05, offset);
        offset += 1;
    }

    return nonce;
}

export function decodeZigbeeNWKGPPayload(
    data: Buffer,
    offset: number,
    decryptKey: Buffer,
    macSource64: bigint | undefined,
    _frameControl: ZigbeeNWKGPFrameControl,
    header: ZigbeeNWKGPHeader,
): ZigbeeNWKGPPayload {
    const cryptedPayload = data.subarray(offset, offset + header.payloadLength); // no MIC
    let decryptedPayload: ZigbeeNWKGPPayload | undefined;

    if (header.frameControlExt?.securityLevel === ZigbeeNWKGPSecurityLevel.FULLENCR) {
        const nonce = makeGPNonce(header, macSource64);
        [, decryptedPayload] = aes128CcmStar(header.micSize, decryptKey, nonce, cryptedPayload);

        // TODO mic/authTag?
    } else {
        decryptedPayload = cryptedPayload;

        // TODO mic/authTag?
    }

    if (!decryptedPayload) {
        throw new Error("Unable to decrypt Zigbee NWK GP payload");
    }

    return decryptedPayload;
}

export function encodeZigbeeNWKGPFrame(
    header: ZigbeeNWKGPHeader,
    payload: ZigbeeNWKGPPayload,
    decryptKey: Buffer,
    macSource64: bigint | undefined,
): Buffer {
    let offset = 0;
    const data = Buffer.alloc(ZigbeeNWKGPConsts.FRAME_MAX_SIZE);

    offset = encodeZigbeeNWKGPHeader(data, offset, header);

    if (header.frameControlExt?.securityLevel === ZigbeeNWKGPSecurityLevel.FULLENCR) {
        const nonce = makeGPNonce(header, macSource64);
        const [, encryptedPayload] = aes128CcmStar(header.micSize, decryptKey, nonce, payload);

        // TODO mic/authTag?

        data.set(encryptedPayload, offset);
        offset += encryptedPayload.byteLength;
    } else {
        data.set(payload, offset);
        offset += payload.byteLength;
    }

    if (header.micSize === 2) {
        data.writeUInt16LE(header.mic!, offset); // at end
    } else if (header.micSize === 4) {
        data.writeUInt32LE(header.mic!, offset); // at end
    }

    offset += header.micSize;

    return data.subarray(0, offset);
}
