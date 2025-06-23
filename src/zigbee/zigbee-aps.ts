import { decryptZigbeePayload, encryptZigbeePayload, type ZigbeeSecurityHeader } from "./zigbee.js";

/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export const enum ZigbeeAPSConsts {
    HEADER_MIN_SIZE = 8,
    HEADER_MAX_SIZE = 21,
    FRAME_MAX_SIZE = 108,
    PAYLOAD_MIN_SIZE = 65,
    /** no NWK security */
    PAYLOAD_MAX_SIZE = 100,

    CMD_KEY_TC_MASTER = 0x00,
    CMD_KEY_STANDARD_NWK = 0x01,
    CMD_KEY_APP_MASTER = 0x02,
    CMD_KEY_APP_LINK = 0x03,
    CMD_KEY_TC_LINK = 0x04,
    CMD_KEY_HIGH_SEC_NWK = 0x05,
    CMD_KEY_LENGTH = 16,

    CMD_REQ_NWK_KEY = 0x01,
    CMD_REQ_APP_KEY = 0x02,

    CMD_UPDATE_STANDARD_SEC_REJOIN = 0x00,
    CMD_UPDATE_STANDARD_UNSEC_JOIN = 0x01,
    CMD_UPDATE_LEAVE = 0x02,
    CMD_UPDATE_STANDARD_UNSEC_REJOIN = 0x03,
    CMD_UPDATE_HIGH_SEC_REJOIN = 0x04,
    CMD_UPDATE_HIGH_UNSEC_JOIN = 0x05,
    CMD_UPDATE_HIGH_UNSEC_REJOIN = 0x07,

    FCF_FRAME_TYPE = 0x03,
    FCF_DELIVERY_MODE = 0x0c,
    /** ZigBee 2004 and earlier.  */
    // FCF_INDIRECT_MODE = 0x10,
    /** ZigBee 2007 and later.    */
    FCF_ACK_FORMAT = 0x10,
    FCF_SECURITY = 0x20,
    FCF_ACK_REQ = 0x40,
    FCF_EXT_HEADER = 0x80,

    EXT_FCF_FRAGMENT = 0x03,
}

export const enum ZigbeeAPSFrameType {
    DATA = 0x00,
    CMD = 0x01,
    ACK = 0x02,
    INTERPAN = 0x03,
}

export const enum ZigbeeAPSDeliveryMode {
    UNICAST = 0x00,
    // INDIRECT = 0x01, /** removed in Zigbee 2006 and later */
    BCAST = 0x02,
    /** ZigBee 2006 and later */
    GROUP = 0x03,
}

export const enum ZigbeeAPSFragmentation {
    NONE = 0x00,
    FIRST = 0x01,
    MIDDLE = 0x02,
}

export const enum ZigbeeAPSCommandId {
    TRANSPORT_KEY = 0x05,
    UPDATE_DEVICE = 0x06,
    REMOVE_DEVICE = 0x07,
    REQUEST_KEY = 0x08,
    SWITCH_KEY = 0x09,
    TUNNEL = 0x0e,
    VERIFY_KEY = 0x0f,
    CONFIRM_KEY = 0x10,
    RELAY_MESSAGE_DOWNSTREAM = 0x11,
    RELAY_MESSAGE_UPSTREAM = 0x12,
}

/**
 * Frame Control Field: Ack (0x02)
 *   .... ..10 = Frame Type: Ack (0x2)
 *   .... 00.. = Delivery Mode: Unicast (0x0)
 *   ...0 .... = Acknowledgement Format: False
 *   ..0. .... = Security: False
 *   .0.. .... = Acknowledgement Request: False
 *   0... .... = Extended Header: False
 */
export type ZigbeeAPSFrameControl = {
    frameType: ZigbeeAPSFrameType;
    deliveryMode: ZigbeeAPSDeliveryMode;
    // indirectMode: ZigbeeAPSIndirectMode;
    ackFormat: boolean;
    security: boolean;
    ackRequest: boolean;
    extendedHeader: boolean;
};

export type ZigbeeAPSHeader = {
    /** uint8_t */
    frameControl: ZigbeeAPSFrameControl;
    /** uint8_t */
    destEndpoint?: number;
    /** uint16_t */
    group?: number;
    /** uint16_t */
    clusterId?: number;
    /** uint16_t */
    profileId?: number;
    /** uint8_t */
    sourceEndpoint?: number;
    /** uint8_t */
    counter?: number;
    /** uint8_t */
    fragmentation?: ZigbeeAPSFragmentation;
    /** uint8_t */
    fragBlockNumber?: number;
    /** uint8_t */
    fragACKBitfield?: number;
    securityHeader?: ZigbeeSecurityHeader;
};

export type ZigbeeAPSPayload = Buffer;

export function decodeZigbeeAPSFrameControl(data: Buffer, offset: number): [ZigbeeAPSFrameControl, offset: number] {
    const fcf = data.readUInt8(offset);
    offset += 1;

    return [
        {
            frameType: fcf & ZigbeeAPSConsts.FCF_FRAME_TYPE,
            deliveryMode: (fcf & ZigbeeAPSConsts.FCF_DELIVERY_MODE) >> 2,
            // indirectMode = (fcf & ZigbeeAPSConsts.FCF_INDIRECT_MODE) >> 4,
            ackFormat: Boolean((fcf & ZigbeeAPSConsts.FCF_ACK_FORMAT) >> 4),
            security: Boolean((fcf & ZigbeeAPSConsts.FCF_SECURITY) >> 5),
            ackRequest: Boolean((fcf & ZigbeeAPSConsts.FCF_ACK_REQ) >> 6),
            extendedHeader: Boolean((fcf & ZigbeeAPSConsts.FCF_EXT_HEADER) >> 7),
        },
        offset,
    ];
}

function encodeZigbeeAPSFrameControl(data: Buffer, offset: number, fcf: ZigbeeAPSFrameControl): number {
    data.writeUInt8(
        (fcf.frameType & ZigbeeAPSConsts.FCF_FRAME_TYPE) |
            ((fcf.deliveryMode << 2) & ZigbeeAPSConsts.FCF_DELIVERY_MODE) |
            // ((fcf.indirectMode << 4) & ZigbeeAPSConsts.FCF_INDIRECT_MODE) |
            (((fcf.ackFormat ? 1 : 0) << 4) & ZigbeeAPSConsts.FCF_ACK_FORMAT) |
            (((fcf.security ? 1 : 0) << 5) & ZigbeeAPSConsts.FCF_SECURITY) |
            (((fcf.ackRequest ? 1 : 0) << 6) & ZigbeeAPSConsts.FCF_ACK_REQ) |
            (((fcf.extendedHeader ? 1 : 0) << 7) & ZigbeeAPSConsts.FCF_EXT_HEADER),
        offset,
    );
    offset += 1;

    return offset;
}

export function decodeZigbeeAPSHeader(data: Buffer, offset: number, frameControl: ZigbeeAPSFrameControl): [ZigbeeAPSHeader, offset: number] {
    let hasEndpointAddressing = true;
    let destPresent = false;
    let sourcePresent = false;
    let destEndpoint: number | undefined;
    let group: number | undefined;
    let clusterId: number | undefined;
    let profileId: number | undefined;
    let sourceEndpoint: number | undefined;

    switch (frameControl.frameType) {
        case ZigbeeAPSFrameType.DATA: {
            break;
        }
        case ZigbeeAPSFrameType.ACK: {
            if (frameControl.ackFormat) {
                hasEndpointAddressing = false;
            }
            break;
        }
        case ZigbeeAPSFrameType.INTERPAN: {
            destPresent = false;
            sourcePresent = false;
            break;
        }
        case ZigbeeAPSFrameType.CMD: {
            hasEndpointAddressing = false;
            break;
        }
    }

    if (hasEndpointAddressing) {
        if (frameControl.frameType !== ZigbeeAPSFrameType.INTERPAN) {
            if (frameControl.deliveryMode === ZigbeeAPSDeliveryMode.UNICAST || frameControl.deliveryMode === ZigbeeAPSDeliveryMode.BCAST) {
                destPresent = true;
                sourcePresent = true;
            } else if (frameControl.deliveryMode === ZigbeeAPSDeliveryMode.GROUP) {
                destPresent = false;
                sourcePresent = true;
            } else {
                throw new Error(`Invalid APS delivery mode ${frameControl.deliveryMode}`);
            }

            if (destPresent) {
                destEndpoint = data.readUInt8(offset);
                offset += 1;
            }
        }

        if (frameControl.deliveryMode === ZigbeeAPSDeliveryMode.GROUP) {
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

    let counter: number | undefined;

    if (frameControl.frameType !== ZigbeeAPSFrameType.INTERPAN) {
        counter = data.readUInt8(offset);
        offset += 1;
    }

    let fragmentation: ZigbeeAPSFragmentation | undefined;
    let fragBlockNumber: number | undefined;
    let fragACKBitfield: number | undefined;

    if (frameControl.extendedHeader) {
        const fcf = data.readUInt8(offset);
        offset += 1;
        fragmentation = fcf & ZigbeeAPSConsts.EXT_FCF_FRAGMENT;

        if (fragmentation !== ZigbeeAPSFragmentation.NONE) {
            fragBlockNumber = data.readUInt8(offset);
            offset += 1;
        }

        if (fragmentation !== ZigbeeAPSFragmentation.NONE && frameControl.frameType === ZigbeeAPSFrameType.ACK) {
            fragACKBitfield = data.readUInt8(offset);
            offset += 1;
        }
    }

    if (fragmentation !== undefined && fragmentation !== ZigbeeAPSFragmentation.NONE) {
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

export function encodeZigbeeAPSHeader(data: Buffer, offset: number, header: ZigbeeAPSHeader): number {
    offset = encodeZigbeeAPSFrameControl(data, offset, header.frameControl);
    let hasEndpointAddressing = true;
    let destPresent = false;
    let sourcePresent = false;

    switch (header.frameControl.frameType) {
        case ZigbeeAPSFrameType.DATA: {
            break;
        }
        case ZigbeeAPSFrameType.ACK: {
            if (header.frameControl.ackFormat) {
                hasEndpointAddressing = false;
            }
            break;
        }
        case ZigbeeAPSFrameType.INTERPAN: {
            destPresent = false;
            sourcePresent = false;
            break;
        }
        case ZigbeeAPSFrameType.CMD: {
            hasEndpointAddressing = false;
            break;
        }
    }

    if (hasEndpointAddressing) {
        if (header.frameControl.frameType !== ZigbeeAPSFrameType.INTERPAN) {
            if (
                header.frameControl.deliveryMode === ZigbeeAPSDeliveryMode.UNICAST ||
                header.frameControl.deliveryMode === ZigbeeAPSDeliveryMode.BCAST
            ) {
                destPresent = true;
                sourcePresent = true;
            } else if (header.frameControl.deliveryMode === ZigbeeAPSDeliveryMode.GROUP) {
                destPresent = false;
                sourcePresent = true;
            } else {
                throw new Error(`Invalid APS delivery mode ${header.frameControl.deliveryMode}`);
            }

            if (destPresent) {
                data.writeUInt8(header.destEndpoint!, offset);
                offset += 1;
            }
        }

        if (header.frameControl.deliveryMode === ZigbeeAPSDeliveryMode.GROUP) {
            data.writeUInt16LE(header.group!, offset);
            offset += 2;
        }

        data.writeUInt16LE(header.clusterId!, offset);
        offset += 2;

        data.writeUInt16LE(header.profileId!, offset);
        offset += 2;

        if (sourcePresent) {
            data.writeUInt8(header.sourceEndpoint!, offset);
            offset += 1;
        }
    }

    if (header.frameControl.frameType !== ZigbeeAPSFrameType.INTERPAN) {
        data.writeUInt8(header.counter!, offset);
        offset += 1;
    }

    if (header.frameControl.extendedHeader) {
        const fcf = header.fragmentation! & ZigbeeAPSConsts.EXT_FCF_FRAGMENT;

        data.writeUInt8(fcf, offset);
        offset += 1;

        if (header.fragmentation! !== ZigbeeAPSFragmentation.NONE) {
            data.writeUInt8(header.fragBlockNumber!, offset);
            offset += 1;
        }

        if (header.fragmentation! !== ZigbeeAPSFragmentation.NONE && header.frameControl.frameType === ZigbeeAPSFrameType.ACK) {
            data.writeUInt8(header.fragACKBitfield!, offset);
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
export function decodeZigbeeAPSPayload(
    data: Buffer,
    offset: number,
    decryptKey: Buffer | undefined,
    nwkSource64: bigint | undefined,
    frameControl: ZigbeeAPSFrameControl,
    header: ZigbeeAPSHeader,
): ZigbeeAPSPayload {
    if (frameControl.security) {
        const [payload, securityHeader, dOutOffset] = decryptZigbeePayload(data, offset, decryptKey, nwkSource64);
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
export function encodeZigbeeAPSFrame(
    header: ZigbeeAPSHeader,
    payload: ZigbeeAPSPayload,
    securityHeader?: ZigbeeSecurityHeader,
    encryptKey?: Buffer,
): Buffer {
    let offset = 0;
    const data = Buffer.alloc(ZigbeeAPSConsts.FRAME_MAX_SIZE);

    offset = encodeZigbeeAPSHeader(data, offset, header);

    if (header.frameControl.security) {
        // the octet string `a` SHALL be the string ApsHeader || Auxiliary-Header and the octet string `m` SHALL be the string Payload
        const [cryptedPayload, authTag, eOutOffset] = encryptZigbeePayload(data, offset, payload, securityHeader!, encryptKey);
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
