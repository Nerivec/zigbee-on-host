import { type ZigbeeSecurityHeader } from "./zigbee.js";
/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export declare const enum ZigbeeAPSConsts {
    HEADER_MIN_SIZE = 8,
    HEADER_MAX_SIZE = 21,
    FRAME_MAX_SIZE = 108,
    PAYLOAD_MIN_SIZE = 65,
    /** no NWK security */
    PAYLOAD_MAX_SIZE = 100,
    CMD_KEY_TC_MASTER = 0,
    CMD_KEY_STANDARD_NWK = 1,
    CMD_KEY_APP_MASTER = 2,
    CMD_KEY_APP_LINK = 3,
    CMD_KEY_TC_LINK = 4,
    CMD_KEY_HIGH_SEC_NWK = 5,
    CMD_KEY_LENGTH = 16,
    CMD_REQ_NWK_KEY = 1,
    CMD_REQ_APP_KEY = 2,
    CMD_UPDATE_STANDARD_SEC_REJOIN = 0,
    CMD_UPDATE_STANDARD_UNSEC_JOIN = 1,
    CMD_UPDATE_LEAVE = 2,
    CMD_UPDATE_STANDARD_UNSEC_REJOIN = 3,
    CMD_UPDATE_HIGH_SEC_REJOIN = 4,
    CMD_UPDATE_HIGH_UNSEC_JOIN = 5,
    CMD_UPDATE_HIGH_UNSEC_REJOIN = 7,
    FCF_FRAME_TYPE = 3,
    FCF_DELIVERY_MODE = 12,
    /** ZigBee 2004 and earlier.  */
    /** ZigBee 2007 and later.    */
    FCF_ACK_FORMAT = 16,
    FCF_SECURITY = 32,
    FCF_ACK_REQ = 64,
    FCF_EXT_HEADER = 128,
    EXT_FCF_FRAGMENT = 3
}
export declare const enum ZigbeeAPSFrameType {
    DATA = 0,
    CMD = 1,
    ACK = 2,
    INTERPAN = 3
}
export declare const enum ZigbeeAPSDeliveryMode {
    UNICAST = 0,
    BCAST = 2,
    /** ZigBee 2006 and later */
    GROUP = 3
}
export declare const enum ZigbeeAPSFragmentation {
    NONE = 0,
    FIRST = 1,
    MIDDLE = 2
}
export declare const enum ZigbeeAPSCommandId {
    TRANSPORT_KEY = 5,
    UPDATE_DEVICE = 6,
    REMOVE_DEVICE = 7,
    REQUEST_KEY = 8,
    SWITCH_KEY = 9,
    TUNNEL = 14,
    VERIFY_KEY = 15,
    CONFIRM_KEY = 16,
    RELAY_MESSAGE_DOWNSTREAM = 17,
    RELAY_MESSAGE_UPSTREAM = 18
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
export declare function decodeZigbeeAPSFrameControl(data: Buffer, offset: number): [ZigbeeAPSFrameControl, offset: number];
export declare function decodeZigbeeAPSHeader(data: Buffer, offset: number, frameControl: ZigbeeAPSFrameControl): [ZigbeeAPSHeader, offset: number];
export declare function encodeZigbeeAPSHeader(data: Buffer, offset: number, header: ZigbeeAPSHeader): number;
/**
 * @param data
 * @param offset
 * @param decryptKey If undefined, use default pre-hashed
 * @param nwkSource64
 * @param frameControl
 * @param header
 */
export declare function decodeZigbeeAPSPayload(data: Buffer, offset: number, decryptKey: Buffer | undefined, nwkSource64: bigint | undefined, frameControl: ZigbeeAPSFrameControl, header: ZigbeeAPSHeader): ZigbeeAPSPayload;
/**
 * @param header
 * @param payload
 * @param securityHeader
 * @param encryptKey If undefined, and security=true, use default pre-hashed
 */
export declare function encodeZigbeeAPSFrame(header: ZigbeeAPSHeader, payload: ZigbeeAPSPayload, securityHeader?: ZigbeeSecurityHeader, encryptKey?: Buffer): Buffer;
