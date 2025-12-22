/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export declare const enum ZigbeeNWKGPConsts {
    FRAME_MAX_SIZE = 116,
    /** no security */
    HEADER_MIN_SIZE = 8,
    HEADER_MAX_SIZE = 30,
    PAYLOAD_MIN_SIZE = 86,
    PAYLOAD_MAX_SIZE = 108,
    FCF_AUTO_COMMISSIONING = 64,
    FCF_CONTROL_EXTENSION = 128,
    FCF_FRAME_TYPE = 3,
    FCF_VERSION = 60,
    FCF_EXT_APP_ID = 7,// 0 - 2 b.
    FCF_EXT_SECURITY_LEVEL = 24,// 3 - 4 b.
    FCF_EXT_SECURITY_KEY = 32,// 5 b.
    FCF_EXT_RX_AFTER_TX = 64,// 6 b.
    FCF_EXT_DIRECTION = 128
}
/** Zigbee NWK GP FCF frame types. */
export declare const enum ZigbeeNWKGPFrameType {
    DATA = 0,
    MAINTENANCE = 1
}
/** Definitions for application IDs. */
export declare const enum ZigbeeNWKGPAppId {
    DEFAULT = 0,
    LPED = 1,
    ZGP = 2
}
/** Definitions for GP directions. */
export declare const enum ZigbeeNWKGPDirection {
    DIRECTION_FROM_ZGPD = 0,
    DIRECTION_FROM_ZGPP = 1
}
/** Security level values. */
export declare const enum ZigbeeNWKGPSecurityLevel {
    /** No Security  */
    NO = 0,
    /** Reserved?  */
    ONELSB = 1,
    /** 4 Byte Frame Counter and 4 Byte MIC */
    FULL = 2,
    /** 4 Byte Frame Counter and 4 Byte MIC with encryption */
    FULLENCR = 3
}
/** GP Security key types. */
export declare const enum ZigbeeNWKGPSecurityKeyType {
    NO_KEY = 0,
    ZB_NWK_KEY = 1,
    GPD_GROUP_KEY = 2,
    NWK_KEY_DERIVED_GPD_KEY_GROUP_KEY = 3,
    PRECONFIGURED_INDIVIDUAL_GPD_KEY = 4,
    DERIVED_INDIVIDUAL_GPD_KEY = 7
}
export declare const enum ZigbeeNWKGPCommandId {
    IDENTIFY = 0,
    RECALL_SCENE0 = 16,
    RECALL_SCENE1 = 17,
    RECALL_SCENE2 = 18,
    RECALL_SCENE3 = 19,
    RECALL_SCENE4 = 20,
    RECALL_SCENE5 = 21,
    RECALL_SCENE6 = 22,
    RECALL_SCENE7 = 23,
    STORE_SCENE0 = 24,
    STORE_SCENE1 = 25,
    STORE_SCENE2 = 26,
    STORE_SCENE3 = 27,
    STORE_SCENE4 = 28,
    STORE_SCENE5 = 29,
    STORE_SCENE6 = 30,
    STORE_SCENE7 = 31,
    OFF = 32,
    ON = 33,
    TOGGLE = 34,
    RELEASE = 35,
    MOVE_UP = 48,
    MOVE_DOWN = 49,
    STEP_UP = 50,
    STEP_DOWN = 51,
    LEVEL_CONTROL_STOP = 52,
    MOVE_UP_WITH_ON_OFF = 53,
    MOVE_DOWN_WITH_ON_OFF = 54,
    STEP_UP_WITH_ON_OFF = 55,
    STEP_DOWN_WITH_ON_OFF = 56,
    MOVE_HUE_STOP = 64,
    MOVE_HUE_UP = 65,
    MOVE_HUE_DOWN = 66,
    STEP_HUE_UP = 67,
    STEP_HUW_DOWN = 68,
    MOVE_SATURATION_STOP = 69,
    MOVE_SATURATION_UP = 70,
    MOVE_SATURATION_DOWN = 71,
    STEP_SATURATION_UP = 72,
    STEP_SATURATION_DOWN = 73,
    MOVE_COLOR = 74,
    STEP_COLOR = 75,
    LOCK_DOOR = 80,
    UNLOCK_DOOR = 81,
    PRESS11 = 96,
    RELEASE11 = 97,
    PRESS12 = 98,
    RELEASE12 = 99,
    PRESS22 = 100,
    RELEASE22 = 101,
    SHORT_PRESS11 = 102,
    SHORT_PRESS12 = 103,
    SHORT_PRESS22 = 104,
    PRESS_8BIT_VECTOR = 105,
    RELEASE_8BIT_VECTOR = 106,
    ATTRIBUTE_REPORTING = 160,
    MANUFACTURE_SPECIFIC_ATTR_REPORTING = 161,
    MULTI_CLUSTER_REPORTING = 162,
    MANUFACTURER_SPECIFIC_MCLUSTER_REPORTING = 163,
    REQUEST_ATTRIBUTES = 164,
    READ_ATTRIBUTES_RESPONSE = 165,
    ZCL_TUNNELING = 166,
    COMPACT_ATTRIBUTE_REPORTING = 168,
    ANY_SENSOR_COMMAND_A0_A3 = 175,
    COMMISSIONING = 224,
    DECOMMISSIONING = 225,
    SUCCESS = 226,
    CHANNEL_REQUEST = 227,
    APPLICATION_DESCRIPTION = 228,
    COMMISSIONING_REPLY = 240,
    WRITE_ATTRIBUTES = 241,
    READ_ATTRIBUTES = 242,
    CHANNEL_CONFIGURATION = 243,
    ZCL_TUNNELING_TO_GPD = 6
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
    source64?: bigint;
    endpoint?: number;
    /** (utility, not part of the spec) */
    micSize: 0 | 2 | 4;
    securityFrameCounter?: number;
    payloadLength: number;
    mic?: number;
};
export type ZigbeeNWKGPPayload = Buffer;
/**
 * Decode Zigbee NWK GP frame control field.
 * HOT PATH: Called for every incoming Green Power frame.
 * 14-0563-19 Green Power, Table 25 (NWK frame control)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Parses auto-commissioning and frame-extension bits per GP network layer definition
 * - ✅ Extracts protocol version to gate GPv2+ logic for later layers
 * - ⚠️  Leaves direction-specific behaviour to extended control parsing
 * DEVICE SCOPE: Green Power proxies, Green Power sinks
 */
export declare function decodeZigbeeNWKGPFrameControl(data: Buffer, offset: number): [ZigbeeNWKGPFrameControl, offset: number];
/**
 * 14-0563-19 Green Power, Tables 27/28 (NWK header formats)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Applies application ID rules to choose between SourceID, IEEE address, and endpoint fields
 * - ✅ Calculates payload length by subtracting MIC for CCM* authenticated payloads
 * - ⚠️  Channel configuration special case still relies on peek to differentiate default appId flow
 * DEVICE SCOPE: Green Power proxies, Green Power sinks
 */
export declare function decodeZigbeeNWKGPHeader(data: Buffer, offset: number, frameControl: ZigbeeNWKGPFrameControl): [ZigbeeNWKGPHeader, offset: number];
/**
 * 14-0563-19 Green Power, 9.3 (Green Power security processing)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Authenticates and decrypts FULLENCR payloads via CCM*, validating MIC before returning
 * - ✅ Supports FULL security by verifying MIC when available (TODO path highlighted)
 * - ⚠️  Leaves ONELSB handling as TODO; callers should avoid enabling unsupported mode
 * DEVICE SCOPE: Green Power proxies, Green Power sinks
 */
export declare function decodeZigbeeNWKGPPayload(data: Buffer, offset: number, decryptKey: Buffer, macSource64: bigint | undefined, _frameControl: ZigbeeNWKGPFrameControl, header: ZigbeeNWKGPHeader): ZigbeeNWKGPPayload;
/**
 * 14-0563-19 Green Power, 9.3 (Green Power security processing)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Generates MIC and performs CCM* encryption for FULLENCR/FULL levels per spec
 * - ✅ Preserves payload ordering ahead of MIC bytes as required by GP sink behaviour
 * - ⚠️  Expects caller to preconfigure frameControlExt/securityFrameCounter correctly for nonce derivation
 * DEVICE SCOPE: Green Power proxies, Green Power sinks
 */
export declare function encodeZigbeeNWKGPFrame(header: ZigbeeNWKGPHeader, payload: ZigbeeNWKGPPayload, decryptKey: Buffer, macSource64: bigint | undefined): Buffer;
