/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export declare const enum ZigbeeConsts {
    COORDINATOR_ADDRESS = 0,
    /** min reserved address for broacasts */
    BCAST_MIN = 65528,
    /** Low power routers only */
    BCAST_LOW_POWER_ROUTERS = 65531,
    /** All routers and coordinator */
    BCAST_DEFAULT = 65532,
    /** macRxOnWhenIdle = TRUE (all non-sleepy devices) */
    BCAST_RX_ON_WHEN_IDLE = 65533,
    /** All devices in PAN (including sleepy end devices) */
    BCAST_SLEEPY = 65535,
    /** The amount of time after which a broadcast is considered propagated throughout the network */
    BCAST_TIME_WINDOW = 9000,
    /** The maximum amount of time that the MAC will hold a message for indirect transmission to a child. (7.68sec for ZigBee Pro) */
    MAC_INDIRECT_TRANSMISSION_TIMEOUT = 7680,
    HA_ENDPOINT = 1,
    HA_PROFILE_ID = 260,
    ZDO_ENDPOINT = 0,
    ZDO_PROFILE_ID = 0,
    NETWORK_ADDRESS_REQUEST = 0,
    IEEE_ADDRESS_REQUEST = 1,
    NODE_DESCRIPTOR_REQUEST = 2,
    POWER_DESCRIPTOR_REQUEST = 3,
    SIMPLE_DESCRIPTOR_REQUEST = 4,
    ACTIVE_ENDPOINTS_REQUEST = 5,
    END_DEVICE_ANNOUNCE = 19,
    LQI_TABLE_REQUEST = 49,
    ROUTING_TABLE_REQUEST = 50,
    NWK_UPDATE_REQUEST = 56,
    GP_ENDPOINT = 242,
    GP_PROFILE_ID = 41440,
    GP_GROUP_ID = 2948,
    GP_CLUSTER_ID = 33,
    TOUCHLINK_PROFILE_ID = 49246,
    SEC_L = 2,
    SEC_BLOCKSIZE = 16,
    SEC_NONCE_LEN = 13,
    SEC_KEYSIZE = 16,
    SEC_CONTROL_VERIFIED_FC = 64,
    /** 3-bit encoding of (L-1) */
    SEC_CCM_FLAG_L = 1,
    SEC_IPAD = 54,
    SEC_OPAD = 92,
    SEC_CONTROL_LEVEL = 7,
    SEC_CONTROL_KEY = 24,
    SEC_CONTROL_NONCE = 32
}
export declare const enum ZigbeeSecurityLevel {
    NONE = 0,
    MIC32 = 1,
    MIC64 = 2,
    MIC128 = 3,
    ENC = 4,
    /** ZigBee 3.0 */
    ENC_MIC32 = 5,
    ENC_MIC64 = 6,
    ENC_MIC128 = 7
}
export declare const enum ZigbeeKeyType {
    LINK = 0,
    NWK = 1,
    TRANSPORT = 2,
    LOAD = 3
}
export type ZigbeeSecurityControl = {
    level: ZigbeeSecurityLevel;
    keyId: ZigbeeKeyType;
    nonce: boolean;
};
export type ZigbeeSecurityHeader = {
    /** uint8_t (same as above) */
    control: ZigbeeSecurityControl;
    /** uint32_t */
    frameCounter: number;
    /** uint64_t */
    source64?: bigint;
    /** uint8_t */
    keySeqNum?: number;
    /** (utility, not part of the spec) */
    micLen?: 0 | 4 | 8 | 16;
};
/**
 * See B.1.3 Cryptographic Hash Function
 *
 * AES-128-MMO (Matyas-Meyer-Oseas) hashing (using node 'crypto' built-in with 'aes-128-ecb')
 *
 * Used for Install Codes - see Document 13-0402-13 - 10.1
 */
export declare function aes128MmoHash(data: Buffer): Buffer;
/**
 * See A CCM* MODE OF OPERATION
 *
 * Used for Zigbee NWK layer encryption/decryption
 */
export declare function aes128CcmStar(M: 0 | 2 | 4 | 8 | 16, key: Buffer, nonce: Buffer, data: Buffer): [authTag: Buffer, ciphertext: Buffer];
/**
 * aes-128-cbc with iv as 0-filled block size
 *
 * Used for Zigbee NWK layer encryption/decryption
 */
export declare function computeAuthTag(authData: Buffer, M: number, key: Buffer, nonce: Buffer, data: Buffer): Buffer;
export declare function combineSecurityControl(control: ZigbeeSecurityControl, levelOverride?: number): number;
export declare function makeNonce(header: ZigbeeSecurityHeader, source64: bigint, levelOverride?: number): Buffer;
/**
 * Pre-hashing default keys makes decryptions ~5x faster
 */
export declare function registerDefaultHashedKeys(link: Buffer, nwk: Buffer, transport: Buffer, load: Buffer): void;
/**
 * See B.1.4 Keyed Hash Function for Message Authentication
 *
 * @param key ZigBee Security Key (must be ZigbeeConsts.SEC_KEYSIZE) in length.
 * @param inputByte Input byte
 */
export declare function makeKeyedHash(key: Buffer, inputByte: number): Buffer;
/** Hash key if needed, else return `key` as is */
export declare function makeKeyedHashByType(keyId: ZigbeeKeyType, key: Buffer): Buffer;
export declare function decodeZigbeeSecurityHeader(data: Buffer, offset: number, source64?: bigint): [ZigbeeSecurityHeader, offset: number];
export declare function encodeZigbeeSecurityHeader(data: Buffer, offset: number, header: ZigbeeSecurityHeader): number;
export declare function decryptZigbeePayload(data: Buffer, offset: number, key?: Buffer, source64?: bigint): [Buffer, header: ZigbeeSecurityHeader, offset: number];
export declare function encryptZigbeePayload(data: Buffer, offset: number, payload: Buffer, header: ZigbeeSecurityHeader, key?: Buffer): [Buffer, authTag: Buffer, offset: number];
/**
 * Converts a channels array to a uint32 channel mask.
 * @param channels
 * @returns
 */
export declare const convertChannelsToMask: (channels: number[]) => number;
/**
 * Converts a uint32 channel mask to a channels array.
 * @param mask
 * @returns
 */
export declare const convertMaskToChannels: (mask: number) => number[];
