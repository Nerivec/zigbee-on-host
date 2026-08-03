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
    /** The maximum amount of time that the MAC will hold a message for indirect transmission to a child. (7.68sec for Zigbee Pro) */
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
    /** 3-bit encoding of (L-1) */
    SEC_CCM_FLAG_L = 1,
    SEC_IPAD = 54,
    SEC_OPAD = 92,
    SEC_CONTROL_LEVEL = 7,
    SEC_CONTROL_KEY = 24,
    SEC_CONTROL_NONCE = 32,
    SEC_CONTROL_REQ_VERIFIED_FC = 64
}
export declare const enum ZigbeeSecurityLevel {
    NONE = 0,
    MIC32 = 1,
    MIC64 = 2,
    MIC128 = 3,
    ENC = 4,
    /** Zigbee 3.0 */
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
    /**
     * TODO: currently always false, see R23.1 4.6.3.8
     * R23:
     * This bit indicates to the receiver that it SHALL only accept the message if the receiver has verified
     * the frame counter of the corresponding apsDeviceKeyPairSet.
     * When the bit is set, and the receiver has an unverified frame counter it SHALL drop the current received message
     * and initiate a challenge via the ZDO Security_Challenge_req. See section 4.6.3.8 for more details.
     */
    reqVerifiedFc: boolean;
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
/** Valid install code lengths excluding CRC (bytes) */
export declare const INSTALL_CODE_VALID_SIZES: readonly [6, 8, 12, 16];
/**
 * 16-02828-012 (Base Device Behavior) §10.1.1.1 (Install code CRC)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Implements CRC-16/X25 parameters defined for install code validation
 * - ✅ Accepts byte arrays or buffers to match commissioning tooling interfaces
 * - ⚠️  Caller must remove trailing CRC bytes before invoking per spec guidance
 * DEVICE SCOPE: Trust Center and joining devices
 */
export declare function computeInstallCodeCRC(data: number[] | Uint8Array | Buffer): number;
/**
 * 13-0402-13 (Zigbee Key Establishment) §10.1 & B.1.3 (Cryptographic hash)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Applies AES-128-MMO padding with 0x80 bit and bit-length trailer as mandated
 * - ✅ Processes full blocks iteratively to support arbitrary-length install codes
 * - ⚠️  Relies on caller to provide raw install code without CRC
 * DEVICE SCOPE: Trust Center and install-code provisioning devices
 */
export declare function aes128MmoHash(data: Buffer): Buffer;
/**
 * 05-3474-23 R23.1, Annex B/A (CCM* mode of operation)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Implements CCM* counter generation with L=2 for Zigbee network/APS security
 * - ✅ Returns authentication tag and ciphertext slices matching Zigbee frame layout
 * - ⚠️  Assumes caller has already constructed nonce and formatted data per CCM* expectations
 * DEVICE SCOPE: All logical devices
 */
export declare function aes128CcmStar(M: 0 | 2 | 4 | 8 | 16, key: Buffer, nonce: Buffer, data: Buffer): [authTag: Buffer, ciphertext: Buffer];
/**
 * 05-3474-23 R23.1, Annex B (CCM* authentication primitive)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Builds B0 and authentication blocks per Zigbee CCM* definition using zero IV
 * - ✅ Pads associated data and payload to AES block size exactly per spec
 * - ⚠️  Caller must supply AAD in correct order (NWK header + security header)
 * DEVICE SCOPE: All logical devices
 */
export declare function computeAuthTag(authData: Buffer, M: number, key: Buffer, nonce: Buffer, data: Buffer): Buffer;
/**
 * 05-3474-23 R23.1, Figure 4-25 (Security control field)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Packs security level, key identifier, and nonce flag per Zigbee bit layout
 * - ✅ Supports temporary level override for CCM* calculations
 * - ⚠️  Caller responsible for ensuring override matches actual MIC length in use
 * DEVICE SCOPE: All logical devices
 */
export declare function combineSecurityControl(control: ZigbeeSecurityControl, levelOverride?: number): number;
/**
 * 05-3474-23 R23.1, Annex B (Nonce construction)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Orders IEEE source, frame counter, and security control bytes per Zigbee CCM* requirements
 * - ✅ Allows level override to align with temporary security level adjustments
 * - ⚠️  Expects caller to provide IEEE source (Trust Center or extended address)
 * DEVICE SCOPE: All logical devices
 */
export declare function makeNonce(header: ZigbeeSecurityHeader, source64: bigint, levelOverride?: number): Buffer;
/**
 * Pre-hashing default keys makes decryptions ~5x faster
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Stores hashed defaults for NWK/LINK/TRANSPORT/LOAD keys per Zigbee security model
 * - ⚠️  Caller must refresh hashes when Trust Center rotates keys
 * DEVICE SCOPE: Trust Center primarily
 */
export declare function registerDefaultHashedKeys(link: Buffer, nwk: Buffer, transport: Buffer, load: Buffer): void;
/**
 * 05-3474-23 R23.1, Annex B.1.4 (Keyed hash for message authentication)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Implements HMAC-like construction using AES-128-MMO with specified ipad/opad constants
 * - ✅ Supports arbitrary input byte per Trust Center transport/load key derivation rules
 * - ⚠️  Requires 16-byte key input; caller must validate length upstream
 * DEVICE SCOPE: Trust Center and devices deriving transport/load keys
 */
export declare function makeKeyedHash(key: Buffer, inputByte: number): Buffer;
/**
 * 05-3474-23 R23.1, Annex B.1.5 (Key usage definitions)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Returns unhashed NWK/LINK keys and hashed transport/load keys as mandated
 * - ✅ Throws on unsupported key identifiers to avoid silent misuse
 * - ⚠️  Caller must provide correct key material (hashed vs raw) for custom key types
 * DEVICE SCOPE: Trust Center and any device handling Zigbee key transports
 */
export declare function makeKeyedHashByType(keyId: ZigbeeKeyType, key: Buffer): Buffer;
/**
 * 05-3474-23 R23.1, Table B-6 (Auxiliary security header)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Parses frame counter, optional extended source, and key sequence per Zigbee security spec
 * - ✅ Forces Zigbee 3.0 security level (ENC-MIC-32) consistent with stack policy
 * - ⚠️  Does not yet evaluate legacy MIC length options (fixed to 4 bytes)
 * DEVICE SCOPE: All logical devices
 */
export declare function decodeZigbeeSecurityHeader(data: Buffer, offset: number, source64?: bigint): [ZigbeeSecurityHeader, offset: number];
/**
 * 05-3474-23 R23.1, Table B-6 (Auxiliary security header)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Serialises security control, frame counter, optional IEEE source, and key sequence
 * - ✅ Aligns with Zigbee requirement to include KeySeqNum when using NWK keys
 * - ⚠️  Caller must ensure header.control.nonce implies presence of source64
 * DEVICE SCOPE: All logical devices
 */
export declare function encodeZigbeeSecurityHeader(data: Buffer, offset: number, header: ZigbeeSecurityHeader): number;
/**
 * 05-3474-23 R23.1, Annex B (Inbound security processing)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Applies CCM* decryption using hashed keys derived per key type definition
 * - ✅ Validates MIC before returning payload, preserving stack integrity
 * - ⚠️  Currently assumes Zigbee 3.0 ENC-MIC-32; legacy level support TODO
 * DEVICE SCOPE: All logical devices
 */
export declare function decryptZigbeePayload(data: Buffer, offset: number, key?: Buffer, source64?: bigint): [Buffer, header: ZigbeeSecurityHeader, offset: number];
/**
 * 05-3474-23 R23.1, Annex B (Outbound security processing)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Computes MIC over NWK/APS header and encrypts payload per CCM* specification
 * - ✅ Utilises hashed key cache for performance while maintaining spec compliance
 * - ⚠️  Requires caller to set header.micLen consistent with selected security level
 * DEVICE SCOPE: All logical devices
 */
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
