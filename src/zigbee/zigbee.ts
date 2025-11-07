import { createCipheriv } from "node:crypto";

/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export const enum ZigbeeConsts {
    COORDINATOR_ADDRESS = 0x0000,
    /** min reserved address for broacasts */
    BCAST_MIN = 0xfff8,
    /** Low power routers only */
    BCAST_LOW_POWER_ROUTERS = 0xfffb,
    /** All routers and coordinator */
    BCAST_DEFAULT = 0xfffc,
    /** macRxOnWhenIdle = TRUE (all non-sleepy devices) */
    BCAST_RX_ON_WHEN_IDLE = 0xfffd,
    /** All devices in PAN (including sleepy end devices) */
    BCAST_SLEEPY = 0xffff,
    /** The amount of time after which a broadcast is considered propagated throughout the network */
    BCAST_TIME_WINDOW = 9000,
    /** The maximum amount of time that the MAC will hold a message for indirect transmission to a child. (7.68sec for Zigbee Pro) */
    MAC_INDIRECT_TRANSMISSION_TIMEOUT = 7680,

    //---- HA
    HA_ENDPOINT = 0x01,
    HA_PROFILE_ID = 0x0104,

    //---- ZDO
    ZDO_ENDPOINT = 0x00,
    ZDO_PROFILE_ID = 0x0000,
    NETWORK_ADDRESS_REQUEST = 0x0000,
    IEEE_ADDRESS_REQUEST = 0x0001,
    NODE_DESCRIPTOR_REQUEST = 0x0002,
    POWER_DESCRIPTOR_REQUEST = 0x0003,
    SIMPLE_DESCRIPTOR_REQUEST = 0x0004,
    ACTIVE_ENDPOINTS_REQUEST = 0x0005,
    END_DEVICE_ANNOUNCE = 0x0013,
    LQI_TABLE_REQUEST = 0x0031,
    ROUTING_TABLE_REQUEST = 0x0032,
    NWK_UPDATE_REQUEST = 0x0038,

    //---- Green Power
    GP_ENDPOINT = 0xf2,
    GP_PROFILE_ID = 0xa1e0,
    GP_GROUP_ID = 0x0b84,
    GP_CLUSTER_ID = 0x0021,

    //---- Touchlink
    TOUCHLINK_PROFILE_ID = 0xc05e,

    //---- Zigbee Security Constants
    SEC_L = 2,
    SEC_BLOCKSIZE = 16,
    SEC_NONCE_LEN = 16 - 2 - 1,
    SEC_KEYSIZE = 16,

    SEC_CONTROL_VERIFIED_FC = 0x40,

    //---- CCM* Flags
    /** 3-bit encoding of (L-1) */
    SEC_CCM_FLAG_L = 0x01,

    SEC_IPAD = 0x36,
    SEC_OPAD = 0x5c,

    //---- Bit masks for the Security Control Field
    SEC_CONTROL_LEVEL = 0x07,
    SEC_CONTROL_KEY = 0x18,
    SEC_CONTROL_NONCE = 0x20,
}

/* Zigbee security levels. */
export const enum ZigbeeSecurityLevel {
    NONE = 0x00,
    MIC32 = 0x01,
    MIC64 = 0x02,
    MIC128 = 0x03,
    ENC = 0x04,
    /** Zigbee 3.0 */
    ENC_MIC32 = 0x05,
    ENC_MIC64 = 0x06,
    ENC_MIC128 = 0x07,
}

/* Zigbee Key Types */
export const enum ZigbeeKeyType {
    LINK = 0x00,
    NWK = 0x01,
    TRANSPORT = 0x02,
    LOAD = 0x03,
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
    /** uint32_t */
    // mic?: number;
};

/** Valid install code lengths excluding CRC (bytes) */
export const INSTALL_CODE_VALID_SIZES = [6, 8, 12, 16] as const;

/**
 * 16-02828-R #10.1.1.1
 *
 * CRC16 X25
 * - Length: 16
 * - Polynomial: 𝑥𝑥 16 + 𝑥𝑥 12 + 𝑥𝑥 5 + 1 (0x1021)
 * - Initialization method: Direct
 * - Initialization value: 0xFFFF
 * - Final XOR value: 0xFFFF
 * - Reflected In: True
 * - Reflected Out: True
 */
const CRC16X25_TABLE = new Uint16Array([
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x0108,
    0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876, 0x2102, 0x308b, 0x0210, 0x1399,
    0x6726, 0x76af, 0x4434, 0x55bd, 0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e,
    0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3, 0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a, 0xdecd, 0xcf44,
    0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5,
    0xa96a, 0xb8e3, 0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738, 0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862,
    0x9af9, 0x8b70, 0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036, 0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e, 0xa50a, 0xb483,
    0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
    0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1,
    0xa33a, 0xb2b3, 0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1, 0x6b46, 0x7acf,
    0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9, 0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e, 0x58d5, 0x495c,
    0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
]);

/**
 * 16-02828-012 (Base Device Behavior) §10.1.1.1 (Install code CRC)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Implements CRC-16/X25 parameters defined for install code validation
 * - ✅ Accepts byte arrays or buffers to match commissioning tooling interfaces
 * - ⚠️  Caller must remove trailing CRC bytes before invoking per spec guidance
 */
export function computeInstallCodeCRC(data: number[] | Uint8Array | Buffer): number {
    let crc = 0xffff;

    for (const aByte of data) {
        const byte = aByte & 0xff;
        crc = (crc >>> 8) ^ CRC16X25_TABLE[(crc ^ byte) & 0xff];
    }

    return ~crc & 0xffff;
}

function aes128MmoHashUpdate(result: Buffer, data: Buffer, dataSize: number): void {
    while (dataSize >= ZigbeeConsts.SEC_BLOCKSIZE) {
        const cipher = createCipheriv("aes-128-ecb", result, null);
        const block = data.subarray(0, ZigbeeConsts.SEC_BLOCKSIZE);
        const u = cipher.update(block);
        const f = cipher.final();
        const encryptedBlock = Buffer.alloc(u.byteLength + f.byteLength);

        u.copy(encryptedBlock, 0);
        f.copy(encryptedBlock, u.byteLength);

        // XOR encrypted and plaintext
        for (let i = 0; i < ZigbeeConsts.SEC_BLOCKSIZE; i++) {
            result[i] = encryptedBlock[i] ^ block[i];
        }

        data = data.subarray(ZigbeeConsts.SEC_BLOCKSIZE);
        dataSize -= ZigbeeConsts.SEC_BLOCKSIZE;
    }
}

/**
 * 13-0402-13 (Zigbee Key Establishment) §10.1 & B.1.3 (Cryptographic hash)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Applies AES-128-MMO padding with 0x80 bit and bit-length trailer as mandated
 * - ✅ Processes full blocks iteratively to support arbitrary-length install codes
 * - ⚠️  Relies on caller to provide raw install code without CRC
 */
export function aes128MmoHash(data: Buffer): Buffer {
    const hashResult = Buffer.alloc(ZigbeeConsts.SEC_BLOCKSIZE);
    let remainingLength = data.byteLength;
    let position = 0;

    for (position; remainingLength >= ZigbeeConsts.SEC_BLOCKSIZE; ) {
        const chunk = data.subarray(position, position + ZigbeeConsts.SEC_BLOCKSIZE);

        aes128MmoHashUpdate(hashResult, chunk, chunk.byteLength);

        position += ZigbeeConsts.SEC_BLOCKSIZE;
        remainingLength -= ZigbeeConsts.SEC_BLOCKSIZE;
    }

    const temp = Buffer.alloc(ZigbeeConsts.SEC_BLOCKSIZE);

    data.subarray(position, position + remainingLength).copy(temp, 0);

    // per the spec, concatenate a 1 bit followed by all zero bits
    temp[remainingLength] = 0x80;

    // if appending the bit string will push us beyond the 16-byte boundary, hash that block and append another 16-byte block
    if (ZigbeeConsts.SEC_BLOCKSIZE - remainingLength < 3) {
        aes128MmoHashUpdate(hashResult, temp, ZigbeeConsts.SEC_BLOCKSIZE);
        temp.fill(0);
    }

    temp[ZigbeeConsts.SEC_BLOCKSIZE - 2] = (data.byteLength >> 5) & 0xff;
    temp[ZigbeeConsts.SEC_BLOCKSIZE - 1] = (data.byteLength << 3) & 0xff;

    aes128MmoHashUpdate(hashResult, temp, ZigbeeConsts.SEC_BLOCKSIZE);

    return hashResult.subarray(0, ZigbeeConsts.SEC_BLOCKSIZE);
}

/**
 * 05-3474-23 R23.1, Annex B/A (CCM* mode of operation)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Implements CCM* counter generation with L=2 for Zigbee network/APS security
 * - ✅ Returns authentication tag and ciphertext slices matching Zigbee frame layout
 * - ⚠️  Assumes caller has already constructed nonce and formatted data per CCM* expectations
 */
export function aes128CcmStar(M: 0 | 2 | 4 | 8 | 16, key: Buffer, nonce: Buffer, data: Buffer): [authTag: Buffer, ciphertext: Buffer] {
    const payloadLengthNoM = data.byteLength - M;
    const blockCount = 1 + Math.ceil(payloadLengthNoM / ZigbeeConsts.SEC_BLOCKSIZE);
    const plaintext = Buffer.alloc(blockCount * ZigbeeConsts.SEC_BLOCKSIZE);

    data.subarray(-M).copy(plaintext, 0);
    data.subarray(0, -M).copy(plaintext, ZigbeeConsts.SEC_BLOCKSIZE);

    const cipher = createCipheriv("aes-128-ecb", key, null);
    const buffer = Buffer.alloc(blockCount * ZigbeeConsts.SEC_BLOCKSIZE);
    const counter = Buffer.alloc(ZigbeeConsts.SEC_BLOCKSIZE);
    counter[0] = ZigbeeConsts.SEC_CCM_FLAG_L;

    nonce.copy(counter, 1);

    for (let blockNum = 0; blockNum < blockCount; blockNum++) {
        // big endian of size ZigbeeConsts.SEC_L
        counter[counter.byteLength - 2] = (blockNum >> 8) & 0xff;
        counter[counter.byteLength - 1] = blockNum & 0xff;
        const plaintextBlock = plaintext.subarray(ZigbeeConsts.SEC_BLOCKSIZE * blockNum, ZigbeeConsts.SEC_BLOCKSIZE * (blockNum + 1));
        const cipherU = cipher.update(counter);

        // XOR cipher and plaintext
        for (let i = 0; i < cipherU.byteLength; i++) {
            cipherU[i] ^= plaintextBlock[i];
        }

        cipherU.copy(buffer, ZigbeeConsts.SEC_BLOCKSIZE * blockNum);
    }

    cipher.final();
    const authTag = buffer.subarray(0, M);
    const ciphertext = buffer.subarray(ZigbeeConsts.SEC_BLOCKSIZE, ZigbeeConsts.SEC_BLOCKSIZE + payloadLengthNoM);

    return [authTag, ciphertext];
}

/**
 * 05-3474-23 R23.1, Annex B (CCM* authentication primitive)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Builds B0 and authentication blocks per Zigbee CCM* definition using zero IV
 * - ✅ Pads associated data and payload to AES block size exactly per spec
 * - ⚠️  Caller must supply AAD in correct order (NWK header + security header)
 */
export function computeAuthTag(authData: Buffer, M: number, key: Buffer, nonce: Buffer, data: Buffer): Buffer {
    const startPaddedSize = Math.ceil(
        (1 + nonce.byteLength + ZigbeeConsts.SEC_L + ZigbeeConsts.SEC_L + authData.byteLength) / ZigbeeConsts.SEC_BLOCKSIZE,
    );
    const endPaddedSize = Math.ceil(data.byteLength / ZigbeeConsts.SEC_BLOCKSIZE);
    const prependAuthData = Buffer.alloc(startPaddedSize * ZigbeeConsts.SEC_BLOCKSIZE + endPaddedSize * ZigbeeConsts.SEC_BLOCKSIZE);
    let offset = 0;
    prependAuthData[offset] = ((((M - 2) / 2) & 0x7) << 3) | (authData.byteLength > 0 ? 0x40 : 0x00) | ZigbeeConsts.SEC_CCM_FLAG_L;
    offset += 1;

    offset += nonce.copy(prependAuthData, offset);

    // big endian of size ZigbeeConsts.SEC_L
    prependAuthData[offset] = (data.byteLength >> 8) & 0xff;
    prependAuthData[offset + 1] = data.byteLength & 0xff;
    offset += 2;

    const prepend = authData.byteLength;
    // big endian of size ZigbeeConsts.SEC_L
    prependAuthData[offset] = (prepend >> 8) & 0xff;
    prependAuthData[offset + 1] = prepend & 0xff;
    offset += 2;

    offset += authData.copy(prependAuthData, offset);

    const dataOffset = Math.ceil(offset / ZigbeeConsts.SEC_BLOCKSIZE) * ZigbeeConsts.SEC_BLOCKSIZE;

    data.copy(prependAuthData, dataOffset);

    const cipher = createCipheriv("aes-128-cbc", key, Buffer.alloc(ZigbeeConsts.SEC_BLOCKSIZE, 0));
    const cipherU = cipher.update(prependAuthData);

    cipher.final();

    const authTag = cipherU.subarray(-ZigbeeConsts.SEC_BLOCKSIZE, -ZigbeeConsts.SEC_BLOCKSIZE + M);

    return authTag;
}

/**
 * 05-3474-23 R23.1, Table B-4 (Security control field)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Packs security level, key identifier, and nonce flag per Zigbee bit layout
 * - ✅ Supports temporary level override for CCM* calculations
 * - ⚠️  Caller responsible for ensuring override matches actual MIC length in use
 */
export function combineSecurityControl(control: ZigbeeSecurityControl, levelOverride?: number): number {
    return (
        ((levelOverride !== undefined ? levelOverride : control.level) & ZigbeeConsts.SEC_CONTROL_LEVEL) |
        ((control.keyId << 3) & ZigbeeConsts.SEC_CONTROL_KEY) |
        (((control.nonce ? 1 : 0) << 5) & ZigbeeConsts.SEC_CONTROL_NONCE)
    );
}

/**
 * 05-3474-23 R23.1, Annex B (Nonce construction)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Orders IEEE source, frame counter, and security control bytes per Zigbee CCM* requirements
 * - ✅ Allows level override to align with temporary security level adjustments
 * - ⚠️  Expects caller to provide IEEE source (Trust Center or extended address)
 */
export function makeNonce(header: ZigbeeSecurityHeader, source64: bigint, levelOverride?: number): Buffer {
    const nonce = Buffer.alloc(ZigbeeConsts.SEC_NONCE_LEN);

    // TODO: write source64 as all 0/F if undefined?
    nonce.writeBigUInt64LE(source64, 0);
    nonce.writeUInt32LE(header.frameCounter, 8);
    nonce.writeUInt8(combineSecurityControl(header.control, levelOverride), 12);

    return nonce;
}

/**
 * In order:
 * ZigbeeKeyType.LINK, ZigbeeKeyType.NWK, ZigbeeKeyType.TRANSPORT, ZigbeeKeyType.LOAD
 */
const defaultHashedKeys: [Buffer, Buffer, Buffer, Buffer] = [Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0)];

/**
 * Pre-hashing default keys makes decryptions ~5x faster
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Stores hashed defaults for NWK/LINK/TRANSPORT/LOAD keys per Zigbee security model
 * - ⚠️  Caller must refresh hashes when Trust Center rotates keys
 */
export function registerDefaultHashedKeys(link: Buffer, nwk: Buffer, transport: Buffer, load: Buffer): void {
    defaultHashedKeys[0] = link;
    defaultHashedKeys[1] = nwk;
    defaultHashedKeys[2] = transport;
    defaultHashedKeys[3] = load;
}

/**
 * 05-3474-23 R23.1, Annex B.1.4 (Keyed hash for message authentication)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Implements HMAC-like construction using AES-128-MMO with specified ipad/opad constants
 * - ✅ Supports arbitrary input byte per Trust Center transport/load key derivation rules
 * - ⚠️  Requires 16-byte key input; caller must validate length upstream
 */
export function makeKeyedHash(key: Buffer, inputByte: number): Buffer {
    const hashOut = Buffer.alloc(ZigbeeConsts.SEC_BLOCKSIZE + 1);
    const hashIn = Buffer.alloc(2 * ZigbeeConsts.SEC_BLOCKSIZE);

    for (let i = 0; i < ZigbeeConsts.SEC_KEYSIZE; i++) {
        // copy the key into hashIn and XOR with opad to form: (Key XOR opad)
        hashIn[i] = key[i] ^ ZigbeeConsts.SEC_OPAD;
        // copy the Key into hashOut and XOR with ipad to form: (Key XOR ipad)
        hashOut[i] = key[i] ^ ZigbeeConsts.SEC_IPAD;
    }

    // append the input byte to form: (Key XOR ipad) || text.
    hashOut[ZigbeeConsts.SEC_BLOCKSIZE] = inputByte;
    // hash the contents of hashOut and append the contents to hashIn to form: (Key XOR opad) || H((Key XOR ipad) || text)
    aes128MmoHash(hashOut).copy(hashIn, ZigbeeConsts.SEC_BLOCKSIZE);
    // hash the contents of hashIn to get the final result
    aes128MmoHash(hashIn).copy(hashOut, 0);

    return hashOut.subarray(0, ZigbeeConsts.SEC_BLOCKSIZE);
}

/**
 * 05-3474-23 R23.1, Annex B.1.5 (Key usage definitions)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Returns unhashed NWK/LINK keys and hashed transport/load keys as mandated
 * - ✅ Throws on unsupported key identifiers to avoid silent misuse
 * - ⚠️  Caller must provide correct key material (hashed vs raw) for custom key types
 */
export function makeKeyedHashByType(keyId: ZigbeeKeyType, key: Buffer): Buffer {
    switch (keyId) {
        case ZigbeeKeyType.NWK:
        case ZigbeeKeyType.LINK: {
            // NWK: decrypt with the PAN's current network key
            // LINK: decrypt with the unhashed link key assigned by the trust center to this source/destination pair
            return key;
        }
        case ZigbeeKeyType.TRANSPORT: {
            // decrypt with a Transport key, a hashed link key that protects network keys sent from the trust center
            return makeKeyedHash(key, 0x00);
        }
        case ZigbeeKeyType.LOAD: {
            // decrypt with a Load key, a hashed link key that protects link keys sent from the trust center
            return makeKeyedHash(key, 0x02);
        }
        default: {
            throw new Error(`Unsupported key ID ${keyId}`);
        }
    }
}

/**
 * 05-3474-23 R23.1, Table B-6 (Auxiliary security header)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Parses frame counter, optional extended source, and key sequence per Zigbee security spec
 * - ✅ Forces Zigbee 3.0 security level (ENC-MIC-32) consistent with stack policy
 * - ⚠️  Does not yet evaluate legacy MIC length options (fixed to 4 bytes)
 */
export function decodeZigbeeSecurityHeader(data: Buffer, offset: number, source64?: bigint): [ZigbeeSecurityHeader, offset: number] {
    const control = data.readUInt8(offset);
    offset += 1;
    const level = ZigbeeSecurityLevel.ENC_MIC32; // overrides control & ZigbeeConsts.SEC_CONTROL_LEVEL;
    const keyId = (control & ZigbeeConsts.SEC_CONTROL_KEY) >> 3;
    const nonce = Boolean((control & ZigbeeConsts.SEC_CONTROL_NONCE) >> 5);

    const frameCounter = data.readUInt32LE(offset);
    offset += 4;

    if (nonce) {
        source64 = data.readBigUInt64LE(offset);
        offset += 8;
    }

    let keySeqNum: number | undefined;

    if (keyId === ZigbeeKeyType.NWK) {
        keySeqNum = data.readUInt8(offset);
        offset += 1;
    }

    const micLen = 4;
    // NOTE: Security level for Zigbee 3.0 === 5
    // let micLen: number;

    // switch (level) {
    //     case ZigbeeSecurityLevel.ENC:
    //     case ZigbeeSecurityLevel.NONE:
    //     default:
    //         micLen = 0;
    //         break;

    //     case ZigbeeSecurityLevel.ENC_MIC32:
    //     case ZigbeeSecurityLevel.MIC32:
    //         micLen = 4;
    //         break;

    //     case ZigbeeSecurityLevel.ENC_MIC64:
    //     case ZigbeeSecurityLevel.MIC64:
    //         micLen = 8;
    //         break;

    //     case ZigbeeSecurityLevel.ENC_MIC128:
    //     case ZigbeeSecurityLevel.MIC128:
    //         micLen = 16;
    //         break;
    // }

    return [
        {
            control: {
                level,
                keyId,
                nonce,
            },
            frameCounter,
            source64,
            keySeqNum,
            micLen,
        },
        offset,
    ];
}

/**
 * 05-3474-23 R23.1, Table B-6 (Auxiliary security header)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Serialises security control, frame counter, optional IEEE source, and key sequence
 * - ✅ Aligns with Zigbee requirement to include KeySeqNum when using NWK keys
 * - ⚠️  Caller must ensure header.control.nonce implies presence of source64
 */
export function encodeZigbeeSecurityHeader(data: Buffer, offset: number, header: ZigbeeSecurityHeader): number {
    offset = data.writeUInt8(combineSecurityControl(header.control), offset);

    offset = data.writeUInt32LE(header.frameCounter, offset);

    if (header.control.nonce) {
        offset = data.writeBigUInt64LE(header.source64!, offset);
    }

    if (header.control.keyId === ZigbeeKeyType.NWK) {
        offset = data.writeUInt8(header.keySeqNum!, offset);
    }

    return offset;
}

/**
 * 05-3474-23 R23.1, Annex B (Inbound security processing)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Applies CCM* decryption using hashed keys derived per key type definition
 * - ✅ Validates MIC before returning payload, preserving stack integrity
 * - ⚠️  Currently assumes Zigbee 3.0 ENC-MIC-32; legacy level support TODO
 */
export function decryptZigbeePayload(
    data: Buffer,
    offset: number,
    key?: Buffer,
    source64?: bigint,
): [Buffer, header: ZigbeeSecurityHeader, offset: number] {
    const controlOffset = offset;
    const [header, hOutOffset] = decodeZigbeeSecurityHeader(data, offset, source64);

    let authTag: Buffer | undefined;
    let decryptedPayload: Buffer | undefined;

    if (header.source64 !== undefined) {
        const hashedKey = key ? makeKeyedHashByType(header.control.keyId, key) : defaultHashedKeys[header.control.keyId];
        const nonce = makeNonce(header, header.source64);
        const encryptedData = data.subarray(hOutOffset); // payload + auth tag

        [authTag, decryptedPayload] = aes128CcmStar(header.micLen!, hashedKey, nonce, encryptedData);

        // take until end of securityHeader for auth tag computation
        const adjustedAuthData = data.subarray(0, hOutOffset);
        // patch the security level to Zigbee 3.0
        const origControl = adjustedAuthData[controlOffset];
        adjustedAuthData[controlOffset] &= ~ZigbeeConsts.SEC_CONTROL_LEVEL;
        adjustedAuthData[controlOffset] |= ZigbeeConsts.SEC_CONTROL_LEVEL & ZigbeeSecurityLevel.ENC_MIC32;

        const computedAuthTag = computeAuthTag(adjustedAuthData, header.micLen!, hashedKey, nonce, decryptedPayload);
        // restore security level
        adjustedAuthData[controlOffset] = origControl;

        if (!computedAuthTag.equals(authTag)) {
            throw new Error("Auth tag mismatch while decrypting Zigbee payload");
        }
    }

    if (!decryptedPayload) {
        throw new Error("Unable to decrypt Zigbee payload");
    }

    return [decryptedPayload, header, hOutOffset];
}

/**
 * 05-3474-23 R23.1, Annex B (Outbound security processing)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Computes MIC over NWK/APS header and encrypts payload per CCM* specification
 * - ✅ Utilises hashed key cache for performance while maintaining spec compliance
 * - ⚠️  Requires caller to set header.micLen consistent with selected security level
 */
export function encryptZigbeePayload(
    data: Buffer,
    offset: number,
    payload: Buffer,
    header: ZigbeeSecurityHeader,
    key?: Buffer,
): [Buffer, authTag: Buffer, offset: number] {
    const controlOffset = offset;
    offset = encodeZigbeeSecurityHeader(data, offset, header);

    let authTag: Buffer | undefined;
    let encryptedPayload: Buffer | undefined;

    if (header.source64 !== undefined) {
        const hashedKey = key ? makeKeyedHashByType(header.control.keyId, key) : defaultHashedKeys[header.control.keyId];
        const nonce = makeNonce(header, header.source64, ZigbeeSecurityLevel.ENC_MIC32);
        const adjustedAuthData = data.subarray(0, offset);
        // patch the security level to Zigbee 3.0
        const origControl = adjustedAuthData[controlOffset];
        adjustedAuthData[controlOffset] &= ~ZigbeeConsts.SEC_CONTROL_LEVEL;
        adjustedAuthData[controlOffset] |= ZigbeeConsts.SEC_CONTROL_LEVEL & ZigbeeSecurityLevel.ENC_MIC32;

        const decryptedData = Buffer.alloc(payload.byteLength + header.micLen!); // payload + auth tag

        payload.copy(decryptedData, 0);

        // take nwkHeader + securityHeader for auth tag computation
        const computedAuthTag = computeAuthTag(adjustedAuthData, header.micLen!, hashedKey, nonce, payload);

        computedAuthTag.copy(decryptedData, payload.byteLength);

        // restore security level
        adjustedAuthData[controlOffset] = origControl;
        [authTag, encryptedPayload] = aes128CcmStar(header.micLen!, hashedKey, nonce, decryptedData);
    }

    if (!encryptedPayload || !authTag) {
        throw new Error("Unable to encrypt Zigbee payload");
    }

    return [encryptedPayload, authTag, offset];
}

/**
 * Converts a channels array to a uint32 channel mask.
 * @param channels
 * @returns
 */
export const convertChannelsToMask = (channels: number[]): number => {
    return channels.reduce((a, c) => a + (1 << c), 0);
};

/**
 * Converts a uint32 channel mask to a channels array.
 * @param mask
 * @returns
 */
export const convertMaskToChannels = (mask: number): number[] => {
    const channels: number[] = [];

    for (const channel of [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]) {
        if ((2 ** channel) & mask) {
            channels.push(channel);
        }
    }

    return channels;
};
