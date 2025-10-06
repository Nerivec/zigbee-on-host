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

function aes128MmoHashUpdate(result: Buffer, data: Buffer, dataSize: number): void {
    while (dataSize >= ZigbeeConsts.SEC_BLOCKSIZE) {
        const cipher = createCipheriv("aes-128-ecb", result, null);
        const block = data.subarray(0, ZigbeeConsts.SEC_BLOCKSIZE);
        const u = cipher.update(block);
        const f = cipher.final();
        const encryptedBlock = Buffer.alloc(u.byteLength + f.byteLength);

        encryptedBlock.set(u, 0);
        encryptedBlock.set(f, u.byteLength);

        // XOR encrypted and plaintext
        for (let i = 0; i < ZigbeeConsts.SEC_BLOCKSIZE; i++) {
            result[i] = encryptedBlock[i] ^ block[i];
        }

        data = data.subarray(ZigbeeConsts.SEC_BLOCKSIZE);
        dataSize -= ZigbeeConsts.SEC_BLOCKSIZE;
    }
}

/**
 * See B.1.3 Cryptographic Hash Function
 *
 * AES-128-MMO (Matyas-Meyer-Oseas) hashing (using node 'crypto' built-in with 'aes-128-ecb')
 *
 * Used for Install Codes - see Document 13-0402-13 - 10.1
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

    temp.set(data.subarray(position, position + remainingLength), 0);

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
 * See A CCM* MODE OF OPERATION
 *
 * Used for Zigbee NWK layer encryption/decryption
 */
export function aes128CcmStar(M: 0 | 2 | 4 | 8 | 16, key: Buffer, nonce: Buffer, data: Buffer): [authTag: Buffer, ciphertext: Buffer] {
    const payloadLengthNoM = data.byteLength - M;
    const blockCount = 1 + Math.ceil(payloadLengthNoM / ZigbeeConsts.SEC_BLOCKSIZE);
    const plaintext = Buffer.alloc(blockCount * ZigbeeConsts.SEC_BLOCKSIZE);

    plaintext.set(data.subarray(-M), 0);
    plaintext.set(data.subarray(0, -M), ZigbeeConsts.SEC_BLOCKSIZE);

    const cipher = createCipheriv("aes-128-ecb", key, null);
    const buffer = Buffer.alloc(blockCount * ZigbeeConsts.SEC_BLOCKSIZE);
    const counter = Buffer.alloc(ZigbeeConsts.SEC_BLOCKSIZE);
    counter[0] = ZigbeeConsts.SEC_CCM_FLAG_L;

    counter.set(nonce, 1);

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

        buffer.set(cipherU, ZigbeeConsts.SEC_BLOCKSIZE * blockNum);
    }

    cipher.final();
    const authTag = buffer.subarray(0, M);
    const ciphertext = buffer.subarray(ZigbeeConsts.SEC_BLOCKSIZE, ZigbeeConsts.SEC_BLOCKSIZE + payloadLengthNoM);

    return [authTag, ciphertext];
}

/**
 * aes-128-cbc with iv as 0-filled block size
 *
 * Used for Zigbee NWK layer encryption/decryption
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

    prependAuthData.set(nonce, offset);
    offset += nonce.byteLength;

    // big endian of size ZigbeeConsts.SEC_L
    prependAuthData[offset] = (data.byteLength >> 8) & 0xff;
    prependAuthData[offset + 1] = data.byteLength & 0xff;
    offset += 2;

    const prepend = authData.byteLength;
    // big endian of size ZigbeeConsts.SEC_L
    prependAuthData[offset] = (prepend >> 8) & 0xff;
    prependAuthData[offset + 1] = prepend & 0xff;
    offset += 2;

    prependAuthData.set(authData, offset);
    offset += authData.byteLength;

    const dataOffset = Math.ceil(offset / ZigbeeConsts.SEC_BLOCKSIZE) * ZigbeeConsts.SEC_BLOCKSIZE;
    prependAuthData.set(data, dataOffset);

    const cipher = createCipheriv("aes-128-cbc", key, Buffer.alloc(ZigbeeConsts.SEC_BLOCKSIZE, 0));
    const cipherU = cipher.update(prependAuthData);

    cipher.final();

    const authTag = cipherU.subarray(-ZigbeeConsts.SEC_BLOCKSIZE, -ZigbeeConsts.SEC_BLOCKSIZE + M);

    return authTag;
}

export function combineSecurityControl(control: ZigbeeSecurityControl, levelOverride?: number): number {
    return (
        ((levelOverride !== undefined ? levelOverride : control.level) & ZigbeeConsts.SEC_CONTROL_LEVEL) |
        ((control.keyId << 3) & ZigbeeConsts.SEC_CONTROL_KEY) |
        (((control.nonce ? 1 : 0) << 5) & ZigbeeConsts.SEC_CONTROL_NONCE)
    );
}

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
 */
export function registerDefaultHashedKeys(link: Buffer, nwk: Buffer, transport: Buffer, load: Buffer): void {
    defaultHashedKeys[0] = link;
    defaultHashedKeys[1] = nwk;
    defaultHashedKeys[2] = transport;
    defaultHashedKeys[3] = load;
}

/**
 * See B.1.4 Keyed Hash Function for Message Authentication
 *
 * @param key Zigbee Security Key (must be ZigbeeConsts.SEC_KEYSIZE) in length.
 * @param inputByte Input byte
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
    hashIn.set(aes128MmoHash(hashOut), ZigbeeConsts.SEC_BLOCKSIZE);
    // hash the contents of hashIn to get the final result
    hashOut.set(aes128MmoHash(hashIn), 0);

    return hashOut.subarray(0, ZigbeeConsts.SEC_BLOCKSIZE);
}

/** Hash key if needed, else return `key` as is */
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

export function encodeZigbeeSecurityHeader(data: Buffer, offset: number, header: ZigbeeSecurityHeader): number {
    data.writeUInt8(combineSecurityControl(header.control), offset);
    offset += 1;

    data.writeUInt32LE(header.frameCounter, offset);
    offset += 4;

    if (header.control.nonce) {
        data.writeBigUInt64LE(header.source64!, offset);
        offset += 8;
    }

    if (header.control.keyId === ZigbeeKeyType.NWK) {
        data.writeUInt8(header.keySeqNum!, offset);
        offset += 1;
    }

    return offset;
}

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
        decryptedData.set(payload, 0);
        // take nwkHeader + securityHeader for auth tag computation
        const computedAuthTag = computeAuthTag(adjustedAuthData, header.micLen!, hashedKey, nonce, payload);
        decryptedData.set(computedAuthTag, payload.byteLength);

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
