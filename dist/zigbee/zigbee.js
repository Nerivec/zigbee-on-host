"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.convertMaskToChannels = exports.convertChannelsToMask = void 0;
exports.aes128MmoHash = aes128MmoHash;
exports.aes128CcmStar = aes128CcmStar;
exports.computeAuthTag = computeAuthTag;
exports.combineSecurityControl = combineSecurityControl;
exports.makeNonce = makeNonce;
exports.registerDefaultHashedKeys = registerDefaultHashedKeys;
exports.makeKeyedHash = makeKeyedHash;
exports.makeKeyedHashByType = makeKeyedHashByType;
exports.decodeZigbeeSecurityHeader = decodeZigbeeSecurityHeader;
exports.encodeZigbeeSecurityHeader = encodeZigbeeSecurityHeader;
exports.decryptZigbeePayload = decryptZigbeePayload;
exports.encryptZigbeePayload = encryptZigbeePayload;
const node_crypto_1 = require("node:crypto");
function aes128MmoHashUpdate(result, data, dataSize) {
    while (dataSize >= 16 /* ZigbeeConsts.SEC_BLOCKSIZE */) {
        const cipher = (0, node_crypto_1.createCipheriv)("aes-128-ecb", result, null);
        const block = data.subarray(0, 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
        const u = cipher.update(block);
        const f = cipher.final();
        const encryptedBlock = Buffer.alloc(u.byteLength + f.byteLength);
        encryptedBlock.set(u, 0);
        encryptedBlock.set(f, u.byteLength);
        // XOR encrypted and plaintext
        for (let i = 0; i < 16 /* ZigbeeConsts.SEC_BLOCKSIZE */; i++) {
            result[i] = encryptedBlock[i] ^ block[i];
        }
        data = data.subarray(16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
        dataSize -= 16 /* ZigbeeConsts.SEC_BLOCKSIZE */;
    }
}
/**
 * See B.1.3 Cryptographic Hash Function
 *
 * AES-128-MMO (Matyas-Meyer-Oseas) hashing (using node 'crypto' built-in with 'aes-128-ecb')
 *
 * Used for Install Codes - see Document 13-0402-13 - 10.1
 */
function aes128MmoHash(data) {
    const hashResult = Buffer.alloc(16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    let remainingLength = data.byteLength;
    let position = 0;
    for (position; remainingLength >= 16 /* ZigbeeConsts.SEC_BLOCKSIZE */;) {
        const chunk = data.subarray(position, position + 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
        aes128MmoHashUpdate(hashResult, chunk, chunk.byteLength);
        position += 16 /* ZigbeeConsts.SEC_BLOCKSIZE */;
        remainingLength -= 16 /* ZigbeeConsts.SEC_BLOCKSIZE */;
    }
    const temp = Buffer.alloc(16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    temp.set(data.subarray(position, position + remainingLength), 0);
    // per the spec, concatenate a 1 bit followed by all zero bits
    temp[remainingLength] = 0x80;
    // if appending the bit string will push us beyond the 16-byte boundary, hash that block and append another 16-byte block
    if (16 /* ZigbeeConsts.SEC_BLOCKSIZE */ - remainingLength < 3) {
        aes128MmoHashUpdate(hashResult, temp, 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
        temp.fill(0);
    }
    temp[16 /* ZigbeeConsts.SEC_BLOCKSIZE */ - 2] = (data.byteLength >> 5) & 0xff;
    temp[16 /* ZigbeeConsts.SEC_BLOCKSIZE */ - 1] = (data.byteLength << 3) & 0xff;
    aes128MmoHashUpdate(hashResult, temp, 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    return hashResult.subarray(0, 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
}
/**
 * See A CCM* MODE OF OPERATION
 *
 * Used for Zigbee NWK layer encryption/decryption
 */
function aes128CcmStar(M, key, nonce, data) {
    const payloadLengthNoM = data.byteLength - M;
    const blockCount = 1 + Math.ceil(payloadLengthNoM / 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    const plaintext = Buffer.alloc(blockCount * 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    plaintext.set(data.subarray(-M), 0);
    plaintext.set(data.subarray(0, -M), 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    const cipher = (0, node_crypto_1.createCipheriv)("aes-128-ecb", key, null);
    const buffer = Buffer.alloc(blockCount * 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    const counter = Buffer.alloc(16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    counter[0] = 1 /* ZigbeeConsts.SEC_CCM_FLAG_L */;
    counter.set(nonce, 1);
    for (let blockNum = 0; blockNum < blockCount; blockNum++) {
        // big endian of size ZigbeeConsts.SEC_L
        counter[counter.byteLength - 2] = (blockNum >> 8) & 0xff;
        counter[counter.byteLength - 1] = blockNum & 0xff;
        const plaintextBlock = plaintext.subarray(16 /* ZigbeeConsts.SEC_BLOCKSIZE */ * blockNum, 16 /* ZigbeeConsts.SEC_BLOCKSIZE */ * (blockNum + 1));
        const cipherU = cipher.update(counter);
        // XOR cipher and plaintext
        for (let i = 0; i < cipherU.byteLength; i++) {
            cipherU[i] ^= plaintextBlock[i];
        }
        buffer.set(cipherU, 16 /* ZigbeeConsts.SEC_BLOCKSIZE */ * blockNum);
    }
    cipher.final();
    const authTag = buffer.subarray(0, M);
    const ciphertext = buffer.subarray(16 /* ZigbeeConsts.SEC_BLOCKSIZE */, 16 /* ZigbeeConsts.SEC_BLOCKSIZE */ + payloadLengthNoM);
    return [authTag, ciphertext];
}
/**
 * aes-128-cbc with iv as 0-filled block size
 *
 * Used for Zigbee NWK layer encryption/decryption
 */
function computeAuthTag(authData, M, key, nonce, data) {
    const startPaddedSize = Math.ceil((1 + nonce.byteLength + 2 /* ZigbeeConsts.SEC_L */ + 2 /* ZigbeeConsts.SEC_L */ + authData.byteLength) / 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    const endPaddedSize = Math.ceil(data.byteLength / 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    const prependAuthData = Buffer.alloc(startPaddedSize * 16 /* ZigbeeConsts.SEC_BLOCKSIZE */ + endPaddedSize * 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    let offset = 0;
    prependAuthData[offset] = ((((M - 2) / 2) & 0x7) << 3) | (authData.byteLength > 0 ? 0x40 : 0x00) | 1 /* ZigbeeConsts.SEC_CCM_FLAG_L */;
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
    const dataOffset = Math.ceil(offset / 16 /* ZigbeeConsts.SEC_BLOCKSIZE */) * 16 /* ZigbeeConsts.SEC_BLOCKSIZE */;
    prependAuthData.set(data, dataOffset);
    const cipher = (0, node_crypto_1.createCipheriv)("aes-128-cbc", key, Buffer.alloc(16 /* ZigbeeConsts.SEC_BLOCKSIZE */, 0));
    const cipherU = cipher.update(prependAuthData);
    cipher.final();
    const authTag = cipherU.subarray(-16 /* ZigbeeConsts.SEC_BLOCKSIZE */, -16 /* ZigbeeConsts.SEC_BLOCKSIZE */ + M);
    return authTag;
}
function combineSecurityControl(control, levelOverride) {
    return (((levelOverride !== undefined ? levelOverride : control.level) & 7 /* ZigbeeConsts.SEC_CONTROL_LEVEL */) |
        ((control.keyId << 3) & 24 /* ZigbeeConsts.SEC_CONTROL_KEY */) |
        (((control.nonce ? 1 : 0) << 5) & 32 /* ZigbeeConsts.SEC_CONTROL_NONCE */));
}
function makeNonce(header, source64, levelOverride) {
    const nonce = Buffer.alloc(13 /* ZigbeeConsts.SEC_NONCE_LEN */);
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
const defaultHashedKeys = [Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0)];
/**
 * Pre-hashing default keys makes decryptions ~5x faster
 */
function registerDefaultHashedKeys(link, nwk, transport, load) {
    defaultHashedKeys[0] = link;
    defaultHashedKeys[1] = nwk;
    defaultHashedKeys[2] = transport;
    defaultHashedKeys[3] = load;
}
/**
 * See B.1.4 Keyed Hash Function for Message Authentication
 *
 * @param key ZigBee Security Key (must be ZigbeeConsts.SEC_KEYSIZE) in length.
 * @param inputByte Input byte
 */
function makeKeyedHash(key, inputByte) {
    const hashOut = Buffer.alloc(16 /* ZigbeeConsts.SEC_BLOCKSIZE */ + 1);
    const hashIn = Buffer.alloc(2 * 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    for (let i = 0; i < 16 /* ZigbeeConsts.SEC_KEYSIZE */; i++) {
        // copy the key into hashIn and XOR with opad to form: (Key XOR opad)
        hashIn[i] = key[i] ^ 92 /* ZigbeeConsts.SEC_OPAD */;
        // copy the Key into hashOut and XOR with ipad to form: (Key XOR ipad)
        hashOut[i] = key[i] ^ 54 /* ZigbeeConsts.SEC_IPAD */;
    }
    // append the input byte to form: (Key XOR ipad) || text.
    hashOut[16 /* ZigbeeConsts.SEC_BLOCKSIZE */] = inputByte;
    // hash the contents of hashOut and append the contents to hashIn to form: (Key XOR opad) || H((Key XOR ipad) || text)
    hashIn.set(aes128MmoHash(hashOut), 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
    // hash the contents of hashIn to get the final result
    hashOut.set(aes128MmoHash(hashIn), 0);
    return hashOut.subarray(0, 16 /* ZigbeeConsts.SEC_BLOCKSIZE */);
}
/** Hash key if needed, else return `key` as is */
function makeKeyedHashByType(keyId, key) {
    switch (keyId) {
        case 1 /* ZigbeeKeyType.NWK */:
        case 0 /* ZigbeeKeyType.LINK */: {
            // NWK: decrypt with the PAN's current network key
            // LINK: decrypt with the unhashed link key assigned by the trust center to this source/destination pair
            return key;
        }
        case 2 /* ZigbeeKeyType.TRANSPORT */: {
            // decrypt with a Transport key, a hashed link key that protects network keys sent from the trust center
            return makeKeyedHash(key, 0x00);
        }
        case 3 /* ZigbeeKeyType.LOAD */: {
            // decrypt with a Load key, a hashed link key that protects link keys sent from the trust center
            return makeKeyedHash(key, 0x02);
        }
        default: {
            throw new Error(`Unsupported key ID ${keyId}`);
        }
    }
}
function decodeZigbeeSecurityHeader(data, offset, source64) {
    const control = data.readUInt8(offset);
    offset += 1;
    const level = 5 /* ZigbeeSecurityLevel.ENC_MIC32 */; // overrides control & ZigbeeConsts.SEC_CONTROL_LEVEL;
    const keyId = (control & 24 /* ZigbeeConsts.SEC_CONTROL_KEY */) >> 3;
    const nonce = Boolean((control & 32 /* ZigbeeConsts.SEC_CONTROL_NONCE */) >> 5);
    const frameCounter = data.readUInt32LE(offset);
    offset += 4;
    if (nonce) {
        source64 = data.readBigUInt64LE(offset);
        offset += 8;
    }
    let keySeqNum;
    if (keyId === 1 /* ZigbeeKeyType.NWK */) {
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
function encodeZigbeeSecurityHeader(data, offset, header) {
    data.writeUInt8(combineSecurityControl(header.control), offset);
    offset += 1;
    data.writeUInt32LE(header.frameCounter, offset);
    offset += 4;
    if (header.control.nonce) {
        data.writeBigUInt64LE(header.source64, offset);
        offset += 8;
    }
    if (header.control.keyId === 1 /* ZigbeeKeyType.NWK */) {
        data.writeUInt8(header.keySeqNum, offset);
        offset += 1;
    }
    return offset;
}
function decryptZigbeePayload(data, offset, key, source64) {
    const controlOffset = offset;
    const [header, hOutOffset] = decodeZigbeeSecurityHeader(data, offset, source64);
    let authTag;
    let decryptedPayload;
    if (header.source64 !== undefined) {
        const hashedKey = key ? makeKeyedHashByType(header.control.keyId, key) : defaultHashedKeys[header.control.keyId];
        const nonce = makeNonce(header, header.source64);
        const encryptedData = data.subarray(hOutOffset); // payload + auth tag
        [authTag, decryptedPayload] = aes128CcmStar(header.micLen, hashedKey, nonce, encryptedData);
        // take until end of securityHeader for auth tag computation
        const adjustedAuthData = data.subarray(0, hOutOffset);
        // patch the security level to ZigBee 3.0
        const origControl = adjustedAuthData[controlOffset];
        adjustedAuthData[controlOffset] &= ~7 /* ZigbeeConsts.SEC_CONTROL_LEVEL */;
        adjustedAuthData[controlOffset] |= 7 /* ZigbeeConsts.SEC_CONTROL_LEVEL */ & 5 /* ZigbeeSecurityLevel.ENC_MIC32 */;
        const computedAuthTag = computeAuthTag(adjustedAuthData, header.micLen, hashedKey, nonce, decryptedPayload);
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
function encryptZigbeePayload(data, offset, payload, header, key) {
    const controlOffset = offset;
    offset = encodeZigbeeSecurityHeader(data, offset, header);
    let authTag;
    let encryptedPayload;
    if (header.source64 !== undefined) {
        const hashedKey = key ? makeKeyedHashByType(header.control.keyId, key) : defaultHashedKeys[header.control.keyId];
        const nonce = makeNonce(header, header.source64, 5 /* ZigbeeSecurityLevel.ENC_MIC32 */);
        const adjustedAuthData = data.subarray(0, offset);
        // patch the security level to ZigBee 3.0
        const origControl = adjustedAuthData[controlOffset];
        adjustedAuthData[controlOffset] &= ~7 /* ZigbeeConsts.SEC_CONTROL_LEVEL */;
        adjustedAuthData[controlOffset] |= 7 /* ZigbeeConsts.SEC_CONTROL_LEVEL */ & 5 /* ZigbeeSecurityLevel.ENC_MIC32 */;
        const decryptedData = Buffer.alloc(payload.byteLength + header.micLen); // payload + auth tag
        decryptedData.set(payload, 0);
        // take nwkHeader + securityHeader for auth tag computation
        const computedAuthTag = computeAuthTag(adjustedAuthData, header.micLen, hashedKey, nonce, payload);
        decryptedData.set(computedAuthTag, payload.byteLength);
        // restore security level
        adjustedAuthData[controlOffset] = origControl;
        [authTag, encryptedPayload] = aes128CcmStar(header.micLen, hashedKey, nonce, decryptedData);
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
const convertChannelsToMask = (channels) => {
    return channels.reduce((a, c) => a + (1 << c), 0);
};
exports.convertChannelsToMask = convertChannelsToMask;
/**
 * Converts a uint32 channel mask to a channels array.
 * @param mask
 * @returns
 */
const convertMaskToChannels = (mask) => {
    const channels = [];
    for (const channel of [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]) {
        if ((2 ** channel) & mask) {
            channels.push(channel);
        }
    }
    return channels;
};
exports.convertMaskToChannels = convertMaskToChannels;
//# sourceMappingURL=zigbee.js.map