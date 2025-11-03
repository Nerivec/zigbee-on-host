import { describe, expect, it } from "vitest";
import {
    aes128MmoHash,
    combineSecurityControl,
    computeAuthTag,
    convertChannelsToMask,
    convertMaskToChannels,
    decryptZigbeePayload,
    encryptZigbeePayload,
    makeKeyedHashByType,
    ZigbeeKeyType,
    type ZigbeeSecurityHeader,
    ZigbeeSecurityLevel,
} from "../../src/zigbee/zigbee.js";

const HASH_INPUT = Buffer.from(Array.from({ length: 31 }, (_value, index) => index + 1));
const HASH_EXPECTED = Buffer.from("b2fb36c3f68807b3536db9732b9f8a41", "hex");

const AUTH_DATA = Buffer.from([0x01, 0x02]);
const AUTH_KEY = Buffer.alloc(16, 0xaa);
const AUTH_NONCE = Buffer.alloc(13, 0xbb);
const AUTH_PAYLOAD = Buffer.from([0x05, 0x06, 0x07, 0x08, 0x09]);
const AUTH_EXPECTED = Buffer.from("69898f01", "hex");

describe("Zigbee core", () => {
    it("hashes data spanning an extra padding block", () => {
        const result = aes128MmoHash(HASH_INPUT);

        expect(result).toStrictEqual(HASH_EXPECTED);
    });

    it("computes auth tag with non-empty authenticated data", () => {
        const authTag = computeAuthTag(AUTH_DATA, 4, AUTH_KEY, AUTH_NONCE, AUTH_PAYLOAD);

        expect(authTag).toStrictEqual(AUTH_EXPECTED);
    });

    it("combines security control flags with nonce bit", () => {
        const value = combineSecurityControl({ level: ZigbeeSecurityLevel.ENC_MIC32, keyId: ZigbeeKeyType.LOAD, nonce: true });

        expect(value & 0x20).toStrictEqual(0x20);
    });

    it("throws on unsupported key type", () => {
        const key = Buffer.alloc(16, 0x11);

        expect(() => makeKeyedHashByType(0xff as ZigbeeKeyType, key)).toThrowError("Unsupported key ID");
    });

    it("throws when decrypting payload without nonce information", () => {
        const frame = Buffer.from([0x05, 0x01, 0x00, 0x00, 0x00]);

        expect(() => decryptZigbeePayload(frame, 0, undefined, undefined)).toThrowError("Unable to decrypt Zigbee payload");
    });

    it("throws when encrypting payload without nonce", () => {
        const header: ZigbeeSecurityHeader = {
            control: {
                level: ZigbeeSecurityLevel.ENC_MIC32,
                keyId: ZigbeeKeyType.NWK,
                nonce: false,
            },
            frameCounter: 0,
        };

        expect(() => encryptZigbeePayload(Buffer.alloc(32), 0, Buffer.from([0x01]), header)).toThrowError("Unable to encrypt Zigbee payload");
    });

    it("encrypts and decrypts using explicit key hashing path", () => {
        const header: ZigbeeSecurityHeader = {
            control: {
                level: ZigbeeSecurityLevel.ENC_MIC32,
                keyId: ZigbeeKeyType.NWK,
                nonce: true,
            },
            frameCounter: 1,
            source64: 0x00124b0000112233n,
            keySeqNum: 0,
            micLen: 4,
        };
        const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
        const key = Buffer.alloc(16, 0x22);
        const buffer = Buffer.alloc(64);

        const [encryptedPayload, authTag, headerOffset] = encryptZigbeePayload(buffer, 0, payload, header, key);
        const fullFrame = Buffer.concat([buffer.subarray(0, headerOffset), encryptedPayload, authTag]);
        const [decodedPayload, decodedHeader, outOffset] = decryptZigbeePayload(fullFrame, 0, key, header.source64);

        expect(decodedHeader.source64).toStrictEqual(header.source64);
        expect(decodedPayload.subarray(0, payload.byteLength)).toStrictEqual(payload);
        expect(outOffset).toBeGreaterThan(0);
    });

    it("converts channels to mask and back", () => {
        const input = [11, 15, 20, 26];
        const mask = convertChannelsToMask(input);
        const output = convertMaskToChannels(mask);

        expect(mask).toStrictEqual((1 << 11) | (1 << 15) | (1 << 20) | (1 << 26));
        expect(output).toStrictEqual(input);
    });
});
