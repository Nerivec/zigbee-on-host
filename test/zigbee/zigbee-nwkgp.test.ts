import { afterEach, describe, expect, it, vi } from "vitest";
import * as ZigbeeModule from "../../src/zigbee/zigbee.js";
import {
    decodeZigbeeNWKGPFrameControl,
    decodeZigbeeNWKGPHeader,
    decodeZigbeeNWKGPPayload,
    encodeZigbeeNWKGPFrame,
    ZigbeeNWKGPAppId,
    ZigbeeNWKGPCommandId,
    ZigbeeNWKGPConsts,
    ZigbeeNWKGPDirection,
    type ZigbeeNWKGPFrameControl,
    ZigbeeNWKGPFrameType,
    type ZigbeeNWKGPHeader,
    ZigbeeNWKGPSecurityLevel,
} from "../../src/zigbee/zigbee-nwkgp.js";

const NETWORK_KEY = Buffer.alloc(16);

describe("Zigbee NWK GP", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("decodes maintenance frame with ONELSB security and MIC", () => {
        const frame = Buffer.alloc(1 + 1 + 4 + 1 + 2);
        frame.writeUInt8(0x8d, 0); // maintenance frame with extension
        frame.writeUInt8(0x08, 1); // appId=DEFAULT, securityLevel=ONELSB
        frame.writeUInt32LE(0x04030201, 2);
        frame.writeUInt8(0x55, 6); // payload byte
        frame.writeUInt16LE(0xabcd, 7); // MIC

        const [frameControl, headerOffset] = decodeZigbeeNWKGPFrameControl(frame, 0);
        const [header, payloadOffset] = decodeZigbeeNWKGPHeader(frame, headerOffset, frameControl);
        const payload = decodeZigbeeNWKGPPayload(frame, payloadOffset, NETWORK_KEY, undefined, frameControl, header);

        expect(header.sourceId).toStrictEqual(0x04030201);
        expect(header.micSize).toStrictEqual(2);
        expect(header.mic).toStrictEqual(0xabcd);
        expect(header.payloadLength).toStrictEqual(1);
        expect(payload).toStrictEqual(Buffer.from([0x55]));
    });

    it("throws when NWK GP frame has no payload", () => {
        const frame = Buffer.alloc(1 + 1 + 4 + 2);
        frame.writeUInt8(0x8d, 0);
        frame.writeUInt8(0x08, 1);
        frame.writeUInt32LE(0x01020304, 2);
        frame.writeUInt16LE(0xabcd, 6);

        const [frameControl, headerOffset] = decodeZigbeeNWKGPFrameControl(frame, 0);

        expect(() => decodeZigbeeNWKGPHeader(frame, headerOffset, frameControl)).toThrowError("Zigbee NWK GP frame without payload");
    });

    it("keeps MIC size zero for LPED ONELSB frames", () => {
        const frame = Buffer.alloc(1 + 1 + 1);
        frame.writeUInt8(0x8c, 0); // data frame with extension
        frame.writeUInt8(0x09, 1); // appId=LPED, securityLevel=ONELSB
        frame.writeUInt8(0x33, 2);

        const [frameControl, headerOffset] = decodeZigbeeNWKGPFrameControl(frame, 0);
        const [header, payloadOffset] = decodeZigbeeNWKGPHeader(frame, headerOffset, frameControl);
        const payload = decodeZigbeeNWKGPPayload(frame, payloadOffset, NETWORK_KEY, undefined, frameControl, header);

        expect(header.frameControlExt?.appId).toStrictEqual(ZigbeeNWKGPAppId.LPED);
        expect(header.micSize).toStrictEqual(0);
        expect(payload).toStrictEqual(Buffer.from([0x33]));
    });

    it("encodes maintenance frame with default app id and source id", () => {
        const header: ZigbeeNWKGPHeader = {
            frameControl: {
                frameType: ZigbeeNWKGPFrameType.MAINTENANCE,
                protocolVersion: 3,
                autoCommissioning: false,
                nwkFrameControlExtension: true,
            },
            frameControlExt: {
                appId: ZigbeeNWKGPAppId.DEFAULT,
                securityLevel: ZigbeeNWKGPSecurityLevel.NO,
                securityKey: false,
                rxAfterTx: false,
                direction: ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD,
            },
            sourceId: 0x11223344,
            micSize: 0,
            payloadLength: 1,
        };

        const frame = encodeZigbeeNWKGPFrame(header, Buffer.from([ZigbeeNWKGPCommandId.COMMISSIONING]), NETWORK_KEY, undefined);

        expect(frame.byteLength).toStrictEqual(1 + 1 + 4 + 1);
        expect(frame.readUInt32LE(2)).toStrictEqual(0x11223344);
    });

    it("encodes LPED frame with FULL security and writes counter", () => {
        const header: ZigbeeNWKGPHeader = {
            frameControl: {
                frameType: ZigbeeNWKGPFrameType.DATA,
                protocolVersion: 3,
                autoCommissioning: false,
                nwkFrameControlExtension: true,
            },
            frameControlExt: {
                appId: ZigbeeNWKGPAppId.LPED,
                securityLevel: ZigbeeNWKGPSecurityLevel.FULL,
                securityKey: true,
                rxAfterTx: false,
                direction: ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD,
            },
            micSize: 4,
            securityFrameCounter: 0x01020304,
            payloadLength: 1,
        };
        const authTag = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]);

        vi.spyOn(ZigbeeModule, "computeAuthTag").mockReturnValue(authTag);
        vi.spyOn(ZigbeeModule, "aes128CcmStar").mockReturnValue([authTag, Buffer.alloc(0)]);

        const frame = encodeZigbeeNWKGPFrame(header, Buffer.from([0x01]), NETWORK_KEY, undefined);

        expect(frame.readUInt32LE(2)).toStrictEqual(0x01020304);
        expect(frame.subarray(-4)).toStrictEqual(authTag);
    });

    it("encodes frame control extension with rxAfterTx flag", () => {
        const header: ZigbeeNWKGPHeader = {
            frameControl: {
                frameType: ZigbeeNWKGPFrameType.DATA,
                protocolVersion: 3,
                autoCommissioning: false,
                nwkFrameControlExtension: true,
            },
            frameControlExt: {
                appId: ZigbeeNWKGPAppId.DEFAULT,
                securityLevel: ZigbeeNWKGPSecurityLevel.NO,
                securityKey: false,
                rxAfterTx: true,
                direction: ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD,
            },
            sourceId: 0x0a0b0c0d,
            micSize: 0,
            payloadLength: 1,
        };

        const frame = encodeZigbeeNWKGPFrame(header, Buffer.from([0x01]), NETWORK_KEY, undefined);

        expect(frame.readUInt8(1) & ZigbeeNWKGPConsts.FCF_EXT_RX_AFTER_TX).toStrictEqual(ZigbeeNWKGPConsts.FCF_EXT_RX_AFTER_TX);
    });

    it("throws when ZGP frame is missing IEEE source", () => {
        const frameControl: ZigbeeNWKGPFrameControl = {
            frameType: ZigbeeNWKGPFrameType.DATA,
            protocolVersion: 3,
            autoCommissioning: false,
            nwkFrameControlExtension: true,
        };
        const header: ZigbeeNWKGPHeader = {
            frameControl,
            frameControlExt: {
                appId: ZigbeeNWKGPAppId.ZGP,
                securityLevel: ZigbeeNWKGPSecurityLevel.FULLENCR,
                securityKey: true,
                rxAfterTx: false,
                direction: ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD,
            },
            micSize: 4,
            securityFrameCounter: 7,
            payloadLength: 1,
        };

        expect(() => decodeZigbeeNWKGPPayload(Buffer.alloc(4), 0, NETWORK_KEY, undefined, frameControl, header)).toThrowError(
            "Zigbee NWK GP frame missing IEEE source for AppId=ZGP",
        );
    });

    it("throws when FULLENCR payload authentication fails", () => {
        const frameControl: ZigbeeNWKGPFrameControl = {
            frameType: ZigbeeNWKGPFrameType.DATA,
            protocolVersion: 3,
            autoCommissioning: false,
            nwkFrameControlExtension: true,
        };
        const header: ZigbeeNWKGPHeader = {
            frameControl,
            frameControlExt: {
                appId: ZigbeeNWKGPAppId.DEFAULT,
                securityLevel: ZigbeeNWKGPSecurityLevel.FULLENCR,
                securityKey: true,
                rxAfterTx: false,
                direction: ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD,
            },
            sourceId: 0x55667788,
            micSize: 4,
            securityFrameCounter: 0x02030405,
            payloadLength: 1,
        };

        vi.spyOn(ZigbeeModule, "aes128CcmStar").mockReturnValue([Buffer.from([1, 2, 3, 4]), Buffer.from([0x42])]);
        vi.spyOn(ZigbeeModule, "computeAuthTag").mockReturnValue(Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]));

        expect(() =>
            decodeZigbeeNWKGPPayload(Buffer.from([0x10, 0x11, 0x12, 0x13, 0x14]), 0, NETWORK_KEY, undefined, frameControl, header),
        ).toThrowError("Auth tag mismatch while decrypting Zigbee NWK GP payload with FULLENCR security level");
    });

    it("throws when FULLENCR payload cannot be decrypted", () => {
        const frameControl: ZigbeeNWKGPFrameControl = {
            frameType: ZigbeeNWKGPFrameType.DATA,
            protocolVersion: 3,
            autoCommissioning: false,
            nwkFrameControlExtension: true,
        };
        const header: ZigbeeNWKGPHeader = {
            frameControl,
            frameControlExt: {
                appId: ZigbeeNWKGPAppId.DEFAULT,
                securityLevel: ZigbeeNWKGPSecurityLevel.FULLENCR,
                securityKey: true,
                rxAfterTx: false,
                direction: ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD,
            },
            sourceId: 0x01020304,
            micSize: 4,
            securityFrameCounter: 0x11121314,
            payloadLength: 1,
        };

        vi.spyOn(ZigbeeModule, "aes128CcmStar").mockReturnValue([Buffer.alloc(4), undefined as unknown as Buffer]);
        vi.spyOn(ZigbeeModule, "computeAuthTag").mockReturnValue(Buffer.alloc(4));

        expect(() => decodeZigbeeNWKGPPayload(Buffer.from([0x20, 0x21, 0x22, 0x23]), 0, NETWORK_KEY, undefined, frameControl, header)).toThrowError(
            "Unable to decrypt Zigbee NWK GP payload",
        );
    });
});
