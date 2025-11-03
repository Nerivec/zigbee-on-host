import { describe, expect, it } from "vitest";
import {
    decodeZigbeeAPSFrameControl,
    decodeZigbeeAPSHeader,
    encodeZigbeeAPSFrame,
    encodeZigbeeAPSHeader,
    ZigbeeAPSConsts,
    ZigbeeAPSDeliveryMode,
    ZigbeeAPSFragmentation,
    ZigbeeAPSFrameType,
    type ZigbeeAPSHeader,
} from "../../src/zigbee/zigbee-aps.js";

describe("Zigbee APS", () => {
    it("decodes ACK frames using compact ack format", () => {
        const buffer = Buffer.from([0x12, 0x33]);

        const [decodedFCF, headerOffset] = decodeZigbeeAPSFrameControl(buffer, 0);
        expect(decodedFCF.ackFormat).toStrictEqual(true);

        const [header, offset] = decodeZigbeeAPSHeader(buffer, headerOffset, decodedFCF);
        expect(header.destEndpoint).toBeUndefined();
        expect(header.clusterId).toBeUndefined();
        expect(header.sourceEndpoint).toBeUndefined();
        expect(header.counter).toStrictEqual(0x33);
        expect(offset).toStrictEqual(buffer.byteLength);
    });

    it("decodes ACK frames with extended fragmentation header", () => {
        const frame = Buffer.alloc(1 + 1 + 2 + 2 + 1 + 1 + 1 + 1 + 1);
        let offset = 0;
        const fcf = ZigbeeAPSFrameType.ACK | (ZigbeeAPSDeliveryMode.UNICAST << 2) | ZigbeeAPSConsts.FCF_EXT_HEADER;
        offset = frame.writeUInt8(fcf, offset);
        offset = frame.writeUInt8(0x05, offset); // dest endpoint
        offset = frame.writeUInt16LE(0x1234, offset); // cluster
        offset = frame.writeUInt16LE(0x5678, offset); // profile
        offset = frame.writeUInt8(0x06, offset); // source endpoint
        offset = frame.writeUInt8(0xaa, offset); // counter
        offset = frame.writeUInt8(ZigbeeAPSFragmentation.MIDDLE, offset); // fragmentation flag
        offset = frame.writeUInt8(0x03, offset); // block number
        frame.writeUInt8(0xfe, offset); // ack bitfield

        const [frameControl, headerOffset] = decodeZigbeeAPSFrameControl(frame, 0);
        const [header] = decodeZigbeeAPSHeader(frame, headerOffset, frameControl);

        expect(header.fragmentation).toStrictEqual(ZigbeeAPSFragmentation.MIDDLE);
        expect(header.fragBlockNumber).toStrictEqual(0x03);
        expect(header.fragACKBitfield).toStrictEqual(0xfe);
    });

    it("decodes INTERPAN frames without counter", () => {
        const frame = Buffer.alloc(1 + 2 + 2);
        frame.writeUInt8(ZigbeeAPSFrameType.INTERPAN, 0);
        frame.writeUInt16LE(0x1111, 1);
        frame.writeUInt16LE(0x2222, 3);

        const [frameControl, headerOffset] = decodeZigbeeAPSFrameControl(frame, 0);
        frameControl.deliveryMode = ZigbeeAPSDeliveryMode.BCAST;

        const [header, payloadOffset] = decodeZigbeeAPSHeader(frame, headerOffset, frameControl);
        expect(header.counter).toBeUndefined();
        expect(payloadOffset).toStrictEqual(frame.byteLength);
    });

    it("throws for invalid delivery mode during decoding", () => {
        const buffer = Buffer.alloc(5);
        buffer.writeUInt8(0x00, 0);
        buffer.writeUInt16LE(0x1111, 1);
        buffer.writeUInt16LE(0x2222, 3);

        const invalidFrameControl = {
            frameType: ZigbeeAPSFrameType.DATA,
            deliveryMode: 0xff,
            ackFormat: false,
            security: false,
            ackRequest: false,
            extendedHeader: false,
        };

        expect(() => decodeZigbeeAPSHeader(buffer, 1, invalidFrameControl)).toThrowError("Invalid APS delivery mode");
    });

    it("encodes ACK header with ack format flag", () => {
        const header: ZigbeeAPSHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.ACK,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: true,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            counter: 0x11,
        };

        const buffer = Buffer.alloc(2);
        encodeZigbeeAPSHeader(buffer, 0, header);
        const fcf = buffer.readUInt8(0);

        expect((fcf & ZigbeeAPSConsts.FCF_ACK_FORMAT) !== 0).toStrictEqual(true);
    });

    it("throws for invalid delivery mode during encoding", () => {
        const header: ZigbeeAPSHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: 0xff as ZigbeeAPSDeliveryMode,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            destEndpoint: 0x01,
            clusterId: 0x1234,
            profileId: 0x2345,
            sourceEndpoint: 0x02,
            counter: 0x10,
        };

        const buffer = Buffer.alloc(10);
        expect(() => encodeZigbeeAPSHeader(buffer, 0, header)).toThrowError("Invalid APS delivery mode");
    });

    it("round-trips APS frame with payload via encode/decode", () => {
        const header: ZigbeeAPSHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.GROUP,
                ackFormat: false,
                security: false,
                ackRequest: true,
                extendedHeader: false,
            },
            group: 0x1001,
            clusterId: 0x2222,
            profileId: 0x3333,
            sourceEndpoint: 0x0a,
            counter: 0x44,
        };

        const payload = Buffer.from([0xde, 0xad]);
        const frame = encodeZigbeeAPSFrame(header, payload);
        const [decodedFCF, headerOffset] = decodeZigbeeAPSFrameControl(frame, 0);
        const [roundHeader, payloadOffset] = decodeZigbeeAPSHeader(frame, headerOffset, decodedFCF);
        const decodedPayload = frame.subarray(payloadOffset);

        expect(roundHeader.group).toStrictEqual(0x1001);
        expect(decodedPayload).toStrictEqual(payload);
    });
});
