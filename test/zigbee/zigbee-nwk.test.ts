import { describe, expect, it } from "vitest";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    encodeZigbeeNWKFrame,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    type ZigbeeNWKHeader,
    ZigbeeNWKRouteDiscovery,
} from "../../src/zigbee/zigbee-nwk.js";

const NETWORK_KEY = Buffer.alloc(16);

describe("Zigbee NWK", () => {
    it("decodes multicast header and payload", () => {
        const buffer = Buffer.alloc(2 + 2 + 2 + 1 + 1 + 1 + 1);
        let offset = 0;
        offset = buffer.writeUInt16LE(ZigbeeNWKConsts.FCF_MULTICAST | ZigbeeNWKFrameType.DATA, offset);
        offset = buffer.writeUInt16LE(0x5678, offset);
        offset = buffer.writeUInt16LE(0x9abc, offset);
        offset = buffer.writeUInt8(3, offset);
        offset = buffer.writeUInt8(0x21, offset);
        offset = buffer.writeUInt8(0x55, offset);
        buffer.writeUInt8(0xee, offset);

        const [frameControl, headerOffset] = decodeZigbeeNWKFrameControl(buffer, 0);
        expect(frameControl.multicast).toStrictEqual(true);

        const [header, payloadOffset] = decodeZigbeeNWKHeader(buffer, headerOffset, frameControl);
        expect(header.destination16).toStrictEqual(0x5678);
        expect(buffer.readUInt8(payloadOffset)).toStrictEqual(0xee);

        const payload = decodeZigbeeNWKPayload(buffer, payloadOffset, NETWORK_KEY, undefined, frameControl, header);
        expect(payload).toStrictEqual(Buffer.from([0xee]));
    });

    it("throws when NWK header has no payload", () => {
        const buffer = Buffer.alloc(2 + 2 + 2 + 1 + 1);
        let offset = 0;
        offset = buffer.writeUInt16LE(ZigbeeNWKFrameType.DATA, offset);
        offset = buffer.writeUInt16LE(0x1001, offset);
        offset = buffer.writeUInt16LE(0x2002, offset);
        offset = buffer.writeUInt8(1, offset);
        buffer.writeUInt8(0x42, offset);

        const [frameControl, headerOffset] = decodeZigbeeNWKFrameControl(buffer, 0);

        expect(() => decodeZigbeeNWKHeader(buffer, headerOffset, frameControl)).toThrowError("Invalid NWK frame: no payload");
    });

    it("encodes multicast and end-device initiator flags", () => {
        const header: ZigbeeNWKHeader = {
            frameControl: {
                frameType: ZigbeeNWKFrameType.CMD,
                protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                multicast: true,
                security: false,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: true,
                endDeviceInitiator: true,
            },
            destination16: 0x1234,
            source16: 0x4321,
            radius: 5,
            seqNum: 9,
            source64: 0x00124b0012345678n,
        };

        const frame = encodeZigbeeNWKFrame(header, Buffer.from([0xaa]));
        const fcf = frame.readUInt16LE(0);

        expect((fcf & ZigbeeNWKConsts.FCF_MULTICAST) !== 0).toStrictEqual(true);
        expect((fcf & ZigbeeNWKConsts.FCF_END_DEVICE_INITIATOR) !== 0).toStrictEqual(true);
        expect(frame.subarray(frame.length - 1)).toStrictEqual(Buffer.from([0xaa]));
    });
});
