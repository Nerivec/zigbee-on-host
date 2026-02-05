import { describe, expect, it } from "vitest";
import { GlobalTlv, readZigbeeTlvs } from "../../src/zigbee/tlvs.js";
import { ZigbeeConsts } from "../../src/zigbee/zigbee.js";

function makeTlv(tag: number, value: Buffer): Buffer {
    if (value.length < 1) {
        throw new Error("Invalid TLV test data");
    }

    const buffer = Buffer.alloc(2 + value.length);

    buffer.writeUInt8(tag, 0);
    buffer.writeUInt8(value.length - 1, 1);
    value.copy(buffer, 2);

    return buffer;
}

describe("Zigbee TLVs", () => {
    it("parses local and common global TLVs", () => {
        const localTlv = makeTlv(1, Buffer.from([0xaa, 0xbb]));
        const manufacturerSpecific = makeTlv(GlobalTlv.MANUFACTURER_SPECIFIC, Buffer.from([0x34, 0x12, 0xde, 0xad]));
        const panIdConflict = makeTlv(GlobalTlv.PAN_ID_CONFLICT_REPORT, Buffer.from([0x11, 0x00]));
        const nextPanId = makeTlv(GlobalTlv.NEXT_PAN_ID, Buffer.from([0x22, 0x11]));
        const nextChannel = makeTlv(GlobalTlv.NEXT_CHANNEL_CHANGE, Buffer.from([0x04, 0x03, 0x02, 0x01]));
        const passphrase = makeTlv(GlobalTlv.SYMMETRIC_PASSPHRASE, Buffer.alloc(ZigbeeConsts.SEC_KEYSIZE, 0xab));
        const routerInfo = makeTlv(GlobalTlv.ROUTER_INFORMATION, Buffer.from([0x44, 0x33]));
        const fragmentation = makeTlv(GlobalTlv.FRAGMENTATION_PARAMETERS, Buffer.from([0x78, 0x56, 0x9a, 0xde, 0xbc]));
        const configParams = makeTlv(GlobalTlv.CONFIGURATION_PARAMETERS, Buffer.from([0x55, 0x44]));
        const capabilityExt = makeTlv(GlobalTlv.DEVICE_CAPABILITY_EXTENSION, Buffer.from([0x77, 0x66]));
        const supportKeyNegociation = makeTlv(
            GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS,
            Buffer.from([0x02, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x4b, 0x12, 0x00]),
        );

        const data = Buffer.concat([
            localTlv,
            manufacturerSpecific,
            panIdConflict,
            nextPanId,
            nextChannel,
            passphrase,
            routerInfo,
            fragmentation,
            configParams,
            capabilityExt,
            supportKeyNegociation,
        ]);

        const [globalTlvs, localTlvs, outOffset] = readZigbeeTlvs(data, 0);

        expect(outOffset).toStrictEqual(data.byteLength);
        expect(localTlvs.get(1)).toStrictEqual(Buffer.from([0xaa, 0xbb]));
        expect(globalTlvs[GlobalTlv.MANUFACTURER_SPECIFIC]).toStrictEqual({
            zigbeeManufacturerId: 0x1234,
            additionalData: Buffer.from([0xde, 0xad]),
        });
        expect(globalTlvs[GlobalTlv.PAN_ID_CONFLICT_REPORT]).toStrictEqual({ nwkPanIdConflictCount: 0x0011 });
        expect(globalTlvs[GlobalTlv.NEXT_PAN_ID]).toStrictEqual({ panId: 0x1122 });
        expect(globalTlvs[GlobalTlv.NEXT_CHANNEL_CHANGE]).toStrictEqual({ channel: 0x01020304 });
        expect(globalTlvs[GlobalTlv.SYMMETRIC_PASSPHRASE]?.passphrase).toStrictEqual(Buffer.alloc(ZigbeeConsts.SEC_KEYSIZE, 0xab));
        expect(globalTlvs[GlobalTlv.ROUTER_INFORMATION]).toStrictEqual({ bitmap: 0x3344 });
        expect(globalTlvs[GlobalTlv.FRAGMENTATION_PARAMETERS]).toStrictEqual({
            nwkAddress: 0x5678,
            fragmentationOptions: 0x9a,
            maxIncomingTransferUnit: 0xbcde,
        });
        expect(globalTlvs[GlobalTlv.CONFIGURATION_PARAMETERS]).toStrictEqual({ parameters: 0x4455 });
        expect(globalTlvs[GlobalTlv.DEVICE_CAPABILITY_EXTENSION]).toStrictEqual({ capabilityExtension: 0x6677 });
        expect(globalTlvs[GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS]).toStrictEqual({
            keyNegotiationProtocolsBitmask: 0x02,
            preSharedSecretsBitmask: 0x00,
            sourceDeviceEui64: 0x00124b0012345678n,
        });
    });

    it("parses supported key negotiation methods with optional sourceDeviceEui64", () => {
        const supportKeyNegociation = makeTlv(GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS, Buffer.from([0x02, 0x00]));
        const [globalTlvs] = readZigbeeTlvs(supportKeyNegociation, 0);

        expect(globalTlvs[GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS]).toStrictEqual({
            keyNegotiationProtocolsBitmask: 0x02,
            preSharedSecretsBitmask: 0x00,
            sourceDeviceEui64: undefined,
        });
    });

    it("parses fragmentation parameters with optional maxIncomingTransferUnit", () => {
        const optionsOnly = makeTlv(GlobalTlv.FRAGMENTATION_PARAMETERS, Buffer.from([0x12, 0x34, 0x56]));
        const [globalTlvs] = readZigbeeTlvs(optionsOnly, 0);

        expect(globalTlvs[GlobalTlv.FRAGMENTATION_PARAMETERS]).toStrictEqual({
            nwkAddress: 0x3412,
            fragmentationOptions: 0x56,
            maxIncomingTransferUnit: undefined,
        });
    });

    it("parses fragmentation parameters with optional fragmentationOptions,maxIncomingTransferUnit", () => {
        const optionsOnly = makeTlv(GlobalTlv.FRAGMENTATION_PARAMETERS, Buffer.from([0x12, 0x34]));
        const [globalTlvs] = readZigbeeTlvs(optionsOnly, 0);

        expect(globalTlvs[GlobalTlv.FRAGMENTATION_PARAMETERS]).toStrictEqual({
            nwkAddress: 0x3412,
            fragmentationOptions: undefined,
            maxIncomingTransferUnit: undefined,
        });
    });

    it("parses encapsulated TLVs", () => {
        const joinerNested = makeTlv(GlobalTlv.CONFIGURATION_PARAMETERS, Buffer.from([0xaa, 0x55]));
        const beaconNested = makeTlv(GlobalTlv.DEVICE_CAPABILITY_EXTENSION, Buffer.from([0x10, 0x00]));
        const bdbNested = makeTlv(GlobalTlv.PAN_ID_CONFLICT_REPORT, Buffer.from([0x01, 0x00]));

        const joiner = makeTlv(GlobalTlv.JOINER_ENCAPSULATION, joinerNested);
        const beacon = makeTlv(GlobalTlv.BEACON_APPENDIX_ENCAPSULATION, beaconNested);
        const bdb = makeTlv(GlobalTlv.BDB_ENCAPSULATION, bdbNested);

        const data = Buffer.concat([joiner, beacon, bdb]);
        const [globalTlvs] = readZigbeeTlvs(data, 0);

        expect(globalTlvs[GlobalTlv.JOINER_ENCAPSULATION]?.additionalTLVs[GlobalTlv.CONFIGURATION_PARAMETERS]).toStrictEqual({
            parameters: 0x55aa,
        });
        expect(globalTlvs[GlobalTlv.BEACON_APPENDIX_ENCAPSULATION]?.additionalTLVs[GlobalTlv.DEVICE_CAPABILITY_EXTENSION]).toStrictEqual({
            capabilityExtension: 0x0010,
        });
        expect(globalTlvs[GlobalTlv.BDB_ENCAPSULATION]?.additionalTLVs[GlobalTlv.PAN_ID_CONFLICT_REPORT]).toStrictEqual({
            nwkPanIdConflictCount: 0x0001,
        });
    });

    it("respects the offset parameter", () => {
        const padding = Buffer.from([0x00, 0x01, 0x02]);
        const tlv = makeTlv(GlobalTlv.NEXT_PAN_ID, Buffer.from([0x34, 0x12]));
        const data = Buffer.concat([padding, tlv]);

        const [globalTlvs, , outOffset] = readZigbeeTlvs(data, padding.byteLength);

        expect(outOffset).toStrictEqual(data.byteLength);
        expect(globalTlvs[GlobalTlv.NEXT_PAN_ID]).toStrictEqual({ panId: 0x1234 });
    });

    it("throws for malformed TLVs", () => {
        expect(() => readZigbeeTlvs(Buffer.from([0x00]), 0)).toThrow("Malformed TLVs");
        expect(() => readZigbeeTlvs(Buffer.from([0x40, 0x00]), 0)).toThrow("Malformed TLVs");
    });

    it("throws for duplicate known global TLVs", () => {
        const first = makeTlv(GlobalTlv.CONFIGURATION_PARAMETERS, Buffer.from([0x01, 0x00]));
        const second = makeTlv(GlobalTlv.CONFIGURATION_PARAMETERS, Buffer.from([0x02, 0x00]));

        expect(() => readZigbeeTlvs(Buffer.concat([first, second]), 0)).toThrow("Invalid duplicate global TLV found tag=75");
    });

    it("throws for duplicate known local TLVs", () => {
        const first = makeTlv(23, Buffer.from([0x01, 0x00]));
        const second = makeTlv(24, Buffer.from([0x01, 0x00]));
        const third = makeTlv(23, Buffer.from([0x02, 0x00]));

        expect(() => readZigbeeTlvs(Buffer.concat([first, second, third]), 0)).toThrow("Invalid duplicate local TLV found tag=23");
    });

    it("throws for nested encapsulation", () => {
        const joinerNested = makeTlv(GlobalTlv.CONFIGURATION_PARAMETERS, Buffer.from([0xaa, 0x55]));
        const beaconNested = makeTlv(GlobalTlv.DEVICE_CAPABILITY_EXTENSION, Buffer.from([0x10, 0x00]));
        const bdbNested = makeTlv(GlobalTlv.PAN_ID_CONFLICT_REPORT, Buffer.from([0x01, 0x00]));

        const joiner = makeTlv(GlobalTlv.JOINER_ENCAPSULATION, joinerNested);
        const beacon = makeTlv(GlobalTlv.BEACON_APPENDIX_ENCAPSULATION, beaconNested);
        const bdb = makeTlv(GlobalTlv.BDB_ENCAPSULATION, bdbNested);

        expect(() => readZigbeeTlvs(joiner, 0, GlobalTlv.JOINER_ENCAPSULATION)).toThrow("Invalid nested encapsulated TLV found");
        expect(() => readZigbeeTlvs(joiner, 0, GlobalTlv.BEACON_APPENDIX_ENCAPSULATION)).toThrow("Invalid nested encapsulated TLV found");
        expect(() => readZigbeeTlvs(joiner, 0, GlobalTlv.BDB_ENCAPSULATION)).toThrow("Invalid nested encapsulated TLV found");
        expect(() => readZigbeeTlvs(beacon, 0, GlobalTlv.JOINER_ENCAPSULATION)).toThrow("Invalid nested encapsulated TLV found");
        expect(() => readZigbeeTlvs(beacon, 0, GlobalTlv.BEACON_APPENDIX_ENCAPSULATION)).toThrow("Invalid nested encapsulated TLV found");
        expect(() => readZigbeeTlvs(beacon, 0, GlobalTlv.BDB_ENCAPSULATION)).toThrow("Invalid nested encapsulated TLV found");
        expect(() => readZigbeeTlvs(bdb, 0, GlobalTlv.JOINER_ENCAPSULATION)).toThrow("Invalid nested encapsulated TLV found");
        expect(() => readZigbeeTlvs(bdb, 0, GlobalTlv.BEACON_APPENDIX_ENCAPSULATION)).toThrow("Invalid nested encapsulated TLV found");
        expect(() => readZigbeeTlvs(bdb, 0, GlobalTlv.BDB_ENCAPSULATION)).toThrow("Invalid nested encapsulated TLV found");
    });

    it("throws for below-minimum TLV lengths", () => {
        const cases = [
            { tag: GlobalTlv.MANUFACTURER_SPECIFIC, length: 1 },
            { tag: GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS, length: 1 },
            { tag: GlobalTlv.PAN_ID_CONFLICT_REPORT, length: 1 },
            { tag: GlobalTlv.NEXT_PAN_ID, length: 1 },
            { tag: GlobalTlv.NEXT_CHANNEL_CHANGE, length: 3 },
            { tag: GlobalTlv.SYMMETRIC_PASSPHRASE, length: ZigbeeConsts.SEC_KEYSIZE - 1 },
            { tag: GlobalTlv.ROUTER_INFORMATION, length: 1 },
            { tag: GlobalTlv.FRAGMENTATION_PARAMETERS, length: 1 },
            { tag: GlobalTlv.JOINER_ENCAPSULATION, length: 1 },
            { tag: GlobalTlv.BEACON_APPENDIX_ENCAPSULATION, length: 1 },
            { tag: GlobalTlv.BDB_ENCAPSULATION, length: 1 },
            { tag: GlobalTlv.CONFIGURATION_PARAMETERS, length: 1 },
            { tag: GlobalTlv.DEVICE_CAPABILITY_EXTENSION, length: 1 },
        ];

        for (const { tag, length } of cases) {
            const tlv = makeTlv(tag, Buffer.alloc(length, 0x00));

            expect(() => readZigbeeTlvs(tlv, 0)).toThrow("Malformed TLV, below minimum length");
        }
    });
});
