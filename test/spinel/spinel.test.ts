import { describe, expect, it, vi } from "vitest";
import { SpinelCommandId } from "../../src/spinel/commands.js";
import * as Hdlc from "../../src/spinel/hdlc.js";
import { SpinelPropertyId } from "../../src/spinel/properties.js";
import {
    decodeSpinelFrame,
    encodeSpinelFrame,
    getPackedUInt,
    getPackedUIntSize,
    readPropertyAi,
    readPropertyb,
    readPropertyC,
    readPropertyc,
    readPropertyD,
    readPropertyd,
    readPropertyE,
    readPropertyi,
    readPropertyii,
    readPropertyS,
    readPropertyU,
    readStreamRaw,
    type SpinelFrame,
    setPackedUInt,
    writePropertyAC,
    writePropertyb,
    writePropertyC,
    writePropertyc,
    writePropertyD,
    writePropertyd,
    writePropertyE,
    writePropertyId,
    writePropertyi,
    writePropertyL,
    writePropertyl,
    writePropertyS,
    writePropertyStreamRaw,
    writePropertys,
    writePropertyU,
} from "../../src/spinel/spinel.js";
import { SpinelStatus } from "../../src/spinel/statuses.js";

describe("Spinel & HDLC", () => {
    const encodeHdlcFrameSpy = vi.spyOn(Hdlc, "encodeHdlcFrame");

    /** see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#appendix-B.1 */
    const packedUint21TestVectors: [number, string][] = [
        [0, "00"],
        [1, "01"],
        [127, "7f"],
        [128, "8001"],
        [129, "8101"],
        [1337, "b90a"],
        [16383, "ff7f"],
        [16384, "808001"],
        [16385, "818001"],
        [2097151, "ffff7f"],
    ];

    for (const [dec, hex] of packedUint21TestVectors) {
        it(`writes Packed Unsigned Integer: ${dec} => ${hex}`, () => {
            const buffer = Buffer.from("0ba124f50000000000", "hex");
            let offset = 4;
            offset = setPackedUInt(buffer, offset, dec);

            expect(offset).toStrictEqual(4 + hex.length / 2);
            expect(buffer.toString("hex").startsWith(`0ba124f5${hex}`)).toStrictEqual(true);
        });

        it(`reads Packed Unsigned Integer: ${hex} => ${dec}`, () => {
            const buffer = Buffer.from(`0ba124f5${hex}4f2f6b7caa`, "hex");
            let offset = 4;

            const [val, newOffset] = getPackedUInt(buffer, offset);
            offset = newOffset;

            expect(offset).toStrictEqual(4 + hex.length / 2);
            expect(val).toStrictEqual(dec);
        });
    }

    it("writePropertyE & readPropertyE", () => {
        const buf = writePropertyE(SpinelPropertyId.MAC_15_4_LADDR, 123n);

        expect(buf).toStrictEqual(Buffer.from([52, 0, 0, 0, 0, 0, 0, 0, 123]));

        const val = readPropertyE(SpinelPropertyId.MAC_15_4_LADDR, buf);

        expect(val).toStrictEqual(123n);
    });

    it("writePropertyS & readPropertyS", () => {
        const buf = writePropertyS(SpinelPropertyId.MAC_15_4_PANID, 43993);

        expect(buf).toStrictEqual(Buffer.from([54, 217, 171]));

        const val = readPropertyS(SpinelPropertyId.MAC_15_4_PANID, buf);

        expect(val).toStrictEqual(43993);
    });

    it("writePropertyAC", () => {
        const buf = writePropertyAC(SpinelPropertyId.MAC_SCAN_MASK, [11, 15, 20, 25]);

        expect(buf).toStrictEqual(Buffer.from([49, 11, 15, 20, 25]));
    });

    /** see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#appendix-B.2 */
    const resetCommandTestVectorFrame: SpinelFrame = {
        header: { tid: 0, nli: 0, flg: 2 },
        commandId: SpinelCommandId.RESET,
        payload: Buffer.alloc(0),
    };
    const resetCommandTestVectorHex = "8001";
    /** verified with code from https://github.com/openthread/openthread/tree/main/src/lib/hdlc */
    const resetCommandTestVectorHdlcHex = "7e800102927e";

    it("writes Reset Command to HDLC", () => {
        const encFrame = encodeSpinelFrame(resetCommandTestVectorFrame);

        expect(encFrame).toBeDefined();
        expect(encodeHdlcFrameSpy).toHaveBeenCalledTimes(1);
        expect(encodeHdlcFrameSpy.mock.calls[0][0].toString("hex")).toStrictEqual(resetCommandTestVectorHex);
        expect(encFrame.length).toStrictEqual(6);
        expect(encFrame.data.subarray(0, encFrame.length)).toStrictEqual(Buffer.from(resetCommandTestVectorHdlcHex, "hex"));
        expect(encFrame.fcs).toStrictEqual(Hdlc.HDLC_GOOD_FCS);
    });

    /** see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#appendix-B.3 */
    const resetNotificationTestVectorFrame: SpinelFrame = {
        header: { tid: 0, nli: 0, flg: 2 },
        commandId: SpinelCommandId.PROP_VALUE_IS,
        // these are technically packed uint21 but we know values are uint8, we can cheat
        payload: Buffer.from([SpinelPropertyId.LAST_STATUS, SpinelStatus.RESET_SOFTWARE]),
    };
    const resetNotificationTestVectorHex = "80060072";
    /** verified with code from https://github.com/openthread/openthread/tree/main/src/lib/hdlc */
    const resetNotificationTestVectorHdlcHex = "7e80060072fc577e";

    it("reads Reset Notification from HDLC", () => {
        const decHdlcFrame = Hdlc.decodeHdlcFrame(Buffer.from(resetNotificationTestVectorHdlcHex, "hex"));

        expect(decHdlcFrame.length).toStrictEqual(resetNotificationTestVectorHex.length / 2);
        expect(decHdlcFrame.data.subarray(0, decHdlcFrame.length)).toStrictEqual(Buffer.from(resetNotificationTestVectorHex, "hex"));
        expect(decHdlcFrame.fcs).toStrictEqual(Hdlc.HDLC_GOOD_FCS);

        const decFrame = decodeSpinelFrame(decHdlcFrame);

        expect(decFrame).toStrictEqual(resetNotificationTestVectorFrame);
    });

    it("reads Spinel STREAM_RAW metadata", () => {
        const payload = Buffer.from([
            0x7e, 0x80, 0x06, 0x71, 0x0a, 0x00, 0x03, 0x08, 0xd0, 0xff, 0xff, 0xff, 0xff, 0x07, 0xff, 0xcc, 0xd7, 0x80, 0x00, 0x00, 0x0a, 0x00, 0x19,
            0xff, 0xc3, 0x0c, 0xc7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0xe9, 0x7e,
        ]);
        const decHdlcFrame = Hdlc.decodeHdlcFrame(payload);
        const decFrame = decodeSpinelFrame(decHdlcFrame);
        const [macData, metadata] = readStreamRaw(decFrame.payload, 1);

        expect(macData).toStrictEqual(Buffer.from([0x03, 0x08, 0xd0, 0xff, 0xff, 0xff, 0xff, 0x07, 0xff, 0xcc]));
        expect(metadata).toStrictEqual({ rssi: -41, noiseFloor: -128, flags: 0 });
    });

    it("getPackedUIntSize handles boundary conditions", () => {
        expect(getPackedUIntSize(0)).toStrictEqual(1);
        expect(getPackedUIntSize((1 << 7) - 1)).toStrictEqual(1);
        expect(getPackedUIntSize(1 << 7)).toStrictEqual(2);
        expect(getPackedUIntSize((1 << 14) - 1)).toStrictEqual(2);
        expect(getPackedUIntSize(1 << 14)).toStrictEqual(3);
        expect(getPackedUIntSize((1 << 21) - 1)).toStrictEqual(3);
        expect(getPackedUIntSize(1 << 21)).toStrictEqual(4);
        expect(getPackedUIntSize((1 << 28) - 1)).toStrictEqual(4);
        expect(getPackedUIntSize(1 << 28)).toStrictEqual(5);
    });

    it("setPackedUInt respects explicit size hints", () => {
        const value = 0x1fffff;
        const size = getPackedUIntSize(value);
        const autoBuf = Buffer.alloc(size);
        const autoOffset = setPackedUInt(autoBuf, 0, value);

        expect(autoOffset).toStrictEqual(size);

        const manualBuf = Buffer.alloc(size);
        const manualOffset = setPackedUInt(manualBuf, 0, value, size);

        expect(manualOffset).toStrictEqual(size);
        expect(manualBuf).toStrictEqual(autoBuf);
    });

    it("getPackedUInt rejects overly long encodings", () => {
        const invalidEncoding = Buffer.from([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]);

        expect(() => getPackedUInt(invalidEncoding, 0)).toThrowError("Invalid Packed UInt, got 42, expected < 40");
    });

    it("writes and reads scalar Spinel properties", () => {
        const boolBuf = writePropertyb(SpinelPropertyId.POWER_STATE, true);

        expect(readPropertyb(SpinelPropertyId.POWER_STATE, boolBuf)).toStrictEqual(true);

        const uint8Val = 222;
        const uint8Buf = writePropertyC(SpinelPropertyId.INTERFACE_COUNT, uint8Val);

        expect(readPropertyC(SpinelPropertyId.INTERFACE_COUNT, uint8Buf)).toStrictEqual(uint8Val);

        const int8Val = -12;
        const int8Buf = writePropertyc(SpinelPropertyId.LOCK, int8Val);

        expect(readPropertyc(SpinelPropertyId.LOCK, int8Buf)).toStrictEqual(int8Val);

        const int16Val = -1234;
        const int16Buf = writePropertys(SpinelPropertyId.HBO_BLOCK_MAX, int16Val);
        const [, int16Offset] = getPackedUInt(int16Buf, 0);

        expect(int16Buf.readInt16LE(int16Offset)).toStrictEqual(int16Val);

        const uint32Val = 0x89abcdef;
        const uint32Buf = writePropertyL(SpinelPropertyId.VENDOR_ID, uint32Val);
        const [, uint32Offset] = getPackedUInt(uint32Buf, 0);

        expect(uint32Buf.readUInt32LE(uint32Offset)).toStrictEqual(uint32Val);

        const int32Val = -123456789;
        const int32Buf = writePropertyl(SpinelPropertyId.LOCK, int32Val);
        const [, int32Offset] = getPackedUInt(int32Buf, 0);

        expect(int32Buf.readInt32LE(int32Offset)).toStrictEqual(int32Val);

        const packedVal = 0x12345;
        const packedBuf = writePropertyi(SpinelPropertyId.INTERFACE_TYPE, packedVal);

        expect(readPropertyi(SpinelPropertyId.INTERFACE_TYPE, packedBuf)).toStrictEqual(packedVal);
    });

    it("reads packed integer aggregates", () => {
        const protocolId = SpinelPropertyId.PROTOCOL_VERSION;
        const major = 4;
        const minor = 3;
        const [pairBuf, pairOffset] = writePropertyId(protocolId, getPackedUIntSize(major) + getPackedUIntSize(minor));
        let cursor = setPackedUInt(pairBuf, pairOffset, major);
        setPackedUInt(pairBuf, cursor, minor);

        expect(readPropertyii(protocolId, pairBuf)).toStrictEqual([major, minor]);

        const caps = [1, 127, 300];
        const capsSize = caps.reduce((acc, cap) => acc + getPackedUIntSize(cap), 0);
        const [capsBuf, capsOffset] = writePropertyId(SpinelPropertyId.CAPS, capsSize);
        cursor = capsOffset;

        for (const cap of caps) {
            cursor = setPackedUInt(capsBuf, cursor, cap);
        }

        expect(readPropertyAi(SpinelPropertyId.CAPS, capsBuf)).toStrictEqual(caps);
    });

    it("writes and reads string and buffer properties", () => {
        const versionStr = "OpenThread";
        const strBuf = writePropertyU(SpinelPropertyId.NCP_VERSION, versionStr);

        expect(readPropertyU(SpinelPropertyId.NCP_VERSION, strBuf)).toStrictEqual(versionStr);

        const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
        const lenBuf = writePropertyd(SpinelPropertyId.HBO_MEM_MAX, payload);

        expect(readPropertyd(SpinelPropertyId.HBO_MEM_MAX, lenBuf)).toStrictEqual(payload);

        const remainderBuf = writePropertyD(SpinelPropertyId.HBO_BLOCK_MAX, payload);

        expect(readPropertyD(SpinelPropertyId.HBO_BLOCK_MAX, remainderBuf)).toStrictEqual(payload);
    });

    it("writes STREAM_RAW frames with metadata", () => {
        const macPayload = Buffer.from([0xaa, 0xbb, 0xcc]);
        const config = {
            txChannel: 11,
            ccaBackoffAttempts: 2,
            ccaRetries: 3,
            enableCSMACA: false,
            headerUpdated: true,
            reTx: true,
            securityProcessed: false,
            txDelay: 0x11223344,
            txDelayBaseTime: 0x55667788,
            rxChannelAfterTxDone: 15,
        } as const;
        const buf = writePropertyStreamRaw(macPayload, config);
        const [propId, offset] = getPackedUInt(buf, 0);

        expect(propId).toStrictEqual(SpinelPropertyId.STREAM_RAW);

        let cursor = offset;
        const length = buf.readUInt16LE(cursor);
        cursor += 2;

        expect(length).toStrictEqual(macPayload.byteLength);
        expect(buf.subarray(cursor, cursor + macPayload.byteLength)).toStrictEqual(macPayload);
        cursor += macPayload.byteLength;
        expect(buf.readUInt8(cursor)).toStrictEqual(config.txChannel);
        cursor += 1;
        expect(buf.readUInt8(cursor)).toStrictEqual(config.ccaBackoffAttempts);
        cursor += 1;
        expect(buf.readUInt8(cursor)).toStrictEqual(config.ccaRetries);
        cursor += 1;
        expect(buf.readUInt8(cursor)).toStrictEqual(0);
        cursor += 1;
        expect(buf.readUInt8(cursor)).toStrictEqual(1);
        cursor += 1;
        expect(buf.readUInt8(cursor)).toStrictEqual(1);
        cursor += 1;
        expect(buf.readUInt8(cursor)).toStrictEqual(0);
        cursor += 1;
        expect(buf.readUInt32LE(cursor)).toStrictEqual(config.txDelay);
        cursor += 4;
        expect(buf.readUInt32LE(cursor)).toStrictEqual(config.txDelayBaseTime);
        cursor += 4;
        expect(buf.readUInt8(cursor)).toStrictEqual(config.rxChannelAfterTxDone);

        const altConfig = {
            txChannel: 20,
            ccaBackoffAttempts: 4,
            ccaRetries: 5,
            enableCSMACA: true,
            headerUpdated: false,
            reTx: false,
            securityProcessed: true,
            txDelay: 1,
            txDelayBaseTime: 2,
            rxChannelAfterTxDone: 26,
        } as const;
        const altBuf = writePropertyStreamRaw(macPayload, altConfig);
        const [, altOffset] = getPackedUInt(altBuf, 0);
        let altCursor = altOffset;
        const altLength = altBuf.readUInt16LE(altCursor);
        altCursor += 2;

        expect(altLength).toStrictEqual(macPayload.byteLength);
        altCursor += macPayload.byteLength;
        altCursor += 3; // skip tx channel, backoff attempts, retries
        expect(altBuf.readUInt8(altCursor)).toStrictEqual(1);
        altCursor += 1;
        expect(altBuf.readUInt8(altCursor)).toStrictEqual(0);
        altCursor += 1;
        expect(altBuf.readUInt8(altCursor)).toStrictEqual(0);
        altCursor += 1;
        expect(altBuf.readUInt8(altCursor)).toStrictEqual(1);
    });

    it("reads STREAM_RAW frames without metadata", () => {
        const macPayload = Buffer.from([0x01, 0x02, 0x03, 0x04]);
        const payload = Buffer.alloc(2 + macPayload.byteLength);
        payload.writeUInt16LE(macPayload.byteLength, 0);
        macPayload.copy(payload, 2);

        const [macData, metadata] = readStreamRaw(payload, 0);

        expect(macData).toStrictEqual(macPayload);
        expect(metadata).toBeUndefined();
    });

    it("decodeHdlcFrame rejects oversized buffers", () => {
        const oversized = Buffer.alloc(Hdlc.HDLC_TX_CHUNK_SIZE + 1);

        expect(() => Hdlc.decodeHdlcFrame(oversized)).toThrowError("HDLC frame too long");
    });

    it("decodeHdlcFrame rejects frames with invalid FCS", () => {
        const invalid = Buffer.from([Hdlc.HdlcReservedByte.FLAG, 0x01, 0x02, Hdlc.HdlcReservedByte.FLAG]);

        expect(() => Hdlc.decodeHdlcFrame(invalid)).toThrowError("HDLC parsing error");
    });

    it("encodeHdlcFrame rejects oversized payloads", () => {
        const oversizedPayload = Buffer.alloc(Hdlc.HDLC_TX_CHUNK_SIZE + 1);

        expect(() => Hdlc.encodeHdlcFrame(oversizedPayload)).toThrowError("HDLC frame would be too long");
    });
});
