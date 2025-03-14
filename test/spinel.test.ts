import { describe, expect, it, vi } from "vitest";
import { SpinelCommandId } from "../src/spinel/commands.js";
import * as Hdlc from "../src/spinel/hdlc.js";
import { SpinelPropertyId } from "../src/spinel/properties.js";
import {
    type SpinelFrame,
    decodeSpinelFrame,
    encodeSpinelFrame,
    getPackedUInt,
    readPropertyE,
    readPropertyS,
    readPropertyStreamRaw,
    setPackedUInt,
    writePropertyE,
    writePropertyS,
} from "../src/spinel/spinel.js";
import { SpinelStatus } from "../src/spinel/statuses.js";

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
        const [macData, metadata] = readPropertyStreamRaw(decFrame.payload, 1);

        expect(macData).toStrictEqual(Buffer.from([0x03, 0x08, 0xd0, 0xff, 0xff, 0xff, 0xff, 0x07, 0xff, 0xcc]));
        expect(metadata).toStrictEqual({ rssi: -41, noiseFloor: -128, flags: 0 });
    });
});
