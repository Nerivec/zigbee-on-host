import { type Socket, createSocket } from "node:dgram";
import { rmSync } from "node:fs";
import { type MockInstance, afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_WIRESHARK_IP, DEFAULT_ZEP_UDP_PORT, createWiresharkZEPFrame } from "../src/dev/wireshark";
import { OTRCPDriver } from "../src/drivers/ot-rcp-driver";
import { SpinelCommandId } from "../src/spinel/commands";
import { SpinelPropertyId } from "../src/spinel/properties";
import { SPINEL_HEADER_FLG_SPINEL, encodeSpinelFrame } from "../src/spinel/spinel";
import { SpinelStatus } from "../src/spinel/statuses";
import { MACAssociationStatus, decodeMACFrameControl, decodeMACHeader } from "../src/zigbee/mac";
import { ZigbeeConsts } from "../src/zigbee/zigbee";
import { type ZigbeeNWKLinkStatus, ZigbeeNWKManyToOne, ZigbeeNWKStatus } from "../src/zigbee/zigbee-nwk";
import {
    A_CHANNEL,
    A_EUI64,
    NET2_ASSOC_REQ_FROM_DEVICE,
    NET2_BEACON_REQ_FROM_DEVICE,
    NET2_COORD_EUI64_BIGINT,
    NET2_DATA_RQ_FROM_DEVICE,
    NET2_DEVICE_ANNOUNCE_BCAST,
    NET2_EXTENDED_PAN_ID,
    NET2_NODE_DESC_REQ_FROM_DEVICE,
    NET2_PAN_ID,
    NET2_REQUEST_KEY_TC_FROM_DEVICE,
    NET2_TRANSPORT_KEY_NWK_FROM_COORD,
    NET2_VERIFY_KEY_TC_FROM_DEVICE,
    NET3_COORD_EUI64_BIGINT,
    NET3_EXTENDED_PAN_ID,
    NET3_NETWORK_KEY,
    NET3_PAN_ID,
    NET3_ROUTE_RECORD,
    NET4_CHANNEL,
    NET4_COORD_EUI64_BIGINT,
    NET4_ROUTE_RECORD_FROM_4B8E_RELAY_CB47,
    NET4_ROUTE_RECORD_FROM_9ED5_RELAY_91D2,
    NET4_ROUTE_RECORD_FROM_91D2_NO_RELAY,
    NET4_ROUTE_RECORD_FROM_96BA_NO_RELAY,
    NET4_ROUTE_RECORD_FROM_6887_RELAY_96BA,
    NETDEF_ACK_FRAME_FROM_COORD,
    NETDEF_ACK_FRAME_TO_COORD,
    NETDEF_EXTENDED_PAN_ID,
    NETDEF_LINK_STATUS_FROM_DEV,
    NETDEF_MTORR_FRAME_FROM_COORD,
    NETDEF_NETWORK_KEY,
    NETDEF_PAN_ID,
    NETDEF_ROUTE_RECORD_TO_COORD,
    NETDEF_TC_KEY,
    NETDEF_ZCL_FRAME_CMD_TO_COORD,
    NETDEF_ZGP_COMMISSIONING,
} from "./data";

const SAVE_DIR = "temp";

describe("OT RCP Driver", () => {
    let driver: OTRCPDriver;
    let wiresharkSeqNum: number;
    let wiresharkSocket: Socket | undefined;
    let setTimeoutSpy: MockInstance<typeof setTimeout>;

    const nextWiresharkSeqNum = (): number => {
        wiresharkSeqNum = (wiresharkSeqNum + 1) & 0xffffffff;

        return wiresharkSeqNum + 1;
    };

    // biome-ignore lint/correctness/noUnusedVariables: local testing only
    const setupWireshark = (): void => {
        wiresharkSeqNum = 0; // start at 1
        wiresharkSocket = createSocket("udp4");
        wiresharkSocket.bind(DEFAULT_ZEP_UDP_PORT);

        driver.on("macFrame", (payload, rssi) => {
            const wsZEPFrame = createWiresharkZEPFrame(driver.netParams.channel, 1, 0, rssi ?? 0, nextWiresharkSeqNum(), payload);

            wiresharkSocket?.send(wsZEPFrame, DEFAULT_ZEP_UDP_PORT, DEFAULT_WIRESHARK_IP);
        });
    };

    const endWireshark = async (): Promise<void> => {
        if (wiresharkSocket) {
            await new Promise<void>((resolve) => wiresharkSocket?.close(() => resolve()));
        }
    };

    const makeSpinelLastStatus = (tid: number, status: SpinelStatus = SpinelStatus.OK): Buffer => {
        const respSpinelFrame = {
            header: {
                tid,
                nli: 0,
                flg: SPINEL_HEADER_FLG_SPINEL,
            },
            commandId: SpinelCommandId.PROP_VALUE_IS,
            payload: Buffer.from([SpinelPropertyId.LAST_STATUS, status]),
        };
        const encRespHdlcFrame = encodeSpinelFrame(respSpinelFrame);

        return Buffer.from(encRespHdlcFrame.data.subarray(0, encRespHdlcFrame.length));
    };

    const makeSpinelStreamRaw = (tid: number, macFrame: Buffer): Buffer => {
        const spinelFrame = {
            header: {
                tid,
                nli: 0,
                flg: SPINEL_HEADER_FLG_SPINEL,
            },
            commandId: SpinelCommandId.PROP_VALUE_IS,
            payload: Buffer.from([SpinelPropertyId.STREAM_RAW, macFrame.byteLength & 0xff, (macFrame.byteLength >> 8) & 0xff, ...macFrame]),
        };
        const encHdlcFrame = encodeSpinelFrame(spinelFrame);

        return Buffer.from(encHdlcFrame.data.subarray(0, encHdlcFrame.length));
    };

    beforeAll(() => {
        vi.useFakeTimers();

        setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");
    });

    afterAll(() => {
        vi.useRealTimers();

        rmSync(SAVE_DIR, { recursive: true, force: true });
    });

    beforeEach(() => {
        if (driver) {
            rmSync(driver.savePath, { recursive: true, force: true });
        }

        setTimeoutSpy.mockClear();
    });

    afterEach(async () => {
        await endWireshark();
    });

    describe("State management", () => {
        beforeEach(() => {
            driver = new OTRCPDriver(
                {
                    txChannel: A_CHANNEL,
                    ccaBackoffAttempts: 1,
                    ccaRetries: 4,
                    enableCSMACA: true,
                    headerUpdated: true,
                    reTx: false,
                    securityProcessed: true,
                    txDelay: 0,
                    txDelayBaseTime: 0,
                    rxChannelAfterTxDone: A_CHANNEL,
                },
                {
                    eui64: Buffer.from(A_EUI64).readBigUInt64LE(0),
                    panId: NETDEF_PAN_ID,
                    extendedPANId: Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0),
                    channel: A_CHANNEL,
                    nwkUpdateId: 0,
                    txPower: 10,
                    networkKey: Buffer.from(NETDEF_NETWORK_KEY),
                    networkKeyFrameCounter: 0,
                    networkKeySequenceNumber: 0,
                    tcKey: Buffer.from(NETDEF_TC_KEY),
                    tcKeyFrameCounter: 0,
                },
                SAVE_DIR,
                // true, // emitMACFrames
            );
            // await driver.loadState();
            driver.parser.on("data", driver.onFrame.bind(driver));

            // @ts-expect-error mock override
            driver.networkUp = true;
        });

        afterEach(() => {
            driver.deviceTable.clear();
            driver.address16ToAddress64.clear();
        });

        it("handles loading with given network params - first start", async () => {
            const saveStateSpy = vi.spyOn(driver, "saveState");

            await driver.loadState();

            expect(saveStateSpy).toHaveBeenCalledTimes(1);

            // reset manually
            driver.netParams.eui64 = 0n;
            driver.netParams.panId = 0x0;
            driver.netParams.extendedPANId = 0n;
            driver.netParams.channel = 11;
            driver.netParams.nwkUpdateId = 0;
            driver.netParams.txPower = 11;
            driver.netParams.networkKey = Buffer.alloc(16);
            driver.netParams.networkKeyFrameCounter = 0;
            driver.netParams.networkKeySequenceNumber = 0;
            driver.netParams.tcKey = Buffer.alloc(16);
            driver.netParams.tcKeyFrameCounter = 0;
            driver.deviceTable.clear();
            driver.address16ToAddress64.clear();
            driver.indirectTransmissions.clear();

            await driver.loadState();

            expect(driver.netParams.eui64).toStrictEqual(Buffer.from(A_EUI64).readBigUInt64LE(0));
            expect(driver.netParams.panId).toStrictEqual(NETDEF_PAN_ID);
            expect(driver.netParams.extendedPANId).toStrictEqual(Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0));
            expect(driver.netParams.channel).toStrictEqual(A_CHANNEL);
            expect(driver.netParams.nwkUpdateId).toStrictEqual(0);
            expect(driver.netParams.txPower).toStrictEqual(10);
            expect(driver.netParams.networkKey).toStrictEqual(Buffer.from(NETDEF_NETWORK_KEY));
            expect(driver.netParams.networkKeyFrameCounter).toStrictEqual(1024);
            expect(driver.netParams.networkKeySequenceNumber).toStrictEqual(0);
            expect(driver.netParams.tcKey).toStrictEqual(Buffer.from(NETDEF_TC_KEY));
            expect(driver.netParams.tcKeyFrameCounter).toStrictEqual(1024);
            expect(driver.deviceTable.size).toStrictEqual(0);
            expect(driver.address16ToAddress64.size).toStrictEqual(0);
            expect(driver.indirectTransmissions.size).toStrictEqual(0);
        });

        it("saves & loads back", async () => {
            driver.netParams.eui64 = 1n;
            driver.netParams.panId = 0x4356;
            driver.netParams.extendedPANId = 893489346n;
            driver.netParams.channel = 25;
            driver.netParams.nwkUpdateId = 1;
            driver.netParams.txPower = 15;
            driver.netParams.networkKey = Buffer.from([
                0x11, 0x29, 0x22, 0x18, 0x13, 0x27, 0x24, 0x16, 0x12, 0x34, 0x56, 0x78, 0x90, 0x98, 0x76, 0x54,
            ]);
            driver.netParams.networkKeyFrameCounter = 235568765;
            driver.netParams.networkKeySequenceNumber = 1;
            driver.netParams.tcKey = Buffer.from([0x51, 0x69, 0x62, 0x58, 0x53, 0x67, 0x64, 0x56, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
            driver.netParams.tcKeyFrameCounter = 896723;
            driver.deviceTable.set(1234n, { address16: 1, rxOnWhenIdle: true, authorized: true, neighbor: true });
            driver.deviceTable.set(12656887476334n, { address16: 3457, rxOnWhenIdle: true, authorized: true, neighbor: true });
            driver.deviceTable.set(12328965645634n, { address16: 9674, rxOnWhenIdle: false, authorized: true, neighbor: false });
            driver.deviceTable.set(234367481234n, { address16: 54748, rxOnWhenIdle: true, authorized: false, neighbor: true });

            await driver.saveState();

            // reset manually
            driver.netParams.eui64 = 0n;
            driver.netParams.panId = 0x0;
            driver.netParams.extendedPANId = 0n;
            driver.netParams.channel = 11;
            driver.netParams.nwkUpdateId = 0;
            driver.netParams.txPower = 11;
            driver.netParams.networkKey = Buffer.alloc(16);
            driver.netParams.networkKeyFrameCounter = 0;
            driver.netParams.networkKeySequenceNumber = 0;
            driver.netParams.tcKey = Buffer.alloc(16);
            driver.netParams.tcKeyFrameCounter = 0;
            driver.deviceTable.clear();
            driver.address16ToAddress64.clear();
            driver.indirectTransmissions.clear();

            await driver.loadState();

            expect(driver.netParams.eui64).toStrictEqual(1n);
            expect(driver.netParams.panId).toStrictEqual(0x4356);
            expect(driver.netParams.extendedPANId).toStrictEqual(893489346n);
            expect(driver.netParams.channel).toStrictEqual(25);
            expect(driver.netParams.nwkUpdateId).toStrictEqual(1);
            expect(driver.netParams.txPower).toStrictEqual(15);
            expect(driver.netParams.networkKey).toStrictEqual(
                Buffer.from([0x11, 0x29, 0x22, 0x18, 0x13, 0x27, 0x24, 0x16, 0x12, 0x34, 0x56, 0x78, 0x90, 0x98, 0x76, 0x54]),
            );
            expect(driver.netParams.networkKeyFrameCounter).toStrictEqual(235568765 + 1024);
            expect(driver.netParams.networkKeySequenceNumber).toStrictEqual(1);
            expect(driver.netParams.tcKey).toStrictEqual(
                Buffer.from([0x51, 0x69, 0x62, 0x58, 0x53, 0x67, 0x64, 0x56, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
            );
            expect(driver.netParams.tcKeyFrameCounter).toStrictEqual(896723 + 1024);
            expect(driver.deviceTable.size).toStrictEqual(4);
            expect(driver.deviceTable.get(1234n)).toStrictEqual({ address16: 1, rxOnWhenIdle: true, authorized: true, neighbor: true });
            expect(driver.deviceTable.get(12656887476334n)).toStrictEqual({ address16: 3457, rxOnWhenIdle: true, authorized: true, neighbor: true });
            expect(driver.deviceTable.get(12328965645634n)).toStrictEqual({
                address16: 9674,
                rxOnWhenIdle: false,
                authorized: true,
                neighbor: false,
            });
            expect(driver.deviceTable.get(234367481234n)).toStrictEqual({ address16: 54748, rxOnWhenIdle: true, authorized: false, neighbor: true });
            expect(driver.address16ToAddress64.size).toStrictEqual(4);
            expect(driver.address16ToAddress64.get(1)).toStrictEqual(1234n);
            expect(driver.address16ToAddress64.get(3457)).toStrictEqual(12656887476334n);
            expect(driver.address16ToAddress64.get(9674)).toStrictEqual(12328965645634n);
            expect(driver.address16ToAddress64.get(54748)).toStrictEqual(234367481234n);
            expect(driver.indirectTransmissions.size).toStrictEqual(1);
            expect(driver.indirectTransmissions.get(12328965645634n)).toStrictEqual([]);
        });

        it("sets node descriptor manufacturer code", async () => {
            await driver.loadState();

            expect(driver.configAttributes.nodeDescriptor).toStrictEqual(
                Buffer.from([0, 0, 0, 0, 0, 64, 143, 160, 197, 127, 127, 0, 65, 44, 127, 0, 0]),
            );

            driver.setManufacturerCode(0x1234);

            expect(driver.configAttributes.nodeDescriptor).toStrictEqual(
                Buffer.from([0, 0, 0, 0, 0, 64, 143, 52, 18, 127, 127, 0, 65, 44, 127, 0, 0]),
            );

            // revert
            driver.setManufacturerCode(0xffff);
        });
    });

    describe("NETDEF", () => {
        beforeEach(async () => {
            driver = new OTRCPDriver(
                {
                    txChannel: A_CHANNEL,
                    ccaBackoffAttempts: 1,
                    ccaRetries: 4,
                    enableCSMACA: true,
                    headerUpdated: true,
                    reTx: false,
                    securityProcessed: true,
                    txDelay: 0,
                    txDelayBaseTime: 0,
                    rxChannelAfterTxDone: A_CHANNEL,
                },
                {
                    eui64: Buffer.from(A_EUI64).readBigUInt64LE(0),
                    panId: NETDEF_PAN_ID,
                    extendedPANId: Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0),
                    channel: A_CHANNEL,
                    nwkUpdateId: 0,
                    txPower: 10,
                    networkKey: Buffer.from(NETDEF_NETWORK_KEY),
                    networkKeyFrameCounter: 0,
                    networkKeySequenceNumber: 0,
                    tcKey: Buffer.from(NETDEF_TC_KEY),
                    tcKeyFrameCounter: 0,
                },
                SAVE_DIR,
                // true, // emitMACFrames
            );
            await driver.loadState();
            driver.parser.on("data", driver.onFrame.bind(driver));

            // @ts-expect-error mock override
            driver.networkUp = true;
        });

        afterEach(() => {
            driver.deviceTable.clear();
            driver.address16ToAddress64.clear();
        });

        it("ignores bogus data before start of HDLC frame", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(1);

            driver.parser._transform(Buffer.concat([Buffer.from([0x12, 0x32]), frame]), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(parserEmit).toHaveBeenNthCalledWith(1, "data", frame);
        });

        it("ignores bogus data after end of HDLC frame", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(1);

            driver.parser._transform(Buffer.concat([frame, Buffer.from([0x12, 0x32])]), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(parserEmit).toHaveBeenNthCalledWith(1, "data", frame);
        });

        it("ignores bogus data before start and after end of HDLC frame", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(1);

            driver.parser._transform(Buffer.concat([Buffer.from([0x12, 0x32]), frame, Buffer.from([0x12, 0x32])]), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(parserEmit).toHaveBeenNthCalledWith(1, "data", frame);
        });

        it("skips duplicate FLAGs of HDLC frame", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(1);

            driver.parser._transform(Buffer.concat([Buffer.from([0x7e, 0x7e]), frame, Buffer.from([0x7e, 0x7e])]), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(parserEmit).toHaveBeenNthCalledWith(1, "data", frame);
        });

        it("handles multiple HDLC frames in same transform call", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(1);
            const frame2 = makeSpinelLastStatus(2);

            driver.parser._transform(Buffer.concat([frame, frame2]), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(parserEmit).toHaveBeenNthCalledWith(1, "data", frame);
            expect(parserEmit).toHaveBeenNthCalledWith(2, "data", frame2);
        });

        it("sends frame NETDEF_ACK_FRAME_FROM_COORD and receives LAST_STATUS response", async () => {
            const waitForTIDSpy = vi.spyOn(driver, "waitForTID");
            const sendFrameSpy = vi.spyOn(driver, "sendFrame");

            const p = driver.sendMACFrame(1, NETDEF_ACK_FRAME_FROM_COORD, undefined, undefined); // bypass indirect transmissions
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            await expect(p).resolves.toStrictEqual(undefined);
            expect(waitForTIDSpy).toHaveBeenCalledWith(1, 10000);
            expect(sendFrameSpy).toHaveBeenCalledTimes(1);
        });

        it("sends frame NETDEF_MTORR_FRAME_FROM_COORD and receives LAST_STATUS response", async () => {
            const waitForTIDSpy = vi.spyOn(driver, "waitForTID");
            const sendFrameSpy = vi.spyOn(driver, "sendFrame");

            const p = driver.sendMACFrame(1, NETDEF_MTORR_FRAME_FROM_COORD, undefined, undefined); // bypass indirect transmissions
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            await expect(p).resolves.toStrictEqual(undefined);
            expect(waitForTIDSpy).toHaveBeenCalledWith(1, 10000);
            expect(sendFrameSpy).toHaveBeenCalledTimes(1);
        });

        it("receives frame NETDEF_ACK_FRAME_TO_COORD", async () => {
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeAPSCommandFrameSpy = vi.spyOn(driver, "processZigbeeAPSCommandFrame");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ACK_FRAME_TO_COORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(1);
            expect(processZigbeeAPSCommandFrameSpy).toHaveBeenCalledTimes(0);
        });

        it("receives frame NETDEF_LINK_STATUS_FROM_DEV", async () => {
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKLinkStatusSpy = vi.spyOn(driver, "processZigbeeNWKLinkStatus");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_LINK_STATUS_FROM_DEV), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(1);
        });

        it("receives frame NETDEF_ZCL_FRAME_CMD_TO_COORD", async () => {
            const emitSpy = vi.spyOn(driver, "emit");
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeAPSCommandFrameSpy = vi.spyOn(driver, "processZigbeeAPSCommandFrame");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ZCL_FRAME_CMD_TO_COORD), "utf8", () => {});
            await vi.runOnlyPendingTimersAsync();

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(1);
            expect(processZigbeeAPSCommandFrameSpy).toHaveBeenCalledTimes(0);
            expect(emitSpy).toHaveBeenCalledWith(
                "frame",
                0xaa38,
                undefined,
                {
                    frameControl: {
                        frameType: 0x0,
                        deliveryMode: 0x0,
                        ackFormat: false,
                        security: false,
                        ackRequest: false,
                        extendedHeader: false,
                    },
                    destEndpoint: 1,
                    group: undefined,
                    clusterId: 0xef00,
                    profileId: 0x0104,
                    sourceEndpoint: 1,
                    counter: 63,
                    fragmentation: undefined,
                    fragBlockNumber: undefined,
                    fragACKBitfield: undefined,
                    securityHeader: undefined,
                },
                Buffer.from([0x09, 0x50, 0x25, 0xaf, 0x00]),
                0, // rssi
            );
        });

        it("receives frame NETDEF_ROUTE_RECORD_TO_COORD", async () => {
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKRouteRecSpy = vi.spyOn(driver, "processZigbeeNWKRouteRecord");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ROUTE_RECORD_TO_COORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKRouteRecSpy).toHaveBeenCalledTimes(1);
        });

        it("receives frame NETDEF_MTORR_FRAME_FROM_COORD", async () => {
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKRouteReqSpy = vi.spyOn(driver, "processZigbeeNWKRouteReq");
            const sendZigbeeNWKRouteReplySpy = vi.spyOn(driver, "sendZigbeeNWKRouteReply");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_MTORR_FRAME_FROM_COORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeNWKRouteReplySpy).toHaveBeenCalledTimes(0);
        });

        it("receives frame NETDEF_ZGP_COMMISSIONING", async () => {
            const emitSpy = vi.spyOn(driver, "emit");
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKGPCommandFrameSpy = vi.spyOn(driver, "processZigbeeNWKGPCommandFrame");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ZGP_COMMISSIONING), "utf8", () => {});
            await vi.runOnlyPendingTimersAsync();

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKGPCommandFrameSpy).toHaveBeenCalledTimes(1);
            expect(emitSpy).toHaveBeenCalledWith(
                "frame",
                0x0155f47a & 0xffff,
                undefined,
                {
                    frameControl: {
                        frameType: 0x1,
                        deliveryMode: 0x2,
                        ackFormat: false,
                        security: false,
                        ackRequest: false,
                        extendedHeader: false,
                    },
                    group: ZigbeeConsts.GP_GROUP_ID,
                    profileId: ZigbeeConsts.GP_PROFILE_ID,
                    clusterId: ZigbeeConsts.GP_CLUSTER_ID,
                    destEndpoint: ZigbeeConsts.GP_ENDPOINT,
                    sourceEndpoint: ZigbeeConsts.GP_ENDPOINT,
                },
                Buffer.from([
                    1, 70, 4, 0, 0, 122, 244, 85, 1, 0, 0, 0, 0, 0xe0, 51, 0x2, 0x85, 0xf2, 0xc9, 0x25, 0x82, 0x1d, 0xf4, 0x6f, 0x45, 0x8c, 0xf0,
                    0xe6, 0x37, 0xaa, 0xc3, 0xba, 0xb6, 0xaa, 0x45, 0x83, 0x1a, 0x11, 0x46, 0x23, 0x0, 0x0, 0x4, 0x16, 0x10, 0x11, 0x22, 0x23, 0x18,
                    0x19, 0x14, 0x15, 0x12, 0x13, 0x64, 0x65, 0x62, 0x63, 0x1e, 0x1f, 0x1c, 0x1d, 0x1a, 0x1b, 0x16, 0x17,
                ]),
                0, // rssi
            );
        });
    });

    describe("NET2", () => {
        beforeEach(async () => {
            driver = new OTRCPDriver(
                {
                    txChannel: A_CHANNEL,
                    ccaBackoffAttempts: 1,
                    ccaRetries: 4,
                    enableCSMACA: true,
                    headerUpdated: true,
                    reTx: false,
                    securityProcessed: true,
                    txDelay: 0,
                    txDelayBaseTime: 0,
                    rxChannelAfterTxDone: A_CHANNEL,
                },
                {
                    eui64: NET2_COORD_EUI64_BIGINT,
                    panId: NET2_PAN_ID,
                    extendedPANId: Buffer.from(NET2_EXTENDED_PAN_ID).readBigUInt64LE(0),
                    channel: A_CHANNEL,
                    nwkUpdateId: 0,
                    txPower: 5,
                    networkKey: Buffer.from(NETDEF_NETWORK_KEY),
                    networkKeyFrameCounter: 0,
                    networkKeySequenceNumber: 0,
                    tcKey: Buffer.from(NETDEF_TC_KEY),
                    tcKeyFrameCounter: 0,
                },
                SAVE_DIR,
                // true, // emitMACFrames
            );
            await driver.loadState();
            driver.parser.on("data", driver.onFrame.bind(driver));

            // @ts-expect-error mock override
            driver.networkUp = true;
        });

        afterEach(() => {
            driver.deviceTable.clear();
            driver.address16ToAddress64.clear();
        });

        it("receives frame NET2_TRANSPORT_KEY_NWK_FROM_COORD - not for coordinator", async () => {
            // encrypted only APS
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeAPSTransportKeySpy = vi.spyOn(driver, "processZigbeeAPSTransportKey");

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_TRANSPORT_KEY_NWK_FROM_COORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeAPSTransportKeySpy).toHaveBeenCalledTimes(0);
        });

        it("receives frame NET2_REQUEST_KEY_TC_FROM_DEVICE", async () => {
            // encrypted at NWK+APS
            const source64 = BigInt("0xa4c1386d9b280fdf");
            driver.deviceTable.set(source64, {
                address16: 0xa18f,
                rxOnWhenIdle: true,
                authorized: false,
                neighbor: true,
            });
            driver.address16ToAddress64.set(0xa18f, source64);

            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeAPSRequestKeySpy = vi.spyOn(driver, "processZigbeeAPSRequestKey");
            const sendZigbeeAPSTransportKeyTCSpy = vi.spyOn(driver, "sendZigbeeAPSTransportKeyTC");

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_REQUEST_KEY_TC_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(1);
            expect(processZigbeeAPSRequestKeySpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeAPSTransportKeyTCSpy).toHaveBeenCalledTimes(1);
        });

        it("tries to join while not allowed", async () => {
            // Expected flow:
            // - NET2_BEACON_REQ_FROM_DEVICE
            // - NET2_BEACON_RESP_FROM_COORD
            // - NET2_ASSOC_REQ_FROM_DEVICE
            // - NET2_DATA_RQ_FROM_DEVICE
            // - NET2_ASSOC_RESP_FROM_COORD
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");
            const sendMACAssocRspSpy = vi.spyOn(driver, "sendMACAssocRsp");

            driver.parser._transform(makeSpinelStreamRaw(100, NET2_BEACON_REQ_FROM_DEVICE), "utf8", () => {});
            driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});

            expect(sendMACFrameSpy).toHaveBeenCalledTimes(1);
            const beaconRespFrame = sendMACFrameSpy.mock.calls[0][1];
            const [decBeaconRespFCF, decBeaconRespFCFOffset] = decodeMACFrameControl(beaconRespFrame, 0);
            const [decBeaconRespHeader] = decodeMACHeader(beaconRespFrame, decBeaconRespFCFOffset, decBeaconRespFCF);

            expect(decBeaconRespHeader.superframeSpec?.associationPermit).toStrictEqual(false);

            driver.parser._transform(makeSpinelStreamRaw(101, NET2_ASSOC_REQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelStreamRaw(102, NET2_DATA_RQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ASSOC_RSP => OK
            driver.parser._transform(makeSpinelLastStatus(2), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(sendMACAssocRspSpy).toHaveBeenCalledTimes(1);
            expect(sendMACAssocRspSpy).toHaveBeenCalledWith(11871832136131022815n, 0xffff, MACAssociationStatus.PAN_ACCESS_DENIED);
        });

        it("performs a join & authorize - ROUTER", async () => {
            // Expected flow (APS acks requested from device are skipped for brevity):
            // - NET2_BEACON_REQ_FROM_DEVICE
            // - NET2_BEACON_RESP_FROM_COORD
            // - NET2_ASSOC_REQ_FROM_DEVICE
            // - NET2_DATA_RQ_FROM_DEVICE
            // - NET2_ASSOC_RESP_FROM_COORD
            // - NET2_TRANSPORT_KEY_NWK_FROM_COORD
            // - NET2_DEVICE_ANNOUNCE_BCAST
            // - NET2_NODE_DESC_REQ_FROM_DEVICE
            // - NET2_REQUEST_KEY_TC_FROM_DEVICE
            // - NET2_TRANSPORT_KEY_TC_FROM_COORD
            // - NET2_VERIFY_KEY_TC_FROM_DEVICE
            // - NET2_CONFIRM_KEY_TC_SUCCESS
            driver.allowJoins(0xfe, true);

            const emitSpy = vi.spyOn(driver, "emit");
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");
            const sendMACAssocRspSpy = vi.spyOn(driver, "sendMACAssocRsp");
            const sendZigbeeAPSTransportKeyNWKSpy = vi.spyOn(driver, "sendZigbeeAPSTransportKeyNWK");
            vi.spyOn(driver, "assignNetworkAddress").mockReturnValueOnce(0xa18f); // force nwk16 matching vectors

            driver.parser._transform(makeSpinelStreamRaw(100, NET2_BEACON_REQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // BEACON_RSP => OK
            driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(sendMACFrameSpy).toHaveBeenCalledTimes(1);
            const beaconRespFrame = sendMACFrameSpy.mock.calls[0][1];
            const [decBeaconRespFCF, decBeaconRespFCFOffset] = decodeMACFrameControl(beaconRespFrame, 0);
            const [decBeaconRespHeader] = decodeMACHeader(beaconRespFrame, decBeaconRespFCFOffset, decBeaconRespFCF);

            expect(decBeaconRespHeader.superframeSpec?.associationPermit).toStrictEqual(true);

            driver.parser._transform(makeSpinelStreamRaw(101, NET2_ASSOC_REQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelStreamRaw(102, NET2_DATA_RQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ASSOC_RSP => OK
            driver.parser._transform(makeSpinelLastStatus(2), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // TRANSPORT_KEY NWK => OK
            driver.parser._transform(makeSpinelLastStatus(3), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(sendMACAssocRspSpy).toHaveBeenCalledTimes(1);
            expect(sendMACAssocRspSpy).toHaveBeenCalledWith(11871832136131022815n, 0xa18f, MACAssociationStatus.SUCCESS);
            expect(sendZigbeeAPSTransportKeyNWKSpy).toHaveBeenCalledTimes(1);
            expect(driver.deviceTable.get(11871832136131022815n)).toStrictEqual({
                address16: 0xa18f,
                rxOnWhenIdle: true,
                authorized: false,
                neighbor: true,
            });

            driver.parser._transform(makeSpinelStreamRaw(103, NET2_DEVICE_ANNOUNCE_BCAST), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(emitSpy).toHaveBeenCalledWith("deviceJoined", 0xa18f, 11871832136131022815n);
            expect(emitSpy).toHaveBeenCalledWith("frame", 0xa18f, undefined, expect.any(Object), expect.any(Buffer), 0 /* rssi */);

            driver.parser._transform(makeSpinelStreamRaw(104, NET2_NODE_DESC_REQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // node desc APS ACK => OK
            driver.parser._transform(makeSpinelLastStatus(4), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // node desc RESP => OK
            driver.parser._transform(makeSpinelLastStatus(5), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            driver.parser._transform(makeSpinelStreamRaw(105, NET2_REQUEST_KEY_TC_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // TRANSPORT_KEY TC => OK
            driver.parser._transform(makeSpinelLastStatus(6), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            driver.parser._transform(makeSpinelStreamRaw(106, NET2_VERIFY_KEY_TC_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // CONFIRM_KEY => OK
            driver.parser._transform(makeSpinelLastStatus(7), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(driver.deviceTable.get(11871832136131022815n)).toStrictEqual({
                address16: 0xa18f,
                rxOnWhenIdle: true,
                authorized: true,
                neighbor: true,
            });
        });

        // it("performs a join & authorize - END DEVICE", async () => {
        //     // TODO: with DATA req (indirect transmission)
        // });
    });

    describe("NET3", () => {
        beforeEach(async () => {
            driver = new OTRCPDriver(
                {
                    txChannel: A_CHANNEL,
                    ccaBackoffAttempts: 1,
                    ccaRetries: 4,
                    enableCSMACA: true,
                    headerUpdated: true,
                    reTx: false,
                    securityProcessed: true,
                    txDelay: 0,
                    txDelayBaseTime: 0,
                    rxChannelAfterTxDone: A_CHANNEL,
                },
                {
                    eui64: NET3_COORD_EUI64_BIGINT,
                    panId: NET3_PAN_ID,
                    extendedPANId: Buffer.from(NET3_EXTENDED_PAN_ID).readBigUInt64LE(0),
                    channel: A_CHANNEL,
                    nwkUpdateId: 0,
                    txPower: 5,
                    networkKey: Buffer.from(NET3_NETWORK_KEY),
                    networkKeyFrameCounter: 0,
                    networkKeySequenceNumber: 0,
                    tcKey: Buffer.from(NETDEF_TC_KEY),
                    tcKeyFrameCounter: 0,
                },
                SAVE_DIR,
                true, // emitMACFrames
            );
            await driver.loadState();
            driver.parser.on("data", driver.onFrame.bind(driver));
            // joined devices
            // 5c:c7:c1:ff:fe:5e:70:ea
            driver.deviceTable.set(6685525477083214058n, { address16: 0x3ab1, rxOnWhenIdle: true, authorized: true, neighbor: true });
            driver.address16ToAddress64.set(0x3ab1, 6685525477083214058n);
            // not set on purpose to observe change from actual route record
            // driver.sourceRouteTable.set(0x3ab1, [{relayAddresses: [], pathCost: 1}]);

            // @ts-expect-error mock override
            driver.networkUp = true;
        });

        afterEach(() => {
            driver.deviceTable.clear();
            driver.address16ToAddress64.clear();
        });

        it("registers timers", async () => {
            const sendPeriodicZigbeeNWKLinkStatusSpy = vi.spyOn(driver, "sendPeriodicZigbeeNWKLinkStatus");
            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");
            const processZigbeeNWKRouteRecordSpy = vi.spyOn(driver, "processZigbeeNWKRouteRecord");
            let linksSpy: ZigbeeNWKLinkStatus[] | undefined;
            let manyToOneSpy: ZigbeeNWKManyToOne | undefined;
            let destination16Spy: number | undefined;

            vi.spyOn(driver, "sendZigbeeNWKLinkStatus").mockImplementationOnce(async (links) => {
                linksSpy = links;
                const p = driver.sendZigbeeNWKLinkStatus(links);
                // LINK_STATUS => OK
                driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            vi.spyOn(driver, "sendZigbeeNWKRouteReq").mockImplementationOnce(async (manyToOne, destination16) => {
                manyToOneSpy = manyToOne;
                destination16Spy = destination16;
                const p = driver.sendZigbeeNWKRouteReq(manyToOne, destination16);
                // ROUTE_REQ => OK
                driver.parser._transform(makeSpinelLastStatus(2), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await driver.registerTimers();

            expect(linksSpy).toStrictEqual([{ address: 0x3ab1, incomingCost: 0, outgoingCost: 0 }]);
            expect(manyToOneSpy).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            expect(destination16Spy).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(sendPeriodicZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(1);
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1);
            expect(setTimeoutSpy).toHaveBeenCalledTimes(2 + 2 /* waiters */);

            driver.parser._transform(makeSpinelStreamRaw(1, NET3_ROUTE_RECORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ROUTE_RECORD => OK
            driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(processZigbeeNWKRouteRecordSpy).toHaveBeenCalledTimes(1);

            //--- SECOND TRIGGER

            vi.spyOn(driver, "sendZigbeeNWKLinkStatus").mockImplementationOnce(async (links) => {
                linksSpy = links;
                const p = driver.sendZigbeeNWKLinkStatus(links);
                // LINK_STATUS => OK
                driver.parser._transform(makeSpinelLastStatus(3), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await vi.advanceTimersByTimeAsync(17000);

            expect(sendPeriodicZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(2);
            expect(linksSpy).toStrictEqual([{ address: 0x3ab1, incomingCost: 1, outgoingCost: 1 }]);

            vi.spyOn(driver, "sendZigbeeNWKLinkStatus").mockImplementationOnce(async (links) => {
                linksSpy = links;
                const p = driver.sendZigbeeNWKLinkStatus(links);
                // LINK_STATUS => OK
                driver.parser._transform(makeSpinelLastStatus(4), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await vi.advanceTimersByTimeAsync(17000);

            expect(sendPeriodicZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(3);
            expect(linksSpy).toStrictEqual([{ address: 0x3ab1, incomingCost: 1, outgoingCost: 1 }]);

            vi.spyOn(driver, "sendZigbeeNWKLinkStatus").mockImplementationOnce(async (links) => {
                linksSpy = links;
                const p = driver.sendZigbeeNWKLinkStatus(links);
                // LINK_STATUS => OK
                driver.parser._transform(makeSpinelLastStatus(5), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await vi.advanceTimersByTimeAsync(17000);

            expect(sendPeriodicZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(4);
            expect(linksSpy).toStrictEqual([{ address: 0x3ab1, incomingCost: 1, outgoingCost: 1 }]);

            vi.spyOn(driver, "sendZigbeeNWKRouteReq").mockImplementationOnce(async (manyToOne, destination16) => {
                manyToOneSpy = manyToOne;
                destination16Spy = destination16;
                const p = driver.sendZigbeeNWKRouteReq(manyToOne, destination16);
                // ROUTE_REQ => OK
                driver.parser._transform(makeSpinelLastStatus(6), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await vi.advanceTimersByTimeAsync(10000);
            await vi.advanceTimersByTimeAsync(100); // flush

            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(2);
            expect(manyToOneSpy).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            expect(destination16Spy).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
        });
    });

    describe("NET4", () => {
        beforeEach(async () => {
            driver = new OTRCPDriver(
                {
                    txChannel: NET4_CHANNEL,
                    ccaBackoffAttempts: 1,
                    ccaRetries: 4,
                    enableCSMACA: true,
                    headerUpdated: true,
                    reTx: false,
                    securityProcessed: true,
                    txDelay: 0,
                    txDelayBaseTime: 0,
                    rxChannelAfterTxDone: NET4_CHANNEL,
                },
                {
                    eui64: NET4_COORD_EUI64_BIGINT,
                    panId: NETDEF_PAN_ID,
                    extendedPANId: Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0),
                    channel: NET4_CHANNEL,
                    nwkUpdateId: 0,
                    txPower: 5,
                    networkKey: Buffer.from(NETDEF_NETWORK_KEY),
                    networkKeyFrameCounter: 0,
                    networkKeySequenceNumber: 0,
                    tcKey: Buffer.from(NETDEF_TC_KEY),
                    tcKeyFrameCounter: 0,
                },
                SAVE_DIR,
                true, // emitMACFrames
            );
            await driver.loadState();
            driver.parser.on("data", driver.onFrame.bind(driver));
            // joined devices
            // 80:4b:50:ff:fe:a4:b9:73
            driver.deviceTable.set(9244571720527165811n, { address16: 0x96ba, rxOnWhenIdle: true, authorized: true, neighbor: true });
            driver.address16ToAddress64.set(0x96ba, 9244571720527165811n);
            // driver.sourceRouteTable.set(0x96ba, [{relayAddresses: [], pathCost: 1}]);
            // 70:ac:08:ff:fe:d0:4a:58
            driver.deviceTable.set(8118874123826907736n, { address16: 0x91d2, rxOnWhenIdle: true, authorized: true, neighbor: true });
            driver.address16ToAddress64.set(0x91d2, 8118874123826907736n);
            // driver.sourceRouteTable.set(0x91d2, [{relayAddresses: [], pathCost: 1}]);
            // 00:12:4b:00:24:c2:e1:e1
            driver.deviceTable.set(5149013569626593n, { address16: 0xcb47, rxOnWhenIdle: true, authorized: true, neighbor: true });
            driver.address16ToAddress64.set(0xcb47, 5149013569626593n);
            // mimic no source route entry for 0xcb47
            // 00:12:4b:00:29:27:fd:8c
            driver.deviceTable.set(5149013643361676n, { address16: 0x6887, rxOnWhenIdle: false, authorized: true, neighbor: false });
            driver.address16ToAddress64.set(0x6887, 5149013643361676n);
            // driver.sourceRouteTable.set(0x6887, [{relayAddresses: [0x96ba], pathCost: 2}]);
            // 00:12:4b:00:25:49:f4:42
            driver.deviceTable.set(5149013578478658n, { address16: 0x9ed5, rxOnWhenIdle: false, authorized: true, neighbor: false });
            driver.address16ToAddress64.set(0x9ed5, 5149013578478658n);
            // driver.sourceRouteTable.set(0x9ed5, [{relayAddresses: [0x91d2], pathCost: 2}]);
            // 00:12:4b:00:25:02:d0:3b
            driver.deviceTable.set(5149013573816379n, { address16: 0x4b8e, rxOnWhenIdle: false, authorized: true, neighbor: false });
            driver.address16ToAddress64.set(0x4b8e, 5149013573816379n);
            // driver.sourceRouteTable.set(0x4b8e, [{relayAddresses: [0xcb47], pathCost: 2}]);

            // @ts-expect-error mock override
            driver.networkUp = true;
        });

        afterEach(() => {
            driver.deviceTable.clear();
            driver.address16ToAddress64.clear();
        });

        it("handles source routing", async () => {
            const sendPeriodicZigbeeNWKLinkStatusSpy = vi.spyOn(driver, "sendPeriodicZigbeeNWKLinkStatus");
            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");
            const processZigbeeNWKRouteRecordSpy = vi.spyOn(driver, "processZigbeeNWKRouteRecord");
            let linksSpy: ZigbeeNWKLinkStatus[] | undefined;
            let manyToOneSpy: ZigbeeNWKManyToOne | undefined;
            let destination16Spy: number | undefined;

            vi.spyOn(driver, "sendZigbeeNWKLinkStatus").mockImplementationOnce(async (links) => {
                linksSpy = links;
                const p = driver.sendZigbeeNWKLinkStatus(links);
                // LINK_STATUS => OK
                driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            vi.spyOn(driver, "sendZigbeeNWKRouteReq").mockImplementationOnce(async (manyToOne, destination16) => {
                manyToOneSpy = manyToOne;
                destination16Spy = destination16;
                const p = driver.sendZigbeeNWKRouteReq(manyToOne, destination16);
                // ROUTE_REQ => OK
                driver.parser._transform(makeSpinelLastStatus(2), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await driver.registerTimers();

            expect(linksSpy).toStrictEqual([
                { address: 0x96ba, incomingCost: 0, outgoingCost: 0 },
                { address: 0x91d2, incomingCost: 0, outgoingCost: 0 },
                { address: 0xcb47, incomingCost: 0, outgoingCost: 0 },
            ]);
            expect(manyToOneSpy).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            expect(destination16Spy).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(sendPeriodicZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(1);
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1);
            expect(setTimeoutSpy).toHaveBeenCalledTimes(2 + 2 /* waiters */);

            driver.parser._transform(makeSpinelStreamRaw(1, NET4_ROUTE_RECORD_FROM_96BA_NO_RELAY), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ROUTE_RECORD => OK
            driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            driver.parser._transform(makeSpinelStreamRaw(2, NET4_ROUTE_RECORD_FROM_91D2_NO_RELAY), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ROUTE_RECORD => OK
            driver.parser._transform(makeSpinelLastStatus(2), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            driver.parser._transform(makeSpinelStreamRaw(3, NET4_ROUTE_RECORD_FROM_6887_RELAY_96BA), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ROUTE_RECORD => OK
            driver.parser._transform(makeSpinelLastStatus(3), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            driver.parser._transform(makeSpinelStreamRaw(4, NET4_ROUTE_RECORD_FROM_9ED5_RELAY_91D2), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ROUTE_RECORD => OK
            driver.parser._transform(makeSpinelLastStatus(4), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            driver.parser._transform(makeSpinelStreamRaw(5, NET4_ROUTE_RECORD_FROM_4B8E_RELAY_CB47), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ROUTE_RECORD => OK
            driver.parser._transform(makeSpinelLastStatus(5), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(processZigbeeNWKRouteRecordSpy).toHaveBeenCalledTimes(5);

            expect(driver.findBestSourceRoute(0x96ba, undefined)).toStrictEqual([undefined, undefined, 1]);
            expect(driver.findBestSourceRoute(undefined, 9244571720527165811n)).toStrictEqual([undefined, undefined, 1]);

            expect(driver.findBestSourceRoute(0x91d2, undefined)).toStrictEqual([undefined, undefined, 1]);
            expect(driver.findBestSourceRoute(undefined, 8118874123826907736n)).toStrictEqual([undefined, undefined, 1]);

            expect(driver.findBestSourceRoute(0xcb47, undefined)).toStrictEqual([undefined, undefined, undefined]);
            expect(driver.findBestSourceRoute(undefined, 5149013569626593n)).toStrictEqual([undefined, undefined, undefined]);

            expect(driver.findBestSourceRoute(0x6887, undefined)).toStrictEqual([0, [0x96ba], 2]);
            expect(driver.findBestSourceRoute(undefined, 5149013643361676n)).toStrictEqual([0, [0x96ba], 2]);

            expect(driver.findBestSourceRoute(0x9ed5, undefined)).toStrictEqual([0, [0x91d2], 2]);
            expect(driver.findBestSourceRoute(undefined, 5149013578478658n)).toStrictEqual([0, [0x91d2], 2]);

            expect(driver.findBestSourceRoute(0x4b8e, undefined)).toStrictEqual([0, [0xcb47], 2]);
            expect(driver.findBestSourceRoute(undefined, 5149013573816379n)).toStrictEqual([0, [0xcb47], 2]);

            const findBestSourceRouteSpy = vi.spyOn(driver, "findBestSourceRoute");
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");

            //-- NWK CMD
            sendMACFrameSpy.mockImplementationOnce(() => Promise.resolve());
            await driver.sendZigbeeNWKStatus(0x96ba, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x96ba, 9244571720527165811n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, 1]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x96ba, undefined);

            sendMACFrameSpy.mockImplementationOnce(() => Promise.resolve());
            await driver.sendZigbeeNWKStatus(0x6887, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x6887, 5149013643361676n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0x96ba], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x96ba, undefined);

            //-- APS CMD
            sendMACFrameSpy.mockImplementationOnce(() => Promise.resolve());
            await driver.sendZigbeeAPSSwitchKey(0x91d2, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x91d2, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, 1]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x91d2, undefined);

            sendMACFrameSpy.mockImplementationOnce(() => Promise.resolve());
            await driver.sendZigbeeAPSSwitchKey(0x9ed5, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x9ed5, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0x91d2], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x91d2, undefined);

            //-- APS DATA
            sendMACFrameSpy.mockImplementationOnce(() => Promise.resolve());
            await driver.sendUnicast(Buffer.from([]), 0x1, 0x1, 0x91d2, undefined, 1, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x91d2, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, 1]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x91d2, undefined);

            sendMACFrameSpy.mockImplementationOnce(() => Promise.resolve());
            await driver.sendUnicast(Buffer.from([]), 0x1, 0x1, 0x6887, undefined, 1, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x6887, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0x96ba], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x96ba, undefined);

            //-- no source route (use given nwkDest16)
            sendMACFrameSpy.mockImplementationOnce(() => Promise.resolve());
            await driver.sendZigbeeNWKStatus(0xcb47, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0xcb47, 5149013569626593n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, undefined]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0xcb47, undefined);

            //-- no source route on source route (doesn't matter)
            sendMACFrameSpy.mockImplementationOnce(() => Promise.resolve());
            await driver.sendZigbeeNWKStatus(0x4b8e, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x4b8e, 5149013573816379n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0xcb47], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0xcb47, undefined);
        });
    });
});
