import { randomBytes } from "node:crypto";
import { type Socket, createSocket } from "node:dgram";
import { existsSync, rmSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_WIRESHARK_IP, DEFAULT_ZEP_UDP_PORT, createWiresharkZEPFrame } from "../src/dev/wireshark";
import { OTRCPDriver, type SourceRouteTableEntry } from "../src/drivers/ot-rcp-driver";
import { SpinelCommandId } from "../src/spinel/commands";
import { decodeHdlcFrame } from "../src/spinel/hdlc";
import { SpinelPropertyId } from "../src/spinel/properties";
import { SPINEL_HEADER_FLG_SPINEL, type SpinelFrame, decodeSpinelFrame, encodeSpinelFrame } from "../src/spinel/spinel";
import { SpinelStatus } from "../src/spinel/statuses";
import { MACAssociationStatus, type MACCapabilities, type MACHeader, decodeMACFrameControl, decodeMACHeader } from "../src/zigbee/mac";
import { ZigbeeConsts } from "../src/zigbee/zigbee";
import { type ZigbeeNWKLinkStatus, ZigbeeNWKManyToOne, ZigbeeNWKStatus } from "../src/zigbee/zigbee-nwk";
import type { ZigbeeNWKGPHeader } from "../src/zigbee/zigbee-nwkgp";
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
    NET5_COORD_EUI64,
    NET5_EXTENDED_PAN_ID,
    NET5_GP_CHANNEL_REQUEST_BCAST,
    NET5_NETWORK_KEY,
    NET5_PAN_ID,
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
    NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0,
} from "./data";

const randomBigInt = (): bigint => BigInt(`0x${randomBytes(8).toString("hex")}`);

const RESET_POWER_ON_FRAME_HEX = "7e80060070ee747e";
const COMMON_FFD_MAC_CAP: MACCapabilities = {
    alternatePANCoordinator: false,
    deviceType: 1,
    powerSource: 1,
    rxOnWhenIdle: true,
    securityCapability: false,
    allocateAddress: true,
};
const COMMON_RFD_MAC_CAP: MACCapabilities = {
    alternatePANCoordinator: false,
    deviceType: 0,
    powerSource: 0,
    rxOnWhenIdle: false,
    securityCapability: false,
    allocateAddress: true,
};

describe("OT RCP Driver", () => {
    let wiresharkSeqNum: number;
    let wiresharkSocket: Socket | undefined;
    let nextTidFromStartup = 1;

    const nextWiresharkSeqNum = (): number => {
        wiresharkSeqNum = (wiresharkSeqNum + 1) & 0xffffffff;

        return wiresharkSeqNum + 1;
    };

    // biome-ignore lint/correctness/noUnusedVariables: local testing only
    const setupWireshark = (driver: OTRCPDriver): void => {
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

    const makeSpinelStreamRaw = (tid: number, macFrame: Buffer, spinelMeta?: Buffer): Buffer => {
        const spinelFrame = {
            header: {
                tid,
                nli: 0,
                flg: SPINEL_HEADER_FLG_SPINEL,
            },
            commandId: SpinelCommandId.PROP_VALUE_IS,
            payload: Buffer.from([
                SpinelPropertyId.STREAM_RAW,
                macFrame.byteLength & 0xff,
                (macFrame.byteLength >> 8) & 0xff,
                ...macFrame,
                ...(spinelMeta || []),
            ]),
        };
        const encHdlcFrame = encodeSpinelFrame(spinelFrame);

        return Buffer.from(encHdlcFrame.data.subarray(0, encHdlcFrame.length));
    };

    const mockGetPropertyPayload = (hex: string): SpinelFrame => decodeSpinelFrame(decodeHdlcFrame(Buffer.from(hex, "hex")));

    const mockStart = async (driver: OTRCPDriver, loadState = true, timeoutReset = false) => {
        if (driver) {
            let loadStateSpy: ReturnType<typeof vi.spyOn> | undefined;

            if (!loadState) {
                loadStateSpy = vi.spyOn(driver, "loadState").mockResolvedValue(undefined);
            }

            const getPropertySpy = vi
                .spyOn(driver, "getProperty")
                .mockResolvedValueOnce(mockGetPropertyPayload("7e8106010403db0a7e")) // PROTOCOL_VERSION
                .mockResolvedValueOnce(
                    mockGetPropertyPayload(
                        "7e820602534c2d4f50454e5448524541442f322e352e322e305f4769744875622d3166636562323235623b2045465233323b204d617220313920323032352031333a34353a343400b5dc7e",
                    ),
                ) // NCP_VERSION
                .mockResolvedValueOnce(mockGetPropertyPayload("7e83060303573a7e")) // INTERFACE_TYPE
                .mockResolvedValueOnce(mockGetPropertyPayload("7e8406b0010a681f7e")) // RCP_API_VERSION
                .mockResolvedValueOnce(mockGetPropertyPayload("7e8506b101048ea77e")); // RCP_MIN_HOST_API_VERSION

            const waitForResetSpy = vi.spyOn(driver, "waitForReset").mockImplementationOnce(async () => {
                const p = driver.waitForReset();

                if (timeoutReset) {
                    await vi.advanceTimersByTimeAsync(5500);
                } else {
                    driver.parser._transform(Buffer.from(RESET_POWER_ON_FRAME_HEX, "hex"), "utf8", () => {});
                    await vi.advanceTimersByTimeAsync(10);
                }

                await p;
            });

            await driver.start();

            nextTidFromStartup += 1; // sendCommand RESET

            loadStateSpy?.mockRestore();
            getPropertySpy.mockRestore();
            waitForResetSpy.mockRestore();

            await vi.advanceTimersByTimeAsync(100); // flush
        }
    };

    const mockStop = async (driver: OTRCPDriver, expectThrow?: string) => {
        if (driver) {
            const setPropertySpy = vi.spyOn(driver, "setProperty").mockResolvedValue();

            if (expectThrow !== undefined) {
                await expect(driver.stop()).rejects.toThrow();
            } else {
                await driver.stop();
            }

            setPropertySpy.mockRestore();

            await vi.advanceTimersByTimeAsync(100); // flush
        }
    };

    const mockFormNetwork = async (driver: OTRCPDriver, registerTimers = false) => {
        if (driver) {
            const setPropertySpy = vi.spyOn(driver, "setProperty").mockResolvedValue();
            const getPropertySpy = vi
                .spyOn(driver, "getProperty")
                .mockResolvedValueOnce(mockGetPropertyPayload("7e8106257d3343647e")) // PHY_TX_POWER
                .mockResolvedValueOnce(mockGetPropertyPayload("7e82062695d88a7e")) // PHY_RSSI
                .mockResolvedValueOnce(mockGetPropertyPayload("7e8306279c7a127e")) // PHY_RX_SENSITIVITY
                .mockResolvedValueOnce(mockGetPropertyPayload("7e840624b5f0d37e")); // PHY_CCA_THRESHOLD

            let registerTimersSpy: ReturnType<typeof vi.spyOn> | undefined;

            if (registerTimers) {
                await mockRegisterTimers(driver);
            } else {
                registerTimersSpy = vi.spyOn(driver, "registerTimers").mockResolvedValue();
            }

            await driver.formNetwork();

            setPropertySpy.mockRestore();
            getPropertySpy.mockRestore();
            registerTimersSpy?.mockRestore();

            await vi.advanceTimersByTimeAsync(100); // flush
        }
    };

    const mockRegisterTimers = async (driver: OTRCPDriver) => {
        if (driver) {
            let linksSpy: ZigbeeNWKLinkStatus[] | undefined;
            let manyToOneSpy: ZigbeeNWKManyToOne | undefined;
            let destination16Spy: number | undefined;

            // creates a bottleneck with vitest & promises, noop it
            const savePeriodicStateSpy = vi.spyOn(driver, "savePeriodicState").mockResolvedValue();
            const sendZigbeeNWKLinkStatusSpy = vi.spyOn(driver, "sendZigbeeNWKLinkStatus").mockImplementationOnce(async (links) => {
                linksSpy = links;
                const p = driver.sendZigbeeNWKLinkStatus(links);
                // LINK_STATUS => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            const sendZigbeeNWKRouteReqSpy = vi.spyOn(driver, "sendZigbeeNWKRouteReq").mockImplementationOnce(async (manyToOne, destination16) => {
                manyToOneSpy = manyToOne;
                destination16Spy = destination16;
                const p = driver.sendZigbeeNWKRouteReq(manyToOne, destination16);
                // ROUTE_REQ => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 1), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await driver.registerTimers();
            await vi.advanceTimersByTimeAsync(100); // flush

            expect(savePeriodicStateSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(1 + 1); // *2 by spy mock
            expect(sendZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(1 + 1); // *2 by spy mock

            nextTidFromStartup += 2;

            return [linksSpy, manyToOneSpy, destination16Spy];
        }

        return [undefined, undefined, undefined];
    };

    beforeAll(() => {
        vi.useFakeTimers();
    });

    afterAll(() => {
        vi.useRealTimers();
    });

    afterEach(async () => {
        await endWireshark();

        nextTidFromStartup = 1;
    });

    describe("State/Network management", () => {
        let driver: OTRCPDriver;

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
                `temp_MGMT_${Math.floor(Math.random() * 1000000)}`,
                // true, // emitMACFrames
            );

            driver.parser.on("data", driver.onFrame.bind(driver));
        });

        afterEach(async () => {
            await mockStop(driver);

            if (driver) {
                rmSync(dirname(driver.savePath), { recursive: true, force: true });
            }
        });

        it("handles loading with given network params - first start", async () => {
            const saveStateSpy = vi.spyOn(driver, "saveState");

            await mockStart(driver);
            await mockFormNetwork(driver);

            expect(saveStateSpy).toHaveBeenCalledTimes(1);

            expect(driver.netParams.eui64).toStrictEqual(Buffer.from(A_EUI64).readBigUInt64LE(0));
            expect(driver.netParams.panId).toStrictEqual(NETDEF_PAN_ID);
            expect(driver.netParams.extendedPANId).toStrictEqual(Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0));
            expect(driver.netParams.channel).toStrictEqual(A_CHANNEL);
            expect(driver.netParams.nwkUpdateId).toStrictEqual(0);
            expect(driver.netParams.txPower).toStrictEqual(10);
            expect(driver.netParams.networkKey).toStrictEqual(Buffer.from(NETDEF_NETWORK_KEY));
            expect(driver.netParams.networkKeyFrameCounter).toStrictEqual(0);
            expect(driver.netParams.networkKeySequenceNumber).toStrictEqual(0);
            expect(driver.netParams.tcKey).toStrictEqual(Buffer.from(NETDEF_TC_KEY));
            expect(driver.netParams.tcKeyFrameCounter).toStrictEqual(0);
            expect(driver.deviceTable.size).toStrictEqual(0);
            expect(driver.address16ToAddress64.size).toStrictEqual(0);
            expect(driver.indirectTransmissions.size).toStrictEqual(0);

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
            const rndEui64 = randomBigInt();
            driver.netParams.eui64 = rndEui64;
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
            driver.deviceTable.set(1234n, {
                address16: 1,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [],
            });
            driver.deviceTable.set(12656887476334n, {
                address16: 3457,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [],
            });
            driver.deviceTable.set(12328965645634n, {
                address16: 9674,
                capabilities: structuredClone(COMMON_RFD_MAC_CAP),
                authorized: true,
                neighbor: false,
                recentLQAs: [],
            });
            driver.deviceTable.set(234367481234n, {
                address16: 54748,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: false,
                neighbor: true,
                recentLQAs: [],
            });
            driver.sourceRouteTable.set(1, [
                { pathCost: 1, relayAddresses: [] },
                { pathCost: 2, relayAddresses: [3457] },
            ]);
            driver.sourceRouteTable.set(3457, []);
            driver.sourceRouteTable.set(9674, [{ pathCost: 3, relayAddresses: [3457, 65348] }]);

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
            driver.sourceRouteTable.clear();

            await driver.loadState();

            expect(driver.netParams.eui64).toStrictEqual(rndEui64);
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
            expect(driver.deviceTable.get(1234n)).toStrictEqual({
                address16: 1,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [],
            });
            expect(driver.deviceTable.get(12656887476334n)).toStrictEqual({
                address16: 3457,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [],
            });
            expect(driver.deviceTable.get(12328965645634n)).toStrictEqual({
                address16: 9674,
                capabilities: structuredClone(COMMON_RFD_MAC_CAP),
                authorized: true,
                neighbor: false,
                recentLQAs: [],
            });
            expect(driver.deviceTable.get(234367481234n)).toStrictEqual({
                address16: 54748,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: false,
                neighbor: true,
                recentLQAs: [],
            });
            expect(driver.address16ToAddress64.size).toStrictEqual(4);
            expect(driver.address16ToAddress64.get(1)).toStrictEqual(1234n);
            expect(driver.address16ToAddress64.get(3457)).toStrictEqual(12656887476334n);
            expect(driver.address16ToAddress64.get(9674)).toStrictEqual(12328965645634n);
            expect(driver.address16ToAddress64.get(54748)).toStrictEqual(234367481234n);
            expect(driver.indirectTransmissions.size).toStrictEqual(1);
            expect(driver.indirectTransmissions.get(12328965645634n)).toStrictEqual([]);
            expect(driver.sourceRouteTable.size).toStrictEqual(2);
            expect(driver.sourceRouteTable.get(1)).toStrictEqual([
                { pathCost: 1, relayAddresses: [] },
                { pathCost: 2, relayAddresses: [3457] },
            ]);
            expect(driver.sourceRouteTable.get(9674)).toStrictEqual([{ pathCost: 3, relayAddresses: [3457, 65348] }]);
        });

        it("loads given network params when invalid state file", async () => {
            await writeFile(driver.savePath, Buffer.alloc(1));
            await driver.loadState();

            expect(driver.netParams.eui64).toStrictEqual(Buffer.from(A_EUI64).readBigUInt64LE(0));
            expect(driver.netParams.panId).toStrictEqual(NETDEF_PAN_ID);
            expect(driver.netParams.extendedPANId).toStrictEqual(Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0));
            expect(driver.netParams.channel).toStrictEqual(A_CHANNEL);
            expect(driver.netParams.nwkUpdateId).toStrictEqual(0);
            expect(driver.netParams.txPower).toStrictEqual(10);
            expect(driver.netParams.networkKey).toStrictEqual(Buffer.from(NETDEF_NETWORK_KEY));
            expect(driver.netParams.networkKeyFrameCounter).toStrictEqual(0);
            expect(driver.netParams.networkKeySequenceNumber).toStrictEqual(0);
            expect(driver.netParams.tcKey).toStrictEqual(Buffer.from(NETDEF_TC_KEY));
            expect(driver.netParams.tcKeyFrameCounter).toStrictEqual(0);
            expect(driver.deviceTable.size).toStrictEqual(0);
            expect(driver.address16ToAddress64.size).toStrictEqual(0);
            expect(driver.indirectTransmissions.size).toStrictEqual(0);
        });

        it("throws when source route table too large for device", async () => {
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
            driver.deviceTable.set(1234n, {
                address16: 1,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [],
            });
            const sourceRouteTableEntries: SourceRouteTableEntry[] = [];

            for (let i = 0; i < 255; i++) {
                sourceRouteTableEntries.push({ pathCost: Math.floor(Math.random() * 10), relayAddresses: [1, 2, 3, 4, 5] });
            }

            driver.sourceRouteTable.set(1, sourceRouteTableEntries);

            await expect(mockStop(driver, "Save size overflow")).resolves.toStrictEqual(undefined);

            rmSync(dirname(driver.savePath), { recursive: true, force: true });
            // @ts-expect-error override, prevent `mockStop` in `afterEach` hook
            driver = undefined;
        });

        it("throw on failed RESET", async () => {
            await expect(mockStart(driver, true, true)).rejects.toThrow("Reset timeout after 5000ms");
        });

        it("resets network", async () => {
            await writeFile(driver.savePath, Buffer.alloc(1));
            await driver.resetNetwork();

            expect(existsSync(driver.savePath)).toStrictEqual(false);
            expect(driver.deviceTable.size).toStrictEqual(0);
            expect(driver.address16ToAddress64.size).toStrictEqual(0);
            expect(driver.sourceRouteTable.size).toStrictEqual(0);
            expect(driver.indirectTransmissions.size).toStrictEqual(0);
            expect(driver.pendingAssociations.size).toStrictEqual(0);
        });

        it("throw when trying to reset network after state already loaded", async () => {
            await mockStart(driver);

            await expect(driver.resetNetwork()).rejects.toThrow("Cannot reset network after state already loaded");
        });

        it("forms network", async () => {
            await mockStart(driver);
            await mockFormNetwork(driver);

            expect(driver.isNetworkUp()).toStrictEqual(true);
            expect(driver.protocolVersionMajor).toStrictEqual(4);
            expect(driver.protocolVersionMinor).toStrictEqual(3);
            expect(driver.ncpVersion).toStrictEqual("SL-OPENTHREAD/2.5.2.0_GitHub-1fceb225b; EFR32; Mar 19 2025 13:45:44");
            expect(driver.interfaceType).toStrictEqual(3);
            expect(driver.rcpAPIVersion).toStrictEqual(10);
            expect(driver.rcpMinHostAPIVersion).toStrictEqual(4);
        });

        it("throws when trying to form network before state is loaded", async () => {
            await expect(driver.formNetwork()).rejects.toThrow("Cannot form network before state is loaded");
        });

        it("sets node descriptor manufacturer code", async () => {
            await mockStart(driver);
            await mockFormNetwork(driver);

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

        it("assigns all possible network addresses without conflicting", () => {
            const assignedAddresses: number[] = [];

            for (let i = 0; i < ZigbeeConsts.BCAST_MIN - 1; i++) {
                const assignedAddress = driver.assignNetworkAddress();
                assignedAddresses.push(assignedAddress);
                driver.address16ToAddress64.set(assignedAddress, 1n); // doesn't matter
            }

            expect(assignedAddresses.length).toStrictEqual(new Set(assignedAddresses).size);
            expect(new Set(assignedAddresses).size).toStrictEqual(ZigbeeConsts.BCAST_MIN - 1);
        });
    });

    describe("NETDEF", () => {
        let driver: OTRCPDriver;

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
                `temp_NETDEF_${Math.floor(Math.random() * 1000000)}`,
                // true, // emitMACFrames
            );
            driver.parser.on("data", driver.onFrame.bind(driver));

            await mockStart(driver);
            await mockFormNetwork(driver);
        });

        afterEach(async () => {
            await mockStop(driver);
            rmSync(dirname(driver.savePath), { recursive: true, force: true });
        });

        it("ignores bogus data before start of HDLC frame", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(nextTidFromStartup);

            driver.parser._transform(Buffer.concat([Buffer.from([0x12, 0x32]), frame]), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(parserEmit).toHaveBeenNthCalledWith(1, "data", frame);
        });

        it("ignores bogus data after end of HDLC frame", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(nextTidFromStartup);

            driver.parser._transform(Buffer.concat([frame, Buffer.from([0x12, 0x32])]), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(parserEmit).toHaveBeenNthCalledWith(1, "data", frame);
        });

        it("ignores bogus data before start and after end of HDLC frame", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(nextTidFromStartup);

            driver.parser._transform(Buffer.concat([Buffer.from([0x12, 0x32]), frame, Buffer.from([0x12, 0x32])]), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(parserEmit).toHaveBeenNthCalledWith(1, "data", frame);
        });

        it("skips duplicate FLAGs of HDLC frame", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(nextTidFromStartup);

            driver.parser._transform(Buffer.concat([Buffer.from([0x7e, 0x7e]), frame, Buffer.from([0x7e, 0x7e])]), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(parserEmit).toHaveBeenNthCalledWith(1, "data", frame);
        });

        it("handles multiple HDLC frames in same transform call", async () => {
            const parserEmit = vi.spyOn(driver.parser, "emit");
            const frame = makeSpinelLastStatus(nextTidFromStartup);
            const frame2 = makeSpinelLastStatus(nextTidFromStartup);

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
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            await expect(p).resolves.toStrictEqual(undefined);
            expect(waitForTIDSpy).toHaveBeenCalledWith(nextTidFromStartup, 10000);
            expect(sendFrameSpy).toHaveBeenCalledTimes(1);
        });

        it("sends frame NETDEF_MTORR_FRAME_FROM_COORD and receives LAST_STATUS response", async () => {
            const waitForTIDSpy = vi.spyOn(driver, "waitForTID");
            const sendFrameSpy = vi.spyOn(driver, "sendFrame");

            const p = driver.sendMACFrame(1, NETDEF_MTORR_FRAME_FROM_COORD, undefined, undefined); // bypass indirect transmissions
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            await expect(p).resolves.toStrictEqual(undefined);
            expect(waitForTIDSpy).toHaveBeenCalledWith(nextTidFromStartup, 10000);
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
                0, // unknown device
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

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(0);
            expect(sendZigbeeNWKRouteReplySpy).toHaveBeenCalledTimes(0);
        });

        it("receives frame NETDEF_ZGP_COMMISSIONING while in commissioning mode", async () => {
            driver.gpEnterCommissioningMode(0xfe); // in commissioning mode

            const emitSpy = vi.spyOn(driver, "emit");
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKGPFrameSpy = vi.spyOn(driver, "processZigbeeNWKGPFrame");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ZGP_COMMISSIONING), "utf8", () => {});
            await vi.runOnlyPendingTimersAsync();

            const expectedMACHeader: MACHeader = {
                frameControl: {
                    frameType: 0x1,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: false,
                    panIdCompression: false,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: 0x2,
                    frameVersion: 0,
                    sourceAddrMode: 0x0,
                },
                sequenceNumber: 70,
                destinationPANId: 0xffff,
                destination16: 0xffff,
                sourcePANId: 0xffff,
                fcs: 0xffff,
            };
            const expectedNWKGPHeader: ZigbeeNWKGPHeader = {
                frameControl: {
                    frameType: 0x0,
                    protocolVersion: 3,
                    autoCommissioning: false,
                    nwkFrameControlExtension: false,
                },
                sourceId: 0x0155f47a,
                micSize: 0,
                payloadLength: 52,
            };

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKGPFrameSpy).toHaveBeenCalledTimes(1);
            expect(emitSpy).toHaveBeenCalledWith(
                "gpFrame",
                0xe0,
                Buffer.from([
                    0x2, 0x85, 0xf2, 0xc9, 0x25, 0x82, 0x1d, 0xf4, 0x6f, 0x45, 0x8c, 0xf0, 0xe6, 0x37, 0xaa, 0xc3, 0xba, 0xb6, 0xaa, 0x45, 0x83, 0x1a,
                    0x11, 0x46, 0x23, 0x0, 0x0, 0x4, 0x16, 0x10, 0x11, 0x22, 0x23, 0x18, 0x19, 0x14, 0x15, 0x12, 0x13, 0x64, 0x65, 0x62, 0x63, 0x1e,
                    0x1f, 0x1c, 0x1d, 0x1a, 0x1b, 0x16, 0x17,
                ]),
                expectedMACHeader,
                expectedNWKGPHeader,
                0,
            );
        });

        it("receives frame NETDEF_ZGP_COMMISSIONING while not in commissioning mode", async () => {
            // driver.gpEnterCommissioningMode(0xfe); // not in commissioning mode

            const emitSpy = vi.spyOn(driver, "emit");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ZGP_COMMISSIONING), "utf8", () => {});
            await vi.runOnlyPendingTimersAsync();

            expect(emitSpy).toHaveBeenCalledTimes(0);
        });

        it("receives frame NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0", async () => {
            const emitSpy = vi.spyOn(driver, "emit");
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKGPFrameSpy = vi.spyOn(driver, "processZigbeeNWKGPFrame");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0), "utf8", () => {});
            await vi.runOnlyPendingTimersAsync();

            const expectedMACHeader: MACHeader = {
                frameControl: {
                    frameType: 0x1,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: false,
                    panIdCompression: false,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: 0x2,
                    frameVersion: 0,
                    sourceAddrMode: 0x0,
                },
                sequenceNumber: 185,
                destinationPANId: 0xffff,
                destination16: 0xffff,
                sourcePANId: 0xffff,
                fcs: 0xffff,
            };
            const expectedNWKGPHeader: ZigbeeNWKGPHeader = {
                frameControl: {
                    frameType: 0x0,
                    protocolVersion: 3,
                    autoCommissioning: false,
                    nwkFrameControlExtension: true,
                },
                frameControlExt: {
                    appId: 0,
                    direction: 0,
                    rxAfterTx: false,
                    securityKey: true,
                    securityLevel: 2,
                },
                sourceId: 24221335,
                securityFrameCounter: 185,
                micSize: 4,
                payloadLength: 1,
                mic: 3523079166,
            };

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKGPFrameSpy).toHaveBeenCalledTimes(1);
            expect(emitSpy).toHaveBeenCalledWith("gpFrame", 0x10, Buffer.from([]), expectedMACHeader, expectedNWKGPHeader, 0);
        });
    });

    describe("NET2", () => {
        let driver: OTRCPDriver;

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
                `temp_NET2_${Math.floor(Math.random() * 1000000)}`,
                // true, // emitMACFrames
            );
            driver.parser.on("data", driver.onFrame.bind(driver));

            await mockStart(driver);
            await mockFormNetwork(driver);
        });

        afterEach(async () => {
            await mockStop(driver);
            rmSync(dirname(driver.savePath), { recursive: true, force: true });
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
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: false,
                neighbor: true,
                recentLQAs: [],
            });
            driver.address16ToAddress64.set(0xa18f, source64);

            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeAPSRequestKeySpy = vi.spyOn(driver, "processZigbeeAPSRequestKey");
            const sendZigbeeAPSTransportKeyTCSpy = vi.spyOn(driver, "sendZigbeeAPSTransportKeyTC");

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_REQUEST_KEY_TC_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

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

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_BEACON_REQ_FROM_DEVICE), "utf8", () => {});
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});

            expect(sendMACFrameSpy).toHaveBeenCalledTimes(1);
            const beaconRespFrame = sendMACFrameSpy.mock.calls[0][1];
            const [decBeaconRespFCF, decBeaconRespFCFOffset] = decodeMACFrameControl(beaconRespFrame, 0);
            const [decBeaconRespHeader] = decodeMACHeader(beaconRespFrame, decBeaconRespFCFOffset, decBeaconRespFCF);

            expect(decBeaconRespHeader.superframeSpec?.associationPermit).toStrictEqual(false);

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_ASSOC_REQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelStreamRaw(1, NET2_DATA_RQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ASSOC_RSP => OK
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
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
            // creates a bottleneck with vitest & promises, noop it
            const savePeriodicStateSpy = vi.spyOn(driver, "savePeriodicState").mockResolvedValue();
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");
            const sendMACAssocRspSpy = vi.spyOn(driver, "sendMACAssocRsp");
            const sendZigbeeAPSTransportKeyNWKSpy = vi.spyOn(driver, "sendZigbeeAPSTransportKeyNWK");
            vi.spyOn(driver, "assignNetworkAddress").mockReturnValueOnce(0xa18f); // force nwk16 matching vectors

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_BEACON_REQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // BEACON_RSP => OK
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(sendMACFrameSpy).toHaveBeenCalledTimes(1);
            const beaconRespFrame = sendMACFrameSpy.mock.calls[0][1];
            const [decBeaconRespFCF, decBeaconRespFCFOffset] = decodeMACFrameControl(beaconRespFrame, 0);
            const [decBeaconRespHeader] = decodeMACHeader(beaconRespFrame, decBeaconRespFCFOffset, decBeaconRespFCF);

            expect(decBeaconRespHeader.superframeSpec?.associationPermit).toStrictEqual(true);

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_ASSOC_REQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelStreamRaw(1, NET2_DATA_RQ_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ASSOC_RSP => OK
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 1), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // TRANSPORT_KEY NWK => OK
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 2), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(savePeriodicStateSpy).toHaveBeenCalledTimes(1);
            expect(sendMACAssocRspSpy).toHaveBeenCalledTimes(1);
            expect(sendMACAssocRspSpy).toHaveBeenCalledWith(11871832136131022815n, 0xa18f, MACAssociationStatus.SUCCESS);
            expect(sendZigbeeAPSTransportKeyNWKSpy).toHaveBeenCalledTimes(1);
            expect(driver.deviceTable.get(11871832136131022815n)).toStrictEqual({
                address16: 0xa18f,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: false,
                neighbor: true,
                recentLQAs: [],
            });

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_DEVICE_ANNOUNCE_BCAST, Buffer.from([0xd8, 0xff, 0x00, 0x00])), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(emitSpy).toHaveBeenNthCalledWith(1, "deviceJoined", 0xa18f, 11871832136131022815n, structuredClone(COMMON_FFD_MAC_CAP));
            expect(emitSpy).toHaveBeenNthCalledWith(2, "frame", 0xa18f, undefined, expect.any(Object), expect.any(Buffer), 200);

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_NODE_DESC_REQ_FROM_DEVICE, Buffer.from([0xce, 0xff, 0x00, 0x00])), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // node desc APS ACK => OK
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 3), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // node desc RESP => OK
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 4), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            driver.parser._transform(
                makeSpinelStreamRaw(1, NET2_REQUEST_KEY_TC_FROM_DEVICE, Buffer.from([0xd3, 0xff, 0x00, 0x00])),
                "utf8",
                () => {},
            );
            await vi.advanceTimersByTimeAsync(10);
            // TRANSPORT_KEY TC => OK
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 5), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_VERIFY_KEY_TC_FROM_DEVICE, Buffer.from([0xd5, 0xff, 0x00, 0x00])), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // CONFIRM_KEY => OK
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 6), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(driver.deviceTable.get(11871832136131022815n)).toStrictEqual({
                address16: 0xa18f,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [200, 153, 178, 188],
            });
        });

        // it("performs a join & authorize - END DEVICE", async () => {
        //     // TODO: with DATA req (indirect transmission)
        // });
    });

    describe("NET3", () => {
        let driver: OTRCPDriver;

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
                `temp_NET3_${Math.floor(Math.random() * 1000000)}`,
                true, // emitMACFrames
            );
            driver.parser.on("data", driver.onFrame.bind(driver));
            // joined devices
            // 5c:c7:c1:ff:fe:5e:70:ea
            driver.deviceTable.set(6685525477083214058n, {
                address16: 0x3ab1,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [],
            });
            driver.address16ToAddress64.set(0x3ab1, 6685525477083214058n);
            // not set on purpose to observe change from actual route record
            // driver.sourceRouteTable.set(0x3ab1, [{relayAddresses: [], pathCost: 1}]);

            await mockStart(driver);
            await mockFormNetwork(driver);
        });

        afterEach(async () => {
            await mockStop(driver);
            rmSync(dirname(driver.savePath), { recursive: true, force: true });
        });

        it("registers timers", async () => {
            const sendPeriodicZigbeeNWKLinkStatusSpy = vi.spyOn(driver, "sendPeriodicZigbeeNWKLinkStatus");
            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");
            const processZigbeeNWKRouteRecordSpy = vi.spyOn(driver, "processZigbeeNWKRouteRecord");

            let [linksSpy, manyToOneSpy, destination16Spy] = await mockRegisterTimers(driver);

            expect(linksSpy).toStrictEqual([{ address: 0x3ab1, incomingCost: 0, outgoingCost: 0 }]);
            expect(manyToOneSpy).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            expect(destination16Spy).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(sendPeriodicZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(1);
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1);

            driver.parser._transform(makeSpinelStreamRaw(1, NET3_ROUTE_RECORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ROUTE_RECORD => OK
            driver.parser._transform(makeSpinelLastStatus(1), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(processZigbeeNWKRouteRecordSpy).toHaveBeenCalledTimes(1);

            //--- SECOND TRIGGER

            const sendZigbeeNWKLinkStatusSpy = vi.spyOn(driver, "sendZigbeeNWKLinkStatus").mockImplementationOnce(async (links) => {
                linksSpy = links;
                const p = driver.sendZigbeeNWKLinkStatus(links);
                // LINK_STATUS => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await vi.advanceTimersByTimeAsync(17000);

            expect(sendPeriodicZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(2);
            expect(linksSpy).toStrictEqual([{ address: 0x3ab1, incomingCost: 1, outgoingCost: 1 }]);

            sendZigbeeNWKLinkStatusSpy.mockImplementationOnce(async (links) => {
                linksSpy = links;
                const p = driver.sendZigbeeNWKLinkStatus(links);
                // LINK_STATUS => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 1), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await vi.advanceTimersByTimeAsync(17000);

            expect(sendPeriodicZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(3);
            expect(linksSpy).toStrictEqual([{ address: 0x3ab1, incomingCost: 1, outgoingCost: 1 }]);

            sendZigbeeNWKLinkStatusSpy.mockImplementationOnce(async (links) => {
                linksSpy = links;
                const p = driver.sendZigbeeNWKLinkStatus(links);
                // LINK_STATUS => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 2), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await vi.advanceTimersByTimeAsync(17000);

            expect(sendPeriodicZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(4);
            expect(linksSpy).toStrictEqual([{ address: 0x3ab1, incomingCost: 1, outgoingCost: 1 }]);

            const sendZigbeeNWKRouteReqSpy = vi.spyOn(driver, "sendZigbeeNWKRouteReq").mockImplementationOnce(async (manyToOne, destination16) => {
                manyToOneSpy = manyToOne;
                destination16Spy = destination16;
                const p = driver.sendZigbeeNWKRouteReq(manyToOne, destination16);
                // ROUTE_REQ => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 3), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                await p;
            });
            await vi.advanceTimersByTimeAsync(10000);
            await vi.advanceTimersByTimeAsync(100); // flush

            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(2);
            expect(sendZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(3 + 3); // *2 spy mock
            expect(sendZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(1 + 1); // *2 spy mock
            expect(manyToOneSpy).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            expect(destination16Spy).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);

            await vi.runOnlyPendingTimersAsync(); // flush
        });
    });

    describe("NET4", () => {
        let driver: OTRCPDriver;

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
                `temp_NET4_${Math.floor(Math.random() * 1000000)}`,
                true, // emitMACFrames
            );

            driver.parser.on("data", driver.onFrame.bind(driver));
            // joined devices
            // 80:4b:50:ff:fe:a4:b9:73
            driver.deviceTable.set(9244571720527165811n, {
                address16: 0x96ba,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [],
            });
            driver.address16ToAddress64.set(0x96ba, 9244571720527165811n);
            // driver.sourceRouteTable.set(0x96ba, [{relayAddresses: [], pathCost: 1}]);
            // 70:ac:08:ff:fe:d0:4a:58
            driver.deviceTable.set(8118874123826907736n, {
                address16: 0x91d2,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [],
            });
            driver.address16ToAddress64.set(0x91d2, 8118874123826907736n);
            // driver.sourceRouteTable.set(0x91d2, [{relayAddresses: [], pathCost: 1}]);
            // 00:12:4b:00:24:c2:e1:e1
            driver.deviceTable.set(5149013569626593n, {
                address16: 0xcb47,
                capabilities: structuredClone(COMMON_FFD_MAC_CAP),
                authorized: true,
                neighbor: true,
                recentLQAs: [],
            });
            driver.address16ToAddress64.set(0xcb47, 5149013569626593n);
            // mimic no source route entry for 0xcb47
            // 00:12:4b:00:29:27:fd:8c
            driver.deviceTable.set(5149013643361676n, {
                address16: 0x6887,
                capabilities: structuredClone(COMMON_RFD_MAC_CAP),
                authorized: true,
                neighbor: false,
                recentLQAs: [],
            });
            driver.address16ToAddress64.set(0x6887, 5149013643361676n);
            // driver.sourceRouteTable.set(0x6887, [{relayAddresses: [0x96ba], pathCost: 2}]);
            // 00:12:4b:00:25:49:f4:42
            driver.deviceTable.set(5149013578478658n, {
                address16: 0x9ed5,
                capabilities: structuredClone(COMMON_RFD_MAC_CAP),
                authorized: true,
                neighbor: false,
                recentLQAs: [],
            });
            driver.address16ToAddress64.set(0x9ed5, 5149013578478658n);
            // driver.sourceRouteTable.set(0x9ed5, [{relayAddresses: [0x91d2], pathCost: 2}]);
            // 00:12:4b:00:25:02:d0:3b
            driver.deviceTable.set(5149013573816379n, {
                address16: 0x4b8e,
                capabilities: structuredClone(COMMON_RFD_MAC_CAP),
                authorized: true,
                neighbor: false,
                recentLQAs: [],
            });
            driver.address16ToAddress64.set(0x4b8e, 5149013573816379n);
            // driver.sourceRouteTable.set(0x4b8e, [{relayAddresses: [0xcb47], pathCost: 2}]);

            await mockStart(driver);
            await mockFormNetwork(driver);
        });

        afterEach(async () => {
            await mockStop(driver);
            rmSync(dirname(driver.savePath), { recursive: true, force: true });
        });

        const fillSourceRouteTableFromRequests = async () => {
            if (driver) {
                driver.parser._transform(makeSpinelStreamRaw(1, NET4_ROUTE_RECORD_FROM_96BA_NO_RELAY), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                // ROUTE_RECORD => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);

                driver.parser._transform(makeSpinelStreamRaw(1, NET4_ROUTE_RECORD_FROM_91D2_NO_RELAY), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                // ROUTE_RECORD => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);

                driver.parser._transform(makeSpinelStreamRaw(1, NET4_ROUTE_RECORD_FROM_6887_RELAY_96BA), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                // ROUTE_RECORD => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);

                driver.parser._transform(makeSpinelStreamRaw(1, NET4_ROUTE_RECORD_FROM_9ED5_RELAY_91D2), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                // ROUTE_RECORD => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);

                driver.parser._transform(makeSpinelStreamRaw(1, NET4_ROUTE_RECORD_FROM_4B8E_RELAY_CB47), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                // ROUTE_RECORD => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
            } else {
                throw new Error("Invalid test state");
            }
        };

        it("handles source routing", async () => {
            const [linksSpy, manyToOneSpy, destination16Spy] = await mockRegisterTimers(driver);

            expect(linksSpy).toStrictEqual([
                { address: 0x96ba, incomingCost: 0, outgoingCost: 0 },
                { address: 0x91d2, incomingCost: 0, outgoingCost: 0 },
                { address: 0xcb47, incomingCost: 0, outgoingCost: 0 },
            ]);
            expect(manyToOneSpy).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            expect(destination16Spy).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);

            const processZigbeeNWKRouteRecordSpy = vi.spyOn(driver, "processZigbeeNWKRouteRecord");

            await fillSourceRouteTableFromRequests();

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
            sendMACFrameSpy.mockResolvedValueOnce();
            await driver.sendZigbeeNWKStatus(0x96ba, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x96ba, 9244571720527165811n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, 1]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x96ba, undefined);

            sendMACFrameSpy.mockResolvedValueOnce();
            await driver.sendZigbeeNWKStatus(0x6887, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x6887, 5149013643361676n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0x96ba], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x96ba, undefined);

            //-- APS CMD
            sendMACFrameSpy.mockResolvedValueOnce();
            await driver.sendZigbeeAPSSwitchKey(0x91d2, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x91d2, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, 1]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x91d2, undefined);

            sendMACFrameSpy.mockResolvedValueOnce();
            await driver.sendZigbeeAPSSwitchKey(0x9ed5, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x9ed5, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0x91d2], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x91d2, undefined);

            //-- APS DATA
            sendMACFrameSpy.mockResolvedValueOnce();
            await driver.sendUnicast(Buffer.from([]), 0x1, 0x1, 0x91d2, undefined, 1, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x91d2, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, 1]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x91d2, undefined);

            sendMACFrameSpy.mockResolvedValueOnce();
            await driver.sendUnicast(Buffer.from([]), 0x1, 0x1, 0x6887, undefined, 1, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x6887, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0x96ba], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x96ba, undefined);

            //-- no source route (use given nwkDest16)
            sendMACFrameSpy.mockResolvedValueOnce();
            await driver.sendZigbeeNWKStatus(0xcb47, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0xcb47, 5149013569626593n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, undefined]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0xcb47, undefined);

            //-- no source route on source route (doesn't matter)
            sendMACFrameSpy.mockResolvedValueOnce();
            await driver.sendZigbeeNWKStatus(0x4b8e, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x4b8e, 5149013573816379n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0xcb47], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0xcb47, undefined);

            //-- no duplication of existing entries
            driver.parser._transform(makeSpinelStreamRaw(1, NET4_ROUTE_RECORD_FROM_4B8E_RELAY_CB47), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            // ROUTE_RECORD => OK
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(driver.sourceRouteTable.get(0x4b8e)!.length).toStrictEqual(1);

            await driver.disassociate(0xcb47, undefined);

            expect(driver.sourceRouteTable.get(0x4b8e)!.length).toStrictEqual(0);

            // triggers cleanup
            driver.findBestSourceRoute(0x4b8e, undefined);

            expect(driver.sourceRouteTable.get(0x4b8e)).toBeUndefined();
        });

        it("checks if source route exists in entries for a given device", () => {
            driver.sourceRouteTable.set(0x4b8e, [
                { relayAddresses: [1, 2], pathCost: 3 },
                { relayAddresses: [11, 22], pathCost: 3 },
                { relayAddresses: [33, 22, 44], pathCost: 4 },
                { relayAddresses: [], pathCost: 1 },
            ]);
            const existingEntries = driver.sourceRouteTable.get(0x4b8e)!;

            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [], pathCost: 1 }, existingEntries)).toStrictEqual(true);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [], pathCost: 2 }, existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [1, 2], pathCost: 3 }, existingEntries)).toStrictEqual(true);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [2, 1], pathCost: 3 }, existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [1, 2], pathCost: 2 }, existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [3], pathCost: 2 }, existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [4, 5], pathCost: 3 }, existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [1, 2], pathCost: 3 })).toStrictEqual(true);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [2, 1], pathCost: 3 })).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [1, 2], pathCost: 2 })).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [3], pathCost: 2 })).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, { relayAddresses: [4, 5], pathCost: 3 })).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x12345, { relayAddresses: [4, 5], pathCost: 3 })).toStrictEqual(false);
        });

        it("gets routing table", async () => {
            await fillSourceRouteTableFromRequests();

            expect(driver.sourceRouteTable.size).toStrictEqual(5);

            const initialRoutingTable = Buffer.from([
                0, // seq num
                0, // status
                3, // total entries
                0, // start index
                3, // entries following
                0x6887 & 0xff,
                (0x6887 >> 8) & 0xff,
                0,
                0x96ba & 0xff,
                (0x96ba >> 8) & 0xff,
                0x9ed5 & 0xff,
                (0x9ed5 >> 8) & 0xff,
                0,
                0x91d2 & 0xff,
                (0x91d2 >> 8) & 0xff,
                0x4b8e & 0xff,
                (0x4b8e >> 8) & 0xff,
                0,
                0xcb47 & 0xff,
                (0xcb47 >> 8) & 0xff,
            ]);
            let routingTable = driver.getRoutingTableResponse(0);

            // 0x6887 => 0x96ba
            // 0x9ed5 => 0x91d2
            // 0x4b8e => 0xcb47
            expect(routingTable).toStrictEqual(initialRoutingTable);

            const sr0x6887 = driver.sourceRouteTable.get(0x6887);
            const sr0x9ed5 = driver.sourceRouteTable.get(0x9ed5);
            const sr0x4b8e = driver.sourceRouteTable.get(0x4b8e);

            sr0x6887?.push({ relayAddresses: [0x0001, 0x0002], pathCost: 3 });
            sr0x6887?.push({ relayAddresses: [0x0003], pathCost: 2 });

            sr0x9ed5?.push({ relayAddresses: [0x0001], pathCost: 2 });

            sr0x4b8e?.push({ relayAddresses: [0x0001, 0x0002, 0x0003], pathCost: 4 });

            routingTable = driver.getRoutingTableResponse(0);

            // still the same
            expect(routingTable).toStrictEqual(initialRoutingTable);

            sr0x6887?.shift();

            routingTable = driver.getRoutingTableResponse(0);

            expect(routingTable).toStrictEqual(
                Buffer.from([
                    0, // seq num
                    0, // status
                    3, // total entries
                    0, // start index
                    3, // entries following
                    0x6887 & 0xff,
                    (0x6887 >> 8) & 0xff,
                    0,
                    0x0003 & 0xff,
                    (0x0003 >> 8) & 0xff,
                    0x9ed5 & 0xff,
                    (0x9ed5 >> 8) & 0xff,
                    0,
                    0x91d2 & 0xff,
                    (0x91d2 >> 8) & 0xff,
                    0x4b8e & 0xff,
                    (0x4b8e >> 8) & 0xff,
                    0,
                    0xcb47 & 0xff,
                    (0xcb47 >> 8) & 0xff,
                ]),
            );

            driver.sourceRouteTable.set(0x2345, [
                { relayAddresses: [0x0001, 0x0002, 0x0003], pathCost: 4 },
                { relayAddresses: [0x0004, 0x0005], pathCost: 3 },
            ]);

            expect(driver.sourceRouteTable.size).toStrictEqual(6);

            routingTable = driver.getRoutingTableResponse(0);

            expect(routingTable).toStrictEqual(
                Buffer.from([
                    0, // seq num
                    0, // status
                    4, // total entries
                    0, // start index
                    4, // entries following
                    0x6887 & 0xff,
                    (0x6887 >> 8) & 0xff,
                    0,
                    0x0003 & 0xff,
                    (0x0003 >> 8) & 0xff,
                    0x9ed5 & 0xff,
                    (0x9ed5 >> 8) & 0xff,
                    0,
                    0x91d2 & 0xff,
                    (0x91d2 >> 8) & 0xff,
                    0x4b8e & 0xff,
                    (0x4b8e >> 8) & 0xff,
                    0,
                    0xcb47 & 0xff,
                    (0xcb47 >> 8) & 0xff,
                    0x2345 & 0xff,
                    (0x2345 >> 8) & 0xff,
                    0,
                    5 & 0xff,
                    (5 >> 8) & 0xff,
                ]),
            );

            //-- mock LEAVE
            await driver.disassociate(0x91d2, 8118874123826907736n);

            expect(driver.sourceRouteTable.size).toStrictEqual(5);

            routingTable = driver.getRoutingTableResponse(0);

            expect(routingTable).toStrictEqual(
                Buffer.from([
                    0, // seq num
                    0, // status
                    4, // total entries
                    0, // start index
                    4, // entries following
                    0x6887 & 0xff,
                    (0x6887 >> 8) & 0xff,
                    0,
                    3 & 0xff,
                    (3 >> 8) & 0xff,
                    0x9ed5 & 0xff,
                    (0x9ed5 >> 8) & 0xff,
                    0,
                    0x0001 & 0xff,
                    (0x0001 >> 8) & 0xff,
                    0x4b8e & 0xff,
                    (0x4b8e >> 8) & 0xff,
                    0,
                    0xcb47 & 0xff,
                    (0xcb47 >> 8) & 0xff,
                    0x2345 & 0xff,
                    (0x2345 >> 8) & 0xff,
                    0,
                    5 & 0xff,
                    (5 >> 8) & 0xff,
                ]),
            );

            driver.sourceRouteTable.clear();

            expect(driver.sourceRouteTable.size).toStrictEqual(0);

            let clippedLastAddr16 = 0;
            let clippedLastRelay16 = 0;
            let lastAdrr16 = 0;
            let lastRelay16 = 0;

            //-- clipped to 0xff to fit ZDO uint8 count-type bytes
            for (let i = 0; i < 300; i++) {
                const addr16 = driver.assignNetworkAddress();
                const relay16 = driver.assignNetworkAddress();
                driver.sourceRouteTable.set(addr16, [{ relayAddresses: [relay16], pathCost: 2 }]);
                driver.address16ToAddress64.set(addr16, randomBigInt()); // just for dupe checking in `assignNetworkAddress`
                driver.address16ToAddress64.set(relay16, randomBigInt()); // just for dupe checking in `assignNetworkAddress`

                if (i === 254 /* 0-based */) {
                    clippedLastRelay16 = relay16;
                    clippedLastAddr16 = addr16;
                }

                lastRelay16 = relay16;
                lastAdrr16 = addr16;
            }

            expect(driver.sourceRouteTable.size).toStrictEqual(300);

            routingTable = driver.getRoutingTableResponse(0);

            expect(routingTable.byteLength).toStrictEqual(5 + 255 * 5);
            expect(routingTable.readUInt16LE(routingTable.byteLength - 5)).toStrictEqual(clippedLastAddr16);
            expect(routingTable.readUInt16LE(routingTable.byteLength - 2)).toStrictEqual(clippedLastRelay16);

            //---- non-zero offset
            routingTable = driver.getRoutingTableResponse(200);

            expect(routingTable.byteLength).toStrictEqual(5 + (300 - 200) * 5);
            expect(routingTable.readUInt16LE(routingTable.byteLength - 5)).toStrictEqual(lastAdrr16);
            expect(routingTable.readUInt16LE(routingTable.byteLength - 2)).toStrictEqual(lastRelay16);

            //---- non-zero offset, removed last entry
            driver.sourceRouteTable.set(lastAdrr16, [{ relayAddresses: [], pathCost: 1 }]);

            routingTable = driver.getRoutingTableResponse(200);

            expect(routingTable.byteLength).toStrictEqual(5 + (299 - 200) * 5);
            expect(routingTable.readUInt16LE(routingTable.byteLength - 5)).not.toStrictEqual(lastAdrr16);
            expect(routingTable.readUInt16LE(routingTable.byteLength - 2)).not.toStrictEqual(lastRelay16);
        });

        it("ignores direct routes when getting routing table ZDO", () => {
            driver.sourceRouteTable.set(0x4b8e, [
                { relayAddresses: [1, 2], pathCost: 3 },
                { relayAddresses: [11, 22], pathCost: 3 },
                { relayAddresses: [33, 22, 44], pathCost: 4 },
                { relayAddresses: [], pathCost: 1 },
            ]);

            const routingTable = driver.getRoutingTableResponse(0);

            expect(routingTable.byteLength).toStrictEqual(5 + 0);
        });

        it("maps RSSI to LQI", () => {
            let lqi = driver.mapRSSIToLQI(driver.rssiMin);
            expect(lqi).toStrictEqual(3); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(driver.rssiMax);
            expect(lqi).toStrictEqual(253); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-10);
            expect(lqi).toStrictEqual(255); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-20);
            expect(lqi).toStrictEqual(255); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-30);
            expect(lqi).toStrictEqual(252); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-35);
            expect(lqi).toStrictEqual(250); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-40);
            expect(lqi).toStrictEqual(246); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-45);
            expect(lqi).toStrictEqual(239); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-50);
            expect(lqi).toStrictEqual(227); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-55);
            expect(lqi).toStrictEqual(207); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-60);
            expect(lqi).toStrictEqual(176); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-65);
            expect(lqi).toStrictEqual(137); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-70);
            expect(lqi).toStrictEqual(97); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-80);
            expect(lqi).toStrictEqual(36); // console.log(lqi)

            lqi = driver.mapRSSIToLQI(-90);
            expect(lqi).toStrictEqual(11); // console.log(lqi)
        });

        it("computes LQA", () => {
            let lqa = driver.computeLQA(driver.rssiMin);
            expect(lqa).toStrictEqual(0); // console.log(lqa)

            lqa = driver.computeLQA(driver.rssiMax);
            expect(lqa).toStrictEqual(255); // console.log(lqa)

            lqa = driver.computeLQA(-10);
            expect(lqa).toStrictEqual(255); // console.log(lqa)

            lqa = driver.computeLQA(-20);
            expect(lqa).toStrictEqual(255); // console.log(lqa)

            lqa = driver.computeLQA(-30);
            expect(lqa).toStrictEqual(238); // console.log(lqa)

            lqa = driver.computeLQA(-35);
            expect(lqa).toStrictEqual(221); // console.log(lqa)

            lqa = driver.computeLQA(-40);
            expect(lqa).toStrictEqual(200); // console.log(lqa)

            lqa = driver.computeLQA(-45);
            expect(lqa).toStrictEqual(178); // console.log(lqa)

            lqa = driver.computeLQA(-50);
            expect(lqa).toStrictEqual(153); // console.log(lqa)

            lqa = driver.computeLQA(-55);
            expect(lqa).toStrictEqual(125); // console.log(lqa)

            lqa = driver.computeLQA(-60);
            expect(lqa).toStrictEqual(93); // console.log(lqa)

            lqa = driver.computeLQA(-65);
            expect(lqa).toStrictEqual(61); // console.log(lqa)

            lqa = driver.computeLQA(-70);
            expect(lqa).toStrictEqual(35); // console.log(lqa)

            lqa = driver.computeLQA(-80);
            expect(lqa).toStrictEqual(6); // console.log(lqa)

            lqa = driver.computeLQA(-90);
            expect(lqa).toStrictEqual(0); // console.log(lqa)
        });

        it("gets LQI table", async () => {
            expect(driver.deviceTable.size).toStrictEqual(6);

            driver.computeDeviceLQA(0x91d2, 8118874123826907736n, -40);
            driver.computeDeviceLQA(0x91d2, 8118874123826907736n, -42);
            driver.computeDeviceLQA(0x91d2, 8118874123826907736n, -45);
            driver.computeDeviceLQA(0x91d2, 8118874123826907736n, -45);
            driver.computeDeviceLQA(0x91d2, 8118874123826907736n, -53);
            driver.computeDeviceLQA(0x91d2, 8118874123826907736n, -48);

            let lqiTable = driver.getLQITableResponse(0);

            // driver.deviceTable.set(9244571720527165811n, { address16: 0x96ba, rxOnWhenIdle: true, authorized: true, neighbor: true, recentLQAs: [] });
            // driver.deviceTable.set(8118874123826907736n, { address16: 0x91d2, rxOnWhenIdle: true, authorized: true, neighbor: true, recentLQAs: [] });
            // driver.deviceTable.set(5149013569626593n, { address16: 0xcb47, rxOnWhenIdle: true, authorized: true, neighbor: true, recentLQAs: [] });
            const expectedLQITable = Buffer.alloc(255);
            let offset = 0;

            expectedLQITable.writeUInt8(0, offset); // seq num
            offset += 1;
            expectedLQITable.writeUInt8(0 /* SUCCESS */, offset); // status
            offset += 1;
            expectedLQITable.writeUInt8(3, offset); // total entries
            offset += 1;
            expectedLQITable.writeUInt8(0, offset); // start index
            offset += 1;
            expectedLQITable.writeUInt8(3, offset); // entries following
            offset += 1;

            expectedLQITable.writeBigUInt64LE(Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0), offset);
            offset += 8;
            expectedLQITable.writeBigUInt64LE(9244571720527165811n, offset);
            offset += 8;
            expectedLQITable.writeUInt16LE(0x96ba, offset);
            offset += 2;
            expectedLQITable.writeUInt8(0x01 | 0x01, offset);
            offset += 1;
            expectedLQITable.writeUInt8(0x02 /* TODO */, offset);
            offset += 1;
            expectedLQITable.writeUInt8(1 /* TODO */, offset);
            offset += 1;
            expectedLQITable.writeUInt8(0 /* no recent LQAs */, offset);
            offset += 1;

            expectedLQITable.writeBigUInt64LE(Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0), offset);
            offset += 8;
            expectedLQITable.writeBigUInt64LE(8118874123826907736n, offset);
            offset += 8;
            expectedLQITable.writeUInt16LE(0x91d2, offset);
            offset += 2;
            expectedLQITable.writeUInt8(0x01 | 0x01, offset);
            offset += 1;
            expectedLQITable.writeUInt8(0x02 /* TODO */, offset);
            offset += 1;
            expectedLQITable.writeUInt8(1 /* TODO */, offset);
            offset += 1;
            expectedLQITable.writeUInt8(178, offset);
            offset += 1;

            expectedLQITable.writeBigUInt64LE(Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0), offset);
            offset += 8;
            expectedLQITable.writeBigUInt64LE(5149013569626593n, offset);
            offset += 8;
            expectedLQITable.writeUInt16LE(0xcb47, offset);
            offset += 2;
            expectedLQITable.writeUInt8(0x01 | 0x01, offset);
            offset += 1;
            expectedLQITable.writeUInt8(0x02 /* TODO */, offset);
            offset += 1;
            expectedLQITable.writeUInt8(1 /* TODO */, offset);
            offset += 1;
            expectedLQITable.writeUInt8(0 /* no recent LQAs */, offset);
            offset += 1;

            expect(lqiTable).toStrictEqual(expectedLQITable.subarray(0, 5 + 3 * 22));

            await driver.disassociate(0xcb47, 5149013569626593n);
            expect(driver.deviceTable.size).toStrictEqual(5);

            lqiTable = driver.getLQITableResponse(0);
            expectedLQITable[2] = 2;
            expectedLQITable[4] = 2;

            expect(lqiTable).toStrictEqual(expectedLQITable.subarray(0, 5 + 2 * 22));
        });
    });

    describe("NET5", () => {
        let driver: OTRCPDriver;

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
                    eui64: Buffer.from(NET5_COORD_EUI64).readBigUInt64LE(0),
                    panId: NET5_PAN_ID,
                    extendedPANId: Buffer.from(NET5_EXTENDED_PAN_ID).readBigUInt64LE(0),
                    channel: A_CHANNEL,
                    nwkUpdateId: 0,
                    txPower: 10,
                    networkKey: Buffer.from(NET5_NETWORK_KEY),
                    networkKeyFrameCounter: 0,
                    networkKeySequenceNumber: 0,
                    tcKey: Buffer.from(NETDEF_TC_KEY),
                    tcKeyFrameCounter: 0,
                },
                `temp_NET5_${Math.floor(Math.random() * 1000000)}`,
                // true, // emitMACFrames
            );

            driver.parser.on("data", driver.onFrame.bind(driver));

            await mockStart(driver);
            await mockFormNetwork(driver);
        });

        afterEach(async () => {
            await mockStop(driver);
            rmSync(dirname(driver.savePath), { recursive: true, force: true });
        });

        it("receives from NET5_GP_CHANNEL_REQUEST_BCAST while in commissioning mode", async () => {
            driver.gpEnterCommissioningMode(0xfe); // in commissioning mode

            const emitSpy = vi.spyOn(driver, "emit");
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const onZigbeeAPSACKRequestSpy = vi.spyOn(driver, "onZigbeeAPSACKRequest");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKGPFrameSpy = vi.spyOn(driver, "processZigbeeNWKGPFrame");

            driver.parser._transform(makeSpinelStreamRaw(1, NET5_GP_CHANNEL_REQUEST_BCAST), "utf8", () => {});
            await vi.runOnlyPendingTimersAsync();
            const expectedMACHeader: MACHeader = {
                frameControl: {
                    frameType: 0x1,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: false,
                    panIdCompression: false,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: 0x2,
                    frameVersion: 0,
                    sourceAddrMode: 0x0,
                },
                sequenceNumber: 1,
                destinationPANId: 0xffff,
                destination16: 0xffff,
                destination64: undefined,
                sourcePANId: 0xffff,
                source16: undefined,
                source64: undefined,
                auxSecHeader: undefined,
                superframeSpec: undefined,
                gtsInfo: undefined,
                pendAddr: undefined,
                commandId: undefined,
                headerIE: undefined,
                frameCounter: undefined,
                keySeqCounter: undefined,
                fcs: 0x7808,
            };
            const expectedNWKGPHeader: ZigbeeNWKGPHeader = {
                frameControl: {
                    frameType: 0x1,
                    protocolVersion: 3,
                    autoCommissioning: true,
                    nwkFrameControlExtension: false,
                },
                frameControlExt: undefined,
                sourceId: undefined,
                endpoint: undefined,
                securityFrameCounter: undefined,
                micSize: 0,
                payloadLength: 2,
                mic: undefined,
            };

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(onZigbeeAPSACKRequestSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKGPFrameSpy).toHaveBeenCalledTimes(1);
            expect(emitSpy).toHaveBeenCalledWith("gpFrame", 0xe3, Buffer.from([0x85]), expectedMACHeader, expectedNWKGPHeader, 0);
        });

        it("receives frame NET5_GP_CHANNEL_REQUEST_BCAST while not in commissioning mode", async () => {
            // driver.gpEnterCommissioningMode(0xfe); // not in commissioning mode

            const emitSpy = vi.spyOn(driver, "emit");

            driver.parser._transform(makeSpinelStreamRaw(1, NET5_GP_CHANNEL_REQUEST_BCAST), "utf8", () => {});
            await vi.runOnlyPendingTimersAsync();

            expect(emitSpy).toHaveBeenCalledTimes(0);
        });

        it("receives duplicate frame NET5_GP_CHANNEL_REQUEST_BCAST", async () => {
            driver.gpEnterCommissioningMode(0xfe); // in commissioning mode

            const emitSpy = vi.spyOn(driver, "emit");
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");

            driver.parser._transform(makeSpinelStreamRaw(1, NET5_GP_CHANNEL_REQUEST_BCAST), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(100);

            driver.parser._transform(makeSpinelStreamRaw(1, NET5_GP_CHANNEL_REQUEST_BCAST), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(100);

            expect(emitSpy).toHaveBeenCalledTimes(1);
            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(2);

            // dupe notification frames from live logs
            driver.parser._transform(
                Buffer.from(
                    "7e8006711800010802ffffffff8c30d755550102020000683e1b87c46921c98000000a0014ff8e54cb990000000001000005000000000000979a7e",
                    "hex",
                ),
                "utf8",
                () => {},
            );
            await vi.advanceTimersByTimeAsync(100);

            driver.parser._transform(
                Buffer.from(
                    "7e8006711800010802ffffffff8c30d755550102020000683e1b87c46921c98000000a0014ff5e5ccb99000000000100000500000000000060a27e",
                    "hex",
                ),
                "utf8",
                () => {},
            );
            await vi.advanceTimersByTimeAsync(100);

            expect(emitSpy).toHaveBeenCalledTimes(2);
            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(4);
        });
    });

    it("NOT A TEST - only meant for quick local parsing", async () => {
        const driver = new OTRCPDriver(
            {
                txChannel: 20,
                ccaBackoffAttempts: 1,
                ccaRetries: 4,
                enableCSMACA: true,
                headerUpdated: true,
                reTx: false,
                securityProcessed: true,
                txDelay: 0,
                txDelayBaseTime: 0,
                rxChannelAfterTxDone: 20,
            },
            {
                eui64: 5562607920115904346n,
                panId: 22464,
                extendedPANId: Buffer.from(NETDEF_EXTENDED_PAN_ID).readBigUInt64LE(0),
                channel: 20,
                nwkUpdateId: 0,
                txPower: 10,
                networkKey: Buffer.from([40, 195, 71, 3, 233, 90, 194, 63, 62, 66, 190, 136, 105, 21, 237, 44]),
                networkKeyFrameCounter: 0,
                networkKeySequenceNumber: 0,
                tcKey: Buffer.from(NETDEF_TC_KEY),
                tcKeyFrameCounter: 0,
            },
            `temp_TMP_${Math.floor(Math.random() * 1000000)}`,
            // true, // emitMACFrames
        );

        driver.parser.on("data", driver.onFrame.bind(driver));

        await mockStart(driver);
        await mockFormNetwork(driver);

        driver.parser._transform(
            Buffer.from(
                "7e8006712f006188e0c05700005ccb091200005ccb016a7f3123feff818e58280b700b087f3123feff818e5800f4d67c4f305990e3ea8000000a0014ff8a719b440000000001000005000000000000484d7e",
                "hex",
            ),
            "utf8",
            () => {},
        );
        await vi.advanceTimersByTimeAsync(10);
        driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
        await vi.advanceTimersByTimeAsync(10);

        await mockStop(driver);
        rmSync(dirname(driver.savePath), { recursive: true, force: true });
    });
});
