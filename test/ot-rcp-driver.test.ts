import { randomBytes } from "node:crypto";
import { createSocket, type Socket } from "node:dgram";
import { existsSync, rmSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createWiresharkZEPFrame, DEFAULT_WIRESHARK_IP, DEFAULT_ZEP_UDP_PORT } from "../src/dev/wireshark";
import { OTRCPDriver, type SourceRouteTableEntry } from "../src/drivers/ot-rcp-driver";
import { SpinelCommandId } from "../src/spinel/commands";
import { SpinelPropertyId } from "../src/spinel/properties";
import { encodeSpinelFrame, SPINEL_HEADER_FLG_SPINEL } from "../src/spinel/spinel";
import { SpinelStatus } from "../src/spinel/statuses";
import {
    decodeMACFrameControl,
    decodeMACHeader,
    decodeMACPayload,
    MACAssociationStatus,
    type MACCapabilities,
    MACFrameAddressMode,
    MACFrameType,
    MACFrameVersion,
    type MACHeader,
    ZigbeeMACConsts,
} from "../src/zigbee/mac";
import { ZigbeeConsts } from "../src/zigbee/zigbee";
import {
    decodeZigbeeAPSFrameControl,
    decodeZigbeeAPSHeader,
    decodeZigbeeAPSPayload,
    ZigbeeAPSCommandId,
    ZigbeeAPSDeliveryMode,
    ZigbeeAPSFrameType,
} from "../src/zigbee/zigbee-aps";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    ZigbeeNWKCommandId,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    type ZigbeeNWKLinkStatus,
    ZigbeeNWKManyToOne,
    ZigbeeNWKRouteDiscovery,
    ZigbeeNWKStatus,
} from "../src/zigbee/zigbee-nwk";
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

/**
 * Helper function to create a SourceRouteTableEntry for tests
 */
function createTestSourceRouteEntry(relayAddresses: number[], pathCost: number): SourceRouteTableEntry {
    return {
        relayAddresses,
        pathCost,
        lastUpdated: Date.now(),
        failureCount: 0,
        lastUsed: undefined,
    };
}

/** SL-OPENTHREAD/2.5.2.0_GitHub-1fceb225b; EFR32; Mar 19 2025 13:45:44 */
const START_FRAMES_SILABS = {
    protocolVersion: "7e8106010403db0a7e",
    ncpVersion:
        "7e820602534c2d4f50454e5448524541442f322e352e322e305f4769744875622d3166636562323235623b2045465233323b204d617220313920323032352031333a34353a343400b5dc7e",
    interfaceType: "7e83060303573a7e",
    rcpAPIVersion: "7e8406b0010a681f7e",
    rcpMinHostAPIVersion: "7e8506b101048ea77e",
    resetPowerOn: "7e80060070ee747e",
};
/** OPENTHREAD/1.4.0-Koenkk-2025.2.1; CC13XX_CC26XX; Feb  3 2025 21:00:02 */
const START_FRAMES_TI = {
    protocolVersion: "7e8106010403db0a7e",
    ncpVersion:
        "7e8206024f50454e5448524541442f312e342e302d4b6f656e6b6b2d323032352e322e313b204343313358585f4343323658583b2046656220203320323032352032313a30303a303200ef147e",
    interfaceType: "7e83060303573a7e",
    rcpAPIVersion: "7e8406b0010be10e7e",
    rcpMinHostAPIVersion: "7e8506b101048ea77e",
    resetPowerOn: "7e80060070ee747e",
};
/** SL-OPENTHREAD/2.5.2.0_GitHub-1fceb225b; EFR32; Mar 19 2025 13:45:44 */
const FORM_FRAMES_SILABS = {
    phyEnabled: "7e87062001f2627e",
    phyChan: "7e88062114ff8e7e",
    phyTxPowerSet: "7e8906257d339b817e",
    mac154LAddr: "7e8a06344d325a6e6f486f5a8f327e",
    mac154SAddr: "7e8b0635000047f67e",
    mac154PANId: "7e8c0636d98579727e",
    macRxOnWhenIdleMode: "7e8d060000e68c7e",
    macRawStreamEnabled: "7e8e06370108437e",
    phyTxPowerGet: "7e8106257d3343647e",
    phyRSSIGet: "7e820626983d517e",
    phyRXSensitivityGet: "7e8306279c7a127e",
    phyCCAThresholdGet: "7e840624b5f0d37e",
};
/** OPENTHREAD/1.4.0-Koenkk-2025.2.1; CC13XX_CC26XX; Feb  3 2025 21:00:02 */
const FORM_FRAMES_TI = {
    phyEnabled: "7e87062001f2627e",
    phyChan: "7e88062114ff8e7e",
    phyTxPowerSet: "7e890625052cf47e",
    mac154LAddr: "7e8a06344d325a6e6f486f5a8f327e",
    mac154SAddr: "7e8b0635000047f67e",
    mac154PANId: "7e8c0636d9c57d5d307e",
    macRxOnWhenIdleMode: "7e8d060000e68c7e",
    macRawStreamEnabled: "7e8e06370108437e",
    phyTxPowerGet: "7e81062505f47d317e",
    phyRSSIGet: "7e820626ef05567e",
    phyRXSensitivityGet: "7e830627a6a38c7e",
    phyCCAThresholdGet: "7e8406000297567e",
};
// /** SL-OPENTHREAD/2.5.2.0_GitHub-1fceb225b; EFR32; Mar 19 2025 13:45:44 */
// const STOP_FRAMES_SILABS = {
//     macRawStreamEnabled: "7e8b063700d63c7e",
//     phyEnabled: "7e8c0620006eb37e",
// }
// /** OPENTHREAD/1.4.0-Koenkk-2025.2.1; CC13XX_CC26XX; Feb  3 2025 21:00:02 */
// const STOP_FRAMES_TI = {
//     macRawStreamEnabled: "7e8c063700f76b7e",
//     phyEnabled: "7e8d062000d5af7e",
// }

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

    const mockStart = async (driver: OTRCPDriver, loadState = true, timeoutReset = false, frames = START_FRAMES_SILABS) => {
        if (driver) {
            let loadStateSpy: ReturnType<typeof vi.spyOn> | undefined;

            if (!loadState) {
                loadStateSpy = vi.spyOn(driver, "loadState").mockResolvedValue(undefined);
            }

            let i = -1;
            const orderedFrames = [
                frames.protocolVersion,
                frames.ncpVersion,
                frames.interfaceType,
                frames.rcpAPIVersion,
                frames.rcpMinHostAPIVersion,
                frames.resetPowerOn,
            ];

            const reply = async () => {
                await vi.advanceTimersByTimeAsync(5);

                // skip cancel byte
                if (i >= 0) {
                    if (i === 5 && timeoutReset) {
                        await vi.advanceTimersByTimeAsync(5500);
                    }

                    driver.parser._transform(Buffer.from(orderedFrames[i], "hex"), "utf8", () => {});
                    await vi.advanceTimersByTimeAsync(5);
                }

                i++;

                if (i === orderedFrames.length) {
                    driver.writer.removeListener("data", reply);
                }
            };

            driver.writer.on("data", reply);
            await driver.start();
            loadStateSpy?.mockRestore();
            await vi.advanceTimersByTimeAsync(100); // flush

            nextTidFromStartup = driver.currentSpinelTID + 1;
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

        nextTidFromStartup = 1;
    };

    const mockFormNetwork = async (driver: OTRCPDriver, registerTimers = false, frames = FORM_FRAMES_SILABS) => {
        if (driver) {
            let i = 0;
            const orderedFrames = [
                frames.phyEnabled,
                frames.phyChan,
                frames.phyTxPowerSet,
                frames.mac154LAddr,
                frames.mac154SAddr,
                frames.mac154PANId,
                frames.macRxOnWhenIdleMode,
                frames.macRawStreamEnabled,
                frames.phyTxPowerGet,
                frames.phyRSSIGet,
                frames.phyRXSensitivityGet,
                frames.phyCCAThresholdGet,
            ];

            const reply = async () => {
                await vi.advanceTimersByTimeAsync(5);
                driver.parser._transform(Buffer.from(orderedFrames[i], "hex"), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(5);

                i++;

                if (i === orderedFrames.length) {
                    driver.writer.removeListener("data", reply);
                }
            };

            driver.writer.on("data", reply);

            let registerTimersSpy: ReturnType<typeof vi.spyOn> | undefined;

            if (registerTimers) {
                await mockRegisterTimers(driver);
            } else {
                registerTimersSpy = vi.spyOn(driver, "registerTimers").mockResolvedValue();
            }

            await driver.formNetwork();

            registerTimersSpy?.mockRestore();

            await vi.advanceTimersByTimeAsync(100); // flush

            nextTidFromStartup = driver.currentSpinelTID + 1;
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
                return await p;
            });
            await driver.registerTimers();
            await vi.advanceTimersByTimeAsync(100); // flush

            expect(savePeriodicStateSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(1 + 1); // *2 by spy mock
            expect(sendZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(1 + 1); // *2 by spy mock

            nextTidFromStartup = driver.currentSpinelTID + 1;

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
            driver.sourceRouteTable.set(1, [createTestSourceRouteEntry([], 1), createTestSourceRouteEntry([3457], 2)]);
            driver.sourceRouteTable.set(3457, []);
            driver.sourceRouteTable.set(9674, [createTestSourceRouteEntry([3457, 65348], 3)]);

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
            const route1 = driver.sourceRouteTable.get(1)!;
            expect(route1).toHaveLength(2);
            expect(route1[0].pathCost).toBe(1);
            expect(route1[0].relayAddresses).toStrictEqual([]);
            expect(route1[0].failureCount).toBe(0);
            expect(route1[1].pathCost).toBe(2);
            expect(route1[1].relayAddresses).toStrictEqual([3457]);
            expect(route1[1].failureCount).toBe(0);
            const route2 = driver.sourceRouteTable.get(9674)!;
            expect(route2).toHaveLength(1);
            expect(route2[0].pathCost).toBe(3);
            expect(route2[0].relayAddresses).toStrictEqual([3457, 65348]);
            expect(route2[0].failureCount).toBe(0);
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
                sourceRouteTableEntries.push(createTestSourceRouteEntry([1, 2, 3, 4, 5], Math.floor(Math.random() * 10)));
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

        it("starts & forms network - Silabs", async () => {
            const consoleInfoSpy = vi.spyOn(console, "info");

            await mockStart(driver, true, false, START_FRAMES_SILABS);
            await mockFormNetwork(driver, false, FORM_FRAMES_SILABS);

            expect(driver.isNetworkUp()).toStrictEqual(true);
            expect(driver.protocolVersionMajor).toStrictEqual(4);
            expect(driver.protocolVersionMinor).toStrictEqual(3);
            expect(driver.ncpVersion).toStrictEqual("SL-OPENTHREAD/2.5.2.0_GitHub-1fceb225b; EFR32; Mar 19 2025 13:45:44");
            expect(driver.interfaceType).toStrictEqual(3);
            expect(driver.rcpAPIVersion).toStrictEqual(10);
            expect(driver.rcpMinHostAPIVersion).toStrictEqual(4);

            expect(consoleInfoSpy).toHaveBeenCalledWith(
                expect.stringContaining(
                    "ot-rcp-driver: ======== Network started (PHY: txPower=19dBm rssi=-104dBm rxSensitivity=-100dBm ccaThreshold=-75dBm) ========",
                ),
            );
        });

        it("starts & forms network - TI", async () => {
            const consoleInfoSpy = vi.spyOn(console, "info");

            await mockStart(driver, true, false, START_FRAMES_TI);
            await mockFormNetwork(driver, false, FORM_FRAMES_TI);

            expect(driver.isNetworkUp()).toStrictEqual(true);
            expect(driver.protocolVersionMajor).toStrictEqual(4);
            expect(driver.protocolVersionMinor).toStrictEqual(3);
            expect(driver.ncpVersion).toStrictEqual("OPENTHREAD/1.4.0-Koenkk-2025.2.1; CC13XX_CC26XX; Feb  3 2025 21:00:02");
            expect(driver.interfaceType).toStrictEqual(3);
            expect(driver.rcpAPIVersion).toStrictEqual(11);
            expect(driver.rcpMinHostAPIVersion).toStrictEqual(4);

            expect(consoleInfoSpy).toHaveBeenCalledWith(
                expect.stringContaining(
                    "ot-rcp-driver: ======== Network started (PHY: txPower=5dBm rssi=-17dBm rxSensitivity=-90dBm ccaThreshold=undefineddBm) ========",
                ),
            );
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

        it("handles allow joins timer", async () => {
            const disallowJoinsSpy = vi.spyOn(driver, "disallowJoins");

            driver.allowJoins(5, true);

            expect(disallowJoinsSpy).toHaveBeenCalledTimes(0);

            await vi.advanceTimersByTimeAsync(6000);

            expect(disallowJoinsSpy).toHaveBeenCalledTimes(1);

            disallowJoinsSpy.mockClear();

            driver.allowJoins(5, true);
            driver.allowJoins(0, false);
            await vi.advanceTimersByTimeAsync(6000);

            expect(disallowJoinsSpy).toHaveBeenCalledTimes(1); // cleared timer

            disallowJoinsSpy.mockClear();

            driver.allowJoins(5, true);
            driver.disallowJoins();
            await vi.advanceTimersByTimeAsync(6000);

            expect(disallowJoinsSpy).toHaveBeenCalledTimes(1); // cleared timer
        });

        it("handles GP commissioning mode timer", async () => {
            const gpExitCommissioningModeSpy = vi.spyOn(driver, "gpExitCommissioningMode");

            driver.gpEnterCommissioningMode(5);

            expect(gpExitCommissioningModeSpy).toHaveBeenCalledTimes(0);

            await vi.advanceTimersByTimeAsync(6000);

            expect(gpExitCommissioningModeSpy).toHaveBeenCalledTimes(1);

            gpExitCommissioningModeSpy.mockClear();

            driver.gpEnterCommissioningMode(5);
            driver.gpEnterCommissioningMode(0);
            await vi.advanceTimersByTimeAsync(6000);

            expect(gpExitCommissioningModeSpy).toHaveBeenCalledTimes(1); // cleared timer

            gpExitCommissioningModeSpy.mockClear();

            driver.gpEnterCommissioningMode(5);
            driver.gpExitCommissioningMode();
            await vi.advanceTimersByTimeAsync(6000);

            expect(gpExitCommissioningModeSpy).toHaveBeenCalledTimes(1); // cleared timer
        });

        it("associates", async () => {
            const assignNetworkAddressSpy = vi.spyOn(driver, "assignNetworkAddress");

            //-- INITIAL JOIN
            // joins not allowed
            let network16 = driver.assignNetworkAddress();
            let network64 = randomBigInt();
            let [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_FFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);
            expect(newAddr16).toStrictEqual(0xffff);

            driver.allowJoins(0xfe, true);

            // neighbor device, joins allowed
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_FFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);
            expect(driver.deviceTable.get(network64)).toBeDefined();
            expect(driver.address16ToAddress64.get(network16)).toBeDefined();
            expect(driver.indirectTransmissions.get(network64)).toBeUndefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();

            // neighbor device, forced denied
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_RFD_MAC_CAP), true, true);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);
            expect(newAddr16).toStrictEqual(0xffff);

            // neighbor device, forced allowed
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_RFD_MAC_CAP), true, false, true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // device, joins allowed
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_RFD_MAC_CAP), false);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);
            expect(driver.deviceTable.get(network64)).toBeDefined();
            expect(driver.address16ToAddress64.get(network16)).toBeDefined();
            expect(driver.indirectTransmissions.get(network64)).toBeDefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();

            // device, forced denied
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_RFD_MAC_CAP), false, true);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);
            expect(newAddr16).toStrictEqual(0xffff);

            // device, forced allowed
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_RFD_MAC_CAP), false, false, true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // conflict, already present
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = driver.address16ToAddress64.get(network16)!;
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_RFD_MAC_CAP), true);

            expect(status).toStrictEqual(ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT);
            expect(newAddr16).toStrictEqual(0xffff);

            // conflict, on network16
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_RFD_MAC_CAP), true);

            expect(status).toStrictEqual(ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT);
            expect(newAddr16).not.toStrictEqual(network16);
            expect(newAddr16).not.toStrictEqual(0xffff);

            // conflict, on network16/network64
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = driver.address16ToAddress64.get(network16)!;
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_FFD_MAC_CAP), true);

            expect(status).toStrictEqual(ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT);
            expect(newAddr16).toStrictEqual(0xffff);

            // by network64 only
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(undefined, network64, true, structuredClone(COMMON_RFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).not.toStrictEqual(0xffff);

            // by network16 only
            network16 = driver.deviceTable.values().next().value!.address16;
            [status, newAddr16] = await driver.associate(network16, undefined, true, structuredClone(COMMON_FFD_MAC_CAP), false);

            expect(status).toStrictEqual(ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT);
            expect(newAddr16).not.toStrictEqual(network16);
            expect(newAddr16).not.toStrictEqual(0xffff);

            // mocked PAN full by network16 only
            network64 = randomBigInt();
            assignNetworkAddressSpy.mockReturnValueOnce(0xffff);
            [status, newAddr16] = await driver.associate(undefined, network64, true, structuredClone(COMMON_RFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_FULL);
            expect(newAddr16).toStrictEqual(0xffff);

            // mocked PAN full by network64 only
            network16 = driver.deviceTable.values().next().value!.address16;
            assignNetworkAddressSpy.mockReturnValueOnce(0xffff);
            [status, newAddr16] = await driver.associate(network16, undefined, true, structuredClone(COMMON_FFD_MAC_CAP), false);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_FULL);
            expect(newAddr16).toStrictEqual(0xffff);

            driver.disallowJoins(); // doesn't matter, but check with disabled just to confirm

            //-- REJOIN
            expect(driver.deviceTable.size).toBeGreaterThan(0);
            expect(driver.address16ToAddress64.size).toBeGreaterThan(0);

            // unknown neighbor device
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_FFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // unknown neighbor device, forced denied
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), true, true);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);
            expect(newAddr16).toStrictEqual(0xffff);

            // unknown neighbor device, forced allowed
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), true, false, true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // unknown device
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), false);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // unknown neighbor device, forced denied
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), false, true);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);
            expect(newAddr16).toStrictEqual(0xffff);

            // unknown neighbor device, forced allowed
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), false, false, true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // existing neighbor device
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = driver.address16ToAddress64.get(network16)!;
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_FFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // existing neighbor device, forced denied
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = driver.address16ToAddress64.get(network16)!;
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), true, true);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);
            expect(newAddr16).toStrictEqual(0xffff);

            // existing neighbor device, forced allowed
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = driver.address16ToAddress64.get(network16)!;
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), true, false, true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // existing device
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = driver.address16ToAddress64.get(network16)!;
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), false);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // existing device, forced denied
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = driver.address16ToAddress64.get(network16)!;
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), false, true);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);
            expect(newAddr16).toStrictEqual(0xffff);

            // existing device, forced allowed
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = driver.address16ToAddress64.get(network16)!;
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), false, false, true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);

            // existing, conflicting, on network16
            network16 = driver.deviceTable.values().next().value!.address16;
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, false, structuredClone(COMMON_RFD_MAC_CAP), true);

            expect(status).toStrictEqual(ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT);
            expect(newAddr16).not.toStrictEqual(network16);
            expect(newAddr16).not.toStrictEqual(0xffff);

            // existing, by network64 only
            network64 = driver.address16ToAddress64.get(network16)!;
            [status, newAddr16] = await driver.associate(undefined, network64, false, structuredClone(COMMON_RFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).not.toStrictEqual(0xffff);

            // existing, by network16 only
            network16 = driver.deviceTable.values().next().value!.address16;
            [status, newAddr16] = await driver.associate(network16, undefined, false, structuredClone(COMMON_RFD_MAC_CAP), true);

            expect(status).toStrictEqual(ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT);
            expect(newAddr16).not.toStrictEqual(network16);
            expect(newAddr16).not.toStrictEqual(0xffff);

            // existing device, by network64 only, mocked PAN full
            network64 = randomBigInt();
            assignNetworkAddressSpy.mockReturnValueOnce(0xffff);
            [status, newAddr16] = await driver.associate(undefined, network64, false, structuredClone(COMMON_RFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_FULL);
            expect(newAddr16).toStrictEqual(0xffff);

            // existing device, by network16 only, mocked PAN full
            network16 = driver.deviceTable.values().next().value!.address16;
            assignNetworkAddressSpy.mockReturnValueOnce(0xffff);
            [status, newAddr16] = await driver.associate(network16, undefined, false, structuredClone(COMMON_FFD_MAC_CAP), false);

            expect(status).toStrictEqual(MACAssociationStatus.PAN_FULL);
            expect(newAddr16).toStrictEqual(0xffff);
        });

        it("disassociates", async () => {
            // no-op, not relevant for this test
            vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest").mockImplementation(async () => {});
            driver.allowJoins(0xfe, true);

            // neighbor FFD
            let network16 = driver.assignNetworkAddress();
            let network64 = randomBigInt();
            let [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_FFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);
            expect(driver.deviceTable.get(network64)).toBeDefined();
            expect(driver.address16ToAddress64.get(network16)).toBeDefined();
            expect(driver.indirectTransmissions.get(network64)).toBeUndefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();

            await driver.disassociate(network16, undefined);

            expect(driver.deviceTable.get(network64)).toBeUndefined();
            expect(driver.address16ToAddress64.get(network16)).toBeUndefined();
            expect(driver.indirectTransmissions.get(network64)).toBeUndefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();

            // FFD
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_FFD_MAC_CAP), false);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);
            expect(driver.deviceTable.get(network64)).toBeDefined();
            expect(driver.address16ToAddress64.get(network16)).toBeDefined();
            expect(driver.indirectTransmissions.get(network64)).toBeUndefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();

            await driver.disassociate(undefined, network64);

            expect(driver.deviceTable.get(network64)).toBeUndefined();
            expect(driver.address16ToAddress64.get(network16)).toBeUndefined();
            expect(driver.indirectTransmissions.get(network64)).toBeUndefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();

            // neighbor RFD
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_RFD_MAC_CAP), true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);
            expect(driver.deviceTable.get(network64)).toBeDefined();
            expect(driver.address16ToAddress64.get(network16)).toBeDefined();
            expect(driver.indirectTransmissions.get(network64)).toBeDefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();

            await driver.disassociate(network16, undefined);

            expect(driver.deviceTable.get(network64)).toBeUndefined();
            expect(driver.address16ToAddress64.get(network16)).toBeUndefined();
            expect(driver.indirectTransmissions.get(network64)).toBeUndefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();

            // RFD
            network16 = driver.assignNetworkAddress();
            network64 = randomBigInt();
            [status, newAddr16] = await driver.associate(network16, network64, true, structuredClone(COMMON_RFD_MAC_CAP), false);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(newAddr16).toStrictEqual(network16);
            expect(driver.deviceTable.get(network64)).toBeDefined();
            expect(driver.address16ToAddress64.get(network16)).toBeDefined();
            expect(driver.indirectTransmissions.get(network64)).toBeDefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();

            await driver.disassociate(undefined, network64);

            expect(driver.deviceTable.get(network64)).toBeUndefined();
            expect(driver.address16ToAddress64.get(network16)).toBeUndefined();
            expect(driver.indirectTransmissions.get(network64)).toBeUndefined();
            expect(driver.sourceRouteTable.get(network16)).toBeUndefined();
            expect(driver.pendingAssociations.get(network64)).toBeUndefined();
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

            await expect(p).resolves.toStrictEqual(true);
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

            await expect(p).resolves.toStrictEqual(true);
            expect(waitForTIDSpy).toHaveBeenCalledWith(nextTidFromStartup, 10000);
            expect(sendFrameSpy).toHaveBeenCalledTimes(1);
        });

        it("receives frame NETDEF_ACK_FRAME_TO_COORD", async () => {
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeAPSCommandSpy = vi.spyOn(driver, "processZigbeeAPSCommand");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ACK_FRAME_TO_COORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(1);
            expect(processZigbeeAPSCommandSpy).toHaveBeenCalledTimes(0);
        });

        it("receives frame NETDEF_LINK_STATUS_FROM_DEV", async () => {
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKLinkStatusSpy = vi.spyOn(driver, "processZigbeeNWKLinkStatus");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_LINK_STATUS_FROM_DEV), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKLinkStatusSpy).toHaveBeenCalledTimes(1);
        });

        it("receives frame NETDEF_ZCL_FRAME_CMD_TO_COORD", async () => {
            const emitSpy = vi.spyOn(driver, "emit");
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeAPSCommandSpy = vi.spyOn(driver, "processZigbeeAPSCommand");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ZCL_FRAME_CMD_TO_COORD), "utf8", () => {});
            await vi.runOnlyPendingTimersAsync();

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(1);
            expect(processZigbeeAPSCommandSpy).toHaveBeenCalledTimes(0);
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
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKRouteRecSpy = vi.spyOn(driver, "processZigbeeNWKRouteRecord");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_ROUTE_RECORD_TO_COORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKRouteRecSpy).toHaveBeenCalledTimes(1);
        });

        it("receives frame NETDEF_MTORR_FRAME_FROM_COORD", async () => {
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeNWKRouteReqSpy = vi.spyOn(driver, "processZigbeeNWKRouteReq");
            const sendZigbeeNWKRouteReplySpy = vi.spyOn(driver, "sendZigbeeNWKRouteReply");

            driver.parser._transform(makeSpinelStreamRaw(1, NETDEF_MTORR_FRAME_FROM_COORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
            expect(onZigbeeAPSFrameSpy).toHaveBeenCalledTimes(0);
            expect(processZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(0);
            expect(sendZigbeeNWKRouteReplySpy).toHaveBeenCalledTimes(0);
        });

        it("receives frame NETDEF_ZGP_COMMISSIONING while in commissioning mode", async () => {
            driver.gpEnterCommissioningMode(0xfe); // in commissioning mode

            const emitSpy = vi.spyOn(driver, "emit");
            const onStreamRawFrameSpy = vi.spyOn(driver, "onStreamRawFrame");
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
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
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
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
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
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
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
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
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeAPSTransportKeySpy = vi.spyOn(driver, "processZigbeeAPSTransportKey");

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_TRANSPORT_KEY_NWK_FROM_COORD), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
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
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
            const onZigbeeAPSFrameSpy = vi.spyOn(driver, "onZigbeeAPSFrame");
            const processZigbeeAPSRequestKeySpy = vi.spyOn(driver, "processZigbeeAPSRequestKey");
            const sendZigbeeAPSTransportKeyTCSpy = vi.spyOn(driver, "sendZigbeeAPSTransportKeyTC");

            driver.parser._transform(makeSpinelStreamRaw(1, NET2_REQUEST_KEY_TC_FROM_DEVICE), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            expect(onStreamRawFrameSpy).toHaveBeenCalledTimes(1);
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
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
            // no-op, not relevant for this test
            vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest").mockImplementation(async () => {});
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

            // Cost calculation depends on available route and LQA data
            expect(linksSpy).toBeDefined();
            expect(Array.isArray(linksSpy)).toBe(true);
            const initialLinks = linksSpy as ZigbeeNWKLinkStatus[];
            expect(initialLinks).toHaveLength(1);
            expect(initialLinks[0].address).toBe(0x3ab1);
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
            // Cost might be higher if no route or LQA data is available
            expect(linksSpy).toBeDefined();
            expect(Array.isArray(linksSpy)).toBe(true);
            const links = linksSpy as ZigbeeNWKLinkStatus[];
            expect(links).toHaveLength(1);
            expect(links[0].address).toBe(0x3ab1);
            expect(links[0].incomingCost).toBeGreaterThanOrEqual(1);
            expect(links[0].incomingCost).toBeLessThanOrEqual(7);

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
            // Cost calculation depends on available route and LQA data
            expect(linksSpy).toBeDefined();
            expect(Array.isArray(linksSpy)).toBe(true);
            const links3 = linksSpy as ZigbeeNWKLinkStatus[];
            expect(links3).toHaveLength(1);
            expect(links3[0].address).toBe(0x3ab1);

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
            // Cost calculation depends on available route and LQA data
            expect(linksSpy).toBeDefined();
            expect(Array.isArray(linksSpy)).toBe(true);
            const links4 = linksSpy as ZigbeeNWKLinkStatus[];
            expect(links4).toHaveLength(1);
            expect(links4[0].address).toBe(0x3ab1);

            const sendZigbeeNWKRouteReqSpy = vi.spyOn(driver, "sendZigbeeNWKRouteReq").mockImplementationOnce(async (manyToOne, destination16) => {
                manyToOneSpy = manyToOne;
                destination16Spy = destination16;
                const p = driver.sendZigbeeNWKRouteReq(manyToOne, destination16);
                // ROUTE_REQ => OK
                driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup + 3), "utf8", () => {});
                await vi.advanceTimersByTimeAsync(10);
                return await p;
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

        it("handles send failures", async () => {
            const waitForTIDSpy = vi.spyOn(driver, "waitForTID");

            const nwkDest16 = 0x2143;
            const nwkDest64 = 8458932590n;

            driver.allowJoins(5, true);
            await driver.associate(nwkDest16, nwkDest64, true, structuredClone(COMMON_FFD_MAC_CAP), true);

            waitForTIDSpy.mockRejectedValueOnce(new Error("Failed with status=NO_ACK"));
            await expect(
                driver.sendZigbeeNWKCommand(ZigbeeNWKCommandId.COMMISSIONING_RESPONSE, Buffer.alloc(2), true, 2314, 654, 5687n, 30),
            ).resolves.toStrictEqual(false);
            waitForTIDSpy.mockRejectedValueOnce(new Error("Failed with status=NO_ACK"));
            await expect(
                driver.sendZigbeeAPSCommand(
                    ZigbeeAPSCommandId.CONFIRM_KEY,
                    Buffer.alloc(1),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    true,
                    nwkDest16,
                    nwkDest64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    undefined,
                    true,
                ),
            ).resolves.toStrictEqual(false);
            waitForTIDSpy.mockRejectedValueOnce(new Error("Failed with status=NO_ACK"));
            await expect(
                driver.sendZigbeeAPSACK(
                    // @ts-expect-error minimal mock
                    {},
                    {
                        seqNum: 11,
                        source16: nwkDest16,
                        source64: nwkDest64,
                    },
                    {
                        sourceEndpoint: 242,
                        clusterId: 2,
                    },
                ),
            ).resolves.toStrictEqual(undefined);
            waitForTIDSpy.mockRejectedValueOnce(new Error("Failed with status=NO_ACK"));
            // throws through respondToCoordinatorZDORequest
            await expect(
                driver.onZigbeeAPSFrame(
                    Buffer.alloc(8),
                    // @ts-expect-error minimal mock
                    {
                        source16: nwkDest16,
                        source64: undefined,
                    },
                    {
                        seqNum: 3,
                        source16: nwkDest16,
                        source64: undefined,
                        destination16: 0x0000, // coordinator (reach code path)
                        destination64: undefined,
                    },
                    {
                        frameControl: {
                            frameType: ZigbeeAPSFrameType.DATA,
                        },
                        profileId: ZigbeeConsts.ZDO_PROFILE_ID,
                        clusterId: 0,
                        sourceEndpoint: 0,
                        destEndpoint: 0,
                    },
                    150,
                ),
            ).resolves.toStrictEqual(undefined);

            waitForTIDSpy.mockRejectedValueOnce(new Error("Failed with status=NO_ACK"));
            await expect(
                driver.sendZigbeeAPSData(
                    Buffer.alloc(3),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    nwkDest16,
                    nwkDest64,
                    ZigbeeAPSDeliveryMode.BCAST,
                    1,
                    1,
                    1,
                    1,
                    undefined,
                ),
            ).rejects.toThrow("Failed to send");
            waitForTIDSpy.mockRejectedValueOnce(new Error("Failed with status=NO_ACK"));
            await expect(driver.sendZDO(Buffer.alloc(1), nwkDest16, nwkDest64, 3)).rejects.toThrow("Failed to send");
            waitForTIDSpy.mockRejectedValueOnce(new Error("Failed with status=NO_ACK"));
            await expect(driver.sendUnicast(Buffer.alloc(2), 2, 3, nwkDest16, nwkDest64, 4, 2)).rejects.toThrow("Failed to send");
            waitForTIDSpy.mockRejectedValueOnce(new Error("Failed with status=NO_ACK"));
            await expect(driver.sendGroupcast(Buffer.alloc(3), 45, 2345, nwkDest16, 23)).rejects.toThrow("Failed to send");
            waitForTIDSpy.mockRejectedValueOnce(new Error("Failed with status=NO_ACK"));
            await expect(driver.sendBroadcast(Buffer.alloc(4), 45677, 34, 0xfffe, 9, 5)).rejects.toThrow("Failed to send");
            await expect(driver.sendBroadcast(Buffer.alloc(4), 45677, 34, 0xff00, 9, 5)).rejects.toThrow("Invalid parameters");
            await expect(driver.sendUnicast(Buffer.alloc(4), 45677, 34, ZigbeeConsts.COORDINATOR_ADDRESS, 9n, 1, 5)).rejects.toThrow(
                "Cannot send unicast to coordinator",
            );
            await expect(driver.sendZDO(Buffer.alloc(4), ZigbeeConsts.COORDINATOR_ADDRESS, 9n, 1)).rejects.toThrow("Cannot send ZDO to coordinator");
        });

        it("sends ZDO - unicast", async () => {
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");

            const payload = Buffer.from("1020304050607080", "hex");
            const nwkDest16 = 0x1221;
            const nwkDest64 = 4321n;
            const clusterId = 0;

            driver.allowJoins(0x5, true);
            await driver.associate(nwkDest16, nwkDest64, true, structuredClone(COMMON_FFD_MAC_CAP), true);

            const p = driver.sendZDO(payload, nwkDest16, nwkDest64, clusterId);
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup, SpinelStatus.OK), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            await expect(p).resolves.toStrictEqual([1, 1]);
            const macFrame = sendMACFrameSpy.mock.calls[0][1];
            const [macFCF, decFCFOffset] = decodeMACFrameControl(macFrame, 0);
            const [macHeader, decHOffset] = decodeMACHeader(macFrame, decFCFOffset, macFCF);
            const macPayload = decodeMACPayload(macFrame, decHOffset, macFCF, macHeader);

            expect(macHeader).toStrictEqual({
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: true,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: 1,
                destinationPANId: NET3_PAN_ID,
                destination16: nwkDest16,
                destination64: undefined,
                sourcePANId: NET3_PAN_ID,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: undefined,
                auxSecHeader: undefined,
                superframeSpec: undefined,
                gtsInfo: undefined,
                pendAddr: undefined,
                commandId: undefined,
                headerIE: undefined,
                frameCounter: undefined,
                keySeqCounter: undefined,
                fcs: 47174,
            });

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            expect(nwkHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: true,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: nwkDest16,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: 29,
                seqNum: 1,
                destination64: nwkDest64,
                source64: undefined,
                relayIndex: undefined,
                relayAddresses: undefined,
                securityHeader: {
                    control: { keyId: 1, level: 5, nonce: true },
                    frameCounter: 1,
                    keySeqNum: 0,
                    micLen: 4,
                    source64: NET3_COORD_EUI64_BIGINT,
                },
            });

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

            expect(apsHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                group: undefined,
                clusterId,
                profileId: ZigbeeConsts.ZDO_PROFILE_ID,
                sourceEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                counter: 1,
                fragmentation: undefined,
                fragBlockNumber: undefined,
                fragACKBitfield: undefined,
                securityHeader: undefined,
            });
            expect(apsPayload).toStrictEqual(payload);
        });

        it("sends ZDO - broadcast", async () => {
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");

            const payload = Buffer.from("4050", "hex");
            const nwkDest16 = ZigbeeConsts.BCAST_DEFAULT;
            const nwkDest64 = undefined;
            const clusterId = 1;

            const p = driver.sendZDO(payload, nwkDest16, nwkDest64, clusterId);
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup, SpinelStatus.OK), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            await expect(p).resolves.toStrictEqual([1, 1]);
            const macFrame = sendMACFrameSpy.mock.calls[0][1];
            const [macFCF, decFCFOffset] = decodeMACFrameControl(macFrame, 0);
            const [macHeader, decHOffset] = decodeMACHeader(macFrame, decFCFOffset, macFCF);
            const macPayload = decodeMACPayload(macFrame, decHOffset, macFCF, macHeader);

            expect(macHeader).toStrictEqual({
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: false,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: 1,
                destinationPANId: NET3_PAN_ID,
                destination16: ZigbeeMACConsts.BCAST_ADDR,
                destination64: undefined,
                sourcePANId: NET3_PAN_ID,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: undefined,
                auxSecHeader: undefined,
                superframeSpec: undefined,
                gtsInfo: undefined,
                pendAddr: undefined,
                commandId: undefined,
                headerIE: undefined,
                frameCounter: undefined,
                keySeqCounter: undefined,
                fcs: 12353,
            });

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            expect(nwkHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: nwkDest16,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: 29,
                seqNum: 1,
                destination64: nwkDest64,
                source64: undefined,
                relayIndex: undefined,
                relayAddresses: undefined,
                securityHeader: {
                    control: { keyId: 1, level: 5, nonce: true },
                    frameCounter: 1,
                    keySeqNum: 0,
                    micLen: 4,
                    source64: NET3_COORD_EUI64_BIGINT,
                },
            });

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

            expect(apsHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.BCAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                group: undefined,
                clusterId,
                profileId: ZigbeeConsts.ZDO_PROFILE_ID,
                sourceEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                counter: 1,
                fragmentation: undefined,
                fragBlockNumber: undefined,
                fragACKBitfield: undefined,
                securityHeader: undefined,
            });
            expect(apsPayload).toStrictEqual(payload);
        });

        it("sends unicasts", async () => {
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");

            const payload = Buffer.from("1020304050607080", "hex");
            const nwkDest16 = 0x1221;
            const nwkDest64 = 4321n;
            const profileId = ZigbeeConsts.HA_PROFILE_ID;
            const clusterId = 45;
            const destEndpoint = 30;
            const sourceEndpoint = 1;

            driver.allowJoins(0x5, true);
            await driver.associate(nwkDest16, nwkDest64, true, structuredClone(COMMON_FFD_MAC_CAP), true);

            const p = driver.sendUnicast(payload, profileId, clusterId, nwkDest16, nwkDest64, destEndpoint, sourceEndpoint);
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup, SpinelStatus.OK), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            await expect(p).resolves.toStrictEqual(1);
            const macFrame = sendMACFrameSpy.mock.calls[0][1];
            const [macFCF, decFCFOffset] = decodeMACFrameControl(macFrame, 0);
            const [macHeader, decHOffset] = decodeMACHeader(macFrame, decFCFOffset, macFCF);
            const macPayload = decodeMACPayload(macFrame, decHOffset, macFCF, macHeader);

            expect(macHeader).toStrictEqual({
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: true,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: 1,
                destinationPANId: NET3_PAN_ID,
                destination16: nwkDest16,
                destination64: undefined,
                sourcePANId: NET3_PAN_ID,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: undefined,
                auxSecHeader: undefined,
                superframeSpec: undefined,
                gtsInfo: undefined,
                pendAddr: undefined,
                commandId: undefined,
                headerIE: undefined,
                frameCounter: undefined,
                keySeqCounter: undefined,
                fcs: 19780,
            });

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            expect(nwkHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: true,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: nwkDest16,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: 29,
                seqNum: 1,
                destination64: nwkDest64,
                source64: undefined,
                relayIndex: undefined,
                relayAddresses: undefined,
                securityHeader: {
                    control: { keyId: 1, level: 5, nonce: true },
                    frameCounter: 1,
                    keySeqNum: 0,
                    micLen: 4,
                    source64: NET3_COORD_EUI64_BIGINT,
                },
            });

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

            expect(apsHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint,
                group: undefined,
                clusterId,
                profileId,
                sourceEndpoint,
                counter: 1,
                fragmentation: undefined,
                fragBlockNumber: undefined,
                fragACKBitfield: undefined,
                securityHeader: undefined,
            });
            expect(apsPayload).toStrictEqual(payload);
        });

        it("sends groupcasts", async () => {
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");

            const payload = Buffer.from("1020304050607080", "hex");
            const groupId = 1;
            const profileId = ZigbeeConsts.HA_PROFILE_ID;
            const clusterId = 34;
            const sourceEndpoint = 1;

            const p = driver.sendGroupcast(payload, profileId, clusterId, groupId, sourceEndpoint);
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup, SpinelStatus.OK), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            await expect(p).resolves.toStrictEqual(1);
            const macFrame = sendMACFrameSpy.mock.calls[0][1];
            const [macFCF, decFCFOffset] = decodeMACFrameControl(macFrame, 0);
            const [macHeader, decHOffset] = decodeMACHeader(macFrame, decFCFOffset, macFCF);
            const macPayload = decodeMACPayload(macFrame, decHOffset, macFCF, macHeader);

            expect(macHeader).toStrictEqual({
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: false,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: 1,
                destinationPANId: NET3_PAN_ID,
                destination16: ZigbeeMACConsts.BCAST_ADDR,
                destination64: undefined,
                sourcePANId: NET3_PAN_ID,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: undefined,
                auxSecHeader: undefined,
                superframeSpec: undefined,
                gtsInfo: undefined,
                pendAddr: undefined,
                commandId: undefined,
                headerIE: undefined,
                frameCounter: undefined,
                keySeqCounter: undefined,
                fcs: 46050,
            });

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            expect(nwkHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.BCAST_RX_ON_WHEN_IDLE,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: 29,
                seqNum: 1,
                destination64: undefined,
                source64: undefined,
                relayIndex: undefined,
                relayAddresses: undefined,
                securityHeader: {
                    control: { keyId: 1, level: 5, nonce: true },
                    frameCounter: 1,
                    keySeqNum: 0,
                    micLen: 4,
                    source64: NET3_COORD_EUI64_BIGINT,
                },
            });

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

            expect(apsHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.GROUP,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint: undefined,
                group: 1,
                clusterId,
                profileId,
                sourceEndpoint,
                counter: 1,
                fragmentation: undefined,
                fragBlockNumber: undefined,
                fragACKBitfield: undefined,
                securityHeader: undefined,
            });
            expect(apsPayload).toStrictEqual(payload);
        });

        it("sends broadcasts", async () => {
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");

            const payload = Buffer.from("1020304050607080", "hex");
            const dest16 = ZigbeeConsts.BCAST_SLEEPY;
            const profileId = ZigbeeConsts.HA_PROFILE_ID;
            const clusterId = 34;
            const destEndpoint = 30;
            const sourceEndpoint = 1;

            const p = driver.sendBroadcast(payload, profileId, clusterId, dest16, destEndpoint, sourceEndpoint);
            driver.parser._transform(makeSpinelLastStatus(nextTidFromStartup, SpinelStatus.OK), "utf8", () => {});
            await vi.advanceTimersByTimeAsync(10);

            await expect(p).resolves.toStrictEqual(1);
            const macFrame = sendMACFrameSpy.mock.calls[0][1];
            const [macFCF, decFCFOffset] = decodeMACFrameControl(macFrame, 0);
            const [macHeader, decHOffset] = decodeMACHeader(macFrame, decFCFOffset, macFCF);
            const macPayload = decodeMACPayload(macFrame, decHOffset, macFCF, macHeader);

            expect(macHeader).toStrictEqual({
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: false,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: 1,
                destinationPANId: NET3_PAN_ID,
                destination16: ZigbeeMACConsts.BCAST_ADDR,
                destination64: undefined,
                sourcePANId: NET3_PAN_ID,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: undefined,
                auxSecHeader: undefined,
                superframeSpec: undefined,
                gtsInfo: undefined,
                pendAddr: undefined,
                commandId: undefined,
                headerIE: undefined,
                frameCounter: undefined,
                keySeqCounter: undefined,
                fcs: 3676,
            });

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            expect(nwkHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: dest16,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: 29,
                seqNum: 1,
                destination64: undefined,
                source64: undefined,
                relayIndex: undefined,
                relayAddresses: undefined,
                securityHeader: {
                    control: { keyId: 1, level: 5, nonce: true },
                    frameCounter: 1,
                    keySeqNum: 0,
                    micLen: 4,
                    source64: NET3_COORD_EUI64_BIGINT,
                },
            });

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

            expect(apsHeader).toStrictEqual({
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.BCAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint,
                group: undefined,
                clusterId,
                profileId,
                sourceEndpoint,
                counter: 1,
                fragmentation: undefined,
                fragBlockNumber: undefined,
                fragACKBitfield: undefined,
                securityHeader: undefined,
            });
            expect(apsPayload).toStrictEqual(payload);
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
                const processZigbeeNWKRouteRecordSpy = vi.spyOn(driver, "processZigbeeNWKRouteRecord");

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

                expect(processZigbeeNWKRouteRecordSpy).toHaveBeenCalledTimes(5);
                expect(driver.sourceRouteTable.size).toStrictEqual(5);

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
            } else {
                throw new Error("Invalid test state");
            }
        };

        it("handles source routing", async () => {
            const [linksSpy, manyToOneSpy, destination16Spy] = await mockRegisterTimers(driver);

            expect(() => driver.findBestSourceRoute(undefined, undefined)).toThrow("Invalid parameters");
            expect(() => driver.findBestSourceRoute(0xfff0, undefined)).toThrow("Unknown destination");
            expect(() => driver.findBestSourceRoute(undefined, randomBigInt())).toThrow("Unknown destination");
            expect(driver.findBestSourceRoute(0xfffc, undefined)).toStrictEqual([undefined, undefined, undefined]); // bcast

            expect(linksSpy).toStrictEqual([
                { address: 0x96ba, incomingCost: 1, outgoingCost: 1 },
                { address: 0x91d2, incomingCost: 1, outgoingCost: 1 },
                { address: 0xcb47, incomingCost: 1, outgoingCost: 1 },
            ]);
            expect(manyToOneSpy).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            expect(destination16Spy).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);

            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");
            const sendZigbeeNWKRouteReqSpy = vi.spyOn(driver, "sendZigbeeNWKRouteReq").mockResolvedValue(true);

            await fillSourceRouteTableFromRequests();

            const findBestSourceRouteSpy = vi.spyOn(driver, "findBestSourceRoute");
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");

            //-- NWK CMD
            sendMACFrameSpy.mockResolvedValueOnce(true);
            await driver.sendZigbeeNWKStatus(0x96ba, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x96ba, 9244571720527165811n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, 1]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x96ba, undefined);

            sendMACFrameSpy.mockResolvedValueOnce(true);
            await driver.sendZigbeeNWKStatus(0x6887, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x6887, 5149013643361676n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0x96ba], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x96ba, undefined);

            //-- APS CMD
            sendMACFrameSpy.mockResolvedValueOnce(true);
            await driver.sendZigbeeAPSSwitchKey(0x91d2, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x91d2, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, 1]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x91d2, undefined);

            sendMACFrameSpy.mockResolvedValueOnce(true);
            await driver.sendZigbeeAPSSwitchKey(0x9ed5, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x9ed5, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0x91d2], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x91d2, undefined);

            //-- APS DATA
            sendMACFrameSpy.mockResolvedValueOnce(true);
            await driver.sendUnicast(Buffer.from([]), 0x1, 0x1, 0x91d2, undefined, 1, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x91d2, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, 1]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x91d2, undefined);

            sendMACFrameSpy.mockResolvedValueOnce(true);
            await driver.sendUnicast(Buffer.from([]), 0x1, 0x1, 0x6887, undefined, 1, 1);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0x6887, undefined);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([0, [0x96ba], 2]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0x96ba, undefined);

            //-- no source route (use given nwkDest16)
            sendMACFrameSpy.mockResolvedValueOnce(true);
            await driver.sendZigbeeNWKStatus(0xcb47, ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE);

            expect(findBestSourceRouteSpy).toHaveBeenLastCalledWith(0xcb47, 5149013569626593n);
            expect(findBestSourceRouteSpy).toHaveLastReturnedWith([undefined, undefined, undefined]);
            expect(sendMACFrameSpy).toHaveBeenLastCalledWith(expect.any(Number), expect.any(Buffer), 0xcb47, undefined);

            //-- no source route on source route (doesn't matter)
            sendMACFrameSpy.mockResolvedValueOnce(true);
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

            //-- triggers cleanup
            await driver.disassociate(0xcb47, undefined);

            expect(driver.sourceRouteTable.get(0x4b8e)).toBeUndefined();
            await vi.advanceTimersByTimeAsync(11000); // past concentrator min time
            expect(driver.findBestSourceRoute(0x4b8e, undefined)).toStrictEqual([undefined, undefined, undefined]);
            await vi.advanceTimersByTimeAsync(10); // flush
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1 + 1 /* disassociate */);
            expect(sendZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(1);

            //-- too many NO_ACK
            driver.sourceRouteTable.set(0x6887, [
                createTestSourceRouteEntry([0x1, 0x2, 0x3], 4),
                createTestSourceRouteEntry([0x4, 0x5], 3),
                createTestSourceRouteEntry([0x6, 0x7, 0x8], 4),
            ]);
            driver.macNoACKs.set(0x4, 3);
            driver.macNoACKs.set(0x2, 5);
            await vi.advanceTimersByTimeAsync(5000); // not past concentrator min time
            // Routes with bad relays are filtered, best remaining route is returned
            expect(driver.findBestSourceRoute(0x6887, undefined)).toStrictEqual([2, [0x6, 0x7, 0x8], 4]);
            await vi.advanceTimersByTimeAsync(10); // flush
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1 + 1 /* disassociate */);
            expect(sendZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(1); // too soon
            const remaining = driver.sourceRouteTable.get(0x6887)!;
            expect(remaining).toHaveLength(1);
            expect(remaining[0].relayAddresses).toStrictEqual([0x6, 0x7, 0x8]);
            expect(remaining[0].pathCost).toBe(4);

            //-- too many NO_ACK, no more route
            driver.macNoACKs.set(0x8, 4);
            await vi.advanceTimersByTimeAsync(6000); // past concentrator min time
            // All routes filtered out, MTORR triggered because device is not a neighbor
            expect(driver.findBestSourceRoute(0x6887, undefined)).toStrictEqual([undefined, undefined, undefined]);
            await vi.advanceTimersByTimeAsync(10); // flush
            // MTORR called once more when no valid routes remain for non-neighbor
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(2 + 1 /* disassociate */);
            expect(sendZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(2);
            expect(driver.sourceRouteTable.get(0x6887)).toBeUndefined();

            //--- received LINK_STATUS indicating direct link to coordinator available
            expect(driver.deviceTable.get(driver.address16ToAddress64.get(0x6887)!)!.neighbor).toStrictEqual(false);
            driver.processZigbeeNWKLinkStatus(
                Buffer.from([97, 0x00, 0x00, 17]),
                0,
                // @ts-expect-error minimal mock
                { source16: 0x6887, source64: 5149013643361676n },
                { source16: 0x6887, source64: 5149013643361676n },
            );
            await vi.advanceTimersByTimeAsync(10); // flush
            const finalRoute = driver.sourceRouteTable.get(0x6887)!;
            expect(finalRoute).toHaveLength(1);
            expect(finalRoute[0].relayAddresses).toStrictEqual([]);
            expect(finalRoute[0].pathCost).toBe(1);
            expect(driver.deviceTable.get(driver.address16ToAddress64.get(0x6887)!)!.neighbor).toStrictEqual(true);
        });

        it("checks if source route exists in entries for a given device", () => {
            driver.sourceRouteTable.set(0x4b8e, [
                createTestSourceRouteEntry([1, 2], 3),
                createTestSourceRouteEntry([11, 22], 3),
                createTestSourceRouteEntry([33, 22, 44], 4),
                createTestSourceRouteEntry([], 1),
            ]);
            const existingEntries = driver.sourceRouteTable.get(0x4b8e)!;

            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([], 1), existingEntries)).toStrictEqual(true);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([], 2), existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([1, 2], 3), existingEntries)).toStrictEqual(true);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([2, 1], 3), existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([1, 2], 2), existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([3], 2), existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([4, 5], 3), existingEntries)).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([1, 2], 3))).toStrictEqual(true);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([2, 1], 3))).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([1, 2], 2))).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([3], 2))).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x4b8e, createTestSourceRouteEntry([4, 5], 3))).toStrictEqual(false);
            expect(driver.hasSourceRoute(0x12345, createTestSourceRouteEntry([4, 5], 3))).toStrictEqual(false);
        });

        it("handles source routing errors", async () => {
            await fillSourceRouteTableFromRequests();

            const findBestSourceRouteSpy = vi.spyOn(driver, "findBestSourceRoute");
            const sendMACFrameSpy = vi.spyOn(driver, "sendMACFrame");

            await expect(
                driver.sendZigbeeNWKCommand(ZigbeeNWKCommandId.COMMISSIONING_RESPONSE, Buffer.alloc(2), true, 2314, 654, 5687n, 30),
            ).resolves.toStrictEqual(false);
            await expect(
                driver.sendZigbeeAPSCommand(
                    ZigbeeAPSCommandId.CONFIRM_KEY,
                    Buffer.alloc(1),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    true,
                    34256,
                    8734545n,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    undefined,
                    true,
                ),
            ).resolves.toStrictEqual(false);
            await expect(
                driver.sendZigbeeAPSACK(
                    // @ts-expect-error minimal mock
                    {},
                    {
                        seqNum: 11,
                        source16: 14556,
                        source64: 568859n,
                    },
                    {
                        sourceEndpoint: 242,
                        clusterId: 2,
                    },
                ),
            ).resolves.toStrictEqual(undefined);
            // throws through respondToCoordinatorZDORequest
            await expect(
                driver.onZigbeeAPSFrame(
                    Buffer.alloc(8),
                    // @ts-expect-error minimal mock
                    {
                        source16: 34251,
                        source64: undefined,
                    },
                    {
                        seqNum: 3,
                        source16: 34567,
                        source64: undefined,
                        destination16: 0x0000, // coordinator (reach code path)
                        destination64: undefined,
                    },
                    {
                        frameControl: {
                            frameType: ZigbeeAPSFrameType.DATA,
                        },
                        profileId: ZigbeeConsts.ZDO_PROFILE_ID,
                        clusterId: 0,
                        sourceEndpoint: 0,
                        destEndpoint: 0,
                    },
                    150,
                ),
            ).resolves.toStrictEqual(undefined);
            expect(findBestSourceRouteSpy).toHaveBeenCalledTimes(4);
            expect(findBestSourceRouteSpy.mock.results[0].value).toStrictEqual(expect.objectContaining({ message: "Unknown destination" }));
            expect(findBestSourceRouteSpy.mock.results[1].value).toStrictEqual(expect.objectContaining({ message: "Unknown destination" }));
            expect(findBestSourceRouteSpy.mock.results[2].value).toStrictEqual(expect.objectContaining({ message: "Unknown destination" }));
            expect(findBestSourceRouteSpy.mock.results[3].value).toStrictEqual(expect.objectContaining({ message: "Unknown destination" }));
            expect(sendMACFrameSpy).toHaveBeenCalledTimes(0);

            await expect(
                driver.sendZigbeeAPSData(
                    Buffer.alloc(3),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    8967,
                    6793424567n,
                    ZigbeeAPSDeliveryMode.BCAST,
                    1,
                    1,
                    1,
                    1,
                    undefined,
                ),
            ).rejects.toThrow("Unknown destination");
            await expect(driver.sendZDO(Buffer.alloc(1), 867, 856787n, 3)).rejects.toThrow("Unknown destination");
            await expect(driver.sendUnicast(Buffer.alloc(2), 2, 3, 12145, 34672n, 4, 2)).rejects.toThrow("Unknown destination");
        });

        it("handles routing failures", async () => {
            await fillSourceRouteTableFromRequests();

            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");
            const sendZigbeeNWKRouteReqSpy = vi.spyOn(driver, "sendZigbeeNWKRouteReq").mockResolvedValueOnce(true);

            const dest16 = 0x91d2;

            // verify route exists
            expect(driver.findBestSourceRoute(0x9ed5, undefined)).toStrictEqual([0, [0x91d2], 2]);

            // first NWK Status: route failure - should purge routes and trigger MTORR once
            driver.processZigbeeNWKStatus(
                Buffer.from([2, dest16 & 0xff, (dest16 >> 8) & 0xff]),
                0,
                // @ts-expect-error minimal mock
                { source16: 0x9ed5, source64: 5149013578478658n },
                { source16: 0x9ed5, source64: 5149013578478658n },
            );

            // route should be purged immediately on first failure (with triggerRepair=true)
            expect(driver.sourceRouteTable.get(0x9ed5)).toBeUndefined();
            // calling findBestSourceRoute will also attempt to trigger MTORR
            expect(driver.findBestSourceRoute(0x9ed5, undefined)).toStrictEqual([undefined, undefined, undefined]);
            await vi.advanceTimersByTimeAsync(10); // flush

            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(2); // processZigbeeNWKStatus + findBestSourceRoute
            expect(sendZigbeeNWKRouteReqSpy).toHaveBeenCalledTimes(1);
        });

        it("gets routing table", async () => {
            await fillSourceRouteTableFromRequests();

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

            sr0x6887?.push(createTestSourceRouteEntry([0x0001, 0x0002], 3));
            sr0x6887?.push(createTestSourceRouteEntry([0x0003], 2));

            sr0x9ed5?.push(createTestSourceRouteEntry([0x0001], 2));

            sr0x4b8e?.push(createTestSourceRouteEntry([0x0001, 0x0002, 0x0003], 4));

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
                createTestSourceRouteEntry([0x0001, 0x0002, 0x0003], 4),
                createTestSourceRouteEntry([0x0004, 0x0005], 3),
            ]);

            expect(driver.sourceRouteTable.size).toStrictEqual(6);

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
                    // 0x2345 & 0xff, // device unknown, route cleaned out
                    // (0x2345 >> 8) & 0xff,
                    // 0,
                    // 5 & 0xff,
                    // (5 >> 8) & 0xff,
                ]),
            );

            //-- mock LEAVE
            vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest").mockImplementationOnce(async () => {}); // no-op for disassociate
            await driver.disassociate(0x91d2, 8118874123826907736n);

            expect(driver.sourceRouteTable.size).toStrictEqual(5);

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
                driver.sourceRouteTable.set(addr16, [createTestSourceRouteEntry([relay16], 2)]);
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
            driver.sourceRouteTable.set(lastAdrr16, [createTestSourceRouteEntry([], 1)]);

            routingTable = driver.getRoutingTableResponse(200);

            expect(routingTable.byteLength).toStrictEqual(5 + (299 - 200) * 5);
            expect(routingTable.readUInt16LE(routingTable.byteLength - 5)).not.toStrictEqual(lastAdrr16);
            expect(routingTable.readUInt16LE(routingTable.byteLength - 2)).not.toStrictEqual(lastRelay16);
        });

        it("ignores direct routes when getting routing table", () => {
            driver.sourceRouteTable.set(0x4b8e, [
                createTestSourceRouteEntry([1, 2], 3),
                createTestSourceRouteEntry([11, 22], 3),
                createTestSourceRouteEntry([33, 22, 44], 4),
                createTestSourceRouteEntry([], 1),
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

            vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest").mockImplementationOnce(async () => {}); // no-op for disassociate
            await driver.disassociate(0xcb47, 5149013569626593n);
            expect(driver.deviceTable.size).toStrictEqual(5);

            lqiTable = driver.getLQITableResponse(0);
            expectedLQITable[2] = 2;
            expectedLQITable[4] = 2;

            expect(lqiTable).toStrictEqual(expectedLQITable.subarray(0, 5 + 2 * 22));
        });

        it("deduplicates MTORR triggers within 1 second", async () => {
            await fillSourceRouteTableFromRequests();

            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");
            const dest16 = 0x91d2;

            // first failure triggers MTORR
            driver.processZigbeeNWKStatus(
                Buffer.from([2, dest16 & 0xff, (dest16 >> 8) & 0xff]),
                0,
                // @ts-expect-error minimal mock
                { source16: 0x9ed5, source64: 5149013578478658n },
                { source16: 0x9ed5, source64: 5149013578478658n },
            );
            await vi.advanceTimersByTimeAsync(10); // flush
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1);

            // multiple failures within short time - all should be deduplicated
            for (let i = 0; i < 5; i++) {
                const dest = 0x1000 + i;

                driver.processZigbeeNWKStatus(
                    Buffer.from([2, dest & 0xff, (dest >> 8) & 0xff]),
                    0,
                    // @ts-expect-error minimal mock
                    { source16: dest, source64: BigInt(dest) },
                    { source16: dest, source64: BigInt(dest) },
                );
                await vi.advanceTimersByTimeAsync(10);
            }

            // all rapid failures should be deduplicated
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1);
        });

        it("purges routes using failed node as relay", async () => {
            // create routes where 0x91d2 is used as a relay
            driver.sourceRouteTable.set(0x6887, [createTestSourceRouteEntry([0x91d2, 0x0001], 3)]);
            driver.sourceRouteTable.set(0x9ed5, [createTestSourceRouteEntry([0x91d2], 2)]);
            driver.sourceRouteTable.set(0x4b8e, [createTestSourceRouteEntry([0xcb47], 2)]); // not using 0x91d2
            driver.sourceRouteTable.set(0x91d2, [createTestSourceRouteEntry([], 1)]); // direct route

            expect(driver.sourceRouteTable.size).toBe(4);

            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");

            // report failure for 0x91d2
            driver.processZigbeeNWKStatus(
                Buffer.from([2, 0x91d2 & 0xff, (0x91d2 >> 8) & 0xff]),
                0,
                // @ts-expect-error minimal mock
                { source16: 0x6887, source64: 5149013573816379n },
                { source16: 0x6887, source64: 5149013573816379n },
            );
            await vi.advanceTimersByTimeAsync(10);

            // routes using 0x91d2 as relay should be purged
            expect(driver.sourceRouteTable.has(0x6887)).toBe(false); // used 0x91d2 as relay
            expect(driver.sourceRouteTable.has(0x9ed5)).toBe(false); // used 0x91d2 as relay
            expect(driver.sourceRouteTable.has(0x91d2)).toBe(false); // direct route purged
            expect(driver.sourceRouteTable.has(0x4b8e)).toBe(true); // didn't use 0x91d2

            // MTORR should be triggered
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1);
        });

        it("increments failure count on MAC NO_ACK", async () => {
            const dest16 = 0x6887;

            driver.sourceRouteTable.set(dest16, [createTestSourceRouteEntry([0x91d2], 2)]);

            const entries = driver.sourceRouteTable.get(dest16)!;

            expect(entries[0].failureCount).toBe(0);

            // simulate MAC transmission failure (this would be called internally)
            // @ts-expect-error private
            const markRouteFailure = driver.markRouteFailure.bind(driver);

            markRouteFailure(dest16, false);
            expect(entries[0].failureCount).toBe(1);

            markRouteFailure(dest16, false);
            expect(entries[0].failureCount).toBe(2);

            // trigger blacklist and MTORR
            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");

            markRouteFailure(dest16, false);
            await vi.advanceTimersByTimeAsync(10);

            expect(entries[0].failureCount).toBe(3);
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1);
            // route should be purged after blacklist
            expect(driver.sourceRouteTable.has(dest16)).toBe(false);
        });

        it("resets failure count on successful transmission", () => {
            const dest16 = 0x6887;

            driver.sourceRouteTable.set(dest16, [createTestSourceRouteEntry([0x91d2], 2)]);

            // @ts-expect-error private
            const markRouteFailure = driver.markRouteFailure.bind(driver);
            // @ts-expect-error private
            const markRouteSuccess = driver.markRouteSuccess.bind(driver);

            // add some failures
            markRouteFailure(dest16, false);
            markRouteFailure(dest16, false);

            const entries = driver.sourceRouteTable.get(dest16)!;

            expect(entries[0].failureCount).toBe(2);

            // success should reset count
            markRouteSuccess(dest16);

            expect(entries[0].failureCount).toBe(0);
            expect(entries[0].lastUsed).toBeDefined();
            expect(entries[0].lastUsed).toBeGreaterThan(0);
        });

        it("filters blacklisted routes in findBestSourceRoute", async () => {
            const dest16 = 0x6887;
            // create multiple routes with different failure counts
            driver.sourceRouteTable.set(dest16, [
                createTestSourceRouteEntry([0x0001, 0x0002], 3), // will be selected initially
                createTestSourceRouteEntry([0x0003], 2), // better cost
                createTestSourceRouteEntry([0x0004, 0x0005], 4), // worse cost
            ]);

            // best route should be the one with cost 2
            let [, relayAddresses, pathCost] = driver.findBestSourceRoute(dest16, undefined);
            expect(relayAddresses).toStrictEqual([0x0003]);
            expect(pathCost).toBe(2);

            // blacklist the best route by setting high failure count
            const entries = driver.sourceRouteTable.get(dest16)!;
            entries[1].failureCount = 3; // blacklist threshold

            // should now return second-best route
            [, relayAddresses, pathCost] = driver.findBestSourceRoute(dest16, undefined);
            expect(relayAddresses).toStrictEqual([0x0001, 0x0002]);
            expect(pathCost).toBe(3);

            // blacklist all routes
            entries[0].failureCount = 3;
            entries[2].failureCount = 3;

            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");

            // should trigger MTORR and return no route
            [, relayAddresses, pathCost] = driver.findBestSourceRoute(dest16, undefined);
            await vi.advanceTimersByTimeAsync(10);

            expect(relayAddresses).toBeUndefined();
            expect(pathCost).toBeUndefined();
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1);
            expect(driver.sourceRouteTable.has(dest16)).toBe(false); // all routes purged
        });

        it("tracks lastUsed timestamp for recency-based selection", () => {
            const dest16 = 0x6887;
            const now = Date.now();

            // create routes with same cost but different ages
            driver.sourceRouteTable.set(dest16, [
                { ...createTestSourceRouteEntry([0x0001], 2), lastUpdated: now - 5000 }, // 5s old
                { ...createTestSourceRouteEntry([0x0002], 2), lastUpdated: now - 1000, lastUsed: now - 500 }, // recently used
                { ...createTestSourceRouteEntry([0x0003], 2), lastUpdated: now - 10000 }, // 10s old
            ]);

            // should prefer recently used route
            const [, relayAddresses] = driver.findBestSourceRoute(dest16, undefined);
            expect(relayAddresses).toStrictEqual([0x0002]);

            // mark another route as used
            // @ts-expect-error private
            const markRouteSuccess = driver.markRouteSuccess.bind(driver);

            // reorder so [0x0001] is first (will be marked as used)
            const entries = driver.sourceRouteTable.get(dest16)!;
            const temp = entries[0];
            entries[0] = entries[1];
            entries[1] = temp;

            markRouteSuccess(dest16);

            // after marking success, the first entry should have lastUsed set
            expect(entries[0].lastUsed).toBeDefined();
            expect(entries[0].lastUsed!).toBeGreaterThanOrEqual(now); // >= since could be same millisecond
            expect(entries[0].failureCount).toBe(0); // should reset on success
        });

        it("does not trigger MTORR when filtering routes with NO_ACK relays", async () => {
            driver.sourceRouteTable.set(0x6887, [
                createTestSourceRouteEntry([0x0001, 0x0002], 3),
                createTestSourceRouteEntry([0x0003], 2), // good route
            ]);

            // mark relay 0x0001 as having too many NO_ACKs
            driver.macNoACKs.set(0x0001, 3); // threshold

            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(driver, "sendPeriodicManyToOneRouteRequest");

            // findBestSourceRoute should filter but not trigger MTORR (valid route remains)
            const [, relayAddresses] = driver.findBestSourceRoute(0x6887, undefined);
            await vi.advanceTimersByTimeAsync(10);

            expect(relayAddresses).toStrictEqual([0x0003]); // good route selected
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(0);

            // only when ALL routes are filtered should MTORR trigger
            driver.macNoACKs.set(0x0003, 3);
            driver.findBestSourceRoute(0x6887, undefined);
            await vi.advanceTimersByTimeAsync(10);

            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalledTimes(1);
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
            const sendZigbeeAPSACKSpy = vi.spyOn(driver, "sendZigbeeAPSACK");
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
            expect(sendZigbeeAPSACKSpy).toHaveBeenCalledTimes(0);
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
                panId: 6342,
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
                "7e800671300061883bc61800001e6b4802000038d11d8528c6847d310099779fbe4c38c1a4006ceeabe886fb158a3e69c907468825fa7fc78000000a0014ffd300659100000000010000050000000000000e737e",
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
