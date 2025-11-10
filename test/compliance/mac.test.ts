/**
 * Zigbee Specification Compliance Tests
 *
 * These tests verify that the handlers adhere to the Zigbee specification.
 * Tests are derived from:
 *   - Zigbee specification (05-3474-23): Revision 23.1
 *   - Base device behavior (16-02828-012): v3.0.1
 *   - ZCL specification (07-5123): Revision 8
 *   - Green Power specification (14-0563-19): Version 1.1.2
 *
 * All tests are independent of the driver and use only handlers and context.
 * Test data is sourced from test/data.ts which contains valid Zigbee payloads.
 */

import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
    decodeMACPayload,
    decodeMACZigbeeBeacon,
    encodeMACFrame,
    MACAssociationStatus,
    type MACCapabilities,
    MACCommandId,
    MACDisassociationReason,
    MACFrameAddressMode,
    MACFrameType,
    MACFrameVersion,
    type MACHeader,
    MACSecurityKeyIdMode,
    MACSecurityLevel,
    ZigbeeMACConsts,
} from "../../src/zigbee/mac.js";
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeConsts, ZigbeeKeyType } from "../../src/zigbee/zigbee.js";
import { decodeZigbeeAPSFrameControl, decodeZigbeeAPSHeader, ZigbeeAPSDeliveryMode, ZigbeeAPSFrameType } from "../../src/zigbee/zigbee-aps.js";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    ZigbeeNWKCommandId,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    ZigbeeNWKRouteDiscovery,
} from "../../src/zigbee/zigbee-nwk.js";
import { APSHandler, type APSHandlerCallbacks } from "../../src/zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../../src/zigbee-stack/nwk-gp-handler.js";
import { CONFIG_NWK_MAX_HOPS, NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import { type NetworkParameters, StackContext, type StackContextCallbacks } from "../../src/zigbee-stack/stack-context.js";
import { NETDEF_ACK_FRAME_FROM_COORD, NETDEF_EXTENDED_PAN_ID, NETDEF_NETWORK_KEY, NETDEF_PAN_ID, NETDEF_TC_KEY } from "../data.js";
import { createMACFrameControl } from "../utils.js";
import { captureMacFrame, type DecodedMACFrame, decodeMACFramePayload, NO_ACK_CODE, registerNeighborDevice, TEST_DEVICE_EUI64 } from "./utils.js";

describe("IEEE 802.15.4-2020 MAC Layer Compliance", () => {
    let netParams: NetworkParameters;
    let saveDir: string;

    let mockStackContextCallbacks: StackContextCallbacks;
    let context: StackContext;
    let mockMACHandlerCallbacks: MACHandlerCallbacks;
    let macHandler: MACHandler;
    let mockNWKHandlerCallbacks: NWKHandlerCallbacks;
    let nwkHandler: NWKHandler;
    let mockNWKGPHandlerCallbacks: NWKGPHandlerCallbacks;
    let nwkGPHandler: NWKGPHandler;
    let mockAPSHandlerCallbacks: APSHandlerCallbacks;
    let apsHandler: APSHandler;

    beforeEach(async () => {
        // Initialize network parameters per Zigbee specification defaults
        netParams = {
            eui64: 0x00124b0012345678n,
            panId: NETDEF_PAN_ID,
            extendedPanId: NETDEF_EXTENDED_PAN_ID.readBigUInt64LE(),
            channel: 15,
            nwkUpdateId: 0,
            txPower: 5,
            networkKey: Buffer.from(NETDEF_NETWORK_KEY),
            networkKeyFrameCounter: 0,
            networkKeySequenceNumber: 0,
            tcKey: Buffer.from(NETDEF_TC_KEY),
            tcKeyFrameCounter: 0,
        };
        saveDir = `temp_COMPLIANCE_${Math.floor(Math.random() * 1000000)}`;

        mkdirSync(saveDir, { recursive: true });

        mockStackContextCallbacks = {
            onDeviceLeft: vi.fn(),
        };
        mockMACHandlerCallbacks = {
            onFrame: vi.fn(),
            onSendFrame: vi.fn(),
            onAPSSendTransportKeyNWK: vi.fn(),
            onMarkRouteSuccess: vi.fn(),
            onMarkRouteFailure: vi.fn(),
        };
        mockNWKHandlerCallbacks = {
            onDeviceRejoined: vi.fn(),
            onAPSSendTransportKeyNWK: vi.fn(),
        };
        mockNWKGPHandlerCallbacks = {
            onGPFrame: vi.fn(),
        };
        mockAPSHandlerCallbacks = {
            onFrame: vi.fn(),
            onDeviceJoined: vi.fn(),
            onDeviceRejoined: vi.fn(),
            onDeviceAuthorized: vi.fn(),
        };

        registerDefaultHashedKeys(
            makeKeyedHashByType(ZigbeeKeyType.LINK, Buffer.from(NETDEF_TC_KEY)),
            makeKeyedHashByType(ZigbeeKeyType.NWK, Buffer.from(NETDEF_NETWORK_KEY)),
            makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, Buffer.from(NETDEF_TC_KEY)),
            makeKeyedHashByType(ZigbeeKeyType.LOAD, Buffer.from(NETDEF_TC_KEY)),
        );

        context = new StackContext(mockStackContextCallbacks, join(saveDir, "zoh.save"), netParams);
        await context.loadState();

        macHandler = new MACHandler(context, mockMACHandlerCallbacks, NO_ACK_CODE);
        nwkHandler = new NWKHandler(context, macHandler, mockNWKHandlerCallbacks);
        nwkGPHandler = new NWKGPHandler(mockNWKGPHandlerCallbacks);
        apsHandler = new APSHandler(context, macHandler, nwkHandler, mockAPSHandlerCallbacks);
    });

    afterEach(() => {
        context.disallowJoins();
        nwkGPHandler.stop();
        vi.restoreAllMocks();
        vi.useRealTimers();
        rmSync(saveDir, { force: true, recursive: true });
    });

    /**
     * IEEE 802.15.4-2020 §6.2.2.1: Frame Control Field
     * The Frame Control field SHALL contain frame type, security, pending, ack request,
     * PAN ID compression, and address mode subfields.
     */
    describe("MAC Frame Control Field (IEEE 802.15.4-2020 §6.2.2.1)", () => {
        it("encodes MAC command frame control fields according to bit layout", async () => {
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x1234, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const fcfValue = decoded.buffer.readUInt16LE(0);

            expect(fcfValue).toStrictEqual(0x8863);
            expect(decoded.frameControl.frameType).toStrictEqual(MACFrameType.CMD);
            expect(decoded.frameControl.securityEnabled).toStrictEqual(false);
            expect(decoded.frameControl.framePending).toStrictEqual(false);
            expect(decoded.frameControl.ackRequest).toStrictEqual(true);
            expect(decoded.frameControl.panIdCompression).toStrictEqual(true);
            expect(decoded.frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.SHORT);
            expect(decoded.frameControl.sourceAddrMode).toStrictEqual(MACFrameAddressMode.SHORT);
        });

        it("generates only valid frame types across coordinator operations", async () => {
            const commandFrame = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x5566, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const beaconFrame = await captureMacFrame(
                () => macHandler.processBeaconReq(Buffer.alloc(0), 0, {} as MACHeader),
                mockMACHandlerCallbacks,
            );

            const dest16 = 0x3344;
            const dest64 = TEST_DEVICE_EUI64;
            registerNeighborDevice(context, dest16, dest64);

            const nwkFrame = await captureMacFrame(
                () =>
                    nwkHandler.sendCommand(
                        ZigbeeNWKCommandId.ROUTE_REQ,
                        Buffer.from([ZigbeeNWKCommandId.ROUTE_REQ]),
                        false,
                        ZigbeeConsts.COORDINATOR_ADDRESS,
                        dest16,
                        dest64,
                        5,
                    ),
                mockMACHandlerCallbacks,
            );

            for (const sample of [commandFrame, beaconFrame, nwkFrame]) {
                expect(sample.frameControl.frameType).toBeGreaterThanOrEqual(0);
                expect(sample.frameControl.frameType).toBeLessThanOrEqual(7);
            }

            expect(commandFrame.frameControl.frameType).toStrictEqual(MACFrameType.CMD);
            expect(beaconFrame.frameControl.frameType).toStrictEqual(MACFrameType.BEACON);
            expect(nwkFrame.frameControl.frameType).toStrictEqual(MACFrameType.DATA);
        });

        it("rejects MAC security because the encoder does not yet implement it", () => {
            expect(() =>
                encodeMACFrame(
                    {
                        frameControl: {
                            frameType: MACFrameType.DATA,
                            securityEnabled: true,
                            framePending: false,
                            ackRequest: false,
                            panIdCompression: false,
                            seqNumSuppress: false,
                            iePresent: false,
                            destAddrMode: MACFrameAddressMode.NONE,
                            frameVersion: MACFrameVersion.V2003,
                            sourceAddrMode: MACFrameAddressMode.SHORT,
                        },
                        sequenceNumber: 1,
                        sourcePANId: context.netParams.panId,
                        source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                        fcs: 0,
                    },
                    Buffer.from([0xaa]),
                ),
            ).toThrowError(new Error("Unsupported: securityEnabled"));
        });

        it("asserts the frame pending bit when indirect transmissions exist", async () => {
            const dest16 = 0x7788;
            const dest64 = TEST_DEVICE_EUI64;
            registerNeighborDevice(context, dest16, dest64);
            context.indirectTransmissions.set(dest64, [
                {
                    sendFrame: vi.fn(() => Promise.resolve(true)),
                    timestamp: Date.now(),
                },
            ]);

            const decoded = await captureMacFrame(async () => {
                const initialLength = context.indirectTransmissions.get(dest64)!.length;
                await nwkHandler.sendCommand(
                    ZigbeeNWKCommandId.REJOIN_REQ,
                    Buffer.from([ZigbeeNWKCommandId.REJOIN_REQ, 0x00]),
                    false,
                    ZigbeeConsts.COORDINATOR_ADDRESS,
                    dest16,
                    dest64,
                    5,
                );

                const queue = context.indirectTransmissions.get(dest64)!;
                expect(queue.length).toBeGreaterThan(initialLength);

                await queue[queue.length - 1]!.sendFrame();
            }, mockMACHandlerCallbacks);

            expect(decoded.frameControl.framePending).toStrictEqual(true);
        });

        it("requests acknowledgments for unicast MAC commands and suppresses them for broadcast", async () => {
            const unicast = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x9001, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const broadcast = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, ZigbeeMACConsts.BCAST_ADDR, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            expect(unicast.frameControl.ackRequest).toStrictEqual(true);
            expect(broadcast.frameControl.ackRequest).toStrictEqual(false);
        });

        it("uses PAN ID compression for intra-PAN frames but leaves beacons uncompressed", async () => {
            const command = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x3001, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const beacon = await captureMacFrame(() => macHandler.processBeaconReq(Buffer.alloc(0), 0, {} as MACHeader), mockMACHandlerCallbacks);

            expect(command.frameControl.panIdCompression).toStrictEqual(true);
            expect(beacon.frameControl.panIdCompression).toStrictEqual(false);
            expect(command.header.destinationPANId).toStrictEqual(netParams.panId);
            expect(beacon.header.sourcePANId).toStrictEqual(netParams.panId);
        });

        it("encodes destination addressing mode based on addressing context", async () => {
            const shortDest = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x4abc, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const extDest = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, undefined, TEST_DEVICE_EUI64, true, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const beacon = await captureMacFrame(() => macHandler.processBeaconReq(Buffer.alloc(0), 0, {} as MACHeader), mockMACHandlerCallbacks);

            expect(shortDest.frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.SHORT);
            expect(shortDest.header.destination16).toStrictEqual(0x4abc);
            expect(extDest.frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.EXT);
            expect(extDest.header.destination64).toStrictEqual(TEST_DEVICE_EUI64);
            expect(beacon.frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.NONE);
        });

        it("sets the frame version to IEEE 802.15.4-2003 for coordinator-originated frames", async () => {
            const command = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x1111, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const beacon = await captureMacFrame(() => macHandler.processBeaconReq(Buffer.alloc(0), 0, {} as MACHeader), mockMACHandlerCallbacks);

            registerNeighborDevice(context, 0x2222, TEST_DEVICE_EUI64);
            const data = await captureMacFrame(
                () =>
                    nwkHandler.sendCommand(
                        ZigbeeNWKCommandId.LINK_STATUS,
                        Buffer.from([ZigbeeNWKCommandId.LINK_STATUS, 0x00, 0x00]),
                        false,
                        ZigbeeConsts.COORDINATOR_ADDRESS,
                        0x2222,
                        TEST_DEVICE_EUI64,
                        5,
                    ),
                mockMACHandlerCallbacks,
            );

            expect(command.frameControl.frameVersion).toStrictEqual(MACFrameVersion.V2003);
            expect(beacon.frameControl.frameVersion).toStrictEqual(MACFrameVersion.V2003);
            expect(data.frameControl.frameVersion).toStrictEqual(MACFrameVersion.V2003);
        });

        it("encodes source addressing mode for short and extended coordinator addresses", async () => {
            const shortSource = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x4001, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const extendedSource = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, undefined, TEST_DEVICE_EUI64, true, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            expect(shortSource.frameControl.sourceAddrMode).toStrictEqual(MACFrameAddressMode.SHORT);
            expect(shortSource.header.source16).toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);
            expect(extendedSource.frameControl.sourceAddrMode).toStrictEqual(MACFrameAddressMode.EXT);
            expect(extendedSource.header.source64).toStrictEqual(context.netParams.eui64);
        });

        it("keeps reserved frame control bits cleared", async () => {
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x7a01, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const rawFCF = decoded.buffer.readUInt16LE(0);

            expect(decoded.frameControl.seqNumSuppress).toStrictEqual(false);
            expect(decoded.frameControl.iePresent).toStrictEqual(false);
            expect(rawFCF & 0x0080).toStrictEqual(0);
            expect(decoded.frameControl.destAddrMode).not.toStrictEqual(MACFrameAddressMode.RESERVED);
            expect(decoded.frameControl.sourceAddrMode).not.toStrictEqual(MACFrameAddressMode.RESERVED);
        });
    });

    /**
     * IEEE 802.15.4-2020 §6.2.2.3: Sequence Number
     * The Sequence Number field SHALL be an integer in the range 0-255 that SHALL be
     * incremented for each new transmission. The value SHALL wrap to 0 after 255.
     */
    describe("MAC Sequence Number (IEEE 802.15.4-2020 §6.2.2.3)", () => {
        it("assigns a valid initial sequence number on first transmission", async () => {
            const sequences: number[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                sequences.push(frame.readUInt8(2));
                return Promise.resolve();
            });

            await macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x1234, undefined, false, Buffer.from([0x00]));

            expect(sequences).toHaveLength(1);
            expect(sequences[0]).toBeGreaterThanOrEqual(0);
            expect(sequences[0]).toBeLessThanOrEqual(0xff);
            expect(sequences[0]).toStrictEqual(1);
        });

        it("increments the sequence number for each subsequent frame", async () => {
            const sequences: number[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                sequences.push(frame.readUInt8(2));
                return Promise.resolve();
            });

            for (let i = 0; i < 4; i++) {
                await macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x1234, undefined, false, Buffer.from([i]));
            }

            expect(sequences).toStrictEqual([1, 2, 3, 4]);
        });

        it("wraps the sequence number from 255 back to 0", async () => {
            const sequences: number[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                sequences.push(frame.readUInt8(2));
                return Promise.resolve();
            });

            for (let i = 0; i < 254; i++) {
                macHandler.nextSeqNum();
            }

            for (let i = 0; i < 3; i++) {
                await macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x1234, undefined, false, Buffer.from([i]));
            }

            expect(sequences).toStrictEqual([0xff, 0x00, 0x01]);
        });

        it("ensures sequence numbers are unique across consecutive frames", async () => {
            const sequences: number[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                sequences.push(frame.readUInt8(2));
                return Promise.resolve();
            });

            for (let i = 0; i < 10; i++) {
                await macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x1234, undefined, false, Buffer.from([i]));
            }

            const unique = new Set(sequences);
            expect(unique.size).toStrictEqual(sequences.length);
        });

        it("maintains correct behavior across 300 transmissions", async () => {
            const sequences: number[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                sequences.push(frame.readUInt8(2));
                return Promise.resolve();
            });

            for (let i = 0; i < 300; i++) {
                await macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x1234, undefined, false, Buffer.from([i & 0xff]));
            }

            const expected = Array.from({ length: 300 }, (_value, index) => (index + 1) & 0xff);
            expect(sequences).toStrictEqual(expected);
        });
    });

    /**
     * IEEE 802.15.4-2020 §6.2.2.7: Destination PAN Identifier
     * The Destination PAN Identifier field SHALL be 2 octets in length and SHALL
     * specify the PAN identifier of the intended recipient.
     */
    describe("MAC PAN Identifier (IEEE 802.15.4-2020 §6.2.2.7)", () => {
        it("includes the destination PAN identifier when a destination address is present", async () => {
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x4321, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            expect(decoded.header.destinationPANId).toStrictEqual(netParams.panId);
        });

        it("omits the destination PAN identifier when the addressing mode is none", async () => {
            const decoded = await captureMacFrame(() => macHandler.processBeaconReq(Buffer.alloc(0), 0, {} as MACHeader), mockMACHandlerCallbacks);

            expect(decoded.frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.NONE);
            expect(decoded.header.destinationPANId).toBeUndefined();
        });

        it("omits the encoded source PAN identifier when PAN ID compression is enabled", async () => {
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x2001, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            expect(decoded.frameControl.panIdCompression).toStrictEqual(true);
            expect(decoded.header.destinationPANId).toStrictEqual(netParams.panId);

            const destPanOffset = 3;
            const sourceAddrOffset = destPanOffset + 4; // dest PAN (2) + dest16 (2)
            expect(decoded.buffer.readUInt16LE(sourceAddrOffset)).toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);
            expect(decoded.header.sourcePANId).toStrictEqual(decoded.header.destinationPANId);
        });

        it("recognizes the broadcast PAN identifier value", () => {
            const frame = encodeMACFrame(
                {
                    frameControl: {
                        frameType: MACFrameType.DATA,
                        securityEnabled: false,
                        framePending: false,
                        ackRequest: false,
                        panIdCompression: false,
                        seqNumSuppress: false,
                        iePresent: false,
                        destAddrMode: MACFrameAddressMode.SHORT,
                        frameVersion: MACFrameVersion.V2003,
                        sourceAddrMode: MACFrameAddressMode.SHORT,
                    },
                    sequenceNumber: 0x42,
                    destinationPANId: ZigbeeMACConsts.BCAST_PAN,
                    destination16: ZigbeeMACConsts.BCAST_ADDR,
                    sourcePANId: ZigbeeMACConsts.BCAST_PAN,
                    source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    fcs: 0,
                },
                Buffer.alloc(0),
            );

            const decoded = decodeMACFramePayload(frame);

            expect(decoded.header.destinationPANId).toStrictEqual(ZigbeeMACConsts.BCAST_PAN);
        });

        it("encodes the PAN identifier using little-endian byte order", async () => {
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x3210, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const destPanOffset = 3; // FCF (2) + sequence number (1)
            expect(decoded.buffer.readUInt16LE(destPanOffset)).toStrictEqual(netParams.panId);
            expect(decoded.buffer[destPanOffset]).toStrictEqual(netParams.panId & 0xff);
            expect(decoded.buffer[destPanOffset + 1]).toStrictEqual((netParams.panId >> 8) & 0xff);
        });
    });

    /**
     * IEEE 802.15.4-2020 §6.2.2.10: Source Address
     * The Source Address field SHALL be present if the source addressing mode is
     * short or extended, and SHALL be omitted if the mode is none.
     */
    describe("MAC Addressing (IEEE 802.15.4-2020 §6.2.2.10)", () => {
        it("encodes 16-bit destination addresses", async () => {
            const destination16 = 0x5acd;
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, destination16, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            expect(decoded.frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.SHORT);
            expect(decoded.header.destination16).toStrictEqual(destination16);
        });

        it("encodes 64-bit destination addresses", async () => {
            const destination64 = 0x00124b0000abcde0n;
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, undefined, destination64, true, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            expect(decoded.frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.EXT);
            expect(decoded.header.destination64).toStrictEqual(destination64);
        });

        it("omits destination addressing when the addressing mode is none", async () => {
            const decoded = await captureMacFrame(() => macHandler.processBeaconReq(Buffer.alloc(0), 0, {} as MACHeader), mockMACHandlerCallbacks);

            expect(decoded.frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.NONE);
            expect(decoded.header.destination16).toBeUndefined();
            expect(decoded.header.destination64).toBeUndefined();
        });

        it("always sources coordinator-originated frames from address 0x0000", async () => {
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x7a10, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            expect(decoded.header.source16).toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);
        });

        it("maps Zigbee broadcast destinations to MAC broadcast addresses", async () => {
            const decoded = await captureMacFrame(
                () =>
                    nwkHandler.sendCommand(
                        ZigbeeNWKCommandId.ROUTE_REQ,
                        Buffer.from([ZigbeeNWKCommandId.ROUTE_REQ]),
                        false,
                        ZigbeeConsts.COORDINATOR_ADDRESS,
                        ZigbeeConsts.BCAST_DEFAULT,
                        undefined,
                        5,
                    ),
                mockMACHandlerCallbacks,
            );

            expect(decoded.header.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
        });

        it("treats reserved broadcast-range destinations as MAC broadcasts", async () => {
            const decoded = await captureMacFrame(
                () =>
                    nwkHandler.sendCommand(
                        ZigbeeNWKCommandId.ROUTE_REQ,
                        Buffer.from([ZigbeeNWKCommandId.ROUTE_REQ]),
                        false,
                        ZigbeeConsts.COORDINATOR_ADDRESS,
                        ZigbeeConsts.BCAST_MIN,
                        undefined,
                        5,
                    ),
                mockMACHandlerCallbacks,
            );

            expect(decoded.header.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
        });

        it("preserves the special 'no short address' value", async () => {
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, ZigbeeMACConsts.NO_ADDR16, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            expect(decoded.header.destination16).toStrictEqual(ZigbeeMACConsts.NO_ADDR16);
            expect(decoded.frameControl.ackRequest).toStrictEqual(true);
        });

        it("encodes 16-bit addresses using little-endian byte order", async () => {
            const destination16 = 0x6b5a;
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.ASSOC_RSP, destination16, undefined, false, Buffer.from([0x00])),
                mockMACHandlerCallbacks,
            );

            const destAddrOffset = 5; // FCF (2) + sequence (1) + dest PAN (2)
            expect(decoded.buffer.readUInt16LE(destAddrOffset)).toStrictEqual(destination16);
            expect(decoded.buffer[destAddrOffset]).toStrictEqual(destination16 & 0xff);
            expect(decoded.buffer[destAddrOffset + 1]).toStrictEqual((destination16 >> 8) & 0xff);
        });
    });

    /**
     * IEEE 802.15.4-2020 §6.3.1: Beacon Frame
     * A beacon frame SHALL contain a beacon payload including superframe specification,
     * GTS fields, and pending address fields.
     */
    describe("MAC Beacon Frame (IEEE 802.15.4-2020 §6.3.1)", () => {
        async function generateBeacon(): Promise<DecodedMACFrame> {
            return await captureMacFrame(() => macHandler.processBeaconReq(Buffer.alloc(0), 0, {} as MACHeader), mockMACHandlerCallbacks);
        }

        it("reports superframe defaults for non-beacon networks", async () => {
            const beacon = await generateBeacon();
            const superframe = beacon.header.superframeSpec;

            expect(superframe).toBeDefined();
            expect(superframe!.beaconOrder).toStrictEqual(0x0f);
            expect(superframe!.superframeOrder).toStrictEqual(0x0f);
            expect(superframe!.finalCAPSlot).toStrictEqual(0x0f);
            expect(superframe!.batteryExtension).toStrictEqual(false);
        });

        it("marks the coordinator role and reflects association policy", async () => {
            const initial = await generateBeacon();
            const baseFrame = initial.header.superframeSpec!;

            expect(baseFrame.panCoordinator).toStrictEqual(true);
            expect(baseFrame.associationPermit).toStrictEqual(false);

            context.associationPermit = true;
            const permissive = await generateBeacon();
            expect(permissive.header.superframeSpec!.associationPermit).toStrictEqual(true);
            context.associationPermit = false;
        });

        it("disables GTS and leaves pending address lists empty", async () => {
            const beacon = await generateBeacon();

            expect(beacon.header.gtsInfo?.permit).toStrictEqual(false);
            expect(beacon.header.gtsInfo?.slots).toBeUndefined();
            expect(beacon.header.pendAddr?.addr16List).toBeUndefined();
            expect(beacon.header.pendAddr?.addr64List).toBeUndefined();
        });

        it("encodes Zigbee beacon payload with coordinator capabilities", async () => {
            const beacon = await generateBeacon();
            const payload = decodeMACZigbeeBeacon(beacon.buffer, beacon.payloadOffset);

            expect(payload.protocolId).toStrictEqual(ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_ID);
            expect(payload.profile).toStrictEqual(0x02);
            expect(payload.version).toStrictEqual(ZigbeeNWKConsts.VERSION_2007);
            expect(payload.routerCapacity).toStrictEqual(true);
            expect(payload.deviceDepth).toStrictEqual(0);
            expect(payload.endDeviceCapacity).toStrictEqual(true);
            expect(payload.extendedPANId).toStrictEqual(netParams.extendedPanId);
            expect(payload.txOffset).toStrictEqual(0x00ffffff);
            expect(payload.updateId).toStrictEqual(netParams.nwkUpdateId);
        });
    });

    /**
     * IEEE 802.15.4-2020 §6.3.2: Data Frame
     * A data frame SHALL be used to transmit data between devices.
     */
    describe("MAC Data Frame (IEEE 802.15.4-2020 §6.3.2)", () => {
        const dest16 = 0x4b21;
        const dest64 = TEST_DEVICE_EUI64;
        const clusterId = 0x1234;
        const profileId = 0x0104;
        const destEndpoint = 0x0a;
        const sourceEndpoint = 0x0b;

        async function sendUnicast(payload: Buffer): Promise<DecodedMACFrame> {
            registerNeighborDevice(context, dest16, dest64);

            return await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        payload,
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        dest16,
                        dest64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        clusterId,
                        profileId,
                        destEndpoint,
                        sourceEndpoint,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
        }

        it("encodes unicast MAC data frames with the expected header fields", async () => {
            const decoded = await sendUnicast(Buffer.from([0xaa, 0xbb]));

            expect(decoded.frameControl.frameType).toStrictEqual(MACFrameType.DATA);
            expect(decoded.frameControl.securityEnabled).toStrictEqual(false);
            expect(decoded.frameControl.panIdCompression).toStrictEqual(true);
            expect(decoded.frameControl.ackRequest).toStrictEqual(true);
            expect(decoded.header.destinationPANId).toStrictEqual(netParams.panId);
            expect(decoded.header.destination16).toStrictEqual(dest16);
            expect(decoded.header.source16).toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);
        });

        it("places the NWK and APS payload immediately after the MAC header", async () => {
            const applicationPayload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
            const decoded = await sendUnicast(applicationPayload);
            const macPayload = decoded.buffer.subarray(decoded.payloadOffset, decoded.buffer.length - 2);

            const [nwkFCF, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            expect(nwkFCF.frameType).toStrictEqual(ZigbeeNWKFrameType.DATA);

            const [nwkHeader, apsOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFCF);
            expect(nwkHeader.destination16).toStrictEqual(dest16);
            expect(nwkHeader.source16).toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);

            const nwkPayload = decodeZigbeeNWKPayload(macPayload, apsOffset, undefined, context.netParams.eui64, nwkFCF, nwkHeader);

            const [apsFCF, apsHeaderOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            expect(apsFCF.frameType).toStrictEqual(ZigbeeAPSFrameType.DATA);
            expect(apsFCF.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.UNICAST);

            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsHeaderOffset, apsFCF);
            expect(apsHeader.clusterId).toStrictEqual(clusterId);
            expect(apsHeader.profileId).toStrictEqual(profileId);
            expect(apsHeader.destEndpoint).toStrictEqual(destEndpoint);
            expect(apsHeader.sourceEndpoint).toStrictEqual(sourceEndpoint);

            const apsPayload = nwkPayload.subarray(apsPayloadOffset);
            expect(apsPayload).toStrictEqual(applicationPayload);
        });

        it("keeps MAC data frames within the IEEE 802.15.4 payload limits", async () => {
            const paddedPayload = Buffer.alloc(30, 0xaa);
            const decoded = await sendUnicast(paddedPayload);

            expect(decoded.buffer.length).toBeLessThanOrEqual(ZigbeeMACConsts.FRAME_MAX_SIZE);
            const macPayloadLength = decoded.buffer.length - decoded.payloadOffset - 2;
            expect(macPayloadLength).toBeLessThanOrEqual(ZigbeeMACConsts.PAYLOAD_MAX_SIZE);
        });

        it("sets the frame pending bit when indirect transmissions are queued", async () => {
            registerNeighborDevice(context, dest16, dest64);

            context.indirectTransmissions.set(dest64, [
                {
                    sendFrame: async () => true,
                    timestamp: Date.now(),
                },
            ]);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await apsHandler.sendData(
                Buffer.from([0x55]),
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                dest16,
                dest64,
                ZigbeeAPSDeliveryMode.UNICAST,
                clusterId,
                profileId,
                destEndpoint,
                sourceEndpoint,
                undefined,
            );

            const indirectQueue = context.indirectTransmissions.get(dest64)!;
            expect(indirectQueue.length).toStrictEqual(2);
            const queuedTx = indirectQueue.pop()!;
            indirectQueue.shift();
            await queuedTx.sendFrame();

            expect(frames).toHaveLength(1);
            const decoded = decodeMACFramePayload(frames[0]!);
            expect(decoded.frameControl.framePending).toStrictEqual(true);

            context.indirectTransmissions.delete(dest64);
        });

        it("suppresses acknowledgments for broadcast data frames", async () => {
            const decoded = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0x01, 0x02]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        ZigbeeConsts.BCAST_DEFAULT,
                        undefined,
                        ZigbeeAPSDeliveryMode.BCAST,
                        clusterId,
                        profileId,
                        destEndpoint,
                        sourceEndpoint,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );

            expect(decoded.frameControl.frameType).toStrictEqual(MACFrameType.DATA);
            expect(decoded.frameControl.ackRequest).toStrictEqual(false);
            expect(decoded.header.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
        });
    });

    /**
     * IEEE 802.15.4-2020 §6.3.3: Association
     * The association procedure SHALL allow a device to join a PAN by
     * exchanging association request and response commands.
     */
    describe("MAC Association Procedure (IEEE 802.15.4-2020 §6.3.3)", () => {
        const device64 = TEST_DEVICE_EUI64;
        const defaultCapabilities =
            0x01 | // alternate PAN coordinator
            (1 << 1) | // FFD device type
            (1 << 2) | // mains power
            (1 << 3) | // receiver on when idle
            (1 << 6) | // security capability
            (1 << 7); // allocate address

        function buildAssocHeader(): MACHeader {
            const frameControl = createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.EXT);
            frameControl.panIdCompression = true;

            return {
                frameControl,
                sequenceNumber: 1,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: device64,
                commandId: MACCommandId.ASSOC_REQ,
                fcs: 0,
            };
        }

        function buildDataRequestHeader(): MACHeader {
            const frameControl = createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.EXT);
            frameControl.panIdCompression = true;

            return {
                frameControl,
                sequenceNumber: 2,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: device64,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            };
        }

        it("decodes capability information from association requests", async () => {
            context.allowJoins(60, true);
            const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.1);
            const associateSpy = vi.spyOn(context, "associate");

            await macHandler.processCommand(Buffer.from([defaultCapabilities]), buildAssocHeader());

            expect(associateSpy).toHaveBeenCalledTimes(1);
            const capabilitiesArg = associateSpy.mock.calls[0][3] as MACCapabilities;
            expect(capabilitiesArg).toStrictEqual({
                alternatePANCoordinator: true,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            });

            randomSpy.mockRestore();
        });

        it("assigns a valid short address on successful association", async () => {
            context.allowJoins(60, true);
            const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.1);

            await macHandler.processCommand(Buffer.from([defaultCapabilities]), buildAssocHeader());

            const device = context.deviceTable.get(device64);
            expect(device).not.toBeUndefined();
            expect(device!.address16).toBeGreaterThanOrEqual(0x0001);
            expect(device!.address16).toBeLessThan(ZigbeeConsts.BCAST_MIN);

            randomSpy.mockRestore();
        });

        it("sends association response payload with assigned address and success status", async () => {
            context.allowJoins(60, true);
            const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.2);

            await macHandler.processCommand(Buffer.from([defaultCapabilities]), buildAssocHeader());

            const pending = context.pendingAssociations.get(device64);
            expect(pending).not.toBeUndefined();

            const sendCommandSpy = vi.spyOn(macHandler, "sendCommand").mockResolvedValue(true);

            await pending!.sendResp();

            expect(sendCommandSpy).toHaveBeenCalledTimes(1);
            const [, , dest64, extSource, payload] = sendCommandSpy.mock.calls[0];
            expect(dest64).toStrictEqual(device64);
            expect(extSource).toStrictEqual(true);
            expect(payload.readUInt16LE(0)).toBeGreaterThanOrEqual(0x0001);
            expect(payload.readUInt16LE(0)).toBeLessThan(ZigbeeMACConsts.BCAST_ADDR);
            expect(payload.readUInt8(2)).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(mockMACHandlerCallbacks.onAPSSendTransportKeyNWK).toHaveBeenCalledTimes(1);

            randomSpy.mockRestore();
        });

        it("propagates PAN_FULL status to association responses", async () => {
            const associateSpy = vi.spyOn(context, "associate").mockResolvedValue([MACAssociationStatus.PAN_FULL, 0xffff, false]);
            const sendCommandSpy = vi.spyOn(macHandler, "sendCommand").mockResolvedValue(true);

            await macHandler.processCommand(Buffer.from([defaultCapabilities]), buildAssocHeader());

            const pending = context.pendingAssociations.get(device64);
            expect(pending).not.toBeUndefined();

            await pending!.sendResp();

            expect(sendCommandSpy).toHaveBeenCalledTimes(1);
            const payload = sendCommandSpy.mock.calls[0][4];
            expect(payload.readUInt16LE(0)).toStrictEqual(0xffff);
            expect(payload.readUInt8(2)).toStrictEqual(MACAssociationStatus.PAN_FULL);
            expect(mockMACHandlerCallbacks.onAPSSendTransportKeyNWK).not.toHaveBeenCalled();
            expect(context.deviceTable.has(device64)).toStrictEqual(false);

            associateSpy.mockRestore();
        });

        it("denies association when joins are not permitted", async () => {
            const sendCommandSpy = vi.spyOn(macHandler, "sendCommand").mockResolvedValue(true);

            await macHandler.processCommand(Buffer.from([defaultCapabilities]), buildAssocHeader());

            const pending = context.pendingAssociations.get(device64);
            expect(pending).not.toBeUndefined();

            await pending!.sendResp();

            const payload = sendCommandSpy.mock.calls[0][4];
            expect(payload.readUInt16LE(0)).toStrictEqual(0xffff);
            expect(payload.readUInt8(2)).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);
            expect(mockMACHandlerCallbacks.onAPSSendTransportKeyNWK).not.toHaveBeenCalled();
            expect(context.deviceTable.has(device64)).toStrictEqual(false);
        });

        it("serves pending association responses within indirect transmission timeout", async () => {
            context.allowJoins(60, true);
            const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.15);
            let currentTime = 1_000_000;
            const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => currentTime);

            await macHandler.processCommand(Buffer.from([defaultCapabilities]), buildAssocHeader());

            const sendCommandSpy = vi.spyOn(macHandler, "sendCommand").mockResolvedValue(true);
            currentTime += ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT - 10;

            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader());

            expect(sendCommandSpy).toHaveBeenCalledTimes(1);
            expect(context.pendingAssociations.has(device64)).toStrictEqual(false);
            expect(mockMACHandlerCallbacks.onAPSSendTransportKeyNWK).toHaveBeenCalledTimes(1);

            randomSpy.mockRestore();
            nowSpy.mockRestore();
        });

        it("expires pending association when data request arrives after timeout", async () => {
            context.allowJoins(60, true);
            const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.05);
            let currentTime = 2_000_000;
            const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => currentTime);

            await macHandler.processCommand(Buffer.from([defaultCapabilities]), buildAssocHeader());

            const sendCommandSpy = vi.spyOn(macHandler, "sendCommand");
            currentTime += ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT + 50;

            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader());

            expect(sendCommandSpy).not.toHaveBeenCalled();
            expect(context.pendingAssociations.has(device64)).toStrictEqual(false);
            expect(mockMACHandlerCallbacks.onAPSSendTransportKeyNWK).not.toHaveBeenCalled();

            randomSpy.mockRestore();
            nowSpy.mockRestore();
        });
    });

    /**
     * IEEE 802.15.4-2020 §6.3.4: Disassociation
     * The disassociation procedure SHALL allow a device to leave a PAN.
     */
    describe("MAC Disassociation Procedure (IEEE 802.15.4-2020 §6.3.4)", () => {
        const disassocDest16 = 0x4455;
        const disassocDest64 = 0x00124b0010102020n;

        function buildDisassocHeader(): MACHeader {
            const frameControl = createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT);
            frameControl.panIdCompression = true;

            return {
                frameControl,
                sequenceNumber: 9,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: disassocDest16,
                commandId: MACCommandId.DISASSOC_NOTIFY,
                fcs: 0,
            };
        }

        beforeEach(() => {
            registerNeighborDevice(context, disassocDest16, disassocDest64);
        });

        it("encodes disassociation notifications with the specified reason code", async () => {
            const decoded = await captureMacFrame(
                () =>
                    macHandler.sendCommand(
                        MACCommandId.DISASSOC_NOTIFY,
                        disassocDest16,
                        disassocDest64,
                        false,
                        Buffer.from([MACDisassociationReason.COORDINATOR_INITIATED]),
                    ),
                mockMACHandlerCallbacks,
            );

            expect(decoded.frameControl.frameType).toStrictEqual(MACFrameType.CMD);
            expect(decoded.header.commandId).toStrictEqual(MACCommandId.DISASSOC_NOTIFY);
            const payload = decoded.buffer.subarray(decoded.payloadOffset, decoded.buffer.length - 2);
            expect(payload.byteLength).toStrictEqual(1);
            expect(payload.readUInt8(0)).toStrictEqual(MACDisassociationReason.COORDINATOR_INITIATED);
        });

        it("processes coordinator-initiated disassociation notifications and removes device state", async () => {
            context.indirectTransmissions.set(disassocDest64, []);
            context.pendingAssociations.set(disassocDest64, {
                sendResp: async () => {},
                timestamp: Date.now(),
            });

            const disassociateSpy = vi.spyOn(context, "disassociate");

            await macHandler.processCommand(Buffer.from([MACDisassociationReason.COORDINATOR_INITIATED]), buildDisassocHeader());

            expect(disassociateSpy).toHaveBeenCalledWith(disassocDest16, undefined);
            expect(context.deviceTable.has(disassocDest64)).toStrictEqual(false);
            expect(context.address16ToAddress64.has(disassocDest16)).toStrictEqual(false);
            expect(context.indirectTransmissions.has(disassocDest64)).toStrictEqual(false);
            expect(context.pendingAssociations.has(disassocDest64)).toStrictEqual(false);
        });

        it("processes device-initiated disassociation notifications", async () => {
            const disassociateSpy = vi.spyOn(context, "disassociate");

            await macHandler.processCommand(Buffer.from([MACDisassociationReason.DEVICE_INITIATED]), buildDisassocHeader());

            expect(disassociateSpy).toHaveBeenCalledWith(disassocDest16, undefined);
            expect(context.deviceTable.has(disassocDest64)).toStrictEqual(false);
        });
    });

    /**
     * IEEE 802.15.4-2020 §6.3.5: Data Request
     * The data request command SHALL be used by a device to request pending data.
     */
    describe("MAC Data Request (IEEE 802.15.4-2020 §6.3.5)", () => {
        const dataReqDest16 = 0x2244;
        const dataReqDest64 = 0x00124b0011112222n;
        const clusterId = 0xef11;
        const profileId = 0x0104;
        const destEndpoint = 1;
        const sourceEndpoint = 1;

        function buildDataRequestHeader(withSource64 = true): MACHeader {
            const frameControl = createMACFrameControl(
                MACFrameType.CMD,
                MACFrameAddressMode.SHORT,
                withSource64 ? MACFrameAddressMode.EXT : MACFrameAddressMode.SHORT,
            );
            frameControl.panIdCompression = true;

            return {
                frameControl,
                sequenceNumber: 5,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: withSource64 ? undefined : dataReqDest16,
                source64: withSource64 ? dataReqDest64 : undefined,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            };
        }

        beforeEach(() => {
            registerNeighborDevice(context, dataReqDest16, dataReqDest64);
            context.indirectTransmissions.set(dataReqDest64, []);
        });

        afterEach(() => {
            context.indirectTransmissions.clear();
            context.pendingAssociations.clear();
            context.deviceTable.clear();
            context.address16ToAddress64.clear();
        });

        it("formats coordinator-originated data request command frames correctly", async () => {
            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.DATA_RQ, dataReqDest16, undefined, false, Buffer.alloc(0)),
                mockMACHandlerCallbacks,
            );

            expect(decoded.frameControl.frameType).toStrictEqual(MACFrameType.CMD);
            expect(decoded.frameControl.ackRequest).toStrictEqual(true);
            expect(decoded.frameControl.panIdCompression).toStrictEqual(true);
            expect(decoded.header.destinationPANId).toStrictEqual(netParams.panId);
            expect(decoded.header.destination16).toStrictEqual(dataReqDest16);
            expect(decoded.header.source16).toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);
            expect(decoded.header.commandId).toStrictEqual(MACCommandId.DATA_RQ);
            expect(decoded.buffer.subarray(decoded.payloadOffset, decoded.buffer.length - 2).byteLength).toStrictEqual(0);
        });

        it("responds to data requests with pending indirect transmissions", async () => {
            const firstPayload = Buffer.from([0xaa]);

            await apsHandler.sendData(
                firstPayload,
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                dataReqDest16,
                dataReqDest64,
                ZigbeeAPSDeliveryMode.UNICAST,
                clusterId,
                profileId,
                destEndpoint,
                sourceEndpoint,
                undefined,
            );

            expect(context.indirectTransmissions.get(dataReqDest64)?.length).toStrictEqual(1);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader());

            expect(frames).toHaveLength(1);
            const decoded = decodeMACFramePayload(frames[0]!);
            expect(decoded.frameControl.frameType).toStrictEqual(MACFrameType.DATA);

            const macPayload = frames[0]!.subarray(decoded.payloadOffset, frames[0]!.length - 2);
            const [nwkFCF, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, apsOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, apsOffset, undefined, context.netParams.eui64, nwkFCF, nwkHeader);
            const [apsFCF, apsHeaderOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsHeaderOffset, apsFCF);
            const apsPayload = nwkPayload.subarray(apsPayloadOffset);

            expect(apsPayload).toStrictEqual(firstPayload);
            expect(context.indirectTransmissions.get(dataReqDest64)?.length).toStrictEqual(0);
        });

        it("ignores data requests when no data is pending", async () => {
            const onSendFrame = vi.fn().mockResolvedValue(undefined);
            mockMACHandlerCallbacks.onSendFrame = onSendFrame;

            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader());

            expect(onSendFrame).not.toHaveBeenCalled();
        });

        it("sets the frame pending bit when additional indirect frames remain", async () => {
            const expiredEntry = {
                sendFrame: vi.fn().mockResolvedValue(true),
                timestamp: Date.now() - ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT - 1000,
            };
            context.indirectTransmissions.set(dataReqDest64, [expiredEntry]);

            await apsHandler.sendData(
                Buffer.from([0xbb, 0xcc]),
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                dataReqDest16,
                dataReqDest64,
                ZigbeeAPSDeliveryMode.UNICAST,
                clusterId,
                profileId,
                destEndpoint,
                sourceEndpoint,
                undefined,
            );

            const nowBase = Date.now() + 5000;
            const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => nowBase);
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader());

            expect(frames).toHaveLength(1);
            const decoded = decodeMACFramePayload(frames[0]!);
            expect(decoded.frameControl.framePending).toStrictEqual(true);
            nowSpy.mockRestore();
        });

        it("purges expired indirect transmissions while preserving valid ones", async () => {
            const activeFrame = Buffer.from([0xdd]);
            const expiredTx = {
                sendFrame: vi.fn().mockResolvedValue(true),
                timestamp: Date.now() - ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT - 2000,
            };
            const validTx = {
                sendFrame: vi.fn(async () => {
                    await mockMACHandlerCallbacks.onSendFrame!(Buffer.from([0xee]));
                    return true;
                }),
                timestamp: Date.now(),
            };
            context.indirectTransmissions.set(dataReqDest64, [expiredTx, validTx]);

            await apsHandler.sendData(
                activeFrame,
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                dataReqDest16,
                dataReqDest64,
                ZigbeeAPSDeliveryMode.UNICAST,
                clusterId,
                profileId,
                destEndpoint,
                sourceEndpoint,
                undefined,
            );

            const nowBase = Date.now() + 1000;
            const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => nowBase);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader(false));

            expect(expiredTx.sendFrame).not.toHaveBeenCalled();
            expect(validTx.sendFrame).toHaveBeenCalledTimes(1);
            expect(frames).toHaveLength(1);
            expect(context.indirectTransmissions.get(dataReqDest64)?.length).toStrictEqual(1);
            nowSpy.mockRestore();
        });
    });

    /**
     * IEEE 802.15.4-2020 §6.7: MAC Constants and PIB Attributes
     * MAC layer SHALL enforce specified constants and maintain PIB attributes.
     */
    describe("MAC Constants and Attributes (IEEE 802.15.4-2020 §6.7)", () => {
        it("keeps encoded MAC frames within aMaxPHYPacketSize and payload limits", async () => {
            const destination16 = 0x5a10;
            const destination64 = TEST_DEVICE_EUI64;
            registerNeighborDevice(context, destination16, destination64);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            try {
                const nearLimitPayload = Buffer.alloc(60, 0xaa);
                const result = await nwkHandler.sendCommand(
                    ZigbeeNWKCommandId.ROUTE_REQ,
                    nearLimitPayload,
                    false,
                    ZigbeeConsts.COORDINATOR_ADDRESS,
                    destination16,
                    destination64,
                    CONFIG_NWK_MAX_HOPS,
                );

                expect(result).toStrictEqual(true);
                expect(frames).toHaveLength(1);

                const decoded = decodeMACFramePayload(frames[0]!);
                expect(frames[0]!.length).toBeLessThanOrEqual(ZigbeeMACConsts.FRAME_MAX_SIZE);
                const macPayloadLength = frames[0]!.length - decoded.payloadOffset - 2;
                expect(macPayloadLength).toBeLessThanOrEqual(ZigbeeMACConsts.PAYLOAD_MAX_SIZE);
            } finally {
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
            }
        });

        it("rejects NWK command payloads that exceed aMaxMACPayloadSize", async () => {
            const destination16 = 0x5a11;
            const destination64 = TEST_DEVICE_EUI64;
            registerNeighborDevice(context, destination16, destination64);

            const oversizePayload = Buffer.alloc(ZigbeeMACConsts.PAYLOAD_MAX_SIZE, 0xbb);
            mockMACHandlerCallbacks.onSendFrame = vi.fn().mockResolvedValue(undefined);

            await expect(
                nwkHandler.sendCommand(
                    ZigbeeNWKCommandId.ROUTE_REQ,
                    oversizePayload,
                    true,
                    ZigbeeConsts.COORDINATOR_ADDRESS,
                    destination16,
                    destination64,
                    CONFIG_NWK_MAX_HOPS,
                ),
            ).rejects.toThrow(RangeError);

            expect(mockMACHandlerCallbacks.onSendFrame).not.toHaveBeenCalled();
            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("requests ACKs for unicast transmissions and records NO_ACK failures after MAC retry window", async () => {
            const destination16 = 0x5a12;
            const destination64 = TEST_DEVICE_EUI64;
            registerNeighborDevice(context, destination16, destination64);
            context.deviceTable.get(destination64)!.capabilities!.rxOnWhenIdle = true;

            const capturedFrames: Buffer[] = [];
            const macError = new Error("NO_ACK", { cause: NO_ACK_CODE });
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                capturedFrames.push(Buffer.from(payload));

                return Promise.reject(macError);
            });

            const sendResult = await macHandler.sendFrame(0x21, NETDEF_ACK_FRAME_FROM_COORD, destination16, destination64);

            expect(sendResult).toStrictEqual(false);
            expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1);
            expect(mockMACHandlerCallbacks.onMarkRouteFailure).toHaveBeenCalledWith(destination16);
            expect(context.macNoACKs.get(destination16)).toStrictEqual(1);
            expect(capturedFrames).toHaveLength(1);

            const decoded = decodeMACFramePayload(capturedFrames[0]!);
            expect(decoded.frameControl.ackRequest).toStrictEqual(true);

            mockMACHandlerCallbacks.onSendFrame = vi.fn().mockResolvedValue(undefined);

            const recoveryResult = await macHandler.sendFrame(0x22, NETDEF_ACK_FRAME_FROM_COORD, destination16, destination64);

            expect(recoveryResult).toStrictEqual(true);
            expect(mockMACHandlerCallbacks.onMarkRouteSuccess).toHaveBeenCalledWith(destination16);
            expect(context.macNoACKs.has(destination16)).toStrictEqual(false);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("delivers pending association responses only within macResponseWaitTime", async () => {
            vi.useFakeTimers();

            try {
                const now = 1_000_000;
                vi.setSystemTime(now);

                const sendResp = vi.fn().mockResolvedValue(undefined);
                context.pendingAssociations.set(TEST_DEVICE_EUI64, {
                    sendResp,
                    timestamp: now - (ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT - 50),
                });

                const macHeader = { source64: TEST_DEVICE_EUI64 } as MACHeader;

                await macHandler.processDataReq(Buffer.alloc(0), 0, macHeader);

                expect(sendResp).toHaveBeenCalledTimes(1);
                expect(context.pendingAssociations.has(TEST_DEVICE_EUI64)).toStrictEqual(false);
            } finally {
                vi.useRealTimers();
            }
        });

        it("expires pending association responses after macResponseWaitTime elapses", async () => {
            vi.useFakeTimers();

            try {
                const now = 2_000_000;
                vi.setSystemTime(now);

                const sendResp = vi.fn().mockResolvedValue(undefined);
                context.pendingAssociations.set(TEST_DEVICE_EUI64, {
                    sendResp,
                    timestamp: now - (ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT + 50),
                });

                const macHeader = { source64: TEST_DEVICE_EUI64 } as MACHeader;

                await macHandler.processDataReq(Buffer.alloc(0), 0, macHeader);

                expect(sendResp).not.toHaveBeenCalled();
                expect(context.pendingAssociations.has(TEST_DEVICE_EUI64)).toStrictEqual(false);
            } finally {
                vi.useRealTimers();
            }
        });
        it("wraps 32-bit security frame counters after reaching 0xffffffff", () => {
            context.netParams.networkKeyFrameCounter = 0xfffffffe;
            context.netParams.tcKeyFrameCounter = 0xfffffffe;

            const nwkMax = context.nextNWKKeyFrameCounter();
            expect(nwkMax).toStrictEqual(0xffffffff);
            const nwkWrapped = context.nextNWKKeyFrameCounter();
            expect(nwkWrapped).toStrictEqual(0x00000000);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(0x00000000);

            const tcMax = context.nextTCKeyFrameCounter();
            expect(tcMax).toStrictEqual(0xffffffff);
            const tcWrapped = context.nextTCKeyFrameCounter();
            expect(tcWrapped).toStrictEqual(0x00000000);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(0x00000000);
        });
    });

    /**
     * IEEE 802.15.4-2020 §9.3: MAC Security
     * When security is enabled, frames SHALL include auxiliary security header.
     */
    describe("MAC Security (IEEE 802.15.4-2020 §9.3)", () => {
        const destPanId = 0x1a62;
        const destAddress16 = ZigbeeConsts.COORDINATOR_ADDRESS;
        const sourceAddress16 = 0x1234;

        function buildSecureMacFrame(options?: {
            securityLevel?: MACSecurityLevel;
            keyIdMode?: MACSecurityKeyIdMode;
            frameCounter?: number;
            keyIndex?: number;
            keySequence?: number;
        }): Buffer {
            const securityLevel = options?.securityLevel ?? MACSecurityLevel.ENC_MIC_32;
            const keyIdMode = options?.keyIdMode ?? MACSecurityKeyIdMode.INDEX;
            const frameCounter = options?.frameCounter ?? 0x01020304;
            const keyIndex = options?.keyIndex ?? 0x07;
            const keySequence = options?.keySequence ?? 0x11;

            const keySourceLength = keyIdMode === MACSecurityKeyIdMode.EXPLICIT_4 ? 4 : keyIdMode === MACSecurityKeyIdMode.EXPLICIT_8 ? 8 : 0;
            const keyIdentifierLength = keyIdMode === MACSecurityKeyIdMode.IMPLICIT ? 0 : 1;
            const auxHeaderLength = 1 + 4 + keySourceLength + keyIdentifierLength;
            const encrypted = (securityLevel & 0x04) !== 0;
            const postAuxLength = encrypted ? 4 + 1 : 0;
            const payloadLength = 3;
            const totalLength =
                2 + // FCF
                1 + // sequence
                2 + // dest PAN
                2 + // dest 16
                2 + // source 16
                auxHeaderLength +
                postAuxLength +
                payloadLength +
                ZigbeeMACConsts.FCS_LEN;

            const frame = Buffer.alloc(totalLength);
            let offset = 0;

            frame.writeUInt16LE(0x8869, offset);
            offset += 2;

            frame.writeUInt8(0x01, offset);
            offset += 1;

            frame.writeUInt16LE(destPanId, offset);
            offset += 2;

            frame.writeUInt16LE(destAddress16, offset);
            offset += 2;

            frame.writeUInt16LE(sourceAddress16, offset);
            offset += 2;

            const securityControl =
                (securityLevel & ZigbeeMACConsts.AUX_SEC_LEVEL_MASK) |
                ((keyIdMode << ZigbeeMACConsts.AUX_KEY_ID_MODE_SHIFT) & ZigbeeMACConsts.AUX_KEY_ID_MODE_MASK);
            frame.writeUInt8(securityControl, offset);
            offset += 1;

            frame.writeUInt32LE(frameCounter, offset);
            offset += 4;

            if (keySourceLength === 4) {
                frame.writeUInt32LE(0xaabbccdd, offset);
                offset += 4;
            } else if (keySourceLength === 8) {
                frame.writeBigUInt64LE(0x00124b0012345678n, offset);
                offset += 8;
            }

            if (keyIdentifierLength === 1) {
                frame.writeUInt8(keyIndex, offset);
                offset += 1;
            }

            if (encrypted) {
                frame.writeUInt32LE(frameCounter, offset);
                offset += 4;
                frame.writeUInt8(keySequence, offset);
                offset += 1;
            }

            frame.writeUInt8(0xaa, offset);
            offset += 1;
            frame.writeUInt8(0xbb, offset);
            offset += 1;
            frame.writeUInt8(0xcc, offset);
            offset += 1;

            frame.writeUInt16LE(0x0000, offset);
            offset += 2;

            return frame;
        }

        it("sets the security enabled bit and exposes the auxiliary security header when MAC security is used", () => {
            const frame = buildSecureMacFrame();
            const decoded = decodeMACFramePayload(frame);

            expect(decoded.frameControl.securityEnabled).toStrictEqual(true);
            expect(decoded.header.auxSecHeader).not.toBeUndefined();
        });

        it("parses auxiliary security header metadata including frame counter and key identifier", () => {
            const frameCounter = 0x01020304;
            const keyIndex = 0x22;
            const keySequence = 0x33;
            const frame = buildSecureMacFrame({ frameCounter, keyIndex, keySequence });
            const decoded = decodeMACFramePayload(frame);

            expect(decoded.header.auxSecHeader?.securityLevel).toStrictEqual(MACSecurityLevel.ENC_MIC_32);
            expect(decoded.header.auxSecHeader?.keyIdMode).toStrictEqual(MACSecurityKeyIdMode.INDEX);
            expect(decoded.header.auxSecHeader?.keyIndex).toStrictEqual(keyIndex);
            expect(decoded.header.frameCounter).toStrictEqual(frameCounter);
            expect(decoded.header.keySeqCounter).toStrictEqual(keySequence);
        });

        it("rejects MAC payload decryption because encryption support is not implemented", () => {
            const frame = buildSecureMacFrame();
            const decoded = decodeMACFramePayload(frame);

            expect(() => decodeMACPayload(decoded.buffer, decoded.payloadOffset, decoded.frameControl, decoded.header)).toThrowError(
                new Error("Unsupported MAC frame: security enabled"),
            );
        });
    });
});
