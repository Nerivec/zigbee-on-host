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
    encodeMACCapabilities,
    MACAssociationStatus,
    type MACCapabilities,
    MACCommandId,
    MACFrameAddressMode,
    MACFrameType,
    type MACHeader,
    ZigbeeMACConsts,
} from "../../src/zigbee/mac.js";
import {
    makeKeyedHashByType,
    registerDefaultHashedKeys,
    ZigbeeConsts,
    ZigbeeKeyType,
    type ZigbeeSecurityHeader,
    ZigbeeSecurityLevel,
} from "../../src/zigbee/zigbee.js";
import {
    decodeZigbeeAPSFrameControl,
    decodeZigbeeAPSHeader,
    decodeZigbeeAPSPayload,
    ZigbeeAPSCommandId,
    ZigbeeAPSConsts,
    ZigbeeAPSDeliveryMode,
    ZigbeeAPSFrameType,
    type ZigbeeAPSHeader,
} from "../../src/zigbee/zigbee-aps.js";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    ZigbeeNWKCommandId,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    type ZigbeeNWKHeader,
    ZigbeeNWKManyToOne,
    ZigbeeNWKRouteDiscovery,
    ZigbeeNWKStatus,
} from "../../src/zigbee/zigbee-nwk.js";
import {
    APSHandler,
    type APSHandlerCallbacks,
    CONFIG_APS_ACK_WAIT_DURATION_MS,
    CONFIG_APS_MAX_FRAME_RETRIES,
} from "../../src/zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../../src/zigbee-stack/nwk-gp-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import {
    type NetworkParameters,
    StackContext,
    type StackContextCallbacks,
    TrustCenterKeyRequestPolicy,
} from "../../src/zigbee-stack/stack-context.js";
import { NETDEF_EXTENDED_PAN_ID, NETDEF_NETWORK_KEY, NETDEF_PAN_ID, NETDEF_TC_KEY } from "../data.js";
import { createMACFrameControl } from "../utils.js";
import { decodeMACFramePayload, decodeNwkCommandFromMac, NO_ACK_CODE, registerDevice, registerNeighborDevice } from "./utils.js";

describe("Integration and End-to-End Compliance", () => {
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
     * Full stack integration tests that verify compliance across all layers.
     */
    function decodeApsFromMac(frame: Buffer) {
        const macDecoded = decodeMACFramePayload(frame);
        const macPayload = macDecoded.buffer.subarray(macDecoded.payloadOffset, macDecoded.buffer.length - 2);
        const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
        const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
        const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsPayloadOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader);

        return { macDecoded, nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload };
    }

    function buildBeaconRequestHeader(device64: bigint, sequenceNumber = 0x15): MACHeader {
        return {
            frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
            sequenceNumber,
            destinationPANId: netParams.panId,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            sourcePANId: netParams.panId,
            source16: ZigbeeMACConsts.NO_ADDR16,
            source64: device64,
            commandId: MACCommandId.BEACON_REQ,
            fcs: 0,
        } satisfies MACHeader;
    }

    function buildAssocHeader(device64: bigint, sequenceNumber = 0x26, source16 = ZigbeeMACConsts.NO_ADDR16): MACHeader {
        return {
            frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
            sequenceNumber,
            destinationPANId: netParams.panId,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            sourcePANId: netParams.panId,
            source16,
            source64: device64,
            commandId: MACCommandId.ASSOC_REQ,
            fcs: 0,
        } satisfies MACHeader;
    }

    function buildDataRequestHeader(device64: bigint, source16: number, sequenceNumber: number): MACHeader {
        return {
            frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
            sequenceNumber,
            destinationPANId: netParams.panId,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            sourcePANId: netParams.panId,
            source16,
            source64: device64,
            commandId: MACCommandId.DATA_RQ,
            fcs: 0,
        } satisfies MACHeader;
    }

    describe("Complete Join Procedure", () => {
        it("performs the full end-to-end join handshake", async () => {
            context.allowJoins(120, true);

            const device64 = 0x00124b00deaa5501n;
            const deviceCapabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 0,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };
            const frames: Buffer[] = [];

            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });
            mockMACHandlerCallbacks.onAPSSendTransportKeyNWK = vi.fn(async (dest16, key, seqNum, dest64) => {
                await apsHandler.sendTransportKeyNWK(dest16, key, seqNum, dest64);
            });

            // Step 1: Device requests beacon information and coordinator responds with association permit set.
            await macHandler.processBeaconReq(Buffer.alloc(0), 0, buildBeaconRequestHeader(device64));
            expect(frames).toHaveLength(1);
            const beaconFrame = decodeMACFramePayload(frames[0]!);
            expect(beaconFrame.frameControl.frameType).toStrictEqual(MACFrameType.BEACON);
            expect(beaconFrame.frameControl.securityEnabled).toStrictEqual(false);
            expect(beaconFrame.header.superframeSpec?.associationPermit).toStrictEqual(true);

            // Step 2: Device issues association request with capabilities.
            await macHandler.processAssocReq(Buffer.from([encodeMACCapabilities(deviceCapabilities)]), 0, buildAssocHeader(device64));
            const entry = context.deviceTable.get(device64);
            expect(entry).not.toBeUndefined();
            expect(entry?.capabilities).toStrictEqual(deviceCapabilities);
            const assigned16 = entry!.address16!;
            expect(assigned16).not.toStrictEqual(0xffff);

            // Step 3: Device polls for data to receive the association response.
            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader(device64, assigned16, 0x31));
            expect(frames).toHaveLength(2);
            const assocFrame = decodeMACFramePayload(frames[1]!);
            expect(assocFrame.frameControl.frameType).toStrictEqual(MACFrameType.CMD);
            expect(assocFrame.frameControl.securityEnabled).toStrictEqual(false);
            expect(assocFrame.header.commandId).toStrictEqual(MACCommandId.ASSOC_RSP);
            const assocPayload = frames[1]!.subarray(assocFrame.payloadOffset, frames[1]!.length - 2);
            expect(assocPayload.readUInt16LE(0)).toStrictEqual(assigned16);
            expect(assocPayload.readUInt8(2)).toStrictEqual(MACAssociationStatus.SUCCESS);

            // Step 4: Coordinator delivers the network key via APS transport key on the next poll.
            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader(device64, assigned16, 0x32));
            expect(frames).toHaveLength(3);
            const transportDecoded = decodeApsFromMac(frames[2]!);
            expect(transportDecoded.nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.DATA);
            expect(transportDecoded.nwkFrameControl.security).toStrictEqual(false);
            expect(transportDecoded.nwkHeader.destination16).toStrictEqual(assigned16);
            expect(transportDecoded.apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(transportDecoded.apsFrameControl.security).toStrictEqual(true);
            expect(transportDecoded.apsFrameControl.ackRequest).toStrictEqual(false);
            expect(transportDecoded.apsHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.TRANSPORT);
            expect(transportDecoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(transportDecoded.apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK);
            expect(transportDecoded.apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.networkKey);
            expect(transportDecoded.apsPayload.readUInt8(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(
                context.netParams.networkKeySequenceNumber,
            );
            expect(transportDecoded.apsPayload.readBigUInt64LE(3 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(device64);
            expect(mockMACHandlerCallbacks.onAPSSendTransportKeyNWK).toHaveBeenCalledWith(
                assigned16,
                context.netParams.networkKey,
                context.netParams.networkKeySequenceNumber,
                device64,
            );

            const indirectQueue = context.indirectTransmissions.get(device64);
            expect(indirectQueue === undefined || indirectQueue.length === 0).toStrictEqual(true);

            // Step 5: Trust Center notifies the network of the unsecured join using Update Device.
            const frameCountBeforeUpdate = frames.length;
            context.address16ToAddress64.set(ZigbeeConsts.COORDINATOR_ADDRESS, context.netParams.eui64);
            const updateSent = await apsHandler.sendUpdateDevice(
                ZigbeeConsts.COORDINATOR_ADDRESS,
                device64,
                assigned16,
                ZigbeeAPSConsts.CMD_UPDATE_STANDARD_UNSEC_JOIN,
            );
            expect(updateSent).toStrictEqual(true);
            expect(frames).toHaveLength(frameCountBeforeUpdate + 1);
            const updateDecoded = decodeApsFromMac(frames[frameCountBeforeUpdate]!);
            expect(updateDecoded.nwkFrameControl.security).toStrictEqual(true);
            expect(updateDecoded.apsFrameControl.security).toStrictEqual(false);
            expect(updateDecoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.UPDATE_DEVICE);
            expect(updateDecoded.apsPayload.readBigUInt64LE(1)).toStrictEqual(device64);
            expect(updateDecoded.apsPayload.readUInt16LE(9)).toStrictEqual(assigned16);
            expect(updateDecoded.apsPayload.readUInt8(11)).toStrictEqual(ZigbeeAPSConsts.CMD_UPDATE_STANDARD_UNSEC_JOIN);

            // Step 6: Device broadcasts an end device announce and the stack reports it to external callbacks.
            const announcePayload = Buffer.alloc(1 + 2 + 8 + 1);
            let announceOffset = 0;
            announcePayload.writeUInt8(0x21, announceOffset);
            announceOffset += 1;
            announcePayload.writeUInt16LE(assigned16, announceOffset);
            announceOffset += 2;
            announcePayload.writeBigUInt64LE(device64, announceOffset);
            announceOffset += 8;
            announcePayload.writeUInt8(encodeMACCapabilities(deviceCapabilities), announceOffset);

            const announceMacHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x33,
                destinationPANId: context.netParams.panId,
                destination16: ZigbeeMACConsts.BCAST_ADDR,
                sourcePANId: context.netParams.panId,
                source16: assigned16,
                source64: device64,
                commandId: undefined,
                fcs: 0,
            };
            const announceNwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: false,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: true,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.BCAST_DEFAULT,
                source16: assigned16,
                source64: device64,
                radius: 5,
                seqNum: 0x44,
            };
            const announceApsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.BCAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                profileId: ZigbeeConsts.ZDO_PROFILE_ID,
                clusterId: ZigbeeConsts.END_DEVICE_ANNOUNCE,
                sourceEndpoint: 0x00,
                destEndpoint: 0x00,
                counter: 0x34,
            };

            await apsHandler.processFrame(announcePayload, announceMacHeader, announceNwkHeader, announceApsHeader, 96);
            await new Promise((resolve) => setImmediate(resolve));

            expect(mockAPSHandlerCallbacks.onDeviceJoined).toHaveBeenCalledWith(assigned16, device64, deviceCapabilities);
            expect(context.deviceTable.get(device64)?.capabilities).toStrictEqual(deviceCapabilities);
        });
    });

    describe("Complete Data Flow", () => {
        function emitAck(
            source16: number,
            source64: bigint,
            profileId: number,
            clusterId: number,
            sourceEndpoint: number,
            destEndpoint: number,
            counter: number,
        ): Promise<void> {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x41,
                destinationPANId: context.netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: context.netParams.panId,
                source16,
                source64,
                commandId: undefined,
                fcs: 0,
            };
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: true,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16,
                source64,
                radius: 3,
                seqNum: 0x52,
            };
            const apsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.ACK,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                profileId,
                clusterId,
                sourceEndpoint,
                destEndpoint,
                counter,
            };

            return apsHandler.processFrame(Buffer.alloc(0), macHeader, nwkHeader, apsHeader, 105);
        }

        it("transmits unicast application data through APS, NWK, and MAC with NWK security applied", async () => {
            const dest16 = 0x6ac1;
            const dest64 = 0x00124b00deadc0den;
            registerNeighborDevice(context, dest16, dest64);
            const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
            const frames: Buffer[] = [];

            mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                frames.push(Buffer.from(frame));
                return Promise.resolve();
            });

            const initialNWKCounter = context.netParams.networkKeyFrameCounter;
            const clusterId = 0x0500;
            const profileId = 0x0104;
            const sourceEndpoint = 0x01;
            const destEndpoint = 0x02;

            const apsCounter = await apsHandler.sendData(
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
            );

            expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1);
            expect(mockMACHandlerCallbacks.onMarkRouteSuccess).toHaveBeenCalledWith(dest16);

            const decoded = decodeApsFromMac(frames[0]!);

            expect(decoded.macDecoded.frameControl.frameType).toStrictEqual(MACFrameType.DATA);
            expect(decoded.macDecoded.frameControl.ackRequest).toStrictEqual(true);
            expect(decoded.macDecoded.header.destination16).toStrictEqual(dest16);

            expect(decoded.nwkFrameControl.security).toStrictEqual(true);
            expect(decoded.nwkHeader.destination16).toStrictEqual(dest16);
            expect(decoded.nwkHeader.securityHeader?.frameCounter).toStrictEqual((initialNWKCounter + 1) >>> 0);

            expect(decoded.apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.DATA);
            expect(decoded.apsFrameControl.security).toStrictEqual(false);
            expect(decoded.apsFrameControl.ackRequest).toStrictEqual(true);
            expect(decoded.apsHeader.profileId).toStrictEqual(profileId);
            expect(decoded.apsHeader.clusterId).toStrictEqual(clusterId);
            expect(decoded.apsHeader.sourceEndpoint).toStrictEqual(sourceEndpoint);
            expect(decoded.apsHeader.destEndpoint).toStrictEqual(destEndpoint);
            expect(decoded.apsHeader.counter).toStrictEqual(apsCounter);
            expect(decoded.apsPayload).toStrictEqual(payload);

            expect(context.netParams.networkKeyFrameCounter).toStrictEqual((initialNWKCounter + 1) >>> 0);
            expect(context.macNoACKs.has(dest16)).toStrictEqual(false);
        });

        it("routes data via stored source route and clears pending ACKs when acknowledgments arrive", async () => {
            vi.useFakeTimers();
            try {
                const dest16 = 0x7b22;
                const dest64 = 0x00124b00cafefeedn;
                registerNeighborDevice(context, dest16, dest64);

                const relayPath = [0x2356, 0x3467];
                const sourceRouteEntry = nwkHandler.createSourceRouteEntry(relayPath, relayPath.length + 1);
                context.sourceRouteTable.set(dest16, [sourceRouteEntry]);

                const frames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                    frames.push(Buffer.from(frame));
                    return Promise.resolve();
                });
                mockMACHandlerCallbacks.onMarkRouteSuccess = vi.fn();

                const payload = Buffer.from([0x33, 0x44]);
                const clusterId = 0x0019;
                const profileId = ZigbeeConsts.ZDO_PROFILE_ID;
                const sourceEndpoint = 0x00;
                const destEndpoint = 0x05;

                const apsCounter = await apsHandler.sendData(
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
                );

                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1);
                const decoded = decodeApsFromMac(frames[0]!);

                const expectedNextHop = relayPath[relayPath.length - 1];
                expect(decoded.macDecoded.header.destination16).toStrictEqual(expectedNextHop);
                expect(decoded.nwkFrameControl.sourceRoute).toStrictEqual(true);
                expect(decoded.nwkHeader.relayIndex).toStrictEqual(relayPath.length - 1);
                expect(decoded.nwkHeader.relayAddresses).toStrictEqual(relayPath);
                expect(mockMACHandlerCallbacks.onMarkRouteSuccess).toHaveBeenCalledWith(expectedNextHop);

                await emitAck(dest16, dest64, profileId, clusterId, destEndpoint, sourceEndpoint, apsCounter);
                await vi.advanceTimersByTimeAsync(1600);

                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1);
                expect(mockMACHandlerCallbacks.onMarkRouteFailure).not.toHaveBeenCalled();
            } finally {
                vi.useRealTimers();
            }
        });
    });

    describe("Route Discovery and Data Delivery", () => {
        it("initiates route discovery when destination has no known path", async () => {
            vi.useFakeTimers();

            try {
                const destination16 = 0x6ac2;
                const destination64 = 0x00124b00aa55aa01n;
                registerDevice(context, destination16, destination64, false);

                const frames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                    frames.push(Buffer.from(frame));
                    return Promise.resolve();
                });

                await apsHandler.sendData(
                    Buffer.from([0x01, 0x02]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    destination16,
                    destination64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x1234,
                    0x0104,
                    0x02,
                    0x01,
                    undefined,
                );

                expect(frames).toHaveLength(1);

                await vi.runOnlyPendingTimersAsync();

                expect(frames.length).toBeGreaterThanOrEqual(2);

                const discoveryFrames = frames.slice(1);
                const decodedDiscovery = discoveryFrames.map((frame) => decodeNwkCommandFromMac(frame, context.netParams.eui64));
                const routeRequests = decodedDiscovery.filter(({ nwkFrameControl, nwkPayload }) => {
                    if (nwkFrameControl.frameType !== ZigbeeNWKFrameType.CMD) {
                        return false;
                    }

                    if (nwkPayload.byteLength === 0) {
                        return false;
                    }

                    return nwkPayload.readUInt8(0) === ZigbeeNWKCommandId.ROUTE_REQ;
                });

                expect(routeRequests.length).toBeGreaterThanOrEqual(1);

                const { macDecoded, nwkHeader, nwkPayload } = routeRequests[0]!;
                expect(macDecoded.frameControl.frameType).toStrictEqual(MACFrameType.DATA);
                expect(macDecoded.header.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
                expect(nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
                const options = nwkPayload.readUInt8(1);
                const manyToOne = (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK) >> 3;
                expect(manyToOne).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            } finally {
                vi.useRealTimers();
            }
        });

        it("stores source routing metadata when processing route replies", async () => {
            const responder16 = 0x7c01;
            const responder64 = 0x00124b00feedc0fen;
            const relay16 = 0x4455;
            const relay64 = 0x00124b0000004455n;

            registerDevice(context, responder16, responder64, false);
            registerDevice(context, relay16, relay64, true);

            const payload = Buffer.alloc(1 + 1 + 1 + 2 + 2 + 1 + 8);
            let offset = 0;
            payload.writeUInt8(ZigbeeNWKCommandId.ROUTE_REPLY, offset);
            offset += 1;
            payload.writeUInt8(ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT, offset);
            offset += 1;
            payload.writeUInt8(0x34, offset);
            offset += 1;
            payload.writeUInt16LE(ZigbeeConsts.COORDINATOR_ADDRESS, offset);
            offset += 2;
            payload.writeUInt16LE(responder16, offset);
            offset += 2;
            payload.writeUInt8(2, offset);
            offset += 1;
            payload.writeBigUInt64LE(responder64, offset);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x41,
                destinationPANId: context.netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: context.netParams.panId,
                source16: relay16,
                source64: relay64,
                commandId: undefined,
                fcs: 0,
            };
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: false,
                    sourceRoute: true,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: responder16,
                radius: 3,
                seqNum: 0x52,
                relayIndex: 0,
                relayAddresses: [relay16],
            };

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            const routes = context.sourceRouteTable.get(responder16);
            expect(routes).not.toBeUndefined();
            expect(routes?.[0]?.relayAddresses).toStrictEqual([relay16]);
            expect(routes?.[0]?.pathCost).toStrictEqual(2);
            expect(context.address16ToAddress64.get(responder16)).toStrictEqual(responder64);
        });

        it("uses the cached route for subsequent APS data", async () => {
            const responder16 = 0x7c01;
            const responder64 = 0x00124b00feedc0fen;
            const relay16 = 0x4455;
            const relay64 = 0x00124b0000004455n;

            registerDevice(context, responder16, responder64, false);
            registerDevice(context, relay16, relay64, true);

            const routeEntry = nwkHandler.createSourceRouteEntry([relay16], 2);
            context.sourceRouteTable.set(responder16, [routeEntry]);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                frames.push(Buffer.from(frame));
                return Promise.resolve();
            });

            await apsHandler.sendData(
                Buffer.from([0xaa, 0xbb]),
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                responder16,
                responder64,
                ZigbeeAPSDeliveryMode.UNICAST,
                0x2345,
                0x0104,
                0x12,
                0x34,
                undefined,
            );

            expect(frames).toHaveLength(1);
            const { macDecoded, nwkFrameControl, nwkHeader } = decodeNwkCommandFromMac(frames[0]!, context.netParams.eui64);
            expect(macDecoded.header.destination16).toStrictEqual(relay16);
            expect(nwkFrameControl.sourceRoute).toStrictEqual(true);
            expect(nwkHeader.relayAddresses).toStrictEqual([relay16]);
            expect(mockMACHandlerCallbacks.onMarkRouteSuccess).toHaveBeenCalledWith(relay16);
        });

        it("broadcasts many-to-one route requests with source routing support", async () => {
            vi.useFakeTimers();

            try {
                const frames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                    frames.push(Buffer.from(frame));
                    return Promise.resolve();
                });

                await nwkHandler.sendRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, ZigbeeConsts.BCAST_DEFAULT);

                expect(frames).toHaveLength(1);
                const { macDecoded, nwkFrameControl, nwkHeader, nwkPayload } = decodeNwkCommandFromMac(frames[0]!, context.netParams.eui64);
                expect(macDecoded.header.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
                expect(nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.CMD);
                expect(nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
                expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.ROUTE_REQ);
                const options = nwkPayload.readUInt8(1);
                const manyToOne = (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK) >> 3;
                expect(manyToOne).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            } finally {
                vi.useRealTimers();
            }
        });

        it("enforces the minimum interval between many-to-one route requests", async () => {
            vi.useFakeTimers();

            try {
                const frames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((frame: Buffer) => {
                    frames.push(Buffer.from(frame));
                    return Promise.resolve();
                });

                vi.setSystemTime(20_000);
                await nwkHandler.sendPeriodicManyToOneRouteRequest();
                expect(frames).toHaveLength(1);

                await nwkHandler.sendPeriodicManyToOneRouteRequest();
                expect(frames).toHaveLength(1);

                vi.setSystemTime(31_000);
                await nwkHandler.sendPeriodicManyToOneRouteRequest();
                expect(frames).toHaveLength(2);
            } finally {
                vi.useRealTimers();
            }
        });
    });

    describe("Security Key Distribution", () => {
        it("delivers the network key with APS transport security immediately after association", async () => {
            context.allowJoins(60, true);

            const device64 = 0x00124b00deaf1101n;
            const deviceCapabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 0,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };
            const frames: Buffer[] = [];

            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });
            mockMACHandlerCallbacks.onAPSSendTransportKeyNWK = vi.fn(async (dest16, key, seqNum, dest64) => {
                await apsHandler.sendTransportKeyNWK(dest16, key, seqNum, dest64);
            });

            await macHandler.processAssocReq(Buffer.from([encodeMACCapabilities(deviceCapabilities)]), 0, buildAssocHeader(device64));
            const pending = context.pendingAssociations.get(device64);
            expect(pending).not.toBeUndefined();
            const deviceEntry = context.deviceTable.get(device64);
            expect(deviceEntry).not.toBeUndefined();
            const assigned16 = deviceEntry!.address16!;

            const startCounter = context.netParams.tcKeyFrameCounter;

            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader(device64, assigned16, 0x41));
            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader(device64, assigned16, 0x42));
            expect(frames.length).toBeGreaterThan(1);

            let decodedTransport: ReturnType<typeof decodeApsFromMac> | undefined;
            for (const frame of frames) {
                try {
                    const decoded = decodeApsFromMac(frame);

                    if (
                        decoded.apsFrameControl.frameType === ZigbeeAPSFrameType.CMD &&
                        decoded.apsPayload.readUInt8(0) === ZigbeeAPSCommandId.TRANSPORT_KEY
                    ) {
                        decodedTransport = decoded;
                        break;
                    }
                } catch {
                    // ignore frames we cannot decode as APS command payloads
                }
            }

            expect(decodedTransport).not.toBeUndefined();
            const transportDecoded = decodedTransport!;
            expect(mockMACHandlerCallbacks.onAPSSendTransportKeyNWK).toHaveBeenCalledTimes(1);
            expect(transportDecoded.nwkFrameControl.security).toStrictEqual(false);
            expect(transportDecoded.nwkHeader.destination16).toStrictEqual(assigned16);
            expect(transportDecoded.apsFrameControl.security).toStrictEqual(true);
            expect(transportDecoded.apsFrameControl.ackRequest).toStrictEqual(false);
            expect(transportDecoded.apsHeader.securityHeader).not.toBeUndefined();
            expect(transportDecoded.apsHeader.securityHeader!.control.keyId).toStrictEqual(ZigbeeKeyType.TRANSPORT);
            expect(transportDecoded.apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.networkKey);
            expect(transportDecoded.apsPayload.readUInt8(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(
                context.netParams.networkKeySequenceNumber,
            );
            expect(transportDecoded.apsPayload.readBigUInt64LE(3 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(device64);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(startCounter + 1);
            expect(context.pendingAssociations.has(device64)).toStrictEqual(false);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
            mockMACHandlerCallbacks.onAPSSendTransportKeyNWK = vi.fn();
            context.disallowJoins();
        });

        it("responds to TC link key requests by sending APS LOAD encrypted transport key", async () => {
            const device16 = 0x6b10;
            const device64 = 0x00124b00ffeed501n;
            registerNeighborDevice(context, device16, device64);

            context.trustCenterPolicies.allowTCKeyRequest = TrustCenterKeyRequestPolicy.ALLOWED;
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.from([ZigbeeAPSCommandId.REQUEST_KEY, ZigbeeAPSConsts.CMD_KEY_TC_LINK]);
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x31,
                destinationPANId: context.netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: context.netParams.panId,
                source16: device16,
                source64: device64,
                commandId: undefined,
                fcs: 0,
            };
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: true,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
                source64: device64,
                radius: 5,
                seqNum: 0x42,
            };
            const apsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.CMD,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: true,
                    ackRequest: true,
                    extendedHeader: false,
                },
                counter: 0x52,
            };

            const tcCounterStart = context.netParams.tcKeyFrameCounter;
            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const decoded = decodeApsFromMac(frames[0]!);
            expect(decoded.nwkFrameControl.security).toStrictEqual(true);
            expect(decoded.nwkHeader.destination16).toStrictEqual(device16);
            expect(decoded.apsFrameControl.security).toStrictEqual(true);
            expect(decoded.apsHeader.securityHeader).not.toBeUndefined();
            expect(decoded.apsHeader.securityHeader!.control.keyId).toStrictEqual(ZigbeeKeyType.LOAD);
            expect(decoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(decoded.apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_TC_LINK);
            expect(decoded.apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.tcKey);
            expect(decoded.apsPayload.readBigUInt64LE(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(device64);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(tcCounterStart + 1);
        });

        it("rotates the staged network key for all devices and applies it on switch command", async () => {
            const deviceA16 = 0x2345;
            const deviceA64 = 0x00124b0000aa5501n;
            const deviceB16 = 0x3478;
            const deviceB64 = 0x00124b0000aa5502n;
            registerNeighborDevice(context, deviceA16, deviceA64);
            registerNeighborDevice(context, deviceB16, deviceB64);

            const pendingKey = Buffer.from("8899aabbccddeeff0011223344556677", "hex");
            const pendingSeq = 0x21;
            context.setPendingNetworkKey(pendingKey, pendingSeq);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const tcCounterStart = context.netParams.tcKeyFrameCounter;
            await apsHandler.sendTransportKeyNWK(deviceA16, pendingKey, pendingSeq, deviceA64);
            await apsHandler.sendTransportKeyNWK(deviceB16, pendingKey, pendingSeq, deviceB64);

            expect(frames).toHaveLength(2);
            const decodedByDest = new Map<number, ReturnType<typeof decodeApsFromMac>>();
            for (const frame of frames) {
                const decoded = decodeApsFromMac(frame);
                decodedByDest.set(decoded.macDecoded.header.destination16!, decoded);
                expect(decoded.nwkFrameControl.security).toStrictEqual(false);
                expect(decoded.apsFrameControl.security).toStrictEqual(true);
                expect(decoded.apsFrameControl.ackRequest).toStrictEqual(false);
                expect(decoded.apsHeader.securityHeader).not.toBeUndefined();
                expect(decoded.apsHeader.securityHeader!.control.keyId).toStrictEqual(ZigbeeKeyType.TRANSPORT);
                expect(decoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
                expect(decoded.apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK);
                expect(decoded.apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(pendingKey);
                expect(decoded.apsPayload.readUInt8(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(pendingSeq);
            }

            const deviceAFrame = decodedByDest.get(deviceA16);
            const deviceBFrame = decodedByDest.get(deviceB16);
            expect(deviceAFrame).not.toBeUndefined();
            expect(deviceBFrame).not.toBeUndefined();
            expect(deviceAFrame!.apsPayload.readBigUInt64LE(3 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(deviceA64);
            expect(deviceBFrame!.apsPayload.readBigUInt64LE(3 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(deviceB64);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(tcCounterStart + 2);

            frames.length = 0;
            const nwkCounterStart = context.netParams.networkKeyFrameCounter;
            await apsHandler.sendSwitchKey(ZigbeeConsts.BCAST_DEFAULT, pendingSeq);

            expect(frames).toHaveLength(1);
            const switchDecoded = decodeApsFromMac(frames[0]!);
            expect(switchDecoded.macDecoded.header.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
            expect(switchDecoded.nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(switchDecoded.nwkFrameControl.security).toStrictEqual(true);
            expect(switchDecoded.apsFrameControl.security).toStrictEqual(false);
            expect(switchDecoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.SWITCH_KEY);
            expect(switchDecoded.apsPayload.readUInt8(1)).toStrictEqual(pendingSeq);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(nwkCounterStart + 1);

            const originalKey = Buffer.from(context.netParams.networkKey);
            const inboundMacHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x80,
                destinationPANId: context.netParams.panId,
                destination16: deviceA16,
                sourcePANId: context.netParams.panId,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: context.netParams.eui64,
                commandId: undefined,
                fcs: 0,
            };
            const inboundNwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: deviceA16,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: 5,
                seqNum: 0x90,
            };
            const inboundApsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.CMD,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                counter: 0x99,
            };

            await apsHandler.processSwitchKey(Buffer.from([pendingSeq]), 0, inboundMacHeader, inboundNwkHeader, inboundApsHeader);

            expect(context.netParams.networkKey.equals(originalKey)).toStrictEqual(false);
            expect(context.netParams.networkKey).toStrictEqual(pendingKey);
            expect(context.netParams.networkKeySequenceNumber).toStrictEqual(pendingSeq & 0xff);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(0);
        });

        it("increments trust center and network key frame counters across key distribution flow", async () => {
            const device16 = 0x4c21;
            const device64 = 0x00124b00c0ffee01n;
            registerNeighborDevice(context, device16, device64);

            mockMACHandlerCallbacks.onSendFrame = vi.fn(() => Promise.resolve());

            const tcStart = context.netParams.tcKeyFrameCounter;
            await apsHandler.sendTransportKeyTC(device16, context.netParams.tcKey, device64);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(tcStart + 1);

            const nwkKey = Buffer.from("00112233445566778899aabbccddeeff", "hex");
            await apsHandler.sendTransportKeyNWK(device16, nwkKey, 0x33, device64);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(tcStart + 2);

            const nwkStart = context.netParams.networkKeyFrameCounter;
            context.setPendingNetworkKey(Buffer.from(nwkKey), 0x33);
            await apsHandler.sendSwitchKey(device16, 0x33);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(nwkStart + 1);

            const inboundMacHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x55,
                destinationPANId: context.netParams.panId,
                destination16: device16,
                sourcePANId: context.netParams.panId,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: context.netParams.eui64,
                commandId: undefined,
                fcs: 0,
            };
            const inboundNwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: device16,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: 5,
                seqNum: 0x56,
            };
            const inboundApsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.CMD,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                counter: 0x57,
            };

            await apsHandler.processSwitchKey(Buffer.from([0x33]), 0, inboundMacHeader, inboundNwkHeader, inboundApsHeader);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(0);
        });
    });

    describe("Device Leave and Rejoin", () => {
        function buildLeaveHeaders(
            device16: number,
            device64: bigint,
            macSeq = 0x70,
            nwkSeq = 0x40,
        ): {
            macHeader: MACHeader;
            nwkHeader: ZigbeeNWKHeader;
        } {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: macSeq,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: netParams.panId,
                source16: device16,
                source64: device64,
                commandId: undefined,
                fcs: 0,
            } satisfies MACHeader;
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: false,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: true,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
                source64: device64,
                radius: 1,
                seqNum: nwkSeq,
            } satisfies ZigbeeNWKHeader;

            return { macHeader, nwkHeader };
        }

        function buildRejoinHeaders(
            device16: number,
            device64: bigint,
            secure: boolean,
            macSeq = 0x80,
            nwkSeq = 0x50,
        ): {
            macHeader: MACHeader;
            nwkHeader: ZigbeeNWKHeader;
        } {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: macSeq,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: netParams.panId,
                source16: device16,
                source64: device64,
                commandId: undefined,
                fcs: 0,
            } satisfies MACHeader;
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: secure,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: true,
                    endDeviceInitiator: true,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
                source64: device64,
                radius: 2,
                seqNum: nwkSeq,
            } satisfies ZigbeeNWKHeader;

            if (secure) {
                nwkHeader.securityHeader = {
                    control: {
                        level: ZigbeeSecurityLevel.ENC_MIC32,
                        keyId: ZigbeeKeyType.NWK,
                        nonce: true,
                        reqVerifiedFc: false,
                    },
                    frameCounter: 0x01020304,
                    source64: device64,
                    keySeqNum: context.netParams.networkKeySequenceNumber,
                    micLen: 4,
                } satisfies ZigbeeSecurityHeader;
            }

            return { macHeader, nwkHeader };
        }

        it("removes device state when a leave command is processed", async () => {
            const device16 = 0x4455;
            const device64 = 0x00124b00deaf1102n;
            registerNeighborDevice(context, device16, device64);
            context.indirectTransmissions.set(device64, []);
            context.macNoACKs.set(device16, 2);

            const { macHeader, nwkHeader } = buildLeaveHeaders(device16, device64);
            const payload = Buffer.from([ZigbeeNWKCommandId.LEAVE, 0x00]);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);
            await new Promise((resolve) => setImmediate(resolve));

            expect(context.deviceTable.has(device64)).toStrictEqual(false);
            expect(context.address16ToAddress64.has(device16)).toStrictEqual(false);
            expect(context.indirectTransmissions.has(device64)).toStrictEqual(false);
            expect(context.macNoACKs.has(device16)).toStrictEqual(false);
            expect(mockStackContextCallbacks.onDeviceLeft).toHaveBeenCalledWith(device16, device64);
        });

        it("processes trust center rejoin requests and updates device capabilities", async () => {
            const device16 = 0x2365;
            const device64 = 0x00124b00deaf1103n;
            registerNeighborDevice(context, device16, device64);
            const existing = context.deviceTable.get(device64)!;
            existing.capabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 0,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            } satisfies MACCapabilities;
            existing.neighbor = false;

            const rejoinCaps: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const { macHeader, nwkHeader } = buildRejoinHeaders(device16, device64, false);
            const payload = Buffer.from([ZigbeeNWKCommandId.REJOIN_REQ, encodeMACCapabilities(rejoinCaps)]);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            expect(frames).toHaveLength(1);
            const decoded = decodeNwkCommandFromMac(frames[0]!, context.netParams.eui64);
            const { nwkPayload } = decoded;
            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.REJOIN_RESP);
            expect(nwkPayload.readUInt16LE(1)).toStrictEqual(device16);
            expect(nwkPayload.readUInt8(3)).toStrictEqual(MACAssociationStatus.SUCCESS);

            const updated = context.deviceTable.get(device64)!;
            expect(updated.capabilities).toStrictEqual(rejoinCaps);
            expect(updated.neighbor).toStrictEqual(true);

            await new Promise((resolve) => setImmediate(resolve));
        });

        it("restores unknown devices by issuing rejoin responses", async () => {
            const device16 = 0x3466;
            const device64 = 0x00124b00deaf1104n;
            const rejoinCaps: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 1,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const { macHeader, nwkHeader } = buildRejoinHeaders(device16, device64, true, 0x82, 0x52);
            const payload = Buffer.from([ZigbeeNWKCommandId.REJOIN_REQ, encodeMACCapabilities(rejoinCaps)]);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            const restored = context.deviceTable.get(device64);
            expect(restored).not.toBeUndefined();
            expect(restored!.address16).toStrictEqual(device16);
            expect(restored!.authorized).toStrictEqual(false);
            expect(context.address16ToAddress64.get(device16)).toStrictEqual(device64);

            const indirectQueue = context.indirectTransmissions.get(device64);
            expect(indirectQueue).not.toBeUndefined();
            expect(indirectQueue!.length).toStrictEqual(1);

            await new Promise((resolve) => setImmediate(resolve));
        });

        it("secures rejoin responses with the network key for secure rejoins", async () => {
            const device16 = 0x4177;
            const device64 = 0x00124b00deaf1105n;
            registerNeighborDevice(context, device16, device64);
            context.deviceTable.get(device64)!.authorized = true;

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const startCounter = context.netParams.networkKeyFrameCounter;
            const { macHeader, nwkHeader } = buildRejoinHeaders(device16, device64, true);
            const payload = Buffer.from([ZigbeeNWKCommandId.REJOIN_REQ, encodeMACCapabilities(context.deviceTable.get(device64)!.capabilities!)]);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            expect(frames).toHaveLength(1);
            const decoded = decodeNwkCommandFromMac(frames[0]!, context.netParams.eui64);
            expect(decoded.nwkFrameControl.security).toStrictEqual(true);
            expect(decoded.nwkHeader.securityHeader).not.toBeUndefined();
            expect(decoded.nwkHeader.securityHeader!.control.keyId).toStrictEqual(ZigbeeKeyType.NWK);
            expect(decoded.nwkHeader.securityHeader!.frameCounter).toStrictEqual(context.netParams.networkKeyFrameCounter);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual((startCounter + 1) >>> 0);
        });
    });

    describe("Error Handling and Recovery", () => {
        it("propagates MAC no-ack failures into NWK route tracking", async () => {
            const destination16 = 0x6b7c;
            const destination64 = 0x00124b00deaf7701n;
            registerNeighborDevice(context, destination16, destination64);

            const routeEntry = nwkHandler.createSourceRouteEntry([], 1);
            context.sourceRouteTable.set(destination16, [routeEntry]);

            const markRouteFailureSpy = vi.spyOn(nwkHandler, "markRouteFailure");
            mockMACHandlerCallbacks.onMarkRouteFailure = vi.fn((dest16: number) => {
                nwkHandler.markRouteFailure(dest16);
            });

            const macError = new Error("NO_ACK", { cause: NO_ACK_CODE });
            mockMACHandlerCallbacks.onSendFrame = vi.fn(() => Promise.reject(macError));

            const result = await nwkHandler.sendStatus(destination16, ZigbeeNWKStatus.LINK_FAILURE, destination16);

            expect(result).toStrictEqual(false);
            expect(markRouteFailureSpy).toHaveBeenCalledWith(destination16);
            expect(context.sourceRouteTable.get(destination16)?.[0]?.failureCount).toStrictEqual(1);
            expect(context.macNoACKs.get(destination16)).toStrictEqual(1);
        });

        it("triggers route repair after consecutive failures", async () => {
            const destination16 = 0x6b7d;
            const destination64 = 0x00124b00deaf7702n;
            registerNeighborDevice(context, destination16, destination64);

            const routeEntry = nwkHandler.createSourceRouteEntry([], 1);
            routeEntry.failureCount = 2; // CONFIG_NWK_ROUTE_MAX_FAILURES - 1
            context.sourceRouteTable.set(destination16, [routeEntry]);

            const sendMTORRSpy = vi.spyOn(nwkHandler, "sendPeriodicManyToOneRouteRequest").mockResolvedValue();
            vi.spyOn(nwkHandler, "markRouteFailure");
            mockMACHandlerCallbacks.onMarkRouteFailure = vi.fn((dest16: number) => {
                nwkHandler.markRouteFailure(dest16);
            });

            const macError = new Error("NO_ACK", { cause: NO_ACK_CODE });
            mockMACHandlerCallbacks.onSendFrame = vi.fn(() => Promise.reject(macError));

            const result = await nwkHandler.sendStatus(destination16, ZigbeeNWKStatus.LINK_FAILURE, destination16);

            expect(result).toStrictEqual(false);
            await new Promise((resolve) => setImmediate(resolve));

            expect(context.sourceRouteTable.has(destination16)).toStrictEqual(false);
            expect(sendMTORRSpy).toHaveBeenCalled();
        });

        it("recovers route state after successful retransmission", async () => {
            const destination16 = 0x6b7e;
            const destination64 = 0x00124b00deaf7703n;
            registerNeighborDevice(context, destination16, destination64);

            const routeEntry = nwkHandler.createSourceRouteEntry([], 1);
            context.sourceRouteTable.set(destination16, [routeEntry]);

            const markRouteFailureSpy = vi.spyOn(nwkHandler, "markRouteFailure");
            const markRouteSuccessSpy = vi.spyOn(nwkHandler, "markRouteSuccess");
            mockMACHandlerCallbacks.onMarkRouteFailure = vi.fn((dest16: number) => {
                nwkHandler.markRouteFailure(dest16);
            });
            mockMACHandlerCallbacks.onMarkRouteSuccess = vi.fn((dest16: number) => {
                nwkHandler.markRouteSuccess(dest16);
            });

            const macError = new Error("NO_ACK", { cause: NO_ACK_CODE });
            mockMACHandlerCallbacks.onSendFrame = vi.fn(() => Promise.reject(macError));

            const firstResult = await nwkHandler.sendStatus(destination16, ZigbeeNWKStatus.LINK_FAILURE, destination16);

            expect(firstResult).toStrictEqual(false);
            expect(markRouteFailureSpy).toHaveBeenCalledWith(destination16);
            expect(context.sourceRouteTable.get(destination16)?.[0]?.failureCount).toStrictEqual(1);

            mockMACHandlerCallbacks.onSendFrame = vi.fn(() => Promise.resolve());

            const secondResult = await nwkHandler.sendStatus(destination16, ZigbeeNWKStatus.LINK_FAILURE, destination16);

            expect(secondResult).toStrictEqual(true);
            expect(markRouteSuccessSpy).toHaveBeenCalledWith(destination16);
            expect(context.sourceRouteTable.get(destination16)?.[0]?.failureCount).toStrictEqual(0);
            expect(context.macNoACKs.has(destination16)).toStrictEqual(false);
        });

        it("retries APS transmissions when acknowledgments are missing", async () => {
            vi.useFakeTimers();

            try {
                const destination16 = 0x6b80;
                const destination64 = 0x00124b00deaf7704n;
                registerNeighborDevice(context, destination16, destination64);
                context.deviceTable.get(destination64)!.capabilities!.rxOnWhenIdle = true;

                const transmittedFrames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                    transmittedFrames.push(Buffer.from(payload));
                    return Promise.resolve();
                });

                await apsHandler.sendData(
                    Buffer.from([0xaa]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    destination16,
                    destination64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0104,
                    0x0104,
                    0x01,
                    0x01,
                    undefined,
                );

                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1);

                for (let attempt = 0; attempt < CONFIG_APS_MAX_FRAME_RETRIES; attempt++) {
                    await vi.advanceTimersByTimeAsync(CONFIG_APS_ACK_WAIT_DURATION_MS - 1);
                    await Promise.resolve();
                }

                await vi.advanceTimersByTimeAsync(CONFIG_APS_ACK_WAIT_DURATION_MS - 1);
                await Promise.resolve();

                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(CONFIG_APS_MAX_FRAME_RETRIES + 1);
                expect(transmittedFrames).toHaveLength(CONFIG_APS_MAX_FRAME_RETRIES + 1);
                expect(mockMACHandlerCallbacks.onMarkRouteFailure).not.toHaveBeenCalled();
            } finally {
                vi.useRealTimers();
            }
        });

        it("throws when processing malformed NWK status payloads lacking destination", async () => {
            const macHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x01,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x6b82,
                fcs: 0,
            } satisfies MACHeader;
            const nwkHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: false,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x6b82,
                radius: 5,
                seqNum: 0x10,
            } satisfies ZigbeeNWKHeader;
            const malformedPayload = Buffer.from([ZigbeeNWKStatus.LINK_FAILURE]);

            await expect(nwkHandler.processStatus(malformedPayload, 0, macHeader, nwkHeader)).rejects.toThrow(RangeError);
        });
    });
});
