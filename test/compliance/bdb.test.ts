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

import { existsSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
    encodeMACCapabilities,
    MACAssociationStatus,
    type MACCapabilities,
    MACCommandId,
    MACDisassociationReason,
    MACFrameAddressMode,
    MACFrameType,
    type MACHeader,
} from "../../src/zigbee/mac.js";
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeConsts, ZigbeeKeyType } from "../../src/zigbee/zigbee.js";
import { ZigbeeAPSConsts, ZigbeeAPSDeliveryMode, ZigbeeAPSFrameType, type ZigbeeAPSHeader } from "../../src/zigbee/zigbee-aps.js";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    ZigbeeNWKCommandId,
    ZigbeeNWKConsts,
    type ZigbeeNWKFrameControl,
    ZigbeeNWKFrameType,
    type ZigbeeNWKHeader,
    ZigbeeNWKRouteDiscovery,
    ZigbeeNWKStatus,
} from "../../src/zigbee/zigbee-nwk.js";
import { APSHandler, type APSHandlerCallbacks } from "../../src/zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../../src/zigbee-stack/nwk-gp-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import { type NetworkParameters, StackContext, type StackContextCallbacks } from "../../src/zigbee-stack/stack-context.js";
import { NETDEF_EXTENDED_PAN_ID, NETDEF_NETWORK_KEY, NETDEF_PAN_ID, NETDEF_TC_KEY } from "../data.js";
import { createMACFrameControl } from "../utils.js";
import { captureMacFrame, cloneNetworkParameters, decodeMACFramePayload, NO_ACK_CODE, TEST_DEVICE_EUI64 } from "./utils.js";

describe("Zigbee 3.0 Device Behavior Compliance", () => {
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
     * Base Device Behavior 16-02828-012 §5.1: Coordinator Behavior
     * Coordinator SHALL form network and manage PAN.
     */
    describe("Coordinator Behavior (BDB §5.1)", () => {
        it("forms network on first start", async () => {
            const freshDir = join(saveDir, "fresh_start");
            mkdirSync(freshDir, { recursive: true });
            const freshSave = join(freshDir, "zoh.save");

            expect(existsSync(freshSave)).toStrictEqual(false);

            const freshContext = new StackContext(mockStackContextCallbacks, freshSave, cloneNetworkParameters(netParams));

            await freshContext.loadState();

            expect(existsSync(freshSave)).toStrictEqual(true);
            expect(freshContext.netParams.panId).toStrictEqual(netParams.panId);
            expect(freshContext.deviceTable.size).toStrictEqual(0);

            freshContext.disallowJoins();
        });

        it("restores network from persistent storage", async () => {
            const baseParams = cloneNetworkParameters(netParams);
            context.allowJoins(60, true);

            const device64 = 0x00124b0000abcde1n;
            const capabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            };

            const [status, assignedAddress] = await context.associate(undefined, device64, true, capabilities, true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(assignedAddress).not.toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);

            const mutatedPanId = 0x7a7b;
            const mutatedChannel = 21;
            const mutatedUpdateId = 3;

            context.netParams.panId = mutatedPanId;
            context.netParams.channel = mutatedChannel;
            context.netParams.nwkUpdateId = mutatedUpdateId;

            await context.saveState();

            const placeholderParams = cloneNetworkParameters(baseParams);
            placeholderParams.panId = 0x1234;
            placeholderParams.channel = 13;
            placeholderParams.nwkUpdateId = 0;

            const restored = new StackContext(mockStackContextCallbacks, join(saveDir, "zoh.save"), placeholderParams);
            await restored.loadState();

            expect(restored.netParams.panId).toStrictEqual(mutatedPanId);
            expect(restored.netParams.channel).toStrictEqual(mutatedChannel);
            expect(restored.netParams.nwkUpdateId).toStrictEqual(mutatedUpdateId);
            expect(restored.deviceTable.has(device64)).toStrictEqual(true);
            expect(restored.address16ToAddress64.get(assignedAddress)).toStrictEqual(device64);

            restored.disallowJoins();
        });

        it("uses network address 0x0000 for coordinator transmissions", async () => {
            const disassocPayload = Buffer.from([MACDisassociationReason.COORDINATOR_INITIATED]);

            const decoded = await captureMacFrame(
                () => macHandler.sendCommand(MACCommandId.DISASSOC_NOTIFY, 0x7a6b, undefined, false, disassocPayload),
                mockMACHandlerCallbacks,
            );

            expect(decoded.frameControl.frameType).toStrictEqual(MACFrameType.CMD);
            expect(decoded.header.source16).toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);
        });

        it("sets PAN coordinator bit in beacons", async () => {
            const beaconReqHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x22,
                destinationPANId: context.netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: context.netParams.panId,
                source16: 0x1357,
                source64: TEST_DEVICE_EUI64,
                commandId: MACCommandId.BEACON_REQ,
                fcs: 0,
            };

            const decoded = await captureMacFrame(() => macHandler.processBeaconReq(Buffer.alloc(0), 0, beaconReqHeader), mockMACHandlerCallbacks);

            expect(decoded.frameControl.frameType).toStrictEqual(MACFrameType.BEACON);
            expect(decoded.header.superframeSpec?.panCoordinator).toStrictEqual(true);
        });

        it("permits association when join policy allows", async () => {
            context.allowJoins(60, true);

            const beaconReqHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x33,
                destinationPANId: context.netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: context.netParams.panId,
                source16: 0x2468,
                source64: TEST_DEVICE_EUI64,
                commandId: MACCommandId.BEACON_REQ,
                fcs: 0,
            };

            const decoded = await captureMacFrame(() => macHandler.processBeaconReq(Buffer.alloc(0), 0, beaconReqHeader), mockMACHandlerCallbacks);

            expect(context.trustCenterPolicies.allowJoins).toStrictEqual(true);
            expect(decoded.header.superframeSpec?.associationPermit).toStrictEqual(true);
        });

        it("assigns unique short addresses to joining devices", async () => {
            context.allowJoins(60, true);

            const capabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            };

            const deviceA = 0x00124b0000aaaaf1n;
            const deviceB = 0x00124b0000bbb0f2n;

            const [statusA, addressA] = await context.associate(undefined, deviceA, true, capabilities, true);
            const [statusB, addressB] = await context.associate(undefined, deviceB, true, capabilities, true);

            expect(statusA).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(statusB).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(addressA).not.toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);
            expect(addressB).not.toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);
            expect(addressA).not.toStrictEqual(addressB);
            expect(context.deviceTable.get(deviceA)?.address16).toStrictEqual(addressA);
            expect(context.deviceTable.get(deviceB)?.address16).toStrictEqual(addressB);
        });
    });

    /**
     * Base Device Behavior 16-02828-012 §5.2: Router Behavior
     * Router SHALL route frames and optionally permit joining.
     */
    describe("Router Behavior (BDB §5.2)", () => {
        it("joins network as a full-function device", async () => {
            context.allowJoins(60, true);

            const router64 = 0x00124b0000f0f0n;
            const capabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            };

            const [status, address16] = await context.associate(undefined, router64, true, capabilities, true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(address16).not.toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);

            const entry = context.deviceTable.get(router64);

            expect(entry).toBeDefined();
            expect(entry?.capabilities?.deviceType).toStrictEqual(1);
            expect(entry?.neighbor).toStrictEqual(true);
            expect(context.indirectTransmissions.has(router64)).toStrictEqual(false);
        });

        it("initiates route discovery when no path exists", async () => {
            vi.useFakeTimers();

            const router16 = 0x4455;
            const router64 = 0x00124b0000f1f2n;

            const sendCommandSpy = vi.spyOn(nwkHandler, "sendCommand");

            context.deviceTable.set(router64, {
                address16: router16,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 1,
                    powerSource: 1,
                    rxOnWhenIdle: true,
                    securityCapability: true,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: false,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(router16, router64);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await nwkHandler.sendStatus(router16, ZigbeeNWKStatus.LINK_FAILURE, router16);

            await vi.runAllTimersAsync();

            vi.useRealTimers();

            expect(frames.length).toBeGreaterThanOrEqual(2);

            const first = decodeMACFramePayload(frames[0]!);
            const [firstNwkFC, firstNwkOffset] = decodeZigbeeNWKFrameControl(first.buffer, first.payloadOffset);
            const [firstNwkHeader] = decodeZigbeeNWKHeader(first.buffer, firstNwkOffset, firstNwkFC);

            expect(firstNwkHeader.frameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.CMD);
            expect(firstNwkHeader.destination16).toStrictEqual(router16);
            expect(firstNwkHeader.seqNum).toBeDefined();

            const second = decodeMACFramePayload(frames[1]!);
            const [secondNwkFC, secondNwkOffset] = decodeZigbeeNWKFrameControl(second.buffer, second.payloadOffset);
            const [secondNwkHeader] = decodeZigbeeNWKHeader(second.buffer, secondNwkOffset, secondNwkFC);

            expect(secondNwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);

            const routeReqCall = sendCommandSpy.mock.calls.find(([cmdId]) => cmdId === ZigbeeNWKCommandId.ROUTE_REQ);

            expect(routeReqCall).toBeDefined();
            const routeReqPayload = routeReqCall![1] as Buffer;

            expect(routeReqPayload[0]).toStrictEqual(ZigbeeNWKCommandId.ROUTE_REQ);

            sendCommandSpy.mockRestore();
        });

        it("relays frames using stored source routes", async () => {
            const relay16 = 0x2233;
            const relay64 = 0x00124b0000f3f4n;
            const destination16 = 0x5566;
            const destination64 = 0x00124b0000f5f6n;

            context.deviceTable.set(relay64, {
                address16: relay16,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 1,
                    powerSource: 1,
                    rxOnWhenIdle: true,
                    securityCapability: true,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: true,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(relay16, relay64);

            context.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 0,
                    powerSource: 1,
                    rxOnWhenIdle: true,
                    securityCapability: true,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: false,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(destination16, destination64);

            context.sourceRouteTable.set(destination16, [
                {
                    relayAddresses: [relay16],
                    pathCost: 2,
                    lastUpdated: Date.now(),
                    failureCount: 0,
                    lastUsed: undefined,
                },
            ]);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const result = await nwkHandler.sendStatus(destination16, ZigbeeNWKStatus.LINK_FAILURE, destination16);

            expect(result).toStrictEqual(true);
            expect(frames).toHaveLength(1);

            const decoded = decodeMACFramePayload(frames[0]!);
            expect(decoded.header.destination16).toStrictEqual(relay16);

            const [nwkFC, nwkOffset] = decodeZigbeeNWKFrameControl(decoded.buffer, decoded.payloadOffset);
            const [nwkHeader] = decodeZigbeeNWKHeader(decoded.buffer, nwkOffset, nwkFC);

            expect(nwkHeader.destination16).toStrictEqual(destination16);
            expect(nwkHeader.relayAddresses).toStrictEqual([relay16]);
            expect(nwkHeader.relayIndex).toStrictEqual(0);
        });

        it("updates neighbor table from link status reports", () => {
            const router16 = 0x6677;
            const router64 = 0x00124b0000f7f8n;

            context.deviceTable.set(router64, {
                address16: router16,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 1,
                    powerSource: 1,
                    rxOnWhenIdle: true,
                    securityCapability: true,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: false,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(router16, router64);

            const payload = Buffer.alloc(1 + 2 + 1);
            let offset = 0;
            payload.writeUInt8(0x61, offset); // first frame, last frame, 1 entry
            offset += 1;
            payload.writeUInt16LE(ZigbeeConsts.COORDINATOR_ADDRESS, offset);
            offset += 2;
            payload.writeUInt8(0x11, offset); // incoming/outgoing cost = 1

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x10,
                destinationPANId: context.netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: context.netParams.panId,
                source16: router16,
                source64: router64,
                fcs: 0,
            };

            const nwkFC = {
                frameType: ZigbeeNWKFrameType.CMD,
                protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                multicast: false,
                security: false,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: true,
                endDeviceInitiator: false,
            } satisfies ZigbeeNWKFrameControl;
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: nwkFC,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: router16,
                radius: 2,
                seqNum: 0x20,
                source64: router64,
                relayIndex: undefined,
                relayAddresses: undefined,
                securityHeader: undefined,
            };

            nwkHandler.processLinkStatus(payload, 0, macHeader, nwkHeader);

            const entry = context.deviceTable.get(router64);
            expect(entry?.neighbor).toStrictEqual(true);
            const routeEntries = context.sourceRouteTable.get(router16);
            expect(routeEntries).toBeDefined();
            expect(routeEntries?.[0]?.relayAddresses).toStrictEqual([]);
            expect(routeEntries?.[0]?.pathCost).toStrictEqual(1);
        });

        it("sends link status frames periodically", async () => {
            vi.useFakeTimers();

            const neighbor16 = 0x7788;
            const neighbor64 = 0x00124b0000f9fan;

            const sendCommandSpy = vi.spyOn(nwkHandler, "sendCommand");

            context.deviceTable.set(neighbor64, {
                address16: neighbor16,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 1,
                    powerSource: 1,
                    rxOnWhenIdle: true,
                    securityCapability: true,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: true,
                recentLQAs: [250, 245, 240],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(neighbor16, neighbor64);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await nwkHandler.start();
            await vi.runOnlyPendingTimersAsync();

            nwkHandler.stop();
            vi.useRealTimers();

            expect(frames.length).toBeGreaterThan(0);

            const decoded = decodeMACFramePayload(frames[0]!);
            const [nwkFC, nwkOffset] = decodeZigbeeNWKFrameControl(decoded.buffer, decoded.payloadOffset);
            const [nwkHeader] = decodeZigbeeNWKHeader(decoded.buffer, nwkOffset, nwkFC);

            expect(nwkHeader.frameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.CMD);

            const linkStatusCall = sendCommandSpy.mock.calls.find(([cmdId]) => cmdId === ZigbeeNWKCommandId.LINK_STATUS);

            expect(linkStatusCall).toBeDefined();
            const linkStatusPayload = linkStatusCall![1] as Buffer;

            expect(linkStatusPayload[0]).toStrictEqual(ZigbeeNWKCommandId.LINK_STATUS);

            sendCommandSpy.mockRestore();
        });
    });

    /**
     * Base Device Behavior 16-02828-012 §5.3: End Device Behavior
     * End device SHALL join network and communicate through parent.
     */
    describe("End Device Behavior (BDB §5.3)", () => {
        function buildAssocHeader(device64: bigint, source16 = 0xfffe): MACHeader {
            return {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x52,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16,
                source64: device64,
                commandId: MACCommandId.ASSOC_REQ,
                fcs: 0,
            } satisfies MACHeader;
        }

        function buildDataRequestHeader(device64: bigint, source16: number): MACHeader {
            return {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x63,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16,
                source64: device64,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            } satisfies MACHeader;
        }

        async function requestAssociation(device64: bigint, capabilities: MACCapabilities, source16 = 0xfffe): Promise<number> {
            const capabilitiesByte = encodeMACCapabilities(capabilities);
            const assocHeader = buildAssocHeader(device64, source16);

            await macHandler.processAssocReq(Buffer.from([capabilitiesByte]), 0, assocHeader);

            const entry = context.deviceTable.get(device64);
            expect(entry).not.toBeUndefined();
            const pending = context.pendingAssociations.get(device64);
            expect(pending).not.toBeUndefined();

            return entry!.address16!;
        }

        function decodeQueuedNWKCommand(frame: Buffer) {
            const macDecoded = decodeMACFramePayload(frame);
            const macPayload = macDecoded.buffer.subarray(macDecoded.payloadOffset, macDecoded.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(
                macPayload,
                payloadOffset,
                context.netParams.networkKey,
                context.netParams.eui64,
                nwkFrameControl,
                nwkHeader,
            );

            return { nwkFrameControl, nwkHeader, payload: nwkPayload };
        }

        it("joins network as reduced-function device and prepares indirect queue", async () => {
            context.allowJoins(60, true);

            const device64 = 0x00124b0000aa11bcn;
            const rfdCapabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 0,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };

            const assigned16 = await requestAssociation(device64, rfdCapabilities);

            const entry = context.deviceTable.get(device64)!;

            expect(assigned16).not.toBeUndefined();
            expect(assigned16).not.toStrictEqual(0xffff);
            expect(entry.capabilities?.deviceType).toStrictEqual(0);
            expect(entry.capabilities?.rxOnWhenIdle).toStrictEqual(false);

            const indirectQueue = context.indirectTransmissions.get(device64);
            expect(indirectQueue).toStrictEqual([]);
        });

        it("joins network as full-function device without indirect queue", async () => {
            context.allowJoins(60, true);

            const device64 = 0x00124b0000aa22cdn;
            const ffdCapabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            };

            const assigned16 = await requestAssociation(device64, ffdCapabilities);

            const entry = context.deviceTable.get(device64)!;

            expect(assigned16).not.toBeUndefined();
            expect(entry.capabilities?.deviceType).toStrictEqual(1);
            expect(entry.capabilities?.rxOnWhenIdle).toStrictEqual(true);
            expect(context.indirectTransmissions.has(device64)).toStrictEqual(false);
        });

        it("serves association response when the sleepy end device polls the parent", async () => {
            context.allowJoins(60, true);

            const device64 = 0x00124b0000aa33den;
            const capabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 0,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };

            const assigned16 = await requestAssociation(device64, capabilities);

            const sendCommandSpy = vi.spyOn(macHandler, "sendCommand").mockResolvedValue(true);
            mockMACHandlerCallbacks.onAPSSendTransportKeyNWK = vi.fn().mockResolvedValue(undefined);

            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader(device64, assigned16));

            expect(sendCommandSpy).toHaveBeenCalledTimes(1);
            const [, , , , assocPayload] = sendCommandSpy.mock.calls[0]!;
            expect(assocPayload.readUInt16LE(0)).toStrictEqual(assigned16);
            expect(assocPayload.readUInt8(2)).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(context.pendingAssociations.has(device64)).toStrictEqual(false);

            sendCommandSpy.mockRestore();
        });

        it("delivers queued indirect transmissions when the end device polls", async () => {
            context.allowJoins(60, true);

            const device64 = 0x00124b0000aa44efn;
            const capabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 0,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };

            const assigned16 = await requestAssociation(device64, capabilities);

            context.pendingAssociations.delete(device64);
            context.indirectTransmissions.set(device64, []);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await nwkHandler.sendStatus(assigned16, ZigbeeNWKStatus.LINK_FAILURE, assigned16);

            expect(frames).toHaveLength(0);
            const queue = context.indirectTransmissions.get(device64);
            expect(queue).not.toBeUndefined();
            expect(queue?.length).toStrictEqual(1);

            await macHandler.processDataReq(Buffer.alloc(0), 0, buildDataRequestHeader(device64, assigned16));

            expect(frames).toHaveLength(1);
            const nwkDecoded = decodeQueuedNWKCommand(frames[0]!);
            expect(nwkDecoded.payload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.NWK_STATUS);
            expect(context.indirectTransmissions.get(device64)).toStrictEqual([]);
        });
    });

    /**
     * Base Device Behavior 16-02828-012 §6: Commissioning
     * Devices SHALL support defined commissioning methods.
     */
    describe("Commissioning (BDB §6)", () => {
        function buildCommissioningHeaders(device64: bigint, source16: number): { mac: MACHeader; nwk: ZigbeeNWKHeader } {
            const mac: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x2a,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: netParams.panId,
                source16,
                source64: device64,
                commandId: undefined,
                fcs: 0,
            };
            const nwk: ZigbeeNWKHeader = {
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
                source16,
                source64: device64,
                radius: 5,
                seqNum: 0x44,
            };

            return { mac, nwk };
        }

        function buildDataRequestHeader(device64: bigint, source16: number): MACHeader {
            return {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x2b,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                sourcePANId: netParams.panId,
                source16,
                source64: device64,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            } satisfies MACHeader;
        }

        function decodeNWKCommandPayload(frame: Buffer) {
            const macDecoded = decodeMACFramePayload(frame);
            const macPayload = macDecoded.buffer.subarray(macDecoded.payloadOffset, macDecoded.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const payload = macPayload.subarray(payloadOffset);

            return { macDecoded, nwkFrameControl, nwkHeader, payload };
        }

        it("assigns addresses and replies to commissioning requests", async () => {
            context.allowJoins(60, true);

            const device64 = 0x00124b00ccdd1101n;
            const device16 = 0x7aa1;
            const capabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 0,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };
            const { mac, nwk } = buildCommissioningHeaders(device64, device16);
            const payload = Buffer.from([ZigbeeNWKCommandId.COMMISSIONING_REQUEST, 0x00, encodeMACCapabilities(capabilities)]);
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((frame) => {
                frames.push(Buffer.from(frame));
                return Promise.resolve();
            });

            await nwkHandler.processCommand(payload, mac, nwk);

            expect(context.deviceTable.has(device64)).toStrictEqual(true);
            const entry = context.deviceTable.get(device64);
            expect(entry?.authorized).toStrictEqual(false);
            expect(entry?.capabilities?.deviceType).toStrictEqual(0);

            const pendingQueue = context.indirectTransmissions.get(device64);
            expect(pendingQueue?.length).toStrictEqual(1);

            const assigned16FromEntry = entry!.address16!;
            const dataReqHeader = buildDataRequestHeader(device64, assigned16FromEntry);
            await macHandler.processDataReq(Buffer.alloc(0), 0, dataReqHeader);

            expect(context.indirectTransmissions.get(device64)).toStrictEqual([]);

            expect(frames).toHaveLength(1);
            const decoded = decodeNWKCommandPayload(frames[0]!);
            expect(decoded.payload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.COMMISSIONING_RESPONSE);
            const assigned16 = decoded.payload.readUInt16LE(1);
            const status = decoded.payload.readUInt8(3);

            expect(assigned16).not.toStrictEqual(0xffff);
            expect(assigned16).toStrictEqual(assigned16FromEntry);
            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(context.address16ToAddress64.get(assigned16)).toStrictEqual(device64);
            expect(mockNWKHandlerCallbacks.onAPSSendTransportKeyNWK).toHaveBeenCalledWith(
                device16,
                context.netParams.networkKey,
                context.netParams.networkKeySequenceNumber,
                device64,
            );
        });

        it("steers joining devices by scheduling network key transport", async () => {
            context.allowJoins(60, true);

            const device64 = 0x00124b00ccdd2202n;
            const device16 = 0x7aa2;
            const capabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            };
            const { mac, nwk } = buildCommissioningHeaders(device64, device16);
            const payload = Buffer.from([ZigbeeNWKCommandId.COMMISSIONING_REQUEST, 0x00, encodeMACCapabilities(capabilities)]);

            const transportSpy = vi
                .spyOn(mockNWKHandlerCallbacks, "onAPSSendTransportKeyNWK")
                .mockImplementation(async (dest16, key, seqNum, dest64) => {
                    await apsHandler.sendTransportKeyNWK(dest16!, key, seqNum, dest64!);
                });
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((frame) => {
                frames.push(Buffer.from(frame));
                return Promise.resolve();
            });

            await nwkHandler.processCommand(payload, mac, nwk);

            expect(transportSpy).toHaveBeenCalledTimes(1);
            const transportArgs = transportSpy.mock.calls[0];
            expect(transportArgs).toStrictEqual([device16, context.netParams.networkKey, context.netParams.networkKeySequenceNumber, device64]);

            const transportFrame = frames.find((frame) => {
                try {
                    const decoded = decodeNWKCommandPayload(frame);
                    return decoded.nwkHeader.frameControl.frameType === ZigbeeNWKFrameType.DATA;
                } catch {
                    return false;
                }
            });

            expect(transportFrame).toBeDefined();

            transportSpy.mockRestore();
        });

        it("updates beacon association permit according to join duration", async () => {
            vi.useFakeTimers();
            try {
                context.allowJoins(2, true);

                const beaconReqHeader: MACHeader = {
                    frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                    sequenceNumber: 0x31,
                    destinationPANId: context.netParams.panId,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    sourcePANId: context.netParams.panId,
                    source16: 0x5566,
                    source64: TEST_DEVICE_EUI64,
                    commandId: MACCommandId.BEACON_REQ,
                    fcs: 0,
                };

                const permitted = await captureMacFrame(
                    () => macHandler.processBeaconReq(Buffer.alloc(0), 0, beaconReqHeader),
                    mockMACHandlerCallbacks,
                );

                expect(permitted.header.superframeSpec?.associationPermit).toStrictEqual(true);

                vi.advanceTimersByTime(2000);

                const denied = await captureMacFrame(() => macHandler.processBeaconReq(Buffer.alloc(0), 0, beaconReqHeader), mockMACHandlerCallbacks);

                expect(context.trustCenterPolicies.allowJoins).toStrictEqual(false);
                expect(denied.header.superframeSpec?.associationPermit).toStrictEqual(false);
            } finally {
                vi.useRealTimers();
            }
        });

        it("emits end device announce callbacks after join", async () => {
            vi.useFakeTimers();
            try {
                const device64 = 0x00124b00ccdd3303n;
                const device16 = 0x7aa3;
                const capabilitiesByte = encodeMACCapabilities({
                    alternatePANCoordinator: false,
                    deviceType: 0,
                    powerSource: 0,
                    rxOnWhenIdle: false,
                    securityCapability: true,
                    allocateAddress: true,
                });

                context.deviceTable.set(device64, {
                    address16: device16,
                    capabilities: undefined,
                    authorized: false,
                    neighbor: true,
                    recentLQAs: [],
                    incomingNWKFrameCounter: undefined,
                    endDeviceTimeout: undefined,
                });
                context.address16ToAddress64.set(device16, device64);

                const data = Buffer.alloc(1 + 2 + 8 + 1);
                let offset = 0;
                data.writeUInt8(0x11, offset);
                offset += 1;
                data.writeUInt16LE(device16, offset);
                offset += 2;
                data.writeBigUInt64LE(device64, offset);
                offset += 8;
                data.writeUInt8(capabilitiesByte, offset);

                const macHeader: MACHeader = {
                    frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                    sequenceNumber: 0x55,
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
                        security: false,
                        sourceRoute: false,
                        extendedDestination: false,
                        extendedSource: true,
                        endDeviceInitiator: false,
                    },
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    source16: device16,
                    source64: device64,
                    radius: 5,
                    seqNum: 0x66,
                };
                const apsHeader: ZigbeeAPSHeader = {
                    frameControl: {
                        frameType: ZigbeeAPSFrameType.DATA,
                        deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                        ackFormat: false,
                        security: false,
                        ackRequest: false,
                        extendedHeader: false,
                    },
                    profileId: ZigbeeConsts.ZDO_PROFILE_ID,
                    clusterId: ZigbeeConsts.END_DEVICE_ANNOUNCE,
                    sourceEndpoint: 0x00,
                    destEndpoint: 0x00,
                    counter: 0x21,
                };

                await apsHandler.onZigbeeAPSFrame(data, macHeader, nwkHeader, apsHeader, 140);
                await vi.runAllTimersAsync();

                expect(mockAPSHandlerCallbacks.onDeviceJoined).toHaveBeenCalledWith(device16, device64, {
                    alternatePANCoordinator: false,
                    deviceType: 0,
                    powerSource: 0,
                    rxOnWhenIdle: false,
                    securityCapability: true,
                    allocateAddress: true,
                });
                expect(context.deviceTable.get(device64)?.capabilities?.deviceType).toStrictEqual(0);
            } finally {
                vi.useRealTimers();
            }
        });

        it("authorizes devices after successful confirm key transmission", async () => {
            vi.useFakeTimers();
            try {
                const device64 = 0x00124b00ccdd4404n;
                const device16 = 0x7aa4;

                context.deviceTable.set(device64, {
                    address16: device16,
                    capabilities: {
                        alternatePANCoordinator: false,
                        deviceType: 1,
                        powerSource: 1,
                        rxOnWhenIdle: true,
                        securityCapability: true,
                        allocateAddress: true,
                    },
                    authorized: false,
                    neighbor: true,
                    recentLQAs: [],
                    incomingNWKFrameCounter: undefined,
                    endDeviceTimeout: undefined,
                });
                context.address16ToAddress64.set(device16, device64);

                mockMACHandlerCallbacks.onSendFrame = vi.fn(() => Promise.resolve());

                await apsHandler.sendConfirmKey(device16, 0x00, ZigbeeAPSConsts.CMD_KEY_TC_LINK, device64);
                await vi.runAllTimersAsync();

                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1);
                expect(context.deviceTable.get(device64)?.authorized).toStrictEqual(true);
                expect(mockAPSHandlerCallbacks.onDeviceAuthorized).toHaveBeenCalledWith(device16, device64);
            } finally {
                vi.useRealTimers();
            }
        });
    });

    /**
     * Base Device Behavior 16-02828-012 §8: Finding and Binding
     * Devices MAY support finding and binding for commissioning.
     */
    describe.skip("Finding and Binding (BDB §8)", () => {
        // TODO: Test identify mode for finding and binding
        // TODO: Test binding table creation
        // TODO: Test simple descriptor matching
    });
});
