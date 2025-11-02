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
import { encodeMACFrameZigbee, MACFrameAddressMode, MACFrameType, type MACHeader, ZigbeeMACConsts } from "../../src/zigbee/mac.js";
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeConsts, ZigbeeKeyType, ZigbeeSecurityLevel } from "../../src/zigbee/zigbee.js";
import {
    decodeZigbeeAPSFrameControl,
    decodeZigbeeAPSHeader,
    decodeZigbeeAPSPayload,
    encodeZigbeeAPSFrame,
    ZigbeeAPSCommandId,
    ZigbeeAPSConsts,
    ZigbeeAPSDeliveryMode,
    ZigbeeAPSFragmentation,
    ZigbeeAPSFrameType,
    type ZigbeeAPSHeader,
} from "../../src/zigbee/zigbee-aps.js";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    encodeZigbeeNWKFrame,
    ZigbeeNWKCommandId,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    type ZigbeeNWKHeader,
    ZigbeeNWKRouteDiscovery,
} from "../../src/zigbee/zigbee-nwk.js";
import { APSHandler, type APSHandlerCallbacks } from "../../src/zigbee-stack/aps-handler.js";
import { processFrame } from "../../src/zigbee-stack/frame.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../../src/zigbee-stack/nwk-gp-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import {
    ApplicationKeyRequestPolicy,
    type NetworkParameters,
    StackContext,
    type StackContextCallbacks,
} from "../../src/zigbee-stack/stack-context.js";
import { NETDEF_EXTENDED_PAN_ID, NETDEF_NETWORK_KEY, NETDEF_PAN_ID, NETDEF_TC_KEY } from "../data.js";
import { createMACFrameControl } from "../utils.js";
import { captureMacFrame, type DecodedMACFrame, decodeMACFramePayload, NO_ACK_CODE, registerNeighborDevice } from "./utils.js";

describe("Zigbee 3.0 Application Support (APS) Layer Compliance", () => {
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

    function decodeAPSFrame(frame: DecodedMACFrame) {
        const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
        const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
        const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
        const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsPayloadOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader);

        return { nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload, nwkPayload };
    }

    /**
     * Zigbee Spec 05-3474-23 §2.2.5: APS Frame Format
     * The APS frame SHALL consist of a frame control field, addressing fields,
     * and frame payload.
     */
    describe("APS Frame Format (Zigbee §2.2.5)", () => {
        const unicastDest16 = 0x2222;
        const unicastDest64 = 0x00124b00aaccef01n;
        const groupId = 0x1234;

        beforeEach(() => {
            registerNeighborDevice(context, unicastDest16, unicastDest64);
        });

        it("encodes unicast data frames with ACK request and endpoint addressing", async () => {
            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xaa, 0xbb]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        unicastDest16,
                        unicastDest64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        0x0b,
                        0x01,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );

            const { apsFrameControl, apsHeader } = decodeAPSFrame(frame);

            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.DATA);
            expect(apsFrameControl.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.UNICAST);
            expect(apsFrameControl.ackFormat).toStrictEqual(false);
            expect(apsFrameControl.security).toStrictEqual(false);
            expect(apsFrameControl.ackRequest).toStrictEqual(true);
            expect(apsFrameControl.extendedHeader).toStrictEqual(false);

            expect(apsHeader.destEndpoint).toStrictEqual(0x0b);
            expect(apsHeader.sourceEndpoint).toStrictEqual(0x01);
            expect(apsHeader.clusterId).toStrictEqual(0x0104);
            expect(apsHeader.profileId).toStrictEqual(0x0104);
        });

        it("suppresses MAC-level acknowledgments for broadcast data frames while APS ACK flag remains set", async () => {
            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xcc]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        ZigbeeConsts.BCAST_DEFAULT,
                        undefined,
                        ZigbeeAPSDeliveryMode.BCAST,
                        0x0006,
                        0x0104,
                        0x0c,
                        0x01,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );

            const { apsFrameControl, apsHeader, nwkHeader } = decodeAPSFrame(frame);

            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.DATA);
            expect(apsFrameControl.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.BCAST);
            expect(apsFrameControl.ackRequest).toStrictEqual(true);
            expect(apsHeader.destEndpoint).toStrictEqual(0x0c);
            expect(nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(frame.frameControl.ackRequest).toStrictEqual(false);
        });

        it("encodes group addressed frames using group delivery mode", async () => {
            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0x33, 0x44]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        ZigbeeConsts.BCAST_RX_ON_WHEN_IDLE,
                        undefined,
                        ZigbeeAPSDeliveryMode.GROUP,
                        0x0104,
                        0x0104,
                        undefined,
                        0x0d,
                        groupId,
                    ),
                mockMACHandlerCallbacks,
            );

            const { apsFrameControl, apsHeader } = decodeAPSFrame(frame);

            expect(apsFrameControl.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.GROUP);
            expect(apsHeader.group).toStrictEqual(groupId);
            expect(apsHeader.destEndpoint).toBeUndefined();
            expect(apsHeader.sourceEndpoint).toStrictEqual(0x0d);
        });

        it("sets the security bit for APS commands requiring encryption", async () => {
            const child16 = 0x2345;
            const child64 = 0x00124b00dcba0001n;
            registerNeighborDevice(context, child16, child64);

            const frame = await captureMacFrame(
                () => apsHandler.sendTransportKeyNWK(child16, Buffer.from("112233445566778899aabbccddeeff00", "hex"), 0x12, child64),
                mockMACHandlerCallbacks,
            );

            const { apsFrameControl, apsHeader, apsPayload } = decodeAPSFrame(frame);

            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(apsFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.ackRequest).toStrictEqual(false);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(apsHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.TRANSPORT);
        });

        it("clears the extended header flag when fragmentation is not used", async () => {
            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0x99]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        unicastDest16,
                        unicastDest64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0006,
                        ZigbeeConsts.HA_PROFILE_ID,
                        0x22,
                        ZigbeeConsts.HA_ENDPOINT,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );

            const { apsFrameControl, apsHeader } = decodeAPSFrame(frame);

            expect(apsFrameControl.extendedHeader).toStrictEqual(false);
            expect(apsHeader.fragmentation).toBeUndefined();
            expect(apsHeader.fragBlockNumber).toBeUndefined();
        });

        it("encodes fragmentation extended header fields when requested", () => {
            const header: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: true,
                },
                destEndpoint: 0x11,
                clusterId: 0x1000,
                profileId: ZigbeeConsts.HA_PROFILE_ID,
                sourceEndpoint: ZigbeeConsts.HA_ENDPOINT,
                counter: 0x42,
                fragmentation: ZigbeeAPSFragmentation.FIRST,
                fragBlockNumber: 0x01,
            };
            const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
            const encoded = encodeZigbeeAPSFrame(header, payload);

            const [decodedFrameControl] = decodeZigbeeAPSFrameControl(encoded, 0);
            expect(decodedFrameControl.extendedHeader).toStrictEqual(true);

            // FCF (1) + dest endpoint (1) + cluster (2) + profile (2) + source endpoint (1) + counter (1)
            const extendedHeaderOffset = 8;
            const fragmentControl = encoded.readUInt8(extendedHeaderOffset);
            const blockNumber = encoded.readUInt8(extendedHeaderOffset + 1);

            expect(fragmentControl & ZigbeeAPSConsts.EXT_FCF_FRAGMENT).toStrictEqual(ZigbeeAPSFragmentation.FIRST);
            expect(blockNumber).toStrictEqual(0x01);
            expect(encoded.subarray(extendedHeaderOffset + 2)).toStrictEqual(payload);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §2.2.5.1.4: APS Counter
     * The APS counter SHALL be an 8-bit value incremented for each transmission.
     */
    describe("APS Counter (Zigbee §2.2.5.1.4)", () => {
        const neighbor16 = 0x2a2a;
        const neighbor64 = 0x00124b00abcddc01n;

        beforeEach(() => {
            registerNeighborDevice(context, neighbor16, neighbor64);
        });

        it("increments for every transmitted APS data frame", async () => {
            let firstCounter = -1;
            let secondCounter = -1;

            const firstFrame = await captureMacFrame(async () => {
                firstCounter = await apsHandler.sendData(
                    Buffer.from([0x55]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    neighbor16,
                    neighbor64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0006,
                    0x0104,
                    0x12,
                    0x01,
                    undefined,
                );
            }, mockMACHandlerCallbacks);
            const secondFrame = await captureMacFrame(async () => {
                secondCounter = await apsHandler.sendData(
                    Buffer.from([0x66]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    neighbor16,
                    neighbor64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0006,
                    0x0104,
                    0x12,
                    0x01,
                    undefined,
                );
            }, mockMACHandlerCallbacks);

            const firstDecoded = decodeAPSFrame(firstFrame);
            const secondDecoded = decodeAPSFrame(secondFrame);

            expect(firstCounter).toStrictEqual(firstDecoded.apsHeader.counter);
            expect(secondCounter).toStrictEqual(secondDecoded.apsHeader.counter);
            expect(secondCounter).toStrictEqual((firstCounter + 1) & 0xff);
        });

        it("wraps from 0xff to 0 after reaching the maximum counter value", async () => {
            for (let i = 0; i < 0xff; i += 1) {
                apsHandler.nextCounter();
            }

            let wrappedCounter = -1;
            let postWrapCounter = -1;

            const wrappedFrame = await captureMacFrame(async () => {
                wrappedCounter = await apsHandler.sendData(
                    Buffer.from([0x99]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    neighbor16,
                    neighbor64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0006,
                    0x0104,
                    0x34,
                    0x01,
                    undefined,
                );
            }, mockMACHandlerCallbacks);
            const postWrapFrame = await captureMacFrame(async () => {
                postWrapCounter = await apsHandler.sendData(
                    Buffer.from([0xaa]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    neighbor16,
                    neighbor64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0006,
                    0x0104,
                    0x34,
                    0x01,
                    undefined,
                );
            }, mockMACHandlerCallbacks);

            const wrappedDecoded = decodeAPSFrame(wrappedFrame);
            const postWrapDecoded = decodeAPSFrame(postWrapFrame);

            expect(wrappedCounter).toStrictEqual(0x00);
            expect(postWrapCounter).toStrictEqual(0x01);
            expect(wrappedDecoded.apsHeader.counter).toStrictEqual(0x00);
            expect(postWrapDecoded.apsHeader.counter).toStrictEqual(0x01);
        });

        it("avoids reusing counter values across consecutive transmissions", async () => {
            const observedCounters = new Set<number>();

            for (let i = 0; i < 4; i += 1) {
                await captureMacFrame(async () => {
                    const counter = await apsHandler.sendData(
                        Buffer.from([0x10 + i]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        neighbor16,
                        neighbor64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0006,
                        0x0104,
                        0x15,
                        0x01,
                        undefined,
                    );
                    expect(observedCounters.has(counter)).toStrictEqual(false);
                    observedCounters.add(counter);
                }, mockMACHandlerCallbacks);
            }

            expect(observedCounters.size).toStrictEqual(4);
        });

        it("uses APS counters to drop duplicate incoming data", async () => {
            const device16 = 0x2b2b;
            const device64 = 0x00124b00abcddc02n;
            registerNeighborDevice(context, device16, device64);

            const apsFrameControl = {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            } as const;
            const baseHeader: ZigbeeAPSHeader = {
                frameControl: apsFrameControl,
                destEndpoint: 0x18,
                clusterId: 0x0006,
                profileId: ZigbeeConsts.HA_PROFILE_ID,
                sourceEndpoint: 0x10,
                counter: 0x5a,
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
                seqNum: 0x42,
            };
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x90,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
                sourcePANId: netParams.panId,
                source64: device64,
                commandId: undefined,
                fcs: 0,
            };
            const payload = Buffer.from([0x01, 0x03, 0x05]);

            const buildFrame = (apsHeader: ZigbeeAPSHeader): Buffer => {
                const apsPayload = encodeZigbeeAPSFrame(apsHeader, payload);
                const nwkPayload = encodeZigbeeNWKFrame(nwkHeader, apsPayload);
                return encodeMACFrameZigbee(macHeader, nwkPayload);
            };

            const frame = buildFrame(baseHeader);
            await processFrame(frame, context, macHandler, nwkHandler, nwkGPHandler, apsHandler, 0x5a);
            await new Promise((resolve) => setImmediate(resolve));
            expect(mockAPSHandlerCallbacks.onFrame).toHaveBeenCalledTimes(1);

            const duplicateFrame = buildFrame({ ...baseHeader });
            await processFrame(duplicateFrame, context, macHandler, nwkHandler, nwkGPHandler, apsHandler, 0x5a);
            await new Promise((resolve) => setImmediate(resolve));
            expect(mockAPSHandlerCallbacks.onFrame).toHaveBeenCalledTimes(1);

            const newCounterHeader: ZigbeeAPSHeader = { ...baseHeader, counter: (baseHeader.counter! + 1) & 0xff };
            const newFrame = buildFrame(newCounterHeader);
            await processFrame(newFrame, context, macHandler, nwkHandler, nwkGPHandler, apsHandler, 0x5a);
            await new Promise((resolve) => setImmediate(resolve));
            expect(mockAPSHandlerCallbacks.onFrame).toHaveBeenCalledTimes(2);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §2.2.6: APS Addressing
     * APS addressing SHALL use endpoint, cluster, and profile identifiers.
     */
    describe("APS Addressing (Zigbee §2.2.6)", () => {
        const neighbor16 = 0x3344;
        const neighbor64 = 0x00124b00bbccddeen;

        beforeEach(() => {
            registerNeighborDevice(context, neighbor16, neighbor64);
        });

        it("encodes boundary application endpoints and little-endian identifiers for Home Automation traffic", async () => {
            const payload = Buffer.from([0xab, 0xcd, 0xef]);
            const clusterId = 0x4567;

            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        payload,
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        neighbor16,
                        neighbor64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        clusterId,
                        ZigbeeConsts.HA_PROFILE_ID,
                        0xfe,
                        0xf0,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );

            const { apsHeader, nwkPayload, apsPayload } = decodeAPSFrame(frame);

            expect(apsHeader.destEndpoint).toStrictEqual(0xfe);
            expect(apsHeader.sourceEndpoint).toStrictEqual(0xf0);
            expect(apsHeader.profileId).toStrictEqual(ZigbeeConsts.HA_PROFILE_ID);
            expect(apsHeader.clusterId).toStrictEqual(clusterId);
            expect(apsPayload.equals(payload)).toStrictEqual(true);

            const clusterOffset = 2; // [0]=FCF, [1]=dest endpoint
            expect(nwkPayload[clusterOffset]).toStrictEqual(0x67); // LSB of 0x4567
            expect(nwkPayload[clusterOffset + 1]).toStrictEqual(0x45); // MSB of 0x4567
            expect(nwkPayload.readUInt16LE(clusterOffset)).toStrictEqual(clusterId);

            const profileOffset = clusterOffset + 2;
            expect(nwkPayload[profileOffset]).toStrictEqual(0x04); // LSB of 0x0104
            expect(nwkPayload[profileOffset + 1]).toStrictEqual(0x01);
            expect(nwkPayload.readUInt16LE(profileOffset)).toStrictEqual(ZigbeeConsts.HA_PROFILE_ID);
        });

        it("responds to coordinator ZDO requests on endpoint 0 and advertises the Green Power endpoint", async () => {
            const requestTsn = 0x39;
            const request = Buffer.from([requestTsn, ZigbeeConsts.COORDINATOR_ADDRESS & 0xff, ZigbeeConsts.COORDINATOR_ADDRESS >> 8]);
            const zdoRequester16 = 0x5566;
            const zdoRequester64 = 0x00124b00aa55aa66n;
            registerNeighborDevice(context, zdoRequester16, zdoRequester64);

            const frame = await captureMacFrame(
                () => apsHandler.respondToCoordinatorZDORequest(request, ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST, zdoRequester16, zdoRequester64),
                mockMACHandlerCallbacks,
            );

            const { apsHeader, apsPayload } = decodeAPSFrame(frame);

            expect(apsHeader.destEndpoint).toStrictEqual(ZigbeeConsts.ZDO_ENDPOINT);
            expect(apsHeader.sourceEndpoint).toStrictEqual(ZigbeeConsts.ZDO_ENDPOINT);
            expect(apsHeader.profileId).toStrictEqual(ZigbeeConsts.ZDO_PROFILE_ID);
            expect(apsHeader.clusterId).toStrictEqual(ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST | 0x8000);

            expect(apsPayload[0]).toStrictEqual(requestTsn);
            const endpointCount = apsPayload[4];
            expect(endpointCount).toStrictEqual(2);
            expect(apsPayload.slice(5, 5 + endpointCount)).toStrictEqual(Buffer.from([ZigbeeConsts.HA_ENDPOINT, ZigbeeConsts.GP_ENDPOINT]));
        });

        it("encodes the broadcast endpoint 0xff when sending network-wide transmissions", async () => {
            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0x42]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        ZigbeeConsts.BCAST_DEFAULT,
                        undefined,
                        ZigbeeAPSDeliveryMode.BCAST,
                        0x0006,
                        ZigbeeConsts.HA_PROFILE_ID,
                        0xff,
                        ZigbeeConsts.HA_ENDPOINT,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );

            const { apsFrameControl, apsHeader, nwkHeader } = decodeAPSFrame(frame);

            expect(apsFrameControl.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.BCAST);
            expect(apsHeader.destEndpoint).toStrictEqual(0xff);
            expect(apsHeader.sourceEndpoint).toStrictEqual(ZigbeeConsts.HA_ENDPOINT);
            expect(nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(frame.frameControl.ackRequest).toStrictEqual(false);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §2.2.8: APS Data Service
     * APS data frames SHALL transport application payloads between endpoints.
     */
    describe("APS Data Service (Zigbee §2.2.8)", () => {
        const unicastDest16 = 0x7788;
        const unicastDest64 = 0x00124b00ddccbb11n;
        const groupId = 0x2345;

        beforeEach(() => {
            registerNeighborDevice(context, unicastDest16, unicastDest64);
        });

        it("transports the application payload and addressing metadata for unicast exchanges", async () => {
            const payload = Buffer.from([0x01, 0x02, 0x03, 0x04]);

            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        payload,
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        unicastDest16,
                        unicastDest64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0500,
                        ZigbeeConsts.HA_PROFILE_ID,
                        0x12,
                        ZigbeeConsts.HA_ENDPOINT,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );

            const { apsFrameControl, apsHeader, apsPayload } = decodeAPSFrame(frame);

            expect(apsFrameControl.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.UNICAST);
            expect(apsHeader.destEndpoint).toStrictEqual(0x12);
            expect(apsHeader.sourceEndpoint).toStrictEqual(ZigbeeConsts.HA_ENDPOINT);
            expect(apsHeader.clusterId).toStrictEqual(0x0500);
            expect(apsHeader.profileId).toStrictEqual(ZigbeeConsts.HA_PROFILE_ID);
            expect(apsPayload.equals(payload)).toStrictEqual(true);
        });

        it("uses APS broadcast delivery mode and Zigbee broadcast addressing for network-wide data", async () => {
            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xaa, 0xbb]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        ZigbeeConsts.BCAST_SLEEPY,
                        undefined,
                        ZigbeeAPSDeliveryMode.BCAST,
                        0x0019,
                        ZigbeeConsts.HA_PROFILE_ID,
                        0xff,
                        ZigbeeConsts.HA_ENDPOINT,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );

            const { apsFrameControl, apsHeader, nwkHeader } = decodeAPSFrame(frame);

            expect(apsFrameControl.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.BCAST);
            expect(apsHeader.destEndpoint).toStrictEqual(0xff);
            expect(nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_SLEEPY);
            expect(frame.frameControl.ackRequest).toStrictEqual(false);
        });

        it("encodes group delivery mode with group addressing semantics", async () => {
            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0x10, 0x20]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        ZigbeeConsts.BCAST_RX_ON_WHEN_IDLE,
                        undefined,
                        ZigbeeAPSDeliveryMode.GROUP,
                        0x0006,
                        ZigbeeConsts.HA_PROFILE_ID,
                        undefined,
                        ZigbeeConsts.HA_ENDPOINT,
                        groupId,
                    ),
                mockMACHandlerCallbacks,
            );

            const { apsFrameControl, apsHeader, nwkHeader } = decodeAPSFrame(frame);

            expect(apsFrameControl.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.GROUP);
            expect(apsHeader.destEndpoint).toBeUndefined();
            expect(apsHeader.group).toStrictEqual(groupId);
            expect(nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_RX_ON_WHEN_IDLE);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §2.2.9: APS Acknowledgment
     * APS acknowledgments SHALL be sent when requested to confirm delivery.
     */
    describe("APS Acknowledgment (Zigbee §2.2.9)", () => {
        it("encodes APS acknowledgments with matching addressing and counter", async () => {
            const device16 = 0x3456;
            const device64 = 0x00124b00eeff0001n;
            registerNeighborDevice(context, device16, device64);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x7a,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
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
                seqNum: 0x55,
            };
            const apsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: true,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint: 0x11,
                clusterId: 0x1234,
                profileId: 0x0104,
                sourceEndpoint: 0x22,
                counter: 0x33,
            };

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await apsHandler.sendACK(macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const decoded = decodeMACFramePayload(frames[0]!);
            expect(decoded.header.destination16).toStrictEqual(device16);

            const { apsFrameControl, apsHeader: ackHeader } = decodeAPSFrame(decoded);

            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.ACK);
            expect(apsFrameControl.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.UNICAST);
            expect(apsFrameControl.ackFormat).toStrictEqual(false);
            expect(apsFrameControl.security).toStrictEqual(false);
            expect(apsFrameControl.ackRequest).toStrictEqual(false);
            expect(ackHeader.destEndpoint).toStrictEqual(0x22);
            expect(ackHeader.sourceEndpoint).toStrictEqual(0x11);
            expect(ackHeader.clusterId).toStrictEqual(0x1234);
            expect(ackHeader.profileId).toStrictEqual(0x0104);
            expect(ackHeader.counter).toStrictEqual(0x33);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("sends APS acknowledgments immediately, satisfying apsAckWaitDuration", async () => {
            const device16 = 0x4567;
            const device64 = 0x00124b00eeff0002n;
            registerNeighborDevice(context, device16, device64);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x81,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
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
                seqNum: 0x66,
            };
            const apsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: true,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint: 0x10,
                clusterId: 0x2233,
                profileId: 0x0104,
                sourceEndpoint: 0x20,
                counter: 0x44,
            };

            vi.useFakeTimers();
            try {
                vi.setSystemTime(2_000_000);
                let ackTimestamp: number | undefined;

                mockMACHandlerCallbacks.onSendFrame = vi.fn(() => {
                    ackTimestamp = Date.now();
                    return Promise.resolve();
                });

                await apsHandler.sendACK(macHeader, nwkHeader, apsHeader);

                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1);
                expect(ackTimestamp).toStrictEqual(2_000_000);
            } finally {
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
                vi.useRealTimers();
            }
        });

        it("retransmits APS data when ACK is not received up to apsMaxFrameRetries", async () => {
            vi.useFakeTimers();

            try {
                const device16 = 0x4a5b;
                const device64 = 0x00124b00eeff0003n;
                registerNeighborDevice(context, device16, device64);
                context.deviceTable.get(device64)!.capabilities!.rxOnWhenIdle = true;

                const sentFrames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                    sentFrames.push(Buffer.from(payload));

                    return Promise.resolve();
                });

                const apsCounter = await apsHandler.sendData(
                    Buffer.from([0xde, 0xad]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    device16,
                    device64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0101,
                    ZigbeeConsts.HA_PROFILE_ID,
                    0x15,
                    0x23,
                    undefined,
                );

                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1);

                for (let attempt = 1; attempt <= 3; attempt += 1) {
                    await vi.runOnlyPendingTimersAsync();
                    expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1 + attempt);
                }

                await vi.runOnlyPendingTimersAsync();

                const ackMacHeader: MACHeader = {
                    frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                    sequenceNumber: 0x92,
                    destinationPANId: netParams.panId,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    source16: device16,
                    commandId: undefined,
                    fcs: 0,
                };
                const ackNwkHeader: ZigbeeNWKHeader = {
                    frameControl: {
                        frameType: ZigbeeNWKFrameType.DATA,
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
                    source16: device16,
                    source64: device64,
                    radius: 5,
                    seqNum: 0x71,
                };
                const ackAPSHeader: ZigbeeAPSHeader = {
                    frameControl: {
                        frameType: ZigbeeAPSFrameType.ACK,
                        deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                        ackFormat: false,
                        security: false,
                        ackRequest: false,
                        extendedHeader: false,
                    },
                    destEndpoint: 0x23,
                    clusterId: 0x0101,
                    profileId: ZigbeeConsts.HA_PROFILE_ID,
                    sourceEndpoint: 0x15,
                    counter: apsCounter,
                };

                await apsHandler.processFrame(Buffer.alloc(0), ackMacHeader, ackNwkHeader, ackAPSHeader, 0x70);

                await vi.runOnlyPendingTimersAsync();

                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(4);
                expect(sentFrames).toHaveLength(4);
            } finally {
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
                vi.useRealTimers();
            }
        });
        it("stops retransmissions once apsMaxFrameRetries is reached", async () => {
            vi.useFakeTimers();

            try {
                const device16 = 0x4a5c;
                const device64 = 0x00124b00eeff0004n;
                registerNeighborDevice(context, device16, device64);
                context.deviceTable.get(device64)!.capabilities!.rxOnWhenIdle = true;

                const sentFrames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                    sentFrames.push(Buffer.from(payload));

                    return Promise.resolve();
                });

                await apsHandler.sendData(
                    Buffer.from([0xba, 0xdc]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    device16,
                    device64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0202,
                    ZigbeeConsts.HA_PROFILE_ID,
                    0x26,
                    0x33,
                    undefined,
                );

                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1);

                for (let attempt = 1; attempt <= 3; attempt += 1) {
                    await vi.runOnlyPendingTimersAsync();
                    expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(1 + attempt);
                }

                await vi.runOnlyPendingTimersAsync();
                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(4);

                await vi.advanceTimersByTimeAsync(60000);
                expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalledTimes(4);
                expect(sentFrames).toHaveLength(4);
            } finally {
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
                vi.useRealTimers();
            }
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.4.3: APS Transport Key Command
     * Transport key command SHALL be used to distribute security keys.
     */
    describe("APS Transport Key Command (Zigbee §4.4.3)", () => {
        const child16 = 0x5c5d;
        const child64 = 0x00124b00ddddeee1n;

        beforeEach(() => {
            registerNeighborDevice(context, child16, child64);
        });

        it("encodes standard network key transport with mandatory fields", async () => {
            const networkKey = Buffer.from("00112233445566778899aabbccddeeff", "hex");
            const sequenceNumber = 7;

            const frame = await captureMacFrame(
                () => apsHandler.sendTransportKeyNWK(child16, networkKey, sequenceNumber, child64),
                mockMACHandlerCallbacks,
            );
            const { nwkFrameControl, apsFrameControl, apsHeader, apsPayload } = decodeAPSFrame(frame);

            expect(nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.DATA);
            expect(nwkFrameControl.security).toStrictEqual(false);

            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(apsFrameControl.deliveryMode).toStrictEqual(ZigbeeAPSDeliveryMode.UNICAST);
            expect(apsFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.ackRequest).toStrictEqual(false);

            expect(apsHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.TRANSPORT);
            expect(apsHeader.securityHeader?.control.level).toStrictEqual(ZigbeeSecurityLevel.ENC_MIC32);
            expect(apsHeader.securityHeader?.micLen).toStrictEqual(4);

            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK);
            expect(apsPayload.length).toStrictEqual(1 + 1 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 1 + 8 + 8);

            const keyOffset = 2;
            const seqOffset = keyOffset + ZigbeeAPSConsts.CMD_KEY_LENGTH;
            const destOffset = seqOffset + 1;
            const sourceOffset = destOffset + 8;

            expect(apsPayload.subarray(keyOffset, seqOffset)).toStrictEqual(networkKey);
            expect(apsPayload.readUInt8(seqOffset)).toStrictEqual(sequenceNumber);
            expect(apsPayload.readBigUInt64LE(destOffset)).toStrictEqual(child64);
            expect(apsPayload.readBigUInt64LE(sourceOffset)).toStrictEqual(context.netParams.eui64);

            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(1);
            expect(apsHeader.securityHeader?.frameCounter).toStrictEqual(context.netParams.tcKeyFrameCounter);
        });

        it("applies NWK and APS security when transporting trust center link keys", async () => {
            const linkKey = Buffer.from("f0e1d2c3b4a5968778695a4b3c2d1e0f", "hex");

            const frame = await captureMacFrame(() => apsHandler.sendTransportKeyTC(child16, linkKey, child64), mockMACHandlerCallbacks);
            const { nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload } = decodeAPSFrame(frame);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(nwkHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.NWK);
            expect(nwkHeader.securityHeader?.frameCounter).toStrictEqual(context.netParams.networkKeyFrameCounter);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(1);

            expect(apsFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.ackRequest).toStrictEqual(true);
            expect(apsHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.LOAD);
            expect(apsHeader.securityHeader?.control.level).toStrictEqual(ZigbeeSecurityLevel.ENC_MIC32);
            expect(apsHeader.securityHeader?.micLen).toStrictEqual(4);

            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_TC_LINK);
            expect(apsPayload.length).toStrictEqual(1 + 1 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 8 + 8);

            const keyOffset = 2;
            const destOffset = keyOffset + ZigbeeAPSConsts.CMD_KEY_LENGTH;
            const sourceOffset = destOffset + 8;

            expect(apsPayload.subarray(keyOffset, destOffset)).toStrictEqual(linkKey);
            expect(apsPayload.readBigUInt64LE(destOffset)).toStrictEqual(child64);
            expect(apsPayload.readBigUInt64LE(sourceOffset)).toStrictEqual(context.netParams.eui64);
        });

        it("encodes application link key transport with partner address and initiator flag", async () => {
            const appKey = Buffer.from("0123456789abcdeffedcba9876543210", "hex");
            const partner64 = 0x00124b00fffedcban;

            const frame = await captureMacFrame(() => apsHandler.sendTransportKeyAPP(child16, appKey, partner64, true), mockMACHandlerCallbacks);
            const { nwkFrameControl, apsFrameControl, apsHeader, apsPayload } = decodeAPSFrame(frame);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.security).toStrictEqual(true);
            expect(apsHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.LOAD);
            expect(apsHeader.securityHeader?.control.level).toStrictEqual(ZigbeeSecurityLevel.ENC_MIC32);
            expect(apsHeader.securityHeader?.micLen).toStrictEqual(4);

            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_APP_LINK);
            expect(apsPayload.length).toStrictEqual(1 + 1 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 8 + 1);

            const keyOffset = 2;
            const partnerOffset = keyOffset + ZigbeeAPSConsts.CMD_KEY_LENGTH;
            const flagOffset = partnerOffset + 8;

            expect(apsPayload.subarray(keyOffset, partnerOffset)).toStrictEqual(appKey);
            expect(apsPayload.readBigUInt64LE(partnerOffset)).toStrictEqual(partner64);
            expect(apsPayload.readUInt8(flagOffset)).toStrictEqual(1);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.4.4: APS Update Device Command
     * Update device command SHALL notify of device status changes.
     */
    describe("APS Update Device Command (Zigbee §4.4.4)", () => {
        const parent16 = 0x2468;
        const parent64 = 0x00124b00aaaabbbcn;

        beforeEach(() => {
            registerNeighborDevice(context, parent16, parent64);
        });

        function decodeAPSCommandFrame(frame: DecodedMACFrame) {
            const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
            const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
            const apsPayload = nwkPayload.subarray(apsPayloadOffset);

            return { nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload };
        }

        it.each([
            ["secure rejoin", ZigbeeAPSConsts.CMD_UPDATE_STANDARD_SEC_REJOIN],
            ["unsecured join", ZigbeeAPSConsts.CMD_UPDATE_STANDARD_UNSEC_JOIN],
            ["device left", ZigbeeAPSConsts.CMD_UPDATE_LEAVE],
            ["trust center rejoin", ZigbeeAPSConsts.CMD_UPDATE_STANDARD_UNSEC_REJOIN],
        ])("encodes update device payload for %s status", async (_label, status) => {
            const device16 = 0x3500 + status;
            const device64 = 0x00124b00cccce000n + BigInt(status);

            const frame = await captureMacFrame(() => apsHandler.sendUpdateDevice(parent16, device64, device16, status), mockMACHandlerCallbacks);
            const { nwkFrameControl, apsFrameControl, apsPayload } = decodeAPSCommandFrame(frame);

            expect(nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.DATA);
            expect(nwkFrameControl.security).toStrictEqual(true);

            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(apsFrameControl.security).toStrictEqual(false);
            expect(apsFrameControl.ackRequest).toStrictEqual(true);

            expect(apsPayload.length).toStrictEqual(1 + 8 + 2 + 1);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.UPDATE_DEVICE);
            expect(apsPayload.readBigUInt64LE(1)).toStrictEqual(device64);
            expect(apsPayload.readUInt16LE(9)).toStrictEqual(device16);
            expect(apsPayload.readUInt8(11)).toStrictEqual(status);
        });

        it("associates devices and tunnels the current network key for unsecured joins", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const device16 = 0x3a55;
            const device64 = 0x00124b00dddde111n;

            const payload = Buffer.alloc(1 + 8 + 2 + 1);
            let offset = 0;
            payload.writeUInt8(ZigbeeAPSCommandId.UPDATE_DEVICE, offset);
            offset += 1;
            payload.writeBigUInt64LE(device64, offset);
            offset += 8;
            payload.writeUInt16LE(device16, offset);
            offset += 2;
            payload.writeUInt8(ZigbeeAPSConsts.CMD_UPDATE_STANDARD_UNSEC_JOIN, offset);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x10,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: parent16,
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
                source16: parent16,
                source64: parent64,
                radius: 5,
                seqNum: 0x22,
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
                counter: 0x33,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            const entry = context.deviceTable.get(device64);
            expect(entry).toBeDefined();
            expect(entry?.address16).toStrictEqual(device16);
            expect(entry?.authorized).toStrictEqual(false);
            expect(context.address16ToAddress64.get(device16)).toStrictEqual(device64);

            expect(frames).toHaveLength(1);
            const tunneled = decodeMACFramePayload(frames[0]!);
            const { nwkFrameControl: tNwkFC, apsFrameControl: tApsFC, apsPayload: tunnelPayload } = decodeAPSCommandFrame(tunneled);

            expect(tNwkFC.security).toStrictEqual(true);
            expect(tApsFC.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(tApsFC.security).toStrictEqual(false);
            expect(tApsFC.ackRequest).toStrictEqual(false);
            expect(tunnelPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TUNNEL);
            expect(tunnelPayload.readBigUInt64LE(1)).toStrictEqual(device64);

            const innerApsFrame = tunnelPayload.subarray(9);
            const [innerFC, innerOffset] = decodeZigbeeAPSFrameControl(innerApsFrame, 0);
            const [innerHeader, innerHeaderOffset] = decodeZigbeeAPSHeader(innerApsFrame, innerOffset, innerFC);
            const innerPayload = decodeZigbeeAPSPayload(innerApsFrame, innerHeaderOffset, undefined, context.netParams.eui64, innerFC, innerHeader);

            expect(innerFC.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(innerHeader.frameControl.security).toStrictEqual(true);
            expect(innerHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.TRANSPORT);
            expect(innerHeader.securityHeader?.micLen).toStrictEqual(4);
            expect(innerPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(innerPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK);
            expect(innerPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.networkKey);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("removes devices when the reported status indicates a leave", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const device16 = 0x3b66;
            const device64 = 0x00124b00eeeef222n;
            registerNeighborDevice(context, device16, device64);

            const payload = Buffer.alloc(1 + 8 + 2 + 1);
            let offset = 0;
            payload.writeUInt8(ZigbeeAPSCommandId.UPDATE_DEVICE, offset);
            offset += 1;
            payload.writeBigUInt64LE(device64, offset);
            offset += 8;
            payload.writeUInt16LE(device16, offset);
            offset += 2;
            payload.writeUInt8(ZigbeeAPSConsts.CMD_UPDATE_LEAVE, offset);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x20,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: parent16,
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
                source16: parent16,
                source64: parent64,
                radius: 5,
                seqNum: 0x23,
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
                counter: 0x34,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(context.deviceTable.has(device64)).toStrictEqual(false);
            expect(context.address16ToAddress64.has(device16)).toStrictEqual(false);
            expect(mockStackContextCallbacks.onDeviceLeft).toHaveBeenCalledWith(device16, device64);
            expect(frames).toHaveLength(0);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("treats trust center rejoin status as a re-association", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const device64 = 0x00124b00fffef333n;
            const oldShort = 0x2c2c;
            const newShort = 0x3c3c;
            registerNeighborDevice(context, oldShort, device64);

            const payload = Buffer.alloc(1 + 8 + 2 + 1);
            let offset = 0;
            payload.writeUInt8(ZigbeeAPSCommandId.UPDATE_DEVICE, offset);
            offset += 1;
            payload.writeBigUInt64LE(device64, offset);
            offset += 8;
            payload.writeUInt16LE(newShort, offset);
            offset += 2;
            payload.writeUInt8(ZigbeeAPSConsts.CMD_UPDATE_STANDARD_UNSEC_REJOIN, offset);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x21,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: parent16,
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
                source16: parent16,
                source64: parent64,
                radius: 5,
                seqNum: 0x24,
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
                counter: 0x35,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            const entry = context.deviceTable.get(device64);
            expect(entry).toBeDefined();
            expect(entry?.address16).toStrictEqual(newShort);
            expect(context.address16ToAddress64.get(newShort)).toStrictEqual(device64);
            expect(frames).toHaveLength(0);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.4.5: APS Remove Device Command
     * Remove device command SHALL instruct a device to remove a child.
     */
    describe("APS Remove Device Command (Zigbee §4.4.5)", () => {
        const parent16 = 0x2a2b;
        const parent64 = 0x00124b00aaaafff1n;

        beforeEach(() => {
            registerNeighborDevice(context, parent16, parent64);
        });

        it("encodes remove device command payload with target IEEE address", async () => {
            const target64 = 0x00124b00bbbccdden;

            const frame = await captureMacFrame(() => apsHandler.sendRemoveDevice(parent16, target64), mockMACHandlerCallbacks);
            const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
            const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
            const apsPayload = nwkPayload.subarray(apsPayloadOffset);

            expect(nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.DATA);
            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(apsFrameControl.security).toStrictEqual(false);
            expect(apsHeader.counter).toBeGreaterThanOrEqual(1);

            expect(apsPayload.length).toStrictEqual(1 + 8);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.REMOVE_DEVICE);
            expect(apsPayload.readBigUInt64LE(1)).toStrictEqual(target64);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("processes remove device command by issuing leave and clearing child state", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const child16 = 0x4d4e;
            const child64 = 0x00124b00cccddaa1n;
            registerNeighborDevice(context, child16, child64);

            const payload = Buffer.alloc(1 + 8);
            payload.writeUInt8(ZigbeeAPSCommandId.REMOVE_DEVICE, 0);
            payload.writeBigUInt64LE(child64, 1);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x50,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: parent16,
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
                source16: parent16,
                source64: parent64,
                radius: 3,
                seqNum: 0x51,
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

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const leaveFrame = decodeMACFramePayload(frames[0]!);
            const leaveMacPayload = leaveFrame.buffer.subarray(leaveFrame.payloadOffset, leaveFrame.buffer.length - 2);
            const [leaveNwkFrameControl, leaveOffset] = decodeZigbeeNWKFrameControl(leaveMacPayload, 0);
            const [leaveNwkHeader, leavePayloadOffset] = decodeZigbeeNWKHeader(leaveMacPayload, leaveOffset, leaveNwkFrameControl);
            const leavePayload = decodeZigbeeNWKPayload(
                leaveMacPayload,
                leavePayloadOffset,
                undefined,
                context.netParams.eui64,
                leaveNwkFrameControl,
                leaveNwkHeader,
            );

            expect(leaveNwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.CMD);
            expect(leaveNwkFrameControl.security).toStrictEqual(true);
            expect(leaveNwkHeader.destination16).toStrictEqual(child16);
            expect(leavePayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.LEAVE);
            expect(leavePayload.readUInt8(1) & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST).toStrictEqual(ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST);

            expect(context.deviceTable.has(child64)).toStrictEqual(false);
            expect(context.address16ToAddress64.has(child16)).toStrictEqual(false);
            expect(mockStackContextCallbacks.onDeviceLeft).toHaveBeenCalledWith(child16, child64);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.4.6: APS Request Key Command
     * Request key command SHALL allow devices to request keys from TC.
     */
    describe("APS Request Key Command (Zigbee §4.4.6)", () => {
        const requester16 = 0x6a6b;
        const requester64 = 0x00124b00abcdd001n;

        beforeEach(() => {
            registerNeighborDevice(context, requester16, requester64);
        });

        function decodeRequestKeyFrame(frame: DecodedMACFrame) {
            const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
            const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsPayloadOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader);

            return { nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload };
        }

        it("encodes request key command payload with partner IEEE address for application link keys", async () => {
            const partner64 = 0x00124b00ffffeeddn;

            const frame = await captureMacFrame(
                () => apsHandler.sendRequestKey(requester16, ZigbeeAPSConsts.CMD_KEY_APP_MASTER, partner64),
                mockMACHandlerCallbacks,
            );
            const { nwkFrameControl, apsFrameControl, apsPayload } = decodeRequestKeyFrame(frame);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.security).toStrictEqual(false);
            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);

            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.REQUEST_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_APP_MASTER);
            expect(apsPayload.length).toStrictEqual(2 + 8);
            expect(apsPayload.readBigUInt64LE(2)).toStrictEqual(partner64);
        });

        it("encodes trust center link key requests without partner address", async () => {
            const frame = await captureMacFrame(
                () => apsHandler.sendRequestKey(requester16, ZigbeeAPSConsts.CMD_KEY_TC_LINK),
                mockMACHandlerCallbacks,
            );
            const { nwkFrameControl, apsFrameControl, apsPayload } = decodeRequestKeyFrame(frame);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(apsPayload.length).toStrictEqual(2);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.REQUEST_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_TC_LINK);
        });

        it("processes network key requests by unicasting the current network key", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.from([ZigbeeAPSCommandId.REQUEST_KEY, ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK]);
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x40,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: requester16,
                commandId: undefined,
                fcs: 0,
            };
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
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
                source16: requester16,
                source64: requester64,
                radius: 5,
                seqNum: 0x41,
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
                counter: 0x42,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const transport = decodeMACFramePayload(frames[0]!);
            const { nwkFrameControl, apsFrameControl, apsPayload } = decodeRequestKeyFrame(transport);

            expect(nwkFrameControl.security).toStrictEqual(false);
            expect(apsFrameControl.security).toStrictEqual(true);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK);
            expect(apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.networkKey);
            expect(apsPayload.readUInt8(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.networkKeySequenceNumber);
            expect(apsPayload.readBigUInt64LE(3 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(requester64);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(1);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("processes application link key requests when policy allows them", async () => {
            context.trustCenterPolicies.allowAppKeyRequest = ApplicationKeyRequestPolicy.ALLOWED;

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const partner64 = 0x00124b00abcdd999n;
            const payload = Buffer.alloc(2 + 8);
            payload.writeUInt8(ZigbeeAPSCommandId.REQUEST_KEY, 0);
            payload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_APP_MASTER, 1);
            payload.writeBigUInt64LE(partner64, 2);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x43,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: requester16,
                commandId: undefined,
                fcs: 0,
            };
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
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
                source16: requester16,
                source64: requester64,
                radius: 5,
                seqNum: 0x44,
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
                counter: 0x45,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const transport = decodeMACFramePayload(frames[0]!);
            const { nwkFrameControl, apsFrameControl, apsPayload } = decodeRequestKeyFrame(transport);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.security).toStrictEqual(true);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_APP_LINK);
            expect(apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.tcKey);
            expect(apsPayload.readBigUInt64LE(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(partner64);
            expect(apsPayload.readUInt8(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 8)).toStrictEqual(1);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(1);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("processes trust center link key requests when policy permits", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.from([ZigbeeAPSCommandId.REQUEST_KEY, ZigbeeAPSConsts.CMD_KEY_TC_LINK]);
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x46,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: requester16,
                commandId: undefined,
                fcs: 0,
            };
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
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
                source16: requester16,
                source64: requester64,
                radius: 5,
                seqNum: 0x47,
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
                counter: 0x48,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const transport = decodeMACFramePayload(frames[0]!);
            const { nwkFrameControl, apsFrameControl, apsPayload } = decodeRequestKeyFrame(transport);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.security).toStrictEqual(true);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_TC_LINK);
            expect(apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.tcKey);
            expect(apsPayload.readBigUInt64LE(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(requester64);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(1);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.4.7-§4.4.8: APS Verify/Confirm Key Commands
     * Verify key response SHALL deliver confirm key status to the requesting device.
     */
    describe("APS Verify/Confirm Key Commands (Zigbee §4.4.7-§4.4.8)", () => {
        const device16 = 0x5b5c;
        const device64 = 0x00124b00deaddeadn;

        beforeEach(() => {
            registerNeighborDevice(context, device16, device64);
            const entry = context.deviceTable.get(device64);
            if (entry !== undefined) {
                entry.authorized = false;
            }
        });

        function decodeKeyCommandFrame(frame: DecodedMACFrame) {
            const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
            const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsPayloadOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader);

            return { nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload };
        }

        it("encodes verify key command payload with source IEEE address and hash", async () => {
            const hash = Buffer.from(context.tcVerifyKeyHash);

            const frame = await captureMacFrame(
                () => apsHandler.sendVerifyKey(device16, ZigbeeAPSConsts.CMD_KEY_TC_LINK, device64, hash),
                mockMACHandlerCallbacks,
            );
            const { nwkFrameControl, apsFrameControl, apsPayload } = decodeKeyCommandFrame(frame);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.security).toStrictEqual(false);
            expect(apsPayload.length).toStrictEqual(1 + 1 + 8 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.VERIFY_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_TC_LINK);
            expect(apsPayload.readBigUInt64LE(2)).toStrictEqual(device64);
            expect(apsPayload.subarray(10)).toStrictEqual(hash);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("processes verify key success by replying with confirm key and authorizing the device", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.alloc(1 + 1 + 8 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
            payload.writeUInt8(ZigbeeAPSCommandId.VERIFY_KEY, 0);
            payload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_TC_LINK, 1);
            payload.writeBigUInt64LE(device64, 2);
            context.tcVerifyKeyHash.copy(payload, 10);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x60,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
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
                seqNum: 0x61,
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
                counter: 0x62,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const confirm = decodeMACFramePayload(frames[0]!);
            const { nwkFrameControl, apsFrameControl, apsPayload } = decodeKeyCommandFrame(confirm);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(apsFrameControl.security).toStrictEqual(true);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.CONFIRM_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(0x00);
            expect(apsPayload.readUInt8(2)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_TC_LINK);
            expect(apsPayload.readBigUInt64LE(3)).toStrictEqual(device64);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(1);

            await new Promise((resolve) => setImmediate(resolve));
            expect(context.deviceTable.get(device64)?.authorized).toStrictEqual(true);
            expect(mockAPSHandlerCallbacks.onDeviceAuthorized).toHaveBeenCalledWith(device16, device64);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("processes verify key hash mismatches with security failure status and keeps device unauthorized", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.alloc(1 + 1 + 8 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
            payload.writeUInt8(ZigbeeAPSCommandId.VERIFY_KEY, 0);
            payload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_TC_LINK, 1);
            payload.writeBigUInt64LE(device64, 2);
            Buffer.alloc(ZigbeeAPSConsts.CMD_KEY_LENGTH, 0xaa).copy(payload, 10);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x63,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
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
                seqNum: 0x64,
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
                counter: 0x65,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const confirm = decodeMACFramePayload(frames[0]!);
            const { apsPayload } = decodeKeyCommandFrame(confirm);

            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.CONFIRM_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(0xad);
            expect(context.deviceTable.get(device64)?.authorized).toStrictEqual(false);
            expect(mockAPSHandlerCallbacks.onDeviceAuthorized).not.toHaveBeenCalled();

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("marks application master verify key requests as illegal", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.alloc(1 + 1 + 8 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
            payload.writeUInt8(ZigbeeAPSCommandId.VERIFY_KEY, 0);
            payload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_APP_MASTER, 1);
            payload.writeBigUInt64LE(device64, 2);
            Buffer.alloc(ZigbeeAPSConsts.CMD_KEY_LENGTH, 0xbb).copy(payload, 10);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x66,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
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
                seqNum: 0x67,
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
                counter: 0x68,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const confirm = decodeMACFramePayload(frames[0]!);
            const { apsPayload } = decodeKeyCommandFrame(confirm);

            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.CONFIRM_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(0xa3);
            expect(context.deviceTable.get(device64)?.authorized).toStrictEqual(false);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("ignores verify key commands received via MAC broadcast", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.alloc(1 + 1 + 8 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
            payload.writeUInt8(ZigbeeAPSCommandId.VERIFY_KEY, 0);
            payload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_TC_LINK, 1);
            payload.writeBigUInt64LE(device64, 2);
            context.tcVerifyKeyHash.copy(payload, 10);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x69,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: ZigbeeMACConsts.BCAST_ADDR,
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
                seqNum: 0x6a,
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
                counter: 0x6b,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(0);
            expect(context.deviceTable.get(device64)?.authorized).toStrictEqual(false);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.4.7: APS Switch Key Command
     * Switch key command SHALL trigger network key update.
     */
    describe("APS Switch Key Command (Zigbee §4.4.7)", () => {
        const router16 = 0x6c6d;
        const router64 = 0x00124b00abbaaddeen;

        beforeEach(() => {
            registerNeighborDevice(context, router16, router64);
        });

        function decodeSwitchKeyFrame(frame: DecodedMACFrame) {
            const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
            const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
            const apsPayload = nwkPayload.subarray(apsPayloadOffset);

            return { nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload };
        }

        it("encodes switch key command payload with sequence number", async () => {
            const nextSeq = 0x07;

            const frame = await captureMacFrame(() => apsHandler.sendSwitchKey(router16, nextSeq), mockMACHandlerCallbacks);
            const { nwkFrameControl, nwkHeader, apsFrameControl, apsPayload } = decodeSwitchKeyFrame(frame);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(nwkHeader.destination16).toStrictEqual(router16);
            expect(apsFrameControl.security).toStrictEqual(false);
            expect(apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(apsPayload.length).toStrictEqual(2);
            expect(apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.SWITCH_KEY);
            expect(apsPayload.readUInt8(1)).toStrictEqual(nextSeq);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("activates pending network key, updates sequence number, and resets frame counter", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const originalKey = Buffer.from(context.netParams.networkKey);
            context.netParams.networkKeyFrameCounter = 0x12345678;
            context.netParams.networkKeySequenceNumber = 0x02;

            const newKey = Buffer.from("112233445566778899aabbccddeeff00", "hex");
            const newSeq = 0x0b;
            const source16 = 0x4a4b;
            const source64 = 0x00124b00cfde0001n;

            const transportPayload = Buffer.alloc(1 + 1 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 1 + 8 + 8);
            let offset = 0;
            transportPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
            offset += 1;
            transportPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK, offset);
            offset += 1;
            newKey.copy(transportPayload, offset);
            offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;
            transportPayload.writeUInt8(newSeq, offset);
            offset += 1;
            transportPayload.writeBigUInt64LE(context.netParams.eui64, offset);
            offset += 8;
            transportPayload.writeBigUInt64LE(source64, offset);

            const transportMac: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x70,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16,
                commandId: undefined,
                fcs: 0,
            };
            const transportNWK: ZigbeeNWKHeader = {
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
                source16,
                source64,
                radius: 5,
                seqNum: 0x71,
            };
            const transportAPS: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.CMD,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                counter: 0x72,
            };

            await apsHandler.processCommand(transportPayload, transportMac, transportNWK, transportAPS);

            const switchPayload = Buffer.from([ZigbeeAPSCommandId.SWITCH_KEY, newSeq]);
            const switchMac: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x73,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16,
                commandId: undefined,
                fcs: 0,
            };
            const switchNWK: ZigbeeNWKHeader = {
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
                source16,
                source64,
                radius: 5,
                seqNum: 0x74,
            };
            const switchAPS: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.CMD,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                counter: 0x75,
            };

            await apsHandler.processCommand(switchPayload, switchMac, switchNWK, switchAPS);

            expect(frames).toHaveLength(0);
            expect(context.netParams.networkKey).toStrictEqual(newKey);
            expect(context.netParams.networkKeySequenceNumber).toStrictEqual(newSeq);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(0);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();

            // Ensure the old key is no longer active
            expect(context.netParams.networkKey).not.toStrictEqual(originalKey);
        });

        it("ignores switch key commands when no pending key is staged", async () => {
            const originalKey = Buffer.from(context.netParams.networkKey);
            context.netParams.networkKeyFrameCounter = 42;
            context.netParams.networkKeySequenceNumber = 0x09;

            const switchPayload = Buffer.from([ZigbeeAPSCommandId.SWITCH_KEY, 0xaa]);
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x80,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: router16,
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
                source16: router16,
                source64: router64,
                radius: 5,
                seqNum: 0x81,
            };
            const apsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.CMD,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                counter: 0x82,
            };

            await apsHandler.processCommand(switchPayload, macHeader, nwkHeader, apsHeader);

            expect(context.netParams.networkKey).toStrictEqual(originalKey);
            expect(context.netParams.networkKeySequenceNumber).toStrictEqual(0x09);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(42);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §2.2.11: APS Security
     * APS security SHALL protect application data using link keys.
     */
    describe("APS Security (Zigbee §2.2.11)", () => {
        const child16 = 0x8c8d;
        const child64 = 0x00124b00ff001122n;

        beforeEach(() => {
            registerNeighborDevice(context, child16, child64);
            const device = context.deviceTable.get(child64);

            if (device !== undefined) {
                device.authorized = false;
            }

            mockAPSHandlerCallbacks.onDeviceAuthorized = vi.fn();
        });

        afterEach(() => {
            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("secures confirm-key responses using the trust center link key", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const initialCounter = context.netParams.tcKeyFrameCounter;
            const result = await apsHandler.sendConfirmKey(child16, 0x00, ZigbeeAPSConsts.CMD_KEY_TC_LINK, child64);

            expect(result).toStrictEqual(true);
            expect(frames).toHaveLength(1);

            const macFrame = decodeMACFramePayload(frames[0]!);
            const decoded = decodeAPSFrame(macFrame);

            expect(decoded.apsFrameControl.security).toStrictEqual(true);
            expect(decoded.apsHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.LINK);
            expect(decoded.apsHeader.securityHeader?.control.nonce).toStrictEqual(true);
            expect(decoded.apsHeader.securityHeader?.source64).toStrictEqual(context.netParams.eui64);
            expect(decoded.apsHeader.securityHeader?.micLen).toStrictEqual(4);

            const expectedCounter = (initialCounter + 1) >>> 0;
            expect(decoded.apsHeader.securityHeader?.frameCounter).toStrictEqual(expectedCounter);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(expectedCounter);

            await new Promise((resolve) => setImmediate(resolve));
            expect(context.deviceTable.get(child64)?.authorized).toStrictEqual(true);
            expect(mockAPSHandlerCallbacks.onDeviceAuthorized).toHaveBeenCalledWith(child16, child64);
        });

        it("monotonically increments the trust center APS frame counter", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await apsHandler.sendConfirmKey(child16, 0x00, ZigbeeAPSConsts.CMD_KEY_TC_LINK, child64);
            await new Promise((resolve) => setImmediate(resolve));

            const firstFrame = frames[0]!;
            frames.length = 0;
            const firstDecoded = decodeAPSFrame(decodeMACFramePayload(firstFrame));
            const firstCounter = firstDecoded.apsHeader.securityHeader?.frameCounter;

            expect(firstCounter).not.toBeUndefined();
            const firstCounterValue = firstCounter!;

            const device = context.deviceTable.get(child64);

            if (device !== undefined) {
                device.authorized = false;
            }

            await apsHandler.sendConfirmKey(child16, 0x00, ZigbeeAPSConsts.CMD_KEY_TC_LINK, child64);
            await new Promise((resolve) => setImmediate(resolve));

            const secondFrame = frames[0]!;
            const secondDecoded = decodeAPSFrame(decodeMACFramePayload(secondFrame));
            const secondCounter = secondDecoded.apsHeader.securityHeader?.frameCounter;

            expect(secondCounter).not.toBeUndefined();
            const secondCounterValue = secondCounter!;

            expect(secondCounterValue).toStrictEqual((firstCounterValue + 1) >>> 0);
            expect(secondCounterValue).not.toStrictEqual(firstCounterValue);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(secondCounterValue);
        });

        it("secures application link key transports using the load key", async () => {
            const appPartner64 = 0x00124b00aa550011n;
            const appLinkKey = Buffer.from("00112233445566778899aabbccddeeff", "hex");
            const frames: Buffer[] = [];
            const initialCounter = context.netParams.tcKeyFrameCounter;

            registerNeighborDevice(context, child16, child64);

            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const frame = await captureMacFrame(
                () => apsHandler.sendTransportKeyAPP(child16, appLinkKey, appPartner64, true),
                mockMACHandlerCallbacks,
            );

            const decoded = decodeAPSFrame(frame);

            expect(decoded.apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(decoded.apsFrameControl.security).toStrictEqual(true);
            expect(decoded.nwkFrameControl.security).toStrictEqual(true);
            expect(decoded.apsHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.LOAD);
            expect(decoded.apsHeader.securityHeader?.control.nonce).toStrictEqual(true);

            const expectedCounter = (initialCounter + 1) >>> 0;
            expect(decoded.apsHeader.securityHeader?.frameCounter).toStrictEqual(expectedCounter);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(expectedCounter);

            expect(decoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(decoded.apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_APP_LINK);
            expect(decoded.apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(appLinkKey);
            const initiatorFlagOffset = 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 8;
            expect(decoded.apsPayload.readUInt8(initiatorFlagOffset)).toStrictEqual(1);
        });

        it("fails to decrypt APS frames when the trust center link key hash is incorrect", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const frame = await captureMacFrame(
                () => apsHandler.sendConfirmKey(child16, 0x00, ZigbeeAPSConsts.CMD_KEY_TC_LINK, child64),
                mockMACHandlerCallbacks,
            );

            const restore = () =>
                registerDefaultHashedKeys(
                    makeKeyedHashByType(ZigbeeKeyType.LINK, Buffer.from(NETDEF_TC_KEY)),
                    makeKeyedHashByType(ZigbeeKeyType.NWK, Buffer.from(NETDEF_NETWORK_KEY)),
                    makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, Buffer.from(NETDEF_TC_KEY)),
                    makeKeyedHashByType(ZigbeeKeyType.LOAD, Buffer.from(NETDEF_TC_KEY)),
                );

            try {
                const wrongLinkKey = Buffer.alloc(16, 0x5a);
                registerDefaultHashedKeys(
                    makeKeyedHashByType(ZigbeeKeyType.LINK, wrongLinkKey),
                    makeKeyedHashByType(ZigbeeKeyType.NWK, Buffer.from(NETDEF_NETWORK_KEY)),
                    makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, Buffer.from(NETDEF_TC_KEY)),
                    makeKeyedHashByType(ZigbeeKeyType.LOAD, Buffer.from(NETDEF_TC_KEY)),
                );

                expect(() => decodeAPSFrame(frame)).toThrow("Auth tag mismatch while decrypting Zigbee payload");
            } finally {
                restore();
            }
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §2.2.12: Fragmentation
     * APS fragmentation SHALL split large payloads across multiple frames.
     */
    describe("APS Fragmentation (Zigbee §2.2.12)", () => {
        const fragmentDest16 = 0x4321;
        const fragmentDest64 = 0x00124b00ffee9911n;
        const fragmentClusterId = 0x1234;
        const fragmentProfileId = 0x0104;
        const fragmentDestEndpoint = 0x15;
        const fragmentSourceEndpoint = 0x01;

        beforeEach(() => {
            registerNeighborDevice(context, fragmentDest16, fragmentDest64);
        });

        function buildAck(
            counter: number,
            nwkSeqNum: number,
        ): {
            mac: MACHeader;
            nwk: ZigbeeNWKHeader;
            aps: ZigbeeAPSHeader;
        } {
            return {
                mac: {
                    frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                    sequenceNumber: (0x70 + nwkSeqNum) & 0xff,
                    destinationPANId: netParams.panId,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    source16: fragmentDest16,
                    commandId: undefined,
                    fcs: 0,
                },
                nwk: {
                    frameControl: {
                        frameType: ZigbeeNWKFrameType.DATA,
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
                    source16: fragmentDest16,
                    source64: fragmentDest64,
                    radius: 5,
                    seqNum: nwkSeqNum & 0xff,
                },
                aps: {
                    frameControl: {
                        frameType: ZigbeeAPSFrameType.ACK,
                        deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                        ackFormat: false,
                        security: false,
                        ackRequest: false,
                        extendedHeader: false,
                    },
                    destEndpoint: fragmentSourceEndpoint,
                    clusterId: fragmentClusterId,
                    profileId: fragmentProfileId,
                    sourceEndpoint: fragmentDestEndpoint,
                    counter,
                },
            };
        }

        async function captureFragments(payload: Buffer): Promise<{ frames: Buffer[]; apsCounter: number }> {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((buffer: Buffer) => {
                frames.push(Buffer.from(buffer));
                return Promise.resolve();
            });

            const apsCounter = await apsHandler.sendData(
                payload,
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                fragmentDest16,
                fragmentDest64,
                ZigbeeAPSDeliveryMode.UNICAST,
                fragmentClusterId,
                fragmentProfileId,
                fragmentDestEndpoint,
                fragmentSourceEndpoint,
                undefined,
            );

            let ackSeq = 0x21;
            let lqa = 0x70;

            for (;;) {
                const priorCount = frames.length;
                const ack = buildAck(apsCounter, ackSeq);
                await apsHandler.processFrame(Buffer.alloc(0), ack.mac, ack.nwk, ack.aps, lqa);

                if (frames.length === priorCount) {
                    break;
                }

                ackSeq = (ackSeq + 1) & 0xff;
                if (lqa > 0) {
                    lqa -= 1;
                }
            }

            mockMACHandlerCallbacks.onSendFrame = vi.fn();

            return { frames, apsCounter };
        }

        it("fragments payloads beyond APS maximum and sends blocks sequentially after acknowledgments", async () => {
            const payload = Buffer.alloc(ZigbeeAPSConsts.PAYLOAD_MAX_SIZE + 40, 0xaa);
            const { frames } = await captureFragments(payload);

            expect(frames.length).toBeGreaterThan(1);

            const descriptors = frames.map((frame) => decodeAPSFrame(decodeMACFramePayload(frame)));
            const fragmentTypes = descriptors.map((descriptor) => descriptor.apsHeader.fragmentation ?? ZigbeeAPSFragmentation.NONE);

            expect(fragmentTypes[0]).toStrictEqual(ZigbeeAPSFragmentation.FIRST);
            expect(fragmentTypes[fragmentTypes.length - 1]).toStrictEqual(ZigbeeAPSFragmentation.LAST);

            const reassembled = Buffer.concat(descriptors.map((descriptor) => descriptor.apsPayload));
            expect(reassembled).toStrictEqual(payload);
        });

        it("includes extended header bitmap when acknowledging fragmented frames", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((buffer: Buffer) => {
                frames.push(Buffer.from(buffer));
                return Promise.resolve();
            });

            const inboundMac: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x90,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: fragmentDest16,
                commandId: undefined,
                fcs: 0,
            };
            const inboundNwk: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
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
                source16: fragmentDest16,
                source64: fragmentDest64,
                radius: 5,
                seqNum: 0x55,
            };
            const inboundAPS: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: true,
                },
                destEndpoint: fragmentDestEndpoint,
                clusterId: fragmentClusterId,
                profileId: fragmentProfileId,
                sourceEndpoint: fragmentSourceEndpoint,
                counter: 0x44,
                fragmentation: ZigbeeAPSFragmentation.MIDDLE,
                fragBlockNumber: 2,
            };

            await apsHandler.sendACK(inboundMac, inboundNwk, inboundAPS);

            expect(frames).toHaveLength(1);
            const ackDescriptor = decodeAPSFrame(decodeMACFramePayload(frames[0]!));
            expect(ackDescriptor.apsFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.ACK);
            expect(ackDescriptor.apsFrameControl.extendedHeader).toStrictEqual(true);
            expect(ackDescriptor.apsHeader.fragmentation).toStrictEqual(ZigbeeAPSFragmentation.FIRST);
            expect(ackDescriptor.apsHeader.fragBlockNumber).toStrictEqual(2);
            expect(ackDescriptor.apsHeader.fragACKBitfield).toStrictEqual(0x01);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("reassembles fragmented payloads before notifying stack callbacks", async () => {
            const payload = Buffer.alloc(ZigbeeAPSConsts.PAYLOAD_MAX_SIZE + 32);
            for (let index = 0; index < payload.length; index += 1) {
                payload[index] = index & 0xff;
            }

            const { frames } = await captureFragments(payload);
            const descriptors = frames.map((frame) => decodeAPSFrame(decodeMACFramePayload(frame)));
            const fragments = descriptors.map((descriptor) => Buffer.from(descriptor.apsPayload));

            const onFrameSpy = vi.fn<typeof mockAPSHandlerCallbacks.onFrame>();
            mockAPSHandlerCallbacks.onFrame = onFrameSpy;

            const apsCounter = descriptors[0]!.apsHeader.counter ?? 0;

            for (let block = 0; block < fragments.length; block += 1) {
                const descriptor = descriptors[block]!;
                const fragmentation = descriptor.apsHeader.fragmentation ?? ZigbeeAPSFragmentation.NONE;

                const inboundMac: MACHeader = {
                    frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                    sequenceNumber: (0x80 + block) & 0xff,
                    destinationPANId: netParams.panId,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    source16: fragmentDest16,
                    commandId: undefined,
                    fcs: 0,
                };
                const inboundNwk: ZigbeeNWKHeader = {
                    frameControl: {
                        frameType: ZigbeeNWKFrameType.DATA,
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
                    source16: fragmentDest16,
                    source64: fragmentDest64,
                    radius: 6,
                    seqNum: (0x90 + block) & 0xff,
                };

                const inboundAPS: ZigbeeAPSHeader = {
                    frameControl: {
                        frameType: ZigbeeAPSFrameType.DATA,
                        deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                        ackFormat: false,
                        security: false,
                        ackRequest: true,
                        extendedHeader: fragmentation !== ZigbeeAPSFragmentation.NONE,
                    },
                    destEndpoint: descriptor.apsHeader.sourceEndpoint,
                    clusterId: descriptor.apsHeader.clusterId,
                    profileId: descriptor.apsHeader.profileId,
                    sourceEndpoint: descriptor.apsHeader.destEndpoint,
                    counter: apsCounter,
                    ...(fragmentation !== ZigbeeAPSFragmentation.NONE
                        ? {
                              fragmentation,
                              fragBlockNumber: descriptor.apsHeader.fragBlockNumber,
                          }
                        : {}),
                };

                await apsHandler.processFrame(fragments[block]!, inboundMac, inboundNwk, inboundAPS, 0x66);

                if (block < fragments.length - 1) {
                    expect(onFrameSpy).not.toHaveBeenCalled();
                }
            }

            await vi.waitFor(() => {
                expect(onFrameSpy).toHaveBeenCalledTimes(1);
            });
            const [sender16, sender64, deliveredAPSHeader, deliveredPayload] = onFrameSpy.mock.calls[0]!;
            expect(sender16).toStrictEqual(fragmentDest16);
            expect(sender64).toStrictEqual(fragmentDest64);
            expect(deliveredAPSHeader.frameControl.extendedHeader).toStrictEqual(false);
            expect(deliveredAPSHeader.fragmentation).toBeUndefined();
            expect(deliveredPayload).toStrictEqual(payload);

            mockAPSHandlerCallbacks.onFrame = vi.fn();
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §2.4: APS Constants
     * APS layer SHALL enforce specified constants.
     */
    describe("APS Constants (Zigbee §2.4)", () => {
        it("waits apsAckWaitDuration before retrying pending unicast data", async () => {
            vi.useFakeTimers();

            try {
                const device16 = 0x4a5d;
                const device64 = 0x00124b00eeff0005n;
                registerNeighborDevice(context, device16, device64);
                context.deviceTable.get(device64)!.capabilities!.rxOnWhenIdle = true;

                const sentFrames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                    sentFrames.push(Buffer.from(payload));
                    return Promise.resolve();
                });

                const apsCounter = await apsHandler.sendData(
                    Buffer.from([0xaa, 0xbb]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    device16,
                    device64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0303,
                    ZigbeeConsts.HA_PROFILE_ID,
                    0x10,
                    0x20,
                    undefined,
                );

                expect(sentFrames).toHaveLength(1);

                await vi.advanceTimersByTimeAsync(1499);
                expect(sentFrames).toHaveLength(1);

                await vi.advanceTimersByTimeAsync(1);
                expect(sentFrames).toHaveLength(2);

                const firstTx = decodeAPSFrame(decodeMACFramePayload(sentFrames[0]!));

                const ackMacHeader: MACHeader = {
                    frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                    sequenceNumber: 0x90,
                    destinationPANId: netParams.panId,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    source16: device16,
                    commandId: undefined,
                    fcs: 0,
                };
                const ackNwkHeader: ZigbeeNWKHeader = {
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
                    seqNum: firstTx.nwkHeader.seqNum,
                };
                const ackAPSHeader: ZigbeeAPSHeader = {
                    frameControl: {
                        frameType: ZigbeeAPSFrameType.ACK,
                        deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                        ackFormat: false,
                        security: false,
                        ackRequest: false,
                        extendedHeader: false,
                    },
                    destEndpoint: firstTx.apsHeader.sourceEndpoint,
                    clusterId: firstTx.apsHeader.clusterId,
                    profileId: firstTx.apsHeader.profileId,
                    sourceEndpoint: firstTx.apsHeader.destEndpoint,
                    counter: apsCounter,
                };

                await apsHandler.processFrame(Buffer.alloc(0), ackMacHeader, ackNwkHeader, ackAPSHeader, 0x60);

                await vi.runOnlyPendingTimersAsync();
                expect(sentFrames).toHaveLength(2);
            } finally {
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
                vi.useRealTimers();
            }
        });

        it("caps retransmissions at apsMaxFrameRetries attempts", async () => {
            vi.useFakeTimers();

            try {
                const device16 = 0x4a5e;
                const device64 = 0x00124b00eeff0006n;
                registerNeighborDevice(context, device16, device64);
                context.deviceTable.get(device64)!.capabilities!.rxOnWhenIdle = true;

                const sentFrames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                    sentFrames.push(Buffer.from(payload));
                    return Promise.resolve();
                });

                await apsHandler.sendData(
                    Buffer.from([0xcc, 0xdd]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    device16,
                    device64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0404,
                    ZigbeeConsts.HA_PROFILE_ID,
                    0x33,
                    0x44,
                    undefined,
                );

                expect(sentFrames).toHaveLength(1);

                for (let attempt = 1; attempt <= 3; attempt += 1) {
                    await vi.advanceTimersByTimeAsync(1500);
                    expect(sentFrames).toHaveLength(1 + attempt);
                }

                await vi.advanceTimersByTimeAsync(1500);
                expect(sentFrames).toHaveLength(4);
            } finally {
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
                vi.useRealTimers();
            }
        });

        it("keeps simple descriptor responses within apscMaxDescriptorSize", () => {
            const seqNum = 0x52;
            const request = Buffer.alloc(4);
            request.writeUInt8(seqNum, 0);
            request.writeUInt16LE(ZigbeeConsts.COORDINATOR_ADDRESS, 1);
            request.writeUInt8(ZigbeeConsts.HA_ENDPOINT, 3);

            const response = apsHandler.getCoordinatorZDOResponse(ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST, request);

            expect(response).toBeDefined();
            const payload = response!;

            expect(payload.length).toBeLessThanOrEqual(80);
            const descriptorLength = payload.readUInt8(4);
            expect(descriptorLength).toBeLessThanOrEqual(75);
            expect(payload.length - 5).toStrictEqual(descriptorLength);
        });

        it("limits unfragmented APS frames to apscMaxFrameSize", () => {
            const payload = Buffer.alloc(ZigbeeAPSConsts.PAYLOAD_MAX_SIZE, 0x5a);
            const header: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint: 0x22,
                clusterId: 0x0606,
                profileId: ZigbeeConsts.HA_PROFILE_ID,
                sourceEndpoint: 0x11,
                counter: 0x5c,
            };

            const encoded = encodeZigbeeAPSFrame(header, payload);

            expect(encoded.length).toBeLessThanOrEqual(ZigbeeAPSConsts.FRAME_MAX_SIZE);
        });
    });
});
