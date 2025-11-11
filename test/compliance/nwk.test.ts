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
import { logger } from "../../src/utils/logger.js";
import {
    decodeMACCapabilities,
    encodeMACCapabilities,
    MACAssociationStatus,
    type MACCapabilities,
    MACFrameAddressMode,
    MACFrameType,
    type MACHeader,
    ZigbeeMACConsts,
} from "../../src/zigbee/mac.js";
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeConsts, ZigbeeKeyType, ZigbeeSecurityLevel } from "../../src/zigbee/zigbee.js";
import { ZigbeeAPSDeliveryMode, ZigbeeAPSFrameType, type ZigbeeAPSHeader } from "../../src/zigbee/zigbee-aps.js";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    ZigbeeNWKCommandId,
    ZigbeeNWKConsts,
    type ZigbeeNWKFrameControl,
    ZigbeeNWKFrameType,
    type ZigbeeNWKHeader,
    type ZigbeeNWKLinkStatus,
    ZigbeeNWKManyToOne,
    ZigbeeNWKRouteDiscovery,
    ZigbeeNWKStatus,
} from "../../src/zigbee/zigbee-nwk.js";
import { APSHandler, type APSHandlerCallbacks } from "../../src/zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../../src/zigbee-stack/nwk-gp-handler.js";
import { CONFIG_NWK_MAX_HOPS, NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import {
    END_DEVICE_TIMEOUT_TABLE_MS,
    type NetworkParameters,
    StackContext,
    type StackContextCallbacks,
} from "../../src/zigbee-stack/stack-context.js";
import { NETDEF_EXTENDED_PAN_ID, NETDEF_NETWORK_KEY, NETDEF_PAN_ID, NETDEF_TC_KEY } from "../data.js";
import { createMACFrameControl } from "../utils.js";
import { captureMacFrame, type DecodedMACFrame, decodeMACFramePayload, NO_ACK_CODE, registerNeighborDevice } from "./utils.js";

describe("Zigbee 3.0 Network Layer (NWK) Compliance", () => {
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

    const nwkDest16 = 0x3344;
    const nwkDest64 = 0x00124b00aabbccddn;
    const groupId = 0x3366;

    function decodeNWKFromMacFrame(frame: DecodedMACFrame, decryptPayload = false) {
        const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
        const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
        const nwkPayload = decryptPayload
            ? decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader)
            : Buffer.alloc(0);

        return { nwkFrameControl, nwkHeader, nwkPayload };
    }

    /**
     * Zigbee Spec 05-3474-23 §3.3.1: NWK Frame Format
     * The NWK frame SHALL consist of a frame control field, addressing fields,
     * sequence number, radius, and frame payload.
     */
    describe("NWK Frame Format (Zigbee §3.3.1)", () => {
        beforeEach(() => {
            registerNeighborDevice(context, nwkDest16, nwkDest64);
        });

        it("encodes unicast NWK data frames with Zigbee PRO defaults", async () => {
            const payload = Buffer.from([0x44, 0x55]);

            const macFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        payload,
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        nwkDest16,
                        nwkDest64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
            const { nwkFrameControl, nwkHeader } = decodeNWKFromMacFrame(macFrame);

            expect(nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.DATA);
            expect(nwkFrameControl.protocolVersion).toStrictEqual(ZigbeeNWKConsts.VERSION_2007);
            expect(nwkFrameControl.discoverRoute).toStrictEqual(ZigbeeNWKRouteDiscovery.SUPPRESS);
            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(nwkFrameControl.sourceRoute).toStrictEqual(false);
            expect(nwkFrameControl.extendedDestination).toStrictEqual(true);
            expect(nwkFrameControl.extendedSource).toStrictEqual(false);
            expect(nwkFrameControl.endDeviceInitiator).toStrictEqual(false);
            expect(nwkHeader.destination16).toStrictEqual(nwkDest16);
            expect(nwkHeader.destination64).toStrictEqual(nwkDest64);
        });

        it("sets the multicast flag for group addressed data frames", async () => {
            const macFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0x01]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        ZigbeeConsts.BCAST_RX_ON_WHEN_IDLE,
                        undefined,
                        ZigbeeAPSDeliveryMode.GROUP,
                        0x0104,
                        0x0104,
                        undefined,
                        1,
                        groupId,
                    ),
                mockMACHandlerCallbacks,
            );
            const { nwkFrameControl, nwkHeader } = decodeNWKFromMacFrame(macFrame);

            expect(nwkFrameControl.extendedDestination).toStrictEqual(false);
            expect(nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_RX_ON_WHEN_IDLE);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.3.1.8: NWK Sequence Number
     * The NWK sequence number SHALL be an 8-bit value incremented for each
     * new transmission and wrapping to 0 after 255.
     */
    describe("NWK Sequence Number (Zigbee §3.3.1.8)", () => {
        beforeEach(() => {
            registerNeighborDevice(context, nwkDest16, nwkDest64);
        });

        it("increments the NWK sequence number for consecutive frames", async () => {
            const firstFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0x10]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        nwkDest16,
                        nwkDest64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
            const firstSeq = decodeNWKFromMacFrame(firstFrame).nwkHeader.seqNum!;

            const secondFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0x11]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        nwkDest16,
                        nwkDest64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
            const secondSeq = decodeNWKFromMacFrame(secondFrame).nwkHeader.seqNum!;

            expect(secondSeq).toStrictEqual((firstSeq + 1) & 0xff);
        });

        it("wraps the sequence number from 255 back to 0", async () => {
            let previous: number | undefined;
            let observedWrap = false;

            for (let i = 0; i < 260; i += 1) {
                const frame = await captureMacFrame(
                    () =>
                        apsHandler.sendData(
                            Buffer.from([i & 0xff]),
                            ZigbeeNWKRouteDiscovery.SUPPRESS,
                            nwkDest16,
                            nwkDest64,
                            ZigbeeAPSDeliveryMode.UNICAST,
                            0x0104,
                            0x0104,
                            1,
                            1,
                            undefined,
                        ),
                    mockMACHandlerCallbacks,
                );
                const seqNum = decodeNWKFromMacFrame(frame).nwkHeader.seqNum!;

                if (previous === 0xff && seqNum === 0x00) {
                    observedWrap = true;
                    break;
                }

                previous = seqNum;
            }

            expect(observedWrap).toStrictEqual(true);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.5: Network Security
     * Network layer security SHALL protect NWK frames using network key.
     */
    describe("NWK Security (Zigbee §3.5)", () => {
        beforeEach(() => {
            registerNeighborDevice(context, nwkDest16, nwkDest64);
        });

        async function produceSecuredFrame(): Promise<{
            macPayload: Buffer;
            nwkFrameControl: ZigbeeNWKFrameControl;
            nwkHeader: ZigbeeNWKHeader;
            payloadOffset: number;
        }> {
            const frame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xab]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        nwkDest16,
                        nwkDest64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
            const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
            const [nwkFrameControl, headerOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, headerOffset, nwkFrameControl);

            return { macPayload, nwkFrameControl, nwkHeader, payloadOffset };
        }

        it("attaches a network security header using the current network key", async () => {
            const initialCounter = context.netParams.networkKeyFrameCounter;
            const { macPayload, nwkFrameControl, nwkHeader, payloadOffset } = await produceSecuredFrame();
            const rawControl = macPayload.readUInt8(payloadOffset);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(nwkPayload.byteLength).toBeGreaterThan(0);
            expect(nwkHeader.securityHeader).not.toBeUndefined();
            expect(nwkHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.NWK);
            // is overridden during encode/decode (to ENC_MIC32), is NONE at this point
            expect(rawControl & ZigbeeConsts.SEC_CONTROL_LEVEL).toStrictEqual(ZigbeeSecurityLevel.NONE);
            expect(rawControl & ZigbeeConsts.SEC_CONTROL_KEY).toStrictEqual(ZigbeeKeyType.NWK << 3);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual((initialCounter + 1) >>> 0);
            expect(nwkHeader.securityHeader?.frameCounter).toStrictEqual(context.netParams.networkKeyFrameCounter);
        });

        it("uses an extended nonce sourced from the coordinator IEEE address", async () => {
            const { macPayload, nwkFrameControl, nwkHeader, payloadOffset } = await produceSecuredFrame();
            decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);

            expect(nwkHeader.securityHeader?.control.nonce).toStrictEqual(true);
            expect(nwkHeader.securityHeader?.source64).toStrictEqual(context.netParams.eui64);
        });

        it("increments the frame counter for each secured transmission", async () => {
            const first = await produceSecuredFrame();
            decodeZigbeeNWKPayload(first.macPayload, first.payloadOffset, undefined, context.netParams.eui64, first.nwkFrameControl, first.nwkHeader);
            const firstCounter = first.nwkHeader.securityHeader?.frameCounter;

            const second = await produceSecuredFrame();
            decodeZigbeeNWKPayload(
                second.macPayload,
                second.payloadOffset,
                undefined,
                context.netParams.eui64,
                second.nwkFrameControl,
                second.nwkHeader,
            );
            const secondCounter = second.nwkHeader.securityHeader?.frameCounter;

            expect(firstCounter).not.toBeUndefined();
            expect(secondCounter).not.toBeUndefined();
            expect(secondCounter).toStrictEqual(((firstCounter ?? 0) + 1) >>> 0);
            expect(secondCounter! > (firstCounter ?? 0)).toStrictEqual(true);
        });

        it("wraps the frame counter after reaching 0xffffffff", async () => {
            context.netParams.networkKeyFrameCounter = 0xfffffffe;
            const first = await produceSecuredFrame();
            decodeZigbeeNWKPayload(first.macPayload, first.payloadOffset, undefined, context.netParams.eui64, first.nwkFrameControl, first.nwkHeader);
            const firstCounter = first.nwkHeader.securityHeader?.frameCounter;

            const second = await produceSecuredFrame();
            decodeZigbeeNWKPayload(
                second.macPayload,
                second.payloadOffset,
                undefined,
                context.netParams.eui64,
                second.nwkFrameControl,
                second.nwkHeader,
            );
            const secondCounter = second.nwkHeader.securityHeader?.frameCounter;

            expect(firstCounter).toStrictEqual(0xffffffff);
            expect(secondCounter).toStrictEqual(0);
        });

        it("propagates the configured network key sequence number", async () => {
            context.netParams.networkKeySequenceNumber = 3;
            const { macPayload, nwkFrameControl, nwkHeader, payloadOffset } = await produceSecuredFrame();
            decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);

            expect(nwkHeader.securityHeader?.keySeqNum).toStrictEqual(3);
        });

        it("reports a 4-byte MIC for secured frames", async () => {
            const { macPayload, nwkFrameControl, nwkHeader, payloadOffset } = await produceSecuredFrame();
            decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);

            expect(nwkHeader.securityHeader?.micLen).toStrictEqual(4);
        });

        it("fails to decrypt when the wrong network key hash is registered", async () => {
            const { macPayload, nwkFrameControl, nwkHeader, payloadOffset } = await produceSecuredFrame();
            const wrongKey = Buffer.alloc(16, 0x5a);

            registerDefaultHashedKeys(
                makeKeyedHashByType(ZigbeeKeyType.LINK, Buffer.from(NETDEF_TC_KEY)),
                makeKeyedHashByType(ZigbeeKeyType.NWK, wrongKey),
                makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, Buffer.from(NETDEF_TC_KEY)),
                makeKeyedHashByType(ZigbeeKeyType.LOAD, Buffer.from(NETDEF_TC_KEY)),
            );

            expect(() => decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader)).toThrow(
                "Auth tag mismatch while decrypting Zigbee payload",
            );
        });

        it("fails to decrypt when the encrypted payload is tampered", async () => {
            const original = await produceSecuredFrame();
            const tampered = Buffer.from(original.macPayload);
            const tamperedIndex = Math.min(original.payloadOffset + 14, tampered.length - 1);
            tampered[tamperedIndex] ^= 0xff;
            const [mutFrameControl, headerOffset] = decodeZigbeeNWKFrameControl(tampered, 0);
            const [mutHeader, payloadOffset] = decodeZigbeeNWKHeader(tampered, headerOffset, mutFrameControl);

            expect(() => decodeZigbeeNWKPayload(tampered, payloadOffset, undefined, context.netParams.eui64, mutFrameControl, mutHeader)).toThrow(
                "Auth tag mismatch while decrypting Zigbee payload",
            );
        });

        it("rejects replayed incoming frame counters for known devices", () => {
            const device = context.deviceTable.get(nwkDest64)!;
            expect(context.updateIncomingNWKFrameCounter(nwkDest64, 10)).toStrictEqual(true);
            expect(device.incomingNWKFrameCounter).toStrictEqual(10);
            expect(context.updateIncomingNWKFrameCounter(nwkDest64, 10)).toStrictEqual(false);
            expect(context.updateIncomingNWKFrameCounter(nwkDest64, 11)).toStrictEqual(true);
        });

        it("rejects replayed NWK security counters for previously seen devices", () => {
            const child16 = 0x8c8d;
            const child64 = 0x00124b00ff001122n;
            registerNeighborDevice(context, child16, child64);
            const device = context.deviceTable.get(child64);

            expect(device).not.toBeUndefined();

            const first = context.updateIncomingNWKFrameCounter(child64, 42);
            expect(first).toStrictEqual(true);
            expect(device?.incomingNWKFrameCounter).toStrictEqual(42);

            const repeat = context.updateIncomingNWKFrameCounter(child64, 42);
            expect(repeat).toStrictEqual(false);
            expect(device?.incomingNWKFrameCounter).toStrictEqual(42);

            const lower = context.updateIncomingNWKFrameCounter(child64, 41);
            expect(lower).toStrictEqual(false);
            expect(device?.incomingNWKFrameCounter).toStrictEqual(42);

            const higher = context.updateIncomingNWKFrameCounter(child64, 48);
            expect(higher).toStrictEqual(true);
            expect(device?.incomingNWKFrameCounter).toStrictEqual(48);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.3.1.9: NWK Radius
     * The radius field SHALL indicate the maximum number of hops a frame will be
     * relayed. It SHALL be decremented by each relaying device.
     */
    describe("NWK Radius (Zigbee §3.3.1.9)", () => {
        const child16 = 0x5566;
        const child64 = 0x00124b00feedfacen;

        beforeEach(() => {
            registerNeighborDevice(context, child16, child64);
        });

        function makeInboundHeaders(radius: number): {
            macHeader: MACHeader;
            nwkHeader: ZigbeeNWKHeader;
            apsHeader: ZigbeeAPSHeader;
        } {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x22,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: child16,
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
                    extendedDestination: true,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: child16,
                source64: child64,
                radius,
                seqNum: 0x33,
            };
            const apsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint: 1,
                clusterId: 0x0006,
                profileId: 0x0104,
                sourceEndpoint: 1,
                counter: 0x44,
            };

            return { macHeader, nwkHeader, apsHeader };
        }

        it("decrements the radius when generating an APS acknowledgement", async () => {
            const inbound = makeInboundHeaders(5);
            const ackFrame = await captureMacFrame(
                () => apsHandler.sendACK(inbound.macHeader, inbound.nwkHeader, inbound.apsHeader),
                mockMACHandlerCallbacks,
            );
            const { nwkHeader } = decodeNWKFromMacFrame(ackFrame, true);

            expect(nwkHeader.radius).toStrictEqual(4);
        });

        it("does not reduce the radius below one for final-hop acknowledgements", async () => {
            const inbound = makeInboundHeaders(1);
            const ackFrame = await captureMacFrame(
                () => apsHandler.sendACK(inbound.macHeader, inbound.nwkHeader, inbound.apsHeader),
                mockMACHandlerCallbacks,
            );
            const { nwkHeader } = decodeNWKFromMacFrame(ackFrame, true);

            expect(nwkHeader.radius).toStrictEqual(1);
        });

        it("treats an incoming radius of zero as the default maximum before decrementing", async () => {
            const inbound = makeInboundHeaders(0);
            const ackFrame = await captureMacFrame(
                () => apsHandler.sendACK(inbound.macHeader, inbound.nwkHeader, inbound.apsHeader),
                mockMACHandlerCallbacks,
            );
            const { nwkHeader } = decodeNWKFromMacFrame(ackFrame, true);

            expect(nwkHeader.radius).toStrictEqual(CONFIG_NWK_MAX_HOPS - 1);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.4.1: Route Discovery
     * Route discovery SHALL use route request and route reply commands.
     */
    describe("NWK Route Discovery (Zigbee §3.4.1)", () => {
        it("encodes route request commands with broadcast addressing and destination extension when provided", async () => {
            const destination16 = 0x7788;
            const destination64 = 0x00124b00ddeeff00n;
            const frame = await captureMacFrame(
                () => nwkHandler.sendRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, destination16, destination64),
                mockMACHandlerCallbacks,
            );
            const { nwkFrameControl, nwkHeader, nwkPayload } = decodeNWKFromMacFrame(frame, true);

            expect(nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.CMD);
            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(nwkFrameControl.extendedDestination).toStrictEqual(false);
            expect(nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);

            const commandId = nwkPayload.readUInt8(0);
            const options = nwkPayload.readUInt8(1);
            const requestId = nwkPayload.readUInt8(2);
            const routeDestination16 = nwkPayload.readUInt16LE(3);

            expect(commandId).toStrictEqual(ZigbeeNWKCommandId.ROUTE_REQ);
            expect((options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT) !== 0).toStrictEqual(true);
            expect((options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK) >> 3).toStrictEqual(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING);
            expect(requestId).toBeGreaterThanOrEqual(1);
            expect(routeDestination16).toStrictEqual(destination16);
        });

        it("increments the route request identifier for each discovery attempt", async () => {
            const firstFrame = await captureMacFrame(
                () => nwkHandler.sendRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, 0x4455),
                mockMACHandlerCallbacks,
            );
            const firstId = decodeNWKFromMacFrame(firstFrame, true).nwkPayload.readUInt8(2);

            const secondFrame = await captureMacFrame(
                () => nwkHandler.sendRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, 0x4455),
                mockMACHandlerCallbacks,
            );
            const secondId = decodeNWKFromMacFrame(secondFrame, true).nwkPayload.readUInt8(2);

            expect(secondId).toStrictEqual(((firstId + 1) & 0xff) >>> 0);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.4.1.3: Route Maintenance
     * Routes SHALL be maintained through route error and route repair mechanisms.
     */
    describe("NWK Route Maintenance (Zigbee §3.4.1.3)", () => {
        const failingChild16 = 0x7788;
        const failingChild64 = 0x00124b00ddeeff11n;

        beforeEach(() => {
            context.deviceTable.set(failingChild64, {
                address16: failingChild16,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 1,
                    powerSource: 1,
                    rxOnWhenIdle: false,
                    securityCapability: true,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: true,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(failingChild16, failingChild64);
        });

        it("encodes NWK status commands with the optional destination field for routing failures", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));

                return Promise.resolve();
            });

            const result = await nwkHandler.sendStatus(failingChild16, ZigbeeNWKStatus.LINK_FAILURE, failingChild16);

            expect(result).toStrictEqual(true);
            expect(frames).toHaveLength(1);

            const macFrame = frames[0]!;
            const decoded = decodeNWKFromMacFrame(decodeMACFramePayload(macFrame), true);
            const { nwkFrameControl, nwkHeader, nwkPayload } = decoded;

            expect(nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.CMD);
            expect(nwkHeader.destination16).toStrictEqual(failingChild16);
            expect(nwkPayload.subarray(0, 4)).toStrictEqual(
                Buffer.from([ZigbeeNWKCommandId.NWK_STATUS, ZigbeeNWKStatus.LINK_FAILURE, failingChild16 & 0xff, failingChild16 >> 8]),
            );
        });

        it("omits the destination field for status codes that do not require it", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));

                return Promise.resolve();
            });

            await nwkHandler.sendStatus(failingChild16, ZigbeeNWKStatus.LEGACY_NO_ROUTE_AVAILABLE);

            const macFrame = frames[0]!;
            const { nwkPayload } = decodeNWKFromMacFrame(decodeMACFramePayload(macFrame), true);

            expect(nwkPayload).toStrictEqual(Buffer.from([ZigbeeNWKCommandId.NWK_STATUS, ZigbeeNWKStatus.LEGACY_NO_ROUTE_AVAILABLE]));
        });

        it("attempts to report delivery failures using NWK status commands", async () => {
            const error = new Error("No ACK");
            (error as Error & { cause?: number }).cause = NO_ACK_CODE;
            mockMACHandlerCallbacks.onSendFrame = vi.fn(() => Promise.reject(error));

            const result = await nwkHandler.sendStatus(failingChild16, ZigbeeNWKStatus.LINK_FAILURE, failingChild16);

            expect(result).toStrictEqual(false);
            expect(mockMACHandlerCallbacks.onMarkRouteFailure).toHaveBeenCalledWith(failingChild16);
            expect(context.macNoACKs.get(failingChild16)).toStrictEqual(1);
        });

        it("purges failing routes and notifies the concentrator when a link failure is reported", async () => {
            vi.useFakeTimers();
            const failingRelay = 0x3344;
            const dependentDest16 = 0x8899;
            const dependentEntry = nwkHandler.createSourceRouteEntry([failingChild16, failingRelay], 3);
            context.sourceRouteTable.set(failingChild16, [nwkHandler.createSourceRouteEntry([failingRelay], 2)]);
            context.sourceRouteTable.set(dependentDest16, [dependentEntry]);

            const sendMTORR = vi.spyOn(nwkHandler, "sendPeriodicManyToOneRouteRequest").mockResolvedValue();

            const statusPayload = Buffer.from([ZigbeeNWKStatus.LINK_FAILURE, failingChild16 & 0xff, failingChild16 >> 8]);
            const macHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x01,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: failingRelay,
                commandId: undefined,
                fcs: 0,
            } satisfies MACHeader;
            const nwkHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: true,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: failingRelay,
                radius: 5,
                seqNum: 0x02,
            } satisfies ZigbeeNWKHeader;

            await nwkHandler.processStatus(statusPayload, 0, macHeader, nwkHeader);
            vi.runAllTimers();

            expect(context.sourceRouteTable.has(failingChild16)).toStrictEqual(false);
            expect(context.sourceRouteTable.has(dependentDest16)).toStrictEqual(false);
            expect(sendMTORR).toHaveBeenCalled();
        });

        it("expires stale routes and schedules discovery for non-neighbor destinations", () => {
            vi.useFakeTimers();
            const distant16 = 0x99aa;
            const distant64 = 0x00124b00aabbccddn;
            context.deviceTable.set(distant64, {
                address16: distant16,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 1,
                    powerSource: 1,
                    rxOnWhenIdle: false,
                    securityCapability: true,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(distant16, distant64);

            const expiredEntry = nwkHandler.createSourceRouteEntry([0x2222, 0x3333], 4);
            expiredEntry.lastUpdated = Date.now() - 310000;
            context.sourceRouteTable.set(distant16, [expiredEntry]);

            const sendMTORR = vi.spyOn(nwkHandler, "sendPeriodicManyToOneRouteRequest").mockResolvedValue();

            const [relayIndex, relays, pathCost] = nwkHandler.findBestSourceRoute(distant16, distant64);
            vi.runAllTimers();

            expect(relayIndex).toBeUndefined();
            expect(relays).toBeUndefined();
            expect(pathCost).toBeUndefined();
            expect(context.sourceRouteTable.has(distant16)).toStrictEqual(false);
            expect(sendMTORR).toHaveBeenCalled();
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.4.1.6: Many-to-One Routing
     * Concentrator devices SHALL use many-to-one route requests to establish
     * routes from all devices back to the concentrator.
     */
    const routerShortAddress = 0x8899;
    const routerIeeeAddress = 0x00124b00ddeeff22n;

    function registerRouter(neighbor: boolean): void {
        context.deviceTable.set(routerIeeeAddress, {
            address16: routerShortAddress,
            capabilities: {
                alternatePANCoordinator: false,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            },
            authorized: true,
            neighbor,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
        });
        context.address16ToAddress64.set(routerShortAddress, routerIeeeAddress);
    }

    function makeRouteRecordCommand(relays: number[]): Buffer {
        const payload = Buffer.alloc(2 + relays.length * 2);
        let offset = 0;
        payload.writeUInt8(ZigbeeNWKCommandId.ROUTE_RECORD, offset);
        offset += 1;
        payload.writeUInt8(relays.length, offset);
        offset += 1;

        for (const relay of relays) {
            payload.writeUInt16LE(relay, offset);
            offset += 2;
        }

        return payload;
    }

    function makeRouteRecordHeaders(): { macHeader: MACHeader; nwkHeader: ZigbeeNWKHeader } {
        const macHeader: MACHeader = {
            frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
            sequenceNumber: 0x21,
            destinationPANId: netParams.panId,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            source16: routerShortAddress,
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
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            source16: routerShortAddress,
            radius: 5,
            seqNum: 0x34,
        };

        return { macHeader, nwkHeader };
    }

    function extractSourceRouteSubframe(frame: DecodedMACFrame): { relayCount: number; relayIndex: number; relays: number[] } {
        const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
        let offset = 0;
        const [frameControl, afterFCF] = decodeZigbeeNWKFrameControl(macPayload, offset);
        offset = afterFCF;

        if (frameControl.frameType === ZigbeeNWKFrameType.INTERPAN) {
            throw new Error("Inter-PAN frames do not carry source routes");
        }

        offset += 2; // destination16
        offset += 2; // source16
        offset += 1; // radius
        offset += 1; // seqNum

        if (frameControl.extendedDestination) {
            offset += 8;
        }

        if (frameControl.extendedSource) {
            offset += 8;
        }

        if (frameControl.multicast) {
            offset += 1;
        }

        if (!frameControl.sourceRoute) {
            throw new Error("Source route subframe absent");
        }

        const relayCount = macPayload.readUInt8(offset);
        offset += 1;
        const relayIndex = macPayload.readUInt8(offset);
        offset += 1;
        const relays: number[] = [];

        for (let i = 0; i < relayCount; i++) {
            relays.push(macPayload.readUInt16LE(offset));
            offset += 2;
        }

        return { relayCount, relayIndex, relays };
    }

    describe("NWK Many-to-One Routing (Zigbee §3.4.1.6)", () => {
        it("broadcasts many-to-one route requests when the concentrator timer fires", async () => {
            vi.useFakeTimers();
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));

                return Promise.resolve();
            });

            vi.setSystemTime(20000);
            await nwkHandler.sendPeriodicManyToOneRouteRequest();

            expect(frames).toHaveLength(1);

            const decodedMac = decodeMACFramePayload(frames[0]!);
            const { nwkFrameControl, nwkHeader, nwkPayload } = decodeNWKFromMacFrame(decodedMac, true);

            expect(nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.CMD);
            expect(nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.ROUTE_REQ);
        });

        it("sets the many-to-one option according to route record support", async () => {
            const destination16 = 0x7766;

            const withRecord = await captureMacFrame(
                () => nwkHandler.sendRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, destination16),
                mockMACHandlerCallbacks,
            );
            const withoutRecord = await captureMacFrame(
                () => nwkHandler.sendRouteReq(ZigbeeNWKManyToOne.WITHOUT_SOURCE_ROUTING, destination16),
                mockMACHandlerCallbacks,
            );

            const withPayload = decodeNWKFromMacFrame(withRecord, true).nwkPayload;
            const withoutPayload = decodeNWKFromMacFrame(withoutRecord, true).nwkPayload;

            const withOptions = withPayload.readUInt8(1) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK;
            const withoutOptions = withoutPayload.readUInt8(1) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK;

            expect(withOptions).toStrictEqual(ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_REC << 3);
            expect(withoutOptions).toStrictEqual(ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_NOREC << 3);
        });

        it("stores route record relay paths before processing concentrator data", async () => {
            registerRouter(false);
            const relays = [0x1111, 0x2222, 0x3333];
            const command = makeRouteRecordCommand(relays);
            const { macHeader, nwkHeader } = makeRouteRecordHeaders();

            await nwkHandler.processCommand(command, macHeader, nwkHeader);

            const entries = context.sourceRouteTable.get(routerShortAddress);

            expect(entries).not.toBeUndefined();
            expect(entries).toHaveLength(1);
            expect(entries?.[0]?.relayAddresses).toStrictEqual(relays);
            expect(entries?.[0]?.pathCost).toStrictEqual(relays.length + 1);
            expect(typeof entries?.[0]?.lastUpdated).toStrictEqual("number");
        });

        it("uses source routing for replies once a route record is available", async () => {
            registerRouter(false);
            const relays = [0x4444, 0x5555];
            const { macHeader, nwkHeader } = makeRouteRecordHeaders();
            const command = makeRouteRecordCommand(relays);

            await nwkHandler.processCommand(command, macHeader, nwkHeader);

            const macFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xaa]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        routerShortAddress,
                        routerIeeeAddress,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
            const { nwkFrameControl, nwkHeader: outboundNWK } = decodeNWKFromMacFrame(macFrame, true);

            expect(nwkFrameControl.sourceRoute).toStrictEqual(true);
            expect(outboundNWK.relayAddresses).toStrictEqual(relays);
            expect(outboundNWK.relayIndex).toStrictEqual(relays.length - 1);
            expect(macFrame.header.destination16).toStrictEqual(relays[relays.length - 1]);
        });

        it("requests route repair when data is sent without a prior route record", async () => {
            vi.useFakeTimers();
            registerRouter(false);
            const sendMTORR = vi.spyOn(nwkHandler, "sendPeriodicManyToOneRouteRequest").mockResolvedValue();

            const macFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xbb]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        routerShortAddress,
                        routerIeeeAddress,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );

            await vi.runAllTimersAsync();

            const { nwkFrameControl } = decodeNWKFromMacFrame(macFrame, true);

            expect(nwkFrameControl.sourceRoute).toStrictEqual(false);
            expect(sendMTORR).toHaveBeenCalled();
        });

        it("enforces the minimum interval between many-to-one requests", async () => {
            vi.useFakeTimers();
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));

                return Promise.resolve();
            });

            vi.setSystemTime(20000);
            await nwkHandler.sendPeriodicManyToOneRouteRequest();

            vi.setSystemTime(25000);
            await nwkHandler.sendPeriodicManyToOneRouteRequest();

            vi.setSystemTime(35000);
            await nwkHandler.sendPeriodicManyToOneRouteRequest();

            expect(frames).toHaveLength(2);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.4.2: Source Routing
     * Source routing SHALL allow the originator to specify the relay path.
     */
    describe("NWK Source Routing (Zigbee §3.4.2)", () => {
        let routeRelays: number[];

        beforeEach(async () => {
            registerRouter(false);
            routeRelays = [0x1234, 0x2345, 0x3456];
            const command = makeRouteRecordCommand(routeRelays);
            const { macHeader, nwkHeader } = makeRouteRecordHeaders();

            await nwkHandler.processCommand(command, macHeader, nwkHeader);
        });

        it("attaches a source route subframe when sending frames with stored paths", async () => {
            const macFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xcd]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        routerShortAddress,
                        routerIeeeAddress,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
            const { nwkFrameControl, nwkHeader } = decodeNWKFromMacFrame(macFrame, true);

            expect(nwkFrameControl.sourceRoute).toStrictEqual(true);
            expect(nwkHeader.relayAddresses).not.toBeUndefined();
            expect(nwkHeader.relayAddresses).toHaveLength(routeRelays.length);
        });

        it("encodes the relay count to match the stored relay addresses", async () => {
            const macFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xde]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        routerShortAddress,
                        routerIeeeAddress,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
            const subframe = extractSourceRouteSubframe(macFrame);

            expect(subframe.relayCount).toStrictEqual(routeRelays.length);
            expect(subframe.relays).toStrictEqual(routeRelays);
        });

        it("initializes the relay index to the last hop so relays decrement it while forwarding", async () => {
            const macFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xef]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        routerShortAddress,
                        routerIeeeAddress,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
            const subframe = extractSourceRouteSubframe(macFrame);

            expect(subframe.relayIndex).toStrictEqual(routeRelays.length - 1);
        });

        it("preserves the relay ordering learned from route record commands", async () => {
            const macFrame = await captureMacFrame(
                () =>
                    apsHandler.sendData(
                        Buffer.from([0xaa]),
                        ZigbeeNWKRouteDiscovery.SUPPRESS,
                        routerShortAddress,
                        routerIeeeAddress,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0104,
                        0x0104,
                        1,
                        1,
                        undefined,
                    ),
                mockMACHandlerCallbacks,
            );
            const { nwkHeader } = decodeNWKFromMacFrame(macFrame, true);

            expect(nwkHeader.relayAddresses).toStrictEqual(routeRelays);
        });

        it("records discovered source routes in the context table", () => {
            const entries = context.sourceRouteTable.get(routerShortAddress);

            expect(entries).not.toBeUndefined();
            expect(entries).toHaveLength(1);
            expect(entries?.[0]?.relayAddresses).toStrictEqual(routeRelays);
            expect(entries?.[0]?.pathCost).toStrictEqual(routeRelays.length + 1);
        });

        it("uses source routing when responding with APS acknowledgements", async () => {
            const inboundMacHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x52,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: routerShortAddress,
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
                    sourceRoute: true,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: routerShortAddress,
                source64: routerIeeeAddress,
                radius: 5,
                seqNum: 0x62,
                relayIndex: 0,
                relayAddresses: routeRelays,
            };
            const inboundApsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint: 1,
                clusterId: 0x0006,
                profileId: 0x0104,
                sourceEndpoint: 1,
                counter: 0x77,
            };

            const ackFrame = await captureMacFrame(
                () => apsHandler.sendACK(inboundMacHeader, inboundNwkHeader, inboundApsHeader),
                mockMACHandlerCallbacks,
            );
            const subframe = extractSourceRouteSubframe(ackFrame);

            expect(subframe.relayCount).toStrictEqual(routeRelays.length);
            expect(subframe.relays).toStrictEqual(routeRelays);
            expect(subframe.relayIndex).toStrictEqual(routeRelays.length - 1);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.6.1: Network Command Frames
     * Network command frames SHALL be used for network management operations.
     */
    describe("NWK Command Frames (Zigbee §3.6.1)", () => {
        it("encodes route request command with IEEE destination extension", async () => {
            const destination16 = 0x5522;
            const destination64 = 0x00124b0011223344n;

            const macFrame = await captureMacFrame(
                () => nwkHandler.sendRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, destination16, destination64),
                mockMACHandlerCallbacks,
            );
            const { nwkPayload } = decodeNWKFromMacFrame(macFrame, true);
            const options = nwkPayload.readUInt8(1);
            const routeRequestId = nwkPayload.readUInt8(2);
            const encodedDest16 = nwkPayload.readUInt16LE(3);
            const pathCost = nwkPayload.readUInt8(5);
            const encodedDest64 = nwkPayload.readBigUInt64LE(6);

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.ROUTE_REQ);
            expect(options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT).toStrictEqual(ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT);
            expect(routeRequestId).toBeGreaterThanOrEqual(0);
            expect(encodedDest16).toStrictEqual(destination16);
            expect(pathCost).toStrictEqual(0);
            expect(encodedDest64).toStrictEqual(destination64);
        });

        it("encodes route reply command with optional IEEE addresses", async () => {
            const firstHop16 = 0x4455;
            const firstHop64 = 0x00124b00ddeedd11n;
            const originator16 = 0x1234;
            const responder16 = 0x5678;
            const originator64 = 0x00124b009900aa11n;
            const responder64 = 0x00124b009900bb22n;

            registerNeighborDevice(context, firstHop16, firstHop64);

            const macFrame = await captureMacFrame(
                () => nwkHandler.sendRouteReply(firstHop16, 3, 0x42, originator16, responder16, originator64, responder64),
                mockMACHandlerCallbacks,
            );
            const { nwkPayload } = decodeNWKFromMacFrame(macFrame, true);
            const options = nwkPayload.readUInt8(1);
            const routeReplyId = nwkPayload.readUInt8(2);
            const encodedOrigin16 = nwkPayload.readUInt16LE(3);
            const encodedResponder16 = nwkPayload.readUInt16LE(5);
            const pathCost = nwkPayload.readUInt8(7);
            const encodedOrigin64 = nwkPayload.readBigUInt64LE(8);
            const encodedResponder64 = nwkPayload.readBigUInt64LE(16);

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.ROUTE_REPLY);
            expect(options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT).toStrictEqual(ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT);
            expect(options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT).toStrictEqual(ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT);
            expect(routeReplyId).toStrictEqual(0x42);
            expect(encodedOrigin16).toStrictEqual(originator16);
            expect(encodedResponder16).toStrictEqual(responder16);
            expect(pathCost).toStrictEqual(1);
            expect(encodedOrigin64).toStrictEqual(originator64);
            expect(encodedResponder64).toStrictEqual(responder64);
        });

        it("encodes network status command with optional destination field", async () => {
            const failingDest16 = 0x7788;
            const failingDest64 = 0x00124b00ccddeeffn;

            registerNeighborDevice(context, failingDest16, failingDest64);

            const macFrame = await captureMacFrame(
                () => nwkHandler.sendStatus(failingDest16, ZigbeeNWKStatus.LINK_FAILURE, 0x8877),
                mockMACHandlerCallbacks,
            );
            const { nwkPayload } = decodeNWKFromMacFrame(macFrame, true);

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.NWK_STATUS);
            expect(nwkPayload.readUInt8(1)).toStrictEqual(ZigbeeNWKStatus.LINK_FAILURE);
            expect(nwkPayload.readUInt16LE(2)).toStrictEqual(0x8877);
        });

        it("encodes leave command matching Zigbee request semantics", async () => {
            const device16 = 0x6611;
            const device64 = 0x00124b00fedcba09n;

            registerNeighborDevice(context, device16, device64);

            const macFrame = await captureMacFrame(() => nwkHandler.sendLeave(device16, true), mockMACHandlerCallbacks);
            const { nwkPayload } = decodeNWKFromMacFrame(macFrame, true);
            const options = nwkPayload.readUInt8(1);

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.LEAVE);
            expect(Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST)).toStrictEqual(true);
            expect(Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN)).toStrictEqual(true);
            expect(Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN)).toStrictEqual(false);
        });

        it("decodes route record command payload and populates source route table", async () => {
            registerRouter(false);
            const relays = [0x1001, 0x2002, 0x3003];
            const command = makeRouteRecordCommand(relays);
            const { macHeader, nwkHeader } = makeRouteRecordHeaders();

            await nwkHandler.processCommand(command, macHeader, nwkHeader);

            const entries = context.sourceRouteTable.get(routerShortAddress);

            expect(entries).not.toBeUndefined();
            expect(entries).toHaveLength(1);
            expect(entries?.[0]?.relayAddresses).toStrictEqual(relays);
            expect(entries?.[0]?.pathCost).toStrictEqual(relays.length + 1);
        });

        it("processes rejoin request frames and responds with assigned address", async () => {
            const device16 = 0x3311;
            const device64 = 0x00124b00aa55bb66n;

            registerNeighborDevice(context, device16, device64);

            const command = Buffer.from([ZigbeeNWKCommandId.REJOIN_REQ, 0x8e]);
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x12,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
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
                source16: device16,
                source64: device64,
                radius: 4,
                seqNum: 0x56,
            };

            const responseFrame = await captureMacFrame(() => nwkHandler.processCommand(command, macHeader, nwkHeader), mockMACHandlerCallbacks);
            const { nwkPayload } = decodeNWKFromMacFrame(responseFrame, true);

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.REJOIN_RESP);
            expect(nwkPayload.readUInt16LE(1)).toStrictEqual(device16);
            expect(nwkPayload.readUInt8(3)).toStrictEqual(MACAssociationStatus.SUCCESS);
        });

        it("encodes rejoin response command with assigned network address", async () => {
            const device16 = 0x2212;
            const device64 = 0x00124b0099aa1122n;

            registerNeighborDevice(context, device16, device64);

            const macFrame = await captureMacFrame(
                () => nwkHandler.sendRejoinResp(device16, device16, MACAssociationStatus.SUCCESS),
                mockMACHandlerCallbacks,
            );
            const { nwkPayload } = decodeNWKFromMacFrame(macFrame, true);

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.REJOIN_RESP);
            expect(nwkPayload.readUInt16LE(1)).toStrictEqual(device16);
            expect(nwkPayload.readUInt8(3)).toStrictEqual(MACAssociationStatus.SUCCESS);
        });

        it("encodes link status command frames with link counts and cost fields", async () => {
            const links = [
                { address: 0x3344, incomingCost: 2, outgoingCost: 3 },
                { address: 0x7788, incomingCost: 4, outgoingCost: 5 },
            ];

            const macFrame = await captureMacFrame(() => nwkHandler.sendLinkStatus(links), mockMACHandlerCallbacks);
            const { nwkPayload } = decodeNWKFromMacFrame(macFrame, true);
            const options = nwkPayload.readUInt8(1);
            const firstEntryAddr = nwkPayload.readUInt16LE(2);
            const firstEntryCosts = nwkPayload.readUInt8(4);
            const secondEntryAddr = nwkPayload.readUInt16LE(5);
            const secondEntryCosts = nwkPayload.readUInt8(7);

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.LINK_STATUS);
            expect(options & ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK).toStrictEqual(links.length);
            expect(Boolean(options & ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME)).toStrictEqual(true);
            expect(Boolean(options & ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME)).toStrictEqual(true);
            expect(firstEntryAddr).toStrictEqual(links[0]!.address);
            expect(firstEntryCosts & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK).toStrictEqual(links[0]!.incomingCost);
            expect((firstEntryCosts & ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK) >> 4).toStrictEqual(links[0]!.outgoingCost);
            expect(secondEntryAddr).toStrictEqual(links[1]!.address);
            expect(secondEntryCosts & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK).toStrictEqual(links[1]!.incomingCost);
            expect((secondEntryCosts & ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK) >> 4).toStrictEqual(links[1]!.outgoingCost);
        });

        it("decodes network report command and exposes conflicting PAN IDs", async () => {
            const logSpy = vi.spyOn(logger, "debug");
            const reportOptions = (2 & ZigbeeNWKConsts.CMD_NWK_REPORT_COUNT_MASK) | ZigbeeNWKConsts.CMD_NWK_REPORT_ID_PAN_CONFLICT;
            const buffer = Buffer.alloc(1 + 1 + 8 + 2 * 2);
            let offset = 0;
            buffer.writeUInt8(ZigbeeNWKCommandId.NWK_REPORT, offset);
            offset += 1;
            buffer.writeUInt8(reportOptions, offset);
            offset += 1;
            buffer.writeBigUInt64LE(0x00124b00aabbccddn, offset);
            offset += 8;
            buffer.writeUInt16LE(0x1a62, offset);
            offset += 2;
            buffer.writeUInt16LE(0x1a63, offset);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x33,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: routerShortAddress,
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
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: routerShortAddress,
                radius: 3,
                seqNum: 0x66,
            };

            await nwkHandler.processCommand(buffer, macHeader, nwkHeader);

            expect(logSpy).toHaveBeenCalled();
            const messageFactory = logSpy.mock.calls[0]?.[0];
            expect(typeof messageFactory).toStrictEqual("function");
            const message = (messageFactory as () => string)();
            expect(message).toContain("conflictPANIds=6754,6755");
            logSpy.mockRestore();
        });

        it("decodes network update command and reads advertised PAN IDs", async () => {
            const logSpy = vi.spyOn(logger, "debug");
            const updateOptions = (1 & ZigbeeNWKConsts.CMD_NWK_UPDATE_COUNT_MASK) | ZigbeeNWKConsts.CMD_NWK_UPDATE_ID_PAN_UPDATE;
            const buffer = Buffer.alloc(1 + 1 + 8 + 1 + 2);
            let offset = 0;
            buffer.writeUInt8(ZigbeeNWKCommandId.NWK_UPDATE, offset);
            offset += 1;
            buffer.writeUInt8(updateOptions, offset);
            offset += 1;
            buffer.writeBigUInt64LE(0x00124b00ffeeccddn, offset);
            offset += 8;
            buffer.writeUInt8(0x09, offset);
            offset += 1;
            buffer.writeUInt16LE(0x1b77, offset);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x44,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: routerShortAddress,
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
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: routerShortAddress,
                radius: 3,
                seqNum: 0x67,
            };

            await nwkHandler.processCommand(buffer, macHeader, nwkHeader);

            expect(logSpy).toHaveBeenCalled();
            const messageFactory = logSpy.mock.calls[0]?.[0];
            expect(typeof messageFactory).toStrictEqual("function");
            const message = (messageFactory as () => string)();
            expect(message).toContain("id=9");
            expect(message).toContain("panIds=7031");
            logSpy.mockRestore();
        });

        it("processes end device timeout requests and replies with accepted timeout", async () => {
            const child16 = 0x1144;
            const child64 = 0x00124b00ddeeff11n;

            registerNeighborDevice(context, child16, child64);

            const command = Buffer.from([ZigbeeNWKCommandId.ED_TIMEOUT_REQUEST, 0x04, 0x00]);
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x51,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: child16,
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
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: child16,
                radius: 2,
                seqNum: 0x72,
            };

            const responseFrame = await captureMacFrame(() => nwkHandler.processCommand(command, macHeader, nwkHeader), mockMACHandlerCallbacks);
            const { nwkPayload } = decodeNWKFromMacFrame(responseFrame, true);

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE);
            expect(nwkPayload.readUInt8(1)).toStrictEqual(0x00);
            expect(nwkPayload.readUInt8(2) & 0x07).toStrictEqual(0x07);
        });

        it("encodes end device timeout response command with validation status", async () => {
            const child16 = 0x2244;
            const child64 = 0x00124b00ffccddeen;

            registerNeighborDevice(context, child16, child64);

            const macFrame = await captureMacFrame(() => nwkHandler.sendEdTimeoutResponse(child16, 15), mockMACHandlerCallbacks);
            const { nwkPayload } = decodeNWKFromMacFrame(macFrame, true);

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE);
            expect(nwkPayload.readUInt8(1)).toStrictEqual(0x01);
            expect(nwkPayload.readUInt8(2) & 0x07).toStrictEqual(0x07);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.6.3: Network Status Command
     * Network status command SHALL report errors and conditions using defined codes.
     */
    describe("NWK Network Status Command (Zigbee §3.6.3)", () => {
        const deprecatedStatusCodes = {
            lowBatteryLevel: 0x03,
            noRoutingCapacity: 0x04,
            noIndirectCapacity: 0x05,
            indirectTransactionExpiry: 0x06,
            targetDeviceUnavailable: 0x07,
            targetAddressUnallocated: 0x08,
            validateRoute: 0x0a,
            verifyAddresses: 0x0e,
            badFrameCounter: 0x11,
            badKeySequenceNumber: 0x12,
        } as const;

        function getStatusName(status: number): string {
            return (ZigbeeNWKStatus as unknown as Record<number, string>)[status] ?? "undefined";
        }

        function makeStatusHeaders(): { macHeader: MACHeader; nwkHeader: ZigbeeNWKHeader } {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x25,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: routerShortAddress,
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
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: routerShortAddress,
                radius: 5,
                seqNum: 0x44,
            };

            return { macHeader, nwkHeader };
        }

        async function processNetworkStatus(status: number, target16?: number): Promise<void> {
            const { macHeader, nwkHeader } = makeStatusHeaders();
            const payload = Buffer.alloc(target16 === undefined ? 2 : 4);
            let offset = 0;
            payload.writeUInt8(ZigbeeNWKCommandId.NWK_STATUS, offset);
            offset += 1;
            payload.writeUInt8(status, offset);
            offset += 1;

            if (target16 !== undefined) {
                payload.writeUInt16LE(target16, offset);
            }

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);
        }

        it("accepts every Zigbee network status code without throwing", async () => {
            const statusCodes = [
                ZigbeeNWKStatus.LEGACY_NO_ROUTE_AVAILABLE,
                ZigbeeNWKStatus.LEGACY_LINK_FAILURE,
                ZigbeeNWKStatus.LINK_FAILURE,
                deprecatedStatusCodes.lowBatteryLevel,
                deprecatedStatusCodes.noRoutingCapacity,
                deprecatedStatusCodes.noIndirectCapacity,
                deprecatedStatusCodes.indirectTransactionExpiry,
                deprecatedStatusCodes.targetDeviceUnavailable,
                deprecatedStatusCodes.targetAddressUnallocated,
                ZigbeeNWKStatus.PARENT_LINK_FAILURE,
                deprecatedStatusCodes.validateRoute,
                ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE,
                ZigbeeNWKStatus.MANY_TO_ONE_ROUTE_FAILURE,
                ZigbeeNWKStatus.ADDRESS_CONFLICT,
                deprecatedStatusCodes.verifyAddresses,
                ZigbeeNWKStatus.PANID_UPDATE,
                ZigbeeNWKStatus.NETWORK_ADDRESS_UPDATE,
                deprecatedStatusCodes.badFrameCounter,
                deprecatedStatusCodes.badKeySequenceNumber,
                ZigbeeNWKStatus.UNKNOWN_COMMAND,
                ZigbeeNWKStatus.PANID_CONFLICT_REPORT,
            ];

            for (const code of statusCodes) {
                await processNetworkStatus(code, 0x5566);
            }
        });

        it.each([
            ["LEGACY_NO_ROUTE_AVAILABLE (0x00)", ZigbeeNWKStatus.LEGACY_NO_ROUTE_AVAILABLE],
            ["LEGACY_LINK_FAILURE (0x01)", ZigbeeNWKStatus.LEGACY_LINK_FAILURE],
            ["LINK_FAILURE (0x02)", ZigbeeNWKStatus.LINK_FAILURE],
            ["SOURCE_ROUTE_FAILURE (0x0b)", ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE],
            ["MANY_TO_ONE_ROUTE_FAILURE (0x0c)", ZigbeeNWKStatus.MANY_TO_ONE_ROUTE_FAILURE],
        ])("purges routes and triggers repair on %s", async (_label, status) => {
            vi.useFakeTimers();
            const target16 = 0x7788;
            const dependent16 = 0x8899;
            context.sourceRouteTable.clear();
            context.sourceRouteTable.set(target16, [nwkHandler.createSourceRouteEntry([0x1001], 2)]);
            context.sourceRouteTable.set(dependent16, [nwkHandler.createSourceRouteEntry([target16], 3)]);
            const repairSpy = vi.spyOn(nwkHandler, "sendPeriodicManyToOneRouteRequest").mockResolvedValue();

            await processNetworkStatus(status, target16);
            await vi.runAllTimersAsync();

            expect(context.sourceRouteTable.has(target16)).toStrictEqual(false);
            expect(context.sourceRouteTable.has(dependent16)).toStrictEqual(false);
            expect(repairSpy).toHaveBeenCalledTimes(1);

            repairSpy.mockRestore();
            vi.useRealTimers();
        });

        it.each([
            ["LOW_BATTERY_LEVEL (0x03)", deprecatedStatusCodes.lowBatteryLevel],
            ["NO_ROUTING_CAPACITY (0x04)", deprecatedStatusCodes.noRoutingCapacity],
            ["NO_INDIRECT_CAPACITY (0x05)", deprecatedStatusCodes.noIndirectCapacity],
            ["INDIRECT_TRANSACTION_EXPIRY (0x06)", deprecatedStatusCodes.indirectTransactionExpiry],
            ["TARGET_DEVICE_UNAVAILABLE (0x07)", deprecatedStatusCodes.targetDeviceUnavailable],
            ["TARGET_ADDRESS_UNALLOCATED (0x08)", deprecatedStatusCodes.targetAddressUnallocated],
            ["PARENT_LINK_FAILURE (0x09)", ZigbeeNWKStatus.PARENT_LINK_FAILURE],
            ["VALIDATE_ROUTE (0x0a)", deprecatedStatusCodes.validateRoute],
            ["VERIFY_ADDRESSES (0x0e)", deprecatedStatusCodes.verifyAddresses],
        ])("logs %s without altering the source route table", async (_label, status) => {
            context.sourceRouteTable.clear();
            context.sourceRouteTable.set(routerShortAddress, [nwkHandler.createSourceRouteEntry([], 1)]);
            const logSpy = vi.spyOn(logger, "debug");

            await processNetworkStatus(status);

            expect(context.sourceRouteTable.has(routerShortAddress)).toStrictEqual(true);
            const messageFactory = logSpy.mock.calls.at(-1)?.[0];
            expect(typeof messageFactory).toStrictEqual("function");
            const message = (messageFactory as () => string)();
            expect(message).toContain(`status=${getStatusName(status)}`);
            expect(message).toContain("dst16=undefined");

            logSpy.mockRestore();
        });

        it.each([
            ["PAN_IDENTIFIER_UPDATE (0x0f)", ZigbeeNWKStatus.PANID_UPDATE],
            ["NETWORK_ADDRESS_UPDATE (0x10)", ZigbeeNWKStatus.NETWORK_ADDRESS_UPDATE],
            ["UNKNOWN_COMMAND (0x13)", ZigbeeNWKStatus.UNKNOWN_COMMAND],
            ["PANID_CONFLICT_REPORT (0x14)", ZigbeeNWKStatus.PANID_CONFLICT_REPORT],
        ])("records log output for %s", async (_label, status) => {
            const logSpy = vi.spyOn(logger, "debug");

            await processNetworkStatus(status);

            const messageFactory = logSpy.mock.calls.at(-1)?.[0];
            expect(typeof messageFactory).toStrictEqual("function");
            const message = (messageFactory as () => string)();
            expect(message).toContain(`status=${getStatusName(status)}`);

            logSpy.mockRestore();
        });

        it.each([
            ["BAD_FRAME_COUNTER (0x11)", deprecatedStatusCodes.badFrameCounter],
            ["BAD_KEY_SEQUENCE_NUMBER (0x12)", deprecatedStatusCodes.badKeySequenceNumber],
        ])("handles %s as undefined status codes", async (_label, status) => {
            const logSpy = vi.spyOn(logger, "debug");

            await processNetworkStatus(status);

            const messageFactory = logSpy.mock.calls.at(-1)?.[0];
            expect(typeof messageFactory).toStrictEqual("function");
            const message = (messageFactory as () => string)();
            expect(message).toContain("status=undefined");

            logSpy.mockRestore();
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.6.4: Leave Command
     * Leave command SHALL allow devices to leave the network gracefully.
     */
    describe("NWK Leave Command (Zigbee §3.6.4)", () => {
        const child16 = 0x3344;
        const child64 = 0x00124b00ccddeeffn;

        function makeLeaveHeaders(source16: number, source64: bigint | undefined = undefined): { macHeader: MACHeader; nwkHeader: ZigbeeNWKHeader } {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x45,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16,
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
                    extendedSource: source64 !== undefined,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16,
                source64,
                radius: 5,
                seqNum: 0x63,
            };

            return { macHeader, nwkHeader };
        }

        function encodeLeavePayload(options: number): Buffer {
            const payload = Buffer.alloc(2);
            payload.writeUInt8(ZigbeeNWKCommandId.LEAVE, 0);
            payload.writeUInt8(options, 1);

            return payload;
        }

        beforeEach(() => {
            registerNeighborDevice(context, child16, child64);
        });

        it("encodes leave command options when initiating a leave request", async () => {
            const macFrame = await captureMacFrame(() => nwkHandler.sendLeave(child16, true), mockMACHandlerCallbacks);
            const { nwkPayload } = decodeNWKFromMacFrame(macFrame, true);
            const options = nwkPayload.readUInt8(1);

            expect(Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST)).toStrictEqual(true);
            expect(Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN)).toStrictEqual(true);
            expect(Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN)).toStrictEqual(false);
        });

        it("sets the rejoin flag when rejoin parameter is true", async () => {
            const withRejoin = await captureMacFrame(() => nwkHandler.sendLeave(child16, true), mockMACHandlerCallbacks);
            const withoutRejoin = await captureMacFrame(() => nwkHandler.sendLeave(child16, false), mockMACHandlerCallbacks);
            const withOptions = decodeNWKFromMacFrame(withRejoin, true).nwkPayload.readUInt8(1);
            const withoutOptions = decodeNWKFromMacFrame(withoutRejoin, true).nwkPayload.readUInt8(1);

            expect(Boolean(withOptions & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN)).toStrictEqual(true);
            expect(Boolean(withoutOptions & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN)).toStrictEqual(false);
        });

        it("marks incoming leave frames with request=false as indications", async () => {
            const { macHeader, nwkHeader } = makeLeaveHeaders(child16, child64);
            const payload = encodeLeavePayload(0b0000_0000);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            const device = context.deviceTable.get(child64);
            expect(device).toBeUndefined();
            expect(context.address16ToAddress64.has(child16)).toStrictEqual(false);
        });

        it("does not disassociate when the request flag is set", async () => {
            const { macHeader, nwkHeader } = makeLeaveHeaders(child16, child64);
            const payload = encodeLeavePayload(0b0100_0000);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            const device = context.deviceTable.get(child64);
            expect(device).not.toBeUndefined();
            expect(context.address16ToAddress64.get(child16)).toStrictEqual(child64);
        });

        it("removes the coordinator entry when it leaves voluntarily", async () => {
            const coordinator64 = netParams.eui64;
            registerNeighborDevice(context, ZigbeeConsts.COORDINATOR_ADDRESS, coordinator64);
            const { macHeader, nwkHeader } = makeLeaveHeaders(ZigbeeConsts.COORDINATOR_ADDRESS, coordinator64);
            nwkHeader.destination16 = ZigbeeConsts.BCAST_DEFAULT;
            macHeader.destination16 = ZigbeeMACConsts.BCAST_ADDR;
            const payload = encodeLeavePayload(0b0000_0000);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            expect(context.deviceTable.has(coordinator64)).toStrictEqual(false);
            expect(context.address16ToAddress64.has(ZigbeeConsts.COORDINATOR_ADDRESS)).toStrictEqual(false);
        });

        it("currently does not remove child entries when remove children flag is set (TODO)", async () => {
            const childA16 = 0x4455;
            const childA64 = 0x00124b00aa11bb22n;
            const childB16 = 0x5566;
            const childB64 = 0x00124b00aa11bb33n;
            registerNeighborDevice(context, childA16, childA64);
            registerNeighborDevice(context, childB16, childB64);

            const { macHeader, nwkHeader } = makeLeaveHeaders(child16, child64);
            const payload = encodeLeavePayload(0b1100_0000);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            expect(context.deviceTable.has(child64)).toStrictEqual(true);
            expect(context.address16ToAddress64.get(child16)).toStrictEqual(child64);
            expect(context.deviceTable.has(childA64)).toStrictEqual(true);
            expect(context.deviceTable.has(childB64)).toStrictEqual(true);
            expect(context.address16ToAddress64.has(childA16)).toStrictEqual(true);
            expect(context.address16ToAddress64.has(childB16)).toStrictEqual(true);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.6.5: Rejoin
     * Rejoin procedures SHALL allow devices to rejoin the network.
     */
    describe("NWK Rejoin Procedure (Zigbee §3.6.5)", () => {
        const rejoiner16 = 0x4466;
        const rejoiner64 = 0x00124b00ccddee11n;
        const baseCapabilities: MACCapabilities = {
            alternatePANCoordinator: false,
            deviceType: 1,
            powerSource: 1,
            rxOnWhenIdle: false,
            securityCapability: true,
            allocateAddress: true,
        };

        function makeRejoinHeaders({
            security = true,
            macSource16 = rejoiner16,
            nwkSource16 = rejoiner16,
            source64 = rejoiner64,
        }: {
            security?: boolean;
            macSource16?: number;
            nwkSource16?: number;
            source64?: bigint;
        } = {}): { macHeader: MACHeader; nwkHeader: ZigbeeNWKHeader } {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x52,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: macSource16,
                commandId: undefined,
                fcs: 0,
            };
            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: true,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: nwkSource16,
                source64,
                radius: 5,
                seqNum: 0x71,
            };

            return { macHeader, nwkHeader };
        }

        function encodeRejoinPayload(capabilitiesByte: number): Buffer {
            const payload = Buffer.alloc(2);
            payload.writeUInt8(ZigbeeNWKCommandId.REJOIN_REQ, 0);
            payload.writeUInt8(capabilitiesByte, 1);
            return payload;
        }

        async function captureRejoinResponse(
            capabilitiesByte: number,
            options?: {
                security?: boolean;
                macSource16?: number;
                nwkSource16?: number;
                source64?: bigint;
            },
        ): Promise<{ nwkFrameControl: ReturnType<typeof decodeZigbeeNWKFrameControl>[0]; nwkPayload: Buffer }> {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const { macHeader, nwkHeader } = makeRejoinHeaders(options);
            const payload = encodeRejoinPayload(capabilitiesByte);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            expect(frames).toHaveLength(1);
            const macFrame = decodeMACFramePayload(frames[0]!);
            const { nwkFrameControl, nwkPayload } = decodeNWKFromMacFrame(macFrame, true);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();

            return { nwkFrameControl, nwkPayload };
        }

        beforeEach(() => {
            context.deviceTable.set(rejoiner64, {
                address16: rejoiner16,
                capabilities: { ...baseCapabilities },
                authorized: true,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(rejoiner16, rejoiner64);
        });

        it("accepts secure rejoins, preserves NWK security, and updates capability information", async () => {
            const desiredCapabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 0,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: false,
            };

            const capabilitiesByte = encodeMACCapabilities(desiredCapabilities);
            const decodedCapabilities = decodeMACCapabilities(capabilitiesByte);
            const { nwkFrameControl, nwkPayload } = await captureRejoinResponse(capabilitiesByte);

            expect(nwkFrameControl.security).toStrictEqual(true);
            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.REJOIN_RESP);
            expect(nwkPayload.readUInt16LE(1)).toStrictEqual(rejoiner16);
            expect(nwkPayload.readUInt8(3)).toStrictEqual(MACAssociationStatus.SUCCESS);

            await new Promise((resolve) => setImmediate(resolve));

            const updatedDevice = context.deviceTable.get(rejoiner64)!;
            expect(updatedDevice.capabilities).toStrictEqual(decodedCapabilities);
        });

        it("assigns a new network address and signals conflict when a rejoin collides", async () => {
            const conflicting64 = 0x00124b00ccddee22n;
            context.deviceTable.set(conflicting64, {
                address16: rejoiner16,
                capabilities: { ...baseCapabilities },
                authorized: true,
                neighbor: true,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(rejoiner16, conflicting64);
            const currentDevice = context.deviceTable.get(rejoiner64)!;
            currentDevice.address16 = 0x5522;
            context.address16ToAddress64.set(0x5522, rejoiner64);

            const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.25);

            const { nwkPayload } = await captureRejoinResponse(encodeMACCapabilities(currentDevice.capabilities!));

            randomSpy.mockRestore();

            const commandId = nwkPayload.readUInt8(0);
            const assignedAddress = nwkPayload.readUInt16LE(1);
            const status = nwkPayload.readUInt8(3);

            expect(commandId).toStrictEqual(ZigbeeNWKCommandId.REJOIN_RESP);
            expect(status).toStrictEqual(ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT);
            expect(assignedAddress).not.toStrictEqual(rejoiner16);
            expect(assignedAddress).toBeLessThan(ZigbeeConsts.BCAST_MIN);
            expect(context.deviceTable.get(rejoiner64)?.address16).toStrictEqual(0x5522);
        });

        it("denies unsecured rejoins from unauthorized devices", async () => {
            const device = context.deviceTable.get(rejoiner64)!;
            device.authorized = false;

            const { nwkPayload } = await captureRejoinResponse(encodeMACCapabilities(device.capabilities!), { security: false });

            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.REJOIN_RESP);
            expect(nwkPayload.readUInt16LE(1)).toStrictEqual(0xffff);
            expect(nwkPayload.readUInt8(3)).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);

            await new Promise((resolve) => setImmediate(resolve));
        });

        it("updates the neighbor relationship based on the MAC-origin information", async () => {
            const { nwkPayload } = await captureRejoinResponse(encodeMACCapabilities(baseCapabilities));

            expect(nwkPayload.readUInt8(3)).toStrictEqual(MACAssociationStatus.SUCCESS);

            await new Promise((resolve) => setImmediate(resolve));
            expect(context.deviceTable.get(rejoiner64)?.neighbor).toStrictEqual(true);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.6.6: Link Status
     * Link status command SHALL be used to maintain link cost information.
     */
    describe("NWK Link Status Command (Zigbee §3.6.6)", () => {
        const neighbor16 = 0x5566;
        const neighbor64 = 0x00124b00ddeeff11n;

        function decodeLinkStatusPayload(nwkPayload: Buffer): { options: number; links: ZigbeeNWKLinkStatus[] } {
            const options = nwkPayload.readUInt8(1);
            const count = options & ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK;
            let offset = 2;
            const links: ZigbeeNWKLinkStatus[] = [];

            for (let i = 0; i < count; i++) {
                const address = nwkPayload.readUInt16LE(offset);
                offset += 2;
                const costByte = nwkPayload.readUInt8(offset);
                offset += 1;

                links.push({
                    address,
                    incomingCost: costByte & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK,
                    outgoingCost: (costByte & ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK) >> 4,
                });
            }

            return { options, links };
        }

        async function captureLinkStatusFrames(
            action: () => Promise<unknown> | unknown,
        ): Promise<Array<{ options: number; links: ZigbeeNWKLinkStatus[] }>> {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            try {
                await action();
            } finally {
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
            }

            return frames.map((frame) => {
                const macFrame = decodeMACFramePayload(frame);
                const { nwkFrameControl, nwkPayload } = decodeNWKFromMacFrame(macFrame, true);
                expect(nwkFrameControl.frameType).toStrictEqual(ZigbeeNWKFrameType.CMD);
                expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.LINK_STATUS);

                return decodeLinkStatusPayload(nwkPayload);
            });
        }

        function makeLinkStatusHeaders(source16: number, source64: bigint): { macHeader: MACHeader; nwkHeader: ZigbeeNWKHeader } {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x61,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16,
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
                source16,
                source64,
                radius: 5,
                seqNum: 0x82,
            };

            return { macHeader, nwkHeader };
        }

        function encodeLinkStatusPayload(
            entries: ZigbeeNWKLinkStatus[],
            flags: { firstFrame?: boolean; lastFrame?: boolean } = { firstFrame: true, lastFrame: true },
        ): Buffer {
            const options =
                (((flags.firstFrame ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME) |
                (((flags.lastFrame ? 1 : 0) << 6) & ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME) |
                (entries.length & ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK);
            const payload = Buffer.alloc(2 + entries.length * 3);
            let offset = 0;
            payload.writeUInt8(ZigbeeNWKCommandId.LINK_STATUS, offset++);
            payload.writeUInt8(options, offset++);

            for (const entry of entries) {
                payload.writeUInt16LE(entry.address, offset);
                offset += 2;
                payload.writeUInt8(
                    (entry.incomingCost & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK) |
                        ((entry.outgoingCost << 4) & ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK),
                    offset,
                );
                offset += 1;
            }

            return payload;
        }

        it("encodes link status command options and entry count", async () => {
            const links: ZigbeeNWKLinkStatus[] = [
                { address: 0x1001, incomingCost: 3, outgoingCost: 4 },
                { address: 0x1002, incomingCost: 2, outgoingCost: 1 },
            ];

            const frames = await captureLinkStatusFrames(() => nwkHandler.sendLinkStatus(links));

            expect(frames).toHaveLength(1);
            const [{ options, links: encodedLinks }] = frames;
            expect(options & ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK).toStrictEqual(links.length);
            expect(Boolean(options & ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME)).toStrictEqual(true);
            expect(Boolean(options & ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME)).toStrictEqual(true);
            expect(encodedLinks).toStrictEqual(links);
        });

        it("truncates encoded link cost fields to the Zigbee 0-7 range", async () => {
            const incomingCost = 9;
            const outgoingCost = 12;
            const frames = await captureLinkStatusFrames(() => nwkHandler.sendLinkStatus([{ address: 0x2001, incomingCost, outgoingCost }]));

            const [{ links: encodedLinks }] = frames;
            expect(encodedLinks[0]?.incomingCost).toStrictEqual(incomingCost & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK);
            expect(encodedLinks[0]?.outgoingCost).toStrictEqual(outgoingCost & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK);
        });

        it("derives link costs from recent LQA samples when sending periodic status", async () => {
            registerNeighborDevice(context, neighbor16, neighbor64);
            const neighbor = context.deviceTable.get(neighbor64)!;
            neighbor.recentLQAs = [30];

            const frames = await captureLinkStatusFrames(() => nwkHandler.sendPeriodicZigbeeNWKLinkStatus());

            const [{ links: encodedLinks }] = frames;
            expect(encodedLinks[0]).toStrictEqual({ address: neighbor16, incomingCost: 7, outgoingCost: 7 });
        });

        it("reuses the computed link cost for the outgoing field", async () => {
            registerNeighborDevice(context, neighbor16, neighbor64);
            const neighbor = context.deviceTable.get(neighbor64)!;
            neighbor.recentLQAs = [200];

            const frames = await captureLinkStatusFrames(() => nwkHandler.sendPeriodicZigbeeNWKLinkStatus());

            const [{ links: encodedLinks }] = frames;
            expect(encodedLinks[0]?.incomingCost).toStrictEqual(encodedLinks[0]?.outgoingCost);
        });

        it("sends link status frames on the configured periodic timer", async () => {
            vi.useFakeTimers();
            const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0);
            registerNeighborDevice(context, neighbor16, neighbor64);
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            try {
                await nwkHandler.start();
                const initialCount = frames.length;

                await vi.advanceTimersByTimeAsync(15000);

                expect(frames.length).toBeGreaterThan(initialCount);
            } finally {
                await nwkHandler.stop();
                randomSpy.mockRestore();
                vi.useRealTimers();
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
            }
        });

        it("updates device neighbor relationship and source routes from received link status", async () => {
            const router16 = 0x3456;
            const router64 = 0x00124b00aa55cc77n;
            registerNeighborDevice(context, router16, router64);
            const device = context.deviceTable.get(router64)!;
            device.neighbor = false;

            const { macHeader, nwkHeader } = makeLinkStatusHeaders(router16, router64);
            const payload = encodeLinkStatusPayload([{ address: ZigbeeConsts.COORDINATOR_ADDRESS, incomingCost: 0, outgoingCost: 3 }]);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            const updated = context.deviceTable.get(router64)!;
            expect(updated.neighbor).toStrictEqual(true);
            const routes = context.sourceRouteTable.get(router16);
            expect(routes).not.toBeUndefined();
            expect(routes![0]?.pathCost).toStrictEqual(1);
            expect(routes![0]?.relayAddresses).toStrictEqual([]);
        });

        it("prefers the lowest-cost relay reported in link status when routing", async () => {
            const router16 = 0x4567;
            const router64 = 0x00124b00aa55cc88n;
            registerNeighborDevice(context, router16, router64);
            const device = context.deviceTable.get(router64)!;
            device.neighbor = false;

            const { macHeader, nwkHeader } = makeLinkStatusHeaders(router16, router64);
            const payload = encodeLinkStatusPayload([
                { address: 0x5010, incomingCost: 1, outgoingCost: 3 },
                { address: 0x5020, incomingCost: 5, outgoingCost: 2 },
            ]);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            const [, relayAddresses, pathCost] = nwkHandler.findBestSourceRoute(router16, router64);
            expect(relayAddresses).toStrictEqual([0x5010]);
            expect(pathCost).toStrictEqual(2);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.6.8: End Device Timeout
     * End device timeout request/response SHALL manage end device aging.
     */
    describe("NWK End Device Timeout (Zigbee §3.6.8)", () => {
        const child16 = 0x6677;
        const child64 = 0x00124b00ffeecc11n;

        function makeEndDeviceTimeoutHeaders({ source16 = child16, source64 = child64 }: { source16?: number; source64?: bigint } = {}): {
            macHeader: MACHeader;
            nwkHeader: ZigbeeNWKHeader;
        } {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x73,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16,
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
                source16,
                source64,
                radius: 5,
                seqNum: 0x90,
            };

            return { macHeader, nwkHeader };
        }

        async function handleTimeoutRequest(
            timeoutIndex: number,
            overrides?: { source16?: number; source64?: bigint; configuration?: number },
            expectResponse = true,
        ) {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            try {
                const { macHeader, nwkHeader } = makeEndDeviceTimeoutHeaders(overrides);
                const payload = Buffer.from([ZigbeeNWKCommandId.ED_TIMEOUT_REQUEST, timeoutIndex, overrides?.configuration ?? 0x00]);

                await nwkHandler.processCommand(payload, macHeader, nwkHeader);
            } finally {
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
            }

            if (!expectResponse) {
                expect(frames).toHaveLength(0);

                return undefined;
            }

            expect(frames).toHaveLength(1);
            const macFrame = decodeMACFramePayload(frames[0]!);
            const decoded = decodeNWKFromMacFrame(macFrame, true);
            expect(decoded.nwkFrameControl.security).toStrictEqual(true);
            expect(decoded.nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE);

            return decoded.nwkPayload;
        }

        beforeEach(() => {
            context.deviceTable.set(child64, {
                address16: child16,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 0,
                    powerSource: 0,
                    rxOnWhenIdle: false,
                    securityCapability: true,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(child16, child64);
        });

        it("responds to timeout requests, stores metadata, and preserves format", async () => {
            vi.useFakeTimers();

            try {
                const now = new Date("2025-10-27T00:00:00Z");
                vi.setSystemTime(now);

                const timeoutIndex = 3;
                const payload = await handleTimeoutRequest(timeoutIndex);
                expect(payload).not.toBeUndefined();
                const status = payload!.readUInt8(1);
                const parentInfo = payload!.readUInt8(2);

                expect(status).toStrictEqual(0x00);
                expect(parentInfo).toStrictEqual(0b00000111);

                const device = context.deviceTable.get(child64)!;
                const metadata = device.endDeviceTimeout;
                expect(metadata?.timeoutIndex).toStrictEqual(timeoutIndex);
                const expectedMs = END_DEVICE_TIMEOUT_TABLE_MS[timeoutIndex]!;
                expect(metadata?.timeoutMs).toStrictEqual(expectedMs);
                expect(metadata?.lastUpdated).toStrictEqual(now.getTime());
                expect(metadata?.expiresAt).toStrictEqual(now.getTime() + expectedMs);
            } finally {
                vi.useRealTimers();
            }
        });

        it("rejects timeout indexes outside the Zigbee-defined range", async () => {
            const payload = await handleTimeoutRequest(0xff);
            expect(payload).not.toBeUndefined();

            expect(payload!.readUInt8(1)).toStrictEqual(0x01);
            expect(context.deviceTable.get(child64)?.endDeviceTimeout).toBeUndefined();
        });

        it("signals unsupported feature when the device is unknown", async () => {
            context.deviceTable.delete(child64);

            const sendSpy = vi.spyOn(nwkHandler, "sendEdTimeoutResponse");

            const payload = await handleTimeoutRequest(1, { source64: undefined });
            expect(payload).not.toBeUndefined();
            expect(payload!.readUInt8(1)).toStrictEqual(0x02);
            expect(sendSpy).toHaveBeenCalled();
            const lastCall = sendSpy.mock.calls.at(-1);
            expect(lastCall?.[2]).toStrictEqual(0x02);
        });

        it("allows overriding status and parent info in outgoing responses", async () => {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            try {
                await nwkHandler.sendEdTimeoutResponse(child16, 4, 0x02, 0x05);
            } finally {
                mockMACHandlerCallbacks.onSendFrame = vi.fn();
            }

            expect(frames).toHaveLength(1);
            const macFrame = decodeMACFramePayload(frames[0]!);
            const { nwkPayload } = decodeNWKFromMacFrame(macFrame, true);
            expect(nwkPayload.readUInt8(0)).toStrictEqual(ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE);
            expect(nwkPayload.readUInt8(1)).toStrictEqual(0x02);
            expect(nwkPayload.readUInt8(2)).toStrictEqual(0x05);
        });

        it("maintains previously stored metadata when new requests use identical timeout", async () => {
            const firstPayload = await handleTimeoutRequest(2);
            expect(firstPayload).not.toBeUndefined();
            expect(firstPayload!.readUInt8(1)).toStrictEqual(0x00);

            const before = context.deviceTable.get(child64)?.endDeviceTimeout;
            expect(before).not.toBeUndefined();

            const secondPayload = await handleTimeoutRequest(2);
            expect(secondPayload).not.toBeUndefined();
            expect(secondPayload!.readUInt8(1)).toStrictEqual(0x00);
            const after = context.deviceTable.get(child64)?.endDeviceTimeout;
            expect(after?.timeoutIndex).toStrictEqual(before?.timeoutIndex);
            expect(after?.timeoutMs).toStrictEqual(before?.timeoutMs);
            expect(after?.expiresAt).toBeGreaterThanOrEqual(before!.expiresAt);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §3.8: Network Constants
     * Network layer SHALL enforce specified constants and attributes.
     */
    describe("NWK Constants (Zigbee §3.8)", () => {
        const broadcastTargets: Array<{ description: string; destination: number }> = [
            {
                description: "all routers and the coordinator",
                destination: ZigbeeConsts.BCAST_DEFAULT,
            },
            {
                description: "all rx-on-when-idle devices",
                destination: ZigbeeConsts.BCAST_RX_ON_WHEN_IDLE,
            },
            {
                description: "devices advertising an unknown short address",
                destination: ZigbeeMACConsts.NO_ADDR16,
            },
            {
                description: "the entire PAN including sleepy end devices",
                destination: ZigbeeConsts.BCAST_SLEEPY,
            },
        ];

        for (const target of broadcastTargets) {
            it(`encodes broadcast frames for ${target.description} using MAC broadcast semantics`, async () => {
                const frames: Buffer[] = [];
                mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                    frames.push(Buffer.from(payload));
                    return Promise.resolve();
                });

                try {
                    const decodedMac = await captureMacFrame(
                        () =>
                            apsHandler.sendData(
                                Buffer.from([0x53, 0x79]),
                                ZigbeeNWKRouteDiscovery.SUPPRESS,
                                target.destination,
                                undefined,
                                ZigbeeAPSDeliveryMode.BCAST,
                                0x0104,
                                0x0104,
                                1,
                                1,
                                undefined,
                            ),
                        mockMACHandlerCallbacks,
                    );

                    const { nwkHeader } = decodeNWKFromMacFrame(decodedMac);

                    expect(decodedMac.header.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
                    expect(decodedMac.frameControl.ackRequest).toStrictEqual(false);
                    expect(nwkHeader.destination16).toStrictEqual(target.destination);
                } finally {
                    mockMACHandlerCallbacks.onSendFrame = vi.fn();
                }
            });
        }

        it("rejects broadcast destinations below the Zigbee reserved range", async () => {
            await expect(
                apsHandler.sendData(
                    Buffer.from([0x01, 0x02]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    ZigbeeConsts.BCAST_MIN - 1,
                    undefined,
                    ZigbeeAPSDeliveryMode.BCAST,
                    0x0104,
                    0x0104,
                    1,
                    1,
                    undefined,
                ),
            ).rejects.toThrow("Unknown destination");
        });

        it("schedules many-to-one route requests using the stack profile discovery interval", async () => {
            vi.useFakeTimers();
            vi.setSystemTime(new Date("2025-10-28T00:00:20Z"));
            const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0);
            const routeSpy = vi.spyOn(nwkHandler, "sendRouteReq").mockResolvedValue(true);

            try {
                await nwkHandler.start();

                expect(routeSpy).toHaveBeenCalledTimes(1);
                routeSpy.mockClear();

                vi.advanceTimersByTime(59_999);
                await vi.runAllTicks();
                expect(routeSpy).not.toHaveBeenCalled();

                vi.advanceTimersByTime(1);
                await vi.runAllTicks();
                expect(routeSpy).toHaveBeenCalledTimes(1);
            } finally {
                nwkHandler.stop();
                randomSpy.mockRestore();
                vi.useRealTimers();
            }
        });

        it("runs periodic link status transmissions on the configured interval", async () => {
            vi.useFakeTimers();
            vi.setSystemTime(new Date("2025-10-28T00:02:00Z"));
            const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0);
            const linkSpy = vi.spyOn(nwkHandler, "sendLinkStatus").mockResolvedValue();
            vi.spyOn(nwkHandler, "sendRouteReq").mockResolvedValue(true);

            try {
                await nwkHandler.start();

                expect(linkSpy).toHaveBeenCalledTimes(1);
                linkSpy.mockClear();

                vi.advanceTimersByTime(14_999);
                await vi.runAllTicks();
                expect(linkSpy).not.toHaveBeenCalled();

                vi.advanceTimersByTime(1);
                await vi.runAllTicks();
                expect(linkSpy).toHaveBeenCalledTimes(1);
            } finally {
                nwkHandler.stop();
                randomSpy.mockRestore();
                vi.useRealTimers();
            }
        });

        it("caps many-to-one route request radius to twice the default network depth", async () => {
            const frame = await captureMacFrame(
                () => nwkHandler.sendRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, 0x4455),
                mockMACHandlerCallbacks,
            );
            const { nwkHeader } = decodeNWKFromMacFrame(frame, true);

            expect(nwkHeader.radius).not.toBeUndefined();
            const radius = nwkHeader.radius!;

            expect(radius + 1).toStrictEqual(CONFIG_NWK_MAX_HOPS);
            expect((radius + 1) / 2).toStrictEqual(15);
        });

        // NOTE: stored on host, ignore max bound
        // it("denies additional router associations once nwkMaxRouters is reached", async () => {
        //     context.allowJoins(60, true);
        //     const saveSpy = vi.spyOn(context, "savePeriodicState").mockResolvedValue();
        //     let randomCounter = 0;
        //     const randomSpy = vi.spyOn(Math, "random").mockImplementation(() => {
        //         randomCounter += 1;
        //         return ((randomCounter % 900) + 1) / 1000;
        //     });

        //     const routerCapabilities: MACCapabilities = {
        //         alternatePANCoordinator: false,
        //         deviceType: 1,
        //         powerSource: 1,
        //         rxOnWhenIdle: true,
        //         securityCapability: true,
        //         allocateAddress: true,
        //     };

        //     try {
        //         for (let i = 0; i < CONFIG_NWK_MAX_ROUTERS; i += 1) {
        //             const device64 = TEST_DEVICE_EUI64 + BigInt(i + 1);
        //             const [status] = await context.associate(undefined, device64, true, routerCapabilities, true);
        //             expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
        //         }

        //         const extraDevice64 = TEST_DEVICE_EUI64 + BigInt(CONFIG_NWK_MAX_ROUTERS + 1);
        //         const [status, addr16] = await context.associate(undefined, extraDevice64, true, routerCapabilities, true);

        //         expect(status).toStrictEqual(MACAssociationStatus.PAN_FULL);
        //         expect(addr16).toStrictEqual(0xffff);
        //         expect(context.deviceTable.has(extraDevice64)).toStrictEqual(false);
        //     } finally {
        //         randomSpy.mockRestore();
        //         saveSpy.mockRestore();
        //     }
        // });

        // NOTE: stored on host, ignore max bound
        // it("denies additional direct children once nwkMaxChildren is reached", async () => {
        //     context.allowJoins(60, true);
        //     const saveSpy = vi.spyOn(context, "savePeriodicState").mockResolvedValue();
        //     let randomCounter = 0;
        //     const randomSpy = vi.spyOn(Math, "random").mockImplementation(() => {
        //         randomCounter += 1;
        //         return ((randomCounter % 900) + 1) / 1200;
        //     });

        //     const routerCapabilities: MACCapabilities = {
        //         alternatePANCoordinator: false,
        //         deviceType: 1,
        //         powerSource: 1,
        //         rxOnWhenIdle: true,
        //         securityCapability: true,
        //         allocateAddress: true,
        //     };
        //     const endDeviceCapabilities: MACCapabilities = {
        //         alternatePANCoordinator: false,
        //         deviceType: 0,
        //         powerSource: 0,
        //         rxOnWhenIdle: false,
        //         securityCapability: true,
        //         allocateAddress: true,
        //     };

        //     try {
        //         for (let i = 0; i < CONFIG_NWK_MAX_ROUTERS; i += 1) {
        //             const device64 = TEST_DEVICE_EUI64 + BigInt(i + 1);
        //             const [status] = await context.associate(undefined, device64, true, routerCapabilities, true);
        //             expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
        //         }

        //         for (let i = CONFIG_NWK_MAX_ROUTERS; i < CONFIG_NWK_MAX_CHILDREN; i += 1) {
        //             const device64 = TEST_DEVICE_EUI64 + BigInt(i + 1);
        //             const [status] = await context.associate(undefined, device64, true, endDeviceCapabilities, true);
        //             expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
        //         }

        //         const extraDevice64 = TEST_DEVICE_EUI64 + BigInt(CONFIG_NWK_MAX_CHILDREN + 1);
        //         const [status, addr16] = await context.associate(undefined, extraDevice64, true, endDeviceCapabilities, true);

        //         expect(status).toStrictEqual(MACAssociationStatus.PAN_FULL);
        //         expect(addr16).toStrictEqual(0xffff);
        //         expect(context.deviceTable.has(extraDevice64)).toStrictEqual(false);
        //     } finally {
        //         randomSpy.mockRestore();
        //         saveSpy.mockRestore();
        //     }
        // });

        // NOTE: stored on host, ignore max bound
        // it("truncates stored source routes beyond nwkMaxSourceRoute relays", () => {
        //     const source16 = 0x2468;
        //     const relayCount = CONFIG_NWK_MAX_SOURCE_ROUTE + 4;
        //     const payload = Buffer.alloc(1 + relayCount * 2);
        //     payload.writeUInt8(relayCount, 0);

        //     for (let i = 0; i < relayCount; i += 1) {
        //         payload.writeUInt16LE(0x3000 + i, 1 + i * 2);
        //     }

        //     const macHeader = { source16 } as MACHeader;
        //     const nwkHeader: ZigbeeNWKHeader = {
        //         frameControl: {
        //             frameType: ZigbeeNWKFrameType.CMD,
        //             protocolVersion: ZigbeeNWKConsts.VERSION_2007,
        //             discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
        //             multicast: false,
        //             security: false,
        //             sourceRoute: false,
        //             extendedDestination: false,
        //             extendedSource: false,
        //             endDeviceInitiator: false,
        //         },
        //         source16,
        //     };

        //     nwkHandler.processRouteRecord(payload, 0, macHeader, nwkHeader);

        //     const entries = context.sourceRouteTable.get(source16);
        //     expect(entries).not.toBeUndefined();
        //     const entry = entries![0]!;
        //     expect(entry.relayAddresses.length).toStrictEqual(CONFIG_NWK_MAX_SOURCE_ROUTE);
        //     expect(entry.relayAddresses).toStrictEqual(Array.from({ length: CONFIG_NWK_MAX_SOURCE_ROUTE }, (_, idx) => 0x3000 + idx));
        //     expect(entry.pathCost).toStrictEqual(CONFIG_NWK_MAX_SOURCE_ROUTE + 1);
        // });
    });
});
