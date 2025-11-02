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
    aes128MmoHash,
    computeInstallCodeCRC,
    makeKeyedHash,
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
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    type ZigbeeNWKHeader,
    ZigbeeNWKRouteDiscovery,
} from "../../src/zigbee/zigbee-nwk.js";
import { APSHandler, type APSHandlerCallbacks } from "../../src/zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../../src/zigbee-stack/nwk-gp-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import {
    ApplicationKeyRequestPolicy,
    InstallCodePolicy,
    type NetworkParameters,
    StackContext,
    type StackContextCallbacks,
    TrustCenterKeyRequestPolicy,
} from "../../src/zigbee-stack/stack-context.js";
import { NETDEF_EXTENDED_PAN_ID, NETDEF_NETWORK_KEY, NETDEF_PAN_ID, NETDEF_TC_KEY } from "../data.js";
import { createMACFrameControl } from "../utils.js";
import {
    captureMacFrame,
    cloneNetworkParameters,
    type DecodedMACFrame,
    decodeMACFramePayload,
    NO_ACK_CODE,
    registerNeighborDevice,
} from "./utils.js";

describe("Zigbee 3.0 Security Compliance", () => {
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
     * Zigbee Spec 05-3474-23 §4.3: Security Processing
     * Security processing SHALL use CCM* (counter with CBC-MAC) mode.
     */
    type CapturedNwkSecurity = {
        macFrame: DecodedMACFrame;
        nwkFrameControl: ReturnType<typeof decodeZigbeeNWKFrameControl>[0];
        nwkHeader: ZigbeeNWKHeader;
        securityHeader: ZigbeeSecurityHeader;
        rawSecurityControl: number;
        plaintextFrame: Buffer;
        ciphertext: Buffer;
        mic: Buffer;
        apsFrameControl: ReturnType<typeof decodeZigbeeAPSFrameControl>[0];
        apsHeader: ZigbeeAPSHeader;
        apsPayload: Buffer;
        ciphertextOffset: number;
        micOffset: number;
    };

    type CapturedApsSecurity = {
        macFrame: DecodedMACFrame;
        nwkPayload: Buffer;
        apsFrameControl: ReturnType<typeof decodeZigbeeAPSFrameControl>[0];
        apsHeader: ZigbeeAPSHeader;
        securityHeader: ZigbeeSecurityHeader;
        rawSecurityControl: number;
        ciphertext: Buffer;
        mic: Buffer;
        apsPayload: Buffer;
        ciphertextOffset: number;
        micOffset: number;
    };

    async function captureSecuredNwkFrame(destination16: number, destination64: bigint, apsPayload: Buffer): Promise<CapturedNwkSecurity> {
        const macFrame = await captureMacFrame(async () => {
            await apsHandler.sendData(
                apsPayload,
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                destination16,
                destination64,
                ZigbeeAPSDeliveryMode.UNICAST,
                0x0505,
                ZigbeeConsts.HA_PROFILE_ID,
                0x16,
                0x26,
                undefined,
            );
        }, mockMACHandlerCallbacks);

        const macPayload = macFrame.buffer.subarray(macFrame.payloadOffset, macFrame.buffer.length - ZigbeeMACConsts.FCS_LEN);
        const [nwkFrameControl, nwkHeaderOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkHeaderOffset, nwkFrameControl);
        const rawSecurityControl = macPayload[payloadOffset]!;
        const plaintextFrame = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
        const securityHeader = nwkHeader.securityHeader!;
        const securityHeaderLength = 1 + 4 + (securityHeader.control.nonce ? 8 : 0) + (securityHeader.control.keyId === ZigbeeKeyType.NWK ? 1 : 0);
        const encryptedStart = payloadOffset + securityHeaderLength;
        const encryptedAndMic = macPayload.subarray(encryptedStart);
        const ciphertextLength = encryptedAndMic.length - securityHeader.micLen!;
        const ciphertext = encryptedAndMic.subarray(0, ciphertextLength);
        const mic = encryptedAndMic.subarray(ciphertextLength);

        const [apsFrameControl, apsHeaderOffset] = decodeZigbeeAPSFrameControl(plaintextFrame, 0);
        const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(plaintextFrame, apsHeaderOffset, apsFrameControl);
        const decryptedApsPayload = decodeZigbeeAPSPayload(
            plaintextFrame,
            apsPayloadOffset,
            undefined,
            context.netParams.eui64,
            apsFrameControl,
            apsHeader,
        );

        return {
            macFrame,
            nwkFrameControl,
            nwkHeader,
            securityHeader,
            rawSecurityControl,
            plaintextFrame,
            ciphertext,
            mic,
            apsFrameControl,
            apsHeader,
            apsPayload: decryptedApsPayload,
            ciphertextOffset: macFrame.payloadOffset + encryptedStart,
            micOffset: macFrame.payloadOffset + encryptedStart + ciphertextLength,
        };
    }

    async function captureApsSecurityFrame(destination16: number, destination64: bigint): Promise<CapturedApsSecurity> {
        const macFrame = await captureMacFrame(async () => {
            await apsHandler.sendTransportKeyNWK(
                destination16,
                context.netParams.networkKey,
                context.netParams.networkKeySequenceNumber,
                destination64,
            );
        }, mockMACHandlerCallbacks);

        const macPayload = macFrame.buffer.subarray(macFrame.payloadOffset, macFrame.buffer.length - ZigbeeMACConsts.FCS_LEN);
        const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, apsOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, apsOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);

        const [apsFrameControl, apsHeaderOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, securityOffset] = decodeZigbeeAPSHeader(nwkPayload, apsHeaderOffset, apsFrameControl);
        const rawSecurityControl = nwkPayload[securityOffset]!;
        const decryptedApsPayload = decodeZigbeeAPSPayload(
            nwkPayload,
            securityOffset,
            undefined,
            context.netParams.eui64,
            apsFrameControl,
            apsHeader,
        );
        const securityHeader = apsHeader.securityHeader!;
        const securityHeaderLength = 1 + 4 + (securityHeader.control.nonce ? 8 : 0) + (securityHeader.control.keyId === ZigbeeKeyType.NWK ? 1 : 0);
        const encryptedStart = securityOffset + securityHeaderLength;
        const encryptedAndMic = nwkPayload.subarray(encryptedStart);
        const ciphertextLength = encryptedAndMic.length - securityHeader.micLen!;
        const ciphertext = encryptedAndMic.subarray(0, ciphertextLength);
        const mic = encryptedAndMic.subarray(ciphertextLength);

        return {
            macFrame,
            nwkPayload: Buffer.from(nwkPayload),
            apsFrameControl,
            apsHeader,
            securityHeader,
            rawSecurityControl,
            ciphertext,
            mic,
            apsPayload: decryptedApsPayload,
            ciphertextOffset: encryptedStart,
            micOffset: encryptedStart + ciphertextLength,
        };
    }

    describe("Security Processing (Zigbee §4.3)", () => {
        const device16 = 0x4c4d;
        const device64 = 0x00124b00ffee0001n;

        beforeEach(() => {
            registerNeighborDevice(context, device16, device64);
            context.deviceTable.get(device64)!.capabilities!.rxOnWhenIdle = true;
        });

        it("flags NWK frames as secured and encrypts the APS payload", async () => {
            const userPayload = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]);
            const frame = await captureSecuredNwkFrame(device16, device64, userPayload);

            expect(frame.nwkFrameControl.security).toStrictEqual(true);
            expect(frame.securityHeader.control.keyId).toStrictEqual(ZigbeeKeyType.NWK);
            expect(frame.securityHeader.micLen).toStrictEqual(4);
            expect(frame.ciphertext.length).toStrictEqual(frame.plaintextFrame.length);
            expect(frame.ciphertext.equals(frame.plaintextFrame)).toStrictEqual(false);
            expect(frame.mic.byteLength).toStrictEqual(frame.securityHeader.micLen);
            expect(frame.apsPayload).toStrictEqual(userPayload);
        });

        it("rejects NWK frames with tampered ciphertext", async () => {
            const frame = await captureSecuredNwkFrame(device16, device64, Buffer.from([0x01, 0x02]));
            const tampered = Buffer.from(frame.macFrame.buffer);
            tampered[frame.ciphertextOffset] ^= 0xff;

            const macPayload = tampered.subarray(frame.macFrame.payloadOffset, tampered.length - ZigbeeMACConsts.FCS_LEN);
            const [nwkFrameControl, nwkHeaderOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkHeaderOffset, nwkFrameControl);

            expect(() =>
                decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader),
            ).toThrowError("Auth tag mismatch");
        });

        it("rejects NWK frames with tampered authentication tags", async () => {
            const frame = await captureSecuredNwkFrame(device16, device64, Buffer.from([0x10, 0x20]));
            const tampered = Buffer.from(frame.macFrame.buffer);
            tampered[frame.micOffset + frame.mic.length - 1]! ^= 0x01;

            const macPayload = tampered.subarray(frame.macFrame.payloadOffset, tampered.length - ZigbeeMACConsts.FCS_LEN);
            const [nwkFrameControl, nwkHeaderOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkHeaderOffset, nwkFrameControl);

            expect(() =>
                decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader),
            ).toThrowError("Auth tag mismatch");
        });

        it("encrypts APS transport key payloads", async () => {
            const frame = await captureApsSecurityFrame(device16, device64);

            expect(frame.apsFrameControl.security).toStrictEqual(true);
            expect(frame.ciphertext.length).toStrictEqual(frame.apsPayload.length);
            expect(frame.ciphertext.equals(frame.apsPayload)).toStrictEqual(false);
            expect(frame.mic.byteLength).toStrictEqual(frame.securityHeader.micLen);
            expect(frame.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
        });

        it("rejects APS transport key frames with tampered ciphertext", async () => {
            const frame = await captureApsSecurityFrame(device16, device64);
            const tampered = Buffer.from(frame.nwkPayload);
            tampered[frame.ciphertextOffset] ^= 0x01;

            const [apsFrameControl, apsHeaderOffset] = decodeZigbeeAPSFrameControl(tampered, 0);
            const [apsHeader, securityOffset] = decodeZigbeeAPSHeader(tampered, apsHeaderOffset, apsFrameControl);

            expect(() =>
                decodeZigbeeAPSPayload(tampered, securityOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader),
            ).toThrowError("Auth tag mismatch");
        });

        it("rejects APS transport key frames with tampered authentication tags", async () => {
            const frame = await captureApsSecurityFrame(device16, device64);
            const tampered = Buffer.from(frame.nwkPayload);
            tampered[frame.micOffset + frame.mic.length - 1]! ^= 0x01;

            const [apsFrameControl, apsHeaderOffset] = decodeZigbeeAPSFrameControl(tampered, 0);
            const [apsHeader, securityOffset] = decodeZigbeeAPSHeader(tampered, apsHeaderOffset, apsFrameControl);

            expect(() =>
                decodeZigbeeAPSPayload(tampered, securityOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader),
            ).toThrowError("Auth tag mismatch");
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.3.1: Security Levels
     * Zigbee SHALL use security level 5 (encryption + 32-bit MIC).
     */
    describe("Security Levels (Zigbee §4.3.1)", () => {
        const device16 = 0x5577;
        const device64 = 0x00124b00ffee0002n;

        beforeEach(() => {
            registerNeighborDevice(context, device16, device64);
            context.deviceTable.get(device64)!.capabilities!.rxOnWhenIdle = true;
        });

        it("uses Zigbee security level 5 for NWK-secured frames", async () => {
            const frame = await captureSecuredNwkFrame(device16, device64, Buffer.from([0x33]));

            expect(frame.securityHeader.control.level).toStrictEqual(ZigbeeSecurityLevel.ENC_MIC32);
            expect(frame.securityHeader.micLen).toStrictEqual(4);
            expect(frame.rawSecurityControl & ZigbeeConsts.SEC_CONTROL_LEVEL).toStrictEqual(ZigbeeSecurityLevel.NONE);
            expect(frame.securityHeader.source64).toStrictEqual(context.netParams.eui64);
        });

        it("uses Zigbee security level 5 for APS encrypted commands", async () => {
            const frame = await captureApsSecurityFrame(device16, device64);

            expect(frame.securityHeader.control.level).toStrictEqual(ZigbeeSecurityLevel.ENC_MIC32);
            expect(frame.securityHeader.control.keyId).toStrictEqual(ZigbeeKeyType.TRANSPORT);
            expect(frame.securityHeader.micLen).toStrictEqual(4);
            expect(frame.rawSecurityControl & ZigbeeConsts.SEC_CONTROL_LEVEL).toStrictEqual(ZigbeeSecurityLevel.NONE);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.3.2: Frame Counters
     * Frame counters SHALL be maintained per key and SHALL NOT repeat.
     */
    function decodeSecurityFrame(frame: DecodedMACFrame) {
        const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
        const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
        const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
        const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsPayloadOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader);

        return { nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload, nwkPayload };
    }

    describe("Frame Counters (Zigbee §4.3.2)", () => {
        const device16 = 0x4c4d;
        const device64 = 0x00124b00ffee0001n;
        const frameCounterJumpOffset = 1024;

        beforeEach(() => {
            registerNeighborDevice(context, device16, device64);
            context.deviceTable.get(device64)!.capabilities!.rxOnWhenIdle = true;
        });

        async function sendSecuredData(): Promise<{
            macFrame: DecodedMACFrame;
            decoded: ReturnType<typeof decodeSecurityFrame>;
            apsCounter: number;
        }> {
            let apsCounter: number | undefined;
            const macFrame = await captureMacFrame(async () => {
                apsCounter = await apsHandler.sendData(
                    Buffer.from([0x33, 0x44]),
                    ZigbeeNWKRouteDiscovery.SUPPRESS,
                    device16,
                    device64,
                    ZigbeeAPSDeliveryMode.UNICAST,
                    0x0505,
                    ZigbeeConsts.HA_PROFILE_ID,
                    0x16,
                    0x26,
                    undefined,
                );
            }, mockMACHandlerCallbacks);

            return { macFrame, decoded: decodeSecurityFrame(macFrame), apsCounter: apsCounter! };
        }

        async function acknowledgeDelivery(
            apsCounter: number,
            macFrame: DecodedMACFrame,
            decoded: ReturnType<typeof decodeSecurityFrame>,
        ): Promise<void> {
            const ackMacHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: macFrame.header.sequenceNumber,
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
                seqNum: decoded.nwkHeader.seqNum,
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
                destEndpoint: decoded.apsHeader.sourceEndpoint,
                clusterId: decoded.apsHeader.clusterId,
                profileId: decoded.apsHeader.profileId,
                sourceEndpoint: decoded.apsHeader.destEndpoint,
                counter: apsCounter,
            };

            await apsHandler.processFrame(Buffer.alloc(0), ackMacHeader, ackNwkHeader, ackAPSHeader, 0x70);
        }

        async function reloadContextWithHandlers(): Promise<void> {
            const reloaded = new StackContext(mockStackContextCallbacks, join(saveDir, "zoh.save"), cloneNetworkParameters(netParams));
            await reloaded.loadState();

            const reloadedMacHandler = new MACHandler(reloaded, mockMACHandlerCallbacks, NO_ACK_CODE);
            const reloadedNWKHandler = new NWKHandler(reloaded, reloadedMacHandler, mockNWKHandlerCallbacks);
            const reloadedAPSHandler = new APSHandler(reloaded, reloadedMacHandler, reloadedNWKHandler, mockAPSHandlerCallbacks);

            context = reloaded;
            netParams = reloaded.netParams;
            macHandler = reloadedMacHandler;
            nwkHandler = reloadedNWKHandler;
            apsHandler = reloadedAPSHandler;

            const reloadedDevice = context.deviceTable.get(device64);
            expect(reloadedDevice).not.toBeUndefined();
            if (reloadedDevice?.capabilities !== undefined) {
                reloadedDevice.capabilities.rxOnWhenIdle = true;
            }

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        }

        it("increments the NWK security frame counter for each secured transmission", async () => {
            const first = await sendSecuredData();
            const firstCounter = first.decoded.nwkHeader.securityHeader?.frameCounter;
            expect(firstCounter).not.toBeUndefined();
            await acknowledgeDelivery(first.apsCounter, first.macFrame, first.decoded);

            const second = await sendSecuredData();
            const secondCounter = second.decoded.nwkHeader.securityHeader?.frameCounter;
            expect(secondCounter).not.toBeUndefined();

            expect(secondCounter).toStrictEqual(((firstCounter! + 1) & 0xffffffff) >>> 0);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(secondCounter);

            await acknowledgeDelivery(second.apsCounter, second.macFrame, second.decoded);
            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("rejects replayed incoming NWK frame counters per device", () => {
            const otherDevice64 = 0x00124b00ffee0002n;
            registerNeighborDevice(context, 0x5a5a, otherDevice64);

            expect(context.updateIncomingNWKFrameCounter(device64, 10)).toStrictEqual(true);
            expect(context.updateIncomingNWKFrameCounter(device64, 10)).toStrictEqual(false);
            expect(context.updateIncomingNWKFrameCounter(device64, 9)).toStrictEqual(false);
            expect(context.updateIncomingNWKFrameCounter(device64, 11)).toStrictEqual(true);

            expect(context.updateIncomingNWKFrameCounter(otherDevice64, 1)).toStrictEqual(true);
            expect(context.updateIncomingNWKFrameCounter(otherDevice64, 0)).toStrictEqual(false);
        });

        it("accepts frame counter wrap from 0xffffffff to 0", () => {
            const device = context.deviceTable.get(device64)!;
            device.incomingNWKFrameCounter = 0xffffffff;

            expect(context.updateIncomingNWKFrameCounter(device64, 0)).toStrictEqual(true);
        });

        it("persists secured NWK frame counters across saves and reloads", async () => {
            const first = await sendSecuredData();
            const firstCounter = first.decoded.nwkHeader.securityHeader?.frameCounter;
            expect(firstCounter).not.toBeUndefined();

            await acknowledgeDelivery(first.apsCounter, first.macFrame, first.decoded);
            mockMACHandlerCallbacks.onSendFrame = vi.fn();

            await context.saveState();

            const reloadedContext = new StackContext(mockStackContextCallbacks, join(saveDir, "zoh.save"), cloneNetworkParameters(netParams));
            await reloadedContext.loadState();

            expect(reloadedContext.netParams.networkKeyFrameCounter).toStrictEqual(((firstCounter! + frameCounterJumpOffset) & 0xffffffff) >>> 0);
            expect(reloadedContext.netParams.tcKeyFrameCounter).toStrictEqual(frameCounterJumpOffset);

            reloadedContext.disallowJoins();
        });

        it("resumes secured transmissions with advanced frame counters after reboot", async () => {
            const first = await sendSecuredData();
            const firstCounter = first.decoded.nwkHeader.securityHeader?.frameCounter ?? 0;
            await acknowledgeDelivery(first.apsCounter, first.macFrame, first.decoded);
            mockMACHandlerCallbacks.onSendFrame = vi.fn();

            await context.saveState();
            await reloadContextWithHandlers();

            const baseCounter = context.netParams.networkKeyFrameCounter;
            expect(baseCounter).toStrictEqual(((firstCounter + frameCounterJumpOffset) & 0xffffffff) >>> 0);

            const reloadedSend = await sendSecuredData();
            const reloadedCounter = reloadedSend.decoded.nwkHeader.securityHeader?.frameCounter;
            expect(reloadedCounter).toStrictEqual(((baseCounter + 1) & 0xffffffff) >>> 0);
            expect(reloadedCounter).toBeGreaterThan(firstCounter + frameCounterJumpOffset);

            await acknowledgeDelivery(reloadedSend.apsCounter, reloadedSend.macFrame, reloadedSend.decoded);
            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("maintains independent NWK and TC key frame counters", async () => {
            const secured = await sendSecuredData();
            await acknowledgeDelivery(secured.apsCounter, secured.macFrame, secured.decoded);
            mockMACHandlerCallbacks.onSendFrame = vi.fn();

            const nwkCounterAfterData = context.netParams.networkKeyFrameCounter;
            expect(nwkCounterAfterData).toBeGreaterThan(0);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(0);

            const capturedTransport = await captureApsSecurityFrame(device16, device64);
            const tcCounterAfterTransport = context.netParams.tcKeyFrameCounter;
            expect(tcCounterAfterTransport).toStrictEqual(1);
            expect(capturedTransport.securityHeader.frameCounter).toStrictEqual(tcCounterAfterTransport);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(nwkCounterAfterData);

            const second = await sendSecuredData();
            await acknowledgeDelivery(second.apsCounter, second.macFrame, second.decoded);
            mockMACHandlerCallbacks.onSendFrame = vi.fn();

            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(((nwkCounterAfterData + 1) & 0xffffffff) >>> 0);
            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(tcCounterAfterTransport);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.5: Trust Center
     * Trust Center SHALL manage network security and key distribution.
     */
    describe("Trust Center Operations (Zigbee §4.5)", () => {
        function decodeCommandFrame(frame: Buffer) {
            const macFrame = decodeMACFramePayload(frame);
            const macPayload = macFrame.buffer.subarray(macFrame.payloadOffset, macFrame.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
            const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsPayloadOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader);

            return { macFrame, nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload };
        }

        it("acts as Trust Center by provisioning new devices and scheduling network key transport", async () => {
            context.allowJoins(60, true);

            const device64 = 0x00124b00ff110001n;
            const capabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            };
            const capabilitiesByte = encodeMACCapabilities(capabilities);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });
            mockMACHandlerCallbacks.onAPSSendTransportKeyNWK = vi.fn(async (dest16, key, seqNum, dest64) => {
                await apsHandler.sendTransportKeyNWK(dest16, key, seqNum, dest64);
            });

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x11,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0xfffe,
                source64: device64,
                commandId: MACCommandId.ASSOC_REQ,
                fcs: 0,
            };

            await macHandler.processAssocReq(Buffer.from([capabilitiesByte]), 0, macHeader);

            const pending = context.pendingAssociations.get(device64);
            expect(pending).not.toBeUndefined();
            await pending!.sendResp();

            const deviceEntry = context.deviceTable.get(device64);
            expect(deviceEntry).not.toBeUndefined();
            expect(deviceEntry?.authorized).toStrictEqual(false);

            expect(mockMACHandlerCallbacks.onAPSSendTransportKeyNWK).toHaveBeenCalledTimes(1);
            const assigned16 = deviceEntry?.address16;
            expect(mockMACHandlerCallbacks.onAPSSendTransportKeyNWK).toHaveBeenCalledWith(
                assigned16,
                context.netParams.networkKey,
                context.netParams.networkKeySequenceNumber,
                device64,
            );

            const transportFrame = frames
                .map((frame) => {
                    try {
                        return decodeCommandFrame(frame);
                    } catch {
                        return undefined;
                    }
                })
                .find((decoded) => decoded !== undefined && decoded.apsPayload.readUInt8(0) === ZigbeeAPSCommandId.TRANSPORT_KEY);

            expect(transportFrame).not.toBeUndefined();
            expect(transportFrame!.apsFrameControl.security).toStrictEqual(true);
            expect(transportFrame!.apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK);
            expect(transportFrame!.apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.networkKey);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
            mockMACHandlerCallbacks.onAPSSendTransportKeyNWK = vi.fn();
            context.disallowJoins();
        });

        it("derives the trust center verify key hash from the link key", () => {
            const expected = makeKeyedHash(context.netParams.tcKey, 0x03);
            expect(context.tcVerifyKeyHash).toStrictEqual(expected);
        });

        it("tunnels network keys to children announced by parent routers", async () => {
            const parent16 = 0x3344;
            const parent64 = 0x00124b00ff220002n;
            const child16 = 0x5566;
            const child64 = 0x00124b00ff330003n;

            registerNeighborDevice(context, parent16, parent64);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.alloc(1 + 8 + 2 + 1);
            let offset = 0;
            payload.writeUInt8(ZigbeeAPSCommandId.UPDATE_DEVICE, offset);
            offset += 1;
            payload.writeBigUInt64LE(child64, offset);
            offset += 8;
            payload.writeUInt16LE(child16, offset);
            offset += 2;
            payload.writeUInt8(0x01, offset);
            offset += 1;

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x21,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: parent16,
                source64: parent64,
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
                counter: 0x23,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            const childEntry = context.deviceTable.get(child64);
            expect(childEntry).not.toBeUndefined();
            expect(childEntry?.authorized).toStrictEqual(false);

            const tunnelFrame = frames
                .map((frame) => {
                    try {
                        return decodeCommandFrame(frame);
                    } catch {
                        return undefined;
                    }
                })
                .find((decoded) => decoded !== undefined && decoded.apsPayload.readUInt8(0) === ZigbeeAPSCommandId.TUNNEL);

            expect(tunnelFrame).not.toBeUndefined();
            expect(tunnelFrame!.apsFrameControl.security).toStrictEqual(false);
            const destination64 = tunnelFrame!.apsPayload.readBigUInt64LE(1);
            expect(destination64).toStrictEqual(child64);
            const embedded = tunnelFrame!.apsPayload.subarray(1 + 8);
            const [embeddedFrameControl, embeddedOffset] = decodeZigbeeAPSFrameControl(embedded, 0);
            const [embeddedHeader, embeddedPayloadOffset] = decodeZigbeeAPSHeader(embedded, embeddedOffset, embeddedFrameControl);
            const embeddedPayload = decodeZigbeeAPSPayload(
                embedded,
                embeddedPayloadOffset,
                undefined,
                context.netParams.eui64,
                embeddedFrameControl,
                embeddedHeader,
            );

            expect(embeddedFrameControl.frameType).toStrictEqual(ZigbeeAPSFrameType.CMD);
            expect(embeddedFrameControl.security).toStrictEqual(true);
            expect(embeddedPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(embeddedPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK);
            expect(embeddedPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(context.netParams.networkKey);
            expect(embeddedHeader.counter).not.toBeUndefined();

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("enforces trust center link key request policy", async () => {
            const device16 = 0x6a6b;
            const device64 = 0x00124b00ff440004n;
            registerNeighborDevice(context, device16, device64);

            mockMACHandlerCallbacks.onSendFrame = vi.fn(() => Promise.resolve());

            const payload = Buffer.alloc(1 + 1);
            payload.writeUInt8(ZigbeeAPSCommandId.REQUEST_KEY, 0);
            payload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_TC_LINK, 1);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x31,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
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
                seqNum: 0x32,
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

            context.trustCenterPolicies.allowTCKeyRequest = TrustCenterKeyRequestPolicy.DISALLOWED;
            await apsHandler.processCommand(Buffer.from(payload), macHeader, nwkHeader, apsHeader);
            expect(mockMACHandlerCallbacks.onSendFrame).not.toHaveBeenCalled();

            context.trustCenterPolicies.allowTCKeyRequest = TrustCenterKeyRequestPolicy.ALLOWED;
            await apsHandler.processCommand(Buffer.from(payload), macHeader, nwkHeader, apsHeader);
            expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalled();

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.6.3.2: Well-Known Keys
     * Well-known keys SHALL be used according to Zigbee 3.0 specification.
     */
    describe("Well-Known Keys (Zigbee §4.6.3.2)", () => {
        it("precomputes the trust center verify hash for the ZigBeeAlliance09 link key", () => {
            const expected = makeKeyedHash(context.netParams.tcKey, 0x03);

            expect(context.tcVerifyKeyHash.equals(expected)).toStrictEqual(true);
        });

        it("derives transport and load hashed keys from the trust center link key", () => {
            const transportKey = makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, context.netParams.tcKey);
            const loadKey = makeKeyedHashByType(ZigbeeKeyType.LOAD, context.netParams.tcKey);
            const expectedTransport = makeKeyedHash(context.netParams.tcKey, 0x00);
            const expectedLoad = makeKeyedHash(context.netParams.tcKey, 0x02);

            expect(transportKey.equals(expectedTransport)).toStrictEqual(true);
            expect(loadKey.equals(expectedLoad)).toStrictEqual(true);
        });

        it("avoids broadcasting the ZigBeeAlliance09 link key as the distributed network key", async () => {
            const captured = await captureApsSecurityFrame(ZigbeeConsts.BCAST_DEFAULT, 0n);
            const transportedKey = captured.apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH);

            expect(transportedKey.equals(NETDEF_TC_KEY)).toStrictEqual(false);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.6.3.4: Install Codes
     * Install codes SHALL be used to derive preconfigured link keys.
     */
    describe("Install Codes (Zigbee §4.6.3.4)", () => {
        function makeInstallCodeBuffer(data: Buffer): Buffer {
            const buffer = Buffer.allocUnsafe(data.length + 2);
            const crc = computeInstallCodeCRC(data);

            data.copy(buffer, 0);
            buffer.writeUInt16LE(crc, data.length);

            return buffer;
        }

        it("rejects install codes when the trust center policy does not support them", () => {
            const device64 = 0x00124b00ffee0000n;
            const code = Buffer.from("00112233445566778899aabbccddeeff", "hex");
            const installCode = makeInstallCodeBuffer(code);

            context.trustCenterPolicies.installCode = InstallCodePolicy.NOT_SUPPORTED;

            expect(() => context.addInstallCode(device64, installCode)).toThrowError(
                "Install codes are not supported by the current Trust Center policy",
            );
        });

        it("derives link keys from install codes using AES-128 MMO hash", () => {
            const device64 = 0x00124b00ffee0101n;
            const code = Buffer.from("112233445566778899aabbccddeeff00", "hex");
            const installCode = makeInstallCodeBuffer(code);
            const derived = context.addInstallCode(device64, installCode);
            const expected = aes128MmoHash(code);
            const stored = context.installCodeTable.get(device64)?.key;
            const linkKey = context.getAppLinkKey(device64, context.netParams.eui64);

            expect(derived.equals(expected)).toStrictEqual(true);
            expect(stored?.equals(expected)).toStrictEqual(true);
            expect(linkKey?.equals(expected)).toStrictEqual(true);
        });

        it("rejects install codes with invalid CRC", () => {
            const device64 = 0x00124b00ffee0202n;
            const code = Buffer.from("8899aabbccddeeff0011223344556677", "hex");
            const invalid = Buffer.concat([code, Buffer.from([0x00, 0x00])]);

            expect(() => context.addInstallCode(device64, invalid)).toThrowError("Invalid install code CRC");
        });

        it("enforces install code policy when required by the trust center", async () => {
            const device64 = 0x00124b00ffee0303n;
            const caps: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            };

            context.trustCenterPolicies.installCode = InstallCodePolicy.REQUIRED;
            context.allowJoins(60, true);

            const [statusWithoutCode] = await context.associate(undefined, device64, true, caps, true);

            expect(statusWithoutCode).toStrictEqual(MACAssociationStatus.PAN_ACCESS_DENIED);

            const code = Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex");
            const installCode = makeInstallCodeBuffer(code);
            context.addInstallCode(device64, installCode);

            const [statusWithCode, assignedAddress] = await context.associate(undefined, device64, true, caps, true);

            expect(statusWithCode).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(assignedAddress).not.toStrictEqual(0xffff);
            expect(context.getAppLinkKey(device64, context.netParams.eui64)).toBeDefined();
        });

        it("allows joins without install codes when policy is not required", async () => {
            const device64 = 0x00124b00ffee0404n;
            const caps: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 0,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            };

            context.trustCenterPolicies.installCode = InstallCodePolicy.NOT_REQUIRED;
            context.allowJoins(60, true);

            const [status, assignedAddress] = await context.associate(undefined, device64, true, caps, true);

            expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
            expect(assignedAddress).not.toStrictEqual(0xffff);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.6.3.5: Network Key Update
     * Network key update SHALL allow periodic key rotation.
     */
    describe("Network Key Update (Zigbee §4.6.3.5)", () => {
        function decodeSwitchKeyFrame(frame: DecodedMACFrame) {
            const macPayload = frame.buffer.subarray(frame.payloadOffset, frame.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
            const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsPayloadOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader);

            return { macHeader: frame.header, nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload };
        }

        it("encodes switch key command for unicast delivery with NWK security", async () => {
            const device16 = 0x4010;
            const device64 = 0x00124b00aa550001n;
            registerNeighborDevice(context, device16, device64);

            const macFrame = await captureMacFrame(() => apsHandler.sendSwitchKey(device16, 0x11), mockMACHandlerCallbacks);
            const decoded = decodeSwitchKeyFrame(macFrame);

            expect(decoded.macHeader.destination16).toStrictEqual(device16);
            expect(decoded.nwkFrameControl.security).toStrictEqual(true);
            expect(decoded.nwkHeader.destination16).toStrictEqual(device16);
            expect(decoded.apsFrameControl.security).toStrictEqual(false);
            expect(decoded.apsPayload.byteLength).toStrictEqual(2);
            expect(decoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.SWITCH_KEY);
            expect(decoded.apsPayload.readUInt8(1)).toStrictEqual(0x11);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("encodes switch key command for broadcast updates", async () => {
            const macFrame = await captureMacFrame(() => apsHandler.sendSwitchKey(ZigbeeConsts.BCAST_DEFAULT, 0x22), mockMACHandlerCallbacks);
            const decoded = decodeSwitchKeyFrame(macFrame);

            expect(decoded.macHeader.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
            expect(decoded.nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(decoded.nwkFrameControl.security).toStrictEqual(true);
            expect(decoded.apsPayload.readUInt8(1)).toStrictEqual(0x22);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("broadcasts transport key payload with zero IEEE destination when updating all devices", async () => {
            const newKey = Buffer.from("00112233445566778899aabbccddeeff", "hex");
            const macFrame = await captureMacFrame(
                () => apsHandler.sendTransportKeyNWK(ZigbeeConsts.BCAST_DEFAULT, newKey, 0x33, 0n),
                mockMACHandlerCallbacks,
            );

            const decoded = decodeSwitchKeyFrame(macFrame);
            expect(decoded.macHeader.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
            expect(decoded.nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(decoded.apsFrameControl.security).toStrictEqual(true);
            expect(decoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(decoded.apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK);
            expect(decoded.apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(newKey);
            const destOffset = 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 1;
            expect(decoded.apsPayload.readBigUInt64LE(destOffset)).toStrictEqual(0n);
            expect(decoded.apsPayload.readBigUInt64LE(destOffset + 8)).toStrictEqual(context.netParams.eui64);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("activates staged network key only after receiving switch key", async () => {
            const originalKey = Buffer.from(context.netParams.networkKey);
            const originalSeq = context.netParams.networkKeySequenceNumber;
            context.netParams.networkKeyFrameCounter = 42;

            const pendingKey = Buffer.from("fedcba98765432100123456789abcdef", "hex");
            const pendingSeq = 0x44;
            context.setPendingNetworkKey(pendingKey, pendingSeq);

            expect(context.netParams.networkKey).toStrictEqual(originalKey);
            expect(context.netParams.networkKeySequenceNumber).toStrictEqual(originalSeq);

            const payload = Buffer.from([ZigbeeAPSCommandId.SWITCH_KEY, pendingSeq]);
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x40,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x1234,
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
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x1234,
                radius: 5,
                seqNum: 0x41,
            };
            const apsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.CMD,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: true,
                    extendedHeader: false,
                },
                counter: 0x42,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(context.netParams.networkKey).toStrictEqual(pendingKey);
            expect(context.netParams.networkKeySequenceNumber).toStrictEqual(pendingSeq);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(0);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.6.3.6: Trust Center Link Key Update
     * TC link key update SHALL use APS request/verify/confirm key commands.
     */
    describe("Trust Center Link Key Update (Zigbee §4.6.3.6)", () => {
        const tcLinkKey = Buffer.from("8899aabbccddeeff0011223344556677", "hex");

        function decodeCommandFrame(frame: Buffer) {
            const macFrame = decodeMACFramePayload(frame);
            const macPayload = macFrame.buffer.subarray(macFrame.payloadOffset, macFrame.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
            const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsPayloadOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader);

            return { macHeader: macFrame.header, nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload };
        }

        it("sends device-specific TC link key transport with APS LOAD security", async () => {
            const device16 = 0x6123;
            const device64 = 0x00124b00bb660001n;
            registerNeighborDevice(context, device16, device64);

            const macFrame = await captureMacFrame(() => apsHandler.sendTransportKeyTC(device16, tcLinkKey, device64), mockMACHandlerCallbacks);
            const decoded = decodeCommandFrame(macFrame.buffer);

            expect(decoded.macHeader.destination16).toStrictEqual(device16);
            expect(decoded.nwkHeader.destination16).toStrictEqual(device16);
            expect(decoded.apsFrameControl.security).toStrictEqual(true);
            expect(decoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(decoded.apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_TC_LINK);
            expect(decoded.apsPayload.subarray(2, 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(tcLinkKey);
            const destOffset = 2 + ZigbeeAPSConsts.CMD_KEY_LENGTH;
            expect(decoded.apsPayload.readBigUInt64LE(destOffset)).toStrictEqual(device64);
            expect(decoded.apsPayload.readBigUInt64LE(destOffset + 8)).toStrictEqual(context.netParams.eui64);
            expect(decoded.apsFrameControl.security).toStrictEqual(true);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("broadcasts TC link key transport to all devices", async () => {
            const macFrame = await captureMacFrame(
                () => apsHandler.sendTransportKeyTC(ZigbeeConsts.BCAST_DEFAULT, tcLinkKey, 0n),
                mockMACHandlerCallbacks,
            );
            const decoded = decodeCommandFrame(macFrame.buffer);

            expect(decoded.macHeader.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
            expect(decoded.nwkHeader.destination16).toStrictEqual(ZigbeeConsts.BCAST_DEFAULT);
            expect(decoded.apsPayload.readBigUInt64LE(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(0n);
            expect(decoded.apsPayload.readBigUInt64LE(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 8)).toStrictEqual(context.netParams.eui64);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("issues verify key command after transporting TC link key", async () => {
            const device16 = 0x6345;
            const device64 = 0x00124b00bb660022n;
            registerNeighborDevice(context, device16, device64);

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            await apsHandler.sendTransportKeyTC(device16, tcLinkKey, device64);
            await apsHandler.sendVerifyKey(device16, ZigbeeAPSConsts.CMD_KEY_TC_LINK, device64, context.tcVerifyKeyHash);

            expect(frames).toHaveLength(2);
            const verifyDecoded = decodeCommandFrame(frames[1]!);

            expect(verifyDecoded.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.VERIFY_KEY);
            expect(verifyDecoded.apsPayload.subarray(10)).toStrictEqual(context.tcVerifyKeyHash);
            expect(verifyDecoded.apsFrameControl.security).toStrictEqual(false);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("responds with confirm key success when device proves TC link key", async () => {
            const device16 = 0x6446;
            const device64 = 0x00124b00bb660033n;
            registerNeighborDevice(context, device16, device64);

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
                sequenceNumber: 0x51,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
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
                seqNum: 0x52,
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
                counter: 0x53,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(1);
            const confirm = decodeCommandFrame(frames[0]!);
            expect(confirm.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.CONFIRM_KEY);
            expect(confirm.apsPayload.readUInt8(1)).toStrictEqual(0x00);
            expect(confirm.apsPayload.readUInt8(2)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_TC_LINK);

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("enforces TC link key request policy during update requests", async () => {
            const device16 = 0x6556;
            const device64 = 0x00124b00bb660044n;
            registerNeighborDevice(context, device16, device64);

            const requestPayload = Buffer.from([ZigbeeAPSCommandId.REQUEST_KEY, ZigbeeAPSConsts.CMD_KEY_TC_LINK]);
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x60,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
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

            mockMACHandlerCallbacks.onSendFrame = vi.fn(() => Promise.resolve());

            context.trustCenterPolicies.allowTCKeyRequest = TrustCenterKeyRequestPolicy.DISALLOWED;
            await apsHandler.processCommand(Buffer.from(requestPayload), macHeader, nwkHeader, apsHeader);
            expect(mockMACHandlerCallbacks.onSendFrame).not.toHaveBeenCalled();

            context.trustCenterPolicies.allowTCKeyRequest = TrustCenterKeyRequestPolicy.ALLOWED;
            await apsHandler.processCommand(Buffer.from(requestPayload), macHeader, nwkHeader, apsHeader);
            expect(mockMACHandlerCallbacks.onSendFrame).toHaveBeenCalled();

            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.6.3.7: Application Link Keys
     * Application link keys SHALL be established between communicating devices.
     */
    describe("Application Link Keys (Zigbee §4.6.3.7)", () => {
        const requester16 = 0x6a01;
        const requester64 = 0x00124b00ccdd1100n;
        const partner16 = 0x6a02;
        const partner64 = 0x00124b00ccdd2200n;

        function decodeAppLinkTransport(frame: Buffer) {
            const macFrame = decodeMACFramePayload(frame);
            const macPayload = macFrame.buffer.subarray(macFrame.payloadOffset, macFrame.buffer.length - 2);
            const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, context.netParams.eui64, nwkFrameControl, nwkHeader);
            const [apsFrameControl, apsOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsPayloadOffset] = decodeZigbeeAPSHeader(nwkPayload, apsOffset, apsFrameControl);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsPayloadOffset, undefined, context.netParams.eui64, apsFrameControl, apsHeader);

            return { macFrame, nwkFrameControl, nwkHeader, apsFrameControl, apsHeader, apsPayload };
        }

        async function simulateApplicationKeyRequest(): Promise<Buffer[]> {
            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.alloc(1 + 1 + 8);
            payload.writeUInt8(ZigbeeAPSCommandId.REQUEST_KEY, 0);
            payload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_APP_MASTER, 1);
            payload.writeBigUInt64LE(partner64, 2);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x70,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: requester16,
                source64: requester64,
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
                source16: requester16,
                source64: requester64,
                radius: 5,
                seqNum: 0x71,
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
                counter: 0x72,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            return frames;
        }

        beforeEach(() => {
            registerNeighborDevice(context, requester16, requester64);
            registerNeighborDevice(context, partner16, partner64);
            context.trustCenterPolicies.allowAppKeyRequest = ApplicationKeyRequestPolicy.ALLOWED;
        });

        afterEach(() => {
            context.trustCenterPolicies.allowAppKeyRequest = ApplicationKeyRequestPolicy.DISALLOWED;
            mockMACHandlerCallbacks.onSendFrame = vi.fn();
        });

        it("processes application link key requests at the Trust Center", async () => {
            const frames = await simulateApplicationKeyRequest();

            expect(frames).toHaveLength(2);
            const requesterFrame = decodeAppLinkTransport(frames[0]!);

            expect(requesterFrame.macFrame.header.destination16).toStrictEqual(requester16);
            expect(requesterFrame.nwkHeader.destination16).toStrictEqual(requester16);
            expect(requesterFrame.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(requesterFrame.apsPayload.readUInt8(1)).toStrictEqual(ZigbeeAPSConsts.CMD_KEY_APP_LINK);
            expect(requesterFrame.apsPayload.readBigUInt64LE(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(partner64);
            expect(requesterFrame.apsPayload.readUInt8(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 8)).toStrictEqual(1);
        });

        it("delivers the generated application link key to the partner device", async () => {
            const frames = await simulateApplicationKeyRequest();
            const partnerFrame = decodeAppLinkTransport(frames[1]!);

            expect(partnerFrame.macFrame.header.destination16).toStrictEqual(partner16);
            expect(partnerFrame.nwkHeader.destination16).toStrictEqual(partner16);
            expect(partnerFrame.apsPayload.readUInt8(0)).toStrictEqual(ZigbeeAPSCommandId.TRANSPORT_KEY);
            expect(partnerFrame.apsPayload.readBigUInt64LE(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH)).toStrictEqual(requester64);
            expect(partnerFrame.apsPayload.readUInt8(2 + ZigbeeAPSConsts.CMD_KEY_LENGTH + 8)).toStrictEqual(0);

            const requesterFrame = decodeAppLinkTransport(frames[0]!);
            const keyLength = ZigbeeAPSConsts.CMD_KEY_LENGTH;
            expect(partnerFrame.apsPayload.subarray(2, 2 + keyLength)).toStrictEqual(requesterFrame.apsPayload.subarray(2, 2 + keyLength));
        });

        it("wraps application link key transport in APS security", async () => {
            const frames = await simulateApplicationKeyRequest();

            for (const frame of frames) {
                const decoded = decodeAppLinkTransport(frame!);
                expect(decoded.nwkFrameControl.security).toStrictEqual(true);
                expect(decoded.apsFrameControl.security).toStrictEqual(true);
                expect(decoded.apsHeader.securityHeader?.control.keyId).toStrictEqual(ZigbeeKeyType.LOAD);
                expect(decoded.apsHeader.securityHeader?.micLen).toStrictEqual(4);
            }
        });

        it("enforces application link key request policy", async () => {
            context.trustCenterPolicies.allowAppKeyRequest = ApplicationKeyRequestPolicy.DISALLOWED;

            const frames: Buffer[] = [];
            mockMACHandlerCallbacks.onSendFrame = vi.fn((payload: Buffer) => {
                frames.push(Buffer.from(payload));
                return Promise.resolve();
            });

            const payload = Buffer.alloc(1 + 1 + 8);
            payload.writeUInt8(ZigbeeAPSCommandId.REQUEST_KEY, 0);
            payload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_APP_MASTER, 1);
            payload.writeBigUInt64LE(partner64, 2);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.DATA, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0x80,
                destinationPANId: netParams.panId,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: requester16,
                source64: requester64,
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
                source16: requester16,
                source64: requester64,
                radius: 5,
                seqNum: 0x81,
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
                counter: 0x82,
            };

            await apsHandler.processCommand(payload, macHeader, nwkHeader, apsHeader);

            expect(frames).toHaveLength(0);
        });
    });

    /**
     * Zigbee Spec 05-3474-23 §4.7: Key Storage
     * Devices SHALL securely store cryptographic keys.
     */
    describe("Key Storage (Zigbee §4.7)", () => {
        const reloadContext = async (): Promise<StackContext> => {
            const reloaded = new StackContext(mockStackContextCallbacks, join(saveDir, "zoh.save"), cloneNetworkParameters(netParams));
            await reloaded.loadState();

            return reloaded;
        };

        it("persists application link keys across saves", async () => {
            const deviceA = 0x00124b0000001111n;
            const deviceB = 0x00124b0000002222n;
            const appKey = Buffer.from([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00]);

            context.setAppLinkKey(deviceB, deviceA, appKey);
            await context.saveState();

            const reloadedContext = await reloadContext();

            const storedKey = reloadedContext.getAppLinkKey(deviceA, deviceB);

            expect(storedKey).toBeDefined();
            expect(storedKey).not.toBeUndefined();
            expect(storedKey!.equals(appKey)).toStrictEqual(true);

            reloadedContext.disallowJoins();
        });

        it("persists network key across saves", async () => {
            const stagedKey = Buffer.from(context.netParams.networkKey);
            stagedKey[0] ^= 0xff;
            const stagedSequence = (context.netParams.networkKeySequenceNumber + 1) & 0xff;

            context.setPendingNetworkKey(stagedKey, stagedSequence);
            expect(context.activatePendingNetworkKey(stagedSequence)).toStrictEqual(true);

            await context.saveState();

            const reloadedContext = await reloadContext();

            expect(reloadedContext.netParams.networkKey.equals(stagedKey)).toStrictEqual(true);

            reloadedContext.disallowJoins();
        });

        it("persists trust center link key across saves", async () => {
            const updatedTCKey = Buffer.from(context.netParams.tcKey);
            updatedTCKey[updatedTCKey.length - 1] ^= 0xab;

            context.netParams.tcKey = updatedTCKey;
            await context.saveState();

            const reloadedContext = await reloadContext();

            expect(reloadedContext.netParams.tcKey.equals(updatedTCKey)).toStrictEqual(true);

            reloadedContext.disallowJoins();
        });

        it("persists distinct application link keys per partner pair", async () => {
            const deviceA = 0x00124b0000003333n;
            const deviceB = 0x00124b0000004444n;
            const deviceC = 0x00124b0000005555n;
            const keyAB = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]);
            const keyAC = Buffer.from([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]);

            context.setAppLinkKey(deviceA, deviceB, keyAB);
            context.setAppLinkKey(deviceA, deviceC, keyAC);
            await context.saveState();

            const reloadedContext = await reloadContext();

            const storedAB = reloadedContext.getAppLinkKey(deviceB, deviceA);
            const storedAC = reloadedContext.getAppLinkKey(deviceA, deviceC);

            expect(storedAB?.equals(keyAB)).toStrictEqual(true);
            expect(storedAC?.equals(keyAC)).toStrictEqual(true);
            expect(reloadedContext.getAppLinkKey(deviceB, deviceC)).toBeUndefined();

            reloadedContext.disallowJoins();
        });

        it("persists network key sequence numbers across saves", async () => {
            const stagedKey = Buffer.from(context.netParams.networkKey);
            stagedKey[1] ^= 0x55;
            const stagedSequence = (context.netParams.networkKeySequenceNumber + 7) & 0xff;

            context.setPendingNetworkKey(stagedKey, stagedSequence);
            expect(context.activatePendingNetworkKey(stagedSequence)).toStrictEqual(true);

            await context.saveState();

            const reloadedContext = await reloadContext();

            expect(reloadedContext.netParams.networkKeySequenceNumber).toStrictEqual(stagedSequence);

            reloadedContext.disallowJoins();
        });

        it("stores key frame counters with jump on reload", async () => {
            context.nextNWKKeyFrameCounter();
            context.nextNWKKeyFrameCounter();
            context.nextTCKeyFrameCounter();
            context.nextTCKeyFrameCounter();
            context.nextTCKeyFrameCounter();

            const nwkCounterBeforeSave = context.netParams.networkKeyFrameCounter;
            const tcCounterBeforeSave = context.netParams.tcKeyFrameCounter;

            await context.saveState();

            const reloadedContext = await reloadContext();

            const nwkJump = reloadedContext.netParams.networkKeyFrameCounter - nwkCounterBeforeSave;
            const tcJump = reloadedContext.netParams.tcKeyFrameCounter - tcCounterBeforeSave;

            expect(nwkJump).toBeGreaterThanOrEqual(1024);
            expect(tcJump).toStrictEqual(nwkJump);

            reloadedContext.disallowJoins();
        });
    });
});
