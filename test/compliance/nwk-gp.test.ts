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
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeConsts, ZigbeeKeyType } from "../../src/zigbee/zigbee.js";
import {
    decodeZigbeeNWKGPFrameControl,
    decodeZigbeeNWKGPHeader,
    encodeZigbeeNWKGPFrame,
    ZigbeeNWKGPAppId,
    ZigbeeNWKGPCommandId,
    ZigbeeNWKGPDirection,
    ZigbeeNWKGPFrameType,
    type ZigbeeNWKGPHeader,
    ZigbeeNWKGPSecurityLevel,
} from "../../src/zigbee/zigbee-nwkgp.js";
import { APSHandler, type APSHandlerCallbacks } from "../../src/zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../../src/zigbee-stack/nwk-gp-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import { type NetworkParameters, StackContext, type StackContextCallbacks } from "../../src/zigbee-stack/stack-context.js";
import { NETDEF_EXTENDED_PAN_ID, NETDEF_NETWORK_KEY, NETDEF_PAN_ID, NETDEF_TC_KEY, NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0 } from "../data.js";
import { decodeMACFramePayload, NO_ACK_CODE } from "./utils.js";

describe("Zigbee 3.0 Green Power (NWK GP) Compliance", () => {
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
    // biome-ignore lint/correctness/noUnusedVariables: tmp
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

    function decodeGPFromMacFrame(frame: Buffer) {
        const macDecoded = decodeMACFramePayload(frame);
        const gpPayload = frame.subarray(macDecoded.payloadOffset, frame.length - 2);
        const [gpFrameControl, afterFCF] = decodeZigbeeNWKGPFrameControl(gpPayload, 0);
        const [gpHeader, payloadOffset] = decodeZigbeeNWKGPHeader(gpPayload, afterFCF, gpFrameControl);
        const gpdf = gpPayload.subarray(payloadOffset, payloadOffset + gpHeader.payloadLength);

        return { macDecoded, gpPayload, gpFrameControl, gpHeader, gpdf };
    }

    it("parses GP stub frame control fields for recall scene broadcasts", () => {
        const decoded = decodeGPFromMacFrame(Buffer.from(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0));

        expect(decoded.gpFrameControl.frameType).toStrictEqual(ZigbeeNWKGPFrameType.DATA);
        expect(decoded.gpFrameControl.protocolVersion).toStrictEqual(3);
        expect(decoded.gpFrameControl.autoCommissioning).toStrictEqual(false);
        expect(decoded.gpFrameControl.nwkFrameControlExtension).toStrictEqual(true);
        expect(decoded.gpHeader.sourceId).toStrictEqual(0x01719697);
        expect(decoded.gpdf[0]).toStrictEqual(ZigbeeNWKGPCommandId.RECALL_SCENE0);
    });

    it("delivers Green Power data frames with decoded security metadata to callbacks", async () => {
        const decoded = decodeGPFromMacFrame(Buffer.from(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0));

        await nwkGPHandler.processFrame(decoded.gpdf, decoded.macDecoded.header, decoded.gpHeader, 0x7f);
        await new Promise((resolve) => setImmediate(resolve));

        expect(mockNWKGPHandlerCallbacks.onGPFrame).toHaveBeenCalledTimes(1);
        expect(mockNWKGPHandlerCallbacks.onGPFrame).toHaveBeenCalledWith(
            ZigbeeNWKGPCommandId.RECALL_SCENE0,
            decoded.gpdf.subarray(1),
            decoded.macDecoded.header,
            decoded.gpHeader,
            0x7f,
        );
        expect(decoded.gpHeader.micSize).toStrictEqual(4);
        expect(decoded.gpHeader.securityFrameCounter).toStrictEqual(0xb9);
    });

    it("encodes IEEE-addressed GP frames with application endpoint 0xf2", () => {
        const ieeeSource = 0x00124b0000112233n;
        const payload = Buffer.from([ZigbeeNWKGPCommandId.SUCCESS]);
        const header: ZigbeeNWKGPHeader = {
            frameControl: {
                frameType: ZigbeeNWKGPFrameType.DATA,
                protocolVersion: 3,
                autoCommissioning: false,
                nwkFrameControlExtension: true,
            },
            frameControlExt: {
                appId: ZigbeeNWKGPAppId.ZGP,
                securityLevel: ZigbeeNWKGPSecurityLevel.FULL,
                securityKey: true,
                rxAfterTx: false,
                direction: ZigbeeNWKGPDirection.DIRECTION_FROM_ZGPD,
            },
            source64: ieeeSource,
            endpoint: ZigbeeConsts.GP_ENDPOINT,
            micSize: 4,
            securityFrameCounter: 0x10203040,
            payloadLength: payload.byteLength,
        };
        const key = Buffer.alloc(16, 0x22);
        const encoded = encodeZigbeeNWKGPFrame(header, payload, key, ieeeSource);
        const [decodedFCF, afterFCF] = decodeZigbeeNWKGPFrameControl(encoded, 0);
        const [decodedHeader, payloadOffset] = decodeZigbeeNWKGPHeader(encoded, afterFCF, decodedFCF);
        const decodedPayload = encoded.subarray(payloadOffset, payloadOffset + decodedHeader.payloadLength);

        expect(decodedFCF.frameType).toStrictEqual(ZigbeeNWKGPFrameType.DATA);
        expect(decodedHeader.frameControlExt?.appId).toStrictEqual(ZigbeeNWKGPAppId.ZGP);
        expect(decodedHeader.endpoint).toStrictEqual(ZigbeeConsts.GP_ENDPOINT);
        expect(decodedHeader.source64).toStrictEqual(ieeeSource);
        expect(decodedHeader.securityFrameCounter).toStrictEqual(0x10203040);
        expect(decodedHeader.micSize).toStrictEqual(4);
        expect(decodedPayload).toStrictEqual(payload);
    });
});
