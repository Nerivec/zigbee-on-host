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

import { expect, vi } from "vitest";
import { decodeMACFrameControl, decodeMACHeader, type MACCapabilities } from "../../src/zigbee/mac.js";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    type ZigbeeNWKFrameControl,
    type ZigbeeNWKHeader,
} from "../../src/zigbee/zigbee-nwk.js";
import type { MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import type { NetworkParameters, StackContext } from "../../src/zigbee-stack/stack-context.js";

export const NO_ACK_CODE = 99999;

export const TEST_DEVICE_EUI64 = 0x001d7fd000000001n;

export type DecodedMACFrame = {
    buffer: Buffer;
    frameControl: ReturnType<typeof decodeMACFrameControl>[0];
    header: ReturnType<typeof decodeMACHeader>[0];
    payloadOffset: number;
};

export function decodeMACFramePayload(frame: Buffer): DecodedMACFrame {
    const [frameControl, afterFCF] = decodeMACFrameControl(frame, 0);
    const [header, payloadOffset] = decodeMACHeader(frame, afterFCF, frameControl);

    return {
        buffer: frame,
        frameControl,
        header,
        payloadOffset,
    };
}

export function decodeNwkCommandFromMac(
    frame: Buffer,
    macSource64Fallback: bigint,
): {
    macDecoded: DecodedMACFrame;
    nwkFrameControl: ZigbeeNWKFrameControl;
    nwkHeader: ZigbeeNWKHeader;
    nwkPayload: Buffer;
} {
    const macDecoded = decodeMACFramePayload(frame);
    const macPayload = macDecoded.buffer.subarray(macDecoded.payloadOffset, macDecoded.buffer.length - 2);
    const [nwkFrameControl, nwkOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
    const [nwkHeader, payloadOffset] = decodeZigbeeNWKHeader(macPayload, nwkOffset, nwkFrameControl);
    const nwkPayload = decodeZigbeeNWKPayload(macPayload, payloadOffset, undefined, macSource64Fallback, nwkFrameControl, nwkHeader);

    return { macDecoded, nwkFrameControl, nwkHeader, nwkPayload };
}

export async function captureMacFrame(action: () => Promise<unknown> | unknown, callbacks: MACHandlerCallbacks): Promise<DecodedMACFrame> {
    const frames: Buffer[] = [];
    callbacks.onSendFrame = vi.fn((payload: Buffer) => {
        frames.push(Buffer.from(payload));
        return Promise.resolve();
    });

    await action();

    expect(frames).toHaveLength(1);

    return decodeMACFramePayload(frames[0]!);
}

export function registerNeighborDevice(context: StackContext, address16: number, address64: bigint): void {
    context.deviceTable.set(address64, {
        address16,
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
        recentLQAs: [],
        incomingNWKFrameCounter: undefined,
        endDeviceTimeout: undefined,
    });
    context.address16ToAddress64.set(address16, address64);
}

export function registerDevice(context: StackContext, address16: number, address64: bigint, neighbor: boolean, capabilities?: MACCapabilities): void {
    context.deviceTable.set(address64, {
        address16,
        capabilities,
        authorized: true,
        neighbor,
        recentLQAs: [],
        incomingNWKFrameCounter: undefined,
        endDeviceTimeout: undefined,
    });
    context.address16ToAddress64.set(address16, address64);
}

export function cloneNetworkParameters(params: NetworkParameters): NetworkParameters {
    return {
        ...params,
        networkKey: Buffer.from(params.networkKey),
        tcKey: Buffer.from(params.tcKey),
    };
}
