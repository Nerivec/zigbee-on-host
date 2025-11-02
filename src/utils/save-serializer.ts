/**
 * Save Type-Length-Value (TLV) binary serialization utilities.
 *
 * Performance-optimized for hot path state saving with extensibility.
 * Format: [Tag: 1 byte][Length: 1-2 bytes][Value: N bytes]
 *
 * - Length < 128: single byte (most common case)
 * - Length >= 128: two bytes with high bit set in first byte
 */

import { ZigbeeConsts } from "../zigbee/zigbee.js";
import type { AppLinkKeyStoreEntry, DeviceTableEntry, NetworkParameters, SourceRouteTableEntry } from "../zigbee-stack/stack-context.js";

/**
 * Parsed device entry with final values ready to use.
 */
interface ParsedSourceRoute extends Pick<SourceRouteTableEntry, "relayAddresses" | "pathCost" | "lastUpdated"> {}

/**
 * Parsed device entry with final values ready to use.
 */
interface ParsedDevice extends Omit<DeviceTableEntry, "capabilities" | "recentLQAs"> {
    // for driver to map with
    address64: bigint;
    // raw for driver to handle
    capabilities: number;

    // Source route entries (parsed route objects)
    sourceRouteEntries: ParsedSourceRoute[];
}

/**
 * Top-level parsed state structure with final values ready to use.
 * All values parsed directly from buffers during TLV reading.
 */
export interface ParsedState extends NetworkParameters {
    // File metadata
    version?: number;

    // Device entries (parsed device objects)
    deviceEntries: ParsedDevice[];

    // Application link keys stored by the Trust Center
    appLinkKeys: AppLinkKeyStoreEntry[];
}

/**
 * Top-level TLV tags for state file structure.
 * Tag ranges:
 * - 0x01-0x7F: Network parameters (extensive space for future expansion)
 * - 0x80-0xDF: Device table and related data
 * - 0xE0-0xEF: Reserved for future use
 * - 0xF0-0xFF: File metadata and markers
 */
export const enum TLVTag {
    // Network core parameters (0x01-0x7f)
    EUI64 = 0x01,
    PAN_ID = 0x02,
    EXTENDED_PAN_ID = 0x03,
    CHANNEL = 0x04,
    NWK_UPDATE_ID = 0x05,
    TX_POWER = 0x06,
    NETWORK_KEY = 0x07,
    NETWORK_KEY_FRAME_COUNTER = 0x08,
    NETWORK_KEY_SEQUENCE_NUMBER = 0x09,
    TC_KEY = 0x0a,
    TC_KEY_FRAME_COUNTER = 0x0b,
    APP_LINK_KEY_ENTRY = 0x0c,

    // Reserved: 0x0c-0x7f for future network params (115 tags available)

    // Device table tags (0x80-0xdf)
    DEVICE_ENTRY = 0x80,

    // Reserved: 0x81-0xdf for future data (95 tags available)

    // File metadata (0xf0-0xff)
    VERSION = 0xf0,
    END_MARKER = 0xff,
}

/**
 * Nested TLV tags for device entry structure.
 * Used within DEVICE_ENTRY TLV values.
 */
export const enum DeviceTLVTag {
    // Device core fields (0x01-0x3f)
    DEVICE_ADDRESS64 = 0x01,
    DEVICE_ADDRESS16 = 0x02,
    DEVICE_CAPABILITIES = 0x03,
    DEVICE_AUTHORIZED = 0x04,
    DEVICE_NEIGHBOR = 0x05,

    // Reserved: 0x06-0x3f for future device core fields

    SOURCE_ROUTE_ENTRY = 0x40,

    // Reserved: 0x41-0xff for future device-related fields
}

/**
 * Nested TLV tags for source route entry structure.
 * Used within SOURCE_ROUTE_ENTRY TLV values.
 */
export const enum SourceRouteTLVTag {
    PATH_COST = 0x01,
    RELAY_ADDRESSES = 0x02,
    LAST_UPDATED = 0x03,
}

const TLV_HEADER_SIZE_SHORT = 2; // tag (1) + length (1)
const TLV_HEADER_SIZE_LONG = 3; // tag (1) + length (2)
const LENGTH_THRESHOLD = 128;

export const SAVE_FORMAT_VERSION = 1;

/**
 * Calculate the required buffer size for a TLV entry.
 *
 * @param valueLength
 * @returns
 */
export function calculateTLVSize(valueLength: number): number {
    return (valueLength < LENGTH_THRESHOLD ? TLV_HEADER_SIZE_SHORT : TLV_HEADER_SIZE_LONG) + valueLength;
}

/**
 * Write a TLV entry to buffer. Returns new offset.
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export function writeTLV(buffer: Buffer, offset: number, tag: TLVTag | DeviceTLVTag | SourceRouteTLVTag, value: Buffer): number {
    const length = value.length;

    buffer.writeUInt8(tag, offset++);

    if (length < LENGTH_THRESHOLD) {
        buffer.writeUInt8(length, offset++);
    } else {
        // Two-byte length with high bit set
        buffer.writeUInt8((length >> 8) | 0x80, offset++);
        buffer.writeUInt8(length & 0xff, offset++);
    }

    value.copy(buffer, offset);

    return offset + length;
}

/**
 * Write a single-byte TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export function writeTLVUInt8(buffer: Buffer, offset: number, tag: TLVTag | DeviceTLVTag | SourceRouteTLVTag, value: number): number {
    buffer.writeUInt8(tag, offset++);
    buffer.writeUInt8(1, offset++);
    buffer.writeUInt8(value, offset++);

    return offset;
}

/**
 * Write a signed single-byte TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export function writeTLVInt8(buffer: Buffer, offset: number, tag: TLVTag, value: number): number {
    buffer.writeUInt8(tag, offset++);
    buffer.writeUInt8(1, offset++);
    buffer.writeInt8(value, offset++);

    return offset;
}

/**
 * Write a 2-byte TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export function writeTLVUInt16LE(buffer: Buffer, offset: number, tag: TLVTag | DeviceTLVTag, value: number): number {
    buffer.writeUInt8(tag, offset++);
    buffer.writeUInt8(2, offset++);
    buffer.writeUInt16LE(value, offset);

    return offset + 2;
}

/**
 * Write a 4-byte TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export function writeTLVUInt32LE(buffer: Buffer, offset: number, tag: TLVTag, value: number): number {
    buffer.writeUInt8(tag, offset++);
    buffer.writeUInt8(4, offset++);
    buffer.writeUInt32LE(value, offset);

    return offset + 4;
}

/**
 * Write an 8-byte BigInt TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export function writeTLVBigUInt64LE(buffer: Buffer, offset: number, tag: TLVTag | DeviceTLVTag, value: bigint): number {
    buffer.writeUInt8(tag, offset++);
    buffer.writeUInt8(8, offset++);
    buffer.writeBigUInt64LE(value, offset);

    return offset + 8;
}

/**
 * Read and parse top-level state TLVs into typed structure.
 * @param buffer State buffer
 * @returns Strongly-typed parsed state with direct property access
 */
export function readTLVs(buffer: Buffer, startOffset = 0, endOffset?: number): ParsedState {
    const state: Partial<ParsedState> = {
        deviceEntries: [],
        appLinkKeys: [],
    };

    let offset = startOffset;
    const limit = endOffset ?? buffer.length;

    while (offset < limit) {
        if (offset + 2 > limit) {
            break;
        }

        const tag = buffer.readUInt8(offset++) as TLVTag;

        if (tag === TLVTag.END_MARKER) {
            break;
        }

        const lengthByte = buffer.readUInt8(offset++);
        let length: number;

        if (lengthByte < LENGTH_THRESHOLD) {
            length = lengthByte;
        } else {
            if (offset >= limit) {
                break;
            }
            length = ((lengthByte & 0x7f) << 8) | buffer.readUInt8(offset++);
        }

        if (offset + length > limit) {
            break;
        }

        // Parse value directly to final type based on tag
        switch (tag) {
            case TLVTag.VERSION:
                state.version = buffer.readUInt8(offset);
                break;
            case TLVTag.EUI64:
                state.eui64 = buffer.readBigUInt64LE(offset);
                break;
            case TLVTag.PAN_ID:
                state.panId = buffer.readUInt16LE(offset);
                break;
            case TLVTag.EXTENDED_PAN_ID:
                state.extendedPanId = buffer.readBigUInt64LE(offset);
                break;
            case TLVTag.CHANNEL:
                state.channel = buffer.readUInt8(offset);
                break;
            case TLVTag.NWK_UPDATE_ID:
                state.nwkUpdateId = buffer.readUInt8(offset);
                break;
            case TLVTag.TX_POWER:
                state.txPower = buffer.readInt8(offset);
                break;
            case TLVTag.NETWORK_KEY:
                state.networkKey = buffer.subarray(offset, offset + length);
                break;
            case TLVTag.NETWORK_KEY_FRAME_COUNTER:
                state.networkKeyFrameCounter = buffer.readUInt32LE(offset);
                break;
            case TLVTag.NETWORK_KEY_SEQUENCE_NUMBER:
                state.networkKeySequenceNumber = buffer.readUInt8(offset);
                break;
            case TLVTag.TC_KEY:
                state.tcKey = buffer.subarray(offset, offset + length);
                break;
            case TLVTag.TC_KEY_FRAME_COUNTER:
                state.tcKeyFrameCounter = buffer.readUInt32LE(offset);
                break;
            case TLVTag.DEVICE_ENTRY:
                state.deviceEntries!.push(readDeviceTLVs(buffer, offset, offset + length));
                break;
            case TLVTag.APP_LINK_KEY_ENTRY:
                state.appLinkKeys!.push(readAppLinkKeyTLV(buffer, offset));
                break;
            // Unknown tags ignored for forward compatibility
        }

        offset += length;
    }

    // Validate required fields
    if (
        state.eui64 === undefined ||
        state.panId === undefined ||
        state.extendedPanId === undefined ||
        state.channel === undefined ||
        state.nwkUpdateId === undefined ||
        state.txPower === undefined ||
        !state.networkKey ||
        state.networkKeyFrameCounter === undefined ||
        state.networkKeySequenceNumber === undefined ||
        !state.tcKey ||
        state.tcKeyFrameCounter === undefined
    ) {
        throw new Error("Missing required network parameters in state file");
    }

    return state as ParsedState;
}

export function readAppLinkKeyTLV(buffer: Buffer, startOffset: number): AppLinkKeyStoreEntry {
    const deviceA = buffer.readBigUInt64LE(startOffset);
    const deviceB = buffer.readBigUInt64LE(startOffset + 8);
    const key = Buffer.from(buffer.subarray(startOffset + 16, startOffset + 16 + ZigbeeConsts.SEC_KEYSIZE));

    return { deviceA, deviceB, key };
}

/**
 * Read and parse device entry TLVs into typed structure with final values.
 * All values are parsed directly from buffers during reading.
 * @param buffer Whole buffer
 * @param startOffset Offset to start parsing TLVs from
 * @param endOffset Offset to end parsing
 * @returns Strongly-typed parsed device with final values ready to use
 */
export function readDeviceTLVs(buffer: Buffer, startOffset: number, endOffset: number): ParsedDevice {
    const device: Partial<ParsedDevice> = {
        sourceRouteEntries: [],
    };

    let offset = startOffset;
    const limit = endOffset;

    while (offset < limit) {
        if (offset + 2 > limit) {
            break;
        }

        const tag = buffer.readUInt8(offset++) as DeviceTLVTag;
        const lengthByte = buffer.readUInt8(offset++);
        let length: number;

        if (lengthByte < LENGTH_THRESHOLD) {
            length = lengthByte;
        } else {
            if (offset >= limit) {
                break;
            }
            length = ((lengthByte & 0x7f) << 8) | buffer.readUInt8(offset++);
        }

        if (offset + length > limit) {
            break;
        }

        // Parse value directly to final type based on tag
        switch (tag) {
            case DeviceTLVTag.DEVICE_ADDRESS64:
                device.address64 = buffer.readBigUInt64LE(offset);
                break;
            case DeviceTLVTag.DEVICE_ADDRESS16:
                device.address16 = buffer.readUInt16LE(offset);
                break;
            case DeviceTLVTag.DEVICE_CAPABILITIES:
                device.capabilities = buffer.readUInt8(offset);
                break;
            case DeviceTLVTag.DEVICE_AUTHORIZED:
                device.authorized = Boolean(buffer.readUInt8(offset));
                break;
            case DeviceTLVTag.DEVICE_NEIGHBOR:
                device.neighbor = Boolean(buffer.readUInt8(offset));
                break;
            case DeviceTLVTag.SOURCE_ROUTE_ENTRY:
                device.sourceRouteEntries!.push(readSourceRouteTLVs(buffer, offset, offset + length));
                break;
            // Unknown tags ignored
        }

        offset += length;
    }

    // Validate required fields
    if (
        device.address64 === undefined ||
        device.address16 === undefined ||
        device.capabilities === undefined ||
        device.authorized === undefined ||
        device.neighbor === undefined
    ) {
        throw new Error("Missing required device fields");
    }

    return device as ParsedDevice;
}

/**
 * Read and parse source route entry TLVs into final values.
 * All values are parsed directly from buffers during reading.
 * @param buffer Whole buffer
 * @param startOffset Offset to start parsing TLVs from
 * @param endOffset Offset to end parsing
 * @returns Parsed source route with final values
 */
export function readSourceRouteTLVs(buffer: Buffer, startOffset: number, endOffset: number): ParsedSourceRoute {
    let pathCost: number | undefined;
    const relayAddresses: number[] = [];
    let lastUpdated: number | undefined;

    let offset = startOffset;
    const limit = endOffset;

    while (offset < limit) {
        if (offset + 2 > limit) {
            break;
        }

        const tag = buffer.readUInt8(offset++) as SourceRouteTLVTag;
        const lengthByte = buffer.readUInt8(offset++);
        let length: number;

        if (lengthByte < LENGTH_THRESHOLD) {
            length = lengthByte;
        } else {
            if (offset >= limit) {
                break;
            }
            length = ((lengthByte & 0x7f) << 8) | buffer.readUInt8(offset++);
        }

        if (offset + length > limit) {
            break;
        }

        // Parse value directly to final type based on tag
        switch (tag) {
            case SourceRouteTLVTag.PATH_COST: {
                pathCost = buffer.readUInt8(offset);
                break;
            }
            case SourceRouteTLVTag.RELAY_ADDRESSES: {
                // Parse relay addresses array
                const relayCount = length / 2;

                for (let i = 0; i < relayCount; i++) {
                    relayAddresses.push(buffer.readUInt16LE(offset + i * 2));
                }

                break;
            }
            case SourceRouteTLVTag.LAST_UPDATED:
                lastUpdated = buffer.readUIntLE(offset, 6);
                break;
            // Unknown tags ignored
        }

        offset += length;
    }

    // Validate required fields
    if (pathCost === undefined || lastUpdated === undefined) {
        throw new Error("Missing required source route fields");
    }

    return { pathCost, relayAddresses, lastUpdated };
}

/**
 * Calculate total size needed for network state with current device count.
 * Provides an upper bound estimate for buffer allocation.
 * @param deviceCount
 * @returns
 */
export function estimateTLVStateSize(deviceCount: number, appLinkKeyCount = 0): number {
    // version + network parameters
    let size = 250;
    // each device entry + source routes (to ~10% of network, min 5)
    const avgDeviceSize = 50 + Math.max(Math.ceil(deviceCount * 0.1), 5) * 15;
    size += deviceCount * calculateTLVSize(avgDeviceSize);

    if (appLinkKeyCount > 0) {
        const appLinkEntrySize = 8 + 8 + 1 + 16;
        size += appLinkKeyCount * calculateTLVSize(appLinkEntrySize);
    }

    // end marker
    size += 1;

    return size;
}

/**
 * Serialize a source route entry to TLV format.
 * @param pathCost
 * @param relayAddresses
 * @param lastUpdated
 * @returns Buffer containing the TLV-encoded source route entry.
 */
export function serializeSourceRouteEntry(pathCost: number, relayAddresses: number[], lastUpdated: number): Buffer {
    // Calculate size: path cost (3) + relay addresses (2-3 + n*2) + lastUpdated (2-3 + 6)
    const size = calculateTLVSize(1) + calculateTLVSize(relayAddresses.length * 2) + calculateTLVSize(6);
    const buffer = Buffer.allocUnsafe(size);
    let offset = 0;

    offset = writeTLVUInt8(buffer, offset, SourceRouteTLVTag.PATH_COST, pathCost);

    if (relayAddresses.length > 0) {
        const relayBuf = Buffer.allocUnsafe(relayAddresses.length * 2);
        let relayOffset = 0;

        for (const address of relayAddresses) {
            relayBuf.writeUInt16LE(address, relayOffset);

            relayOffset += 2;
        }

        offset = writeTLV(buffer, offset, SourceRouteTLVTag.RELAY_ADDRESSES, relayBuf);
    }

    // Write lastUpdated as 48-bit timestamp (fits until year 2255)
    const timestampBuf = Buffer.allocUnsafe(6);

    timestampBuf.writeUIntLE(lastUpdated, 0, 6);

    offset = writeTLV(buffer, offset, SourceRouteTLVTag.LAST_UPDATED, timestampBuf);

    return buffer.subarray(0, offset);
}

/**
 * Serialize device entry with source routes to TLV format.
 * @param address64
 * @param address16
 * @param capabilities
 * @param authorized
 * @param neighbor
 * @param sourceRouteEntries
 * @returns Buffer containing the TLV-encoded device entry.
 */
export function serializeDeviceEntry(
    address64: bigint,
    address16: number,
    capabilities: number,
    authorized: boolean,
    neighbor: boolean,
    sourceRouteEntries?: SourceRouteTableEntry[],
): Buffer {
    // Estimate size generously
    let estimatedSize = 100; // base fields with TLV overhead

    if (sourceRouteEntries) {
        for (const entry of sourceRouteEntries) {
            estimatedSize += calculateTLVSize(50 + entry.relayAddresses.length * 2);
        }
    }

    const buffer = Buffer.allocUnsafe(estimatedSize);
    let offset = 0;
    // Write device core fields
    offset = writeTLVBigUInt64LE(buffer, offset, DeviceTLVTag.DEVICE_ADDRESS64, address64);
    offset = writeTLVUInt16LE(buffer, offset, DeviceTLVTag.DEVICE_ADDRESS16, address16);
    offset = writeTLVUInt8(buffer, offset, DeviceTLVTag.DEVICE_CAPABILITIES, capabilities);
    offset = writeTLVUInt8(buffer, offset, DeviceTLVTag.DEVICE_AUTHORIZED, authorized ? 1 : 0);
    offset = writeTLVUInt8(buffer, offset, DeviceTLVTag.DEVICE_NEIGHBOR, neighbor ? 1 : 0);

    // Write source route entries (if any)
    if (sourceRouteEntries) {
        for (const entry of sourceRouteEntries) {
            const routeEntry = serializeSourceRouteEntry(entry.pathCost, entry.relayAddresses, entry.lastUpdated);
            offset = writeTLV(buffer, offset, DeviceTLVTag.SOURCE_ROUTE_ENTRY, routeEntry);
        }
    }

    return buffer.subarray(0, offset);
}

export function serializeAppLinkKeyEntry(deviceA: bigint, deviceB: bigint, key: Buffer): Buffer {
    const payload = Buffer.allocUnsafe(16 + ZigbeeConsts.SEC_KEYSIZE);
    let offset = 0;

    offset = payload.writeBigUInt64LE(deviceA, offset);
    offset = payload.writeBigUInt64LE(deviceB, offset);
    key.copy(payload, offset);

    return payload;
}
