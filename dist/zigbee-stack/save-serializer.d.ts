/**
 * Save Type-Length-Value (TLV) binary serialization utilities.
 *
 * Performance-optimized for hot path state saving with extensibility.
 * Format: [Tag: 1 byte][Length: 1-2 bytes][Value: N bytes]
 *
 * - Length < 128: single byte (most common case)
 * - Length >= 128: two bytes with high bit set in first byte
 */
import type { AppLinkKeyStoreEntry, DeviceTableEntry, NetworkParameters, SourceRouteTableEntry } from "./stack-context.js";
/**
 * Parsed device entry with final values ready to use.
 */
interface ParsedSourceRoute extends Pick<SourceRouteTableEntry, "relayAddresses" | "pathCost" | "lastUpdated"> {
}
/**
 * Parsed device entry with final values ready to use.
 */
interface ParsedDevice extends Omit<DeviceTableEntry, "capabilities" | "recentLQAs" | "lastDeviceAnnounceAt"> {
    address64: bigint;
    capabilities: number;
    sourceRouteEntries: ParsedSourceRoute[];
}
/**
 * Top-level parsed state structure with final values ready to use.
 * All values parsed directly from buffers during TLV reading.
 */
export interface ParsedState extends NetworkParameters {
    version?: number;
    deviceEntries: ParsedDevice[];
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
export declare const enum TLVTag {
    EUI64 = 1,
    PAN_ID = 2,
    EXTENDED_PAN_ID = 3,
    CHANNEL = 4,
    NWK_UPDATE_ID = 5,
    TX_POWER = 6,
    NETWORK_KEY = 7,
    NETWORK_KEY_FRAME_COUNTER = 8,
    NETWORK_KEY_SEQUENCE_NUMBER = 9,
    TC_KEY = 10,
    TC_KEY_FRAME_COUNTER = 11,
    APP_LINK_KEY_ENTRY = 12,
    DEVICE_ENTRY = 128,
    VERSION = 240,
    END_MARKER = 255
}
/**
 * Nested TLV tags for device entry structure.
 * Used within DEVICE_ENTRY TLV values.
 */
export declare const enum DeviceTLVTag {
    DEVICE_ADDRESS64 = 1,
    DEVICE_ADDRESS16 = 2,
    DEVICE_CAPABILITIES = 3,
    DEVICE_AUTHORIZED = 4,
    DEVICE_NEIGHBOR = 5,
    DEVICE_LAST_NWK_KEY_SEQ = 6,
    SOURCE_ROUTE_ENTRY = 64
}
/**
 * Nested TLV tags for source route entry structure.
 * Used within SOURCE_ROUTE_ENTRY TLV values.
 */
export declare const enum SourceRouteTLVTag {
    PATH_COST = 1,
    RELAY_ADDRESSES = 2,
    LAST_UPDATED = 3
}
export declare const SAVE_FORMAT_VERSION = 1;
/**
 * Calculate the required buffer size for a TLV entry.
 *
 * @param valueLength
 * @returns
 */
export declare function calculateTLVSize(valueLength: number): number;
/**
 * Write a TLV entry to buffer. Returns new offset.
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export declare function writeTLV(buffer: Buffer, offset: number, tag: TLVTag | DeviceTLVTag | SourceRouteTLVTag, value: Buffer): number;
/**
 * Write a single-byte TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export declare function writeTLVUInt8(buffer: Buffer, offset: number, tag: TLVTag | DeviceTLVTag | SourceRouteTLVTag, value: number): number;
/**
 * Write a signed single-byte TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export declare function writeTLVInt8(buffer: Buffer, offset: number, tag: TLVTag, value: number): number;
/**
 * Write a 2-byte TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export declare function writeTLVUInt16LE(buffer: Buffer, offset: number, tag: TLVTag | DeviceTLVTag, value: number): number;
/**
 * Write a 4-byte TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export declare function writeTLVUInt32LE(buffer: Buffer, offset: number, tag: TLVTag, value: number): number;
/**
 * Write an 8-byte BigInt TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
export declare function writeTLVBigUInt64LE(buffer: Buffer, offset: number, tag: TLVTag | DeviceTLVTag, value: bigint): number;
/**
 * Read and parse top-level state TLVs into typed structure.
 * @param buffer State buffer
 * @returns Strongly-typed parsed state with direct property access
 */
export declare function readTLVs(buffer: Buffer, startOffset?: number, endOffset?: number): ParsedState;
export declare function readAppLinkKeyTLV(buffer: Buffer, startOffset: number): AppLinkKeyStoreEntry;
/**
 * Read and parse device entry TLVs into typed structure with final values.
 * All values are parsed directly from buffers during reading.
 * @param buffer Whole buffer
 * @param startOffset Offset to start parsing TLVs from
 * @param endOffset Offset to end parsing
 * @returns Strongly-typed parsed device with final values ready to use
 */
export declare function readDeviceTLVs(buffer: Buffer, startOffset: number, endOffset: number): ParsedDevice;
/**
 * Read and parse source route entry TLVs into final values.
 * All values are parsed directly from buffers during reading.
 * @param buffer Whole buffer
 * @param startOffset Offset to start parsing TLVs from
 * @param endOffset Offset to end parsing
 * @returns Parsed source route with final values
 */
export declare function readSourceRouteTLVs(buffer: Buffer, startOffset: number, endOffset: number): ParsedSourceRoute;
/**
 * Calculate total size needed for network state with current device count.
 * Provides an upper bound estimate for buffer allocation.
 * @param deviceCount
 * @returns
 */
export declare function estimateTLVStateSize(deviceCount: number, appLinkKeyCount?: number): number;
/**
 * Serialize a source route entry to TLV format.
 * @param pathCost
 * @param relayAddresses
 * @param lastUpdated
 * @returns Buffer containing the TLV-encoded source route entry.
 */
export declare function serializeSourceRouteEntry(pathCost: number, relayAddresses: number[], lastUpdated: number): Buffer;
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
export declare function serializeDeviceEntry(address64: bigint, address16: number, capabilities: number, authorized: boolean, neighbor: boolean, lastTransportedNetworkKeySeq: number | undefined, sourceRouteEntries?: SourceRouteTableEntry[]): Buffer;
export declare function serializeAppLinkKeyEntry(deviceA: bigint, deviceB: bigint, key: Buffer): Buffer;
export {};
