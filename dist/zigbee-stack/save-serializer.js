"use strict";
/**
 * Save Type-Length-Value (TLV) binary serialization utilities.
 *
 * Performance-optimized for hot path state saving with extensibility.
 * Format: [Tag: 1 byte][Length: 1-2 bytes][Value: N bytes]
 *
 * - Length < 128: single byte (most common case)
 * - Length >= 128: two bytes with high bit set in first byte
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SAVE_FORMAT_VERSION = void 0;
exports.calculateTLVSize = calculateTLVSize;
exports.writeTLV = writeTLV;
exports.writeTLVUInt8 = writeTLVUInt8;
exports.writeTLVInt8 = writeTLVInt8;
exports.writeTLVUInt16LE = writeTLVUInt16LE;
exports.writeTLVUInt32LE = writeTLVUInt32LE;
exports.writeTLVBigUInt64LE = writeTLVBigUInt64LE;
exports.readTLVs = readTLVs;
exports.readAppLinkKeyTLV = readAppLinkKeyTLV;
exports.readDeviceTLVs = readDeviceTLVs;
exports.readSourceRouteTLVs = readSourceRouteTLVs;
exports.estimateTLVStateSize = estimateTLVStateSize;
exports.serializeSourceRouteEntry = serializeSourceRouteEntry;
exports.serializeDeviceEntry = serializeDeviceEntry;
exports.serializeAppLinkKeyEntry = serializeAppLinkKeyEntry;
const TLV_HEADER_SIZE_SHORT = 2; // tag (1) + length (1)
const TLV_HEADER_SIZE_LONG = 3; // tag (1) + length (2)
const LENGTH_THRESHOLD = 128;
exports.SAVE_FORMAT_VERSION = 1;
/**
 * Calculate the required buffer size for a TLV entry.
 *
 * @param valueLength
 * @returns
 */
function calculateTLVSize(valueLength) {
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
function writeTLV(buffer, offset, tag, value) {
    const length = value.length;
    offset = buffer.writeUInt8(tag, offset);
    if (length < LENGTH_THRESHOLD) {
        offset = buffer.writeUInt8(length, offset);
    }
    else {
        // Two-byte length with high bit set
        offset = buffer.writeUInt8((length >> 8) | 0x80, offset);
        offset = buffer.writeUInt8(length & 0xff, offset);
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
function writeTLVUInt8(buffer, offset, tag, value) {
    offset = buffer.writeUInt8(tag, offset);
    offset = buffer.writeUInt8(1, offset);
    offset = buffer.writeUInt8(value, offset);
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
function writeTLVInt8(buffer, offset, tag, value) {
    offset = buffer.writeUInt8(tag, offset);
    offset = buffer.writeUInt8(1, offset);
    offset = buffer.writeInt8(value, offset);
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
function writeTLVUInt16LE(buffer, offset, tag, value) {
    offset = buffer.writeUInt8(tag, offset);
    offset = buffer.writeUInt8(2, offset);
    offset = buffer.writeUInt16LE(value, offset);
    return offset;
}
/**
 * Write a 4-byte TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
function writeTLVUInt32LE(buffer, offset, tag, value) {
    offset = buffer.writeUInt8(tag, offset);
    offset = buffer.writeUInt8(4, offset);
    offset = buffer.writeUInt32LE(value, offset);
    return offset;
}
/**
 * Write an 8-byte BigInt TLV entry (optimized path).
 * @param buffer
 * @param offset
 * @param tag
 * @param value
 * @returns
 */
function writeTLVBigUInt64LE(buffer, offset, tag, value) {
    offset = buffer.writeUInt8(tag, offset);
    offset = buffer.writeUInt8(8, offset);
    offset = buffer.writeBigUInt64LE(value, offset);
    return offset;
}
/**
 * Read and parse top-level state TLVs into typed structure.
 * @param buffer State buffer
 * @returns Strongly-typed parsed state with direct property access
 */
function readTLVs(buffer, startOffset = 0, endOffset) {
    const state = {
        deviceEntries: [],
        appLinkKeys: [],
    };
    let offset = startOffset;
    const limit = endOffset ?? buffer.length;
    while (offset < limit) {
        if (offset + 2 > limit) {
            break;
        }
        const tag = buffer.readUInt8(offset++);
        if (tag === 255 /* TLVTag.END_MARKER */) {
            break;
        }
        const lengthByte = buffer.readUInt8(offset++);
        let length;
        if (lengthByte < LENGTH_THRESHOLD) {
            length = lengthByte;
        }
        else {
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
            case 240 /* TLVTag.VERSION */:
                state.version = buffer.readUInt8(offset);
                break;
            case 1 /* TLVTag.EUI64 */:
                state.eui64 = buffer.readBigUInt64LE(offset);
                break;
            case 2 /* TLVTag.PAN_ID */:
                state.panId = buffer.readUInt16LE(offset);
                break;
            case 3 /* TLVTag.EXTENDED_PAN_ID */:
                state.extendedPanId = buffer.readBigUInt64LE(offset);
                break;
            case 4 /* TLVTag.CHANNEL */:
                state.channel = buffer.readUInt8(offset);
                break;
            case 5 /* TLVTag.NWK_UPDATE_ID */:
                state.nwkUpdateId = buffer.readUInt8(offset);
                break;
            case 6 /* TLVTag.TX_POWER */:
                state.txPower = buffer.readInt8(offset);
                break;
            case 7 /* TLVTag.NETWORK_KEY */:
                state.networkKey = buffer.subarray(offset, offset + length);
                break;
            case 8 /* TLVTag.NETWORK_KEY_FRAME_COUNTER */:
                state.networkKeyFrameCounter = buffer.readUInt32LE(offset);
                break;
            case 9 /* TLVTag.NETWORK_KEY_SEQUENCE_NUMBER */:
                state.networkKeySequenceNumber = buffer.readUInt8(offset);
                break;
            case 10 /* TLVTag.TC_KEY */:
                state.tcKey = buffer.subarray(offset, offset + length);
                break;
            case 11 /* TLVTag.TC_KEY_FRAME_COUNTER */:
                state.tcKeyFrameCounter = buffer.readUInt32LE(offset);
                break;
            case 128 /* TLVTag.DEVICE_ENTRY */:
                state.deviceEntries.push(readDeviceTLVs(buffer, offset, offset + length));
                break;
            case 12 /* TLVTag.APP_LINK_KEY_ENTRY */:
                state.appLinkKeys.push(readAppLinkKeyTLV(buffer, offset));
                break;
            // Unknown tags ignored for forward compatibility
        }
        offset += length;
    }
    // Validate required fields
    if (state.eui64 === undefined ||
        state.panId === undefined ||
        state.extendedPanId === undefined ||
        state.channel === undefined ||
        state.nwkUpdateId === undefined ||
        state.txPower === undefined ||
        !state.networkKey ||
        state.networkKeyFrameCounter === undefined ||
        state.networkKeySequenceNumber === undefined ||
        !state.tcKey ||
        state.tcKeyFrameCounter === undefined) {
        throw new Error("Missing required network parameters in state file");
    }
    return state;
}
function readAppLinkKeyTLV(buffer, startOffset) {
    const deviceA = buffer.readBigUInt64LE(startOffset);
    const deviceB = buffer.readBigUInt64LE(startOffset + 8);
    const key = Buffer.from(buffer.subarray(startOffset + 16, startOffset + 16 + 16 /* ZigbeeConsts.SEC_KEYSIZE */));
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
function readDeviceTLVs(buffer, startOffset, endOffset) {
    const device = {
        sourceRouteEntries: [],
    };
    let offset = startOffset;
    const limit = endOffset;
    while (offset < limit) {
        if (offset + 2 > limit) {
            break;
        }
        const tag = buffer.readUInt8(offset++);
        const lengthByte = buffer.readUInt8(offset++);
        let length;
        if (lengthByte < LENGTH_THRESHOLD) {
            length = lengthByte;
        }
        else {
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
            case 1 /* DeviceTLVTag.DEVICE_ADDRESS64 */:
                device.address64 = buffer.readBigUInt64LE(offset);
                break;
            case 2 /* DeviceTLVTag.DEVICE_ADDRESS16 */:
                device.address16 = buffer.readUInt16LE(offset);
                break;
            case 3 /* DeviceTLVTag.DEVICE_CAPABILITIES */:
                device.capabilities = buffer.readUInt8(offset);
                break;
            case 4 /* DeviceTLVTag.DEVICE_AUTHORIZED */:
                device.authorized = Boolean(buffer.readUInt8(offset));
                break;
            case 5 /* DeviceTLVTag.DEVICE_NEIGHBOR */:
                device.neighbor = Boolean(buffer.readUInt8(offset));
                break;
            case 6 /* DeviceTLVTag.DEVICE_LAST_NWK_KEY_SEQ */:
                device.lastTransportedNetworkKeySeq = buffer.readUInt8(offset);
                break;
            case 64 /* DeviceTLVTag.SOURCE_ROUTE_ENTRY */:
                device.sourceRouteEntries.push(readSourceRouteTLVs(buffer, offset, offset + length));
                break;
            // Unknown tags ignored
        }
        offset += length;
    }
    // Validate required fields
    if (device.address64 === undefined ||
        device.address16 === undefined ||
        device.capabilities === undefined ||
        device.authorized === undefined ||
        device.neighbor === undefined) {
        throw new Error("Missing required device fields");
    }
    return device;
}
/**
 * Read and parse source route entry TLVs into final values.
 * All values are parsed directly from buffers during reading.
 * @param buffer Whole buffer
 * @param startOffset Offset to start parsing TLVs from
 * @param endOffset Offset to end parsing
 * @returns Parsed source route with final values
 */
function readSourceRouteTLVs(buffer, startOffset, endOffset) {
    let pathCost;
    const relayAddresses = [];
    let lastUpdated;
    let offset = startOffset;
    const limit = endOffset;
    while (offset < limit) {
        if (offset + 2 > limit) {
            break;
        }
        const tag = buffer.readUInt8(offset++);
        const lengthByte = buffer.readUInt8(offset++);
        let length;
        if (lengthByte < LENGTH_THRESHOLD) {
            length = lengthByte;
        }
        else {
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
            case 1 /* SourceRouteTLVTag.PATH_COST */: {
                pathCost = buffer.readUInt8(offset);
                break;
            }
            case 2 /* SourceRouteTLVTag.RELAY_ADDRESSES */: {
                // Parse relay addresses array
                const relayCount = length / 2;
                for (let i = 0; i < relayCount; i++) {
                    relayAddresses.push(buffer.readUInt16LE(offset + i * 2));
                }
                break;
            }
            case 3 /* SourceRouteTLVTag.LAST_UPDATED */:
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
function estimateTLVStateSize(deviceCount, appLinkKeyCount = 0) {
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
function serializeSourceRouteEntry(pathCost, relayAddresses, lastUpdated) {
    // Calculate size: path cost (3) + relay addresses (2-3 + n*2) + lastUpdated (2-3 + 6)
    const size = calculateTLVSize(1) + calculateTLVSize(relayAddresses.length * 2) + calculateTLVSize(6);
    const buffer = Buffer.allocUnsafe(size);
    let offset = 0;
    offset = writeTLVUInt8(buffer, offset, 1 /* SourceRouteTLVTag.PATH_COST */, pathCost);
    if (relayAddresses.length > 0) {
        const relayBuf = Buffer.allocUnsafe(relayAddresses.length * 2);
        let relayOffset = 0;
        for (const address of relayAddresses) {
            relayOffset = relayBuf.writeUInt16LE(address, relayOffset);
        }
        offset = writeTLV(buffer, offset, 2 /* SourceRouteTLVTag.RELAY_ADDRESSES */, relayBuf);
    }
    // Write lastUpdated as 48-bit timestamp (fits until year 2255)
    const timestampBuf = Buffer.allocUnsafe(6);
    timestampBuf.writeUIntLE(lastUpdated, 0, 6);
    offset = writeTLV(buffer, offset, 3 /* SourceRouteTLVTag.LAST_UPDATED */, timestampBuf);
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
function serializeDeviceEntry(address64, address16, capabilities, authorized, neighbor, lastTransportedNetworkKeySeq, sourceRouteEntries) {
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
    offset = writeTLVBigUInt64LE(buffer, offset, 1 /* DeviceTLVTag.DEVICE_ADDRESS64 */, address64);
    offset = writeTLVUInt16LE(buffer, offset, 2 /* DeviceTLVTag.DEVICE_ADDRESS16 */, address16);
    offset = writeTLVUInt8(buffer, offset, 3 /* DeviceTLVTag.DEVICE_CAPABILITIES */, capabilities);
    offset = writeTLVUInt8(buffer, offset, 4 /* DeviceTLVTag.DEVICE_AUTHORIZED */, authorized ? 1 : 0);
    offset = writeTLVUInt8(buffer, offset, 5 /* DeviceTLVTag.DEVICE_NEIGHBOR */, neighbor ? 1 : 0);
    if (lastTransportedNetworkKeySeq !== undefined) {
        offset = writeTLVUInt8(buffer, offset, 6 /* DeviceTLVTag.DEVICE_LAST_NWK_KEY_SEQ */, lastTransportedNetworkKeySeq);
    }
    // Write source route entries (if any)
    if (sourceRouteEntries) {
        for (const entry of sourceRouteEntries) {
            const routeEntry = serializeSourceRouteEntry(entry.pathCost, entry.relayAddresses, entry.lastUpdated);
            offset = writeTLV(buffer, offset, 64 /* DeviceTLVTag.SOURCE_ROUTE_ENTRY */, routeEntry);
        }
    }
    return buffer.subarray(0, offset);
}
function serializeAppLinkKeyEntry(deviceA, deviceB, key) {
    const payload = Buffer.allocUnsafe(16 + 16 /* ZigbeeConsts.SEC_KEYSIZE */);
    let offset = 0;
    offset = payload.writeBigUInt64LE(deviceA, offset);
    offset = payload.writeBigUInt64LE(deviceB, offset);
    key.copy(payload, offset);
    return payload;
}
//# sourceMappingURL=save-serializer.js.map