"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SPINEL_RCP_API_VERSION = exports.SPINEL_HEADER_FLG_SPINEL = void 0;
exports.decodeSpinelFrame = decodeSpinelFrame;
exports.encodeSpinelFrame = encodeSpinelFrame;
exports.getPackedUIntSize = getPackedUIntSize;
exports.setPackedUInt = setPackedUInt;
exports.getPackedUInt = getPackedUInt;
exports.writePropertyId = writePropertyId;
exports.writePropertyb = writePropertyb;
exports.readPropertyb = readPropertyb;
exports.writePropertyC = writePropertyC;
exports.readPropertyC = readPropertyC;
exports.writePropertyAC = writePropertyAC;
exports.writePropertyc = writePropertyc;
exports.readPropertyc = readPropertyc;
exports.writePropertyS = writePropertyS;
exports.readPropertyS = readPropertyS;
exports.writePropertys = writePropertys;
exports.writePropertyL = writePropertyL;
exports.writePropertyl = writePropertyl;
exports.writePropertyi = writePropertyi;
exports.readPropertyi = readPropertyi;
exports.readPropertyii = readPropertyii;
exports.readPropertyAi = readPropertyAi;
exports.writePropertyU = writePropertyU;
exports.readPropertyU = readPropertyU;
exports.writePropertyE = writePropertyE;
exports.readPropertyE = readPropertyE;
exports.writePropertyd = writePropertyd;
exports.readPropertyd = readPropertyd;
exports.writePropertyD = writePropertyD;
exports.readPropertyD = readPropertyD;
exports.writePropertyStreamRaw = writePropertyStreamRaw;
exports.readStreamRaw = readStreamRaw;
const node_assert_1 = __importDefault(require("node:assert"));
const hdlc_js_1 = require("./hdlc.js");
const SPINEL_HEADER_TID_MASK = 0x0f;
const SPINEL_HEADER_NLI_MASK = 0x30;
const SPINEL_HEADER_NLI_SHIFT = 4;
const SPINEL_HEADER_FLG_MASK = 0xc0;
const SPINEL_HEADER_FLG_SHIFT = 6;
/** @see SpinelFrameHeader.flg */
exports.SPINEL_HEADER_FLG_SPINEL = 2;
exports.SPINEL_RCP_API_VERSION = 11;
/**
 * Decode HDLC frame into Spinel frame
 * HOT PATH: Called for every incoming frame from RCP.
 */
/* @__INLINE__ */
function decodeSpinelFrame(hdlcFrame) {
    // HOT PATH: Extract header fields with bitwise operations
    const header = hdlcFrame.data[0];
    const tid = header & SPINEL_HEADER_TID_MASK;
    const nli = (header & SPINEL_HEADER_NLI_MASK) >> SPINEL_HEADER_NLI_SHIFT;
    const flg = (header & SPINEL_HEADER_FLG_MASK) >> SPINEL_HEADER_FLG_SHIFT;
    const [commandId, outOffset] = getPackedUInt(hdlcFrame.data, 1);
    const payload = hdlcFrame.data.subarray(outOffset, hdlcFrame.length);
    return {
        header: { tid, nli, flg },
        commandId,
        payload,
    };
}
/**
 * Encode Spinel frame into HDLC frame
 * HOT PATH: Called for every outgoing frame to RCP.
 */
/* @__INLINE__ */
function encodeSpinelFrame(frame) {
    const cmdIdSize = getPackedUIntSize(frame.commandId);
    const buffer = Buffer.alloc(frame.payload.byteLength + 1 + cmdIdSize);
    const headerByte = (frame.header.tid & SPINEL_HEADER_TID_MASK) |
        ((frame.header.nli << SPINEL_HEADER_NLI_SHIFT) & SPINEL_HEADER_NLI_MASK) |
        ((frame.header.flg << SPINEL_HEADER_FLG_SHIFT) & SPINEL_HEADER_FLG_MASK);
    buffer[0] = headerByte;
    const outOffset = setPackedUInt(buffer, 1, frame.commandId, cmdIdSize);
    frame.payload.copy(buffer, outOffset);
    return (0, hdlc_js_1.encodeHdlcFrame)(buffer);
}
const SPINEL_PACKED_UINT_MASK = 0x80;
const SPINEL_PACKED_UINT_MSO_MASK = 0x7f;
/**
 * Calculate size needed for packed unsigned integer encoding.
 * HOT PATH: Called during frame encoding.
 */
/* @__INLINE__ */
function getPackedUIntSize(value) {
    if (value < 1 << 7) {
        return 1;
    }
    if (value < 1 << 14) {
        return 2;
    }
    if (value < 1 << 21) {
        return 3;
    }
    if (value < 1 << 28) {
        return 4;
    }
    return 5;
}
/**
 * Encode packed unsigned integer into buffer.
 * HOT PATH: Called during frame encoding.
 */
/* @__INLINE__ */
function setPackedUInt(data, offset, value, size) {
    if (!size) {
        size = getPackedUIntSize(value);
    }
    for (let i = 0; i !== size - 1; i++) {
        data[offset] = (value & SPINEL_PACKED_UINT_MSO_MASK) | SPINEL_PACKED_UINT_MASK;
        offset += 1;
        value >>= 7;
    }
    data[offset] = value & SPINEL_PACKED_UINT_MSO_MASK;
    offset += 1;
    return offset;
}
/**
 * Decode packed unsigned integer from buffer.
 * HOT PATH: Called for every incoming frame.
 */
/* @__INLINE__ */
function getPackedUInt(data, offset) {
    let value = 0;
    let i = 0;
    // HOT PATH: Decode variable-length integer
    do {
        if (i >= 40) {
            throw new Error(`Invalid Packed UInt, got ${i}, expected < 40`);
        }
        value |= (data[offset] & SPINEL_PACKED_UINT_MSO_MASK) << i;
        i += 7;
        offset += 1;
    } while ((data[offset - 1] & SPINEL_PACKED_UINT_MASK) === SPINEL_PACKED_UINT_MASK);
    return [value, offset];
}
/** Create output array of given (size + property size) and set the property ID at index 0 */
function writePropertyId(propertyId, size) {
    const propIdSize = getPackedUIntSize(propertyId);
    const buf = Buffer.alloc(propIdSize + size);
    const offset = setPackedUInt(buf, 0, propertyId, propIdSize);
    return [buf, offset];
}
/** Write as boolean */
function writePropertyb(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, 1);
    buf[offset] = value ? 1 : 0;
    return buf;
}
/** Read as boolean */
function readPropertyb(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    return !!data[pOutOffset];
}
/** Write as uint8 */
function writePropertyC(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, 1);
    buf[offset] = value;
    return buf;
}
/** Read as uint8 */
function readPropertyC(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    return data[pOutOffset];
}
/** Write as list of uint8 */
function writePropertyAC(propertyId, values) {
    const [buf, pOffset] = writePropertyId(propertyId, values.length);
    let offset = pOffset;
    for (const value of values) {
        offset = buf.writeUInt8(value, offset);
    }
    return buf;
}
/** Write as int8 */
function writePropertyc(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, 1);
    buf.writeInt8(value, offset);
    return buf;
}
/** Read as int8 */
function readPropertyc(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    return data.readInt8(pOutOffset);
}
/** Write as uint16 */
function writePropertyS(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, 2);
    buf.writeUInt16LE(value, offset);
    return buf;
}
/** Read as uint16 */
function readPropertyS(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    return data.readUInt16LE(pOutOffset);
}
/** Write as int16 */
function writePropertys(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, 2);
    buf.writeInt16LE(value, offset);
    return buf;
}
/** Write as uint32 */
function writePropertyL(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, 4);
    buf.writeUInt32LE(value, offset);
    return buf;
}
/** Write as int32 */
function writePropertyl(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, 4);
    buf.writeInt32LE(value, offset);
    return buf;
}
/** Write as packed uint */
function writePropertyi(propertyId, value) {
    const valueSize = getPackedUIntSize(value);
    const [buf, offset] = writePropertyId(propertyId, valueSize);
    setPackedUInt(buf, offset, value, valueSize);
    return buf;
}
/** Read as packed uint */
function readPropertyi(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    const [i] = getPackedUInt(data, pOutOffset);
    return i;
}
/** Read as packed uint x2 */
function readPropertyii(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    const [major, maOutOffset] = getPackedUInt(data, pOutOffset);
    const [minor] = getPackedUInt(data, maOutOffset);
    return [major, minor];
}
/** Read as list of packed uint */
function readPropertyAi(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    const caps = [];
    for (let i = pOutOffset; i < data.byteLength;) {
        const [cap, cOutOffset] = getPackedUInt(data, i);
        caps.push(cap);
        i = cOutOffset;
    }
    return caps;
}
/** Write as UTF8 string */
function writePropertyU(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, value.length);
    buf.write(value, offset, "utf8");
    return buf;
}
/** Read as UTF8 string */
function readPropertyU(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    return data.toString("utf8", pOutOffset);
}
/** Write as bigint */
function writePropertyE(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, 8);
    buf.writeBigUInt64BE(value, offset);
    return buf;
}
/** Read as bigint */
function readPropertyE(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    return data.readBigUInt64BE(pOutOffset);
}
/** Write as Buffer of specific length */
function writePropertyd(propertyId, value) {
    const [buf, pOutOffset] = writePropertyId(propertyId, 2 + value.byteLength);
    let offset = pOutOffset;
    offset = buf.writeUInt16LE(value.byteLength, offset);
    value.copy(buf, offset);
    return buf;
}
/** Read as Buffer of specific length */
function readPropertyd(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    const length = data.readUInt16LE(pOutOffset);
    const lOutOffset = pOutOffset + 2;
    return data.subarray(lOutOffset, lOutOffset + length);
}
/** Write as Buffer of remaining length */
function writePropertyD(propertyId, value) {
    const [buf, offset] = writePropertyId(propertyId, value.byteLength);
    value.copy(buf, offset);
    return buf;
}
/** Read as Buffer of remaining length */
function readPropertyD(propertyId, data, offset = 0) {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    (0, node_assert_1.default)(propId === propertyId);
    return data.subarray(pOutOffset);
}
/** @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.6.2 */
function writePropertyStreamRaw(data, config) {
    const [buf, pOutOffset] = writePropertyId(113 /* SpinelPropertyId.STREAM_RAW */, data.byteLength + 18);
    let offset = pOutOffset;
    offset = buf.writeUInt16LE(data.byteLength, offset);
    offset += data.copy(buf, offset);
    offset = buf.writeUInt8(config.txChannel, offset);
    offset = buf.writeUInt8(config.ccaBackoffAttempts, offset);
    offset = buf.writeUInt8(config.ccaRetries, offset);
    offset = buf.writeUInt8(config.enableCSMACA ? 1 : 0, offset);
    offset = buf.writeUInt8(config.headerUpdated ? 1 : 0, offset);
    offset = buf.writeUInt8(config.reTx ? 1 : 0, offset);
    offset = buf.writeUInt8(config.securityProcessed ? 1 : 0, offset);
    offset = buf.writeUInt32LE(config.txDelay, offset);
    offset = buf.writeUInt32LE(config.txDelayBaseTime, offset);
    offset = buf.writeUInt8(config.rxChannelAfterTxDone, offset);
    return buf;
}
/**
 * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.6.2.1
 *
 * Assumes payload comes from `spinel.payload` and offset is right after `SpinelPropertyId.STREAM_RAW`, per below
 *
 * Packed-Encoding: "dD"
 *
 * +---------+----------------+------------+----------------+
 * | Octets: |       2        |     n      |       n        |
 * +---------+----------------+------------+----------------+
 * | Fields: | FRAME_DATA_LEN | FRAME_DATA | FRAME_METADATA |
 * +---------+----------------+------------+----------------+
 *
 * from pyspinel (https://github.com/openthread/pyspinel/blob/main/sniffer.py#L283):
 * metadata format (totally 19 bytes or 26 bytes):
 * 0. RSSI(int8)
 * 1. Noise Floor(int8)
 * 2. Flags(uint16)
 * 3. PHY-specific data struct contains:
 *     3.0 Channel(uint8)
 *     3.1 LQI(uint8)
 *     3.2 Timestamp in microseconds(uint64)
 * 4. Vendor data struct contains:
 *     4.0 Receive error(uint8)
 * 5. (optional) MAC data struct contains:
 *     5.0 ACK key ID(uint8)
 *     5.1 ACK frame counter(uint32)
 */
function readStreamRaw(payload, offset) {
    const frameDataLen = payload.readUInt16LE(offset);
    offset += 2;
    let metaOffset = offset + frameDataLen;
    let metadata;
    if (payload.byteLength > metaOffset) {
        const rssi = payload.readInt8(metaOffset);
        metaOffset += 1;
        const noiseFloor = payload.readInt8(metaOffset);
        metaOffset += 1;
        const flags = payload.readUInt16LE(metaOffset);
        metaOffset += 2;
        // Silabs EFR32 PHY: channel: ok, lqi: 0xff or 0x00 (not working?), timestamp: seems ok
        // Silabs EFR32 VEN: error: 0x00 (not implemented?)
        // Silabs EFR32 MAC: ackKeyId: 0x00 (not implemented?), ackFramceCounter: 0x00000000 (not implemented?)
        // let phyChannel: number | undefined;
        // let phyLQI: number | undefined;
        // let phyTimestamp: bigint | undefined;
        // const phyDataLen = payload.readUInt16LE(metaOffset);
        // metaOffset += 2;
        // if (phyDataLen >= 1) {
        //     phyChannel = payload.readUInt8(metaOffset);
        //     metaOffset += 1;
        // }
        // if (phyDataLen >= 2) {
        //     phyLQI = payload.readUInt8(metaOffset);
        //     metaOffset += 1;
        // }
        // if (phyDataLen >= 10) {
        //     phyTimestamp = payload.readBigUInt64LE(metaOffset);
        //     metaOffset += 8;
        // }
        // metaOffset += phyDataLen - 10;
        // let vendorRxError: number | undefined;
        // const vendorDataLen = payload.readUInt16LE(metaOffset);
        // metaOffset += 2;
        // if (vendorDataLen >= 1) {
        //     vendorRxError = payload.readUInt8(metaOffset);
        //     metaOffset += 1;
        // }
        // metaOffset += vendorDataLen - 1;
        // let macACKKeyId: number | undefined;
        // let macACKFrameCounter: number | undefined;
        // const macDataLen = payload.readUInt16LE(metaOffset);
        // metaOffset += 2;
        // if (macDataLen >= 1) {
        //     vendorRxError = payload.readUInt8(metaOffset);
        //     metaOffset += 1;
        // }
        // if (macDataLen >= 5) {
        //     vendorRxError = payload.readUInt32LE(metaOffset);
        //     metaOffset += 4;
        // }
        // metaOffset += macDataLen - 5;
        metadata = {
            rssi,
            noiseFloor,
            flags,
            // phyChannel,
            // phyLQI,
            // phyTimestamp,
            // // phyOtherData,
            // vendorRxError,
            // // vendorOtherData,
            // macACKKeyId,
            // macACKFrameCounter,
            // // macOtherData,
        };
    }
    return [payload.subarray(offset, offset + frameDataLen), metadata];
}
//# sourceMappingURL=spinel.js.map