import assert from "node:assert";
import { encodeHdlcFrame, type HdlcFrame } from "./hdlc.js";
import { SpinelPropertyId } from "./properties.js";

/**
 * Spinel data types:
 *
 * +----------+----------------------+---------------------------------+
 * |   Char   | Name                 | Description                     |
 * +----------+----------------------+---------------------------------+
 * |   "."    | DATATYPE_VOID        | Empty data type. Used           |
 * |          |                      | internally.                     |
 * |   "b"    | DATATYPE_BOOL        | Boolean value. Encoded in       |
 * |          |                      | 8-bits as either 0x00 or 0x01.  |
 * |          |                      | All other values are illegal.   |
 * |   "C"    | DATATYPE_UINT8       | Unsigned 8-bit integer.         |
 * |   "c"    | DATATYPE_INT8        | Signed 8-bit integer.           |
 * |   "S"    | DATATYPE_UINT16      | Unsigned 16-bit integer.        |
 * |   "s"    | DATATYPE_INT16       | Signed 16-bit integer.          |
 * |   "L"    | DATATYPE_UINT32      | Unsigned 32-bit integer.        |
 * |   "l"    | DATATYPE_INT32       | Signed 32-bit integer.          |
 * |   "i"    | DATATYPE_UINT_PACKED | Packed Unsigned Integer. See    |
 * |          |                      | Section 3.2.                    |
 * |   "6"    | DATATYPE_IPv6ADDR    | IPv6 Address. (Big-endian)      |
 * |   "E"    | DATATYPE_EUI64       | EUI-64 Address. (Big-endian)    |
 * |   "e"    | DATATYPE_EUI48       | EUI-48 Address. (Big-endian)    |
 * |   "D"    | DATATYPE_DATA        | Arbitrary data. See Section     |
 * |          |                      | 3.3.                            |
 * |   "d"    | DATATYPE_DATA_WLEN   | Arbitrary data with prepended   |
 * |          |                      | length. See Section 3.3.        |
 * |   "U"    | DATATYPE_UTF8        | Zero-terminated UTF8-encoded    |
 * |          |                      | string.                         |
 * | "t(...)" | DATATYPE_STRUCT      | Structured datatype with        |
 * |          |                      | prepended length. See Section   |
 * |          |                      | 3.4.                            |
 * | "A(...)" | DATATYPE_ARRAY       | Array of datatypes. Compound    |
 * |          |                      | type. See Section 3.5.          |
 * +----------+----------------------+---------------------------------+
 */

/**
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * |  FLG  |  NLI  |      TID      |
 * +---+---+---+---+---+---+---+---+
 */
type SpinelFrameHeader = {
    /**
     * The least significant bits of the header represent the Transaction
     * Identifier(TID).  The TID is used for correlating responses to the
     * commands which generated them.
     *
     * When a command is sent from the host, any reply to that command sent
     * by the NCP will use the same value for the TID.  When the host
     * receives a frame that matches the TID of the command it sent, it can
     * easily recognize that frame as the actual response to that command.
     *
     * The TID value of zero (0) is used for commands to which a correlated
     * response is not expected or needed, such as for unsolicited update
     * commands sent to the host from the NCP.
     */
    tid: number;
    /**
     * The Network Link Identifier (NLI) is a number between 0 and 3, which
     * is associated by the OS with one of up to four IPv6 zone indices
     * corresponding to conceptual IPv6 interfaces on the NCP.  This allows
     * the protocol to support IPv6 nodes connecting simultaneously to more
     * than one IPv6 network link using a single NCP instance.  The first
     * Network Link Identifier (0) MUST refer to a distinguished conceptual
     * interface provided by the NCP for its IPv6 link type.  The other
     * three Network Link Identifiers (1, 2 and 3) MAY be dissociated from
     * any conceptual interface.
     */
    nli: number;
    /**
     * The flag field of the header byte ("FLG") is always set to the value
     * two (or "10" in binary).  Any frame received with these bits set to
     * any other value else MUST NOT be considered a Spinel frame.
     *
     * This convention allows Spinel to be line compatible with BTLE HCI.
     * By defining the first two bit in this way we can disambiguate between
     * Spinel frames and HCI frames (which always start with either "0x01"
     * or "0x04") without any additional framing overhead.
     */
    flg: number;
};

/**
 *  0               1               2               3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     HEADER    |  COMMAND ID   | PAYLOAD ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
export type SpinelFrame = {
    header: SpinelFrameHeader;
    /**
     * The command identifier is a 21-bit unsigned integer encoded in up to
     * three bytes using the packed unsigned integer format described in
     * Section 3.2.  This encoding allows for up to 2,097,152 individual
     * commands, with the first 127 commands represented as a single byte.
     * Command identifiers larger than 2,097,151 are explicitly forbidden.
     *
     * +-----------------------+----------------------------+
     * |       CID Range       |        Description         |
     * +-----------------------+----------------------------+
     * |         0 - 63        | Reserved for core commands |
     * |      64 - 15,359      |       _UNALLOCATED_        |
     * |    15,360 - 16,383    |      Vendor-specific       |
     * |   16,384 - 1,999,999  |       _UNALLOCATED_        |
     * | 2,000,000 - 2,097,151 |   Experimental use only    |
     * +-----------------------+----------------------------+
     */
    commandId: number;
    /**
     * Depending on the semantics of the command in question, a payload MAY
     * be included in the frame.  The exact composition and length of the
     * payload is defined by the command identifier.
     */
    payload: Buffer;
};

export const enum SpinelResetReason {
    PLATFORM = 1,
    STACK = 2,
    BOOTLOADER = 3,
}

const SPINEL_HEADER_TID_MASK = 0x0f;
const SPINEL_HEADER_NLI_MASK = 0x30;
const SPINEL_HEADER_NLI_SHIFT = 4;
const SPINEL_HEADER_FLG_MASK = 0xc0;
const SPINEL_HEADER_FLG_SHIFT = 6;
/** @see SpinelFrameHeader.flg */
export const SPINEL_HEADER_FLG_SPINEL = 2;

export const SPINEL_RCP_API_VERSION = 11;

/**
 * Decode HDLC frame into Spinel frame
 * HOT PATH: Called for every incoming frame from RCP.
 */
/* @__INLINE__ */
export function decodeSpinelFrame(hdlcFrame: HdlcFrame): SpinelFrame {
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
export function encodeSpinelFrame(frame: SpinelFrame): HdlcFrame {
    const cmdIdSize = getPackedUIntSize(frame.commandId);
    const buffer = Buffer.alloc(frame.payload.byteLength + 1 + cmdIdSize);
    const headerByte =
        (frame.header.tid & SPINEL_HEADER_TID_MASK) |
        ((frame.header.nli << SPINEL_HEADER_NLI_SHIFT) & SPINEL_HEADER_NLI_MASK) |
        ((frame.header.flg << SPINEL_HEADER_FLG_SHIFT) & SPINEL_HEADER_FLG_MASK);
    buffer[0] = headerByte;
    const outOffset = setPackedUInt(buffer, 1, frame.commandId, cmdIdSize);
    buffer.set(frame.payload, outOffset);

    return encodeHdlcFrame(buffer);
}

const SPINEL_PACKED_UINT_MASK = 0x80;
const SPINEL_PACKED_UINT_MSO_MASK = 0x7f;

/**
 * Calculate size needed for packed unsigned integer encoding.
 * HOT PATH: Called during frame encoding.
 */
/* @__INLINE__ */
export function getPackedUIntSize(value: number): number {
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
export function setPackedUInt(data: Buffer, offset: number, value: number, size?: number): number {
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
export function getPackedUInt(data: Buffer, offset: number): [value: number, outOffset: number] {
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
export function writePropertyId(propertyId: SpinelPropertyId, size: number): [Buffer, outOffset: number] {
    const propIdSize = getPackedUIntSize(propertyId);
    const buf = Buffer.alloc(propIdSize + size);
    const offset = setPackedUInt(buf, 0, propertyId, propIdSize);

    return [buf, offset];
}

/** Write as boolean */
export function writePropertyb(propertyId: SpinelPropertyId, value: boolean): Buffer {
    const [buf, offset] = writePropertyId(propertyId, 1);
    buf[offset] = value ? 1 : 0;

    return buf;
}

/** Read as boolean */
export function readPropertyb(propertyId: SpinelPropertyId, data: Buffer, offset = 0): boolean {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    return !!data[pOutOffset];
}

/** Write as uint8 */
export function writePropertyC(propertyId: SpinelPropertyId, value: number): Buffer {
    const [buf, offset] = writePropertyId(propertyId, 1);
    buf[offset] = value as number;

    return buf;
}

/** Read as uint8 */
export function readPropertyC(propertyId: SpinelPropertyId, data: Buffer, offset = 0): number {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    return data[pOutOffset];
}

/** Write as list of uint8 */
export function writePropertyAC(propertyId: SpinelPropertyId, values: number[]): Buffer {
    const [buf, pOffset] = writePropertyId(propertyId, values.length);
    let offset = pOffset;

    for (const value of values) {
        buf.writeUInt8(value, offset);
        offset += 1;
    }

    return buf;
}

/** Write as int8 */
export function writePropertyc(propertyId: SpinelPropertyId, value: number): Buffer {
    const [buf, offset] = writePropertyId(propertyId, 1);

    buf.writeInt8(value as number, offset);

    return buf;
}

/** Read as int8 */
export function readPropertyc(propertyId: SpinelPropertyId, data: Buffer, offset = 0): number {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    return data.readInt8(pOutOffset);
}

/** Write as uint16 */
export function writePropertyS(propertyId: SpinelPropertyId, value: number): Buffer {
    const [buf, offset] = writePropertyId(propertyId, 2);

    buf.writeUInt16LE(value as number, offset);

    return buf;
}

/** Read as uint16 */
export function readPropertyS(propertyId: SpinelPropertyId, data: Buffer, offset = 0): number {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    return data.readUInt16LE(pOutOffset);
}

/** Write as int16 */
export function writePropertys(propertyId: SpinelPropertyId, value: number): Buffer {
    const [buf, offset] = writePropertyId(propertyId, 2);

    buf.writeInt16LE(value as number, offset);

    return buf;
}

/** Write as uint32 */
export function writePropertyL(propertyId: SpinelPropertyId, value: number): Buffer {
    const [buf, offset] = writePropertyId(propertyId, 4);

    buf.writeUInt32LE(value as number, offset);

    return buf;
}

/** Write as int32 */
export function writePropertyl(propertyId: SpinelPropertyId, value: number): Buffer {
    const [buf, offset] = writePropertyId(propertyId, 4);

    buf.writeInt32LE(value as number, offset);

    return buf;
}

/** Write as packed uint */
export function writePropertyi(propertyId: SpinelPropertyId, value: number): Buffer {
    const valueSize = getPackedUIntSize(value as number);
    const [buf, offset] = writePropertyId(propertyId, valueSize);

    setPackedUInt(buf, offset, value as number, valueSize);

    return buf;
}

/** Read as packed uint */
export function readPropertyi(propertyId: SpinelPropertyId, data: Buffer, offset = 0): number {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    const [i] = getPackedUInt(data, pOutOffset);

    return i;
}

/** Read as packed uint x2 */
export function readPropertyii(propertyId: SpinelPropertyId, data: Buffer, offset = 0): [i1: number, i2: number] {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    const [major, maOutOffset] = getPackedUInt(data, pOutOffset);
    const [minor] = getPackedUInt(data, maOutOffset);

    return [major, minor];
}

/** Read as list of packed uint */
export function readPropertyAi(propertyId: SpinelPropertyId, data: Buffer, offset = 0): number[] {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    const caps: number[] = [];

    for (let i = pOutOffset; i < data.byteLength; ) {
        const [cap, cOutOffset] = getPackedUInt(data, i);

        caps.push(cap);

        i += cOutOffset;
    }

    return caps;
}

/** Write as UTF8 string */
export function writePropertyU(propertyId: SpinelPropertyId, value: string): Buffer {
    const [buf, offset] = writePropertyId(propertyId, value.length);

    buf.write(value, offset, "utf8");

    return buf;
}

/** Read as UTF8 string */
export function readPropertyU(propertyId: SpinelPropertyId, data: Buffer, offset = 0): string {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    return data.toString("utf8", pOutOffset);
}

/** Write as bigint */
export function writePropertyE(propertyId: SpinelPropertyId, value: bigint): Buffer {
    const [buf, offset] = writePropertyId(propertyId, 8);

    buf.writeBigUInt64BE(value, offset);

    return buf;
}

/** Read as bigint */
export function readPropertyE(propertyId: SpinelPropertyId, data: Buffer, offset = 0): bigint {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    return data.readBigUInt64BE(pOutOffset);
}

/** Write as Buffer of specific length */
export function writePropertyd(propertyId: SpinelPropertyId, value: Buffer): Buffer {
    const [buf, offset] = writePropertyId(propertyId, 2 + value.byteLength);

    buf.writeUInt16LE(value.byteLength, offset);
    buf.set(value, offset);

    return buf;
}

/** Read as Buffer of specific length */
export function readPropertyd(propertyId: SpinelPropertyId, data: Buffer, offset = 0): Buffer {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    const length = data.readUInt16LE(pOutOffset);
    const lOutOffset = pOutOffset + 2;

    return data.subarray(lOutOffset, lOutOffset + length);
}

/** Write as Buffer of remaining length */
export function writePropertyD(propertyId: SpinelPropertyId, value: Buffer): Buffer {
    const [buf, offset] = writePropertyId(propertyId, value.byteLength);

    buf.set(value, offset);

    return buf;
}

/** Read as Buffer of remaining length */
export function readPropertyD(propertyId: SpinelPropertyId, data: Buffer, offset = 0): Buffer {
    const [propId, pOutOffset] = getPackedUInt(data, offset);
    assert(propId === propertyId);

    return data.subarray(pOutOffset);
}

/** @see SpinelPropertyId.STREAM_RAW */
export type StreamRawConfig = {
    /**
     * `C` : Channel (for frame tx) - MUST be included.
     *
     */
    txChannel: number;
    /**
     * `C` : Maximum number of backoffs attempts before declaring CCA failure (use Thread stack default if not specified)
     *
     */
    ccaBackoffAttempts: number;
    /**
     * `C` : Maximum number of retries allowed after a transmission failure (use Thread stack default if not specified)
     *
     */
    ccaRetries: number;
    /**
     * `b` : Set to true to enable CSMA-CA for this packet, false otherwise. (default true).
     *
     * Set to true to enable CSMA-CA for this packet, false to disable both CSMA backoff and CCA.
     *
     * When it is set to `false`, the frame MUST be sent without performing CCA. In this case `mMaxCsmaBackoffs` MUST also be ignored.
     */
    enableCSMACA: boolean;
    /**
     * `b` : Set to true to indicate if header is updated - related to `mIsHeaderUpdated` in `otRadioFrame` (default false).
     *
     * Indicates whether frame counter and CSL IEs are properly updated in the header.
     *
     * If the platform layer does not provide `OT_RADIO_CAPS_TRANSMIT_SEC` capability, it can ignore this flag.
     *
     * If the platform provides `OT_RADIO_CAPS_TRANSMIT_SEC` capability, then platform is expected to handle tx
     * security processing and assignment of frame counter. In this case the following behavior is expected:
     *
     * When `mIsHeaderUpdated` is set, it indicates that OpenThread core has already set the frame counter and
     * CSL IEs (if security is enabled) in the prepared frame. The counter is ensured to match the counter value
     * from the previous attempts of the same frame. The platform should not assign or change the frame counter
     * (but may still need to perform security processing depending on `mIsSecurityProcessed` flag).
     *
     * If `mIsHeaderUpdated` is not set, then the frame counter and key CSL IE not set in the frame by
     * OpenThread core and it is the responsibility of the radio platform to assign them. The platform
     * must update the frame header (assign counter and CSL IE values) before sending the frame over the air,
     * however if the the transmission gets aborted and the frame is never sent over the air (e.g., channel
     * access error) the platform may choose to not update the header. If the platform updates the header,
     * it must also set this flag before passing the frame back from the `otPlatRadioTxDone()` callback.
     */
    headerUpdated: boolean;
    /**
     * `b` : Set to true to indicate it is a retransmission - related to `mIsARetx` in `otRadioFrame` (default false).
     *
     * Indicates whether the frame is a retransmission or not.
     */
    reTx: boolean;
    /**
     * `b` : Set to true to indicate security was processed on tx frame `mIsSecurityProcessed` in `otRadioFrame` (default false).
     *
     * True if SubMac should skip the AES processing of this frame.
     */
    securityProcessed: boolean;
    /**
     * `L` : TX delay interval used for CSL - related to `mTxDelay` in `otRadioFrame` (default zero).
     *
     * The delay time in microseconds for this transmission referenced to `mTxDelayBaseTime`.
     *
     * Note: `mTxDelayBaseTime` + `mTxDelay` SHALL point to the point in time when the end of the SFD will be present at the local
     * antenna, relative to the local radio clock.
     *
     * If this field is non-zero, `mMaxCsmaBackoffs` should be ignored.
     *
     * This field does not affect CCA behavior which is controlled by `mCsmaCaEnabled`.
     */
    txDelay: number;
    /**
     * `L` : TX delay based time used for CSL - related to `mTxDelayBaseTime` in `otRadioFrame` (default zero).
     *
     * The base time in microseconds for scheduled transmissions relative to the local radio clock, see `otPlatRadioGetNow` and `mTxDelay`.
     *
     * If this field is non-zero, `mMaxCsmaBackoffs` should be ignored.
     *
     * This field does not affect CCA behavior which is controlled by `mCsmaCaEnabled`.
     */
    txDelayBaseTime: number;
    /**
     * `C` : RX channel after TX done (default assumed to be same as channel in metadata)
     *
     * The RX channel after frame TX is done (after all frame retries - ack received, or timeout, or abort).
     *
     * Radio platforms can choose to fully ignore this. OT stack will make sure to call `otPlatRadioReceive()`
     * with the desired RX channel after a frame TX is done and signaled in `otPlatRadioTxDone()` callback.
     * Radio platforms that don't provide `OT_RADIO_CAPS_TRANSMIT_RETRIES` must always ignore this.
     *
     * This is intended for situations where there may be delay in interactions between OT stack and radio, as
     * an example this is used in RCP/host architecture to make sure RCP switches to PAN channel more quickly.
     * In particular, this can help with CSL tx to a sleepy child, where the child may use a different channel
     * for CSL than the PAN channel. After frame tx, we want the radio/RCP to go back to the PAN channel
     * quickly to ensure that parent does not miss tx from child afterwards, e.g., child responding to the
     * earlier CSL transmitted frame from parent using PAN channel while radio still staying on CSL channel.
     *
     * The switch to the RX channel MUST happen after the frame TX is fully done, i.e., after all retries and
     * when ack is received (when "Ack Request" flag is set on the TX frame) or ack timeout. Note that ack is
     * expected on the same channel that frame is sent on.
     */
    rxChannelAfterTxDone: number;
};

/** @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.6.2 */
export function writePropertyStreamRaw(data: Buffer, config: StreamRawConfig): Buffer {
    const [buf, pOutOffset] = writePropertyId(SpinelPropertyId.STREAM_RAW, data.byteLength + 18);
    let offset = pOutOffset;

    buf.writeUInt16LE(data.byteLength, offset);
    offset += 2;

    buf.set(data, offset);
    offset += data.byteLength;

    buf.writeUInt8(config.txChannel, offset);
    offset += 1;

    buf.writeUInt8(config.ccaBackoffAttempts, offset);
    offset += 1;

    buf.writeUInt8(config.ccaRetries, offset);
    offset += 1;

    buf.writeUInt8(config.enableCSMACA ? 1 : 0, offset);
    offset += 1;

    buf.writeUInt8(config.headerUpdated ? 1 : 0, offset);
    offset += 1;

    buf.writeUInt8(config.reTx ? 1 : 0, offset);
    offset += 1;

    buf.writeUInt8(config.securityProcessed ? 1 : 0, offset);
    offset += 1;

    buf.writeUInt32LE(config.txDelay, offset);
    offset += 4;

    buf.writeUInt32LE(config.txDelayBaseTime, offset);
    offset += 4;

    buf.writeUInt8(config.rxChannelAfterTxDone, offset);
    offset += 1;

    return buf;
}

/**
 * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.6.2.1
 * +----------+-----------------------+------------+-----+---------+
 * | Field    | Description           | Type       | Len | Default |
 * +----------+-----------------------+------------+-----+---------+
 * | MD_POWER | (dBm) RSSI/TX-Power   | "c" int8   |  1  |   -128  |
 * | MD_NOISE | (dBm) Noise floor     | "c" int8   |  1  |   -128  |
 * | MD_FLAG  | Flags (defined below) | "S" uint16 |  2  |         |
 * | MD_PHY   | PHY-specific data     | "d" data   | >=2 |         |
 * | MD_VEND  | Vendor-specific data  | "d" data   | >=2 |         |
 * +----------+-----------------------+------------+-----+---------+
 *
 * The bit values in "MD_FLAG" are defined as follows:
 * +---------+--------+------------------+-----------------------------+
 * |   Bit   |  Mask  | Name             | Description if set          |
 * +---------+--------+------------------+-----------------------------+
 * |    15   | 0x0001 | MD_FLAG_TX       | Packet was transmitted, not |
 * |         |        |                  | received.                   |
 * |    13   | 0x0004 | MD_FLAG_BAD_FCS  | Packet was received with    |
 * |         |        |                  | bad FCS                     |
 * |    12   | 0x0008 | MD_FLAG_DUPE     | Packet seems to be a        |
 * |         |        |                  | duplicate                   |
 * |  0-11,  | 0xFFF2 | MD_FLAG_RESERVED | Flags reserved for future   |
 * |    14   |        |                  | use.                        |
 * +---------+--------+------------------+-----------------------------+
 */
export type SpinelStreamRawMetadata = {
    /** int8 */
    rssi: number;
    /** int8 */
    noiseFloor: number;
    /** uint16 */
    flags: number;
    // XXX: unreliable?
    // /** uint8 */
    // phyChannel?: number;
    // /** uint8 */
    // phyLQI?: number;
    // /** uint64 */
    // phyTimestamp?: bigint;
    // // phyOtherData?: unknown;
    // /** uint8 */
    // vendorRxError?: number;
    // // vendorOtherData?: unknown;
    // /** uint8 */
    // macACKKeyId?: number;
    // /** uint32 */
    // macACKFrameCounter?: number;
    // // macOtherData?: unknown;
};

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
export function readStreamRaw(payload: Buffer, offset: number): [macData: Buffer, metadata: SpinelStreamRawMetadata | undefined] {
    const frameDataLen = payload.readUInt16LE(offset);
    offset += 2;
    let metaOffset = offset + frameDataLen;
    let metadata: SpinelStreamRawMetadata | undefined;

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
