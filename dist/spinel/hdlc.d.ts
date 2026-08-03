export declare const enum HdlcReservedByte {
    XON = 17,
    XOFF = 19,
    FLAG = 126,
    ESCAPE = 125,
    FLAG_SPECIAL = 248
}
/** Good FCS value. */
export declare const HDLC_GOOD_FCS = 61624;
export declare const HDLC_TX_CHUNK_SIZE = 2048;
/**
 * Update FCS (Frame Check Sequence) with new byte.
 * HOT PATH: Called for every byte in frame during encoding/decoding.
 * Uses lookup table for fast CRC calculation.
 */
export declare function updateFcs(aFcs: number, aByte: number): number;
/**
 * Decode HDLC frame from buffer.
 * HOT PATH: Called for every incoming frame from serial port.
 * Optimized with minimal allocations and inline FCS checking.
 */
export declare function decodeHdlcFrame(buffer: Buffer): Buffer;
export declare function encodeHdlcFrame(buffer: Buffer): Buffer;
