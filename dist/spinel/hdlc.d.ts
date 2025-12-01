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
export type HdlcFrame = {
    data: Buffer;
    /** For decoded frames, this stops before FCS+FLAG */
    length: number;
    /** Final value should match HDLC_GOOD_FCS */
    fcs: number;
};
/**
 * Check if byte needs HDLC escaping.
 * HOT PATH: Called during frame encoding.
 * Uses simple comparison for fast checking.
 */
export declare function hdlcByteNeedsEscape(aByte: number): boolean;
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
export declare function decodeHdlcFrame(buffer: Buffer): HdlcFrame;
/**
 * @returns The new offset after encoded byte is added
 */
export declare function encodeByte(hdlcFrame: HdlcFrame, aByte: number, dataOffset: number): number;
export declare function encodeHdlcFrame(buffer: Buffer): HdlcFrame;
