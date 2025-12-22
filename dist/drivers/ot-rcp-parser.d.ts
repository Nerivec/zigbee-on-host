import { Transform, type TransformCallback } from "node:stream";
export declare class OTRCPParser extends Transform {
    #private;
    _transform(chunk: Buffer, _encoding: BufferEncoding, cb: TransformCallback): void;
    _flush(cb: TransformCallback): void;
}
