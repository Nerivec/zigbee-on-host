import { Transform, type TransformCallback, type TransformOptions } from "node:stream";
export declare class OTRCPParser extends Transform {
    #private;
    constructor(opts?: TransformOptions);
    _transform(chunk: Buffer, _encoding: BufferEncoding, cb: TransformCallback): void;
    _flush(cb: TransformCallback): void;
}
