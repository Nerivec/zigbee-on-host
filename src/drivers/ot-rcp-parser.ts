import { Transform, type TransformCallback, type TransformOptions } from "node:stream";
import { HdlcReservedByte } from "../spinel/hdlc.js";
import { logger } from "../utils/logger.js";

const NS = "ot-rcp-driver:parser";

export class OTRCPParser extends Transform {
    #buffer: Buffer;

    public constructor(opts?: TransformOptions) {
        super(opts);

        this.#buffer = Buffer.alloc(0);
    }

    override _transform(chunk: Buffer, _encoding: BufferEncoding, cb: TransformCallback): void {
        let data = Buffer.concat([this.#buffer, chunk]);

        if (data[0] !== HdlcReservedByte.FLAG) {
            // discard data before FLAG
            data = data.subarray(data.indexOf(HdlcReservedByte.FLAG));
        }

        let position: number = data.indexOf(HdlcReservedByte.FLAG, 1);

        while (position !== -1) {
            const endPosition = position + 1;

            // ignore repeated successive flags
            if (position > 1) {
                const frame = data.subarray(0, endPosition);

                logger.debug(() => `<<< FRAME[${frame.toString("hex")}]`, NS);

                this.push(frame);

                // remove the frame from internal buffer (set below)
                data = data.subarray(endPosition);
            } else {
                data = data.subarray(position);
            }

            position = data.indexOf(HdlcReservedByte.FLAG, 1);
        }

        this.#buffer = data;

        cb();
    }

    /* v8 ignore next -- @preserve */
    override _flush(cb: TransformCallback): void {
        if (this.#buffer.byteLength > 0) {
            this.push(this.#buffer);

            this.#buffer = Buffer.alloc(0);
        }

        cb();
    }
}
