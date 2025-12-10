"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OTRCPParser = void 0;
const node_stream_1 = require("node:stream");
const logger_js_1 = require("../utils/logger.js");
const NS = "ot-rcp-driver:parser";
class OTRCPParser extends node_stream_1.Transform {
    #buffer = Buffer.alloc(0);
    _transform(chunk, _encoding, cb) {
        let data = Buffer.concat([this.#buffer, chunk]);
        if (data[0] !== 126 /* HdlcReservedByte.FLAG */) {
            // discard data before FLAG
            data = data.subarray(data.indexOf(126 /* HdlcReservedByte.FLAG */));
        }
        let position = data.indexOf(126 /* HdlcReservedByte.FLAG */, 1);
        while (position !== -1) {
            const endPosition = position + 1;
            // ignore repeated successive flags
            if (position > 1) {
                const frame = data.subarray(0, endPosition);
                logger_js_1.logger.debug(() => `<<< FRAME[${frame.toString("hex")}]`, NS);
                this.push(frame);
                // remove the frame from internal buffer (set below)
                data = data.subarray(endPosition);
            }
            else {
                data = data.subarray(position);
            }
            position = data.indexOf(126 /* HdlcReservedByte.FLAG */, 1);
        }
        this.#buffer = data;
        cb();
    }
    /* v8 ignore next -- @preserve */
    _flush(cb) {
        if (this.#buffer.byteLength > 0) {
            this.push(this.#buffer);
            this.#buffer = Buffer.alloc(0);
        }
        cb();
    }
}
exports.OTRCPParser = OTRCPParser;
//# sourceMappingURL=ot-rcp-parser.js.map