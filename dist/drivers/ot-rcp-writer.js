"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OTRCPWriter = void 0;
const node_stream_1 = require("node:stream");
const logger_js_1 = require("../utils/logger.js");
const NS = "ot-rcp-driver:writer";
class OTRCPWriter extends node_stream_1.Readable {
    writeBuffer(buffer) {
        logger_js_1.logger.debug(() => `>>> FRAME[${buffer.toString("hex")}]`, NS);
        // this.push(buffer);
        this.emit("data", buffer); // XXX: this is faster
    }
    /* v8 ignore next -- @preserve */
    _read() { }
}
exports.OTRCPWriter = OTRCPWriter;
//# sourceMappingURL=ot-rcp-writer.js.map