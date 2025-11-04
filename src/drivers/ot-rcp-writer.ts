import { Readable } from "node:stream";
import { logger } from "../utils/logger.js";

const NS = "ot-rcp-driver:writer";

export class OTRCPWriter extends Readable {
    public writeBuffer(buffer: Buffer): void {
        logger.debug(() => `>>> FRAME[${buffer.toString("hex")}]`, NS);

        // this.push(buffer);
        this.emit("data", buffer); // XXX: this is faster
    }

    /* v8 ignore next -- @preserve */
    public override _read(): void {}
}
