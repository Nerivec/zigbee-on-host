import { Readable } from "node:stream";
export declare class OTRCPWriter extends Readable {
    writeBuffer(buffer: Buffer): void;
    _read(): void;
}
