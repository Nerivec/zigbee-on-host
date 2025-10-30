import { createSocket } from "node:dgram";
import { describe, it } from "vitest";
import { createWiresharkZEPFrame, DEFAULT_WIRESHARK_IP, DEFAULT_ZEP_UDP_PORT } from "../src/dev/wireshark.js";

/**
 * Util for quick triggering of "send frame to wireshark", not an actual test.
 */
describe.skip("Send to Wireshark", () => {
    let wiresharkSeqNum = 0;

    const nextWiresharkSeqNum = (): number => {
        wiresharkSeqNum = (wiresharkSeqNum + 1) & 0xffffffff;

        return wiresharkSeqNum + 1;
    };

    it("send", () => {
        const wiresharkSocket = createSocket("udp4");
        wiresharkSocket.bind(DEFAULT_ZEP_UDP_PORT);

        const buf = Buffer.from([]);
        const wsZEPFrame = createWiresharkZEPFrame(15, 1, 0, 0, nextWiresharkSeqNum(), buf);

        console.log(wsZEPFrame.toString("hex"));
        wiresharkSocket.send(wsZEPFrame, DEFAULT_ZEP_UDP_PORT, DEFAULT_WIRESHARK_IP, () => {
            wiresharkSocket.close();
        });
    });
});
