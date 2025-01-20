import { readFileSync } from "node:fs";
import { join } from "node:path";
import { MinimalAdapter } from "./minimal-adapter.js";

if (require.main === module) {
    // biome-ignore lint/suspicious/noExplicitAny: dev
    const conf = JSON.parse(readFileSync(join(__dirname, "conf.json"), "utf8")) as Record<string, any>;

    console.log("Starting with conf:", JSON.stringify(conf));

    const adapter = new MinimalAdapter(
        conf.adapter,
        conf.streamRaw,
        // NOTE: this information is overwritten on `start` if a save exists
        {
            eui64: Buffer.from(conf.network.eui64).readBigUInt64LE(0),
            panId: conf.network.panId,
            extendedPANId: Buffer.from(conf.network.extendedPANId).readBigUInt64LE(0),
            channel: conf.network.channel,
            nwkUpdateId: conf.network.nwkUpdateId,
            txPower: conf.network.txPower,
            networkKey: Buffer.from(conf.network.networkKey),
            networkKeyFrameCounter: conf.network.networkKeyFrameCounter,
            networkKeySequenceNumber: conf.network.networkKeySequenceNumber,
            tcKey: Buffer.from(conf.network.tcKey),
            tcKeyFrameCounter: conf.network.tcKeyFrameCounter,
        },
        conf.sendMACToZEP,
    );

    process.on("SIGINT", async () => await adapter.stop());
    process.on("SIGTERM", async () => await adapter.stop());

    void adapter.start();
}
