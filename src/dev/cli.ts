import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { StreamRawConfig } from "../spinel/spinel.js";
import { MinimalAdapter, type PortOptions, type ResetType, type StartOptions } from "./minimal-adapter.js";

type Conf = {
    adapter: PortOptions;
    streamRaw: StreamRawConfig;
    network: {
        tcKey: number[];
        tcKeyFrameCounter: number;
        networkKey: number[];
        networkKeyFrameCounter: number;
        networkKeySequenceNumber: number;
        panId: number;
        extendedPANId: number[];
        channel: number;
        eui64: number[];
        nwkUpdateId: number;
        txPower: number;
    };
    sendMACToZEP: boolean;
};

function argToBool(arg: string): boolean {
    arg = arg.toLowerCase();

    return arg === "1" || arg === "true" || arg === "yes" || arg === "on";
}

function printHelp(shouldThrow: boolean): void {
    console.log("\nForm:");
    console.log("    dev:cli form <allow_joins>");

    // console.log("\nScan:");
    // console.log("    dev:cli scan <channels_csv min=11 max=26> <period_per_channel min=50 max=500> [tx_power min=-128 max=127]");

    console.log("\nSniff:");
    console.log("    dev:cli sniff <channel min=11 max=26>");

    console.log("\nReset:");
    console.log("    dev:cli reset <stack|bootloader>");

    console.log("\n- Boolean 'yes' can take any of the following forms (any other will be considered no/false): 1, true, yes, on");
    console.log("- CSVs are expected without spaces");
    console.log("- Following ENV vars will override 'conf.json': ADAPTER_PATH, ADAPTER_BAUDRATE, ADAPTER_RTSCTS");
    console.log(
        "- If you have any trouble starting a command after completing another, try to unplug/replug the adapter or the 'reset stack' command",
    );

    if (shouldThrow) {
        throw new Error("Invalid parameters");
    }
}

if (require.main === module) {
    const confPath = join(__dirname, "conf.json");
    const conf = JSON.parse(readFileSync(confPath, "utf8")) as Conf;

    if (process.env.ADAPTER_PATH) {
        conf.adapter.path = process.env.ADAPTER_PATH;
    }

    if (process.env.ADAPTER_BAUDRATE) {
        conf.adapter.baudRate = Number.parseInt(process.env.ADAPTER_BAUDRATE, 10);
    }

    if (process.env.ADAPTER_RTSCTS) {
        conf.adapter.rtscts = argToBool(process.env.ADAPTER_RTSCTS);
    }

    console.log("Starting with conf:", JSON.stringify(conf));

    if (process.argv[2] === "help") {
        // after above log to be able to see conf without side-effect
        printHelp(false);
    } else {
        if (process.argv.length <= 2) {
            printHelp(true);
        }

        const mode = process.argv[2] as StartOptions["mode"]; // typing validated below

        if (mode !== "form" && mode !== "scan" && mode !== "sniff" && mode !== "reset") {
            printHelp(true);
        }

        const adapter = new MinimalAdapter(
            conf.adapter,
            conf.streamRaw,
            // NOTE: this information is overwritten on `start` if a save exists
            {
                eui64: Buffer.from(conf.network.eui64).readBigUInt64LE(0),
                panId: conf.network.panId,
                extendedPanId: Buffer.from(conf.network.extendedPANId).readBigUInt64LE(0),
                channel: conf.network.channel,
                nwkUpdateId: conf.network.nwkUpdateId,
                txPower: conf.network.txPower,
                networkKey: Buffer.from(conf.network.networkKey),
                networkKeyFrameCounter: conf.network.networkKeyFrameCounter,
                networkKeySequenceNumber: conf.network.networkKeySequenceNumber,
                tcKey: Buffer.from(conf.network.tcKey),
                tcKeyFrameCounter: conf.network.tcKeyFrameCounter,
            },
            conf.sendMACToZEP || mode === "sniff",
        );

        const onStop = async () => {
            switch (mode) {
                case "form": {
                    break;
                }
                // case "scan": {
                //     // await adapter.driver.stopEnergyScan();
                //     break;
                // }
                case "sniff": {
                    await adapter.driver.stopSniffer();
                    break;
                }
                case "reset": {
                    break;
                }
            }

            await adapter.stop();
        };

        process.on("SIGINT", onStop);
        process.on("SIGTERM", onStop);

        switch (mode) {
            case "form": {
                if (process.argv.length !== 4) {
                    printHelp(true);
                }

                const allowJoins = argToBool(process.argv[3]);

                console.log(`Starting 'form' mode with allowJoins=${allowJoins} (advanced configs loaded from ${confPath})`);

                void adapter.start({ mode: "form", allowJoins });
                break;
            }

            // TODO: not stable...
            // case "scan": {
            //     if (process.argv.length !== 5 && process.argv.length !== 6) {
            //         printHelp();
            //     }

            //     const channels = process.argv[3].split(",").map((v) => {
            //         const channel = Number.parseInt(v, 10);

            //         if (channel > 26 || channel < 11) {
            //             throw new Error("Invalid channel: [11..26]");
            //         }

            //         return channel;
            //     });

            //     const period = Math.min(Math.max(Number.parseInt(process.argv[4], 10), 50), 500);
            //     const txPower = process.argv[5] ? Math.min(Math.max(Number.parseInt(process.argv[5], 10), -128), 127) : conf.network.txPower;

            //     console.log(`Starting 'scan' mode with channels=${channels} period=${period} txPower=${txPower}`);

            //     void adapter.start({ mode: "scan", channels, period, txPower });
            //     break;
            // }

            case "sniff": {
                if (process.argv.length !== 4) {
                    printHelp(true);
                }

                const channel = Number.parseInt(process.argv[3], 10);

                if (channel > 26 || channel < 11) {
                    throw new Error("Invalid channel: [11..26]");
                }

                console.log(`Starting 'sniff' mode with channel=${channel}`);

                void adapter.start({ mode: "sniff", channel });
                break;
            }

            case "reset": {
                if (process.argv.length !== 3 && process.argv.length !== 4) {
                    printHelp(true);
                }

                const type = process.argv[3] as ResetType; // typing validated below

                if (type && type !== "stack" && type !== "bootloader") {
                    printHelp(true);
                }

                console.log("Starting 'reset' mode");

                void adapter.start({ mode: "reset", type: type ?? "stack" });
                break;
            }
        }
    }
}
