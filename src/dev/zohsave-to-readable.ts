import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { OTRCPDriver } from "../drivers/ot-rcp-driver";

async function printSave(dataPath: string): Promise<void> {
    const driver = new OTRCPDriver(
        // @ts-expect-error not needed here
        {},
        {
            eui64: 0n,
            panId: 0,
            extendedPanId: 0n,
            channel: 0,
            nwkUpdateId: -1,
            txPower: 5,
            // ZigBeeAlliance09
            tcKey: Buffer.from([0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39]),
            tcKeyFrameCounter: 0,
            networkKey: Buffer.alloc(16),
            networkKeyFrameCounter: 0,
            networkKeySequenceNumber: 0,
        },
        dataPath,
    );

    await driver.loadState();

    // @ts-expect-error workaround
    BigInt.prototype.toJSON = function (): string {
        return `0x${this.toString(16).padStart(16, "0")}`;
    };
    Buffer.prototype.toJSON = function (): string {
        return this.toString("hex");
    };

    const netParamsJson = JSON.stringify(driver.netParams, undefined, 2);

    console.log(netParamsJson);

    await writeFile(join(dataPath, "zohsave-netparams.json"), netParamsJson, "utf8");

    const devices = [];

    for (const [addr64, device] of driver.deviceTable) {
        devices.push({ addr64, ...device });
    }

    const devicesJson = JSON.stringify(devices, undefined, 2);

    console.log(devicesJson);

    await writeFile(join(dataPath, "zohsave-devices.json"), devicesJson, "utf8");

    const routes = [];

    for (const [addr16, entries] of driver.sourceRouteTable) {
        routes.push({ addr16, entries });
    }

    const routesJson = JSON.stringify(routes, undefined, 2);

    console.log(routesJson);

    await writeFile(join(dataPath, "zohsave-routes.json"), routesJson, "utf8");
}

if (require.main === module) {
    const dataPath = process.argv[2];

    if (!dataPath || dataPath === "help") {
        console.log("Print and save the content of the 'zoh.save' in the given directory in human-readable format (as JSON, in same directory).");
        console.log("Usage:");
        console.log("node ./dist/dev/zohsave-to-readable.js ../path/to/data/");
    } else {
        console.log("Using: ", dataPath);

        if (!existsSync(join(dataPath, "zoh.save"))) {
            throw new Error(`No 'zoh.save' exists at ${dataPath}`);
        }

        void printSave(dataPath);
    }
}
