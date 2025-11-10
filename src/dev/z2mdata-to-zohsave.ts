import assert from "node:assert";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { OTRCPDriver } from "../drivers/ot-rcp-driver";

type DeviceDatabaseEntry = {
    id: number;
    type: "Coordinator" | "Router" | "EndDevice" | "Unknown" | "GreenPower";
    nwkAddr: number;
    ieeeAddr: string;
    powerSource?:
        | "Unknown"
        | "Mains (single phase)"
        | "Mains (3 phase)"
        | "Battery"
        | "DC Source"
        | "Emergency mains constantly powered"
        | "Emergency mains and transfer switch";
    interviewCompleted: boolean;
};
type GroupDatabaseEntry = {
    id: number;
    type: "Group";
    members: { deviceIeeeAddr: string; endpointID: number }[];
    groupID: number;
};

type DatabaseEntry = DeviceDatabaseEntry | GroupDatabaseEntry;

async function openDb(path: string): Promise<[devices: DeviceDatabaseEntry[], groups: GroupDatabaseEntry[]]> {
    const devices: DeviceDatabaseEntry[] = [];
    const groups: GroupDatabaseEntry[] = [];

    if (existsSync(path)) {
        const file = await readFile(path, "utf-8");

        for (const row of file.split("\n")) {
            if (!row) {
                continue;
            }

            try {
                const json = JSON.parse(row) as DatabaseEntry;

                switch (json.type) {
                    case "Group": {
                        groups.push(json);
                        break;
                    }
                    case "EndDevice":
                    case "Router":
                    case "GreenPower":
                    case "Unknown": {
                        devices.push(json);
                        break;
                    }
                }
            } catch (error) {
                console.error(`Corrupted database line, ignoring. ${error}`);
            }
        }
    } else {
        console.error(`Invalid DB path ${path}`);
    }

    return [devices, groups];
}

export interface UnifiedBackupStorage {
    metadata: {
        format: "zigpy/open-coordinator-backup";
        version: 1;
        source: string;
        internal: {
            /* zigbee-herdsman specific data */
            date: string;
            znpVersion?: number;
            ezspVersion?: number;

            [key: string]: unknown;
        };
    };
    // biome-ignore lint/style/useNamingConvention: out of control
    stack_specific?: {
        zstack?: {
            // biome-ignore lint/style/useNamingConvention: out of control
            tclk_seed?: string;
        };
        ezsp?: {
            // biome-ignore lint/style/useNamingConvention: out of control
            hashed_tclk?: string;
        };
    };
    // biome-ignore lint/style/useNamingConvention: out of control
    coordinator_ieee: string;
    // biome-ignore lint/style/useNamingConvention: out of control
    pan_id: string;
    // biome-ignore lint/style/useNamingConvention: out of control
    extended_pan_id: string;
    // biome-ignore lint/style/useNamingConvention: out of control
    security_level: number;
    // biome-ignore lint/style/useNamingConvention: out of control
    nwk_update_id: number;
    channel: number;
    // biome-ignore lint/style/useNamingConvention: out of control
    channel_mask: number[];
    // biome-ignore lint/style/useNamingConvention: out of control
    network_key: {
        key: string;
        // biome-ignore lint/style/useNamingConvention: out of control
        sequence_number: number;
        // biome-ignore lint/style/useNamingConvention: out of control
        frame_counter: number;
    };
    devices: {
        // biome-ignore lint/style/useNamingConvention: out of control
        nwk_address: string | null;
        // biome-ignore lint/style/useNamingConvention: out of control
        ieee_address: string;
        // biome-ignore lint/style/useNamingConvention: out of control
        is_child: boolean;
        // biome-ignore lint/style/useNamingConvention: out of control
        link_key: { key: string; rx_counter: number; tx_counter: number } | undefined;
    }[];
}

function findDeviceInBackup(backup: UnifiedBackupStorage, ieeeAddress: string): UnifiedBackupStorage["devices"][number] | undefined {
    return backup.devices.find((d) => d.ieee_address === ieeeAddress.slice(2 /* 0x */));
}

async function convert(dataPath: string): Promise<void> {
    const backup = JSON.parse(await readFile(join(dataPath, "coordinator_backup.json"), "utf8")) as UnifiedBackupStorage;

    if (backup.metadata.version !== 1) {
        throw new Error(`Coordinator Backup of version ${backup.metadata.version} not supported`);
    }

    if (!backup.metadata.source.includes("zigbee-herdsman")) {
        throw new Error("Coordinator Backup not from Zigbee2MQTT not supported");
    }

    const isEmber = Boolean(backup.stack_specific?.ezsp?.hashed_tclk);
    const isZstack = Boolean(backup.stack_specific?.zstack?.tclk_seed);

    if (!isEmber && !isZstack) {
        throw new Error("Coordinator Backup not from [ember, zstack] drivers not supported");
    }

    let txPower = 5;

    if (existsSync(join(dataPath, "configuration.yaml"))) {
        const conf = await readFile(join(dataPath, "configuration.yaml"), "utf8");
        const txPowerMatch = conf.match(/transmit_power: (\d*)$/m);

        if (txPowerMatch) {
            txPower = Number.parseInt(txPowerMatch[1], 10);
        }
    }

    const eui64Buf = Buffer.from(backup.coordinator_ieee, "hex");
    const eui64 = isEmber ? eui64Buf.readBigUInt64LE(0) : /* isZstack */ eui64Buf.readBigUInt64BE(0);
    const panId = Number.parseInt(backup.pan_id, 16);
    const extendedPanId = Buffer.from(backup.extended_pan_id, "hex").readBigUInt64LE(0);
    const channel = backup.channel;
    const nwkUpdateId = backup.nwk_update_id;
    const networkKey = Buffer.from(backup.network_key.key, "hex");
    const networkKeyFrameCounter = backup.network_key.frame_counter;
    const networkKeySequenceNumber = backup.network_key.sequence_number;

    let driver = new OTRCPDriver(
        // @ts-expect-error not needed here
        {},
        {},
        {
            eui64,
            panId,
            extendedPanId,
            channel,
            nwkUpdateId,
            txPower,
            // ZigBeeAlliance09
            tcKey: Buffer.from([0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39]),
            tcKeyFrameCounter: 0,
            networkKey,
            networkKeyFrameCounter,
            networkKeySequenceNumber,
        },
        dataPath,
    );
    const [devices /*, group*/] = await openDb(join(dataPath, "database.db"));

    for (const device of devices) {
        const backupDevice = findDeviceInBackup(backup, device.ieeeAddr);

        driver.context.deviceTable.set(BigInt(device.ieeeAddr), {
            address16: device.nwkAddr,
            // this could be... wrong, devices not always use this properly
            capabilities: {
                alternatePANCoordinator: false,
                deviceType: device.type === "Router" ? 0x01 : 0x00,
                powerSource: device.powerSource !== "Unknown" && device.powerSource !== "Battery" ? 0x01 : 0x00,
                rxOnWhenIdle: device.type === "Router" && device.powerSource !== "Unknown" && device.powerSource !== "Battery",
                securityCapability: false,
                allocateAddress: true,
            },
            // technically not correct, but reasonable expectation
            authorized: device.interviewCompleted === true,
            // add support for not knowing this in driver (re-evaluation)
            neighbor: backupDevice?.is_child !== true,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
        });
    }

    // for (const group of groups) {}

    await driver.context.saveState();

    driver = new OTRCPDriver(
        // @ts-expect-error not needed here
        {},
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

    await driver.context.loadState();

    assert(driver.context.netParams.eui64 === eui64);
    assert(driver.context.netParams.panId === panId);
    assert(driver.context.netParams.extendedPanId === extendedPanId);
    assert(driver.context.netParams.nwkUpdateId === nwkUpdateId);
    assert(driver.context.netParams.networkKey.equals(networkKey));
    assert(driver.context.netParams.networkKeyFrameCounter === networkKeyFrameCounter + 1024);
    assert(driver.context.netParams.networkKeySequenceNumber === networkKeySequenceNumber);

    for (const device of devices) {
        assert(driver.context.deviceTable.get(BigInt(device.ieeeAddr)));
    }
}

if (require.main === module) {
    const dataPath = process.argv[2];

    if (!dataPath || dataPath === "help") {
        console.log("Create a 'zoh.save' from the content of a Zigbee2MQTT data folder.");
        console.log("The presence and validity of these files is required for this operation:");
        console.log("  - coordinator_backup.json");
        console.log("  - database.db");
        console.log("Allows to quickly take over a network created by another Zigbee2MQTT driver ('ember', 'zstack').");
        console.log("Usage:");
        console.log("node ./dist/dev/z2mdata-to-zohsave.js ../path/to/data/");
    } else {
        console.log("Using: ", dataPath);

        if (!existsSync(join(dataPath, "coordinator_backup.json"))) {
            throw new Error(`No 'coordinator_backup.json' exists at ${dataPath}`);
        }

        if (!existsSync(join(dataPath, "database.db"))) {
            throw new Error(`No 'database.db' exists at ${dataPath}`);
        }

        void convert(dataPath);
    }
}
