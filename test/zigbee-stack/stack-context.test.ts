import { mkdirSync, rmSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MACCapabilities } from "../../src/zigbee/mac.js";
import { DeviceTLVTag, readDeviceTLVs, readSourceRouteTLVs, SourceRouteTLVTag, TLVTag } from "../../src/zigbee-stack/save-serializer.js";
import {
    ApplicationKeyRequestPolicy,
    InstallCodePolicy,
    NetworkKeyUpdateMethod,
    type NetworkParameters,
    type SourceRouteTableEntry,
    StackContext,
    type StackContextCallbacks,
    TrustCenterKeyRequestPolicy,
} from "../../src/zigbee-stack/stack-context.js";

const createNetParams = (): NetworkParameters => ({
    eui64: 0x00124b0012345678n,
    panId: 0x1a62,
    extendedPanId: 0xdddddddddddddddn,
    channel: 15,
    nwkUpdateId: 0,
    txPower: 5,
    networkKey: Buffer.from("01030507090b0d0f00020406080a0c0d", "hex"),
    networkKeyFrameCounter: 0,
    networkKeySequenceNumber: 0,
    tcKey: Buffer.from("abcdabcdabcdabcdabcdabcdabcdabcd", "hex"),
    tcKeyFrameCounter: 0,
});

const LENGTH_THRESHOLD = 0x80;

type TLVInfo = {
    offset: number;
    valueOffset: number;
    length: number;
    headerSize: number;
};

const findTopLevelTLV = (buffer: Buffer, targetTag: number): TLVInfo | undefined => {
    let offset = 0;

    while (offset < buffer.length) {
        const tag = buffer[offset];

        if (tag === TLVTag.END_MARKER) {
            return undefined;
        }

        if (offset + 1 >= buffer.length) {
            return undefined;
        }

        const lengthByte = buffer[offset + 1];
        let headerSize = 2;
        let length: number;

        if (lengthByte < LENGTH_THRESHOLD) {
            length = lengthByte;
        } else {
            if (offset + 2 >= buffer.length) {
                return undefined;
            }

            length = ((lengthByte & 0x7f) << 8) | buffer[offset + 2];
            headerSize += 1;
        }

        if (offset + headerSize + length > buffer.length) {
            return undefined;
        }

        if (tag === targetTag) {
            return {
                offset,
                valueOffset: offset + headerSize,
                length,
                headerSize,
            };
        }

        offset += headerSize + length;
    }

    return undefined;
};

const findNestedTLV = (buffer: Buffer, start: number, end: number, targetTag: number): TLVInfo | undefined => {
    let offset = start;

    while (offset < end) {
        if (offset + 1 >= end) {
            return undefined;
        }

        const tag = buffer[offset];
        const lengthByte = buffer[offset + 1];
        let headerSize = 2;
        let length: number;

        if (lengthByte < LENGTH_THRESHOLD) {
            length = lengthByte;
        } else {
            if (offset + 2 >= end) {
                return undefined;
            }

            length = ((lengthByte & 0x7f) << 8) | buffer[offset + 2];
            headerSize += 1;
        }

        if (offset + headerSize + length > end) {
            return undefined;
        }

        if (tag === targetTag) {
            return {
                offset,
                valueOffset: offset + headerSize,
                length,
                headerSize,
            };
        }

        offset += headerSize + length;
    }

    return undefined;
};

describe("StackContext", () => {
    let saveDir: string;
    let mockStackContextCallbacks: StackContextCallbacks;
    let context: StackContext;
    let netParams: NetworkParameters;

    beforeEach(() => {
        netParams = createNetParams();

        saveDir = `temp_StackContext_${Math.floor(Math.random() * 1000000)}`;
        mkdirSync(saveDir, { recursive: true });

        mockStackContextCallbacks = {
            onDeviceLeft: vi.fn(),
        };

        context = new StackContext(mockStackContextCallbacks, join(saveDir, "zoh.save"), netParams);
    });

    afterEach(() => {
        rmSync(saveDir, { force: true, recursive: true });
    });

    describe("constructor", () => {
        it("should initialize with provided network parameters", () => {
            expect(context.netParams).toStrictEqual(netParams);
            expect(context.netParams.eui64).toStrictEqual(0x00124b0012345678n);
            expect(context.netParams.panId).toStrictEqual(0x1a62);
        });

        it("should initialize empty device table", () => {
            expect(context.deviceTable.size).toStrictEqual(0);
        });

        it("should initialize empty address lookup table", () => {
            expect(context.address16ToAddress64.size).toStrictEqual(0);
        });

        it("should initialize empty source route table", () => {
            expect(context.sourceRouteTable.size).toStrictEqual(0);
        });

        it("should initialize empty indirect transmissions", () => {
            expect(context.indirectTransmissions.size).toStrictEqual(0);
        });

        it("should initialize default trust center policies", () => {
            expect(context.trustCenterPolicies.allowJoins).toStrictEqual(false);
            expect(context.trustCenterPolicies.installCode).toStrictEqual(InstallCodePolicy.NOT_REQUIRED);
            expect(context.trustCenterPolicies.allowRejoinsWithWellKnownKey).toStrictEqual(true);
            expect(context.trustCenterPolicies.allowTCKeyRequest).toStrictEqual(TrustCenterKeyRequestPolicy.ALLOWED);
            expect(context.trustCenterPolicies.networkKeyUpdatePeriod).toStrictEqual(0);
            expect(context.trustCenterPolicies.networkKeyUpdateMethod).toStrictEqual(NetworkKeyUpdateMethod.BROADCAST);
            expect(context.trustCenterPolicies.allowAppKeyRequest).toStrictEqual(ApplicationKeyRequestPolicy.DISALLOWED);
            expect(context.trustCenterPolicies.allowRemoteTCPolicyChange).toStrictEqual(false);
            expect(context.trustCenterPolicies.allowVirtualDevices).toStrictEqual(false);
        });

        it("should initialize default RSSI/LQI ranges", () => {
            expect(context.rssiMin).toStrictEqual(-100);
            expect(context.rssiMax).toStrictEqual(-25);
            expect(context.lqiMin).toStrictEqual(15);
            expect(context.lqiMax).toStrictEqual(250);
        });

        it("should initialize empty configuration attributes", () => {
            expect(context.configAttributes.address.length).toStrictEqual(0);
            expect(context.configAttributes.nodeDescriptor.length).toStrictEqual(0);
            expect(context.configAttributes.powerDescriptor.length).toStrictEqual(0);
            expect(context.configAttributes.simpleDescriptors.length).toStrictEqual(0);
            expect(context.configAttributes.activeEndpoints.length).toStrictEqual(0);
        });
    });

    describe("counter methods", () => {
        describe("nextTCKeyFrameCounter", () => {
            it("should start at 1 and increment", () => {
                expect(context.nextTCKeyFrameCounter()).toStrictEqual(1);
                expect(context.nextTCKeyFrameCounter()).toStrictEqual(2);
                expect(context.nextTCKeyFrameCounter()).toStrictEqual(3);
            });

            it("should wrap at 0xffffffff", () => {
                context.netParams.tcKeyFrameCounter = 0xfffffffe;
                expect(context.nextTCKeyFrameCounter()).toStrictEqual(0xffffffff);
                expect(context.nextTCKeyFrameCounter()).toStrictEqual(0);
                expect(context.nextTCKeyFrameCounter()).toStrictEqual(1);
            });
        });

        describe("nextNWKKeyFrameCounter", () => {
            it("should start at 1 and increment", () => {
                expect(context.nextNWKKeyFrameCounter()).toStrictEqual(1);
                expect(context.nextNWKKeyFrameCounter()).toStrictEqual(2);
                expect(context.nextNWKKeyFrameCounter()).toStrictEqual(3);
            });

            it("should wrap at 0xffffffff", () => {
                context.netParams.networkKeyFrameCounter = 0xfffffffe;
                expect(context.nextNWKKeyFrameCounter()).toStrictEqual(0xffffffff);
                expect(context.nextNWKKeyFrameCounter()).toStrictEqual(0);
                expect(context.nextNWKKeyFrameCounter()).toStrictEqual(1);
            });
        });
    });

    describe("source route table", () => {
        it("should allow adding source routes", () => {
            const dest16 = 0x1234;
            const routes = [
                {
                    relayAddresses: [0x0001, 0x0002],
                    pathCost: 2,
                    lastUpdated: Date.now(),
                    failureCount: 0,
                },
            ];

            context.sourceRouteTable.set(dest16, routes);
            expect(context.sourceRouteTable.get(dest16)).toStrictEqual(routes);
            expect(context.sourceRouteTable.size).toStrictEqual(1);
        });
    });

    describe("network parameters", () => {
        it("should allow modifying network parameters", () => {
            context.netParams.channel = 20;
            context.netParams.panId = 0xabcd;

            expect(context.netParams.channel).toStrictEqual(20);
            expect(context.netParams.panId).toStrictEqual(0xabcd);
        });

        it("should allow modifying frame counters", () => {
            context.netParams.tcKeyFrameCounter = 1000;
            context.netParams.networkKeyFrameCounter = 2000;

            expect(context.netParams.tcKeyFrameCounter).toStrictEqual(1000);
            expect(context.netParams.networkKeyFrameCounter).toStrictEqual(2000);
        });
    });

    describe("trust center policies", () => {
        it("should allow modifying policies", () => {
            context.trustCenterPolicies.allowJoins = true;
            context.trustCenterPolicies.installCode = InstallCodePolicy.REQUIRED;

            expect(context.trustCenterPolicies.allowJoins).toStrictEqual(true);
            expect(context.trustCenterPolicies.installCode).toStrictEqual(InstallCodePolicy.REQUIRED);
        });
    });

    describe("RSSI/LQI ranges", () => {
        it("should allow modifying ranges", () => {
            context.rssiMin = -90;
            context.rssiMax = -20;
            context.lqiMin = 0;
            context.lqiMax = 255;

            expect(context.rssiMin).toStrictEqual(-90);
            expect(context.rssiMax).toStrictEqual(-20);
            expect(context.lqiMin).toStrictEqual(0);
            expect(context.lqiMax).toStrictEqual(255);
        });
    });

    it("maps RSSI to LQI", () => {
        let lqi = context.mapRSSIToLQI(context.rssiMin);
        expect(lqi).toStrictEqual(3); // console.log(lqi)

        lqi = context.mapRSSIToLQI(context.rssiMax);
        expect(lqi).toStrictEqual(253); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-10);
        expect(lqi).toStrictEqual(255); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-20);
        expect(lqi).toStrictEqual(255); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-30);
        expect(lqi).toStrictEqual(252); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-35);
        expect(lqi).toStrictEqual(250); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-40);
        expect(lqi).toStrictEqual(246); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-45);
        expect(lqi).toStrictEqual(239); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-50);
        expect(lqi).toStrictEqual(227); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-55);
        expect(lqi).toStrictEqual(207); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-60);
        expect(lqi).toStrictEqual(176); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-65);
        expect(lqi).toStrictEqual(137); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-70);
        expect(lqi).toStrictEqual(97); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-80);
        expect(lqi).toStrictEqual(36); // console.log(lqi)

        lqi = context.mapRSSIToLQI(-90);
        expect(lqi).toStrictEqual(11); // console.log(lqi)
    });

    it("computes LQA", () => {
        let lqa = context.computeLQA(context.rssiMin);
        expect(lqa).toStrictEqual(0); // console.log(lqa)

        lqa = context.computeLQA(context.rssiMax);
        expect(lqa).toStrictEqual(255); // console.log(lqa)

        lqa = context.computeLQA(-10);
        expect(lqa).toStrictEqual(255); // console.log(lqa)

        lqa = context.computeLQA(-20);
        expect(lqa).toStrictEqual(255); // console.log(lqa)

        lqa = context.computeLQA(-30);
        expect(lqa).toStrictEqual(238); // console.log(lqa)

        lqa = context.computeLQA(-35);
        expect(lqa).toStrictEqual(221); // console.log(lqa)

        lqa = context.computeLQA(-40);
        expect(lqa).toStrictEqual(200); // console.log(lqa)

        lqa = context.computeLQA(-45);
        expect(lqa).toStrictEqual(178); // console.log(lqa)

        lqa = context.computeLQA(-50);
        expect(lqa).toStrictEqual(153); // console.log(lqa)

        lqa = context.computeLQA(-55);
        expect(lqa).toStrictEqual(125); // console.log(lqa)

        lqa = context.computeLQA(-60);
        expect(lqa).toStrictEqual(93); // console.log(lqa)

        lqa = context.computeLQA(-65);
        expect(lqa).toStrictEqual(61); // console.log(lqa)

        lqa = context.computeLQA(-70);
        expect(lqa).toStrictEqual(35); // console.log(lqa)

        lqa = context.computeLQA(-80);
        expect(lqa).toStrictEqual(6); // console.log(lqa)

        lqa = context.computeLQA(-90);
        expect(lqa).toStrictEqual(0); // console.log(lqa)
    });

    it("should decrement radius when > 1", () => {
        expect(context.decrementRadius(5)).toStrictEqual(4);
        expect(context.decrementRadius(10)).toStrictEqual(9);
        expect(context.decrementRadius(2)).toStrictEqual(1);
    });

    it("should handle large radius values", () => {
        expect(context.decrementRadius(255)).toStrictEqual(254);
        expect(context.decrementRadius(30)).toStrictEqual(29);
    });

    describe("state persistence", () => {
        it("saves and reloads TLVs with extended lengths", async () => {
            const device64 = 0x00124b0000abcdefn;

            const capabilities: MACCapabilities = {
                alternatePANCoordinator: true,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };

            const address16 = 0x2345;
            const longRelays = Array.from({ length: 70 }, (_, index) => 0x3000 + index);

            context.netParams.networkKeyFrameCounter = 42;
            context.netParams.tcKeyFrameCounter = 84;

            context.deviceTable.set(device64, {
                address16,
                capabilities,
                authorized: true,
                neighbor: true,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(address16, device64);

            const sourceRouteEntries: SourceRouteTableEntry[] = [
                {
                    relayAddresses: [],
                    pathCost: 1,
                    lastUpdated: 0x010203040506,
                    failureCount: 0,
                    lastUsed: undefined,
                },
                {
                    relayAddresses: longRelays,
                    pathCost: 2,
                    lastUpdated: 0x060504030201,
                    failureCount: 0,
                    lastUsed: undefined,
                },
            ];

            context.sourceRouteTable.set(address16, sourceRouteEntries);

            const appLinkKey = Buffer.from("00112233445566778899aabbccddeeff", "hex");
            context.setAppLinkKey(device64, context.netParams.eui64, appLinkKey);

            await context.saveState();

            const statePath = join(saveDir, "zoh.save");
            const reloadedContext = new StackContext(mockStackContextCallbacks, statePath, createNetParams());

            await reloadedContext.loadState();

            const reloadedDevice = reloadedContext.deviceTable.get(device64);

            expect(reloadedContext.deviceTable.size).toStrictEqual(1);
            expect(reloadedDevice).toBeDefined();
            expect(reloadedDevice?.address16).toStrictEqual(address16);
            expect(reloadedDevice?.authorized).toStrictEqual(true);
            expect(reloadedDevice?.capabilities?.rxOnWhenIdle).toStrictEqual(capabilities.rxOnWhenIdle);
            expect(reloadedContext.indirectTransmissions.has(device64)).toStrictEqual(true);

            const reloadedRoutes = reloadedContext.sourceRouteTable.get(address16);

            expect(reloadedRoutes).toBeDefined();
            expect(reloadedRoutes).toHaveLength(2);
            expect(reloadedRoutes?.[0].relayAddresses).toHaveLength(0);
            expect(reloadedRoutes?.[1].relayAddresses).toStrictEqual(longRelays);

            const networkJump = reloadedContext.netParams.networkKeyFrameCounter - 42;
            const tcJump = reloadedContext.netParams.tcKeyFrameCounter - 84;

            expect(networkJump).toStrictEqual(1024);
            expect(tcJump).toStrictEqual(1024);

            const restoredKey = reloadedContext.getAppLinkKey(device64, reloadedContext.netParams.eui64);

            expect(restoredKey).toStrictEqual(appLinkKey);
        });

        it("loads state with trailing padding after end marker", async () => {
            await context.saveState();

            const statePath = join(saveDir, "zoh.save");
            const saved = await readFile(statePath);
            const padded = Buffer.concat([saved, Buffer.from([0x00])]);

            await writeFile(statePath, padded);

            const reloaded = new StackContext(mockStackContextCallbacks, statePath, createNetParams());

            await reloaded.loadState();

            expect(reloaded.deviceTable.size).toStrictEqual(0);
            expect(reloaded.netParams.networkKeyFrameCounter).toStrictEqual(1024);
        });

        it("recovers when long length header is truncated", async () => {
            const device64 = 0x00124b0000cccdden;

            const capabilities: MACCapabilities = {
                alternatePANCoordinator: true,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: false,
                securityCapability: true,
                allocateAddress: true,
            };

            const address16 = 0x2abc;
            const longRelays = Array.from({ length: 70 }, (_, index) => 0x4000 + index);

            context.deviceTable.set(device64, {
                address16,
                capabilities,
                authorized: true,
                neighbor: true,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(address16, device64);
            context.sourceRouteTable.set(address16, [
                {
                    relayAddresses: longRelays,
                    pathCost: 4,
                    lastUpdated: 0x010203040506,
                    failureCount: 0,
                    lastUsed: undefined,
                },
            ]);

            await context.saveState();

            const statePath = join(saveDir, "zoh.save");
            let corrupted = Buffer.from(await readFile(statePath));
            const deviceEntryInfo = findTopLevelTLV(corrupted, TLVTag.DEVICE_ENTRY);

            expect(deviceEntryInfo).toBeDefined();

            if (deviceEntryInfo !== undefined) {
                corrupted = corrupted.subarray(0, deviceEntryInfo.offset + 2);
            }

            await writeFile(statePath, corrupted);

            const reloaded = new StackContext(mockStackContextCallbacks, statePath, createNetParams());

            await reloaded.loadState();

            expect(reloaded.deviceTable.size).toStrictEqual(0);
            expect(reloaded.sourceRouteTable.size).toStrictEqual(0);
        });

        it("regenerates state when network key payload is truncated", async () => {
            await context.saveState();

            const statePath = join(saveDir, "zoh.save");
            let corrupted = Buffer.from(await readFile(statePath));
            const networkKeyInfo = findTopLevelTLV(corrupted, TLVTag.NETWORK_KEY);

            expect(networkKeyInfo).toBeDefined();

            if (networkKeyInfo !== undefined) {
                corrupted = Buffer.concat([
                    corrupted.subarray(0, networkKeyInfo.valueOffset + networkKeyInfo.length - 4),
                    corrupted.subarray(networkKeyInfo.valueOffset + networkKeyInfo.length),
                ]);
            }

            await writeFile(statePath, corrupted);

            const reloaded = new StackContext(mockStackContextCallbacks, statePath, createNetParams());

            await reloaded.loadState();

            expect(reloaded.deviceTable.size).toStrictEqual(0);
            expect(reloaded.netParams.networkKeyFrameCounter).toStrictEqual(0);

            const regenerated = await readFile(statePath);
            const regeneratedNetworkKey = findTopLevelTLV(regenerated, TLVTag.NETWORK_KEY);

            expect(regeneratedNetworkKey).toBeDefined();
            expect(regeneratedNetworkKey?.length).toStrictEqual(16);
        });

        it("regenerates state when device TLV lengths are inconsistent", async () => {
            const device64 = 0x00124b0000ffeedcn;

            const capabilities: MACCapabilities = {
                alternatePANCoordinator: false,
                deviceType: 1,
                powerSource: 0,
                rxOnWhenIdle: true,
                securityCapability: false,
                allocateAddress: true,
            };

            const address16 = 0x3456;

            context.deviceTable.set(device64, {
                address16,
                capabilities,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(address16, device64);

            await context.saveState();

            const statePath = join(saveDir, "zoh.save");
            let corrupted = Buffer.from(await readFile(statePath));
            const deviceEntryInfo = findTopLevelTLV(corrupted, TLVTag.DEVICE_ENTRY);

            expect(deviceEntryInfo).toBeDefined();

            const neighborInfo =
                deviceEntryInfo === undefined
                    ? undefined
                    : findNestedTLV(
                          corrupted,
                          deviceEntryInfo.valueOffset,
                          deviceEntryInfo.valueOffset + deviceEntryInfo.length,
                          DeviceTLVTag.DEVICE_NEIGHBOR,
                      );

            expect(neighborInfo).toBeDefined();

            if (neighborInfo !== undefined) {
                corrupted = Buffer.concat([
                    corrupted.subarray(0, neighborInfo.offset),
                    corrupted.subarray(neighborInfo.offset + neighborInfo.headerSize + neighborInfo.length),
                ]);
            }

            await writeFile(statePath, corrupted);

            const reloaded = new StackContext(mockStackContextCallbacks, statePath, createNetParams());

            await reloaded.loadState();

            expect(reloaded.deviceTable.size).toStrictEqual(0);
            expect(reloaded.appLinkKeyTable.size).toStrictEqual(0);

            const regenerated = await readFile(statePath);
            const regeneratedDeviceInfo = findTopLevelTLV(regenerated, TLVTag.DEVICE_ENTRY);

            expect(regeneratedDeviceInfo).toBeUndefined();
        });

        it("regenerates state when source route TLV lengths are inconsistent", async () => {
            const device64 = 0x00124b0000aaaabcn;

            const capabilities: MACCapabilities = {
                alternatePANCoordinator: true,
                deviceType: 1,
                powerSource: 1,
                rxOnWhenIdle: true,
                securityCapability: true,
                allocateAddress: true,
            };

            const address16 = 0x4567;
            const sourceRoute: SourceRouteTableEntry = {
                relayAddresses: [0x0001, 0x0002],
                pathCost: 3,
                lastUpdated: 0x010203040506,
                failureCount: 0,
                lastUsed: undefined,
            };

            context.deviceTable.set(device64, {
                address16,
                capabilities,
                authorized: true,
                neighbor: true,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
            });
            context.address16ToAddress64.set(address16, device64);
            context.sourceRouteTable.set(address16, [sourceRoute]);

            await context.saveState();

            const statePath = join(saveDir, "zoh.save");
            let corrupted = Buffer.from(await readFile(statePath));
            const deviceEntryInfo = findTopLevelTLV(corrupted, TLVTag.DEVICE_ENTRY);

            expect(deviceEntryInfo).toBeDefined();

            const sourceRouteInfo =
                deviceEntryInfo === undefined
                    ? undefined
                    : findNestedTLV(
                          corrupted,
                          deviceEntryInfo.valueOffset,
                          deviceEntryInfo.valueOffset + deviceEntryInfo.length,
                          DeviceTLVTag.SOURCE_ROUTE_ENTRY,
                      );

            expect(sourceRouteInfo).toBeDefined();

            const lastUpdatedInfo =
                sourceRouteInfo === undefined
                    ? undefined
                    : findNestedTLV(
                          corrupted,
                          sourceRouteInfo.valueOffset,
                          sourceRouteInfo.valueOffset + sourceRouteInfo.length,
                          SourceRouteTLVTag.LAST_UPDATED,
                      );

            expect(lastUpdatedInfo).toBeDefined();

            if (lastUpdatedInfo !== undefined) {
                corrupted = Buffer.concat([
                    corrupted.subarray(0, lastUpdatedInfo.valueOffset + 3),
                    corrupted.subarray(lastUpdatedInfo.valueOffset + lastUpdatedInfo.length),
                ]);
            }

            await writeFile(statePath, corrupted);

            const reloaded = new StackContext(mockStackContextCallbacks, statePath, createNetParams());

            await reloaded.loadState();

            expect(reloaded.sourceRouteTable.size).toStrictEqual(0);

            const regenerated = await readFile(statePath);
            const regeneratedDeviceInfo = findTopLevelTLV(regenerated, TLVTag.DEVICE_ENTRY);

            expect(regeneratedDeviceInfo).toBeUndefined();
        });
    });

    describe("save-serializer defensive parsing", () => {
        it("throws when device entry header is truncated", () => {
            const truncated = Buffer.from([DeviceTLVTag.DEVICE_ADDRESS64]);

            expect(() => readDeviceTLVs(truncated, 0, truncated.length)).toThrowError("Missing required device fields");
        });

        it("throws when device entry long length is missing low byte", () => {
            const missingLength = Buffer.from([DeviceTLVTag.DEVICE_ADDRESS64, 0x80]);

            expect(() => readDeviceTLVs(missingLength, 0, missingLength.length)).toThrowError("Missing required device fields");
        });

        it("throws when device entry value is shorter than declared length", () => {
            const shortValue = Buffer.concat([Buffer.from([DeviceTLVTag.DEVICE_ADDRESS64, 0x08]), Buffer.alloc(4)]);

            expect(() => readDeviceTLVs(shortValue, 0, shortValue.length)).toThrowError("Missing required device fields");
        });

        it("throws when source route entry value is shorter than declared length", () => {
            const truncatedRoute = Buffer.from([SourceRouteTLVTag.PATH_COST, 0x01, 0x01, SourceRouteTLVTag.LAST_UPDATED, 0x06, 0x00, 0x01, 0x02]);

            expect(() => readSourceRouteTLVs(truncatedRoute, 0, truncatedRoute.length)).toThrowError("Missing required source route fields");
        });

        it("throws when source route entry long length is missing low byte", () => {
            const missingLength = Buffer.from([SourceRouteTLVTag.RELAY_ADDRESSES, 0x80]);

            expect(() => readSourceRouteTLVs(missingLength, 0, missingLength.length)).toThrowError("Missing required source route fields");
        });

        it("throws when source route entry long value is truncated", () => {
            const truncatedLong = Buffer.from([SourceRouteTLVTag.RELAY_ADDRESSES, 0x80, 0x06, 0x00, 0x01]);

            expect(() => readSourceRouteTLVs(truncatedLong, 0, truncatedLong.length)).toThrowError("Missing required source route fields");
        });

        it("throws when source route entry header is truncated", () => {
            const truncatedHeader = Buffer.from([SourceRouteTLVTag.PATH_COST]);

            expect(() => readSourceRouteTLVs(truncatedHeader, 0, truncatedHeader.length)).toThrowError("Missing required source route fields");
        });
    });
});
