import { rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
    ApplicationKeyRequestPolicy,
    InstallCodePolicy,
    NetworkKeyUpdateMethod,
    type NetworkParameters,
    StackContext,
    type StackContextCallbacks,
    TrustCenterKeyRequestPolicy,
} from "../../src/zigbee-stack/stack-context.js";

describe("StackContext", () => {
    let saveDir: string;
    let mockStackContextCallbacks: StackContextCallbacks;
    let context: StackContext;
    let netParams: NetworkParameters;

    beforeEach(() => {
        netParams = {
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
        };

        saveDir = `temp_StackContext_${Math.floor(Math.random() * 1000000)}`;

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

    describe("device management", () => {
        const device64 = 0x00124b0098765432n;
        const device16 = 0x1234;

        beforeEach(() => {
            context.deviceTable.set(device64, {
                address16: device16,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 1,
                    powerSource: 1,
                    rxOnWhenIdle: true,
                    securityCapability: true,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: true,
                recentLQAs: [100, 110, 120],
            });
            context.address16ToAddress64.set(device16, device64);
        });

        describe("getDevice", () => {
            it("should get device by 64-bit address", () => {
                const device = context.getDevice(device64);
                expect(device).toBeDefined();
                expect(device?.address16).toStrictEqual(device16);
                expect(device?.authorized).toStrictEqual(true);
            });

            it("should get device by 16-bit address", () => {
                const device = context.getDevice(device16);
                expect(device).toBeDefined();
                expect(device?.address16).toStrictEqual(device16);
                expect(device?.authorized).toStrictEqual(true);
            });

            it("should return undefined for unknown 64-bit address", () => {
                const device = context.getDevice(0x9999999999999999n);
                expect(device).toBeUndefined();
            });

            it("should return undefined for unknown 16-bit address", () => {
                const device = context.getDevice(0x9999);
                expect(device).toBeUndefined();
            });
        });

        describe("getAddress64", () => {
            it("should get 64-bit address from 16-bit address", () => {
                const addr64 = context.getAddress64(device16);
                expect(addr64).toStrictEqual(device64);
            });

            it("should return undefined for unknown 16-bit address", () => {
                const addr64 = context.getAddress64(0x9999);
                expect(addr64).toBeUndefined();
            });
        });

        describe("getAddress16", () => {
            it("should get 16-bit address from 64-bit address", () => {
                const addr16 = context.getAddress16(device64);
                expect(addr16).toStrictEqual(device16);
            });

            it("should return undefined for unknown 64-bit address", () => {
                const addr16 = context.getAddress16(0x9999999999999999n);
                expect(addr16).toBeUndefined();
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

    it("should return 0 when radius equal or below 1", () => {
        expect(context.decrementRadius(1)).toStrictEqual(1);
        expect(context.decrementRadius(0)).toStrictEqual(1);
    });

    it("should handle large radius values", () => {
        expect(context.decrementRadius(255)).toStrictEqual(254);
        expect(context.decrementRadius(30)).toStrictEqual(29);
    });
});
