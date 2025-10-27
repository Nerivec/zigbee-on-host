import { rmSync } from "node:fs";
import { join } from "node:path";
import { bench, describe } from "vitest";
import { decodeMACFrameControl, decodeMACHeader, decodeMACPayload } from "../../src/zigbee/mac.js";
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeKeyType } from "../../src/zigbee/zigbee.js";
import { decodeZigbeeAPSFrameControl, decodeZigbeeAPSHeader, decodeZigbeeAPSPayload, ZigbeeAPSDeliveryMode } from "../../src/zigbee/zigbee-aps.js";
import { decodeZigbeeNWKFrameControl, decodeZigbeeNWKHeader, decodeZigbeeNWKPayload, ZigbeeNWKRouteDiscovery } from "../../src/zigbee/zigbee-nwk.js";
import { APSHandler, type APSHandlerCallbacks } from "../../src/zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../../src/zigbee-stack/nwk-gp-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import { type NetworkParameters, StackContext, type StackContextCallbacks } from "../../src/zigbee-stack/stack-context.js";
import { BENCH_OPTIONS } from "../bench-options.js";
import {
    NET2_ASSOC_REQ_FROM_DEVICE,
    NET2_DATA_RQ_FROM_DEVICE,
    NET2_REQUEST_KEY_TC_FROM_DEVICE,
    NET2_TRANSPORT_KEY_NWK_FROM_COORD,
    NETDEF_LINK_STATUS_FROM_DEV,
    NETDEF_NETWORK_KEY,
    NETDEF_ROUTE_RECORD_TO_COORD,
    NETDEF_TC_KEY,
    NETDEF_ZGP_COMMISSIONING,
    NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0,
} from "../data.js";

const NO_ACK_CODE = 99999;

let saveDir: string;
let context: StackContext;
let macHandler: MACHandler;
let nwkHandler: NWKHandler;
let apsHandler: APSHandler;
let nwkGPHandler: NWKGPHandler;
let netParams: NetworkParameters;

const setup = () => {
    registerDefaultHashedKeys(
        makeKeyedHashByType(ZigbeeKeyType.LINK, NETDEF_TC_KEY),
        makeKeyedHashByType(ZigbeeKeyType.NWK, NETDEF_NETWORK_KEY),
        makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, NETDEF_TC_KEY),
        makeKeyedHashByType(ZigbeeKeyType.LOAD, NETDEF_TC_KEY),
    );

    netParams = {
        eui64: 0x00124b0012345678n,
        panId: 0x1a62,
        extendedPanId: 0xdddddddddddddddn,
        channel: 15,
        nwkUpdateId: 0,
        txPower: 5,
        networkKey: NETDEF_NETWORK_KEY,
        networkKeyFrameCounter: 0,
        networkKeySequenceNumber: 0,
        tcKey: NETDEF_TC_KEY,
        tcKeyFrameCounter: 0,
    };

    saveDir = `temp_ZigbeeStackBench_${Math.floor(Math.random() * 1000000)}`;

    const stackContextCallbacks: StackContextCallbacks = {
        onDeviceLeft: () => {},
    };

    context = new StackContext(stackContextCallbacks, join(saveDir, "zoh.save"), netParams);

    const macCallbacks: MACHandlerCallbacks = {
        onFrame: () => {},
        onSendFrame: () => Promise.resolve(),
        onAPSSendTransportKeyNWK: () => Promise.resolve(),
        onMarkRouteSuccess: () => {},
        onMarkRouteFailure: () => {},
    };

    macHandler = new MACHandler(context, macCallbacks, NO_ACK_CODE);

    const nwkCallbacks: NWKHandlerCallbacks = {
        onDeviceRejoined: () => {},
        onAPSSendTransportKeyNWK: () => Promise.resolve(),
    };

    nwkHandler = new NWKHandler(context, macHandler, nwkCallbacks);

    const apsCallbacks: APSHandlerCallbacks = {
        onFrame: () => {},
        onDeviceJoined: () => {},
        onDeviceRejoined: () => {},
        onDeviceAuthorized: () => {},
    };

    apsHandler = new APSHandler(context, macHandler, nwkHandler, apsCallbacks);

    const nwkGPCallbacks: NWKGPHandlerCallbacks = {
        onGPFrame: () => {},
    };

    nwkGPHandler = new NWKGPHandler(nwkGPCallbacks);
};

const teardown = () => {
    rmSync(saveDir, { force: true, recursive: true });
};

describe("Zigbee Stack Handlers", () => {
    describe("MACHandler", () => {
        bench(
            "sendFrameDirect - direct transmission without device lookup",
            async () => {
                const payload = Buffer.from([0x61, 0x88, 0xbf, 0x62, 0x1a, 0x00, 0x00, 0xba, 0x96]);
                await macHandler.sendFrameDirect(1, payload, 0x1234, undefined);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "sendFrame - check for indirect transmission queue",
            async () => {
                const payload = Buffer.from([0x61, 0x88, 0xbf, 0x62, 0x1a, 0x00, 0x00, 0xba, 0x96]);
                await macHandler.sendFrame(1, payload, 0x1234, undefined);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "processCommand - ASSOC_REQ (deepest path with full association flow)",
            async () => {
                const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_ASSOC_REQ_FROM_DEVICE, 0);
                const [macHeader, macHOutOffset] = decodeMACHeader(NET2_ASSOC_REQ_FROM_DEVICE, macFCFOutOffset, macFCF);
                const macPayload = decodeMACPayload(NET2_ASSOC_REQ_FROM_DEVICE, macHOutOffset, macFCF, macHeader);

                context.associationPermit = true;
                await macHandler.processCommand(macPayload, macHeader);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "processCommand - DATA_RQ (deepest path with pending association and indirect transmission)",
            async () => {
                const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_DATA_RQ_FROM_DEVICE, 0);
                const [macHeader, macHOutOffset] = decodeMACHeader(NET2_DATA_RQ_FROM_DEVICE, macFCFOutOffset, macFCF);
                const macPayload = decodeMACPayload(NET2_DATA_RQ_FROM_DEVICE, macHOutOffset, macFCF, macHeader);

                // Setup pending association (simulating prior ASSOC_REQ)
                const deviceEUI64 = macHeader.source64!;
                context.pendingAssociations.set(deviceEUI64, {
                    sendResp: async () => {},
                    timestamp: Date.now(),
                });

                // Add indirect transmission queue for device
                context.indirectTransmissions.set(deviceEUI64, [
                    {
                        sendFrame: async () => true,
                        timestamp: Date.now(),
                    },
                ]);

                await macHandler.processCommand(macPayload, macHeader);

                // Cleanup for next run
                context.pendingAssociations.delete(deviceEUI64);
                context.indirectTransmissions.delete(deviceEUI64);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );
    });

    describe("NWKHandler", () => {
        bench(
            "findBestSourceRoute - routing table lookup and best path selection",
            () => {
                const dest16 = 0x1234;
                const dest64 = 0x00124b0098765432n;

                // Setup source routing table with multiple routes
                context.sourceRouteTable.set(dest16, [
                    {
                        relayAddresses: [0x5678, 0x9abc],
                        pathCost: 10,
                        lastUpdated: Date.now(),
                        failureCount: 0,
                        lastUsed: Date.now(),
                    },
                ]);

                try {
                    nwkHandler.findBestSourceRoute(dest16, dest64);
                } catch {
                    // Expected to throw if no valid route
                }

                // Cleanup
                context.sourceRouteTable.delete(dest16);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "processCommand - LINK_STATUS (deepest path with neighbor table updates)",
            async () => {
                const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_LINK_STATUS_FROM_DEV, 0);
                const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_LINK_STATUS_FROM_DEV, macFCFOutOffset, macFCF);
                const macPayload = decodeMACPayload(NETDEF_LINK_STATUS_FROM_DEV, macHOutOffset, macFCF, macHeader);

                const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
                const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
                const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

                // Setup device in context
                const source64 = macHeader.source64!;
                const source16 = macHeader.source16!;
                context.deviceTable.set(source64, {
                    address16: source16,
                    capabilities: undefined,
                    authorized: true,
                    neighbor: true,
                    recentLQAs: [],
                });
                context.address16ToAddress64.set(source16, source64);

                await nwkHandler.processCommand(nwkPayload, macHeader, nwkHeader);

                // Cleanup
                context.deviceTable.delete(source64);
                context.address16ToAddress64.delete(source16);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "processCommand - ROUTE_RECORD (deepest path with source route table update)",
            async () => {
                const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ROUTE_RECORD_TO_COORD, 0);
                const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ROUTE_RECORD_TO_COORD, macFCFOutOffset, macFCF);
                const macPayload = decodeMACPayload(NETDEF_ROUTE_RECORD_TO_COORD, macHOutOffset, macFCF, macHeader);

                const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
                const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
                const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

                await nwkHandler.processCommand(nwkPayload, macHeader, nwkHeader);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "sendLinkStatus - full link status frame construction with neighbor table",
            async () => {
                // Setup multiple neighbors
                const neighbors = [
                    { address64: 0x00124b0012345671n, address16: 0x1111 },
                    { address64: 0x00124b0012345672n, address16: 0x2222 },
                    { address64: 0x00124b0012345673n, address16: 0x3333 },
                ];

                for (const neighbor of neighbors) {
                    context.deviceTable.set(neighbor.address64, {
                        address16: neighbor.address16,
                        capabilities: undefined,
                        authorized: true,
                        neighbor: true,
                        recentLQAs: [255, 240, 230],
                    });
                    context.address16ToAddress64.set(neighbor.address16, neighbor.address64);
                }

                // Build link status entries from neighbors
                const links = [];
                for (const neighbor of neighbors) {
                    links.push({
                        address: neighbor.address16,
                        address16: neighbor.address16,
                        incomingCost: 1,
                        outgoingCost: 1,
                    });
                }

                await nwkHandler.sendLinkStatus(links);

                // Cleanup
                for (const neighbor of neighbors) {
                    context.deviceTable.delete(neighbor.address64);
                    context.address16ToAddress64.delete(neighbor.address16);
                }
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "sendPeriodicManyToOneRouteRequest - full concentrator route discovery",
            async () => {
                await nwkHandler.sendPeriodicManyToOneRouteRequest();
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );
    });

    describe("APSHandler", () => {
        bench(
            "sendData - unicast with source routing (deepest transmission path)",
            async () => {
                const dest16 = 0x1234;
                const dest64 = 0x00124b0098765432n;
                const payload = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]);

                // Setup device and routing
                context.deviceTable.set(dest64, {
                    address16: dest16,
                    capabilities: undefined,
                    authorized: true,
                    neighbor: false,
                    recentLQAs: [],
                });
                context.address16ToAddress64.set(dest16, dest64);

                context.sourceRouteTable.set(dest16, [
                    {
                        relayAddresses: [0x5678, 0x9abc],
                        pathCost: 10,
                        lastUpdated: Date.now(),
                        failureCount: 0,
                        lastUsed: Date.now(),
                    },
                ]);

                try {
                    await apsHandler.sendData(
                        payload,
                        ZigbeeNWKRouteDiscovery.ENABLE,
                        dest16,
                        dest64,
                        ZigbeeAPSDeliveryMode.UNICAST,
                        0x0006,
                        0x0104,
                        0x01,
                        0x01,
                        undefined,
                    );
                } catch {
                    // May fail in benchmark context, focus on path execution
                }

                // Cleanup
                context.deviceTable.delete(dest64);
                context.address16ToAddress64.delete(dest16);
                context.sourceRouteTable.delete(dest16);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "processCommand - TRANSPORT_KEY NWK (deepest key distribution path)",
            async () => {
                const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_TRANSPORT_KEY_NWK_FROM_COORD, 0);
                const [macHeader, macHOutOffset] = decodeMACHeader(NET2_TRANSPORT_KEY_NWK_FROM_COORD, macFCFOutOffset, macFCF);
                const macPayload = decodeMACPayload(NET2_TRANSPORT_KEY_NWK_FROM_COORD, macHOutOffset, macFCF, macHeader);

                const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
                const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
                const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

                const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
                const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
                const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

                await apsHandler.processCommand(apsPayload, macHeader, nwkHeader, apsHeader);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "processCommand - REQUEST_KEY (deepest TC key request path)",
            async () => {
                const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_REQUEST_KEY_TC_FROM_DEVICE, 0);
                const [macHeader, macHOutOffset] = decodeMACHeader(NET2_REQUEST_KEY_TC_FROM_DEVICE, macFCFOutOffset, macFCF);
                const macPayload = decodeMACPayload(NET2_REQUEST_KEY_TC_FROM_DEVICE, macHOutOffset, macFCF, macHeader);

                const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
                const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
                const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

                const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
                const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
                const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

                // Setup device
                const source64 = macHeader.source64!;
                const source16 = nwkHeader.source16!;
                context.deviceTable.set(source64, {
                    address16: source16,
                    capabilities: undefined,
                    authorized: false,
                    neighbor: false,
                    recentLQAs: [],
                });
                context.address16ToAddress64.set(source16, source64);

                await apsHandler.processCommand(apsPayload, macHeader, nwkHeader, apsHeader);

                // Cleanup
                context.deviceTable.delete(source64);
                context.address16ToAddress64.delete(source16);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "sendTransportKeyNWK - full network key distribution with encryption",
            async () => {
                const dest64 = 0x00124b0098765432n;
                const dest16 = 0x1234;

                context.deviceTable.set(dest64, {
                    address16: dest16,
                    capabilities: undefined,
                    authorized: false,
                    neighbor: false,
                    recentLQAs: [],
                });
                context.address16ToAddress64.set(dest16, dest64);

                try {
                    await apsHandler.sendTransportKeyNWK(dest16, NETDEF_NETWORK_KEY, 0, dest64);
                } catch {
                    // May fail in benchmark context
                }

                context.deviceTable.delete(dest64);
                context.address16ToAddress64.delete(dest16);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );
    });

    describe("NWKGPHandler", () => {
        bench(
            "checkDuplicate - security frame counter check (hot path)",
            () => {
                const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, 0);
                const [macHeader] = decodeMACHeader(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, macFCFOutOffset, macFCF);

                nwkGPHandler.isDuplicateFrame(macHeader, {
                    frameControl: { frameType: 0, protocolVersion: 3, autoCommissioning: false, nwkFrameControlExtension: false },
                    securityFrameCounter: 12345,
                    sourceId: 0x87654321,
                    micSize: 4,
                    payloadLength: 10,
                });
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "processFrame - Green Power commissioning (deepest GP path)",
            () => {
                const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZGP_COMMISSIONING, 0);
                const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZGP_COMMISSIONING, macFCFOutOffset, macFCF);
                const macPayload = decodeMACPayload(NETDEF_ZGP_COMMISSIONING, macHOutOffset, macFCF, macHeader);

                // Enable commissioning mode
                nwkGPHandler.enterCommissioningMode(180);

                // Simulate GP frame processing
                const gpData = macPayload.subarray(2); // Skip NWK GP header for this benchmark
                const mockNwkHeader = {
                    frameControl: { frameType: 0, protocolVersion: 3, autoCommissioning: false, nwkFrameControlExtension: false },
                    sourceId: 0x12345678,
                    micSize: 0 as 0 | 2 | 4,
                    payloadLength: gpData.length,
                };

                nwkGPHandler.processFrame(gpData, macHeader, mockNwkHeader, 255);

                nwkGPHandler.exitCommissioningMode();
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "processFrame - Green Power scene recall (standard GP path)",
            () => {
                const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, 0);
                const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, macFCFOutOffset, macFCF);
                const macPayload = decodeMACPayload(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, macHOutOffset, macFCF, macHeader);

                const gpData = macPayload.subarray(2);
                const mockNwkHeader = {
                    frameControl: { frameType: 0, protocolVersion: 3, autoCommissioning: false, nwkFrameControlExtension: false },
                    sourceId: 0x87654321,
                    securityFrameCounter: 12345,
                    micSize: 4 as 0 | 2 | 4,
                    payloadLength: gpData.length,
                };

                nwkGPHandler.processFrame(gpData, macHeader, mockNwkHeader, 255);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );
    });

    describe("StackContext", () => {
        bench(
            "getDevice - device table lookup (hot path)",
            () => {
                const eui64 = 0x00124b0098765432n;
                context.deviceTable.set(eui64, {
                    address16: 0x1234,
                    capabilities: undefined,
                    authorized: true,
                    neighbor: false,
                    recentLQAs: [255, 240, 230],
                });

                context.getDevice(eui64);

                context.deviceTable.delete(eui64);
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );

        bench(
            "mapRSSIToLQI - RSSI to LQI conversion (hot path)",
            () => {
                for (let rssi = -90; rssi <= -20; rssi += 5) {
                    context.mapRSSIToLQI(rssi);
                }
            },
            {
                ...BENCH_OPTIONS,
                setup: (task, mode) => {
                    BENCH_OPTIONS.setup?.(task, mode);
                    setup();
                },
                teardown: (task, mode) => {
                    BENCH_OPTIONS.teardown?.(task, mode);
                    teardown();
                },
            },
        );
    });
});
