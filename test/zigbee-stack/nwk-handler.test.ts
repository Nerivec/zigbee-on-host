import { rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { logger } from "../../src/utils/logger.js";
import { MACAssociationStatus, type MACCapabilities, type MACHeader } from "../../src/zigbee/mac.js";
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeConsts, ZigbeeKeyType } from "../../src/zigbee/zigbee.js";
import { ZigbeeNWKCommandId, ZigbeeNWKConsts, type ZigbeeNWKHeader } from "../../src/zigbee/zigbee-nwk.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import { type NetworkParameters, StackContext, type StackContextCallbacks } from "../../src/zigbee-stack/stack-context.js";

describe("NWK Handler", () => {
    let saveDir: string;
    let nwkHandler: NWKHandler;
    let mockStackContextCallbacks: StackContextCallbacks;
    let mockContext: StackContext;
    let mockMACCallbacks: MACHandlerCallbacks;
    let mockMACHandler: MACHandler;
    let mockCallbacks: NWKHandlerCallbacks;
    let netParams: NetworkParameters;

    beforeEach(() => {
        // Register default hashed keys for encryption/decryption
        const networkKey = Buffer.from("01030507090b0d0f00020406080a0c0d", "hex");
        const tcKey = Buffer.from("5a6967426565416c6c69616e63653039", "hex");
        registerDefaultHashedKeys(
            makeKeyedHashByType(ZigbeeKeyType.LINK, tcKey),
            makeKeyedHashByType(ZigbeeKeyType.NWK, networkKey),
            makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, tcKey),
            makeKeyedHashByType(ZigbeeKeyType.LOAD, tcKey),
        );

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

        saveDir = `temp_NWKHandler_${Math.floor(Math.random() * 1000000)}`;

        mockStackContextCallbacks = {
            onDeviceLeft: vi.fn(),
        };

        mockContext = new StackContext(mockStackContextCallbacks, join(saveDir, "zoh.save"), netParams);

        // Spy on context methods to track calls while preserving functionality
        vi.spyOn(mockContext, "nextNWKKeyFrameCounter");
        vi.spyOn(mockContext, "nextTCKeyFrameCounter");
        vi.spyOn(mockContext, "associate").mockResolvedValue([MACAssociationStatus.SUCCESS, 0x1234]);
        vi.spyOn(mockContext, "disassociate").mockResolvedValue(undefined);

        mockMACCallbacks = {
            onFrame: vi.fn(),
            onSendFrame: vi.fn().mockResolvedValue(undefined),
            onAPSSendTransportKeyNWK: vi.fn().mockResolvedValue(undefined),
            onMarkRouteSuccess: vi.fn(),
            onMarkRouteFailure: vi.fn(),
        };

        mockMACHandler = new MACHandler(mockContext, mockMACCallbacks, 99999);

        // Spy on MACHandler methods to track calls
        vi.spyOn(mockMACHandler, "nextSeqNum");
        vi.spyOn(mockMACHandler, "sendFrame");
        vi.spyOn(mockMACHandler, "sendFrameDirect");

        mockCallbacks = {
            onDeviceRejoined: vi.fn(),
            onAPSSendTransportKeyNWK: vi.fn(async () => {}),
        };

        nwkHandler = new NWKHandler(mockContext, mockMACHandler, mockCallbacks);

        vi.spyOn(nwkHandler, "nextSeqNum");
        vi.spyOn(nwkHandler, "nextRouteRequestId");
    });

    afterEach(() => {
        rmSync(saveDir, { force: true, recursive: true });
    });

    describe("nextNWKSeqNum", () => {
        it("should start at 1 and increment", () => {
            expect(nwkHandler.nextSeqNum()).toStrictEqual(1);
            expect(nwkHandler.nextSeqNum()).toStrictEqual(2);
            expect(nwkHandler.nextSeqNum()).toStrictEqual(3);
        });

        it("should wrap at 255", () => {
            for (let i = 0; i < 254; i++) {
                nwkHandler.nextSeqNum();
            }

            expect(nwkHandler.nextSeqNum()).toStrictEqual(255);
            expect(nwkHandler.nextSeqNum()).toStrictEqual(0);
            expect(nwkHandler.nextSeqNum()).toStrictEqual(1);
        });
    });

    describe("nextRouteRequestId", () => {
        it("should start at 1 and increment", () => {
            expect(nwkHandler.nextRouteRequestId()).toStrictEqual(1);
            expect(nwkHandler.nextRouteRequestId()).toStrictEqual(2);
            expect(nwkHandler.nextRouteRequestId()).toStrictEqual(3);
        });

        it("should wrap at 255", () => {
            for (let i = 0; i < 254; i++) {
                nwkHandler.nextRouteRequestId();
            }

            expect(nwkHandler.nextRouteRequestId()).toStrictEqual(255);
            expect(nwkHandler.nextRouteRequestId()).toStrictEqual(0);
            expect(nwkHandler.nextRouteRequestId()).toStrictEqual(1);
        });
    });

    describe("Route Management", () => {
        it("should find best source route", () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            // Add address mapping
            mockContext.address16ToAddress64.set(device16, device64);

            // Add some routes
            mockContext.sourceRouteTable.set(device16, [
                {
                    relayAddresses: [0x0001, 0x0002],
                    pathCost: 3,
                    lastUpdated: Date.now(),
                    failureCount: 0,
                    lastUsed: undefined,
                },
                {
                    relayAddresses: [0x0003],
                    pathCost: 2,
                    lastUpdated: Date.now(),
                    failureCount: 0,
                    lastUsed: Date.now() - 1000,
                },
            ]);

            const [relayIndex, relayAddresses] = nwkHandler.findBestSourceRoute(device16, device64);

            // Should prefer recently used route with lower cost
            expect(relayIndex).toStrictEqual(0);
            expect(relayAddresses).toEqual([0x0003]);
        });

        it("should filter expired routes", () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            // Add address mapping
            mockContext.address16ToAddress64.set(device16, device64);

            // Add expired route (> 10 minutes old)
            mockContext.sourceRouteTable.set(device16, [
                {
                    relayAddresses: [0x0001],
                    pathCost: 2,
                    lastUpdated: Date.now() - 11 * 60 * 1000, // 11 minutes ago
                    failureCount: 0,
                    lastUsed: undefined,
                },
            ]);

            const [relayIndex, relayAddresses] = nwkHandler.findBestSourceRoute(device16, device64);

            // Should not find expired route
            expect(relayIndex).toBeUndefined();
            expect(relayAddresses).toBeUndefined();
        });

        it("should filter blacklisted routes", () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            // Add address mapping
            mockContext.address16ToAddress64.set(device16, device64);

            // Add route with high failure count
            mockContext.sourceRouteTable.set(device16, [
                {
                    relayAddresses: [0x0001],
                    pathCost: 2,
                    lastUpdated: Date.now(),
                    failureCount: 3, // >= MAX_FAILURES
                    lastUsed: undefined,
                },
            ]);

            const [relayIndex, relayAddresses] = nwkHandler.findBestSourceRoute(device16, device64);

            // Should not find blacklisted route
            expect(relayIndex).toBeUndefined();
            expect(relayAddresses).toBeUndefined();
        });

        it("should mark route success", () => {
            const device16 = 0x1234;

            mockContext.sourceRouteTable.set(device16, [
                {
                    relayAddresses: [0x0001],
                    pathCost: 2,
                    lastUpdated: Date.now(),
                    failureCount: 2,
                    lastUsed: undefined,
                },
            ]);

            nwkHandler.markRouteSuccess(device16);

            const routes = mockContext.sourceRouteTable.get(device16)!;
            expect(routes[0].failureCount).toStrictEqual(0);
            expect(routes[0].lastUsed).toBeDefined();
        });

        it("should mark route failure and trigger MTORR", async () => {
            const sendPeriodicManyToOneRouteRequestSpy = vi.spyOn(nwkHandler, "sendPeriodicManyToOneRouteRequest");
            const device16 = 0x1234;

            mockContext.sourceRouteTable.set(device16, [
                {
                    relayAddresses: [0x0001],
                    pathCost: 2,
                    lastUpdated: Date.now(),
                    failureCount: 2,
                    lastUsed: undefined,
                },
            ]);

            nwkHandler.markRouteFailure(device16, true);

            // Wait for setImmediate callback to execute
            await new Promise((resolve) => setImmediate(resolve));

            // Should trigger MTORR
            expect(sendPeriodicManyToOneRouteRequestSpy).toHaveBeenCalled();

            // Route should be purged (blacklisted with failureCount >= 3)
            const routes = mockContext.sourceRouteTable.get(device16);
            expect(routes).toBeUndefined();
        });
    });

    describe("NWK Command Sending", () => {
        it("should send route request command", async () => {
            const result = await nwkHandler.sendRouteReq(0, 0x1234, 0x00124b0012345678n);

            expect(result).toStrictEqual(true);
            expect(nwkHandler.nextRouteRequestId).toHaveBeenCalled();
            expect(nwkHandler.nextSeqNum).toHaveBeenCalled();
            expect(mockMACHandler.nextSeqNum).toHaveBeenCalled();
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send route reply command", async () => {
            // Add address mappings for the test
            mockContext.address16ToAddress64.set(0x0001, 0x00124b0000000001n);
            mockContext.address16ToAddress64.set(0x1234, 0x00124b0012345678n);
            mockContext.address16ToAddress64.set(0x5678, 0x00124b0056780000n);

            const result = await nwkHandler.sendRouteReply(0x0001, 10, 5, 0x1234, 0x5678, 0x00124b0012345678n, 0x00124b0087654321n);

            expect(result).toStrictEqual(true);
            expect(nwkHandler.nextSeqNum).toHaveBeenCalled();
            expect(mockMACHandler.nextSeqNum).toHaveBeenCalled();
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send network status command", async () => {
            // Add address mapping for the destination
            mockContext.address16ToAddress64.set(0x1234, 0x00124b0012345678n);

            const result = await nwkHandler.sendStatus(0x1234, 0x00);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send leave command", async () => {
            mockContext.address16ToAddress64.set(0x1234, 0x00124b0012345678n);

            const result = await nwkHandler.sendLeave(0x1234, false);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send link status command", async () => {
            await nwkHandler.sendLinkStatus([]);

            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });
    });

    describe("NWK Command Processing", () => {
        it("should process route request", async () => {
            const macHeader: MACHeader = {
                frameControl: {
                    frameType: 1,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: true,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: 2,
                    frameVersion: 0,
                    sourceAddrMode: 2,
                },
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: ZigbeeConsts.BCAST_DEFAULT,
                source16: 0x1234,
                fcs: 0,
            };

            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: 1,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: false,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.BCAST_DEFAULT,
                source16: 0x1234,
                radius: 10,
                seqNum: 5,
            };

            const payload = Buffer.from([
                ZigbeeNWKCommandId.ROUTE_REQ,
                0x00, // options
                10, // id
                0x78,
                0x56, // destination16
                0, // pathCost
            ]);

            mockContext.address16ToAddress64.set(0x1234, 0x00124b0012345678n);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            // Should have sent route reply
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should process leave request", async () => {
            const macHeader: MACHeader = {
                frameControl: {
                    frameType: 1,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: true,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: 2,
                    frameVersion: 0,
                    sourceAddrMode: 2,
                },
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x1234,
                source64: 0x00124b0012345678n,
                fcs: 0,
            };

            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: 1,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: false,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x1234,
                source64: 0x00124b0012345678n,
                radius: 1,
                seqNum: 5,
            };

            const payload = Buffer.from([
                ZigbeeNWKCommandId.LEAVE,
                0x00, // options (not rejoin, not request)
            ]);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            // Should have called disassociate callback
            expect(mockContext.disassociate).toHaveBeenCalledWith(0x1234, 0x00124b0012345678n);
        });

        it("should process route record", () => {
            const macHeader: MACHeader = {
                frameControl: {
                    frameType: 1,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: true,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: 2,
                    frameVersion: 0,
                    sourceAddrMode: 2,
                },
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x1234,
                source64: 0x00124b0012345678n,
                fcs: 0,
            };

            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: 1,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: false,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x1234,
                source64: 0x00124b0012345678n,
                radius: 10,
                seqNum: 5,
            };

            const payload = Buffer.from([
                ZigbeeNWKCommandId.ROUTE_RECORD,
                2, // relay count
                0x01,
                0x00, // relay 1
                0x02,
                0x00, // relay 2
            ]);

            nwkHandler.processCommand(payload, macHeader, nwkHeader);

            // Should have stored source route
            const routes = mockContext.sourceRouteTable.get(0x1234);
            expect(routes).toBeDefined();
            expect(routes![0].relayAddresses).toEqual([0x0001, 0x0002]);
            expect(routes![0].pathCost).toStrictEqual(3); // relayCount + 1
        });
    });

    describe("Rejoin Handling", () => {
        it("should process rejoin request and call associate callback", async () => {
            const macHeader: MACHeader = {
                frameControl: {
                    frameType: 1,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: true,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: 2,
                    frameVersion: 0,
                    sourceAddrMode: 2,
                },
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x1234,
                source64: 0x00124b0012345678n,
                fcs: 0,
            };

            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: 1,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: false,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: true,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x1234,
                source64: 0x00124b0012345678n,
                radius: 10,
                seqNum: 5,
            };

            const payload = Buffer.from([
                ZigbeeNWKCommandId.REJOIN_REQ,
                0x8e, // capabilities
            ]);

            mockContext.address16ToAddress64.set(0x1234, 0x00124b0012345678n);

            await nwkHandler.processCommand(payload, macHeader, nwkHeader);

            // Should have called associate callback
            expect(mockContext.associate).toHaveBeenCalledWith(
                0x1234,
                0x00124b0012345678n,
                false, // rejoin (not initial join)
                expect.objectContaining({
                    deviceType: 1,
                    rxOnWhenIdle: true,
                    allocateAddress: true,
                }), // capabilities
                true, // neighbor
                true, // denyOverride (security is implicitly false, checks source64 vs trusted center)
            );

            // Should have sent rejoin response
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });
    });

    describe("Link Status Processing", () => {
        it("should process link status and update source routes", () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            mockContext.deviceTable.set(device64, {
                address16: device16,
                authorized: true,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 1,
                    powerSource: 1,
                    rxOnWhenIdle: true,
                    securityCapability: true,
                    allocateAddress: true,
                },
                neighbor: false,
                recentLQAs: [255],
            });

            const macHeader: MACHeader = {
                frameControl: {
                    frameType: 1,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: true,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: 2,
                    frameVersion: 0,
                    sourceAddrMode: 2,
                },
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
                source64: device64,
                fcs: 0,
            };

            const nwkHeader: ZigbeeNWKHeader = {
                frameControl: {
                    frameType: 1,
                    protocolVersion: 2,
                    discoverRoute: 0,
                    multicast: false,
                    security: false,
                    sourceRoute: false,
                    extendedDestination: false,
                    extendedSource: true,
                    endDeviceInitiator: false,
                },
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: device16,
                source64: device64,
                radius: 1,
                seqNum: 5,
            };

            const payload = Buffer.from([
                ZigbeeNWKCommandId.LINK_STATUS,
                0x61, // options: entry count = 1, first frame, last frame
                ZigbeeConsts.COORDINATOR_ADDRESS & 0xff,
                (ZigbeeConsts.COORDINATOR_ADDRESS >> 8) & 0xff,
                0x03, // incoming cost = 3, outgoing cost = 0
            ]);

            nwkHandler.processCommand(payload, macHeader, nwkHeader);

            // Should have created source route
            const routes = mockContext.sourceRouteTable.get(device16);
            expect(routes).toBeDefined();
            expect(routes![0].pathCost).toStrictEqual(3);
        });
    });

    describe("Additional NWK Commands", () => {
        it("should process route reply", () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            mockContext.address16ToAddress64.set(device16, device64);

            const payload = Buffer.from([
                ZigbeeNWKCommandId.ROUTE_REPLY,
                0x00, // options
                15, // route request ID
                ZigbeeConsts.COORDINATOR_ADDRESS & 0xff,
                (ZigbeeConsts.COORDINATOR_ADDRESS >> 8) & 0xff,
                device16 & 0xff,
                (device16 >> 8) & 0xff,
                0x05, // path cost = 5
            ]);

            const offset = nwkHandler.processRouteReply(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    source64: device64,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    source64: device64,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toBeGreaterThan(0);
        });

        it("should process network status", () => {
            const device16 = 0x1234;
            const payload = Buffer.from([ZigbeeNWKCommandId.NWK_STATUS, 0x0b, 0x56, 0x34]);

            const offset = nwkHandler.processStatus(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toBeGreaterThan(0);
        });

        it("should send network status", async () => {
            const device16 = 0x1234;
            mockContext.address16ToAddress64.set(device16, 0x00124b0012345678n);

            const result = await nwkHandler.sendStatus(device16, 0x01); // NOT_MEMBER

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should process rejoin response", () => {
            const device16 = 0x1234;
            const payload = Buffer.from([device16 & 0xff, (device16 >> 8) & 0xff, MACAssociationStatus.SUCCESS]);

            const offset = nwkHandler.processRejoinResp(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toStrictEqual(3);
        });

        it("should process end device timeout request", async () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            mockContext.address16ToAddress64.set(device16, device64);
            mockContext.deviceTable.set(device64, {
                address16: device16,
                capabilities: {
                    rxOnWhenIdle: false,
                    deviceType: 1,
                    alternatePANCoordinator: false,
                    powerSource: 0,
                    securityCapability: false,
                    allocateAddress: false,
                },
                authorized: true,
                neighbor: false,
                recentLQAs: [],
            });

            const payload = Buffer.from([ZigbeeNWKCommandId.ED_TIMEOUT_REQUEST, 0x04, 0x00]);

            const offset = await nwkHandler.processEdTimeoutRequest(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    source64: device64,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    source64: device64,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toStrictEqual(2); // Command ID + requested timeout = 2 (config mask is not read)
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should process end device timeout response", () => {
            const device16 = 0x1234;
            const payload = Buffer.from([0x00, 0x04]);

            const offset = nwkHandler.processEdTimeoutResponse(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toStrictEqual(2);
        });

        it("should send end device timeout response", async () => {
            const device16 = 0x1234;
            mockContext.address16ToAddress64.set(device16, 0x00124b0012345678n);

            const result = await nwkHandler.sendEdTimeoutResponse(device16, 4);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should process network report", () => {
            const device16 = 0x1234;
            // NWK Report needs: options + extended PAN ID (8 bytes) + (PANIDs if report type = 0)
            const payload = Buffer.from([
                0x00, // options: report count = 0, report type = 0 (PAN conflict)
                0xdd,
                0xdd,
                0xdd,
                0xdd,
                0xdd,
                0xdd,
                0xdd,
                0xdd, // extended PAN ID
                // No PAN IDs since count = 0
            ]);

            const offset = nwkHandler.processReport(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toStrictEqual(9); // options (1) + extended PAN ID (8) = 9
        });

        it("should process network update", () => {
            const device16 = 0x1234;
            // NWK Update needs: options + extended PAN ID + update ID + (PANIDs if update type = 0)
            const payload = Buffer.from([
                0x00, // options: update count = 0, update type = 0
                0xdd,
                0xdd,
                0xdd,
                0xdd,
                0xdd,
                0xdd,
                0xdd,
                0xdd, // extended PAN ID
                0x01, // update ID
                // No PAN IDs since count = 0
            ]);

            const offset = nwkHandler.processUpdate(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toStrictEqual(10); // options (1) + extended PAN ID (8) + update ID (1) = 10
        });

        it("should process link power delta", () => {
            const device16 = 0x1234;
            const payload = Buffer.from([
                0x01, // options: type = 1 (request)
                0x01, // count = 1
                0x34,
                0x12,
                0x05,
            ]);

            const offset = nwkHandler.processLinkPwrDelta(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toStrictEqual(5);
        });

        it("should process commissioning request", async () => {
            const device16 = 0x1234;
            const payload = Buffer.from([ZigbeeNWKCommandId.COMMISSIONING_REQUEST, 0x62, 0x1a, 15]);

            const offset = await nwkHandler.processCommissioningRequest(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toStrictEqual(2); // Command ID + PAN ID (2 bytes) = 3, but channel not read
        });

        it("should process commissioning response", () => {
            const device16 = 0x1234;
            const payload = Buffer.from([0x34, 0x12, 0x00]);

            const offset = nwkHandler.processCommissioningResponse(
                payload,
                0,
                {
                    frameControl: {},
                    source16: device16,
                    sequenceNumber: 10,
                } as MACHeader,
                {
                    frameControl: {},
                    source16: device16,
                    destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                    seqNum: 20,
                } as ZigbeeNWKHeader,
            );

            expect(offset).toStrictEqual(3); // Command ID + new address (2 bytes) = 3 (status not read)
        });

        it("should send commissioning response", async () => {
            const device16 = 0x1234;
            mockContext.address16ToAddress64.set(device16, 0x00124b0012345678n);

            const result = await nwkHandler.sendCommissioningResponse(device16, 0x5678, 0x00);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send periodic link status", async () => {
            const device1Addr64 = 0x00124b0012345678n;
            const device2Addr64 = 0x00124b0087654321n;

            mockContext.deviceTable.set(device1Addr64, {
                address16: 0x1234,
                capabilities: { rxOnWhenIdle: true, deviceType: 1, alternatePANCoordinator: false } as MACCapabilities,
                authorized: true,
                neighbor: true,
                recentLQAs: [200],
            });

            mockContext.deviceTable.set(device2Addr64, {
                address16: 0x5678,
                capabilities: { rxOnWhenIdle: true, deviceType: 1, alternatePANCoordinator: false } as MACCapabilities,
                authorized: true,
                neighbor: true,
                recentLQAs: [180],
            });

            mockContext.address16ToAddress64.set(0x1234, device1Addr64);
            mockContext.address16ToAddress64.set(0x5678, device2Addr64);

            await nwkHandler.sendPeriodicZigbeeNWKLinkStatus();

            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send periodic many-to-one route request", async () => {
            await nwkHandler.sendPeriodicManyToOneRouteRequest();

            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should detect duplicate source route entries", () => {
            const device16 = 0x1234;

            const entry1 = {
                relayAddresses: [0x0001, 0x0002],
                pathCost: 3,
                lastUpdated: Date.now(),
                failureCount: 0,
                lastUsed: undefined,
            };

            const entry2 = {
                relayAddresses: [0x0001, 0x0002],
                pathCost: 3,
                lastUpdated: Date.now(),
                failureCount: 0,
                lastUsed: undefined,
            };

            const isDuplicate = nwkHandler.hasSourceRoute(device16, entry2, [entry1]);
            expect(isDuplicate).toStrictEqual(true);
        });
    });

    it("dispatches rejoin response via processCommand", () => {
        const device16 = 0x4321;
        const payload = Buffer.from([ZigbeeNWKCommandId.REJOIN_RESP, device16 & 0xff, (device16 >> 8) & 0xff, MACAssociationStatus.SUCCESS]);

        const macHeader = {
            frameControl: {},
            source16: device16,
            sequenceNumber: 7,
        } as MACHeader;
        const nwkHeader = {
            frameControl: {},
            source16: device16,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            seqNum: 4,
        } as ZigbeeNWKHeader;

        const debugSpy = vi.spyOn(logger, "debug");

        nwkHandler.processCommand(payload, macHeader, nwkHeader);

        expect(debugSpy.mock.calls.some(([, ns]) => ns === "nwk-handler")).toStrictEqual(true);
        debugSpy.mockRestore();
    });

    it("routes ED timeout response through processCommand", () => {
        const spy = vi.spyOn(nwkHandler, "processEdTimeoutResponse");
        const payload = Buffer.from([ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE, 0x00, 0x07]);

        nwkHandler.processCommand(
            payload,
            {
                frameControl: {},
                source16: 0x1001,
                sequenceNumber: 1,
            } as MACHeader,
            {
                frameControl: {},
                source16: 0x1001,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                seqNum: 11,
            } as ZigbeeNWKHeader,
        );

        expect(spy).toHaveBeenCalledOnce();
        spy.mockRestore();
    });

    it("routes link power delta through processCommand", () => {
        const spy = vi.spyOn(nwkHandler, "processLinkPwrDelta");
        const payload = Buffer.from([ZigbeeNWKCommandId.LINK_PWR_DELTA, 0x02, 0x00]);

        nwkHandler.processCommand(
            payload,
            {
                frameControl: {},
                source16: 0x2002,
                sequenceNumber: 3,
            } as MACHeader,
            {
                frameControl: {},
                source16: 0x2002,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                seqNum: 5,
            } as ZigbeeNWKHeader,
        );

        expect(spy).toHaveBeenCalledOnce();
        spy.mockRestore();
    });

    it("routes commissioning response through processCommand", () => {
        const spy = vi.spyOn(nwkHandler, "processCommissioningResponse");
        const payload = Buffer.from([ZigbeeNWKCommandId.COMMISSIONING_RESPONSE, 0x78, 0x56, 0x00]);

        nwkHandler.processCommand(
            payload,
            {
                frameControl: {},
                source16: 0x3003,
                sequenceNumber: 9,
            } as MACHeader,
            {
                frameControl: {},
                source16: 0x3003,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                seqNum: 6,
            } as ZigbeeNWKHeader,
        );

        expect(spy).toHaveBeenCalledOnce();
        spy.mockRestore();
    });

    it("logs unsupported NWK command", () => {
        const errorSpy = vi.spyOn(logger, "error");

        nwkHandler.processCommand(
            Buffer.from([0xff]),
            {
                frameControl: {},
                source16: 0x4444,
                sequenceNumber: 12,
            } as MACHeader,
            {
                frameControl: {},
                source16: 0x4444,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                seqNum: 15,
            } as ZigbeeNWKHeader,
        );

        expect(errorSpy.mock.calls.some((call) => typeof call[0] === "string" && call[0].includes("Unsupported"))).toStrictEqual(true);
        errorSpy.mockRestore();
    });

    it("decodes route request with extended destination", async () => {
        const sendRouteReplySpy = vi.spyOn(nwkHandler, "sendRouteReply").mockResolvedValue(true);
        const destination64 = 0x00124b0000000001n;
        const payload = Buffer.alloc(1 + 1 + 1 + 2 + 1 + 8);
        let offset = 0;
        offset = payload.writeUInt8(ZigbeeNWKCommandId.ROUTE_REQ, offset);
        offset = payload.writeUInt8(ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT, offset);
        offset = payload.writeUInt8(0x55, offset);
        offset = payload.writeUInt16LE(0x3456, offset);
        offset = payload.writeUInt8(0x00, offset);
        payload.writeBigUInt64LE(destination64, offset);

        await nwkHandler.processCommand(
            payload,
            {
                frameControl: {},
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source16: 0x2100,
                sequenceNumber: 18,
            } as MACHeader,
            {
                frameControl: {},
                source16: 0x2100,
                source64: 0x00124b0011223344n,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: 2,
                seqNum: 19,
            } as ZigbeeNWKHeader,
        );

        expect(sendRouteReplySpy).toHaveBeenCalledOnce();
        expect(sendRouteReplySpy.mock.calls[0][6]).toStrictEqual(destination64);
        sendRouteReplySpy.mockRestore();
    });

    it("purges relay references while retaining alternate routes", async () => {
        vi.spyOn(nwkHandler, "sendPeriodicManyToOneRouteRequest").mockResolvedValue();

        const failingDest = 0x2200;
        const now = Date.now();

        mockContext.sourceRouteTable.set(failingDest, [
            {
                relayAddresses: [0x3300],
                pathCost: 1,
                lastUpdated: now,
                failureCount: 2,
                lastUsed: undefined,
            },
        ]);

        mockContext.sourceRouteTable.set(0x4400, [
            {
                relayAddresses: [failingDest],
                pathCost: 3,
                lastUpdated: now,
                failureCount: 0,
                lastUsed: undefined,
            },
            {
                relayAddresses: [0x5500],
                pathCost: 2,
                lastUpdated: now,
                failureCount: 0,
                lastUsed: undefined,
            },
        ]);

        nwkHandler.markRouteFailure(failingDest);

        await new Promise((resolve) => setImmediate(resolve));

        const filtered = mockContext.sourceRouteTable.get(0x4400);
        expect(filtered).toBeDefined();
        expect(filtered).toHaveLength(1);
        expect(filtered?.[0].relayAddresses).toEqual([0x5500]);
    });

    it("stores route record using IEEE source when short address missing", () => {
        const device64 = 0x00124b0000667788n;
        mockContext.deviceTable.set(device64, {
            address16: 0x7788,
            capabilities: undefined,
            authorized: true,
            neighbor: true,
            recentLQAs: [],
        });

        const existingEntry = nwkHandler.createSourceRouteEntry([0x1001], 2);
        mockContext.sourceRouteTable.set(0x7788, [existingEntry]);

        const payload = Buffer.from([ZigbeeNWKCommandId.ROUTE_RECORD, 0x01, 0x34, 0x12]);

        nwkHandler.processCommand(
            payload,
            {
                frameControl: {},
                source16: 0x5555,
                sequenceNumber: 8,
            } as MACHeader,
            {
                frameControl: {},
                source16: undefined,
                source64: device64,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                seqNum: 13,
            } as ZigbeeNWKHeader,
        );

        const routes = mockContext.sourceRouteTable.get(0x7788);
        expect(routes).toBeDefined();
        expect(routes).toHaveLength(2);
    });

    it("updates source route entries when route reply introduces new path", () => {
        const responder16 = 0x6677;
        const responder64 = 0x00124b0010102020n;

        mockContext.deviceTable.set(responder64, {
            address16: responder16,
            capabilities: undefined,
            authorized: true,
            neighbor: true,
            recentLQAs: [],
        });
        mockContext.address16ToAddress64.set(responder16, responder64);

        const existing = nwkHandler.createSourceRouteEntry([0x1111], 2);
        mockContext.sourceRouteTable.set(responder16, [existing]);

        const payload = Buffer.alloc(1 + 1 + 1 + 2 + 2 + 1 + 8 + 8);
        let offset = 0;
        offset = payload.writeUInt8(ZigbeeNWKCommandId.ROUTE_REPLY, offset);
        offset = payload.writeUInt8(ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT | ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT, offset);
        offset = payload.writeUInt8(0x42, offset);
        offset = payload.writeUInt16LE(ZigbeeConsts.COORDINATOR_ADDRESS, offset);
        offset = payload.writeUInt16LE(responder16, offset);
        offset = payload.writeUInt8(0x00, offset);
        offset = payload.writeBigUInt64LE(mockContext.netParams.eui64, offset);
        payload.writeBigUInt64LE(responder64, offset);

        nwkHandler.processCommand(
            payload,
            {
                frameControl: {},
                source16: 0x2222,
                sequenceNumber: 14,
            } as MACHeader,
            {
                frameControl: {},
                source16: 0x1234,
                relayAddresses: [0x9999],
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
                seqNum: 16,
            } as ZigbeeNWKHeader,
        );

        const routes = mockContext.sourceRouteTable.get(responder16);
        expect(routes).toBeDefined();
        expect(routes).toHaveLength(2);
        expect(routes?.[1].relayAddresses).toEqual([0x9999, 0x2222]);
    });

    it("skips neighbors without short address mapping in periodic link status", async () => {
        const device64 = 0x00124b00aa55eeffn;
        mockContext.deviceTable.set(device64, {
            address16: 0x8899,
            capabilities: undefined,
            authorized: true,
            neighbor: true,
            recentLQAs: [],
        });

        const linkSpy = vi.spyOn(nwkHandler, "sendLinkStatus").mockResolvedValue();

        await nwkHandler.sendPeriodicZigbeeNWKLinkStatus();

        expect(linkSpy).toHaveBeenCalledWith([]);
        linkSpy.mockRestore();
    });
});
