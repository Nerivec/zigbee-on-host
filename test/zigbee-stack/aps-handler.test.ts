import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from "vitest";
import { logger } from "../../src/utils/logger.js";
import { MACAssociationStatus, type MACHeader } from "../../src/zigbee/mac.js";
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeConsts, ZigbeeKeyType } from "../../src/zigbee/zigbee.js";
import {
    ZigbeeAPSCommandId,
    ZigbeeAPSConsts,
    ZigbeeAPSDeliveryMode,
    ZigbeeAPSFragmentation,
    ZigbeeAPSFrameType,
    type ZigbeeAPSHeader,
} from "../../src/zigbee/zigbee-aps.js";
import { type ZigbeeNWKHeader, ZigbeeNWKRouteDiscovery } from "../../src/zigbee/zigbee-nwk.js";
import { APSHandler, type APSHandlerCallbacks, CONFIG_APS_ACK_WAIT_DURATION_MS } from "../../src/zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import {
    ApplicationKeyRequestPolicy,
    type NetworkParameters,
    StackContext,
    type StackContextCallbacks,
} from "../../src/zigbee-stack/stack-context.js";
import { createMACHeader } from "../utils.js";

describe("APS Handler", () => {
    let saveDir: string;
    let apsHandler: APSHandler;
    let mockStackContextCallbacks: StackContextCallbacks;
    let mockContext: StackContext;
    let mockMACCallbacks: MACHandlerCallbacks;
    let mockMACHandler: MACHandler;
    let mockNWKCallbacks: NWKHandlerCallbacks;
    let mockNWKHandler: NWKHandler;
    let mockCallbacks: APSHandlerCallbacks;
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

        saveDir = `temp_APSHandler_${Math.floor(Math.random() * 1000000)}`;
        mkdirSync(saveDir, { recursive: true });

        mockStackContextCallbacks = {
            onDeviceLeft: vi.fn(),
        };

        mockContext = new StackContext(mockStackContextCallbacks, join(saveDir, "zoh.save"), netParams);

        // Spy on context methods to track calls while preserving functionality
        vi.spyOn(mockContext, "nextNWKKeyFrameCounter");
        vi.spyOn(mockContext, "nextTCKeyFrameCounter");
        vi.spyOn(mockContext, "computeDeviceLQA").mockReturnValue(150);
        vi.spyOn(mockContext, "associate").mockImplementation(
            (source16, _source64, _initialJoin, _capabilities, _neighbor, _denyOverride, _allowOverride) => {
                const assigned16 = source16 ?? 0x1234;

                return Promise.resolve([MACAssociationStatus.SUCCESS, assigned16, true]);
            },
        );
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
        vi.spyOn(mockMACHandler, "sendFrame");
        vi.spyOn(mockMACHandler, "sendFrameDirect");

        mockNWKCallbacks = {
            onAPSSendTransportKeyNWK: vi.fn(async () => {}),
        };

        mockNWKHandler = new NWKHandler(mockContext, mockMACHandler, mockNWKCallbacks);

        mockCallbacks = {
            onFrame: vi.fn(),
            onDeviceJoined: vi.fn(),
            onDeviceRejoined: vi.fn(),
            onDeviceAuthorized: vi.fn(),
        };

        apsHandler = new APSHandler(mockContext, mockMACHandler, mockNWKHandler, mockCallbacks);

        vi.spyOn(apsHandler, "nextCounter");
    });

    afterEach(() => {
        apsHandler.stop();
        rmSync(saveDir, { force: true, recursive: true });
    });

    describe("constructor", () => {
        it("should initialize with provided context and callbacks", () => {
            expect(apsHandler).toBeDefined();
        });
    });

    describe("stop", () => {
        it("should call stop without error", () => {
            expect(() => apsHandler.stop()).not.toThrow();
        });
    });

    describe("nextAPSCounter", () => {
        it("should start at 1 and increment", () => {
            expect(apsHandler.nextCounter()).toStrictEqual(1);
            expect(apsHandler.nextCounter()).toStrictEqual(2);
            expect(apsHandler.nextCounter()).toStrictEqual(3);
        });

        it("should wrap at 255", () => {
            for (let i = 0; i < 254; i++) {
                apsHandler.nextCounter();
            }

            expect(apsHandler.nextCounter()).toStrictEqual(255);
            expect(apsHandler.nextCounter()).toStrictEqual(0);
            expect(apsHandler.nextCounter()).toStrictEqual(1);
        });
    });

    describe("nextZDOSeqNum", () => {
        it("should start at 1 and increment", () => {
            expect(apsHandler.nextZDOSeqNum()).toStrictEqual(1);
            expect(apsHandler.nextZDOSeqNum()).toStrictEqual(2);
            expect(apsHandler.nextZDOSeqNum()).toStrictEqual(3);
        });

        it("should wrap at 255", () => {
            for (let i = 0; i < 254; i++) {
                apsHandler.nextZDOSeqNum();
            }

            expect(apsHandler.nextZDOSeqNum()).toStrictEqual(255);
            expect(apsHandler.nextZDOSeqNum()).toStrictEqual(0);
            expect(apsHandler.nextZDOSeqNum()).toStrictEqual(1);
        });
    });

    describe("APS Data Sending", () => {
        it("should send APS data frame with valid parameters", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const apsPayload = Buffer.from("test data");
            const clusterId = 0x0006;
            const profileId = 0x0104;
            const sourceEndpoint = 0x01;
            const destEndpoint = 0x01;

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendData(
                apsPayload,
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                destination16,
                destination64,
                ZigbeeAPSDeliveryMode.UNICAST,
                clusterId,
                profileId,
                destEndpoint,
                sourceEndpoint,
                undefined,
            );

            expect(result).toBeGreaterThanOrEqual(0); // Returns APS counter
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
            expect(apsHandler.nextCounter).toHaveBeenCalled();
        });

        it("should send broadcast APS data", async () => {
            const apsPayload = Buffer.from("broadcast data");
            const clusterId = 0x0006;
            const profileId = 0x0104;
            const sourceEndpoint = 0x01;

            const result = await apsHandler.sendData(
                apsPayload,
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                0xfffc, // broadcast address
                undefined,
                ZigbeeAPSDeliveryMode.BCAST,
                clusterId,
                profileId,
                undefined, // no dest endpoint for broadcast
                sourceEndpoint,
                undefined,
            );

            expect(result).toBeGreaterThanOrEqual(0);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });
    });

    describe("APS Command Sending - Transport Key", () => {
        it("should send Transport Key TC command", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const key = Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex");

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendTransportKeyTC(destination16, key, destination64);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
            expect(mockContext.nextTCKeyFrameCounter).toHaveBeenCalled();
        });

        it("should send Transport Key NWK command", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const key = Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex");
            const seqNum = 0;

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendTransportKeyNWK(destination16, key, seqNum, destination64);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send Transport Key APP command", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const key = Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex");
            const partner64 = 0x00124b0011223344n;
            const initiatorFlag = true;

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendTransportKeyAPP(destination16, key, partner64, initiatorFlag);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });
    });

    describe("APS Command Sending - Device Management", () => {
        it("should send Update Device command", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const device64 = 0x00124b0011223344n;
            const device16 = 0x5678;
            const status = 0x00; // secured rejoin

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendUpdateDevice(destination16, device64, device16, status);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send Remove Device command", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const target64 = 0x00124b0011223344n;

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendRemoveDevice(destination16, target64);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });
    });

    describe("APS Command Sending - Key Management", () => {
        it("should send Request Key command for TC key", async () => {
            const destination16 = ZigbeeConsts.COORDINATOR_ADDRESS;
            const destination64 = netParams.eui64;

            // Add coordinator to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendRequestKey(destination16, 0x04);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send Request Key command for APP key", async () => {
            const destination16 = ZigbeeConsts.COORDINATOR_ADDRESS;
            const destination64 = netParams.eui64;
            const partner64 = 0x00124b0011223344n;

            // Add coordinator to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendRequestKey(destination16, 0x02, partner64);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send Switch Key command", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const seqNum = 1;

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendSwitchKey(destination16, seqNum);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send Verify Key command", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const keyType = 0x01; // TC key
            const source64 = 0x00124b0012345678n;
            const hash = Buffer.alloc(16, 0xff);

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendVerifyKey(destination16, keyType, source64, hash);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });

        it("should send Confirm Key command", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const status = 0x00; // success
            const keyType = 0x01; // TC key

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendConfirmKey(destination16, status, keyType, destination64);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });
    });

    describe("APS Command Sending - Tunnel", () => {
        it("should send Tunnel command", async () => {
            const destination16 = 0x1234;
            const destination64 = 0x00124b0087654321n;
            const tunnelPayload = Buffer.from("tunneled command");

            // Add device to device table
            mockContext.deviceTable.set(destination64, {
                address16: destination16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
            mockContext.address16ToAddress64.set(destination16, destination64);

            const result = await apsHandler.sendTunnel(destination16, destination64, tunnelPayload);

            expect(result).toStrictEqual(true);
            expect(mockMACHandler.sendFrame).toHaveBeenCalled();
        });
    });

    describe("APS Command Processing", () => {
        it("should process Transport Key command", () => {
            const data = Buffer.alloc(50);
            let offset = 0;

            // Command ID
            data.writeUInt8(0x05, offset++); // TRANSPORT_KEY

            // Key type (Network Key)
            data.writeUInt8(0x01, offset++);

            // Key
            Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex").copy(data, offset);
            offset += 16;

            // Sequence number
            data.writeUInt8(0, offset++);

            // Destination address
            data.writeBigUInt64LE(0x00124b0012345678n, offset);

            // Source address
            data.writeBigUInt64LE(0x00224b0012345678n, offset);

            const macHeader = createMACHeader();
            const nwkHeader = { frameControl: {} } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            // Should not throw
            // TODO: more complete tests
            expect(() => {
                apsHandler.processTransportKey(data, 0, macHeader, nwkHeader, apsHeader);
            }).not.toThrow();
        });

        it("should process Switch Key command", () => {
            const data = Buffer.alloc(10);
            let offset = 0;

            // Command ID
            data.writeUInt8(0x06, offset++); // SWITCH_KEY

            // Sequence number
            data.writeUInt8(1, offset++);

            const macHeader = createMACHeader();
            const nwkHeader = { frameControl: {} } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            // Should not throw
            // TODO: more complete tests
            expect(() => {
                apsHandler.processSwitchKey(data, 0, macHeader, nwkHeader, apsHeader);
            }).not.toThrow();
        });

        it("should process Remove Device command", () => {
            const data = Buffer.alloc(20);
            let offset = 0;

            // Command ID
            data.writeUInt8(0x0b, offset++); // REMOVE_DEVICE

            // Target IEEE address
            data.writeBigUInt64LE(0x00124b0011223344n, offset);

            const macHeader = createMACHeader();
            const nwkHeader = { frameControl: {} } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            // Should not throw
            // TODO: more complete tests
            expect(() => {
                apsHandler.processRemoveDevice(data, 0, macHeader, nwkHeader, apsHeader);
            }).not.toThrow();
        });

        it("should process Tunnel command", () => {
            const data = Buffer.alloc(30);
            let offset = 0;

            // Command ID
            data.writeUInt8(0x0e, offset++); // TUNNEL

            // Destination address
            data.writeBigUInt64LE(0x00124b0087654321n, offset);
            offset += 8;

            // Tunneled APS command
            data.writeUInt8(0x05, offset++); // Example: TRANSPORT_KEY

            const macHeader = createMACHeader();
            const nwkHeader = { frameControl: {} } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            // Should not throw
            // TODO: more complete tests
            expect(() => {
                apsHandler.processTunnel(data, 0, macHeader, nwkHeader, apsHeader);
            }).not.toThrow();
        });

        it("should process Confirm Key command", () => {
            const data = Buffer.alloc(20);
            let offset = 0;

            // Command ID
            data.writeUInt8(0x0f, offset++); // CONFIRM_KEY

            // Status
            data.writeUInt8(0x00, offset++); // success

            // Key type
            data.writeUInt8(0x01, offset++); // TC key

            // Destination address
            data.writeBigUInt64LE(0x00124b0087654321n, offset);

            const macHeader = createMACHeader();
            const nwkHeader = { frameControl: {} } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            // Should not throw
            // TODO: more complete tests
            expect(() => {
                apsHandler.processConfirmKey(data, 0, macHeader, nwkHeader, apsHeader);
            }).not.toThrow();
        });
    });

    describe("APS Frame Processing", () => {
        it("should emit frame event on valid APS data frame", async () => {
            const macHeader: MACHeader = {
                source16: 0x1234,
                source64: 0x00124b0087654321n,
            } as MACHeader;

            const nwkHeader: ZigbeeNWKHeader = {
                source16: 0x1234,
                source64: 0x00124b0087654321n, // Add source64 to NWK header
            } as ZigbeeNWKHeader;

            const apsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: 0, // DATA
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                destEndpoint: 0x01,
                clusterId: 0x0006,
                profileId: 0x0104,
                sourceEndpoint: 0x01,
                counter: 10,
            };

            const apsPayload = Buffer.from("test data");
            const lqa = 150;

            await apsHandler.processFrame(apsPayload, macHeader, nwkHeader, apsHeader, lqa);

            // Wait for setImmediate callback
            await new Promise((resolve) => setImmediate(resolve));

            expect(mockCallbacks.onFrame).toHaveBeenCalledWith(0x1234, 0x00124b0087654321n, apsHeader, apsPayload, lqa);
        });

        it("should respond to ZDO requests for coordinator", async () => {
            // Spy on ZDO methods
            const isZDOSpy = vi.spyOn(apsHandler, "isZDORequestForCoordinator").mockReturnValue(true);
            const respondZDOSpy = vi.spyOn(apsHandler, "respondToCoordinatorZDORequest").mockResolvedValue(undefined);

            const macHeader: MACHeader = {
                source16: 0x1234,
                source64: 0x00124b0087654321n,
            } as MACHeader;

            const nwkHeader: ZigbeeNWKHeader = {
                source16: 0x1234,
                destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            } as ZigbeeNWKHeader;

            const apsHeader: ZigbeeAPSHeader = {
                frameControl: {
                    frameType: 0, // DATA
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                destEndpoint: 0x00, // ZDO endpoint
                clusterId: 0x0000, // ZDO cluster (request, not response)
                profileId: 0x0000,
                sourceEndpoint: 0x00,
                counter: 10,
            };

            const apsPayload = Buffer.from("zdo request");
            const lqa = 150;

            await apsHandler.processFrame(apsPayload, macHeader, nwkHeader, apsHeader, lqa);

            expect(isZDOSpy).toHaveBeenCalled();
            expect(respondZDOSpy).toHaveBeenCalled();

            isZDOSpy.mockRestore();
            respondZDOSpy.mockRestore();
        });

        it("ignores APS data frames without payload", async () => {
            (mockCallbacks.onFrame as Mock).mockClear();

            const macHeader = { frameControl: {}, source16: 0x2010, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: 0x2010, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as ZigbeeNWKHeader;
            const apsHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                destEndpoint: 0x04,
                clusterId: 0x1234,
                profileId: 0x0104,
                sourceEndpoint: 0x01,
                counter: 0x10,
            } as ZigbeeAPSHeader;

            await apsHandler.processFrame(Buffer.alloc(0), macHeader, nwkHeader, apsHeader, 160);

            expect(mockCallbacks.onFrame).not.toHaveBeenCalled();
        });

        it("ignores end device announcements from unknown devices", async () => {
            (mockCallbacks.onDeviceJoined as Mock).mockClear();
            (mockCallbacks.onDeviceRejoined as Mock).mockClear();

            const announcePayload = Buffer.alloc(12);
            let offset = 0;
            announcePayload.writeUInt8(0x01, offset);
            offset += 1;
            const device16 = 0x3322;
            const device64 = 0x00124b0000003322n;
            announcePayload.writeUInt16LE(device16, offset);
            offset += 2;
            announcePayload.writeBigUInt64LE(device64, offset);
            offset += 8;
            announcePayload.writeUInt8(0x8e, offset);

            const macHeader = { frameControl: {}, source16: device16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as ZigbeeNWKHeader;
            const apsHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                destEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                clusterId: ZigbeeConsts.END_DEVICE_ANNOUNCE,
                profileId: ZigbeeConsts.ZDO_PROFILE_ID,
                sourceEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                counter: 0x11,
            } as ZigbeeAPSHeader;

            await apsHandler.processFrame(announcePayload, macHeader, nwkHeader, apsHeader, 150);
            await new Promise((resolve) => setImmediate(resolve));

            expect(mockCallbacks.onDeviceJoined).not.toHaveBeenCalled();
            expect(mockCallbacks.onDeviceRejoined).not.toHaveBeenCalled();
        });

        it("reports authorized devices as rejoining on end device announce", async () => {
            (mockCallbacks.onDeviceJoined as Mock).mockClear();
            (mockCallbacks.onDeviceRejoined as Mock).mockClear();

            const device16 = 0x4422;
            const device64 = 0x00124b0000004422n;

            mockContext.deviceTable.set(device64, {
                address16: device16,
                capabilities: undefined,
                authorized: true,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });

            const payload = Buffer.alloc(12);
            let offset = 0;
            payload.writeUInt8(0x02, offset);
            offset += 1;
            payload.writeUInt16LE(device16, offset);
            offset += 2;
            payload.writeBigUInt64LE(device64, offset);
            offset += 8;
            payload.writeUInt8(0x8e, offset);

            const macHeader = { frameControl: {}, source16: device16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as ZigbeeNWKHeader;
            const apsHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                destEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                clusterId: ZigbeeConsts.END_DEVICE_ANNOUNCE,
                profileId: ZigbeeConsts.ZDO_PROFILE_ID,
                sourceEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                counter: 0x12,
            } as ZigbeeAPSHeader;

            await apsHandler.processFrame(payload, macHeader, nwkHeader, apsHeader, 140);
            await new Promise((resolve) => setImmediate(resolve));

            expect(mockCallbacks.onDeviceJoined).not.toHaveBeenCalled();
            expect(mockCallbacks.onDeviceRejoined).toHaveBeenCalledWith(
                device16,
                device64,
                expect.objectContaining({ rxOnWhenIdle: expect.any(Boolean) }),
            );
        });

        it("reports unauthorized devices as newly joined on end device announce", async () => {
            (mockCallbacks.onDeviceJoined as Mock).mockClear();
            (mockCallbacks.onDeviceRejoined as Mock).mockClear();

            const device16 = 0x5522;
            const device64 = 0x00124b0000005522n;

            mockContext.deviceTable.set(device64, {
                address16: device16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });

            const payload = Buffer.alloc(12);
            let offset = 0;
            payload.writeUInt8(0x03, offset);
            offset += 1;
            payload.writeUInt16LE(device16, offset);
            offset += 2;
            payload.writeBigUInt64LE(device64, offset);
            offset += 8;
            payload.writeUInt8(0x8c, offset);

            const macHeader = { frameControl: {}, source16: device16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as ZigbeeNWKHeader;
            const apsHeader = {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                destEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                clusterId: ZigbeeConsts.END_DEVICE_ANNOUNCE,
                profileId: ZigbeeConsts.ZDO_PROFILE_ID,
                sourceEndpoint: ZigbeeConsts.ZDO_ENDPOINT,
                counter: 0x13,
            } as ZigbeeAPSHeader;

            await apsHandler.processFrame(payload, macHeader, nwkHeader, apsHeader, 130);
            await new Promise((resolve) => setImmediate(resolve));

            expect(mockCallbacks.onDeviceJoined).toHaveBeenCalledWith(
                device16,
                device64,
                expect.objectContaining({ rxOnWhenIdle: expect.any(Boolean) }),
            );
            expect(mockCallbacks.onDeviceRejoined).not.toHaveBeenCalled();
        });

        it("throws when APS frame type is unsupported", async () => {
            const macHeader = { frameControl: {}, source16: 0x6611, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: 0x6611, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as ZigbeeNWKHeader;
            const apsHeader = {
                frameControl: {
                    frameType: 0x7f as unknown as ZigbeeAPSFrameType,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
            } as ZigbeeAPSHeader;

            await expect(apsHandler.processFrame(Buffer.from([0x01]), macHeader, nwkHeader, apsHeader, 120)).rejects.toThrow(
                "Illegal frame type 127",
            );
        });
    });

    describe("ZDO Response Helpers", () => {
        it("should generate LQI table response", () => {
            // Add some neighbor devices to device table
            mockContext.deviceTable.set(0x00124b0011111111n, {
                address16: 0x1234,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 1,
                    powerSource: 1,
                    rxOnWhenIdle: true,
                    securityCapability: false,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: true,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [150, 155, 152],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });

            mockContext.deviceTable.set(0x00124b0022222222n, {
                address16: 0x5678,
                capabilities: {
                    alternatePANCoordinator: false,
                    deviceType: 0,
                    powerSource: 0,
                    rxOnWhenIdle: false,
                    securityCapability: false,
                    allocateAddress: true,
                },
                authorized: true,
                neighbor: true,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [100],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });

            mockContext.deviceTable.set(0x00124b0033333333n, {
                address16: 0x9abc,
                capabilities: undefined,
                authorized: false,
                neighbor: false, // Not a neighbor, should be skipped
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });

            const lqiTable = apsHandler.getLQITableResponse(0);

            // Verify structure: [seq, status, total, startIndex, count, ...entries]
            expect(lqiTable.readUInt8(0)).toStrictEqual(0); // seq num
            expect(lqiTable.readUInt8(1)).toStrictEqual(0); // SUCCESS
            expect(lqiTable.readUInt8(2)).toStrictEqual(2); // total neighbor entries
            expect(lqiTable.readUInt8(3)).toStrictEqual(0); // start index
            expect(lqiTable.readUInt8(4)).toStrictEqual(2); // entries following

            // Each entry is 22 bytes: extPanId(8) + eui64(8) + nwkAddr(2) + deviceType(1) + permitJoin(1) + depth(1) + lqa(1)
            expect(lqiTable.byteLength).toStrictEqual(5 + 2 * 22);

            // Verify first entry
            expect(lqiTable.readBigUInt64LE(5)).toStrictEqual(mockContext.netParams.extendedPanId);
            expect(lqiTable.readBigUInt64LE(13)).toStrictEqual(0x00124b0011111111n);
            expect(lqiTable.readUInt16LE(21)).toStrictEqual(0x1234);
            // offset: 5 + 8 (extPanId) + 8 (eui64) + 2 (nwkAddr) + 1 (deviceType) + 1 (permitJoin) = 25
            expect(lqiTable.readUInt8(25)).toStrictEqual(1); // depth
            expect(lqiTable.readUInt8(26)).toStrictEqual(150); // lqa

            // Verify second entry (starts at 5 + 22 = 27)
            expect(lqiTable.readBigUInt64LE(27)).toStrictEqual(mockContext.netParams.extendedPanId);
            expect(lqiTable.readBigUInt64LE(35)).toStrictEqual(0x00124b0022222222n);
            expect(lqiTable.readUInt16LE(43)).toStrictEqual(0x5678);
            expect(lqiTable.readUInt8(47)).toStrictEqual(1); // depth
            expect(lqiTable.readUInt8(48)).toStrictEqual(150); // lqa (from mock)
        });

        it("should handle LQI table with start index", () => {
            // Add multiple neighbor devices
            for (let i = 0; i < 10; i++) {
                mockContext.deviceTable.set(BigInt(0x00124b0000000000 + i), {
                    address16: 0x1000 + i,
                    capabilities: {
                        alternatePANCoordinator: false,
                        deviceType: 1,
                        powerSource: 1,
                        rxOnWhenIdle: true,
                        securityCapability: false,
                        allocateAddress: true,
                    },
                    authorized: true,
                    neighbor: true,
                    lastTransportedNetworkKeySeq: undefined,
                    recentLQAs: [],
                    incomingNWKFrameCounter: undefined,
                    endDeviceTimeout: undefined,
                    linkStatusMisses: 0,
                });
            }

            const lqiTable = apsHandler.getLQITableResponse(5);

            expect(lqiTable.readUInt8(2)).toStrictEqual(10); // total entries
            expect(lqiTable.readUInt8(3)).toStrictEqual(5); // start index
            expect(lqiTable.readUInt8(4)).toStrictEqual(5); // 5 entries from index 5
        });

        it("should generate routing table response", () => {
            // Add source routes
            mockContext.sourceRouteTable.set(0x1234, [
                {
                    relayAddresses: [0x0001, 0x0002],
                    pathCost: 3,
                    lastUpdated: Date.now(),
                    failureCount: 0,
                    lastUsed: undefined,
                },
            ]);

            mockContext.sourceRouteTable.set(0x5678, [
                {
                    relayAddresses: [0x0003],
                    pathCost: 2,
                    lastUpdated: Date.now(),
                    failureCount: 0,
                    lastUsed: undefined,
                },
            ]);

            // Spy on findBestSourceRoute to return the relay addresses
            const findBestSourceRouteSpy = vi.spyOn(mockNWKHandler, "findBestSourceRoute");
            findBestSourceRouteSpy.mockReturnValueOnce([1, [0x0001, 0x0002], 3]);
            findBestSourceRouteSpy.mockReturnValueOnce([0, [0x0003], 2]);

            const routingTable = apsHandler.getRoutingTableResponse(0);

            // Verify structure: [seq, status, total, startIndex, count, ...entries]
            expect(routingTable.readUInt8(0)).toStrictEqual(0); // seq num
            expect(routingTable.readUInt8(1)).toStrictEqual(0); // SUCCESS
            expect(routingTable.readUInt8(2)).toStrictEqual(2); // total entries
            expect(routingTable.readUInt8(3)).toStrictEqual(0); // start index
            expect(routingTable.readUInt8(4)).toStrictEqual(2); // entries following

            // Each entry is 5 bytes: destination(2) + status(1) + nextHop(2)
            expect(routingTable.byteLength).toStrictEqual(5 + 2 * 5);

            // Verify first entry
            expect(routingTable.readUInt16LE(5)).toStrictEqual(0x1234);
            expect(routingTable.readUInt8(7)).toStrictEqual(0); // status byte (ACTIVE)
            expect(routingTable.readUInt16LE(8)).toStrictEqual(0x0002); // next hop (last in relay)

            // Verify second entry
            expect(routingTable.readUInt16LE(10)).toStrictEqual(0x5678);
            expect(routingTable.readUInt8(12)).toStrictEqual(0); // status byte (ACTIVE)
            expect(routingTable.readUInt16LE(13)).toStrictEqual(0x0003); // next hop
        });

        it("should handle routing table with start index and clipping", () => {
            // Add many source routes
            for (let i = 0; i < 300; i++) {
                mockContext.sourceRouteTable.set(0x1000 + i, [
                    {
                        relayAddresses: [0x0001],
                        pathCost: 2,
                        lastUpdated: Date.now(),
                        failureCount: 0,
                        lastUsed: undefined,
                    },
                ]);
            }

            const findBestSourceRouteSpy = vi.spyOn(mockNWKHandler, "findBestSourceRoute");
            findBestSourceRouteSpy.mockReturnValue([0, [0x0001], 2]);

            const routingTable = apsHandler.getRoutingTableResponse(0);

            // Should clip to 255 entries
            expect(routingTable.readUInt8(2)).toStrictEqual(255); // clipped total
            expect(routingTable.readUInt8(4)).toStrictEqual(255); // 255 entries

            const routingTableOffset = apsHandler.getRoutingTableResponse(200);
            expect(routingTableOffset.readUInt8(3)).toStrictEqual(200); // start index
            expect(routingTableOffset.readUInt8(4)).toStrictEqual(100); // remaining 100 entries
        });

        it("should generate coordinator ZDO responses", () => {
            // Set up test config attributes (write directly to the buffers)
            const testAddress = Buffer.from([0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
            const testNodeDesc = Buffer.from([0, 10, 11, 12, 13]);
            const testPowerDesc = Buffer.from([0, 20, 21, 22]);
            const testSimpleDesc = Buffer.from([0, 30, 31, 32]);
            const testActiveEP = Buffer.from([0, 40, 41, 42]);

            testAddress.copy(mockContext.configAttributes.address);
            testNodeDesc.copy(mockContext.configAttributes.nodeDescriptor);
            testPowerDesc.copy(mockContext.configAttributes.powerDescriptor);
            testSimpleDesc.copy(mockContext.configAttributes.simpleDescriptors);
            testActiveEP.copy(mockContext.configAttributes.activeEndpoints);

            // Test NETWORK_ADDRESS_REQUEST
            let response = apsHandler.getCoordinatorZDOResponse(ZigbeeConsts.NETWORK_ADDRESS_REQUEST, Buffer.from([0x00]));
            expect(response).toEqual(mockContext.configAttributes.address);

            // Test IEEE_ADDRESS_REQUEST
            response = apsHandler.getCoordinatorZDOResponse(ZigbeeConsts.IEEE_ADDRESS_REQUEST, Buffer.from([0x00]));
            expect(response).toEqual(mockContext.configAttributes.address);

            // Test NODE_DESCRIPTOR_REQUEST
            response = apsHandler.getCoordinatorZDOResponse(ZigbeeConsts.NODE_DESCRIPTOR_REQUEST, Buffer.from([0x00]));
            expect(response).toEqual(mockContext.configAttributes.nodeDescriptor);

            // Test POWER_DESCRIPTOR_REQUEST
            response = apsHandler.getCoordinatorZDOResponse(ZigbeeConsts.POWER_DESCRIPTOR_REQUEST, Buffer.from([0x00]));
            expect(response).toEqual(mockContext.configAttributes.powerDescriptor);

            // Test SIMPLE_DESCRIPTOR_REQUEST
            response = apsHandler.getCoordinatorZDOResponse(ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST, Buffer.from([0x00]));
            expect(response).toEqual(mockContext.configAttributes.simpleDescriptors);

            // Test ACTIVE_ENDPOINTS_REQUEST
            response = apsHandler.getCoordinatorZDOResponse(ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST, Buffer.from([0x00]));
            expect(response).toEqual(mockContext.configAttributes.activeEndpoints);

            // Test unsupported cluster
            response = apsHandler.getCoordinatorZDOResponse(0xffff, Buffer.from([0x00]));
            expect(response).toBeUndefined();
        });

        it("should check if ZDO request is for coordinator - direct address", () => {
            const data = Buffer.alloc(10);

            // Direct to coordinator address
            expect(apsHandler.isZDORequestForCoordinator(0x0000, ZigbeeConsts.COORDINATOR_ADDRESS, undefined, data)).toStrictEqual(true);

            // Direct to coordinator EUI64
            expect(apsHandler.isZDORequestForCoordinator(0x0000, undefined, mockContext.netParams.eui64, data)).toStrictEqual(true);

            // Not for coordinator
            expect(apsHandler.isZDORequestForCoordinator(0x0000, 0x1234, undefined, data)).toStrictEqual(false);
        });

        it("should check if ZDO request is for coordinator - broadcast", () => {
            // NETWORK_ADDRESS_REQUEST broadcast with coordinator EUI64
            const data1 = Buffer.alloc(10);
            data1.writeBigUInt64LE(mockContext.netParams.eui64, 1);
            expect(
                apsHandler.isZDORequestForCoordinator(ZigbeeConsts.NETWORK_ADDRESS_REQUEST, ZigbeeConsts.BCAST_DEFAULT, undefined, data1),
            ).toStrictEqual(true);

            // NETWORK_ADDRESS_REQUEST broadcast with different EUI64
            const data2 = Buffer.alloc(10);
            data2.writeBigUInt64LE(0x00124b0099999999n, 1);
            expect(
                apsHandler.isZDORequestForCoordinator(ZigbeeConsts.NETWORK_ADDRESS_REQUEST, ZigbeeConsts.BCAST_DEFAULT, undefined, data2),
            ).toStrictEqual(false);

            // IEEE_ADDRESS_REQUEST broadcast with coordinator address
            const data3 = Buffer.alloc(10);
            data3.writeUInt16LE(ZigbeeConsts.COORDINATOR_ADDRESS, 1);
            expect(
                apsHandler.isZDORequestForCoordinator(ZigbeeConsts.IEEE_ADDRESS_REQUEST, ZigbeeConsts.BCAST_DEFAULT, undefined, data3),
            ).toStrictEqual(true);

            // NODE_DESCRIPTOR_REQUEST broadcast with coordinator address
            const data4 = Buffer.alloc(10);
            data4.writeUInt16LE(ZigbeeConsts.COORDINATOR_ADDRESS, 1);
            expect(
                apsHandler.isZDORequestForCoordinator(ZigbeeConsts.NODE_DESCRIPTOR_REQUEST, ZigbeeConsts.BCAST_DEFAULT, undefined, data4),
            ).toStrictEqual(true);

            // Not a broadcast
            expect(apsHandler.isZDORequestForCoordinator(ZigbeeConsts.NODE_DESCRIPTOR_REQUEST, 0x1234, undefined, data4)).toStrictEqual(false);
        });

        it("should respond to coordinator ZDO request", async () => {
            // Set up config attributes with sequence number at position 0
            const testNodeDesc = Buffer.from([0x42, 10, 11, 12, 13]);
            mockContext.configAttributes.nodeDescriptor = testNodeDesc;

            const sendDataSpy = vi.spyOn(apsHandler, "sendData").mockResolvedValue(123);

            const requestData = Buffer.alloc(10);
            requestData[0] = 0x42; // sequence number

            await apsHandler.respondToCoordinatorZDORequest(requestData, ZigbeeConsts.NODE_DESCRIPTOR_REQUEST, 0x1234, 0x00124b0087654321n);

            expect(sendDataSpy).toHaveBeenCalled();
            const sentPayload = sendDataSpy.mock.calls[0][0] as Buffer;
            expect(sentPayload[0]).toStrictEqual(0x42); // Sequence number copied from request

            sendDataSpy.mockRestore();
        });

        it("should not respond to coordinator ZDO request for unsupported cluster", async () => {
            const sendDataSpy = vi.spyOn(apsHandler, "sendData").mockResolvedValue(123);

            const requestData = Buffer.alloc(10);

            await apsHandler.respondToCoordinatorZDORequest(requestData, 0xffff, 0x1234, 0x00124b0087654321n);

            expect(sendDataSpy).not.toHaveBeenCalled();

            sendDataSpy.mockRestore();
        });
    });

    describe("Request Key Processing", () => {
        it("should process APP key request when policy allows", async () => {
            mockContext.trustCenterPolicies.allowAppKeyRequest = 1; // ALLOWED
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;
            const partner64 = 0x00124b0087654321n;

            mockContext.address16ToAddress64.set(device16, device64);

            const data = Buffer.alloc(10);
            let offset = 0;

            data.writeUInt8(0x02, offset++); // CMD_KEY_APP_MASTER
            data.writeBigUInt64LE(partner64, offset);

            const macHeader = { frameControl: {}, source16: device16, source64: device64 } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16, source64: device64 } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: { security: true } } as ZigbeeAPSHeader;

            const sendSpy = vi.spyOn(apsHandler, "sendTransportKeyAPP").mockResolvedValue(true);

            await apsHandler.processRequestKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(sendSpy).toHaveBeenCalled();
            sendSpy.mockRestore();
        });

        it("should process TC key request when policy allows", async () => {
            mockContext.trustCenterPolicies.allowTCKeyRequest = 1; // ALLOWED
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            mockContext.address16ToAddress64.set(device16, device64);

            const data = Buffer.alloc(10);
            data.writeUInt8(0x04, 0); // CMD_KEY_TC_LINK

            const macHeader = { frameControl: {}, source16: device16, source64: device64 } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16, source64: device64 } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: { security: true } } as ZigbeeAPSHeader;

            const sendSpy = vi.spyOn(apsHandler, "sendTransportKeyTC").mockResolvedValue(true);

            await apsHandler.processRequestKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(sendSpy).toHaveBeenCalled();
            sendSpy.mockRestore();
        });

        it("should drop request key if not APS encrypted", async () => {
            const device16 = 0x1234;
            const data = Buffer.alloc(10);
            data.writeUInt8(0x02, 0); // CMD_KEY_APP_MASTER

            const macHeader = { frameControl: {}, source16: device16 } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16 } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: { security: false } } as ZigbeeAPSHeader;

            const sendSpy = vi.spyOn(apsHandler, "sendTransportKeyAPP");

            const offset = await apsHandler.processRequestKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(offset).toBe(1); // Should just consume the key type byte
            expect(sendSpy).not.toHaveBeenCalled();
            sendSpy.mockRestore();
        });

        it("should not send key to unknown device", async () => {
            const device16 = 0x9999; // Unknown device
            const data = Buffer.alloc(10);
            data.writeUInt8(0x02, 0); // CMD_KEY_APP_MASTER

            const macHeader = { frameControl: {}, source16: device16 } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16 } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: { security: true } } as ZigbeeAPSHeader;

            const sendSpy = vi.spyOn(apsHandler, "sendTransportKeyAPP");

            await apsHandler.processRequestKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(sendSpy).not.toHaveBeenCalled();
            sendSpy.mockRestore();
        });
    });

    describe("Verify Key Processing", () => {
        it("should process TC link key verification with correct hash", async () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            // Set up tcVerifyKeyHash
            mockContext.tcVerifyKeyHash = Buffer.from("abcdef1234567890abcdef1234567890", "hex");

            const data = Buffer.alloc(26);
            let offset = 0;

            data.writeUInt8(0x04, offset++); // CMD_KEY_TC_LINK
            data.writeBigUInt64LE(device64, offset);
            offset += 8;
            mockContext.tcVerifyKeyHash.copy(data, offset); // Correct hash

            const macHeader = { frameControl: {}, source16: device16, source64: device64 } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16, source64: device64 } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            const sendSpy = vi.spyOn(apsHandler, "sendConfirmKey").mockResolvedValue(true);

            await apsHandler.processVerifyKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(sendSpy).toHaveBeenCalledWith(device16, 0x00, 0x04, device64); // SUCCESS
            sendSpy.mockRestore();
        });

        it("should process TC link key verification with incorrect hash", async () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            const data = Buffer.alloc(26);
            let offset = 0;

            data.writeUInt8(0x04, offset++); // CMD_KEY_TC_LINK
            data.writeBigUInt64LE(device64, offset);
            offset += 8;
            Buffer.from("ffffffffffffffffffffffffffffffff", "hex").copy(data, offset); // Wrong hash

            const macHeader = { frameControl: {}, source16: device16, source64: device64 } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16, source64: device64 } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            const sendSpy = vi.spyOn(apsHandler, "sendConfirmKey").mockResolvedValue(true);

            await apsHandler.processVerifyKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(sendSpy).toHaveBeenCalledWith(device16, 0xad, 0x04, device64); // SECURITY_FAILURE
            sendSpy.mockRestore();
        });

        it("should reject APP master key verification as illegal", async () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            const data = Buffer.alloc(26);
            let offset = 0;

            data.writeUInt8(0x02, offset++); // CMD_KEY_APP_MASTER
            data.writeBigUInt64LE(device64, offset);
            offset += 8;
            Buffer.alloc(16).copy(data, offset);

            const macHeader = { frameControl: {}, source16: device16, source64: device64 } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16, source64: device64 } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            const sendSpy = vi.spyOn(apsHandler, "sendConfirmKey").mockResolvedValue(true);

            await apsHandler.processVerifyKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(sendSpy).toHaveBeenCalledWith(device16, 0xa3, 0x02, device64); // ILLEGAL_REQUEST
            sendSpy.mockRestore();
        });

        it("should reject unsupported key type", async () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            const data = Buffer.alloc(26);
            let offset = 0;

            data.writeUInt8(0x99, offset++); // Unsupported key type
            data.writeBigUInt64LE(device64, offset);
            offset += 8;
            Buffer.alloc(16).copy(data, offset);

            const macHeader = { frameControl: {}, source16: device16, source64: device64 } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16, source64: device64 } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            const sendSpy = vi.spyOn(apsHandler, "sendConfirmKey").mockResolvedValue(true);

            await apsHandler.processVerifyKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(sendSpy).toHaveBeenCalledWith(device16, 0xaa, 0x99, device64); // NOT_SUPPORTED
            sendSpy.mockRestore();
        });

        it("should ignore verify key from broadcast address", async () => {
            const data = Buffer.alloc(26);
            data.writeUInt8(0x04, 0); // CMD_KEY_TC_LINK

            const macHeader = { frameControl: {}, source16: 0xffff } as MACHeader; // Broadcast
            const nwkHeader = { frameControl: {}, source16: 0xffff } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            const sendSpy = vi.spyOn(apsHandler, "sendConfirmKey");

            await apsHandler.processVerifyKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(sendSpy).not.toHaveBeenCalled();
            sendSpy.mockRestore();
        });
    });

    describe("Update Device Processing", () => {
        it("should process update device command", async () => {
            const device16 = 0x1234;
            const device64 = 0x00124b0012345678n;

            const data = Buffer.alloc(12);
            let offset = 0;

            data.writeBigUInt64LE(device64, offset);
            offset += 8;
            data.writeUInt16LE(device16, offset);
            offset += 2;
            data.writeUInt8(0x00, offset); // status = SECURED_REJOIN

            const macHeader = { frameControl: {}, source16: device16 } as MACHeader;
            const nwkHeader = { frameControl: {}, source16: device16 } as ZigbeeNWKHeader;
            const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

            const result = await apsHandler.processUpdateDevice(data, 0, macHeader, nwkHeader, apsHeader);

            expect(result).toBe(11);
        });
    });

    it("skips duplicate detection when APS counter is absent", () => {
        const nwkHeader = { source16: 0x4f01 } as ZigbeeNWKHeader;
        const header = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
        } as ZigbeeAPSHeader;

        expect(apsHandler.isDuplicateFrame(nwkHeader, header)).toStrictEqual(false);
    });

    it("tracks duplicate APS fragments", () => {
        const now = Date.now();
        const nwkHeader = { source16: 0x1111 } as ZigbeeNWKHeader;
        const baseFrameControl = {
            frameType: ZigbeeAPSFrameType.DATA,
            deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
            ackFormat: false,
            security: false,
            ackRequest: false,
            extendedHeader: true,
        };
        const firstHeader = {
            frameControl: { ...baseFrameControl },
            counter: 7,
            fragmentation: ZigbeeAPSFragmentation.FIRST,
            fragBlockNumber: 0,
        } as ZigbeeAPSHeader;

        expect(apsHandler.isDuplicateFrame(nwkHeader, firstHeader, now)).toStrictEqual(false);
        expect(apsHandler.isDuplicateFrame(nwkHeader, { ...firstHeader }, now + 1)).toStrictEqual(true);

        const nextHeader = {
            frameControl: { ...baseFrameControl },
            counter: 7,
            fragmentation: ZigbeeAPSFragmentation.MIDDLE,
            fragBlockNumber: 1,
        } as ZigbeeAPSHeader;

        expect(apsHandler.isDuplicateFrame(nwkHeader, nextHeader, now + 2)).toStrictEqual(false);
    });

    it("uses IEEE source table when short address is unknown", () => {
        const start = Date.now();
        const source64 = 0x00124b0000004001n;
        const nwkHeader = { source64 } as ZigbeeNWKHeader;
        const header = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            counter: 0x22,
        } as ZigbeeAPSHeader;

        expect(apsHandler.isDuplicateFrame(nwkHeader, header, start)).toStrictEqual(false);
        expect(apsHandler.isDuplicateFrame(nwkHeader, { ...header }, start + 1000)).toStrictEqual(true);
        expect(apsHandler.isDuplicateFrame(nwkHeader, { ...header }, start + 9000)).toStrictEqual(false);
    });

    it("drops fragment blocks when the first fragment is missing", async () => {
        (mockCallbacks.onFrame as Mock).mockClear();

        const macHeader = { frameControl: {}, source16: 0x6201, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const nwkHeader = {
            frameControl: {},
            source16: 0x6201,
            source64: 0x00124b0000006201n,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
        } as ZigbeeNWKHeader;
        const apsHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: true,
            },
            destEndpoint: 0x05,
            sourceEndpoint: 0x06,
            profileId: 0x0104,
            clusterId: 0x0006,
            counter: 0x31,
            fragmentation: ZigbeeAPSFragmentation.MIDDLE,
            fragBlockNumber: 1,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.from([0x10, 0x11]), macHeader, nwkHeader, apsHeader, 190);

        expect((mockCallbacks.onFrame as Mock).mock.calls).toHaveLength(0);
    });

    it("waits for missing fragments before delivering payload", async () => {
        (mockCallbacks.onFrame as Mock).mockClear();

        const macHeader = { frameControl: {}, source16: 0x6202, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const nwkHeader = {
            frameControl: {},
            source16: 0x6202,
            source64: 0x00124b0000006202n,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
        } as ZigbeeNWKHeader;
        const frameControl = {
            frameType: ZigbeeAPSFrameType.DATA,
            deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
            ackFormat: false,
            security: false,
            ackRequest: false,
            extendedHeader: true,
        };
        const firstHeader = {
            frameControl,
            destEndpoint: 0x05,
            sourceEndpoint: 0x06,
            profileId: 0x0104,
            clusterId: 0x0006,
            counter: 0x32,
            fragmentation: ZigbeeAPSFragmentation.FIRST,
            fragBlockNumber: 0,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.from([0x01, 0x02, 0x03]), macHeader, nwkHeader, firstHeader, 185);

        const lastHeader = {
            frameControl,
            destEndpoint: 0x05,
            sourceEndpoint: 0x06,
            profileId: 0x0104,
            clusterId: 0x0006,
            counter: 0x32,
            fragmentation: ZigbeeAPSFragmentation.LAST,
            fragBlockNumber: 2,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.from([0x07]), macHeader, nwkHeader, lastHeader, 184);
        await new Promise((resolve) => setImmediate(resolve));

        expect((mockCallbacks.onFrame as Mock).mock.calls).toHaveLength(0);
    });

    it("prunes stale fragment reassembly state after timeout", async () => {
        (mockCallbacks.onFrame as Mock).mockClear();

        let now = 1000;
        const dateSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

        const macHeader = { frameControl: {}, source16: 0x6203, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const nwkHeader = {
            frameControl: {},
            source16: 0x6203,
            source64: 0x00124b0000006203n,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
        } as ZigbeeNWKHeader;
        const baseHeaders = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: true,
            },
            destEndpoint: 0x05,
            sourceEndpoint: 0x06,
            profileId: 0x0104,
            clusterId: 0x0006,
            counter: 0x33,
        } as ZigbeeAPSHeader;

        const firstHeader = { ...baseHeaders, fragmentation: ZigbeeAPSFragmentation.FIRST, fragBlockNumber: 0 } as ZigbeeAPSHeader;
        await apsHandler.processFrame(Buffer.from([0x20, 0x21]), macHeader, nwkHeader, firstHeader, 183);

        now = 40000;
        const lastHeader = { ...baseHeaders, fragmentation: ZigbeeAPSFragmentation.LAST, fragBlockNumber: 1 } as ZigbeeAPSHeader;
        await apsHandler.processFrame(Buffer.from([0x30, 0x31]), macHeader, nwkHeader, lastHeader, 182);
        await new Promise((resolve) => setImmediate(resolve));

        expect((mockCallbacks.onFrame as Mock).mock.calls).toHaveLength(0);

        dateSpy.mockRestore();
    });

    it("resolves IEEE destination when sending data", async () => {
        const destination64 = 0x00124b0099999999n;
        mockContext.deviceTable.set(destination64, {
            address16: 0x7788,
            capabilities: undefined,
            authorized: false,
            neighbor: false,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        });
        mockContext.address16ToAddress64.set(0x7788, destination64);

        const result = await apsHandler.sendData(
            Buffer.from([0xaa, 0xbb]),
            ZigbeeNWKRouteDiscovery.SUPPRESS,
            undefined,
            destination64,
            ZigbeeAPSDeliveryMode.UNICAST,
            0x1234,
            0x5678,
            0x0a,
            0x0b,
            undefined,
        );

        expect(result).toBeGreaterThanOrEqual(0);
        expect(mockMACHandler.sendFrame).toHaveBeenCalled();
    });

    it("throws when APS destination cannot be resolved", async () => {
        const routeSpy = vi.spyOn(mockNWKHandler, "findBestSourceRoute");
        routeSpy.mockReturnValueOnce([undefined, undefined, undefined]);

        await expect(
            apsHandler.sendData(
                Buffer.from([0x01]),
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                undefined,
                0x00124b00aaaaaaaan,
                ZigbeeAPSDeliveryMode.UNICAST,
                0x0006,
                0x0104,
                0x01,
                0x01,
                undefined,
            ),
        ).rejects.toThrow("Invalid parameters");

        routeSpy.mockRestore();
    });

    it("rejects fragmented broadcast transmissions", async () => {
        const largePayload = Buffer.alloc(ZigbeeAPSConsts.PAYLOAD_MAX_SIZE + 8, 0xcd);

        await expect(
            apsHandler.sendData(
                largePayload,
                ZigbeeNWKRouteDiscovery.SUPPRESS,
                ZigbeeConsts.BCAST_DEFAULT,
                undefined,
                ZigbeeAPSDeliveryMode.BCAST,
                0x0006,
                0x0104,
                undefined,
                0x01,
                undefined,
            ),
        ).rejects.toThrow("APS fragmentation requires unicast destination acknowledgments");
    });

    it("skips ACK transmission when destination is unknown", async () => {
        const routeSpy = vi.spyOn(mockNWKHandler, "findBestSourceRoute");
        routeSpy.mockReturnValueOnce([undefined, undefined, undefined]);

        const macHeader = { frameControl: {}, source16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const nwkHeader = {
            frameControl: {},
            source16: undefined,
            source64: 0x00124b0011112222n,
            seqNum: 1,
        } as ZigbeeNWKHeader;
        const apsHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            sourceEndpoint: 0x11,
            destEndpoint: 0x22,
            clusterId: 0x1234,
            profileId: 0x5678,
            counter: 0x33,
        } as ZigbeeAPSHeader;

        await apsHandler.sendACK(macHeader, nwkHeader, apsHeader);

        expect(mockMACHandler.sendFrame).not.toHaveBeenCalled();

        routeSpy.mockRestore();
    });

    it("sends ACK with fragment metadata when required", async () => {
        const macHeader = { frameControl: {}, source16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const nwkHeader = {
            frameControl: {},
            source16: 0x3344,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            seqNum: 5,
            radius: 3,
        } as ZigbeeNWKHeader;
        const responder64 = 0x00124b0044332211n;
        mockContext.address16ToAddress64.set(0x3344, responder64);
        mockContext.deviceTable.set(responder64, {
            address16: 0x3344,
            capabilities: undefined,
            authorized: true,
            neighbor: true,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        });
        const apsHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: true,
            },
            sourceEndpoint: 0x11,
            destEndpoint: 0x22,
            clusterId: 0x0104,
            profileId: 0x0104,
            counter: 0x21,
            fragmentation: ZigbeeAPSFragmentation.FIRST,
            fragBlockNumber: 0x02,
        } as ZigbeeAPSHeader;

        await apsHandler.sendACK(macHeader, nwkHeader, apsHeader);

        expect(mockMACHandler.sendFrame).toHaveBeenCalled();
    });

    it("reuses cached application link key for request key handling", async () => {
        mockContext.trustCenterPolicies.allowAppKeyRequest = ApplicationKeyRequestPolicy.ALLOWED;

        const requester16 = 0x2010;
        const requester64 = 0x00124b0000002010n;
        const partner16 = 0x3010;
        const partner64 = 0x00124b0000003010n;
        const cachedKey = Buffer.alloc(16, 0x66);

        mockContext.address16ToAddress64.set(requester16, requester64);
        mockContext.address16ToAddress64.set(partner16, partner64);
        mockContext.deviceTable.set(partner64, {
            address16: partner16,
            capabilities: undefined,
            authorized: true,
            neighbor: false,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        });
        mockContext.setAppLinkKey(requester64, partner64, cachedKey);

        const data = Buffer.alloc(9);
        data.writeUInt8(ZigbeeAPSConsts.CMD_KEY_APP_MASTER, 0);
        data.writeBigUInt64LE(partner64, 1);

        const macHeader = { frameControl: {}, source16: requester16, source64: requester64 } as MACHeader;
        const nwkHeader = { frameControl: {}, source16: requester16, source64: requester64 } as ZigbeeNWKHeader;
        const apsHeader = { frameControl: { security: true } } as ZigbeeAPSHeader;

        const setSpy = vi.spyOn(mockContext, "setAppLinkKey");
        const sendSpy = vi.spyOn(apsHandler, "sendTransportKeyAPP").mockResolvedValue(true);

        await apsHandler.processRequestKey(data, 0, macHeader, nwkHeader, apsHeader);

        expect(setSpy).not.toHaveBeenCalled();
        expect(sendSpy).toHaveBeenCalledWith(requester16, cachedKey, partner64, true);

        setSpy.mockRestore();
        sendSpy.mockRestore();
    });

    it("creates fragment tracking for existing duplicate entries", () => {
        const now = Date.now();
        const nwkHeader = { source16: 0x4001 } as ZigbeeNWKHeader;
        const baseHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            counter: 0x22,
        } as ZigbeeAPSHeader;

        expect(apsHandler.isDuplicateFrame(nwkHeader, baseHeader, now)).toStrictEqual(false);

        const fragmentHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: true,
            },
            counter: 0x22,
            fragmentation: ZigbeeAPSFragmentation.FIRST,
            fragBlockNumber: 0,
        } as ZigbeeAPSHeader;

        expect(apsHandler.isDuplicateFrame(nwkHeader, fragmentHeader, now + 1)).toStrictEqual(false);
        expect(apsHandler.isDuplicateFrame(nwkHeader, { ...fragmentHeader }, now + 2)).toStrictEqual(true);
    });

    it("prunes expired duplicate entries", () => {
        const now = Date.now();
        const nwkHeader = { source16: 0x5001 } as ZigbeeNWKHeader;
        const header = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            counter: 0x33,
        } as ZigbeeAPSHeader;

        expect(apsHandler.isDuplicateFrame(nwkHeader, header, now)).toStrictEqual(false);

        const later = now + 9000;
        expect(apsHandler.isDuplicateFrame(nwkHeader, { ...header }, later)).toStrictEqual(false);
        expect(apsHandler.isDuplicateFrame(nwkHeader, { ...header }, later + 1)).toStrictEqual(true);
    });

    it("reassembles incoming fragments and clears state", async () => {
        const macHeader = { frameControl: {}, source16: 0x6001, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const nwkHeader = {
            frameControl: {},
            source16: 0x6001,
            source64: 0x00124b0000006001n,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            seqNum: 0x10,
        } as ZigbeeNWKHeader;
        const baseFrameControl = {
            frameType: ZigbeeAPSFrameType.DATA,
            deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
            ackFormat: false,
            security: false,
            ackRequest: false,
            extendedHeader: true,
        };

        const firstHeader = {
            frameControl: { ...baseFrameControl },
            destEndpoint: 0x05,
            sourceEndpoint: 0x06,
            profileId: 0x0104,
            clusterId: 0x0006,
            counter: 0x48,
            fragmentation: ZigbeeAPSFragmentation.FIRST,
            fragBlockNumber: 0,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.from([0x01, 0x02]), macHeader, nwkHeader, firstHeader, 200);
        expect(mockCallbacks.onFrame).not.toHaveBeenCalled();

        const middleHeader = {
            frameControl: { ...baseFrameControl },
            destEndpoint: 0x05,
            sourceEndpoint: 0x06,
            profileId: 0x0104,
            clusterId: 0x0006,
            counter: 0x48,
            fragmentation: ZigbeeAPSFragmentation.MIDDLE,
            fragBlockNumber: 1,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.from([0x03, 0x04]), macHeader, nwkHeader, middleHeader, 200);
        expect(mockCallbacks.onFrame).not.toHaveBeenCalled();

        const lastHeader = {
            frameControl: { ...baseFrameControl },
            destEndpoint: 0x05,
            sourceEndpoint: 0x06,
            profileId: 0x0104,
            clusterId: 0x0006,
            counter: 0x48,
            fragmentation: ZigbeeAPSFragmentation.LAST,
            fragBlockNumber: 2,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.from([0x05]), macHeader, nwkHeader, lastHeader, 200);
        await new Promise((resolve) => setImmediate(resolve));

        expect(mockCallbacks.onFrame).toHaveBeenCalledTimes(1);
        const onFrameMock = mockCallbacks.onFrame as Mock;
        const [, , deliveredHeader, deliveredPayload] = onFrameMock.mock.calls[0];
        expect(deliveredHeader.fragmentation).toBeUndefined();
        expect(deliveredHeader.frameControl.extendedHeader).toStrictEqual(false);
        expect(deliveredPayload).toStrictEqual(Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]));
    });

    it("clears ACK timers when acknowledgement is processed", async () => {
        const dest16 = 0x7001;
        const dest64 = 0x00124b0000007001n;

        mockContext.deviceTable.set(dest64, {
            address16: dest16,
            capabilities: undefined,
            authorized: true,
            neighbor: true,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        });
        mockContext.address16ToAddress64.set(dest16, dest64);

        const apsCounter = await apsHandler.sendData(
            Buffer.from([0xaa]),
            ZigbeeNWKRouteDiscovery.SUPPRESS,
            dest16,
            dest64,
            ZigbeeAPSDeliveryMode.UNICAST,
            0x0006,
            0x0104,
            0x02,
            0x01,
            undefined,
        );

        const clearSpy = vi.spyOn(global, "clearTimeout");

        const ackMacHeader = { frameControl: {}, source16: dest16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const ackNwkHeader = { frameControl: {}, source16: dest16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS, seqNum: 0x33 } as ZigbeeNWKHeader;
        const ackHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.ACK,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            counter: apsCounter,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.alloc(0), ackMacHeader, ackNwkHeader, ackHeader, 180);

        expect(clearSpy).toHaveBeenCalled();

        clearSpy.mockRestore();
    });

    it("resolves APS ACKs via IEEE mapping when short address is absent", async () => {
        const sendFrameMock = mockMACHandler.sendFrame as Mock;
        sendFrameMock.mockClear();
        vi.useFakeTimers();

        const dest16 = 0x7002;
        const dest64 = 0x00124b0000007002n;

        mockContext.deviceTable.set(dest64, {
            address16: dest16,
            capabilities: undefined,
            authorized: true,
            neighbor: true,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        });
        mockContext.address16ToAddress64.set(dest16, dest64);

        const apsCounter = await apsHandler.sendData(
            Buffer.from([0xaa]),
            ZigbeeNWKRouteDiscovery.SUPPRESS,
            dest16,
            dest64,
            ZigbeeAPSDeliveryMode.UNICAST,
            0x0006,
            0x0104,
            0x02,
            0x01,
            undefined,
        );

        expect(sendFrameMock).toHaveBeenCalledTimes(1);

        const ackMacHeader = { frameControl: {}, source16: dest16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const ackNwkHeader = {
            frameControl: {},
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            source64: dest64,
            seqNum: 0x44,
        } as ZigbeeNWKHeader;
        const ackHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.ACK,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            counter: apsCounter,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.alloc(0), ackMacHeader, ackNwkHeader, ackHeader, 175);

        await vi.advanceTimersByTimeAsync(CONFIG_APS_ACK_WAIT_DURATION_MS - 1);
        await vi.runOnlyPendingTimersAsync();

        expect(sendFrameMock).toHaveBeenCalledTimes(1);

        vi.clearAllTimers();
        vi.useRealTimers();
    });

    it("ignores APS ACKs when IEEE mapping is unavailable", async () => {
        const sendFrameMock = mockMACHandler.sendFrame as Mock;
        sendFrameMock.mockClear();
        vi.useFakeTimers();

        const dest16 = 0x7003;
        const dest64 = 0x00124b0000007003n;

        const savedEntry = {
            address16: dest16,
            capabilities: undefined,
            authorized: false,
            neighbor: true,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        };
        mockContext.deviceTable.set(dest64, savedEntry);
        mockContext.address16ToAddress64.set(dest16, dest64);

        const apsCounter = await apsHandler.sendData(
            Buffer.from([0xbb]),
            ZigbeeNWKRouteDiscovery.SUPPRESS,
            dest16,
            dest64,
            ZigbeeAPSDeliveryMode.UNICAST,
            0x0008,
            0x0104,
            0x03,
            0x01,
            undefined,
        );

        expect(sendFrameMock).toHaveBeenCalledTimes(1);

        mockContext.deviceTable.delete(dest64);
        mockContext.address16ToAddress64.delete(dest16);

        const ackMacHeader = { frameControl: {}, source16: dest16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const ackNwkHeader = {
            frameControl: {},
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            source64: dest64,
            seqNum: 0x45,
        } as ZigbeeNWKHeader;
        const ackHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.ACK,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            counter: apsCounter,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.alloc(0), ackMacHeader, ackNwkHeader, ackHeader, 170);

        mockContext.deviceTable.set(dest64, savedEntry);
        mockContext.address16ToAddress64.set(dest16, dest64);

        await vi.advanceTimersByTimeAsync(CONFIG_APS_ACK_WAIT_DURATION_MS - 1);
        await vi.runOnlyPendingTimersAsync();

        expect(sendFrameMock.mock.calls.length).toBeGreaterThan(1);

        vi.clearAllTimers();
        vi.useRealTimers();
    });

    it("ignores APS ACKs for unknown pending entries", async () => {
        const sendFrameMock = mockMACHandler.sendFrame as Mock;
        sendFrameMock.mockClear();
        const clearSpy = vi.spyOn(global, "clearTimeout");

        const ackMacHeader = { frameControl: {}, source16: 0x7fff, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const ackNwkHeader = {
            frameControl: {},
            source16: 0x7fff,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            seqNum: 0x50,
        } as ZigbeeNWKHeader;
        const ackHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.ACK,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            counter: 0x99,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.alloc(0), ackMacHeader, ackNwkHeader, ackHeader, 160);

        expect(sendFrameMock).not.toHaveBeenCalled();
        expect(clearSpy).not.toHaveBeenCalled();

        clearSpy.mockRestore();
    });

    it("replaces pending ACK timers when retransmitting identical counters", async () => {
        vi.useFakeTimers();

        const dest16 = 0x7004;
        const dest64 = 0x00124b0000007004n;

        mockContext.deviceTable.set(dest64, {
            address16: dest16,
            capabilities: undefined,
            authorized: true,
            neighbor: true,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        });
        mockContext.address16ToAddress64.set(dest16, dest64);

        const counterSpy = vi.spyOn(apsHandler, "nextCounter").mockReturnValue(0x55);
        const clearSpy = vi.spyOn(global, "clearTimeout");

        await apsHandler.sendData(
            Buffer.from([0xcc]),
            ZigbeeNWKRouteDiscovery.SUPPRESS,
            dest16,
            dest64,
            ZigbeeAPSDeliveryMode.UNICAST,
            0x0009,
            0x0104,
            0x04,
            0x01,
            undefined,
        );

        await apsHandler.sendData(
            Buffer.from([0xcd]),
            ZigbeeNWKRouteDiscovery.SUPPRESS,
            dest16,
            dest64,
            ZigbeeAPSDeliveryMode.UNICAST,
            0x0009,
            0x0104,
            0x04,
            0x01,
            undefined,
        );

        expect(clearSpy).toHaveBeenCalled();

        counterSpy.mockRestore();
        clearSpy.mockRestore();
        vi.clearAllTimers();
        vi.useRealTimers();
    });

    it("handles pending ACK timeout after entry removal", async () => {
        const dest16 = 0x7005;
        const dest64 = 0x00124b0000007005n;
        const scheduled: Array<() => Promise<void> | void> = [];

        const setTimeoutSpy = vi.spyOn(global, "setTimeout").mockImplementation(((
            handler: (...args: unknown[]) => unknown,
            timeout?: number,
            ...callbackArgs: unknown[]
        ) => {
            void timeout;
            const callback = handler.bind(undefined, ...callbackArgs);
            scheduled.push(callback as () => Promise<void> | void);

            return 1 as unknown as NodeJS.Timeout;
        }) as unknown as typeof setTimeout);
        const clearTimeoutSpy = vi.spyOn(global, "clearTimeout").mockImplementation(() => {});

        mockContext.deviceTable.set(dest64, {
            address16: dest16,
            capabilities: undefined,
            authorized: true,
            neighbor: true,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        });
        mockContext.address16ToAddress64.set(dest16, dest64);

        const apsCounter = await apsHandler.sendData(
            Buffer.from([0xde]),
            ZigbeeNWKRouteDiscovery.SUPPRESS,
            dest16,
            dest64,
            ZigbeeAPSDeliveryMode.UNICAST,
            0x000a,
            0x0104,
            0x05,
            0x01,
            undefined,
        );

        const ackMacHeader = { frameControl: {}, source16: dest16, destination16: ZigbeeConsts.COORDINATOR_ADDRESS } as MACHeader;
        const ackNwkHeader = {
            frameControl: {},
            source16: dest16,
            destination16: ZigbeeConsts.COORDINATOR_ADDRESS,
            seqNum: 0x46,
        } as ZigbeeNWKHeader;
        const ackHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.ACK,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            counter: apsCounter,
        } as ZigbeeAPSHeader;

        await apsHandler.processFrame(Buffer.alloc(0), ackMacHeader, ackNwkHeader, ackHeader, 165);

        expect(scheduled.length).toBeGreaterThan(0);

        const timeoutHandler = scheduled[0];
        if (timeoutHandler !== undefined) {
            const result = timeoutHandler();
            if (result instanceof Promise) {
                await result;
            }
        }

        setTimeoutSpy.mockRestore();
        clearTimeoutSpy.mockRestore();
    });

    it("updates source route mapping when child rejoins securely", async () => {
        const macHeader = { frameControl: {}, source16: 0x7101, source64: 0x00124b0000007101n } as MACHeader;
        const nwkHeader = { frameControl: {}, source16: 0x7101, source64: 0x00124b0000007101n } as ZigbeeNWKHeader;

        const payload = Buffer.alloc(11);
        let offset = 0;
        const child64 = 0x00124b0000008001n;
        const child16 = 0x8001;
        offset = payload.writeBigUInt64LE(child64, offset);
        offset = payload.writeUInt16LE(child16, offset);
        payload.writeUInt8(0x00, offset); // Standard Device Secured Rejoin

        const routeSpy = vi.spyOn(mockNWKHandler, "findBestSourceRoute").mockReturnValue([0, [0x9001, 0x9002], 1]);

        await apsHandler.processUpdateDevice(payload, 0, macHeader, nwkHeader, {} as ZigbeeAPSHeader);

        expect(mockContext.sourceRouteTable.get(child16)).toBeDefined();

        routeSpy.mockRestore();
    });

    it("skips source route updates when parent short address is unknown", async () => {
        const macHeader = { frameControl: {}, source64: 0x00124b0000007102n } as MACHeader;
        const nwkHeader = { frameControl: {}, source64: 0x00124b0000007102n } as ZigbeeNWKHeader;

        const payload = Buffer.alloc(11);
        let offset = 0;
        const child64 = 0x00124b0000008101n;
        const child16 = 0x8101;
        offset = payload.writeBigUInt64LE(child64, offset);
        offset = payload.writeUInt16LE(child16, offset);
        payload.writeUInt8(0x00, offset);

        const routeSpy = vi.spyOn(mockNWKHandler, "findBestSourceRoute");

        await apsHandler.processUpdateDevice(payload, 0, macHeader, nwkHeader, {} as ZigbeeAPSHeader);

        expect(routeSpy).not.toHaveBeenCalled();
        expect(mockContext.sourceRouteTable.has(child16)).toStrictEqual(false);

        routeSpy.mockRestore();
    });

    it("logs clipping when LQI response exceeds single frame", () => {
        const debugSpy = vi.spyOn(logger, "debug");

        for (let index = 0; index < 260; index += 1) {
            const address64 = 0x00124b0000100000n + BigInt(index);
            mockContext.deviceTable.set(address64, {
                address16: 0x1000 + index,
                capabilities: undefined,
                authorized: true,
                neighbor: true,
                lastTransportedNetworkKeySeq: undefined,
                recentLQAs: [],
                incomingNWKFrameCounter: undefined,
                endDeviceTimeout: undefined,
                linkStatusMisses: 0,
            });
        }

        expect(() => apsHandler.getLQITableResponse(0)).toThrow(RangeError);
        const clipCall = debugSpy.mock.calls.find(([messageFactory]) => {
            return typeof messageFactory === "function" && messageFactory().includes("LQI table clipped");
        });
        expect(clipCall).toBeDefined();

        debugSpy.mockRestore();
    });

    it("returns false when command destination cannot be resolved", async () => {
        const routeSpy = vi.spyOn(mockNWKHandler, "findBestSourceRoute");
        routeSpy.mockReturnValueOnce([undefined, undefined, undefined]);

        const result = await apsHandler.sendCommand(
            ZigbeeAPSCommandId.REMOVE_DEVICE,
            Buffer.from([ZigbeeAPSCommandId.REMOVE_DEVICE]),
            ZigbeeNWKRouteDiscovery.SUPPRESS,
            true,
            undefined,
            0x00124b00bbbbbbbbn,
            ZigbeeAPSDeliveryMode.UNICAST,
            undefined,
        );

        expect(result).toStrictEqual(false);

        routeSpy.mockRestore();
    });

    it("processes tunnel, confirm key and relay commands", async () => {
        const macHeader = { frameControl: {}, source16: 0x2001, source64: 0x00124b0022223333n } as MACHeader;
        const nwkHeader = { frameControl: {}, source16: 0x2001, source64: 0x00124b0022223333n } as ZigbeeNWKHeader;
        const apsHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.CMD,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
        } as ZigbeeAPSHeader;

        const tunnelPayload = Buffer.alloc(1 + 8 + 2);
        tunnelPayload.writeUInt8(ZigbeeAPSCommandId.TUNNEL, 0);
        tunnelPayload.writeBigUInt64LE(0x00124b00ccddee00n, 1);
        tunnelPayload.writeUInt16LE(0x1234, 9);
        await apsHandler.processCommand(tunnelPayload, macHeader, nwkHeader, apsHeader);

        const confirmPayload = Buffer.alloc(1 + 1 + 1 + 8);
        confirmPayload.writeUInt8(ZigbeeAPSCommandId.CONFIRM_KEY, 0);
        confirmPayload.writeUInt8(0x01, 1);
        confirmPayload.writeUInt8(0x03, 2);
        confirmPayload.writeBigUInt64LE(0x00124b00aabbccddn, 3);
        await apsHandler.processCommand(confirmPayload, macHeader, nwkHeader, apsHeader);

        const relayDown = Buffer.alloc(1 + 8);
        relayDown.writeUInt8(ZigbeeAPSCommandId.RELAY_MESSAGE_DOWNSTREAM, 0);
        relayDown.writeBigUInt64LE(0x00124b00ddeeff00n, 1);
        await apsHandler.processCommand(relayDown, macHeader, nwkHeader, apsHeader);

        const relayUp = Buffer.alloc(1 + 8);
        relayUp.writeUInt8(ZigbeeAPSCommandId.RELAY_MESSAGE_UPSTREAM, 0);
        relayUp.writeBigUInt64LE(0x00124b00eeff1100n, 1);
        await apsHandler.processCommand(relayUp, macHeader, nwkHeader, apsHeader);

        const warnSpy = vi.spyOn(logger, "warning");
        await apsHandler.processCommand(Buffer.from([0xff]), macHeader, nwkHeader, apsHeader);
        expect(warnSpy).toHaveBeenCalled();
        warnSpy.mockRestore();
    });

    it("parses transport key payload variants", () => {
        const macHeader = { frameControl: {}, source16: 0x3001, source64: 0x00124b0033334444n } as MACHeader;
        const nwkHeader = { frameControl: {}, source16: 0x3001, source64: 0x00124b0033334444n } as ZigbeeNWKHeader;
        const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

        const tcPayload = Buffer.alloc(1 + 16 + 8 + 8);
        tcPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_TC_LINK, 0);
        Buffer.alloc(16, 0xaa).copy(tcPayload, 1);
        tcPayload.writeBigUInt64LE(0x00124b00aaaa0001n, 17);
        tcPayload.writeBigUInt64LE(0x00124b00bbbb0002n, 25);
        const tcOffset = apsHandler.processTransportKey(tcPayload, 0, macHeader, nwkHeader, apsHeader);
        expect(tcOffset).toStrictEqual(tcPayload.length);

        const appPayload = Buffer.alloc(1 + 16 + 8 + 1);
        appPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_APP_MASTER, 0);
        Buffer.alloc(16, 0xbb).copy(appPayload, 1);
        appPayload.writeBigUInt64LE(0x00124b00cccc0003n, 17);
        appPayload.writeUInt8(0x01, 25);
        const appOffset = apsHandler.processTransportKey(appPayload, 0, macHeader, nwkHeader, apsHeader);
        expect(appOffset).toStrictEqual(appPayload.length);
    });

    it("handles remove device outcomes", async () => {
        const target64 = 0x00124b0044445555n;
        mockContext.deviceTable.set(target64, {
            address16: 0x5566,
            capabilities: undefined,
            authorized: true,
            neighbor: false,
            lastTransportedNetworkKeySeq: undefined,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        });

        const leaveSpy = vi.spyOn(mockNWKHandler, "sendLeave").mockResolvedValueOnce(false);
        const warnSpy = vi.spyOn(logger, "warning");

        const payload = Buffer.alloc(1 + 8);
        payload.writeUInt8(ZigbeeAPSCommandId.REMOVE_DEVICE, 0);
        payload.writeBigUInt64LE(target64, 1);

        await apsHandler.processRemoveDevice(
            payload,
            1,
            { frameControl: {}, source16: 0x5566 } as MACHeader,
            {
                frameControl: {},
                source16: 0x5566,
            } as ZigbeeNWKHeader,
            {} as ZigbeeAPSHeader,
        );

        expect(leaveSpy).toHaveBeenCalledWith(0x5566, false);
        expect(mockContext.disassociate).toHaveBeenCalledWith(0x5566, target64);

        // Unknown device branch
        const unknownPayload = Buffer.alloc(1 + 8);
        unknownPayload.writeUInt8(ZigbeeAPSCommandId.REMOVE_DEVICE, 0);
        unknownPayload.writeBigUInt64LE(0x00124b0055556666n, 1);

        await apsHandler.processRemoveDevice(
            unknownPayload,
            1,
            { frameControl: {}, source16: 0x1111 } as MACHeader,
            {
                frameControl: {},
                source16: 0x1111,
            } as ZigbeeNWKHeader,
            {} as ZigbeeAPSHeader,
        );

        expect(warnSpy).toHaveBeenCalled();

        leaveSpy.mockRestore();
        warnSpy.mockRestore();
    });
});
