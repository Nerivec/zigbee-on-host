import { rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MACAssociationStatus, MACCommandId, MACFrameAddressMode, MACFrameType, type MACHeader } from "../../src/zigbee/mac.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { type NetworkParameters, StackContext, type StackContextCallbacks } from "../../src/zigbee-stack/stack-context.js";
import { createMACFrameControl } from "../utils.js";

const NO_ACK_CODE = 99999;

describe("MACHandler", () => {
    let saveDir: string;
    let macHandler: MACHandler;
    let mockStackContextCallbacks: StackContextCallbacks;
    let mockContext: StackContext;
    let mockCallbacks: MACHandlerCallbacks;
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

        saveDir = `temp_MACHandler_${Math.floor(Math.random() * 1000000)}`;

        mockStackContextCallbacks = {
            onDeviceLeft: vi.fn(),
        };

        mockContext = new StackContext(mockStackContextCallbacks, join(saveDir, "zoh.save"), netParams);

        vi.spyOn(mockContext, "associate").mockResolvedValue([MACAssociationStatus.SUCCESS, 0x1234]);
        vi.spyOn(mockContext, "disassociate").mockResolvedValue(undefined);

        mockCallbacks = {
            onFrame: vi.fn(),
            onSendFrame: vi.fn().mockResolvedValue(undefined),
            onAPSSendTransportKeyNWK: vi.fn().mockResolvedValue(undefined),
            onMarkRouteSuccess: vi.fn(),
            onMarkRouteFailure: vi.fn(),
        };

        macHandler = new MACHandler(mockContext, mockCallbacks, NO_ACK_CODE);
    });

    afterEach(() => {
        rmSync(saveDir, { force: true, recursive: true });
    });

    describe("constructor", () => {
        it("should initialize with provided context and callbacks", () => {
            expect(macHandler).toBeDefined();
        });

        it("should initialize empty pending associations", () => {
            expect(mockContext.pendingAssociations.size).toStrictEqual(0);
        });

        it("should initialize empty MAC NO_ACK counts", () => {
            expect(mockContext.macNoACKs.size).toStrictEqual(0);
        });
    });

    describe("nextMACSeqNum", () => {
        it("should start at 1 and increment", () => {
            expect(macHandler.nextSeqNum()).toStrictEqual(1);
            expect(macHandler.nextSeqNum()).toStrictEqual(2);
            expect(macHandler.nextSeqNum()).toStrictEqual(3);
        });

        it("should wrap at 255", () => {
            for (let i = 0; i < 254; i++) {
                macHandler.nextSeqNum();
            }

            expect(macHandler.nextSeqNum()).toStrictEqual(255);
            expect(macHandler.nextSeqNum()).toStrictEqual(0);
            expect(macHandler.nextSeqNum()).toStrictEqual(1);
        });
    });

    describe("sendFrameDirect", () => {
        it("should send MAC frame successfully", async () => {
            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const result = await macHandler.sendFrameDirect(1, payload, 0x1234, undefined);

            expect(result).toStrictEqual(true);
            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();
        });

        it("should resolve dest16 from dest64 if not provided", async () => {
            const dest64 = 0x00124b0098765432n;
            const dest16 = 0x5678;

            mockContext.deviceTable.set(dest64, {
                address16: dest16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                recentLQAs: [],
            });
            mockContext.address16ToAddress64.set(dest16, dest64);

            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const result = await macHandler.sendFrameDirect(1, payload, undefined, dest64);

            expect(result).toStrictEqual(true);
            expect(mockCallbacks.onMarkRouteSuccess).toHaveBeenCalledWith(dest16);
        });

        it("should clear MAC NO_ACK on successful send", async () => {
            const dest16 = 0x1234;
            mockContext.macNoACKs.set(dest16, 3);

            const payload = Buffer.from([0x01, 0x02, 0x03]);
            await macHandler.sendFrameDirect(1, payload, dest16, undefined);

            expect(mockContext.macNoACKs.has(dest16)).toStrictEqual(false);
        });

        it("should mark route as successful on send", async () => {
            const payload = Buffer.from([0x01, 0x02, 0x03]);
            await macHandler.sendFrameDirect(1, payload, 0x1234, undefined);

            expect(mockCallbacks.onMarkRouteSuccess).toHaveBeenCalledWith(0x1234);
        });

        it("should handle NO_ACK error", async () => {
            const dest16 = 0x1234;
            const error = new Error("MAC NO_ACK", { cause: NO_ACK_CODE });
            (mockCallbacks.onSendFrame as ReturnType<typeof vi.fn>).mockRejectedValueOnce(error);

            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const result = await macHandler.sendFrameDirect(1, payload, dest16, undefined);

            expect(result).toStrictEqual(false);
            expect(mockContext.macNoACKs.get(dest16)).toStrictEqual(1);
            expect(mockCallbacks.onMarkRouteFailure).toHaveBeenCalledWith(dest16);
        });

        it("should increment NO_ACK count on subsequent failures", async () => {
            const dest16 = 0x1234;
            mockContext.macNoACKs.set(dest16, 2);

            const error = new Error("MAC NO_ACK", { cause: NO_ACK_CODE });
            (mockCallbacks.onSendFrame as ReturnType<typeof vi.fn>).mockRejectedValueOnce(error);

            const payload = Buffer.from([0x01, 0x02, 0x03]);
            await macHandler.sendFrameDirect(1, payload, dest16, undefined);

            expect(mockContext.macNoACKs.get(dest16)).toStrictEqual(3);
        });

        it("should emit MAC frame if enabled", async () => {
            const handlerWithEmit = new MACHandler(mockContext, { ...mockCallbacks }, NO_ACK_CODE, true);

            const payload = Buffer.from([0x01, 0x02, 0x03]);
            await handlerWithEmit.sendFrameDirect(1, payload, 0x1234, undefined);

            // Wait for setImmediate
            await new Promise((resolve) => setImmediate(resolve));

            expect(mockCallbacks.onFrame).toHaveBeenCalledWith(payload);
        });
    });

    describe("sendFrame", () => {
        it("should send frame directly when no indirect transmission needed", async () => {
            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const result = await macHandler.sendFrame(1, payload, 0x1234, undefined);

            expect(result).toStrictEqual(true);
            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();
        });

        it("should queue for indirect transmission when device has rxOnWhenIdle=false", async () => {
            const dest64 = 0x00124b0098765432n;
            const dest16 = 0x5678;

            // Setup indirect transmission queue
            mockContext.indirectTransmissions.set(dest64, []);

            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const result = await macHandler.sendFrame(1, payload, dest16, dest64);

            expect(result).toBeUndefined();
            expect(mockContext.indirectTransmissions.get(dest64)?.length).toStrictEqual(1);
            expect(mockCallbacks.onSendFrame).not.toHaveBeenCalled();
        });

        it("should resolve dest64 from dest16 when checking for indirect transmission", async () => {
            const dest64 = 0x00124b0098765432n;
            const dest16 = 0x5678;

            mockContext.address16ToAddress64.set(dest16, dest64);
            mockContext.indirectTransmissions.set(dest64, []);

            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const result = await macHandler.sendFrame(1, payload, dest16, undefined);

            expect(result).toBeUndefined();
            expect(mockContext.indirectTransmissions.get(dest64)?.length).toStrictEqual(1);
        });

        it("should send broadcast frames directly", async () => {
            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const result = await macHandler.sendFrame(1, payload, undefined, undefined);

            expect(result).toStrictEqual(true);
            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();
        });
    });

    describe("sendCommand", () => {
        it("should send MAC command with correct parameters", async () => {
            const cmdPayload = Buffer.from([0xaa, 0xbb]);
            const result = await macHandler.sendCommand(MACCommandId.ASSOC_RSP, 0x1234, undefined, false, cmdPayload);

            expect(result).toStrictEqual(true);
            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();
        });

        it("should use extended source when requested", async () => {
            const cmdPayload = Buffer.from([0xaa, 0xbb]);
            await macHandler.sendCommand(MACCommandId.ASSOC_RSP, undefined, 0x00124b0098765432n, true, cmdPayload);

            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();
        });
    });

    describe("processCommand", () => {
        it("should dispatch ASSOC_REQ to handler", async () => {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source16: 0xffff,
                source64: 0x00124b0098765432n,
                commandId: MACCommandId.ASSOC_REQ,
                fcs: 0,
            };

            const data = Buffer.from([0x8e]); // capabilities
            await macHandler.processCommand(data, macHeader);

            expect(mockContext.associate).toHaveBeenCalledOnce();
        });

        it("should dispatch BEACON_REQ to handler", async () => {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0xffff,
                destination16: 0xffff,
                commandId: MACCommandId.BEACON_REQ,
                fcs: 0,
            };

            await macHandler.processCommand(Buffer.alloc(0), macHeader);

            expect(mockCallbacks.onSendFrame).toHaveBeenCalled();
        });

        it("should dispatch DATA_RQ to handler", async () => {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source16: 0x1234,
                source64: 0x00124b0098765432n,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            };

            await macHandler.processCommand(Buffer.alloc(0), macHeader);
            // Should complete without error
        });

        it("should log error for unsupported command", async () => {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                commandId: 99 as MACCommandId, // Unsupported
                fcs: 0,
            };

            await macHandler.processCommand(Buffer.alloc(0), macHeader);
            // Should log error but not throw
        });
    });

    describe("processAssocReq", () => {
        it("should process association request from new device", async () => {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source64: 0x00124b0098765432n,
                commandId: MACCommandId.ASSOC_REQ,
                fcs: 0,
            };

            const data = Buffer.from([0x8e]); // capabilities: rxOnWhenIdle=true, deviceType=FFD, powerSource=mains, securityCapability=true, allocateAddress=true
            await macHandler.processAssocReq(data, 0, macHeader);

            expect(mockContext.associate).toHaveBeenCalledWith(undefined, 0x00124b0098765432n, true, expect.any(Object), true);
            expect(mockContext.pendingAssociations.has(0x00124b0098765432n)).toStrictEqual(true);
        });

        it("should process association request from known device (rejoin)", async () => {
            const dest64 = 0x00124b0098765432n;
            const dest16 = 0x5678;

            mockContext.deviceTable.set(dest64, {
                address16: dest16,
                capabilities: undefined,
                authorized: false,
                neighbor: false,
                recentLQAs: [],
            });

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source64: dest64,
                commandId: MACCommandId.ASSOC_REQ,
                fcs: 0,
            };

            const data = Buffer.from([0x8e]);
            await macHandler.processAssocReq(data, 0, macHeader);

            expect(mockContext.associate).toHaveBeenCalledWith(dest16, dest64, false, expect.any(Object), true);
        });

        it("should handle association request without source64", async () => {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source16: 0xffff,
                commandId: MACCommandId.ASSOC_REQ,
                fcs: 0,
            };

            const data = Buffer.from([0x8e]);
            await macHandler.processAssocReq(data, 0, macHeader);

            expect(mockContext.associate).not.toHaveBeenCalled();
        });
    });

    describe("sendAssocRsp", () => {
        it("should send association response", async () => {
            const result = await macHandler.sendAssocRsp(0x00124b0098765432n, 0x1234, MACAssociationStatus.SUCCESS);

            expect(result).toStrictEqual(true);
            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();
        });

        it("should send association response with failure status", async () => {
            const result = await macHandler.sendAssocRsp(0x00124b0098765432n, 0xffff, MACAssociationStatus.PAN_FULL);

            expect(result).toStrictEqual(true);
        });
    });

    describe("processBeaconReq", () => {
        it("should send beacon response", async () => {
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0xffff,
                destination16: 0xffff,
                commandId: MACCommandId.BEACON_REQ,
                fcs: 0,
            };

            await macHandler.processBeaconReq(Buffer.alloc(0), 0, macHeader);

            expect(mockCallbacks.onSendFrame).toHaveBeenCalled();
        });

        it("should include association permit in beacon", async () => {
            mockContext.associationPermit = true;

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0xffff,
                destination16: 0xffff,
                commandId: MACCommandId.BEACON_REQ,
                fcs: 0,
            };

            await macHandler.processBeaconReq(Buffer.alloc(0), 0, macHeader);

            expect(mockCallbacks.onSendFrame).toHaveBeenCalled();
        });
    });

    describe("processDataReq", () => {
        it("should send pending association response", async () => {
            const dest64 = 0x00124b0098765432n;
            const sendResp = vi.fn().mockResolvedValue(undefined);

            mockContext.pendingAssociations.set(dest64, {
                sendResp,
                timestamp: Date.now(),
            });

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source64: dest64,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            };

            await macHandler.processDataReq(Buffer.alloc(0), 0, macHeader);

            expect(sendResp).toHaveBeenCalledOnce();
            expect(mockContext.pendingAssociations.has(dest64)).toStrictEqual(false);
        });

        it("should delete expired pending association without sending", async () => {
            const dest64 = 0x00124b0098765432n;
            const sendResp = vi.fn().mockResolvedValue(undefined);

            mockContext.pendingAssociations.set(dest64, {
                sendResp,
                timestamp: Date.now() - 10000, // Expired
            });

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source64: dest64,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            };

            await macHandler.processDataReq(Buffer.alloc(0), 0, macHeader);

            expect(sendResp).not.toHaveBeenCalled();
            expect(mockContext.pendingAssociations.has(dest64)).toStrictEqual(false);
        });

        it("should send indirect transmission frame", async () => {
            const dest64 = 0x00124b0098765432n;
            const sendFrame = vi.fn().mockResolvedValue(true);

            mockContext.indirectTransmissions.set(dest64, [
                {
                    sendFrame,
                    timestamp: Date.now(),
                },
            ]);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source64: dest64,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            };

            await macHandler.processDataReq(Buffer.alloc(0), 0, macHeader);

            expect(sendFrame).toHaveBeenCalledOnce();
            expect(mockContext.indirectTransmissions.get(dest64)?.length).toStrictEqual(0);
        });

        it("should skip expired indirect transmissions", async () => {
            const dest64 = 0x00124b0098765432n;
            const expiredSendFrame = vi.fn().mockResolvedValue(true);
            const validSendFrame = vi.fn().mockResolvedValue(true);

            mockContext.indirectTransmissions.set(dest64, [
                {
                    sendFrame: expiredSendFrame,
                    timestamp: Date.now() - 10000, // Expired
                },
                {
                    sendFrame: validSendFrame,
                    timestamp: Date.now(),
                },
            ]);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source64: dest64,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            };

            await macHandler.processDataReq(Buffer.alloc(0), 0, macHeader);

            expect(expiredSendFrame).not.toHaveBeenCalled();
            expect(validSendFrame).toHaveBeenCalledOnce();
        });

        it("should resolve source64 from source16 when needed", async () => {
            const dest64 = 0x00124b0098765432n;
            const dest16 = 0x5678;

            mockContext.address16ToAddress64.set(dest16, dest64);

            const sendFrame = vi.fn().mockResolvedValue(true);

            mockContext.indirectTransmissions.set(dest64, [
                {
                    sendFrame,
                    timestamp: Date.now(),
                },
            ]);

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0x1a62,
                destination16: 0x0000,
                source16: dest16,
                commandId: MACCommandId.DATA_RQ,
                fcs: 0,
            };

            await macHandler.processDataReq(Buffer.alloc(0), 0, macHeader);

            expect(sendFrame).toHaveBeenCalledOnce();
        });
    });
});
