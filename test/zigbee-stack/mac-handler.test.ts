import { rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
    decodeMACFrameControl,
    decodeMACHeader,
    decodeMACPayload,
    decodeMACZigbeeBeacon,
    encodeMACFrame,
    MACAssociationStatus,
    MACCommandId,
    MACFrameAddressMode,
    type MACFrameControl,
    MACFrameType,
    MACFrameVersion,
    type MACHeader,
    ZigbeeMACConsts,
} from "../../src/zigbee/mac.js";
import { ZigbeeConsts } from "../../src/zigbee/zigbee.js";
import { ZigbeeNWKConsts } from "../../src/zigbee/zigbee-nwk.js";
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

        vi.spyOn(mockContext, "associate").mockImplementation(
            (_source16, _source64, _initialJoin, _capabilities, _neighbor, denyOverride, allowOverride) => {
                if (denyOverride) {
                    return Promise.resolve([MACAssociationStatus.PAN_ACCESS_DENIED, 0xffff]);
                }

                if (allowOverride) {
                    return Promise.resolve([MACAssociationStatus.SUCCESS, 0x1234]);
                }

                return Promise.resolve([MACAssociationStatus.SUCCESS, 0x1234]);
            },
        );
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

    const getOnSendFrameMock = () => mockCallbacks.onSendFrame as ReturnType<typeof vi.fn>;

    afterEach(() => {
        rmSync(saveDir, { force: true, recursive: true });
        mockContext?.disallowJoins();
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
            getOnSendFrameMock().mockRejectedValueOnce(error);

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
            getOnSendFrameMock().mockRejectedValueOnce(error);

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

        it("encodes broadcast command without ACK and with PAN compression", async () => {
            getOnSendFrameMock().mockClear();

            const cmdPayload = Buffer.from([0x11, 0x22]);
            await macHandler.sendCommand(MACCommandId.DATA_RQ, ZigbeeMACConsts.BCAST_ADDR, undefined, false, cmdPayload);

            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();
            const macFrame = getOnSendFrameMock().mock.calls[0][0] as Buffer;
            const [frameControl, offsetAfterFCF] = decodeMACFrameControl(macFrame, 0);

            expect(frameControl.ackRequest).toStrictEqual(false);
            expect(frameControl.panIdCompression).toStrictEqual(true);
            expect(frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.SHORT);

            const [decodedHeader, payloadOffset] = decodeMACHeader(macFrame, offsetAfterFCF, frameControl);

            expect(decodedHeader.destination16).toStrictEqual(ZigbeeMACConsts.BCAST_ADDR);
            expect(decodedHeader.destinationPANId).toStrictEqual(mockContext.netParams.panId);
            expect(decodedHeader.sourcePANId).toStrictEqual(mockContext.netParams.panId);
            const payload = decodeMACPayload(macFrame, payloadOffset, frameControl, decodedHeader);

            expect(payload.subarray(0, cmdPayload.length)).toStrictEqual(cmdPayload);
        });

        it("encodes extended command with ACK and extended source", async () => {
            getOnSendFrameMock().mockClear();

            const dest64 = 0x00124b0098765432n;
            const cmdPayload = Buffer.from([0x33, 0x44, 0x55]);

            await macHandler.sendCommand(MACCommandId.DISASSOC_NOTIFY, undefined, dest64, true, cmdPayload);

            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();
            const macFrame = getOnSendFrameMock().mock.calls[0][0] as Buffer;
            const [frameControl, offsetAfterFCF] = decodeMACFrameControl(macFrame, 0);

            expect(frameControl.ackRequest).toStrictEqual(true);
            expect(frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.EXT);
            expect(frameControl.sourceAddrMode).toStrictEqual(MACFrameAddressMode.EXT);

            const [decodedHeader, payloadOffset] = decodeMACHeader(macFrame, offsetAfterFCF, frameControl);

            expect(decodedHeader.destination64).toStrictEqual(dest64);
            expect(decodedHeader.source64).toStrictEqual(mockContext.netParams.eui64);
            const payload = decodeMACPayload(macFrame, payloadOffset, frameControl, decodedHeader);

            expect(payload.subarray(0, cmdPayload.length)).toStrictEqual(cmdPayload);
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
            mockContext.allowJoins(0xfe, true);

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

            expect(mockContext.associate).toHaveBeenCalledWith(undefined, 0x00124b0098765432n, true, expect.any(Object), true, false);
            expect(mockContext.pendingAssociations.has(0x00124b0098765432n)).toStrictEqual(true);
        });

        it("should process association request from known device (rejoin)", async () => {
            mockContext.allowJoins(0xfe, true);

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

            expect(mockContext.associate).toHaveBeenCalledWith(dest16, dest64, false, expect.any(Object), true, false);
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
            getOnSendFrameMock().mockClear();
            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0xffff,
                destination16: 0xffff,
                commandId: MACCommandId.BEACON_REQ,
                fcs: 0,
            };

            await macHandler.processBeaconReq(Buffer.alloc(0), 0, macHeader);

            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();

            const macFrame = getOnSendFrameMock().mock.calls[0][0] as Buffer;
            const [frameControl, offsetAfterFCF] = decodeMACFrameControl(macFrame, 0);

            expect(frameControl.frameType).toStrictEqual(MACFrameType.BEACON);
            expect(frameControl.destAddrMode).toStrictEqual(MACFrameAddressMode.NONE);
            expect(frameControl.sourceAddrMode).toStrictEqual(MACFrameAddressMode.SHORT);

            const [decodedHeader, payloadOffset] = decodeMACHeader(macFrame, offsetAfterFCF, frameControl);

            expect(decodedHeader.superframeSpec?.associationPermit).toStrictEqual(false);
            expect(decodedHeader.superframeSpec?.panCoordinator).toStrictEqual(true);
            expect(decodedHeader.gtsInfo?.permit).toStrictEqual(false);
            expect(decodedHeader.pendAddr?.addr16List).toBeUndefined();
            const payload = decodeMACPayload(macFrame, payloadOffset, frameControl, decodedHeader);
            const beacon = decodeMACZigbeeBeacon(payload, 0);

            expect(beacon.profile).toStrictEqual(0x2);
            expect(beacon.extendedPANId).toStrictEqual(mockContext.netParams.extendedPanId);
        });

        it("should include association permit in beacon", async () => {
            mockContext.associationPermit = true;
            getOnSendFrameMock().mockClear();

            const macHeader: MACHeader = {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 1,
                destinationPANId: 0xffff,
                destination16: 0xffff,
                commandId: MACCommandId.BEACON_REQ,
                fcs: 0,
            };

            await macHandler.processBeaconReq(Buffer.alloc(0), 0, macHeader);

            expect(mockCallbacks.onSendFrame).toHaveBeenCalledOnce();

            const macFrame = getOnSendFrameMock().mock.calls[0][0] as Buffer;
            const [frameControl, offsetAfterFCF] = decodeMACFrameControl(macFrame, 0);
            const [decodedHeader, payloadOffset] = decodeMACHeader(macFrame, offsetAfterFCF, frameControl);

            expect(decodedHeader.superframeSpec?.associationPermit).toStrictEqual(true);
            const payload = decodeMACPayload(macFrame, payloadOffset, frameControl, decodedHeader);
            const beacon = decodeMACZigbeeBeacon(payload, 0);

            expect(beacon.routerCapacity).toStrictEqual(true);
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

    describe("MAC frame encode/decode coverage", () => {
        it("encodes command frames with short addressing using PAN compression", async () => {
            getOnSendFrameMock().mockClear();
            const payload = Buffer.from([0xaa, 0xbb]);

            await macHandler.sendCommand(MACCommandId.DATA_RQ, 0x3456, undefined, false, payload);

            const macFrame = getOnSendFrameMock().mock.calls.at(-1)?.[0] as Buffer;
            expect(macFrame).toBeInstanceOf(Buffer);

            const [fcf, headerOffset] = decodeMACFrameControl(macFrame, 0);
            const [decodedHeader, payloadOffset] = decodeMACHeader(macFrame, headerOffset, fcf);

            expect(decodedHeader.destinationPANId).toStrictEqual(netParams.panId);
            expect(decodedHeader.sourcePANId).toStrictEqual(netParams.panId);
            expect(decodedHeader.destination16).toStrictEqual(0x3456);
            expect(decodedHeader.source16).toStrictEqual(ZigbeeConsts.COORDINATOR_ADDRESS);

            const decodedPayload = decodeMACPayload(macFrame, payloadOffset, fcf, decodedHeader);
            expect(decodedPayload.subarray(0, payload.length)).toStrictEqual(payload);
        });

        it("encodes association responses with extended addressing", async () => {
            getOnSendFrameMock().mockClear();
            const dest64 = 0x00124b0099998888n;

            await macHandler.sendAssocRsp(dest64, 0x2468, MACAssociationStatus.SUCCESS);

            const macFrame = getOnSendFrameMock().mock.calls.at(-1)?.[0] as Buffer;
            expect(macFrame).toBeInstanceOf(Buffer);

            const [fcf, headerOffset] = decodeMACFrameControl(macFrame, 0);
            const [decodedHeader] = decodeMACHeader(macFrame, headerOffset, fcf);

            expect(decodedHeader.destination64).toStrictEqual(dest64);
            expect(decodedHeader.destinationPANId).toStrictEqual(netParams.panId);
            expect(decodedHeader.source64).toStrictEqual(netParams.eui64);
            expect(decodedHeader.sourcePANId).toStrictEqual(netParams.panId);
        });

        it("encodes beacon responses with Zigbee beacon payload", async () => {
            getOnSendFrameMock().mockClear();

            await macHandler.processBeaconReq(Buffer.alloc(0), 0, {
                frameControl: createMACFrameControl(MACFrameType.CMD, MACFrameAddressMode.SHORT, MACFrameAddressMode.SHORT),
                sequenceNumber: 0,
                destinationPANId: 0xffff,
                destination16: ZigbeeMACConsts.BCAST_ADDR,
                commandId: MACCommandId.BEACON_REQ,
                fcs: 0,
            });

            const macFrame = getOnSendFrameMock().mock.calls.at(-1)?.[0] as Buffer;
            expect(macFrame).toBeInstanceOf(Buffer);

            const [fcf, headerOffset] = decodeMACFrameControl(macFrame, 0);
            const [decodedHeader, payloadOffset] = decodeMACHeader(macFrame, headerOffset, fcf);

            expect(decodedHeader.destinationPANId).toBeUndefined();
            expect(decodedHeader.sourcePANId).toStrictEqual(netParams.panId);
            expect(decodedHeader.superframeSpec?.panCoordinator).toStrictEqual(true);

            const payload = decodeMACPayload(macFrame, payloadOffset, fcf, decodedHeader);
            const beacon = decodeMACZigbeeBeacon(payload, 0);

            expect(beacon.profile).toStrictEqual(0x2);
            expect(beacon.version).toStrictEqual(ZigbeeNWKConsts.VERSION_2007);
            expect(beacon.txOffset).toStrictEqual(0xffffff);
            expect(beacon.updateId).toStrictEqual(netParams.nwkUpdateId);
        });
    });

    describe("mac.ts direct coverage (non-Zigbee cases)", () => {
        const dest16Value = 0x3344;
        const source16Value = 0x5566;
        const dest64Value = 0x00124b0000abcdden;
        const source64Value = 0x00124b0000fedcban;
        const destPanId = 0x1a62;
        const sourcePanId = 0x1b63;

        const makeHeader = (
            frameControlOverrides: Partial<MACFrameControl>,
            headerOverrides: Partial<Omit<MACHeader, "frameControl">> = {},
        ): MACHeader => {
            const frameControl: MACFrameControl = {
                frameType: MACFrameType.DATA,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: MACFrameAddressMode.NONE,
                frameVersion: MACFrameVersion.V2003,
                sourceAddrMode: MACFrameAddressMode.NONE,
                ...frameControlOverrides,
            };

            return {
                frameControl,
                sequenceNumber: 0x5a,
                fcs: 0,
                ...headerOverrides,
            };
        };

        const decodeHeader = (frame: Buffer): MACHeader => {
            const [fcf, headerOffset] = decodeMACFrameControl(frame, 0);
            const [decodedHeader] = decodeMACHeader(frame, headerOffset, fcf);
            return decodedHeader;
        };

        type PresenceCase = {
            name: string;
            frameControl: Partial<MACFrameControl>;
            header: Partial<Omit<MACHeader, "frameControl">>;
            expectDestPan: boolean;
            expectSourcePan: boolean;
        };

        const ensureAddressFields = (frameControl: Partial<MACFrameControl>, header: PresenceCase["header"]): PresenceCase["header"] => {
            const resolvedHeader = { ...header };

            if (frameControl.destAddrMode === MACFrameAddressMode.SHORT && resolvedHeader.destination16 === undefined) {
                resolvedHeader.destination16 = dest16Value;
            } else if (frameControl.destAddrMode === MACFrameAddressMode.EXT && resolvedHeader.destination64 === undefined) {
                resolvedHeader.destination64 = dest64Value;
            }

            if (frameControl.sourceAddrMode === MACFrameAddressMode.SHORT && resolvedHeader.source16 === undefined) {
                resolvedHeader.source16 = source16Value;
            } else if (frameControl.sourceAddrMode === MACFrameAddressMode.EXT && resolvedHeader.source64 === undefined) {
                resolvedHeader.source64 = source64Value;
            }

            return resolvedHeader;
        };

        const v2003Cases: PresenceCase[] = [
            {
                name: "dest+source short without compression",
                frameControl: {
                    frameVersion: MACFrameVersion.V2003,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                    panIdCompression: false,
                },
                header: {
                    destinationPANId: destPanId,
                    sourcePANId: sourcePanId,
                },
                expectDestPan: true,
                expectSourcePan: true,
            },
            {
                name: "dest+source short with compression",
                frameControl: {
                    frameVersion: MACFrameVersion.V2003,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                    panIdCompression: true,
                },
                header: {
                    destinationPANId: destPanId,
                },
                expectDestPan: true,
                expectSourcePan: false,
            },
            {
                name: "destination short only",
                frameControl: {
                    frameVersion: MACFrameVersion.V2003,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    sourceAddrMode: MACFrameAddressMode.NONE,
                },
                header: {
                    destinationPANId: destPanId,
                },
                expectDestPan: true,
                expectSourcePan: false,
            },
            {
                name: "source short only",
                frameControl: {
                    frameVersion: MACFrameVersion.V2003,
                    destAddrMode: MACFrameAddressMode.NONE,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                header: {
                    sourcePANId: sourcePanId,
                },
                expectDestPan: false,
                expectSourcePan: true,
            },
            {
                name: "no addressing",
                frameControl: {
                    frameVersion: MACFrameVersion.V2003,
                    destAddrMode: MACFrameAddressMode.NONE,
                    sourceAddrMode: MACFrameAddressMode.NONE,
                },
                header: {},
                expectDestPan: false,
                expectSourcePan: false,
            },
            {
                name: "v2006 mirrored logic",
                frameControl: {
                    frameVersion: MACFrameVersion.V2006,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                    panIdCompression: false,
                },
                header: {
                    destinationPANId: destPanId,
                    sourcePANId: sourcePanId,
                },
                expectDestPan: true,
                expectSourcePan: true,
            },
        ];

        it.each(v2003Cases)("encodes %s", ({ frameControl, header, expectDestPan, expectSourcePan }) => {
            const macHeader = makeHeader(frameControl, ensureAddressFields(frameControl, header));
            const frame = encodeMACFrame(macHeader, Buffer.alloc(0));
            const decodedHeader = decodeHeader(frame);

            if (expectDestPan) {
                expect(decodedHeader.destinationPANId).toStrictEqual(destPanId);
            } else {
                expect(decodedHeader.destinationPANId).toBeUndefined();
            }

            const fallbackSourcePanId = expectDestPan ? destPanId : ZigbeeMACConsts.BCAST_PAN;

            if (expectSourcePan) {
                expect(decodedHeader.sourcePANId).toStrictEqual(sourcePanId);
            } else {
                expect(decodedHeader.sourcePANId).toStrictEqual(fallbackSourcePanId);
            }
        });

        it("throws on unexpected PAN compression for 2003 frames", () => {
            const header = makeHeader(
                {
                    frameVersion: MACFrameVersion.V2003,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    sourceAddrMode: MACFrameAddressMode.NONE,
                    panIdCompression: true,
                },
                {
                    destination16: dest16Value,
                },
            );

            expect(() => encodeMACFrame(header, Buffer.alloc(0))).toThrowError("Invalid MAC frame: unexpected PAN ID compression");
        });

        it("throws on unsupported frame type", () => {
            const header = makeHeader({ frameType: MACFrameType.MULTIPURPOSE });

            expect(() => encodeMACFrame(header, Buffer.alloc(0))).toThrowError("Unsupported MAC frame type MULTIPURPOSE (5)");
        });

        it("throws on reserved destination mode", () => {
            const header = makeHeader({ destAddrMode: MACFrameAddressMode.RESERVED });

            expect(() => encodeMACFrame(header, Buffer.alloc(0))).toThrowError("Invalid MAC frame: destination address mode 1");
        });

        it("throws on reserved source mode", () => {
            const header = makeHeader({ sourceAddrMode: MACFrameAddressMode.RESERVED });

            expect(() => encodeMACFrame(header, Buffer.alloc(0))).toThrowError("Invalid MAC frame: source address mode 1");
        });

        it.each([MACFrameVersion.V2015, MACFrameVersion.RESERVED])("throws on invalid frame version %s", (version) => {
            const header = makeHeader({ frameVersion: version });

            expect(() => encodeMACFrame(header, Buffer.alloc(0))).toThrowError("Invalid MAC frame: invalid version");
        });

        it("throws when MAC security is requested", () => {
            const header = makeHeader({ securityEnabled: true, frameVersion: MACFrameVersion.V2003 });

            expect(() => encodeMACFrame(header, Buffer.alloc(0))).toThrowError("Unsupported: securityEnabled");
        });

        it("throws when decoding encrypted MAC payloads", () => {
            const payload = Buffer.from([0x01, 0x02, 0x03, 0x04]);
            const header = makeHeader({ destAddrMode: MACFrameAddressMode.NONE, sourceAddrMode: MACFrameAddressMode.NONE });
            const frame = encodeMACFrame(header, payload);
            const [fcf] = decodeMACFrameControl(frame, 0);

            fcf.securityEnabled = true;

            expect(() => decodeMACPayload(frame, frame.length - ZigbeeMACConsts.FCS_LEN - payload.length, fcf, header)).toThrowError(
                "Unsupported MAC frame: security enabled",
            );
        });

        it("throws when decoded payload lacks FCS", () => {
            const frame = Buffer.from([0x61, 0x01]);
            const frameControl: MACFrameControl = {
                frameType: MACFrameType.DATA,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: MACFrameAddressMode.NONE,
                frameVersion: MACFrameVersion.V2003,
                sourceAddrMode: MACFrameAddressMode.NONE,
            };
            const header = makeHeader({});

            expect(() => decodeMACPayload(frame, 1, frameControl, header)).toThrowError("Invalid MAC frame: no FCS");
        });
    });
});
