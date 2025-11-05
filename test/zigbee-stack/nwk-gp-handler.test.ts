import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MACFrameAddressMode, MACFrameType } from "../../src/zigbee/mac.js";
import { ZigbeeNWKGPAppId, ZigbeeNWKGPCommandId, ZigbeeNWKGPFrameType } from "../../src/zigbee/zigbee-nwkgp.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../../src/zigbee-stack/nwk-gp-handler.js";
import { createMACHeader, createNWKGPHeader } from "../utils.js";

describe("NWK GP Handler", () => {
    let nwkgpHandler: NWKGPHandler;
    let mockCallbacks: NWKGPHandlerCallbacks;

    beforeEach(() => {
        mockCallbacks = {
            onGPFrame: vi.fn(),
        };

        nwkgpHandler = new NWKGPHandler(mockCallbacks);
    });

    afterEach(() => {
        nwkgpHandler.stop();
        vi.useRealTimers();
    });

    describe("Duplicate Detection", () => {
        it("should detect duplicate based on security frame counter", () => {
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            // First call should not be duplicate
            const isDuplicate1 = nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader);
            expect(isDuplicate1).toStrictEqual(false);

            // Same frame counter should be duplicate
            const isDuplicate2 = nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader);
            expect(isDuplicate2).toStrictEqual(true);

            // Different frame counter should not be duplicate
            nwkHeader.securityFrameCounter = 101;
            const isDuplicate3 = nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader);
            expect(isDuplicate3).toStrictEqual(false);
        });

        it("should detect duplicate based on MAC sequence number when no security frame counter", () => {
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            macHeader.sequenceNumber = 10;

            const nwkHeader = createNWKGPHeader();
            nwkHeader.securityFrameCounter = undefined;

            // First call should not be duplicate
            const isDuplicate1 = nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader);
            expect(isDuplicate1).toStrictEqual(false);

            // Same MAC sequence number should be duplicate
            const isDuplicate2 = nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader);
            expect(isDuplicate2).toStrictEqual(true);

            // Different MAC sequence number should not be duplicate
            macHeader.sequenceNumber = 11;
            const isDuplicate3 = nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader);
            expect(isDuplicate3).toStrictEqual(false);
        });

        it("uses endpoint as part of IEEE-addressed duplicate key", () => {
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            nwkHeader.sourceId = undefined;
            nwkHeader.frameControl.frameType = ZigbeeNWKGPFrameType.DATA;
            nwkHeader.frameControl.nwkFrameControlExtension = true;
            nwkHeader.frameControlExt = {
                appId: ZigbeeNWKGPAppId.ZGP,
                securityLevel: 0,
                securityKey: false,
                rxAfterTx: false,
                direction: 0,
            };
            nwkHeader.source64 = 0x00124b0000112233n;
            nwkHeader.endpoint = 0xf2;

            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(false);
            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(true);

            const nwkHeaderDifferentEndpoint = { ...nwkHeader, endpoint: 0xf3 };

            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeaderDifferentEndpoint)).toStrictEqual(false);
        });

        it("expires duplicate cache entries after timeout", () => {
            vi.useFakeTimers();

            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(false);

            vi.advanceTimersByTime(1900);
            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(true);

            vi.advanceTimersByTime(500);
            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(false);
        });

        it("clears duplicate cache on stop", () => {
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(false);
            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(true);

            nwkgpHandler.stop();

            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(false);
        });

        it("returns false when no duplicate key can be derived", () => {
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.NONE, MACFrameAddressMode.NONE);
            macHeader.source64 = undefined;
            macHeader.sequenceNumber = undefined;
            delete (macHeader as { fcs?: number }).fcs;
            macHeader.destination16 = undefined;

            const nwkHeader = createNWKGPHeader();
            nwkHeader.sourceId = undefined;
            nwkHeader.source64 = undefined;
            nwkHeader.securityFrameCounter = undefined;

            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(false);
        });

        it("returns false when fallback key lacks sequence number", () => {
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.NONE, MACFrameAddressMode.SHORT);
            macHeader.source64 = undefined;
            macHeader.source16 = 0x3344;
            macHeader.sequenceNumber = undefined;

            const nwkHeader = createNWKGPHeader();
            nwkHeader.sourceId = undefined;
            nwkHeader.source64 = undefined;
            nwkHeader.securityFrameCounter = undefined;

            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(false);
        });

        it("treats missing IEEE endpoint as 0xff for duplicate 64 tracking", () => {
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            nwkHeader.sourceId = undefined;
            nwkHeader.frameControl.frameType = ZigbeeNWKGPFrameType.DATA;
            nwkHeader.frameControl.nwkFrameControlExtension = true;
            nwkHeader.frameControlExt = {
                appId: ZigbeeNWKGPAppId.ZGP,
                securityLevel: 0,
                securityKey: false,
                rxAfterTx: false,
                direction: 0,
            };
            nwkHeader.source64 = 0x00124b0000778899n;
            nwkHeader.endpoint = undefined;

            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(false);
            expect(nwkgpHandler.isDuplicateFrame(macHeader, nwkHeader)).toStrictEqual(true);
        });
    });

    describe("Green Power Frame Processing", () => {
        it("should process GP frame and emit event", async () => {
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            // Enter commissioning mode first
            nwkgpHandler.enterCommissioningMode(10);

            const commandId = ZigbeeNWKGPCommandId.COMMISSIONING;
            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const data = Buffer.concat([Buffer.from([commandId]), payload]);

            nwkgpHandler.processFrame(data, macHeader, nwkHeader, 150);

            // Wait for setImmediate callback to execute
            await new Promise((resolve) => setImmediate(resolve));

            expect(mockCallbacks.onGPFrame).toHaveBeenCalledWith(commandId, payload, macHeader, nwkHeader, 150);
        });

        it("should ignore commissioning commands when not in commissioning mode", async () => {
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            // Not in commissioning mode
            const commandId = ZigbeeNWKGPCommandId.COMMISSIONING;
            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const data = Buffer.concat([Buffer.from([commandId]), payload]);

            nwkgpHandler.processFrame(data, macHeader, nwkHeader, 150);

            // Wait for setImmediate callback to execute
            await new Promise((resolve) => setImmediate(resolve));

            // Should not emit event
            expect(mockCallbacks.onGPFrame).not.toHaveBeenCalled();
        });
    });

    describe("Commissioning Mode", () => {
        it("should enter commissioning mode with specified window", () => {
            nwkgpHandler.enterCommissioningMode(60);

            // Process a commissioning command to verify we're in commissioning mode
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            const commandId = ZigbeeNWKGPCommandId.COMMISSIONING;
            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const data = Buffer.concat([Buffer.from([commandId]), payload]);

            nwkgpHandler.processFrame(data, macHeader, nwkHeader, 150);

            // In commissioning mode, so should process the frame
            // (we don't check the result here, just that it doesn't throw)
        });

        it("should exit commissioning mode when window is 0", () => {
            nwkgpHandler.enterCommissioningMode(60);
            nwkgpHandler.enterCommissioningMode(0);

            // Commissioning command should now be ignored
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            const commandId = ZigbeeNWKGPCommandId.COMMISSIONING;
            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const data = Buffer.concat([Buffer.from([commandId]), payload]);

            nwkgpHandler.processFrame(data, macHeader, nwkHeader, 150);

            // Should not process the frame (no event emitted)
        });

        it("should exit commissioning mode explicitly", () => {
            nwkgpHandler.enterCommissioningMode(60);
            nwkgpHandler.exitCommissioningMode();

            // Commissioning command should now be ignored
            const macHeader = createMACHeader(MACFrameType.DATA, MACFrameAddressMode.EXT, MACFrameAddressMode.EXT);
            const nwkHeader = createNWKGPHeader();

            const commandId = ZigbeeNWKGPCommandId.COMMISSIONING;
            const payload = Buffer.from([0x01, 0x02, 0x03]);
            const data = Buffer.concat([Buffer.from([commandId]), payload]);

            nwkgpHandler.processFrame(data, macHeader, nwkHeader, 150);

            // Should not process the frame (no event emitted)
        });
    });
});
