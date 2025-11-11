import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { logger } from "../../src/utils/logger.js";
import type { MACFrameControl, MACHeader } from "../../src/zigbee/mac.js";
import * as macModule from "../../src/zigbee/mac.js";
import { ZigbeeConsts, ZigbeeKeyType, ZigbeeSecurityLevel } from "../../src/zigbee/zigbee.js";
import type { ZigbeeAPSFrameControl, ZigbeeAPSHeader } from "../../src/zigbee/zigbee-aps.js";
import * as apsModule from "../../src/zigbee/zigbee-aps.js";
import type { ZigbeeNWKFrameControl, ZigbeeNWKHeader } from "../../src/zigbee/zigbee-nwk.js";
import * as nwkModule from "../../src/zigbee/zigbee-nwk.js";
import type { ZigbeeNWKGPFrameControl, ZigbeeNWKGPHeader } from "../../src/zigbee/zigbee-nwkgp.js";
import * as nwkgpModule from "../../src/zigbee/zigbee-nwkgp.js";
import type { APSHandler } from "../../src/zigbee-stack/aps-handler.js";
import { processFrame } from "../../src/zigbee-stack/frame.js";
import type { MACHandler } from "../../src/zigbee-stack/mac-handler.js";
import type { NWKGPHandler } from "../../src/zigbee-stack/nwk-gp-handler.js";
import type { NWKHandler } from "../../src/zigbee-stack/nwk-handler.js";
import type { StackContext } from "../../src/zigbee-stack/stack-context.js";
import { createMACFrameControl } from "../utils.js";

type TestContext = {
    netParams: {
        panId: number;
        eui64: bigint;
        networkKey: Buffer;
    };
    address16ToAddress64: Map<number, bigint>;
    deviceTable: Map<bigint, { address16?: number }>;
    computeLQA: ReturnType<typeof vi.fn>;
    computeDeviceLQA: ReturnType<typeof vi.fn>;
    updateIncomingNWKFrameCounter: ReturnType<typeof vi.fn>;
    rssiMin: number;
};

type MacHandlerMock = {
    processCommand: ReturnType<typeof vi.fn>;
};

type NwkHandlerMock = {
    processCommand: ReturnType<typeof vi.fn>;
};

type NwkGPHandlerMock = {
    isDuplicateFrame: ReturnType<typeof vi.fn>;
    processFrame: ReturnType<typeof vi.fn>;
};

type APSHandlerMock = {
    sendACK: ReturnType<typeof vi.fn>;
    isDuplicateFrame: ReturnType<typeof vi.fn>;
    processFrame: ReturnType<typeof vi.fn>;
};

const buildMacHeader = (frameControl: MACFrameControl, overrides: Partial<MACHeader> = {}): MACHeader => ({
    frameControl,
    sequenceNumber: 0x12,
    destinationPANId: 0x1a62,
    destination16: 0x0000,
    sourcePANId: 0x1a62,
    source16: 0x1234,
    fcs: 0,
    ...overrides,
});

const buildNWKFrameControl = (overrides: Partial<ZigbeeNWKFrameControl> = {}): ZigbeeNWKFrameControl => ({
    frameType: nwkModule.ZigbeeNWKFrameType.DATA,
    protocolVersion: nwkModule.ZigbeeNWKConsts.VERSION_2007,
    discoverRoute: 0,
    multicast: false,
    security: false,
    sourceRoute: false,
    extendedDestination: false,
    extendedSource: false,
    endDeviceInitiator: false,
    ...overrides,
});

const buildNWKHeader = (frameControl: ZigbeeNWKFrameControl, overrides: Partial<ZigbeeNWKHeader> = {}): ZigbeeNWKHeader => ({
    frameControl,
    destination16: 0x0000,
    source16: 0x5678,
    radius: 5,
    seqNum: 0x34,
    ...overrides,
});

const buildAPSFrameControl = (overrides: Partial<ZigbeeAPSFrameControl> = {}): ZigbeeAPSFrameControl => ({
    frameType: apsModule.ZigbeeAPSFrameType.DATA,
    deliveryMode: apsModule.ZigbeeAPSDeliveryMode.UNICAST,
    ackFormat: false,
    security: false,
    ackRequest: false,
    extendedHeader: false,
    ...overrides,
});

const buildAPSHeader = (frameControl: ZigbeeAPSFrameControl, overrides: Partial<ZigbeeAPSHeader> = {}): ZigbeeAPSHeader => ({
    frameControl,
    destEndpoint: 0x11,
    clusterId: 0x0006,
    profileId: 0x0104,
    sourceEndpoint: 0x22,
    counter: 0x44,
    ...overrides,
});

const buildNWKGPFrameControl = (overrides: Partial<ZigbeeNWKGPFrameControl> = {}): ZigbeeNWKGPFrameControl => ({
    frameType: nwkgpModule.ZigbeeNWKGPFrameType.DATA,
    protocolVersion: 0,
    autoCommissioning: false,
    nwkFrameControlExtension: false,
    ...overrides,
});

const buildNWKGPHeader = (frameControl: ZigbeeNWKGPFrameControl, overrides: Partial<ZigbeeNWKGPHeader> = {}): ZigbeeNWKGPHeader => ({
    frameControl,
    micSize: 0,
    payloadLength: 3,
    securityFrameCounter: 5,
    ...overrides,
});

const mockMACDecoding = (frameControl: MACFrameControl, header: MACHeader, payload: Buffer): void => {
    vi.spyOn(macModule, "decodeMACFrameControl").mockReturnValue([frameControl, 1]);
    vi.spyOn(macModule, "decodeMACHeader").mockReturnValue([header, 2]);
    vi.spyOn(macModule, "decodeMACPayload").mockReturnValue(payload);
};

const mockNWKDecoding = (frameControl: ZigbeeNWKFrameControl, header: ZigbeeNWKHeader, payload: Buffer): void => {
    vi.spyOn(nwkModule, "decodeZigbeeNWKFrameControl").mockReturnValue([frameControl, 1]);
    vi.spyOn(nwkModule, "decodeZigbeeNWKHeader").mockReturnValue([header, 2]);
    vi.spyOn(nwkModule, "decodeZigbeeNWKPayload").mockReturnValue(payload);
};

const mockAPSDecoding = (frameControl: ZigbeeAPSFrameControl, header: ZigbeeAPSHeader, payload: Buffer): void => {
    vi.spyOn(apsModule, "decodeZigbeeAPSFrameControl").mockReturnValue([frameControl, 1]);
    vi.spyOn(apsModule, "decodeZigbeeAPSHeader").mockReturnValue([header, 2]);
    vi.spyOn(apsModule, "decodeZigbeeAPSPayload").mockReturnValue(payload);
};

const mockNWKGPDecoding = (frameControl: ZigbeeNWKGPFrameControl, header: ZigbeeNWKGPHeader, payload: Buffer): void => {
    vi.spyOn(nwkgpModule, "decodeZigbeeNWKGPFrameControl").mockReturnValue([frameControl, 1]);
    vi.spyOn(nwkgpModule, "decodeZigbeeNWKGPHeader").mockReturnValue([header, 2]);
    vi.spyOn(nwkgpModule, "decodeZigbeeNWKGPPayload").mockReturnValue(payload);
};

describe("Frame handler", () => {
    let rawContext: TestContext;
    let context: StackContext;
    let macHandlerMock: MacHandlerMock;
    let macHandler: MACHandler;
    let nwkHandlerMock: NwkHandlerMock;
    let nwkHandler: NWKHandler;
    let nwkGPHandlerMock: NwkGPHandlerMock;
    let nwkGPHandler: NWKGPHandler;
    let apsHandlerMock: APSHandlerMock;
    let apsHandler: APSHandler;

    beforeEach(() => {
        rawContext = {
            netParams: {
                panId: 0x1a62,
                eui64: 0x00124b0012345678n,
                networkKey: Buffer.alloc(16, 0xaa),
            },
            address16ToAddress64: new Map(),
            deviceTable: new Map(),
            computeLQA: vi.fn(() => 0x50),
            computeDeviceLQA: vi.fn(() => 0x60),
            updateIncomingNWKFrameCounter: vi.fn(() => true),
            rssiMin: -60,
        };
        context = rawContext as unknown as StackContext;

        macHandlerMock = {
            processCommand: vi.fn().mockResolvedValue(undefined),
        };
        macHandler = macHandlerMock as unknown as MACHandler;

        nwkHandlerMock = {
            processCommand: vi.fn().mockResolvedValue(undefined),
        };
        nwkHandler = nwkHandlerMock as unknown as NWKHandler;

        nwkGPHandlerMock = {
            isDuplicateFrame: vi.fn().mockReturnValue(false),
            processFrame: vi.fn(),
        };
        nwkGPHandler = nwkGPHandlerMock as unknown as NWKGPHandler;

        apsHandlerMock = {
            sendACK: vi.fn().mockResolvedValue(undefined),
            isDuplicateFrame: vi.fn().mockReturnValue(false),
            processFrame: vi.fn().mockResolvedValue(undefined),
        };
        apsHandler = apsHandlerMock as unknown as APSHandler;
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("ignores MAC frames that are not CMD or DATA", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.ACK);
        vi.spyOn(macModule, "decodeMACFrameControl").mockReturnValue([fcf, 1]);
        const decodeHeaderSpy = vi.spyOn(macModule, "decodeMACHeader");

        await processFrame(Buffer.from([0x00]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(macHandlerMock.processCommand).not.toHaveBeenCalled();
        expect(decodeHeaderSpy).not.toHaveBeenCalled();
    });

    it("delegates MAC command frames to the MAC handler", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.CMD);
        const header = buildMacHeader(fcf);
        const payload = Buffer.from([0xaa]);
        mockMACDecoding(fcf, header, payload);

        await processFrame(payload, context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(macHandlerMock.processCommand).toHaveBeenCalledTimes(1);
        expect(macHandlerMock.processCommand).toHaveBeenCalledWith(payload, header);
        expect(nwkHandlerMock.processCommand).not.toHaveBeenCalled();
    });

    it("drops data frames with mismatching PAN identifiers", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA);
        const header = buildMacHeader(fcf, { destinationPANId: 0x2222 });
        mockMACDecoding(fcf, header, Buffer.alloc(0));

        await processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(nwkHandlerMock.processCommand).not.toHaveBeenCalled();
        expect(apsHandlerMock.processFrame).not.toHaveBeenCalled();
    });

    it("drops short-addressed frames not targeted at the coordinator", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf, { destination16: 0x1235 });
        vi.spyOn(macModule, "decodeMACFrameControl").mockReturnValue([fcf, 1]);
        vi.spyOn(macModule, "decodeMACHeader").mockReturnValue([header, 2]);
        vi.spyOn(macModule, "decodeMACPayload").mockReturnValue(Buffer.from([0x08]));

        await processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(nwkHandlerMock.processCommand).not.toHaveBeenCalled();
        expect(apsHandlerMock.processFrame).not.toHaveBeenCalled();
    });

    it("routes Green Power frames through the NWK GP handler", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf, { destination16: macModule.ZigbeeMACConsts.BCAST_ADDR, source64: 0x00124b0000000001n });
        const macPayload = Buffer.from([nwkModule.ZigbeeNWKConsts.VERSION_GREEN_POWER << 2]);
        mockMACDecoding(fcf, header, macPayload);

        const gpFCF = buildNWKGPFrameControl();
        const gpHeader = buildNWKGPHeader(gpFCF, { frameControl: gpFCF, payloadLength: 1 });
        const gpPayload = Buffer.from([0x01]);
        mockNWKGPDecoding(gpFCF, gpHeader, gpPayload);

        await processFrame(macPayload, context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(nwkGPHandlerMock.isDuplicateFrame).toHaveBeenCalledTimes(1);
        expect(nwkGPHandlerMock.processFrame).toHaveBeenCalledWith(gpPayload, header, gpHeader, expect.any(Number));
        expect(apsHandlerMock.processFrame).not.toHaveBeenCalled();
    });

    it("routes Green Power frames addressed with extended destinations", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.EXT, macModule.MACFrameAddressMode.EXT);
        const header = buildMacHeader(fcf, {
            destination16: undefined,
            destination64: 0x00124b0000000002n,
            source64: 0x00124b0000000001n,
        });
        const macPayload = Buffer.from([nwkModule.ZigbeeNWKConsts.VERSION_GREEN_POWER << 2]);
        mockMACDecoding(fcf, header, macPayload);

        const gpFCF = buildNWKGPFrameControl();
        const gpHeader = buildNWKGPHeader(gpFCF, { frameControl: gpFCF, payloadLength: 1 });
        const gpPayload = Buffer.from([0x0a]);
        mockNWKGPDecoding(gpFCF, gpHeader, gpPayload);

        await processFrame(macPayload, context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(nwkGPHandlerMock.processFrame).toHaveBeenCalledWith(gpPayload, header, gpHeader, expect.any(Number));
    });

    it("ignores Green Power frames with unsupported frame types", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf, { destination16: macModule.ZigbeeMACConsts.BCAST_ADDR });
        const macPayload = Buffer.from([nwkModule.ZigbeeNWKConsts.VERSION_GREEN_POWER << 2]);
        mockMACDecoding(fcf, header, macPayload);

        const gpFCF = buildNWKGPFrameControl({ frameType: 0x02 });
        const gpHeader = buildNWKGPHeader(gpFCF, { frameControl: gpFCF });
        mockNWKGPDecoding(gpFCF, gpHeader, Buffer.from([0x0b]));

        await processFrame(macPayload, context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(nwkGPHandlerMock.isDuplicateFrame).not.toHaveBeenCalled();
        expect(nwkGPHandlerMock.processFrame).not.toHaveBeenCalled();
    });

    it("ignores Green Power frames with invalid addressing", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf);
        const macPayload = Buffer.from([nwkModule.ZigbeeNWKConsts.VERSION_GREEN_POWER << 2]);
        mockMACDecoding(fcf, header, macPayload);

        const decodeGPFrameSpy = vi.spyOn(nwkgpModule, "decodeZigbeeNWKGPFrameControl");
        const decodeGPHeaderSpy = vi.spyOn(nwkgpModule, "decodeZigbeeNWKGPHeader");
        const decodeGPPayloadSpy = vi.spyOn(nwkgpModule, "decodeZigbeeNWKGPPayload");
        const loggerDebugSpy = vi.spyOn(logger, "debug");

        await processFrame(macPayload, context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(decodeGPFrameSpy).not.toHaveBeenCalled();
        expect(decodeGPHeaderSpy).not.toHaveBeenCalled();
        expect(decodeGPPayloadSpy).not.toHaveBeenCalled();
        expect(loggerDebugSpy).toHaveBeenCalledWith(expect.any(Function), "frame-handler");
        expect((loggerDebugSpy.mock.calls.at(-1)?.[0] as () => string)()).toContain("Invalid frame addressing");
        expect(nwkGPHandlerMock.processFrame).not.toHaveBeenCalled();
    });

    it("drops duplicate Green Power frames", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf, { destination16: macModule.ZigbeeMACConsts.BCAST_ADDR });
        const macPayload = Buffer.from([nwkModule.ZigbeeNWKConsts.VERSION_GREEN_POWER << 2]);
        mockMACDecoding(fcf, header, macPayload);

        const gpFCF = buildNWKGPFrameControl();
        const gpHeader = buildNWKGPHeader(gpFCF);
        const gpPayload = Buffer.from([0x02]);
        mockNWKGPDecoding(gpFCF, gpHeader, gpPayload);
        nwkGPHandlerMock.isDuplicateFrame.mockReturnValue(true);

        await processFrame(macPayload, context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(nwkGPHandlerMock.processFrame).not.toHaveBeenCalled();
    });

    it("skips broadcast loopback frames originating from the coordinator", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf, { destination16: macModule.ZigbeeMACConsts.BCAST_ADDR });
        mockMACDecoding(fcf, header, Buffer.from([0x08]));

        const nwkFCF = buildNWKFrameControl();
        const nwkHeader = buildNWKHeader(nwkFCF, { source16: ZigbeeConsts.COORDINATOR_ADDRESS });
        mockNWKDecoding(nwkFCF, nwkHeader, Buffer.from([0x01]));

        await processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(apsHandlerMock.processFrame).not.toHaveBeenCalled();
    });

    it("sends APS acknowledgments when requested", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf, { destination16: ZigbeeConsts.COORDINATOR_ADDRESS });
        rawContext.address16ToAddress64.set(0x5678, 0x00124b0000000001n);
        mockMACDecoding(fcf, header, Buffer.from([0x08]));

        const nwkFCF = buildNWKFrameControl();
        const nwkHeader = buildNWKHeader(nwkFCF, { source16: 0x5678, source64: 0x00124b0000000001n });
        const nwkPayload = Buffer.from([0x02]);
        mockNWKDecoding(nwkFCF, nwkHeader, nwkPayload);

        const apsFCF = buildAPSFrameControl({ ackRequest: true });
        const apsHeader = buildAPSHeader(apsFCF);
        const apsPayload = Buffer.from([0x03]);
        mockAPSDecoding(apsFCF, apsHeader, apsPayload);

        await processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(apsHandlerMock.sendACK).toHaveBeenCalledTimes(1);
        expect(apsHandlerMock.sendACK).toHaveBeenCalledWith(header, nwkHeader, apsHeader);
        expect(apsHandlerMock.processFrame).toHaveBeenCalledWith(apsPayload, header, nwkHeader, apsHeader, expect.any(Number));
    });

    it("resolves missing source64 using the address16 map", async () => {
        const source16 = 0x6789;
        const resolvedSource64 = 0x00124b0000000003n;
        rawContext.address16ToAddress64.set(source16, resolvedSource64);

        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf, { destination16: ZigbeeConsts.COORDINATOR_ADDRESS });
        mockMACDecoding(fcf, header, Buffer.from([0x08]));

        const nwkFCF = buildNWKFrameControl();
        const nwkHeader = buildNWKHeader(nwkFCF, { source16, source64: undefined });
        const nwkPayload = Buffer.from([0x02]);
        mockNWKDecoding(nwkFCF, nwkHeader, nwkPayload);

        const apsFCF = buildAPSFrameControl();
        const apsHeader = buildAPSHeader(apsFCF);
        const apsPayload = Buffer.from([0x06]);
        mockAPSDecoding(apsFCF, apsHeader, apsPayload);

        const mapGetSpy = vi.spyOn(rawContext.address16ToAddress64, "get");

        await processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(mapGetSpy).toHaveBeenCalledWith(source16);
        expect(apsHandlerMock.processFrame).toHaveBeenCalledWith(apsPayload, header, nwkHeader, apsHeader, expect.any(Number));
    });

    it("ignores APS frames with no sender information", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf, { destination16: ZigbeeConsts.COORDINATOR_ADDRESS });
        mockMACDecoding(fcf, header, Buffer.from([0x08]));

        const nwkFCF = buildNWKFrameControl();
        const nwkHeader = buildNWKHeader(nwkFCF, { source16: undefined, source64: undefined });
        const nwkPayload = Buffer.from([0x02]);
        mockNWKDecoding(nwkFCF, nwkHeader, nwkPayload);

        const apsFCF = buildAPSFrameControl();
        const apsHeader = buildAPSHeader(apsFCF);
        const apsPayload = Buffer.from([0x05]);
        mockAPSDecoding(apsFCF, apsHeader, apsPayload);

        await processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(apsHandlerMock.isDuplicateFrame).not.toHaveBeenCalled();
        expect(apsHandlerMock.processFrame).not.toHaveBeenCalled();
    });

    it("filters duplicate APS data frames before handler processing", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf);
        mockMACDecoding(fcf, header, Buffer.from([0x08]));

        const nwkFCF = buildNWKFrameControl();
        const nwkHeader = buildNWKHeader(nwkFCF, { source16: 0x5678 });
        const nwkPayload = Buffer.from([0x02]);
        mockNWKDecoding(nwkFCF, nwkHeader, nwkPayload);

        const apsFCF = buildAPSFrameControl();
        const apsHeader = buildAPSHeader(apsFCF);
        const apsPayload = Buffer.from([0x04]);
        mockAPSDecoding(apsFCF, apsHeader, apsPayload);
        apsHandlerMock.isDuplicateFrame.mockReturnValue(true);

        await processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(apsHandlerMock.processFrame).not.toHaveBeenCalled();
    });

    it("delegates NWK command frames to the NWK handler", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf);
        mockMACDecoding(fcf, header, Buffer.from([0x08]));

        const nwkFCF = buildNWKFrameControl({ frameType: nwkModule.ZigbeeNWKFrameType.CMD });
        const nwkHeader = buildNWKHeader(nwkFCF);
        const nwkPayload = Buffer.from([0x05]);
        mockNWKDecoding(nwkFCF, nwkHeader, nwkPayload);

        await processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(nwkHandlerMock.processCommand).toHaveBeenCalledTimes(1);
        expect(nwkHandlerMock.processCommand).toHaveBeenCalledWith(nwkPayload, header, nwkHeader);
    });

    it("rejects unsupported INTERPAN frames", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf);
        mockMACDecoding(fcf, header, Buffer.from([0x08]));

        const nwkFCF = buildNWKFrameControl({ frameType: nwkModule.ZigbeeNWKFrameType.INTERPAN });
        const nwkHeader = buildNWKHeader(nwkFCF);
        const nwkPayload = Buffer.from([0x06]);
        mockNWKDecoding(nwkFCF, nwkHeader, nwkPayload);

        await expect(processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler)).rejects.toThrow(
            "INTERPAN not supported",
        );
    });

    it("drops NWK frames when replay protection rejects the counter", async () => {
        const fcf = createMACFrameControl(macModule.MACFrameType.DATA, macModule.MACFrameAddressMode.SHORT, macModule.MACFrameAddressMode.SHORT);
        const header = buildMacHeader(fcf);
        mockMACDecoding(fcf, header, Buffer.from([0x08]));

        const nwkFCF = buildNWKFrameControl({ security: true });
        const nwkHeader = buildNWKHeader(nwkFCF, {
            securityHeader: {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.NWK,
                    nonce: false,
                    reqVerifiedFc: false,
                },
                frameCounter: 10,
            },
        });
        const nwkPayload = Buffer.from([0x07]);
        mockNWKDecoding(nwkFCF, nwkHeader, nwkPayload);
        rawContext.updateIncomingNWKFrameCounter.mockReturnValue(false);

        const apsFCF = buildAPSFrameControl();
        const apsHeader = buildAPSHeader(apsFCF);
        const apsPayload = Buffer.from([0x09]);
        mockAPSDecoding(apsFCF, apsHeader, apsPayload);

        await processFrame(Buffer.from([0x08]), context, macHandler, nwkHandler, nwkGPHandler, apsHandler);

        expect(rawContext.updateIncomingNWKFrameCounter).toHaveBeenCalledWith(undefined, 10);
        expect(apsHandlerMock.processFrame).not.toHaveBeenCalled();
    });
});
