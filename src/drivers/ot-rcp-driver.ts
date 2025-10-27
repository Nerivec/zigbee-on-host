import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { SpinelCommandId } from "../spinel/commands.js";
import { decodeHdlcFrame, HDLC_TX_CHUNK_SIZE, HdlcReservedByte } from "../spinel/hdlc.js";
import { SpinelPropertyId } from "../spinel/properties.js";
import {
    decodeSpinelFrame,
    encodeSpinelFrame,
    getPackedUInt,
    readPropertyc,
    readPropertyi,
    readPropertyii,
    readPropertyU,
    readStreamRaw,
    SPINEL_HEADER_FLG_SPINEL,
    type SpinelFrame,
    SpinelResetReason,
    type SpinelStreamRawMetadata,
    type StreamRawConfig,
    writePropertyAC,
    writePropertyb,
    writePropertyC,
    writePropertyc,
    writePropertyE,
    writePropertyId,
    writePropertyS,
    writePropertyStreamRaw,
} from "../spinel/spinel.js";
import { SpinelStatus } from "../spinel/statuses.js";
import { logger } from "../utils/logger.js";
import { decodeMACFrameControl, decodeMACHeader, decodeMACPayload, MACFrameAddressMode, MACFrameType, ZigbeeMACConsts } from "../zigbee/mac.js";
import { convertMaskToChannels, ZigbeeConsts } from "../zigbee/zigbee.js";
import { decodeZigbeeAPSFrameControl, decodeZigbeeAPSHeader, decodeZigbeeAPSPayload, ZigbeeAPSDeliveryMode } from "../zigbee/zigbee-aps.js";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    ZigbeeNWKRouteDiscovery,
} from "../zigbee/zigbee-nwk.js";
import { decodeZigbeeNWKGPFrameControl, decodeZigbeeNWKGPHeader, decodeZigbeeNWKGPPayload, ZigbeeNWKGPFrameType } from "../zigbee/zigbee-nwkgp.js";
import { APSHandler, type APSHandlerCallbacks } from "../zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../zigbee-stack/mac-handler.js";
import { NWKGPHandler, type NWKGPHandlerCallbacks } from "../zigbee-stack/nwk-gp-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../zigbee-stack/nwk-handler.js";
import { type NetworkParameters, type StackCallbacks, StackContext, type StackContextCallbacks } from "../zigbee-stack/stack-context.js";
import { OTRCPParser } from "./ot-rcp-parser.js";
import { OTRCPWriter } from "./ot-rcp-writer.js";

const NS = "ot-rcp-driver";

// const SPINEL_FRAME_MAX_SIZE = 1300;
// const SPINEL_FRAME_MAX_COMMAND_HEADER_SIZE = 4;
// const SPINEL_FRAME_MAX_COMMAND_PAYLOAD_SIZE = SPINEL_FRAME_MAX_SIZE - SPINEL_FRAME_MAX_COMMAND_HEADER_SIZE;
// const SPINEL_ENCRYPTER_EXTRA_DATA_SIZE = 0;
// const SPINEL_FRAME_BUFFER_SIZE = SPINEL_FRAME_MAX_SIZE + SPINEL_ENCRYPTER_EXTRA_DATA_SIZE;

const CONFIG_TID_MASK = 0x0e;
const CONFIG_HIGHWATER_MARK = HDLC_TX_CHUNK_SIZE * 4;

export class OTRCPDriver {
    readonly #onMACFrame: StackCallbacks["onMACFrame"];
    readonly #streamRawConfig: StreamRawConfig;
    readonly writer: OTRCPWriter;
    readonly parser: OTRCPParser;

    #protocolVersionMajor = 0;
    #protocolVersionMinor = 0;
    #ncpVersion = "";
    #interfaceType = 0;
    #rcpAPIVersion = 0;
    #rcpMinHostAPIVersion = 0;

    /** Centralized stack context holding all shared state */
    readonly context: StackContext;
    /** MAC layer handler */
    readonly macHandler: MACHandler;
    /** NWK layer handler */
    readonly nwkHandler: NWKHandler;
    /** APS layer handler */
    readonly apsHandler: APSHandler;
    /** NWK GP layer handler */
    readonly nwkGPHandler: NWKGPHandler;

    /**
     * Transaction ID used in Spinel frame
     *
     * NOTE: 0 is used for "no response expected/needed" (e.g. unsolicited update commands from NCP to host)
     */
    #spinelTID: number;

    /** If defined, indicates we're waiting for the property with the specific payload to come in */
    #resetWaiter: { timer: NodeJS.Timeout | undefined; resolve: (frame: SpinelFrame) => void } | undefined;
    /** TID currently being awaited */
    readonly #tidWaiters: Map<
        number,
        {
            timer: NodeJS.Timeout | undefined;
            resolve: (frame: SpinelFrame) => void;
            reject: (error: Error) => void;
        }
    >;

    #networkUp: boolean;

    #pendingChangeChannel: NodeJS.Timeout | undefined;

    constructor(callbacks: StackCallbacks, streamRawConfig: StreamRawConfig, netParams: NetworkParameters, saveDir: string, emitMACFrames = false) {
        if (!existsSync(saveDir)) {
            mkdirSync(saveDir);
        }

        this.#onMACFrame = callbacks.onMACFrame;
        this.#streamRawConfig = streamRawConfig;
        this.writer = new OTRCPWriter({ highWaterMark: CONFIG_HIGHWATER_MARK });
        this.parser = new OTRCPParser({ readableHighWaterMark: CONFIG_HIGHWATER_MARK });

        this.#spinelTID = -1; // start at 0 but effectively 1 returned by first nextTID() call
        this.#resetWaiter = undefined;
        this.#tidWaiters = new Map();

        this.#networkUp = false;

        const contextCallbacks: StackContextCallbacks = {
            onDeviceLeft: callbacks.onDeviceLeft,
        };

        this.context = new StackContext(contextCallbacks, join(saveDir, "zoh.save"), netParams);

        const macCallbacks: MACHandlerCallbacks = {
            onFrame: callbacks.onMACFrame,
            onSendFrame: this.sendStreamRaw.bind(this),
            onAPSSendTransportKeyNWK: async (address16, key, keySeqNum, destination64) => {
                await this.apsHandler.sendTransportKeyNWK(address16, key, keySeqNum, destination64);
            },
            onMarkRouteSuccess: (destination16) => {
                this.nwkHandler.markRouteSuccess(destination16);
            },
            onMarkRouteFailure: (destination16) => {
                this.nwkHandler.markRouteFailure(destination16);
            },
        };

        this.macHandler = new MACHandler(this.context, macCallbacks, SpinelStatus.NO_ACK, emitMACFrames);

        const nwkCallbacks: NWKHandlerCallbacks = {
            onDeviceRejoined: callbacks.onDeviceRejoined,
            onAPSSendTransportKeyNWK: async (address16, key, keySeqNum, destination64) => {
                await this.apsHandler.sendTransportKeyNWK(address16, key, keySeqNum, destination64);
            },
        };

        this.nwkHandler = new NWKHandler(this.context, this.macHandler, nwkCallbacks);

        const apsCallbacks: APSHandlerCallbacks = {
            onFrame: callbacks.onFrame,
            onDeviceJoined: callbacks.onDeviceJoined,
            onDeviceRejoined: callbacks.onDeviceRejoined,
            onDeviceAuthorized: callbacks.onDeviceAuthorized,
        };

        this.apsHandler = new APSHandler(this.context, this.macHandler, this.nwkHandler, apsCallbacks);

        // Setup NWK GP handler callbacks
        const nwkGPCallbacks: NWKGPHandlerCallbacks = {
            onGPFrame: callbacks.onGPFrame,
        };

        this.nwkGPHandler = new NWKGPHandler(nwkGPCallbacks);
    }

    // #region Getters/Setters

    get protocolVersionMajor(): number {
        return this.#protocolVersionMajor;
    }

    get protocolVersionMinor(): number {
        return this.#protocolVersionMinor;
    }

    get ncpVersion(): string {
        return this.#ncpVersion;
    }

    get interfaceType(): number {
        return this.#interfaceType;
    }

    get rcpAPIVersion(): number {
        return this.#rcpAPIVersion;
    }

    get rcpMinHostAPIVersion(): number {
        return this.#rcpMinHostAPIVersion;
    }

    get currentSpinelTID(): number {
        return this.#spinelTID + 1;
    }

    // #endregion

    // #region TIDs/counters

    /**
     * @returns increased TID offsetted by +1. [1-14] range for the "actually-used" value (0 is reserved)
     */
    private nextSpinelTID(): number {
        this.#spinelTID = (this.#spinelTID + 1) % CONFIG_TID_MASK;

        return this.#spinelTID + 1;
    }

    // #endregion

    // #region HDLC/Spinel

    public async waitForTID(tid: number, timeout: number): Promise<SpinelFrame> {
        return await new Promise<SpinelFrame>((resolve, reject) => {
            // TODO reject if tid already present? (shouldn't happen as long as concurrency is fine...)
            this.#tidWaiters.set(tid, {
                timer: setTimeout(reject.bind(this, new Error(`-x-> SPINEL[tid=${tid}] Timeout after ${timeout}ms`)), timeout),
                resolve,
                reject,
            });
        });
    }

    /**
     * Logic optimizes code paths to try to avoid more parsing when frames will eventually get ignored by detecting as early as possible.
     * HOT PATH: This method is called for every incoming frame. Optimizations:
     * - Early bail-outs to minimize processing
     * - Inline-able operations
     * - Minimal allocations in critical paths
     */
    public async onStreamRawFrame(payload: Buffer, metadata: SpinelStreamRawMetadata | undefined): Promise<void> {
        // HOT PATH: Early bail-out - discard MAC frames before network is started
        /* @__INLINE__ */
        if (!this.#networkUp) {
            return;
        }

        // Emit MAC frames if listeners registered (not in hot path for normal operation)
        if (this.macHandler.emitFrames) {
            setImmediate(() => {
                this.#onMACFrame(payload, metadata?.rssi);
            });
        }

        try {
            // HOT PATH: Decode frame control - inlined by V8 optimizer
            /* @__INLINE__ */
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(payload, 0);

            // HOT PATH: Early bail-out - only process CMD and DATA frames
            /* @__INLINE__ */
            // TODO: process BEACON for PAN ID conflict detection?
            if (macFCF.frameType !== MACFrameType.CMD && macFCF.frameType !== MACFrameType.DATA) {
                logger.debug(() => `<-~- MAC Ignoring frame with type not CMD/DATA (${macFCF.frameType})`, NS);
                return;
            }

            // HOT PATH: Decode MAC header
            const [macHeader, macHOutOffset] = decodeMACHeader(payload, macFCFOutOffset, macFCF);

            // Metadata logging (not in hot path, behind lazy lambda)
            if (metadata) {
                logger.debug(
                    () => `<--- SPINEL STREAM_RAW METADATA[rssi=${metadata.rssi} noiseFloor=${metadata.noiseFloor} flags=${metadata.flags}]`,
                    NS,
                );
            }

            // HOT PATH: Decode MAC payload
            const macPayload = decodeMACPayload(payload, macHOutOffset, macFCF, macHeader);

            // HOT PATH: Process MAC commands (association, data request, etc.)
            /* @__INLINE__ */
            if (macFCF.frameType === MACFrameType.CMD) {
                await this.macHandler.processCommand(macPayload, macHeader);

                // done
                return;
            }

            // HOT PATH: Early bail-out - validate PAN ID
            /* @__INLINE__ */
            if (macHeader.destinationPANId !== ZigbeeMACConsts.BCAST_PAN && macHeader.destinationPANId !== this.context.netParams.panId) {
                logger.debug(() => `<-~- MAC Ignoring frame with mismatching PAN Id ${macHeader.destinationPANId}`, NS);
                return;
            }

            // HOT PATH: Early bail-out - validate destination address
            /* @__INLINE__ */
            if (
                macFCF.destAddrMode === MACFrameAddressMode.SHORT &&
                macHeader.destination16! !== ZigbeeMACConsts.BCAST_ADDR &&
                macHeader.destination16! !== ZigbeeConsts.COORDINATOR_ADDRESS
            ) {
                logger.debug(() => `<-~- MAC Ignoring frame intended for device ${macHeader.destination16}`, NS);
                return;
            }

            // HOT PATH: Process payload if present
            /* @__INLINE__ */
            if (macPayload.byteLength > 0) {
                // HOT PATH: Check protocol version - inlined bitwise operation
                /* @__INLINE__ */
                const protocolVersion = (macPayload.readUInt8(0) & ZigbeeNWKConsts.FCF_VERSION) >> 2;

                // HOT PATH: Branch based on protocol version
                /* @__INLINE__ */
                if (protocolVersion === ZigbeeNWKConsts.VERSION_GREEN_POWER) {
                    if (
                        (macFCF.destAddrMode === MACFrameAddressMode.SHORT && macHeader.destination16 === ZigbeeMACConsts.BCAST_ADDR) ||
                        macFCF.destAddrMode === MACFrameAddressMode.EXT
                    ) {
                        const [nwkGPFCF, nwkGPFCFOutOffset] = decodeZigbeeNWKGPFrameControl(macPayload, 0);
                        const [nwkGPHeader, nwkGPHOutOffset] = decodeZigbeeNWKGPHeader(macPayload, nwkGPFCFOutOffset, nwkGPFCF);

                        if (
                            nwkGPHeader.frameControl.frameType !== ZigbeeNWKGPFrameType.DATA &&
                            nwkGPHeader.frameControl.frameType !== ZigbeeNWKGPFrameType.MAINTENANCE
                        ) {
                            logger.debug(() => `<-~- NWKGP Ignoring frame with type ${nwkGPHeader.frameControl.frameType}`, NS);
                            return;
                        }

                        // Delegate GP duplicate check to NWK GP handler
                        if (this.nwkGPHandler.isDuplicateFrame(macHeader, nwkGPHeader)) {
                            logger.debug(
                                () =>
                                    `<-~- NWKGP Ignoring duplicate frame macSeqNum=${macHeader.sequenceNumber} nwkGPFC=${nwkGPHeader.securityFrameCounter}`,
                                NS,
                            );
                            return;
                        }

                        const nwkGPPayload = decodeZigbeeNWKGPPayload(
                            macPayload,
                            nwkGPHOutOffset,
                            this.context.netParams.networkKey,
                            macHeader.source64,
                            nwkGPFCF,
                            nwkGPHeader,
                        );

                        // Delegate GP frame processing to NWK GP handler
                        this.nwkGPHandler.processFrame(
                            nwkGPPayload,
                            macHeader,
                            nwkGPHeader,
                            this.context.computeLQA(metadata?.rssi ?? this.context.rssiMin),
                        );
                    } else {
                        logger.debug(() => `<-x- NWKGP Invalid frame addressing ${macFCF.destAddrMode} (${macHeader.destination16})`, NS);
                        return;
                    }
                } else {
                    const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
                    const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);

                    if (
                        macHeader.destination16 !== undefined &&
                        macHeader.destination16 >= ZigbeeConsts.BCAST_MIN &&
                        nwkHeader.source16 === ZigbeeConsts.COORDINATOR_ADDRESS
                    ) {
                        logger.debug(() => "<-~- NWK Ignoring frame from coordinator (broadcast loopback)", NS);
                        return;
                    }

                    const resolvedSource64 =
                        nwkHeader.source64 ??
                        (nwkHeader.source16 !== undefined ? this.context.address16ToAddress64.get(nwkHeader.source16) : undefined);
                    const sourceLQA = this.context.computeDeviceLQA(nwkHeader.source16, nwkHeader.source64, metadata?.rssi ?? this.context.rssiMin);
                    const nwkPayload = decodeZigbeeNWKPayload(
                        macPayload,
                        nwkHOutOffset,
                        undefined, // use pre-hashed this.context.netParams.networkKey,
                        resolvedSource64,
                        nwkFCF,
                        nwkHeader,
                    );

                    if (nwkFCF.security && nwkHeader.securityHeader) {
                        const accepted = this.context.updateIncomingNWKFrameCounter(resolvedSource64, nwkHeader.securityHeader.frameCounter);

                        if (!accepted) {
                            logger.warning(
                                () =>
                                    `<-x- NWK Rejecting replay frame src16=${nwkHeader.source16}:${resolvedSource64} counter=${nwkHeader.securityHeader?.frameCounter}`,
                                NS,
                            );

                            return;
                        }
                    }

                    if (nwkFCF.frameType === ZigbeeNWKFrameType.DATA) {
                        const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
                        const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);

                        if (apsHeader.frameControl.ackRequest && nwkHeader.source16 !== ZigbeeConsts.COORDINATOR_ADDRESS) {
                            await this.apsHandler.sendACK(macHeader, nwkHeader, apsHeader);
                        }

                        const apsPayload = decodeZigbeeAPSPayload(
                            nwkPayload,
                            apsHOutOffset,
                            undefined, // use pre-hashed this.context.netParams.tcKey,
                            /* nwkHeader.frameControl.extendedSource ? nwkHeader.source64 : this.context.address16ToAddress64.get(nwkHeader.source16!) */
                            nwkHeader.source64 ?? this.context.address16ToAddress64.get(nwkHeader.source16!),
                            apsFCF,
                            apsHeader,
                        );

                        // Delegate APS frame processing to APS handler
                        await this.apsHandler.onZigbeeAPSFrame(apsPayload, macHeader, nwkHeader, apsHeader, sourceLQA);
                    } else if (nwkFCF.frameType === ZigbeeNWKFrameType.CMD) {
                        // Delegate NWK command processing to NWK handler
                        await this.nwkHandler.processCommand(nwkPayload, macHeader, nwkHeader);
                    } else if (nwkFCF.frameType === ZigbeeNWKFrameType.INTERPAN) {
                        throw new Error("INTERPAN not supported");
                    }
                }
            }
        } catch (error) {
            // TODO log or throw depending on error
            logger.error((error as Error).stack!, NS);
        }
    }

    public async onFrame(buffer: Buffer): Promise<void> {
        const hdlcFrame = decodeHdlcFrame(buffer);
        // logger.debug(() => `<--- HDLC[length=${hdlcFrame.length}]`, NS);
        const spinelFrame = decodeSpinelFrame(hdlcFrame);

        /* v8 ignore start */
        if (spinelFrame.header.flg !== SPINEL_HEADER_FLG_SPINEL) {
            // non-Spinel frame (likely BLE HCI)
            return;
        }
        /* v8 ignore stop */

        logger.debug(() => `<--- SPINEL[tid=${spinelFrame.header.tid} cmdId=${spinelFrame.commandId} len=${spinelFrame.payload.byteLength}]`, NS);

        // resolve waiter if any (never for tid===0 since unsolicited frames)
        const waiter = spinelFrame.header.tid > 0 ? this.#tidWaiters.get(spinelFrame.header.tid) : undefined;
        let status: SpinelStatus = SpinelStatus.OK;

        if (waiter) {
            clearTimeout(waiter.timer);
        }

        if (spinelFrame.commandId === SpinelCommandId.PROP_VALUE_IS) {
            const [propId, pOffset] = getPackedUInt(spinelFrame.payload, 0);

            switch (propId) {
                case SpinelPropertyId.STREAM_RAW: {
                    const [macData, metadata] = readStreamRaw(spinelFrame.payload, pOffset);

                    await this.onStreamRawFrame(macData, metadata);
                    break;
                }
                case SpinelPropertyId.LAST_STATUS: {
                    [status] = getPackedUInt(spinelFrame.payload, pOffset);

                    // verbose, waiter will provide feedback
                    // logger.debug(() => `<--- SPINEL LAST_STATUS[${SpinelStatus[status]}]`, NS);

                    // TODO: getting RESET_POWER_ON after RESET instead of RESET_SOFTWARE??
                    if (this.#resetWaiter && (status === SpinelStatus.RESET_SOFTWARE || status === SpinelStatus.RESET_POWER_ON)) {
                        clearTimeout(this.#resetWaiter.timer);
                        this.#resetWaiter.resolve(spinelFrame);

                        this.#resetWaiter = undefined;
                    }

                    break;
                }
                case SpinelPropertyId.MAC_ENERGY_SCAN_RESULT: {
                    // https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.10
                    let resultOffset = pOffset;
                    const channel = spinelFrame.payload.readUInt8(resultOffset);
                    resultOffset += 1;
                    const rssi = spinelFrame.payload.readInt8(resultOffset);
                    resultOffset += 1;

                    logger.info(`<=== ENERGY_SCAN[channel=${channel} rssi=${rssi}]`, NS);
                    break;
                }
            }
        }

        if (waiter) {
            if (status === SpinelStatus.OK) {
                waiter.resolve(spinelFrame);
            } else {
                waiter.reject(new Error(`Failed with status=${SpinelStatus[status]}`, { cause: status }));
            }
        }

        this.#tidWaiters.delete(spinelFrame.header.tid);
    }

    public async sendCommand(commandId: SpinelCommandId, buffer: Buffer, waitForResponse: false): Promise<undefined>;
    public async sendCommand(commandId: SpinelCommandId, buffer: Buffer, waitForResponse: true, timeout: number): Promise<SpinelFrame>;
    public async sendCommand(commandId: SpinelCommandId, buffer: Buffer, waitForResponse = true, timeout = 10000): Promise<SpinelFrame | undefined> {
        const tid = this.nextSpinelTID();
        logger.debug(() => `---> SPINEL[tid=${tid} cmdId=${commandId} len=${buffer.byteLength} wait=${waitForResponse} timeout=${timeout}]`, NS);
        const spinelFrame = {
            header: {
                tid,
                nli: 0,
                flg: SPINEL_HEADER_FLG_SPINEL,
            },
            commandId,
            payload: buffer,
        };
        const hdlcFrame = encodeSpinelFrame(spinelFrame);

        // only send what is recorded as "data" (by length)
        this.writer.writeBuffer(hdlcFrame.data.subarray(0, hdlcFrame.length));

        if (waitForResponse) {
            return await this.waitForTID(spinelFrame.header.tid, timeout);
        }
    }

    public async getProperty(propertyId: SpinelPropertyId, timeout = 10000): ReturnType<typeof this.sendCommand> {
        const [data] = writePropertyId(propertyId, 0);

        return await this.sendCommand(SpinelCommandId.PROP_VALUE_GET, data, true, timeout);
    }

    public async setProperty(payload: Buffer, timeout = 10000): Promise<void> {
        // LAST_STATUS checked in `onFrame`
        await this.sendCommand(SpinelCommandId.PROP_VALUE_SET, payload, true, timeout);
    }

    public async sendStreamRaw(payload: Buffer): Promise<void> {
        await this.setProperty(writePropertyStreamRaw(payload, this.#streamRawConfig));
    }

    /**
     * The CCA (clear-channel assessment) threshold.
     * NOTE: Currently not implemented in: ot-ti
     * @returns dBm (int8)
     */
    public async getPHYCCAThreshold(): Promise<number> {
        const response = await this.getProperty(SpinelPropertyId.PHY_CCA_THRESHOLD);

        return readPropertyc(SpinelPropertyId.PHY_CCA_THRESHOLD, response.payload);
    }

    /**
     * The CCA (clear-channel assessment) threshold.
     * Set to -128 to disable.
     * The value will be rounded down to a value that is supported by the underlying radio hardware.
     * NOTE: Currently not implemented in: ot-ti
     * @param ccaThreshold dBm (>= -128 and <= 127)
     */
    public async setPHYCCAThreshold(ccaThreshold: number): Promise<void> {
        await this.setProperty(writePropertyc(SpinelPropertyId.PHY_CCA_THRESHOLD, Math.min(Math.max(ccaThreshold, -128), 127)));
    }

    /**
     * The transmit power of the radio.
     * @returns dBm (int8)
     */
    public async getPHYTXPower(): Promise<number> {
        const response = await this.getProperty(SpinelPropertyId.PHY_TX_POWER);

        return readPropertyc(SpinelPropertyId.PHY_TX_POWER, response.payload);
    }

    /**
     * The transmit power of the radio.
     * The value will be rounded down to a value that is supported by the underlying radio hardware.
     * @param txPower dBm (>= -128 and <= 127)
     */
    public async setPHYTXPower(txPower: number): Promise<void> {
        await this.setProperty(writePropertyc(SpinelPropertyId.PHY_TX_POWER, Math.min(Math.max(txPower, -128), 127)));
    }

    /**
     * The current RSSI (Received signal strength indication) from the radio.
     * This value can be used in energy scans and for determining the ambient noise floor for the operating environment.
     * @returns dBm (int8)
     */
    public async getPHYRSSI(): Promise<number> {
        const response = await this.getProperty(SpinelPropertyId.PHY_RSSI);

        return readPropertyc(SpinelPropertyId.PHY_RSSI, response.payload);
    }

    /**
     * The radio receive sensitivity.
     * This value can be used as lower bound noise floor for link metrics computation.
     * @returns dBm (int8)
     */
    public async getPHYRXSensitivity(): Promise<number> {
        const response = await this.getProperty(SpinelPropertyId.PHY_RX_SENSITIVITY);

        return readPropertyc(SpinelPropertyId.PHY_RX_SENSITIVITY, response.payload);
    }

    /* v8 ignore start */
    /**
     * Start an energy scan.
     * Cannot be used after state is loaded or network is up.
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.1
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.10
     * @param channels List of channels to scan
     * @param period milliseconds per channel
     * @param txPower
     */
    public async startEnergyScan(channels: number[], period: number, txPower: number): Promise<void> {
        if (this.context.loaded || this.#networkUp) {
            return;
        }

        const radioRSSI = await this.getPHYRSSI();
        const rxSensitivity = await this.getPHYRXSensitivity();

        logger.info(`PHY state: rssi=${radioRSSI} rxSensitivity=${rxSensitivity}`, NS);

        await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, true));
        await this.setPHYTXPower(txPower);
        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RX_ON_WHEN_IDLE_MODE, true));
        await this.setProperty(writePropertyAC(SpinelPropertyId.MAC_SCAN_MASK, channels));
        await this.setProperty(writePropertyS(SpinelPropertyId.MAC_SCAN_PERIOD, period));
        await this.setProperty(writePropertyC(SpinelPropertyId.MAC_SCAN_STATE, 2 /* SCAN_STATE_ENERGY */));
    }

    public async stopEnergyScan(): Promise<void> {
        await this.setProperty(writePropertyS(SpinelPropertyId.MAC_SCAN_PERIOD, 100));
        await this.setProperty(writePropertyC(SpinelPropertyId.MAC_SCAN_STATE, 0 /* SCAN_STATE_IDLE */));
        await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, false));
    }

    /**
     * Start sniffing.
     * Cannot be used after state is loaded or network is up.
     * WARNING: This is expected to run in the "run-and-quit" pattern as it overrides the `onStreamRawFrame` function.
     * @param channel The channel to sniff on
     */
    public async startSniffer(channel: number): Promise<void> {
        if (this.context.loaded || this.#networkUp) {
            return;
        }

        await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, true));
        await this.setProperty(writePropertyC(SpinelPropertyId.PHY_CHAN, channel));
        // 0 => MAC_PROMISCUOUS_MODE_OFF" => Normal MAC filtering is in place.
        // 1 => MAC_PROMISCUOUS_MODE_NETWORK" => All MAC packets matching network are passed up the stack.
        // 2 => MAC_PROMISCUOUS_MODE_FULL" => All decoded MAC packets are passed up the stack.
        await this.setProperty(writePropertyC(SpinelPropertyId.MAC_PROMISCUOUS_MODE, 2));
        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RX_ON_WHEN_IDLE_MODE, true));
        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RAW_STREAM_ENABLED, true));

        // override `onStreamRawFrame` behavior for sniff
        this.onStreamRawFrame = async (payload, metadata) => {
            this.#onMACFrame(payload, metadata?.rssi);
            await Promise.resolve();
        };
    }

    public async stopSniffer(): Promise<void> {
        await this.setProperty(writePropertyC(SpinelPropertyId.MAC_PROMISCUOUS_MODE, 0));
        await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, false)); // first, avoids BUSY signal
        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RAW_STREAM_ENABLED, false));
    }
    /* v8 ignore stop */

    // #endregion

    // #region Network Management

    //---- 05-3474-23 #2.5.4.6
    // Network Discovery, Get, and Set attributes (both requests and confirms) are mandatory
    // Zigbee Coordinator:
    //   - The NWK Formation request and confirm, the NWK Leave request, NWK Leave indication, NWK Leave confirm, NWK Join indication,
    //     NWK Permit Joining request, NWK Permit Joining confirm, NWK Route Discovery request, and NWK Route Discovery confirm SHALL be supported.
    //   - The NWK Direct Join request and NWK Direct Join confirm MAY be supported.
    //   - The NWK Join request and the NWK Join confirm SHALL NOT be supported.
    // NWK Sync request, indication and confirm plus NWK reset request and confirm plus NWK route discovery request and confirm SHALL be optional
    // reception of the NWK Network Status indication SHALL be supported, but no action is required

    get isNetworkUp(): boolean {
        return this.#networkUp;
    }

    /**
     * Set the Spinel properties required to start a 802.15.4 MAC network.
     *
     * Should be called after `start`.
     */
    public async formNetwork(): Promise<void> {
        logger.info("======== Network starting ========", NS);

        if (!this.context.loaded) {
            throw new Error("Cannot form network before state is loaded");
        }

        // TODO: sanity checks?
        await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, true));
        await this.setProperty(writePropertyC(SpinelPropertyId.PHY_CHAN, this.context.netParams.channel));

        // TODO: ?
        // try { await this.setPHYCCAThreshold(10); } catch (error) {}
        await this.setPHYTXPower(this.context.netParams.txPower);

        await this.setProperty(writePropertyE(SpinelPropertyId.MAC_15_4_LADDR, this.context.netParams.eui64));
        await this.setProperty(writePropertyS(SpinelPropertyId.MAC_15_4_SADDR, ZigbeeConsts.COORDINATOR_ADDRESS));
        await this.setProperty(writePropertyS(SpinelPropertyId.MAC_15_4_PANID, this.context.netParams.panId));

        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RX_ON_WHEN_IDLE_MODE, true));
        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RAW_STREAM_ENABLED, true));

        const txPower = await this.getPHYTXPower();
        const radioRSSI = await this.getPHYRSSI();
        this.context.rssiMin = await this.getPHYRXSensitivity();
        let ccaThreshold: number | undefined;

        try {
            ccaThreshold = await this.getPHYCCAThreshold();
        } catch (error) {
            logger.debug(() => `PHY_CCA_THRESHOLD: ${error}`, NS);
        }

        logger.info(
            `======== Network started (PHY: txPower=${txPower}dBm rssi=${radioRSSI}dBm rxSensitivity=${this.context.rssiMin}dBm ccaThreshold=${ccaThreshold}dBm) ========`,
            NS,
        );

        this.#networkUp = true;

        await this.startStack();
    }

    /**
     * Remove the current state file and clear all related tables.
     *
     * Will throw if state already loaded (should be called before `start`).
     */
    public async resetNetwork(): Promise<void> {
        logger.info("======== Network resetting ========", NS);

        if (this.context.loaded) {
            throw new Error("Cannot reset network after state already loaded");
        }

        await this.context.clear();
        this.context.pendingAssociations.clear();

        logger.info("======== Network reset ========", NS);
    }

    /**
     * Start the components of the Zigbee stack
     */
    public async startStack(): Promise<void> {
        await this.context.start();
        await this.macHandler.start();
        await this.nwkHandler.start();
        await this.nwkGPHandler.start();
        await this.apsHandler.start();
    }

    /**
     * Stop the components of the Zigbee stack
     */
    public stopStack(): void {
        this.apsHandler.stop();
        this.nwkGPHandler.stop();
        this.nwkHandler.stop();
        this.macHandler.stop();
        this.context.stop();
    }

    // TODO: interference detection (& optionally auto channel changing)

    // #endregion

    // #region Driver

    public async waitForReset(): Promise<void> {
        await new Promise<SpinelFrame>((resolve, reject) => {
            this.#resetWaiter = {
                timer: setTimeout(reject.bind(this, new Error("Reset timeout after 5000ms")), 5000),
                resolve,
            };
        });
    }

    /**
     * Get the basic info from the RCP firmware and reset it.
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#appendix-C.1
     *
     * Should be called before `formNetwork` but after `resetNetwork` (if needed)
     */
    public async start(): Promise<void> {
        logger.info("======== Driver starting ========", NS);
        await this.context.loadState();

        // flush
        this.writer.writeBuffer(Buffer.from([HdlcReservedByte.FLAG]));

        // Example output:
        //   Protocol version: 4.3
        //   NCP version: SL-OPENTHREAD/2.5.2.0_GitHub-1fceb225b; EFR32; Mar 19 2025 13:45:44
        //   Interface type: 3
        //   RCP API version: 10
        //   RCP min host API version: 4

        // check the protocol version to see if it is supported
        let response = await this.getProperty(SpinelPropertyId.PROTOCOL_VERSION);
        [this.#protocolVersionMajor, this.#protocolVersionMinor] = readPropertyii(SpinelPropertyId.PROTOCOL_VERSION, response.payload);

        logger.info(`Protocol version: ${this.#protocolVersionMajor}.${this.#protocolVersionMinor}`, NS);

        // check the NCP version to see if a firmware update may be necessary
        response = await this.getProperty(SpinelPropertyId.NCP_VERSION);
        // recommended format: STACK-NAME/STACK-VERSION[BUILD_INFO][; OTHER_INFO]; BUILD_DATE_AND_TIME
        this.#ncpVersion = readPropertyU(SpinelPropertyId.NCP_VERSION, response.payload).replaceAll("\u0000", "");

        logger.info(`NCP version: ${this.#ncpVersion}`, NS);

        // check interface type to make sure that it is what we expect
        response = await this.getProperty(SpinelPropertyId.INTERFACE_TYPE);
        this.#interfaceType = readPropertyi(SpinelPropertyId.INTERFACE_TYPE, response.payload);

        logger.info(`Interface type: ${this.#interfaceType}`, NS);

        response = await this.getProperty(SpinelPropertyId.RCP_API_VERSION);
        this.#rcpAPIVersion = readPropertyi(SpinelPropertyId.RCP_API_VERSION, response.payload);

        logger.info(`RCP API version: ${this.#rcpAPIVersion}`, NS);

        response = await this.getProperty(SpinelPropertyId.RCP_MIN_HOST_API_VERSION);
        this.#rcpMinHostAPIVersion = readPropertyi(SpinelPropertyId.RCP_MIN_HOST_API_VERSION, response.payload);

        logger.info(`RCP min host API version: ${this.#rcpMinHostAPIVersion}`, NS);

        await this.sendCommand(SpinelCommandId.RESET, Buffer.from([SpinelResetReason.STACK]), false);
        await this.waitForReset();

        logger.info("======== Driver started ========", NS);
    }

    public async stop(): Promise<void> {
        logger.info("======== Driver stopping ========", NS);

        const networkWasUp = this.#networkUp;
        // pre-emptive
        this.#networkUp = false;

        // TODO: clear all timeouts/intervals
        if (this.#resetWaiter?.timer) {
            clearTimeout(this.#resetWaiter.timer);
            this.#resetWaiter.timer = undefined;
            this.#resetWaiter = undefined;
        }

        this.stopStack();

        clearTimeout(this.#pendingChangeChannel);
        this.#pendingChangeChannel = undefined;

        for (const [, waiter] of this.#tidWaiters) {
            clearTimeout(waiter.timer);
            waiter.timer = undefined;

            waiter.reject(new Error("Driver stopping"));
        }

        this.#tidWaiters.clear();

        if (networkWasUp) {
            // TODO: proper spinel/radio shutdown?
            await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, false));
            await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RAW_STREAM_ENABLED, false));
        }

        await this.context.saveState();

        logger.info("======== Driver stopped ========", NS);
    }

    /**
     * Performs a STACK reset after resetting a few PHY/MAC properties to default.
     * If up, will stop network before.
     */
    public async resetStack(): Promise<void> {
        await this.setProperty(writePropertyC(SpinelPropertyId.MAC_SCAN_STATE, 0 /* SCAN_STATE_IDLE */));
        // await this.setProperty(writePropertyC(SpinelPropertyId.MAC_PROMISCUOUS_MODE, 0 /* MAC_PROMISCUOUS_MODE_OFF */));
        await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, false));
        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RAW_STREAM_ENABLED, false));

        if (this.#networkUp) {
            await this.stop();
        }

        await this.sendCommand(SpinelCommandId.RESET, Buffer.from([SpinelResetReason.STACK]), false);
        await this.waitForReset();
    }

    /**
     * Performs a software reset into bootloader.
     * If up, will stop network before.
     */
    public async resetIntoBootloader(): Promise<void> {
        if (this.#networkUp) {
            await this.stop();
        }

        await this.sendCommand(SpinelCommandId.RESET, Buffer.from([SpinelResetReason.BOOTLOADER]), false);
    }

    // #endregion

    // #region Wrappers

    /**
     * Wraps Zigbee APS DATA sending for ZDO.
     * Throws if could not send.
     * @param payload
     * @param nwkDest16
     * @param nwkDest64
     * @param clusterId
     * @returns
     * - The APS counter of the sent frame.
     * - The ZDO counter of the sent frame.
     */
    public async sendZDO(payload: Buffer, nwkDest16: number, nwkDest64: bigint | undefined, clusterId: number): Promise<[number, number]> {
        if (nwkDest16 === ZigbeeConsts.COORDINATOR_ADDRESS || nwkDest64 === this.context.netParams.eui64) {
            throw new Error("Cannot send ZDO to coordinator");
        }

        // increment and set the ZDO sequence number in outgoing payload
        const zdoCounter = this.apsHandler.nextZDOSeqNum();
        payload[0] = zdoCounter;

        logger.debug(() => `===> ZDO[seqNum=${payload[0]} clusterId=${clusterId} nwkDst=${nwkDest16}:${nwkDest64}]`, NS);

        if (clusterId === ZigbeeConsts.NWK_UPDATE_REQUEST && nwkDest16 >= ZigbeeConsts.BCAST_DEFAULT && payload[5] === 0xfe) {
            // TODO: needs testing
            this.context.netParams.channel = convertMaskToChannels(payload.readUInt32LE(1))[0];
            this.context.netParams.nwkUpdateId = payload[6];

            // force saving after net params change
            await this.context.savePeriodicState();

            this.#pendingChangeChannel = setTimeout(
                this.setProperty.bind(this, writePropertyC(SpinelPropertyId.PHY_CHAN, this.context.netParams.channel)),
                ZigbeeConsts.BCAST_TIME_WINDOW,
            );
        }

        const apsCounter = await this.apsHandler.sendData(
            payload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            nwkDest16, // nwkDest16
            nwkDest64, // nwkDest64
            nwkDest16 < ZigbeeConsts.BCAST_MIN ? ZigbeeAPSDeliveryMode.UNICAST : ZigbeeAPSDeliveryMode.BCAST, // apsDeliveryMode
            clusterId, // clusterId
            ZigbeeConsts.ZDO_PROFILE_ID, // profileId
            ZigbeeConsts.ZDO_ENDPOINT, // destEndpoint
            ZigbeeConsts.ZDO_ENDPOINT, // sourceEndpoint
            undefined, // group
        );

        return [apsCounter, zdoCounter];
    }

    /**
     * Wraps Zigbee APS DATA sending for unicast.
     * Throws if could not send.
     * @param payload
     * @param profileId
     * @param clusterId
     * @param dest16
     * @param dest64
     * @param destEp
     * @param sourceEp
     * @returns The APS counter of the sent frame.
     */
    public async sendUnicast(
        payload: Buffer,
        profileId: number,
        clusterId: number,
        dest16: number,
        dest64: bigint | undefined,
        destEp: number,
        sourceEp: number,
    ): Promise<number> {
        if (dest16 === ZigbeeConsts.COORDINATOR_ADDRESS || dest64 === this.context.netParams.eui64) {
            throw new Error("Cannot send unicast to coordinator");
        }

        return await this.apsHandler.sendData(
            payload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            dest16, // nwkDest16
            dest64, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            clusterId, // clusterId
            profileId, // profileId
            destEp, // destEndpoint
            sourceEp, // sourceEndpoint
            undefined, // group
        );
    }

    /**
     * Wraps Zigbee APS DATA sending for groupcast.
     * Throws if could not send.
     * @param payload
     * @param profileId
     * @param clusterId
     * @param group The group to send to
     * @param destEp
     * @param sourceEp
     * @returns The APS counter of the sent frame.
     */
    public async sendGroupcast(payload: Buffer, profileId: number, clusterId: number, group: number, sourceEp: number): Promise<number> {
        return await this.apsHandler.sendData(
            payload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            ZigbeeConsts.BCAST_RX_ON_WHEN_IDLE, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.GROUP, // apsDeliveryMode
            clusterId, // clusterId
            profileId, // profileId
            undefined, // destEndpoint
            sourceEp, // sourceEndpoint
            group, // group
        );
    }

    /**
     * Wraps Zigbee APS DATA sending for broadcast.
     * Throws if could not send.
     * @param payload
     * @param profileId
     * @param clusterId
     * @param dest16 The broadcast address to send to [0xfff8..0xffff]
     * @param destEp
     * @param sourceEp
     * @returns The APS counter of the sent frame.
     */
    public async sendBroadcast(
        payload: Buffer,
        profileId: number,
        clusterId: number,
        dest16: number,
        destEp: number,
        sourceEp: number,
    ): Promise<number> {
        if (dest16 < ZigbeeConsts.BCAST_MIN || dest16 > ZigbeeConsts.BCAST_SLEEPY) {
            throw new Error("Invalid parameters");
        }

        return await this.apsHandler.sendData(
            payload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            dest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.BCAST, // apsDeliveryMode
            clusterId, // clusterId
            profileId, // profileId
            destEp, // destEndpoint
            sourceEp, // sourceEndpoint
            undefined, // group
        );
    }

    // #endregion
}
