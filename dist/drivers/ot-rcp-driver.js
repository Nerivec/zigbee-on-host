"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OTRCPDriver = void 0;
const node_fs_1 = require("node:fs");
const node_path_1 = require("node:path");
const hdlc_js_1 = require("../spinel/hdlc.js");
const spinel_js_1 = require("../spinel/spinel.js");
const statuses_js_1 = require("../spinel/statuses.js");
const logger_js_1 = require("../utils/logger.js");
const zigbee_js_1 = require("../zigbee/zigbee.js");
const aps_handler_js_1 = require("../zigbee-stack/aps-handler.js");
const frame_js_1 = require("../zigbee-stack/frame.js");
const mac_handler_js_1 = require("../zigbee-stack/mac-handler.js");
const nwk_gp_handler_js_1 = require("../zigbee-stack/nwk-gp-handler.js");
const nwk_handler_js_1 = require("../zigbee-stack/nwk-handler.js");
const stack_context_js_1 = require("../zigbee-stack/stack-context.js");
const ot_rcp_parser_js_1 = require("./ot-rcp-parser.js");
const ot_rcp_writer_js_1 = require("./ot-rcp-writer.js");
const NS = "ot-rcp-driver";
// const SPINEL_FRAME_MAX_SIZE = 1300;
// const SPINEL_FRAME_MAX_COMMAND_HEADER_SIZE = 4;
// const SPINEL_FRAME_MAX_COMMAND_PAYLOAD_SIZE = SPINEL_FRAME_MAX_SIZE - SPINEL_FRAME_MAX_COMMAND_HEADER_SIZE;
// const SPINEL_ENCRYPTER_EXTRA_DATA_SIZE = 0;
// const SPINEL_FRAME_BUFFER_SIZE = SPINEL_FRAME_MAX_SIZE + SPINEL_ENCRYPTER_EXTRA_DATA_SIZE;
const CONFIG_TID_MASK = 0x0e;
const CONFIG_HIGHWATER_MARK = hdlc_js_1.HDLC_TX_CHUNK_SIZE * 4;
class OTRCPDriver {
    #onMACFrame;
    #streamRawConfig;
    writer = new ot_rcp_writer_js_1.OTRCPWriter({ highWaterMark: CONFIG_HIGHWATER_MARK });
    parser = new ot_rcp_parser_js_1.OTRCPParser({ readableHighWaterMark: CONFIG_HIGHWATER_MARK });
    #protocolVersionMajor = 0;
    #protocolVersionMinor = 0;
    #ncpVersion = "";
    #interfaceType = 0;
    #rcpAPIVersion = 0;
    #rcpMinHostAPIVersion = 0;
    /** Centralized stack context holding all shared state */
    context;
    /** MAC layer handler */
    macHandler;
    /** NWK layer handler */
    nwkHandler;
    /** APS layer handler */
    apsHandler;
    /** NWK GP layer handler */
    nwkGPHandler;
    /**
     * Transaction ID used in Spinel frame
     *
     * NOTE: 0 is used for "no response expected/needed" (e.g. unsolicited update commands from NCP to host)
     */
    #spinelTID = -1; // start at 0 but effectively 1 returned by first `nextSpinelTID` call
    /** If defined, indicates we're waiting for the property with the specific payload to come in */
    #resetWaiter;
    /** TID currently being awaited */
    #tidWaiters = new Map();
    #networkUp = false;
    #pendingChangeChannel;
    constructor(callbacks, streamRawConfig, netParams, saveDir, emitMACFrames = false) {
        /* v8 ignore else -- @preserve */
        if (!(0, node_fs_1.existsSync)(saveDir)) {
            (0, node_fs_1.mkdirSync)(saveDir);
        }
        this.#onMACFrame = callbacks.onMACFrame;
        this.#streamRawConfig = streamRawConfig;
        const contextCallbacks = {
            onDeviceLeft: callbacks.onDeviceLeft,
        };
        this.context = new stack_context_js_1.StackContext(contextCallbacks, (0, node_path_1.join)(saveDir, "zoh.save"), netParams);
        const macCallbacks = {
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
        this.macHandler = new mac_handler_js_1.MACHandler(this.context, macCallbacks, statuses_js_1.SpinelStatus.NO_ACK, emitMACFrames);
        const nwkCallbacks = {
            onAPSSendTransportKeyNWK: async (address16, key, keySeqNum, destination64) => {
                await this.apsHandler.sendTransportKeyNWK(address16, key, keySeqNum, destination64);
            },
        };
        this.nwkHandler = new nwk_handler_js_1.NWKHandler(this.context, this.macHandler, nwkCallbacks);
        const apsCallbacks = {
            onFrame: callbacks.onFrame,
            onDeviceJoined: callbacks.onDeviceJoined,
            onDeviceRejoined: callbacks.onDeviceRejoined,
            onDeviceAuthorized: callbacks.onDeviceAuthorized,
        };
        this.apsHandler = new aps_handler_js_1.APSHandler(this.context, this.macHandler, this.nwkHandler, apsCallbacks);
        // Setup NWK GP handler callbacks
        const nwkGPCallbacks = {
            onGPFrame: callbacks.onGPFrame,
        };
        this.nwkGPHandler = new nwk_gp_handler_js_1.NWKGPHandler(nwkGPCallbacks);
    }
    // #region Getters/Setters
    get protocolVersionMajor() {
        return this.#protocolVersionMajor;
    }
    get protocolVersionMinor() {
        return this.#protocolVersionMinor;
    }
    get ncpVersion() {
        return this.#ncpVersion;
    }
    get interfaceType() {
        return this.#interfaceType;
    }
    get rcpAPIVersion() {
        return this.#rcpAPIVersion;
    }
    get rcpMinHostAPIVersion() {
        return this.#rcpMinHostAPIVersion;
    }
    get currentSpinelTID() {
        return this.#spinelTID + 1;
    }
    // #endregion
    // #region TIDs/counters
    /**
     * @returns increased TID offsetted by +1. [1-14] range for the "actually-used" value (0 is reserved)
     */
    nextSpinelTID() {
        this.#spinelTID = (this.#spinelTID + 1) % CONFIG_TID_MASK;
        return this.#spinelTID + 1;
    }
    // #endregion
    // #region HDLC/Spinel
    async waitForTID(tid, timeout) {
        return await new Promise((resolve, reject) => {
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
    async onStreamRawFrame(payload, metadata) {
        if (!this.#networkUp) {
            return;
        }
        // Emit MAC frames if listeners registered (not in hot path for normal operation)
        if (this.macHandler.emitFrames) {
            setImmediate(() => {
                this.#onMACFrame(payload, metadata?.rssi);
            });
        }
        // Metadata logging
        if (metadata) {
            logger_js_1.logger.debug(() => `<--- SPINEL STREAM_RAW METADATA[rssi=${metadata.rssi} noiseFloor=${metadata.noiseFloor} flags=${metadata.flags}]`, NS);
        }
        try {
            await (0, frame_js_1.processFrame)(payload, this.context, this.macHandler, this.nwkHandler, this.nwkGPHandler, this.apsHandler, metadata?.rssi);
        }
        catch (error) {
            // TODO log or throw depending on error
            logger_js_1.logger.error(error.stack, NS);
        }
    }
    async onFrame(buffer) {
        const hdlcFrame = (0, hdlc_js_1.decodeHdlcFrame)(buffer);
        // logger.debug(() => `<--- HDLC[length=${hdlcFrame.length}]`, NS);
        const spinelFrame = (0, spinel_js_1.decodeSpinelFrame)(hdlcFrame);
        /* v8 ignore if -- @preserve */
        if (spinelFrame.header.flg !== spinel_js_1.SPINEL_HEADER_FLG_SPINEL) {
            // non-Spinel frame (likely BLE HCI)
            return;
        }
        logger_js_1.logger.debug(() => `<--- SPINEL[tid=${spinelFrame.header.tid} cmdId=${spinelFrame.commandId} len=${spinelFrame.payload.byteLength}]`, NS);
        // resolve waiter if any (never for tid===0 since unsolicited frames)
        const waiter = spinelFrame.header.tid > 0 ? this.#tidWaiters.get(spinelFrame.header.tid) : undefined;
        let status = statuses_js_1.SpinelStatus.OK;
        if (waiter) {
            clearTimeout(waiter.timer);
        }
        /* v8 ignore else -- @preserve */
        if (spinelFrame.commandId === 6 /* SpinelCommandId.PROP_VALUE_IS */) {
            const [propId, pOffset] = (0, spinel_js_1.getPackedUInt)(spinelFrame.payload, 0);
            switch (propId) {
                case 113 /* SpinelPropertyId.STREAM_RAW */: {
                    const [macData, metadata] = (0, spinel_js_1.readStreamRaw)(spinelFrame.payload, pOffset);
                    await this.onStreamRawFrame(macData, metadata);
                    break;
                }
                case 0 /* SpinelPropertyId.LAST_STATUS */: {
                    [status] = (0, spinel_js_1.getPackedUInt)(spinelFrame.payload, pOffset);
                    // verbose, waiter will provide feedback
                    // logger.debug(() => `<--- SPINEL LAST_STATUS[${SpinelStatus[status]}]`, NS);
                    // TODO: getting RESET_POWER_ON after RESET instead of RESET_SOFTWARE??
                    if (this.#resetWaiter && (status === statuses_js_1.SpinelStatus.RESET_SOFTWARE || status === statuses_js_1.SpinelStatus.RESET_POWER_ON)) {
                        clearTimeout(this.#resetWaiter.timer);
                        this.#resetWaiter.resolve(spinelFrame);
                        this.#resetWaiter = undefined;
                    }
                    break;
                }
                case 57 /* SpinelPropertyId.MAC_ENERGY_SCAN_RESULT */: {
                    // https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.10
                    let resultOffset = pOffset;
                    const channel = spinelFrame.payload.readUInt8(resultOffset);
                    resultOffset += 1;
                    const rssi = spinelFrame.payload.readInt8(resultOffset);
                    resultOffset += 1;
                    logger_js_1.logger.info(`<=== ENERGY_SCAN[channel=${channel} rssi=${rssi}]`, NS);
                    break;
                }
            }
        }
        if (waiter) {
            if (status === statuses_js_1.SpinelStatus.OK) {
                waiter.resolve(spinelFrame);
            }
            else {
                waiter.reject(new Error(`Failed with status=${statuses_js_1.SpinelStatus[status]}`, { cause: status }));
            }
        }
        this.#tidWaiters.delete(spinelFrame.header.tid);
    }
    async sendCommand(commandId, buffer, waitForResponse = true, timeout = 10000) {
        const tid = this.nextSpinelTID();
        logger_js_1.logger.debug(() => `---> SPINEL[tid=${tid} cmdId=${commandId} len=${buffer.byteLength} wait=${waitForResponse} timeout=${timeout}]`, NS);
        const spinelFrame = {
            header: {
                tid,
                nli: 0,
                flg: spinel_js_1.SPINEL_HEADER_FLG_SPINEL,
            },
            commandId,
            payload: buffer,
        };
        const hdlcFrame = (0, spinel_js_1.encodeSpinelFrame)(spinelFrame);
        // only send what is recorded as "data" (by length)
        this.writer.writeBuffer(hdlcFrame.data.subarray(0, hdlcFrame.length));
        if (waitForResponse) {
            return await this.waitForTID(spinelFrame.header.tid, timeout);
        }
    }
    async getProperty(propertyId, timeout = 10000) {
        const [data] = (0, spinel_js_1.writePropertyId)(propertyId, 0);
        return await this.sendCommand(2 /* SpinelCommandId.PROP_VALUE_GET */, data, true, timeout);
    }
    async setProperty(payload, timeout = 10000) {
        // LAST_STATUS checked in `onFrame`
        await this.sendCommand(3 /* SpinelCommandId.PROP_VALUE_SET */, payload, true, timeout);
    }
    async sendStreamRaw(payload) {
        await this.setProperty((0, spinel_js_1.writePropertyStreamRaw)(payload, this.#streamRawConfig));
    }
    /**
     * @returns [SPINEL_PROTOCOL_VERSION_THREAD_MAJOR, SPINEL_PROTOCOL_VERSION_THREAD_MINOR]
     */
    async getProtocolVersion() {
        const response = await this.getProperty(1 /* SpinelPropertyId.PROTOCOL_VERSION */);
        return (0, spinel_js_1.readPropertyii)(1 /* SpinelPropertyId.PROTOCOL_VERSION */, response.payload);
    }
    /**
     * Recommended format: STACK-NAME/STACK-VERSION[BUILD_INFO][; OTHER_INFO]; BUILD_DATE_AND_TIME
     * Encoded as a zero-terminated UTF-8 string.
     */
    async getNCPVersion() {
        const response = await this.getProperty(2 /* SpinelPropertyId.NCP_VERSION */);
        return (0, spinel_js_1.readPropertyU)(2 /* SpinelPropertyId.NCP_VERSION */, response.payload).replaceAll("\u0000", "");
    }
    /**
     * @returns SPINEL_PROTOCOL_TYPE_*
     */
    async getInterfaceType() {
        const response = await this.getProperty(3 /* SpinelPropertyId.INTERFACE_TYPE */);
        return (0, spinel_js_1.readPropertyi)(3 /* SpinelPropertyId.INTERFACE_TYPE */, response.payload);
    }
    async getRCPAPIVersion() {
        const response = await this.getProperty(176 /* SpinelPropertyId.RCP_API_VERSION */);
        return (0, spinel_js_1.readPropertyi)(176 /* SpinelPropertyId.RCP_API_VERSION */, response.payload);
    }
    async getRCPMinHostAPIVersion() {
        const response = await this.getProperty(177 /* SpinelPropertyId.RCP_MIN_HOST_API_VERSION */);
        return (0, spinel_js_1.readPropertyi)(177 /* SpinelPropertyId.RCP_MIN_HOST_API_VERSION */, response.payload);
    }
    /**
     * The CCA (clear-channel assessment) threshold.
     * NOTE: Currently not implemented in: ot-ti
     * @returns dBm (int8)
     */
    async getPHYCCAThreshold() {
        const response = await this.getProperty(36 /* SpinelPropertyId.PHY_CCA_THRESHOLD */);
        return (0, spinel_js_1.readPropertyc)(36 /* SpinelPropertyId.PHY_CCA_THRESHOLD */, response.payload);
    }
    /**
     * The CCA (clear-channel assessment) threshold.
     * Set to -128 to disable.
     * The value will be rounded down to a value that is supported by the underlying radio hardware.
     * NOTE: Currently not implemented in: ot-ti
     * @param ccaThreshold dBm (>= -128 and <= 127)
     */
    async setPHYCCAThreshold(ccaThreshold) {
        await this.setProperty((0, spinel_js_1.writePropertyc)(36 /* SpinelPropertyId.PHY_CCA_THRESHOLD */, Math.min(Math.max(ccaThreshold, -128), 127)));
    }
    /**
     * The transmit power of the radio.
     * @returns dBm (int8)
     */
    async getPHYTXPower() {
        const response = await this.getProperty(37 /* SpinelPropertyId.PHY_TX_POWER */);
        return (0, spinel_js_1.readPropertyc)(37 /* SpinelPropertyId.PHY_TX_POWER */, response.payload);
    }
    /**
     * The transmit power of the radio.
     * The value will be rounded down to a value that is supported by the underlying radio hardware.
     * @param txPower dBm (>= -128 and <= 127)
     */
    async setPHYTXPower(txPower) {
        await this.setProperty((0, spinel_js_1.writePropertyc)(37 /* SpinelPropertyId.PHY_TX_POWER */, Math.min(Math.max(txPower, -128), 127)));
    }
    /**
     * The current RSSI (Received signal strength indication) from the radio.
     * This value can be used in energy scans and for determining the ambient noise floor for the operating environment.
     * @returns dBm (int8)
     */
    async getPHYRSSI() {
        const response = await this.getProperty(38 /* SpinelPropertyId.PHY_RSSI */);
        return (0, spinel_js_1.readPropertyc)(38 /* SpinelPropertyId.PHY_RSSI */, response.payload);
    }
    /**
     * The radio receive sensitivity.
     * This value can be used as lower bound noise floor for link metrics computation.
     * @returns dBm (int8)
     */
    async getPHYRXSensitivity() {
        const response = await this.getProperty(39 /* SpinelPropertyId.PHY_RX_SENSITIVITY */);
        return (0, spinel_js_1.readPropertyc)(39 /* SpinelPropertyId.PHY_RX_SENSITIVITY */, response.payload);
    }
    /**
     * Start an energy scan.
     * Cannot be used after state is loaded or network is up.
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.1
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.10
     * @param channels List of channels to scan
     * @param period milliseconds per channel
     * @param txPower
     */
    async startEnergyScan(channels, period, txPower) {
        if (this.context.loaded || this.#networkUp) {
            return;
        }
        const radioRSSI = await this.getPHYRSSI();
        const rxSensitivity = await this.getPHYRXSensitivity();
        logger_js_1.logger.info(`PHY state: rssi=${radioRSSI} rxSensitivity=${rxSensitivity}`, NS);
        await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, true));
        await this.setPHYTXPower(txPower);
        await this.setProperty((0, spinel_js_1.writePropertyb)(59 /* SpinelPropertyId.MAC_RX_ON_WHEN_IDLE_MODE */, true));
        await this.setProperty((0, spinel_js_1.writePropertyAC)(49 /* SpinelPropertyId.MAC_SCAN_MASK */, channels));
        await this.setProperty((0, spinel_js_1.writePropertyS)(50 /* SpinelPropertyId.MAC_SCAN_PERIOD */, period));
        await this.setProperty((0, spinel_js_1.writePropertyC)(48 /* SpinelPropertyId.MAC_SCAN_STATE */, 2 /* SCAN_STATE_ENERGY */));
    }
    async stopEnergyScan() {
        await this.setProperty((0, spinel_js_1.writePropertyS)(50 /* SpinelPropertyId.MAC_SCAN_PERIOD */, 100));
        await this.setProperty((0, spinel_js_1.writePropertyC)(48 /* SpinelPropertyId.MAC_SCAN_STATE */, 0 /* SCAN_STATE_IDLE */));
        await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, false));
    }
    /**
     * Start sniffing.
     * Cannot be used after state is loaded or network is up.
     * WARNING: This is expected to run in the "run-and-quit" pattern as it overrides the `onStreamRawFrame` function.
     * @param channel The channel to sniff on
     */
    async startSniffer(channel) {
        if (this.context.loaded || this.#networkUp) {
            return;
        }
        await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, true));
        await this.setProperty((0, spinel_js_1.writePropertyC)(33 /* SpinelPropertyId.PHY_CHAN */, channel));
        // 0 => MAC_PROMISCUOUS_MODE_OFF" => Normal MAC filtering is in place.
        // 1 => MAC_PROMISCUOUS_MODE_NETWORK" => All MAC packets matching network are passed up the stack.
        // 2 => MAC_PROMISCUOUS_MODE_FULL" => All decoded MAC packets are passed up the stack.
        await this.setProperty((0, spinel_js_1.writePropertyC)(56 /* SpinelPropertyId.MAC_PROMISCUOUS_MODE */, 2));
        await this.setProperty((0, spinel_js_1.writePropertyb)(59 /* SpinelPropertyId.MAC_RX_ON_WHEN_IDLE_MODE */, true));
        await this.setProperty((0, spinel_js_1.writePropertyb)(55 /* SpinelPropertyId.MAC_RAW_STREAM_ENABLED */, true));
        // override `onStreamRawFrame` behavior for sniff
        this.onStreamRawFrame = async (payload, metadata) => {
            this.#onMACFrame(payload, metadata?.rssi);
            await Promise.resolve();
        };
    }
    async stopSniffer() {
        await this.setProperty((0, spinel_js_1.writePropertyC)(56 /* SpinelPropertyId.MAC_PROMISCUOUS_MODE */, 0));
        await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, false)); // first, avoids BUSY signal
        await this.setProperty((0, spinel_js_1.writePropertyb)(55 /* SpinelPropertyId.MAC_RAW_STREAM_ENABLED */, false));
    }
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
    get isNetworkUp() {
        return this.#networkUp;
    }
    /**
     * Set the Spinel properties required to start a 802.15.4 MAC network.
     *
     * Should be called after `start`.
     */
    async formNetwork() {
        logger_js_1.logger.info("======== Network starting ========", NS);
        if (!this.context.loaded) {
            throw new Error("Cannot form network before state is loaded");
        }
        // TODO: sanity checks?
        await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, true));
        await this.setProperty((0, spinel_js_1.writePropertyC)(33 /* SpinelPropertyId.PHY_CHAN */, this.context.netParams.channel));
        // TODO: ?
        // try { await this.setPHYCCAThreshold(10); } catch (error) {}
        await this.setPHYTXPower(this.context.netParams.txPower);
        await this.setProperty((0, spinel_js_1.writePropertyE)(52 /* SpinelPropertyId.MAC_15_4_LADDR */, this.context.netParams.eui64));
        await this.setProperty((0, spinel_js_1.writePropertyS)(53 /* SpinelPropertyId.MAC_15_4_SADDR */, 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */));
        await this.setProperty((0, spinel_js_1.writePropertyS)(54 /* SpinelPropertyId.MAC_15_4_PANID */, this.context.netParams.panId));
        await this.setProperty((0, spinel_js_1.writePropertyb)(59 /* SpinelPropertyId.MAC_RX_ON_WHEN_IDLE_MODE */, true));
        await this.setProperty((0, spinel_js_1.writePropertyb)(55 /* SpinelPropertyId.MAC_RAW_STREAM_ENABLED */, true));
        const txPower = await this.getPHYTXPower();
        const radioRSSI = await this.getPHYRSSI();
        this.context.rssiMin = await this.getPHYRXSensitivity();
        let ccaThreshold;
        try {
            ccaThreshold = await this.getPHYCCAThreshold();
        }
        catch (error) {
            logger_js_1.logger.debug(() => `PHY_CCA_THRESHOLD: ${error}`, NS);
        }
        logger_js_1.logger.info(`======== Network started (PHY: txPower=${txPower}dBm rssi=${radioRSSI}dBm rxSensitivity=${this.context.rssiMin}dBm ccaThreshold=${ccaThreshold}dBm) ========`, NS);
        await this.startStack();
        this.#networkUp = true;
    }
    /**
     * Remove the current state file and clear all related tables.
     *
     * Will throw if state already loaded (should be called before `start`).
     */
    async resetNetwork() {
        logger_js_1.logger.info("======== Network resetting ========", NS);
        if (this.context.loaded) {
            throw new Error("Cannot reset network after state already loaded");
        }
        await this.context.clear();
        logger_js_1.logger.info("======== Network reset ========", NS);
    }
    /**
     * Start the components of the Zigbee stack
     */
    async startStack() {
        await this.context.start();
        await this.macHandler.start();
        await this.nwkHandler.start();
        await this.nwkGPHandler.start();
        await this.apsHandler.start();
    }
    /**
     * Stop the components of the Zigbee stack
     */
    stopStack() {
        this.apsHandler.stop();
        this.nwkGPHandler.stop();
        this.nwkHandler.stop();
        this.macHandler.stop();
        this.context.stop();
    }
    // TODO: interference detection (& optionally auto channel changing)
    // #endregion
    // #region Driver
    async waitForReset() {
        await new Promise((resolve, reject) => {
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
    async start() {
        logger_js_1.logger.info("======== Driver starting ========", NS);
        await this.context.loadState();
        // flush
        this.writer.writeBuffer(Buffer.from([126 /* HdlcReservedByte.FLAG */]));
        // Example output:
        //   Protocol version: 4.3
        //   NCP version: SL-OPENTHREAD/2.5.2.0_GitHub-1fceb225b; EFR32; Mar 19 2025 13:45:44
        //   Interface type: 3
        //   RCP API version: 10
        //   RCP min host API version: 4
        // check the protocol version to see if it is supported
        [this.#protocolVersionMajor, this.#protocolVersionMinor] = await this.getProtocolVersion();
        logger_js_1.logger.info(`Protocol version: ${this.#protocolVersionMajor}.${this.#protocolVersionMinor}`, NS);
        // check the NCP version to see if a firmware update may be necessary
        this.#ncpVersion = await this.getNCPVersion();
        logger_js_1.logger.info(`NCP version: ${this.#ncpVersion}`, NS);
        // check interface type to make sure that it is what we expect
        this.#interfaceType = await this.getInterfaceType();
        logger_js_1.logger.info(`Interface type: ${this.#interfaceType}`, NS);
        this.#rcpAPIVersion = await this.getRCPAPIVersion();
        logger_js_1.logger.info(`RCP API version: ${this.#rcpAPIVersion}`, NS);
        this.#rcpMinHostAPIVersion = await this.getRCPMinHostAPIVersion();
        logger_js_1.logger.info(`RCP min host API version: ${this.#rcpMinHostAPIVersion}`, NS);
        await this.sendCommand(1 /* SpinelCommandId.RESET */, Buffer.from([2 /* SpinelResetReason.STACK */]), false);
        await this.waitForReset();
        logger_js_1.logger.info("======== Driver started ========", NS);
    }
    async stop() {
        logger_js_1.logger.info("======== Driver stopping ========", NS);
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
            await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, false));
            await this.setProperty((0, spinel_js_1.writePropertyb)(55 /* SpinelPropertyId.MAC_RAW_STREAM_ENABLED */, false));
        }
        await this.context.saveState();
        logger_js_1.logger.info("======== Driver stopped ========", NS);
    }
    /**
     * Performs a STACK reset after resetting a few PHY/MAC properties to default.
     * If up, will stop network before.
     */
    async resetStack() {
        await this.setProperty((0, spinel_js_1.writePropertyC)(48 /* SpinelPropertyId.MAC_SCAN_STATE */, 0 /* SCAN_STATE_IDLE */));
        // await this.setProperty(writePropertyC(SpinelPropertyId.MAC_PROMISCUOUS_MODE, 0 /* MAC_PROMISCUOUS_MODE_OFF */));
        await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, false));
        await this.setProperty((0, spinel_js_1.writePropertyb)(55 /* SpinelPropertyId.MAC_RAW_STREAM_ENABLED */, false));
        if (this.#networkUp) {
            await this.stop();
        }
        await this.sendCommand(1 /* SpinelCommandId.RESET */, Buffer.from([2 /* SpinelResetReason.STACK */]), false);
        await this.waitForReset();
    }
    /**
     * Performs a software reset into bootloader.
     * If up, will stop network before.
     */
    async resetIntoBootloader() {
        if (this.#networkUp) {
            await this.stop();
        }
        await this.sendCommand(1 /* SpinelCommandId.RESET */, Buffer.from([3 /* SpinelResetReason.BOOTLOADER */]), false);
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
    async sendZDO(payload, nwkDest16, nwkDest64, clusterId) {
        if (nwkDest16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ || nwkDest64 === this.context.netParams.eui64) {
            throw new Error("Cannot send ZDO to coordinator");
        }
        // increment and set the ZDO sequence number in outgoing payload
        const zdoCounter = this.apsHandler.nextZDOSeqNum();
        payload[0] = zdoCounter;
        logger_js_1.logger.debug(() => `===> ZDO[seqNum=${payload[0]} clusterId=${clusterId} nwkDst=${nwkDest16}:${nwkDest64}]`, NS);
        if (clusterId === 56 /* ZigbeeConsts.NWK_UPDATE_REQUEST */ && nwkDest16 >= 65532 /* ZigbeeConsts.BCAST_DEFAULT */ && payload[5] === 0xfe) {
            // TODO: needs testing
            this.context.netParams.channel = (0, zigbee_js_1.convertMaskToChannels)(payload.readUInt32LE(1))[0];
            this.context.netParams.nwkUpdateId = payload[6];
            // force saving after net params change
            await this.context.savePeriodicState();
            this.#pendingChangeChannel = setTimeout(this.setProperty.bind(this, (0, spinel_js_1.writePropertyC)(33 /* SpinelPropertyId.PHY_CHAN */, this.context.netParams.channel)), 9000 /* ZigbeeConsts.BCAST_TIME_WINDOW */);
        }
        const apsCounter = await this.apsHandler.sendData(payload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        nwkDest16, // nwkDest16
        nwkDest64, // nwkDest64
        nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ ? 0 /* ZigbeeAPSDeliveryMode.UNICAST */ : 2 /* ZigbeeAPSDeliveryMode.BCAST */, // apsDeliveryMode
        clusterId, // clusterId
        0 /* ZigbeeConsts.ZDO_PROFILE_ID */, // profileId
        0 /* ZigbeeConsts.ZDO_ENDPOINT */, // destEndpoint
        0 /* ZigbeeConsts.ZDO_ENDPOINT */, // sourceEndpoint
        undefined);
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
    async sendUnicast(payload, profileId, clusterId, dest16, dest64, destEp, sourceEp) {
        if (dest16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ || dest64 === this.context.netParams.eui64) {
            throw new Error("Cannot send unicast to coordinator");
        }
        return await this.apsHandler.sendData(payload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        dest16, // nwkDest16
        dest64, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        clusterId, // clusterId
        profileId, // profileId
        destEp, // destEndpoint
        sourceEp, // sourceEndpoint
        undefined);
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
    async sendGroupcast(payload, profileId, clusterId, group, sourceEp) {
        return await this.apsHandler.sendData(payload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        65533 /* ZigbeeConsts.BCAST_RX_ON_WHEN_IDLE */, // nwkDest16
        undefined, // nwkDest64
        3 /* ZigbeeAPSDeliveryMode.GROUP */, // apsDeliveryMode
        clusterId, // clusterId
        profileId, // profileId
        undefined, // destEndpoint
        sourceEp, // sourceEndpoint
        group);
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
    async sendBroadcast(payload, profileId, clusterId, dest16, destEp, sourceEp) {
        if (dest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ || dest16 > 65535 /* ZigbeeConsts.BCAST_SLEEPY */) {
            throw new Error("Invalid parameters");
        }
        return await this.apsHandler.sendData(payload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        dest16, // nwkDest16
        undefined, // nwkDest64
        2 /* ZigbeeAPSDeliveryMode.BCAST */, // apsDeliveryMode
        clusterId, // clusterId
        profileId, // profileId
        destEp, // destEndpoint
        sourceEp, // sourceEndpoint
        undefined);
    }
}
exports.OTRCPDriver = OTRCPDriver;
//# sourceMappingURL=ot-rcp-driver.js.map