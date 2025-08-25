"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OTRCPDriver = exports.NetworkKeyUpdateMethod = exports.ApplicationKeyRequestPolicy = exports.TrustCenterKeyRequestPolicy = exports.InstallCodePolicy = void 0;
const node_events_1 = __importDefault(require("node:events"));
const node_fs_1 = require("node:fs");
const promises_1 = require("node:fs/promises");
const node_path_1 = require("node:path");
const hdlc_js_1 = require("../spinel/hdlc.js");
const spinel_js_1 = require("../spinel/spinel.js");
const statuses_js_1 = require("../spinel/statuses.js");
const logger_js_1 = require("../utils/logger.js");
const mac_js_1 = require("../zigbee/mac.js");
const zigbee_js_1 = require("../zigbee/zigbee.js");
const zigbee_aps_js_1 = require("../zigbee/zigbee-aps.js");
const zigbee_nwk_js_1 = require("../zigbee/zigbee-nwk.js");
const zigbee_nwkgp_js_1 = require("../zigbee/zigbee-nwkgp.js");
const descriptors_js_1 = require("./descriptors.js");
const ot_rcp_parser_js_1 = require("./ot-rcp-parser.js");
const ot_rcp_writer_js_1 = require("./ot-rcp-writer.js");
const NS = "ot-rcp-driver";
var InstallCodePolicy;
(function (InstallCodePolicy) {
    /** Do not support Install Codes */
    InstallCodePolicy[InstallCodePolicy["NOT_SUPPORTED"] = 0] = "NOT_SUPPORTED";
    /** Support but do not require use of Install Codes or preset passphrases */
    InstallCodePolicy[InstallCodePolicy["NOT_REQUIRED"] = 1] = "NOT_REQUIRED";
    /** Require the use of Install Codes by joining devices or preset Passphrases */
    InstallCodePolicy[InstallCodePolicy["REQUIRED"] = 2] = "REQUIRED";
})(InstallCodePolicy || (exports.InstallCodePolicy = InstallCodePolicy = {}));
var TrustCenterKeyRequestPolicy;
(function (TrustCenterKeyRequestPolicy) {
    TrustCenterKeyRequestPolicy[TrustCenterKeyRequestPolicy["DISALLOWED"] = 0] = "DISALLOWED";
    /** Any device MAY request */
    TrustCenterKeyRequestPolicy[TrustCenterKeyRequestPolicy["ALLOWED"] = 1] = "ALLOWED";
    /** Only devices in the apsDeviceKeyPairSet with a KeyAttribute value of PROVISIONAL_KEY MAY request. */
    TrustCenterKeyRequestPolicy[TrustCenterKeyRequestPolicy["ONLY_PROVISIONAL"] = 2] = "ONLY_PROVISIONAL";
})(TrustCenterKeyRequestPolicy || (exports.TrustCenterKeyRequestPolicy = TrustCenterKeyRequestPolicy = {}));
var ApplicationKeyRequestPolicy;
(function (ApplicationKeyRequestPolicy) {
    ApplicationKeyRequestPolicy[ApplicationKeyRequestPolicy["DISALLOWED"] = 0] = "DISALLOWED";
    /** Any device MAY request an application link key with any device (except the Trust Center) */
    ApplicationKeyRequestPolicy[ApplicationKeyRequestPolicy["ALLOWED"] = 1] = "ALLOWED";
    /** Only those devices listed in applicationKeyRequestList MAY request and receive application link keys. */
    ApplicationKeyRequestPolicy[ApplicationKeyRequestPolicy["ONLY_APPROVED"] = 2] = "ONLY_APPROVED";
})(ApplicationKeyRequestPolicy || (exports.ApplicationKeyRequestPolicy = ApplicationKeyRequestPolicy = {}));
var NetworkKeyUpdateMethod;
(function (NetworkKeyUpdateMethod) {
    /** Broadcast using only network encryption */
    NetworkKeyUpdateMethod[NetworkKeyUpdateMethod["BROADCAST"] = 0] = "BROADCAST";
    /** Unicast using network encryption and APS encryption with a device’s link key. */
    NetworkKeyUpdateMethod[NetworkKeyUpdateMethod["UNICAST"] = 1] = "UNICAST";
})(NetworkKeyUpdateMethod || (exports.NetworkKeyUpdateMethod = NetworkKeyUpdateMethod = {}));
// const SPINEL_FRAME_MAX_SIZE = 1300;
// const SPINEL_FRAME_MAX_COMMAND_HEADER_SIZE = 4;
// const SPINEL_FRAME_MAX_COMMAND_PAYLOAD_SIZE = SPINEL_FRAME_MAX_SIZE - SPINEL_FRAME_MAX_COMMAND_HEADER_SIZE;
// const SPINEL_ENCRYPTER_EXTRA_DATA_SIZE = 0;
// const SPINEL_FRAME_BUFFER_SIZE = SPINEL_FRAME_MAX_SIZE + SPINEL_ENCRYPTER_EXTRA_DATA_SIZE;
const CONFIG_TID_MASK = 0x0e;
const CONFIG_HIGHWATER_MARK = hdlc_js_1.HDLC_TX_CHUNK_SIZE * 4;
/** The number of OctetDurations until a route discovery expires. */
// const CONFIG_NWK_ROUTE_DISCOVERY_TIME = 0x4c4b4; // 0x2710 msec on 2.4GHz
/** The maximum depth of the network (number of hops) used for various calculations of network timing and limitations. */
const CONFIG_NWK_MAX_DEPTH = 15;
const CONFIG_NWK_MAX_HOPS = CONFIG_NWK_MAX_DEPTH * 2;
/** The number of network layer retries on unicast messages that are attempted before reporting the result to the higher layer. */
// const CONFIG_NWK_UNICAST_RETRIES = 3;
/** The delay between network layer retries. (ms) */
// const CONFIG_NWK_UNICAST_RETRY_DELAY = 50;
/** The total delivery time for a broadcast transmission to be delivered to all RxOnWhenIdle=TRUE devices in the network. (sec) */
// const CONFIG_NWK_BCAST_DELIVERY_TIME = 9;
/** The time between link status command frames (msec) */
const CONFIG_NWK_LINK_STATUS_PERIOD = 15000;
/** Avoid synchronization with other nodes by randomizing `CONFIG_NWK_LINK_STATUS_PERIOD` with this (msec) */
const CONFIG_NWK_LINK_STATUS_JITTER = 1000;
/** The number of missed link status command frames before resetting the link costs to zero. */
// const CONFIG_NWK_ROUTER_AGE_LIMIT = 3;
/** This is an index into Table 3-54. It indicates the default timeout in minutes for any end device that does not negotiate a different timeout value. */
// const CONFIG_NWK_END_DEVICE_TIMEOUT_DEFAULT = 8;
/** The time between concentrator route discoveries. (msec) */
const CONFIG_NWK_CONCENTRATOR_DISCOVERY_TIME = 60000;
/** The hop count radius for concentrator route discoveries. */
const CONFIG_NWK_CONCENTRATOR_RADIUS = CONFIG_NWK_MAX_HOPS;
/** The number of delivery failures that trigger an immediate concentrator route discoveries. */
const CONFIG_NWK_CONCENTRATOR_DELIVERY_FAILURE_THRESHOLD = 1;
/** The number of route failures that trigger an immediate concentrator route discoveries. */
const CONFIG_NWK_CONCENTRATOR_ROUTE_FAILURE_THRESHOLD = 3;
/** Minimum Time between MTORR broadcasts (msec) */
const CONFIG_NWK_CONCENTRATOR_MIN_TIME = 10000;
/** The time between state saving to disk. (msec) */
const CONFIG_SAVE_STATE_TIME = 60000;
class OTRCPDriver extends node_events_1.default {
    writer;
    parser;
    streamRawConfig;
    savePath;
    #emitMACFrames;
    #protocolVersionMajor = 0;
    #protocolVersionMinor = 0;
    #ncpVersion = "";
    #interfaceType = 0;
    #rcpAPIVersion = 0;
    #rcpMinHostAPIVersion = 0;
    /** The minimum observed RSSI */
    rssiMin = -100;
    /** The maximum observed RSSI */
    rssiMax = -25;
    /** The minimum observed LQI */
    lqiMin = 15;
    /** The maximum observed LQI */
    lqiMax = 250;
    /**
     * Transaction ID used in Spinel frame
     *
     * NOTE: 0 is used for "no response expected/needed" (e.g. unsolicited update commands from NCP to host)
     */
    #spinelTID;
    /** Sequence number used in outgoing MAC frames */
    #macSeqNum;
    /** Sequence number used in outgoing NWK frames */
    #nwkSeqNum;
    /** Counter used in outgoing APS frames */
    #apsCounter;
    /** Sequence number used in outgoing ZDO frames */
    #zdoSeqNum;
    /**
     * 8-bit sequence number for route requests. Incremented by 1 every time the NWK layer on a particular device issues a route request.
     */
    #routeRequestId;
    /** If defined, indicates we're waiting for the property with the specific payload to come in */
    #resetWaiter;
    /** TID currently being awaited */
    #tidWaiters;
    #stateLoaded;
    #networkUp;
    #saveStateTimeout;
    #pendingChangeChannel;
    #nwkLinkStatusTimeout;
    #manyToOneRouteRequestTimeout;
    /** Associations pending DATA_RQ from device. Mapping by network64 */
    pendingAssociations;
    /** Indirect transmission for devices with rxOnWhenIdle set to false. Mapping by network64 */
    indirectTransmissions;
    /** Count of MAC NO_ACK reported by Spinel for each device (only present if any). Mapping by network16 */
    macNoACKs;
    /** Count of route failures reported by the network for each device (only present if any). Mapping by network16 */
    routeFailures;
    //---- Trust Center (see 05-3474-R #4.7.1)
    #trustCenterPolicies;
    #macAssociationPermit;
    #allowJoinTimeout;
    //----- Green Power (see 14-0563-18)
    #gpCommissioningMode;
    #gpCommissioningWindowTimeout;
    #gpLastMACSequenceNumber;
    #gpLastSecurityFrameCounter;
    //---- NWK
    netParams;
    /** pre-computed hash of default TC link key for VERIFY_KEY. set by `loadState` */
    #tcVerifyKeyHash;
    /** Time of last many-to-one route request */
    #lastMTORRTime;
    /** Master table of all known devices on the network. mapping by network64 */
    deviceTable;
    /** Lookup synced with deviceTable, maps network address to IEEE address */
    address16ToAddress64;
    /** mapping by network16 */
    sourceRouteTable;
    // TODO: possibility of a route/sourceRoute blacklist?
    //---- APS
    /** mapping by network16 */
    // public readonly apsDeviceKeyPairSet: Map<number, APSDeviceKeyPairSet>;
    /** mapping by network16 */
    // public readonly apsBindingTable: Map<number, APSBindingTable>;
    //---- Attribute
    /** Several attributes are set by `loadState` */
    configAttributes;
    constructor(streamRawConfig, netParams, saveDir, emitMACFrames = false) {
        super();
        if (!(0, node_fs_1.existsSync)(saveDir)) {
            (0, node_fs_1.mkdirSync)(saveDir);
        }
        this.savePath = (0, node_path_1.join)(saveDir, "zoh.save");
        this.#emitMACFrames = emitMACFrames;
        this.streamRawConfig = streamRawConfig;
        this.writer = new ot_rcp_writer_js_1.OTRCPWriter({ highWaterMark: CONFIG_HIGHWATER_MARK });
        this.parser = new ot_rcp_parser_js_1.OTRCPParser({ readableHighWaterMark: CONFIG_HIGHWATER_MARK });
        this.#spinelTID = -1; // start at 0 but effectively 1 returned by first nextTID() call
        this.#resetWaiter = undefined;
        this.#tidWaiters = new Map();
        this.#macSeqNum = 0; // start at 1
        this.#nwkSeqNum = 0; // start at 1
        this.#apsCounter = 0; // start at 1
        this.#zdoSeqNum = 0; // start at 1
        this.#routeRequestId = 0; // start at 1
        this.#stateLoaded = false;
        this.#networkUp = false;
        this.pendingAssociations = new Map();
        this.indirectTransmissions = new Map();
        this.macNoACKs = new Map();
        this.routeFailures = new Map();
        //---- Trust Center
        this.#trustCenterPolicies = {
            allowJoins: false,
            installCode: InstallCodePolicy.NOT_REQUIRED,
            allowRejoinsWithWellKnownKey: true,
            allowTCKeyRequest: TrustCenterKeyRequestPolicy.ALLOWED,
            networkKeyUpdatePeriod: 0, // disable
            networkKeyUpdateMethod: NetworkKeyUpdateMethod.BROADCAST,
            allowAppKeyRequest: ApplicationKeyRequestPolicy.DISALLOWED,
            // appKeyRequestList: undefined,
            allowRemoteTCPolicyChange: false,
            allowVirtualDevices: false,
        };
        this.#macAssociationPermit = false;
        //---- Green Power
        this.#gpCommissioningMode = false;
        this.#gpLastMACSequenceNumber = -1;
        this.#gpLastSecurityFrameCounter = -1;
        //---- NWK
        this.netParams = netParams;
        this.#tcVerifyKeyHash = Buffer.alloc(0); // set by `loadState`
        this.#lastMTORRTime = 0;
        this.deviceTable = new Map();
        this.address16ToAddress64 = new Map();
        this.sourceRouteTable = new Map();
        //---- APS
        // this.apsDeviceKeyPairSet = new Map();
        // this.apsBindingTable = new Map();
        //---- Attributes
        this.configAttributes = {
            address: Buffer.alloc(0), // set by `loadState`
            nodeDescriptor: Buffer.alloc(0), // set by `loadState`
            powerDescriptor: Buffer.alloc(0), // set by `loadState`
            simpleDescriptors: Buffer.alloc(0), // set by `loadState`
            activeEndpoints: Buffer.alloc(0), // set by `loadState`
        };
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
    nextMACSeqNum() {
        this.#macSeqNum = (this.#macSeqNum + 1) & 0xff;
        return this.#macSeqNum;
    }
    nextNWKSeqNum() {
        this.#nwkSeqNum = (this.#nwkSeqNum + 1) & 0xff;
        return this.#nwkSeqNum;
    }
    nextAPSCounter() {
        this.#apsCounter = (this.#apsCounter + 1) & 0xff;
        return this.#apsCounter;
    }
    nextZDOSeqNum() {
        this.#zdoSeqNum = (this.#zdoSeqNum + 1) & 0xff;
        return this.#zdoSeqNum;
    }
    nextTCKeyFrameCounter() {
        this.netParams.tcKeyFrameCounter = (this.netParams.tcKeyFrameCounter + 1) & 0xffffffff;
        return this.netParams.tcKeyFrameCounter;
    }
    nextNWKKeyFrameCounter() {
        this.netParams.networkKeyFrameCounter = (this.netParams.networkKeyFrameCounter + 1) & 0xffffffff;
        return this.netParams.networkKeyFrameCounter;
    }
    nextRouteRequestId() {
        this.#routeRequestId = (this.#routeRequestId + 1) & 0xff;
        return this.#routeRequestId;
    }
    decrementRadius(radius) {
        // XXX: init at 29 when passed CONFIG_NWK_MAX_HOPS?
        return radius - 1 || 1;
    }
    // #endregion
    /**
     * Get the basic info from the RCP firmware and reset it.
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#appendix-C.1
     *
     * Should be called before `formNetwork` but after `resetNetwork` (if needed)
     */
    async start() {
        logger_js_1.logger.info("======== Driver starting ========", NS);
        await this.loadState();
        // flush
        this.writer.writeBuffer(Buffer.from([126 /* HdlcReservedByte.FLAG */]));
        // Example output:
        //   Protocol version: 4.3
        //   NCP version: SL-OPENTHREAD/2.5.2.0_GitHub-1fceb225b; EFR32; Mar 19 2025 13:45:44
        //   Interface type: 3
        //   RCP API version: 10
        //   RCP min host API version: 4
        // check the protocol version to see if it is supported
        let response = await this.getProperty(1 /* SpinelPropertyId.PROTOCOL_VERSION */);
        [this.#protocolVersionMajor, this.#protocolVersionMinor] = (0, spinel_js_1.readPropertyii)(1 /* SpinelPropertyId.PROTOCOL_VERSION */, response.payload);
        logger_js_1.logger.info(`Protocol version: ${this.#protocolVersionMajor}.${this.#protocolVersionMinor}`, NS);
        // check the NCP version to see if a firmware update may be necessary
        response = await this.getProperty(2 /* SpinelPropertyId.NCP_VERSION */);
        // recommended format: STACK-NAME/STACK-VERSION[BUILD_INFO][; OTHER_INFO]; BUILD_DATE_AND_TIME
        this.#ncpVersion = (0, spinel_js_1.readPropertyU)(2 /* SpinelPropertyId.NCP_VERSION */, response.payload).replaceAll("\u0000", "");
        logger_js_1.logger.info(`NCP version: ${this.#ncpVersion}`, NS);
        // check interface type to make sure that it is what we expect
        response = await this.getProperty(3 /* SpinelPropertyId.INTERFACE_TYPE */);
        this.#interfaceType = (0, spinel_js_1.readPropertyi)(3 /* SpinelPropertyId.INTERFACE_TYPE */, response.payload);
        logger_js_1.logger.info(`Interface type: ${this.#interfaceType}`, NS);
        response = await this.getProperty(176 /* SpinelPropertyId.RCP_API_VERSION */);
        this.#rcpAPIVersion = (0, spinel_js_1.readPropertyi)(176 /* SpinelPropertyId.RCP_API_VERSION */, response.payload);
        logger_js_1.logger.info(`RCP API version: ${this.#rcpAPIVersion}`, NS);
        response = await this.getProperty(177 /* SpinelPropertyId.RCP_MIN_HOST_API_VERSION */);
        this.#rcpMinHostAPIVersion = (0, spinel_js_1.readPropertyi)(177 /* SpinelPropertyId.RCP_MIN_HOST_API_VERSION */, response.payload);
        logger_js_1.logger.info(`RCP min host API version: ${this.#rcpMinHostAPIVersion}`, NS);
        await this.sendCommand(1 /* SpinelCommandId.RESET */, Buffer.from([2 /* SpinelResetReason.STACK */]), false);
        await this.waitForReset();
        logger_js_1.logger.info("======== Driver started ========", NS);
    }
    async stop() {
        logger_js_1.logger.info("======== Driver stopping ========", NS);
        this.disallowJoins();
        this.gpExitCommissioningMode();
        const networkWasUp = this.#networkUp;
        // pre-emptive
        this.#networkUp = false;
        // TODO: clear all timeouts/intervals
        if (this.#resetWaiter?.timer) {
            clearTimeout(this.#resetWaiter.timer);
            this.#resetWaiter.timer = undefined;
            this.#resetWaiter = undefined;
        }
        clearTimeout(this.#saveStateTimeout);
        this.#saveStateTimeout = undefined;
        clearTimeout(this.#nwkLinkStatusTimeout);
        this.#nwkLinkStatusTimeout = undefined;
        clearTimeout(this.#manyToOneRouteRequestTimeout);
        this.#manyToOneRouteRequestTimeout = undefined;
        clearTimeout(this.#pendingChangeChannel);
        this.#pendingChangeChannel = undefined;
        for (const [, waiter] of this.#tidWaiters) {
            clearTimeout(waiter.timer);
            waiter.timer = undefined;
            waiter.reject(new Error("Driver stopping", { cause: statuses_js_1.SpinelStatus.INVALID_STATE }));
        }
        this.#tidWaiters.clear();
        if (networkWasUp) {
            // TODO: proper spinel/radio shutdown?
            await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, false));
            await this.setProperty((0, spinel_js_1.writePropertyb)(55 /* SpinelPropertyId.MAC_RAW_STREAM_ENABLED */, false));
        }
        await this.saveState();
        logger_js_1.logger.info("======== Driver stopped ========", NS);
    }
    async waitForReset() {
        await new Promise((resolve, reject) => {
            this.#resetWaiter = {
                timer: setTimeout(reject.bind(this, new Error("Reset timeout after 5000ms", { cause: statuses_js_1.SpinelStatus.RESPONSE_TIMEOUT })), 5000),
                resolve,
            };
        });
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
    // #region HDLC/Spinel
    async onFrame(buffer) {
        const hdlcFrame = (0, hdlc_js_1.decodeHdlcFrame)(buffer);
        // logger.debug(() => `<--- HDLC[length=${hdlcFrame.length}]`, NS);
        const spinelFrame = (0, spinel_js_1.decodeSpinelFrame)(hdlcFrame);
        /* v8 ignore start */
        if (spinelFrame.header.flg !== spinel_js_1.SPINEL_HEADER_FLG_SPINEL) {
            // non-Spinel frame (likely BLE HCI)
            return;
        }
        /* v8 ignore stop */
        logger_js_1.logger.debug(() => `<--- SPINEL[tid=${spinelFrame.header.tid} cmdId=${spinelFrame.commandId} len=${spinelFrame.payload.byteLength}]`, NS);
        // resolve waiter if any (never for tid===0 since unsolicited frames)
        const waiter = spinelFrame.header.tid > 0 ? this.#tidWaiters.get(spinelFrame.header.tid) : undefined;
        let status = statuses_js_1.SpinelStatus.OK;
        if (waiter) {
            clearTimeout(waiter.timer);
        }
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
    /**
     * Logic optimizes code paths to try to avoid more parsing when frames will eventually get ignored by detecting as early as possible.
     */
    async onStreamRawFrame(payload, metadata) {
        // discard MAC frames before network is started
        if (!this.#networkUp) {
            return;
        }
        if (this.#emitMACFrames) {
            setImmediate(() => {
                this.emit("macFrame", payload, metadata?.rssi);
            });
        }
        try {
            const [macFCF, macFCFOutOffset] = (0, mac_js_1.decodeMACFrameControl)(payload, 0);
            // TODO: process BEACON for PAN ID conflict detection?
            if (macFCF.frameType !== 3 /* MACFrameType.CMD */ && macFCF.frameType !== 1 /* MACFrameType.DATA */) {
                logger_js_1.logger.debug(() => `<-~- MAC Ignoring frame with type not CMD/DATA (${macFCF.frameType})`, NS);
                return;
            }
            const [macHeader, macHOutOffset] = (0, mac_js_1.decodeMACHeader)(payload, macFCFOutOffset, macFCF);
            if (metadata) {
                logger_js_1.logger.debug(() => `<--- SPINEL STREAM_RAW METADATA[rssi=${metadata.rssi} noiseFloor=${metadata.noiseFloor} flags=${metadata.flags}]`, NS);
            }
            const macPayload = (0, mac_js_1.decodeMACPayload)(payload, macHOutOffset, macFCF, macHeader);
            if (macFCF.frameType === 3 /* MACFrameType.CMD */) {
                await this.processMACCommand(macPayload, macHeader);
                // done
                return;
            }
            if (macHeader.destinationPANId !== 65535 /* ZigbeeMACConsts.BCAST_PAN */ && macHeader.destinationPANId !== this.netParams.panId) {
                logger_js_1.logger.debug(() => `<-~- MAC Ignoring frame with mismatching PAN Id ${macHeader.destinationPANId}`, NS);
                return;
            }
            if (macFCF.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ &&
                macHeader.destination16 !== 65535 /* ZigbeeMACConsts.BCAST_ADDR */ &&
                macHeader.destination16 !== 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */) {
                logger_js_1.logger.debug(() => `<-~- MAC Ignoring frame intended for device ${macHeader.destination16}`, NS);
                return;
            }
            if (macPayload.byteLength > 0) {
                const protocolVersion = (macPayload.readUInt8(0) & 60 /* ZigbeeNWKConsts.FCF_VERSION */) >> 2;
                if (protocolVersion === 3 /* ZigbeeNWKConsts.VERSION_GREEN_POWER */) {
                    if ((macFCF.destAddrMode === 2 /* MACFrameAddressMode.SHORT */ && macHeader.destination16 === 65535 /* ZigbeeMACConsts.BCAST_ADDR */) ||
                        macFCF.destAddrMode === 3 /* MACFrameAddressMode.EXT */) {
                        const [nwkGPFCF, nwkGPFCFOutOffset] = (0, zigbee_nwkgp_js_1.decodeZigbeeNWKGPFrameControl)(macPayload, 0);
                        const [nwkGPHeader, nwkGPHOutOffset] = (0, zigbee_nwkgp_js_1.decodeZigbeeNWKGPHeader)(macPayload, nwkGPFCFOutOffset, nwkGPFCF);
                        if (nwkGPHeader.frameControl.frameType !== 0 /* ZigbeeNWKGPFrameType.DATA */ &&
                            nwkGPHeader.frameControl.frameType !== 1 /* ZigbeeNWKGPFrameType.MAINTENANCE */) {
                            logger_js_1.logger.debug(() => `<-~- NWKGP Ignoring frame with type ${nwkGPHeader.frameControl.frameType}`, NS);
                            return;
                        }
                        if (this.checkZigbeeNWKGPDuplicate(macHeader, nwkGPHeader)) {
                            logger_js_1.logger.debug(() => `<-~- NWKGP Ignoring duplicate frame macSeqNum=${macHeader.sequenceNumber} nwkGPFC=${nwkGPHeader.securityFrameCounter}`, NS);
                            return;
                        }
                        const nwkGPPayload = (0, zigbee_nwkgp_js_1.decodeZigbeeNWKGPPayload)(macPayload, nwkGPHOutOffset, this.netParams.networkKey, macHeader.source64, nwkGPFCF, nwkGPHeader);
                        this.processZigbeeNWKGPFrame(nwkGPPayload, macHeader, nwkGPHeader, this.computeLQA(metadata?.rssi ?? this.rssiMin));
                    }
                    else {
                        logger_js_1.logger.debug(() => `<-x- NWKGP Invalid frame addressing ${macFCF.destAddrMode} (${macHeader.destination16})`, NS);
                        return;
                    }
                }
                else {
                    const [nwkFCF, nwkFCFOutOffset] = (0, zigbee_nwk_js_1.decodeZigbeeNWKFrameControl)(macPayload, 0);
                    const [nwkHeader, nwkHOutOffset] = (0, zigbee_nwk_js_1.decodeZigbeeNWKHeader)(macPayload, nwkFCFOutOffset, nwkFCF);
                    if (macHeader.destination16 !== undefined &&
                        macHeader.destination16 >= 65528 /* ZigbeeConsts.BCAST_MIN */ &&
                        nwkHeader.source16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */) {
                        logger_js_1.logger.debug(() => "<-~- NWK Ignoring frame from coordinator (broadcast loopback)", NS);
                        return;
                    }
                    const sourceLQA = this.computeDeviceLQA(nwkHeader.source16, nwkHeader.source64, metadata?.rssi ?? this.rssiMin);
                    const nwkPayload = (0, zigbee_nwk_js_1.decodeZigbeeNWKPayload)(macPayload, nwkHOutOffset, undefined, // use pre-hashed this.netParams.networkKey,
                    /* nwkHeader.frameControl.extendedSource ? nwkHeader.source64 : this.address16ToAddress64.get(nwkHeader.source16!) */
                    nwkHeader.source64 ?? this.address16ToAddress64.get(nwkHeader.source16), nwkFCF, nwkHeader);
                    if (nwkFCF.frameType === 0 /* ZigbeeNWKFrameType.DATA */) {
                        const [apsFCF, apsFCFOutOffset] = (0, zigbee_aps_js_1.decodeZigbeeAPSFrameControl)(nwkPayload, 0);
                        const [apsHeader, apsHOutOffset] = (0, zigbee_aps_js_1.decodeZigbeeAPSHeader)(nwkPayload, apsFCFOutOffset, apsFCF);
                        if (apsHeader.frameControl.ackRequest && nwkHeader.source16 !== 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */) {
                            await this.sendZigbeeAPSACK(macHeader, nwkHeader, apsHeader);
                        }
                        const apsPayload = (0, zigbee_aps_js_1.decodeZigbeeAPSPayload)(nwkPayload, apsHOutOffset, undefined, // use pre-hashed this.netParams.tcKey,
                        /* nwkHeader.frameControl.extendedSource ? nwkHeader.source64 : this.address16ToAddress64.get(nwkHeader.source16!) */
                        nwkHeader.source64 ?? this.address16ToAddress64.get(nwkHeader.source16), apsFCF, apsHeader);
                        await this.onZigbeeAPSFrame(apsPayload, macHeader, nwkHeader, apsHeader, sourceLQA);
                    }
                    else if (nwkFCF.frameType === 1 /* ZigbeeNWKFrameType.CMD */) {
                        await this.processZigbeeNWKCommand(nwkPayload, macHeader, nwkHeader);
                    }
                    else if (nwkFCF.frameType === 3 /* ZigbeeNWKFrameType.INTERPAN */) {
                        throw new Error("INTERPAN not supported", { cause: statuses_js_1.SpinelStatus.UNIMPLEMENTED });
                    }
                }
            }
        }
        catch (error) {
            // TODO log or throw depending on error
            logger_js_1.logger.error(error.stack, NS);
        }
    }
    sendFrame(hdlcFrame) {
        // only send what is recorded as "data" (by length)
        this.writer.writeBuffer(hdlcFrame.data.subarray(0, hdlcFrame.length));
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
        this.sendFrame(hdlcFrame);
        if (waitForResponse) {
            return await this.waitForTID(spinelFrame.header.tid, timeout);
        }
    }
    async waitForTID(tid, timeout) {
        return await new Promise((resolve, reject) => {
            // TODO reject if tid already present? (shouldn't happen as long as concurrency is fine...)
            this.#tidWaiters.set(tid, {
                timer: setTimeout(reject.bind(this, new Error(`-x-> SPINEL[tid=${tid}] Timeout after ${timeout}ms`, { cause: statuses_js_1.SpinelStatus.RESPONSE_TIMEOUT })), timeout),
                resolve,
                reject,
            });
        });
    }
    async getProperty(propertyId, timeout = 10000) {
        const [data] = (0, spinel_js_1.writePropertyId)(propertyId, 0);
        return await this.sendCommand(2 /* SpinelCommandId.PROP_VALUE_GET */, data, true, timeout);
    }
    async setProperty(payload, timeout = 10000) {
        // LAST_STATUS checked in `onFrame`
        await this.sendCommand(3 /* SpinelCommandId.PROP_VALUE_SET */, payload, true, timeout);
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
    async startEnergyScan(channels, period, txPower) {
        if (this.#stateLoaded || this.#networkUp) {
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
        if (this.#stateLoaded || this.#networkUp) {
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
            this.emit("macFrame", payload, metadata?.rssi);
            await Promise.resolve();
        };
    }
    async stopSniffer() {
        await this.setProperty((0, spinel_js_1.writePropertyC)(56 /* SpinelPropertyId.MAC_PROMISCUOUS_MODE */, 0));
        await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, false)); // first, avoids BUSY signal
        await this.setProperty((0, spinel_js_1.writePropertyb)(55 /* SpinelPropertyId.MAC_RAW_STREAM_ENABLED */, false));
    }
    /* v8 ignore stop */
    // #endregion
    // #region MAC Layer
    /**
     * Send 802.15.4 MAC frame without checking for need to use indirect transmission.
     * @param seqNum
     * @param payload
     * @param dest16
     * @param dest64
     * @returns True if success sending
     */
    async sendMACFrameDirect(seqNum, payload, dest16, dest64) {
        if (dest16 === undefined && dest64 !== undefined) {
            dest16 = this.deviceTable.get(dest64)?.address16;
        }
        try {
            logger_js_1.logger.debug(() => `===> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}]`, NS);
            await this.setProperty((0, spinel_js_1.writePropertyStreamRaw)(payload, this.streamRawConfig));
            if (this.#emitMACFrames) {
                setImmediate(() => {
                    this.emit("macFrame", payload);
                });
            }
            if (dest16 !== undefined) {
                this.macNoACKs.delete(dest16);
                this.routeFailures.delete(dest16);
            }
            return true;
        }
        catch (error) {
            logger_js_1.logger.debug(() => `=x=> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}] ${error.message}`, NS);
            if (error.cause === statuses_js_1.SpinelStatus.NO_ACK && dest16 !== undefined) {
                this.macNoACKs.set(dest16, (this.macNoACKs.get(dest16) ?? 0) + 1);
            }
            // TODO: ?
            // - NOMEM
            // - BUSY
            // - DROPPED
            // - CCA_FAILURE
            return false;
        }
    }
    /**
     * Send 802.15.4 MAC frame.
     * @param seqNum
     * @param payload
     * @param dest16
     * @param dest64
     * @returns True if success sending. Undefined if set for indirect transmission.
     */
    async sendMACFrame(seqNum, payload, dest16, dest64) {
        if (dest16 !== undefined || dest64 !== undefined) {
            if (dest64 === undefined && dest16 !== undefined) {
                dest64 = this.address16ToAddress64.get(dest16);
            }
            if (dest64 !== undefined) {
                const addrTXs = this.indirectTransmissions.get(dest64);
                if (addrTXs) {
                    addrTXs.push({
                        sendFrame: this.sendMACFrameDirect.bind(this, seqNum, payload, dest16, dest64),
                        timestamp: Date.now(),
                    });
                    logger_js_1.logger.debug(() => `=|=> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}] set for indirect transmission (count=${addrTXs.length})`, NS);
                    return; // done
                }
            }
        }
        // just send the packet when:
        // - RX on when idle
        // - can't determine radio state
        // - no dest info
        return await this.sendMACFrameDirect(seqNum, payload, dest16, dest64);
    }
    /**
     * Send 802.15.4 MAC command
     * @param cmdId
     * @param dest16
     * @param dest64
     * @param extSource
     * @param payload
     * @returns True if success sending
     */
    async sendMACCommand(cmdId, dest16, dest64, extSource, payload) {
        const macSeqNum = this.nextMACSeqNum();
        logger_js_1.logger.debug(() => `===> MAC CMD[seqNum=${macSeqNum} cmdId=${cmdId} dst=${dest16}:${dest64} extSrc=${extSource}]`, NS);
        const macFrame = (0, mac_js_1.encodeMACFrame)({
            frameControl: {
                frameType: 3 /* MACFrameType.CMD */,
                securityEnabled: false,
                framePending: false,
                ackRequest: dest16 !== 65535 /* ZigbeeMACConsts.BCAST_ADDR */,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: dest64 !== undefined ? 3 /* MACFrameAddressMode.EXT */ : 2 /* MACFrameAddressMode.SHORT */,
                frameVersion: 0 /* MACFrameVersion.V2003 */,
                sourceAddrMode: extSource ? 3 /* MACFrameAddressMode.EXT */ : 2 /* MACFrameAddressMode.SHORT */,
            },
            sequenceNumber: macSeqNum,
            destinationPANId: this.netParams.panId,
            destination16: dest16, // depends on `destAddrMode` above
            destination64: dest64, // depends on `destAddrMode` above
            // sourcePANId: undefined, // panIdCompression=true
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // depends on `sourceAddrMode` above
            source64: this.netParams.eui64, // depends on `sourceAddrMode` above
            commandId: cmdId,
            fcs: 0,
        }, payload);
        return await this.sendMACFrameDirect(macSeqNum, macFrame, dest16, dest64);
    }
    /**
     * Process 802.15.4 MAC command.
     * @param data
     * @param macHeader
     * @returns
     */
    async processMACCommand(data, macHeader) {
        let offset = 0;
        switch (macHeader.commandId) {
            case 1 /* MACCommandId.ASSOC_REQ */: {
                offset = await this.processMACAssocReq(data, offset, macHeader);
                break;
            }
            case 2 /* MACCommandId.ASSOC_RSP */: {
                offset = this.processMACAssocRsp(data, offset, macHeader);
                break;
            }
            case 7 /* MACCommandId.BEACON_REQ */: {
                offset = await this.processMACBeaconReq(data, offset, macHeader);
                break;
            }
            case 4 /* MACCommandId.DATA_RQ */: {
                offset = await this.processMACDataReq(data, offset, macHeader);
                break;
            }
            // TODO: other cases?
            // DISASSOC_NOTIFY
            // PANID_CONFLICT
            // ORPHAN_NOTIFY
            // COORD_REALIGN
            // GTS_REQ
            default: {
                logger_js_1.logger.error(`<=x= MAC CMD[cmdId=${macHeader.commandId} macSrc=${macHeader.source16}:${macHeader.source64}] Unsupported`, NS);
                return;
            }
        }
        // excess data in packet
        // if (offset < data.byteLength) {
        //     logger.debug(() => `<=== MAC CMD contained more data: ${data.toString('hex')}`, NS);
        // }
    }
    /**
     * Process 802.15.4 MAC association request.
     * @param data
     * @param offset
     * @param macHeader
     * @returns
     */
    async processMACAssocReq(data, offset, macHeader) {
        const capabilities = data.readUInt8(offset);
        offset += 1;
        logger_js_1.logger.debug(() => `<=== MAC ASSOC_REQ[macSrc=${macHeader.source16}:${macHeader.source64} cap=${capabilities}]`, NS);
        if (macHeader.source64 === undefined) {
            logger_js_1.logger.debug(() => `<=x= MAC ASSOC_REQ[macSrc=${macHeader.source16}:${macHeader.source64} cap=${capabilities}] Invalid source64`, NS);
        }
        else {
            const address16 = this.deviceTable.get(macHeader.source64)?.address16;
            const decodedCap = (0, mac_js_1.decodeMACCapabilities)(capabilities);
            const [status, newAddress16] = await this.associate(address16, macHeader.source64, address16 === undefined /* initial join if unknown device, else rejoin */, decodedCap, true /* neighbor */);
            this.pendingAssociations.set(macHeader.source64, {
                sendResp: async () => {
                    await this.sendMACAssocRsp(macHeader.source64, newAddress16, status);
                    if (status === mac_js_1.MACAssociationStatus.SUCCESS) {
                        await this.sendZigbeeAPSTransportKeyNWK(newAddress16, this.netParams.networkKey, this.netParams.networkKeySequenceNumber, macHeader.source64);
                    }
                },
                timestamp: Date.now(),
            });
        }
        return offset;
    }
    /**
     * Process 802.15.4 MAC association response.
     * @param data
     * @param offset
     * @param macHeader
     * @returns
     */
    processMACAssocRsp(data, offset, macHeader) {
        const address = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;
        logger_js_1.logger.debug(() => `<=== MAC ASSOC_RSP[macSrc=${macHeader.source16}:${macHeader.source64} addr16=${address} status=${mac_js_1.MACAssociationStatus[status]}]`, NS);
        return offset;
    }
    /**
     * Send 802.15.4 MAC association response
     * @param dest64
     * @param newAddress16
     * @param status
     * @returns
     */
    async sendMACAssocRsp(dest64, newAddress16, status) {
        logger_js_1.logger.debug(() => `===> MAC ASSOC_RSP[dst64=${dest64} newAddr16=${newAddress16} status=${status}]`, NS);
        const finalPayload = Buffer.alloc(3);
        let offset = 0;
        finalPayload.writeUInt16LE(newAddress16, offset);
        offset += 2;
        finalPayload.writeUInt8(status, offset);
        offset += 1;
        return await this.sendMACCommand(2 /* MACCommandId.ASSOC_RSP */, undefined, // dest16
        dest64, // dest64
        true, // sourceExt
        finalPayload);
    }
    /**
     * Process 802.15.4 MAC beacon request.
     * @param _data
     * @param offset
     * @param _macHeader
     * @returns
     */
    async processMACBeaconReq(_data, offset, _macHeader) {
        logger_js_1.logger.debug(() => "<=== MAC BEACON_REQ[]", NS);
        const macSeqNum = this.nextMACSeqNum();
        const macFrame = (0, mac_js_1.encodeMACFrame)({
            frameControl: {
                frameType: 0 /* MACFrameType.BEACON */,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 0 /* MACFrameAddressMode.NONE */,
                frameVersion: 0 /* MACFrameVersion.V2003 */,
                sourceAddrMode: 2 /* MACFrameAddressMode.SHORT */,
            },
            sequenceNumber: macSeqNum,
            sourcePANId: this.netParams.panId,
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            superframeSpec: {
                beaconOrder: 0x0f, // value from spec
                superframeOrder: 0x0f, // value from spec
                finalCAPSlot: 0x0f, // XXX: value from sniff, matches above...
                batteryExtension: false,
                panCoordinator: true,
                associationPermit: this.#macAssociationPermit,
            },
            gtsInfo: { permit: false },
            pendAddr: {},
            fcs: 0,
        }, (0, mac_js_1.encodeMACZigbeeBeacon)({
            protocolId: 0 /* ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_ID */,
            profile: 0x2, // ZigBee PRO
            version: 2 /* ZigbeeNWKConsts.VERSION_2007 */,
            routerCapacity: true,
            deviceDepth: 0, // coordinator
            endDeviceCapacity: true,
            extendedPANId: this.netParams.extendedPANId,
            txOffset: 0xffffff, // XXX: value from sniffed frames
            updateId: this.netParams.nwkUpdateId, // XXX: correct?
        }));
        logger_js_1.logger.debug(() => `===> MAC BEACON[seqNum=${macSeqNum}]`, NS);
        await this.sendMACFrame(macSeqNum, macFrame, undefined, undefined);
        return offset;
    }
    /**
     * Process 802.15.4 MAC data request.
     * Used by indirect transmission devices to retrieve information from parent.
     * @param _data
     * @param offset
     * @param macHeader
     * @returns
     */
    async processMACDataReq(_data, offset, macHeader) {
        logger_js_1.logger.debug(() => `<=== MAC DATA_RQ[macSrc=${macHeader.source16}:${macHeader.source64}]`, NS);
        let address64 = macHeader.source64;
        if (address64 === undefined && macHeader.source16 !== undefined) {
            address64 = this.address16ToAddress64.get(macHeader.source16);
        }
        if (address64 !== undefined) {
            const pendingAssoc = this.pendingAssociations.get(address64);
            if (pendingAssoc) {
                if (pendingAssoc.timestamp + 7680 /* ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT */ > Date.now()) {
                    await pendingAssoc.sendResp();
                }
                // always delete, ensures no stale
                this.pendingAssociations.delete(address64);
            }
            else {
                const addrTXs = this.indirectTransmissions.get(address64);
                if (addrTXs !== undefined) {
                    let tx = addrTXs.shift();
                    // deal with expired tx by looking for first that isn't
                    do {
                        if (tx !== undefined && tx.timestamp + 7680 /* ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT */ > Date.now()) {
                            await tx.sendFrame();
                            break;
                        }
                        tx = addrTXs.shift();
                    } while (tx !== undefined);
                }
            }
        }
        return offset;
    }
    // #endregion
    // #region Zigbee NWK layer
    /**
     * @param cmdId
     * @param finalPayload expected to contain the full payload (including cmdId)
     * @param macDest16
     * @param nwkSource16
     * @param nwkDest16
     * @param nwkDest64
     * @param nwkRadius
     * @returns True if success sending (or indirect transmission)
     */
    async sendZigbeeNWKCommand(cmdId, finalPayload, nwkSecurity, nwkSource16, nwkDest16, nwkDest64, nwkRadius) {
        let nwkSecurityHeader;
        if (nwkSecurity) {
            nwkSecurityHeader = {
                control: {
                    level: 0 /* ZigbeeSecurityLevel.NONE */,
                    keyId: 1 /* ZigbeeKeyType.NWK */,
                    nonce: true,
                },
                frameCounter: this.nextNWKKeyFrameCounter(),
                source64: this.netParams.eui64,
                keySeqNum: this.netParams.networkKeySequenceNumber,
                micLen: 4,
            };
        }
        const nwkSeqNum = this.nextNWKSeqNum();
        const macSeqNum = this.nextMACSeqNum();
        let relayIndex;
        let relayAddresses;
        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        }
        catch (error) {
            logger_js_1.logger.error(`=x=> NWK CMD[seqNum=(${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64}] ${error.message}`, NS);
            return false;
        }
        const macDest16 = nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ ? (relayAddresses?.[relayIndex] ?? nwkDest16) : 65535 /* ZigbeeMACConsts.BCAST_ADDR */;
        logger_js_1.logger.debug(() => `===> NWK CMD[seqNum=(${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} macDst16=${macDest16} nwkSrc16=${nwkSource16} nwkDst=${nwkDest16}:${nwkDest64} nwkRad=${nwkRadius}]`, NS);
        const source64 = nwkSource16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ ? this.netParams.eui64 : this.address16ToAddress64.get(nwkSource16);
        const nwkFrame = (0, zigbee_nwk_js_1.encodeZigbeeNWKFrame)({
            frameControl: {
                frameType: 1 /* ZigbeeNWKFrameType.CMD */,
                protocolVersion: 2 /* ZigbeeNWKConsts.VERSION_2007 */,
                discoverRoute: 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */,
                multicast: false,
                security: nwkSecurity,
                sourceRoute: relayIndex !== undefined,
                extendedDestination: nwkDest64 !== undefined,
                extendedSource: source64 !== undefined,
                endDeviceInitiator: false,
            },
            destination16: nwkDest16,
            destination64: nwkDest64,
            source16: nwkSource16,
            source64,
            radius: this.decrementRadius(nwkRadius),
            seqNum: nwkSeqNum,
            relayIndex,
            relayAddresses,
        }, finalPayload, nwkSecurityHeader, undefined);
        const macFrame = (0, mac_js_1.encodeMACFrameZigbee)({
            frameControl: {
                frameType: 1 /* MACFrameType.DATA */,
                securityEnabled: false,
                framePending: Boolean(this.indirectTransmissions.get(nwkDest64 ?? this.address16ToAddress64.get(nwkDest16))?.length),
                ackRequest: macDest16 !== 65535 /* ZigbeeMACConsts.BCAST_ADDR */,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2 /* MACFrameAddressMode.SHORT */,
                frameVersion: 0 /* MACFrameVersion.V2003 */,
                sourceAddrMode: 2 /* MACFrameAddressMode.SHORT */,
            },
            sequenceNumber: macSeqNum,
            destinationPANId: this.netParams.panId,
            destination16: macDest16,
            // sourcePANId: undefined, // panIdCompression=true
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            fcs: 0,
        }, nwkFrame);
        const result = await this.sendMACFrame(macSeqNum, macFrame, macDest16, undefined);
        return result !== false;
    }
    async processZigbeeNWKCommand(data, macHeader, nwkHeader) {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;
        switch (cmdId) {
            case 1 /* ZigbeeNWKCommandId.ROUTE_REQ */: {
                offset = await this.processZigbeeNWKRouteReq(data, offset, macHeader, nwkHeader);
                break;
            }
            case 2 /* ZigbeeNWKCommandId.ROUTE_REPLY */: {
                offset = this.processZigbeeNWKRouteReply(data, offset, macHeader, nwkHeader);
                break;
            }
            case 3 /* ZigbeeNWKCommandId.NWK_STATUS */: {
                offset = this.processZigbeeNWKStatus(data, offset, macHeader, nwkHeader);
                break;
            }
            case 4 /* ZigbeeNWKCommandId.LEAVE */: {
                offset = await this.processZigbeeNWKLeave(data, offset, macHeader, nwkHeader);
                break;
            }
            case 5 /* ZigbeeNWKCommandId.ROUTE_RECORD */: {
                offset = this.processZigbeeNWKRouteRecord(data, offset, macHeader, nwkHeader);
                break;
            }
            case 6 /* ZigbeeNWKCommandId.REJOIN_REQ */: {
                offset = await this.processZigbeeNWKRejoinReq(data, offset, macHeader, nwkHeader);
                break;
            }
            case 7 /* ZigbeeNWKCommandId.REJOIN_RESP */: {
                offset = this.processZigbeeNWKRejoinResp(data, offset, macHeader, nwkHeader);
                break;
            }
            case 8 /* ZigbeeNWKCommandId.LINK_STATUS */: {
                offset = this.processZigbeeNWKLinkStatus(data, offset, macHeader, nwkHeader);
                break;
            }
            case 9 /* ZigbeeNWKCommandId.NWK_REPORT */: {
                offset = this.processZigbeeNWKReport(data, offset, macHeader, nwkHeader);
                break;
            }
            case 10 /* ZigbeeNWKCommandId.NWK_UPDATE */: {
                offset = this.processZigbeeNWKUpdate(data, offset, macHeader, nwkHeader);
                break;
            }
            case 11 /* ZigbeeNWKCommandId.ED_TIMEOUT_REQUEST */: {
                offset = await this.processZigbeeNWKEdTimeoutRequest(data, offset, macHeader, nwkHeader);
                break;
            }
            case 12 /* ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE */: {
                offset = this.processZigbeeNWKEdTimeoutResponse(data, offset, macHeader, nwkHeader);
                break;
            }
            case 13 /* ZigbeeNWKCommandId.LINK_PWR_DELTA */: {
                offset = this.processZigbeeNWKLinkPwrDelta(data, offset, macHeader, nwkHeader);
                break;
            }
            case 14 /* ZigbeeNWKCommandId.COMMISSIONING_REQUEST */: {
                offset = await this.processZigbeeNWKCommissioningRequest(data, offset, macHeader, nwkHeader);
                break;
            }
            case 15 /* ZigbeeNWKCommandId.COMMISSIONING_RESPONSE */: {
                offset = this.processZigbeeNWKCommissioningResponse(data, offset, macHeader, nwkHeader);
                break;
            }
            default: {
                logger_js_1.logger.error(`<=x= NWK CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}] Unsupported`, NS);
                return;
            }
        }
        // excess data in packet
        // if (offset < data.byteLength) {
        //     logger.debug(() => `<=== NWK CMD contained more data: ${data.toString('hex')}`, NS);
        // }
    }
    /**
     * 05-3474-R #3.4.1
     */
    async processZigbeeNWKRouteReq(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const manyToOne = (options & 24 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK */) >> 3; // ZigbeeNWKManyToOne
        const id = data.readUInt8(offset);
        offset += 1;
        const destination16 = data.readUInt16LE(offset);
        offset += 2;
        const pathCost = data.readUInt8(offset);
        offset += 1;
        let destination64;
        if (options & 32 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT */) {
            destination64 = data.readBigUInt64LE(offset);
            offset += 8;
        }
        logger_js_1.logger.debug(() => `<=== NWK ROUTE_REQ[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} id=${id} dst=${destination16}:${destination64} pCost=${pathCost} mto=${manyToOne}]`, NS);
        if (destination16 < 65528 /* ZigbeeConsts.BCAST_MIN */) {
            await this.sendZigbeeNWKRouteReply(macHeader.destination16, nwkHeader.radius, id, nwkHeader.source16, destination16, nwkHeader.source64 ?? this.address16ToAddress64.get(nwkHeader.source16), destination64);
        }
        return offset;
    }
    /**
     * 05-3474-R #3.4.1
     *
     * @param manyToOne
     * @param destination16 intended destination of the route request command frame
     * @param destination64 SHOULD always be added if it is known
     * @returns
     */
    async sendZigbeeNWKRouteReq(manyToOne, destination16, destination64) {
        logger_js_1.logger.debug(() => `===> NWK ROUTE_REQ[mto=${manyToOne} dst=${destination16}:${destination64}]`, NS);
        const hasDestination64 = destination64 !== undefined;
        const options = (((manyToOne ? 1 : 0) << 3) & 24 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK */) |
            (((hasDestination64 ? 1 : 0) << 5) & 32 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT */);
        const finalPayload = Buffer.alloc(1 + 1 + 1 + 2 + 1 + (hasDestination64 ? 8 : 0));
        let offset = 0;
        finalPayload.writeUInt8(1 /* ZigbeeNWKCommandId.ROUTE_REQ */, offset);
        offset += 1;
        finalPayload.writeUInt8(options, offset);
        offset += 1;
        finalPayload.writeUInt8(this.nextRouteRequestId(), offset);
        offset += 1;
        finalPayload.writeUInt16LE(destination16, offset);
        offset += 2;
        finalPayload.writeUInt8(0, offset); // pathCost
        offset += 1;
        if (hasDestination64) {
            finalPayload.writeBigUInt64LE(destination64, offset);
            offset += 8;
        }
        return await this.sendZigbeeNWKCommand(1 /* ZigbeeNWKCommandId.ROUTE_REQ */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        65532 /* ZigbeeConsts.BCAST_DEFAULT */, // nwkDest16
        undefined, // nwkDest64
        CONFIG_NWK_CONCENTRATOR_RADIUS);
    }
    /**
     * 05-3474-R #3.4.2
     */
    processZigbeeNWKRouteReply(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const id = data.readUInt8(offset);
        offset += 1;
        const originator16 = data.readUInt16LE(offset);
        offset += 2;
        const responder16 = data.readUInt16LE(offset);
        offset += 2;
        const pathCost = data.readUInt8(offset);
        offset += 1;
        let originator64;
        let responder64;
        if (options & 16 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT */) {
            originator64 = data.readBigUInt64LE(offset);
            offset += 8;
        }
        if (options & 32 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT */) {
            responder64 = data.readBigUInt64LE(offset);
            offset += 8;
        }
        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);
        logger_js_1.logger.debug(() => `<=== NWK ROUTE_REPLY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} id=${id} orig=${originator16}:${originator64} rsp=${responder16}:${responder64} pCost=${pathCost}]`, NS);
        // TODO
        return offset;
    }
    /**
     * 05-3474-R #3.4.2, #3.6.4.5.2
     *
     * @param requestDest1stHop16 SHALL be set to the network address of the first hop in the path back to the originator of the corresponding route request command frame
     * @param requestRadius
     * @param requestId 8-bit sequence number of the route request to which this frame is a reply
     * @param originator16 SHALL contain the 16-bit network address of the originator of the route request command frame to which this frame is a reply
     * @param responder16 SHALL always be the same as the value in the destination address field of the corresponding route request command frame
     * @param originator64 SHALL be 8 octets in length and SHALL contain the 64-bit address of the originator of the route request command frame to which this frame is a reply.
     * This field SHALL only be present if the originator IEEE address sub-field of the command options field has a value of 1.
     * @param responder64 SHALL be 8 octets in length and SHALL contain the 64-bit address of the destination of the route request command frame to which this frame is a reply.
     * This field SHALL only be present if the responder IEEE address sub-field of the command options field has a value of 1.
     * @returns
     */
    async sendZigbeeNWKRouteReply(requestDest1stHop16, requestRadius, requestId, originator16, responder16, originator64, responder64) {
        logger_js_1.logger.debug(() => `===> NWK ROUTE_REPLY[reqDst1stHop16=${requestDest1stHop16} reqRad=${requestRadius} reqId=${requestId} orig=${originator16}:${originator64} rsp=${responder16}:${responder64}]`, NS);
        const hasOriginator64 = originator64 !== undefined;
        const hasResponder64 = responder64 !== undefined;
        const options = (((hasOriginator64 ? 1 : 0) << 4) & 16 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT */) |
            (((hasResponder64 ? 1 : 0) << 5) & 32 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT */);
        const finalPayload = Buffer.alloc(1 + 1 + 1 + 2 + 2 + 1 + (hasOriginator64 ? 8 : 0) + (hasResponder64 ? 8 : 0));
        let offset = 0;
        finalPayload.writeUInt8(2 /* ZigbeeNWKCommandId.ROUTE_REPLY */, offset);
        offset += 1;
        finalPayload.writeUInt8(options, offset);
        offset += 1;
        finalPayload.writeUInt8(requestId, offset);
        offset += 1;
        finalPayload.writeUInt16LE(originator16, offset);
        offset += 2;
        finalPayload.writeUInt16LE(responder16, offset);
        offset += 2;
        finalPayload.writeUInt8(1, offset); // pathCost TODO: init to 0 or 1?
        offset += 1;
        if (hasOriginator64) {
            finalPayload.writeBigUInt64LE(originator64, offset);
            offset += 8;
        }
        if (hasResponder64) {
            finalPayload.writeBigUInt64LE(responder64, offset);
            offset += 8;
        }
        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeNWKTLVs();
        return await this.sendZigbeeNWKCommand(2 /* ZigbeeNWKCommandId.ROUTE_REPLY */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestDest1stHop16, // nwkDest16
        this.address16ToAddress64.get(requestDest1stHop16), // nwkDest64 SHALL contain the 64-bit IEEE address of the first hop in the path back to the originator of the corresponding route request
        requestRadius);
    }
    /**
     * 05-3474-R #3.4.3
     */
    processZigbeeNWKStatus(data, offset, macHeader, nwkHeader) {
        const status = data.readUInt8(offset);
        offset += 1;
        // target SHALL be present if, and only if, frame is being sent in response to a routing failure or a network address conflict
        let target16;
        if (status === zigbee_nwk_js_1.ZigbeeNWKStatus.LEGACY_NO_ROUTE_AVAILABLE ||
            status === zigbee_nwk_js_1.ZigbeeNWKStatus.LEGACY_LINK_FAILURE ||
            status === zigbee_nwk_js_1.ZigbeeNWKStatus.LINK_FAILURE ||
            status === zigbee_nwk_js_1.ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE ||
            status === zigbee_nwk_js_1.ZigbeeNWKStatus.MANY_TO_ONE_ROUTE_FAILURE) {
            // In case of a routing failure, it SHALL contain the destination address from the data frame that encountered the failure
            target16 = data.readUInt16LE(offset);
            offset += 2;
            let routeFailures = this.routeFailures.get(target16);
            if (routeFailures === undefined) {
                this.routeFailures.set(target16, 1);
            }
            else {
                routeFailures += 1;
                if (routeFailures >= CONFIG_NWK_CONCENTRATOR_ROUTE_FAILURE_THRESHOLD) {
                    for (const [addr16, entries] of this.sourceRouteTable) {
                        // entries using target as relay are no longer valid
                        const filteredEntries = entries.filter((entry) => !entry.relayAddresses.includes(target16));
                        if (filteredEntries.length === 0) {
                            this.sourceRouteTable.delete(addr16);
                        }
                        else if (filteredEntries.length !== entries.length) {
                            this.sourceRouteTable.set(addr16, filteredEntries);
                        }
                    }
                    this.sourceRouteTable.delete(target16); // TODO: delete the source routes for the target itself?
                    this.routeFailures.set(target16, 0); // reset
                }
                else {
                    this.routeFailures.set(target16, routeFailures);
                }
            }
        }
        else if (status === zigbee_nwk_js_1.ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            // In case of an address conflict, it SHALL contain the offending network address.
            target16 = data.readUInt16LE(offset);
            offset += 2;
        }
        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);
        logger_js_1.logger.debug(() => `<=== NWK NWK_STATUS[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${zigbee_nwk_js_1.ZigbeeNWKStatus[status]} dst16=${target16}]`, NS);
        // TODO
        // network address update notification from here?
        return offset;
    }
    /**
     * 05-3474-R #3.4.3
     *
     * @param requestSource16
     * @param status
     * @param destination Destination address (only if status is LINK_FAILURE or ADDRESS_CONFLICT)
     * - in case of a routing failure, it SHALL contain the destination address from the data frame that encountered the failure
     * - in case of an address conflict, it SHALL contain the offending network address.
     * @returns
     */
    async sendZigbeeNWKStatus(requestSource16, status, destination) {
        logger_js_1.logger.debug(() => `===> NWK NWK_STATUS[reqSrc16=${requestSource16} status=${status} dst16=${destination}]`, NS);
        let finalPayload;
        if (status === zigbee_nwk_js_1.ZigbeeNWKStatus.LINK_FAILURE || status === zigbee_nwk_js_1.ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            finalPayload = Buffer.from([3 /* ZigbeeNWKCommandId.NWK_STATUS */, status, destination & 0xff, (destination >> 8) & 0xff]);
        }
        else {
            finalPayload = Buffer.from([3 /* ZigbeeNWKCommandId.NWK_STATUS */, status]);
        }
        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeNWKTLVs();
        return await this.sendZigbeeNWKCommand(3 /* ZigbeeNWKCommandId.NWK_STATUS */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestSource16, // nwkDest16
        this.address16ToAddress64.get(requestSource16), // nwkDest64
        CONFIG_NWK_MAX_HOPS);
    }
    /**
     * 05-3474-R #3.4.4
     */
    async processZigbeeNWKLeave(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const removeChildren = Boolean(options & 128 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN */);
        const request = Boolean(options & 64 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST */);
        const rejoin = Boolean(options & 32 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN */);
        logger_js_1.logger.debug(() => `<=== NWK LEAVE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} remChildren=${removeChildren} req=${request} rejoin=${rejoin}]`, NS);
        if (!rejoin && !request) {
            await this.disassociate(nwkHeader.source16, nwkHeader.source64);
        }
        return offset;
    }
    /**
     * 05-3474-R #3.4.3
     *
     * NOTE: `request` option always true
     * NOTE: `removeChildren` option should not be used (mesh disruption)
     *
     * @param destination16
     * @param rejoin if true, the device that is leaving from its current parent will rejoin the network
     * @returns
     */
    async sendZigbeeNWKLeave(destination16, rejoin) {
        logger_js_1.logger.debug(() => `===> NWK LEAVE[dst16=${destination16} rejoin=${rejoin}]`, NS);
        const options = (0 & 128 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN */) |
            ((1 << 6) & 64 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST */) |
            (((rejoin ? 1 : 0) << 5) & 32 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN */);
        const finalPayload = Buffer.from([4 /* ZigbeeNWKCommandId.LEAVE */, options]);
        return await this.sendZigbeeNWKCommand(4 /* ZigbeeNWKCommandId.LEAVE */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        destination16, // nwkDest16
        this.address16ToAddress64.get(destination16), // nwkDest64
        1);
    }
    /**
     * 05-3474-R #3.4.5
     */
    processZigbeeNWKRouteRecord(data, offset, macHeader, nwkHeader) {
        const relayCount = data.readUInt8(offset);
        offset += 1;
        const relays = [];
        for (let i = 0; i < relayCount; i++) {
            const relay = data.readUInt16LE(offset);
            offset += 2;
            relays.push(relay);
        }
        logger_js_1.logger.debug(() => `<=== NWK ROUTE_RECORD[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} relays=${relays}]`, NS);
        const source16 = nwkHeader.source16 === undefined
            ? nwkHeader.source64 === undefined
                ? undefined
                : this.deviceTable.get(nwkHeader.source64)?.address16
            : nwkHeader.source16;
        if (source16 !== undefined) {
            const entry = {
                relayAddresses: relays,
                pathCost: relayCount + 1, // TODO: ?
            };
            const entries = this.sourceRouteTable.get(source16);
            if (entries === undefined) {
                this.sourceRouteTable.set(source16, [entry]);
            }
            else if (!this.hasSourceRoute(source16, entry, entries)) {
                entries.push(entry);
            }
        }
        return offset;
    }
    // NOTE: sendZigbeeNWKRouteRecord not for coordinator
    /**
     * 05-3474-R #3.4.6
     * Optional
     */
    async processZigbeeNWKRejoinReq(data, offset, macHeader, nwkHeader) {
        const capabilities = data.readUInt8(offset);
        offset += 1;
        const decodedCap = (0, mac_js_1.decodeMACCapabilities)(capabilities);
        logger_js_1.logger.debug(() => `<=== NWK REJOIN_REQ[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} cap=${capabilities}]`, NS);
        let deny = false;
        if (!nwkHeader.frameControl.security) {
            // Trust Center Rejoin
            let source64 = nwkHeader.source64;
            if (source64 === undefined) {
                if (nwkHeader.source16 === undefined) {
                    // invalid, drop completely, should never happen
                    return offset;
                }
                source64 = this.address16ToAddress64.get(nwkHeader.source16);
            }
            if (source64 === undefined) {
                // can't identify device
                deny = true;
            }
            else {
                const device = this.deviceTable.get(source64);
                // XXX: Unsecured Packets at the network layer claiming to be from existing neighbors (coordinators, routers or end devices) must not rewrite legitimate data in the nwkNeighborTable.
                //      if apsTrustCenterAddress is all FF (distributed) / all 00 (pre-TRANSPORT_KEY), reject with PAN_ACCESS_DENIED
                if (!device?.authorized) {
                    // device unknown or unauthorized
                    deny = true;
                }
            }
        }
        const [status, newAddress16] = await this.associate(nwkHeader.source16, nwkHeader.source64, false /* rejoin */, decodedCap, macHeader.source16 === nwkHeader.source16, deny);
        await this.sendZigbeeNWKRejoinResp(nwkHeader.source16, newAddress16, status, decodedCap);
        // NOTE: a device does not have to verify its trust center link key with the APSME-VERIFY-KEY services after a rejoin.
        return offset;
    }
    // NOTE: sendZigbeeNWKRejoinReq not for coordinator
    /**
     * 05-3474-R #3.4.7
     * Optional
     */
    processZigbeeNWKRejoinResp(data, offset, macHeader, nwkHeader) {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;
        if (status !== mac_js_1.MACAssociationStatus.SUCCESS) {
            logger_js_1.logger.error(`<=x= NWK REJOIN_RESP[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress} status=${mac_js_1.MACAssociationStatus[status]}]`, NS);
        }
        else {
            logger_js_1.logger.debug(() => `<=== NWK REJOIN_RESP[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress}]`, NS);
        }
        return offset;
    }
    /**
     * 05-3474-R #3.4.7
     * Optional
     *
     * @param requestSource16 new network address assigned to the rejoining device
     * @param newAddress16
     * @param status
     * @param capabilities
     * @returns
     */
    async sendZigbeeNWKRejoinResp(requestSource16, newAddress16, status, capabilities) {
        logger_js_1.logger.debug(() => `===> NWK REJOIN_RESP[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);
        const finalPayload = Buffer.from([7 /* ZigbeeNWKCommandId.REJOIN_RESP */, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);
        const result = await this.sendZigbeeNWKCommand(7 /* ZigbeeNWKCommandId.REJOIN_RESP */, finalPayload, true, // nwkSecurity TODO: ??
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestSource16, // nwkDest16
        this.address16ToAddress64.get(newAddress16), // nwkDest64
        CONFIG_NWK_MAX_HOPS);
        if (status === mac_js_1.MACAssociationStatus.SUCCESS) {
            setImmediate(() => {
                this.emit("deviceRejoined", newAddress16, this.address16ToAddress64.get(newAddress16), capabilities);
            });
        }
        return result;
    }
    /**
     * 05-3474-R #3.4.8
     */
    processZigbeeNWKLinkStatus(data, offset, macHeader, nwkHeader) {
        // Bit: 0 – 4        5            6           7
        //      Entry count  First frame  Last frame  Reserved
        const options = data.readUInt8(offset);
        offset += 1;
        const firstFrame = Boolean((options & 32 /* ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME */) >> 5);
        const lastFrame = Boolean((options & 64 /* ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME */) >> 6);
        const linkCount = options & 31 /* ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK */;
        const links = [];
        let device = nwkHeader.source64 !== undefined ? this.deviceTable.get(nwkHeader.source64) : undefined;
        if (!device && nwkHeader.source16 !== undefined) {
            const source64 = this.address16ToAddress64.get(nwkHeader.source16);
            if (source64 !== undefined) {
                device = this.deviceTable.get(source64);
            }
        }
        for (let i = 0; i < linkCount; i++) {
            const address = data.readUInt16LE(offset);
            offset += 2;
            const costByte = data.readUInt8(offset);
            offset += 1;
            links.push({
                address,
                incomingCost: costByte & 7 /* ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK */,
                outgoingCost: (costByte & 112 /* ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK */) >> 4,
            });
            if (device) {
                if (address === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */) {
                    // if neighbor is coordinator, update device table
                    device.neighbor = true;
                }
                const entry = address === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */
                    ? { relayAddresses: [], pathCost: 1 /* TODO ? */ }
                    : { relayAddresses: [address], pathCost: 2 /* TODO ? */ };
                const entries = this.sourceRouteTable.get(device.address16);
                if (entries === undefined) {
                    this.sourceRouteTable.set(device.address16, [entry]);
                }
                else if (!this.hasSourceRoute(device.address16, entry, entries)) {
                    entries.push(entry);
                }
            }
        }
        logger_js_1.logger.debug(() => {
            let linksStr = "";
            for (const link of links) {
                linksStr += `{${link.address}|in:${link.incomingCost}|out:${link.outgoingCost}}`;
            }
            return `<=== NWK LINK_STATUS[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} first=${firstFrame} last=${lastFrame} links=${linksStr}]`;
        }, NS);
        // TODO: NeighborTableEntry.age = 0 // max 0xff
        // TODO: NeighborTableEntry.routerAge += 1 // max 0xffff
        // TODO: NeighborTableEntry.routerConnectivity = formula
        // TODO: NeighborTableEntry.routerNeighborSetDiversity = formula
        // TODO: if NeighborTableEntry does not exist, create one with routerAge = 0 and routerConnectivity/routerNeighborSetDiversity as above
        return offset;
    }
    /**
     * 05-3474-R #3.4.8
     *
     * @param links set of link status entries derived from the neighbor table (SHALL be specific to the interface to be transmitted on)
     * Links are expected sorted in ascending order by network address.
     * - incoming cost contains device's estimate of the link cost for the neighbor
     * - outgoing cost contains value of outgoing cost from neighbor table
     */
    async sendZigbeeNWKLinkStatus(links) {
        logger_js_1.logger.debug(() => {
            let linksStr = "";
            for (const link of links) {
                linksStr += `{${link.address}|in:${link.incomingCost}|out:${link.outgoingCost}}`;
            }
            return `===> NWK LINK_STATUS[links=${linksStr}]`;
        }, NS);
        // TODO: check repeat logic
        const linkSize = links.length * 3;
        const maxLinksPayloadSize = 86 /* ZigbeeNWKConsts.PAYLOAD_MIN_SIZE */ - 2; // 84 (- cmdId[1] - options[1])
        const maxLinksPerFrame = Math.floor(maxLinksPayloadSize / 3); // 27
        const frameCount = Math.ceil((linkSize + 3) / maxLinksPayloadSize); // (+ repeated link[3])
        let linksOffset = 0;
        for (let i = 0; i < frameCount; i++) {
            const linkCount = links.length - i * maxLinksPerFrame;
            const frameSize = 2 + Math.min(linkCount * 3, maxLinksPayloadSize);
            const options = (((i === 0 ? 1 : 0) << 5) & 32 /* ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME */) |
                (((i === frameCount - 1 ? 1 : 0) << 6) & 64 /* ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME */) |
                (linkCount & 31 /* ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK */);
            const finalPayload = Buffer.alloc(frameSize);
            let finalPayloadOffset = 0;
            finalPayload.writeUInt8(8 /* ZigbeeNWKCommandId.LINK_STATUS */, finalPayloadOffset);
            finalPayloadOffset += 1;
            finalPayload.writeUInt8(options, finalPayloadOffset);
            finalPayloadOffset += 1;
            for (let j = 0; j < linkCount; j++) {
                const link = links[linksOffset];
                finalPayload.writeUInt16LE(link.address, finalPayloadOffset);
                finalPayloadOffset += 2;
                finalPayload.writeUInt8((link.incomingCost & 7 /* ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK */) |
                    ((link.outgoingCost << 4) & 112 /* ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK */), finalPayloadOffset);
                finalPayloadOffset += 1;
                // last in previous frame is repeated first in next frame
                if (j < linkCount - 1) {
                    linksOffset++;
                }
            }
            await this.sendZigbeeNWKCommand(8 /* ZigbeeNWKCommandId.LINK_STATUS */, finalPayload, true, // nwkSecurity
            0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
            65532 /* ZigbeeConsts.BCAST_DEFAULT */, // nwkDest16
            undefined, // nwkDest64
            1);
        }
    }
    /**
     * 05-3474-R #3.4.9
     *  deprecated in R23, should no longer be sent by R23 devices
     */
    processZigbeeNWKReport(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const reportCount = options & 31 /* ZigbeeNWKConsts.CMD_NWK_REPORT_COUNT_MASK */;
        const reportType = options & 224 /* ZigbeeNWKConsts.CMD_NWK_REPORT_ID_MASK */;
        const extendedPANId = data.readBigUInt64LE(offset);
        offset += 8;
        let conflictPANIds;
        if (reportType === 0 /* ZigbeeNWKConsts.CMD_NWK_REPORT_ID_PAN_CONFLICT */) {
            conflictPANIds = [];
            for (let i = 0; i < reportCount; i++) {
                const panId = data.readUInt16LE(offset);
                offset += 2;
                conflictPANIds.push(panId);
            }
        }
        logger_js_1.logger.debug(() => `<=== NWK NWK_REPORT[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} extPANId=${extendedPANId} repType=${reportType} conflictPANIds=${conflictPANIds}]`, NS);
        return offset;
    }
    // NOTE: sendZigbeeNWKReport deprecated in R23
    /**
     * 05-3474-R #3.4.10
     */
    processZigbeeNWKUpdate(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const updateCount = options & 31 /* ZigbeeNWKConsts.CMD_NWK_UPDATE_COUNT_MASK */;
        const updateType = options & 224 /* ZigbeeNWKConsts.CMD_NWK_UPDATE_ID_MASK */;
        const extendedPANId = data.readBigUInt64LE(offset);
        offset += 8;
        const updateId = data.readUInt8(offset);
        offset += 1;
        let panIds;
        if (updateType === 0 /* ZigbeeNWKConsts.CMD_NWK_UPDATE_ID_PAN_UPDATE */) {
            panIds = [];
            for (let i = 0; i < updateCount; i++) {
                const panId = data.readUInt16LE(offset);
                offset += 2;
                panIds.push(panId);
            }
        }
        logger_js_1.logger.debug(() => `<=== NWK NWK_UPDATE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} extPANId=${extendedPANId} id=${updateId} type=${updateType} panIds=${panIds}]`, NS);
        // TODO
        return offset;
    }
    // NOTE: sendZigbeeNWKUpdate PAN ID change not supported
    /**
     * 05-3474-R #3.4.11
     */
    async processZigbeeNWKEdTimeoutRequest(data, offset, macHeader, nwkHeader) {
        // 0 => 10 seconds
        // 1 => 2 minutes
        // 2 => 4 minutes
        // 3 => 8 minutes
        // 4 => 16 minutes
        // 5 => 32 minutes
        // 6 => 64 minutes
        // 7 => 128 minutes
        // 8 => 256 minutes
        // 9 => 512 minutes
        // 10 => 1024 minutes
        // 11 => 2048 minutes
        // 12 => 4096 minutes
        // 13 => 8192 minutes
        // 14 => 16384 minutes
        const requestedTimeout = data.readUInt8(offset);
        offset += 1;
        // not currently used (all reserved)
        const configuration = data.readUInt8(offset);
        offset += 1;
        logger_js_1.logger.debug(() => `<=== NWK ED_TIMEOUT_REQUEST[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} reqTimeout=${requestedTimeout} conf=${configuration}]`, NS);
        await this.sendZigbeeNWKEdTimeoutResponse(nwkHeader.source16, requestedTimeout);
        return offset;
    }
    // NOTE: sendZigbeeNWKEdTimeoutRequest not for coordinator
    /**
     * 05-3474-R #3.4.12
     */
    processZigbeeNWKEdTimeoutResponse(data, offset, macHeader, nwkHeader) {
        // SUCCESS 0x00 The End Device Timeout Request message was accepted by the parent.
        // INCORRECT_VALUE 0x01 The received timeout value in the End Device Timeout Request command was outside the allowed range.
        // UNSUPPORTED_FEATURE 0x02 The requested feature is not supported by the parent router.
        const status = data.readUInt8(offset);
        offset += 1;
        // Bit 0 MAC Data Poll Keepalive Supported
        // Bit 1 End Device Timeout Request Keepalive Supported
        // Bit 2 Power Negotiation Support
        const parentInfo = data.readUInt8(offset);
        offset += 1;
        logger_js_1.logger.debug(() => `<=== NWK ED_TIMEOUT_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${status} parentInfo=${parentInfo}]`, NS);
        // TODO
        return offset;
    }
    /**
     * 05-3474-R #3.4.12
     *
     * @param requestDest16
     * @param requestedTimeout Requested timeout enumeration [0-14] (mapping to actual timeout) @see processZigbeeNWKEdTimeoutRequest
     * @returns
     */
    async sendZigbeeNWKEdTimeoutResponse(requestDest16, requestedTimeout) {
        logger_js_1.logger.debug(() => `===> NWK ED_TIMEOUT_RESPONSE[reqDst16=${requestDest16} requestedTimeout=${requestedTimeout}]`, NS);
        // sanity check
        const status = requestedTimeout >= 0 && requestedTimeout <= 14 ? 0x00 : 0x01;
        const parentInfo = 0b00000111; // TODO: ?
        const finalPayload = Buffer.from([12 /* ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE */, status, parentInfo]);
        return await this.sendZigbeeNWKCommand(12 /* ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestDest16, // nwkDest16
        this.address16ToAddress64.get(requestDest16), // nwkDest64
        1);
    }
    /**
     * 05-3474-R #3.4.13
     */
    processZigbeeNWKLinkPwrDelta(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        // 0 Notification An unsolicited notification. These frames are typically sent periodically from an RxOn device. If the device is a FFD, it is broadcast to all RxOn devices (0xfffd), and includes power information for all neighboring RxOn devices. If the device is an RFD with RxOn, it is sent unicast to its Parent, and includes only power information for the Parent device.
        // 1 Request Typically used by sleepy RFD devices that do not receive the periodic Notifications from their Parent. The sleepy RFD will wake up periodically to send this frame to its Parent, including only the Parent’s power information in its payload. Upon receipt, the Parent sends a Response (Type = 2) as an indirect transmission, with only the RFD’s power information in its payload. After macResponseWaitTime, the RFD polls its Parent for the Response, before going back to sleep. Request commands are sent as unicast. Note: any device MAY send a Request to solicit a Response from another device. These commands SHALL be sent as unicast and contain only the power information for the destination device. If this command is received as a broadcast, it SHALL be discarded with no action.
        // 2 Response This command is sent in response to a Request. Response commands are sent as unicast to the sender of the Request. The response includes only the power information for the requesting device.
        // 3 Reserved
        const type = options & 3 /* ZigbeeNWKConsts.CMD_NWK_LINK_PWR_DELTA_TYPE_MASK */;
        const count = data.readUInt8(offset);
        offset += 1;
        const deltas = [];
        for (let i = 0; i < count; i++) {
            const device = data.readUInt16LE(offset);
            offset += 2;
            const delta = data.readUInt8(offset);
            offset += 1;
            deltas.push({ device, delta });
        }
        logger_js_1.logger.debug(() => `<=== NWK LINK_PWR_DELTA[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${type} deltas=${deltas}]`, NS);
        // TODO
        return offset;
    }
    // NOTE: sendZigbeeNWKLinkPwrDelta not supported
    /**
     * 05-3474-23 #3.4.14
     * Optional
     */
    async processZigbeeNWKCommissioningRequest(data, offset, macHeader, nwkHeader) {
        // 0x00 Initial Join
        // 0x01 Rejoin
        const assocType = data.readUInt8(offset);
        offset += 1;
        const capabilities = data.readUInt8(offset);
        offset += 1;
        const decodedCap = (0, mac_js_1.decodeMACCapabilities)(capabilities);
        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);
        logger_js_1.logger.debug(() => `<=== NWK COMMISSIONING_REQUEST[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} assocType=${assocType} cap=${capabilities}]`, NS);
        // NOTE: send Remove Device CMD to TC deny the join (or let timeout): `sendZigbeeAPSRemoveDevice`
        const [status, newAddress16] = await this.associate(nwkHeader.source16, nwkHeader.source64, assocType === 0x00 /* initial join */, decodedCap, macHeader.source16 === nwkHeader.source16, nwkHeader.frameControl.security /* deny if true */);
        await this.sendZigbeeNWKCommissioningResponse(nwkHeader.source16, newAddress16, status);
        if (status === mac_js_1.MACAssociationStatus.SUCCESS) {
            // TODO also for rejoin in case of nwk key change?
            await this.sendZigbeeAPSTransportKeyNWK(nwkHeader.source16, this.netParams.networkKey, this.netParams.networkKeySequenceNumber, this.address16ToAddress64.get(newAddress16));
        }
        return offset;
    }
    // NOTE: sendZigbeeNWKCommissioningRequest not for coordinator
    /**
     * 05-3474-23 #3.4.15
     * Optional
     */
    processZigbeeNWKCommissioningResponse(data, offset, macHeader, nwkHeader) {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        // `ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT`, or MACAssociationStatus
        const status = data.readUInt8(offset);
        offset += 1;
        if (status !== mac_js_1.MACAssociationStatus.SUCCESS) {
            logger_js_1.logger.error(`<=x= NWK COMMISSIONING_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress} status=${mac_js_1.MACAssociationStatus[status] ?? "NWK_ADDR_CONFLICT"}]`, NS);
        }
        else {
            logger_js_1.logger.debug(() => `<=== NWK COMMISSIONING_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress}]`, NS);
        }
        // TODO
        return offset;
    }
    /**
     * 05-3474-23 #3.4.15
     * Optional
     *
     * @param requestSource16
     * @param newAddress16 the new 16-bit network address assigned, may be same as `requestDest16`
     * @returns
     */
    async sendZigbeeNWKCommissioningResponse(requestSource16, newAddress16, status) {
        logger_js_1.logger.debug(() => `===> NWK COMMISSIONING_RESPONSE[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);
        const finalPayload = Buffer.from([15 /* ZigbeeNWKCommandId.COMMISSIONING_RESPONSE */, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);
        return await this.sendZigbeeNWKCommand(15 /* ZigbeeNWKCommandId.COMMISSIONING_RESPONSE */, finalPayload, false, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestSource16, // nwkDest16
        this.address16ToAddress64.get(requestSource16), // nwkDest64
        CONFIG_NWK_MAX_HOPS);
    }
    // #endregion
    // #region Zigbee NWK GP layer
    checkZigbeeNWKGPDuplicate(macHeader, nwkHeader) {
        let duplicate = false;
        if (nwkHeader.securityFrameCounter !== undefined) {
            if (nwkHeader.securityFrameCounter === this.#gpLastSecurityFrameCounter) {
                duplicate = true;
            }
            this.#gpLastSecurityFrameCounter = nwkHeader.securityFrameCounter;
        }
        else if (macHeader.sequenceNumber !== undefined) {
            if (macHeader.sequenceNumber === this.#gpLastMACSequenceNumber) {
                duplicate = true;
            }
            this.#gpLastMACSequenceNumber = macHeader.sequenceNumber;
        }
        return duplicate;
    }
    /**
     * See 14-0563-19 #A.3.8.2
     * @param data
     * @param macHeader
     * @param nwkHeader
     * @param rssi
     * @returns
     */
    processZigbeeNWKGPFrame(data, macHeader, nwkHeader, lqa) {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;
        const framePayload = data.subarray(offset);
        if (!this.#gpCommissioningMode &&
            (cmdId === 224 /* ZigbeeNWKGPCommandId.COMMISSIONING */ || cmdId === 226 /* ZigbeeNWKGPCommandId.SUCCESS */ || cmdId === 227 /* ZigbeeNWKGPCommandId.CHANNEL_REQUEST */)) {
            logger_js_1.logger.debug(() => `<=~= NWKGP[cmdId=${cmdId} src=${nwkHeader.sourceId}:${macHeader.source64}] Not in commissioning mode`, NS);
            return;
        }
        logger_js_1.logger.debug(() => `<=== NWKGP[cmdId=${cmdId} src=${nwkHeader.sourceId}:${macHeader.source64}]`, NS);
        setImmediate(() => {
            this.emit("gpFrame", cmdId, framePayload, macHeader, nwkHeader, lqa);
        });
    }
    // #endregion
    // #region Zigbee APS layer
    /**
     * 05-3474-R #4.4.11
     *
     * @param cmdId
     * @param finalPayload expected to contain the full payload (including cmdId)
     * @param macDest16
     * @param nwkDest16
     * @param nwkDest64
     * @param nwkRadius
     * @param apsDeliveryMode
     * @returns True if success sending (or indirect transmission)
     */
    async sendZigbeeAPSCommand(cmdId, finalPayload, nwkDiscoverRoute, nwkSecurity, nwkDest16, nwkDest64, apsDeliveryMode, apsSecurityHeader, disableACKRequest = false) {
        let nwkSecurityHeader;
        if (nwkSecurity) {
            nwkSecurityHeader = {
                control: {
                    level: 0 /* ZigbeeSecurityLevel.NONE */,
                    keyId: 1 /* ZigbeeKeyType.NWK */,
                    nonce: true,
                },
                frameCounter: this.nextNWKKeyFrameCounter(),
                source64: this.netParams.eui64,
                keySeqNum: this.netParams.networkKeySequenceNumber,
                micLen: 4,
            };
        }
        const apsCounter = this.nextAPSCounter();
        const nwkSeqNum = this.nextNWKSeqNum();
        const macSeqNum = this.nextMACSeqNum();
        let relayIndex;
        let relayAddresses;
        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        }
        catch (error) {
            logger_js_1.logger.error(`=x=> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64}] ${error.message}`, NS);
            return false;
        }
        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.deviceTable.get(nwkDest64)?.address16;
        }
        if (nwkDest16 === undefined) {
            logger_js_1.logger.error(`=x=> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} nwkSec=${nwkSecurity} apsDlv=${apsDeliveryMode} apsSec=${apsSecurityHeader !== undefined}]`, NS);
            return false;
        }
        const macDest16 = nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ ? (relayAddresses?.[relayIndex] ?? nwkDest16) : 65535 /* ZigbeeMACConsts.BCAST_ADDR */;
        logger_js_1.logger.debug(() => `===> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} nwkSec=${nwkSecurity} apsDlv=${apsDeliveryMode} apsSec=${apsSecurityHeader !== undefined}]`, NS);
        const apsFrame = (0, zigbee_aps_js_1.encodeZigbeeAPSFrame)({
            frameControl: {
                frameType: 1 /* ZigbeeAPSFrameType.CMD */,
                deliveryMode: apsDeliveryMode,
                ackFormat: false,
                security: apsSecurityHeader !== undefined,
                // XXX: spec says all should request ACK except TUNNEL, but vectors show not a lot of stacks respect that, what's best?
                ackRequest: cmdId !== 14 /* ZigbeeAPSCommandId.TUNNEL */ && !disableACKRequest,
                extendedHeader: false,
            },
            counter: apsCounter,
        }, finalPayload, apsSecurityHeader, undefined);
        const nwkFrame = (0, zigbee_nwk_js_1.encodeZigbeeNWKFrame)({
            frameControl: {
                frameType: 0 /* ZigbeeNWKFrameType.DATA */,
                protocolVersion: 2 /* ZigbeeNWKConsts.VERSION_2007 */,
                discoverRoute: nwkDiscoverRoute,
                multicast: false,
                security: nwkSecurity,
                sourceRoute: relayIndex !== undefined,
                extendedDestination: nwkDest64 !== undefined,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: nwkDest16,
            destination64: nwkDest64,
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            radius: this.decrementRadius(CONFIG_NWK_MAX_HOPS),
            seqNum: nwkSeqNum,
            relayIndex,
            relayAddresses,
        }, apsFrame, nwkSecurityHeader, undefined);
        const macFrame = (0, mac_js_1.encodeMACFrameZigbee)({
            frameControl: {
                frameType: 1 /* MACFrameType.DATA */,
                securityEnabled: false,
                framePending: Boolean(this.indirectTransmissions.get(nwkDest64 ?? this.address16ToAddress64.get(nwkDest16))?.length),
                ackRequest: macDest16 !== 65535 /* ZigbeeMACConsts.BCAST_ADDR */,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2 /* MACFrameAddressMode.SHORT */,
                frameVersion: 0 /* MACFrameVersion.V2003 */,
                sourceAddrMode: 2 /* MACFrameAddressMode.SHORT */,
            },
            sequenceNumber: macSeqNum,
            destinationPANId: this.netParams.panId,
            destination16: macDest16,
            // sourcePANId: undefined, // panIdCompression=true
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            fcs: 0,
        }, nwkFrame);
        const result = await this.sendMACFrame(macSeqNum, macFrame, macDest16, undefined);
        return result !== false;
    }
    /**
     * Send a ZigBee APS DATA frame.
     * Throws if could not send.
     * @param finalPayload
     * @param macDest16
     * @param nwkDiscoverRoute
     * @param nwkDest16
     * @param nwkDest64
     * @param apsDeliveryMode
     * @param clusterId
     * @param profileId
     * @param destEndpoint
     * @param sourceEndpoint
     * @param group
     * @returns The APS counter of the sent frame.
     */
    async sendZigbeeAPSData(finalPayload, nwkDiscoverRoute, nwkDest16, nwkDest64, apsDeliveryMode, clusterId, profileId, destEndpoint, sourceEndpoint, group) {
        const apsCounter = this.nextAPSCounter();
        const nwkSeqNum = this.nextNWKSeqNum();
        const macSeqNum = this.nextMACSeqNum();
        let relayIndex;
        let relayAddresses;
        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        }
        catch (error) {
            logger_js_1.logger.error(`=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) nwkDst=${nwkDest16}:${nwkDest64}] ${error.message}`, NS);
            throw error;
        }
        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.deviceTable.get(nwkDest64)?.address16;
        }
        if (nwkDest16 === undefined) {
            logger_js_1.logger.error(`=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) nwkDst=${nwkDest16}:${nwkDest64}] Invalid parameters`, NS);
            throw new Error("Invalid parameters", { cause: statuses_js_1.SpinelStatus.INVALID_ARGUMENT });
        }
        const macDest16 = nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ ? (relayAddresses?.[relayIndex] ?? nwkDest16) : 65535 /* ZigbeeMACConsts.BCAST_ADDR */;
        logger_js_1.logger.debug(() => `===> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} apsDlv=${apsDeliveryMode}]`, NS);
        const apsFrame = (0, zigbee_aps_js_1.encodeZigbeeAPSFrame)({
            frameControl: {
                frameType: 0 /* ZigbeeAPSFrameType.DATA */,
                deliveryMode: apsDeliveryMode,
                ackFormat: false,
                security: false, // TODO link key support
                ackRequest: true,
                extendedHeader: false,
            },
            destEndpoint,
            group,
            clusterId,
            profileId,
            sourceEndpoint,
            counter: apsCounter,
        }, finalPayload);
        const nwkFrame = (0, zigbee_nwk_js_1.encodeZigbeeNWKFrame)({
            frameControl: {
                frameType: 0 /* ZigbeeNWKFrameType.DATA */,
                protocolVersion: 2 /* ZigbeeNWKConsts.VERSION_2007 */,
                discoverRoute: nwkDiscoverRoute,
                multicast: false,
                security: true,
                sourceRoute: relayIndex !== undefined,
                extendedDestination: nwkDest64 !== undefined,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: nwkDest16,
            destination64: nwkDest64,
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            radius: this.decrementRadius(CONFIG_NWK_MAX_HOPS),
            seqNum: nwkSeqNum,
            relayIndex,
            relayAddresses,
        }, apsFrame, {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 1 /* ZigbeeKeyType.NWK */,
                nonce: true,
            },
            frameCounter: this.nextNWKKeyFrameCounter(),
            source64: this.netParams.eui64,
            keySeqNum: this.netParams.networkKeySequenceNumber,
            micLen: 4,
        }, undefined);
        const macFrame = (0, mac_js_1.encodeMACFrameZigbee)({
            frameControl: {
                frameType: 1 /* MACFrameType.DATA */,
                securityEnabled: false,
                framePending: group === undefined && nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */
                    ? Boolean(this.indirectTransmissions.get(nwkDest64 ?? this.address16ToAddress64.get(nwkDest16))?.length)
                    : false,
                ackRequest: macDest16 !== 65535 /* ZigbeeMACConsts.BCAST_ADDR */,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2 /* MACFrameAddressMode.SHORT */,
                frameVersion: 0 /* MACFrameVersion.V2003 */,
                sourceAddrMode: 2 /* MACFrameAddressMode.SHORT */,
            },
            sequenceNumber: macSeqNum,
            destinationPANId: this.netParams.panId,
            destination16: macDest16,
            // sourcePANId: undefined, // panIdCompression=true
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            fcs: 0,
        }, nwkFrame);
        const result = await this.sendMACFrame(macSeqNum, macFrame, macDest16, undefined);
        if (result === false) {
            logger_js_1.logger.error(`=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64}] Failed to send`, NS);
            throw new Error("Failed to send", { cause: statuses_js_1.SpinelStatus.FAILURE });
        }
        return apsCounter;
    }
    async sendZigbeeAPSACK(macHeader, nwkHeader, apsHeader) {
        logger_js_1.logger.debug(() => `===> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`, NS);
        let nwkDest16 = nwkHeader.source16;
        const nwkDest64 = nwkHeader.source64;
        let relayIndex;
        let relayAddresses;
        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        }
        catch (error) {
            logger_js_1.logger.debug(() => `=x=> APS ACK[dst16=${nwkDest16} seqNum=${nwkHeader.seqNum}] ${error.message}`, NS);
            return;
        }
        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.deviceTable.get(nwkDest64)?.address16;
        }
        if (nwkDest16 === undefined) {
            logger_js_1.logger.debug(() => `=x=> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`, NS);
            return;
        }
        const macDest16 = nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ ? (relayAddresses?.[relayIndex] ?? nwkDest16) : 65535 /* ZigbeeMACConsts.BCAST_ADDR */;
        const ackAPSFrame = (0, zigbee_aps_js_1.encodeZigbeeAPSFrame)({
            frameControl: {
                frameType: 2 /* ZigbeeAPSFrameType.ACK */,
                deliveryMode: 0 /* ZigbeeAPSDeliveryMode.UNICAST */,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            destEndpoint: apsHeader.sourceEndpoint,
            clusterId: apsHeader.clusterId,
            profileId: apsHeader.profileId,
            sourceEndpoint: apsHeader.destEndpoint,
            counter: apsHeader.counter,
        }, Buffer.alloc(0));
        const ackNWKFrame = (0, zigbee_nwk_js_1.encodeZigbeeNWKFrame)({
            frameControl: {
                frameType: 0 /* ZigbeeNWKFrameType.DATA */,
                protocolVersion: 2 /* ZigbeeNWKConsts.VERSION_2007 */,
                discoverRoute: 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */,
                multicast: false,
                security: true,
                sourceRoute: relayIndex !== undefined,
                extendedDestination: false,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: nwkHeader.source16,
            source16: nwkHeader.destination16,
            radius: this.decrementRadius(nwkHeader.radius ?? CONFIG_NWK_MAX_HOPS),
            seqNum: nwkHeader.seqNum,
            relayIndex,
            relayAddresses,
        }, ackAPSFrame, {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 1 /* ZigbeeKeyType.NWK */,
                nonce: true,
            },
            frameCounter: this.nextNWKKeyFrameCounter(),
            source64: this.netParams.eui64,
            keySeqNum: this.netParams.networkKeySequenceNumber,
            micLen: 4,
        }, undefined);
        const ackMACFrame = (0, mac_js_1.encodeMACFrameZigbee)({
            frameControl: {
                frameType: 1 /* MACFrameType.DATA */,
                securityEnabled: false,
                framePending: Boolean(this.indirectTransmissions.get(nwkDest64 ?? this.address16ToAddress64.get(nwkDest16))?.length),
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2 /* MACFrameAddressMode.SHORT */,
                frameVersion: 0 /* MACFrameVersion.V2003 */,
                sourceAddrMode: 2 /* MACFrameAddressMode.SHORT */,
            },
            sequenceNumber: macHeader.sequenceNumber,
            destinationPANId: macHeader.destinationPANId,
            destination16: macDest16,
            // sourcePANId: undefined, // panIdCompression=true
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            fcs: 0,
        }, ackNWKFrame);
        await this.sendMACFrame(macHeader.sequenceNumber, ackMACFrame, macHeader.source16, undefined);
    }
    async onZigbeeAPSFrame(data, macHeader, nwkHeader, apsHeader, lqa) {
        switch (apsHeader.frameControl.frameType) {
            case 2 /* ZigbeeAPSFrameType.ACK */: {
                // ACKs should never contain a payload
                // TODO: ?
                break;
            }
            case 0 /* ZigbeeAPSFrameType.DATA */:
            case 3 /* ZigbeeAPSFrameType.INTERPAN */: {
                if (data.byteLength < 1) {
                    return;
                }
                logger_js_1.logger.debug(() => `<=== APS DATA[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${nwkHeader.seqNum} profileId=${apsHeader.profileId} clusterId=${apsHeader.clusterId} srcEp=${apsHeader.sourceEndpoint} dstEp=${apsHeader.destEndpoint} bcast=${macHeader.destination16 === 65535 /* ZigbeeMACConsts.BCAST_ADDR */ || (nwkHeader.destination16 !== undefined && nwkHeader.destination16 >= 65528 /* ZigbeeConsts.BCAST_MIN */)}]`, NS);
                if (apsHeader.profileId === 0 /* ZigbeeConsts.ZDO_PROFILE_ID */) {
                    if (apsHeader.clusterId === 19 /* ZigbeeConsts.END_DEVICE_ANNOUNCE */) {
                        let offset = 1; // skip seq num
                        const address16 = data.readUInt16LE(offset);
                        offset += 2;
                        const address64 = data.readBigUInt64LE(offset);
                        offset += 8;
                        const capabilities = data.readUInt8(offset);
                        offset += 1;
                        const device = this.deviceTable.get(address64);
                        if (!device) {
                            // unknown device, should have been added by `associate`, something's not right, ignore it
                            return;
                        }
                        const decodedCap = (0, mac_js_1.decodeMACCapabilities)(capabilities);
                        // just in case
                        device.capabilities = decodedCap;
                        // TODO: ideally, this shouldn't trigger (prevents early interview process from app) until AFTER authorized=true
                        setImmediate(() => {
                            // if device is authorized, it means it completed the TC link key update, so, a rejoin
                            this.emit(device.authorized ? "deviceRejoined" : "deviceJoined", address16, address64, decodedCap);
                        });
                    }
                    else {
                        const isRequest = (apsHeader.clusterId & 0x8000) === 0;
                        if (isRequest) {
                            if (this.isZDORequestForCoordinator(apsHeader.clusterId, nwkHeader.destination16, nwkHeader.destination64, data)) {
                                await this.respondToCoordinatorZDORequest(data, apsHeader.clusterId, nwkHeader.source16, nwkHeader.source64);
                            }
                            // don't emit received ZDO requests
                            return;
                        }
                    }
                }
                if (nwkHeader.source16 === undefined && nwkHeader.source64 === undefined) {
                    logger_js_1.logger.debug(() => "<=~= APS Ignoring frame with no sender info", NS);
                    return;
                }
                setImmediate(() => {
                    // TODO: always lookup source64 if undef?
                    this.emit("frame", nwkHeader.source16, nwkHeader.source64, apsHeader, data, lqa);
                });
                break;
            }
            case 1 /* ZigbeeAPSFrameType.CMD */: {
                await this.processZigbeeAPSCommand(data, macHeader, nwkHeader, apsHeader);
                break;
            }
            default: {
                throw new Error(`Illegal frame type ${apsHeader.frameControl.frameType}`, { cause: statuses_js_1.SpinelStatus.INVALID_ARGUMENT });
            }
        }
    }
    async processZigbeeAPSCommand(data, macHeader, nwkHeader, apsHeader) {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;
        switch (cmdId) {
            case 5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */: {
                offset = this.processZigbeeAPSTransportKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 6 /* ZigbeeAPSCommandId.UPDATE_DEVICE */: {
                offset = await this.processZigbeeAPSUpdateDevice(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 7 /* ZigbeeAPSCommandId.REMOVE_DEVICE */: {
                offset = this.processZigbeeAPSRemoveDevice(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 8 /* ZigbeeAPSCommandId.REQUEST_KEY */: {
                offset = await this.processZigbeeAPSRequestKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 9 /* ZigbeeAPSCommandId.SWITCH_KEY */: {
                offset = this.processZigbeeAPSSwitchKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 14 /* ZigbeeAPSCommandId.TUNNEL */: {
                offset = this.processZigbeeAPSTunnel(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 15 /* ZigbeeAPSCommandId.VERIFY_KEY */: {
                offset = await this.processZigbeeAPSVerifyKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 16 /* ZigbeeAPSCommandId.CONFIRM_KEY */: {
                offset = this.processZigbeeAPSConfirmKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 17 /* ZigbeeAPSCommandId.RELAY_MESSAGE_DOWNSTREAM */: {
                offset = this.processZigbeeAPSRelayMessageDownstream(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 18 /* ZigbeeAPSCommandId.RELAY_MESSAGE_UPSTREAM */: {
                offset = this.processZigbeeAPSRelayMessageUpstream(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            default: {
                logger_js_1.logger.warning(`<=x= APS CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}] Unsupported`, NS);
                return;
            }
        }
        // excess data in packet
        // if (offset < data.byteLength) {
        //     logger.debug(() => `<=== APS CMD contained more data: ${data.toString('hex')}`, NS);
        // }
    }
    /**
     * 05-3474-R #4.4.11.1
     */
    processZigbeeAPSTransportKey(data, offset, macHeader, nwkHeader, _apsHeader) {
        const keyType = data.readUInt8(offset);
        offset += 1;
        const key = data.subarray(offset, offset + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        offset += 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */;
        switch (keyType) {
            case 1 /* ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK */:
            case 5 /* ZigbeeAPSConsts.CMD_KEY_HIGH_SEC_NWK */: {
                const seqNum = data.readUInt8(offset);
                offset += 1;
                const destination = data.readBigUInt64LE(offset);
                offset += 8;
                const source = data.readBigUInt64LE(offset);
                offset += 8;
                logger_js_1.logger.debug(() => `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} seqNum=${seqNum} dst64=${destination} src64=${source}]`, NS);
                break;
            }
            case 0 /* ZigbeeAPSConsts.CMD_KEY_TC_MASTER */:
            case 4 /* ZigbeeAPSConsts.CMD_KEY_TC_LINK */: {
                const destination = data.readBigUInt64LE(offset);
                offset += 8;
                const source = data.readBigUInt64LE(offset);
                offset += 8;
                // TODO
                // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);
                logger_js_1.logger.debug(() => `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} dst64=${destination} src64=${source}]`, NS);
                break;
            }
            case 2 /* ZigbeeAPSConsts.CMD_KEY_APP_MASTER */:
            case 3 /* ZigbeeAPSConsts.CMD_KEY_APP_LINK */: {
                const partner = data.readBigUInt64LE(offset);
                offset += 8;
                const initiatorFlag = data.readUInt8(offset);
                offset += 1;
                // TODO
                // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);
                logger_js_1.logger.debug(() => `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} partner64=${partner} initiatorFlag=${initiatorFlag}]`, NS);
                break;
            }
        }
        return offset;
    }
    /**
     * 05-3474-R #4.4.11.1
     *
     * @param nwkDest16
     * @param key SHALL contain the link key that SHOULD be used for APS encryption
     * @param destination64 SHALL contain the address of the device which SHOULD use this link key
     * @returns
     */
    async sendZigbeeAPSTransportKeyTC(nwkDest16, key, destination64) {
        // TODO: tunneling support `, tunnelDest?: bigint`
        //       If the TunnelCommand parameter is TRUE, an APS Tunnel Command SHALL be constructed as described in section 4.6.3.7.
        //       It SHALL then be sent to the device specified by the TunnelAddress parameter by issuing an NLDE-DATA.request primitive.
        logger_js_1.logger.debug(() => `===> APS TRANSPORT_KEY_TC[key=${key.toString("hex")} dst64=${destination64}]`, NS);
        const finalPayload = Buffer.alloc(18 + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        let offset = 0;
        finalPayload.writeUInt8(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, offset);
        offset += 1;
        finalPayload.writeUInt8(4 /* ZigbeeAPSConsts.CMD_KEY_TC_LINK */, offset);
        offset += 1;
        finalPayload.set(key, offset);
        offset += 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        finalPayload.writeBigUInt64LE(this.netParams.eui64, offset);
        offset += 8;
        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeAPSTLVs();
        // encryption NWK=true, APS=true
        return await this.sendZigbeeAPSCommand(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 3 /* ZigbeeKeyType.LOAD */,
                nonce: true,
            },
            frameCounter: this.nextTCKeyFrameCounter(),
            source64: this.netParams.eui64,
            // keySeqNum: undefined, only for keyId NWK
            micLen: 4,
        });
    }
    /**
     * 05-3474-R #4.4.11.1 #4.4.11.1.3.2
     *
     * @param nwkDest16
     * @param key SHALL contain a network key
     * @param seqNum SHALL contain the sequence number associated with this network key
     * @param destination64 SHALL contain the address of the device which SHOULD use this network key
     * If the network key is sent to a broadcast address, the destination address subfield SHALL be set to the all-zero string and SHALL be ignored upon reception.
     * @returns
     */
    async sendZigbeeAPSTransportKeyNWK(nwkDest16, key, seqNum, destination64) {
        // TODO: tunneling support `, tunnelDest?: bigint`
        logger_js_1.logger.debug(() => `===> APS TRANSPORT_KEY_NWK[key=${key.toString("hex")} seqNum=${seqNum} dst64=${destination64}]`, NS);
        const finalPayload = Buffer.alloc(19 + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        let offset = 0;
        finalPayload.writeUInt8(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, offset);
        offset += 1;
        finalPayload.writeUInt8(1 /* ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK */, offset);
        offset += 1;
        finalPayload.set(key, offset);
        offset += 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */;
        finalPayload.writeUInt8(seqNum, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        finalPayload.writeBigUInt64LE(this.netParams.eui64, offset); // 0xFFFFFFFFFFFFFFFF in distributed network (no TC)
        offset += 8;
        // see 05-3474-23 #4.4.1.5
        // Conversely, a device receiving an APS transport key command MAY choose whether or not APS encryption is required.
        // This is most often done during initial joining.
        // For example, during joining a device that has no preconfigured link key would only accept unencrypted transport key messages,
        // while a device with a preconfigured link key would only accept a transport key APS encrypted with its preconfigured key.
        // encryption NWK=true, APS=false
        // await this.sendZigbeeAPSCommand(
        //     ZigbeeAPSCommandId.TRANSPORT_KEY,
        //     finalPayload,
        //     ZigbeeNWKRouteDiscovery.SUPPRESS,
        //     true, // nwkSecurity
        //     nwkDest16, // nwkDest16
        //     undefined, // nwkDest64
        //     ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
        //     undefined, // apsSecurityHeader
        // );
        // encryption NWK=false, APS=true
        return await this.sendZigbeeAPSCommand(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        false, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 2 /* ZigbeeKeyType.TRANSPORT */,
                nonce: true,
            },
            frameCounter: this.nextTCKeyFrameCounter(),
            source64: this.netParams.eui64,
            // keySeqNum: undefined, only for keyId NWK
            micLen: 4,
        }, // apsSecurityHeader
        true);
    }
    /**
     * 05-3474-R #4.4.11.1 #4.4.11.1.3.3
     *
     * @param nwkDest16
     * @param key SHALL contain a link key that is shared with the device identified in the partner address sub-field
     * @param partner SHALL contain the address of the other device that was sent this link key
     * @param initiatorFlag SHALL be set to 1 if the device receiving this packet requested this key. Otherwise, this sub-field SHALL be set to 0.
     * @returns
     */
    async sendZigbeeAPSTransportKeyAPP(nwkDest16, key, partner, initiatorFlag) {
        // TODO: tunneling support `, tunnelDest?: bigint`
        logger_js_1.logger.debug(() => `===> APS TRANSPORT_KEY_APP[key=${key.toString("hex")} partner64=${partner} initiatorFlag=${initiatorFlag}]`, NS);
        const finalPayload = Buffer.alloc(11 + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        let offset = 0;
        finalPayload.writeUInt8(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, offset);
        offset += 1;
        finalPayload.writeUInt8(3 /* ZigbeeAPSConsts.CMD_KEY_APP_LINK */, offset);
        offset += 1;
        finalPayload.set(key, offset);
        offset += 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */;
        finalPayload.writeBigUInt64LE(partner, offset);
        offset += 8;
        finalPayload.writeUInt8(initiatorFlag ? 1 : 0, offset);
        offset += 1;
        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeAPSTLVs();
        return await this.sendZigbeeAPSCommand(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 3 /* ZigbeeKeyType.LOAD */,
                nonce: true,
            },
            frameCounter: this.nextTCKeyFrameCounter(),
            source64: this.netParams.eui64,
            // keySeqNum: undefined, only for keyId NWK
            micLen: 4,
        });
    }
    /**
     * 05-3474-R #4.4.11.2
     */
    async processZigbeeAPSUpdateDevice(data, offset, macHeader, nwkHeader, _apsHeader) {
        const device64 = data.readBigUInt64LE(offset);
        offset += 8;
        // ZigBee 2006 and later
        const device16 = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;
        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);
        logger_js_1.logger.debug(() => `<=== APS UPDATE_DEVICE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dev=${device16}:${device64} status=${status} src16=${nwkHeader.source16}]`, NS);
        // 0x00 = Standard Device Secured Rejoin
        // 0x01 = Standard Device Unsecured Join
        // 0x02 = Device Left
        // 0x03 = Standard Device Trust Center Rejoin
        // 0x04 – 0x07 = Reserved
        if (status === 0x01) {
            await this.associate(device16, device64, true, // initial join
            undefined, // no MAC cap through router
            false, // not neighbor
            false, true);
            // TODO: better handling
            try {
                const [, parentRelays] = this.findBestSourceRoute(nwkHeader.source16, nwkHeader.source64);
                if (parentRelays) {
                    // parent is nested
                    this.sourceRouteTable.set(device16, [{ relayAddresses: parentRelays, pathCost: parentRelays.length + 1 }]);
                }
                else {
                    // parent is direct to coordinator
                    this.sourceRouteTable.set(device16, [{ relayAddresses: [nwkHeader.source16], pathCost: 2 }]);
                }
            }
            catch {
                /* ignore */
            }
            const tApsCmdPayload = Buffer.alloc(19 + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
            let offset = 0;
            tApsCmdPayload.writeUInt8(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, offset);
            offset += 1;
            tApsCmdPayload.writeUInt8(1 /* ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK */, offset);
            offset += 1;
            tApsCmdPayload.set(this.netParams.networkKey, offset);
            offset += 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */;
            tApsCmdPayload.writeUInt8(this.netParams.networkKeySequenceNumber, offset);
            offset += 1;
            tApsCmdPayload.writeBigUInt64LE(device64, offset);
            offset += 8;
            tApsCmdPayload.writeBigUInt64LE(this.netParams.eui64, offset); // 0xFFFFFFFFFFFFFFFF in distributed network (no TC)
            offset += 8;
            const tApsCmdFrame = (0, zigbee_aps_js_1.encodeZigbeeAPSFrame)({
                frameControl: {
                    frameType: 1 /* ZigbeeAPSFrameType.CMD */,
                    deliveryMode: 0 /* ZigbeeAPSDeliveryMode.UNICAST */,
                    ackFormat: false,
                    security: true,
                    ackRequest: false,
                    extendedHeader: false,
                },
                counter: this.nextAPSCounter(),
            }, tApsCmdPayload, {
                control: {
                    level: 0 /* ZigbeeSecurityLevel.NONE */,
                    keyId: 2 /* ZigbeeKeyType.TRANSPORT */,
                    nonce: true,
                },
                frameCounter: this.nextTCKeyFrameCounter(),
                source64: this.netParams.eui64,
                micLen: 4,
            }, undefined);
            await this.sendZigbeeAPSTunnel(nwkHeader.source16, device64, tApsCmdFrame);
        }
        else if (status === 0x03) {
            // rejoin
            await this.associate(device16, device64, false, // rejoin
            undefined, // no MAC cap through router
            false, // not neighbor
            false, true);
        }
        else if (status === 0x02) {
            // left
            // TODO: according to spec, this is "informative" only, should not take any action?
            await this.disassociate(device16, device64);
        }
        return offset;
    }
    /**
     * 05-3474-R #4.4.11.2
     *
     * @param nwkDest16 device that SHALL be sent the update information
     * @param device64 device whose status is being updated
     * @param device16 device whose status is being updated
     * @param status Indicates the updated status of the device given by the device64 parameter:
     * - 0x00 = Standard Device Secured Rejoin
     * - 0x01 = Standard Device Unsecured Join
     * - 0x02 = Device Left
     * - 0x03 = Standard Device Trust Center Rejoin
     * - 0x04 – 0x07 = Reserved
     * @param tlvs as relayed during Network Commissioning
     * @returns
     */
    async sendZigbeeAPSUpdateDevice(nwkDest16, device64, device16, status) {
        logger_js_1.logger.debug(() => `===> APS UPDATE_DEVICE[dev=${device16}:${device64} status=${status}]`, NS);
        const finalPayload = Buffer.alloc(12 /* + TLVs */);
        let offset = 0;
        finalPayload.writeUInt8(6 /* ZigbeeAPSCommandId.UPDATE_DEVICE */, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(device64, offset);
        offset += 8;
        finalPayload.writeUInt16LE(device16, offset);
        offset += 2;
        finalPayload.writeUInt8(status, offset);
        offset += 1;
        // TODO TLVs
        return await this.sendZigbeeAPSCommand(6 /* ZigbeeAPSCommandId.UPDATE_DEVICE */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-R #4.4.11.3
     */
    processZigbeeAPSRemoveDevice(data, offset, macHeader, nwkHeader, _apsHeader) {
        const target = data.readBigUInt64LE(offset);
        offset += 8;
        logger_js_1.logger.debug(() => `<=== APS REMOVE_DEVICE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} target64=${target}]`, NS);
        return offset;
    }
    /**
     * 05-3474-R #4.4.11.3
     *
     * @param nwkDest16 parent
     * @param target64
     * @returns
     */
    async sendZigbeeAPSRemoveDevice(nwkDest16, target64) {
        logger_js_1.logger.debug(() => `===> APS REMOVE_DEVICE[target64=${target64}]`, NS);
        const finalPayload = Buffer.alloc(9);
        let offset = 0;
        finalPayload.writeUInt8(7 /* ZigbeeAPSCommandId.REMOVE_DEVICE */, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(target64, offset);
        offset += 8;
        return await this.sendZigbeeAPSCommand(7 /* ZigbeeAPSCommandId.REMOVE_DEVICE */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-R #4.4.11.4 #4.4.5.2.3
     */
    async processZigbeeAPSRequestKey(data, offset, macHeader, nwkHeader, apsHeader) {
        // ZigbeeAPSConsts.CMD_KEY_APP_MASTER || ZigbeeAPSConsts.CMD_KEY_TC_LINK
        const keyType = data.readUInt8(offset);
        offset += 1;
        // If the APS Command Request Key message is not APS encrypted, the device SHALL drop the message and no further processing SHALL be done.
        if (!apsHeader.frameControl.security) {
            return offset;
        }
        const device64 = this.address16ToAddress64.get(nwkHeader.source16);
        // don't send to unknown device
        if (device64 !== undefined) {
            // TODO:
            //   const deviceKeyPair = this.apsDeviceKeyPairSet.get(nwkHeader.source16!);
            //   if (!deviceKeyPair || deviceKeyPair.keyNegotiationMethod === 0x00 /* `APS Request Key` method */) {
            if (keyType === 2 /* ZigbeeAPSConsts.CMD_KEY_APP_MASTER */) {
                const partner = data.readBigUInt64LE(offset);
                offset += 8;
                logger_js_1.logger.debug(() => `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} partner64=${partner}]`, NS);
                if (this.#trustCenterPolicies.allowAppKeyRequest === ApplicationKeyRequestPolicy.ALLOWED) {
                    await this.sendZigbeeAPSTransportKeyAPP(nwkHeader.source16, this.getOrGenerateAppLinkKey(nwkHeader.source16, partner), partner, true);
                }
                // TODO ApplicationKeyRequestPolicy.ONLY_APPROVED
            }
            else if (keyType === 4 /* ZigbeeAPSConsts.CMD_KEY_TC_LINK */) {
                logger_js_1.logger.debug(() => `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}]`, NS);
                if (this.#trustCenterPolicies.allowTCKeyRequest === TrustCenterKeyRequestPolicy.ALLOWED) {
                    await this.sendZigbeeAPSTransportKeyTC(nwkHeader.source16, this.netParams.tcKey, device64);
                }
                // TODO TrustCenterKeyRequestPolicy.ONLY_PROVISIONAL
                //      this.apsDeviceKeyPairSet => find deviceAddress === this.deviceTable.get(nwkHeader.source).address64 => check provisional or drop msg
            }
        }
        else {
            logger_js_1.logger.warning(`<=x= APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}] Unknown device`, NS);
        }
        return offset;
    }
    async sendZigbeeAPSRequestKey(nwkDest16, keyType, partner64) {
        logger_js_1.logger.debug(() => `===> APS REQUEST_KEY[type=${keyType} partner64=${partner64}]`, NS);
        const hasPartner64 = keyType === 2 /* ZigbeeAPSConsts.CMD_KEY_APP_MASTER */;
        const finalPayload = Buffer.alloc(2 + (hasPartner64 ? 8 : 0));
        let offset = 0;
        finalPayload.writeUInt8(8 /* ZigbeeAPSCommandId.REQUEST_KEY */, offset);
        offset += 1;
        finalPayload.writeUInt8(keyType, offset);
        offset += 1;
        if (hasPartner64) {
            finalPayload.writeBigUInt64LE(partner64, offset);
            offset += 8;
        }
        return await this.sendZigbeeAPSCommand(8 /* ZigbeeAPSCommandId.REQUEST_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-R #4.4.11.5
     */
    processZigbeeAPSSwitchKey(data, offset, macHeader, nwkHeader, _apsHeader) {
        const seqNum = data.readUInt8(offset);
        offset += 1;
        logger_js_1.logger.debug(() => `<=== APS SWITCH_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${seqNum}]`, NS);
        return offset;
    }
    /**
     * 05-3474-R #4.4.11.5
     *
     * @param nwkDest16
     * @param seqNum SHALL contain the sequence number identifying the network key to be made active.
     * @returns
     */
    async sendZigbeeAPSSwitchKey(nwkDest16, seqNum) {
        logger_js_1.logger.debug(() => `===> APS SWITCH_KEY[seqNum=${seqNum}]`, NS);
        const finalPayload = Buffer.from([9 /* ZigbeeAPSCommandId.SWITCH_KEY */, seqNum]);
        return await this.sendZigbeeAPSCommand(9 /* ZigbeeAPSCommandId.SWITCH_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-R #4.4.11.6
     */
    processZigbeeAPSTunnel(data, offset, macHeader, nwkHeader, _apsHeader) {
        const destination = data.readBigUInt64LE(offset);
        offset += 8;
        const tunneledAPSFrame = data.subarray(offset);
        offset += tunneledAPSFrame.byteLength;
        logger_js_1.logger.debug(() => `<=== APS TUNNEL[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dst=${destination} tAPSFrame=${tunneledAPSFrame}]`, NS);
        return offset;
    }
    /**
     * 05-3474-R #4.4.11.6
     *
     * @param nwkDest16
     * @param destination64 SHALL be the 64-bit extended address of the device that is to receive the tunneled command
     * @param tApsCmdFrame SHALL be the APS command payload to be sent to the destination
     * @returns
     */
    async sendZigbeeAPSTunnel(nwkDest16, destination64, tApsCmdFrame) {
        logger_js_1.logger.debug(() => `===> APS TUNNEL[dst64=${destination64}]`, NS);
        const finalPayload = Buffer.alloc(9 + tApsCmdFrame.byteLength);
        let offset = 0;
        finalPayload.writeUInt8(14 /* ZigbeeAPSCommandId.TUNNEL */, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        finalPayload.set(tApsCmdFrame, offset);
        offset += tApsCmdFrame.byteLength;
        return await this.sendZigbeeAPSCommand(14 /* ZigbeeAPSCommandId.TUNNEL */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-R #4.4.11.7
     */
    async processZigbeeAPSVerifyKey(data, offset, macHeader, nwkHeader, _apsHeader) {
        const keyType = data.readUInt8(offset);
        offset += 1;
        const source = data.readBigUInt64LE(offset);
        offset += 8;
        const keyHash = data.subarray(offset, offset + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        offset += 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */;
        if (macHeader.source16 !== 65535 /* ZigbeeMACConsts.BCAST_ADDR */) {
            logger_js_1.logger.debug(() => `<=== APS VERIFY_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} src64=${source} hash=${keyHash.toString("hex")}]`, NS);
            if (keyType === 4 /* ZigbeeAPSConsts.CMD_KEY_TC_LINK */) {
                // TODO: not valid if operating in distributed network
                const status = this.#tcVerifyKeyHash.equals(keyHash) ? 0x00 /* SUCCESS */ : 0xad; /* SECURITY_FAILURE */
                await this.sendZigbeeAPSConfirmKey(nwkHeader.source16, status, keyType, source);
            }
            else if (keyType === 2 /* ZigbeeAPSConsts.CMD_KEY_APP_MASTER */) {
                // this is illegal for TC
                await this.sendZigbeeAPSConfirmKey(nwkHeader.source16, 0xa3 /* ILLEGAL_REQUEST */, keyType, source);
            }
            else {
                await this.sendZigbeeAPSConfirmKey(nwkHeader.source16, 0xaa /* NOT_SUPPORTED */, keyType, source);
            }
        }
        return offset;
    }
    /**
     * 05-3474-R #4.4.11.7
     *
     * @param nwkDest16
     * @param keyType type of key being verified
     * @param source64 SHALL be the 64-bit extended address of the partner device that the destination shares the link key with
     * @param hash outcome of executing the specialized keyed hash function specified in section B.1.4 using a key with the 1-octet string ‘0x03’ as the input string
     * The resulting value SHALL NOT be used as a key for encryption or decryption
     * @returns
     */
    async sendZigbeeAPSVerifyKey(nwkDest16, keyType, source64, hash) {
        logger_js_1.logger.debug(() => `===> APS VERIFY_KEY[type=${keyType} src64=${source64} hash=${hash.toString("hex")}]`, NS);
        const finalPayload = Buffer.alloc(26);
        let offset = 0;
        finalPayload.writeUInt8(15 /* ZigbeeAPSCommandId.VERIFY_KEY */, offset);
        offset += 1;
        finalPayload.writeUInt8(keyType, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(source64, offset);
        offset += 8;
        finalPayload.set(hash, offset);
        offset += hash.byteLength; // 16
        return await this.sendZigbeeAPSCommand(15 /* ZigbeeAPSCommandId.VERIFY_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-R #4.4.11.8
     */
    processZigbeeAPSConfirmKey(data, offset, macHeader, nwkHeader, _apsHeader) {
        const status = data.readUInt8(offset);
        offset += 8;
        const keyType = data.readUInt8(offset);
        offset += 1;
        const destination = data.readBigUInt64LE(offset);
        offset += 8;
        logger_js_1.logger.debug(() => `<=== APS CONFIRM_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${status} type=${keyType} dst64=${destination}]`, NS);
        return offset;
    }
    /**
     * 05-3474-R #4.4.11.8
     *
     * @param nwkDest16
     * @param status 1-byte status code indicating the result of the operation. See Table 2.27
     * @param keyType the type of key being verified
     * @param destination64 SHALL be the 64-bit extended address of the source device of the Verify-Key message
     * @returns
     */
    async sendZigbeeAPSConfirmKey(nwkDest16, status, keyType, destination64) {
        logger_js_1.logger.debug(() => `===> APS CONFIRM_KEY[status=${status} type=${keyType} dst64=${destination64}]`, NS);
        const finalPayload = Buffer.alloc(11);
        let offset = 0;
        finalPayload.writeUInt8(16 /* ZigbeeAPSCommandId.CONFIRM_KEY */, offset);
        offset += 1;
        finalPayload.writeUInt8(status, offset);
        offset += 1;
        finalPayload.writeUInt8(keyType, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        const result = await this.sendZigbeeAPSCommand(16 /* ZigbeeAPSCommandId.CONFIRM_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 0 /* ZigbeeKeyType.LINK */, // XXX: TRANSPORT?
                nonce: true,
            },
            frameCounter: this.nextTCKeyFrameCounter(),
            source64: this.netParams.eui64,
            // keySeqNum: undefined, only for keyId NWK
            micLen: 4,
        });
        const device = this.deviceTable.get(destination64);
        // TODO: proper place?
        if (device !== undefined && device.authorized === false) {
            device.authorized = true;
            setImmediate(() => {
                this.emit("deviceAuthorized", device.address16, destination64);
            });
        }
        return result;
    }
    /**
     * 05-3474-R #4.4.11.9
     */
    processZigbeeAPSRelayMessageDownstream(data, offset, macHeader, nwkHeader, _apsHeader) {
        // this includes only TLVs
        // This contains the EUI64 of the unauthorized neighbor that is the intended destination of the relayed message.
        const destination64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the Trust Center to the Joining device.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;
        logger_js_1.logger.debug(() => `<=== APS RELAY_MESSAGE_DOWNSTREAM[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dst64=${destination64}]`, NS);
        return offset;
    }
    // TODO: send RELAY_MESSAGE_DOWNSTREAM
    /**
     * 05-3474-R #4.4.11.10
     */
    processZigbeeAPSRelayMessageUpstream(data, offset, macHeader, nwkHeader, _apsHeader) {
        // this includes only TLVs
        // This contains the EUI64 of the unauthorized neighbor that is the source of the relayed message.
        const source64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the joining device to the Trust Center.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;
        logger_js_1.logger.debug(() => `<=== APS RELAY_MESSAGE_UPSTREAM[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} src64=${source64}]`, NS);
        return offset;
    }
    // TODO: send RELAY_MESSAGE_UPSTREAM
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
    getOrGenerateAppLinkKey(_device16, _partner64) {
        // TODO: whole mechanism
        return this.netParams.tcKey;
    }
    isNetworkUp() {
        return this.#networkUp;
    }
    /**
     * Set the Spinel properties required to start a 802.15.4 MAC network.
     *
     * Should be called after `start`.
     */
    async formNetwork() {
        logger_js_1.logger.info("======== Network starting ========", NS);
        if (!this.#stateLoaded) {
            throw new Error("Cannot form network before state is loaded", { cause: statuses_js_1.SpinelStatus.INVALID_STATE });
        }
        // TODO: sanity checks?
        await this.setProperty((0, spinel_js_1.writePropertyb)(32 /* SpinelPropertyId.PHY_ENABLED */, true));
        await this.setProperty((0, spinel_js_1.writePropertyC)(33 /* SpinelPropertyId.PHY_CHAN */, this.netParams.channel));
        // TODO: ?
        // try { await this.setPHYCCAThreshold(10); } catch (error) {}
        await this.setPHYTXPower(this.netParams.txPower);
        await this.setProperty((0, spinel_js_1.writePropertyE)(52 /* SpinelPropertyId.MAC_15_4_LADDR */, this.netParams.eui64));
        await this.setProperty((0, spinel_js_1.writePropertyS)(53 /* SpinelPropertyId.MAC_15_4_SADDR */, 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */));
        await this.setProperty((0, spinel_js_1.writePropertyS)(54 /* SpinelPropertyId.MAC_15_4_PANID */, this.netParams.panId));
        await this.setProperty((0, spinel_js_1.writePropertyb)(59 /* SpinelPropertyId.MAC_RX_ON_WHEN_IDLE_MODE */, true));
        await this.setProperty((0, spinel_js_1.writePropertyb)(55 /* SpinelPropertyId.MAC_RAW_STREAM_ENABLED */, true));
        const txPower = await this.getPHYTXPower();
        const radioRSSI = await this.getPHYRSSI();
        this.rssiMin = await this.getPHYRXSensitivity();
        let ccaThreshold;
        try {
            ccaThreshold = await this.getPHYCCAThreshold();
        }
        catch (error) {
            logger_js_1.logger.debug(() => `PHY_CCA_THRESHOLD: ${error}`, NS);
        }
        logger_js_1.logger.info(`======== Network started (PHY: txPower=${txPower}dBm rssi=${radioRSSI}dBm rxSensitivity=${this.rssiMin}dBm ccaThreshold=${ccaThreshold}dBm) ========`, NS);
        this.#networkUp = true;
        await this.registerTimers();
    }
    /**
     * Remove the current state file and clear all related tables.
     *
     * Will throw if state already loaded (should be called before `start`).
     */
    async resetNetwork() {
        logger_js_1.logger.info("======== Network resetting ========", NS);
        if (this.#stateLoaded) {
            throw new Error("Cannot reset network after state already loaded", { cause: statuses_js_1.SpinelStatus.INVALID_STATE });
        }
        // remove `zoh.save`
        await (0, promises_1.rm)(this.savePath, { force: true });
        this.deviceTable.clear();
        this.address16ToAddress64.clear();
        this.indirectTransmissions.clear();
        this.sourceRouteTable.clear();
        this.pendingAssociations.clear();
        logger_js_1.logger.info("======== Network reset ========", NS);
    }
    async registerTimers() {
        // TODO: periodic/delayed actions
        this.#saveStateTimeout = setTimeout(this.savePeriodicState.bind(this), CONFIG_SAVE_STATE_TIME);
        this.#nwkLinkStatusTimeout = setTimeout(this.sendPeriodicZigbeeNWKLinkStatus.bind(this), CONFIG_NWK_LINK_STATUS_PERIOD + Math.random() * CONFIG_NWK_LINK_STATUS_JITTER);
        this.#manyToOneRouteRequestTimeout = setTimeout(this.sendPeriodicManyToOneRouteRequest.bind(this), CONFIG_NWK_CONCENTRATOR_DISCOVERY_TIME);
        await this.savePeriodicState();
        await this.sendPeriodicZigbeeNWKLinkStatus();
        await this.sendPeriodicManyToOneRouteRequest();
    }
    async savePeriodicState() {
        await this.saveState();
        this.#saveStateTimeout?.refresh();
    }
    async sendPeriodicZigbeeNWKLinkStatus() {
        const links = [];
        for (const [device64, entry] of this.deviceTable.entries()) {
            if (entry.neighbor) {
                try {
                    // TODO: proper cost values
                    const [, , pathCost] = this.findBestSourceRoute(entry.address16, device64);
                    links.push({
                        address: entry.address16,
                        incomingCost: pathCost ?? 0,
                        outgoingCost: pathCost ?? 0,
                    });
                }
                catch {
                    /* ignore */
                }
            }
        }
        await this.sendZigbeeNWKLinkStatus(links);
        this.#nwkLinkStatusTimeout?.refresh();
    }
    async sendPeriodicManyToOneRouteRequest() {
        if (Date.now() > this.#lastMTORRTime + CONFIG_NWK_CONCENTRATOR_MIN_TIME) {
            await this.sendZigbeeNWKRouteReq(1 /* ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING */, 65532 /* ZigbeeConsts.BCAST_DEFAULT */);
            this.#manyToOneRouteRequestTimeout?.refresh();
            this.#lastMTORRTime = Date.now();
        }
    }
    /**
     * @param duration The length of time in seconds during which the trust center will allow joins.
     * The value 0x00 and 0xff indicate that permission is disabled or enabled, respectively, without a specified time limit.
     * 0xff is clamped to 0xfe for security reasons
     * @param macAssociationPermit If true, also allow association on coordinator itself. Ignored if duration 0.
     */
    allowJoins(duration, macAssociationPermit) {
        if (duration > 0) {
            clearTimeout(this.#allowJoinTimeout);
            this.#trustCenterPolicies.allowJoins = true;
            this.#trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
            this.#macAssociationPermit = macAssociationPermit;
            this.#allowJoinTimeout = setTimeout(this.disallowJoins.bind(this), Math.min(duration, 0xfe) * 1000);
            logger_js_1.logger.info(`Allowed joins for ${duration} seconds (self=${macAssociationPermit})`, NS);
        }
        else {
            this.disallowJoins();
        }
    }
    /**
     * Revert allowing joins (keeps `allowRejoinsWithWellKnownKey=true`).
     */
    disallowJoins() {
        clearTimeout(this.#allowJoinTimeout);
        this.#allowJoinTimeout = undefined;
        this.#trustCenterPolicies.allowJoins = false;
        this.#trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
        this.#macAssociationPermit = false;
        logger_js_1.logger.info("Disallowed joins", NS);
    }
    /**
     * Put the coordinator in Green Power commissioning mode.
     * @param commissioningWindow Defaults to 180 if unspecified. Max 254. 0 means exit.
     */
    gpEnterCommissioningMode(commissioningWindow = 180) {
        if (commissioningWindow > 0) {
            clearTimeout(this.#gpCommissioningWindowTimeout);
            this.#gpCommissioningMode = true;
            this.#gpCommissioningWindowTimeout = setTimeout(this.gpExitCommissioningMode.bind(this), Math.min(commissioningWindow, 0xfe) * 1000);
            logger_js_1.logger.info(`Entered Green Power commissioning mode for ${commissioningWindow} seconds`, NS);
        }
        else {
            this.gpExitCommissioningMode();
        }
    }
    gpExitCommissioningMode() {
        clearTimeout(this.#gpCommissioningWindowTimeout);
        this.#gpCommissioningWindowTimeout = undefined;
        this.#gpCommissioningMode = false;
        logger_js_1.logger.info("Exited Green Power commissioning mode", NS);
    }
    /**
     * 05-3474-23 #3.6.1.10
     */
    assignNetworkAddress() {
        let newNetworkAddress = 0xffff;
        let unique = false;
        do {
            // maximum exclusive, minimum inclusive
            newNetworkAddress = Math.floor(Math.random() * (65528 /* ZigbeeConsts.BCAST_MIN */ - 0x0001) + 0x0001);
            unique = this.address16ToAddress64.get(newNetworkAddress) === undefined;
        } while (!unique);
        return newNetworkAddress;
    }
    /**
     * @param source16
     * @param source64 Assumed valid if assocType === 0x00
     * @param initialJoin If false, rejoin.
     * @param neighbor True if the device associating is a neighbor of the coordinator
     * @param capabilities MAC capabilities
     * @param denyOverride Treat as MACAssociationStatus.PAN_ACCESS_DENIED
     * @param allowOverride Treat as MACAssociationStatus.SUCCESS
     * @returns
     */
    async associate(source16, source64, initialJoin, capabilities, neighbor, denyOverride, allowOverride) {
        // 0xffff when not successful and should not be retried
        let newAddress16 = source16;
        let status = mac_js_1.MACAssociationStatus.SUCCESS;
        let unknownRejoin = false;
        if (denyOverride) {
            newAddress16 = 0xffff;
            status = mac_js_1.MACAssociationStatus.PAN_ACCESS_DENIED;
        }
        else if (allowOverride) {
            if ((source16 === undefined || !this.address16ToAddress64.has(source16)) && (source64 === undefined || !this.deviceTable.has(source64))) {
                // device unknown
                unknownRejoin = true;
            }
        }
        else {
            if (initialJoin) {
                if (this.#trustCenterPolicies.allowJoins) {
                    if (source16 === undefined || source16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ || source16 >= 65528 /* ZigbeeConsts.BCAST_MIN */) {
                        // MAC join (no `source16`)
                        newAddress16 = this.assignNetworkAddress();
                        if (newAddress16 === 0xffff) {
                            status = mac_js_1.MACAssociationStatus.PAN_FULL;
                        }
                    }
                    else if (source64 !== undefined && this.deviceTable.get(source64) !== undefined) {
                        // initial join should not conflict on 64, don't allow join if it does
                        newAddress16 = 0xffff;
                        status = 240 /* ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT */;
                    }
                    else {
                        const existingAddress64 = this.address16ToAddress64.get(source16);
                        if (existingAddress64 !== undefined && source64 !== existingAddress64) {
                            // join with already taken source16
                            newAddress16 = this.assignNetworkAddress();
                            if (newAddress16 === 0xffff) {
                                status = mac_js_1.MACAssociationStatus.PAN_FULL;
                            }
                            else {
                                // tell device to use the newly generated value
                                status = 240 /* ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT */;
                            }
                        }
                    }
                }
                else {
                    newAddress16 = 0xffff;
                    status = mac_js_1.MACAssociationStatus.PAN_ACCESS_DENIED;
                }
            }
            else {
                // rejoin
                if (source16 === undefined || source16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ || source16 >= 65528 /* ZigbeeConsts.BCAST_MIN */) {
                    // rejoin without 16, generate one (XXX: never happens?)
                    newAddress16 = this.assignNetworkAddress();
                    if (newAddress16 === 0xffff) {
                        status = mac_js_1.MACAssociationStatus.PAN_FULL;
                    }
                }
                else {
                    const existingAddress64 = this.address16ToAddress64.get(source16);
                    if (existingAddress64 === undefined) {
                        // device unknown
                        unknownRejoin = true;
                    }
                    else if (existingAddress64 !== source64) {
                        // rejoin with already taken source16
                        newAddress16 = this.assignNetworkAddress();
                        if (newAddress16 === 0xffff) {
                            status = mac_js_1.MACAssociationStatus.PAN_FULL;
                        }
                        else {
                            // tell device to use the newly generated value
                            status = 240 /* ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT */;
                        }
                    }
                }
                // if rejoin, network address will be stored
                // if (this.trustCenterPolicies.allowRejoinsWithWellKnownKey) {
                // }
            }
        }
        // something went wrong above
        /* v8 ignore start */
        if (newAddress16 === undefined) {
            newAddress16 = 0xffff;
            status = mac_js_1.MACAssociationStatus.PAN_ACCESS_DENIED;
        }
        /* v8 ignore stop */
        logger_js_1.logger.debug(() => `DEVICE_JOINING[src=${source16}:${source64} newAddr16=${newAddress16} initialJoin=${initialJoin} deviceType=${capabilities?.deviceType} powerSource=${capabilities?.powerSource} rxOnWhenIdle=${capabilities?.rxOnWhenIdle}] replying with status=${status}`, NS);
        if (status === mac_js_1.MACAssociationStatus.SUCCESS) {
            if (initialJoin || unknownRejoin) {
                this.deviceTable.set(source64, {
                    address16: newAddress16,
                    capabilities, // TODO: only valid if not triggered by `processZigbeeAPSUpdateDevice`
                    // on initial join success, device is considered joined but unauthorized after MAC Assoc / NWK Commissioning response is sent
                    authorized: false,
                    neighbor,
                    recentLQAs: [],
                });
                this.address16ToAddress64.set(newAddress16, source64);
                // `processZigbeeAPSUpdateDevice` has no `capabilities` info, device is joined through router, so, no indirect tx for coordinator
                if (capabilities && !capabilities.rxOnWhenIdle) {
                    this.indirectTransmissions.set(source64, []);
                }
            }
            else {
                // update records on rejoin in case anything has changed (like neighbor for routing)
                this.address16ToAddress64.set(newAddress16, source64);
                const device = this.deviceTable.get(source64);
                device.address16 = newAddress16;
                device.capabilities = capabilities;
                device.neighbor = neighbor;
            }
            // force saving after device change
            await this.savePeriodicState();
        }
        return [status, newAddress16];
    }
    async disassociate(source16, source64) {
        if (source64 === undefined && source16 !== undefined) {
            source64 = this.address16ToAddress64.get(source16);
        }
        else if (source16 === undefined && source64 !== undefined) {
            source16 = this.deviceTable.get(source64)?.address16;
        }
        // sanity check
        if (source16 !== undefined && source64 !== undefined) {
            this.deviceTable.delete(source64);
            this.address16ToAddress64.delete(source16);
            this.indirectTransmissions.delete(source64);
            this.sourceRouteTable.delete(source16);
            this.pendingAssociations.delete(source64); // should never amount to a delete
            this.macNoACKs.delete(source16);
            this.routeFailures.delete(source16);
            // XXX: should only be needed for `rxOnWhenIdle`, but for now always trigger (tricky bit, not always correct)
            for (const [addr16, entries] of this.sourceRouteTable) {
                // entries using this device as relay are no longer valid
                const filteredEntries = entries.filter((entry) => !entry.relayAddresses.includes(source16));
                if (filteredEntries.length === 0) {
                    this.sourceRouteTable.delete(addr16);
                }
                else if (filteredEntries.length !== entries.length) {
                    this.sourceRouteTable.set(addr16, filteredEntries);
                }
            }
            logger_js_1.logger.debug(() => `DEVICE_LEFT[src=${source16}:${source64}]`, NS);
            setImmediate(() => {
                this.emit("deviceLeft", source16, source64);
            });
            // force new MTORR
            await this.sendPeriodicManyToOneRouteRequest();
            // force saving after device change
            await this.savePeriodicState();
        }
    }
    /**
     * Check if a source route entry for the given address is already present.
     * If `existingEntries` not given and address16 doesn't have any entries, always returns false.
     * @param address16 The network address to check for
     * @param newEntry The entry to check
     * @param existingEntries If given, skip the retrieval from `sourceRouteTable` and use these entries to check against instead
     * @returns
     */
    hasSourceRoute(address16, newEntry, existingEntries) {
        if (!existingEntries) {
            existingEntries = this.sourceRouteTable.get(address16);
            if (!existingEntries) {
                return false;
            }
        }
        for (const existingEntry of existingEntries) {
            if (newEntry.pathCost === existingEntry.pathCost && newEntry.relayAddresses.length === existingEntry.relayAddresses.length) {
                let matching = true;
                for (let i = 0; i < newEntry.relayAddresses.length; i++) {
                    if (newEntry.relayAddresses[i] !== existingEntry.relayAddresses[i]) {
                        matching = false;
                        break;
                    }
                }
                if (matching) {
                    return true;
                }
            }
        }
        return false;
    }
    /**
     * Finds the best source route to the destination.
     * Entries with relays with too many NO_ACK will be purged.
     * Bails early if destination16 is broadcast.
     * Throws if both 16/64 are undefined or if destination is unknown (not in device table).
     * Throws if no route and device is not neighbor.
     * @param destination16
     * @param destination64
     * @returns
     * - request invalid or neighbor without source route entries: [undefined, undefined, undefined]
     * - request valid and source route available and >=1 relay: [last index in relayAddresses, list of relay addresses, cost of the path]
     * - request valid and source route available and 0 relay: [undefined, undefined, cost of the path]
     */
    findBestSourceRoute(destination16, destination64) {
        if (destination16 !== undefined && destination16 >= 65528 /* ZigbeeConsts.BCAST_MIN */) {
            return [undefined, undefined, undefined];
        }
        if (destination16 === undefined) {
            if (destination64 === undefined) {
                throw new Error("Invalid parameters", { cause: statuses_js_1.SpinelStatus.INVALID_ARGUMENT });
            }
            const device = this.deviceTable.get(destination64);
            if (device === undefined) {
                throw new Error("Unknown destination", { cause: statuses_js_1.SpinelStatus.ITEM_NOT_FOUND });
            }
            destination16 = device.address16;
        }
        else if (!this.address16ToAddress64.has(destination16)) {
            throw new Error("Unknown destination", { cause: statuses_js_1.SpinelStatus.ITEM_NOT_FOUND });
        }
        const sourceRouteEntries = this.sourceRouteTable.get(destination16);
        if (sourceRouteEntries === undefined || sourceRouteEntries.length === 0) {
            // cleanup
            this.sourceRouteTable.delete(destination16);
            if (!this.deviceTable.get(destination64 ?? this.address16ToAddress64.get(destination16)).neighbor) {
                // force immediate MTORR
                logger_js_1.logger.warning("No known route to destination, forcing discovery", NS);
                setImmediate(this.sendPeriodicManyToOneRouteRequest.bind(this));
                // will send direct as "last resort"
            }
            return [undefined, undefined, undefined];
        }
        if (sourceRouteEntries.length > 1) {
            // sort by lowest cost first, if more than one entry
            // TODO: add property that keeps track of error count to further sort identical cost matches?
            sourceRouteEntries.sort((a, b) => a.pathCost - b.pathCost);
        }
        let relays = sourceRouteEntries[0].relayAddresses;
        let relayLastIndex = relays.length - 1;
        // don't check relays validity when direct
        if (relayLastIndex !== -1) {
            let mtorr = false;
            let valid = true;
            do {
                valid = true;
                // check relays for NO_ACK state, and either continue, or find the next best route
                for (const relay of relays) {
                    const macNoACKs = this.macNoACKs.get(relay);
                    if (macNoACKs !== undefined && macNoACKs >= CONFIG_NWK_CONCENTRATOR_DELIVERY_FAILURE_THRESHOLD) {
                        mtorr = true;
                        sourceRouteEntries.shift();
                        if (sourceRouteEntries.length === 0) {
                            this.sourceRouteTable.delete(destination16);
                            if (!this.deviceTable.get(destination64 ?? this.address16ToAddress64.get(destination16)).neighbor) {
                                // force immediate MTORR
                                logger_js_1.logger.warning("No known route to destination, forcing discovery", NS);
                                setImmediate(this.sendPeriodicManyToOneRouteRequest.bind(this));
                                // will send direct as "last resort"
                            }
                            // no more source route, bail
                            return [undefined, undefined, undefined];
                        }
                        relays = sourceRouteEntries[0].relayAddresses;
                        relayLastIndex = relays.length - 1;
                        valid = false;
                        break;
                    }
                }
            } while (!valid);
            if (mtorr) {
                // force immediate MTORR
                setImmediate(this.sendPeriodicManyToOneRouteRequest.bind(this));
            }
        }
        if (relayLastIndex >= 0) {
            return [relayLastIndex, relays, sourceRouteEntries[0].pathCost];
        }
        return [undefined, undefined, sourceRouteEntries[0].pathCost];
    }
    // TODO: interference detection (& optionally auto channel changing)
    /**
     * Apply logistic curve on standard mapping to LQI range [0..255]
     *
     * - Silabs EFR32: the RSSI range of [-100..-36] is mapped to an LQI range [0..255]
     * - TI zstack: `LQI = (MAC_SPEC_ED_MAX * (RSSIdbm - ED_RF_POWER_MIN_DBM)) / (ED_RF_POWER_MAX_DBM - ED_RF_POWER_MIN_DBM);`
     *     where `MAC_SPEC_ED_MAX = 255`, `ED_RF_POWER_MIN_DBM = -87`, `ED_RF_POWER_MAX_DBM = -10`
     * - Nordic: RSSI accuracy valid range -90 to -20 dBm
     */
    mapRSSIToLQI(rssi) {
        if (rssi < this.rssiMin) {
            return 0;
        }
        if (rssi > this.rssiMax) {
            return 255;
        }
        return Math.floor(255 / (1 + Math.exp(-0.13 * (rssi - (this.rssiMin + 0.45 * (this.rssiMax - this.rssiMin))))));
    }
    /**
     * LQA_raw (c, r) = 255 * (c - c_min) / (c_max - c_min) * (r - r_min) / (r_max - r_min)
     * - c_min is the lowest signal quality ever reported, i.e. for a packet that can barely be received
     * - c_max is the highest signal quality ever reported, i.e. for a packet received under ideal conditions
     * - r_min is the lowest signal strength ever reported, i.e. for a packet close to receiver sensitivity
     * - r_max is the highest signal strength ever reported, i.e. for a packet received from a strong, close-by transmitter
     * @param signalStrength
     * @param signalQuality
     * @returns
     */
    computeLQA(signalStrength, signalQuality) {
        if (signalQuality === undefined) {
            signalQuality = this.mapRSSIToLQI(signalStrength);
        }
        if (signalStrength < this.rssiMin) {
            signalStrength = this.rssiMin;
        }
        if (signalStrength > this.rssiMax) {
            signalStrength = this.rssiMax;
        }
        if (signalQuality < this.lqiMin) {
            signalQuality = this.lqiMin;
        }
        if (signalQuality > this.lqiMax) {
            signalQuality = this.lqiMax;
        }
        return Math.floor((((255 * (signalQuality - this.lqiMin)) / (this.lqiMax - this.lqiMin)) * (signalStrength - this.rssiMin)) / (this.rssiMax - this.rssiMin));
    }
    /**
     * Compute the median LQA for a device from `recentLQAs` or using `signalStrength` directly if device unknown.
     * If given, stores the computed LQA from given parameters in the `recentLQAs` list of the device before computing median.
     * @param address16 Used to retrieve `address64` if not given (must be valid if 64 is not)
     * @param address64 The address 64 of the device
     * @param signalStrength RSSI. Optional (only use existing entries if not given)
     * @param signalQuality LQI. Optional (only use existing entries if not given)
     * @param maxRecent The number of `recentLQAs` to keep for the device (only used if signal params given). Default: 10
     * @returns The computed LQA
     * - Always 0 if device not found AND no `signalStrength` given.
     * - Always 0 if the device does not have any recent LQAs AND no `signalStrength` given
     */
    computeDeviceLQA(address16, address64, signalStrength, signalQuality, maxRecent = 10) {
        if (address64 === undefined && address16 !== undefined) {
            address64 = this.address16ToAddress64.get(address16);
        }
        // sanity check
        if (address64 !== undefined) {
            const device = this.deviceTable.get(address64);
            if (!device) {
                return 0;
            }
            if (signalStrength !== undefined) {
                const lqa = this.computeLQA(signalStrength, signalQuality);
                if (device.recentLQAs.length > maxRecent) {
                    // remove oldest LQA if necessary
                    device.recentLQAs.shift();
                }
                device.recentLQAs.push(lqa);
            }
            if (device.recentLQAs.length === 0) {
                return 0;
            }
            if (device.recentLQAs.length === 1) {
                return device.recentLQAs[0];
            }
            const sortedLQAs = device.recentLQAs.slice( /* copy */).sort((a, b) => a - b);
            const midIndex = Math.floor(sortedLQAs.length / 2);
            const median = Math.floor(sortedLQAs.length % 2 === 1 ? sortedLQAs[midIndex] : (sortedLQAs[midIndex - 1] + sortedLQAs[midIndex]) / 2);
            return median;
        }
        return signalStrength !== undefined ? this.computeLQA(signalStrength, signalQuality) : 0;
    }
    /**
     * ZDO response to LQI_TABLE_REQUEST for coordinator
     * @see 05-3474-23 #2.4.4.3.2
     * @param startIndex
     * @returns
     */
    getLQITableResponse(startIndex) {
        let neighborRouteTableIndex = 0;
        let neighborTableEntries = 0;
        // multiple of 7: [extendedPanId, eui64, nwkAddress, deviceTypeByte, permitJoiningByte, depth, lqa, ...repeat]
        const lqiTableArr = [];
        // XXX: this is not great...
        for (const [addr64, entry] of this.deviceTable) {
            if (entry.neighbor) {
                if (neighborRouteTableIndex < startIndex) {
                    // if under `startIndex`, just count
                    neighborRouteTableIndex += 1;
                    neighborTableEntries += 1;
                    continue;
                }
                if (neighborRouteTableIndex >= startIndex + 0xff) {
                    // if over uint8 size from `startIndex`, just count
                    neighborRouteTableIndex += 1;
                    neighborTableEntries += 1;
                    continue;
                }
                const deviceType = entry.capabilities ? (entry.capabilities.deviceType === 1 ? 0x01 /* ZR */ : 0x02 /* ZED */) : 0x03 /* UNK */;
                const rxOnWhenIdle = entry.capabilities ? (entry.capabilities.rxOnWhenIdle ? 0x01 /* ON */ : 0x00 /* OFF */) : 0x02 /* UNK */;
                const relationship = 0x02; // TODO // 0x00 = neighbor is the parent, 0x01 = neighbor is a child, 0x02 = neighbor is a sibling, 0x03 = None of the above
                const permitJoining = 0x02; // TODO // 0x00 = neighbor is not accepting join requests, 0x01 = neighbor is accepting join requests, 0x02 = unknown
                const deviceTypeByte = (deviceType & 0x03) | ((rxOnWhenIdle << 2) & 0x03) | ((relationship << 4) & 0x07) | ((0 /* reserved */ << 7) & 0x01);
                const permitJoiningByte = (permitJoining & 0x03) | ((0 /* reserved2 */ << 2) & 0x3f);
                const depth = 1; // TODO // 0x00 indicates that the device is the Zigbee coordinator for the network
                const lqa = this.computeDeviceLQA(entry.address16, addr64);
                lqiTableArr.push(this.netParams.extendedPANId);
                lqiTableArr.push(addr64);
                lqiTableArr.push(entry.address16);
                lqiTableArr.push(deviceTypeByte);
                lqiTableArr.push(permitJoiningByte);
                lqiTableArr.push(depth);
                lqiTableArr.push(lqa);
                neighborTableEntries += 1;
                neighborRouteTableIndex += 1;
            }
        }
        // have to fit uint8 count-type bytes of ZDO response
        const clipped = neighborTableEntries > 0xff;
        const entryCount = lqiTableArr.length / 7;
        const lqiTable = Buffer.alloc(5 + entryCount * 22);
        let offset = 0;
        if (clipped) {
            logger_js_1.logger.debug(() => `LQI table clipped at 255 entries to fit ZDO response (actual=${neighborTableEntries})`, NS);
        }
        lqiTable.writeUInt8(0 /* seq num */, offset);
        offset += 1;
        lqiTable.writeUInt8(0 /* SUCCESS */, offset);
        offset += 1;
        lqiTable.writeUInt8(neighborTableEntries, offset);
        offset += 1;
        lqiTable.writeUInt8(startIndex, offset);
        offset += 1;
        lqiTable.writeUInt8(entryCount, offset);
        offset += 1;
        let entryIndex = 0;
        for (let i = 0; i < entryCount; i++) {
            lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex] /* extendedPanId */, offset);
            offset += 8;
            lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex + 1] /* eui64 */, offset);
            offset += 8;
            lqiTable.writeUInt16LE(lqiTableArr[entryIndex + 2] /* nwkAddress */, offset);
            offset += 2;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 3] /* deviceTypeByte */, offset);
            offset += 1;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 4] /* permitJoiningByte */, offset);
            offset += 1;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 5] /* depth */, offset);
            offset += 1;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 6] /* lqa */, offset);
            offset += 1;
            entryIndex += 7;
        }
        return lqiTable;
    }
    /**
     * ZDO response to ROUTING_TABLE_REQUEST for coordinator
     * NOTE: Only outputs the best source route for each entry in the table (clipped to max 255 entries).
     * @see 05-3474-23 #2.4.4.3.3
     * @param startIndex
     * @returns
     */
    getRoutingTableResponse(startIndex) {
        let sourceRouteTableIndex = 0;
        let routingTableEntries = 0;
        // multiple of 3: [destination16, statusByte, nextHopAddress, ...repeat]
        const routingTableArr = [];
        // XXX: this is not great...
        for (const [addr16] of this.sourceRouteTable) {
            try {
                const [relayLastIndex, relayAddresses] = this.findBestSourceRoute(addr16, undefined);
                if (relayLastIndex !== undefined && relayAddresses !== undefined) {
                    if (sourceRouteTableIndex < startIndex) {
                        // if under `startIndex`, just count
                        sourceRouteTableIndex += 1;
                        routingTableEntries += 1;
                        continue;
                    }
                    if (sourceRouteTableIndex >= startIndex + 0xff) {
                        // if over uint8 size from `startIndex`, just count
                        sourceRouteTableIndex += 1;
                        routingTableEntries += 1;
                        continue;
                    }
                    const status = 0x0; // ACTIVE
                    const memoryConstrained = 0; // TODO
                    const manyToOne = 0; // TODO
                    const routeRecordRequired = 0; // TODO
                    const statusByte = (status & 0x07) |
                        ((memoryConstrained << 3) & 0x01) |
                        ((manyToOne << 4) & 0x01) |
                        ((routeRecordRequired << 5) & 0x01) |
                        ((0 /* reserved */ << 6) & 0x03);
                    // last entry is next hop
                    const nextHopAddress = relayAddresses[relayLastIndex];
                    routingTableArr.push(addr16);
                    routingTableArr.push(statusByte);
                    routingTableArr.push(nextHopAddress);
                    routingTableEntries += 1;
                }
            }
            catch {
                /* ignore */
            }
            sourceRouteTableIndex += 1;
        }
        // have to fit uint8 count-type bytes of ZDO response
        const clipped = routingTableEntries > 0xff;
        const entryCount = routingTableArr.length / 3;
        const routingTable = Buffer.alloc(5 + entryCount * 5);
        let offset = 0;
        if (clipped) {
            logger_js_1.logger.debug(() => `Routing table clipped at 255 entries to fit ZDO response (actual=${routingTableEntries})`, NS);
        }
        routingTable.writeUInt8(0 /* seq num */, offset);
        offset += 1;
        routingTable.writeUInt8(0 /* SUCCESS */, offset);
        offset += 1;
        routingTable.writeUInt8(clipped ? 0xff : routingTableEntries, offset);
        offset += 1;
        routingTable.writeUInt8(startIndex, offset);
        offset += 1;
        routingTable.writeUInt8(entryCount, offset);
        offset += 1;
        let entryIndex = 0;
        for (let i = 0; i < entryCount; i++) {
            routingTable.writeUInt16LE(routingTableArr[entryIndex] /* destination16 */, offset);
            offset += 2;
            routingTable.writeUInt8(routingTableArr[entryIndex + 1] /* statusByte */, offset);
            offset += 1;
            routingTable.writeUInt16LE(routingTableArr[entryIndex + 2] /* nextHopAddress */, offset);
            offset += 2;
            entryIndex += 3;
        }
        return routingTable;
    }
    getCoordinatorZDOResponse(clusterId, requestData) {
        switch (clusterId) {
            case 0 /* ZigbeeConsts.NETWORK_ADDRESS_REQUEST */: {
                // TODO: handle reportKids & index, this payload is only for 0, 0
                return Buffer.from(this.configAttributes.address); // copy
            }
            case 1 /* ZigbeeConsts.IEEE_ADDRESS_REQUEST */: {
                // TODO: handle reportKids & index, this payload is only for 0, 0
                return Buffer.from(this.configAttributes.address); // copy
            }
            case 2 /* ZigbeeConsts.NODE_DESCRIPTOR_REQUEST */: {
                return Buffer.from(this.configAttributes.nodeDescriptor); // copy
            }
            case 3 /* ZigbeeConsts.POWER_DESCRIPTOR_REQUEST */: {
                return Buffer.from(this.configAttributes.powerDescriptor); // copy
            }
            case 4 /* ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST */: {
                return Buffer.from(this.configAttributes.simpleDescriptors); // copy
            }
            case 5 /* ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST */: {
                return Buffer.from(this.configAttributes.activeEndpoints); // copy
            }
            case 49 /* ZigbeeConsts.LQI_TABLE_REQUEST */: {
                return this.getLQITableResponse(requestData[1 /* 0 is tsn */]);
            }
            case 50 /* ZigbeeConsts.ROUTING_TABLE_REQUEST */: {
                return this.getRoutingTableResponse(requestData[1 /* 0 is tsn */]);
            }
        }
    }
    /**
     * Check if ZDO request is intended for coordinator.
     * @param clusterId
     * @param nwkDst16
     * @param nwkDst64
     * @param data
     * @returns
     */
    isZDORequestForCoordinator(clusterId, nwkDst16, nwkDst64, data) {
        if (nwkDst16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ || nwkDst64 === this.netParams.eui64) {
            // target is coordinator
            return true;
        }
        if (nwkDst16 !== undefined && nwkDst16 >= 65528 /* ZigbeeConsts.BCAST_MIN */) {
            // target is BCAST and ZDO "of interest" is coordinator
            switch (clusterId) {
                case 0 /* ZigbeeConsts.NETWORK_ADDRESS_REQUEST */: {
                    return data.readBigUInt64LE(1 /* skip seq num */) === this.netParams.eui64;
                }
                case 1 /* ZigbeeConsts.IEEE_ADDRESS_REQUEST */:
                case 2 /* ZigbeeConsts.NODE_DESCRIPTOR_REQUEST */:
                case 3 /* ZigbeeConsts.POWER_DESCRIPTOR_REQUEST */:
                case 4 /* ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST */:
                case 5 /* ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST */: {
                    return data.readUInt16LE(1 /* skip seq num */) === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */;
                }
            }
        }
        return false;
    }
    /**
     * Respond to ZDO requests aimed at coordinator if needed.
     * @param data
     * @param clusterId
     * @param macDest16
     * @param nwkDest16
     * @param nwkDest64
     */
    async respondToCoordinatorZDORequest(data, clusterId, nwkDest16, nwkDest64) {
        const finalPayload = this.getCoordinatorZDOResponse(clusterId, data);
        if (finalPayload) {
            // set the ZDO sequence number in outgoing payload same as incoming request
            const seqNum = data[0];
            finalPayload[0] = seqNum;
            logger_js_1.logger.debug(() => `===> COORD_ZDO[seqNum=${seqNum} clusterId=${clusterId} nwkDst=${nwkDest16}:${nwkDest64}]`, NS);
            try {
                await this.sendZigbeeAPSData(finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
                nwkDest16, // nwkDest16
                nwkDest64, // nwkDest64
                0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
                clusterId | 0x8000, // clusterId
                0 /* ZigbeeConsts.ZDO_PROFILE_ID */, // profileId
                0 /* ZigbeeConsts.ZDO_ENDPOINT */, // destEndpoint
                0 /* ZigbeeConsts.ZDO_ENDPOINT */, // sourceEndpoint
                undefined);
            }
            catch {
                // logged in `sendZigbeeAPSData`
                return;
            }
        }
    }
    // #endregion
    // #region State Management
    /**
     * Format is:
     * - network data: ${SaveConsts.NETWORK_STATE_SIZE} bytes
     * - device count: 2 bytes
     * - device data: ${SaveConsts.DEVICE_STATE_SIZE} bytes * ${device count}
     */
    async saveState() {
        const state = Buffer.alloc(1024 /* SaveConsts.NETWORK_DATA_SIZE */ + 2 + this.deviceTable.size * 512 /* SaveConsts.DEVICE_DATA_SIZE */);
        let offset = 0;
        state.writeBigUInt64LE(this.netParams.eui64, offset);
        offset += 8;
        state.writeUInt16LE(this.netParams.panId, offset);
        offset += 2;
        state.writeBigUInt64LE(this.netParams.extendedPANId, offset);
        offset += 8;
        state.writeUInt8(this.netParams.channel, offset);
        offset += 1;
        state.writeUInt8(this.netParams.nwkUpdateId, offset);
        offset += 1;
        state.writeInt8(this.netParams.txPower, offset);
        offset += 1;
        state.set(this.netParams.networkKey, offset);
        offset += 16 /* ZigbeeConsts.SEC_KEYSIZE */;
        state.writeUInt32LE(this.netParams.networkKeyFrameCounter + 1024 /* SaveConsts.FRAME_COUNTER_JUMP_OFFSET */, offset);
        offset += 4;
        state.writeUInt8(this.netParams.networkKeySequenceNumber, offset);
        offset += 1;
        state.set(this.netParams.tcKey, offset);
        offset += 16 /* ZigbeeConsts.SEC_KEYSIZE */;
        state.writeUInt32LE(this.netParams.tcKeyFrameCounter + 1024 /* SaveConsts.FRAME_COUNTER_JUMP_OFFSET */, offset);
        offset += 4;
        // reserved
        offset = 1024 /* SaveConsts.NETWORK_DATA_SIZE */;
        state.writeUInt16LE(this.deviceTable.size, offset);
        offset += 2;
        for (const [device64, device] of this.deviceTable) {
            state.writeBigUInt64LE(device64, offset);
            offset += 8;
            state.writeUInt16LE(device.address16, offset);
            offset += 2;
            state.writeUInt8(device.capabilities ? (0, mac_js_1.encodeMACCapabilities)(device.capabilities) : 0x00, offset);
            offset += 1;
            state.writeUInt8(device.authorized ? 1 : 0, offset);
            offset += 1;
            state.writeUInt8(device.neighbor ? 1 : 0, offset);
            offset += 1;
            // reserved
            offset += 64 - 13; // currently: 51
            const sourceRouteEntries = this.sourceRouteTable.get(device.address16);
            const sourceRouteEntryCount = sourceRouteEntries?.length ?? 0;
            let sourceRouteTableSize = 0;
            state.writeUInt8(sourceRouteEntryCount, offset);
            offset += 1;
            if (sourceRouteEntries) {
                for (const sourceRouteEntry of sourceRouteEntries) {
                    sourceRouteTableSize += 2 + sourceRouteEntry.relayAddresses.length * 2;
                    if (64 + 1 + sourceRouteTableSize > 512 /* SaveConsts.DEVICE_DATA_SIZE */) {
                        throw new Error("Save size overflow", { cause: statuses_js_1.SpinelStatus.INTERNAL_ERROR });
                    }
                    state.writeUInt8(sourceRouteEntry.pathCost, offset);
                    offset += 1;
                    state.writeUInt8(sourceRouteEntry.relayAddresses.length, offset);
                    offset += 1;
                    for (const relayAddress of sourceRouteEntry.relayAddresses) {
                        state.writeUInt16LE(relayAddress, offset);
                        offset += 2;
                    }
                }
            }
            // reserved
            offset += 512 /* SaveConsts.DEVICE_DATA_SIZE */ - 64 - 1 - sourceRouteTableSize;
        }
        await (0, promises_1.writeFile)(this.savePath, state);
    }
    /**
     * Load state from file system if exists, else save "initial" state.
     * Afterwards, various keys are pre-hashed and descriptors pre-encoded.
     */
    async loadState() {
        // pre-emptive
        this.#stateLoaded = true;
        try {
            const state = await (0, promises_1.readFile)(this.savePath);
            logger_js_1.logger.debug(() => `Loaded state from ${this.savePath} (${state.byteLength} bytes)`, NS);
            if (state.byteLength < 1024 /* SaveConsts.NETWORK_DATA_SIZE */) {
                throw new Error("Invalid save state size", { cause: statuses_js_1.SpinelStatus.INTERNAL_ERROR });
            }
            this.netParams = await this.readNetworkState(state);
            // reserved
            let offset = 1024 /* SaveConsts.NETWORK_DATA_SIZE */;
            const deviceCount = state.readUInt16LE(offset);
            offset += 2;
            logger_js_1.logger.debug(() => `Current save devices: ${deviceCount}`, NS);
            for (let i = 0; i < deviceCount; i++) {
                const address64 = state.readBigUInt64LE(offset);
                offset += 8;
                const address16 = state.readUInt16LE(offset);
                offset += 2;
                const capabilities = state.readUInt8(offset);
                offset += 1;
                const authorized = Boolean(state.readUInt8(offset));
                offset += 1;
                const neighbor = Boolean(state.readUInt8(offset));
                offset += 1;
                // reserved
                offset += 64 - 13; // currently: 51
                const decodedCap = capabilities !== 0 ? (0, mac_js_1.decodeMACCapabilities)(capabilities) : undefined;
                this.deviceTable.set(address64, {
                    address16,
                    capabilities: decodedCap,
                    authorized,
                    neighbor,
                    recentLQAs: [],
                });
                this.address16ToAddress64.set(address16, address64);
                if (decodedCap && !decodedCap.rxOnWhenIdle) {
                    this.indirectTransmissions.set(address64, []);
                }
                let sourceRouteTableSize = 0;
                const sourceRouteEntryCount = state.readUInt8(offset);
                offset += 1;
                if (sourceRouteEntryCount > 0) {
                    const sourceRouteEntries = [];
                    for (let i = 0; i < sourceRouteEntryCount; i++) {
                        const pathCost = state.readUInt8(offset);
                        offset += 1;
                        const relayAddressCount = state.readUInt8(offset);
                        offset += 1;
                        const relayAddresses = [];
                        sourceRouteTableSize += 2 + relayAddressCount * 2;
                        for (let j = 0; j < relayAddressCount; j++) {
                            relayAddresses.push(state.readUInt16LE(offset));
                            offset += 2;
                        }
                        sourceRouteEntries.push({ pathCost, relayAddresses });
                    }
                    this.sourceRouteTable.set(address16, sourceRouteEntries);
                }
                // reserved
                offset += 512 /* SaveConsts.DEVICE_DATA_SIZE */ - 64 - 1 - sourceRouteTableSize;
            }
        }
        catch {
            // `this.savePath` does not exist, using constructor-given network params, do initial save
            await this.saveState();
        }
        // pre-compure hashes for default keys for faster processing
        (0, zigbee_js_1.registerDefaultHashedKeys)((0, zigbee_js_1.makeKeyedHashByType)(0 /* ZigbeeKeyType.LINK */, this.netParams.tcKey), (0, zigbee_js_1.makeKeyedHashByType)(1 /* ZigbeeKeyType.NWK */, this.netParams.networkKey), (0, zigbee_js_1.makeKeyedHashByType)(2 /* ZigbeeKeyType.TRANSPORT */, this.netParams.tcKey), (0, zigbee_js_1.makeKeyedHashByType)(3 /* ZigbeeKeyType.LOAD */, this.netParams.tcKey));
        this.#tcVerifyKeyHash = (0, zigbee_js_1.makeKeyedHash)(this.netParams.tcKey, 0x03 /* input byte per spec for VERIFY_KEY */);
        const [address, nodeDescriptor, powerDescriptor, simpleDescriptors, activeEndpoints] = (0, descriptors_js_1.encodeCoordinatorDescriptors)(this.netParams.eui64);
        this.configAttributes.address = address;
        this.configAttributes.nodeDescriptor = nodeDescriptor;
        this.configAttributes.powerDescriptor = powerDescriptor;
        this.configAttributes.simpleDescriptors = simpleDescriptors;
        this.configAttributes.activeEndpoints = activeEndpoints;
    }
    async readNetworkState(readState) {
        try {
            const state = readState ?? (await (0, promises_1.readFile)(this.savePath));
            let offset = 0;
            const eui64 = state.readBigUInt64LE(offset);
            offset += 8;
            const panId = state.readUInt16LE(offset);
            offset += 2;
            const extendedPANId = state.readBigUInt64LE(offset);
            offset += 8;
            const channel = state.readUInt8(offset);
            offset += 1;
            const nwkUpdateId = state.readUInt8(offset);
            offset += 1;
            const txPower = state.readInt8(offset);
            offset += 1;
            const networkKey = state.subarray(offset, offset + 16 /* ZigbeeConsts.SEC_KEYSIZE */);
            offset += 16 /* ZigbeeConsts.SEC_KEYSIZE */;
            const networkKeyFrameCounter = state.readUInt32LE(offset);
            offset += 4;
            const networkKeySequenceNumber = state.readUInt8(offset);
            offset += 1;
            const tcKey = state.subarray(offset, offset + 16 /* ZigbeeConsts.SEC_KEYSIZE */);
            offset += 16 /* ZigbeeConsts.SEC_KEYSIZE */;
            const tcKeyFrameCounter = state.readUInt32LE(offset);
            offset += 4;
            logger_js_1.logger.debug(() => `Current save network: eui64=${eui64} panId=${panId} channel=${channel}`, NS);
            return {
                eui64,
                panId,
                extendedPANId,
                channel,
                nwkUpdateId,
                txPower,
                networkKey,
                networkKeyFrameCounter,
                networkKeySequenceNumber,
                tcKey,
                tcKeyFrameCounter,
            };
        }
        catch {
            /* empty */
        }
    }
    /**
     * Set the manufacturer code in the pre-encoded node descriptor
     * @param code
     */
    setManufacturerCode(code) {
        this.configAttributes.nodeDescriptor.writeUInt16LE(code, 7 /* static offset */);
    }
    // #endregion
    // #region Wrappers
    /**
     * Wraps ZigBee APS DATA sending for ZDO.
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
        if (nwkDest16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ || nwkDest64 === this.netParams.eui64) {
            throw new Error("Cannot send ZDO to coordinator", { cause: statuses_js_1.SpinelStatus.INVALID_ARGUMENT });
        }
        // increment and set the ZDO sequence number in outgoing payload
        const zdoCounter = this.nextZDOSeqNum();
        payload[0] = zdoCounter;
        logger_js_1.logger.debug(() => `===> ZDO[seqNum=${payload[0]} clusterId=${clusterId} nwkDst=${nwkDest16}:${nwkDest64}]`, NS);
        if (clusterId === 56 /* ZigbeeConsts.NWK_UPDATE_REQUEST */ && nwkDest16 >= 65532 /* ZigbeeConsts.BCAST_DEFAULT */ && payload[5] === 0xfe) {
            // TODO: needs testing
            this.netParams.channel = (0, zigbee_js_1.convertMaskToChannels)(payload.readUInt32LE(1))[0];
            this.netParams.nwkUpdateId = payload[6];
            // force saving after net params change
            await this.savePeriodicState();
            this.#pendingChangeChannel = setTimeout(this.setProperty.bind(this, (0, spinel_js_1.writePropertyC)(33 /* SpinelPropertyId.PHY_CHAN */, this.netParams.channel)), 9000 /* ZigbeeConsts.BCAST_TIME_WINDOW */);
        }
        const apsCounter = await this.sendZigbeeAPSData(payload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
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
     * Wraps ZigBee APS DATA sending for unicast.
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
        if (dest16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ || dest64 === this.netParams.eui64) {
            throw new Error("Cannot send unicast to coordinator", { cause: statuses_js_1.SpinelStatus.INVALID_ARGUMENT });
        }
        return await this.sendZigbeeAPSData(payload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
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
     * Wraps ZigBee APS DATA sending for groupcast.
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
        return await this.sendZigbeeAPSData(payload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
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
     * Wraps ZigBee APS DATA sending for broadcast.
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
            throw new Error("Invalid parameters", { cause: statuses_js_1.SpinelStatus.INVALID_ARGUMENT });
        }
        return await this.sendZigbeeAPSData(payload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
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