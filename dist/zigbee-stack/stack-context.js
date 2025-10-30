"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StackContext = exports.NetworkKeyUpdateMethod = exports.ApplicationKeyRequestPolicy = exports.TrustCenterKeyRequestPolicy = exports.InstallCodePolicy = void 0;
const promises_1 = require("node:fs/promises");
const descriptors_js_1 = require("../drivers/descriptors.js");
const logger_js_1 = require("../utils/logger.js");
const save_serializer_js_1 = require("../utils/save-serializer.js");
const mac_js_1 = require("../zigbee/mac.js");
const zigbee_js_1 = require("../zigbee/zigbee.js");
const NS = "stack-context";
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
/** The time between state saving to disk. (msec) */
const CONFIG_SAVE_STATE_TIME = 60000;
/** Offset added to frame counter properties on save */
const CONFIG_SAVE_FRAME_COUNTER_JUMP_OFFSET = 1024;
/**
 * Centralized shared state and counters for the Zigbee stack.
 *
 * This context holds all shared state between protocol layers including:
 * - Network parameters
 * - Device and routing tables
 * - Frame counters (MAC, NWK, APS, ZDO)
 * - Trust Center policies
 * - RSSI/LQI ranges
 */
class StackContext {
    #callbacks;
    /** Master table of all known devices on the network (mapped by IEEE address) */
    deviceTable = new Map();
    /** Address lookup: 16-bit to 64-bit (synced with deviceTable) */
    address16ToAddress64 = new Map();
    /** Source routing table (mapped by 16-bit address) */
    sourceRouteTable = new Map();
    /** Trust Center policies */
    trustCenterPolicies = {
        allowJoins: false,
        installCode: InstallCodePolicy.NOT_REQUIRED,
        allowRejoinsWithWellKnownKey: true,
        allowTCKeyRequest: TrustCenterKeyRequestPolicy.ALLOWED,
        networkKeyUpdatePeriod: 0, // disable
        networkKeyUpdateMethod: NetworkKeyUpdateMethod.BROADCAST,
        allowAppKeyRequest: ApplicationKeyRequestPolicy.DISALLOWED,
        allowRemoteTCPolicyChange: false,
        allowVirtualDevices: false,
    };
    /** Configuration attributes */
    configAttributes = {
        address: Buffer.alloc(0),
        nodeDescriptor: Buffer.alloc(0),
        powerDescriptor: Buffer.alloc(0),
        simpleDescriptors: Buffer.alloc(0),
        activeEndpoints: Buffer.alloc(0),
    };
    /** Count of MAC NO_ACK reported for each device (mapping by network address) */
    macNoACKs = new Map();
    /** Associations pending DATA_RQ from device (mapping by IEEE address) */
    pendingAssociations = new Map();
    /** Indirect transmission for devices with rxOnWhenIdle=false (mapping by IEEE address) */
    indirectTransmissions = new Map();
    #savePath;
    #saveStateTimeout;
    #loaded = false;
    /** Network parameters */
    netParams;
    /** Pre-computed hash of default TC link key for VERIFY_KEY */
    tcVerifyKeyHash = Buffer.alloc(0);
    /** MAC association permit flag */
    associationPermit = false;
    //---- Trust Center (see 05-3474-R #4.7.1)
    #allowJoinTimeout;
    /** Minimum observed RSSI */
    rssiMin = -100;
    /** Maximum observed RSSI */
    rssiMax = -25;
    /** Minimum observed LQI */
    lqiMin = 15;
    /** Maximum observed LQI */
    lqiMax = 250;
    constructor(callbacks, savePath, netParams) {
        this.#callbacks = callbacks;
        this.#savePath = savePath;
        this.netParams = netParams;
    }
    // #region Getters/Setters
    get loaded() {
        return this.#loaded;
    }
    // #endregion
    async start() {
        // TODO: periodic/delayed actions
        this.#saveStateTimeout = setTimeout(this.savePeriodicState.bind(this), CONFIG_SAVE_STATE_TIME);
        await this.savePeriodicState();
    }
    stop() {
        clearTimeout(this.#saveStateTimeout);
        this.#saveStateTimeout = undefined;
        this.disallowJoins();
    }
    /** Remove the save file and clear tables (just in case) */
    async clear() {
        // remove `zoh.save`
        await (0, promises_1.rm)(this.#savePath, { force: true });
        this.deviceTable.clear();
        this.address16ToAddress64.clear();
        this.sourceRouteTable.clear();
        this.indirectTransmissions.clear();
    }
    /**
     * Get next Trust Center key frame counter.
     * HOT PATH: Optimized counter increment
     * @returns Incremented TC key frame counter (wraps at 0xffffffff)
     */
    /* @__INLINE__ */
    nextTCKeyFrameCounter() {
        this.netParams.tcKeyFrameCounter = ((this.netParams.tcKeyFrameCounter + 1) & 0xffffffff) >>> 0;
        return this.netParams.tcKeyFrameCounter;
    }
    /**
     * Get next network key frame counter.
     * HOT PATH: Optimized counter increment
     * @returns Incremented network key frame counter (wraps at 0xffffffff)
     */
    /* @__INLINE__ */
    nextNWKKeyFrameCounter() {
        this.netParams.networkKeyFrameCounter = ((this.netParams.networkKeyFrameCounter + 1) & 0xffffffff) >>> 0;
        return this.netParams.networkKeyFrameCounter;
    }
    /**
     * Get device by IEEE (64-bit) or network (16-bit) address.
     * @param address IEEE address (bigint) or network address (number)
     * @returns Device table entry or undefined if not found
     */
    getDevice(address) {
        if (typeof address === "bigint") {
            return this.deviceTable.get(address);
        }
        const address64 = this.address16ToAddress64.get(address);
        if (address64 === undefined) {
            return undefined;
        }
        return this.deviceTable.get(address64);
    }
    /**
     * Get IEEE (64-bit) address from network (16-bit) address.
     * @param address16 Network address
     * @returns IEEE address or undefined if not found
     */
    getAddress64(address16) {
        return this.address16ToAddress64.get(address16);
    }
    /**
     * Get network (16-bit) address from IEEE (64-bit) address.
     * @param address64 IEEE address
     * @returns Network address or undefined if not found
     */
    getAddress16(address64) {
        const device = this.deviceTable.get(address64);
        return device?.address16;
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
     * HOT PATH: Called for every incoming frame to compute link quality assessment.
     * @param signalStrength RSSI value
     * @param signalQuality LQI value (optional, computed from RSSI if not provided)
     * @returns Computed LQA value (0-255)
     */
    /* @__INLINE__ */
    computeLQA(signalStrength, signalQuality) {
        // HOT PATH: Map RSSI to LQI if not provided
        if (signalQuality === undefined) {
            signalQuality = this.mapRSSIToLQI(signalStrength);
        }
        // HOT PATH: Clamp signal strength to valid range
        if (signalStrength < this.rssiMin) {
            signalStrength = this.rssiMin;
        }
        if (signalStrength > this.rssiMax) {
            signalStrength = this.rssiMax;
        }
        // HOT PATH: Clamp signal quality to valid range
        if (signalQuality < this.lqiMin) {
            signalQuality = this.lqiMin;
        }
        if (signalQuality > this.lqiMax) {
            signalQuality = this.lqiMax;
        }
        // HOT PATH: Compute LQA with optimized formula (single Math.floor call)
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
     * Decrement radius value for NWK frame forwarding.
     * HOT PATH: Optimized computation
     * @param radius Current radius value
     * @returns Decremented radius (minimum 1)
     */
    /* @__INLINE__ */
    decrementRadius(radius) {
        const newRadius = radius - 1;
        return newRadius < 1 ? 1 : newRadius;
    }
    /**
     * Save state to file system in TLV format.
     * Format version 1:
     * - VERSION tag
     * - Network parameter tags (EUI64, PAN_ID, etc.)
     * - DEVICE_ENTRY tags (each containing nested TLV device data)
     * - END_MARKER
     */
    async saveState() {
        // estimate buffer size (generous upper bound)
        const estimatedSize = (0, save_serializer_js_1.estimateTLVStateSize)(this.deviceTable.size);
        const state = Buffer.allocUnsafe(estimatedSize);
        let offset = 0;
        // write version first
        offset = (0, save_serializer_js_1.writeTLVUInt8)(state, offset, 240 /* TLVTag.VERSION */, save_serializer_js_1.SAVE_FORMAT_VERSION);
        // network parameters (can be added/removed without breaking old readers)
        offset = (0, save_serializer_js_1.writeTLVBigUInt64LE)(state, offset, 1 /* TLVTag.EUI64 */, this.netParams.eui64);
        offset = (0, save_serializer_js_1.writeTLVUInt16LE)(state, offset, 2 /* TLVTag.PAN_ID */, this.netParams.panId);
        offset = (0, save_serializer_js_1.writeTLVBigUInt64LE)(state, offset, 3 /* TLVTag.EXTENDED_PAN_ID */, this.netParams.extendedPanId);
        offset = (0, save_serializer_js_1.writeTLVUInt8)(state, offset, 4 /* TLVTag.CHANNEL */, this.netParams.channel);
        offset = (0, save_serializer_js_1.writeTLVUInt8)(state, offset, 5 /* TLVTag.NWK_UPDATE_ID */, this.netParams.nwkUpdateId);
        offset = (0, save_serializer_js_1.writeTLVInt8)(state, offset, 6 /* TLVTag.TX_POWER */, this.netParams.txPower);
        offset = (0, save_serializer_js_1.writeTLV)(state, offset, 7 /* TLVTag.NETWORK_KEY */, this.netParams.networkKey);
        offset = (0, save_serializer_js_1.writeTLVUInt32LE)(state, offset, 8 /* TLVTag.NETWORK_KEY_FRAME_COUNTER */, this.netParams.networkKeyFrameCounter + CONFIG_SAVE_FRAME_COUNTER_JUMP_OFFSET);
        offset = (0, save_serializer_js_1.writeTLVUInt8)(state, offset, 9 /* TLVTag.NETWORK_KEY_SEQUENCE_NUMBER */, this.netParams.networkKeySequenceNumber);
        offset = (0, save_serializer_js_1.writeTLV)(state, offset, 10 /* TLVTag.TC_KEY */, this.netParams.tcKey);
        offset = (0, save_serializer_js_1.writeTLVUInt32LE)(state, offset, 11 /* TLVTag.TC_KEY_FRAME_COUNTER */, this.netParams.tcKeyFrameCounter + CONFIG_SAVE_FRAME_COUNTER_JUMP_OFFSET);
        // device table (count is implicit in number of DEVICE_ENTRY tags)
        for (const [device64, device] of this.deviceTable) {
            const sourceRouteEntries = this.sourceRouteTable.get(device.address16);
            const deviceEntry = (0, save_serializer_js_1.serializeDeviceEntry)(device64, device.address16, device.capabilities ? (0, mac_js_1.encodeMACCapabilities)(device.capabilities) : 0x00, device.authorized, device.neighbor, sourceRouteEntries);
            offset = (0, save_serializer_js_1.writeTLV)(state, offset, 128 /* TLVTag.DEVICE_ENTRY */, deviceEntry);
        }
        // write end marker (aids debugging and validates complete write)
        state.writeUInt8(255 /* TLVTag.END_MARKER */, offset++);
        const writtenState = state.subarray(0, offset);
        // write only the used portion
        await (0, promises_1.writeFile)(this.#savePath, writtenState);
        logger_js_1.logger.debug(() => `Saved state to ${this.#savePath} (${writtenState.byteLength} bytes)`, NS);
    }
    /**
     * Read the current network state in the save file, if any present.
     * @returns
     */
    async readNetworkState() {
        try {
            const stateBuffer = await (0, promises_1.readFile)(this.#savePath);
            logger_js_1.logger.debug(() => `Loaded state from ${this.#savePath} (${stateBuffer.byteLength} bytes)`, NS);
            // Parse state once into typed structure with all values already converted to final types
            const state = (0, save_serializer_js_1.readTLVs)(stateBuffer);
            // Check version (already parsed to number)
            const version = state.version ?? 1;
            if (version > save_serializer_js_1.SAVE_FORMAT_VERSION) {
                logger_js_1.logger.warning(`Unknown save format version ${version}, attempting to load`, NS);
            }
            logger_js_1.logger.debug(() => `Current save network: eui64=${state.eui64} panId=${state.panId} channel=${state.channel}`, NS);
            return state;
        }
        catch {
            /* empty */
        }
    }
    /**
     * Load state from file system if exists, else save "initial" state.
     * Afterwards, various keys are pre-hashed and descriptors pre-encoded.
     */
    async loadState() {
        // pre-emptive
        this.#loaded = true;
        const state = await this.readNetworkState();
        if (state) {
            // Network parameters already parsed to final types - update context
            this.netParams.eui64 = state.eui64;
            this.netParams.panId = state.panId;
            this.netParams.extendedPanId = state.extendedPanId;
            this.netParams.channel = state.channel;
            this.netParams.nwkUpdateId = state.nwkUpdateId;
            this.netParams.txPower = state.txPower;
            this.netParams.networkKey = state.networkKey;
            this.netParams.networkKeyFrameCounter = state.networkKeyFrameCounter;
            this.netParams.networkKeySequenceNumber = state.networkKeySequenceNumber;
            this.netParams.tcKey = state.tcKey;
            this.netParams.tcKeyFrameCounter = state.tcKeyFrameCounter;
            // Device entries already parsed with all nested source routes
            logger_js_1.logger.debug(() => `Current save devices: ${state.deviceEntries.length}`, NS);
            for (const device of state.deviceEntries) {
                // Device values already parsed - just destructure
                const { address64, address16, capabilities, authorized, neighbor, sourceRouteEntries } = device;
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
                if (sourceRouteEntries.length > 0) {
                    const routes = sourceRouteEntries.map((entry) => ({
                        relayAddresses: entry.relayAddresses,
                        pathCost: entry.pathCost,
                        lastUpdated: entry.lastUpdated,
                        failureCount: 0,
                        lastUsed: undefined,
                    }));
                    this.sourceRouteTable.set(address16, routes);
                }
            }
        }
        else {
            // `this.#savePath` does not exist, using constructor-given network params, do initial save
            await this.saveState();
        }
        // pre-compute hashes for default keys for faster processing
        (0, zigbee_js_1.registerDefaultHashedKeys)((0, zigbee_js_1.makeKeyedHashByType)(0 /* ZigbeeKeyType.LINK */, this.netParams.tcKey), (0, zigbee_js_1.makeKeyedHashByType)(1 /* ZigbeeKeyType.NWK */, this.netParams.networkKey), (0, zigbee_js_1.makeKeyedHashByType)(2 /* ZigbeeKeyType.TRANSPORT */, this.netParams.tcKey), (0, zigbee_js_1.makeKeyedHashByType)(3 /* ZigbeeKeyType.LOAD */, this.netParams.tcKey));
        this.tcVerifyKeyHash = (0, zigbee_js_1.makeKeyedHash)(this.netParams.tcKey, 0x03 /* input byte per spec for VERIFY_KEY */);
        const [address, nodeDescriptor, powerDescriptor, simpleDescriptors, activeEndpoints] = (0, descriptors_js_1.encodeCoordinatorDescriptors)(this.netParams.eui64);
        this.configAttributes.address = address;
        this.configAttributes.nodeDescriptor = nodeDescriptor;
        this.configAttributes.powerDescriptor = powerDescriptor;
        this.configAttributes.simpleDescriptors = simpleDescriptors;
        this.configAttributes.activeEndpoints = activeEndpoints;
    }
    /**
     * Set the manufacturer code in the pre-encoded node descriptor
     * @param code
     */
    setManufacturerCode(code) {
        this.configAttributes.nodeDescriptor.writeUInt16LE(code, 7 /* static offset */);
    }
    async savePeriodicState() {
        await this.saveState();
        this.#saveStateTimeout?.refresh();
    }
    /**
     * Revert allowing joins (keeps `allowRejoinsWithWellKnownKey=true`).
     *
     * SPEC COMPLIANCE:
     * - ✅ Clears timer correctly
     * - ✅ Updates Trust Center allowJoins policy
     * - ✅ Maintains allowRejoinsWithWellKnownKey for rejoins
     * - ✅ Sets associationPermit flag for MAC layer
     */
    disallowJoins() {
        clearTimeout(this.#allowJoinTimeout);
        this.#allowJoinTimeout = undefined;
        this.trustCenterPolicies.allowJoins = false;
        this.trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
        this.associationPermit = false;
        logger_js_1.logger.info("Disallowed joins", NS);
    }
    /**
     * @param duration The length of time in seconds during which the trust center will allow joins.
     * The value 0x00 and 0xff indicate that permission is disabled or enabled, respectively, without a specified time limit.
     * 0xff is clamped to 0xfe for security reasons
     * @param macAssociationPermit If true, also allow association on coordinator itself. Ignored if duration 0.
     *
     * SPEC COMPLIANCE:
     * - ✅ Implements timed join window per spec
     * - ✅ Updates Trust Center policies
     * - ✅ Sets MAC associationPermit flag
     * - ✅ Clamps 0xff to 0xfe for security
     * - ✅ Auto-disallows after timeout
     */
    allowJoins(duration, macAssociationPermit) {
        if (duration > 0) {
            clearTimeout(this.#allowJoinTimeout);
            this.trustCenterPolicies.allowJoins = true;
            this.trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
            this.associationPermit = macAssociationPermit;
            this.#allowJoinTimeout = setTimeout(this.disallowJoins.bind(this), Math.min(duration, 0xfe) * 1000);
            logger_js_1.logger.info(`Allowed joins for ${duration} seconds (self=${macAssociationPermit})`, NS);
        }
        else {
            this.disallowJoins();
        }
    }
    /**
     * Handle device association (initial join or rejoin)
     *
     * SPEC COMPLIANCE:
     * - ✅ Validates allowJoins policy for initial join
     * - ✅ Assigns network addresses correctly
     * - ✅ Detects and handles address conflicts
     * - ✅ Creates device table entries with capabilities
     * - ✅ Sets up indirect transmission for rxOnWhenIdle=false
     * - ✅ Returns appropriate status codes per IEEE 802.15.4
     * - ✅ Triggers state save after association
     * - ⚠️ Unknown rejoins succeed if allowOverride=true (potential security risk)
     * - ❌ NOT IMPLEMENTED: Install code enforcement (policy checked but not enforced)
     * - ❌ NOT IMPLEMENTED: Network key change detection on rejoin
     * - ❌ NOT IMPLEMENTED: Device announcement tracking
     *
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
                if (this.trustCenterPolicies.allowJoins) {
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
                    capabilities, // TODO: only valid if not triggered by `processUpdateDevice`
                    // on initial join success, device is considered joined but unauthorized after MAC Assoc / NWK Commissioning response is sent
                    authorized: false,
                    neighbor,
                    recentLQAs: [],
                });
                this.address16ToAddress64.set(newAddress16, source64);
                // `processUpdateDevice` has no `capabilities` info, device is joined through router, so, no indirect tx for coordinator
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
    /**
     * Handle device disassociation (leave)
     *
     * SPEC COMPLIANCE:
     * - ✅ Removes from device table
     * - ✅ Removes from address mappings (16↔64)
     * - ✅ Cleans up indirect transmissions
     * - ✅ Removes from source route table
     * - ✅ Cleans up pending associations
     * - ✅ Clears MAC NO_ACK counters
     * - ✅ Removes routes using device as relay
     * - ✅ Triggers onDeviceLeft callback
     * - ✅ Forces state save
     * - ✅ Handles both address16 and address64 resolution
     *
     * THOROUGH CLEANUP: All device-related state properly removed
     */
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
                this.#callbacks.onDeviceLeft(source16, source64);
            });
            // force new MTORR
            // await this.nwkHandler.sendPeriodicManyToOneRouteRequest();
            // force saving after device change
            await this.savePeriodicState();
        }
    }
}
exports.StackContext = StackContext;
//# sourceMappingURL=stack-context.js.map