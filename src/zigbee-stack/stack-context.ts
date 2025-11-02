import { readFile, rm, writeFile } from "node:fs/promises";
import { encodeCoordinatorDescriptors } from "../drivers/descriptors.js";
import { logger } from "../utils/logger.js";
import {
    estimateTLVStateSize,
    type ParsedState,
    readTLVs,
    SAVE_FORMAT_VERSION,
    serializeAppLinkKeyEntry,
    serializeDeviceEntry,
    TLVTag,
    writeTLV,
    writeTLVBigUInt64LE,
    writeTLVInt8,
    writeTLVUInt8,
    writeTLVUInt16LE,
    writeTLVUInt32LE,
} from "../utils/save-serializer.js";
import { decodeMACCapabilities, encodeMACCapabilities, MACAssociationStatus, type MACCapabilities, type MACHeader } from "../zigbee/mac.js";
import {
    aes128MmoHash,
    computeInstallCodeCRC,
    INSTALL_CODE_VALID_SIZES,
    makeKeyedHash,
    makeKeyedHashByType,
    registerDefaultHashedKeys,
    ZigbeeConsts,
    ZigbeeKeyType,
} from "../zigbee/zigbee.js";
import type { ZigbeeAPSHeader, ZigbeeAPSPayload } from "../zigbee/zigbee-aps.js";
import { ZigbeeNWKConsts } from "../zigbee/zigbee-nwk.js";
import type { ZigbeeNWKGPHeader } from "../zigbee/zigbee-nwkgp.js";
import { CONFIG_NWK_MAX_HOPS } from "./nwk-handler.js";

const NS = "stack-context";

/**
 * Network parameters for the Zigbee network.
 */
export type NetworkParameters = {
    eui64: bigint;
    panId: number;
    extendedPanId: bigint;
    channel: number;
    nwkUpdateId: number;
    txPower: number;
    // TODO: implement ~30-day automatic key rotation?
    networkKey: Buffer;
    // TODO: wrap-to-zero mechanism / APS SWITCH_KEY
    networkKeyFrameCounter: number;
    networkKeySequenceNumber: number;
    tcKey: Buffer;
    tcKeyFrameCounter: number;
};

export enum InstallCodePolicy {
    /** Do not support Install Codes */
    NOT_SUPPORTED = 0x00,
    /** Support but do not require use of Install Codes or preset passphrases */
    NOT_REQUIRED = 0x01,
    /** Require the use of Install Codes by joining devices or preset Passphrases */
    REQUIRED = 0x02,
}

export type InstallCodeEntry = {
    code: Buffer;
    crc: number;
    key: Buffer;
};

export enum TrustCenterKeyRequestPolicy {
    DISALLOWED = 0x00,
    /** Any device MAY request */
    ALLOWED = 0x01,
    /** Only devices in the apsDeviceKeyPairSet with a KeyAttribute value of PROVISIONAL_KEY MAY request. */
    ONLY_PROVISIONAL = 0x02,
}

export enum ApplicationKeyRequestPolicy {
    DISALLOWED = 0x00,
    /** Any device MAY request an application link key with any device (except the Trust Center) */
    ALLOWED = 0x01,
    /** Only those devices listed in applicationKeyRequestList MAY request and receive application link keys. */
    ONLY_APPROVED = 0x02,
}

export enum NetworkKeyUpdateMethod {
    /** Broadcast using only network encryption */
    BROADCAST = 0x00,
    /** Unicast using network encryption and APS encryption with a device’s link key. */
    UNICAST = 0x01,
}

/**
 * see 05-3474-23 #4.7.3
 */
export type TrustCenterPolicies = {
    /**
     * This boolean indicates whether the Trust Center is currently allowing devices to join the network.
     * A value of TRUE means that the Trust Center is allowing devices that have never been sent the network key or a trust center link key, to join the network.
     */
    allowJoins: boolean;
    /** This enumeration indicates if the Trust Center requires install codes to be used with joining devices. */
    installCode: InstallCodePolicy;
    /**
     * This value indicates if the trust center allows rejoins using well known or default keys.
     * A setting of FALSE means rejoins are only allowed with trust center link keys where the KeyAttributes of the apsDeviceKeyPairSet entry indicates VERIFIED_KEY.
     */
    allowRejoinsWithWellKnownKey: boolean;
    /** This value controls whether devices are allowed to request a Trust Center Link Key after they have joined the network. */
    allowTCKeyRequest: TrustCenterKeyRequestPolicy;
    /** This policy indicates whether a node on the network that transmits a ZDO Mgmt_Permit_Join with a significance set to 1 is allowed to effect the local Trust Center’s policies. */
    allowRemoteTCPolicyChange: boolean;
    /** This value determines how the Trust Center SHALL handle attempts to request an application link key with a partner node. */
    allowAppKeyRequest: ApplicationKeyRequestPolicy;
    /**
     * This is a list of IEEE pairs of devices, which are allowed to establish application link keys between one another.
     * The first IEEE address is the initiator, the second is the responder.
     * If the responder address is set to 0xFFFFFFFFFFFFFFFF, then the initiator is allowed to request an application link key with any device.
     * If the responder’s address is not 0xFFFFFFFFFFFFFFFF, then it MAY also initiate an application link key request.
     * This list is only valid if allowAppKeyRequest is set to 0x02.
     */
    appKeyRequestList?: [responder64: bigint, initiator64: bigint][];
    /**
     * TODO: should do at least once a year to prevent deadlock at 0xffffffff
     *       alt: update when counter reaches 0x40000000
     * The period, in minutes, of how often the network key is updated by the Trust Center.
     * A period of 0 means the Trust Center will not periodically update the network key (it MAY still update key at other times).
     * uint32_t
     */
    networkKeyUpdatePeriod: number;
    /** This value describes the method the Trust Center uses to update the network key. */
    networkKeyUpdateMethod: NetworkKeyUpdateMethod;
    /**
     * This Boolean indicates whether the Trust Center is currently allowing Zigbee Direct Virtual Devices (ZVDs) to join the network.
     * A value of TRUE means that the Trust Center is allowing such devices.
     */
    allowVirtualDevices: boolean;
};

/**
 * List of all devices currently on the network.
 */
export type DeviceTableEntry = {
    // address64: bigint; // mapped
    address16: number;
    /** Indicates whether the device keeps its receiver on when idle */
    capabilities: MACCapabilities | undefined;
    /** Indicates whether the device verified its key */
    authorized: boolean;
    /** Indicates whether the device is a neighbor */
    neighbor: boolean;
    /**
     * List of recently observed LQAs.
     * Note: this is runtime-only
     */
    recentLQAs: number[];
    /** Last accepted NWK security frame counter. Runtime-only. */
    incomingNWKFrameCounter?: number;
    /** End device timeout metadata. Runtime-only. */
    endDeviceTimeout?: {
        timeoutIndex: number;
        timeoutMs: number;
        lastUpdated: number;
        expiresAt: number;
    };
};

export type SourceRouteTableEntry = {
    /** Relay addresses (empty if direct route) */
    relayAddresses: number[];
    /** Cost of the path (based on hop count and link quality) */
    pathCost: number;
    /** Timestamp when this route was last updated (used for route aging) */
    lastUpdated: number;
    /** Count of consecutive failures using this route */
    failureCount: number;
    /** Timestamp when this route was last used successfully (undefined if never used) */
    lastUsed?: number;
};

export type AppLinkKeyStoreEntry = {
    deviceA: bigint;
    deviceB: bigint;
    key: Buffer;
};

/**
 * 05-3474-23 #2.5.5
 */
export type ConfigurationAttributes = {
    /**
     * NOTE: Pre-encoded as "sendable" ZDO response (see descriptors.ts for more details):
     */
    address: Buffer;
    /**
     * 05-3474-23 #2.3.2.3
     * The :Config_Node_Descriptor is either created when the application is first loaded or initialized with a commissioning tool prior to when the device begins operations in the network.
     * It is used for service discovery to describe node features to external inquiring devices.
     *
     * NOTE: Pre-encoded as "sendable" ZDO response (see descriptors.ts for more details):
     * - Byte 1: sequence number
     * - Byte 2: status
     * - Byte 3-4: 0x0000 (coordinator nwk addr)
     */
    nodeDescriptor: Buffer;
    /**
     * 05-3474-23 #2.3.2.4
     * The :Config_Power_Descriptor is either created when the application is first loaded or initialized with a commissioning tool prior to when the device begins operations in the network.
     * It is used for service discovery to describe node power features to external inquiring devices.
     *
     * NOTE: Pre-encoded as "sendable" ZDO response (see descriptors.ts for more details):
     * - Byte 1: sequence number
     * - Byte 2: status
     * - Byte 3-4: 0x0000 (coordinator nwk addr)
     */
    powerDescriptor: Buffer;
    /**
     * 05-3474-23 #2.3.2.5
     * The :Config_Simple_Descriptors are created when the application is first loaded and are treated as “read-only.”
     * The Simple Descriptor are used for service discovery to describe interfacing features to external inquiring devices.
     *
     * NOTE: Pre-encoded as "sendable" ZDO response (see descriptors.ts for more details):
     * - Byte 1: sequence number
     * - Byte 2: status
     * - Byte 3-4: 0x0000 (coordinator nwk addr)
     */
    simpleDescriptors: Buffer;
    /**
     * NOTE: Pre-encoded as "sendable" ZDO response (see descriptors.ts for more details):
     */
    activeEndpoints: Buffer;
    /**
     * The :Config_NWK_Scan_Attempts is employed within ZDO to call the NLME-NETWORK-AND-PARENTDISCOVERY.request primitive the indicated number of times (for routers and end devices).
     * Integer value representing the number of scan attempts to make before the NWK layer decides which Zigbee coordinator or router to associate with (see section 2.5.4.5.1).
     * This attribute has default value of 5 and valid values between 1 and 255.
     */
    // nwkScanAttempts: number;
    /**
     * The Config_NWK_Time_btwn_Scans is employed within ZDO to provide a time duration between the NLMENETWORK-AND-PARENT-DISCOVERY.request attempts.
     * Integer value representing the time duration (in OctetDurations) between each NWK discovery attempt described by :Config_NWK_Scan_Attempts (see section).
     * This attribute has a default value of 0xc35 OctetDurations (100 milliseconds on 2.4GHz) and valid values between 1 and 0x1f3fe1 OctetDurations (65535 milliseconds on 2.4GHz).
     */
    // nwkTimeBetweenScans: number;
    /**
     * The :Config_Max_Bind is a maximum number of supported Binding Table entries for this device.
     */
    // maxBind: number; // optional
    /**
     * The default value for :Config_Permit_Join_Duration is 0x00, however, this value can be established differently according to the needs of the profile.
     * Permit Join Duration value set by the NLME-PERMIT-JOINING. request primitive (see Chapter 3).
     */
    // permitJoinDuration: number; // optional
    /**
     * This attribute is used only on the Trust Center and is used to set the level of security on the network.
     * Security level of the network (see Chapter 3).
     */
    // nwkSecurityLevel: number; // optional
    /**
     * This attribute is used only on the Trust Center and is used to determine if network layer security SHALL be applied to all frames in the network.
     * If all network frames SHOULD be secured (see Chapter 3).
     */
    // nwkSecureAllFrames: number; // optional
    /**
     * 05-3474-23 Table 2-134
     * The value for this configuration attribute is established in the Stack Profile.
     */
    // nwkBroadcastDeliveryTime: number; // optional
    /**
     * 05-3474-23 Table 2-134
     * The value for this configuration attribute is established in the Stack Profile.
     * This attribute is mandatory for the Zigbee coordinator and Zigbee routers and not used for Zigbee End Devices.
     */
    // nwkTransactionPersistenceTime: number; // optional
    // nwkIndirectPollRate: number; // ZED-only
    /**
     * The value for this configuration attribute is established by the stack profile in use on the device.
     * Note that for some stack profiles, the maximum associations MAY have a dimension which provides for separate maximums for router associations and end device associations.
     * Sets the maximum allowed associations, either of routers, end devices, or both, to a parent router or coordinator.
     */
    // maxAssoc: number; // optional
    /**
     * 05-3474-23 #3.2.2.16
     * :Config_NWK_Join_Direct_Addrs permits the Zigbee Coordinator or Router to be pre-configured with a list of addresses to be direct joined.
     * Consists of the following fields:
     * - DeviceAddress - 64-bit IEEE address for the device to be direct joined.
     * - CapabilityInformation - Operating capabilities of the device to be direct joined.
     * - Link Key - If security is enabled, link key for use in the key-pair descriptor for this new device (see Table 4-36).
     */
    // nwkJoinDirectAddrs: {device64: bigint; capabilities: number; linkKey: Buffer}[]; // optional
    // parentLinkRetryThreshold: number; // ZED-only
    // rejoinInterval: number; // ZED-only
    // maxRejoinInterval: number; // ZED-only
};

/**
 * Pending association context
 */
interface AssociationContext {
    sendResp: () => Promise<void>;
    timestamp: number;
}

/**
 * Indirect transmission context
 */
interface IndirectTxContext {
    sendFrame: () => Promise<boolean>;
    timestamp: number;
}

export interface StackCallbacks {
    onFatalError: (message: string) => void;

    /** Only triggered if MAC `emitFrames===true` */
    onMACFrame: (payload: Buffer, rssi?: number) => void;
    onFrame: (
        sender16: number | undefined,
        sender64: bigint | undefined,
        apsHeader: ZigbeeAPSHeader,
        apsPayload: ZigbeeAPSPayload,
        lqa: number,
    ) => void;
    onGPFrame: (cmdId: number, payload: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, lqa: number) => void;

    onDeviceJoined: (source16: number, source64: bigint, capabilities: MACCapabilities) => void;
    onDeviceRejoined: (source16: number, source64: bigint, capabilities: MACCapabilities) => void;
    onDeviceLeft: (source16: number, source64: bigint) => void;
    onDeviceAuthorized: (source16: number, source64: bigint) => void;
}

/**
 * Callbacks from stack context to parent layer
 */
export interface StackContextCallbacks {
    /** Handle post-disassociate */
    onDeviceLeft: StackCallbacks["onDeviceLeft"];
}

/** Table 3-54 */
export const END_DEVICE_TIMEOUT_TABLE_MS = [
    10_000,
    2 * 60 * 1000,
    4 * 60 * 1000,
    8 * 60 * 1000,
    16 * 60 * 1000,
    32 * 60 * 1000,
    64 * 60 * 1000,
    128 * 60 * 1000,
    256 * 60 * 1000,
    512 * 60 * 1000,
    1024 * 60 * 1000,
    2048 * 60 * 1000,
    4096 * 60 * 1000,
    8192 * 60 * 1000,
    16_384 * 60 * 1000,
] as const;

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
export class StackContext {
    readonly #callbacks: StackContextCallbacks;
    /** Master table of all known devices on the network (mapped by IEEE address) */
    readonly deviceTable = new Map<bigint, DeviceTableEntry>();
    /** Address lookup: 16-bit to 64-bit (synced with deviceTable) */
    readonly address16ToAddress64 = new Map<number, bigint>();
    /** Source routing table (mapped by 16-bit address) */
    readonly sourceRouteTable = new Map<number, SourceRouteTableEntry[]>();
    /** Application link keys stored for device pairs (ordered by IEEE address) */
    readonly appLinkKeyTable = new Map<string, AppLinkKeyStoreEntry>();
    /** Install code metadata per device (mapped by IEEE address) */
    readonly installCodeTable = new Map<bigint, InstallCodeEntry>();
    /** Trust Center policies */
    readonly trustCenterPolicies: TrustCenterPolicies = {
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
    readonly configAttributes: ConfigurationAttributes = {
        address: Buffer.alloc(0),
        nodeDescriptor: Buffer.alloc(0),
        powerDescriptor: Buffer.alloc(0),
        simpleDescriptors: Buffer.alloc(0),
        activeEndpoints: Buffer.alloc(0),
    };
    /** Count of MAC NO_ACK reported for each device (mapping by network address) */
    readonly macNoACKs = new Map<number, number>();
    /** Associations pending DATA_RQ from device (mapping by IEEE address) */
    readonly pendingAssociations = new Map<bigint, AssociationContext>();
    /** Indirect transmission for devices with rxOnWhenIdle=false (mapping by IEEE address) */
    readonly indirectTransmissions = new Map<bigint, IndirectTxContext[]>();

    #savePath: string;
    #saveStateTimeout: NodeJS.Timeout | undefined;

    #loaded = false;

    /** Network parameters */
    netParams: NetworkParameters;
    /** Pre-computed hash of default TC link key for VERIFY_KEY */
    tcVerifyKeyHash: Buffer = Buffer.alloc(0);
    /** MAC association permit flag */
    associationPermit = false;

    //---- Trust Center (see 05-3474-R #4.7.1)

    #allowJoinTimeout: NodeJS.Timeout | undefined;

    #pendingNetworkKey: Buffer | undefined;
    #pendingNetworkKeySequenceNumber: number | undefined;

    /** Minimum observed RSSI */
    rssiMin = -100;
    /** Maximum observed RSSI */
    rssiMax = -25;
    /** Minimum observed LQI */
    lqiMin = 15;
    /** Maximum observed LQI */
    lqiMax = 250;

    constructor(callbacks: StackContextCallbacks, savePath: string, netParams: NetworkParameters) {
        this.#callbacks = callbacks;

        this.#savePath = savePath;
        this.netParams = netParams;
    }

    // #region Getters/Setters

    get loaded(): boolean {
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
        await rm(this.#savePath, { force: true });

        this.deviceTable.clear();
        this.address16ToAddress64.clear();
        this.sourceRouteTable.clear();
        this.indirectTransmissions.clear();
        this.appLinkKeyTable.clear();
        this.installCodeTable.clear();
    }

    /**
     * Get next Trust Center key frame counter.
     * HOT PATH: Optimized counter increment
     * @returns Incremented TC key frame counter (wraps at 0xffffffff)
     */
    /* @__INLINE__ */
    public nextTCKeyFrameCounter(): number {
        this.netParams.tcKeyFrameCounter = ((this.netParams.tcKeyFrameCounter + 1) & 0xffffffff) >>> 0;

        return this.netParams.tcKeyFrameCounter;
    }

    /**
     * Get next network key frame counter.
     * HOT PATH: Optimized counter increment
     * @returns Incremented network key frame counter (wraps at 0xffffffff)
     */
    /* @__INLINE__ */
    public nextNWKKeyFrameCounter(): number {
        this.netParams.networkKeyFrameCounter = ((this.netParams.networkKeyFrameCounter + 1) & 0xffffffff) >>> 0;

        return this.netParams.networkKeyFrameCounter;
    }

    /**
     * Store a pending network key that will become active once a matching SWITCH_KEY is received.
     * @param key Raw network key bytes (16 bytes)
     * @param sequenceNumber Sequence number advertised for the pending key
     */
    public setPendingNetworkKey(key: Buffer, sequenceNumber: number): void {
        this.#pendingNetworkKey = Buffer.from(key);
        this.#pendingNetworkKeySequenceNumber = sequenceNumber & 0xff;

        logger.debug(() => `Staged pending network key seq=${this.#pendingNetworkKeySequenceNumber}`, NS);
    }

    /**
     * Activate the staged network key if the sequence number matches.
     * Resets frame counters and re-registers hashed keys for cryptographic operations.
     * @param sequenceNumber Sequence number referenced by SWITCH_KEY command
     * @returns true when activation succeeded, false when no matching pending key exists
     */
    public activatePendingNetworkKey(sequenceNumber: number): boolean {
        const normalizedSeq = sequenceNumber & 0xff;

        if (this.#pendingNetworkKey === undefined || this.#pendingNetworkKeySequenceNumber !== normalizedSeq) {
            return false;
        }

        this.netParams.networkKey = Buffer.from(this.#pendingNetworkKey);
        this.netParams.networkKeySequenceNumber = normalizedSeq;
        this.netParams.networkKeyFrameCounter = 0;

        this.#pendingNetworkKey = undefined;
        this.#pendingNetworkKeySequenceNumber = undefined;

        registerDefaultHashedKeys(
            makeKeyedHashByType(ZigbeeKeyType.LINK, this.netParams.tcKey),
            makeKeyedHashByType(ZigbeeKeyType.NWK, this.netParams.networkKey),
            makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, this.netParams.tcKey),
            makeKeyedHashByType(ZigbeeKeyType.LOAD, this.netParams.tcKey),
        );

        logger.debug(() => `Activated network key seq=${normalizedSeq}`, NS);

        return true;
    }

    // private countDirectChildren(exclude64?: bigint): { childCount: number; routerCount: number } {
    //     let childCount = 0;
    //     let routerCount = 0;

    //     for (const [device64, entry] of this.deviceTable) {
    //         if (!entry.neighbor) {
    //             continue;
    //         }

    //         if (exclude64 !== undefined && device64 === exclude64) {
    //             continue;
    //         }

    //         childCount += 1;

    //         if (entry.capabilities?.deviceType === 1) {
    //             routerCount += 1;
    //         }
    //     }

    //     return { childCount, routerCount };
    // }

    /**
     * 05-3474-23 #3.6.1.10
     */
    public assignNetworkAddress(): number {
        let newNetworkAddress = 0xffff;
        let unique = false;

        do {
            // maximum exclusive, minimum inclusive
            newNetworkAddress = Math.floor(Math.random() * (ZigbeeConsts.BCAST_MIN - 0x0001) + 0x0001);
            unique = this.address16ToAddress64.get(newNetworkAddress) === undefined;
        } while (!unique);

        return newNetworkAddress;
    }

    /**
     * Update the stored end device timeout metadata for a device.
     * @param address64 IEEE address of the end device.
     * @param timeoutIndex Requested timeout index (0-14).
     * @param now Optional timestamp override (for testing).
     * @returns Updated timeout metadata or undefined if device/index invalid.
     */
    public updateEndDeviceTimeout(address64: bigint, timeoutIndex: number, now = Date.now()): DeviceTableEntry["endDeviceTimeout"] | undefined {
        const timeoutMs = END_DEVICE_TIMEOUT_TABLE_MS[timeoutIndex];

        if (timeoutMs === undefined) {
            return undefined;
        }

        const device = this.deviceTable.get(address64);

        if (device === undefined) {
            return undefined;
        }

        device.endDeviceTimeout = {
            timeoutIndex,
            timeoutMs,
            lastUpdated: now,
            expiresAt: now + timeoutMs,
        };

        return device.endDeviceTimeout;
    }

    /**
     * Update and validate the incoming NWK security frame counter for a device.
     * Returns false if the provided counter is a replay (<= stored value, excluding wrap).
     */
    public updateIncomingNWKFrameCounter(address64: bigint | undefined, frameCounter: number): boolean {
        if (address64 === undefined) {
            return true;
        }

        const device = this.deviceTable.get(address64);

        if (device === undefined) {
            return true;
        }

        const previous = device.incomingNWKFrameCounter;

        if (previous === undefined) {
            device.incomingNWKFrameCounter = frameCounter >>> 0;

            return true;
        }

        const normalizedCounter = frameCounter >>> 0;

        if (previous === 0xffffffff && normalizedCounter === 0) {
            device.incomingNWKFrameCounter = normalizedCounter;

            return true;
        }

        if (normalizedCounter > previous) {
            device.incomingNWKFrameCounter = normalizedCounter;

            return true;
        }

        return false;
    }

    /**
     * Apply logistic curve on standard mapping to LQI range [0..255]
     *
     * - Silabs EFR32: the RSSI range of [-100..-36] is mapped to an LQI range [0..255]
     * - TI zstack: `LQI = (MAC_SPEC_ED_MAX * (RSSIdbm - ED_RF_POWER_MIN_DBM)) / (ED_RF_POWER_MAX_DBM - ED_RF_POWER_MIN_DBM);`
     *     where `MAC_SPEC_ED_MAX = 255`, `ED_RF_POWER_MIN_DBM = -87`, `ED_RF_POWER_MAX_DBM = -10`
     * - Nordic: RSSI accuracy valid range -90 to -20 dBm
     */
    public mapRSSIToLQI(rssi: number): number {
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
    public computeLQA(signalStrength: number, signalQuality?: number): number {
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
        return Math.floor(
            (((255 * (signalQuality - this.lqiMin)) / (this.lqiMax - this.lqiMin)) * (signalStrength - this.rssiMin)) / (this.rssiMax - this.rssiMin),
        );
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
    public computeDeviceLQA(
        address16: number | undefined,
        address64: bigint | undefined,
        signalStrength?: number,
        signalQuality?: number,
        maxRecent = 10,
    ): number {
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

            const sortedLQAs = device.recentLQAs.slice(/* copy */).sort((a, b) => a - b);
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
    public decrementRadius(radius: number): number {
        const newRadius = (radius === 0 ? CONFIG_NWK_MAX_HOPS : radius) - 1;

        return newRadius < 1 ? 1 : newRadius;
    }

    /**
     * Make a key for AppLinkKeyStoreEntry
     * HOT PATH: Optimized computation
     * @param deviceA
     * @param deviceB
     * @returns
     */
    /* @__INLINE__ */
    #makeAppLinkKeyId(deviceA: bigint, deviceB: bigint): string {
        return deviceA < deviceB ? `${deviceA}-${deviceB}` : `${deviceB}-${deviceA}`;
    }

    public getAppLinkKey(deviceA: bigint, deviceB: bigint): Buffer | undefined {
        const entry = this.appLinkKeyTable.get(this.#makeAppLinkKeyId(deviceA, deviceB));

        if (entry === undefined) {
            return undefined;
        }

        return entry.key;
    }

    public setAppLinkKey(deviceA: bigint, deviceB: bigint, key: Buffer): void {
        const [canonicalA, canonicalB] = deviceA < deviceB ? [deviceA, deviceB] : [deviceB, deviceA];
        const stored: AppLinkKeyStoreEntry = {
            deviceA: canonicalA,
            deviceB: canonicalB,
            key,
        };

        this.appLinkKeyTable.set(this.#makeAppLinkKeyId(canonicalA, canonicalB), stored);
    }

    public addInstallCode(device64: bigint, installCode: Buffer): Buffer {
        if (this.trustCenterPolicies.installCode === InstallCodePolicy.NOT_SUPPORTED) {
            throw new Error("Install codes are not supported by the current Trust Center policy");
        }

        const payloadLength = installCode.byteLength - 2;

        if (!INSTALL_CODE_VALID_SIZES.some((size) => size === payloadLength)) {
            throw new Error(`Invalid install code length ${payloadLength}`);
        }

        const code = installCode.subarray(0, payloadLength);
        const providedCRC = installCode.readUInt16LE(payloadLength);
        const computedCRC = computeInstallCodeCRC(code);

        if (providedCRC !== computedCRC) {
            throw new Error("Invalid install code CRC");
        }

        const key = aes128MmoHash(code);
        const entry: InstallCodeEntry = {
            code: Buffer.from(code),
            crc: providedCRC,
            key,
        };

        this.installCodeTable.set(device64, entry);
        this.setAppLinkKey(device64, this.netParams.eui64, key);

        return key;
    }

    public removeInstallCode(device64: bigint): void {
        this.installCodeTable.delete(device64);
        // Keep derived link key in appLinkKeyTable; it may have been rotated independently.
    }

    /**
     * Save state to file system in TLV format.
     * Format version 1:
     * - VERSION tag
     * - Network parameter tags (EUI64, PAN_ID, etc.)
     * - DEVICE_ENTRY tags (each containing nested TLV device data)
     * - END_MARKER
     */
    public async saveState(): Promise<void> {
        // estimate buffer size (generous upper bound)
        const estimatedSize = estimateTLVStateSize(this.deviceTable.size, this.appLinkKeyTable.size);
        const state = Buffer.allocUnsafe(estimatedSize);
        let offset = 0;

        // write version first
        offset = writeTLVUInt8(state, offset, TLVTag.VERSION, SAVE_FORMAT_VERSION);
        // network parameters (can be added/removed without breaking old readers)
        offset = writeTLVBigUInt64LE(state, offset, TLVTag.EUI64, this.netParams.eui64);
        offset = writeTLVUInt16LE(state, offset, TLVTag.PAN_ID, this.netParams.panId);
        offset = writeTLVBigUInt64LE(state, offset, TLVTag.EXTENDED_PAN_ID, this.netParams.extendedPanId);
        offset = writeTLVUInt8(state, offset, TLVTag.CHANNEL, this.netParams.channel);
        offset = writeTLVUInt8(state, offset, TLVTag.NWK_UPDATE_ID, this.netParams.nwkUpdateId);
        offset = writeTLVInt8(state, offset, TLVTag.TX_POWER, this.netParams.txPower);
        offset = writeTLV(state, offset, TLVTag.NETWORK_KEY, this.netParams.networkKey);
        offset = writeTLVUInt32LE(
            state,
            offset,
            TLVTag.NETWORK_KEY_FRAME_COUNTER,
            this.netParams.networkKeyFrameCounter + CONFIG_SAVE_FRAME_COUNTER_JUMP_OFFSET,
        );
        offset = writeTLVUInt8(state, offset, TLVTag.NETWORK_KEY_SEQUENCE_NUMBER, this.netParams.networkKeySequenceNumber);
        offset = writeTLV(state, offset, TLVTag.TC_KEY, this.netParams.tcKey);
        offset = writeTLVUInt32LE(
            state,
            offset,
            TLVTag.TC_KEY_FRAME_COUNTER,
            this.netParams.tcKeyFrameCounter + CONFIG_SAVE_FRAME_COUNTER_JUMP_OFFSET,
        );

        // device table (count is implicit in number of DEVICE_ENTRY tags)
        for (const [device64, device] of this.deviceTable) {
            const sourceRouteEntries = this.sourceRouteTable.get(device.address16);
            const deviceEntry = serializeDeviceEntry(
                device64,
                device.address16,
                device.capabilities ? encodeMACCapabilities(device.capabilities) : 0x00,
                device.authorized,
                device.neighbor,
                sourceRouteEntries,
            );
            offset = writeTLV(state, offset, TLVTag.DEVICE_ENTRY, deviceEntry);
        }

        for (const entry of this.appLinkKeyTable.values()) {
            const serializedEntry = serializeAppLinkKeyEntry(entry.deviceA, entry.deviceB, entry.key);
            offset = writeTLV(state, offset, TLVTag.APP_LINK_KEY_ENTRY, serializedEntry);
        }

        // write end marker (aids debugging and validates complete write)
        state.writeUInt8(TLVTag.END_MARKER, offset++);

        const writtenState = state.subarray(0, offset);

        // write only the used portion
        await writeFile(this.#savePath, writtenState);

        logger.debug(() => `Saved state to ${this.#savePath} (${writtenState.byteLength} bytes)`, NS);
    }

    /**
     * Read the current network state in the save file, if any present.
     * @returns
     */
    public async readNetworkState(): Promise<ParsedState | undefined> {
        try {
            const stateBuffer = await readFile(this.#savePath);

            logger.debug(() => `Loaded state from ${this.#savePath} (${stateBuffer.byteLength} bytes)`, NS);

            // Parse state once into typed structure with all values already converted to final types
            const state = readTLVs(stateBuffer);

            // Check version (already parsed to number)
            const version = state.version ?? 1;

            if (version > SAVE_FORMAT_VERSION) {
                logger.warning(`Unknown save format version ${version}, attempting to load`, NS);
            }

            logger.debug(() => `Current save network: eui64=${state.eui64} panId=${state.panId} channel=${state.channel}`, NS);

            return state;
        } catch {
            /* empty */
        }
    }

    /**
     * Load state from file system if exists, else save "initial" state.
     * Afterwards, various keys are pre-hashed and descriptors pre-encoded.
     */
    public async loadState(): Promise<void> {
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
            logger.debug(() => `Current save devices: ${state.deviceEntries.length}`, NS);

            for (const device of state.deviceEntries) {
                // Device values already parsed - just destructure
                const { address64, address16, capabilities, authorized, neighbor, sourceRouteEntries } = device;
                const decodedCap = capabilities !== 0 ? decodeMACCapabilities(capabilities) : undefined;

                this.deviceTable.set(address64, {
                    address16,
                    capabilities: decodedCap,
                    authorized,
                    neighbor,
                    recentLQAs: [],
                    incomingNWKFrameCounter: undefined, // TODO: record this (should persist across reboots)
                    endDeviceTimeout: undefined,
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

            for (const entry of state.appLinkKeys) {
                this.setAppLinkKey(entry.deviceA, entry.deviceB, entry.key);
            }
        } else {
            // `this.#savePath` does not exist, using constructor-given network params, do initial save
            await this.saveState();
        }

        // pre-compute hashes for default keys for faster processing
        registerDefaultHashedKeys(
            makeKeyedHashByType(ZigbeeKeyType.LINK, this.netParams.tcKey),
            makeKeyedHashByType(ZigbeeKeyType.NWK, this.netParams.networkKey),
            makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, this.netParams.tcKey),
            makeKeyedHashByType(ZigbeeKeyType.LOAD, this.netParams.tcKey),
        );

        this.tcVerifyKeyHash = makeKeyedHash(this.netParams.tcKey, 0x03 /* input byte per spec for VERIFY_KEY */);

        const [address, nodeDescriptor, powerDescriptor, simpleDescriptors, activeEndpoints] = encodeCoordinatorDescriptors(this.netParams.eui64);

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
    public setManufacturerCode(code: number): void {
        this.configAttributes.nodeDescriptor.writeUInt16LE(code, 7 /* static offset */);
    }

    public async savePeriodicState(): Promise<void> {
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
    public disallowJoins(): void {
        clearTimeout(this.#allowJoinTimeout);
        this.#allowJoinTimeout = undefined;

        this.trustCenterPolicies.allowJoins = false;
        this.trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
        this.associationPermit = false;

        logger.info("Disallowed joins", NS);
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
    public allowJoins(duration: number, macAssociationPermit: boolean): void {
        if (duration > 0) {
            clearTimeout(this.#allowJoinTimeout);

            this.trustCenterPolicies.allowJoins = true;
            this.trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
            this.associationPermit = macAssociationPermit;

            this.#allowJoinTimeout = setTimeout(this.disallowJoins.bind(this), Math.min(duration, 0xfe) * 1000);

            logger.info(`Allowed joins for ${duration} seconds (self=${macAssociationPermit})`, NS);
        } else {
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
     * - ✅ Enforces install code requirement (denies initial join when missing)
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
    public async associate(
        source16: number | undefined,
        source64: bigint | undefined,
        initialJoin: boolean,
        capabilities: MACCapabilities | undefined,
        neighbor: boolean,
        denyOverride?: boolean,
        allowOverride?: boolean,
    ): Promise<[status: MACAssociationStatus | number, newAddress16: number]> {
        // 0xffff when not successful and should not be retried
        let newAddress16 = source16;
        let status: MACAssociationStatus | number = MACAssociationStatus.SUCCESS;
        let unknownRejoin = false;

        if (denyOverride) {
            newAddress16 = 0xffff;
            status = MACAssociationStatus.PAN_ACCESS_DENIED;
        } else if (allowOverride) {
            if ((source16 === undefined || !this.address16ToAddress64.has(source16)) && (source64 === undefined || !this.deviceTable.has(source64))) {
                // device unknown
                unknownRejoin = true;
            }
        } else {
            if (initialJoin) {
                if (this.trustCenterPolicies.allowJoins) {
                    if (source16 === undefined || source16 === ZigbeeConsts.COORDINATOR_ADDRESS || source16 >= ZigbeeConsts.BCAST_MIN) {
                        // MAC join (no `source16`)
                        newAddress16 = this.assignNetworkAddress();

                        if (newAddress16 === 0xffff) {
                            status = MACAssociationStatus.PAN_FULL;
                        }
                    } else if (source64 !== undefined && this.deviceTable.get(source64) !== undefined) {
                        // initial join should not conflict on 64, don't allow join if it does
                        newAddress16 = 0xffff;
                        status = ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT;
                    } else {
                        const existingAddress64 = this.address16ToAddress64.get(source16);

                        if (existingAddress64 !== undefined && source64 !== existingAddress64) {
                            // join with already taken source16
                            newAddress16 = this.assignNetworkAddress();

                            if (newAddress16 === 0xffff) {
                                status = MACAssociationStatus.PAN_FULL;
                            } else {
                                // tell device to use the newly generated value
                                status = ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT;
                            }
                        }
                    }
                } else {
                    newAddress16 = 0xffff;
                    status = MACAssociationStatus.PAN_ACCESS_DENIED;
                }
            } else {
                // rejoin
                if (source16 === undefined || source16 === ZigbeeConsts.COORDINATOR_ADDRESS || source16 >= ZigbeeConsts.BCAST_MIN) {
                    // rejoin without 16, generate one (XXX: never happens?)
                    newAddress16 = this.assignNetworkAddress();

                    if (newAddress16 === 0xffff) {
                        status = MACAssociationStatus.PAN_FULL;
                    }
                } else {
                    const existingAddress64 = this.address16ToAddress64.get(source16);

                    if (existingAddress64 === undefined) {
                        // device unknown
                        unknownRejoin = true;
                    } else if (existingAddress64 !== source64) {
                        // rejoin with already taken source16
                        newAddress16 = this.assignNetworkAddress();

                        if (newAddress16 === 0xffff) {
                            status = MACAssociationStatus.PAN_FULL;
                        } else {
                            // tell device to use the newly generated value
                            status = ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT;
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
            status = MACAssociationStatus.PAN_ACCESS_DENIED;
        }
        /* v8 ignore stop */

        // const existingDevice64 = source64 ?? (source16 !== undefined ? this.address16ToAddress64.get(source16) : undefined);
        // const existingEntry = existingDevice64 !== undefined ? this.deviceTable.get(existingDevice64) : undefined;

        // if (status === MACAssociationStatus.SUCCESS && neighbor) {
        //     const isExistingDirectChild = existingEntry?.neighbor === true;

        //     if (!isExistingDirectChild && initialJoin && !unknownRejoin) {
        //         const { childCount, routerCount } = this.countDirectChildren(existingDevice64);

        //         if (childCount >= CONFIG_NWK_MAX_CHILDREN) {
        //             newAddress16 = 0xffff;
        //             status = MACAssociationStatus.PAN_FULL;
        //         } else if (capabilities?.deviceType === 1 && routerCount >= CONFIG_NWK_MAX_ROUTERS) {
        //             newAddress16 = 0xffff;
        //             status = MACAssociationStatus.PAN_FULL;
        //         }
        //     }
        // }

        logger.debug(
            () =>
                `DEVICE_JOINING[src=${source16}:${source64} newAddr16=${newAddress16} initialJoin=${initialJoin} deviceType=${capabilities?.deviceType} powerSource=${capabilities?.powerSource} rxOnWhenIdle=${capabilities?.rxOnWhenIdle}] replying with status=${status}`,
            NS,
        );

        if (
            status === MACAssociationStatus.SUCCESS &&
            initialJoin &&
            this.trustCenterPolicies.installCode === InstallCodePolicy.REQUIRED &&
            (source64 === undefined || this.installCodeTable.get(source64) === undefined)
        ) {
            newAddress16 = 0xffff;
            status = MACAssociationStatus.PAN_ACCESS_DENIED;
        }

        if (status === MACAssociationStatus.SUCCESS) {
            if (initialJoin || unknownRejoin) {
                this.deviceTable.set(source64!, {
                    address16: newAddress16,
                    capabilities, // TODO: only valid if not triggered by `processUpdateDevice`
                    // on initial join success, device is considered joined but unauthorized after MAC Assoc / NWK Commissioning response is sent
                    authorized: false,
                    neighbor,
                    recentLQAs: [],
                    incomingNWKFrameCounter: undefined,
                    endDeviceTimeout: undefined,
                });
                this.address16ToAddress64.set(newAddress16, source64!);

                // `processUpdateDevice` has no `capabilities` info, device is joined through router, so, no indirect tx for coordinator
                if (capabilities && !capabilities.rxOnWhenIdle) {
                    this.indirectTransmissions.set(source64!, []);
                }
            } else {
                // update records on rejoin in case anything has changed (like neighbor for routing)
                this.address16ToAddress64.set(newAddress16, source64!);
                const device = this.deviceTable.get(source64!)!;
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
    public async disassociate(source16: number | undefined, source64: bigint | undefined): Promise<void> {
        if (source64 === undefined && source16 !== undefined) {
            source64 = this.address16ToAddress64.get(source16);
        } else if (source16 === undefined && source64 !== undefined) {
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
                } else if (filteredEntries.length !== entries.length) {
                    this.sourceRouteTable.set(addr16, filteredEntries);
                }
            }

            logger.debug(() => `DEVICE_LEFT[src=${source16}:${source64}]`, NS);

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
