import { type ParsedState } from "../utils/save-serializer.js";
import { MACAssociationStatus, type MACCapabilities, type MACHeader } from "../zigbee/mac.js";
import type { ZigbeeAPSHeader, ZigbeeAPSPayload } from "../zigbee/zigbee-aps.js";
import type { ZigbeeNWKGPHeader } from "../zigbee/zigbee-nwkgp.js";
export interface StackCallbacks {
    onFatalError: (message: string) => void;
    /** Only triggered if MAC `emitFrames===true` */
    onMACFrame: (payload: Buffer, rssi?: number) => void;
    onFrame: (sender16: number | undefined, sender64: bigint | undefined, apsHeader: ZigbeeAPSHeader, apsPayload: ZigbeeAPSPayload, lqa: number) => void;
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
    networkKey: Buffer;
    networkKeyFrameCounter: number;
    networkKeySequenceNumber: number;
    tcKey: Buffer;
    tcKeyFrameCounter: number;
};
export declare enum InstallCodePolicy {
    /** Do not support Install Codes */
    NOT_SUPPORTED = 0,
    /** Support but do not require use of Install Codes or preset passphrases */
    NOT_REQUIRED = 1,
    /** Require the use of Install Codes by joining devices or preset Passphrases */
    REQUIRED = 2
}
export declare enum TrustCenterKeyRequestPolicy {
    DISALLOWED = 0,
    /** Any device MAY request */
    ALLOWED = 1,
    /** Only devices in the apsDeviceKeyPairSet with a KeyAttribute value of PROVISIONAL_KEY MAY request. */
    ONLY_PROVISIONAL = 2
}
export declare enum ApplicationKeyRequestPolicy {
    DISALLOWED = 0,
    /** Any device MAY request an application link key with any device (except the Trust Center) */
    ALLOWED = 1,
    /** Only those devices listed in applicationKeyRequestList MAY request and receive application link keys. */
    ONLY_APPROVED = 2
}
export declare enum NetworkKeyUpdateMethod {
    /** Broadcast using only network encryption */
    BROADCAST = 0,
    /** Unicast using network encryption and APS encryption with a device’s link key. */
    UNICAST = 1
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
export declare class StackContext {
    #private;
    /** Master table of all known devices on the network (mapped by IEEE address) */
    readonly deviceTable: Map<bigint, DeviceTableEntry>;
    /** Address lookup: 16-bit to 64-bit (synced with deviceTable) */
    readonly address16ToAddress64: Map<number, bigint>;
    /** Source routing table (mapped by 16-bit address) */
    readonly sourceRouteTable: Map<number, SourceRouteTableEntry[]>;
    /** Trust Center policies */
    readonly trustCenterPolicies: TrustCenterPolicies;
    /** Configuration attributes */
    readonly configAttributes: ConfigurationAttributes;
    /** Count of MAC NO_ACK reported for each device (mapping by network address) */
    readonly macNoACKs: Map<number, number>;
    /** Associations pending DATA_RQ from device (mapping by IEEE address) */
    readonly pendingAssociations: Map<bigint, AssociationContext>;
    /** Indirect transmission for devices with rxOnWhenIdle=false (mapping by IEEE address) */
    readonly indirectTransmissions: Map<bigint, IndirectTxContext[]>;
    /** Network parameters */
    netParams: NetworkParameters;
    /** Pre-computed hash of default TC link key for VERIFY_KEY */
    tcVerifyKeyHash: Buffer;
    /** MAC association permit flag */
    associationPermit: boolean;
    /** Minimum observed RSSI */
    rssiMin: number;
    /** Maximum observed RSSI */
    rssiMax: number;
    /** Minimum observed LQI */
    lqiMin: number;
    /** Maximum observed LQI */
    lqiMax: number;
    constructor(callbacks: StackContextCallbacks, savePath: string, netParams: NetworkParameters);
    get loaded(): boolean;
    start(): Promise<void>;
    stop(): void;
    /** Remove the save file and clear tables (just in case) */
    clear(): Promise<void>;
    /**
     * Get next Trust Center key frame counter.
     * HOT PATH: Optimized counter increment
     * @returns Incremented TC key frame counter (wraps at 0xffffffff)
     */
    nextTCKeyFrameCounter(): number;
    /**
     * Get next network key frame counter.
     * HOT PATH: Optimized counter increment
     * @returns Incremented network key frame counter (wraps at 0xffffffff)
     */
    nextNWKKeyFrameCounter(): number;
    /**
     * Get device by IEEE (64-bit) or network (16-bit) address.
     * @param address IEEE address (bigint) or network address (number)
     * @returns Device table entry or undefined if not found
     */
    getDevice(address: bigint | number): DeviceTableEntry | undefined;
    /**
     * Get IEEE (64-bit) address from network (16-bit) address.
     * @param address16 Network address
     * @returns IEEE address or undefined if not found
     */
    getAddress64(address16: number): bigint | undefined;
    /**
     * Get network (16-bit) address from IEEE (64-bit) address.
     * @param address64 IEEE address
     * @returns Network address or undefined if not found
     */
    getAddress16(address64: bigint): number | undefined;
    /**
     * 05-3474-23 #3.6.1.10
     */
    assignNetworkAddress(): number;
    /**
     * Apply logistic curve on standard mapping to LQI range [0..255]
     *
     * - Silabs EFR32: the RSSI range of [-100..-36] is mapped to an LQI range [0..255]
     * - TI zstack: `LQI = (MAC_SPEC_ED_MAX * (RSSIdbm - ED_RF_POWER_MIN_DBM)) / (ED_RF_POWER_MAX_DBM - ED_RF_POWER_MIN_DBM);`
     *     where `MAC_SPEC_ED_MAX = 255`, `ED_RF_POWER_MIN_DBM = -87`, `ED_RF_POWER_MAX_DBM = -10`
     * - Nordic: RSSI accuracy valid range -90 to -20 dBm
     */
    mapRSSIToLQI(rssi: number): number;
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
    computeLQA(signalStrength: number, signalQuality?: number): number;
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
    computeDeviceLQA(address16: number | undefined, address64: bigint | undefined, signalStrength?: number, signalQuality?: number, maxRecent?: number): number;
    /**
     * Decrement radius value for NWK frame forwarding.
     * HOT PATH: Optimized computation
     * @param radius Current radius value
     * @returns Decremented radius (minimum 1)
     */
    decrementRadius(radius: number): number;
    /**
     * Save state to file system in TLV format.
     * Format version 1:
     * - VERSION tag
     * - Network parameter tags (EUI64, PAN_ID, etc.)
     * - DEVICE_ENTRY tags (each containing nested TLV device data)
     * - END_MARKER
     */
    saveState(): Promise<void>;
    /**
     * Read the current network state in the save file, if any present.
     * @returns
     */
    readNetworkState(): Promise<ParsedState | undefined>;
    /**
     * Load state from file system if exists, else save "initial" state.
     * Afterwards, various keys are pre-hashed and descriptors pre-encoded.
     */
    loadState(): Promise<void>;
    /**
     * Set the manufacturer code in the pre-encoded node descriptor
     * @param code
     */
    setManufacturerCode(code: number): void;
    savePeriodicState(): Promise<void>;
    /**
     * Revert allowing joins (keeps `allowRejoinsWithWellKnownKey=true`).
     *
     * SPEC COMPLIANCE:
     * - ✅ Clears timer correctly
     * - ✅ Updates Trust Center allowJoins policy
     * - ✅ Maintains allowRejoinsWithWellKnownKey for rejoins
     * - ✅ Sets associationPermit flag for MAC layer
     */
    disallowJoins(): void;
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
    allowJoins(duration: number, macAssociationPermit: boolean): void;
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
    associate(source16: number | undefined, source64: bigint | undefined, initialJoin: boolean, capabilities: MACCapabilities | undefined, neighbor: boolean, denyOverride?: boolean, allowOverride?: boolean): Promise<[status: MACAssociationStatus | number, newAddress16: number]>;
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
    disassociate(source16: number | undefined, source64: bigint | undefined): Promise<void>;
}
export {};
