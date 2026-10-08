import { MACAssociationStatus, type MACCapabilities, type MACHeader } from "../zigbee/mac.js";
import type { ZigbeeAPSHeader, ZigbeeAPSPayload } from "../zigbee/zigbee-aps.js";
import type { ZigbeeNWKGPHeader } from "../zigbee/zigbee-nwkgp.js";
import { type ParsedState } from "./save-serializer.js";
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
    /** Last network key sequence number successfully transported to the device */
    lastTransportedNetworkKeySeq: number | undefined;
    /**
     * List of recently observed LQAs.
     * Note: this is runtime-only
     */
    recentLQAs: number[];
    /** Last accepted NWK security frame counter. Runtime-only. */
    incomingNWKFrameCounter: number | undefined;
    /** End device timeout metadata. Runtime-only. */
    endDeviceTimeout: {
        timeoutIndex: number;
        timeoutMs: number;
        lastUpdated: number;
        expiresAt: number;
    } | undefined;
    /** Counter for consecutive missed link status commands. Runtime-only. */
    linkStatusMisses: number | undefined;
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
/** Table 3-54 */
export declare const END_DEVICE_TIMEOUT_TABLE_MS: readonly [10000, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
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
    /** Application link keys stored for device pairs (ordered by IEEE address) */
    readonly appLinkKeyTable: Map<string, AppLinkKeyStoreEntry>;
    /** Install code metadata per device (mapped by IEEE address) */
    readonly installCodeTable: Map<bigint, Buffer<ArrayBufferLike>>;
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
    /**
     * 05-3474-23 #4.7.6 (Trust Center maintenance)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Schedules periodic state persistence while stack is running
     * - ✅ Immediately saves state to ensure on-disk snapshot reflects startup values
     * - ⚠️  Additional periodic tasks (key rotation, metrics) remain TODO
     * DEVICE SCOPE: Trust Center
     */
    start(): Promise<void>;
    /**
     * 05-3474-23 #4.7.6 (Trust Center maintenance)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Cancels pending timers and ensures join window closed on shutdown
     * - ✅ Mirrors spec recommendation to revoke permit-join when TC inactive
     * DEVICE SCOPE: Trust Center
     */
    stop(): void;
    /**
     * 05-3474-23 #4.7.6 (Trust Center maintenance)
     *
     * Remove the save file and clear tables (just in case)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Clears persistent storage and in-memory tables when performing factory reset
     * - ⚠️  Caller must reinitialize descriptors/netParams afterwards per spec flow
     * DEVICE SCOPE: Trust Center
     */
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
     * 05-3474-23 #4.4.11.2 (Network Key transport)
     *
     * Store a pending network key that will become active once a matching SWITCH_KEY is received.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Stages pending network key and associated sequence number per TRANSPORT_KEY requirements
     * - ✅ Normalizes sequence to 8-bit value to mirror Zigbee NWK field size
     * - ✅ Copies key material to avoid caller mutations (spec mandates immutable staging)
     * - ⚠️  Does not persist staged key to disk; relies on immediate SWITCH_KEY follow-up (acceptable for coordinator uptime)
     * DEVICE SCOPE: Trust Center
     *
     * @param key Raw network key bytes (16 bytes)
     * @param sequenceNumber Sequence number advertised for the pending key
     */
    setPendingNetworkKey(key: Buffer, sequenceNumber: number): void;
    markNetworkKeyTransported(address64: bigint): void;
    /**
     * 05-3474-23 #4.4.11.5 (Switch Key)
     *
     * Activate the staged network key if the sequence number matches.
     * Resets frame counters and re-registers hashed keys for cryptographic operations.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Activates staged key only when sequence matches SWITCH_KEY command
     * - ✅ Resets NWK frame counter as mandated after key activation
     * - ✅ Re-registers hashed keys for LINK/NWK/TRANSPORT/LOAD contexts to keep crypto in sync
     * - ✅ Clears staging buffers to prevent reuse or leakage
     * - ⚠️  Does not emit management notifications; assumes higher layer handles ANNCE broadcasts
     * DEVICE SCOPE: Trust Center
     *
     * @param sequenceNumber Sequence number referenced by SWITCH_KEY command
     * @returns true when activation succeeded, false when no matching pending key exists
     */
    activatePendingNetworkKey(sequenceNumber: number): boolean;
    /**
     * 05-3474-23 #3.6.1.10 (Network address allocation)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Allocates short addresses within 0x0001-0xfff7 range, excluding coordinator and broadcast values
     * - ✅ Ensures uniqueness against current `address16ToAddress64` map before assignment
     * - ⚠️  Uses pseudo-random selection rather than deterministic increment (allowed by spec)
     * - ⚠️  No persistence of last issued address; relies on state table to avoid collisions after reboot
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
    assignNetworkAddress(): number;
    /**
     * 05-3474-23 #3.6.1.11 / Table 3-54 (End Device Timeout)
     *
     * Update the stored end device timeout metadata for a device.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Validates timeout index against Table 3-54 mapping (0-14)
     * - ✅ Stores absolute expiration timestamp for NLME-ED-TIMEOUT enforcement
     * - ✅ Persists last requested index to reuse during retransmission handling
     * - ⚠️  Does not enforce parent capability bits; assumes MAC handler already vetted support
     * - ⚠️  Lifetime not persisted to disk (cleared on restart per spec allowance)
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param address64 IEEE address of the end device
     * @param timeoutIndex Requested timeout index (0-14)
     * @param now Optional timestamp override (for testing)
     * @returns Updated timeout metadata or undefined if device/index invalid
     */
    updateEndDeviceTimeout(address64: bigint, timeoutIndex: number, now?: number): DeviceTableEntry["endDeviceTimeout"] | undefined;
    /**
     * 05-3474-23 #3.7.3 (NWK security) / IEEE 802.15.4-2015 #9.4.2
     *
     * Update and validate the incoming NWK security frame counter for a device.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Rejects replayed NWK security frames when counter does not strictly increase
     * - ✅ Handles counter wrap from 0xffffffff → 0 per Zigbee PRO requirement
     * - ✅ Stores last accepted counter per IEEE address for subsequent validation
     * - ⚠️  Devices without stored state (e.g., unknown IEEE) default to allowing frame (per spec recommendation)
     * - ⚠️  Persistence across restarts not implemented (TODO noted)
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param address64
     * @param frameCounter
     * @returns false if the provided counter is a replay (<= stored value, excluding wrap).
     */
    updateIncomingNWKFrameCounter(address64: bigint | undefined, frameCounter: number): boolean;
    /**
     * IEEE 802.15.4-2015 #10.2.1 (Link Quality Indication)
     *
     * Apply logistic curve on standard mapping to LQI range [0..255]
     *
     * - Silabs EFR32: the RSSI range of [-100..-36] is mapped to an LQI range [0..255]
     * - TI zstack: `LQI = (MAC_SPEC_ED_MAX * (RSSIdbm - ED_RF_POWER_MIN_DBM)) / (ED_RF_POWER_MAX_DBM - ED_RF_POWER_MIN_DBM);`
     *     where `MAC_SPEC_ED_MAX = 255`, `ED_RF_POWER_MIN_DBM = -87`, `ED_RF_POWER_MAX_DBM = -10`
     * - Nordic: RSSI accuracy valid range -90 to -20 dBm
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Produces LQI values in mandated 0-255 range
     * - ✅ Clamps RSSI to implementation-defined sensitivity window before scaling
     * - ✅ Applies monotonic mapping to preserve relative ordering (spec leaves exact curve implementation-defined)
     * - ⚠️  Logistic curve tuned to typical 2.4 GHz radios; may require calibration per PHY
     * - ⚠️  rssiMin/rssiMax derived from runtime observation rather than PHY constants
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    mapRSSIToLQI(rssi: number): number;
    /**
     * 05-3474-23 #3.3.4.3 (Link Quality Assessment)
     *
     * LQA_raw (c, r) = 255 * (c - c_min) / (c_max - c_min) * (r - r_min) / (r_max - r_min)
     * - c_min is the lowest signal quality ever reported, i.e. for a packet that can barely be received
     * - c_max is the highest signal quality ever reported, i.e. for a packet received under ideal conditions
     * - r_min is the lowest signal strength ever reported, i.e. for a packet close to receiver sensitivity
     * - r_max is the highest signal strength ever reported, i.e. for a packet received from a strong, close-by transmitter
     * HOT PATH: Called for every incoming frame to compute link quality assessment.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Computes link quality assessment (LQA) using normalized RSSI/LQI ranges per Zigbee PRO guidance
     * - ✅ Ensures output range 0-255 for compatibility with NLME-LQI reports
     * - ✅ Accepts externally provided LQI or derives from RSSI for MACs that omit it
     * - ⚠️  Logistic coefficients tuned empirically; spec allows vendor-specific mapping
     * - ⚠️  Runtime min/max windows updated elsewhere; assumes values reflect current environment
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param signalStrength RSSI value
     * @param signalQuality LQI value (optional, computed from RSSI if not provided)
     * @returns Computed LQA value (0-255)
     */
    computeLQA(signalStrength: number, signalQuality?: number): number;
    /**
     * 05-3474-23 #2.4.4.2.3 (Neighbor table reporting)
     *
     * Compute the median LQA for a device from `recentLQAs` or using `signalStrength` directly if device unknown.
     * If given, stores the computed LQA from given parameters in the `recentLQAs` list of the device before computing median.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Maintains rolling median of recent LQA samples for stable reporting in Mgmt_Lqi_rsp
     * - ✅ Falls back to instantaneous computation when history absent, matching spec guidance
     * - ✅ Resolves IEEE address from short address when needed for table lookup
     * - ⚠️  Median window size configurable (default 10) - spec does not mandate exact count
     * - ⚠️  Zero returned when device unknown aligns with spec allowance for missing entries
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param address16 Used to retrieve `address64` if not given (must be valid if 64 is not)
     * @param address64 The IEEE address of the device
     * @param signalStrength RSSI. Optional (only use existing entries if not given)
     * @param signalQuality LQI. Optional (only use existing entries if not given)
     * @param maxRecent Number of entries to retain in rolling window (default 10)
     * @returns Median LQA for the device or 0 when unavailable
     */
    computeDeviceLQA(address16: number | undefined, address64: bigint | undefined, signalStrength?: number, signalQuality?: number, maxRecent?: number): number;
    /**
     * 05-3474-23 #3.3.1.5 (NWK radius handling)
     *
     * Decrement radius value for NWK frame forwarding.
     * HOT PATH: Optimized computation
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Decrements NWK radius while enforcing minimum value of 1 as mandated
     * - ✅ Substitutes CONFIG_NWK_MAX_HOPS when radius=0 (interpreted as unlimited per spec)
     * - ⚠️  Does not update route record metrics; caller responsible for hop tracking
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param radius Current radius value
     * @returns Decremented radius (minimum 1)
     */
    decrementRadius(radius: number): number;
    /**
     * 05-3474-23 #4.4.11 (Trust Center link/app keys)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Retrieves stored application/link key using canonicalized IEEE pair
     * - ✅ Returns undefined when pair missing, allowing caller to trigger key negotiation per spec
     * - ⚠️  Does not validate key freshness; higher layers manage key attributes
     * DEVICE SCOPE: Trust Center
     */
    getAppLinkKey(deviceA: bigint, deviceB: bigint): Buffer | undefined;
    /**
     * 05-3474-23 #4.4.11.1 (Application Link Key establishment)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Stores link/application keys using sorted IEEE tuple to match spec requirement for unordered pairs
     * - ✅ Keeps full 16-byte key material intact for subsequent APS ENCRYPT operations
     * - ⚠️  Does not persist key attributes (VERIFIED/PROVISIONAL) – tracked elsewhere
     * DEVICE SCOPE: Trust Center
     */
    setAppLinkKey(deviceA: bigint, deviceB: bigint, key: Buffer): void;
    /**
     * 05-3474-23 #4.5.1 (Install Code processing)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Validates install code length against permitted sizes (8/10/14/18/22/26 bytes)
     * - ✅ Verifies CRC-16 per Zigbee specification before accepting raw install codes
     * - ✅ Derives link key using AES-MMO hash when provided with plain install code
     * - ✅ Stores hashed value when caller already supplied derived key (e.g., from commissioning tool)
     * - ⚠️  CRC computed locally; assumes little-endian order per spec Appendix B
     * DEVICE SCOPE: Trust Center
     *
     * @param device64 IEEE address of device whose code is being stored
     * @param installCode Install code or hashed key buffer (length varies)
     * @param hashed Indicates that `installCode` already contains derived key material
     * @returns Derived application link key associated with Trust Center
     */
    addInstallCode(device64: bigint, installCode: Buffer, hashed?: boolean): Buffer;
    /**
     * 05-3474-23 #4.5.1 (Install Code lifecycle)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Removes stored install code metadata upon revocation
     * - ⚠️  Leaves derived link key intact (spec allows retention for existing secure links)
     * DEVICE SCOPE: Trust Center
     */
    removeInstallCode(device64: bigint): void;
    /**
     * 05-3474-23 #4.7.6 (Trust Center persistent data)
     *
     * Save state to file system in TLV format.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Persists Trust Center datasets (network parameters, device table, link keys) between restarts
     * - ✅ Adds frame-counter jump offset when storing to meet anti-replay requirements after reboot
     * - ✅ Serializes TLV records for extensibility and backward compatibility
     * - ⚠️  Format version tracked locally; interoperability with other implementations requires converter
     * - ⚠️  Application link key attributes not currently stored (keys only)
     * DEVICE SCOPE: Trust Center
     *
     * Format version 1:
     * - VERSION tag
     * - Network parameter tags (EUI64, PAN_ID, etc.)
     * - DEVICE_ENTRY tags (each containing nested TLV device data)
     * - END_MARKER
     */
    saveState(): Promise<void>;
    /**
     * 05-3474-23 #4.7.6 (Trust Center persistent data)
     *
     * Read the current network state in the save file, if any present.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Reads TLV state blob and validates version before applying
     * - ✅ Logs metadata (PAN ID, channel) for diagnostics per spec recommendations
     * - ⚠️  Unknown future versions are attempted with warning rather than hard fail (best effort)
     * DEVICE SCOPE: Trust Center
     */
    readNetworkState(): Promise<ParsedState | undefined>;
    /**
     * 05-3474-23 #4.7.6 (Trust Center start-up procedure)
     *
     * Load state from file system if exists, else save "initial" state.
     * Afterwards, various keys are pre-hashed and descriptors pre-encoded.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Restores network parameters, device table, and link keys before enabling stack operations
     * - ✅ Recomputes hashed keys for LINK/NWK/TRANSPORT/LOAD usage as required for secure processing
     * - ✅ Initializes coordinator descriptors per Zigbee Device Objects defaults
     * - ⚠️  Missing persistence for per-device incoming NWK frame counters (TODO noted)
     * - ⚠️  Creates initial save file when none exists to align with spec initialization sequence
     * DEVICE SCOPE: Trust Center
     */
    loadState(): Promise<void>;
    /**
     * 05-3474-23 #2.3.2.3 (Node Descriptor)
     *
     * Set the manufacturer code in the pre-encoded node descriptor
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Writes manufacturer code at fixed offset within pre-encoded ZDO node descriptor response
     * - ⚠️  Assumes descriptor already generated via `encodeCoordinatorDescriptors`
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param code Manufacturer code assigned by CSA
     */
    setManufacturerCode(code: number): void;
    /**
     * 05-3474-23 #4.7.6 (Trust Center maintenance)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Persists state at configured interval while refreshing timer to maintain cadence
     * - ⚠️  Interval configurable via CONFIG_SAVE_STATE_TIME (60s default)
     * DEVICE SCOPE: Trust Center
     */
    savePeriodicState(): Promise<void>;
    /**
     * Revert allowing joins (keeps `allowRejoinsWithWellKnownKey=true`).
     *
     * SPEC COMPLIANCE:
     * - ✅ Clears timer correctly
     * - ✅ Updates Trust Center allowJoins policy
     * - ✅ Maintains allowRejoinsWithWellKnownKey for rejoins
     * - ✅ Sets associationPermit flag for MAC layer
     * DEVICE SCOPE: Trust Center
     */
    disallowJoins(): void;
    /**
     * SPEC COMPLIANCE:
     * - ✅ Implements timed join window per spec
     * - ✅ Updates Trust Center policies
     * - ✅ Sets MAC associationPermit flag
     * - ✅ Clamps 0xff to 0xfe for security
     * - ✅ Auto-disallows after timeout
     * DEVICE SCOPE: Trust Center
     *
     * @param duration The length of time in seconds during which the trust center will allow joins.
     * The value 0x00 and 0xff indicate that permission is disabled or enabled, respectively, without a specified time limit.
     * 0xff is clamped to 0xfe for security reasons
     * @param macAssociationPermit If true, also allow association on coordinator itself. Ignored if duration 0.
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
     * - ✅ Enforces install code requirement (denies initial join when missing)
     * - ✅ Detects network key changes on rejoin and schedules transport
     * DEVICE SCOPE: Coordinator, routers (N/A)
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
    associate(source16: number | undefined, source64: bigint | undefined, initialJoin: boolean, capabilities: MACCapabilities | undefined, neighbor: boolean, denyOverride?: boolean, allowOverride?: boolean): Promise<[status: MACAssociationStatus | number, newAddress16: number, requiresTransportKey: boolean]>;
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
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
    disassociate(source16: number | undefined, source64: bigint | undefined): Promise<void>;
}
export {};
