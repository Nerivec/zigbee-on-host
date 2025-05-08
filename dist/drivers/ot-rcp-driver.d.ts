import EventEmitter from "node:events";
import { SpinelCommandId } from "../spinel/commands.js";
import { type HdlcFrame } from "../spinel/hdlc.js";
import { SpinelPropertyId } from "../spinel/properties.js";
import { type SpinelFrame, type SpinelStreamRawMetadata, type StreamRawConfig } from "../spinel/spinel.js";
import { MACAssociationStatus, type MACCapabilities, MACCommandId, type MACHeader } from "../zigbee/mac.js";
import { ZigbeeAPSCommandId, ZigbeeAPSDeliveryMode, type ZigbeeAPSHeader, type ZigbeeAPSPayload } from "../zigbee/zigbee-aps.js";
import { ZigbeeNWKCommandId, type ZigbeeNWKHeader, type ZigbeeNWKLinkStatus, ZigbeeNWKManyToOne, ZigbeeNWKRouteDiscovery, ZigbeeNWKStatus } from "../zigbee/zigbee-nwk.js";
import { type ZigbeeNWKGPHeader } from "../zigbee/zigbee-nwkgp.js";
import { type ZigbeeSecurityHeader } from "../zigbee/zigbee.js";
import { OTRCPParser } from "./ot-rcp-parser.js";
import { OTRCPWriter } from "./ot-rcp-writer.js";
interface AdapterDriverEventMap {
    macFrame: [payload: Buffer, rssi?: number];
    fatalError: [message: string];
    frame: [sender16: number | undefined, sender64: bigint | undefined, apsHeader: ZigbeeAPSHeader, apsPayload: ZigbeeAPSPayload, lqa: number];
    gpFrame: [cmdId: number, payload: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, lqa: number];
    deviceJoined: [source16: number, source64: bigint, capabilities: MACCapabilities];
    deviceRejoined: [source16: number, source64: bigint, capabilities: MACCapabilities];
    deviceLeft: [source16: number, source64: bigint];
    deviceAuthorized: [source16: number, source64: bigint];
}
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
export type NetworkParameters = {
    eui64: bigint;
    panId: number;
    extendedPANId: bigint;
    channel: number;
    nwkUpdateId: number;
    txPower: number;
    networkKey: Buffer;
    networkKeyFrameCounter: number;
    networkKeySequenceNumber: number;
    tcKey: Buffer;
    tcKeyFrameCounter: number;
};
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
 * see 05-3474-23 #3.6.1.7
 *
 * SHALL contain information on every device on the current Zigbee network within transmission range, up to some implementation-dependent limit.
 * The neighbor does not store information about potential networks and candidate parents to join or rejoin.
 * The Discovery table SHALL be used for this.
 */
export type NeighborTableEntry = {
    /** 64-bit IEEE address that is unique to every device. */
    address64: bigint;
    /**
     * The type of neighbor device:
     * - 0x00 = Zigbee coordinator
     * - 0x01 = Zigbee router
     * - 0x02 = Zigbee end device
     *
     * This field SHALL be present in every neighbor table entry.
     */
    deviceType: number;
    rxOnWhenIdle: boolean;
    capabilities: number;
    /** The end device’s configuration. See section 3.4.11.3.2. The default value SHALL be 0. uint16_t */
    endDeviceConfig: number;
    /**
     * This field indicates the current time remaining, in seconds, for the end device.
     * 0x00000000 – 0x00F00000
     */
    timeoutCounter?: number;
    /**
     * This field indicates the timeout, in seconds, for the end device child.
     * The default value for end device entries is calculated by using the nwkEndDeviceTimeoutDefault value and indexing into Table 3-54, then converting the value to seconds.
     * End Devices MAY negotiate a longer or shorter time using the NWK Command End Device Timeout Request.
     * 0x00000000 – 0x0001FA40
     */
    deviceTimeout?: number;
    /**
     * The relationship between the neighbor and the current device:
     * - 0x00 = neighbor is the parent
     * - 0x01 = neighbor is a child
     * - 0x02 = neighbor is a sibling
     * - 0x03 = none of the above
     * - 0x04 = previous child
     * - 0x05 = unauthenticated child
     * - 0x06 = unauthorized child with relay allowed
     * - 0x07 = neighbor is a lost child
     * - 0x08 = neighbor is a child with address conflict
     * - 0x09 = neighbor is a backbone mesh sibling
     *
     * This field SHALL be present in every neighbor table entry.
     */
    relationship: number;
    /**
     * A value indicating if previous transmissions to the device were successful or not.
     * Higher values indicate more failures.
     * uint8_t
     *
     * This field SHALL be present in every neighbor table entry.
     */
    transmitFailure: number;
    /**
     * The estimated link quality for RF transmissions from this device.
     * See section 3.6.4.1 for a discussion of how this is calculated.
     * uint8_t
     *
     * This field SHALL be present in every neighbor table entry.
     */
    lqa: number;
    /**
     * The cost of an outgoing link as measured by the neighbor.
     * A value of 0 indicates no outgoing cost is available.
     * uint8_t
     *
     * This field is mandatory.
     */
    outgoingCost: number;
    /**
     * The number of nwkLinkStatusPeriod intervals since a link status command was received.
     * uint8_t
     *
     * This field is mandatory.
     */
    age: number;
    /**
     * The time, in symbols, at which the last beacon frame was received from the neighbor.
     * This value is equal to the timestamp taken when the beacon frame was received, as described in IEEE Std 802.15.4-2020 [B1].
     * 0x000000 – 0xffffff
     *
     * This field is optional.
     */
    incomingBeaconTimestamp?: number;
    /**
     * The transmission time difference, in symbols, between the neighbor’s beacon and its parent’s beacon.
     * This difference MAY be subtracted from the corresponding incoming beacon timestamp to calculate the beacon transmission time of the neighbor’s parent.
     * 0x000000 – 0xffffff
     *
     * This field is optional.
     */
    beaconTransmissionTimeOffset?: number;
    /** This value indicates at least one keepalive has been received from the end device since the router has rebooted. */
    keepaliveReceived: boolean;
    /** This is an index into the MAC Interface Table indicating what interface the neighbor or child is bound to. 0-31 */
    macInterfaceIndex: number;
    /** The number of bytes transmitted via MAC unicast to the neighbor. This is an optional field. uint32_t */
    macUnicastBytesTransmitted?: number;
    /** The number of bytes received via MAC unicast from this neighbor. This is an optional field. uint32_t */
    macUnicastBytesReceived?: number;
    /**
     * The number of nwkLinkStatusPeriod intervals, which elapsed since this router neighbor was added to the neighbor table.
     * This value is only maintained on routers and the coordinator and is only valid for entries with a relationship of ‘parent’, ‘sibling’ or ‘backbone mesh sibling’.
     * This is a saturating up-counter, which does not roll-over.
     * uint16_t
     */
    routerAge: number;
    /**
     * An indicator for how well this router neighbor is connected to other routers in its vicinity.
     * Higher numbers indicate better connectivity.
     * This metric takes the number of mesh links and their incoming and outgoing costs into account.
     * This value is only maintained on routers and the coordinator and is only valid for entries with a relationship of ‘parent’, ‘sibling’ or ‘backbone mesh sibling’.
     * 0x00-0xb6
     */
    routerConnectivity: number;
    /**
     * An indicator for how different the sibling router’s set of neighbors is compared to the local router’s set of neighbors.
     * Higher numbers indicate a higher degree of diversity.
     * This value is only maintained on routers and the coordinator and is only valid for entries with a relationship of ‘parent’, ‘sibling’ or ‘backbone mesh sibling’.
     */
    routerNeighborSetDiversity: number;
    /**
     * A saturating counter, which is preloaded with nwkRouterAgeLimit when this neighbor table entry is created;
     * incremented whenever this neighbor is used as a next hop for a data packet; and decremented unconditionally once every nwkLinkStatusPeriod.
     * This value is only maintained on routers and the coordinator and is only valid for entries with a relationship of ‘parent’, ‘sibling’ or ‘backbone mesh sibling’.
     * uint8_t
     */
    routerOutboundActivity: number;
    /**
     * A saturating counter, which is preloaded with nwkRouterAgeLimit when this neighbor table entry is created;
     * incremented whenever the local device is used by this neighbor as a next hop for a data packet; and decremented unconditionally once every nwkLinkStatus-Period.
     * This value is only maintained on routers and the coordinator and is only valid for entries with a relationship of ‘parent’, ‘sibling’ or ‘backbone mesh sibling’.
     * uint8_t
     */
    routerInboundActivity: number;
    /**
     * If the local device is joined to the network this is a countdown timer indicating how long an “unauthorized child” neighbor is allowed to be kept in the neighbor table.
     * If the timer reaches zero the entry SHALL be deleted.
     * If the local device is an unauthorized child and not fully joined to the network, this is a timer indicating how long it will maintain its parent before giving up the join or rejoin.
     * If the timer reaches zero then the device SHALL leave the network.
     * uint8_t
     */
    securityTimer: number;
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
    relayAddresses: number[];
    /** TODO: formula? */
    pathCost: number;
};
/**
 * see 05-3474-23 Table 4-2
 * TODO
 * This set contains the network keying material, which SHOULD be accessible to commissioning applications.
 */
export type NWKSecurityMaterialSet = undefined;
/**
 * see 05-3474-23 Table 2-24
 * TODO
 * The binding table for this device. Binding provides a separation of concerns in the sense that applications MAY operate without having to manage recipient address information for the frames they emit. This information can be input at commissioning time without the main application on the device even being aware of it.
 */
export type APSBindingTable = {
    destination: number;
};
/**
 * see 05-3474-23 Table 4-35
 * A set of key-pair descriptors containing link keys shared with other devices.
 */
export type APSDeviceKeyPairSet = {
    /**
     * A set of feature flags pertaining to this security material or denoting the peer’s support for specific APS security features:
     * - Bit #0: Frame Counter Synchronization Support When set to ‘1' the peer device supports APS frame counter synchronization; else, when set to '0’,
     *   the peer device does not support APS frame counter synchronization.
     * - Bits #1..#7 are reserved and SHALL be set to '0' by implementations of the current Revision of this specification and ignored when processing.
     *
     * 0x00-0x01, default: 0x00
     */
    featuresCapabilities: number;
    /** Identifies the address of the entity with which this key-pair is shared. */
    deviceAddress: bigint;
    /**
     * This indicates attributes about the key.
     * - 0x00 = PROVISIONAL_KEY
     * - 0x01 = UNVERIFIED_KEY
     * - 0x02 = VERIFIED_KEY
     */
    keyAttributes: number;
    /** The actual value of the link key. */
    linkKey: Buffer;
    /** Outgoing frame counter for use with this link key. uint32_t */
    outgoingFrameCounter: number;
    /** Incoming frame counter value corresponding to DeviceAddress. uint32_t */
    incomingFrameCounter: number;
    /**
     * The type of link key in use. This will determine the security policies associated with sending and receiving APS messages.
     * - 0x00 = Unique Link Key
     * - 0x01 = Global Link Key
     *
     * Default: 0x00
     */
    apsLinkKeyType: number;
    /**
     * - 0x00 = NO_AUTHENTICATION
     * - 0x01 = INSTALL_CODE_KEY
     * - 0x02 = ANONYMOUS_KEY_NEGOTIATION
     * - 0x03 = KEY_NEGOTIATION_WITH_AUTHENTICATION
     *
     * Default: 0x00
     */
    initialJoinAuthentication: number;
    /** The value of the selected TLV sent to the device. 0x00-0x08, default: 0x00 (`APS Request Key` method) */
    keyNegotiationMethod: number;
    /**
     * - 0x00 = NO_KEY_NEGOTIATION
     * - 0x01 = START_KEY_NEGOTIATION
     * - 0x02 = COMPLETE_KEY_NEGOTIATION
     *
     * default: 0x00
     */
    keyNegotiationState: number;
    /**
     * A value that is used by both sides during dynamic key negotiation.
     * An unset value means this key-pair entry was not dynamically negotiated.
     * Any other value indicates the entry was dynamically negotiated.
     */
    passphrase?: Buffer;
    /**
     * The timeout, in seconds, for the specified key.
     * When this timeout expires, the key SHALL be marked EXPIRED_KEY in the KeyAttributes and the LinkKey value SHALL not be used for encryption of messages.
     * A value of 0xFFFF for the Timeout mean the key never expires.
     *
     * default: 0xffff
     */
    timeout: number;
    /**
     * This indicates whether the particular KeyPair passphrase MAY be updated for the device.
     * A passphrase update is normally only allowed shortly after joining.
     * See section 4.7.2.1.
     *
     * default: true
     */
    passphraseUpdateAllowed: boolean;
    /**
     * Indicates whether the incoming frame counter value has been verified through a challenge response.
     *
     * default: false
     */
    verifiedFrameCounter: boolean;
    /**
     * This indicates what Link Key update method was used after the device joined the network.
     * - 0x00 = Not Updated
     * - 0x01 = Key Request Method
     * - 0x02 = Unauthenticated Key Negotiation
     * - 0x03 = Authenticated Key Negotiation
     * - 0x04 = Application Defined Certificate Based Mutual Authentication
     */
    postJoinKeyUpdateMethod: number;
    /**
     * The key used to indicate a Trust Center Swap-out has occurred.
     * This key SHALL always be set to a hash of the LinkKey element.
     * If the LinkKey is updated, then this value MUST be updated as well.
     * See section 4.7.4.1.2.4.
     * If the entry in the apsDeviceKeyPairSet is an application link key (where local device and the partner are not Trust Centers),
     * implementations MAY elide this element for that entry.
     */
    trustCenterSwapOutLinkKey?: Buffer;
    /**
     * If set to TRUE, the device identified by DeviceAddress is a Zigbee Direct Virtual Device (ZVD).
     * A Trust Center SHALL NOT send network keys to this device.
     *
     * default: false
     */
    isVirtualDevice: boolean;
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
 * R23 changes the "recommended" way to backup by introducing hash-based keys restoration.
 * Devices pre-R23 require backing up the actual keys.
 */
export type Backup = {
    nwkPANId: bigint;
    nwkExtendedPANId: bigint;
    nwkIEEEAddress: bigint;
    nwkChannel: number;
    nwkActiveKeySeqNum: number;
    nwkSecurityMaterialSet: NWKSecurityMaterialSet;
    apsBindingTable: Map<number, APSBindingTable>;
    apsDeviceKeyPairSet: Map<number, Partial<APSDeviceKeyPairSet>>;
    trustCenterPolicies: TrustCenterPolicies;
};
export declare class OTRCPDriver extends EventEmitter<AdapterDriverEventMap> {
    #private;
    readonly writer: OTRCPWriter;
    readonly parser: OTRCPParser;
    readonly streamRawConfig: StreamRawConfig;
    readonly savePath: string;
    /** The minimum observed RSSI */
    rssiMin: number;
    /** The maximum observed RSSI */
    rssiMax: number;
    /** The minimum observed LQI */
    lqiMin: number;
    /** The maximum observed LQI */
    lqiMax: number;
    /** Associations pending DATA_RQ from device. Mapping by network64 */
    readonly pendingAssociations: Map<bigint, {
        sendResp: () => Promise<void>;
        timestamp: number;
    }>;
    /** Indirect transmission for devices with rxOnWhenIdle set to false. Mapping by network64 */
    readonly indirectTransmissions: Map<bigint, {
        sendFrame: () => Promise<boolean>;
        timestamp: number;
    }[]>;
    /** Count of MAC NO_ACK reported by Spinel for each device (only present if any). Mapping by network16 */
    readonly macNoACKs: Map<number, number>;
    /** Count of route failures reported by the network for each device (only present if any). Mapping by network16 */
    readonly routeFailures: Map<number, number>;
    netParams: NetworkParameters;
    /** Master table of all known devices on the network. mapping by network64 */
    readonly deviceTable: Map<bigint, DeviceTableEntry>;
    /** Lookup synced with deviceTable, maps network address to IEEE address */
    readonly address16ToAddress64: Map<number, bigint>;
    /** mapping by network16 */
    readonly sourceRouteTable: Map<number, SourceRouteTableEntry[]>;
    /** mapping by network16 */
    /** mapping by network16 */
    /** Several attributes are set by `loadState` */
    readonly configAttributes: ConfigurationAttributes;
    constructor(streamRawConfig: StreamRawConfig, netParams: NetworkParameters, saveDir: string, emitMACFrames?: boolean);
    get protocolVersionMajor(): number;
    get protocolVersionMinor(): number;
    get ncpVersion(): string;
    get interfaceType(): number;
    get rcpAPIVersion(): number;
    get rcpMinHostAPIVersion(): number;
    get currentSpinelTID(): number;
    /**
     * @returns increased TID offsetted by +1. [1-14] range for the "actually-used" value (0 is reserved)
     */
    private nextSpinelTID;
    private nextMACSeqNum;
    private nextNWKSeqNum;
    private nextAPSCounter;
    private nextZDOSeqNum;
    private nextTCKeyFrameCounter;
    private nextNWKKeyFrameCounter;
    private nextRouteRequestId;
    private decrementRadius;
    /**
     * Get the basic info from the RCP firmware and reset it.
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#appendix-C.1
     *
     * Should be called before `formNetwork` but after `resetNetwork` (if needed)
     */
    start(): Promise<void>;
    stop(): Promise<void>;
    waitForReset(): Promise<void>;
    /**
     * Performs a STACK reset after resetting a few PHY/MAC properties to default.
     * If up, will stop network before.
     */
    resetStack(): Promise<void>;
    /**
     * Performs a software reset into bootloader.
     * If up, will stop network before.
     */
    resetIntoBootloader(): Promise<void>;
    onFrame(buffer: Buffer): Promise<void>;
    /**
     * Logic optimizes code paths to try to avoid more parsing when frames will eventually get ignored by detecting as early as possible.
     */
    onStreamRawFrame(payload: Buffer, metadata: SpinelStreamRawMetadata | undefined): Promise<void>;
    sendFrame(hdlcFrame: HdlcFrame): void;
    sendCommand(commandId: SpinelCommandId, buffer: Buffer, waitForResponse: false): Promise<undefined>;
    sendCommand(commandId: SpinelCommandId, buffer: Buffer, waitForResponse: true, timeout: number): Promise<SpinelFrame>;
    waitForTID(tid: number, timeout: number): Promise<SpinelFrame>;
    getProperty(propertyId: SpinelPropertyId, timeout?: number): ReturnType<typeof this.sendCommand>;
    setProperty(payload: Buffer, timeout?: number): Promise<void>;
    /**
     * The CCA (clear-channel assessment) threshold.
     * NOTE: Currently not implemented in: ot-ti
     * @returns dBm (int8)
     */
    getPHYCCAThreshold(): Promise<number>;
    /**
     * The CCA (clear-channel assessment) threshold.
     * Set to -128 to disable.
     * The value will be rounded down to a value that is supported by the underlying radio hardware.
     * NOTE: Currently not implemented in: ot-ti
     * @param ccaThreshold dBm (>= -128 and <= 127)
     */
    setPHYCCAThreshold(ccaThreshold: number): Promise<void>;
    /**
     * The transmit power of the radio.
     * @returns dBm (int8)
     */
    getPHYTXPower(): Promise<number>;
    /**
     * The transmit power of the radio.
     * The value will be rounded down to a value that is supported by the underlying radio hardware.
     * @param txPower dBm (>= -128 and <= 127)
     */
    setPHYTXPower(txPower: number): Promise<void>;
    /**
     * The current RSSI (Received signal strength indication) from the radio.
     * This value can be used in energy scans and for determining the ambient noise floor for the operating environment.
     * @returns dBm (int8)
     */
    getPHYRSSI(): Promise<number>;
    /**
     * The radio receive sensitivity.
     * This value can be used as lower bound noise floor for link metrics computation.
     * @returns dBm (int8)
     */
    getPHYRXSensitivity(): Promise<number>;
    /**
     * Start an energy scan.
     * Cannot be used after state is loaded or network is up.
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.1
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.10
     * @param channels List of channels to scan
     * @param period milliseconds per channel
     * @param txPower
     */
    startEnergyScan(channels: number[], period: number, txPower: number): Promise<void>;
    stopEnergyScan(): Promise<void>;
    /**
     * Start sniffing.
     * Cannot be used after state is loaded or network is up.
     * WARNING: This is expected to run in the "run-and-quit" pattern as it overrides the `onStreamRawFrame` function.
     * @param channel The channel to sniff on
     */
    startSniffer(channel: number): Promise<void>;
    stopSniffer(): Promise<void>;
    /**
     * Send 802.15.4 MAC frame without checking for need to use indirect transmission.
     * @param seqNum
     * @param payload
     * @param dest16
     * @param dest64
     * @returns True if success sending
     */
    sendMACFrameDirect(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean>;
    /**
     * Send 802.15.4 MAC frame.
     * @param seqNum
     * @param payload
     * @param dest16
     * @param dest64
     * @returns True if success sending. Undefined if set for indirect transmission.
     */
    sendMACFrame(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean | undefined>;
    /**
     * Send 802.15.4 MAC command
     * @param cmdId
     * @param dest16
     * @param dest64
     * @param extSource
     * @param payload
     * @returns True if success sending
     */
    sendMACCommand(cmdId: MACCommandId, dest16: number | undefined, dest64: bigint | undefined, extSource: boolean, payload: Buffer): Promise<boolean>;
    /**
     * Process 802.15.4 MAC command.
     * @param data
     * @param macHeader
     * @returns
     */
    processMACCommand(data: Buffer, macHeader: MACHeader): Promise<void>;
    /**
     * Process 802.15.4 MAC association request.
     * @param data
     * @param offset
     * @param macHeader
     * @returns
     */
    processMACAssocReq(data: Buffer, offset: number, macHeader: MACHeader): Promise<number>;
    /**
     * Process 802.15.4 MAC association response.
     * @param data
     * @param offset
     * @param macHeader
     * @returns
     */
    processMACAssocRsp(data: Buffer, offset: number, macHeader: MACHeader): number;
    /**
     * Send 802.15.4 MAC association response
     * @param dest64
     * @param newAddress16
     * @param status
     * @returns
     */
    sendMACAssocRsp(dest64: bigint, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean>;
    /**
     * Process 802.15.4 MAC beacon request.
     * @param _data
     * @param offset
     * @param _macHeader
     * @returns
     */
    processMACBeaconReq(_data: Buffer, offset: number, _macHeader: MACHeader): Promise<number>;
    /**
     * Process 802.15.4 MAC data request.
     * Used by indirect transmission devices to retrieve information from parent.
     * @param _data
     * @param offset
     * @param macHeader
     * @returns
     */
    processMACDataReq(_data: Buffer, offset: number, macHeader: MACHeader): Promise<number>;
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
    sendZigbeeNWKCommand(cmdId: ZigbeeNWKCommandId, finalPayload: Buffer, nwkSecurity: boolean, nwkSource16: number, nwkDest16: number, nwkDest64: bigint | undefined, nwkRadius: number): Promise<boolean>;
    processZigbeeNWKCommand(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<void>;
    /**
     * 05-3474-R #3.4.1
     */
    processZigbeeNWKRouteReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-R #3.4.1
     *
     * @param manyToOne
     * @param destination16 intended destination of the route request command frame
     * @param destination64 SHOULD always be added if it is known
     * @returns
     */
    sendZigbeeNWKRouteReq(manyToOne: ZigbeeNWKManyToOne, destination16: number, destination64?: bigint): Promise<boolean>;
    /**
     * 05-3474-R #3.4.2
     */
    processZigbeeNWKRouteReply(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
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
    sendZigbeeNWKRouteReply(requestDest1stHop16: number, requestRadius: number, requestId: number, originator16: number, responder16: number, originator64?: bigint, responder64?: bigint): Promise<boolean>;
    /**
     * 05-3474-R #3.4.3
     */
    processZigbeeNWKStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
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
    sendZigbeeNWKStatus(requestSource16: number, status: ZigbeeNWKStatus, destination?: number): Promise<boolean>;
    /**
     * 05-3474-R #3.4.4
     */
    processZigbeeNWKLeave(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
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
    sendZigbeeNWKLeave(destination16: number, rejoin: boolean): Promise<boolean>;
    /**
     * 05-3474-R #3.4.5
     */
    processZigbeeNWKRouteRecord(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.6
     * Optional
     */
    processZigbeeNWKRejoinReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-R #3.4.7
     * Optional
     */
    processZigbeeNWKRejoinResp(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
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
    sendZigbeeNWKRejoinResp(requestSource16: number, newAddress16: number, status: MACAssociationStatus | number, capabilities: MACCapabilities): Promise<boolean>;
    /**
     * 05-3474-R #3.4.8
     */
    processZigbeeNWKLinkStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.8
     *
     * @param links set of link status entries derived from the neighbor table (SHALL be specific to the interface to be transmitted on)
     * Links are expected sorted in ascending order by network address.
     * - incoming cost contains device's estimate of the link cost for the neighbor
     * - outgoing cost contains value of outgoing cost from neighbor table
     */
    sendZigbeeNWKLinkStatus(links: ZigbeeNWKLinkStatus[]): Promise<void>;
    /**
     * 05-3474-R #3.4.9
     *  deprecated in R23, should no longer be sent by R23 devices
     */
    processZigbeeNWKReport(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.10
     */
    processZigbeeNWKUpdate(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.11
     */
    processZigbeeNWKEdTimeoutRequest(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-R #3.4.12
     */
    processZigbeeNWKEdTimeoutResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.12
     *
     * @param requestDest16
     * @param requestedTimeout Requested timeout enumeration [0-14] (mapping to actual timeout) @see processZigbeeNWKEdTimeoutRequest
     * @returns
     */
    sendZigbeeNWKEdTimeoutResponse(requestDest16: number, requestedTimeout: number): Promise<boolean>;
    /**
     * 05-3474-R #3.4.13
     */
    processZigbeeNWKLinkPwrDelta(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.14
     * Optional
     */
    processZigbeeNWKCommissioningRequest(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-23 #3.4.15
     * Optional
     */
    processZigbeeNWKCommissioningResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.15
     * Optional
     *
     * @param requestSource16
     * @param newAddress16 the new 16-bit network address assigned, may be same as `requestDest16`
     * @returns
     */
    sendZigbeeNWKCommissioningResponse(requestSource16: number, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean>;
    checkZigbeeNWKGPDuplicate(macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader): boolean;
    /**
     * See 14-0563-19 #A.3.8.2
     * @param data
     * @param macHeader
     * @param nwkHeader
     * @param rssi
     * @returns
     */
    processZigbeeNWKGPFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, lqa: number): void;
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
    sendZigbeeAPSCommand(cmdId: ZigbeeAPSCommandId, finalPayload: Buffer, nwkDiscoverRoute: ZigbeeNWKRouteDiscovery, nwkSecurity: boolean, nwkDest16: number | undefined, nwkDest64: bigint | undefined, apsDeliveryMode: ZigbeeAPSDeliveryMode.UNICAST | ZigbeeAPSDeliveryMode.BCAST, apsSecurityHeader: ZigbeeSecurityHeader | undefined, disableACKRequest?: boolean): Promise<boolean>;
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
    sendZigbeeAPSData(finalPayload: Buffer, nwkDiscoverRoute: ZigbeeNWKRouteDiscovery, nwkDest16: number | undefined, nwkDest64: bigint | undefined, apsDeliveryMode: ZigbeeAPSDeliveryMode, clusterId: number, profileId: number, destEndpoint: number | undefined, sourceEndpoint: number | undefined, group: number | undefined): Promise<number>;
    sendZigbeeAPSACK(macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void>;
    onZigbeeAPSFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader, lqa: number): Promise<void>;
    processZigbeeAPSCommand(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void>;
    /**
     * 05-3474-R #4.4.11.1
     */
    processZigbeeAPSTransportKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * 05-3474-R #4.4.11.1
     *
     * @param nwkDest16
     * @param key SHALL contain the link key that SHOULD be used for APS encryption
     * @param destination64 SHALL contain the address of the device which SHOULD use this link key
     * @returns
     */
    sendZigbeeAPSTransportKeyTC(nwkDest16: number, key: Buffer, destination64: bigint): Promise<boolean>;
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
    sendZigbeeAPSTransportKeyNWK(nwkDest16: number, key: Buffer, seqNum: number, destination64: bigint): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.1 #4.4.11.1.3.3
     *
     * @param nwkDest16
     * @param key SHALL contain a link key that is shared with the device identified in the partner address sub-field
     * @param partner SHALL contain the address of the other device that was sent this link key
     * @param initiatorFlag SHALL be set to 1 if the device receiving this packet requested this key. Otherwise, this sub-field SHALL be set to 0.
     * @returns
     */
    sendZigbeeAPSTransportKeyAPP(nwkDest16: number, key: Buffer, partner: bigint, initiatorFlag: boolean): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.2
     */
    processZigbeeAPSUpdateDevice(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): Promise<number>;
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
    sendZigbeeAPSUpdateDevice(nwkDest16: number, device64: bigint, device16: number, status: number): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.3
     */
    processZigbeeAPSRemoveDevice(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * 05-3474-R #4.4.11.3
     *
     * @param nwkDest16 parent
     * @param target64
     * @returns
     */
    sendZigbeeAPSRemoveDevice(nwkDest16: number, target64: bigint): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.4 #4.4.5.2.3
     */
    processZigbeeAPSRequestKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<number>;
    /**
     * 05-3474-R #4.4.11.4
     *
     * @param nwkDest16
     * @param keyType SHALL be set to the key being requested
     * - 0x02: App link key
     * - 0x04: TC link key
     * @param partner64 When the RequestKeyType field is 2 (that is, an application key),
     * the partner address field SHALL contain the extended 64-bit address of the partner device that SHALL be sent the key.
     * Both the partner device and the device originating the request-key command will be sent the key.
     * @returns
     */
    sendZigbeeAPSRequestKey(nwkDest16: number, keyType: 0x02, partner64: bigint): Promise<boolean>;
    sendZigbeeAPSRequestKey(nwkDest16: number, keyType: 0x04): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.5
     */
    processZigbeeAPSSwitchKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * 05-3474-R #4.4.11.5
     *
     * @param nwkDest16
     * @param seqNum SHALL contain the sequence number identifying the network key to be made active.
     * @returns
     */
    sendZigbeeAPSSwitchKey(nwkDest16: number, seqNum: number): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.6
     */
    processZigbeeAPSTunnel(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * 05-3474-R #4.4.11.6
     *
     * @param nwkDest16
     * @param destination64 SHALL be the 64-bit extended address of the device that is to receive the tunneled command
     * @param tApsCmdFrame SHALL be the APS command payload to be sent to the destination
     * @returns
     */
    sendZigbeeAPSTunnel(nwkDest16: number, destination64: bigint, tApsCmdFrame: Buffer): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.7
     */
    processZigbeeAPSVerifyKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): Promise<number>;
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
    sendZigbeeAPSVerifyKey(nwkDest16: number, keyType: number, source64: bigint, hash: Buffer): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.8
     */
    processZigbeeAPSConfirmKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * 05-3474-R #4.4.11.8
     *
     * @param nwkDest16
     * @param status 1-byte status code indicating the result of the operation. See Table 2.27
     * @param keyType the type of key being verified
     * @param destination64 SHALL be the 64-bit extended address of the source device of the Verify-Key message
     * @returns
     */
    sendZigbeeAPSConfirmKey(nwkDest16: number, status: number, keyType: number, destination64: bigint): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.9
     */
    processZigbeeAPSRelayMessageDownstream(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * 05-3474-R #4.4.11.10
     */
    processZigbeeAPSRelayMessageUpstream(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    getOrGenerateAPPLinkKey(_device16: number, _partner64: bigint): Buffer;
    isNetworkUp(): boolean;
    /**
     * Set the Spinel properties required to start a 802.15.4 MAC network.
     *
     * Should be called after `start`.
     */
    formNetwork(): Promise<void>;
    /**
     * Remove the current state file and clear all related tables.
     *
     * Will throw if state already loaded (should be called before `start`).
     */
    resetNetwork(): Promise<void>;
    registerTimers(): Promise<void>;
    savePeriodicState(): Promise<void>;
    sendPeriodicZigbeeNWKLinkStatus(): Promise<void>;
    sendPeriodicManyToOneRouteRequest(): Promise<void>;
    /**
     * @param duration The length of time in seconds during which the trust center will allow joins.
     * The value 0x00 and 0xff indicate that permission is disabled or enabled, respectively, without a specified time limit.
     * 0xff is clamped to 0xfe for security reasons
     * @param macAssociationPermit If true, also allow association on coordinator itself. Ignored if duration 0.
     */
    allowJoins(duration: number, macAssociationPermit: boolean): void;
    /**
     * Revert allowing joins (keeps `allowRejoinsWithWellKnownKey=true`).
     */
    disallowJoins(): void;
    /**
     * Put the coordinator in Green Power commissioning mode.
     * @param commissioningWindow Defaults to 180 if unspecified. Max 254. 0 means exit.
     */
    gpEnterCommissioningMode(commissioningWindow?: number): void;
    gpExitCommissioningMode(): void;
    /**
     * 05-3474-23 #3.6.1.10
     */
    assignNetworkAddress(): number;
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
    associate(source16: number | undefined, source64: bigint | undefined, initialJoin: boolean, capabilities: MACCapabilities | undefined, neighbor: boolean, denyOverride?: boolean, allowOverride?: boolean): Promise<[status: MACAssociationStatus | number, newAddress16: number]>;
    disassociate(source16: number | undefined, source64: bigint | undefined): Promise<void>;
    /**
     * Check if a source route entry for the given address is already present.
     * If `existingEntries` not given and address16 doesn't have any entries, always returns false.
     * @param address16 The network address to check for
     * @param newEntry The entry to check
     * @param existingEntries If given, skip the retrieval from `sourceRouteTable` and use these entries to check against instead
     * @returns
     */
    hasSourceRoute(address16: number, newEntry: SourceRouteTableEntry, existingEntries?: SourceRouteTableEntry[]): boolean;
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
    findBestSourceRoute(destination16: number | undefined, destination64: bigint | undefined): [relayIndex: number | undefined, relayAddresses: number[] | undefined, pathCost: number | undefined];
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
     * @param signalStrength
     * @param signalQuality
     * @returns
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
     * ZDO response to LQI_TABLE_REQUEST for coordinator
     * @see 05-3474-23 #2.4.4.3.2
     * @param startIndex
     * @returns
     */
    getLQITableResponse(startIndex: number): Buffer;
    /**
     * ZDO response to ROUTING_TABLE_REQUEST for coordinator
     * NOTE: Only outputs the best source route for each entry in the table (clipped to max 255 entries).
     * @see 05-3474-23 #2.4.4.3.3
     * @param startIndex
     * @returns
     */
    getRoutingTableResponse(startIndex: number): Buffer;
    getCoordinatorZDOResponse(clusterId: number, requestData: Buffer): Buffer | undefined;
    /**
     * Check if ZDO request is intended for coordinator.
     * @param clusterId
     * @param nwkDst16
     * @param nwkDst64
     * @param data
     * @returns
     */
    private isZDORequestForCoordinator;
    /**
     * Respond to ZDO requests aimed at coordinator if needed.
     * @param data
     * @param clusterId
     * @param macDest16
     * @param nwkDest16
     * @param nwkDest64
     */
    private respondToCoordinatorZDORequest;
    /**
     * Format is:
     * - network data: ${SaveConsts.NETWORK_STATE_SIZE} bytes
     * - device count: 2 bytes
     * - device data: ${SaveConsts.DEVICE_STATE_SIZE} bytes * ${device count}
     */
    saveState(): Promise<void>;
    /**
     * Load state from file system if exists, else save "initial" state.
     * Afterwards, various keys are pre-hashed and descriptors pre-encoded.
     */
    loadState(): Promise<void>;
    /**
     * Read the current network state in the save file, if any present.
     * @param readState Optional. For use in places where the state file has already been read.
     * @returns
     */
    readNetworkState(readState: Buffer): Promise<NetworkParameters>;
    readNetworkState(): Promise<NetworkParameters | undefined>;
    /**
     * Set the manufacturer code in the pre-encoded node descriptor
     * @param code
     */
    setManufacturerCode(code: number): void;
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
    sendZDO(payload: Buffer, nwkDest16: number, nwkDest64: bigint | undefined, clusterId: number): Promise<[number, number]>;
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
    sendUnicast(payload: Buffer, profileId: number, clusterId: number, dest16: number, dest64: bigint | undefined, destEp: number, sourceEp: number): Promise<number>;
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
    sendGroupcast(payload: Buffer, profileId: number, clusterId: number, group: number, sourceEp: number): Promise<number>;
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
    sendBroadcast(payload: Buffer, profileId: number, clusterId: number, dest16: number, destEp: number, sourceEp: number): Promise<number>;
}
export {};
