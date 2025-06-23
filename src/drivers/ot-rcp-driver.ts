import EventEmitter from "node:events";
import { existsSync, mkdirSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { SpinelCommandId } from "../spinel/commands.js";
import { decodeHdlcFrame, HDLC_TX_CHUNK_SIZE, type HdlcFrame, HdlcReservedByte } from "../spinel/hdlc.js";
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
import {
    decodeMACCapabilities,
    decodeMACFrameControl,
    decodeMACHeader,
    decodeMACPayload,
    encodeMACCapabilities,
    encodeMACFrame,
    encodeMACFrameZigbee,
    encodeMACZigbeeBeacon,
    MACAssociationStatus,
    type MACCapabilities,
    MACCommandId,
    MACFrameAddressMode,
    MACFrameType,
    MACFrameVersion,
    type MACHeader,
    ZigbeeMACConsts,
} from "../zigbee/mac.js";
import {
    convertMaskToChannels,
    makeKeyedHash,
    makeKeyedHashByType,
    registerDefaultHashedKeys,
    ZigbeeConsts,
    ZigbeeKeyType,
    type ZigbeeSecurityHeader,
    ZigbeeSecurityLevel,
} from "../zigbee/zigbee.js";
import {
    decodeZigbeeAPSFrameControl,
    decodeZigbeeAPSHeader,
    decodeZigbeeAPSPayload,
    encodeZigbeeAPSFrame,
    ZigbeeAPSCommandId,
    ZigbeeAPSConsts,
    ZigbeeAPSDeliveryMode,
    ZigbeeAPSFrameType,
    type ZigbeeAPSHeader,
    type ZigbeeAPSPayload,
} from "../zigbee/zigbee-aps.js";
import {
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    encodeZigbeeNWKFrame,
    ZigbeeNWKCommandId,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    type ZigbeeNWKHeader,
    type ZigbeeNWKLinkStatus,
    ZigbeeNWKManyToOne,
    ZigbeeNWKRouteDiscovery,
    ZigbeeNWKStatus,
} from "../zigbee/zigbee-nwk.js";
import {
    decodeZigbeeNWKGPFrameControl,
    decodeZigbeeNWKGPHeader,
    decodeZigbeeNWKGPPayload,
    ZigbeeNWKGPCommandId,
    ZigbeeNWKGPFrameType,
    type ZigbeeNWKGPHeader,
} from "../zigbee/zigbee-nwkgp.js";
import { encodeCoordinatorDescriptors } from "./descriptors.js";
import { OTRCPParser } from "./ot-rcp-parser.js";
import { OTRCPWriter } from "./ot-rcp-writer.js";

const NS = "ot-rcp-driver";

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

const enum SaveConsts {
    NETWORK_DATA_SIZE = 1024,
    DEVICE_DATA_SIZE = 512,
    FRAME_COUNTER_JUMP_OFFSET = 1024,
}

export enum InstallCodePolicy {
    /** Do not support Install Codes */
    NOT_SUPPORTED = 0x00,
    /** Support but do not require use of Install Codes or preset passphrases */
    NOT_REQUIRED = 0x01,
    /** Require the use of Install Codes by joining devices or preset Passphrases */
    REQUIRED = 0x02,
}

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

export type NetworkParameters = {
    eui64: bigint;
    panId: number;
    extendedPANId: bigint;
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
    // address16: number; // mapped
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
    rxOnWhenIdle: boolean; // TODO: in `capabilities`?
    capabilities: number; // TODO: MACCapabilityFlags or parse only "when-needed" and keep as number?
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
    linkKey: Buffer; // not backed up in R23
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
    keyNegotiationState: number; // not backed up
    /**
     * A value that is used by both sides during dynamic key negotiation.
     * An unset value means this key-pair entry was not dynamically negotiated.
     * Any other value indicates the entry was dynamically negotiated.
     */
    passphrase?: Buffer; // if supported
    /**
     * The timeout, in seconds, for the specified key.
     * When this timeout expires, the key SHALL be marked EXPIRED_KEY in the KeyAttributes and the LinkKey value SHALL not be used for encryption of messages.
     * A value of 0xFFFF for the Timeout mean the key never expires.
     *
     * default: 0xffff
     */
    timeout: number; // not backed up
    /**
     * This indicates whether the particular KeyPair passphrase MAY be updated for the device.
     * A passphrase update is normally only allowed shortly after joining.
     * See section 4.7.2.1.
     *
     * default: true
     */
    passphraseUpdateAllowed: boolean; // not backed up
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

// const SPINEL_FRAME_MAX_SIZE = 1300;
// const SPINEL_FRAME_MAX_COMMAND_HEADER_SIZE = 4;
// const SPINEL_FRAME_MAX_COMMAND_PAYLOAD_SIZE = SPINEL_FRAME_MAX_SIZE - SPINEL_FRAME_MAX_COMMAND_HEADER_SIZE;
// const SPINEL_ENCRYPTER_EXTRA_DATA_SIZE = 0;
// const SPINEL_FRAME_BUFFER_SIZE = SPINEL_FRAME_MAX_SIZE + SPINEL_ENCRYPTER_EXTRA_DATA_SIZE;

const CONFIG_TID_MASK = 0x0e;
const CONFIG_HIGHWATER_MARK = HDLC_TX_CHUNK_SIZE * 4;
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

export class OTRCPDriver extends EventEmitter<AdapterDriverEventMap> {
    public readonly writer: OTRCPWriter;
    public readonly parser: OTRCPParser;
    public readonly streamRawConfig: StreamRawConfig;
    public readonly savePath: string;
    #emitMACFrames: boolean;

    #protocolVersionMajor = 0;
    #protocolVersionMinor = 0;
    #ncpVersion = "";
    #interfaceType = 0;
    #rcpAPIVersion = 0;
    #rcpMinHostAPIVersion = 0;

    /** The minimum observed RSSI */
    public rssiMin = -100;
    /** The maximum observed RSSI */
    public rssiMax = -25;

    /** The minimum observed LQI */
    public lqiMin = 15;
    /** The maximum observed LQI */
    public lqiMax = 250;

    /**
     * Transaction ID used in Spinel frame
     *
     * NOTE: 0 is used for "no response expected/needed" (e.g. unsolicited update commands from NCP to host)
     */
    #spinelTID: number;
    /** Sequence number used in outgoing MAC frames */
    #macSeqNum: number;
    /** Sequence number used in outgoing NWK frames */
    #nwkSeqNum: number;
    /** Counter used in outgoing APS frames */
    #apsCounter: number;
    /** Sequence number used in outgoing ZDO frames */
    #zdoSeqNum: number;
    /**
     * 8-bit sequence number for route requests. Incremented by 1 every time the NWK layer on a particular device issues a route request.
     */
    #routeRequestId: number;

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

    #stateLoaded: boolean;
    #networkUp: boolean;

    #saveStateTimeout: NodeJS.Timeout | undefined;
    #pendingChangeChannel: NodeJS.Timeout | undefined;
    #nwkLinkStatusTimeout: NodeJS.Timeout | undefined;
    #manyToOneRouteRequestTimeout: NodeJS.Timeout | undefined;

    /** Associations pending DATA_RQ from device. Mapping by network64 */
    public readonly pendingAssociations: Map<bigint, { sendResp: () => Promise<void>; timestamp: number }>;
    /** Indirect transmission for devices with rxOnWhenIdle set to false. Mapping by network64 */
    public readonly indirectTransmissions: Map<bigint, { sendFrame: () => Promise<boolean>; timestamp: number }[]>;
    /** Count of MAC NO_ACK reported by Spinel for each device (only present if any). Mapping by network16 */
    public readonly macNoACKs: Map<number, number>;
    /** Count of route failures reported by the network for each device (only present if any). Mapping by network16 */
    public readonly routeFailures: Map<number, number>;

    //---- Trust Center (see 05-3474-R #4.7.1)

    readonly #trustCenterPolicies: TrustCenterPolicies;
    #macAssociationPermit: boolean;
    #allowJoinTimeout: NodeJS.Timeout | undefined;

    //----- Green Power (see 14-0563-18)

    #gpCommissioningMode: boolean;
    #gpCommissioningWindowTimeout: NodeJS.Timeout | undefined;
    #gpLastMACSequenceNumber: number;
    #gpLastSecurityFrameCounter: number;

    //---- NWK

    public netParams: NetworkParameters;
    /** pre-computed hash of default TC link key for VERIFY_KEY. set by `loadState` */
    #tcVerifyKeyHash!: Buffer;
    /** Time of last many-to-one route request */
    #lastMTORRTime: number;
    /** Master table of all known devices on the network. mapping by network64 */
    public readonly deviceTable: Map<bigint, DeviceTableEntry>;
    /** Lookup synced with deviceTable, maps network address to IEEE address */
    public readonly address16ToAddress64: Map<number, bigint>;
    /** mapping by network16 */
    public readonly sourceRouteTable: Map<number, SourceRouteTableEntry[]>;
    // TODO: possibility of a route/sourceRoute blacklist?

    //---- APS

    /** mapping by network16 */
    // public readonly apsDeviceKeyPairSet: Map<number, APSDeviceKeyPairSet>;
    /** mapping by network16 */
    // public readonly apsBindingTable: Map<number, APSBindingTable>;

    //---- Attribute

    /** Several attributes are set by `loadState` */
    public readonly configAttributes: ConfigurationAttributes;

    constructor(streamRawConfig: StreamRawConfig, netParams: NetworkParameters, saveDir: string, emitMACFrames = false) {
        super();

        if (!existsSync(saveDir)) {
            mkdirSync(saveDir);
        }

        this.savePath = join(saveDir, "zoh.save");
        this.#emitMACFrames = emitMACFrames;
        this.streamRawConfig = streamRawConfig;
        this.writer = new OTRCPWriter({ highWaterMark: CONFIG_HIGHWATER_MARK });
        this.parser = new OTRCPParser({ readableHighWaterMark: CONFIG_HIGHWATER_MARK });

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

    private nextMACSeqNum(): number {
        this.#macSeqNum = (this.#macSeqNum + 1) & 0xff;

        return this.#macSeqNum;
    }

    private nextNWKSeqNum(): number {
        this.#nwkSeqNum = (this.#nwkSeqNum + 1) & 0xff;

        return this.#nwkSeqNum;
    }

    private nextAPSCounter(): number {
        this.#apsCounter = (this.#apsCounter + 1) & 0xff;

        return this.#apsCounter;
    }

    private nextZDOSeqNum(): number {
        this.#zdoSeqNum = (this.#zdoSeqNum + 1) & 0xff;

        return this.#zdoSeqNum;
    }

    private nextTCKeyFrameCounter(): number {
        this.netParams.tcKeyFrameCounter = (this.netParams.tcKeyFrameCounter + 1) & 0xffffffff;

        return this.netParams.tcKeyFrameCounter;
    }

    private nextNWKKeyFrameCounter(): number {
        this.netParams.networkKeyFrameCounter = (this.netParams.networkKeyFrameCounter + 1) & 0xffffffff;

        return this.netParams.networkKeyFrameCounter;
    }

    private nextRouteRequestId(): number {
        this.#routeRequestId = (this.#routeRequestId + 1) & 0xff;

        return this.#routeRequestId;
    }

    private decrementRadius(radius: number): number {
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
    public async start(): Promise<void> {
        logger.info("======== Driver starting ========", NS);
        await this.loadState();

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

            waiter.reject(new Error("Driver stopping", { cause: SpinelStatus.INVALID_STATE }));
        }

        this.#tidWaiters.clear();

        if (networkWasUp) {
            // TODO: proper spinel/radio shutdown?
            await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, false));
            await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RAW_STREAM_ENABLED, false));
        }

        await this.saveState();

        logger.info("======== Driver stopped ========", NS);
    }

    public async waitForReset(): Promise<void> {
        await new Promise<SpinelFrame>((resolve, reject) => {
            this.#resetWaiter = {
                timer: setTimeout(reject.bind(this, new Error("Reset timeout after 5000ms", { cause: SpinelStatus.RESPONSE_TIMEOUT })), 5000),
                resolve,
            };
        });
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

    // #region HDLC/Spinel

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

    /**
     * Logic optimizes code paths to try to avoid more parsing when frames will eventually get ignored by detecting as early as possible.
     */
    public async onStreamRawFrame(payload: Buffer, metadata: SpinelStreamRawMetadata | undefined): Promise<void> {
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
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(payload, 0);

            // TODO: process BEACON for PAN ID conflict detection?
            if (macFCF.frameType !== MACFrameType.CMD && macFCF.frameType !== MACFrameType.DATA) {
                logger.debug(() => `<-~- MAC Ignoring frame with type not CMD/DATA (${macFCF.frameType})`, NS);
                return;
            }

            const [macHeader, macHOutOffset] = decodeMACHeader(payload, macFCFOutOffset, macFCF);

            if (metadata) {
                logger.debug(
                    () => `<--- SPINEL STREAM_RAW METADATA[rssi=${metadata.rssi} noiseFloor=${metadata.noiseFloor} flags=${metadata.flags}]`,
                    NS,
                );
            }

            const macPayload = decodeMACPayload(payload, macHOutOffset, macFCF, macHeader);

            if (macFCF.frameType === MACFrameType.CMD) {
                await this.processMACCommand(macPayload, macHeader);

                // done
                return;
            }

            if (macHeader.destinationPANId !== ZigbeeMACConsts.BCAST_PAN && macHeader.destinationPANId !== this.netParams.panId) {
                logger.debug(() => `<-~- MAC Ignoring frame with mismatching PAN Id ${macHeader.destinationPANId}`, NS);
                return;
            }

            if (
                macFCF.destAddrMode === MACFrameAddressMode.SHORT &&
                macHeader.destination16! !== ZigbeeMACConsts.BCAST_ADDR &&
                macHeader.destination16! !== ZigbeeConsts.COORDINATOR_ADDRESS
            ) {
                logger.debug(() => `<-~- MAC Ignoring frame intended for device ${macHeader.destination16}`, NS);
                return;
            }

            if (macPayload.byteLength > 0) {
                const protocolVersion = (macPayload.readUInt8(0) & ZigbeeNWKConsts.FCF_VERSION) >> 2;

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

                        if (this.checkZigbeeNWKGPDuplicate(macHeader, nwkGPHeader)) {
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
                            this.netParams.networkKey,
                            macHeader.source64,
                            nwkGPFCF,
                            nwkGPHeader,
                        );

                        this.processZigbeeNWKGPFrame(nwkGPPayload, macHeader, nwkGPHeader, this.computeLQA(metadata?.rssi ?? this.rssiMin));
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

                    const sourceLQA = this.computeDeviceLQA(nwkHeader.source16, nwkHeader.source64, metadata?.rssi ?? this.rssiMin);
                    const nwkPayload = decodeZigbeeNWKPayload(
                        macPayload,
                        nwkHOutOffset,
                        undefined, // use pre-hashed this.netParams.networkKey,
                        /* nwkHeader.frameControl.extendedSource ? nwkHeader.source64 : this.address16ToAddress64.get(nwkHeader.source16!) */
                        nwkHeader.source64 ?? this.address16ToAddress64.get(nwkHeader.source16!),
                        nwkFCF,
                        nwkHeader,
                    );

                    if (nwkFCF.frameType === ZigbeeNWKFrameType.DATA) {
                        const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
                        const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);

                        if (apsHeader.frameControl.ackRequest && nwkHeader.source16 !== ZigbeeConsts.COORDINATOR_ADDRESS) {
                            await this.sendZigbeeAPSACK(macHeader, nwkHeader, apsHeader);
                        }

                        const apsPayload = decodeZigbeeAPSPayload(
                            nwkPayload,
                            apsHOutOffset,
                            undefined, // use pre-hashed this.netParams.tcKey,
                            /* nwkHeader.frameControl.extendedSource ? nwkHeader.source64 : this.address16ToAddress64.get(nwkHeader.source16!) */
                            nwkHeader.source64 ?? this.address16ToAddress64.get(nwkHeader.source16!),
                            apsFCF,
                            apsHeader,
                        );

                        await this.onZigbeeAPSFrame(apsPayload, macHeader, nwkHeader, apsHeader, sourceLQA);
                    } else if (nwkFCF.frameType === ZigbeeNWKFrameType.CMD) {
                        await this.processZigbeeNWKCommand(nwkPayload, macHeader, nwkHeader);
                    } else if (nwkFCF.frameType === ZigbeeNWKFrameType.INTERPAN) {
                        throw new Error("INTERPAN not supported", { cause: SpinelStatus.UNIMPLEMENTED });
                    }
                }
            }
        } catch (error) {
            // TODO log or throw depending on error
            logger.error((error as Error).stack!, NS);
        }
    }

    public sendFrame(hdlcFrame: HdlcFrame): void {
        // only send what is recorded as "data" (by length)
        this.writer.writeBuffer(hdlcFrame.data.subarray(0, hdlcFrame.length));
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

        this.sendFrame(hdlcFrame);

        if (waitForResponse) {
            return await this.waitForTID(spinelFrame.header.tid, timeout);
        }
    }

    public async waitForTID(tid: number, timeout: number): Promise<SpinelFrame> {
        return await new Promise<SpinelFrame>((resolve, reject) => {
            // TODO reject if tid already present? (shouldn't happen as long as concurrency is fine...)
            this.#tidWaiters.set(tid, {
                timer: setTimeout(
                    reject.bind(this, new Error(`-x-> SPINEL[tid=${tid}] Timeout after ${timeout}ms`, { cause: SpinelStatus.RESPONSE_TIMEOUT })),
                    timeout,
                ),
                resolve,
                reject,
            });
        });
    }

    public async getProperty(propertyId: SpinelPropertyId, timeout = 10000): ReturnType<typeof this.sendCommand> {
        const [data] = writePropertyId(propertyId, 0);

        return await this.sendCommand(SpinelCommandId.PROP_VALUE_GET, data, true, timeout);
    }

    public async setProperty(payload: Buffer, timeout = 10000): Promise<void> {
        // LAST_STATUS checked in `onFrame`
        await this.sendCommand(SpinelCommandId.PROP_VALUE_SET, payload, true, timeout);
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
        if (this.#stateLoaded || this.#networkUp) {
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
        if (this.#stateLoaded || this.#networkUp) {
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
            this.emit("macFrame", payload, metadata?.rssi);
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

    // #region MAC Layer

    /**
     * Send 802.15.4 MAC frame without checking for need to use indirect transmission.
     * @param seqNum
     * @param payload
     * @param dest16
     * @param dest64
     * @returns True if success sending
     */
    public async sendMACFrameDirect(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean> {
        if (dest16 === undefined && dest64 !== undefined) {
            dest16 = this.deviceTable.get(dest64)?.address16;
        }

        try {
            logger.debug(() => `===> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}]`, NS);

            await this.setProperty(writePropertyStreamRaw(payload, this.streamRawConfig));

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
        } catch (error) {
            logger.debug(() => `=x=> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}] ${(error as Error).message}`, NS);

            if ((error as Error).cause === SpinelStatus.NO_ACK && dest16 !== undefined) {
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
    public async sendMACFrame(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean | undefined> {
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

                    logger.debug(
                        () => `=|=> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}] set for indirect transmission (count=${addrTXs.length})`,
                        NS,
                    );

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
    public async sendMACCommand(
        cmdId: MACCommandId,
        dest16: number | undefined,
        dest64: bigint | undefined,
        extSource: boolean,
        payload: Buffer,
    ): Promise<boolean> {
        const macSeqNum = this.nextMACSeqNum();

        logger.debug(() => `===> MAC CMD[seqNum=${macSeqNum} cmdId=${cmdId} dst=${dest16}:${dest64} extSrc=${extSource}]`, NS);

        const macFrame = encodeMACFrame(
            {
                frameControl: {
                    frameType: MACFrameType.CMD,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: dest16 !== ZigbeeMACConsts.BCAST_ADDR,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: dest64 !== undefined ? MACFrameAddressMode.EXT : MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: extSource ? MACFrameAddressMode.EXT : MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macSeqNum,
                destinationPANId: this.netParams.panId,
                destination16: dest16, // depends on `destAddrMode` above
                destination64: dest64, // depends on `destAddrMode` above
                // sourcePANId: undefined, // panIdCompression=true
                source16: ZigbeeConsts.COORDINATOR_ADDRESS, // depends on `sourceAddrMode` above
                source64: this.netParams.eui64, // depends on `sourceAddrMode` above
                commandId: cmdId,
                fcs: 0,
            },
            payload,
        );

        return await this.sendMACFrameDirect(macSeqNum, macFrame, dest16, dest64);
    }

    /**
     * Process 802.15.4 MAC command.
     * @param data
     * @param macHeader
     * @returns
     */
    public async processMACCommand(data: Buffer, macHeader: MACHeader): Promise<void> {
        let offset = 0;

        switch (macHeader.commandId!) {
            case MACCommandId.ASSOC_REQ: {
                offset = await this.processMACAssocReq(data, offset, macHeader);
                break;
            }
            case MACCommandId.ASSOC_RSP: {
                offset = this.processMACAssocRsp(data, offset, macHeader);
                break;
            }
            case MACCommandId.BEACON_REQ: {
                offset = await this.processMACBeaconReq(data, offset, macHeader);
                break;
            }
            case MACCommandId.DATA_RQ: {
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
                logger.error(`<=x= MAC CMD[cmdId=${macHeader.commandId} macSrc=${macHeader.source16}:${macHeader.source64}] Unsupported`, NS);
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
    public async processMACAssocReq(data: Buffer, offset: number, macHeader: MACHeader): Promise<number> {
        const capabilities = data.readUInt8(offset);
        offset += 1;

        logger.debug(() => `<=== MAC ASSOC_REQ[macSrc=${macHeader.source16}:${macHeader.source64} cap=${capabilities}]`, NS);

        if (macHeader.source64 === undefined) {
            logger.debug(() => `<=x= MAC ASSOC_REQ[macSrc=${macHeader.source16}:${macHeader.source64} cap=${capabilities}] Invalid source64`, NS);
        } else {
            const address16 = this.deviceTable.get(macHeader.source64)?.address16;
            const decodedCap = decodeMACCapabilities(capabilities);
            const [status, newAddress16] = await this.associate(
                address16,
                macHeader.source64,
                address16 === undefined /* initial join if unknown device, else rejoin */,
                decodedCap,
                true /* neighbor */,
            );

            this.pendingAssociations.set(macHeader.source64, {
                sendResp: async () => {
                    await this.sendMACAssocRsp(macHeader.source64!, newAddress16, status);

                    if (status === MACAssociationStatus.SUCCESS) {
                        await this.sendZigbeeAPSTransportKeyNWK(
                            newAddress16,
                            this.netParams.networkKey,
                            this.netParams.networkKeySequenceNumber,
                            macHeader.source64!,
                        );
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
    public processMACAssocRsp(data: Buffer, offset: number, macHeader: MACHeader): number {
        const address = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;

        logger.debug(
            () => `<=== MAC ASSOC_RSP[macSrc=${macHeader.source16}:${macHeader.source64} addr16=${address} status=${MACAssociationStatus[status]}]`,
            NS,
        );

        return offset;
    }

    /**
     * Send 802.15.4 MAC association response
     * @param dest64
     * @param newAddress16
     * @param status
     * @returns
     */
    public async sendMACAssocRsp(dest64: bigint, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean> {
        logger.debug(() => `===> MAC ASSOC_RSP[dst64=${dest64} newAddr16=${newAddress16} status=${status}]`, NS);

        const finalPayload = Buffer.alloc(3);
        let offset = 0;
        finalPayload.writeUInt16LE(newAddress16, offset);
        offset += 2;
        finalPayload.writeUInt8(status, offset);
        offset += 1;

        return await this.sendMACCommand(
            MACCommandId.ASSOC_RSP,
            undefined, // dest16
            dest64, // dest64
            true, // sourceExt
            finalPayload,
        );
    }

    /**
     * Process 802.15.4 MAC beacon request.
     * @param _data
     * @param offset
     * @param _macHeader
     * @returns
     */
    public async processMACBeaconReq(_data: Buffer, offset: number, _macHeader: MACHeader): Promise<number> {
        logger.debug(() => "<=== MAC BEACON_REQ[]", NS);

        const macSeqNum = this.nextMACSeqNum();
        const macFrame = encodeMACFrame(
            {
                frameControl: {
                    frameType: MACFrameType.BEACON,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: false,
                    panIdCompression: false,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.NONE,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macSeqNum,
                sourcePANId: this.netParams.panId,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
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
            },
            encodeMACZigbeeBeacon({
                protocolId: ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_ID,
                profile: 0x2, // ZigBee PRO
                version: ZigbeeNWKConsts.VERSION_2007,
                routerCapacity: true,
                deviceDepth: 0, // coordinator
                endDeviceCapacity: true,
                extendedPANId: this.netParams.extendedPANId,
                txOffset: 0xffffff, // XXX: value from sniffed frames
                updateId: this.netParams.nwkUpdateId, // XXX: correct?
            }),
        );

        logger.debug(() => `===> MAC BEACON[seqNum=${macSeqNum}]`, NS);

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
    public async processMACDataReq(_data: Buffer, offset: number, macHeader: MACHeader): Promise<number> {
        logger.debug(() => `<=== MAC DATA_RQ[macSrc=${macHeader.source16}:${macHeader.source64}]`, NS);

        let address64 = macHeader.source64;

        if (address64 === undefined && macHeader.source16 !== undefined) {
            address64 = this.address16ToAddress64.get(macHeader.source16);
        }

        if (address64 !== undefined) {
            const pendingAssoc = this.pendingAssociations.get(address64);

            if (pendingAssoc) {
                if (pendingAssoc.timestamp + ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT > Date.now()) {
                    await pendingAssoc.sendResp();
                }

                // always delete, ensures no stale
                this.pendingAssociations.delete(address64);
            } else {
                const addrTXs = this.indirectTransmissions.get(address64);

                if (addrTXs !== undefined) {
                    let tx = addrTXs.shift();

                    // deal with expired tx by looking for first that isn't
                    do {
                        if (tx !== undefined && tx.timestamp + ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT > Date.now()) {
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
    public async sendZigbeeNWKCommand(
        cmdId: ZigbeeNWKCommandId,
        finalPayload: Buffer,
        nwkSecurity: boolean,
        nwkSource16: number,
        nwkDest16: number,
        nwkDest64: bigint | undefined,
        nwkRadius: number,
    ): Promise<boolean> {
        let nwkSecurityHeader: ZigbeeSecurityHeader | undefined;

        if (nwkSecurity) {
            nwkSecurityHeader = {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.NWK,
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
        let relayIndex: number | undefined;
        let relayAddresses: number[] | undefined;

        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        } catch (error) {
            logger.error(
                `=x=> NWK CMD[seqNum=(${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64}] ${(error as Error).message}`,
                NS,
            );

            return false;
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;

        logger.debug(
            () =>
                `===> NWK CMD[seqNum=(${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} macDst16=${macDest16} nwkSrc16=${nwkSource16} nwkDst=${nwkDest16}:${nwkDest64} nwkRad=${nwkRadius}]`,
            NS,
        );

        const source64 = nwkSource16 === ZigbeeConsts.COORDINATOR_ADDRESS ? this.netParams.eui64 : this.address16ToAddress64.get(nwkSource16);
        const nwkFrame = encodeZigbeeNWKFrame(
            {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
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
            },
            finalPayload,
            nwkSecurityHeader,
            undefined, // use pre-hashed this.netParams.networkKey,
        );
        const macFrame = encodeMACFrameZigbee(
            {
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: Boolean(this.indirectTransmissions.get(nwkDest64 ?? this.address16ToAddress64.get(nwkDest16)!)?.length),
                    ackRequest: macDest16 !== ZigbeeMACConsts.BCAST_ADDR,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macSeqNum,
                destinationPANId: this.netParams.panId,
                destination16: macDest16,
                // sourcePANId: undefined, // panIdCompression=true
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                fcs: 0,
            },
            nwkFrame,
        );

        const result = await this.sendMACFrame(macSeqNum, macFrame, macDest16, undefined);

        return result !== false;
    }

    public async processZigbeeNWKCommand(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<void> {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;

        switch (cmdId) {
            case ZigbeeNWKCommandId.ROUTE_REQ: {
                offset = await this.processZigbeeNWKRouteReq(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.ROUTE_REPLY: {
                offset = this.processZigbeeNWKRouteReply(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.NWK_STATUS: {
                offset = this.processZigbeeNWKStatus(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.LEAVE: {
                offset = await this.processZigbeeNWKLeave(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.ROUTE_RECORD: {
                offset = this.processZigbeeNWKRouteRecord(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.REJOIN_REQ: {
                offset = await this.processZigbeeNWKRejoinReq(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.REJOIN_RESP: {
                offset = this.processZigbeeNWKRejoinResp(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.LINK_STATUS: {
                offset = this.processZigbeeNWKLinkStatus(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.NWK_REPORT: {
                offset = this.processZigbeeNWKReport(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.NWK_UPDATE: {
                offset = this.processZigbeeNWKUpdate(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.ED_TIMEOUT_REQUEST: {
                offset = await this.processZigbeeNWKEdTimeoutRequest(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE: {
                offset = this.processZigbeeNWKEdTimeoutResponse(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.LINK_PWR_DELTA: {
                offset = this.processZigbeeNWKLinkPwrDelta(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.COMMISSIONING_REQUEST: {
                offset = await this.processZigbeeNWKCommissioningRequest(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.COMMISSIONING_RESPONSE: {
                offset = this.processZigbeeNWKCommissioningResponse(data, offset, macHeader, nwkHeader);
                break;
            }
            default: {
                logger.error(
                    `<=x= NWK CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}] Unsupported`,
                    NS,
                );
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
    public async processZigbeeNWKRouteReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        const options = data.readUInt8(offset);
        offset += 1;
        const manyToOne = (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK) >> 3; // ZigbeeNWKManyToOne
        const id = data.readUInt8(offset);
        offset += 1;
        const destination16 = data.readUInt16LE(offset);
        offset += 2;
        const pathCost = data.readUInt8(offset);
        offset += 1;
        let destination64: bigint | undefined;

        if (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT) {
            destination64 = data.readBigUInt64LE(offset);
            offset += 8;
        }

        logger.debug(
            () =>
                `<=== NWK ROUTE_REQ[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} id=${id} dst=${destination16}:${destination64} pCost=${pathCost} mto=${manyToOne}]`,
            NS,
        );

        if (destination16 < ZigbeeConsts.BCAST_MIN) {
            await this.sendZigbeeNWKRouteReply(
                macHeader.destination16!,
                nwkHeader.radius!,
                id,
                nwkHeader.source16!,
                destination16,
                nwkHeader.source64 ?? this.address16ToAddress64.get(nwkHeader.source16!),
                destination64,
            );
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
    public async sendZigbeeNWKRouteReq(manyToOne: ZigbeeNWKManyToOne, destination16: number, destination64?: bigint): Promise<boolean> {
        logger.debug(() => `===> NWK ROUTE_REQ[mto=${manyToOne} dst=${destination16}:${destination64}]`, NS);
        const hasDestination64 = destination64 !== undefined;
        const options =
            (((manyToOne ? 1 : 0) << 3) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK) |
            (((hasDestination64 ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT);
        const finalPayload = Buffer.alloc(1 + 1 + 1 + 2 + 1 + (hasDestination64 ? 8 : 0));
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeNWKCommandId.ROUTE_REQ, offset);
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
            finalPayload.writeBigUInt64LE(destination64!, offset);
            offset += 8;
        }

        return await this.sendZigbeeNWKCommand(
            ZigbeeNWKCommandId.ROUTE_REQ,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            ZigbeeConsts.BCAST_DEFAULT, // nwkDest16
            undefined, // nwkDest64
            CONFIG_NWK_CONCENTRATOR_RADIUS, // nwkRadius
        );
    }

    /**
     * 05-3474-R #3.4.2
     */
    public processZigbeeNWKRouteReply(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
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
        let originator64: bigint | undefined;
        let responder64: bigint | undefined;

        if (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT) {
            originator64 = data.readBigUInt64LE(offset);
            offset += 8;
        }

        if (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT) {
            responder64 = data.readBigUInt64LE(offset);
            offset += 8;
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);

        logger.debug(
            () =>
                `<=== NWK ROUTE_REPLY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} id=${id} orig=${originator16}:${originator64} rsp=${responder16}:${responder64} pCost=${pathCost}]`,
            NS,
        );
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
    public async sendZigbeeNWKRouteReply(
        requestDest1stHop16: number,
        requestRadius: number,
        requestId: number,
        originator16: number,
        responder16: number,
        originator64?: bigint,
        responder64?: bigint,
    ): Promise<boolean> {
        logger.debug(
            () =>
                `===> NWK ROUTE_REPLY[reqDst1stHop16=${requestDest1stHop16} reqRad=${requestRadius} reqId=${requestId} orig=${originator16}:${originator64} rsp=${responder16}:${responder64}]`,
            NS,
        );
        const hasOriginator64 = originator64 !== undefined;
        const hasResponder64 = responder64 !== undefined;
        const options =
            (((hasOriginator64 ? 1 : 0) << 4) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT) |
            (((hasResponder64 ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT);
        const finalPayload = Buffer.alloc(1 + 1 + 1 + 2 + 2 + 1 + (hasOriginator64 ? 8 : 0) + (hasResponder64 ? 8 : 0));
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeNWKCommandId.ROUTE_REPLY, offset);
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
            finalPayload.writeBigUInt64LE(originator64!, offset);
            offset += 8;
        }

        if (hasResponder64) {
            finalPayload.writeBigUInt64LE(responder64!, offset);
            offset += 8;
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeNWKTLVs();

        return await this.sendZigbeeNWKCommand(
            ZigbeeNWKCommandId.ROUTE_REPLY,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestDest1stHop16, // nwkDest16
            this.address16ToAddress64.get(requestDest1stHop16), // nwkDest64 SHALL contain the 64-bit IEEE address of the first hop in the path back to the originator of the corresponding route request
            requestRadius, // nwkRadius
        );
    }

    /**
     * 05-3474-R #3.4.3
     */
    public processZigbeeNWKStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const status = data.readUInt8(offset);
        offset += 1;
        // target SHALL be present if, and only if, frame is being sent in response to a routing failure or a network address conflict
        let target16: number | undefined;

        if (
            status === ZigbeeNWKStatus.LEGACY_NO_ROUTE_AVAILABLE ||
            status === ZigbeeNWKStatus.LEGACY_LINK_FAILURE ||
            status === ZigbeeNWKStatus.LINK_FAILURE ||
            status === ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE ||
            status === ZigbeeNWKStatus.MANY_TO_ONE_ROUTE_FAILURE
        ) {
            // In case of a routing failure, it SHALL contain the destination address from the data frame that encountered the failure
            target16 = data.readUInt16LE(offset);
            offset += 2;

            let routeFailures = this.routeFailures.get(target16);

            if (routeFailures === undefined) {
                this.routeFailures.set(target16, 1);
            } else {
                routeFailures += 1;

                if (routeFailures >= CONFIG_NWK_CONCENTRATOR_ROUTE_FAILURE_THRESHOLD) {
                    for (const [addr16, entries] of this.sourceRouteTable) {
                        // entries using target as relay are no longer valid
                        const filteredEntries = entries.filter((entry) => !entry.relayAddresses.includes(target16!));

                        if (filteredEntries.length === 0) {
                            this.sourceRouteTable.delete(addr16);
                        } else if (filteredEntries.length !== entries.length) {
                            this.sourceRouteTable.set(addr16, filteredEntries);
                        }
                    }

                    this.sourceRouteTable.delete(target16!); // TODO: delete the source routes for the target itself?
                    this.routeFailures.set(target16, 0); // reset
                } else {
                    this.routeFailures.set(target16, routeFailures);
                }
            }
        } else if (status === ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            // In case of an address conflict, it SHALL contain the offending network address.
            target16 = data.readUInt16LE(offset);
            offset += 2;
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);

        logger.debug(
            () =>
                `<=== NWK NWK_STATUS[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${ZigbeeNWKStatus[status]} dst16=${target16}]`,
            NS,
        );
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
    public async sendZigbeeNWKStatus(requestSource16: number, status: ZigbeeNWKStatus, destination?: number): Promise<boolean> {
        logger.debug(() => `===> NWK NWK_STATUS[reqSrc16=${requestSource16} status=${status} dst16=${destination}]`, NS);
        let finalPayload: Buffer;

        if (status === ZigbeeNWKStatus.LINK_FAILURE || status === ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            finalPayload = Buffer.from([ZigbeeNWKCommandId.NWK_STATUS, status, destination! & 0xff, (destination! >> 8) & 0xff]);
        } else {
            finalPayload = Buffer.from([ZigbeeNWKCommandId.NWK_STATUS, status]);
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeNWKTLVs();

        return await this.sendZigbeeNWKCommand(
            ZigbeeNWKCommandId.NWK_STATUS,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestSource16, // nwkDest16
            this.address16ToAddress64.get(requestSource16), // nwkDest64
            CONFIG_NWK_MAX_HOPS, // nwkRadius
        );
    }

    /**
     * 05-3474-R #3.4.4
     */
    public async processZigbeeNWKLeave(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        const options = data.readUInt8(offset);
        offset += 1;
        const removeChildren = Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN);
        const request = Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST);
        const rejoin = Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN);

        logger.debug(
            () =>
                `<=== NWK LEAVE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} remChildren=${removeChildren} req=${request} rejoin=${rejoin}]`,
            NS,
        );

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
    public async sendZigbeeNWKLeave(destination16: number, rejoin: boolean): Promise<boolean> {
        logger.debug(() => `===> NWK LEAVE[dst16=${destination16} rejoin=${rejoin}]`, NS);

        const options =
            (0 & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN) |
            ((1 << 6) & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST) |
            (((rejoin ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN);
        const finalPayload = Buffer.from([ZigbeeNWKCommandId.LEAVE, options]);

        return await this.sendZigbeeNWKCommand(
            ZigbeeNWKCommandId.LEAVE,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            destination16, // nwkDest16
            this.address16ToAddress64.get(destination16), // nwkDest64
            1, // nwkRadius
        );
    }

    /**
     * 05-3474-R #3.4.5
     */
    public processZigbeeNWKRouteRecord(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const relayCount = data.readUInt8(offset);
        offset += 1;
        const relays: number[] = [];

        for (let i = 0; i < relayCount; i++) {
            const relay = data.readUInt16LE(offset);
            offset += 2;

            relays.push(relay);
        }

        logger.debug(
            () =>
                `<=== NWK ROUTE_RECORD[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} relays=${relays}]`,
            NS,
        );

        const source16 =
            nwkHeader.source16 === undefined
                ? nwkHeader.source64 === undefined
                    ? undefined
                    : this.deviceTable.get(nwkHeader.source64)?.address16
                : nwkHeader.source16;

        if (source16 !== undefined) {
            const entry: SourceRouteTableEntry = {
                relayAddresses: relays,
                pathCost: relayCount + 1, // TODO: ?
            };
            const entries = this.sourceRouteTable.get(source16);

            if (entries === undefined) {
                this.sourceRouteTable.set(source16, [entry]);
            } else if (!this.hasSourceRoute(source16, entry, entries)) {
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
    public async processZigbeeNWKRejoinReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        const capabilities = data.readUInt8(offset);
        offset += 1;

        const decodedCap = decodeMACCapabilities(capabilities);

        logger.debug(
            () =>
                `<=== NWK REJOIN_REQ[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} cap=${capabilities}]`,
            NS,
        );

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
            } else {
                const device = this.deviceTable.get(source64);

                // XXX: Unsecured Packets at the network layer claiming to be from existing neighbors (coordinators, routers or end devices) must not rewrite legitimate data in the nwkNeighborTable.
                //      if apsTrustCenterAddress is all FF (distributed) / all 00 (pre-TRANSPORT_KEY), reject with PAN_ACCESS_DENIED
                if (!device?.authorized) {
                    // device unknown or unauthorized
                    deny = true;
                }
            }
        }

        const [status, newAddress16] = await this.associate(
            nwkHeader.source16!,
            nwkHeader.source64,
            false /* rejoin */,
            decodedCap,
            macHeader.source16 === nwkHeader.source16,
            deny,
        );

        await this.sendZigbeeNWKRejoinResp(nwkHeader.source16!, newAddress16, status, decodedCap);

        // NOTE: a device does not have to verify its trust center link key with the APSME-VERIFY-KEY services after a rejoin.

        return offset;
    }

    // NOTE: sendZigbeeNWKRejoinReq not for coordinator

    /**
     * 05-3474-R #3.4.7
     * Optional
     */
    public processZigbeeNWKRejoinResp(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;

        if (status !== MACAssociationStatus.SUCCESS) {
            logger.error(
                `<=x= NWK REJOIN_RESP[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress} status=${MACAssociationStatus[status]}]`,
                NS,
            );
        } else {
            logger.debug(
                () =>
                    `<=== NWK REJOIN_RESP[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress}]`,
                NS,
            );
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
    public async sendZigbeeNWKRejoinResp(
        requestSource16: number,
        newAddress16: number,
        status: MACAssociationStatus | number,
        capabilities: MACCapabilities,
    ): Promise<boolean> {
        logger.debug(() => `===> NWK REJOIN_RESP[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);

        const finalPayload = Buffer.from([ZigbeeNWKCommandId.REJOIN_RESP, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);

        const result = await this.sendZigbeeNWKCommand(
            ZigbeeNWKCommandId.REJOIN_RESP,
            finalPayload,
            true, // nwkSecurity TODO: ??
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestSource16, // nwkDest16
            this.address16ToAddress64.get(newAddress16), // nwkDest64
            CONFIG_NWK_MAX_HOPS, // nwkRadius
        );

        if (status === MACAssociationStatus.SUCCESS) {
            setImmediate(() => {
                this.emit("deviceRejoined", newAddress16, this.address16ToAddress64.get(newAddress16)!, capabilities);
            });
        }

        return result;
    }

    /**
     * 05-3474-R #3.4.8
     */
    public processZigbeeNWKLinkStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        // Bit: 0 – 4        5            6           7
        //      Entry count  First frame  Last frame  Reserved
        const options = data.readUInt8(offset);
        offset += 1;
        const firstFrame = Boolean((options & ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME) >> 5);
        const lastFrame = Boolean((options & ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME) >> 6);
        const linkCount = options & ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK;
        const links: ZigbeeNWKLinkStatus[] = [];

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
                incomingCost: costByte & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK,
                outgoingCost: (costByte & ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK) >> 4,
            });

            if (device) {
                if (address === ZigbeeConsts.COORDINATOR_ADDRESS) {
                    // if neighbor is coordinator, update device table
                    device.neighbor = true;
                }

                const entry: SourceRouteTableEntry =
                    address === ZigbeeConsts.COORDINATOR_ADDRESS
                        ? { relayAddresses: [], pathCost: 1 /* TODO ? */ }
                        : { relayAddresses: [address], pathCost: 2 /* TODO ? */ };
                const entries = this.sourceRouteTable.get(device.address16);

                if (entries === undefined) {
                    this.sourceRouteTable.set(device.address16, [entry]);
                } else if (!this.hasSourceRoute(device.address16, entry, entries)) {
                    entries.push(entry);
                }
            }
        }

        logger.debug(() => {
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
    public async sendZigbeeNWKLinkStatus(links: ZigbeeNWKLinkStatus[]): Promise<void> {
        logger.debug(() => {
            let linksStr = "";

            for (const link of links) {
                linksStr += `{${link.address}|in:${link.incomingCost}|out:${link.outgoingCost}}`;
            }

            return `===> NWK LINK_STATUS[links=${linksStr}]`;
        }, NS);

        // TODO: check repeat logic
        const linkSize = links.length * 3;
        const maxLinksPayloadSize = ZigbeeNWKConsts.PAYLOAD_MIN_SIZE - 2; // 84 (- cmdId[1] - options[1])
        const maxLinksPerFrame = Math.floor(maxLinksPayloadSize / 3); // 27
        const frameCount = Math.ceil((linkSize + 3) / maxLinksPayloadSize); // (+ repeated link[3])
        let linksOffset = 0;

        for (let i = 0; i < frameCount; i++) {
            const linkCount = links.length - i * maxLinksPerFrame;
            const frameSize = 2 + Math.min(linkCount * 3, maxLinksPayloadSize);
            const options =
                (((i === 0 ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME) |
                (((i === frameCount - 1 ? 1 : 0) << 6) & ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME) |
                (linkCount & ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK);
            const finalPayload = Buffer.alloc(frameSize);
            let finalPayloadOffset = 0;
            finalPayload.writeUInt8(ZigbeeNWKCommandId.LINK_STATUS, finalPayloadOffset);
            finalPayloadOffset += 1;
            finalPayload.writeUInt8(options, finalPayloadOffset);
            finalPayloadOffset += 1;

            for (let j = 0; j < linkCount; j++) {
                const link = links[linksOffset];
                finalPayload.writeUInt16LE(link.address, finalPayloadOffset);
                finalPayloadOffset += 2;
                finalPayload.writeUInt8(
                    (link.incomingCost & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK) |
                        ((link.outgoingCost << 4) & ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK),
                    finalPayloadOffset,
                );
                finalPayloadOffset += 1;

                // last in previous frame is repeated first in next frame
                if (j < linkCount - 1) {
                    linksOffset++;
                }
            }

            await this.sendZigbeeNWKCommand(
                ZigbeeNWKCommandId.LINK_STATUS,
                finalPayload,
                true, // nwkSecurity
                ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
                ZigbeeConsts.BCAST_DEFAULT, // nwkDest16
                undefined, // nwkDest64
                1, // nwkRadius
            );
        }
    }

    /**
     * 05-3474-R #3.4.9
     *  deprecated in R23, should no longer be sent by R23 devices
     */
    public processZigbeeNWKReport(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const options = data.readUInt8(offset);
        offset += 1;
        const reportCount = options & ZigbeeNWKConsts.CMD_NWK_REPORT_COUNT_MASK;
        const reportType = options & ZigbeeNWKConsts.CMD_NWK_REPORT_ID_MASK;
        const extendedPANId = data.readBigUInt64LE(offset);
        offset += 8;
        let conflictPANIds: number[] | undefined;

        if (reportType === ZigbeeNWKConsts.CMD_NWK_REPORT_ID_PAN_CONFLICT) {
            conflictPANIds = [];

            for (let i = 0; i < reportCount; i++) {
                const panId = data.readUInt16LE(offset);
                offset += 2;

                conflictPANIds.push(panId);
            }
        }

        logger.debug(
            () =>
                `<=== NWK NWK_REPORT[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} extPANId=${extendedPANId} repType=${reportType} conflictPANIds=${conflictPANIds}]`,
            NS,
        );

        return offset;
    }

    // NOTE: sendZigbeeNWKReport deprecated in R23

    /**
     * 05-3474-R #3.4.10
     */
    public processZigbeeNWKUpdate(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const options = data.readUInt8(offset);
        offset += 1;
        const updateCount = options & ZigbeeNWKConsts.CMD_NWK_UPDATE_COUNT_MASK;
        const updateType = options & ZigbeeNWKConsts.CMD_NWK_UPDATE_ID_MASK;
        const extendedPANId = data.readBigUInt64LE(offset);
        offset += 8;
        const updateId = data.readUInt8(offset);
        offset += 1;
        let panIds: number[] | undefined;

        if (updateType === ZigbeeNWKConsts.CMD_NWK_UPDATE_ID_PAN_UPDATE) {
            panIds = [];

            for (let i = 0; i < updateCount; i++) {
                const panId = data.readUInt16LE(offset);
                offset += 2;

                panIds.push(panId);
            }
        }

        logger.debug(
            () =>
                `<=== NWK NWK_UPDATE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} extPANId=${extendedPANId} id=${updateId} type=${updateType} panIds=${panIds}]`,
            NS,
        );
        // TODO

        return offset;
    }

    // NOTE: sendZigbeeNWKUpdate PAN ID change not supported

    /**
     * 05-3474-R #3.4.11
     */
    public async processZigbeeNWKEdTimeoutRequest(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
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

        logger.debug(
            () =>
                `<=== NWK ED_TIMEOUT_REQUEST[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} reqTimeout=${requestedTimeout} conf=${configuration}]`,
            NS,
        );

        await this.sendZigbeeNWKEdTimeoutResponse(nwkHeader.source16!, requestedTimeout);

        return offset;
    }

    // NOTE: sendZigbeeNWKEdTimeoutRequest not for coordinator

    /**
     * 05-3474-R #3.4.12
     */
    public processZigbeeNWKEdTimeoutResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
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

        logger.debug(
            () =>
                `<=== NWK ED_TIMEOUT_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${status} parentInfo=${parentInfo}]`,
            NS,
        );
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
    public async sendZigbeeNWKEdTimeoutResponse(requestDest16: number, requestedTimeout: number): Promise<boolean> {
        logger.debug(() => `===> NWK ED_TIMEOUT_RESPONSE[reqDst16=${requestDest16} requestedTimeout=${requestedTimeout}]`, NS);

        // sanity check
        const status = requestedTimeout >= 0 && requestedTimeout <= 14 ? 0x00 : 0x01;
        const parentInfo = 0b00000111; // TODO: ?
        const finalPayload = Buffer.from([ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE, status, parentInfo]);

        return await this.sendZigbeeNWKCommand(
            ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestDest16, // nwkDest16
            this.address16ToAddress64.get(requestDest16), // nwkDest64
            1, // nwkRadius
        );
    }

    /**
     * 05-3474-R #3.4.13
     */
    public processZigbeeNWKLinkPwrDelta(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const options = data.readUInt8(offset);
        offset += 1;
        // 0 Notification An unsolicited notification. These frames are typically sent periodically from an RxOn device. If the device is a FFD, it is broadcast to all RxOn devices (0xfffd), and includes power information for all neighboring RxOn devices. If the device is an RFD with RxOn, it is sent unicast to its Parent, and includes only power information for the Parent device.
        // 1 Request Typically used by sleepy RFD devices that do not receive the periodic Notifications from their Parent. The sleepy RFD will wake up periodically to send this frame to its Parent, including only the Parent’s power information in its payload. Upon receipt, the Parent sends a Response (Type = 2) as an indirect transmission, with only the RFD’s power information in its payload. After macResponseWaitTime, the RFD polls its Parent for the Response, before going back to sleep. Request commands are sent as unicast. Note: any device MAY send a Request to solicit a Response from another device. These commands SHALL be sent as unicast and contain only the power information for the destination device. If this command is received as a broadcast, it SHALL be discarded with no action.
        // 2 Response This command is sent in response to a Request. Response commands are sent as unicast to the sender of the Request. The response includes only the power information for the requesting device.
        // 3 Reserved
        const type = options & ZigbeeNWKConsts.CMD_NWK_LINK_PWR_DELTA_TYPE_MASK;
        const count = data.readUInt8(offset);
        offset += 1;
        const deltas: { device: number; delta: number }[] = [];

        for (let i = 0; i < count; i++) {
            const device = data.readUInt16LE(offset);
            offset += 2;
            const delta = data.readUInt8(offset);
            offset += 1;

            deltas.push({ device, delta });
        }

        logger.debug(
            () =>
                `<=== NWK LINK_PWR_DELTA[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${type} deltas=${deltas}]`,
            NS,
        );
        // TODO

        return offset;
    }

    // NOTE: sendZigbeeNWKLinkPwrDelta not supported

    /**
     * 05-3474-23 #3.4.14
     * Optional
     */
    public async processZigbeeNWKCommissioningRequest(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
    ): Promise<number> {
        // 0x00 Initial Join
        // 0x01 Rejoin
        const assocType = data.readUInt8(offset);
        offset += 1;
        const capabilities = data.readUInt8(offset);
        offset += 1;

        const decodedCap = decodeMACCapabilities(capabilities);

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);

        logger.debug(
            () =>
                `<=== NWK COMMISSIONING_REQUEST[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} assocType=${assocType} cap=${capabilities}]`,
            NS,
        );

        // NOTE: send Remove Device CMD to TC deny the join (or let timeout): `sendZigbeeAPSRemoveDevice`

        const [status, newAddress16] = await this.associate(
            nwkHeader.source16!,
            nwkHeader.source64,
            assocType === 0x00 /* initial join */,
            decodedCap,
            macHeader.source16 === nwkHeader.source16,
            nwkHeader.frameControl.security /* deny if true */,
        );

        await this.sendZigbeeNWKCommissioningResponse(nwkHeader.source16!, newAddress16, status);

        if (status === MACAssociationStatus.SUCCESS) {
            // TODO also for rejoin in case of nwk key change?
            await this.sendZigbeeAPSTransportKeyNWK(
                nwkHeader.source16!,
                this.netParams.networkKey,
                this.netParams.networkKeySequenceNumber,
                this.address16ToAddress64.get(newAddress16)!, // valid from `associate`
            );
        }

        return offset;
    }

    // NOTE: sendZigbeeNWKCommissioningRequest not for coordinator

    /**
     * 05-3474-23 #3.4.15
     * Optional
     */
    public processZigbeeNWKCommissioningResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        // `ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT`, or MACAssociationStatus
        const status = data.readUInt8(offset);
        offset += 1;

        if (status !== MACAssociationStatus.SUCCESS) {
            logger.error(
                `<=x= NWK COMMISSIONING_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress} status=${MACAssociationStatus[status] ?? "NWK_ADDR_CONFLICT"}]`,
                NS,
            );
        } else {
            logger.debug(
                () =>
                    `<=== NWK COMMISSIONING_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress}]`,
                NS,
            );
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
    public async sendZigbeeNWKCommissioningResponse(
        requestSource16: number,
        newAddress16: number,
        status: MACAssociationStatus | number,
    ): Promise<boolean> {
        logger.debug(() => `===> NWK COMMISSIONING_RESPONSE[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);

        const finalPayload = Buffer.from([ZigbeeNWKCommandId.COMMISSIONING_RESPONSE, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);

        return await this.sendZigbeeNWKCommand(
            ZigbeeNWKCommandId.COMMISSIONING_RESPONSE,
            finalPayload,
            false, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestSource16, // nwkDest16
            this.address16ToAddress64.get(requestSource16), // nwkDest64
            CONFIG_NWK_MAX_HOPS, // nwkRadius
        );
    }

    // #endregion

    // #region Zigbee NWK GP layer

    public checkZigbeeNWKGPDuplicate(macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader): boolean {
        let duplicate = false;

        if (nwkHeader.securityFrameCounter !== undefined) {
            if (nwkHeader.securityFrameCounter === this.#gpLastSecurityFrameCounter) {
                duplicate = true;
            }

            this.#gpLastSecurityFrameCounter = nwkHeader.securityFrameCounter;
        } else if (macHeader.sequenceNumber !== undefined) {
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
    public processZigbeeNWKGPFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, lqa: number): void {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;
        const framePayload = data.subarray(offset);

        if (
            !this.#gpCommissioningMode &&
            (cmdId === ZigbeeNWKGPCommandId.COMMISSIONING || cmdId === ZigbeeNWKGPCommandId.SUCCESS || cmdId === ZigbeeNWKGPCommandId.CHANNEL_REQUEST)
        ) {
            logger.debug(() => `<=~= NWKGP[cmdId=${cmdId} src=${nwkHeader.sourceId}:${macHeader.source64}] Not in commissioning mode`, NS);

            return;
        }

        logger.debug(() => `<=== NWKGP[cmdId=${cmdId} src=${nwkHeader.sourceId}:${macHeader.source64}]`, NS);

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
    public async sendZigbeeAPSCommand(
        cmdId: ZigbeeAPSCommandId,
        finalPayload: Buffer,
        nwkDiscoverRoute: ZigbeeNWKRouteDiscovery,
        nwkSecurity: boolean,
        nwkDest16: number | undefined,
        nwkDest64: bigint | undefined,
        apsDeliveryMode: ZigbeeAPSDeliveryMode.UNICAST | ZigbeeAPSDeliveryMode.BCAST,
        apsSecurityHeader: ZigbeeSecurityHeader | undefined,
        disableACKRequest = false,
    ): Promise<boolean> {
        let nwkSecurityHeader: ZigbeeSecurityHeader | undefined;

        if (nwkSecurity) {
            nwkSecurityHeader = {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.NWK,
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
        let relayIndex: number | undefined;
        let relayAddresses: number[] | undefined;

        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        } catch (error) {
            logger.error(
                `=x=> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64}] ${(error as Error).message}`,
                NS,
            );

            return false;
        }

        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.deviceTable.get(nwkDest64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.error(
                `=x=> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} nwkSec=${nwkSecurity} apsDlv=${apsDeliveryMode} apsSec=${apsSecurityHeader !== undefined}]`,
                NS,
            );

            return false;
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;

        logger.debug(
            () =>
                `===> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} nwkSec=${nwkSecurity} apsDlv=${apsDeliveryMode} apsSec=${apsSecurityHeader !== undefined}]`,
            NS,
        );

        const apsFrame = encodeZigbeeAPSFrame(
            {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.CMD,
                    deliveryMode: apsDeliveryMode,
                    ackFormat: false,
                    security: apsSecurityHeader !== undefined,
                    // XXX: spec says all should request ACK except TUNNEL, but vectors show not a lot of stacks respect that, what's best?
                    ackRequest: cmdId !== ZigbeeAPSCommandId.TUNNEL && !disableACKRequest,
                    extendedHeader: false,
                },
                counter: apsCounter,
            },
            finalPayload,
            apsSecurityHeader,
            undefined, // use pre-hashed this.netParams.tcKey,
        );
        const nwkFrame = encodeZigbeeNWKFrame(
            {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
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
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: this.decrementRadius(CONFIG_NWK_MAX_HOPS),
                seqNum: nwkSeqNum,
                relayIndex,
                relayAddresses,
            },
            apsFrame,
            nwkSecurityHeader,
            undefined, // use pre-hashed this.netParams.networkKey,
        );
        const macFrame = encodeMACFrameZigbee(
            {
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: Boolean(this.indirectTransmissions.get(nwkDest64 ?? this.address16ToAddress64.get(nwkDest16)!)?.length),
                    ackRequest: macDest16 !== ZigbeeMACConsts.BCAST_ADDR,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macSeqNum,
                destinationPANId: this.netParams.panId,
                destination16: macDest16,
                // sourcePANId: undefined, // panIdCompression=true
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                fcs: 0,
            },
            nwkFrame,
        );

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
    public async sendZigbeeAPSData(
        finalPayload: Buffer,
        nwkDiscoverRoute: ZigbeeNWKRouteDiscovery,
        nwkDest16: number | undefined,
        nwkDest64: bigint | undefined,
        apsDeliveryMode: ZigbeeAPSDeliveryMode,
        clusterId: number,
        profileId: number,
        destEndpoint: number | undefined,
        sourceEndpoint: number | undefined,
        group: number | undefined,
    ): Promise<number> {
        const apsCounter = this.nextAPSCounter();
        const nwkSeqNum = this.nextNWKSeqNum();
        const macSeqNum = this.nextMACSeqNum();
        let relayIndex: number | undefined;
        let relayAddresses: number[] | undefined;

        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        } catch (error) {
            logger.error(
                `=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) nwkDst=${nwkDest16}:${nwkDest64}] ${(error as Error).message}`,
                NS,
            );

            throw error;
        }

        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.deviceTable.get(nwkDest64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.error(`=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) nwkDst=${nwkDest16}:${nwkDest64}] Invalid parameters`, NS);

            throw new Error("Invalid parameters", { cause: SpinelStatus.INVALID_ARGUMENT });
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;

        logger.debug(
            () =>
                `===> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} apsDlv=${apsDeliveryMode}]`,
            NS,
        );

        const apsFrame = encodeZigbeeAPSFrame(
            {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
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
            },
            finalPayload,
            // undefined,
            // undefined,
        );
        const nwkFrame = encodeZigbeeNWKFrame(
            {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
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
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: this.decrementRadius(CONFIG_NWK_MAX_HOPS),
                seqNum: nwkSeqNum,
                relayIndex,
                relayAddresses,
            },
            apsFrame,
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.NWK,
                    nonce: true,
                },
                frameCounter: this.nextNWKKeyFrameCounter(),
                source64: this.netParams.eui64,
                keySeqNum: this.netParams.networkKeySequenceNumber,
                micLen: 4,
            },
            undefined, // use pre-hashed this.netParams.networkKey,
        );
        const macFrame = encodeMACFrameZigbee(
            {
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending:
                        group === undefined && nwkDest16 < ZigbeeConsts.BCAST_MIN
                            ? Boolean(this.indirectTransmissions.get(nwkDest64 ?? this.address16ToAddress64.get(nwkDest16)!)?.length)
                            : false,
                    ackRequest: macDest16 !== ZigbeeMACConsts.BCAST_ADDR,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macSeqNum,
                destinationPANId: this.netParams.panId,
                destination16: macDest16,
                // sourcePANId: undefined, // panIdCompression=true
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                fcs: 0,
            },
            nwkFrame,
        );

        const result = await this.sendMACFrame(macSeqNum, macFrame, macDest16, undefined);

        if (result === false) {
            logger.error(
                `=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64}] Failed to send`,
                NS,
            );

            throw new Error("Failed to send", { cause: SpinelStatus.FAILURE });
        }

        return apsCounter;
    }

    public async sendZigbeeAPSACK(macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void> {
        logger.debug(
            () =>
                `===> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`,
            NS,
        );

        let nwkDest16 = nwkHeader.source16;
        const nwkDest64 = nwkHeader.source64;
        let relayIndex: number | undefined;
        let relayAddresses: number[] | undefined;

        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        } catch (error) {
            logger.debug(() => `=x=> APS ACK[dst16=${nwkDest16} seqNum=${nwkHeader.seqNum}] ${(error as Error).message}`, NS);

            return;
        }

        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.deviceTable.get(nwkDest64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.debug(
                () =>
                    `=x=> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`,
                NS,
            );

            return;
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;
        const ackAPSFrame = encodeZigbeeAPSFrame(
            {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.ACK,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
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
            },
            Buffer.alloc(0), // TODO optimize
            // undefined,
            // undefined,
        );
        const ackNWKFrame = encodeZigbeeNWKFrame(
            {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
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
            },
            ackAPSFrame,
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.NWK,
                    nonce: true,
                },
                frameCounter: this.nextNWKKeyFrameCounter(),
                source64: this.netParams.eui64,
                keySeqNum: this.netParams.networkKeySequenceNumber,
                micLen: 4,
            },
            undefined, // use pre-hashed this.netParams.networkKey,
        );
        const ackMACFrame = encodeMACFrameZigbee(
            {
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: Boolean(this.indirectTransmissions.get(nwkDest64 ?? this.address16ToAddress64.get(nwkDest16)!)?.length),
                    ackRequest: true,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macHeader.sequenceNumber,
                destinationPANId: macHeader.destinationPANId,
                destination16: macDest16,
                // sourcePANId: undefined, // panIdCompression=true
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                fcs: 0,
            },
            ackNWKFrame,
        );

        await this.sendMACFrame(macHeader.sequenceNumber!, ackMACFrame, macHeader.source16, undefined);
    }

    public async onZigbeeAPSFrame(
        data: Buffer,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        apsHeader: ZigbeeAPSHeader,
        lqa: number,
    ): Promise<void> {
        switch (apsHeader.frameControl.frameType) {
            case ZigbeeAPSFrameType.ACK: {
                // ACKs should never contain a payload
                // TODO: ?
                break;
            }
            case ZigbeeAPSFrameType.DATA:
            case ZigbeeAPSFrameType.INTERPAN: {
                if (data.byteLength < 1) {
                    return;
                }

                logger.debug(
                    () =>
                        `<=== APS DATA[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${nwkHeader.seqNum} profileId=${apsHeader.profileId} clusterId=${apsHeader.clusterId} srcEp=${apsHeader.sourceEndpoint} dstEp=${apsHeader.destEndpoint} bcast=${macHeader.destination16 === ZigbeeMACConsts.BCAST_ADDR || (nwkHeader.destination16 !== undefined && nwkHeader.destination16 >= ZigbeeConsts.BCAST_MIN)}]`,
                    NS,
                );

                if (apsHeader.profileId === ZigbeeConsts.ZDO_PROFILE_ID) {
                    if (apsHeader.clusterId === ZigbeeConsts.END_DEVICE_ANNOUNCE) {
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

                        const decodedCap = decodeMACCapabilities(capabilities);
                        // just in case
                        device.capabilities = decodedCap;

                        // TODO: ideally, this shouldn't trigger (prevents early interview process from app) until AFTER authorized=true
                        setImmediate(() => {
                            // if device is authorized, it means it completed the TC link key update, so, a rejoin
                            this.emit(device.authorized ? "deviceRejoined" : "deviceJoined", address16, address64, decodedCap);
                        });
                    } else {
                        const isRequest = (apsHeader.clusterId! & 0x8000) === 0;

                        if (isRequest) {
                            if (this.isZDORequestForCoordinator(apsHeader.clusterId!, nwkHeader.destination16, nwkHeader.destination64, data)) {
                                await this.respondToCoordinatorZDORequest(data, apsHeader.clusterId!, nwkHeader.source16, nwkHeader.source64);
                            }

                            // don't emit received ZDO requests
                            return;
                        }
                    }
                }

                if (nwkHeader.source16 === undefined && nwkHeader.source64 === undefined) {
                    logger.debug(() => "<=~= APS Ignoring frame with no sender info", NS);
                    return;
                }

                setImmediate(() => {
                    // TODO: always lookup source64 if undef?
                    this.emit("frame", nwkHeader.source16, nwkHeader.source64, apsHeader, data, lqa);
                });

                break;
            }
            case ZigbeeAPSFrameType.CMD: {
                await this.processZigbeeAPSCommand(data, macHeader, nwkHeader, apsHeader);
                break;
            }
            default: {
                throw new Error(`Illegal frame type ${apsHeader.frameControl.frameType}`, { cause: SpinelStatus.INVALID_ARGUMENT });
            }
        }
    }

    public async processZigbeeAPSCommand(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void> {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;

        switch (cmdId) {
            case ZigbeeAPSCommandId.TRANSPORT_KEY: {
                offset = this.processZigbeeAPSTransportKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.UPDATE_DEVICE: {
                offset = await this.processZigbeeAPSUpdateDevice(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.REMOVE_DEVICE: {
                offset = this.processZigbeeAPSRemoveDevice(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.REQUEST_KEY: {
                offset = await this.processZigbeeAPSRequestKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.SWITCH_KEY: {
                offset = this.processZigbeeAPSSwitchKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.TUNNEL: {
                offset = this.processZigbeeAPSTunnel(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.VERIFY_KEY: {
                offset = await this.processZigbeeAPSVerifyKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.CONFIRM_KEY: {
                offset = this.processZigbeeAPSConfirmKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.RELAY_MESSAGE_DOWNSTREAM: {
                offset = this.processZigbeeAPSRelayMessageDownstream(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.RELAY_MESSAGE_UPSTREAM: {
                offset = this.processZigbeeAPSRelayMessageUpstream(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            default: {
                logger.warning(
                    `<=x= APS CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}] Unsupported`,
                    NS,
                );
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
    public processZigbeeAPSTransportKey(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        const keyType = data.readUInt8(offset);
        offset += 1;
        const key = data.subarray(offset, offset + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;

        switch (keyType) {
            case ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK:
            case ZigbeeAPSConsts.CMD_KEY_HIGH_SEC_NWK: {
                const seqNum = data.readUInt8(offset);
                offset += 1;
                const destination = data.readBigUInt64LE(offset);
                offset += 8;
                const source = data.readBigUInt64LE(offset);
                offset += 8;

                logger.debug(
                    () =>
                        `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} seqNum=${seqNum} dst64=${destination} src64=${source}]`,
                    NS,
                );

                break;
            }
            case ZigbeeAPSConsts.CMD_KEY_TC_MASTER:
            case ZigbeeAPSConsts.CMD_KEY_TC_LINK: {
                const destination = data.readBigUInt64LE(offset);
                offset += 8;
                const source = data.readBigUInt64LE(offset);
                offset += 8;

                // TODO
                // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);

                logger.debug(
                    () =>
                        `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} dst64=${destination} src64=${source}]`,
                    NS,
                );
                break;
            }
            case ZigbeeAPSConsts.CMD_KEY_APP_MASTER:
            case ZigbeeAPSConsts.CMD_KEY_APP_LINK: {
                const partner = data.readBigUInt64LE(offset);
                offset += 8;
                const initiatorFlag = data.readUInt8(offset);
                offset += 1;

                // TODO
                // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);

                logger.debug(
                    () =>
                        `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} partner64=${partner} initiatorFlag=${initiatorFlag}]`,
                    NS,
                );
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
    public async sendZigbeeAPSTransportKeyTC(nwkDest16: number, key: Buffer, destination64: bigint): Promise<boolean> {
        // TODO: tunneling support `, tunnelDest?: bigint`
        //       If the TunnelCommand parameter is TRUE, an APS Tunnel Command SHALL be constructed as described in section 4.6.3.7.
        //       It SHALL then be sent to the device specified by the TunnelAddress parameter by issuing an NLDE-DATA.request primitive.
        logger.debug(() => `===> APS TRANSPORT_KEY_TC[key=${key.toString("hex")} dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(18 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_TC_LINK, offset);
        offset += 1;
        finalPayload.set(key, offset);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        finalPayload.writeBigUInt64LE(this.netParams.eui64, offset);
        offset += 8;

        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeAPSTLVs();

        // encryption NWK=true, APS=true
        return await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.TRANSPORT_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.LOAD,
                    nonce: true,
                },
                frameCounter: this.nextTCKeyFrameCounter(),
                source64: this.netParams.eui64,
                // keySeqNum: undefined, only for keyId NWK
                micLen: 4,
            }, // apsSecurityHeader
        );
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
    public async sendZigbeeAPSTransportKeyNWK(nwkDest16: number, key: Buffer, seqNum: number, destination64: bigint): Promise<boolean> {
        // TODO: tunneling support `, tunnelDest?: bigint`
        logger.debug(() => `===> APS TRANSPORT_KEY_NWK[key=${key.toString("hex")} seqNum=${seqNum} dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(19 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK, offset);
        offset += 1;
        finalPayload.set(key, offset);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;
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
        return await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.TRANSPORT_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            false, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.TRANSPORT,
                    nonce: true,
                },
                frameCounter: this.nextTCKeyFrameCounter(),
                source64: this.netParams.eui64,
                // keySeqNum: undefined, only for keyId NWK
                micLen: 4,
            }, // apsSecurityHeader
            true, // disableACKRequest TODO: follows sniffed but not spec?
        );
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
    public async sendZigbeeAPSTransportKeyAPP(nwkDest16: number, key: Buffer, partner: bigint, initiatorFlag: boolean): Promise<boolean> {
        // TODO: tunneling support `, tunnelDest?: bigint`
        logger.debug(() => `===> APS TRANSPORT_KEY_APP[key=${key.toString("hex")} partner64=${partner} initiatorFlag=${initiatorFlag}]`, NS);

        const finalPayload = Buffer.alloc(11 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_APP_LINK, offset);
        offset += 1;
        finalPayload.set(key, offset);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;
        finalPayload.writeBigUInt64LE(partner, offset);
        offset += 8;
        finalPayload.writeUInt8(initiatorFlag ? 1 : 0, offset);
        offset += 1;

        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeAPSTLVs();

        return await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.TRANSPORT_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.LOAD,
                    nonce: true,
                },
                frameCounter: this.nextTCKeyFrameCounter(),
                source64: this.netParams.eui64,
                // keySeqNum: undefined, only for keyId NWK
                micLen: 4,
            }, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.2
     */
    public async processZigbeeAPSUpdateDevice(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): Promise<number> {
        const device64 = data.readBigUInt64LE(offset);
        offset += 8;
        // ZigBee 2006 and later
        const device16 = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);

        logger.debug(
            () =>
                `<=== APS UPDATE_DEVICE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dev=${device16}:${device64} status=${status} src16=${nwkHeader.source16}]`,
            NS,
        );

        // 0x00 = Standard Device Secured Rejoin
        // 0x01 = Standard Device Unsecured Join
        // 0x02 = Device Left
        // 0x03 = Standard Device Trust Center Rejoin
        // 0x04 – 0x07 = Reserved
        if (status === 0x01) {
            await this.associate(
                device16,
                device64,
                true, // initial join
                undefined, // no MAC cap through router
                false, // not neighbor
                false,
                true, // was allowed by parent
            );

            // TODO: better handling
            try {
                const [, parentRelays] = this.findBestSourceRoute(nwkHeader.source16, nwkHeader.source64);

                if (parentRelays) {
                    // parent is nested
                    this.sourceRouteTable.set(device16, [{ relayAddresses: parentRelays, pathCost: parentRelays.length + 1 }]);
                } else {
                    // parent is direct to coordinator
                    this.sourceRouteTable.set(device16, [{ relayAddresses: [nwkHeader.source16!], pathCost: 2 }]);
                }
            } catch {
                /* ignore */
            }

            const tApsCmdPayload = Buffer.alloc(19 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
            let offset = 0;
            tApsCmdPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
            offset += 1;
            tApsCmdPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK, offset);
            offset += 1;
            tApsCmdPayload.set(this.netParams.networkKey, offset);
            offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;
            tApsCmdPayload.writeUInt8(this.netParams.networkKeySequenceNumber, offset);
            offset += 1;
            tApsCmdPayload.writeBigUInt64LE(device64, offset);
            offset += 8;
            tApsCmdPayload.writeBigUInt64LE(this.netParams.eui64, offset); // 0xFFFFFFFFFFFFFFFF in distributed network (no TC)
            offset += 8;

            const tApsCmdFrame = encodeZigbeeAPSFrame(
                {
                    frameControl: {
                        frameType: ZigbeeAPSFrameType.CMD,
                        deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                        ackFormat: false,
                        security: true,
                        ackRequest: false,
                        extendedHeader: false,
                    },
                    counter: this.nextAPSCounter(),
                },
                tApsCmdPayload,
                {
                    control: {
                        level: ZigbeeSecurityLevel.NONE,
                        keyId: ZigbeeKeyType.TRANSPORT,
                        nonce: true,
                    },
                    frameCounter: this.nextTCKeyFrameCounter(),
                    source64: this.netParams.eui64,
                    micLen: 4,
                },
                undefined, // use pre-hashed this.netParams.tcKey,
            );

            await this.sendZigbeeAPSTunnel(nwkHeader.source16!, device64, tApsCmdFrame);
        } else if (status === 0x03) {
            // rejoin
            await this.associate(
                device16,
                device64,
                false, // rejoin
                undefined, // no MAC cap through router
                false, // not neighbor
                false,
                true, // was allowed by parent, expected valid
            );
        } else if (status === 0x02) {
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
    public async sendZigbeeAPSUpdateDevice(
        nwkDest16: number,
        device64: bigint,
        device16: number,
        status: number,
        // tlvs: unknown[],
    ): Promise<boolean> {
        logger.debug(() => `===> APS UPDATE_DEVICE[dev=${device16}:${device64} status=${status}]`, NS);

        const finalPayload = Buffer.alloc(12 /* + TLVs */);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.UPDATE_DEVICE, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(device64, offset);
        offset += 8;
        finalPayload.writeUInt16LE(device16, offset);
        offset += 2;
        finalPayload.writeUInt8(status, offset);
        offset += 1;

        // TODO TLVs

        return await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.UPDATE_DEVICE,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.3
     */
    public processZigbeeAPSRemoveDevice(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        const target = data.readBigUInt64LE(offset);
        offset += 8;

        logger.debug(
            () =>
                `<=== APS REMOVE_DEVICE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} target64=${target}]`,
            NS,
        );

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.3
     *
     * @param nwkDest16 parent
     * @param target64
     * @returns
     */
    public async sendZigbeeAPSRemoveDevice(nwkDest16: number, target64: bigint): Promise<boolean> {
        logger.debug(() => `===> APS REMOVE_DEVICE[target64=${target64}]`, NS);

        const finalPayload = Buffer.alloc(9);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.REMOVE_DEVICE, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(target64, offset);
        offset += 8;

        return await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.REMOVE_DEVICE,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.4 #4.4.5.2.3
     */
    public async processZigbeeAPSRequestKey(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        apsHeader: ZigbeeAPSHeader,
    ): Promise<number> {
        // ZigbeeAPSConsts.CMD_KEY_APP_MASTER || ZigbeeAPSConsts.CMD_KEY_TC_LINK
        const keyType = data.readUInt8(offset);
        offset += 1;

        // If the APS Command Request Key message is not APS encrypted, the device SHALL drop the message and no further processing SHALL be done.
        if (!apsHeader.frameControl.security) {
            return offset;
        }

        const device64 = this.address16ToAddress64.get(nwkHeader.source16!);

        // don't send to unknown device
        if (device64 !== undefined) {
            // TODO:
            //   const deviceKeyPair = this.apsDeviceKeyPairSet.get(nwkHeader.source16!);
            //   if (!deviceKeyPair || deviceKeyPair.keyNegotiationMethod === 0x00 /* `APS Request Key` method */) {

            if (keyType === ZigbeeAPSConsts.CMD_KEY_APP_MASTER) {
                const partner = data.readBigUInt64LE(offset);
                offset += 8;

                logger.debug(
                    () =>
                        `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} partner64=${partner}]`,
                    NS,
                );

                if (this.#trustCenterPolicies.allowAppKeyRequest === ApplicationKeyRequestPolicy.ALLOWED) {
                    await this.sendZigbeeAPSTransportKeyAPP(
                        nwkHeader.source16!,
                        this.getOrGenerateAppLinkKey(nwkHeader.source16!, partner),
                        partner,
                        true,
                    );
                }
                // TODO ApplicationKeyRequestPolicy.ONLY_APPROVED
            } else if (keyType === ZigbeeAPSConsts.CMD_KEY_TC_LINK) {
                logger.debug(
                    () =>
                        `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}]`,
                    NS,
                );

                if (this.#trustCenterPolicies.allowTCKeyRequest === TrustCenterKeyRequestPolicy.ALLOWED) {
                    await this.sendZigbeeAPSTransportKeyTC(nwkHeader.source16!, this.netParams.tcKey, device64);
                }
                // TODO TrustCenterKeyRequestPolicy.ONLY_PROVISIONAL
                //      this.apsDeviceKeyPairSet => find deviceAddress === this.deviceTable.get(nwkHeader.source).address64 => check provisional or drop msg
            }
        } else {
            logger.warning(
                `<=x= APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}] Unknown device`,
                NS,
            );
        }

        return offset;
    }

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
    public async sendZigbeeAPSRequestKey(nwkDest16: number, keyType: 0x02, partner64: bigint): Promise<boolean>;
    public async sendZigbeeAPSRequestKey(nwkDest16: number, keyType: 0x04): Promise<boolean>;
    public async sendZigbeeAPSRequestKey(nwkDest16: number, keyType: 0x02 | 0x04, partner64?: bigint): Promise<boolean> {
        logger.debug(() => `===> APS REQUEST_KEY[type=${keyType} partner64=${partner64}]`, NS);

        const hasPartner64 = keyType === ZigbeeAPSConsts.CMD_KEY_APP_MASTER;
        const finalPayload = Buffer.alloc(2 + (hasPartner64 ? 8 : 0));
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.REQUEST_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(keyType, offset);
        offset += 1;

        if (hasPartner64) {
            finalPayload.writeBigUInt64LE(partner64!, offset);
            offset += 8;
        }

        return await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.REQUEST_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.5
     */
    public processZigbeeAPSSwitchKey(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        const seqNum = data.readUInt8(offset);
        offset += 1;

        logger.debug(
            () =>
                `<=== APS SWITCH_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${seqNum}]`,
            NS,
        );

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.5
     *
     * @param nwkDest16
     * @param seqNum SHALL contain the sequence number identifying the network key to be made active.
     * @returns
     */
    public async sendZigbeeAPSSwitchKey(nwkDest16: number, seqNum: number): Promise<boolean> {
        logger.debug(() => `===> APS SWITCH_KEY[seqNum=${seqNum}]`, NS);

        const finalPayload = Buffer.from([ZigbeeAPSCommandId.SWITCH_KEY, seqNum]);

        return await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.SWITCH_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.6
     */
    public processZigbeeAPSTunnel(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        const destination = data.readBigUInt64LE(offset);
        offset += 8;
        const tunneledAPSFrame = data.subarray(offset);
        offset += tunneledAPSFrame.byteLength;

        logger.debug(
            () =>
                `<=== APS TUNNEL[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dst=${destination} tAPSFrame=${tunneledAPSFrame}]`,
            NS,
        );

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
    public async sendZigbeeAPSTunnel(nwkDest16: number, destination64: bigint, tApsCmdFrame: Buffer): Promise<boolean> {
        logger.debug(() => `===> APS TUNNEL[dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(9 + tApsCmdFrame.byteLength);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.TUNNEL, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        finalPayload.set(tApsCmdFrame, offset);
        offset += tApsCmdFrame.byteLength;

        return await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.TUNNEL,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.7
     */
    public async processZigbeeAPSVerifyKey(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): Promise<number> {
        const keyType = data.readUInt8(offset);
        offset += 1;
        const source = data.readBigUInt64LE(offset);
        offset += 8;
        const keyHash = data.subarray(offset, offset + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;

        if (macHeader.source16 !== ZigbeeMACConsts.BCAST_ADDR) {
            logger.debug(
                () =>
                    `<=== APS VERIFY_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} src64=${source} hash=${keyHash.toString("hex")}]`,
                NS,
            );

            if (keyType === ZigbeeAPSConsts.CMD_KEY_TC_LINK) {
                // TODO: not valid if operating in distributed network
                const status = this.#tcVerifyKeyHash.equals(keyHash) ? 0x00 /* SUCCESS */ : 0xad; /* SECURITY_FAILURE */

                await this.sendZigbeeAPSConfirmKey(nwkHeader.source16!, status, keyType, source);
            } else if (keyType === ZigbeeAPSConsts.CMD_KEY_APP_MASTER) {
                // this is illegal for TC
                await this.sendZigbeeAPSConfirmKey(nwkHeader.source16!, 0xa3 /* ILLEGAL_REQUEST */, keyType, source);
            } else {
                await this.sendZigbeeAPSConfirmKey(nwkHeader.source16!, 0xaa /* NOT_SUPPORTED */, keyType, source);
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
    public async sendZigbeeAPSVerifyKey(nwkDest16: number, keyType: number, source64: bigint, hash: Buffer): Promise<boolean> {
        logger.debug(() => `===> APS VERIFY_KEY[type=${keyType} src64=${source64} hash=${hash.toString("hex")}]`, NS);

        const finalPayload = Buffer.alloc(26);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.VERIFY_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(keyType, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(source64, offset);
        offset += 8;
        finalPayload.set(hash, offset);
        offset += hash.byteLength; // 16

        return await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.VERIFY_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.8
     */
    public processZigbeeAPSConfirmKey(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        const status = data.readUInt8(offset);
        offset += 8;
        const keyType = data.readUInt8(offset);
        offset += 1;
        const destination = data.readBigUInt64LE(offset);
        offset += 8;

        logger.debug(
            () =>
                `<=== APS CONFIRM_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${status} type=${keyType} dst64=${destination}]`,
            NS,
        );

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
    public async sendZigbeeAPSConfirmKey(nwkDest16: number, status: number, keyType: number, destination64: bigint): Promise<boolean> {
        logger.debug(() => `===> APS CONFIRM_KEY[status=${status} type=${keyType} dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(11);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.CONFIRM_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(status, offset);
        offset += 1;
        finalPayload.writeUInt8(keyType, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;

        const result = await this.sendZigbeeAPSCommand(
            ZigbeeAPSCommandId.CONFIRM_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.LINK, // XXX: TRANSPORT?
                    nonce: true,
                },
                frameCounter: this.nextTCKeyFrameCounter(),
                source64: this.netParams.eui64,
                // keySeqNum: undefined, only for keyId NWK
                micLen: 4,
            }, // apsSecurityHeader
        );

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
    public processZigbeeAPSRelayMessageDownstream(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        // this includes only TLVs

        // This contains the EUI64 of the unauthorized neighbor that is the intended destination of the relayed message.
        const destination64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the Trust Center to the Joining device.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;

        logger.debug(
            () =>
                `<=== APS RELAY_MESSAGE_DOWNSTREAM[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dst64=${destination64}]`,
            NS,
        );

        return offset;
    }

    // TODO: send RELAY_MESSAGE_DOWNSTREAM

    /**
     * 05-3474-R #4.4.11.10
     */
    public processZigbeeAPSRelayMessageUpstream(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        // this includes only TLVs

        // This contains the EUI64 of the unauthorized neighbor that is the source of the relayed message.
        const source64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the joining device to the Trust Center.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;

        logger.debug(
            () =>
                `<=== APS RELAY_MESSAGE_UPSTREAM[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} src64=${source64}]`,
            NS,
        );

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

    public getOrGenerateAppLinkKey(_device16: number, _partner64: bigint): Buffer {
        // TODO: whole mechanism
        return this.netParams.tcKey;
    }

    public isNetworkUp(): boolean {
        return this.#networkUp;
    }

    /**
     * Set the Spinel properties required to start a 802.15.4 MAC network.
     *
     * Should be called after `start`.
     */
    public async formNetwork(): Promise<void> {
        logger.info("======== Network starting ========", NS);

        if (!this.#stateLoaded) {
            throw new Error("Cannot form network before state is loaded", { cause: SpinelStatus.INVALID_STATE });
        }

        // TODO: sanity checks?
        await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, true));
        await this.setProperty(writePropertyC(SpinelPropertyId.PHY_CHAN, this.netParams.channel));

        // TODO: ?
        // try { await this.setPHYCCAThreshold(10); } catch (error) {}
        await this.setPHYTXPower(this.netParams.txPower);

        await this.setProperty(writePropertyE(SpinelPropertyId.MAC_15_4_LADDR, this.netParams.eui64));
        await this.setProperty(writePropertyS(SpinelPropertyId.MAC_15_4_SADDR, ZigbeeConsts.COORDINATOR_ADDRESS));
        await this.setProperty(writePropertyS(SpinelPropertyId.MAC_15_4_PANID, this.netParams.panId));

        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RX_ON_WHEN_IDLE_MODE, true));
        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RAW_STREAM_ENABLED, true));

        const txPower = await this.getPHYTXPower();
        const radioRSSI = await this.getPHYRSSI();
        this.rssiMin = await this.getPHYRXSensitivity();
        let ccaThreshold: number | undefined;

        try {
            ccaThreshold = await this.getPHYCCAThreshold();
        } catch (error) {
            logger.debug(() => `PHY_CCA_THRESHOLD: ${error}`, NS);
        }

        logger.info(
            `======== Network started (PHY: txPower=${txPower}dBm rssi=${radioRSSI}dBm rxSensitivity=${this.rssiMin}dBm ccaThreshold=${ccaThreshold}dBm) ========`,
            NS,
        );

        this.#networkUp = true;

        await this.registerTimers();
    }

    /**
     * Remove the current state file and clear all related tables.
     *
     * Will throw if state already loaded (should be called before `start`).
     */
    public async resetNetwork(): Promise<void> {
        logger.info("======== Network resetting ========", NS);

        if (this.#stateLoaded) {
            throw new Error("Cannot reset network after state already loaded", { cause: SpinelStatus.INVALID_STATE });
        }

        // remove `zoh.save`
        await rm(this.savePath, { force: true });

        this.deviceTable.clear();
        this.address16ToAddress64.clear();
        this.indirectTransmissions.clear();
        this.sourceRouteTable.clear();
        this.pendingAssociations.clear();

        logger.info("======== Network reset ========", NS);
    }

    public async registerTimers(): Promise<void> {
        // TODO: periodic/delayed actions
        this.#saveStateTimeout = setTimeout(this.savePeriodicState.bind(this), CONFIG_SAVE_STATE_TIME);
        this.#nwkLinkStatusTimeout = setTimeout(
            this.sendPeriodicZigbeeNWKLinkStatus.bind(this),
            CONFIG_NWK_LINK_STATUS_PERIOD + Math.random() * CONFIG_NWK_LINK_STATUS_JITTER,
        );
        this.#manyToOneRouteRequestTimeout = setTimeout(this.sendPeriodicManyToOneRouteRequest.bind(this), CONFIG_NWK_CONCENTRATOR_DISCOVERY_TIME);

        await this.savePeriodicState();
        await this.sendPeriodicZigbeeNWKLinkStatus();
        await this.sendPeriodicManyToOneRouteRequest();
    }

    public async savePeriodicState(): Promise<void> {
        await this.saveState();
        this.#saveStateTimeout?.refresh();
    }

    public async sendPeriodicZigbeeNWKLinkStatus(): Promise<void> {
        const links: ZigbeeNWKLinkStatus[] = [];

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
                } catch {
                    /* ignore */
                }
            }
        }

        await this.sendZigbeeNWKLinkStatus(links);
        this.#nwkLinkStatusTimeout?.refresh();
    }

    public async sendPeriodicManyToOneRouteRequest(): Promise<void> {
        if (Date.now() > this.#lastMTORRTime + CONFIG_NWK_CONCENTRATOR_MIN_TIME) {
            await this.sendZigbeeNWKRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, ZigbeeConsts.BCAST_DEFAULT);
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
    public allowJoins(duration: number, macAssociationPermit: boolean): void {
        if (duration > 0) {
            clearTimeout(this.#allowJoinTimeout);

            this.#trustCenterPolicies.allowJoins = true;
            this.#trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
            this.#macAssociationPermit = macAssociationPermit;

            this.#allowJoinTimeout = setTimeout(this.disallowJoins.bind(this), Math.min(duration, 0xfe) * 1000);

            logger.info(`Allowed joins for ${duration} seconds (self=${macAssociationPermit})`, NS);
        } else {
            this.disallowJoins();
        }
    }

    /**
     * Revert allowing joins (keeps `allowRejoinsWithWellKnownKey=true`).
     */
    public disallowJoins(): void {
        clearTimeout(this.#allowJoinTimeout);
        this.#allowJoinTimeout = undefined;

        this.#trustCenterPolicies.allowJoins = false;
        this.#trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
        this.#macAssociationPermit = false;

        logger.info("Disallowed joins", NS);
    }

    /**
     * Put the coordinator in Green Power commissioning mode.
     * @param commissioningWindow Defaults to 180 if unspecified. Max 254. 0 means exit.
     */
    public gpEnterCommissioningMode(commissioningWindow = 180): void {
        if (commissioningWindow > 0) {
            clearTimeout(this.#gpCommissioningWindowTimeout);

            this.#gpCommissioningMode = true;

            this.#gpCommissioningWindowTimeout = setTimeout(this.gpExitCommissioningMode.bind(this), Math.min(commissioningWindow, 0xfe) * 1000);

            logger.info(`Entered Green Power commissioning mode for ${commissioningWindow} seconds`, NS);
        } else {
            this.gpExitCommissioningMode();
        }
    }

    public gpExitCommissioningMode(): void {
        clearTimeout(this.#gpCommissioningWindowTimeout);
        this.#gpCommissioningWindowTimeout = undefined;

        this.#gpCommissioningMode = false;

        logger.info("Exited Green Power commissioning mode", NS);
    }

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
                if (this.#trustCenterPolicies.allowJoins) {
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

        logger.debug(
            () =>
                `DEVICE_JOINING[src=${source16}:${source64} newAddr16=${newAddress16} initialJoin=${initialJoin} deviceType=${capabilities?.deviceType} powerSource=${capabilities?.powerSource} rxOnWhenIdle=${capabilities?.rxOnWhenIdle}] replying with status=${status}`,
            NS,
        );

        if (status === MACAssociationStatus.SUCCESS) {
            if (initialJoin || unknownRejoin) {
                this.deviceTable.set(source64!, {
                    address16: newAddress16,
                    capabilities, // TODO: only valid if not triggered by `processZigbeeAPSUpdateDevice`
                    // on initial join success, device is considered joined but unauthorized after MAC Assoc / NWK Commissioning response is sent
                    authorized: false,
                    neighbor,
                    recentLQAs: [],
                });
                this.address16ToAddress64.set(newAddress16, source64!);

                // `processZigbeeAPSUpdateDevice` has no `capabilities` info, device is joined through router, so, no indirect tx for coordinator
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
            this.routeFailures.delete(source16);

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
    public hasSourceRoute(address16: number, newEntry: SourceRouteTableEntry, existingEntries?: SourceRouteTableEntry[]): boolean {
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
    public findBestSourceRoute(
        destination16: number | undefined,
        destination64: bigint | undefined,
    ): [relayIndex: number | undefined, relayAddresses: number[] | undefined, pathCost: number | undefined] {
        if (destination16 !== undefined && destination16 >= ZigbeeConsts.BCAST_MIN) {
            return [undefined, undefined, undefined];
        }

        if (destination16 === undefined) {
            if (destination64 === undefined) {
                throw new Error("Invalid parameters", { cause: SpinelStatus.INVALID_ARGUMENT });
            }

            const device = this.deviceTable.get(destination64);

            if (device === undefined) {
                throw new Error("Unknown destination", { cause: SpinelStatus.ITEM_NOT_FOUND });
            }

            destination16 = device.address16;
        } else if (!this.address16ToAddress64.has(destination16)) {
            throw new Error("Unknown destination", { cause: SpinelStatus.ITEM_NOT_FOUND });
        }

        const sourceRouteEntries = this.sourceRouteTable.get(destination16);

        if (sourceRouteEntries === undefined || sourceRouteEntries.length === 0) {
            // cleanup
            this.sourceRouteTable.delete(destination16);

            if (!this.deviceTable.get(destination64 ?? this.address16ToAddress64.get(destination16)!)!.neighbor) {
                // force immediate MTORR
                logger.warning("No known route to destination, forcing discovery", NS);
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

                            if (!this.deviceTable.get(destination64 ?? this.address16ToAddress64.get(destination16)!)!.neighbor) {
                                // force immediate MTORR
                                logger.warning("No known route to destination, forcing discovery", NS);
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
     * @param signalStrength
     * @param signalQuality
     * @returns
     */
    public computeLQA(signalStrength: number, signalQuality?: number): number {
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
     * ZDO response to LQI_TABLE_REQUEST for coordinator
     * @see 05-3474-23 #2.4.4.3.2
     * @param startIndex
     * @returns
     */
    public getLQITableResponse(startIndex: number): Buffer {
        let neighborRouteTableIndex = 0;
        let neighborTableEntries = 0;
        // multiple of 7: [extendedPanId, eui64, nwkAddress, deviceTypeByte, permitJoiningByte, depth, lqa, ...repeat]
        const lqiTableArr: (number | bigint)[] = [];

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
                const deviceTypeByte =
                    (deviceType & 0x03) | ((rxOnWhenIdle << 2) & 0x03) | ((relationship << 4) & 0x07) | ((0 /* reserved */ << 7) & 0x01);
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
            logger.debug(() => `LQI table clipped at 255 entries to fit ZDO response (actual=${neighborTableEntries})`, NS);
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
            lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex] as bigint /* extendedPanId */, offset);
            offset += 8;
            lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex + 1] as bigint /* eui64 */, offset);
            offset += 8;
            lqiTable.writeUInt16LE(lqiTableArr[entryIndex + 2] as number /* nwkAddress */, offset);
            offset += 2;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 3] as number /* deviceTypeByte */, offset);
            offset += 1;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 4] as number /* permitJoiningByte */, offset);
            offset += 1;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 5] as number /* depth */, offset);
            offset += 1;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 6] as number /* lqa */, offset);
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
    public getRoutingTableResponse(startIndex: number): Buffer {
        let sourceRouteTableIndex = 0;
        let routingTableEntries = 0;
        // multiple of 3: [destination16, statusByte, nextHopAddress, ...repeat]
        const routingTableArr: number[] = [];

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
                    const statusByte =
                        (status & 0x07) |
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
            } catch {
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
            logger.debug(() => `Routing table clipped at 255 entries to fit ZDO response (actual=${routingTableEntries})`, NS);
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

    public getCoordinatorZDOResponse(clusterId: number, requestData: Buffer): Buffer | undefined {
        switch (clusterId) {
            case ZigbeeConsts.NETWORK_ADDRESS_REQUEST: {
                // TODO: handle reportKids & index, this payload is only for 0, 0
                return Buffer.from(this.configAttributes.address); // copy
            }
            case ZigbeeConsts.IEEE_ADDRESS_REQUEST: {
                // TODO: handle reportKids & index, this payload is only for 0, 0
                return Buffer.from(this.configAttributes.address); // copy
            }
            case ZigbeeConsts.NODE_DESCRIPTOR_REQUEST: {
                return Buffer.from(this.configAttributes.nodeDescriptor); // copy
            }
            case ZigbeeConsts.POWER_DESCRIPTOR_REQUEST: {
                return Buffer.from(this.configAttributes.powerDescriptor); // copy
            }
            case ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST: {
                return Buffer.from(this.configAttributes.simpleDescriptors); // copy
            }
            case ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST: {
                return Buffer.from(this.configAttributes.activeEndpoints); // copy
            }
            case ZigbeeConsts.LQI_TABLE_REQUEST: {
                return this.getLQITableResponse(requestData[1 /* 0 is tsn */]);
            }
            case ZigbeeConsts.ROUTING_TABLE_REQUEST: {
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
    private isZDORequestForCoordinator(clusterId: number, nwkDst16: number | undefined, nwkDst64: bigint | undefined, data: Buffer): boolean {
        if (nwkDst16 === ZigbeeConsts.COORDINATOR_ADDRESS || nwkDst64 === this.netParams.eui64) {
            // target is coordinator
            return true;
        }

        if (nwkDst16 !== undefined && nwkDst16 >= ZigbeeConsts.BCAST_MIN) {
            // target is BCAST and ZDO "of interest" is coordinator
            switch (clusterId) {
                case ZigbeeConsts.NETWORK_ADDRESS_REQUEST: {
                    return data.readBigUInt64LE(1 /* skip seq num */) === this.netParams.eui64;
                }

                case ZigbeeConsts.IEEE_ADDRESS_REQUEST:
                case ZigbeeConsts.NODE_DESCRIPTOR_REQUEST:
                case ZigbeeConsts.POWER_DESCRIPTOR_REQUEST:
                case ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST:
                case ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST: {
                    return data.readUInt16LE(1 /* skip seq num */) === ZigbeeConsts.COORDINATOR_ADDRESS;
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
    private async respondToCoordinatorZDORequest(
        data: Buffer,
        clusterId: number,
        nwkDest16: number | undefined,
        nwkDest64: bigint | undefined,
    ): Promise<void> {
        const finalPayload = this.getCoordinatorZDOResponse(clusterId, data);

        if (finalPayload) {
            // set the ZDO sequence number in outgoing payload same as incoming request
            const seqNum = data[0];
            finalPayload[0] = seqNum;

            logger.debug(() => `===> COORD_ZDO[seqNum=${seqNum} clusterId=${clusterId} nwkDst=${nwkDest16}:${nwkDest64}]`, NS);

            try {
                await this.sendZigbeeAPSData(
                    finalPayload,
                    ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
                    nwkDest16, // nwkDest16
                    nwkDest64, // nwkDest64
                    ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
                    clusterId | 0x8000, // clusterId
                    ZigbeeConsts.ZDO_PROFILE_ID, // profileId
                    ZigbeeConsts.ZDO_ENDPOINT, // destEndpoint
                    ZigbeeConsts.ZDO_ENDPOINT, // sourceEndpoint
                    undefined, // group
                );
            } catch {
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
    public async saveState(): Promise<void> {
        const state = Buffer.alloc(SaveConsts.NETWORK_DATA_SIZE + 2 + this.deviceTable.size * SaveConsts.DEVICE_DATA_SIZE);
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
        offset += ZigbeeConsts.SEC_KEYSIZE;
        state.writeUInt32LE(this.netParams.networkKeyFrameCounter + SaveConsts.FRAME_COUNTER_JUMP_OFFSET, offset);
        offset += 4;
        state.writeUInt8(this.netParams.networkKeySequenceNumber, offset);
        offset += 1;
        state.set(this.netParams.tcKey, offset);
        offset += ZigbeeConsts.SEC_KEYSIZE;
        state.writeUInt32LE(this.netParams.tcKeyFrameCounter + SaveConsts.FRAME_COUNTER_JUMP_OFFSET, offset);
        offset += 4;

        // reserved
        offset = SaveConsts.NETWORK_DATA_SIZE;

        state.writeUInt16LE(this.deviceTable.size, offset);
        offset += 2;

        for (const [device64, device] of this.deviceTable) {
            state.writeBigUInt64LE(device64, offset);
            offset += 8;
            state.writeUInt16LE(device.address16, offset);
            offset += 2;
            state.writeUInt8(device.capabilities ? encodeMACCapabilities(device.capabilities) : 0x00, offset);
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

                    if (64 + 1 + sourceRouteTableSize > SaveConsts.DEVICE_DATA_SIZE) {
                        throw new Error("Save size overflow", { cause: SpinelStatus.INTERNAL_ERROR });
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
            offset += SaveConsts.DEVICE_DATA_SIZE - 64 - 1 - sourceRouteTableSize;
        }

        await writeFile(this.savePath, state);
    }

    /**
     * Load state from file system if exists, else save "initial" state.
     * Afterwards, various keys are pre-hashed and descriptors pre-encoded.
     */
    public async loadState(): Promise<void> {
        // pre-emptive
        this.#stateLoaded = true;

        try {
            const state = await readFile(this.savePath);

            logger.debug(() => `Loaded state from ${this.savePath} (${state.byteLength} bytes)`, NS);

            if (state.byteLength < SaveConsts.NETWORK_DATA_SIZE) {
                throw new Error("Invalid save state size", { cause: SpinelStatus.INTERNAL_ERROR });
            }

            this.netParams = await this.readNetworkState(state);

            // reserved
            let offset = SaveConsts.NETWORK_DATA_SIZE;

            const deviceCount = state.readUInt16LE(offset);
            offset += 2;

            logger.debug(() => `Current save devices: ${deviceCount}`, NS);

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

                const decodedCap = capabilities !== 0 ? decodeMACCapabilities(capabilities) : undefined;

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
                    const sourceRouteEntries: SourceRouteTableEntry[] = [];

                    for (let i = 0; i < sourceRouteEntryCount; i++) {
                        const pathCost = state.readUInt8(offset);
                        offset += 1;
                        const relayAddressCount = state.readUInt8(offset);
                        offset += 1;
                        const relayAddresses: number[] = [];
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
                offset += SaveConsts.DEVICE_DATA_SIZE - 64 - 1 - sourceRouteTableSize;
            }
        } catch {
            // `this.savePath` does not exist, using constructor-given network params, do initial save
            await this.saveState();
        }

        // pre-compure hashes for default keys for faster processing
        registerDefaultHashedKeys(
            makeKeyedHashByType(ZigbeeKeyType.LINK, this.netParams.tcKey),
            makeKeyedHashByType(ZigbeeKeyType.NWK, this.netParams.networkKey),
            makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, this.netParams.tcKey),
            makeKeyedHashByType(ZigbeeKeyType.LOAD, this.netParams.tcKey),
        );

        this.#tcVerifyKeyHash = makeKeyedHash(this.netParams.tcKey, 0x03 /* input byte per spec for VERIFY_KEY */);

        const [address, nodeDescriptor, powerDescriptor, simpleDescriptors, activeEndpoints] = encodeCoordinatorDescriptors(this.netParams.eui64);

        this.configAttributes.address = address;
        this.configAttributes.nodeDescriptor = nodeDescriptor;
        this.configAttributes.powerDescriptor = powerDescriptor;
        this.configAttributes.simpleDescriptors = simpleDescriptors;
        this.configAttributes.activeEndpoints = activeEndpoints;
    }

    /**
     * Read the current network state in the save file, if any present.
     * @param readState Optional. For use in places where the state file has already been read.
     * @returns
     */
    public async readNetworkState(readState: Buffer): Promise<NetworkParameters>;
    public async readNetworkState(): Promise<NetworkParameters | undefined>;
    public async readNetworkState(readState?: Buffer): Promise<NetworkParameters | undefined> {
        try {
            const state = readState ?? (await readFile(this.savePath));
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
            const networkKey = state.subarray(offset, offset + ZigbeeConsts.SEC_KEYSIZE);
            offset += ZigbeeConsts.SEC_KEYSIZE;
            const networkKeyFrameCounter = state.readUInt32LE(offset);
            offset += 4;
            const networkKeySequenceNumber = state.readUInt8(offset);
            offset += 1;
            const tcKey = state.subarray(offset, offset + ZigbeeConsts.SEC_KEYSIZE);
            offset += ZigbeeConsts.SEC_KEYSIZE;
            const tcKeyFrameCounter = state.readUInt32LE(offset);
            offset += 4;

            logger.debug(() => `Current save network: eui64=${eui64} panId=${panId} channel=${channel}`, NS);

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
        } catch {
            /* empty */
        }
    }

    /**
     * Set the manufacturer code in the pre-encoded node descriptor
     * @param code
     */
    public setManufacturerCode(code: number): void {
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
    public async sendZDO(payload: Buffer, nwkDest16: number, nwkDest64: bigint | undefined, clusterId: number): Promise<[number, number]> {
        if (nwkDest16 === ZigbeeConsts.COORDINATOR_ADDRESS || nwkDest64 === this.netParams.eui64) {
            throw new Error("Cannot send ZDO to coordinator", { cause: SpinelStatus.INVALID_ARGUMENT });
        }

        // increment and set the ZDO sequence number in outgoing payload
        const zdoCounter = this.nextZDOSeqNum();
        payload[0] = zdoCounter;

        logger.debug(() => `===> ZDO[seqNum=${payload[0]} clusterId=${clusterId} nwkDst=${nwkDest16}:${nwkDest64}]`, NS);

        if (clusterId === ZigbeeConsts.NWK_UPDATE_REQUEST && nwkDest16 >= ZigbeeConsts.BCAST_DEFAULT && payload[5] === 0xfe) {
            // TODO: needs testing
            this.netParams.channel = convertMaskToChannels(payload.readUInt32LE(1))[0];
            this.netParams.nwkUpdateId = payload[6];

            // force saving after net params change
            await this.savePeriodicState();

            this.#pendingChangeChannel = setTimeout(
                this.setProperty.bind(this, writePropertyC(SpinelPropertyId.PHY_CHAN, this.netParams.channel)),
                ZigbeeConsts.BCAST_TIME_WINDOW,
            );
        }

        const apsCounter = await this.sendZigbeeAPSData(
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
    public async sendUnicast(
        payload: Buffer,
        profileId: number,
        clusterId: number,
        dest16: number,
        dest64: bigint | undefined,
        destEp: number,
        sourceEp: number,
    ): Promise<number> {
        if (dest16 === ZigbeeConsts.COORDINATOR_ADDRESS || dest64 === this.netParams.eui64) {
            throw new Error("Cannot send unicast to coordinator", { cause: SpinelStatus.INVALID_ARGUMENT });
        }

        return await this.sendZigbeeAPSData(
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
    public async sendGroupcast(payload: Buffer, profileId: number, clusterId: number, group: number, sourceEp: number): Promise<number> {
        return await this.sendZigbeeAPSData(
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
    public async sendBroadcast(
        payload: Buffer,
        profileId: number,
        clusterId: number,
        dest16: number,
        destEp: number,
        sourceEp: number,
    ): Promise<number> {
        if (dest16 < ZigbeeConsts.BCAST_MIN || dest16 > ZigbeeConsts.BCAST_SLEEPY) {
            throw new Error("Invalid parameters", { cause: SpinelStatus.INVALID_ARGUMENT });
        }

        return await this.sendZigbeeAPSData(
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
