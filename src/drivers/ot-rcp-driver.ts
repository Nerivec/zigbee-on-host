import EventEmitter from "node:events";

import { existsSync, mkdirSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { SpinelCommandId } from "../spinel/commands.js";
import { HDLC_TX_CHUNK_SIZE, type HdlcFrame, HdlcReservedByte, decodeHdlcFrame } from "../spinel/hdlc.js";
import { SpinelPropertyId } from "../spinel/properties.js";
import {
    SPINEL_HEADER_FLG_SPINEL,
    type SpinelFrame,
    SpinelResetReason,
    type SpinelStreamRawMetadata,
    type StreamRawConfig,
    decodeSpinelFrame,
    encodeSpinelFrame,
    getPackedUInt,
    readPropertyStreamRaw,
    readPropertyU,
    readPropertyi,
    readPropertyii,
    writePropertyC,
    writePropertyE,
    writePropertyId,
    writePropertyS,
    writePropertyStreamRaw,
    writePropertyb,
    writePropertyc,
} from "../spinel/spinel.js";
import { SpinelStatus } from "../spinel/statuses.js";
import { logger } from "../utils/logger.js";
import {
    MACAssociationStatus,
    MACCommandId,
    MACFrameAddressMode,
    MACFrameType,
    MACFrameVersion,
    type MACHeader,
    ZigbeeMACConsts,
    decodeMACFrameControl,
    decodeMACHeader,
    decodeMACPayload,
    encodeMACFrame,
    encodeMACFrameZigbee,
    encodeMACZigbeeBeacon,
} from "../zigbee/mac.js";
import {
    ZigbeeAPSCommandId,
    ZigbeeAPSConsts,
    ZigbeeAPSDeliveryMode,
    ZigbeeAPSFrameType,
    type ZigbeeAPSHeader,
    type ZigbeeAPSPayload,
    decodeZigbeeAPSFrameControl,
    decodeZigbeeAPSHeader,
    decodeZigbeeAPSPayload,
    encodeZigbeeAPSFrame,
} from "../zigbee/zigbee-aps.js";
import {
    ZigbeeNWKCommandId,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    type ZigbeeNWKHeader,
    type ZigbeeNWKLinkStatus,
    ZigbeeNWKManyToOne,
    type ZigbeeNWKMulticastControl,
    ZigbeeNWKMulticastMode,
    ZigbeeNWKRouteDiscovery,
    ZigbeeNWKStatus,
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    encodeZigbeeNWKFrame,
} from "../zigbee/zigbee-nwk.js";
import {
    ZigbeeNWKGPCommandId,
    ZigbeeNWKGPFrameType,
    type ZigbeeNWKGPHeader,
    decodeZigbeeNWKGPFrameControl,
    decodeZigbeeNWKGPHeader,
    decodeZigbeeNWKGPPayload,
} from "../zigbee/zigbee-nwkgp.js";
import {
    ZigbeeConsts,
    ZigbeeKeyType,
    type ZigbeeSecurityHeader,
    ZigbeeSecurityLevel,
    convertMaskToChannels,
    makeKeyedHash,
    makeKeyedHashByType,
    registerDefaultHashedKeys,
} from "../zigbee/zigbee.js";
import { encodeCoordinatorDescriptors } from "./descriptors.js";
import { OTRCPParser } from "./ot-rcp-parser.js";
import { OTRCPWriter } from "./ot-rcp-writer.js";

const NS = "ot-rcp-driver";

interface AdapterDriverEventMap {
    macFrame: [payload: Buffer, rssi?: number];
    fatalError: [message: string];
    frame: [sender16: number | undefined, sender64: bigint | undefined, apsHeader: ZigbeeAPSHeader, apsPayload: ZigbeeAPSPayload, rssi: number];
    gpFrame: [cmdId: number, payload: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, rssi: number];
    deviceJoined: [source16: number, source64: bigint];
    deviceRejoined: [source16: number, source64: bigint];
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
    rxOnWhenIdle: boolean;
    /** Indicates whether the device verified its key */
    authorized: boolean;
    /** Indicates whether the device is a neighbor */
    neighbor: boolean;
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
/** The number of failures that trigger an immediate concentrator route discoveries. */
// const CONFIG_NWK_CONCENTRATOR_FORCE_DISCOVERY_FAILURES = 3; // TODO
/** The time between state saving to disk. (msec) */
const CONFIG_SAVE_STATE_TIME = 60000;

export class OTRCPDriver extends EventEmitter<AdapterDriverEventMap> {
    public readonly writer: OTRCPWriter;
    public readonly parser: OTRCPParser;
    public readonly streamRawConfig: StreamRawConfig;
    public readonly savePath: string;
    private emitMACFrames: boolean;

    /**
     * Transaction ID used in Spinel frame
     *
     * NOTE: 0 is used for "no response expected/needed" (e.g. unsolicited update commands from NCP to host)
     */
    private spinelTID: number;
    /** Sequence number used in outgoing MAC frames */
    private macSeqNum: number;
    /** Sequence number used in outgoing NWK frames */
    private nwkSeqNum: number;
    /** Counter used in outgoing APS frames */
    private apsCounter: number;
    /** Sequence number used in outgoing ZDO frames */
    private zdoSeqNum: number;
    /** Whether source routing is currently enabled */
    private sourceRouting: boolean;
    /**
     * 8-bit sequence number for route requests. Incremented by 1 every time the NWK layer on a particular device issues a route request.
     */
    private routeRequestId: number;

    /** If defined, indicates we're waiting for the property with the specific payload to come in */
    private resetWaiter: { timer: NodeJS.Timeout; resolve: (frame: SpinelFrame) => void } | undefined;
    /** TID currently being awaited */
    private readonly tidWaiters: Map<
        number,
        {
            timer: NodeJS.Timeout;
            resolve: (frame: SpinelFrame) => void;
            reject: (error: Error) => void;
        }
    >;

    private stateLoaded: boolean;
    private networkUp: boolean;

    private saveStateTimeout: NodeJS.Timeout | undefined;
    private pendingChangeChannel: NodeJS.Timeout | undefined;
    private nwkLinkStatusTimeout: NodeJS.Timeout | undefined;
    private manyToOneRouteRequestTimeout: NodeJS.Timeout | undefined;

    /** Associations pending DATA_RQ from device */
    public readonly pendingAssociations: Map<bigint, { func: () => Promise<void>; timestamp: number }>;
    /** Indirect transmission for devices with rxOnWhenIdle set to false */
    public readonly indirectTransmissions: Map<bigint, { func: () => Promise<void>; timestamp: number }[]>;

    //---- Trust Center (see 05-3474-R #4.7.1)

    private readonly trustCenterPolicies: TrustCenterPolicies;
    private macAssociationPermit: boolean;
    private allowJoinTimeout: NodeJS.Timeout | undefined;

    //----- Green Power (see 14-0563-18)
    private gpCommissioningMode: boolean;
    private gpCommissioningWindowTimeout: NodeJS.Timeout | undefined;

    //---- NWK

    public netParams: NetworkParameters;
    /** pre-computed hash of default TC link key for VERIFY_KEY. set by `loadState` */
    private tcVerifyKeyHash!: Buffer;
    /** Master table of all known devices on the network. mapping by network64 */
    public readonly deviceTable: Map<bigint, DeviceTableEntry>;
    /** Lookup synced with deviceTable, maps network address to IEEE address */
    public readonly address16ToAddress64: Map<number, bigint>;
    /** mapping by network16 */
    public readonly sourceRouteTable: Map<number, SourceRouteTableEntry[]>;
    // TODO: possibility of a route/sourceRoute blacklist?

    //---- APS

    /** mapping by network16 */
    public readonly apsDeviceKeyPairSet: Map<number, APSDeviceKeyPairSet>;
    /** mapping by network16 */
    public readonly apsBindingTable: Map<number, APSBindingTable>;

    //---- Attribute

    /** Several attributes are set by `loadState` */
    public readonly configAttributes: ConfigurationAttributes;

    constructor(streamRawConfig: StreamRawConfig, netParams: NetworkParameters, saveDir: string, emitMACFrames = false) {
        super();

        if (!existsSync(saveDir)) {
            mkdirSync(saveDir);
        }

        this.savePath = join(saveDir, "zoh.save");
        this.emitMACFrames = emitMACFrames;
        this.streamRawConfig = streamRawConfig;
        this.writer = new OTRCPWriter({ highWaterMark: CONFIG_HIGHWATER_MARK });
        this.parser = new OTRCPParser({ readableHighWaterMark: CONFIG_HIGHWATER_MARK });

        this.spinelTID = -1; // start at 0 but effectively 1 returned by first nextTID() call
        this.resetWaiter = undefined;
        this.tidWaiters = new Map();

        this.macSeqNum = 0; // start at 1
        this.nwkSeqNum = 0; // start at 1
        this.apsCounter = 0; // start at 1
        this.zdoSeqNum = 0; // start at 1
        this.sourceRouting = true;
        this.routeRequestId = 0; // start at 1

        this.stateLoaded = false;
        this.networkUp = false;
        this.pendingAssociations = new Map();
        this.indirectTransmissions = new Map();

        //---- Trust Center
        this.trustCenterPolicies = {
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
        this.macAssociationPermit = false;
        this.gpCommissioningMode = false;

        //---- NWK
        this.netParams = netParams;
        this.tcVerifyKeyHash = Buffer.alloc(0); // set by `loadState`

        this.deviceTable = new Map();
        this.address16ToAddress64 = new Map();
        this.sourceRouteTable = new Map();

        //---- APS
        this.apsDeviceKeyPairSet = new Map();
        this.apsBindingTable = new Map();

        //---- Attributes
        this.configAttributes = {
            address: Buffer.alloc(0), // set by `loadState`
            nodeDescriptor: Buffer.alloc(0), // set by `loadState`
            powerDescriptor: Buffer.alloc(0), // set by `loadState`
            simpleDescriptors: Buffer.alloc(0), // set by `loadState`
            activeEndpoints: Buffer.alloc(0), // set by `loadState`
        };
    }

    // #region TIDs/counters

    /**
     * @returns increased TID offsetted by +1. [1-14] range for the "actually-used" value (0 is reserved)
     */
    private nextSpinelTID(): number {
        this.spinelTID = (this.spinelTID + 1) % CONFIG_TID_MASK;

        return this.spinelTID + 1;
    }

    private nextMACSeqNum(): number {
        this.macSeqNum = (this.macSeqNum + 1) & 0xff;

        return this.macSeqNum;
    }

    private nextNWKSeqNum(): number {
        this.nwkSeqNum = (this.nwkSeqNum + 1) & 0xff;

        return this.nwkSeqNum;
    }

    private nextAPSCounter(): number {
        this.apsCounter = (this.apsCounter + 1) & 0xff;

        return this.apsCounter;
    }

    private nextZDOSeqNum(): number {
        this.zdoSeqNum = (this.zdoSeqNum + 1) & 0xff;

        return this.zdoSeqNum;
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
        this.routeRequestId = (this.routeRequestId + 1) & 0xff;

        return this.routeRequestId;
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

        // check the protocol version to see if it is supported
        let response = await this.getProperty(SpinelPropertyId.PROTOCOL_VERSION);
        const [major, minor] = readPropertyii(SpinelPropertyId.PROTOCOL_VERSION, response.payload);

        logger.info(`Protocol version: ${major}.${minor}`, NS);

        // check the NCP version to see if a firmware update may be necessary
        response = await this.getProperty(SpinelPropertyId.NCP_VERSION);
        // recommended format: STACK-NAME/STACK-VERSION[BUILD_INFO][; OTHER_INFO]; BUILD_DATE_AND_TIME
        const ncpVersion = readPropertyU(SpinelPropertyId.NCP_VERSION, response.payload);

        logger.info(`NCP version: ${ncpVersion}`, NS);

        // check interface type to make sure that it is what we expect
        response = await this.getProperty(SpinelPropertyId.INTERFACE_TYPE);
        const interfaceType = readPropertyi(SpinelPropertyId.INTERFACE_TYPE, response.payload);

        logger.info(`Interface type: ${interfaceType}`, NS);

        response = await this.getProperty(SpinelPropertyId.RCP_API_VERSION);
        const rcpAPIVersion = readPropertyi(SpinelPropertyId.RCP_API_VERSION, response.payload);

        logger.info(`RCP API version: ${rcpAPIVersion}`, NS);

        response = await this.getProperty(SpinelPropertyId.RCP_MIN_HOST_API_VERSION);
        const rcpMinHostAPIVersion = readPropertyi(SpinelPropertyId.RCP_MIN_HOST_API_VERSION, response.payload);

        logger.info(`RCP min host API version: ${rcpMinHostAPIVersion}`, NS);

        await this.sendCommand(SpinelCommandId.RESET, Buffer.from([SpinelResetReason.STACK]), false);

        await new Promise<SpinelFrame>((resolve, reject) => {
            this.resetWaiter = {
                timer: setTimeout(() => reject(new Error("Reset timeout after 5000ms")), 5000),
                resolve,
            };
        });

        logger.info("======== Driver started ========", NS);
    }

    public async stop(): Promise<void> {
        logger.info("======== Driver stopping ========", NS);

        this.disallowJoins();
        this.gpExitCommissioningMode();

        // pre-emptive
        this.networkUp = false;

        // TODO: clear all timeouts/intervals
        clearTimeout(this.saveStateTimeout);
        clearTimeout(this.pendingChangeChannel);
        clearTimeout(this.nwkLinkStatusTimeout);
        clearTimeout(this.manyToOneRouteRequestTimeout);

        for (const [, waiter] of this.tidWaiters) {
            clearTimeout(waiter.timer);
            // waiter.reject(new Error("Driver stopping"));
        }

        this.tidWaiters.clear();

        // TODO: proper spinel/radio shutdown?
        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RAW_STREAM_ENABLED, false));
        await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, false));

        await this.saveState();

        logger.info("======== Driver stopped ========", NS);
    }

    /**
     * Performs a software reset into bootloader.
     * Will stop network if up.
     */
    public async resetIntoBootloader(): Promise<void> {
        if (this.networkUp) {
            await this.stop();
        }

        await this.sendCommand(SpinelCommandId.RESET, Buffer.from([SpinelResetReason.BOOTLOADER]), false);
    }

    // #region HDLC/Spinel

    public async onFrame(buffer: Buffer): Promise<void> {
        const hdlcFrame = decodeHdlcFrame(buffer);
        // logger.debug(() => `<--- HDLC[length=${hdlcFrame.length}]`, NS);
        const spinelFrame = decodeSpinelFrame(hdlcFrame);

        if (spinelFrame.header.flg !== SPINEL_HEADER_FLG_SPINEL) {
            // non-Spinel frame (likely BLE HCI)
            return;
        }

        logger.debug(() => `<--- SPINEL[tid=${spinelFrame.header.tid} cmdId=${spinelFrame.commandId} len=${spinelFrame.payload.byteLength}]`, NS);

        // resolve waiter if any (never for tid===0 since unsolicited frames)
        const waiter = spinelFrame.header.tid > 0 ? this.tidWaiters.get(spinelFrame.header.tid) : undefined;
        let status: SpinelStatus = SpinelStatus.OK;

        if (waiter) {
            clearTimeout(waiter.timer);
        }

        if (spinelFrame.commandId === SpinelCommandId.PROP_VALUE_IS) {
            const [propId, pOffset] = getPackedUInt(spinelFrame.payload, 0);

            switch (propId) {
                case SpinelPropertyId.STREAM_RAW: {
                    const [macData, metadata] = readPropertyStreamRaw(spinelFrame.payload, pOffset);

                    await this.onStreamRawFrame(macData, metadata);
                    break;
                }

                case SpinelPropertyId.LAST_STATUS: {
                    [status] = getPackedUInt(spinelFrame.payload, pOffset);

                    logger.debug(() => `<--- SPINEL LAST_STATUS[${SpinelStatus[status]}]`, NS);

                    // TODO: getting RESET_POWER_ON after RESET instead of RESET_SOFTWARE??
                    if (this.resetWaiter && (status === SpinelStatus.RESET_SOFTWARE || status === SpinelStatus.RESET_POWER_ON)) {
                        clearTimeout(this.resetWaiter.timer);
                        this.resetWaiter.resolve(spinelFrame);

                        this.resetWaiter = undefined;
                    }

                    break;
                }
            }
        }

        if (waiter) {
            if (status === SpinelStatus.OK) {
                waiter.resolve(spinelFrame);
            } else {
                waiter.reject(new Error(`Failed with status=${SpinelStatus[status]}`));
            }
        }

        this.tidWaiters.delete(spinelFrame.header.tid);
    }

    /**
     * Logic optimizes code paths to try to avoid more parsing when frames will eventually get ignored by detecting as early as possible.
     */
    public async onStreamRawFrame(payload: Buffer, metadata: SpinelStreamRawMetadata | undefined): Promise<void> {
        // discard MAC frames before network is started
        if (!this.networkUp) {
            return;
        }

        if (this.emitMACFrames) {
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
                await this.processMACCommandFrame(macPayload, macHeader);

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

                        if (nwkGPHeader.frameControl.frameType === ZigbeeNWKGPFrameType.DATA && nwkGPHeader.sourceId === undefined) {
                            // TODO: is this always proper?
                            logger.debug(() => "<-~- NWKGP Ignoring DATA frame without srcId", NS);
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

                        this.processZigbeeNWKGPFrame(nwkGPPayload, macHeader, nwkGPHeader, metadata?.rssi ?? 0);
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
                            await this.onZigbeeAPSACKRequest(macHeader, nwkHeader, apsHeader);
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

                        await this.onZigbeeAPSFrame(apsPayload, macHeader, nwkHeader, apsHeader, metadata?.rssi ?? 0);
                    } else if (nwkFCF.frameType === ZigbeeNWKFrameType.CMD) {
                        await this.processZigbeeNWKCommandFrame(nwkPayload, macHeader, nwkHeader);
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
            this.tidWaiters.set(tid, {
                timer: setTimeout(() => reject(new Error(`-x-> SPINEL[tid=${tid}] Timeout after ${timeout}ms`)), timeout),
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

    // #endregion

    // #region MAC Layer

    public async sendMACFrame(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<void> {
        const func = async (): Promise<void> => {
            try {
                logger.debug(() => `===> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}]`, NS);

                if (this.emitMACFrames) {
                    setImmediate(() => {
                        this.emit("macFrame", payload);
                    });
                }

                await this.setProperty(writePropertyStreamRaw(payload, this.streamRawConfig));

                logger.debug(() => `<=== MAC[seqNum=${seqNum} dst=${dest16}:${dest64}]`, NS);
            } catch (error) {
                logger.error(`=x=> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}] ${(error as Error).message}`, NS);
            }
        };

        // TODO: optimize (not needed for non-neighbor of coordinator, etc.)
        if (dest16 !== undefined || dest64 !== undefined) {
            if (dest64 === undefined && dest16 !== undefined) {
                dest64 = this.address16ToAddress64.get(dest16);
            }

            if (dest64 === undefined) {
                // if can't determine radio state, just send the packet
                await func();
            } else {
                const addrTXs = this.indirectTransmissions.get(dest64);

                if (addrTXs) {
                    addrTXs.push({
                        func,
                        timestamp: Date.now(),
                    });

                    logger.debug(
                        () => `=|=> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}] set for indirect transmission (count: ${addrTXs.length})`,
                        NS,
                    );
                } else {
                    // RX on when idle
                    await func();
                }
            }
        } else {
            // no dest info, just send the packet
            await func();
        }
    }

    public async sendMACCommand(
        cmdId: MACCommandId,
        dest16: number | undefined,
        dest64: bigint | undefined,
        extSource: boolean,
        payload: Buffer,
    ): Promise<void> {
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
                destination16: dest16,
                destination64: dest64,
                // sourcePANId: undefined, // panIdCompression=true
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: this.netParams.eui64,
                commandId: cmdId,
                fcs: 0,
            },
            payload,
        );

        await this.sendMACFrame(macSeqNum, macFrame, dest16, dest64);
    }

    public async processMACCommandFrame(data: Buffer, macHeader: MACHeader): Promise<void> {
        let offset = 0;

        logger.debug(() => `<=== MAC CMD[cmdId=${macHeader.commandId} macSrc=${macHeader.source16}:${macHeader.source64}]`, NS);

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
                logger.error(`<=x= MAC CMD Unsupported ${macHeader.commandId}.`, NS);
                return;
            }
        }

        // excess data in packet
        // if (offset < data.byteLength) {
        //     logger.debug(() => `<=== MAC CMD contained more data: ${data.toString('hex')}`, NS);
        // }
    }

    public async processMACAssocReq(data: Buffer, offset: number, macHeader: MACHeader): Promise<number> {
        const capabilities = data.readUInt8(offset);
        offset += 1;

        logger.debug(() => `<=== MAC ASSOC_REQ[cap=${capabilities}]`, NS);

        if (macHeader.source64 === undefined) {
            logger.debug(() => `<=x= MAC ASSOC_REQ[cap=${capabilities}] Invalid source64`, NS);
        } else {
            const [status, newAddress16] = await this.associate(
                undefined,
                macHeader.source64,
                true /* initial join */,
                capabilities,
                true /* neighbor */,
            );

            this.pendingAssociations.set(macHeader.source64, {
                func: async () => {
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

    public processMACAssocRsp(data: Buffer, offset: number, _macHeader: MACHeader): number {
        const address = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;

        logger.debug(() => `<=== MAC ASSOC_RSP[addr16=${address} status=${MACAssociationStatus[status]}]`, NS);

        return offset;
    }

    public async sendMACAssocRsp(dest64: bigint, newAddress16: number, status: MACAssociationStatus | number): Promise<void> {
        logger.debug(() => `===> MAC ASSOC_RSP[dst64=${dest64} newAddr16=${newAddress16} status=${status}]`, NS);

        const finalPayload = Buffer.alloc(3);
        let offset = 0;
        finalPayload.writeUInt16LE(newAddress16, offset);
        offset += 2;
        finalPayload.writeUInt8(status, offset);
        offset += 1;

        await this.sendMACCommand(
            MACCommandId.ASSOC_RSP,
            undefined, // dest16
            dest64, // dest64
            true, // sourceExt
            finalPayload,
        );
    }

    public async processMACBeaconReq(_data: Buffer, offset: number, _macHeader: MACHeader): Promise<number> {
        logger.debug(() => "<=== MAC BEACON_REQ[]", NS);

        const macSeqNum = this.nextMACSeqNum();

        logger.debug(() => `===> MAC BEACON[seqNum=${macSeqNum}]`, NS);

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
                    associationPermit: this.macAssociationPermit,
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
                txOffset: 0xffffff, // TODO: value from sniffed frames
                updateId: 0,
            }),
        );

        await this.sendMACFrame(macSeqNum, macFrame, undefined, undefined);

        return offset;
    }

    public async processMACDataReq(_data: Buffer, offset: number, macHeader: MACHeader): Promise<number> {
        logger.debug(() => "<=== MAC DATA_RQ[]", NS);

        let addr = macHeader.source64;

        if (addr === undefined && macHeader.source16 !== undefined) {
            addr = this.address16ToAddress64.get(macHeader.source16);
        }

        if (addr !== undefined) {
            const pendingAssoc = this.pendingAssociations.get(addr);

            if (pendingAssoc) {
                if (pendingAssoc.timestamp + ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT > Date.now()) {
                    await pendingAssoc.func();
                }

                // always delete, ensures no stale
                this.pendingAssociations.delete(addr);
            } else {
                const addrTXs = this.indirectTransmissions.get(addr);

                if (addrTXs !== undefined) {
                    let tx = addrTXs.shift();

                    // deal with expired tx by looking for first that isn't
                    do {
                        if (tx !== undefined && tx.timestamp + ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT > Date.now()) {
                            await tx.func();
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
     * @param cmdId
     * @param finalPayload expected to contain the full payload (including cmdId)
     * @param macDest16
     * @param nwkSource16
     * @param nwkDest16
     * @param nwkDest64
     * @param nwkRadius
     */
    public async sendZigbeeNWKCommand(
        cmdId: ZigbeeNWKCommandId,
        finalPayload: Buffer,
        nwkSecurity: boolean,
        nwkSource16: number,
        nwkDest16: number,
        nwkDest64: bigint | undefined,
        nwkRadius: number,
    ): Promise<void> {
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
        const [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
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
                    framePending: false,
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

        await this.sendMACFrame(macSeqNum, macFrame, macDest16, undefined);
    }

    public async processZigbeeNWKCommandFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<void> {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;

        logger.debug(
            () =>
                `<=== NWK CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}]`,
            NS,
        );

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
                logger.error(`<=x= NWK CMD Unsupported ${cmdId}.`, NS);
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

        logger.debug(() => `<=== NWK ROUTE_REQ[id=${id} dst=${destination16}:${destination64} pCost=${pathCost} mto=${manyToOne}]`, NS);

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
     */
    public async sendZigbeeNWKRouteReq(manyToOne: ZigbeeNWKManyToOne, destination16: number, destination64?: bigint): Promise<void> {
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

        await this.sendZigbeeNWKCommand(
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
    public processZigbeeNWKRouteReply(data: Buffer, offset: number, _macHeader: MACHeader, _nwkHeader: ZigbeeNWKHeader): number {
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
            () => `<=== NWK ROUTE_REPLY[id=${id} orig=${originator16}:${originator64} rsp=${responder16}:${responder64} pCost=${pathCost}]`,
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
     */
    public async sendZigbeeNWKRouteReply(
        requestDest1stHop16: number,
        requestRadius: number,
        requestId: number,
        originator16: number,
        responder16: number,
        originator64?: bigint,
        responder64?: bigint,
    ): Promise<void> {
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

        await this.sendZigbeeNWKCommand(
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
    public processZigbeeNWKStatus(data: Buffer, offset: number, _macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const status = data.readUInt8(offset);
        offset += 1;
        let destination: number | undefined;

        if (status === ZigbeeNWKStatus.LINK_FAILURE || status === ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            destination = data.readUInt16LE(offset);
            offset += 2;
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);

        logger.debug(() => `<=== NWK NWK_STATUS[status=${ZigbeeNWKStatus[status]} dst16=${destination} src16=${nwkHeader.source16}]`, NS);
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
     */
    public async sendZigbeeNWKStatus(requestSource16: number, status: ZigbeeNWKStatus, destination?: number): Promise<void> {
        logger.debug(() => `===> NWK NWK_STATUS[reqSrc16=${requestSource16} status=${status} dst16=${destination}]`, NS);
        let finalPayload: Buffer;

        if (status === ZigbeeNWKStatus.LINK_FAILURE || status === ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            finalPayload = Buffer.from([ZigbeeNWKCommandId.NWK_STATUS, status, destination! & 0xff, (destination! >> 8) & 0xff]);
        } else {
            finalPayload = Buffer.from([ZigbeeNWKCommandId.NWK_STATUS, status]);
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeNWKTLVs();

        await this.sendZigbeeNWKCommand(
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
    public async processZigbeeNWKLeave(data: Buffer, offset: number, _macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        const options = data.readUInt8(offset);
        offset += 1;
        const removeChildren = Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN);
        const request = Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST);
        const rejoin = Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN);

        logger.debug(() => `<=== NWK LEAVE[remChildren=${removeChildren} req=${request} rejoin=${rejoin}]`, NS);

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
     */
    public async sendZigbeeNWKLeave(destination16: number, rejoin: boolean): Promise<void> {
        logger.debug(() => `===> NWK LEAVE[dst16=${destination16} rejoin=${rejoin}]`, NS);

        const options =
            (0 & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN) |
            ((1 << 6) & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST) |
            (((rejoin ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN);
        const finalPayload = Buffer.from([ZigbeeNWKCommandId.LEAVE, options]);

        await this.sendZigbeeNWKCommand(
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
    public processZigbeeNWKRouteRecord(data: Buffer, offset: number, _macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const relayCount = data.readUInt8(offset);
        offset += 1;
        const relays: number[] = [];

        for (let i = 0; i < relayCount; i++) {
            const relay = data.readUInt16LE(offset);
            offset += 2;

            relays.push(relay);
        }

        logger.debug(() => `<=== NWK ROUTE_RECORD[relays=${relays}]`, NS);

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
            } else {
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

        logger.debug(() => `<=== NWK REJOIN_REQ[cap=${capabilities}]`, NS);

        // XXX: if !header.frameControl.security => Trust Center Rejoin
        //      => Unsecured Packets at the network layer claiming to be from existing neighbors (coordinators, routers or end devices) must not rewrite legitimate data in the nwkNeighborTable.
        //      send NWK key again in that case?
        const [status, newAddress16] = await this.associate(
            nwkHeader.source16!,
            nwkHeader.source64,
            false /* rejoin */,
            capabilities,
            macHeader.source16 === nwkHeader.source16,
        );

        await this.sendZigbeeNWKRejoinResp(nwkHeader.source16!, newAddress16, status);

        // NOTE: a device does not have to verify its trust center link key with the APSME-VERIFY-KEY services after a rejoin.

        return offset;
    }

    // NOTE: sendZigbeeNWKRejoinReq not for coordinator

    /**
     * 05-3474-R #3.4.7
     * Optional
     */
    public processZigbeeNWKRejoinResp(data: Buffer, offset: number, _macHeader: MACHeader, _nwkHeader: ZigbeeNWKHeader): number {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;

        if (status !== MACAssociationStatus.SUCCESS) {
            logger.error(`<=x= NWK REJOIN_RESP[newAddr16=${newAddress} status=${MACAssociationStatus[status]}]`, NS);
        } else {
            logger.debug(() => `<=== NWK REJOIN_RESP[newAddr16=${newAddress}]`, NS);
        }

        return offset;
    }

    /**
     * 05-3474-R #3.4.7
     * Optional
     *
     * @param requestSource16 new network address assigned to the rejoining device
     */
    public async sendZigbeeNWKRejoinResp(requestSource16: number, newAddress16: number, status: MACAssociationStatus | number): Promise<void> {
        logger.debug(() => `===> NWK REJOIN_RESP[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);

        const finalPayload = Buffer.from([ZigbeeNWKCommandId.REJOIN_RESP, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);

        await this.sendZigbeeNWKCommand(
            ZigbeeNWKCommandId.REJOIN_RESP,
            finalPayload,
            true, // nwkSecurity TODO: ??
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestSource16, // nwkDest16
            undefined, // nwkDest64
            CONFIG_NWK_MAX_HOPS, // nwkRadius
        );

        setImmediate(() => {
            this.emit("deviceRejoined", newAddress16, this.address16ToAddress64.get(newAddress16)!);
        });
    }

    /**
     * 05-3474-R #3.4.8
     */
    public processZigbeeNWKLinkStatus(data: Buffer, offset: number, _macHeader: MACHeader, _nwkHeader: ZigbeeNWKHeader): number {
        // Bit: 0 – 4        5            6           7
        //      Entry count  First frame  Last frame  Reserved
        const options = data.readUInt8(offset);
        offset += 1;
        const firstFrame = Boolean((options & ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME) >> 5);
        const lastFrame = Boolean((options & ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME) >> 6);
        const linkCount = options & ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK;
        const links: ZigbeeNWKLinkStatus[] = [];

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
        }

        logger.debug(() => {
            let linksStr = "";

            for (const link of links) {
                linksStr += `{${link.address}|in:${link.incomingCost}|out:${link.outgoingCost}}`;
            }

            return `<=== NWK LINK_STATUS[first=${firstFrame} last=${lastFrame} links=${linksStr}]`;
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
    public processZigbeeNWKReport(data: Buffer, offset: number, _macHeader: MACHeader, _nwkHeader: ZigbeeNWKHeader): number {
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

        logger.debug(() => `<=== NWK NWK_REPORT[extPANId=${extendedPANId} repType=${reportType} conflictPANIds=${conflictPANIds}]`, NS);

        return offset;
    }

    // NOTE: sendZigbeeNWKReport deprecated in R23

    /**
     * 05-3474-R #3.4.10
     */
    public processZigbeeNWKUpdate(data: Buffer, offset: number, _macHeader: MACHeader, _nwkHeader: ZigbeeNWKHeader): number {
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

        logger.debug(() => `<=== NWK NWK_UPDATE[extPANId=${extendedPANId} id=${updateId} type=${updateType} panIds=${panIds}]`, NS);
        // TODO

        return offset;
    }

    // NOTE: sendZigbeeNWKUpdate PAN ID change not supported

    /**
     * 05-3474-R #3.4.11
     */
    public async processZigbeeNWKEdTimeoutRequest(data: Buffer, offset: number, _macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
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

        logger.debug(() => `<=== NWK ED_TIMEOUT_REQUEST[reqTimeout=${requestedTimeout} conf=${configuration}]`, NS);

        await this.sendZigbeeNWKEdTimeoutResponse(nwkHeader.source16!, requestedTimeout);

        return offset;
    }

    // NOTE: sendZigbeeNWKEdTimeoutRequest not for coordinator

    /**
     * 05-3474-R #3.4.12
     */
    public processZigbeeNWKEdTimeoutResponse(data: Buffer, offset: number, _macHeader: MACHeader, _nwkHeader: ZigbeeNWKHeader): number {
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

        logger.debug(() => `<=== NWK ED_TIMEOUT_RESPONSE[status=${status} parentInfo=${parentInfo}]`, NS);
        // TODO

        return offset;
    }

    /**
     * 05-3474-R #3.4.12
     *
     * @param requestDest16
     * @param requestedTimeout Requested timeout enumeration [0-14] (mapping to actual timeout) @see processZigbeeNWKEdTimeoutRequest
     */
    public async sendZigbeeNWKEdTimeoutResponse(requestDest16: number, requestedTimeout: number): Promise<void> {
        logger.debug(() => `===> NWK ED_TIMEOUT_RESPONSE[reqDst16=${requestDest16} requestedTimeout=${requestedTimeout}]`, NS);

        // sanity check
        const status = requestedTimeout >= 0 && requestedTimeout <= 14 ? 0x00 : 0x01;
        const parentInfo = 0b00000111; // TODO: ?
        const finalPayload = Buffer.from([ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE, status, parentInfo]);

        await this.sendZigbeeNWKCommand(
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
    public processZigbeeNWKLinkPwrDelta(data: Buffer, offset: number, _macHeader: MACHeader, _nwkHeader: ZigbeeNWKHeader): number {
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

        logger.debug(() => `<=== NWK LINK_PWR_DELTA[type=${type} deltas=${deltas}]`, NS);
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

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);

        logger.debug(() => `<=== NWK COMMISSIONING_REQUEST[assocType=${assocType} cap=${capabilities}]`, NS);

        // NOTE: send Remove Device CMD to TC deny the join (or let timeout): `sendZigbeeAPSRemoveDevice`

        const [status, newAddress16] = await this.associate(
            nwkHeader.source16!,
            nwkHeader.source64,
            assocType === 0x00 /* initial join */,
            capabilities,
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
    public processZigbeeNWKCommissioningResponse(data: Buffer, offset: number, _macHeader: MACHeader, _nwkHeader: ZigbeeNWKHeader): number {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        // `ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT`, or MACAssociationStatus
        const status = data.readUInt8(offset);
        offset += 1;

        if (status !== MACAssociationStatus.SUCCESS) {
            logger.error(
                `<=x= NWK COMMISSIONING_RESPONSE[newAddr16=${newAddress} status=${MACAssociationStatus[status] ?? "NWK_ADDR_CONFLICT"}]`,
                NS,
            );
        } else {
            logger.debug(() => `<=== NWK COMMISSIONING_RESPONSE[newAddr16=${newAddress}]`, NS);
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
     */
    public async sendZigbeeNWKCommissioningResponse(
        requestSource16: number,
        newAddress16: number,
        status: MACAssociationStatus | number,
    ): Promise<void> {
        logger.debug(() => `===> NWK COMMISSIONING_RESPONSE[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);

        const finalPayload = Buffer.from([ZigbeeNWKCommandId.COMMISSIONING_RESPONSE, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);

        await this.sendZigbeeNWKCommand(
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

    public processZigbeeNWKGPFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, rssi: number): void {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;
        const framePayload = data.subarray(offset);

        if (!this.gpCommissioningMode && (cmdId === ZigbeeNWKGPCommandId.CHANNEL_REQUEST || cmdId === ZigbeeNWKGPCommandId.COMMISSIONING)) {
            logger.debug(
                () =>
                    `<=~= NWKGP[cmdId=${cmdId} dstPANId=${macHeader.destinationPANId} dst64=${macHeader.destination64} srcId=${nwkHeader.sourceId}] Not in commissioning mode`,
                NS,
            );

            return;
        }

        logger.debug(
            () => `<=== NWKGP[cmdId=${cmdId} dstPANId=${macHeader.destinationPANId} dst64=${macHeader.destination64} srcId=${nwkHeader.sourceId}]`,
            NS,
        );

        setImmediate(() => {
            this.emit("gpFrame", cmdId, framePayload, macHeader, nwkHeader, rssi);
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
    ): Promise<void> {
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
        const [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);

        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.deviceTable.get(nwkDest64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.debug(
                () =>
                    `=x=> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} nwkSec=${nwkSecurity} apsDlv=${apsDeliveryMode} apsSec=${apsSecurityHeader !== undefined}]`,
                NS,
            );

            throw new Error("Invalid APS CMD parameters: cannot determine destination");
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
                    framePending: false,
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

        await this.sendMACFrame(macSeqNum, macFrame, macDest16, undefined);
    }

    /**
     * Send a ZigBee APS DATA frame.
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
     * @returns The APS counter of the sent frame
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
        const [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);

        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.deviceTable.get(nwkDest64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.debug(
                () =>
                    `=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) nwkDiscRte=${nwkDiscoverRoute} nwkDst=${nwkDest16}:${nwkDest64} apsDlv=${apsDeliveryMode}]`,
                NS,
            );

            throw new Error("Invalid APS DATA parameters: cannot determine destination");
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;

        logger.debug(
            () =>
                `===> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) macDst16=${macDest16} nwkDiscRte=${nwkDiscoverRoute} nwkDst=${nwkDest16}:${nwkDest64} apsDlv=${apsDeliveryMode}]`,
            NS,
        );

        let multicastControl: ZigbeeNWKMulticastControl | undefined;

        if (apsDeliveryMode === ZigbeeAPSDeliveryMode.GROUP) {
            // TODO
            multicastControl = {
                mode: ZigbeeNWKMulticastMode.MEMBER,
                radius: CONFIG_NWK_MAX_HOPS,
                maxRadius: CONFIG_NWK_MAX_HOPS,
            };
        }

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
                    multicast: multicastControl !== undefined,
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
                multicastControl,
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
                    framePending: false,
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

        await this.sendMACFrame(macSeqNum, macFrame, macDest16, undefined);

        return apsCounter;
    }

    public async onZigbeeAPSACKRequest(macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void> {
        logger.debug(
            () =>
                `===> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`,
            NS,
        );

        let nwkDest16 = nwkHeader.source16;
        const [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkHeader.source64);

        if (nwkDest16 === undefined && nwkHeader.source64 !== undefined) {
            nwkDest16 = this.deviceTable.get(nwkHeader.source64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.debug(
                () =>
                    `=x=> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`,
                NS,
            );

            throw new Error("Invalid APS ACK parameters: cannot determine destination");
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
                    framePending: false,
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
        rssi: number,
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

                let processed = false;

                if (apsHeader.profileId === ZigbeeConsts.ZDO_PROFILE_ID) {
                    processed = await this.filterZDO(data, apsHeader.clusterId!, nwkHeader.source16, nwkHeader.source64);
                }

                if (!processed) {
                    if (nwkHeader.source16 === undefined && nwkHeader.source64 === undefined) {
                        logger.debug(() => "<=~= APS Ignoring frame with no sender info", NS);
                        return;
                    }

                    logger.debug(
                        () =>
                            `<=== APS DATA[src=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${nwkHeader.seqNum} profileId=${apsHeader.profileId} clusterId=${apsHeader.clusterId} srcEp=${apsHeader.sourceEndpoint} dstEp=${apsHeader.destEndpoint}]`,
                        NS,
                    );

                    setImmediate(() => {
                        // TODO: always lookup source64 if undef?
                        this.emit("frame", nwkHeader.source16, nwkHeader.source64, apsHeader, data, rssi);
                    });
                }

                break;
            }
            case ZigbeeAPSFrameType.CMD: {
                await this.processZigbeeAPSCommandFrame(data, macHeader, nwkHeader, apsHeader);
                break;
            }
            default: {
                throw new Error(`Illegal frame type ${apsHeader.frameControl.frameType}`);
            }
        }
    }

    public async processZigbeeAPSCommandFrame(
        data: Buffer,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        apsHeader: ZigbeeAPSHeader,
    ): Promise<void> {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;

        logger.debug(
            () =>
                `<=== APS CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}]`,
            NS,
        );

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
        _macHeader: MACHeader,
        _nwkHeader: ZigbeeNWKHeader,
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

                logger.debug(() => `<=== APS TRANSPORT_KEY[type=${keyType} key=${key} seqNum=${seqNum} dst64=${destination} src64=${source}]`, NS);

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

                logger.debug(() => `<=== APS TRANSPORT_KEY[type=${keyType} key=${key} dst64=${destination} src64=${source}]`, NS);
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

                logger.debug(() => `<=== APS TRANSPORT_KEY[type=${keyType} key=${key} partner64=${partner} initiatorFlag=${initiatorFlag}]`, NS);
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
     */
    public async sendZigbeeAPSTransportKeyTC(nwkDest16: number, key: Buffer, destination64: bigint): Promise<void> {
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
        await this.sendZigbeeAPSCommand(
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
     */
    public async sendZigbeeAPSTransportKeyNWK(nwkDest16: number, key: Buffer, seqNum: number, destination64: bigint): Promise<void> {
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
        await this.sendZigbeeAPSCommand(
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
     */
    public async sendZigbeeAPSTransportKeyAPP(nwkDest16: number, key: Buffer, partner: bigint, initiatorFlag: boolean): Promise<void> {
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

        await this.sendZigbeeAPSCommand(
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
        _macHeader: MACHeader,
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

        logger.debug(() => `<=== APS UPDATE_DEVICE[dev=${device16}:${device64} status=${status} src16=${nwkHeader.source16}]`, NS);

        // 0x00 = Standard Device Secured Rejoin
        // 0x01 = Standard Device Unsecured Join
        // 0x02 = Device Left
        // 0x03 = Standard Device Trust Center Rejoin
        // 0x04 – 0x07 = Reserved
        if (status === 0x01) {
            await this.associate(
                device16,
                device64,
                true /* initial join */,
                0x00,
                false /* not neighbor */,
                false,
                true /* was allowed by parent */,
            );

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
            await this.associate(device16, device64, false /* rejoin */, 0x00, false /* not neighbor */, false, true /* was allowed by parent */);
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
     */
    public async sendZigbeeAPSUpdateDevice(
        nwkDest16: number,
        device64: bigint,
        device16: number,
        status: number,
        // tlvs: unknown[],
    ): Promise<void> {
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

        await this.sendZigbeeAPSCommand(
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
        _macHeader: MACHeader,
        _nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        const target = data.readBigUInt64LE(offset);
        offset += 8;

        logger.debug(() => `<=== APS REMOVE_DEVICE[target64=${target}]`, NS);

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.3
     *
     * @param nwkDest16 parent
     * @param target64
     */
    public async sendZigbeeAPSRemoveDevice(nwkDest16: number, target64: bigint): Promise<void> {
        logger.debug(() => `===> APS REMOVE_DEVICE[target64=${target64}]`, NS);

        const finalPayload = Buffer.alloc(9);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.REMOVE_DEVICE, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(target64, offset);
        offset += 8;

        await this.sendZigbeeAPSCommand(
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
        _macHeader: MACHeader,
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

                logger.debug(() => `<=== APS REQUEST_KEY[type=${keyType} partner64=${partner}]`, NS);

                if (this.trustCenterPolicies.allowAppKeyRequest === ApplicationKeyRequestPolicy.ALLOWED) {
                    await this.sendZigbeeAPSTransportKeyAPP(
                        nwkHeader.source16!,
                        this.getOrGenerateAPPLinkKey(nwkHeader.source16!, partner),
                        partner,
                        true,
                    );
                }
                // TODO ApplicationKeyRequestPolicy.ONLY_APPROVED
            } else if (keyType === ZigbeeAPSConsts.CMD_KEY_TC_LINK) {
                logger.debug(() => `<=== APS REQUEST_KEY[type=${keyType}]`, NS);

                if (this.trustCenterPolicies.allowTCKeyRequest === TrustCenterKeyRequestPolicy.ALLOWED) {
                    await this.sendZigbeeAPSTransportKeyTC(nwkHeader.source16!, this.netParams.tcKey, device64);
                }
                // TODO TrustCenterKeyRequestPolicy.ONLY_PROVISIONAL
                //      this.apsDeviceKeyPairSet => find deviceAddress === this.deviceTable.get(nwkHeader.source).address64 => check provisional or drop msg
            }
        } else {
            logger.warning(`Received key request from unknown device src16=${nwkHeader.source16}`, NS);
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
     */
    public async sendZigbeeAPSRequestKey(nwkDest16: number, keyType: 0x02, partner64: bigint): Promise<void>;
    public async sendZigbeeAPSRequestKey(nwkDest16: number, keyType: 0x04): Promise<void>;
    public async sendZigbeeAPSRequestKey(nwkDest16: number, keyType: 0x02 | 0x04, partner64?: bigint): Promise<void> {
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

        await this.sendZigbeeAPSCommand(
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
        _macHeader: MACHeader,
        _nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        const seqNum = data.readUInt8(offset);
        offset += 1;

        logger.debug(() => `<=== APS SWITCH_KEY[seqNum=${seqNum}]`, NS);

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.5
     *
     * @param nwkDest16
     * @param seqNum SHALL contain the sequence number identifying the network key to be made active.
     */
    public async sendZigbeeAPSSwitchKey(nwkDest16: number, seqNum: number): Promise<void> {
        logger.debug(() => `===> APS SWITCH_KEY[seqNum=${seqNum}]`, NS);

        const finalPayload = Buffer.from([ZigbeeAPSCommandId.SWITCH_KEY, seqNum]);

        await this.sendZigbeeAPSCommand(
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
        _macHeader: MACHeader,
        _nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        const destination = data.readBigUInt64LE(offset);
        offset += 8;
        const tunneledAPSFrame = data.subarray(offset);
        offset += tunneledAPSFrame.byteLength;

        logger.debug(() => `<=== APS TUNNEL[dst=${destination} tAPSFrame=${tunneledAPSFrame}]`, NS);

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.6
     *
     * @param nwkDest16
     * @param destination64 SHALL be the 64-bit extended address of the device that is to receive the tunneled command
     * @param tApsCmdFrame SHALL be the APS command payload to be sent to the destination
     */
    public async sendZigbeeAPSTunnel(nwkDest16: number, destination64: bigint, tApsCmdFrame: Buffer): Promise<void> {
        logger.debug(() => `===> APS TUNNEL[dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(9 + tApsCmdFrame.byteLength);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.TUNNEL, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        finalPayload.set(tApsCmdFrame, offset);
        offset += tApsCmdFrame.byteLength;

        await this.sendZigbeeAPSCommand(
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
            logger.debug(() => `<=== APS VERIFY_KEY[type=${keyType} src64=${source} hash=${keyHash.toString("hex")}]`, NS);

            if (keyType === ZigbeeAPSConsts.CMD_KEY_TC_LINK) {
                // TODO: not valid if operating in distributed network
                const status = this.tcVerifyKeyHash.equals(keyHash) ? 0x00 /* SUCCESS */ : 0xad; /* SECURITY_FAILURE */

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
     */
    public async sendZigbeeAPSVerifyKey(nwkDest16: number, keyType: number, source64: bigint, hash: Buffer): Promise<void> {
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

        await this.sendZigbeeAPSCommand(
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
        _macHeader: MACHeader,
        _nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        const status = data.readUInt8(offset);
        offset += 8;
        const keyType = data.readUInt8(offset);
        offset += 1;
        const destination = data.readBigUInt64LE(offset);
        offset += 8;

        logger.debug(() => `<=== APS CONFIRM_KEY[status=${status} type=${keyType} dst64=${destination}]`, NS);

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.8
     *
     * @param nwkDest16
     * @param status 1-byte status code indicating the result of the operation. See Table 2.27
     * @param keyType the type of key being verified
     * @param destination64 SHALL be the 64-bit extended address of the source device of the Verify-Key message
     */
    public async sendZigbeeAPSConfirmKey(nwkDest16: number, status: number, keyType: number, destination64: bigint): Promise<void> {
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

        await this.sendZigbeeAPSCommand(
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
    }

    /**
     * 05-3474-R #4.4.11.9
     */
    public processZigbeeAPSRelayMessageDownstream(
        data: Buffer,
        offset: number,
        _macHeader: MACHeader,
        _nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        // this includes only TLVs

        // This contains the EUI64 of the unauthorized neighbor that is the intended destination of the relayed message.
        const destination64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the Trust Center to the Joining device.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;

        logger.debug(() => `<=== APS RELAY_MESSAGE_DOWNSTREAM[dst64=${destination64}]`, NS);

        return offset;
    }

    // TODO: send RELAY_MESSAGE_DOWNSTREAM

    /**
     * 05-3474-R #4.4.11.10
     */
    public processZigbeeAPSRelayMessageUpstream(
        data: Buffer,
        offset: number,
        _macHeader: MACHeader,
        _nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        // this includes only TLVs

        // This contains the EUI64 of the unauthorized neighbor that is the source of the relayed message.
        const source64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the joining device to the Trust Center.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;

        logger.debug(() => `<=== APS RELAY_MESSAGE_UPSTREAM[src64=${source64}]`, NS);

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

    public getOrGenerateAPPLinkKey(_device16: number, _partner64: bigint): Buffer {
        // TODO: whole mechanism
        return this.netParams.tcKey;
    }

    public isNetworkUp(): boolean {
        return this.networkUp;
    }

    /**
     * Set the Spinel properties required to start a MAC 802.15.4 network.
     *
     * Should be called after `start`.
     */
    public async formNetwork(): Promise<void> {
        logger.info("======== Network starting ========", NS);

        if (!this.stateLoaded) {
            throw new Error("Cannot form network before state is loaded");
        }

        // TODO: sanity checks?
        await this.setProperty(writePropertyb(SpinelPropertyId.PHY_ENABLED, true));
        await this.setProperty(writePropertyC(SpinelPropertyId.PHY_CHAN, this.netParams.channel));

        // -128 == disable
        // TODO: ?
        // await this.spinel.setProperty(writePropertyc(SpinelPropertyId.PHY_CCA_THRESHOLD, 10));

        await this.setProperty(writePropertyc(SpinelPropertyId.PHY_TX_POWER, this.netParams.txPower));

        await this.setProperty(writePropertyE(SpinelPropertyId.MAC_15_4_LADDR, this.netParams.eui64));
        await this.setProperty(writePropertyS(SpinelPropertyId.MAC_15_4_SADDR, ZigbeeConsts.COORDINATOR_ADDRESS));
        await this.setProperty(writePropertyS(SpinelPropertyId.MAC_15_4_PANID, this.netParams.panId));

        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RX_ON_WHEN_IDLE_MODE, true));
        await this.setProperty(writePropertyb(SpinelPropertyId.MAC_RAW_STREAM_ENABLED, true));

        logger.info("======== Network started ========", NS);

        this.networkUp = true;

        await this.registerTimers();
    }

    /**
     * Remove the current state file and clear all related tables.
     *
     * Will throw if state already loaded (should be called before `start`).
     */
    public async resetNetwork(): Promise<void> {
        logger.info("======== Network resetting ========", NS);

        if (this.stateLoaded) {
            throw new Error("Cannot reset network after state already loaded");
        }

        // remove `zoh.save`
        await rm(this.savePath, { force: true });

        this.deviceTable.clear();
        this.address16ToAddress64.clear();
        this.indirectTransmissions.clear();
        this.sourceRouteTable.clear();

        logger.info("======== Network reset ========", NS);
    }

    public async registerTimers(): Promise<void> {
        // TODO: periodic/delayed actions
        await this.savePeriodicState();
        await this.sendPeriodicZigbeeNWKLinkStatus();
        await this.sendPeriodicManyToOneRouteRequest();
    }

    public async savePeriodicState(): Promise<void> {
        clearTimeout(this.saveStateTimeout);
        await this.saveState();

        this.saveStateTimeout = setTimeout(async () => {
            await this.savePeriodicState();
        }, CONFIG_SAVE_STATE_TIME);
    }

    public async sendPeriodicZigbeeNWKLinkStatus(): Promise<void> {
        clearTimeout(this.nwkLinkStatusTimeout);
        const links: ZigbeeNWKLinkStatus[] = [];

        for (const [device64, entry] of this.deviceTable.entries()) {
            if (entry.neighbor) {
                // TODO: proper cost values
                const [, , pathCost] = this.findBestSourceRoute(entry.address16, device64);

                links.push({
                    address: entry.address16,
                    incomingCost: pathCost ?? 0,
                    outgoingCost: pathCost ?? 0,
                });
            }
        }

        await this.sendZigbeeNWKLinkStatus(links);

        this.nwkLinkStatusTimeout = setTimeout(
            async () => {
                await this.sendPeriodicZigbeeNWKLinkStatus();
            },
            CONFIG_NWK_LINK_STATUS_PERIOD + Math.random() * CONFIG_NWK_LINK_STATUS_JITTER,
        );
    }

    /**
     * TODO: trigger manually upon receipt of a route failure
     */
    public async sendPeriodicManyToOneRouteRequest(): Promise<void> {
        clearTimeout(this.manyToOneRouteRequestTimeout);
        await this.sendZigbeeNWKRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, ZigbeeConsts.BCAST_DEFAULT);

        this.manyToOneRouteRequestTimeout = setTimeout(async () => {
            await this.sendPeriodicManyToOneRouteRequest();
        }, CONFIG_NWK_CONCENTRATOR_DISCOVERY_TIME);
    }

    /**
     * @param duration The length of time in seconds during which the trust center will allow joins.
     * The value 0x00 and 0xff indicate that permission is disabled or enabled, respectively, without a specified time limit.
     * 0xff is clamped to 0xfe for security reasons
     * @param macAssociationPermit If true, also allow association on coordinator itself.
     */
    public allowJoins(duration: number, macAssociationPermit: boolean): void {
        if (duration > 0) {
            clearTimeout(this.allowJoinTimeout);
            this.trustCenterPolicies.allowJoins = true;
            this.trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
            this.macAssociationPermit = macAssociationPermit;

            this.allowJoinTimeout = setTimeout(this.disallowJoins.bind(this), Math.min(duration, 0xfe) * 1000);
        } else {
            this.disallowJoins();
        }
    }

    /**
     * Revert allowing joins (keeps `allowRejoinsWithWellKnownKey=true`).
     */
    public disallowJoins(): void {
        clearTimeout(this.allowJoinTimeout);

        this.trustCenterPolicies.allowJoins = false;
        this.trustCenterPolicies.allowRejoinsWithWellKnownKey = true;
        this.macAssociationPermit = false;
    }

    /**
     * Put the coordinator in Green Power commissioning mode.
     * @param commissioningWindow Defaults to 180 if unspecified. Max 254
     */
    public gpEnterCommissioningMode(commissioningWindow = 180): void {
        if (commissioningWindow > 0) {
            this.gpCommissioningMode = true;

            this.gpCommissioningWindowTimeout = setTimeout(this.gpExitCommissioningMode.bind(this), Math.min(commissioningWindow, 0xfe) * 1000);
        } else {
            this.gpExitCommissioningMode();
        }
    }

    public gpExitCommissioningMode(): void {
        clearTimeout(this.gpCommissioningWindowTimeout);

        this.gpCommissioningMode = false;
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
    private async associate(
        source16: number | undefined,
        source64: bigint | undefined,
        initialJoin: boolean,
        capabilities: number,
        neighbor: boolean,
        denyOverride?: boolean,
        allowOverride?: boolean,
    ): Promise<[status: MACAssociationStatus | number, newAddress16: number]> {
        // 0xffff when not successful and should not be retried
        let newAddress16 = source16;
        let status: MACAssociationStatus | number = MACAssociationStatus.SUCCESS;

        if (denyOverride) {
            newAddress16 = 0xffff;
            status = MACAssociationStatus.PAN_ACCESS_DENIED;
        } else if (!allowOverride) {
            if (initialJoin) {
                if (this.trustCenterPolicies.allowJoins) {
                    if (source16 === undefined) {
                        // MAC join (no source16)
                        newAddress16 = this.assignNetworkAddress();

                        if (newAddress16 === 0xffff) {
                            status = MACAssociationStatus.PAN_FULL;
                        }
                    } else if (this.address16ToAddress64.get(source16) !== undefined) {
                        // join with already taken source16
                        newAddress16 = this.assignNetworkAddress();

                        if (newAddress16 === 0xffff) {
                            status = MACAssociationStatus.PAN_FULL;
                        } else if (newAddress16 !== source16) {
                            status = ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT;
                        }
                    }
                } else {
                    newAddress16 = 0xffff;
                    status = MACAssociationStatus.PAN_ACCESS_DENIED;
                }
            } else {
                // rejoin
                // if rejoin, network address will be stored
                // if (this.trustCenterPolicies.allowRejoinsWithWellKnownKey) {
                // }
                // TODO: handle rejoin from device that previously left and was removed from known devices (could conflict on 16)
            }
        }

        // something went wrong above
        if (newAddress16 === undefined) {
            newAddress16 = 0xffff;
            status = MACAssociationStatus.PAN_ACCESS_DENIED;
        }

        logger.debug(
            () =>
                `DEVICE_JOINING[src=${source16}:${source64} newAddr16=${newAddress16} initialJoin=${initialJoin} cap=${capabilities}] replying with status=${status}`,
            NS,
        );

        if (status === MACAssociationStatus.SUCCESS) {
            if (initialJoin) {
                const rxOnWhenIdle = Boolean((capabilities & 0x08) >> 3);

                this.deviceTable.set(source64!, {
                    address16: newAddress16,
                    rxOnWhenIdle, // TODO: only valid if not triggered by `processZigbeeAPSUpdateDevice`
                    // on initial join success, device is considered joined but unauthorized after MAC Assoc / NWK Commissioning response is sent
                    authorized: false,
                    neighbor,
                });
                this.address16ToAddress64.set(newAddress16, source64!);

                // `processZigbeeAPSUpdateDevice` has no `capabilities` info, device is joined through router, so, no indirect tx for coordinator
                if (!rxOnWhenIdle && capabilities !== 0x00) {
                    this.indirectTransmissions.set(source64!, []);
                }

                // force saving after device change
                await this.savePeriodicState();
            } else {
                // TODO: rejoin
            }
        }

        return [status, newAddress16];
    }

    private async disassociate(source16: number | undefined, source64: bigint | undefined): Promise<void> {
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

            logger.debug(() => `DEVICE_LEFT[src=${source16}:${source64}]`, NS);

            setImmediate(() => {
                this.emit("deviceLeft", source16, source64);
            });

            // force saving after device change
            await this.savePeriodicState();
        }
    }

    /**
     * Finds the best source route to the destination.
     * Bails early if source routing is disabled, or destination16 is broadcast.
     * @param destination16
     * @param destination64
     * @returns
     * - request invalid or source route unavailable: [undefined, undefined, undefined]
     * - request valid and source route available and >=1 relay: [last index in relayAddresses, list of relay addresses, cost of the path]
     * - request valid and source route available and 0 relay: [undefined, undefined, cost of the path]
     */
    public findBestSourceRoute(
        destination16: number | undefined,
        destination64: bigint | undefined,
    ): [relayIndex: number | undefined, relayAddresses: number[] | undefined, pathCost: number | undefined] {
        if (!this.sourceRouting || (destination16 !== undefined && destination16 >= ZigbeeConsts.BCAST_MIN)) {
            return [undefined, undefined, undefined];
        }

        if (destination16 === undefined) {
            if (destination64 === undefined) {
                // TODO: invalid?
                return [undefined, undefined, undefined];
            }

            const device = this.deviceTable.get(destination64);

            if (device === undefined) {
                // TODO: unknown?
                return [undefined, undefined, undefined];
            }

            destination16 = device.address16;
        }

        const sourceRouteEntries = this.sourceRouteTable.get(destination16);

        if (sourceRouteEntries === undefined) {
            return [undefined, undefined, undefined];
        }

        if (sourceRouteEntries.length === 0) {
            // cleanup
            this.sourceRouteTable.delete(destination16);

            return [undefined, undefined, undefined];
        }

        if (sourceRouteEntries.length > 1) {
            // sort by lowest cost first, if more than one entry
            // TODO: add property that keeps track of error count to further sort identical cost matches?
            sourceRouteEntries.sort((a, b) => a.pathCost - b.pathCost);
        }

        const relays = sourceRouteEntries[0].relayAddresses;
        const relayLastIndex = relays.length - 1;

        if (relayLastIndex >= 0) {
            return [relayLastIndex, relays, sourceRouteEntries[0].pathCost];
        }

        return [undefined, undefined, sourceRouteEntries[0].pathCost];
    }

    // TODO: interference detection (& optionally auto channel changing)

    /**
     * Check if ZDO message is aimed at coordinator, and if it should be emitted.
     * @param data
     * @param clusterId
     * @param macDest16
     * @param nwkDest16
     * @param nwkDest64
     * @returns True if a request was sent and no further processing is needed
     */
    private async filterZDO(data: Buffer, clusterId: number, nwkDest16: number | undefined, nwkDest64: bigint | undefined): Promise<boolean> {
        let finalPayload: Buffer;

        switch (clusterId) {
            case ZigbeeConsts.NETWORK_ADDRESS_REQUEST: {
                if (data.readBigUInt64LE(1 /* skip seq num */) !== this.netParams.eui64) {
                    // target of ZDO req is not coordinator, but is request, ignore it
                    return true;
                }

                // TODO: handle reportKids & index, this payload is only for 0, 0
                finalPayload = Buffer.from(this.configAttributes.address); // copy
                break;
            }
            case ZigbeeConsts.IEEE_ADDRESS_REQUEST: {
                if (data.readUInt16LE(1 /* skip seq num */) !== ZigbeeConsts.COORDINATOR_ADDRESS) {
                    // target of ZDO req is not coordinator, but is request, ignore it
                    return true;
                }

                // TODO: handle reportKids & index, this payload is only for 0, 0
                finalPayload = Buffer.from(this.configAttributes.address); // copy
                break;
            }
            case ZigbeeConsts.NODE_DESCRIPTOR_REQUEST: {
                if (data.readUInt16LE(1 /* skip seq num */) !== ZigbeeConsts.COORDINATOR_ADDRESS) {
                    // target of ZDO req is not coordinator (nwk addr of interest), but is request, ignore it
                    return true;
                }

                finalPayload = Buffer.from(this.configAttributes.nodeDescriptor); // copy
                break;
            }
            case ZigbeeConsts.POWER_DESCRIPTOR_REQUEST: {
                if (data.readUInt16LE(1 /* skip seq num */) !== ZigbeeConsts.COORDINATOR_ADDRESS) {
                    // target of ZDO req is not coordinator (nwk addr of interest), but is request, ignore it
                    return true;
                }

                finalPayload = Buffer.from(this.configAttributes.powerDescriptor); // copy
                break;
            }
            case ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST: {
                if (data.readUInt16LE(1 /* skip seq num */) !== ZigbeeConsts.COORDINATOR_ADDRESS) {
                    // target of ZDO req is not coordinator (nwk addr of interest), but is request, ignore it
                    return true;
                }

                finalPayload = Buffer.from(this.configAttributes.simpleDescriptors); // copy
                break;
            }
            case ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST: {
                if (data.readUInt16LE(1 /* skip seq num */) !== ZigbeeConsts.COORDINATOR_ADDRESS) {
                    // target of ZDO req is not coordinator (nwk addr of interest), but is request, ignore it
                    return true;
                }

                finalPayload = Buffer.from(this.configAttributes.activeEndpoints); // copy
                break;
            }
            case ZigbeeConsts.END_DEVICE_ANNOUNCE: {
                let offset = 1; // skip seq num
                const address16 = data.readUInt16LE(offset);
                offset += 2;
                const address64 = data.readBigUInt64LE(offset);
                offset += 8;
                const capabilities = data.readUInt8(offset);
                offset += 1;

                const device = this.deviceTable.get(address64);

                if (device) {
                    // just in case
                    device.rxOnWhenIdle = Boolean((capabilities & 0x08) >> 3);

                    // TODO: ideally, this shouldn't trigger (prevents early interview process from app) until AFTER authorized=true
                    setImmediate(() => {
                        // if device is authorized, it means it completed the TC link key update, so, a rejoin
                        this.emit(device.authorized ? "deviceRejoined" : "deviceJoined", address16, address64);
                    });

                    return false;
                }

                // unknown device, should have been added by `associate`, something's not right, ignore it
                return true;
            }
            default: {
                // REQUEST type shouldn't continue
                return (clusterId & 0x8000) === 0;
            }
        }

        // set the ZDO sequence number in outgoing payload same as incoming request
        finalPayload[0] = data[0];

        logger.debug(() => `===> COORD_ZDO[seqNum=${finalPayload[0]} clusterId=${clusterId} nwkDst=${nwkDest16}:${nwkDest64}]`, NS);

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

        return true;
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
            state.writeUInt8(device.rxOnWhenIdle ? 1 : 0, offset);
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
                        throw new Error("Save size overflow");
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
        this.stateLoaded = true;

        try {
            const state = await readFile(this.savePath);

            logger.debug(() => `Loaded state from ${this.savePath} (${state.byteLength} bytes)`, NS);

            if (state.byteLength < SaveConsts.NETWORK_DATA_SIZE) {
                throw new Error("Invalid save state size");
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
                const rxOnWhenIdle = Boolean(state.readUInt8(offset));
                offset += 1;
                const authorized = Boolean(state.readUInt8(offset));
                offset += 1;
                const neighbor = Boolean(state.readUInt8(offset));
                offset += 1;

                // reserved
                offset += 64 - 13; // currently: 51

                this.deviceTable.set(address64, {
                    address16,
                    rxOnWhenIdle,
                    authorized,
                    neighbor,
                });
                this.address16ToAddress64.set(address16, address64);

                if (!rxOnWhenIdle) {
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

        this.tcVerifyKeyHash = makeKeyedHash(this.netParams.tcKey, 0x03 /* input byte per spec for VERIFY_KEY */);

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
            throw new Error("Cannot send ZDO to coordinator");
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

            this.pendingChangeChannel = setTimeout(async () => {
                await this.setProperty(writePropertyC(SpinelPropertyId.PHY_CHAN, this.netParams.channel));
            }, ZigbeeConsts.BCAST_TIME_WINDOW);
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
            throw new Error("Cannot send unicast to coordinator");
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
     * Wraps ZigBee APS DATA sending for multicast.
     * @param payload
     * @param profileId
     * @param clusterId
     * @param dest16
     * @param destEp
     * @param sourceEp
     * @returns The APS counter of the sent frame.
     */
    public async sendMulticast(
        payload: Buffer,
        profileId: number,
        clusterId: number,
        dest16: number,
        destEp: number,
        sourceEp: number,
    ): Promise<number> {
        return await this.sendZigbeeAPSData(
            payload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            dest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.GROUP, // apsDeliveryMode
            clusterId, // clusterId
            profileId, // profileId
            destEp, // destEndpoint
            sourceEp, // sourceEndpoint
            undefined, // group
        );
    }

    /**
     * Wraps ZigBee APS DATA sending for broadcast.
     * @param payload
     * @param profileId
     * @param clusterId
     * @param dest16
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
