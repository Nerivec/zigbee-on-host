import type { TrustCenterPolicies } from "../zigbee-stack/stack-context";

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
