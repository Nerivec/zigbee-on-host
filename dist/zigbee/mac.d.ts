/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export declare const enum ZigbeeMACConsts {
    NO_ADDR16 = 65534,
    BCAST_ADDR = 65535,
    BCAST_PAN = 65535,
    HEADER_SIZE = 11,// 9 + 2 FCS
    FRAME_MAX_SIZE = 127,
    /**
     * IEEE 802.15.4-2020:
     * - aMaxMACPayloadSize(118)
     * - aMaxMACSafePayloadSize(102)
     */
    PAYLOAD_MAX_SIZE = 116,// zigbee-payload-calculator (r19)
    PAYLOAD_MAX_SAFE_SIZE = 102,
    ACK_FRAME_SIZE = 11,
    /** Frame Type Mask */
    FCF_TYPE_MASK = 7,
    FCF_SEC_EN = 8,
    FCF_FRAME_PND = 16,
    FCF_ACK_REQ = 32,
    /** known as Intra PAN prior to IEEE 802.15.4-2006 */
    FCF_PAN_ID_COMPRESSION = 64,
    FCF_SEQNO_SUPPRESSION = 256,
    FCF_IE_PRESENT = 512,
    /** destination addressing mask */
    FCF_DADDR_MASK = 3072,
    FCF_VERSION = 12288,
    /** source addressing mask */
    FCF_SADDR_MASK = 49152,
    AUX_SEC_LEVEL_MASK = 7,
    AUX_KEY_ID_MODE_MASK = 24,
    AUX_KEY_ID_MODE_SHIFT = 3,
    /** 802.15.4-2015 */
    AUX_FRAME_COUNTER_SUPPRESSION_MASK = 32,
    /** 802.15.4-2015 */
    AUX_ASN_IN_NONCE_MASK = 64,
    SUPERFRAME_BEACON_ORDER_MASK = 15,
    SUPERFRAME_ORDER_MASK = 240,
    SUPERFRAME_CAP_MASK = 3840,
    SUPERFRAME_BATT_EXTENSION_MASK = 4096,
    SUPERFRAME_COORD_MASK = 16384,
    SUPERFRAME_ASSOC_PERMIT_MASK = 32768,
    SUPERFRAME_ORDER_SHIFT = 4,
    SUPERFRAME_CAP_SHIFT = 8,
    SUPERFRAME_BATT_EXTENSION_SHIFT = 12,
    SUPERFRAME_COORD_SHIFT = 14,
    SUPERFRAME_ASSOC_PERMIT_SHIFT = 15,
    GTS_COUNT_MASK = 7,
    GTS_PERMIT_MASK = 128,
    GTS_SLOT_MASK = 15,
    GTS_LENGTH_MASK = 240,
    GTS_LENGTH_SHIFT = 4,
    PENDADDR_SHORT_MASK = 7,
    PENDADDR_LONG_MASK = 112,
    PENDADDR_LONG_SHIFT = 4,
    /** currently assumed always 2 */
    FCS_LEN = 2,
    DEVICE_TYPE_RFD = 0,
    DEVICE_TYPE_FFD = 1,
    POWER_SOURCE_OTHER = 0,
    POWER_SOURCE_MAINS = 1,
    ZIGBEE_PAYLOAD_IE_OUI = 4856091,
    ZIGBEE_BEACON_PROTOCOL_ID = 0,
    ZIGBEE_BEACON_STACK_PROFILE_MASK = 15,
    ZIGBEE_BEACON_PROTOCOL_VERSION_MASK = 240,
    ZIGBEE_BEACON_PROTOCOL_VERSION_SHIFT = 4,
    ZIGBEE_BEACON_ROUTER_CAPACITY_MASK = 1024,
    ZIGBEE_BEACON_ROUTER_CAPACITY_SHIFT = 10,
    ZIGBEE_BEACON_NETWORK_DEPTH_MASK = 30720,
    ZIGBEE_BEACON_NETWORK_DEPTH_SHIFT = 11,
    ZIGBEE_BEACON_END_DEVICE_CAPACITY_MASK = 32768,
    ZIGBEE_BEACON_END_DEVICE_CAPACITY_SHIFT = 15,
    ZIGBEE_BEACON_LENGTH = 15,
    ZIGBEE_BEACON_TX_OFFSET_MASK = 16777215,
    ZIGBEE_BEACON_UPDATE_ID_MASK = 255,
    ZIGBEE_BEACON_UPDATE_ID_SHIFT = 24
}
/** Frame Type Definitions */
export declare const enum MACFrameType {
    /** Beacon Frame */
    BEACON = 0,
    /** Data Frame */
    DATA = 1,
    /** Acknowlegement Frame */
    ACK = 2,
    /** MAC Command Frame */
    CMD = 3,
    /** reserved */
    RESERVED = 4,
    /** Multipurpose */
    MULTIPURPOSE = 5,
    /** Fragment or Frak */
    FRAGMENT = 6,
    /** Extended */
    EXTENDED = 7
}
/** Frame version definitions. */
export declare const enum MACFrameVersion {
    /** conforming to the 802.15.4-2003 standard */
    V2003 = 0,
    /** conforming to the 802.15.4-2006 standard */
    V2006 = 1,
    /** conforming to the 802.15.4-2015 standard */
    V2015 = 2,
    RESERVED = 3
}
/** Address Mode Definitions */
export declare const enum MACFrameAddressMode {
    /** PAN identifier and address field are not present. */
    NONE = 0,
    RESERVED = 1,
    /** Address field contains a 16 bit short address. */
    SHORT = 2,
    /** Address field contains a 64 bit extended address. */
    EXT = 3
}
/** Definitions for Association Response Command */
export declare enum MACAssociationStatus {
    SUCCESS = 0,
    PAN_FULL = 1,
    PAN_ACCESS_DENIED = 2
}
/** Command Frame Identifier Types Definitions */
export declare const enum MACCommandId {
    ASSOC_REQ = 1,
    ASSOC_RSP = 2,
    DISASSOC_NOTIFY = 3,
    DATA_RQ = 4,
    PANID_CONFLICT = 5,
    ORPHAN_NOTIFY = 6,
    BEACON_REQ = 7,
    COORD_REALIGN = 8,
    GTS_REQ = 9,
    TRLE_MGMT_REQ = 10,
    TRLE_MGMT_RSP = 11,
    DSME_ASSOC_REQ = 19,
    DSME_ASSOC_RSP = 20,
    DSME_GTS_REQ = 21,
    DSME_GTS_RSP = 22,
    DSME_GTS_NOTIFY = 23,
    DSME_INFO_REQ = 24,
    DSME_INFO_RSP = 25,
    DSME_BEACON_ALLOC_NOTIFY = 26,
    DSME_BEACON_COLL_NOTIFY = 27,
    DSME_LINK_REPORT = 28,
    RIT_DATA_REQ = 32,
    DBS_REQ = 33,
    DBS_RSP = 34,
    RIT_DATA_RSP = 35,
    VENDOR_SPECIFIC = 36
}
export declare const enum MACDisassociationReason {
    COORDINATOR_INITIATED = 1,
    DEVICE_INITIATED = 2
}
export declare const enum MACSecurityLevel {
    NONE = 0,
    MIC_32 = 1,
    MIC_64 = 2,
    MIC_128 = 3,
    ENC = 4,
    ENC_MIC_32 = 5,
    ENC_MIC_64 = 6,
    ENC_MIC_128 = 7
}
export declare const enum MACSecurityKeyIdMode {
    IMPLICIT = 0,
    INDEX = 1,
    EXPLICIT_4 = 2,
    EXPLICIT_8 = 3
}
/**
 * Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *   .... .... .... .001 = Frame Type: Data (0x1)
 *   .... .... .... 0... = Security Enabled: False
 *   .... .... ...0 .... = Frame Pending: False
 *   .... .... ..1. .... = Acknowledge Request: True
 *   .... .... .1.. .... = PAN ID Compression: True
 *   .... .... 0... .... = Reserved: False
 *   .... ...0 .... .... = Sequence Number Suppression: False
 *   .... ..0. .... .... = Information Elements Present: False
 *   .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *   ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *   10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 */
export type MACFrameControl = {
    frameType: MACFrameType;
    /**
     * - 0 if the frame is not cryptographically protected by the MAC sublayer
     * - 1 the frame shall be protected using the keys stored in the MAC PIB for the security relationship indicated by the current frame
     */
    securityEnabled: boolean;
    /** shall be set to 1 if the device sending the frame has additional data to send to the recipient following the current transfer */
    framePending: boolean;
    /** specifies whether an acknowledgment is required from the recipient device on receipt of a data or MAC command frame */
    ackRequest: boolean;
    panIdCompression: boolean;
    seqNumSuppress: boolean;
    /** information elements present */
    iePresent: boolean;
    destAddrMode: MACFrameAddressMode;
    frameVersion: MACFrameVersion;
    sourceAddrMode: MACFrameAddressMode;
};
export type MACAuxSecHeader = {
    securityLevel?: number;
    keyIdMode?: number;
    asn?: number;
    frameCounter?: number;
    keySourceAddr32?: number;
    keySourceAddr64?: bigint;
    keyIndex?: number;
};
export type MACSuperframeSpec = {
    beaconOrder: number;
    superframeOrder: number;
    finalCAPSlot: number;
    batteryExtension: boolean;
    panCoordinator: boolean;
    associationPermit: boolean;
};
export type MACGtsInfo = {
    permit: boolean;
    directionByte?: number;
    directions?: number[];
    addresses?: number[];
    timeLengths?: number[];
    slots?: number[];
};
export type MACPendAddr = {
    addr16List?: number[];
    addr64List?: bigint[];
};
export type MACHeaderIE = {
    ies: {
        id: number;
        length: number;
    }[];
    payloadIEPresent: boolean;
};
export type MACHeader = {
    /** uint16_t */
    frameControl: MACFrameControl;
    /** uint8_t */
    sequenceNumber?: number;
    /** uint16_t */
    destinationPANId?: number;
    /** uint16_t */
    destination16?: number;
    /** uint64_t */
    destination64?: bigint;
    /** uint16_t */
    sourcePANId?: number;
    /** uint16_t */
    source16?: number;
    /** uint64_t */
    source64?: bigint;
    /** [1-14 bytes] */
    auxSecHeader?: MACAuxSecHeader;
    /** uint16_t */
    superframeSpec?: MACSuperframeSpec;
    /** [1-.. bytes] */
    gtsInfo?: MACGtsInfo;
    /** [1-.. bytes] */
    pendAddr?: MACPendAddr;
    /** uint8_t */
    commandId?: number;
    /** [0-.. bytes] */
    headerIE?: MACHeaderIE;
    /** uint32_t */
    frameCounter?: number;
    /** uint8_t */
    keySeqCounter?: number;
    /** uint16_t */
    fcs: number;
};
/**
 * Bits:
 * - [alternatePANCoordinator: 1]
 * - [deviceType: 1]
 * - [powerSource: 1]
 * - [rxOnWhenIdle: 1]
 * - [reserved1: 1]
 * - [reserved2: 1]
 * - [securityCapability: 1]
 * - [securityCapability: 1]
 */
export type MACCapabilities = {
    /**
     * The alternate PAN coordinator sub-field is one bit in length and shall be set to 1 if this node is capable of becoming a PAN coordinator.
     * Otherwise, the alternative PAN coordinator sub-field shall be set to 0.
     */
    alternatePANCoordinator: boolean;
    /**
     * The device type sub-field is one bit in length and shall be set to 1 if this node is a full function device (FFD).
     * Otherwise, the device type sub-field shall be set to 0, indicating a reduced function device (RFD).
     */
    deviceType: number;
    /**
     * The power source sub-field is one bit in length and shall be set to 1 if the current power source is mains power.
     * Otherwise, the power source sub-field shall be set to 0.
     * This information is derived from the node current power source field of the node power descriptor.
     */
    powerSource: number;
    /**
     * The receiver on when idle sub-field is one bit in length and shall be set to 1 if the device does not disable its receiver to
     * conserve power during idle periods.
     * Otherwise, the receiver on when idle sub-field shall be set to 0 (see also section 2.3.2.4.)
     */
    rxOnWhenIdle: boolean;
    /**
     * The security capability sub-field is one bit in length and shall be set to 1 if the device is capable of sending and receiving
     * frames secured using the security suite specified in [B1].
     * Otherwise, the security capability sub-field shall be set to 0.
     */
    securityCapability: boolean;
    /** The allocate address sub-field is one bit in length and shall be set to 0 or 1. */
    allocateAddress: boolean;
};
/**
 * if the security enabled subfield is set to 1 in the frame control field, the frame payload is protected as defined by the security suite selected for that relationship.
 */
export type MACPayload = Buffer;
export declare function getMICLength(securityLevel: number): number;
/**
 * Decode MAC frame control field.
 * HOT PATH: Called for every incoming MAC frame.
 * IEEE Std 802.15.4-2020, 7.2.1 (Frame control field)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Parses Zigbee-required FCF bits and reconstructs addressing/security flags
 * - ✅ Rejects Multipurpose frame type forbidden by Zigbee MAC profile
 * - ⚠️  Leaves Information Element interpretation to higher layers by design
 * DEVICE SCOPE: All logical devices.
 */
export declare function decodeMACFrameControl(data: Buffer, offset: number): [MACFrameControl, offset: number];
/**
 * 05-3474-23 R23.1, Table 2-36 (MAC capability information field)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Maps capability bits used during association joins (device type, power, security)
 * - ✅ Preserves reserved bits as zero to comply with Zigbee profile requirements
 * - ⚠️  Leaves semantic validation (e.g., alt coordinator) to stack-context policy
 * DEVICE SCOPE: All logical devices.
 */
export declare function decodeMACCapabilities(capabilities: number): MACCapabilities;
/**
 * 05-3474-23 R23.1, Table 2-36 (MAC capability information field)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Encodes capability flags in Zigbee-defined bit order for association responses
 * - ✅ Zeroes reserved bits to maintain spec compliance
 * - ⚠️  Assumes caller verified combination viability (e.g., router capacity)
 * DEVICE SCOPE: All logical devices.
 */
export declare function encodeMACCapabilities(capabilities: MACCapabilities): number;
/**
 * IEEE Std 802.15.4-2020, 7.2.2 (MAC header fields)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * Decode MAC header from frame.
 * HOT PATH: Called for every incoming MAC frame.
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Validates addressing mode combinations and PAN ID compression per Zigbee limits
 * - ✅ Parses beacon, command, and data header extensions (GTS, pending list) as required
 * - ⚠️  Supports MAC security only for legacy 2003 mode; production security handled above MAC
 * DEVICE SCOPE: All logical devices.
 */
export declare function decodeMACHeader(data: Buffer, offset: number, frameControl: MACFrameControl): [MACHeader, offset: number];
/**
 * IEEE Std 802.15.4-2020, 7.2.2.4 (MAC payload and FCS handling)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Rejects MAC-layer security frames in line with Zigbee host design (security handled at NWK/APS)
 * - ✅ Verifies FCS presence and stores it for diagnostics per Zigbee stack requirements
 * - ⚠️  Leaves MIC validation to upper layers because MAC security is disabled
 * DEVICE SCOPE: All logical devices.
 */
export declare function decodeMACPayload(data: Buffer, offset: number, frameControl: MACFrameControl, header: MACHeader): MACPayload;
/**
 * IEEE Std 802.15.4-2020, 7.2.2 (General MAC frame format)
 * 05-3474-23 R23.1, Annex C.2 (Zigbee MAC frame subset)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Emits canonical MAC frames with Zigbee-safe payload length and CRC tail
 * - ✅ Shares encoding path with general 802.15.4 data while honouring Zigbee restrictions
 * - ⚠️  Assumes caller already prepared payload within MAC safe size
 * DEVICE SCOPE: All logical devices.
 */
export declare function encodeMACFrame(header: MACHeader, payload: Buffer): Buffer;
/** Subset of @see MACHeader */
export type MACHeaderZigbee = {
    /** uint16_t */
    frameControl: MACFrameControl;
    /** uint8_t */
    sequenceNumber?: number;
    /** uint16_t */
    destinationPANId?: number;
    /** uint16_t */
    destination16?: number;
    /** uint16_t */
    sourcePANId?: number;
    /** uint16_t */
    source16?: number;
    /** uint16_t */
    fcs: number;
};
/**
 * Encode MAC frame with hotpath for Zigbee NWK/APS payload
 * 05-3474-23 R23.1, Annex C.2.1 (Zigbee data frame rules)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Forces frame version to 2003 as mandated for Zigbee data/command frames
 * - ✅ Encodes only Zigbee-relevant addressing fields for NWK hot path efficiency
 * - ⚠️  Caller must enforce payload length not exceeding Zigbee safe payload size
 * DEVICE SCOPE: All logical devices.
 */
export declare function encodeMACFrameZigbee(header: MACHeaderZigbee, payload: Buffer): Buffer;
export type MACZigbeeBeacon = {
    protocolId: number;
    profile: number;
    version: number;
    /** Whether the device can accept join requests from routing capable devices */
    routerCapacity: boolean;
    /** The tree depth of the device, 0 indicates the network coordinator */
    deviceDepth: number;
    /** Whether the device can accept join requests from Zigbee end devices */
    endDeviceCapacity: boolean;
    extendedPANId: bigint;
    /** The time difference between a device and its parent's beacon. */
    txOffset: number;
    updateId: number;
};
/**
 * 05-3474-23 R23.1, 2.2.2 (Beacon payload format)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Parses routing and end-device capacity bits for join admission logic
 * - ✅ Retains Update ID for network parameter synchronization
 * - ⚠️  Exposes protocolId even though Zigbee fixes it to zero for diagnostics
 * DEVICE SCOPE: Beacon receivers (all logical devices)
 */
export declare function decodeMACZigbeeBeacon(data: Buffer, offset: number): MACZigbeeBeacon;
/**
 * 05-3474-23 R23.1, 2.2.2 (Beacon payload format)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Serialises Zigbee beacon descriptor using mandated masks and shifts
 * - ✅ Hardcodes protocol ID to zero per Zigbee specification
 * - ⚠️  Relies on caller to enforce txOffset bounds defined by aMaxBeaconTxOffset
 * DEVICE SCOPE: Beacon transmitters (coordinator/router)
 */
export declare function encodeMACZigbeeBeacon(beacon: MACZigbeeBeacon): Buffer;
