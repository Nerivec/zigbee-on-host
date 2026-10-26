import { type ZigbeeSecurityHeader } from "./zigbee.js";
/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export declare const enum ZigbeeNWKConsts {
    FRAME_MAX_SIZE = 116,
    /** no security */
    HEADER_MIN_SIZE = 8,
    HEADER_MAX_SIZE = 30,
    PAYLOAD_MIN_SIZE = 86,
    PAYLOAD_MAX_SIZE = 108,
    /** Re: 053474r06ZB_TSC-ZigbeeSpecification.pdf */
    /** Re: 053474r17ZB_TSC-ZigbeeSpecification.pdf */
    VERSION_2007 = 2,
    VERSION_GREEN_POWER = 3,
    /** Zigbee 2004 only. */
    /** Zigbee 2006 and later */
    ROUTE_OPTION_MCAST = 64,
    /** Zigbee 2007 and later (route request only). */
    ROUTE_OPTION_DEST_EXT = 32,
    /** Zigbee 2007 and later (route request only). */
    ROUTE_OPTION_MANY_MASK = 24,
    /** Zigbee 2007 and layer (route reply only). */
    ROUTE_OPTION_RESP_EXT = 32,
    /** Zigbee 2007 and later (route reply only). */
    ROUTE_OPTION_ORIG_EXT = 16,
    ROUTE_OPTION_MANY_NONE = 0,
    ROUTE_OPTION_MANY_REC = 1,
    ROUTE_OPTION_MANY_NOREC = 2,
    CMD_ROUTE_OPTION_DEST_EXT = 32,
    CMD_ROUTE_OPTION_MANY_MASK = 24,
    CMD_ROUTE_OPTION_RESP_EXT = 32,
    CMD_ROUTE_OPTION_ORIG_EXT = 16,
    CMD_ROUTE_OPTION_MANY_NONE = 0,
    CMD_ROUTE_OPTION_MANY_REC = 1,
    CMD_ROUTE_OPTION_MANY_NOREC = 2,
    CMD_LEAVE_OPTION_REMOVE_CHILDREN = 128,
    CMD_LEAVE_OPTION_REQUEST = 64,
    CMD_LEAVE_OPTION_REJOIN = 32,
    CMD_LINK_OPTION_LAST_FRAME = 64,
    CMD_LINK_OPTION_FIRST_FRAME = 32,
    CMD_LINK_OPTION_COUNT_MASK = 31,
    CMD_LINK_INCOMING_COST_MASK = 7,
    CMD_LINK_OUTGOING_COST_MASK = 112,
    CMD_NWK_REPORT_COUNT_MASK = 31,
    CMD_NWK_REPORT_ID_MASK = 224,
    CMD_NWK_REPORT_ID_PAN_CONFLICT = 0,
    CMD_NWK_UPDATE_COUNT_MASK = 31,
    CMD_NWK_UPDATE_ID_MASK = 224,
    CMD_NWK_UPDATE_ID_PAN_UPDATE = 0,
    CMD_ED_TIMEO_RSP_PRNT_INFO_MAC_DATA_POLL_KEEPAL_SUPP = 1,
    CMD_ED_TIMEO_RSP_PRNT_INFO_ED_TIMOU_REQ_KEEPAL_SUPP = 2,
    CMD_ED_TIMEO_RSP_PRNT_INFO_PWR_NEG_SUPP = 4,
    CMD_NWK_LINK_PWR_DELTA_TYPE_MASK = 3,
    ASSOC_STATUS_ADDR_CONFLICT = 240,
    FCF_FRAME_TYPE = 3,
    FCF_VERSION = 60,
    FCF_DISCOVER_ROUTE = 192,
    /** Zigbee 2006 and Later */
    FCF_MULTICAST = 256,
    FCF_SECURITY = 512,
    /** Zigbee 2006 and Later */
    FCF_SOURCE_ROUTE = 1024,
    /** Zigbee 2006 and Later */
    FCF_EXT_DEST = 2048,
    /** Zigbee 2006 and Later */
    FCF_EXT_SOURCE = 4096,
    /** Zigbee PRO r21 */
    FCF_END_DEVICE_INITIATOR = 8192,
    MCAST_MODE = 3,
    MCAST_RADIUS = 28,
    MCAST_MAX_RADIUS = 224
}
/** Zigbee NWK FCF Frame Types */
export declare const enum ZigbeeNWKFrameType {
    DATA = 0,
    CMD = 1,
    INTERPAN = 3
}
/** Zigbee NWK Discovery Modes. */
export declare const enum ZigbeeNWKRouteDiscovery {
    SUPPRESS = 0,
    ENABLE = 1,
    FORCE = 3
}
export declare const enum ZigbeeNWKMulticastMode {
    NONMEMBER = 0,
    MEMBER = 1
}
export declare const enum ZigbeeNWKRelayType {
    NO_RELAY = 0,
    RELAY_UPSTREAM = 1,
    RELAY_DOWNSTREAM = 2
}
/** Zigbee NWK Command Types */
export declare const enum ZigbeeNWKCommandId {
    ROUTE_REQ = 1,
    ROUTE_REPLY = 2,
    NWK_STATUS = 3,
    LEAVE = 4,
    ROUTE_RECORD = 5,
    REJOIN_REQ = 6,
    REJOIN_RESP = 7,
    LINK_STATUS = 8,
    NWK_REPORT = 9,
    NWK_UPDATE = 10,
    ED_TIMEOUT_REQUEST = 11,
    ED_TIMEOUT_RESPONSE = 12,
    LINK_PWR_DELTA = 13,
    COMMISSIONING_REQUEST = 14,
    COMMISSIONING_RESPONSE = 15
}
/** Network Status Code Definitions. */
export declare enum ZigbeeNWKStatus {
    /** @deprecated in R23, should no longer be sent, but still processed (same as @see LINK_FAILURE ) */
    LEGACY_NO_ROUTE_AVAILABLE = 0,
    /** @deprecated in R23, should no longer be sent, but still processed (same as @see LINK_FAILURE ) */
    LEGACY_LINK_FAILURE = 1,
    /** This link code indicates a failure to route across a link. */
    LINK_FAILURE = 2,
    /**
     * The failure occurred as a result of a failure in the RF link to the device’s parent.
     * This status is only used locally on a device to indicate loss of communication with the parent.
     */
    PARENT_LINK_FAILURE = 9,
    /** Source routing has failed, probably indicating a link failure in one of the source route’s links. */
    SOURCE_ROUTE_FAILURE = 11,
    /** A route established as a result of a many-to-one route request has failed. */
    MANY_TO_ONE_ROUTE_FAILURE = 12,
    /** The address in the destination address field has been determined to be in use by two or more devices. */
    ADDRESS_CONFLICT = 13,
    /** The operational network PAN identifier of the device has been updated. */
    PANID_UPDATE = 15,
    /** The network address of the local device has been updated. */
    NETWORK_ADDRESS_UPDATE = 16,
    /** The NWK command ID is not known to the device. */
    UNKNOWN_COMMAND = 19,
    /** Notification to the local application that a PAN ID Conflict Report has been received by the local Network Manager. */
    PANID_CONFLICT_REPORT = 20
}
export declare const enum ZigbeeNWKManyToOne {
    /** The route request is not a many-to-one route request. */
    DISABLED = 0,
    /** The route request is a many-to-one route request and the sender supports a route record table. */
    WITH_SOURCE_ROUTING = 1,
    /** The route request is a many-to-one route request and the sender does not support a route record table. */
    WITHOUT_SOURCE_ROUTING = 2
}
export declare const enum ZigbeeNWKRouteStatus {
    ACTIVE = 0,
    DISCOVERY_UNDERWAY = 1,
    DISCOVERY_FAILED = 2,
    INACTIVE = 3
}
export type ZigbeeNWKLinkStatus = {
    /** uint16_t */
    address: number;
    /** LB uint8_t */
    incomingCost: number;
    /** HB uint8_t */
    outgoingCost: number;
};
/**
 * Frame Control Field: 0x0248, Frame Type: Data, Discover Route: Enable, Security Data
 *   .... .... .... ..00 = Frame Type: Data (0x0)
 *   .... .... ..00 10.. = Protocol Version: 2
 *   .... .... 01.. .... = Discover Route: Enable (0x1)
 *   .... ...0 .... .... = Multicast: False
 *   .... ..1. .... .... = Security: True
 *   .... .0.. .... .... = Source Route: False
 *   .... 0... .... .... = Destination: False
 *   ...0 .... .... .... = Extended Source: False
 *   ..0. .... .... .... = End Device Initiator: False
 */
export type ZigbeeNWKFrameControl = {
    frameType: ZigbeeNWKFrameType;
    protocolVersion: number;
    discoverRoute: ZigbeeNWKRouteDiscovery;
    /** Zigbee 2006 and Later @deprecated */
    multicast?: boolean;
    security: boolean;
    /** Zigbee 2006 and Later */
    sourceRoute: boolean;
    /** Zigbee 2006 and Later */
    extendedDestination: boolean;
    /** Zigbee 2006 and Later */
    extendedSource: boolean;
    /** Zigbee PRO r21 */
    endDeviceInitiator: boolean;
};
export type ZigbeeNWKHeader = {
    frameControl: ZigbeeNWKFrameControl;
    destination16?: number;
    source16?: number;
    radius?: number;
    seqNum?: number;
    destination64?: bigint;
    source64?: bigint;
    relayIndex?: number;
    relayAddresses?: number[];
    securityHeader?: ZigbeeSecurityHeader;
};
/**
 * if the security subfield is set to 1 in the frame control field, the frame payload is protected as defined by the security suite selected for that relationship.
 *
 * Octets: variable
 */
export type ZigbeeNWKPayload = Buffer;
/**
 * Decode Zigbee NWK frame control field.
 * HOT PATH: Called for every incoming Zigbee NWK frame.
 * 05-3474-23 R23.1, Table 3-19 (NWK frame control field)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Extracts protocol version, discover route, source route, and security bits per Zigbee PRO
 * - ✅ Surfaces end-device initiator bit introduced in r21 for parent-loss detection
 * - ⚠️  Leaves multicast control parsing to later stages since Zigbee seldom uses legacy flag
 * DEVICE SCOPE: All logical devices
 */
export declare function decodeZigbeeNWKFrameControl(data: Buffer, offset: number): [ZigbeeNWKFrameControl, offset: number];
/**
 * 05-3474-23 R23.1, Tables 3-20/3-21 (NWK frame formats)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Applies frame-type specific field presence rules (extended addressing, source routes)
 * - ✅ Tracks radius/sequence to support routing loops and replay protection per spec
 * - ⚠️  Skips multicast control field body since Zigbee host does not emit legacy multicast frames
 * DEVICE SCOPE: All logical devices
 */
export declare function decodeZigbeeNWKHeader(data: Buffer, offset: number, frameControl: ZigbeeNWKFrameControl): [ZigbeeNWKHeader, offset: number];
/**
 *
 * @param data
 * @param offset
 * @param decryptKey If undefined, use default pre-hashed
 * @param macSource64
 * @param frameControl
 * @param header
 */
/**
 * 05-3474-23 R23.1, Annex A (NWK security)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Invokes CCM* decrypt when security bit set, storing auxiliary header for Trust Center use
 * - ✅ Supports fallback to default hashed NWK keys when dedicated key not supplied
 * - ⚠️  Defers key selection policy (global vs. unique) to higher stack layers
 * DEVICE SCOPE: All logical devices
 */
export declare function decodeZigbeeNWKPayload(data: Buffer, offset: number, decryptKey: Buffer | undefined, macSource64: bigint | undefined, frameControl: ZigbeeNWKFrameControl, header: ZigbeeNWKHeader): ZigbeeNWKPayload;
/**
 * @param header
 * @param payload
 * @param securityHeader
 * @param encryptKey If undefined, and security=true, use default pre-hashed
 */
/**
 * 05-3474-23 R23.1, Table 3-20 (NWK data frame format) & Annex A (NWK security)
 *
 * SPEC COMPLIANCE NOTES:
 * - ✅ Constructs NWK frame then encrypts/authenticates payload per Zigbee security flag
 * - ✅ Copies authentication tag trailing bytes as mandated by CCM*
 * - ⚠️  Caller must ensure payload length respects NWK/APS combined MTU when security enabled
 * DEVICE SCOPE: All logical devices
 */
export declare function encodeZigbeeNWKFrame(header: ZigbeeNWKHeader, payload: ZigbeeNWKPayload, securityHeader?: ZigbeeSecurityHeader, encryptKey?: Buffer): Buffer;
