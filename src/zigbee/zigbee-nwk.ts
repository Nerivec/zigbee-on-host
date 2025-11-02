import { decryptZigbeePayload, encryptZigbeePayload, type ZigbeeSecurityHeader } from "./zigbee.js";

/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export const enum ZigbeeNWKConsts {
    FRAME_MAX_SIZE = 116,
    /** no security */
    HEADER_MIN_SIZE = 8,
    HEADER_MAX_SIZE = 30,
    PAYLOAD_MIN_SIZE = 86,
    PAYLOAD_MAX_SIZE = 108,

    //---- Zigbee version numbers.
    /** Re: 053474r06ZB_TSC-ZigbeeSpecification.pdf */
    // VERSION_2004 = 1,
    /** Re: 053474r17ZB_TSC-ZigbeeSpecification.pdf */
    VERSION_2007 = 2,
    VERSION_GREEN_POWER = 3,

    //---- Zigbee NWK Route Options Flags
    /** Zigbee 2004 only. */
    // ROUTE_OPTION_REPAIR = 0x80,
    /** Zigbee 2006 and later */
    ROUTE_OPTION_MCAST = 0x40,
    /** Zigbee 2007 and later (route request only). */
    ROUTE_OPTION_DEST_EXT = 0x20,
    /** Zigbee 2007 and later (route request only). */
    ROUTE_OPTION_MANY_MASK = 0x18,
    /** Zigbee 2007 and layer (route reply only). */
    ROUTE_OPTION_RESP_EXT = 0x20,
    /** Zigbee 2007 and later (route reply only). */
    ROUTE_OPTION_ORIG_EXT = 0x10,
    /* Many-to-One modes, Zigbee 2007 and later (route request only). */
    ROUTE_OPTION_MANY_NONE = 0x00,
    /* Many-to-One modes, Zigbee 2007 and later (route request only). */
    ROUTE_OPTION_MANY_REC = 0x01,
    /* Many-to-One modes, Zigbee 2007 and later (route request only). */
    ROUTE_OPTION_MANY_NOREC = 0x02,

    //---- Zigbee NWK Route Options Flags
    // CMD_ROUTE_OPTION_REPAIR = 0x80, /* Zigbee 2004 only. */
    // CMD_ROUTE_OPTION_MCAST = 0x40, /* Zigbee 2006 and later, @deprecated */
    CMD_ROUTE_OPTION_DEST_EXT = 0x20 /* Zigbee 2007 and later (route request only). */,
    CMD_ROUTE_OPTION_MANY_MASK = 0x18 /* Zigbee 2007 and later (route request only). */,
    CMD_ROUTE_OPTION_RESP_EXT = 0x20 /* Zigbee 2007 and layer (route reply only). */,
    CMD_ROUTE_OPTION_ORIG_EXT = 0x10 /* Zigbee 2007 and later (route reply only). */,

    //---- Many-to-One modes, Zigbee 2007 and later (route request only)
    CMD_ROUTE_OPTION_MANY_NONE = 0x00,
    CMD_ROUTE_OPTION_MANY_REC = 0x01,
    CMD_ROUTE_OPTION_MANY_NOREC = 0x02,

    //----  Zigbee NWK Leave Options Flags
    CMD_LEAVE_OPTION_REMOVE_CHILDREN = 0x80,
    CMD_LEAVE_OPTION_REQUEST = 0x40,
    CMD_LEAVE_OPTION_REJOIN = 0x20,

    //---- Zigbee NWK Link Status Options
    CMD_LINK_OPTION_LAST_FRAME = 0x40,
    CMD_LINK_OPTION_FIRST_FRAME = 0x20,
    CMD_LINK_OPTION_COUNT_MASK = 0x1f,

    //---- Zigbee NWK Link Status cost fields
    CMD_LINK_INCOMING_COST_MASK = 0x07,
    CMD_LINK_OUTGOING_COST_MASK = 0x70,

    //---- Zigbee NWK Report Options
    CMD_NWK_REPORT_COUNT_MASK = 0x1f,
    CMD_NWK_REPORT_ID_MASK = 0xe0,
    CMD_NWK_REPORT_ID_PAN_CONFLICT = 0x00,

    //---- Zigbee NWK Update Options
    CMD_NWK_UPDATE_COUNT_MASK = 0x1f,
    CMD_NWK_UPDATE_ID_MASK = 0xe0,
    CMD_NWK_UPDATE_ID_PAN_UPDATE = 0x00,

    //---- Zigbee NWK Values of the Parent Information Bitmask (Table 3.47)
    CMD_ED_TIMEO_RSP_PRNT_INFO_MAC_DATA_POLL_KEEPAL_SUPP = 0x01,
    CMD_ED_TIMEO_RSP_PRNT_INFO_ED_TIMOU_REQ_KEEPAL_SUPP = 0x02,
    CMD_ED_TIMEO_RSP_PRNT_INFO_PWR_NEG_SUPP = 0x04,

    //---- Zigbee NWK Link Power Delta Options
    CMD_NWK_LINK_PWR_DELTA_TYPE_MASK = 0x03,

    //---- MAC Association Status extension
    ASSOC_STATUS_ADDR_CONFLICT = 0xf0,

    //---- Zigbee NWK FCF fields
    FCF_FRAME_TYPE = 0x0003,
    FCF_VERSION = 0x003c,
    FCF_DISCOVER_ROUTE = 0x00c0,
    /** Zigbee 2006 and Later */
    FCF_MULTICAST = 0x0100,
    FCF_SECURITY = 0x0200,
    /** Zigbee 2006 and Later */
    FCF_SOURCE_ROUTE = 0x0400,
    /** Zigbee 2006 and Later */
    FCF_EXT_DEST = 0x0800,
    /** Zigbee 2006 and Later */
    FCF_EXT_SOURCE = 0x1000,
    /** Zigbee PRO r21 */
    FCF_END_DEVICE_INITIATOR = 0x2000,

    //---- Zigbee NWK Multicast Control fields - Zigbee 2006 and later
    MCAST_MODE = 0x03,
    MCAST_RADIUS = 0x1c,
    MCAST_MAX_RADIUS = 0xe0,
}

/** Zigbee NWK FCF Frame Types */
export const enum ZigbeeNWKFrameType {
    DATA = 0x00,
    CMD = 0x01,
    INTERPAN = 0x03,
}

/** Zigbee NWK Discovery Modes. */
export const enum ZigbeeNWKRouteDiscovery {
    SUPPRESS = 0x0000,
    ENABLE = 0x0001,
    FORCE = 0x0003,
}

export const enum ZigbeeNWKMulticastMode {
    NONMEMBER = 0x00,
    MEMBER = 0x01,
}

export const enum ZigbeeNWKRelayType {
    NO_RELAY = 0,
    RELAY_UPSTREAM = 1,
    RELAY_DOWNSTREAM = 2,
}

/** Zigbee NWK Command Types */
export const enum ZigbeeNWKCommandId {
    /* Route Request Command. */
    ROUTE_REQ = 0x01,
    /* Route Reply Command. */
    ROUTE_REPLY = 0x02,
    /* Network Status Command. */
    NWK_STATUS = 0x03,
    /* Leave Command. Zigbee 2006 and Later */
    LEAVE = 0x04,
    /* Route Record Command.  Zigbee 2006 and later */
    ROUTE_RECORD = 0x05,
    /* Rejoin Request Command. Zigbee 2006 and later */
    REJOIN_REQ = 0x06,
    /* Rejoin Response Command. Zigbee 2006 and later */
    REJOIN_RESP = 0x07,
    /* Link Status Command. Zigbee 2007 and later */
    LINK_STATUS = 0x08,
    /* Network Report Command. Zigbee 2007 and later */
    NWK_REPORT = 0x09,
    /* Network Update Command. Zigbee 2007 and later */
    NWK_UPDATE = 0x0a,
    /* Network End Device Timeout Request Command. r21 */
    ED_TIMEOUT_REQUEST = 0x0b,
    /* Network End Device Timeout Response Command. r21 */
    ED_TIMEOUT_RESPONSE = 0x0c,
    /* Link Power Delta Command. r22 */
    LINK_PWR_DELTA = 0x0d,
    /* Network Commissioning Request Command. r23 */
    COMMISSIONING_REQUEST = 0x0e,
    /* Network Commissioning Response Command. r23 */
    COMMISSIONING_RESPONSE = 0x0f,
}

/** Network Status Code Definitions. */
export enum ZigbeeNWKStatus {
    /** @deprecated in R23, should no longer be sent, but still processed (same as @see LINK_FAILURE ) */
    LEGACY_NO_ROUTE_AVAILABLE = 0x00,
    /** @deprecated in R23, should no longer be sent, but still processed (same as @see LINK_FAILURE ) */
    LEGACY_LINK_FAILURE = 0x01,
    /** This link code indicates a failure to route across a link. */
    LINK_FAILURE = 0x02,
    // LOW_BATTERY = 0x03, // deprecated
    // NO_ROUTING = 0x04, // deprecated
    // NO_INDIRECT = 0x05, // deprecated
    // INDIRECT_EXPIRE = 0x06, // deprecated
    // DEVICE_UNAVAIL = 0x07, // deprecated
    // ADDR_UNAVAIL = 0x08, // deprecated
    /**
     * The failure occurred as a result of a failure in the RF link to the device’s parent.
     * This status is only used locally on a device to indicate loss of communication with the parent.
     */
    PARENT_LINK_FAILURE = 0x09,
    // VALIDATE_ROUTE = 0x0a, // deprecated
    /** Source routing has failed, probably indicating a link failure in one of the source route’s links. */
    SOURCE_ROUTE_FAILURE = 0x0b,
    /** A route established as a result of a many-to-one route request has failed. */
    MANY_TO_ONE_ROUTE_FAILURE = 0x0c,
    /** The address in the destination address field has been determined to be in use by two or more devices. */
    ADDRESS_CONFLICT = 0x0d,
    // VERIFY_ADDRESS = 0x0e, // deprecated
    /** The operational network PAN identifier of the device has been updated. */
    PANID_UPDATE = 0x0f,
    /** The network address of the local device has been updated. */
    NETWORK_ADDRESS_UPDATE = 0x10,
    // BAD_FRAME_COUNTER = 0x11, // XXX: not in spec
    // BAD_KEY_SEQNO = 0x12, // XXX: not in spec
    /** The NWK command ID is not known to the device. */
    UNKNOWN_COMMAND = 0x13,
    /** Notification to the local application that a PAN ID Conflict Report has been received by the local Network Manager. */
    PANID_CONFLICT_REPORT = 0x14,
    // RESERVED = 0x15-0xff,
}

export const enum ZigbeeNWKManyToOne {
    /** The route request is not a many-to-one route request. */
    DISABLED = 0,
    /** The route request is a many-to-one route request and the sender supports a route record table. */
    WITH_SOURCE_ROUTING = 1,
    /** The route request is a many-to-one route request and the sender does not support a route record table. */
    WITHOUT_SOURCE_ROUTING = 2,
    // RESERVED = 3,
}

export const enum ZigbeeNWKRouteStatus {
    ACTIVE = 0x0,
    DISCOVERY_UNDERWAY = 0x1,
    DISCOVERY_FAILED = 0x2,
    INACTIVE = 0x3,
    // RESERVED = 0x4-0x7,
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
 */
/* @__INLINE__ */
export function decodeZigbeeNWKFrameControl(data: Buffer, offset: number): [ZigbeeNWKFrameControl, offset: number] {
    // HOT PATH: Extract NWK FCF fields with bitwise operations
    const fcf = data.readUInt16LE(offset);
    offset += 2;

    return [
        {
            frameType: fcf & ZigbeeNWKConsts.FCF_FRAME_TYPE,
            protocolVersion: (fcf & ZigbeeNWKConsts.FCF_VERSION) >> 2,
            discoverRoute: (fcf & ZigbeeNWKConsts.FCF_DISCOVER_ROUTE) >> 6,
            multicast: Boolean((fcf & ZigbeeNWKConsts.FCF_MULTICAST) >> 8),
            security: Boolean((fcf & ZigbeeNWKConsts.FCF_SECURITY) >> 9),
            sourceRoute: Boolean((fcf & ZigbeeNWKConsts.FCF_SOURCE_ROUTE) >> 10),
            extendedDestination: Boolean((fcf & ZigbeeNWKConsts.FCF_EXT_DEST) >> 11),
            extendedSource: Boolean((fcf & ZigbeeNWKConsts.FCF_EXT_SOURCE) >> 12),
            endDeviceInitiator: Boolean((fcf & ZigbeeNWKConsts.FCF_END_DEVICE_INITIATOR) >> 13),
        },
        offset,
    ];
}

function encodeZigbeeNWKFrameControl(view: Buffer, offset: number, fcf: ZigbeeNWKFrameControl): number {
    offset = view.writeUInt16LE(
        (fcf.frameType & ZigbeeNWKConsts.FCF_FRAME_TYPE) |
            ((fcf.protocolVersion << 2) & ZigbeeNWKConsts.FCF_VERSION) |
            ((fcf.discoverRoute << 6) & ZigbeeNWKConsts.FCF_DISCOVER_ROUTE) |
            (((fcf.multicast ? 1 : 0) << 8) & ZigbeeNWKConsts.FCF_MULTICAST) |
            (((fcf.security ? 1 : 0) << 9) & ZigbeeNWKConsts.FCF_SECURITY) |
            (((fcf.sourceRoute ? 1 : 0) << 10) & ZigbeeNWKConsts.FCF_SOURCE_ROUTE) |
            (((fcf.extendedDestination ? 1 : 0) << 11) & ZigbeeNWKConsts.FCF_EXT_DEST) |
            (((fcf.extendedSource ? 1 : 0) << 12) & ZigbeeNWKConsts.FCF_EXT_SOURCE) |
            (((fcf.endDeviceInitiator ? 1 : 0) << 13) & ZigbeeNWKConsts.FCF_END_DEVICE_INITIATOR),
        offset,
    );

    return offset;
}

export function decodeZigbeeNWKHeader(data: Buffer, offset: number, frameControl: ZigbeeNWKFrameControl): [ZigbeeNWKHeader, offset: number] {
    let destination16: number | undefined;
    let source16: number | undefined;
    let radius: number | undefined;
    let seqNum: number | undefined;
    let destination64: bigint | undefined;
    let source64: bigint | undefined;
    let relayIndex: number | undefined;
    let relayAddresses: number[] | undefined;

    if (frameControl.frameType !== ZigbeeNWKFrameType.INTERPAN) {
        destination16 = data.readUInt16LE(offset);
        offset += 2;
        source16 = data.readUInt16LE(offset);
        offset += 2;
        radius = data.readUInt8(offset);
        offset += 1;
        seqNum = data.readUInt8(offset);
        offset += 1;

        if (frameControl.extendedDestination) {
            destination64 = data.readBigUInt64LE(offset);
            offset += 8;
        }

        if (frameControl.extendedSource) {
            source64 = data.readBigUInt64LE(offset);
            offset += 8;
        }

        if (frameControl.multicast) {
            offset += 1;
        }

        if (frameControl.sourceRoute) {
            const relayCount = data.readUInt8(offset);
            offset += 1;
            relayIndex = data.readUInt8(offset);
            offset += 1;
            relayAddresses = [];

            for (let i = 0; i < relayCount; i++) {
                relayAddresses.push(data.readUInt16LE(offset));
                offset += 2;
            }
        }
    }

    if (offset >= data.byteLength) {
        throw new Error("Invalid NWK frame: no payload");
    }

    return [
        {
            frameControl,
            destination16,
            source16,
            radius,
            seqNum,
            destination64,
            source64,
            relayIndex,
            relayAddresses,
            securityHeader: undefined, // set later, or not
        },
        offset,
    ];
}

function encodeZigbeeNWKHeader(data: Buffer, offset: number, header: ZigbeeNWKHeader): number {
    offset = encodeZigbeeNWKFrameControl(data, offset, header.frameControl);

    if (header.frameControl.frameType !== ZigbeeNWKFrameType.INTERPAN) {
        offset = data.writeUInt16LE(header.destination16!, offset);
        offset = data.writeUInt16LE(header.source16!, offset);
        offset = data.writeUInt8(header.radius!, offset);
        offset = data.writeUInt8(header.seqNum!, offset);

        if (header.frameControl.extendedDestination) {
            offset = data.writeBigUInt64LE(header.destination64!, offset);
        }

        if (header.frameControl.extendedSource) {
            offset = data.writeBigUInt64LE(header.source64!, offset);
        }

        if (header.frameControl.sourceRoute) {
            offset = data.writeUInt8(header.relayAddresses!.length, offset);
            offset = data.writeUInt8(header.relayIndex!, offset);

            for (const relayAddress of header.relayAddresses!) {
                offset = data.writeUInt16LE(relayAddress, offset);
            }
        }
    }

    return offset;
}

/**
 *
 * @param data
 * @param offset
 * @param decryptKey If undefined, use default pre-hashed
 * @param macSource64
 * @param frameControl
 * @param header
 */
export function decodeZigbeeNWKPayload(
    data: Buffer,
    offset: number,
    decryptKey: Buffer | undefined,
    macSource64: bigint | undefined,
    frameControl: ZigbeeNWKFrameControl,
    header: ZigbeeNWKHeader,
): ZigbeeNWKPayload {
    if (frameControl.security) {
        const [payload, securityHeader, dOutOffset] = decryptZigbeePayload(data, offset, decryptKey, macSource64);
        offset = dOutOffset;
        header.securityHeader = securityHeader;

        return payload;
    }

    return data.subarray(offset);
}

/**
 * @param header
 * @param payload
 * @param securityHeader
 * @param encryptKey If undefined, and security=true, use default pre-hashed
 */
export function encodeZigbeeNWKFrame(
    header: ZigbeeNWKHeader,
    payload: ZigbeeNWKPayload,
    securityHeader?: ZigbeeSecurityHeader,
    encryptKey?: Buffer,
): Buffer {
    let offset = 0;
    const data = Buffer.alloc(ZigbeeNWKConsts.FRAME_MAX_SIZE);

    offset = encodeZigbeeNWKHeader(data, offset, header);

    if (header.frameControl.security) {
        const [cryptedPayload, authTag, eOutOffset] = encryptZigbeePayload(data, offset, payload, securityHeader!, encryptKey);
        offset = eOutOffset;
        offset += cryptedPayload.copy(data, offset);
        offset += authTag.copy(data, offset);

        return data.subarray(0, offset);
    }

    offset += payload.copy(data, offset);

    return data.subarray(0, offset);
}
