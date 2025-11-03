/**
 * const enum with sole purpose of avoiding "magic numbers" in code for well-known values
 */
export const enum ZigbeeMACConsts {
    //---- Special IEEE802.15.4 Addresses
    NO_ADDR16 = 0xfffe,
    BCAST_ADDR = 0xffff,
    BCAST_PAN = 0xffff,

    HEADER_SIZE = 11, // 9 + 2 FCS
    FRAME_MAX_SIZE = 127,
    /**
     * IEEE 802.15.4-2020:
     * - aMaxMACPayloadSize(118)
     * - aMaxMACSafePayloadSize(102)
     */
    PAYLOAD_MAX_SIZE = 116, // zigbee-payload-calculator (r19)
    PAYLOAD_MAX_SAFE_SIZE = 102,
    ACK_FRAME_SIZE = 11,

    //---- Bit-masks for the FCF
    /** Frame Type Mask */
    FCF_TYPE_MASK = 0x0007,
    FCF_SEC_EN = 0x0008,
    FCF_FRAME_PND = 0x0010,
    FCF_ACK_REQ = 0x0020,
    /** known as Intra PAN prior to IEEE 802.15.4-2006 */
    FCF_PAN_ID_COMPRESSION = 0x0040,
    FCF_SEQNO_SUPPRESSION = 0x0100,
    FCF_IE_PRESENT = 0x0200,
    /** destination addressing mask */
    FCF_DADDR_MASK = 0x0c00,
    FCF_VERSION = 0x3000,
    /** source addressing mask */
    FCF_SADDR_MASK = 0xc000,

    /* Auxiliary Security Header */
    AUX_SEC_LEVEL_MASK = 0x07,
    AUX_KEY_ID_MODE_MASK = 0x18,
    AUX_KEY_ID_MODE_SHIFT = 3,
    /** 802.15.4-2015 */
    AUX_FRAME_COUNTER_SUPPRESSION_MASK = 0x20,
    /** 802.15.4-2015 */
    AUX_ASN_IN_NONCE_MASK = 0x40,
    /* Note: 802.15.4-2015 specifies bits 6-7 as reserved, but 6 is used for ASN */
    // MAC_AUX_CTRL_RESERVED_MASK = 0x80,

    SUPERFRAME_BEACON_ORDER_MASK = 0x000f,
    SUPERFRAME_ORDER_MASK = 0x00f0,
    SUPERFRAME_CAP_MASK = 0x0f00,
    SUPERFRAME_BATT_EXTENSION_MASK = 0x1000,
    SUPERFRAME_COORD_MASK = 0x4000,
    SUPERFRAME_ASSOC_PERMIT_MASK = 0x8000,
    SUPERFRAME_ORDER_SHIFT = 4,
    SUPERFRAME_CAP_SHIFT = 8,
    SUPERFRAME_BATT_EXTENSION_SHIFT = 12,
    SUPERFRAME_COORD_SHIFT = 14,
    SUPERFRAME_ASSOC_PERMIT_SHIFT = 15,

    GTS_COUNT_MASK = 0x07,
    GTS_PERMIT_MASK = 0x80,
    GTS_SLOT_MASK = 0x0f,
    GTS_LENGTH_MASK = 0xf0,
    GTS_LENGTH_SHIFT = 4,

    PENDADDR_SHORT_MASK = 0x07,
    PENDADDR_LONG_MASK = 0x70,
    PENDADDR_LONG_SHIFT = 4,

    HEADER_IE_TYPE_MASK = 0x8000,
    HEADER_IE_ID_MASK = 0x7f80,
    HEADER_IE_LENGTH_MASK = 0x007f,
    HEADER_IE_HT1 = 0x7e,
    HEADER_IE_HT2 = 0x7f,

    /** currently assumed always 2 */
    FCS_LEN = 2,

    //---- Zigbee-specific
    ZIGBEE_PAYLOAD_IE_OUI = 0x4a191b,

    ZIGBEE_BEACON_PROTOCOL_ID = 0x00,
    ZIGBEE_BEACON_STACK_PROFILE_MASK = 0x000f,
    ZIGBEE_BEACON_PROTOCOL_VERSION_MASK = 0x00f0,
    ZIGBEE_BEACON_PROTOCOL_VERSION_SHIFT = 4,
    ZIGBEE_BEACON_ROUTER_CAPACITY_MASK = 0x0400,
    ZIGBEE_BEACON_ROUTER_CAPACITY_SHIFT = 10,
    ZIGBEE_BEACON_NETWORK_DEPTH_MASK = 0x7800,
    ZIGBEE_BEACON_NETWORK_DEPTH_SHIFT = 11,
    ZIGBEE_BEACON_END_DEVICE_CAPACITY_MASK = 0x8000,
    ZIGBEE_BEACON_END_DEVICE_CAPACITY_SHIFT = 15,
    ZIGBEE_BEACON_LENGTH = 15,

    ZIGBEE_BEACON_TX_OFFSET_MASK = 0xffffff,
    ZIGBEE_BEACON_UPDATE_ID_MASK = 0xff,
    ZIGBEE_BEACON_UPDATE_ID_SHIFT = 24,
}

/** Frame Type Definitions */
export const enum MACFrameType {
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
    EXTENDED = 7,
}

/** Frame version definitions. */
export const enum MACFrameVersion {
    /** conforming to the 802.15.4-2003 standard */
    V2003 = 0,
    /** conforming to the 802.15.4-2006 standard */
    V2006 = 1,
    /** conforming to the 802.15.4-2015 standard */
    V2015 = 2,
    RESERVED = 3,
}

/** Address Mode Definitions */
export const enum MACFrameAddressMode {
    /** PAN identifier and address field are not present. */
    NONE = 0,
    RESERVED = 1,
    /** Address field contains a 16 bit short address. */
    SHORT = 2,
    /** Address field contains a 64 bit extended address. */
    EXT = 3,
}

/** Definitions for Association Response Command */
export enum MACAssociationStatus {
    SUCCESS = 0x00,
    PAN_FULL = 0x01,
    PAN_ACCESS_DENIED = 0x02,
}

/** Command Frame Identifier Types Definitions */
export const enum MACCommandId {
    ASSOC_REQ = 0x01,
    ASSOC_RSP = 0x02,
    DISASSOC_NOTIFY = 0x03,
    DATA_RQ = 0x04,
    PANID_CONFLICT = 0x05,
    ORPHAN_NOTIFY = 0x06,
    BEACON_REQ = 0x07,
    COORD_REALIGN = 0x08,
    GTS_REQ = 0x09,
    TRLE_MGMT_REQ = 0x0a,
    TRLE_MGMT_RSP = 0x0b,
    /* 0x0c-0x12 reserved in IEEE802.15.4-2015 */
    DSME_ASSOC_REQ = 0x13,
    DSME_ASSOC_RSP = 0x14,
    DSME_GTS_REQ = 0x15,
    DSME_GTS_RSP = 0x16,
    DSME_GTS_NOTIFY = 0x17,
    DSME_INFO_REQ = 0x18,
    DSME_INFO_RSP = 0x19,
    DSME_BEACON_ALLOC_NOTIFY = 0x1a,
    DSME_BEACON_COLL_NOTIFY = 0x1b,
    DSME_LINK_REPORT = 0x1c,
    /* 0x1d-0x1f reserved in IEEE802.15.4-2015 */
    RIT_DATA_REQ = 0x20,
    DBS_REQ = 0x21,
    DBS_RSP = 0x22,
    RIT_DATA_RSP = 0x23,
    VENDOR_SPECIFIC = 0x24,
    /* 0x25-0xff reserved in IEEE802.15.4-2015 */
}

export const enum MACDisassociationReason {
    COORDINATOR_INITIATED = 0x01,
    DEVICE_INITIATED = 0x02,
}

export const enum MACSecurityLevel {
    NONE = 0x00,
    MIC_32 = 0x01,
    MIC_64 = 0x02,
    MIC_128 = 0x03,
    ENC = 0x04,
    ENC_MIC_32 = 0x05,
    ENC_MIC_64 = 0x06,
    ENC_MIC_128 = 0x07,
}

export const enum MACSecurityKeyIdMode {
    IMPLICIT = 0x00,
    INDEX = 0x01,
    EXPLICIT_4 = 0x02,
    EXPLICIT_8 = 0x03,
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
    // reserved: number;
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
    frameCounterSuppression: boolean;
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
    // reserved1: number;
    // reserved2: number;
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

/* Compute the MIC length. */
export function getMICLength(securityLevel: number): number {
    return (0x2 << (securityLevel & 0x3)) & ~0x3;
}

/**
 * Decode MAC frame control field.
 * HOT PATH: Called for every incoming MAC frame.
 */
/* @__INLINE__ */
export function decodeMACFrameControl(data: Buffer, offset: number): [MACFrameControl, offset: number] {
    // HOT PATH: Read FCF and extract fields with bitwise operations
    const fcf = data.readUInt16LE(offset);
    offset += 2;
    const frameType = fcf & ZigbeeMACConsts.FCF_TYPE_MASK;

    if (frameType === MACFrameType.MULTIPURPOSE) {
        throw new Error(`Unsupported MAC frame type MULTIPURPOSE (${frameType})`);
    }

    return [
        {
            frameType,
            securityEnabled: Boolean((fcf & ZigbeeMACConsts.FCF_SEC_EN) >> 3),
            framePending: Boolean((fcf & ZigbeeMACConsts.FCF_FRAME_PND) >> 4),
            ackRequest: Boolean((fcf & ZigbeeMACConsts.FCF_ACK_REQ) >> 5),
            panIdCompression: Boolean((fcf & ZigbeeMACConsts.FCF_PAN_ID_COMPRESSION) >> 6),
            /* bit 7 reserved */
            seqNumSuppress: Boolean((fcf & ZigbeeMACConsts.FCF_SEQNO_SUPPRESSION) >> 8),
            iePresent: Boolean((fcf & ZigbeeMACConsts.FCF_IE_PRESENT) >> 9),
            destAddrMode: (fcf & ZigbeeMACConsts.FCF_DADDR_MASK) >> 10,
            frameVersion: (fcf & ZigbeeMACConsts.FCF_VERSION) >> 12,
            sourceAddrMode: (fcf & ZigbeeMACConsts.FCF_SADDR_MASK) >> 14,
        },
        offset,
    ];
}

function encodeMACFrameControl(data: Buffer, offset: number, fcf: MACFrameControl): number {
    if (fcf.frameType === MACFrameType.MULTIPURPOSE) {
        throw new Error(`Unsupported MAC frame type MULTIPURPOSE (${fcf.frameType})`);
    }

    offset = data.writeUInt16LE(
        (fcf.frameType & ZigbeeMACConsts.FCF_TYPE_MASK) |
            (((fcf.securityEnabled ? 1 : 0) << 3) & ZigbeeMACConsts.FCF_SEC_EN) |
            (((fcf.framePending ? 1 : 0) << 4) & ZigbeeMACConsts.FCF_FRAME_PND) |
            (((fcf.ackRequest ? 1 : 0) << 5) & ZigbeeMACConsts.FCF_ACK_REQ) |
            (((fcf.panIdCompression ? 1 : 0) << 6) & ZigbeeMACConsts.FCF_PAN_ID_COMPRESSION) |
            /* bit 7 reserved */
            (((fcf.seqNumSuppress ? 1 : 0) << 8) & ZigbeeMACConsts.FCF_SEQNO_SUPPRESSION) |
            (((fcf.iePresent ? 1 : 0) << 9) & ZigbeeMACConsts.FCF_IE_PRESENT) |
            ((fcf.destAddrMode << 10) & ZigbeeMACConsts.FCF_DADDR_MASK) |
            ((fcf.frameVersion << 12) & ZigbeeMACConsts.FCF_VERSION) |
            ((fcf.sourceAddrMode << 14) & ZigbeeMACConsts.FCF_SADDR_MASK),
        offset,
    );

    return offset;
}

function decodeMACAuxSecHeader(data: Buffer, offset: number, frameControl: MACFrameControl): [MACAuxSecHeader, offset: number] {
    let frameCounterSuppression = false;
    let asn: number | undefined;
    let frameCounter: number | undefined;
    let keySourceAddr32: number | undefined;
    let keySourceAddr64: bigint | undefined;
    let keyIndex: number | undefined;

    const securityControl = data.readUInt8(offset);
    offset += 1;
    const securityLevel = securityControl & ZigbeeMACConsts.AUX_SEC_LEVEL_MASK;
    const keyIdMode = (securityControl & ZigbeeMACConsts.AUX_KEY_ID_MODE_MASK) >> ZigbeeMACConsts.AUX_KEY_ID_MODE_SHIFT;

    if (frameControl.frameVersion === MACFrameVersion.V2015) {
        frameCounterSuppression = Boolean(securityControl & ZigbeeMACConsts.AUX_FRAME_COUNTER_SUPPRESSION_MASK);
        // TODO: correct??
        asn = (securityControl & ZigbeeMACConsts.AUX_ASN_IN_NONCE_MASK) >> 6;
    }

    if (!frameCounterSuppression) {
        frameCounter = data.readUInt32LE(offset);
        offset += 4;
    }

    if (keyIdMode !== MACSecurityKeyIdMode.IMPLICIT) {
        if (keyIdMode === MACSecurityKeyIdMode.EXPLICIT_4) {
            keySourceAddr32 = data.readUInt32LE(offset);
            offset += 4;
        } else if (keyIdMode === MACSecurityKeyIdMode.EXPLICIT_8) {
            keySourceAddr64 = data.readBigUInt64LE(offset);
            offset += 8;
        }

        keyIndex = data.readUInt8(offset);
        offset += 1;
    }

    return [
        {
            securityLevel,
            keyIdMode,
            frameCounterSuppression,
            asn,
            frameCounter,
            keySourceAddr32,
            keySourceAddr64,
            keyIndex,
        },
        offset,
    ];
}

// function encodeMACAuxSecHeader(data: Buffer, offset: number): number {}

function decodeMACSuperframeSpec(data: Buffer, offset: number): [MACSuperframeSpec, offset: number] {
    const spec = data.readUInt16LE(offset);
    offset += 2;
    const beaconOrder = spec & ZigbeeMACConsts.SUPERFRAME_BEACON_ORDER_MASK;
    const superframeOrder = (spec & ZigbeeMACConsts.SUPERFRAME_ORDER_MASK) >> ZigbeeMACConsts.SUPERFRAME_ORDER_SHIFT;
    const finalCAPSlot = (spec & ZigbeeMACConsts.SUPERFRAME_CAP_MASK) >> ZigbeeMACConsts.SUPERFRAME_CAP_SHIFT;
    const batteryExtension = Boolean((spec & ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_MASK) >> ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_SHIFT);
    const panCoordinator = Boolean((spec & ZigbeeMACConsts.SUPERFRAME_COORD_MASK) >> ZigbeeMACConsts.SUPERFRAME_COORD_SHIFT);
    const associationPermit = Boolean((spec & ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_MASK) >> ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_SHIFT);

    return [
        {
            beaconOrder,
            superframeOrder,
            finalCAPSlot,
            batteryExtension,
            panCoordinator,
            associationPermit,
        },
        offset,
    ];
}

function encodeMACSuperframeSpec(data: Buffer, offset: number, header: MACHeader): number {
    const spec = header.superframeSpec!;
    offset = data.writeUInt16LE(
        (spec.beaconOrder & ZigbeeMACConsts.SUPERFRAME_BEACON_ORDER_MASK) |
            ((spec.superframeOrder << ZigbeeMACConsts.SUPERFRAME_ORDER_SHIFT) & ZigbeeMACConsts.SUPERFRAME_ORDER_MASK) |
            ((spec.finalCAPSlot << ZigbeeMACConsts.SUPERFRAME_CAP_SHIFT) & ZigbeeMACConsts.SUPERFRAME_CAP_MASK) |
            (((spec.batteryExtension ? 1 : 0) << ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_SHIFT) & ZigbeeMACConsts.SUPERFRAME_BATT_EXTENSION_MASK) |
            (((spec.panCoordinator ? 1 : 0) << ZigbeeMACConsts.SUPERFRAME_COORD_SHIFT) & ZigbeeMACConsts.SUPERFRAME_COORD_MASK) |
            (((spec.associationPermit ? 1 : 0) << ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_SHIFT) & ZigbeeMACConsts.SUPERFRAME_ASSOC_PERMIT_MASK),
        offset,
    );

    return offset;
}

function decodeMACGtsInfo(data: Buffer, offset: number): [MACGtsInfo, offset: number] {
    let directionByte: number | undefined;
    let directions: number[] | undefined;
    let addresses: number[] | undefined;
    let timeLengths: number[] | undefined;
    let slots: number[] | undefined;

    const spec = data.readUInt8(offset);
    offset += 1;
    const count = spec & ZigbeeMACConsts.GTS_COUNT_MASK;
    const permit = Boolean(spec & ZigbeeMACConsts.GTS_PERMIT_MASK);

    if (count > 0) {
        directionByte = data.readUInt8(offset);
        offset += 1;
        directions = [];
        addresses = [];
        timeLengths = [];
        slots = [];

        for (let i = 0; i < count; i++) {
            directions.push(directionByte & (0x01 << i));
            const addr = data.readUInt16LE(offset);
            offset += 2;
            const slotByte = data.readUInt8(offset);
            offset += 1;
            const timeLength = (slotByte & ZigbeeMACConsts.GTS_LENGTH_MASK) >> ZigbeeMACConsts.GTS_LENGTH_SHIFT;
            const slot = slotByte & ZigbeeMACConsts.GTS_SLOT_MASK;

            addresses.push(addr);
            timeLengths.push(timeLength);
            slots.push(slot);
        }
    }

    return [
        {
            permit,
            directionByte,
            directions,
            addresses,
            timeLengths,
            slots,
        },
        offset,
    ];
}

function encodeMACGtsInfo(data: Buffer, offset: number, header: MACHeader): number {
    const info = header.gtsInfo!;
    const count = info.directions ? info.directions.length : 0;
    offset = data.writeUInt8((count & ZigbeeMACConsts.GTS_COUNT_MASK) | ((info.permit ? 1 : 0) & ZigbeeMACConsts.GTS_PERMIT_MASK), offset);

    if (count > 0) {
        // assert(info.directionByte !== undefined);
        offset = data.writeUInt8(info.directionByte!, offset);

        for (let i = 0; i < count; i++) {
            offset = data.writeUInt16LE(info.addresses![i], offset);
            const timeLength = info.timeLengths![i];
            const slot = info.slots![i];
            offset = data.writeUInt8(
                ((timeLength << ZigbeeMACConsts.GTS_LENGTH_SHIFT) & ZigbeeMACConsts.GTS_LENGTH_MASK) | (slot & ZigbeeMACConsts.GTS_SLOT_MASK),
                offset,
            );
        }
    }

    return offset;
}

function decodeMACPendAddr(data: Buffer, offset: number): [MACPendAddr, offset: number] {
    const spec = data.readUInt8(offset);
    offset += 1;
    const num16 = spec & ZigbeeMACConsts.PENDADDR_SHORT_MASK;
    const num64 = (spec & ZigbeeMACConsts.PENDADDR_LONG_MASK) >> ZigbeeMACConsts.PENDADDR_LONG_SHIFT;
    let addr16List: number[] | undefined;
    let addr64List: bigint[] | undefined;

    if (num16 > 0) {
        addr16List = [];

        for (let i = 0; i < num16; i++) {
            addr16List.push(data.readUInt16LE(offset));

            offset += 2;
        }
    }

    if (num64 > 0) {
        addr64List = [];

        for (let i = 0; i < num64; i++) {
            addr64List.push(data.readBigUInt64LE(offset));

            offset += 8;
        }
    }

    return [
        {
            addr16List,
            addr64List,
        },
        offset,
    ];
}

function encodeMACPendAddr(data: Buffer, offset: number, header: MACHeader): number {
    const pendAddr = header.pendAddr!;
    const num16 = pendAddr.addr16List ? pendAddr.addr16List.length : 0;
    const num64 = pendAddr.addr64List ? pendAddr.addr64List.length : 0;
    offset = data.writeUInt8(
        (num16 & ZigbeeMACConsts.PENDADDR_SHORT_MASK) | ((num64 << ZigbeeMACConsts.PENDADDR_LONG_SHIFT) & ZigbeeMACConsts.PENDADDR_LONG_MASK),
        offset,
    );

    for (let i = 0; i < num16; i++) {
        offset = data.writeUInt16LE(pendAddr.addr16List![i], offset);
    }

    for (let i = 0; i < num64; i++) {
        offset = data.writeBigUInt64LE(pendAddr.addr64List![i], offset);
    }

    return offset;
}

export const enum MacZigbeePayloadIESubId {
    REJOIN = 0x00,
    TX_POWER = 0x01,
    EB_PAYLOAD = 0x02,
    // 0x003-0x3ff Reserved
}

function decodeMACHeaderIEs(data: Buffer, offset: number, auxSecHeader: MACAuxSecHeader | undefined): [MACHeaderIE, offset: number] {
    let remaining = data.byteLength - offset - getMICLength(auxSecHeader?.securityLevel ?? 0);
    let payloadIEPresent = false;
    const ies: MACHeaderIE["ies"] = [];

    do {
        const header = data.readUInt16LE(offset);
        offset += 2;
        const id = (header & ZigbeeMACConsts.HEADER_IE_ID_MASK) >> 7;
        const length = header & ZigbeeMACConsts.HEADER_IE_LENGTH_MASK;

        ies.push({ id, length });

        offset += 2 + length;
        remaining -= 2 + length;

        if (id === ZigbeeMACConsts.HEADER_IE_HT1 || id === ZigbeeMACConsts.HEADER_IE_HT2) {
            payloadIEPresent = id === ZigbeeMACConsts.HEADER_IE_HT1;

            break;
        }
    } while (remaining > 0);

    return [
        {
            ies,
            payloadIEPresent,
        },
        offset,
    ];
}

// function encodeMACHeaderIEs(data: Buffer, offset: number): number {}

// export type MACHeaderPayloadIE = {

// }

// /**
//  * TODO: proper support for all IE stuff
//  *
//  * The Zigbee Payload IE is a Vendor Specific Payload IE (Group ID = 0x2) using the Zigbee OUI value of 0x4A191B.
//  *   - Bits: 0-5     6-15    Octets: Variable
//  *   -       Length  Sub-ID  Content
//  *
//  * REJOIN:
//  *   - Octets: 8                        2
//  *   -         Network Extended PAN ID  Sender Short Address
//  *
//  * TX_POWER:
//  *   - Octets: 1
//  *   -         TX Power (in dBm - used to send the frame)
//  *
//  * EB_PAYLOAD:
//  *   - Octets: 15              2                         2
//  *   -         Beacon Payload  Superframe Specification  Sender Short Address
//  */
// function decodeMACHeaderPayloadIEs(data: Buffer, offset: number, headerIE: MACHeaderIE): [MACHeaderPayloadIE[], offset: number] {
//     return [[], offset];
// }

export function decodeMACCapabilities(capabilities: number): MACCapabilities {
    return {
        alternatePANCoordinator: Boolean(capabilities & 0x01),
        deviceType: (capabilities & 0x02) >> 1,
        powerSource: (capabilities & 0x04) >> 2,
        rxOnWhenIdle: Boolean((capabilities & 0x08) >> 3),
        // reserved1: (capabilities & 0x10) >> 4,
        // reserved2: (capabilities & 0x20) >> 5,
        securityCapability: Boolean((capabilities & 0x40) >> 6),
        allocateAddress: Boolean((capabilities & 0x80) >> 7),
    };
}

export function encodeMACCapabilities(capabilities: MACCapabilities): number {
    return (
        ((capabilities.alternatePANCoordinator ? 1 : 0) & 0x01) |
        ((capabilities.deviceType << 1) & 0x02) |
        ((capabilities.powerSource << 2) & 0x04) |
        (((capabilities.rxOnWhenIdle ? 1 : 0) << 3) & 0x08) |
        // (capabilities.reserved1 << 4) & 0x10) |
        // (capabilities.reserved2 << 5) & 0x20) |
        (((capabilities.securityCapability ? 1 : 0) << 6) & 0x40) |
        (((capabilities.allocateAddress ? 1 : 0) << 7) & 0x80)
    );
}

/**
 * Decode MAC header from frame.
 * HOT PATH: Called for every incoming MAC frame.
 */
/* @__INLINE__ */
export function decodeMACHeader(data: Buffer, offset: number, frameControl: MACFrameControl): [MACHeader, offset: number] {
    let sequenceNumber: number | undefined;
    let destinationPANId: number | undefined;
    let sourcePANId: number | undefined;

    if (!frameControl.seqNumSuppress) {
        sequenceNumber = data.readUInt8(offset);
        offset += 1;
    }

    if (frameControl.destAddrMode === MACFrameAddressMode.RESERVED) {
        throw new Error(`Invalid MAC frame: destination address mode ${frameControl.destAddrMode}`);
    }

    if (frameControl.sourceAddrMode === MACFrameAddressMode.RESERVED) {
        throw new Error(`Invalid MAC frame: source address mode ${frameControl.sourceAddrMode}`);
    }

    let destPANPresent = false;
    let sourcePANPresent = false;

    if (frameControl.frameType === MACFrameType.MULTIPURPOSE) {
        throw new Error("Unsupported MAC frame: MULTIPURPOSE");
    }

    if (frameControl.frameVersion === MACFrameVersion.V2003 || frameControl.frameVersion === MACFrameVersion.V2006) {
        if (frameControl.destAddrMode !== MACFrameAddressMode.NONE && frameControl.sourceAddrMode !== MACFrameAddressMode.NONE) {
            // addressing information is present
            if (frameControl.panIdCompression) {
                // PAN IDs are identical
                destPANPresent = true;
                sourcePANPresent = false;
            } else {
                // PAN IDs are different, both shall be included in the frame
                destPANPresent = true;
                sourcePANPresent = true;
            }
        } else {
            if (frameControl.panIdCompression) {
                throw new Error("Invalid MAC frame: unexpected PAN ID compression");
            }

            // only either the destination or the source addressing information is present
            if (frameControl.destAddrMode !== MACFrameAddressMode.NONE && frameControl.sourceAddrMode === MACFrameAddressMode.NONE) {
                destPANPresent = true;
                sourcePANPresent = false;
            } else if (frameControl.destAddrMode === MACFrameAddressMode.NONE && frameControl.sourceAddrMode !== MACFrameAddressMode.NONE) {
                destPANPresent = false;
                sourcePANPresent = true;
            } else if (frameControl.destAddrMode === MACFrameAddressMode.NONE && frameControl.sourceAddrMode === MACFrameAddressMode.NONE) {
                destPANPresent = false;
                sourcePANPresent = false;
            } else {
                throw new Error("Invalid MAC frame: invalid addressing");
            }
        }
    } else if (frameControl.frameVersion === MACFrameVersion.V2015) {
        if (
            frameControl.frameType === MACFrameType.BEACON ||
            frameControl.frameType === MACFrameType.DATA ||
            frameControl.frameType === MACFrameType.ACK ||
            frameControl.frameType === MACFrameType.CMD
        ) {
            if (
                frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                frameControl.sourceAddrMode === MACFrameAddressMode.NONE &&
                !frameControl.panIdCompression
            ) {
                destPANPresent = false;
                sourcePANPresent = false;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                frameControl.sourceAddrMode === MACFrameAddressMode.NONE &&
                frameControl.panIdCompression
            ) {
                destPANPresent = true;
                sourcePANPresent = false;
            } else if (
                frameControl.destAddrMode !== MACFrameAddressMode.NONE &&
                frameControl.sourceAddrMode === MACFrameAddressMode.NONE &&
                !frameControl.panIdCompression
            ) {
                destPANPresent = true;
                sourcePANPresent = false;
            } else if (
                frameControl.destAddrMode !== MACFrameAddressMode.NONE &&
                frameControl.sourceAddrMode === MACFrameAddressMode.NONE &&
                frameControl.panIdCompression
            ) {
                destPANPresent = false;
                sourcePANPresent = false;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                frameControl.sourceAddrMode !== MACFrameAddressMode.NONE &&
                !frameControl.panIdCompression
            ) {
                destPANPresent = false;
                sourcePANPresent = true;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                frameControl.sourceAddrMode !== MACFrameAddressMode.NONE &&
                frameControl.panIdCompression
            ) {
                destPANPresent = false;
                sourcePANPresent = false;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.EXT &&
                frameControl.sourceAddrMode === MACFrameAddressMode.EXT &&
                !frameControl.panIdCompression
            ) {
                destPANPresent = true;
                sourcePANPresent = false;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.EXT &&
                frameControl.sourceAddrMode === MACFrameAddressMode.EXT &&
                frameControl.panIdCompression
            ) {
                destPANPresent = false;
                sourcePANPresent = false;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.SHORT &&
                frameControl.sourceAddrMode === MACFrameAddressMode.SHORT &&
                !frameControl.panIdCompression
            ) {
                destPANPresent = true;
                sourcePANPresent = true;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.SHORT &&
                frameControl.sourceAddrMode === MACFrameAddressMode.EXT &&
                !frameControl.panIdCompression
            ) {
                destPANPresent = true;
                sourcePANPresent = true;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.EXT &&
                frameControl.sourceAddrMode === MACFrameAddressMode.SHORT &&
                !frameControl.panIdCompression
            ) {
                destPANPresent = true;
                sourcePANPresent = true;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.SHORT &&
                frameControl.sourceAddrMode === MACFrameAddressMode.EXT &&
                frameControl.panIdCompression
            ) {
                destPANPresent = true;
                sourcePANPresent = false;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.EXT &&
                frameControl.sourceAddrMode === MACFrameAddressMode.SHORT &&
                frameControl.panIdCompression
            ) {
                destPANPresent = true;
                sourcePANPresent = false;
            } else if (
                frameControl.destAddrMode === MACFrameAddressMode.SHORT &&
                frameControl.sourceAddrMode === MACFrameAddressMode.SHORT &&
                frameControl.panIdCompression
            ) {
                destPANPresent = true;
                sourcePANPresent = false;
            } else {
                throw new Error("Invalid MAC frame: unexpected PAN ID compression");
            }
        } else {
            // PAN ID Compression is not used
            destPANPresent = false;
            sourcePANPresent = false;
        }
    } else {
        throw new Error("Invalid MAC frame: invalid version");
    }

    let destination16: number | undefined;
    let destination64: bigint | undefined;
    let source16: number | undefined;
    let source64: bigint | undefined;

    if (destPANPresent) {
        destinationPANId = data.readUInt16LE(offset);
        offset += 2;
    }

    if (frameControl.destAddrMode === MACFrameAddressMode.SHORT) {
        destination16 = data.readUInt16LE(offset);
        offset += 2;
    } else if (frameControl.destAddrMode === MACFrameAddressMode.EXT) {
        destination64 = data.readBigUInt64LE(offset);
        offset += 8;
    }

    if (sourcePANPresent) {
        sourcePANId = data.readUInt16LE(offset);
        offset += 2;
    } else {
        sourcePANId = destPANPresent ? destinationPANId : ZigbeeMACConsts.BCAST_PAN;
    }

    if (frameControl.sourceAddrMode === MACFrameAddressMode.SHORT) {
        source16 = data.readUInt16LE(offset);
        offset += 2;
    } else if (frameControl.sourceAddrMode === MACFrameAddressMode.EXT) {
        source64 = data.readBigUInt64LE(offset);
        offset += 8;
    }

    let auxSecHeader: MACAuxSecHeader | undefined;

    if (
        frameControl.securityEnabled &&
        /*(frameControl.frameType === MACFrameType.MULTIPURPOSE || */ frameControl.frameVersion === MACFrameVersion.V2003
    ) {
        [auxSecHeader, offset] = decodeMACAuxSecHeader(data, offset, frameControl);
    }

    let superframeSpec: MACSuperframeSpec | undefined;
    let gtsInfo: MACGtsInfo | undefined;
    let pendAddr: MACPendAddr | undefined;
    let commandId: number | undefined;
    let headerIE: MACHeaderIE | undefined;

    if (
        /*frameControl.frameType !== MACFrameType.MULTIPURPOSE && */
        frameControl.frameVersion === MACFrameVersion.V2003 ||
        frameControl.frameVersion === MACFrameVersion.V2006
    ) {
        if (frameControl.frameType === MACFrameType.BEACON) {
            [superframeSpec, offset] = decodeMACSuperframeSpec(data, offset);
            [gtsInfo, offset] = decodeMACGtsInfo(data, offset);
            [pendAddr, offset] = decodeMACPendAddr(data, offset);
        } else if (frameControl.frameType === MACFrameType.CMD) {
            commandId = data.readUInt8(offset);
            offset += 1;
        }
    } else {
        if (frameControl.iePresent) {
            [headerIE, offset] = decodeMACHeaderIEs(data, offset, auxSecHeader);
            // TODO: headerIE.payloadIEPresent === true, Zigbee OUI?
        }
    }

    let frameCounter: number | undefined;
    let keySeqCounter: number | undefined;

    if (
        frameControl.securityEnabled &&
        /*frameControl.frameType !== MACFrameType.MULTIPURPOSE && */
        frameControl.frameVersion === MACFrameVersion.V2003
    ) {
        // auxSecHeader?.securityLevel = ???;
        const isEncrypted = auxSecHeader!.securityLevel! & 0x04;

        if (isEncrypted) {
            frameCounter = data.readUInt32LE(offset);
            offset += 4;
            keySeqCounter = data.readUInt8(offset);
            offset += 1;
        }
    }

    if (offset >= data.byteLength) {
        throw new Error("Invalid MAC frame: no payload");
    }

    return [
        {
            frameControl,
            sequenceNumber,
            destinationPANId,
            destination16,
            destination64,
            sourcePANId,
            source16,
            source64,
            auxSecHeader,
            superframeSpec,
            gtsInfo,
            pendAddr,
            commandId,
            headerIE,
            frameCounter,
            keySeqCounter,
            fcs: 0, // set after decoded payload
        },
        offset,
    ];
}

function encodeMACHeader(data: Buffer, offset: number, header: MACHeader, zigbee: boolean): number {
    offset = encodeMACFrameControl(data, offset, header.frameControl);

    if (zigbee) {
        offset = data.writeUInt8(header.sequenceNumber!, offset);
        offset = data.writeUInt16LE(header.destinationPANId!, offset);
        offset = data.writeUInt16LE(header.destination16!, offset);

        if (header.sourcePANId !== undefined) {
            offset = data.writeUInt16LE(header.sourcePANId, offset);
        }

        // NWK GP can be NONE
        if (header.frameControl.sourceAddrMode === MACFrameAddressMode.SHORT) {
            offset = data.writeUInt16LE(header.source16!, offset);
        }
    } else {
        if (!header.frameControl.seqNumSuppress) {
            offset = data.writeUInt8(header.sequenceNumber!, offset);
        }

        if (header.frameControl.destAddrMode === MACFrameAddressMode.RESERVED) {
            throw new Error(`Invalid MAC frame: destination address mode ${header.frameControl.destAddrMode}`);
        }

        if (header.frameControl.sourceAddrMode === MACFrameAddressMode.RESERVED) {
            throw new Error(`Invalid MAC frame: source address mode ${header.frameControl.sourceAddrMode}`);
        }

        let destPANPresent = false;
        let sourcePANPresent = false;

        if (header.frameControl.frameType === MACFrameType.MULTIPURPOSE) {
            throw new Error("Unsupported MAC frame: MULTIPURPOSE");
        }

        if (header.frameControl.frameVersion === MACFrameVersion.V2003 || header.frameControl.frameVersion === MACFrameVersion.V2006) {
            if (header.frameControl.destAddrMode !== MACFrameAddressMode.NONE && header.frameControl.sourceAddrMode !== MACFrameAddressMode.NONE) {
                // addressing information is present
                if (header.frameControl.panIdCompression) {
                    // PAN IDs are identical
                    destPANPresent = true;
                    sourcePANPresent = false;
                } else {
                    // PAN IDs are different, both shall be included in the frame
                    destPANPresent = true;
                    sourcePANPresent = true;
                }
            } else {
                if (header.frameControl.panIdCompression) {
                    throw new Error("Invalid MAC frame: unexpected PAN ID compression");
                }

                // only either the destination or the source addressing information is present
                if (
                    header.frameControl.destAddrMode !== MACFrameAddressMode.NONE &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.NONE
                ) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                    header.frameControl.sourceAddrMode !== MACFrameAddressMode.NONE
                ) {
                    destPANPresent = false;
                    sourcePANPresent = true;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.NONE
                ) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                } else {
                    throw new Error("Invalid MAC frame: invalid addressing");
                }
            }
        } else if (header.frameControl.frameVersion === MACFrameVersion.V2015) {
            if (
                header.frameControl.frameType === MACFrameType.BEACON ||
                header.frameControl.frameType === MACFrameType.DATA ||
                header.frameControl.frameType === MACFrameType.ACK ||
                header.frameControl.frameType === MACFrameType.CMD
            ) {
                if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.NONE &&
                    !header.frameControl.panIdCompression
                ) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.NONE &&
                    header.frameControl.panIdCompression
                ) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode !== MACFrameAddressMode.NONE &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.NONE &&
                    !header.frameControl.panIdCompression
                ) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode !== MACFrameAddressMode.NONE &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.NONE &&
                    header.frameControl.panIdCompression
                ) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                    header.frameControl.sourceAddrMode !== MACFrameAddressMode.NONE &&
                    !header.frameControl.panIdCompression
                ) {
                    destPANPresent = false;
                    sourcePANPresent = true;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.NONE &&
                    header.frameControl.sourceAddrMode !== MACFrameAddressMode.NONE &&
                    header.frameControl.panIdCompression
                ) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.EXT &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.EXT &&
                    !header.frameControl.panIdCompression
                ) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.EXT &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.EXT &&
                    header.frameControl.panIdCompression
                ) {
                    destPANPresent = false;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.SHORT &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.SHORT &&
                    !header.frameControl.panIdCompression
                ) {
                    destPANPresent = true;
                    sourcePANPresent = true;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.SHORT &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.EXT &&
                    !header.frameControl.panIdCompression
                ) {
                    destPANPresent = true;
                    sourcePANPresent = true;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.EXT &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.SHORT &&
                    !header.frameControl.panIdCompression
                ) {
                    destPANPresent = true;
                    sourcePANPresent = true;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.SHORT &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.EXT &&
                    header.frameControl.panIdCompression
                ) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.EXT &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.SHORT &&
                    header.frameControl.panIdCompression
                ) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                } else if (
                    header.frameControl.destAddrMode === MACFrameAddressMode.SHORT &&
                    header.frameControl.sourceAddrMode === MACFrameAddressMode.SHORT &&
                    header.frameControl.panIdCompression
                ) {
                    destPANPresent = true;
                    sourcePANPresent = false;
                } else {
                    throw new Error("Invalid MAC frame: unexpected PAN ID compression");
                }
            } else {
                // PAN ID Compression is not used
                destPANPresent = false;
                sourcePANPresent = false;
            }
        } else {
            throw new Error("Invalid MAC frame: invalid version");
        }

        if (destPANPresent) {
            offset = data.writeUInt16LE(header.destinationPANId!, offset);
        }

        if (header.frameControl.destAddrMode === MACFrameAddressMode.SHORT) {
            offset = data.writeUInt16LE(header.destination16!, offset);
        } else if (header.frameControl.destAddrMode === MACFrameAddressMode.EXT) {
            offset = data.writeBigUInt64LE(header.destination64!, offset);
        }

        if (sourcePANPresent) {
            offset = data.writeUInt16LE(header.sourcePANId!, offset);
        }

        if (header.frameControl.sourceAddrMode === MACFrameAddressMode.SHORT) {
            offset = data.writeUInt16LE(header.source16!, offset);
        } else if (header.frameControl.sourceAddrMode === MACFrameAddressMode.EXT) {
            offset = data.writeBigUInt64LE(header.source64!, offset);
        }

        let auxSecHeader: MACAuxSecHeader | undefined;

        if (
            header.frameControl.securityEnabled &&
            /*(header.frameControl.frameType === MACFrameType.MULTIPURPOSE || */ header.frameControl.frameVersion === MACFrameVersion.V2003
        ) {
            throw new Error("Unsupported: securityEnabled");
            // [auxSecHeader, offset] = encodeMACAuxSecHeader(data, offset, header.frameControl);
        }

        if (
            /*header.frameControl.frameType !== MACFrameType.MULTIPURPOSE && */
            header.frameControl.frameVersion === MACFrameVersion.V2003 ||
            header.frameControl.frameVersion === MACFrameVersion.V2006
        ) {
            if (header.frameControl.frameType === MACFrameType.BEACON) {
                offset = encodeMACSuperframeSpec(data, offset, header);
                offset = encodeMACGtsInfo(data, offset, header);
                offset = encodeMACPendAddr(data, offset, header);
            } else if (header.frameControl.frameType === MACFrameType.CMD) {
                offset = data.writeUInt8(header.commandId!, offset);
            }
        } else {
            if (header.frameControl.iePresent) {
                throw new Error("Unsupported iePresent");
                // offset = encodeMACHeaderIEs(data, offset, auxSecHeader);
            }
        }

        if (
            header.frameControl.securityEnabled &&
            /*header.frameControl.frameType !== MACFrameType.MULTIPURPOSE && */
            header.frameControl.frameVersion === MACFrameVersion.V2003
        ) {
            // auxSecHeader?.securityLevel = ???;
            const isEncrypted = auxSecHeader!.securityLevel! & 0x04;

            if (isEncrypted) {
                offset = data.writeUInt32LE(header.frameCounter!, offset);
                offset = data.writeUInt8(header.keySeqCounter!, offset);
            }
        }
    }

    return offset;
}

function crc16CCITT(data: Buffer): number {
    let fcs = 0x0000;

    for (const aByte of data) {
        let q = (fcs ^ aByte) & 0x0f;
        fcs = (fcs >> 4) ^ (q * 0x1081);
        q = (fcs ^ (aByte >> 4)) & 0x0f;
        fcs = (fcs >> 4) ^ (q * 0x1081);
    }

    return fcs;
}

export function decodeMACPayload(data: Buffer, offset: number, frameControl: MACFrameControl, header: MACHeader): MACPayload {
    if (frameControl.securityEnabled) {
        // XXX: not needed for Zigbee
        throw new Error("Unsupported MAC frame: security enabled");
    }

    const endOffset = data.byteLength - ZigbeeMACConsts.FCS_LEN;

    if (endOffset - offset < 0) {
        throw new Error("Invalid MAC frame: no FCS");
    }

    const payload = data.subarray(offset, endOffset);

    header.fcs = data.readUInt16LE(endOffset);

    return payload;
}

export function encodeMACFrame(header: MACHeader, payload: Buffer): Buffer {
    let offset = 0;
    const data = Buffer.alloc(ZigbeeMACConsts.PAYLOAD_MAX_SAFE_SIZE);
    offset = encodeMACHeader(data, offset, header, false);
    offset += payload.copy(data, offset);
    offset = data.writeUInt16LE(crc16CCITT(data.subarray(0, offset)), offset);

    return data.subarray(0, offset);
}

// #region Zigbee-specific

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

/** Encode MAC frame with hotpath for Zigbee NWK/APS payload */
export function encodeMACFrameZigbee(header: MACHeaderZigbee, payload: Buffer): Buffer {
    let offset = 0;
    const data = Buffer.alloc(ZigbeeMACConsts.PAYLOAD_MAX_SAFE_SIZE); // TODO: optimize with max Zigbee header length

    // always transmit with v2003 (0) frame version @see D.6 Frame Version Value of 05-3474-23
    header.frameControl.frameVersion = MACFrameVersion.V2003;

    offset = encodeMACHeader(data, offset, header, true); // zigbee hotpath
    offset += payload.copy(data, offset);
    offset = data.writeUInt16LE(crc16CCITT(data.subarray(0, offset)), offset);

    return data.subarray(0, offset);
}

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

export function decodeMACZigbeeBeacon(data: Buffer, offset: number): MACZigbeeBeacon {
    const protocolId = data.readUInt8(offset);
    offset += 1;
    const beacon = data.readUInt16LE(offset);
    offset += 2;
    const profile = beacon & ZigbeeMACConsts.ZIGBEE_BEACON_STACK_PROFILE_MASK;
    const version = (beacon & ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_MASK) >> ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_SHIFT;
    const routerCapacity = Boolean(
        (beacon & ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_MASK) >> ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_SHIFT,
    );
    const deviceDepth = (beacon & ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_MASK) >> ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_SHIFT;
    const endDeviceCapacity = Boolean(
        (beacon & ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_MASK) >> ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_SHIFT,
    );
    const extendedPANId = data.readBigUInt64LE(offset);
    offset += 8;
    const endBytes = data.readUInt32LE(offset);
    const txOffset = endBytes & ZigbeeMACConsts.ZIGBEE_BEACON_TX_OFFSET_MASK;
    const updateId = (endBytes & ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_MASK) >> ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_SHIFT;

    return {
        protocolId,
        profile,
        version,
        routerCapacity,
        deviceDepth,
        endDeviceCapacity,
        extendedPANId,
        txOffset,
        updateId,
    };
}

export function encodeMACZigbeeBeacon(beacon: MACZigbeeBeacon): Buffer {
    const payload = Buffer.alloc(ZigbeeMACConsts.ZIGBEE_BEACON_LENGTH);
    let offset = 0;
    offset = payload.writeUInt8(0, offset); // protocol ID always 0 on Zigbee beacons
    offset = payload.writeUInt16LE(
        (beacon.profile & ZigbeeMACConsts.ZIGBEE_BEACON_STACK_PROFILE_MASK) |
            ((beacon.version << ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_SHIFT) & ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_VERSION_MASK) |
            (((beacon.routerCapacity ? 1 : 0) << ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_SHIFT) &
                ZigbeeMACConsts.ZIGBEE_BEACON_ROUTER_CAPACITY_MASK) |
            ((beacon.deviceDepth << ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_SHIFT) & ZigbeeMACConsts.ZIGBEE_BEACON_NETWORK_DEPTH_MASK) |
            (((beacon.endDeviceCapacity ? 1 : 0) << ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_SHIFT) &
                ZigbeeMACConsts.ZIGBEE_BEACON_END_DEVICE_CAPACITY_MASK),
        offset,
    );
    offset = payload.writeBigUInt64LE(beacon.extendedPANId, offset);
    offset = payload.writeUInt32LE(
        (beacon.txOffset & ZigbeeMACConsts.ZIGBEE_BEACON_TX_OFFSET_MASK) |
            ((beacon.updateId << ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_SHIFT) & ZigbeeMACConsts.ZIGBEE_BEACON_UPDATE_ID_MASK),
        offset,
    );

    return payload;
}

// #endregion
