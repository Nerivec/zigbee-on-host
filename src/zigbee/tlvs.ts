import type { RequiredNonNullable } from "../utils/types.js";
import { ZigbeeConsts } from "./zigbee.js";

export const enum GlobalTlvConsts {
    KEY_NEGOTATION_METHOD_STATIC = 0b000,
    KEY_NEGOTATION_METHOD_MMO128 = 0b010,
    KEY_NEGOTATION_METHOD_SHA256 = 0b100,
}

export const enum GlobalTlv {
    /** minLen=2 */
    MANUFACTURER_SPECIFIC = 64,
    /** minLen=2 */
    SUPPORTED_KEY_NEGOTIATION_METHODS = 65,
    /** minLen=2 */
    PAN_ID_CONFLICT_REPORT = 66,
    /** minLen=2 */
    NEXT_PAN_ID = 67,
    /** minLen=4 */
    NEXT_CHANNEL_CHANGE = 68,
    /** minLen=16 */
    SYMMETRIC_PASSPHRASE = 69,
    /** minLen=2 */
    ROUTER_INFORMATION = 70,
    /** minLen=2 */
    FRAGMENTATION_PARAMETERS = 71,
    JOINER_ENCAPSULATION = 72,
    BEACON_APPENDIX_ENCAPSULATION = 73,
    BDB_ENCAPSULATION = 74,
    CONFIGURATION_PARAMETERS = 75,
    /** Zigbee Direct */
    DEVICE_CAPABILITY_EXTENSION = 76,
    // Reserved = 77-255
}

type GlobalTlvEncapsulated = {
    additionalTlvs: ZigbeeGlobalTlvs;
    additionalLocalTlvs: Map<number, Buffer>;
};

type GlobalTlvManufacturerSpecific = {
    /** uint16 */
    zigbeeManufacturerId: number;
    /** variable */
    additionalData: Buffer;
};

type GlobalTlvSupportedKeyNegotiatioMethods = {
    /**
     * uint8
     * - Bit 0: Static Key Request (Zigbee 3.0 Mechanism, TCLK procedure)
     * - Bit 1: SPEKE using Curve25519 with Hash AES-MMO-128
     * - Bit 2: SPEKE using Curve25519 with Hash SHA-256
     * - Bit 3–7: Reserved
     */
    keyNegotiationProtocolsBitmask: number;
    /**
     * uint8
     * - Bit 0: Symmetric Authentication Token
     *   - This is a token unique to the Trust Center and network that the device is running on, and is assigned by the Trust center after joining.
     *     The token is used to renegotiate a link key using the Key Negotiation protocol and is good for the life of the device on the network.
     * - Bit 1: Install Code Key
     *   - 128-bit pre-configured link-key derived from install code
     * - Bit 2: Passcode Key
     *   - A variable length passcode for PAKE protocols. This passcode can be shorter for easy entry by a user.
     * - Bit 3: Basic Access Key
     *   - This key is used by other Zigbee specifications for joining with an alternate pre-shared secret. The definition and usage is defined by those specifications. The usage is optional by the core Zigbee specification.
     * - Bit 4: Administrative Access Key
     *   - This key is used by other Zigbee specifications for joining with an alternate pre-shared secret. The definition and usage is defined by those specifications. The usage is optional by the core Zigbee specification.
     * - Bit 5-7: Reserved
     */
    preSharedSecretsBitmask: number;
    sourceDeviceEui64: bigint | undefined;
};

type GlobalTlvPanIdConflictReport = {
    /** uint16 */
    nwkPanIdConflictCount: number;
};

type GlobalTlvNextPanId = {
    /** uint16 */
    panId: number;
};

type GlobalTlvNextChannelChange = {
    /** uint32 */
    channel: number;
};

type GlobalTlvSummetricPassphrase = {
    /** 16-byte */
    passphrase: Buffer;
};

type GlobalTlvRouterInformation = {
    /**
     * uint16
     * - Bit 0: Hub Connectivity
     *   - This bit indicates the state of nwkHubConnectivity from the NIB of the local device.
     *     It advertises whether the router has connectivity to a Hub device as defined by the higher-level application layer.
     *     A value of 1 means there is connectivity, and avalue of 0 means there is no current Hub connectivity.
     * - Bit 1: Uptime
     *   - This 1-bit value indicates the uptime of the router.
     *     A value of 1 indicates the router has been up for more than 24 hours.
     *     A value of 0 indicates the router has been up for less than 24 hours.
     * - Bit 2: Preferred Parent
     *   - This bit indicates the state of nwkPreferredParent from the NIB of the local device.
     *     When supported, it extends Hub Connecivity, advertising the devices capacity to be the parent for an additional device.
     *     A value of 1 means that this device should be preferred.
     *     A value of 0 indicates that it should not be preferred.
     *     Devices that do not make this determination SHALL always report a value of 0.
     * - Bit 3: Battery Backup
     *   - This bit indicates that the router has battery backup and thus will not be affected by temporary losses in power.
     * - Bit 4: Enhanced Beacon Request Support
     *   - When this bit is set to 1, it indicates that the router supports responding to Enhanced beacon requests as defined by IEEE Std 802.15.4.
     *     A zero for this bit indicates the device has no support for responding to enhanced beacon requests.
     * - Bit 5: MAC Data Poll Keepalive Support
     *   - This indicates that the device has support for the MAC Data Poll Keepalive method for End Device timeouts.
     * - Bit 6: End Device Keepalive Support
     *   - This indicates that the device has support for the End Device Keepalive method for End Device timeouts.
     * - Bit 7: Power Negotiation Support
     *   - This indicates the device has support for Power Negotiation with end devices.
     * - Bit 8-15: Reserved
     *   - These bits SHALL be set to 0.
     */
    bitmask: number;
};

type GlobalTlvFragmentationParameters = {
    /** uint16 */
    nwkAddress: number;
    /**
     * uint8
     * - Bit 0 = Application Fragmentation Supported (mirrors AIB attribute 0xd5, apsApplicationFragmentationSupport).
     * - Bit 1-7 = Reserved for future use
     */
    fragmentationOptions: number | undefined;
    /** uint16 */
    maxIncomingTransferUnit: number | undefined;
};

type GlobalTlvConfigurationParameters = {
    /** uint16 */
    parameters: number;
};

type GlobalTlvDeviceCapabilityExtension = {
    /** uint16 */
    capabilityExtension: number;
};

export type ZigbeeGlobalTlvs = {
    /** Should be ignored if unknown */
    [GlobalTlv.MANUFACTURER_SPECIFIC]?: GlobalTlvManufacturerSpecific;
    [GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS]?: GlobalTlvSupportedKeyNegotiatioMethods;
    [GlobalTlv.PAN_ID_CONFLICT_REPORT]?: GlobalTlvPanIdConflictReport;
    [GlobalTlv.NEXT_PAN_ID]?: GlobalTlvNextPanId;
    [GlobalTlv.NEXT_CHANNEL_CHANGE]?: GlobalTlvNextChannelChange;
    [GlobalTlv.SYMMETRIC_PASSPHRASE]?: GlobalTlvSummetricPassphrase;
    [GlobalTlv.ROUTER_INFORMATION]?: GlobalTlvRouterInformation;
    [GlobalTlv.FRAGMENTATION_PARAMETERS]?: GlobalTlvFragmentationParameters;
    [GlobalTlv.JOINER_ENCAPSULATION]?: GlobalTlvEncapsulated;
    [GlobalTlv.BEACON_APPENDIX_ENCAPSULATION]?: GlobalTlvEncapsulated;
    [GlobalTlv.BDB_ENCAPSULATION]?: GlobalTlvEncapsulated;
    [GlobalTlv.CONFIGURATION_PARAMETERS]?: GlobalTlvConfigurationParameters;
    [GlobalTlv.DEVICE_CAPABILITY_EXTENSION]?: GlobalTlvDeviceCapabilityExtension;
};

/**
 * SPEC COMPLIANCE:
 * - ✅ TLV format: 1-byte tag + 1-byte length field where actual value length is length+1.
 * - ✅ Local TLVs (0-63) are captured verbatim; Global TLVs (64-255) are parsed when known and ignored when unknown.
 * - ✅ Rejects malformed TLVs that underflow minimum lengths or overrun the provided buffer.
 * - ✅ Allows multiple Manufacturer-Specific TLVs; rejects duplicate instances of other known Global TLVs.
 * - ✅ Encapsulation TLVs are supported with a single nesting level (nested encapsulation is rejected).
 */
export function readZigbeeTlvs(data: Buffer, offset: number, parent?: number): [ZigbeeGlobalTlvs, localTlvs: Map<number, Buffer>, outOffset: number] {
    const globalTlvs: ZigbeeGlobalTlvs = {};
    const localTlvs = new Map<number, Buffer>();
    const endOffset = data.byteLength;

    while (offset < endOffset) {
        // early bail-out if malformed
        if (endOffset - offset < 2) {
            throw new Error("Malformed TLVs");
        }

        // 0..63=local, 64..255=global
        const tag = data.readUInt8(offset);
        offset += 1;
        const length = data.readUInt8(offset) + 1; // per spec, actual data length is `length field + 1`
        offset += 1;
        // keep a separate counter for offset of known fields being parsed
        let tlvOffset = offset;
        // `offset` is now TLV end offset
        offset += length;

        // early bail-out if malformed
        if (offset > endOffset) {
            throw new Error("Malformed TLVs");
        }

        if (tag < GlobalTlv.MANUFACTURER_SPECIFIC) {
            // local
            if (localTlvs.has(tag)) {
                throw new Error(`Invalid duplicate local TLV found tag=${tag}`);
            }

            localTlvs.set(tag, data.subarray(tlvOffset, tlvOffset + length));
        } else {
            // global
            if (tag !== GlobalTlv.MANUFACTURER_SPECIFIC && tag in globalTlvs) {
                throw new Error(`Invalid duplicate global TLV found tag=${tag}`);
            }

            switch (tag) {
                case GlobalTlv.MANUFACTURER_SPECIFIC: {
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const zigbeeManufacturerId = data.readUInt16LE(tlvOffset);
                    tlvOffset += 2;
                    const additionalData = data.subarray(tlvOffset, tlvOffset + length - 2);

                    globalTlvs[GlobalTlv.MANUFACTURER_SPECIFIC] = { zigbeeManufacturerId, additionalData };

                    break;
                }
                case GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS: {
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const keyNegotiationProtocolsBitmask = data.readUInt8(tlvOffset);
                    tlvOffset += 1;
                    const preSharedSecretsBitmask = data.readUInt8(tlvOffset);
                    tlvOffset += 1;
                    let sourceDeviceEui64: bigint | undefined;

                    if (length >= 10) {
                        sourceDeviceEui64 = data.readBigUInt64LE(tlvOffset);
                    }

                    globalTlvs[GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS] = {
                        keyNegotiationProtocolsBitmask,
                        preSharedSecretsBitmask,
                        sourceDeviceEui64,
                    };

                    break;
                }
                case GlobalTlv.PAN_ID_CONFLICT_REPORT: {
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const nwkPanIdConflictCount = data.readUInt16LE(tlvOffset);

                    globalTlvs[GlobalTlv.PAN_ID_CONFLICT_REPORT] = { nwkPanIdConflictCount };

                    break;
                }
                case GlobalTlv.NEXT_PAN_ID: {
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const panId = data.readUInt16LE(tlvOffset);

                    globalTlvs[GlobalTlv.NEXT_PAN_ID] = { panId };

                    break;
                }
                case GlobalTlv.NEXT_CHANNEL_CHANGE: {
                    if (length < 4) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const channel = data.readUInt32LE(tlvOffset);

                    globalTlvs[GlobalTlv.NEXT_CHANNEL_CHANGE] = { channel };

                    break;
                }
                case GlobalTlv.SYMMETRIC_PASSPHRASE: {
                    if (length < ZigbeeConsts.SEC_KEYSIZE) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const passphrase = data.subarray(tlvOffset, tlvOffset + ZigbeeConsts.SEC_KEYSIZE);

                    globalTlvs[GlobalTlv.SYMMETRIC_PASSPHRASE] = { passphrase };

                    break;
                }
                case GlobalTlv.ROUTER_INFORMATION: {
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const bitmap = data.readUInt16LE(tlvOffset);

                    globalTlvs[GlobalTlv.ROUTER_INFORMATION] = { bitmask: bitmap };

                    break;
                }
                case GlobalTlv.FRAGMENTATION_PARAMETERS: {
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const nwkAddress = data.readUInt16LE(tlvOffset);
                    tlvOffset += 2;
                    let fragmentationOptions: number | undefined;
                    let maxIncomingTransferUnit: number | undefined;

                    if (length >= 3) {
                        fragmentationOptions = data.readUInt8(tlvOffset);
                        tlvOffset += 1;
                    }

                    if (length >= 5) {
                        maxIncomingTransferUnit = data.readUInt16LE(tlvOffset);
                    }

                    globalTlvs[GlobalTlv.FRAGMENTATION_PARAMETERS] = { nwkAddress, fragmentationOptions, maxIncomingTransferUnit };

                    break;
                }
                case GlobalTlv.JOINER_ENCAPSULATION: {
                    if (parent !== undefined) {
                        throw new Error(`Invalid nested encapsulated TLV found tag=${tag} parent=${parent}`);
                    }

                    // at least the length of tagId+length for first encapsulated tlv, doesn't make sense otherwise
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const [additionalTlvs, additionalLocalTlvs] = readZigbeeTlvs(data.subarray(tlvOffset, tlvOffset + length), 0, tag);

                    globalTlvs[GlobalTlv.JOINER_ENCAPSULATION] = { additionalTlvs, additionalLocalTlvs };

                    break;
                }
                case GlobalTlv.BEACON_APPENDIX_ENCAPSULATION: {
                    if (parent !== undefined) {
                        throw new Error(`Invalid nested encapsulated TLV found tag=${tag} parent=${parent}`);
                    }

                    // at least the length of tagId+length for first encapsulated tlv, doesn't make sense otherwise
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const [additionalTlvs, additionalLocalTlvs] = readZigbeeTlvs(data.subarray(tlvOffset, tlvOffset + length), 0, tag);

                    globalTlvs[GlobalTlv.BEACON_APPENDIX_ENCAPSULATION] = { additionalTlvs, additionalLocalTlvs };

                    break;
                }
                case GlobalTlv.BDB_ENCAPSULATION: {
                    if (parent !== undefined) {
                        throw new Error(`Invalid nested encapsulated TLV found tag=${tag} parent=${parent}`);
                    }

                    if (length < 2) {
                        // at least the length of tagId+length for first encapsulated tlv, doesn't make sense otherwise
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const [additionalTlvs, additionalLocalTlvs] = readZigbeeTlvs(data.subarray(tlvOffset, tlvOffset + length), 0, tag);

                    globalTlvs[GlobalTlv.BDB_ENCAPSULATION] = { additionalTlvs, additionalLocalTlvs };

                    break;
                }
                case GlobalTlv.CONFIGURATION_PARAMETERS: {
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const configurationParameters = data.readUInt16LE(tlvOffset);

                    globalTlvs[GlobalTlv.CONFIGURATION_PARAMETERS] = { parameters: configurationParameters };

                    break;
                }
                case GlobalTlv.DEVICE_CAPABILITY_EXTENSION: {
                    if (length < 2) {
                        throw new Error(`Malformed TLV, below minimum length (${length})`);
                    }

                    const capabilityExtension = data.readUInt16LE(tlvOffset);

                    globalTlvs[GlobalTlv.DEVICE_CAPABILITY_EXTENSION] = { capabilityExtension };

                    break;
                }
            }
        }
    }

    return [globalTlvs, localTlvs, offset];
}

export function writeZigbeeTlvSupportedKeyNegotiationMethods(
    data: Buffer,
    offset: number,
    tlv: RequiredNonNullable<GlobalTlvSupportedKeyNegotiatioMethods>,
): number {
    offset = data.writeUInt8(GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS, offset);
    offset = data.writeUInt8(9, offset); // per spec, actual data length is `length field + 1`
    offset = data.writeUInt8(tlv.keyNegotiationProtocolsBitmask, offset);
    offset = data.writeUInt8(tlv.preSharedSecretsBitmask, offset);
    offset = data.writeBigUInt64LE(tlv.sourceDeviceEui64, offset);

    return offset;
}

export function writeZigbeeTlvFragmentationParameters(
    data: Buffer,
    offset: number,
    tlv: RequiredNonNullable<GlobalTlvFragmentationParameters>,
): number {
    offset = data.writeUInt8(GlobalTlv.FRAGMENTATION_PARAMETERS, offset);
    offset = data.writeUInt8(4, offset); // per spec, actual data length is `length field + 1`
    offset = data.writeUInt16LE(tlv.nwkAddress, offset);
    offset = data.writeUInt8(tlv.fragmentationOptions, offset);
    offset = data.writeUInt16LE(tlv.maxIncomingTransferUnit, offset);

    return offset;
}

export function writeZigbeeTlvRouterInformation(data: Buffer, offset: number, tlv: RequiredNonNullable<GlobalTlvRouterInformation>): number {
    offset = data.writeUInt8(GlobalTlv.ROUTER_INFORMATION, offset);
    offset = data.writeUInt8(1, offset); // per spec, actual data length is `length field + 1`
    offset = data.writeUInt16LE(tlv.bitmask, offset);

    return offset;
}
