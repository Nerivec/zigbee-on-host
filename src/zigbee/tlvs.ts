import { ZigbeeConsts } from "./zigbee.js";

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

export type ZigbeeGlobalTlvs = {
    /** Should be ignored if unknown */
    [GlobalTlv.MANUFACTURER_SPECIFIC]?: {
        /** uint16 */
        zigbeeManufacturerId: number;
        /** variable */
        additionalData: Buffer;
    };
    [GlobalTlv.SUPPORTED_KEY_NEGOTIATION_METHODS]?: {
        /** uint8 */
        keyNegotiationProtocolsBitmask: number;
        /** uint8 */
        preSharedSecretsBitmask: number;
        sourceDeviceEui64: bigint | undefined;
    };
    [GlobalTlv.PAN_ID_CONFLICT_REPORT]?: {
        /** uint16 */
        nwkPanIdConflictCount: number;
    };
    [GlobalTlv.NEXT_PAN_ID]?: {
        /** uint16 */
        panId: number;
    };
    [GlobalTlv.NEXT_CHANNEL_CHANGE]?: {
        /** uint32 */
        channel: number;
    };
    [GlobalTlv.SYMMETRIC_PASSPHRASE]?: {
        /** 16-byte */
        passphrase: Buffer;
    };
    [GlobalTlv.ROUTER_INFORMATION]?: {
        /** uint16 */
        bitmap: number;
    };
    [GlobalTlv.FRAGMENTATION_PARAMETERS]?: {
        /** uint16 */
        nwkAddress: number;
        /** uint8 */
        fragmentationOptions: number | undefined;
        /** uint16 */
        maxIncomingTransferUnit: number | undefined;
    };
    [GlobalTlv.JOINER_ENCAPSULATION]?: {
        additionalTLVs: ZigbeeGlobalTlvs;
    };
    [GlobalTlv.BEACON_APPENDIX_ENCAPSULATION]?: {
        additionalTLVs: ZigbeeGlobalTlvs;
    };
    [GlobalTlv.BDB_ENCAPSULATION]?: {
        additionalTLVs: ZigbeeGlobalTlvs;
    };
    [GlobalTlv.CONFIGURATION_PARAMETERS]?: {
        /** uint16 */
        parameters: number;
    };
    [GlobalTlv.DEVICE_CAPABILITY_EXTENSION]?: {
        /** uint16 */
        capabilityExtension: number;
    };
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

                    globalTlvs[GlobalTlv.ROUTER_INFORMATION] = { bitmap };

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

                    const [additionalTLVs] = readZigbeeTlvs(data.subarray(tlvOffset, tlvOffset + length), 0, tag);

                    globalTlvs[GlobalTlv.JOINER_ENCAPSULATION] = { additionalTLVs };

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

                    const [additionalTLVs] = readZigbeeTlvs(data.subarray(tlvOffset, tlvOffset + length), 0, tag);

                    globalTlvs[GlobalTlv.BEACON_APPENDIX_ENCAPSULATION] = { additionalTLVs };

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

                    const [additionalTLVs] = readZigbeeTlvs(data.subarray(tlvOffset, tlvOffset + length), 0, tag);

                    globalTlvs[GlobalTlv.BDB_ENCAPSULATION] = { additionalTLVs };

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
