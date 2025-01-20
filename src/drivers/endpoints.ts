import { ZigbeeMACConsts } from "../zigbee/mac.js";
import { ZigbeeConsts } from "../zigbee/zigbee.js";

const MAC_CAPABILITIES =
    (1 & 0x01) | // alternatePANCoordinator
    ((1 << 1) & 0x02) | // deviceType
    ((1 << 2) & 0x04) | // powerSource
    ((1 << 3) & 0x08) | // rxOnWhenIdle
    ((0 << 4) & 0x10) | // reserved1
    ((0 << 5) & 0x20) | // reserved2
    ((0 << 6) & 0x40) | // securityCapability
    ((1 << 7) & 0x80); // allocateAddress
const MANUFACTURER_CODE = 0xffff;
const SERVER_MASK =
    (1 & 0x01) | // primaryTrustCenter
    ((0 << 1) & 0x02) | // backupTrustCenter
    ((0 << 2) & 0x04) | // deprecated1
    ((0 << 3) & 0x08) | // deprecated2
    ((0 << 4) & 0x10) | // deprecated3
    ((0 << 5) & 0x20) | // deprecated4
    ((1 << 6) & 0x40) | // networkManager
    ((0 << 7) & 0x80) | // reserved1
    ((0 << 8) & 0x100) | // reserved2
    ((22 << 9) & 0xfe00); // stackComplianceRevision TODO: update to 23 once properly supported

const EP_HA = 1;
const EP_HA_PROFILE_ID = 0x0104;
const EP_HA_DEVICE_ID = 0x65;
const EP_HA_INPUT_CLUSTERS = [
    0x0000, // Basic
    0x0003, // Identify
    0x0006, // On/off
    0x0008, // Level Control
    0x000a, // Time
    0x0019, // Over the Air Bootloading
    // Cluster.genPowerProfile.ID,// 0x001A, // Power Profile XXX: missing ZCL cluster def in Z2M?
    0x0300, // Color Control
];
const EP_HA_OUTPUT_CLUSTERS = [
    0x0000, // Basic
    0x0003, // Identify
    0x0004, // Groups
    0x0005, // Scenes
    0x0006, // On/off
    0x0008, // Level Control
    0x0020, // Poll Control
    0x0300, // Color Control
    0x0400, // Illuminance Measurement
    0x0402, // Temperature Measurement
    0x0405, // Relative Humidity Measurement
    0x0406, // Occupancy Sensing
    0x0500, // IAS Zone
    0x0702, // Simple Metering
    0x0b01, // Meter Identification
    0x0b03, // Appliance Statistics
    0x0b04, // Electrical Measurement
    0x1000, // touchlink
];
const EP_GP = 242;
const EP_GP_PROFILE_ID = 0xa1e0;
const EP_GP_DEVICE_ID = 0x66;
const EP_GP_INPUT_CLUSTERS = [
    0x0021, // Green Power
];
const EP_GP_OUTPUT_CLUSTERS = [
    0x0021, // Green Power
];

const ACTIVE_ENDPOINTS_RESPONSE = [0x00, 0x00, 0x00, 0x00, 2, EP_HA, EP_GP];

export function encodeCoordinatorDescriptors(eui64: bigint): [address: Buffer, node: Buffer, power: Buffer, simple: Buffer, activeEndpoints: Buffer] {
    // works for both NETWORK & IEEE response
    const address = Buffer.alloc(12);
    let offset = 2; // skip seqNum (set on use), status

    address.writeBigUInt64LE(eui64, offset);
    offset += 8;
    address.writeUInt16LE(ZigbeeConsts.COORDINATOR_ADDRESS, offset);
    offset += 2;

    const node = Buffer.alloc(17);
    offset = 4; // skip seqNum (set on use), status, nwkAddress

    node.writeUInt8(
        (0 & 0x07) | // logicalType
            ((0 << 5) & 0x20), // fragmentationSupported
        offset,
    );
    offset += 1;
    node.writeUInt8(
        (0 & 0x07) | // apsFlags
            ((8 << 3) & 0xf8), // frequencyBand
        offset,
    );
    offset += 1;
    node.writeUInt8(MAC_CAPABILITIES, offset);
    offset += 1;
    node.writeUInt16LE(MANUFACTURER_CODE, offset);
    offset += 2;
    node.writeUInt8(0xff, offset);
    offset += 1;
    node.writeUInt16LE(ZigbeeMACConsts.FRAME_MAX_SIZE, offset);
    offset += 2;
    node.writeUInt16LE(SERVER_MASK, offset);
    offset += 2;
    node.writeUInt16LE(ZigbeeMACConsts.FRAME_MAX_SIZE, offset);
    offset += 2;
    // skip deprecated
    offset += 1;

    const power = Buffer.alloc(6);
    offset = 4; // skip seqNum (set on use), status, nwkAddress

    power.writeUInt8(
        (0 & 0xf) | // currentPowerMode
            ((0 & 0xf) << 4), // availPowerSources
        offset,
    );
    offset += 1;
    power.writeUInt8(
        (0 & 0xf) | // currentPowerSource
            ((0b1100 & 0xf) << 4), // currentPowerSourceLevel
        offset,
    );
    offset += 1;

    const simple = Buffer.alloc(
        21 +
            (EP_HA_INPUT_CLUSTERS.length + EP_HA_OUTPUT_CLUSTERS.length + EP_GP_INPUT_CLUSTERS.length + EP_GP_OUTPUT_CLUSTERS.length) *
                2 /* uint16_t */,
    );
    offset = 4; // skip seqNum (set on use), status, nwkAddress

    simple.writeUInt8(
        16 +
            (EP_HA_INPUT_CLUSTERS.length + EP_HA_OUTPUT_CLUSTERS.length + EP_GP_INPUT_CLUSTERS.length + EP_GP_OUTPUT_CLUSTERS.length) *
                2 /* uint16_t */,
        offset,
    );
    offset += 1;
    // HA endpoint
    simple.writeUInt8(EP_HA, offset);
    offset += 1;
    simple.writeUInt16LE(EP_HA_PROFILE_ID, offset);
    offset += 2;
    simple.writeUInt16LE(EP_HA_DEVICE_ID, offset);
    offset += 2;
    simple.writeUInt8(1, offset);
    offset += 1;
    simple.writeUInt8(EP_HA_INPUT_CLUSTERS.length, offset);
    offset += 1;

    for (const haInCluster of EP_HA_INPUT_CLUSTERS) {
        simple.writeUInt16LE(haInCluster, offset);
        offset += 2;
    }

    simple.writeUInt8(EP_HA_OUTPUT_CLUSTERS.length, offset);
    offset += 1;

    for (const haOutCluster of EP_HA_OUTPUT_CLUSTERS) {
        simple.writeUInt16LE(haOutCluster, offset);
        offset += 2;
    }

    // GP endpoint
    simple.writeUInt8(EP_GP, offset);
    offset += 1;
    simple.writeUInt16LE(EP_GP_PROFILE_ID, offset);
    offset += 2;
    simple.writeUInt16LE(EP_GP_DEVICE_ID, offset);
    offset += 2;
    simple.writeUInt8(1, offset);
    offset += 1;
    simple.writeUInt8(EP_GP_INPUT_CLUSTERS.length, offset);
    offset += 1;

    for (const gpInCluster of EP_GP_INPUT_CLUSTERS) {
        simple.writeUInt16LE(gpInCluster, offset);
        offset += 2;
    }

    simple.writeUInt8(EP_GP_OUTPUT_CLUSTERS.length, offset);
    offset += 1;

    for (const gpOutCluster of EP_GP_OUTPUT_CLUSTERS) {
        simple.writeUInt16LE(gpOutCluster, offset);
        offset += 2;
    }

    const activeEndpoints = Buffer.from(ACTIVE_ENDPOINTS_RESPONSE);

    return [address, node, power, simple, activeEndpoints];
}
