import { beforeAll, describe, expect, it } from "vitest";
import {
    type MACCapabilities,
    type MACHeader,
    type MACZigbeeBeacon,
    decodeMACCapabilities,
    decodeMACFrameControl,
    decodeMACHeader,
    decodeMACPayload,
    decodeMACZigbeeBeacon,
    encodeMACCapabilities,
    encodeMACFrame,
    encodeMACFrameZigbee,
    encodeMACZigbeeBeacon,
} from "../src/zigbee/mac.js";
import {
    type ZigbeeAPSHeader,
    decodeZigbeeAPSFrameControl,
    decodeZigbeeAPSHeader,
    decodeZigbeeAPSPayload,
    encodeZigbeeAPSFrame,
} from "../src/zigbee/zigbee-aps.js";
import {
    type ZigbeeNWKHeader,
    decodeZigbeeNWKFrameControl,
    decodeZigbeeNWKHeader,
    decodeZigbeeNWKPayload,
    encodeZigbeeNWKFrame,
} from "../src/zigbee/zigbee-nwk.js";
import {
    type ZigbeeNWKGPHeader,
    decodeZigbeeNWKGPFrameControl,
    decodeZigbeeNWKGPHeader,
    decodeZigbeeNWKGPPayload,
    encodeZigbeeNWKGPFrame,
} from "../src/zigbee/zigbee-nwkgp.js";
import { ZigbeeKeyType, makeKeyedHashByType, registerDefaultHashedKeys } from "../src/zigbee/zigbee.js";
import {
    NET2_ASSOC_REQ_FROM_DEVICE,
    NET2_ASSOC_RESP_FROM_COORD,
    NET2_BEACON_REQ_FROM_DEVICE,
    NET2_BEACON_RESP_FROM_COORD,
    NET2_COORD_EUI64_BIGINT,
    NET2_DEVICE_LEAVE_BROADCAST,
    NET2_REQUEST_KEY_TC_FROM_DEVICE,
    NET2_TRANSPORT_KEY_NWK_FROM_COORD,
    NET5_GP_CHANNEL_REQUEST_BCAST,
    NET5_NETWORK_KEY,
    NETDEF_ACK_FRAME_FROM_COORD,
    NETDEF_ACK_FRAME_TO_COORD,
    NETDEF_LINK_STATUS_FROM_DEV,
    NETDEF_MTORR_FRAME_FROM_COORD,
    NETDEF_NETWORK_KEY,
    NETDEF_ROUTE_RECORD_TO_COORD,
    NETDEF_TC_KEY,
    NETDEF_ZCL_FRAME_CMD_TO_COORD,
    NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD,
    NETDEF_ZGP_COMMISSIONING,
    NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0,
} from "./data.js";

describe("Zigbee", () => {
    beforeAll(() => {
        registerDefaultHashedKeys(
            makeKeyedHashByType(ZigbeeKeyType.LINK, NETDEF_TC_KEY),
            makeKeyedHashByType(ZigbeeKeyType.NWK, NETDEF_NETWORK_KEY),
            makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, NETDEF_TC_KEY),
            makeKeyedHashByType(ZigbeeKeyType.LOAD, NETDEF_TC_KEY),
        );
    });

    it("encodes/decodes MAC capabilities", () => {
        // common RFD
        let decodedCap: MACCapabilities = {
            alternatePANCoordinator: false,
            deviceType: 0,
            powerSource: 0,
            rxOnWhenIdle: false,
            securityCapability: false,
            allocateAddress: true,
        };
        let encodedCap = 0x80;

        expect(encodeMACCapabilities(decodedCap)).toStrictEqual(encodedCap);
        expect(decodeMACCapabilities(encodedCap)).toStrictEqual(decodedCap);

        // common FFD
        decodedCap = {
            alternatePANCoordinator: false,
            deviceType: 1,
            powerSource: 1,
            rxOnWhenIdle: true,
            securityCapability: false,
            allocateAddress: true,
        };
        encodedCap = 0x8e;

        expect(encodeMACCapabilities(decodedCap)).toStrictEqual(encodedCap);
        expect(decodeMACCapabilities(encodedCap)).toStrictEqual(decodedCap);

        // common COORD
        decodedCap = {
            alternatePANCoordinator: true,
            deviceType: 1,
            powerSource: 1,
            rxOnWhenIdle: true,
            securityCapability: false,
            allocateAddress: true,
        };
        encodedCap = 0x8f;

        expect(encodeMACCapabilities(decodedCap)).toStrictEqual(encodedCap);
        expect(decodeMACCapabilities(encodedCap)).toStrictEqual(decodedCap);
    });

    it("NETDEF_ACK_FRAME_TO_COORD", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ACK_FRAME_TO_COORD, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ACK_FRAME_TO_COORD, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NETDEF_ACK_FRAME_TO_COORD, macHOutOffset, macFCF, macHeader);
        const expectedHeader: MACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 191,
            destinationPANId: 0x1a62,
            destination16: 0x0000,
            destination64: undefined,
            sourcePANId: 0x1a62,
            source16: 0x96ba,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xb4ab,
        };

        expect(macHeader).toStrictEqual(expectedHeader);
        expect(macPayload.byteLength).toStrictEqual(34);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader: ZigbeeNWKHeader = {
            frameControl: {
                frameType: 0,
                protocolVersion: 2,
                discoverRoute: 1,
                multicast: false,
                security: true,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: 0x0000,
            source16: 0x96ba,
            radius: 30,
            seqNum: 151,
            destination64: undefined,
            source64: undefined,
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: {
                control: {
                    keyId: 1,
                    level: 5,
                    nonce: true,
                },
                frameCounter: 45318893,
                keySeqNum: 0,
                micLen: 4,
                source64: 9244571720527165811n,
            },
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);
        expect(nwkPayload).toStrictEqual(Buffer.from([0x02, 0x01, 0x00, 0xef, 0x04, 0x01, 0x01, 0x33]));

        const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
        const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

        const expectedAPSHeader: ZigbeeAPSHeader = {
            frameControl: {
                frameType: 0x2,
                deliveryMode: 0x0,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            destEndpoint: 1,
            group: undefined,
            clusterId: 0xef00,
            profileId: 0x0104,
            sourceEndpoint: 1,
            counter: 51,
            fragmentation: undefined,
            fragBlockNumber: undefined,
            fragACKBitfield: undefined,
            securityHeader: undefined,
        };

        expect(apsHeader).toStrictEqual(expectedAPSHeader);
        expect(apsPayload).toStrictEqual(Buffer.from([]));

        const encMACHeader = structuredClone(macHeader);
        encMACHeader.sourcePANId = undefined;
        const encMACFrame = encodeMACFrameZigbee(encMACHeader, macPayload);

        expect(encMACFrame.subarray(0, -2)).toStrictEqual(NETDEF_ACK_FRAME_TO_COORD.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        encNWKHeader.securityHeader!.control.level = 0;
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);

        const encAPSHeader = structuredClone(apsHeader);
        const encAPSFrame = encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);

        expect(encAPSFrame).toStrictEqual(nwkPayload);
    });

    it("NETDEF_ACK_FRAME_FROM_COORD", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ACK_FRAME_FROM_COORD, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ACK_FRAME_FROM_COORD, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NETDEF_ACK_FRAME_FROM_COORD, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 73,
            destinationPANId: 0x1a62,
            destination16: 0x87c6,
            destination64: undefined,
            sourcePANId: 0x1a62,
            source16: 0x0000,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xf4cb,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(34);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader: ZigbeeNWKHeader = {
            frameControl: {
                frameType: 0,
                protocolVersion: 2,
                discoverRoute: 1,
                multicast: false,
                security: true,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: 0x96ba,
            source16: 0x0000,
            radius: 30,
            seqNum: 203,
            destination64: undefined,
            source64: undefined,
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: {
                control: {
                    keyId: 1,
                    level: 5,
                    nonce: true,
                },
                frameCounter: 99044312,
                keySeqNum: 0,
                micLen: 4,
                source64: 16175115667303284240n,
            },
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);
        expect(nwkPayload).toStrictEqual(Buffer.from([0x02, 0x01, 0x00, 0xef, 0x04, 0x01, 0x01, 0x4d]));

        const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
        const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);
        const expectedAPSHeader: ZigbeeAPSHeader = {
            frameControl: {
                frameType: 0x2,
                deliveryMode: 0x0,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            destEndpoint: 1,
            group: undefined,
            clusterId: 0xef00,
            profileId: 0x0104,
            sourceEndpoint: 1,
            counter: 77,
            fragmentation: undefined,
            fragBlockNumber: undefined,
            fragACKBitfield: undefined,
            securityHeader: undefined,
        };

        expect(apsHeader).toStrictEqual(expectedAPSHeader);
        expect(apsPayload).toStrictEqual(Buffer.from([]));

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;
        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NETDEF_ACK_FRAME_FROM_COORD.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        encNWKHeader.securityHeader!.control.level = 0;
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);

        const encAPSHeader = structuredClone(apsHeader);
        const encAPSFrame = encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);

        expect(encAPSFrame).toStrictEqual(nwkPayload);
    });

    it("NETDEF_LINK_STATUS_FROM_DEV", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_LINK_STATUS_FROM_DEV, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_LINK_STATUS_FROM_DEV, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NETDEF_LINK_STATUS_FROM_DEV, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 92,
            destinationPANId: 0x1a62,
            destination16: 0xffff,
            destination64: undefined,
            sourcePANId: 0x1a62,
            source16: 0xf0a2,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xcab6,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(87);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader: ZigbeeNWKHeader = {
            frameControl: {
                frameType: 1,
                protocolVersion: 2,
                discoverRoute: 0,
                multicast: false,
                security: true,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: true,
                endDeviceInitiator: false,
            },
            destination16: 0xfffc,
            source16: 0xf0a2,
            radius: 1,
            seqNum: 223,
            destination64: undefined,
            source64: 5149013569654176n,
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: {
                control: {
                    keyId: 1,
                    level: 5,
                    nonce: true,
                },
                frameCounter: 5505754,
                keySeqNum: 0,
                micLen: 4,
                source64: 5149013569654176n,
            },
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);
        expect(nwkPayload).toStrictEqual(
            Buffer.from([
                0x08, 0x71, 0x00, 0x00, 0x11, 0x7c, 0x0b, 0x77, 0xca, 0x16, 0x11, 0x20, 0x20, 0x01, 0x03, 0x23, 0x77, 0x74, 0x5e, 0x11, 0xb1, 0x65,
                0x11, 0xb4, 0x67, 0x11, 0x26, 0x73, 0x77, 0xc6, 0x87, 0x31, 0x4f, 0x8c, 0x77, 0xba, 0x96, 0x11, 0x38, 0xaa, 0x11, 0xcd, 0xc8, 0x11,
                0x54, 0xd0, 0x11, 0xf0, 0xf1, 0x11, 0x3d, 0xfd, 0x11,
            ]),
        );

        // TODO Zigbee NWK cmd

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;
        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NETDEF_LINK_STATUS_FROM_DEV.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        encNWKHeader.securityHeader!.control.level = 0;
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);
    });

    it("NETDEF_ZCL_FRAME_CMD_TO_COORD", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZCL_FRAME_CMD_TO_COORD, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZCL_FRAME_CMD_TO_COORD, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NETDEF_ZCL_FRAME_CMD_TO_COORD, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 230,
            destinationPANId: 0x1a62,
            destination16: 0x0000,
            destination64: undefined,
            sourcePANId: 0x1a62,
            source16: 0xaa38,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xc4b3,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(39);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader: ZigbeeNWKHeader = {
            frameControl: {
                frameType: 0,
                protocolVersion: 2,
                discoverRoute: 1,
                multicast: false,
                security: true,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: 0x0000,
            source16: 0xaa38,
            radius: 30,
            seqNum: 128,
            destination64: undefined,
            source64: undefined,
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: {
                control: {
                    keyId: 1,
                    level: 5,
                    nonce: true,
                },
                frameCounter: 43659054,
                keySeqNum: 0,
                micLen: 4,
                source64: 8118874123826907736n,
            },
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);
        expect(nwkPayload).toStrictEqual(Buffer.from([0x00, 0x01, 0x00, 0xef, 0x04, 0x01, 0x01, 0x3f, 0x09, 0x50, 0x25, 0xaf, 0x00]));

        const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
        const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

        const expectedAPSHeader: ZigbeeAPSHeader = {
            frameControl: {
                frameType: 0x0,
                deliveryMode: 0x0,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: false,
            },
            destEndpoint: 1,
            group: undefined,
            clusterId: 0xef00,
            profileId: 0x0104,
            sourceEndpoint: 1,
            counter: 63,
            fragmentation: undefined,
            fragBlockNumber: undefined,
            fragACKBitfield: undefined,
            securityHeader: undefined,
        };

        expect(apsHeader).toStrictEqual(expectedAPSHeader);
        expect(apsPayload).toStrictEqual(Buffer.from([0x09, 0x50, 0x25, 0xaf, 0x00]));

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;
        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NETDEF_ZCL_FRAME_CMD_TO_COORD.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        encNWKHeader.securityHeader!.control.level = 0;
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);

        const encAPSHeader = structuredClone(apsHeader);
        const encAPSFrame = encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);

        expect(encAPSFrame).toStrictEqual(nwkPayload);
    });

    it("NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 231,
            destinationPANId: 0x1a62,
            destination16: 0x0000,
            destination64: undefined,
            sourcePANId: 0x1a62,
            source16: 0xaa38,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xc4b3,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(39);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader: ZigbeeNWKHeader = {
            frameControl: {
                frameType: 0,
                protocolVersion: 2,
                discoverRoute: 1,
                multicast: false,
                security: true,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: 0,
            source16: 0xaa38,
            radius: 30,
            seqNum: 130,
            destination64: undefined,
            source64: undefined,
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: {
                control: {
                    keyId: 1,
                    level: 5,
                    nonce: true,
                },
                frameCounter: 43659055,
                keySeqNum: 0,
                micLen: 4,
                source64: 8118874123826907736n,
            },
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);
        expect(nwkPayload).toStrictEqual(Buffer.from([0x40, 0x01, 0x00, 0xef, 0x04, 0x01, 0x01, 0x40, 0x08, 0x32, 0x0b, 0x25, 0x00]));

        const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
        const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

        const expectedAPSHeader: ZigbeeAPSHeader = {
            frameControl: {
                frameType: 0x0,
                deliveryMode: 0x0,
                ackFormat: false,
                security: false,
                ackRequest: true,
                extendedHeader: false,
            },
            destEndpoint: 1,
            group: undefined,
            clusterId: 0xef00,
            profileId: 0x0104,
            sourceEndpoint: 1,
            counter: 64,
            fragmentation: undefined,
            fragBlockNumber: undefined,
            fragACKBitfield: undefined,
            securityHeader: undefined,
        };

        expect(apsHeader).toStrictEqual(expectedAPSHeader);
        expect(apsPayload).toStrictEqual(Buffer.from([0x08, 0x32, 0x0b, 0x25, 0x00]));

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;
        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        encNWKHeader.securityHeader!.control.level = 0;
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);

        const encAPSHeader = structuredClone(apsHeader);
        const encAPSFrame = encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);

        expect(encAPSFrame).toStrictEqual(nwkPayload);
    });

    it("NETDEF_ROUTE_RECORD_TO_COORD", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ROUTE_RECORD_TO_COORD, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ROUTE_RECORD_TO_COORD, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NETDEF_ROUTE_RECORD_TO_COORD, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 155,
            destinationPANId: 0x1a62,
            destination16: 0x0000,
            destination64: undefined,
            sourcePANId: 0x1a62,
            source16: 0xf1f0,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0x9c9f,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(38);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader = {
            frameControl: {
                frameType: 1,
                protocolVersion: 2,
                discoverRoute: 0,
                multicast: false,
                security: true,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: true,
                endDeviceInitiator: false,
            },
            destination16: 0x0000,
            source16: 0xac3a,
            radius: 30,
            seqNum: 207,
            destination64: undefined,
            source64: 5149013578478658n,
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: {
                control: {
                    keyId: 1,
                    level: 5,
                    nonce: true,
                },
                frameCounter: 6240313,
                keySeqNum: 0,
                micLen: 4,
                source64: 5149013569454355n,
            },
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);
        expect(nwkPayload).toStrictEqual(Buffer.from([0x05, 0x01, 0xf0, 0xf1]));

        // TODO Zigbee NWK cmd

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;
        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NETDEF_ROUTE_RECORD_TO_COORD.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        encNWKHeader.securityHeader!.control.level = 0;
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);
    });

    it("NETDEF_MTORR_FRAME_FROM_COORD", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_MTORR_FRAME_FROM_COORD, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_MTORR_FRAME_FROM_COORD, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NETDEF_MTORR_FRAME_FROM_COORD, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 93,
            destinationPANId: 0x1a62,
            destination16: 0xffff,
            destination64: undefined,
            sourcePANId: 0x1a62,
            source16: 0x0000,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xf4cb,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(40);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader: ZigbeeNWKHeader = {
            frameControl: {
                frameType: 1,
                protocolVersion: 2,
                discoverRoute: 0,
                multicast: false,
                security: true,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: true,
                endDeviceInitiator: false,
            },
            destination16: 0xfffc,
            source16: 0,
            radius: 30,
            seqNum: 237,
            destination64: undefined,
            source64: 16175115667303284240n,
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: {
                control: {
                    keyId: 1,
                    level: 5,
                    nonce: true,
                },
                frameCounter: 99044332,
                keySeqNum: 0,
                micLen: 4,
                source64: 16175115667303284240n,
            },
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);
        expect(nwkPayload).toStrictEqual(Buffer.from([0x01, 0x08, 0x2d, 0xfc, 0xff, 0x00]));

        // TODO Zigbee NWK cmd

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;
        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NETDEF_MTORR_FRAME_FROM_COORD.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        encNWKHeader.securityHeader!.control.level = 0;
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);
    });

    it("NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 0x1,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 0x2,
                frameVersion: 0,
                sourceAddrMode: 0x0,
            },
            sequenceNumber: 185,
            destinationPANId: 0xffff,
            destination16: 0xffff,
            destination64: undefined,
            sourcePANId: 0xffff,
            source16: undefined,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(15);

        const [nwkGPFCF, nwkGPFCFOutOffset] = decodeZigbeeNWKGPFrameControl(macPayload, 0);
        const [nwkGPHeader, nwkGPHOutOffset] = decodeZigbeeNWKGPHeader(macPayload, nwkGPFCFOutOffset, nwkGPFCF);
        const nwkGPPayload = decodeZigbeeNWKGPPayload(macPayload, nwkGPHOutOffset, NETDEF_NETWORK_KEY, macHeader.source64, nwkGPFCF, nwkGPHeader);
        const expectedNWKGPHeader: ZigbeeNWKGPHeader = {
            frameControl: {
                frameType: 0x0,
                protocolVersion: 3,
                autoCommissioning: false,
                nwkFrameControlExtension: true,
            },
            frameControlExt: {
                appId: 0,
                securityLevel: 2,
                securityKey: true,
                rxAfterTx: false,
                direction: 0,
            },
            sourceId: 0x01719697,
            endpoint: undefined,
            securityFrameCounter: 185,
            micSize: 4,
            payloadLength: 1,
            mic: 0xd1fdebfe,
        };

        expect(nwkGPHeader).toStrictEqual(expectedNWKGPHeader);
        expect(nwkGPPayload).toStrictEqual(Buffer.from([0x10]));

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;

        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0.subarray(0, -2));

        // XXX: don't have the GP security key for this one
        // const encNWKGPHeader = structuredClone(nwkGPHeader);

        // const encNWKFrame = encodeZigbeeNWKGPFrame(encNWKGPHeader, nwkGPPayload, NETDEF_NETWORK_KEY, macHeader.source64);

        // expect(encNWKFrame).toStrictEqual(macPayload);
    });

    it("NETDEF_ZGP_COMMISSIONING", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZGP_COMMISSIONING, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZGP_COMMISSIONING, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NETDEF_ZGP_COMMISSIONING, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 0x1,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 0x2,
                frameVersion: 0,
                sourceAddrMode: 0x0,
            },
            sequenceNumber: 70,
            destinationPANId: 0xffff,
            destination16: 0xffff,
            destination64: undefined,
            sourcePANId: 0xffff,
            source16: undefined,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(57);

        const [nwkGPFCF, nwkGPFCFOutOffset] = decodeZigbeeNWKGPFrameControl(macPayload, 0);
        const [nwkGPHeader, nwkGPHOutOffset] = decodeZigbeeNWKGPHeader(macPayload, nwkGPFCFOutOffset, nwkGPFCF);
        const nwkGPPayload = decodeZigbeeNWKGPPayload(macPayload, nwkGPHOutOffset, NETDEF_NETWORK_KEY, macHeader.source64, nwkGPFCF, nwkGPHeader);
        const expectedNWKGPHeader: ZigbeeNWKGPHeader = {
            frameControl: {
                frameType: 0x0,
                protocolVersion: 3,
                autoCommissioning: false,
                nwkFrameControlExtension: false,
            },
            frameControlExt: undefined,
            sourceId: 0x0155f47a,
            endpoint: undefined,
            securityFrameCounter: undefined,
            micSize: 0,
            payloadLength: 52,
            mic: undefined,
        };

        expect(nwkGPHeader).toStrictEqual(expectedNWKGPHeader);
        expect(nwkGPPayload).toStrictEqual(
            Buffer.from([
                0xe0, 0x2, 0x85, 0xf2, 0xc9, 0x25, 0x82, 0x1d, 0xf4, 0x6f, 0x45, 0x8c, 0xf0, 0xe6, 0x37, 0xaa, 0xc3, 0xba, 0xb6, 0xaa, 0x45, 0x83,
                0x1a, 0x11, 0x46, 0x23, 0x0, 0x0, 0x4, 0x16, 0x10, 0x11, 0x22, 0x23, 0x18, 0x19, 0x14, 0x15, 0x12, 0x13, 0x64, 0x65, 0x62, 0x63, 0x1e,
                0x1f, 0x1c, 0x1d, 0x1a, 0x1b, 0x16, 0x17,
            ]),
        );

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;

        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NETDEF_ZGP_COMMISSIONING.subarray(0, -2));

        const encNWKGPHeader = structuredClone(nwkGPHeader);

        const encNWKFrame = encodeZigbeeNWKGPFrame(encNWKGPHeader, nwkGPPayload, NETDEF_NETWORK_KEY, macHeader.source64);

        expect(encNWKFrame).toStrictEqual(macPayload);
    });

    it("NET2_DEVICE_LEAVE_BROADCAST", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_DEVICE_LEAVE_BROADCAST, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NET2_DEVICE_LEAVE_BROADCAST, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NET2_DEVICE_LEAVE_BROADCAST, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 237,
            destinationPANId: 0x1a64,
            destination16: 0xffff,
            destination64: undefined,
            sourcePANId: 0x1a64,
            source16: 0xa18f,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(36);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader: ZigbeeNWKHeader = {
            frameControl: {
                frameType: 1,
                protocolVersion: 2,
                discoverRoute: 0,
                multicast: false,
                security: true,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: true,
                endDeviceInitiator: false,
            },
            destination16: 0xfffd,
            source16: 0xa18f,
            radius: 1,
            seqNum: 195,
            destination64: undefined,
            source64: BigInt("0xa4c1386d9b280fdf"),
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: {
                control: {
                    keyId: 1,
                    level: 5,
                    nonce: true,
                },
                frameCounter: 33483,
                keySeqNum: 0,
                micLen: 4,
                source64: BigInt("0xa4c1386d9b280fdf"),
            },
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);
        expect(nwkPayload).toStrictEqual(Buffer.from([0x04, 0x00]));

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;

        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NET2_DEVICE_LEAVE_BROADCAST.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        encNWKHeader.securityHeader!.control.level = 0;
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);
    });

    it("NET2_BEACON_REQ_FROM_DEVICE", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_BEACON_REQ_FROM_DEVICE, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NET2_BEACON_REQ_FROM_DEVICE, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NET2_BEACON_REQ_FROM_DEVICE, macHOutOffset, macFCF, macHeader);

        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 3,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 0,
            },
            sequenceNumber: 100,
            destinationPANId: 65535,
            destination16: 65535,
            destination64: undefined,
            sourcePANId: 65535,
            source16: undefined,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: 7,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(0);
    });

    it("NET2_BEACON_RESP_FROM_COORD", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_BEACON_RESP_FROM_COORD, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NET2_BEACON_RESP_FROM_COORD, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NET2_BEACON_RESP_FROM_COORD, macHOutOffset, macFCF, macHeader);
        const beacon = decodeMACZigbeeBeacon(macPayload, 0);

        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 0,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 0,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 186,
            destinationPANId: undefined,
            destination16: undefined,
            destination64: undefined,
            sourcePANId: 0x1a64,
            source16: 0x0000,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: {
                beaconOrder: 15,
                superframeOrder: 15,
                finalCAPSlot: 15,
                batteryExtension: false,
                panCoordinator: true,
                associationPermit: true,
            },
            gtsInfo: {
                permit: false,
                directionByte: undefined,
                directions: undefined,
                addresses: undefined,
                timeLengths: undefined,
                slots: undefined,
            },
            pendAddr: { addr16List: undefined, addr64List: undefined },
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };
        const expectedBeacon: MACZigbeeBeacon = {
            protocolId: 0,
            profile: 2,
            version: 2,
            routerCapacity: true,
            deviceDepth: 0,
            endDeviceCapacity: true,
            extendedPANId: 15987178197214944733n,
            txOffset: 16777215,
            updateId: 0,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(15);
        expect(beacon).toStrictEqual(expectedBeacon);
        expect(macPayload).toStrictEqual(encodeMACZigbeeBeacon(beacon));
    });

    it("NET2_ASSOC_REQ_FROM_DEVICE", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_ASSOC_REQ_FROM_DEVICE, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NET2_ASSOC_REQ_FROM_DEVICE, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NET2_ASSOC_REQ_FROM_DEVICE, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 0x3,
                securityEnabled: false,
                framePending: false,
                ackRequest: true,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 0x2,
                frameVersion: 0,
                sourceAddrMode: 0x3,
            },
            sequenceNumber: 116,
            destinationPANId: 0x1a64,
            destination16: 0x0000,
            destination64: undefined,
            sourcePANId: 0xffff,
            source16: undefined,
            source64: BigInt("0xa4c1386d9b280fdf"),
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: 0x01,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(1);
        expect(macPayload).toStrictEqual(Buffer.from([0x8e]));

        const encHeader = structuredClone(macHeader);

        const encFrame = encodeMACFrame(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NET2_ASSOC_REQ_FROM_DEVICE.subarray(0, -2));
    });

    it("NET2_ASSOC_RESP_FROM_COORD", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_ASSOC_RESP_FROM_COORD, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NET2_ASSOC_RESP_FROM_COORD, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NET2_ASSOC_RESP_FROM_COORD, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 0x3,
                securityEnabled: false,
                framePending: false,
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 0x3,
                frameVersion: 0,
                sourceAddrMode: 0x3,
            },
            sequenceNumber: 187,
            destinationPANId: 0x1a64,
            destination16: undefined,
            destination64: BigInt("0xa4c1386d9b280fdf"),
            sourcePANId: 0x1a64,
            source16: undefined,
            source64: NET2_COORD_EUI64_BIGINT,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: 0x02,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(3);
        expect(macPayload).toStrictEqual(Buffer.from([0x8f, 0xa1, 0x00]));

        const encHeader = structuredClone(macHeader);

        const encFrame = encodeMACFrame(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NET2_ASSOC_RESP_FROM_COORD.subarray(0, -2));
    });

    it("NET2_TRANSPORT_KEY_NWK_FROM_COORD", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_TRANSPORT_KEY_NWK_FROM_COORD, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NET2_TRANSPORT_KEY_NWK_FROM_COORD, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NET2_TRANSPORT_KEY_NWK_FROM_COORD, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 189,
            destinationPANId: 0x1a64,
            destination16: 0xa18f,
            destination64: undefined,
            sourcePANId: 0x1a64,
            source16: 0x0000,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(62);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader: ZigbeeNWKHeader = {
            frameControl: {
                frameType: 0,
                protocolVersion: 2,
                discoverRoute: 0x0,
                multicast: false,
                security: false,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: 0xa18f,
            source16: 0x0000,
            radius: 30,
            seqNum: 161,
            destination64: undefined,
            source64: undefined,
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: undefined,
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);

        const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
        const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, NET2_COORD_EUI64_BIGINT, apsFCF, apsHeader);

        const expectedAPSHeader: ZigbeeAPSHeader = {
            frameControl: {
                frameType: 0x1,
                deliveryMode: 0x0,
                ackFormat: false,
                security: true,
                ackRequest: false,
                extendedHeader: false,
            },
            destEndpoint: undefined,
            group: undefined,
            clusterId: undefined,
            profileId: undefined,
            sourceEndpoint: undefined,
            counter: 106,
            fragmentation: undefined,
            fragBlockNumber: undefined,
            fragACKBitfield: undefined,
            securityHeader: {
                control: {
                    level: 5,
                    keyId: 0x2,
                    nonce: true,
                },
                frameCounter: 86022,
                source64: NET2_COORD_EUI64_BIGINT,
                keySeqNum: undefined,
                micLen: 4,
            },
        };

        expect(apsHeader).toStrictEqual(expectedAPSHeader);
        expect(apsPayload).toStrictEqual(
            Buffer.from([
                0x05, 0x01, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0d, 0x00, 0xdf, 0x0f, 0x28,
                0x9b, 0x6d, 0x38, 0xc1, 0xa4, 0xf9, 0x99, 0x05, 0xfe, 0xff, 0x50, 0x4b, 0x80,
            ]),
        );

        const encMACHeader = structuredClone(macHeader);
        encMACHeader.sourcePANId = undefined;
        const encMACFrame = encodeMACFrameZigbee(encMACHeader, macPayload);

        expect(encMACFrame.subarray(0, -2)).toStrictEqual(NET2_TRANSPORT_KEY_NWK_FROM_COORD.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);

        const encAPSHeader = structuredClone(apsHeader);
        encAPSHeader.securityHeader!.control.level = 0;
        const encAPSFrame = encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);

        expect(encAPSFrame).toStrictEqual(nwkPayload);
    });

    it("NET2_REQUEST_KEY_TC_FROM_DEVICE", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_REQUEST_KEY_TC_FROM_DEVICE, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NET2_REQUEST_KEY_TC_FROM_DEVICE, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NET2_REQUEST_KEY_TC_FROM_DEVICE, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 1,
                securityEnabled: false,
                framePending: false,
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2,
                frameVersion: 0,
                sourceAddrMode: 2,
            },
            sequenceNumber: 130,
            destinationPANId: 0x1a64,
            destination16: 0x0000,
            destination64: undefined,
            sourcePANId: 0x1a64,
            source16: 0xa18f,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(47);

        const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
        const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
        const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);
        const expectedNWKHeader: ZigbeeNWKHeader = {
            frameControl: {
                frameType: 0,
                protocolVersion: 2,
                discoverRoute: 0x1,
                multicast: false,
                security: true,
                sourceRoute: false,
                extendedDestination: false,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: 0x0000,
            source16: 0xa18f,
            radius: 30,
            seqNum: 39,
            destination64: undefined,
            source64: undefined,
            relayIndex: undefined,
            relayAddresses: undefined,
            securityHeader: {
                control: {
                    keyId: 0x01,
                    level: 0x05,
                    nonce: true,
                },
                frameCounter: 33497,
                keySeqNum: 0,
                micLen: 4,
                source64: 11871832136131022815n,
            },
        };

        expect(nwkHeader).toStrictEqual(expectedNWKHeader);

        const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
        const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
        const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, NET2_COORD_EUI64_BIGINT, apsFCF, apsHeader);
        const expectedAPSHeader: ZigbeeAPSHeader = {
            frameControl: {
                frameType: 0x1,
                deliveryMode: 0x0,
                ackFormat: false,
                security: true,
                ackRequest: false,
                extendedHeader: false,
            },
            destEndpoint: undefined,
            group: undefined,
            clusterId: undefined,
            profileId: undefined,
            sourceEndpoint: undefined,
            counter: 131,
            fragmentation: undefined,
            fragBlockNumber: undefined,
            fragACKBitfield: undefined,
            securityHeader: {
                control: {
                    level: 5,
                    keyId: 0x0,
                    nonce: true,
                },
                frameCounter: 33496,
                source64: 11871832136131022815n,
                keySeqNum: undefined,
                micLen: 4,
            },
        };

        expect(apsHeader).toStrictEqual(expectedAPSHeader);
        expect(apsPayload).toStrictEqual(Buffer.from([0x08, 0x04]));

        const encMACHeader = structuredClone(macHeader);
        encMACHeader.sourcePANId = undefined;
        const encMACFrame = encodeMACFrameZigbee(encMACHeader, macPayload);

        expect(encMACFrame.subarray(0, -2)).toStrictEqual(NET2_REQUEST_KEY_TC_FROM_DEVICE.subarray(0, -2));

        const encNWKHeader = structuredClone(nwkHeader);
        encNWKHeader.securityHeader!.control.level = 0;
        const encNWKFrame = encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

        expect(encNWKFrame).toStrictEqual(macPayload);

        const encAPSHeader = structuredClone(apsHeader);
        encAPSHeader.securityHeader!.control.level = 0;
        const encAPSFrame = encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);

        expect(encAPSFrame).toStrictEqual(nwkPayload);
    });

    it("NET5_GP_CHANNEL_REQUEST_BCAST", () => {
        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET5_GP_CHANNEL_REQUEST_BCAST, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(NET5_GP_CHANNEL_REQUEST_BCAST, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(NET5_GP_CHANNEL_REQUEST_BCAST, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 0x1,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 0x2,
                frameVersion: 0,
                sourceAddrMode: 0x0,
            },
            sequenceNumber: 1,
            destinationPANId: 0xffff,
            destination16: 0xffff,
            destination64: undefined,
            sourcePANId: 0xffff,
            source16: undefined,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0x7808,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(3);

        const [nwkGPFCF, nwkGPFCFOutOffset] = decodeZigbeeNWKGPFrameControl(macPayload, 0);
        const [nwkGPHeader, nwkGPHOutOffset] = decodeZigbeeNWKGPHeader(macPayload, nwkGPFCFOutOffset, nwkGPFCF);
        const nwkGPPayload = decodeZigbeeNWKGPPayload(macPayload, nwkGPHOutOffset, NET5_NETWORK_KEY, macHeader.source64, nwkGPFCF, nwkGPHeader);
        const expectedNWKGPHeader: ZigbeeNWKGPHeader = {
            frameControl: {
                frameType: 0x1,
                protocolVersion: 3,
                autoCommissioning: true,
                nwkFrameControlExtension: false,
            },
            frameControlExt: undefined,
            sourceId: undefined,
            endpoint: undefined,
            securityFrameCounter: undefined,
            micSize: 0,
            payloadLength: 2,
            mic: undefined,
        };

        expect(nwkGPHeader).toStrictEqual(expectedNWKGPHeader);
        expect(nwkGPPayload).toStrictEqual(Buffer.from([0xe3, 0x85]));

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;

        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(NET5_GP_CHANNEL_REQUEST_BCAST.subarray(0, -2));

        const encNWKGPHeader = structuredClone(nwkGPHeader);
        const encNWKFrame = encodeZigbeeNWKGPFrame(encNWKGPHeader, nwkGPPayload, NET5_NETWORK_KEY, macHeader.source64);

        expect(encNWKFrame).toStrictEqual(macPayload);
    });

    it("ZGP FULL test vector from spec v1.1.1 #A.1.5.4.2", () => {
        const securityKey = Buffer.from([0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf]);
        const rawPayload = Buffer.from([
            0x01, 0x08, 0x02, 0xff, 0xff, 0xff, 0xff, 0x8c, 0x10, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00, 0x20, 0xcf, 0x78, 0x7e, 0x72, 0xff,
            0xff,
        ]);

        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(rawPayload, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(rawPayload, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(rawPayload, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 0x1,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 0x2,
                frameVersion: 0,
                sourceAddrMode: 0x0,
            },
            sequenceNumber: 0x02,
            destinationPANId: 0xffff,
            destination16: 0xffff,
            destination64: undefined,
            sourcePANId: 0xffff,
            source16: undefined,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(15);

        const [nwkGPFCF, nwkGPFCFOutOffset] = decodeZigbeeNWKGPFrameControl(macPayload, 0);
        const [nwkGPHeader, nwkGPHOutOffset] = decodeZigbeeNWKGPHeader(macPayload, nwkGPFCFOutOffset, nwkGPFCF);
        const nwkGPPayload = decodeZigbeeNWKGPPayload(macPayload, nwkGPHOutOffset, securityKey, macHeader.source64, nwkGPFCF, nwkGPHeader);
        const expectedNWKGPHeader: ZigbeeNWKGPHeader = {
            frameControl: {
                frameType: 0x0,
                protocolVersion: 3,
                autoCommissioning: false,
                nwkFrameControlExtension: true,
            },
            frameControlExt: {
                appId: 0,
                securityLevel: 2,
                securityKey: false,
                rxAfterTx: false,
                direction: 0,
            },
            sourceId: 0x87654321,
            endpoint: undefined,
            securityFrameCounter: 0x00000002,
            micSize: 4,
            payloadLength: 1,
            mic: 0x727e78cf,
        };

        expect(nwkGPHeader).toStrictEqual(expectedNWKGPHeader);
        expect(nwkGPPayload).toStrictEqual(Buffer.from([0x20]));

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;

        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(rawPayload.subarray(0, -2));

        const encNWKGPHeader = structuredClone(nwkGPHeader);

        const encNWKFrame = encodeZigbeeNWKGPFrame(encNWKGPHeader, nwkGPPayload, securityKey, macHeader.source64);

        expect(encNWKFrame).toStrictEqual(macPayload);
    });

    it("ZGP FULLENCR test vector from spec v1.1.1 #A.1.5.4.3", () => {
        const securityKey = Buffer.from([0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf]);
        const rawPayload = Buffer.from([
            0x01, 0x08, 0x02, 0xff, 0xff, 0xff, 0xff, 0x8c, 0x18, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00, 0x83, 0xca, 0x43, 0x24, 0xdd, 0xff,
            0xff,
        ]);

        const [macFCF, macFCFOutOffset] = decodeMACFrameControl(rawPayload, 0);
        const [macHeader, macHOutOffset] = decodeMACHeader(rawPayload, macFCFOutOffset, macFCF);
        const macPayload = decodeMACPayload(rawPayload, macHOutOffset, macFCF, macHeader);
        const expectedMACHeader: MACHeader = {
            frameControl: {
                frameType: 0x1,
                securityEnabled: false,
                framePending: false,
                ackRequest: false,
                panIdCompression: false,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 0x2,
                frameVersion: 0,
                sourceAddrMode: 0x0,
            },
            sequenceNumber: 0x02,
            destinationPANId: 0xffff,
            destination16: 0xffff,
            destination64: undefined,
            sourcePANId: 0xffff,
            source16: undefined,
            source64: undefined,
            auxSecHeader: undefined,
            superframeSpec: undefined,
            gtsInfo: undefined,
            pendAddr: undefined,
            commandId: undefined,
            headerIE: undefined,
            frameCounter: undefined,
            keySeqCounter: undefined,
            fcs: 0xffff,
        };

        expect(macHeader).toStrictEqual(expectedMACHeader);
        expect(macPayload.byteLength).toStrictEqual(15);

        const [nwkGPFCF, nwkGPFCFOutOffset] = decodeZigbeeNWKGPFrameControl(macPayload, 0);
        const [nwkGPHeader, nwkGPHOutOffset] = decodeZigbeeNWKGPHeader(macPayload, nwkGPFCFOutOffset, nwkGPFCF);
        const nwkGPPayload = decodeZigbeeNWKGPPayload(macPayload, nwkGPHOutOffset, securityKey, macHeader.source64, nwkGPFCF, nwkGPHeader);
        const expectedNWKGPHeader: ZigbeeNWKGPHeader = {
            frameControl: {
                frameType: 0x0,
                protocolVersion: 3,
                autoCommissioning: false,
                nwkFrameControlExtension: true,
            },
            frameControlExt: {
                appId: 0,
                securityLevel: 3,
                securityKey: false,
                rxAfterTx: false,
                direction: 0,
            },
            sourceId: 0x87654321,
            endpoint: undefined,
            securityFrameCounter: 0x00000002,
            micSize: 4,
            payloadLength: 1,
            mic: 0xdd2443ca,
        };

        expect(nwkGPHeader).toStrictEqual(expectedNWKGPHeader);
        expect(nwkGPPayload).toStrictEqual(Buffer.from([0x20]));

        const encHeader = structuredClone(macHeader);
        encHeader.sourcePANId = undefined;

        const encFrame = encodeMACFrameZigbee(encHeader, macPayload);

        expect(encFrame.subarray(0, -2)).toStrictEqual(rawPayload.subarray(0, -2));

        const encNWKGPHeader = structuredClone(nwkGPHeader);

        const encNWKFrame = encodeZigbeeNWKGPFrame(encNWKGPHeader, nwkGPPayload, securityKey, macHeader.source64);

        expect(encNWKFrame).toStrictEqual(macPayload);
    });
});
