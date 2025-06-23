import { bench, describe } from "vitest";
import {
    decodeMACFrameControl,
    decodeMACHeader,
    decodeMACPayload,
    decodeMACZigbeeBeacon,
    encodeMACFrame,
    encodeMACFrameZigbee,
} from "../src/zigbee/mac";
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeKeyType } from "../src/zigbee/zigbee";
import { decodeZigbeeAPSFrameControl, decodeZigbeeAPSHeader, decodeZigbeeAPSPayload, encodeZigbeeAPSFrame } from "../src/zigbee/zigbee-aps";
import { decodeZigbeeNWKFrameControl, decodeZigbeeNWKHeader, decodeZigbeeNWKPayload, encodeZigbeeNWKFrame } from "../src/zigbee/zigbee-nwk";
import { decodeZigbeeNWKGPFrameControl, decodeZigbeeNWKGPHeader, decodeZigbeeNWKGPPayload, encodeZigbeeNWKGPFrame } from "../src/zigbee/zigbee-nwkgp";
import {
    NET2_ASSOC_REQ_FROM_DEVICE,
    NET2_ASSOC_RESP_FROM_COORD,
    NET2_BEACON_REQ_FROM_DEVICE,
    NET2_BEACON_RESP_FROM_COORD,
    NET2_COORD_EUI64_BIGINT,
    NET2_DEVICE_LEAVE_BROADCAST,
    NET2_REQUEST_KEY_TC_FROM_DEVICE,
    NET2_TRANSPORT_KEY_NWK_FROM_COORD,
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
} from "./data";

describe("Zigbee", () => {
    registerDefaultHashedKeys(
        makeKeyedHashByType(ZigbeeKeyType.LINK, NETDEF_TC_KEY),
        makeKeyedHashByType(ZigbeeKeyType.NWK, NETDEF_NETWORK_KEY),
        makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, NETDEF_TC_KEY),
        makeKeyedHashByType(ZigbeeKeyType.LOAD, NETDEF_TC_KEY),
    );

    bench(
        "NETDEF_ACK_FRAME_TO_COORD",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ACK_FRAME_TO_COORD, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ACK_FRAME_TO_COORD, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NETDEF_ACK_FRAME_TO_COORD, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

            const encMACHeader = structuredClone(macHeader);
            encMACHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encMACHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);

            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

            const encAPSHeader = structuredClone(apsHeader);

            encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NETDEF_ACK_FRAME_FROM_COORD",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ACK_FRAME_FROM_COORD, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ACK_FRAME_FROM_COORD, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NETDEF_ACK_FRAME_FROM_COORD, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

            const encHeader = structuredClone(macHeader);
            encHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);

            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

            const encAPSHeader = structuredClone(apsHeader);

            encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NETDEF_LINK_STATUS_FROM_DEV",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_LINK_STATUS_FROM_DEV, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_LINK_STATUS_FROM_DEV, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NETDEF_LINK_STATUS_FROM_DEV, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            const encHeader = structuredClone(macHeader);
            encHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);

            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NETDEF_ZCL_FRAME_CMD_TO_COORD",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZCL_FRAME_CMD_TO_COORD, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZCL_FRAME_CMD_TO_COORD, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NETDEF_ZCL_FRAME_CMD_TO_COORD, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

            const encHeader = structuredClone(macHeader);
            encHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);

            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

            const encAPSHeader = structuredClone(apsHeader);

            encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, undefined, apsFCF, apsHeader);

            const encHeader = structuredClone(macHeader);
            encHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);

            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

            const encAPSHeader = structuredClone(apsHeader);

            encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NETDEF_ROUTE_RECORD_TO_COORD",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ROUTE_RECORD_TO_COORD, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ROUTE_RECORD_TO_COORD, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NETDEF_ROUTE_RECORD_TO_COORD, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            // TODO Zigbee NWK cmd

            const encHeader = structuredClone(macHeader);
            encHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);

            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NETDEF_MTORR_FRAME_FROM_COORD",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_MTORR_FRAME_FROM_COORD, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_MTORR_FRAME_FROM_COORD, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NETDEF_MTORR_FRAME_FROM_COORD, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            // TODO Zigbee NWK cmd

            const encHeader = structuredClone(macHeader);
            encHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);

            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0, macHOutOffset, macFCF, macHeader);

            const [nwkGPFCF, nwkGPFCFOutOffset] = decodeZigbeeNWKGPFrameControl(macPayload, 0);
            const [nwkGPHeader, nwkGPHOutOffset] = decodeZigbeeNWKGPHeader(macPayload, nwkGPFCFOutOffset, nwkGPFCF);
            const nwkGPPayload = decodeZigbeeNWKGPPayload(macPayload, nwkGPHOutOffset, NETDEF_NETWORK_KEY, macHeader.source64, nwkGPFCF, nwkGPHeader);

            const encHeader = structuredClone(macHeader);
            encHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encHeader, macPayload);

            const encNWKGPHeader = structuredClone(nwkGPHeader);

            encodeZigbeeNWKGPFrame(encNWKGPHeader, nwkGPPayload, NETDEF_NETWORK_KEY, macHeader.source64);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NETDEF_ZGP_COMMISSIONING",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NETDEF_ZGP_COMMISSIONING, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NETDEF_ZGP_COMMISSIONING, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NETDEF_ZGP_COMMISSIONING, macHOutOffset, macFCF, macHeader);

            const [nwkGPFCF, nwkGPFCFOutOffset] = decodeZigbeeNWKGPFrameControl(macPayload, 0);
            const [nwkGPHeader, nwkGPHOutOffset] = decodeZigbeeNWKGPHeader(macPayload, nwkGPFCFOutOffset, nwkGPFCF);
            const nwkGPPayload = decodeZigbeeNWKGPPayload(macPayload, nwkGPHOutOffset, NETDEF_NETWORK_KEY, macHeader.source64, nwkGPFCF, nwkGPHeader);

            const encHeader = structuredClone(macHeader);
            encHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encHeader, macPayload);

            const encNWKGPHeader = structuredClone(nwkGPHeader);

            encodeZigbeeNWKGPFrame(encNWKGPHeader, nwkGPPayload, NETDEF_NETWORK_KEY, macHeader.source64);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NET2_DEVICE_LEAVE_BROADCAST",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_DEVICE_LEAVE_BROADCAST, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NET2_DEVICE_LEAVE_BROADCAST, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NET2_DEVICE_LEAVE_BROADCAST, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            const encHeader = structuredClone(macHeader);
            encHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);

            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NET2_BEACON_REQ_FROM_DEVICE",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_BEACON_REQ_FROM_DEVICE, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NET2_BEACON_REQ_FROM_DEVICE, macFCFOutOffset, macFCF);
            decodeMACPayload(NET2_BEACON_REQ_FROM_DEVICE, macHOutOffset, macFCF, macHeader);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NET2_BEACON_RESP_FROM_COORD",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_BEACON_RESP_FROM_COORD, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NET2_BEACON_RESP_FROM_COORD, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NET2_BEACON_RESP_FROM_COORD, macHOutOffset, macFCF, macHeader);
            decodeMACZigbeeBeacon(macPayload, 0);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NET2_ASSOC_REQ_FROM_DEVICE",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_ASSOC_REQ_FROM_DEVICE, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NET2_ASSOC_REQ_FROM_DEVICE, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NET2_ASSOC_REQ_FROM_DEVICE, macHOutOffset, macFCF, macHeader);

            const encHeader = structuredClone(macHeader);

            encodeMACFrame(encHeader, macPayload);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NET2_ASSOC_RESP_FROM_COORD",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_ASSOC_RESP_FROM_COORD, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NET2_ASSOC_RESP_FROM_COORD, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NET2_ASSOC_RESP_FROM_COORD, macHOutOffset, macFCF, macHeader);

            const encHeader = structuredClone(macHeader);

            encodeMACFrame(encHeader, macPayload);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NET2_TRANSPORT_KEY_NWK_FROM_COORD",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_TRANSPORT_KEY_NWK_FROM_COORD, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NET2_TRANSPORT_KEY_NWK_FROM_COORD, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NET2_TRANSPORT_KEY_NWK_FROM_COORD, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, NET2_COORD_EUI64_BIGINT, apsFCF, apsHeader);

            const encMACHeader = structuredClone(macHeader);
            encMACHeader.sourcePANId = undefined;

            encodeMACFrameZigbee(encMACHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);

            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

            const encAPSHeader = structuredClone(apsHeader);

            encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );

    bench(
        "NET2_REQUEST_KEY_TC_FROM_DEVICE",
        () => {
            const [macFCF, macFCFOutOffset] = decodeMACFrameControl(NET2_REQUEST_KEY_TC_FROM_DEVICE, 0);
            const [macHeader, macHOutOffset] = decodeMACHeader(NET2_REQUEST_KEY_TC_FROM_DEVICE, macFCFOutOffset, macFCF);
            const macPayload = decodeMACPayload(NET2_REQUEST_KEY_TC_FROM_DEVICE, macHOutOffset, macFCF, macHeader);

            const [nwkFCF, nwkFCFOutOffset] = decodeZigbeeNWKFrameControl(macPayload, 0);
            const [nwkHeader, nwkHOutOffset] = decodeZigbeeNWKHeader(macPayload, nwkFCFOutOffset, nwkFCF);
            const nwkPayload = decodeZigbeeNWKPayload(macPayload, nwkHOutOffset, undefined, macHeader.source64, nwkFCF, nwkHeader);

            const [apsFCF, apsFCFOutOffset] = decodeZigbeeAPSFrameControl(nwkPayload, 0);
            const [apsHeader, apsHOutOffset] = decodeZigbeeAPSHeader(nwkPayload, apsFCFOutOffset, apsFCF);
            const apsPayload = decodeZigbeeAPSPayload(nwkPayload, apsHOutOffset, undefined, NET2_COORD_EUI64_BIGINT, apsFCF, apsHeader);

            const encMACHeader = structuredClone(macHeader);
            encMACHeader.sourcePANId = undefined;
            encodeMACFrameZigbee(encMACHeader, macPayload);

            const encNWKHeader = structuredClone(nwkHeader);
            encodeZigbeeNWKFrame(encNWKHeader, nwkPayload, encNWKHeader.securityHeader!, undefined);

            const encAPSHeader = structuredClone(apsHeader);
            encodeZigbeeAPSFrame(encAPSHeader, apsPayload, encAPSHeader.securityHeader!, undefined);
        },
        { warmupTime: 1000 },
    );
});
