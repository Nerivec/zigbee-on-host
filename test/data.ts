import { ZigbeeKeyType, makeKeyedHash, makeKeyedHashByType } from "../src/zigbee/zigbee";

export const A_CHANNEL = 15;
export const A_PAN_ID = 0xcd12;
export const A_EXTENDED_PAN_ID = Buffer.from([0xff, 0xee, 0xdd, 0xcc, 0x44, 0x33, 0x22, 0x11]);
export const A_EUI64 = Buffer.from([0xef, 0xac, 0x23, 0x45, 0xbb, 0xff, 0x86, 0x99]);

//---- Frames below are from sniffs of actual ZigBee networks (with various coordinators, and dates varying from 2022 to now) with details from Wireshark
//---- NOTE: FCS is using TI format in most cases which is not valid against proper IEEE 802.15.4 CRC (i.e. do not compare last two bytes)

// #region NETDEF

/** ZigBeeAlliance09 */
export const NETDEF_TC_KEY = Buffer.from([0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39]);
/** Default Zigbee2MQTT PAN ID */
export const NETDEF_PAN_ID = 0x1a62;
/** Default Zigbee2MQTT extended PAN ID */
export const NETDEF_EXTENDED_PAN_ID = Buffer.from([0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd]);
/** Default Zigbee2MQTT network key */
export const NETDEF_NETWORK_KEY = Buffer.from([0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0d]);

/**
 * IEEE 802.15.4 Data, Src: 0x96ba, Dst: 0x0000
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 191
 *   Destination PAN: 0x1a62
 *   Destination: 0x0000
 *   Source: 0x96ba
 *   [Extended Source: SiliconLabor_ff:fe:a4:b9:73 (80:4b:50:ff:fe:a4:b9:73)]
 *   TI CC24xx-format metadata: FCS OK
 *       FCS Valid: True
 *       RSSI: -85 dB
 *       LQI Correlation Value: 52
 *
 * ZigBee Network Layer Data, Dst: 0x0000, Src: 0x96ba
 *   Frame Control Field: 0x0248, Frame Type: Data, Discover Route: Enable, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 01.. .... = Discover Route: Enable (0x1)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0x0000
 *   Source: 0x96ba
 *   Radius: 30
 *   Sequence Number: 151
 *   [Extended Source: SiliconLabor_ff:fe:a4:b9:73 (80:4b:50:ff:fe:a4:b9:73)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 45318893
 *       Extended Source: SiliconLabor_ff:fe:a4:b9:73 (80:4b:50:ff:fe:a4:b9:73)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 74295ed5
 *
 * ZigBee Application Support Layer Ack, Dst Endpt: 1, Src Endpt: 1
 *   Frame Control Field: Ack (0x02)
 *       .... ..10 = Frame Type: Ack (0x2)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ...0 .... = Acknowledgement Format: False
 *       ..0. .... = Security: False
 *       .0.. .... = Acknowledgement Request: False
 *       0... .... = Extended Header: False
 *   Destination Endpoint: 1
 *   Cluster: Unknown (0xef00)
 *   Profile: Home Automation (0x0104)
 *   Source Endpoint: 1
 *   Counter: 51
 */
export const NETDEF_ACK_FRAME_TO_COORD = Buffer.from([
    0x61, 0x88, 0xbf, 0x62, 0x1a, 0x0, 0x0, 0xba, 0x96, 0x48, 0x2, 0x0, 0x0, 0xba, 0x96, 0x1e, 0x97, 0x28, 0xed, 0x82, 0xb3, 0x2, 0x73, 0xb9, 0xa4,
    0xfe, 0xff, 0x50, 0x4b, 0x80, 0x0, 0x24, 0x90, 0x91, 0xd5, 0x9c, 0xff, 0x6, 0xda, 0x74, 0x29, 0x5e, 0xd5, 0xab, 0xb4,
]);

/**
 * IEEE 802.15.4 Data, Src: 0x0000, Dst: 0x87c6
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 73
 *   Destination PAN: 0x1a62
 *   Destination: 0x87c6
 *   Source: 0x0000
 *   [Extended Source: SiliconLabor_ff:fe:77:be:10 (e0:79:8d:ff:fe:77:be:10)]
 *   TI CC24xx-format metadata: FCS OK
 *       FCS Valid: True
 *       RSSI: -53 dB
 *       LQI Correlation Value: 116
 *
 * ZigBee Network Layer Data, Dst: 0x96ba, Src: 0x0000
 *   Frame Control Field: 0x0248, Frame Type: Data, Discover Route: Enable, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 01.. .... = Discover Route: Enable (0x1)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0x96ba
 *   Source: 0x0000
 *   Radius: 30
 *   Sequence Number: 203
 *   [Extended Source: SiliconLabor_ff:fe:77:be:10 (e0:79:8d:ff:fe:77:be:10)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 99044312
 *       Extended Source: SiliconLabor_ff:fe:77:be:10 (e0:79:8d:ff:fe:77:be:10)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 55e1234c
 *
 * ZigBee Application Support Layer Ack, Dst Endpt: 1, Src Endpt: 1
 *   Frame Control Field: Ack (0x02)
 *       .... ..10 = Frame Type: Ack (0x2)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ...0 .... = Acknowledgement Format: False
 *       ..0. .... = Security: False
 *       .0.. .... = Acknowledgement Request: False
 *       0... .... = Extended Header: False
 *   Destination Endpoint: 1
 *   Cluster: Unknown (0xef00)
 *   Profile: Home Automation (0x0104)
 *   Source Endpoint: 1
 *   Counter: 77
 **/
export const NETDEF_ACK_FRAME_FROM_COORD = Buffer.from([
    0x61, 0x88, 0x49, 0x62, 0x1a, 0xc6, 0x87, 0x0, 0x0, 0x48, 0x2, 0xba, 0x96, 0x0, 0x0, 0x1e, 0xcb, 0x28, 0xd8, 0x4b, 0xe7, 0x5, 0x10, 0xbe, 0x77,
    0xfe, 0xff, 0x8d, 0x79, 0xe0, 0x0, 0x1b, 0xf0, 0x72, 0xc2, 0xbe, 0xf1, 0xb, 0xd9, 0x55, 0xe1, 0x23, 0x4c, 0xcb, 0xf4,
]);

/**
 * IEEE 802.15.4 Data, Src: 0xf0a2, Dst: Broadcast
 *   Frame Control Field: 0x8841, Frame Type: Data, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 92
 *   Destination PAN: 0x1a62
 *   Destination: 0xffff
 *   Source: 0xf0a2
 *   [Extended Source: TexasInstrum_00:24:c3:4d:a0 (00:12:4b:00:24:c3:4d:a0)]
 *   TI CC24xx-format metadata: FCS OK
 *       FCS Valid: True
 *       RSSI: -74 dB
 *       LQI Correlation Value: 74
 *
 * ZigBee Network Layer Command, Dst: Broadcast, Src: 0xf0a2
 *   Frame Control Field: 0x1209, Frame Type: Command, Discover Route: Suppress, Security, Extended Source Command
 *       .... .... .... ..01 = Frame Type: Command (0x1)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...1 .... .... .... = Extended Source: True
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0xfffc
 *   Source: 0xf0a2
 *   Radius: 1
 *   Sequence Number: 223
 *   Extended Source: TexasInstrum_00:24:c3:4d:a0 (00:12:4b:00:24:c3:4d:a0)
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 5505754
 *       Extended Source: TexasInstrum_00:24:c3:4d:a0 (00:12:4b:00:24:c3:4d:a0)
 *       Key Sequence Number: 0
 *       Message Integrity Code: b74632de
 *   Command Frame: Link Status
 *       Command Identifier: Link Status (0x08)
 *       .1.. .... = Last Frame: True
 *       ..1. .... = First Frame: True
 *       ...1 0001 = Link Status Count: 17
 *       Link 1
 *           Address: 0x0000
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 2
 *           Address: 0x0b7c
 *           .... .111 = Incoming Cost: 7
 *           .111 .... = Outgoing Cost: 7
 *       Link 3
 *           Address: 0x16ca
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 4
 *           Address: 0x2020
 *           .... .001 = Incoming Cost: 1
 *           .000 .... = Outgoing Cost: 0
 *       Link 5
 *           Address: 0x2303
 *           .... .111 = Incoming Cost: 7
 *           .111 .... = Outgoing Cost: 7
 *       Link 6
 *           Address: 0x5e74
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 7
 *           Address: 0x65b1
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 8
 *           Address: 0x67b4
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 9
 *           Address: 0x7326
 *           .... .111 = Incoming Cost: 7
 *           .111 .... = Outgoing Cost: 7
 *       Link 10
 *           Address: 0x87c6
 *           .... .001 = Incoming Cost: 1
 *           .011 .... = Outgoing Cost: 3
 *       Link 11
 *           Address: 0x8c4f
 *           .... .111 = Incoming Cost: 7
 *           .111 .... = Outgoing Cost: 7
 *       Link 12
 *           Address: 0x96ba
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 13
 *           Address: 0xaa38
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 14
 *           Address: 0xc8cd
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 15
 *           Address: 0xd054
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 16
 *           Address: 0xf1f0
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 *       Link 17
 *           Address: 0xfd3d
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 */
export const NETDEF_LINK_STATUS_FROM_DEV = Buffer.from([
    0x41, 0x88, 0x5c, 0x62, 0x1a, 0xff, 0xff, 0xa2, 0xf0, 0x9, 0x12, 0xfc, 0xff, 0xa2, 0xf0, 0x1, 0xdf, 0xa0, 0x4d, 0xc3, 0x24, 0x0, 0x4b, 0x12, 0x0,
    0x28, 0xda, 0x2, 0x54, 0x0, 0xa0, 0x4d, 0xc3, 0x24, 0x0, 0x4b, 0x12, 0x0, 0x0, 0x57, 0xf8, 0x6e, 0x1e, 0x50, 0xc8, 0xe9, 0xc6, 0x0, 0x7c, 0xd2,
    0x3a, 0xcd, 0x3c, 0x4c, 0x3f, 0xf4, 0xc4, 0xb7, 0xfa, 0xf8, 0xe, 0x46, 0xb8, 0x54, 0x45, 0xbb, 0x4c, 0x60, 0x91, 0x10, 0xd9, 0xf7, 0x4c, 0xed,
    0x18, 0x24, 0xa0, 0x68, 0xf6, 0xb, 0xe6, 0xa6, 0x1d, 0x33, 0xe, 0x98, 0xc5, 0xb3, 0xc2, 0xab, 0x72, 0xe7, 0xb7, 0x46, 0x32, 0xde, 0xb6, 0xca,
]);

/**
 * IEEE 802.15.4 Data, Src: 0xaa38, Dst: 0x0000
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 230
 *   Destination PAN: 0x1a62
 *   Destination: 0x0000
 *   Source: 0xaa38
 *   [Extended Source: SiliconLabor_ff:fe:d0:4a:58 (70:ac:08:ff:fe:d0:4a:58)]
 *   TI CC24xx-format metadata: FCS OK
 *       FCS Valid: True
 *       RSSI: -77 dB
 *       LQI Correlation Value: 68
 *
 * ZigBee Network Layer Data, Dst: 0x0000, Src: 0xaa38
 *   Frame Control Field: 0x0248, Frame Type: Data, Discover Route: Enable, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 01.. .... = Discover Route: Enable (0x1)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0x0000
 *   Source: 0xaa38
 *   Radius: 30
 *   Sequence Number: 128
 *   [Extended Source: SiliconLabor_ff:fe:d0:4a:58 (70:ac:08:ff:fe:d0:4a:58)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 43659054
 *       Extended Source: SiliconLabor_ff:fe:d0:4a:58 (70:ac:08:ff:fe:d0:4a:58)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 88ef5e6d
 *
 * ZigBee Application Support Layer Data, Dst Endpt: 1, Src Endpt: 1
 *   Frame Control Field: Data (0x00)
 *       .... ..00 = Frame Type: Data (0x0)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ..0. .... = Security: False
 *       .0.. .... = Acknowledgement Request: False
 *       0... .... = Extended Header: False
 *   Destination Endpoint: 1
 *   Cluster: Unknown (0xef00)
 *   Profile: Home Automation (0x0104)
 *   Source Endpoint: 1
 *   Counter: 63
 *
 * ZigBee Cluster Library Frame
 *   Frame Control Field: Cluster-specific (0x09)
 *       .... ..01 = Frame Type: Cluster-specific (0x1)
 *       .... .0.. = Manufacturer Specific: False
 *       .... 1... = Direction: Server to Client
 *       ...0 .... = Disable Default Response: False
 *   Sequence Number: 80
 *   Command: Unknown (0x25)
 */
export const NETDEF_ZCL_FRAME_CMD_TO_COORD = Buffer.from([
    0x61, 0x88, 0xe6, 0x62, 0x1a, 0x0, 0x0, 0x38, 0xaa, 0x48, 0x2, 0x0, 0x0, 0x38, 0xaa, 0x1e, 0x80, 0x28, 0x2e, 0x2f, 0x9a, 0x2, 0x58, 0x4a, 0xd0,
    0xfe, 0xff, 0x8, 0xac, 0x70, 0x0, 0x51, 0x52, 0x87, 0x1, 0x52, 0x10, 0xa7, 0x4f, 0xb7, 0x34, 0xf1, 0xd9, 0xc8, 0x88, 0xef, 0x5e, 0x6d, 0xb3, 0xc4,
]);

/**
 * IEEE 802.15.4 Data, Src: 0xaa38, Dst: 0x0000
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 231
 *   Destination PAN: 0x1a62
 *   Destination: 0x0000
 *   Source: 0xaa38
 *   [Extended Source: SiliconLabor_ff:fe:d0:4a:58 (70:ac:08:ff:fe:d0:4a:58)]
 *   TI CC24xx-format metadata: FCS OK
 *       FCS Valid: True
 *       RSSI: -77 dB
 *       LQI Correlation Value: 68
 *
 * ZigBee Network Layer Data, Dst: 0x0000, Src: 0xaa38
 *   Frame Control Field: 0x0248, Frame Type: Data, Discover Route: Enable, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 01.. .... = Discover Route: Enable (0x1)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0x0000
 *   Source: 0xaa38
 *   Radius: 30
 *   Sequence Number: 130
 *   [Extended Source: SiliconLabor_ff:fe:d0:4a:58 (70:ac:08:ff:fe:d0:4a:58)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 43659055
 *       Extended Source: SiliconLabor_ff:fe:d0:4a:58 (70:ac:08:ff:fe:d0:4a:58)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 3674143b
 *       [Key: 01030507090b0d0f00020406080a0c0d]
 *
 * ZigBee Application Support Layer Data, Dst Endpt: 1, Src Endpt: 1
 *   Frame Control Field: Data (0x40)
 *       .... ..00 = Frame Type: Data (0x0)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ..0. .... = Security: False
 *       .1.. .... = Acknowledgement Request: True
 *       0... .... = Extended Header: False
 *   Destination Endpoint: 1
 *   Cluster: Unknown (0xef00)
 *   Profile: Home Automation (0x0104)
 *   Source Endpoint: 1
 *   Counter: 64
 *
 * ZigBee Cluster Library Frame, Command: Default Response, Seq: 50
 *   Frame Control Field: Profile-wide (0x08)
 *       .... ..00 = Frame Type: Profile-wide (0x0)
 *       .... .0.. = Manufacturer Specific: False
 *       .... 1... = Direction: Server to Client
 *       ...0 .... = Disable Default Response: False
 *   Sequence Number: 50
 *   Command: Default Response (0x0b)
 *   Response to Command: 0x25
 *   Status: Success (0x00)
 */
export const NETDEF_ZCL_FRAME_DEF_RSP_TO_COORD = Buffer.from([
    0x61, 0x88, 0xe7, 0x62, 0x1a, 0x0, 0x0, 0x38, 0xaa, 0x48, 0x2, 0x0, 0x0, 0x38, 0xaa, 0x1e, 0x82, 0x28, 0x2f, 0x2f, 0x9a, 0x2, 0x58, 0x4a, 0xd0,
    0xfe, 0xff, 0x8, 0xac, 0x70, 0x0, 0x47, 0x3b, 0x70, 0x51, 0x48, 0x1a, 0xfd, 0xd1, 0x6a, 0x37, 0xaf, 0x59, 0xe9, 0x36, 0x74, 0x14, 0x3b, 0xb3,
    0xc4,
]);

/**
 * IEEE 802.15.4 Data, Src: 0xf1f0, Dst: 0x0000
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 155
 *   Destination PAN: 0x1a62
 *   Destination: 0x0000
 *   Source: 0xf1f0
 *   [Extended Source: TexasInstrum_00:24:c0:41:13 (00:12:4b:00:24:c0:41:13)]
 *   TI CC24xx-format metadata: FCS OK
 *       FCS Valid: True
 *       RSSI: -97 dB
 *       LQI Correlation Value: 28
 *
 * ZigBee Network Layer Command, Dst: 0x0000, Src: 0xac3a
 *   Frame Control Field: 0x1209, Frame Type: Command, Discover Route: Suppress, Security, Extended Source Command
 *       .... .... .... ..01 = Frame Type: Command (0x1)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...1 .... .... .... = Extended Source: True
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0x0000
 *   Source: 0xac3a
 *   Radius: 30
 *   Sequence Number: 207
 *   Extended Source: TexasInstrum_00:25:49:f4:42 (00:12:4b:00:25:49:f4:42)
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 6240313
 *       Extended Source: TexasInstrum_00:24:c0:41:13 (00:12:4b:00:24:c0:41:13)
 *       Key Sequence Number: 0
 *       Message Integrity Code: f406c868
 *   Command Frame: Route Record
 *       Command Identifier: Route Record (0x05)
 *       Relay Count: 1
 *       Relay Device 1: 0xf1f0
 */
export const NETDEF_ROUTE_RECORD_TO_COORD = Buffer.from([
    0x61, 0x88, 0x9b, 0x62, 0x1a, 0x0, 0x0, 0xf0, 0xf1, 0x9, 0x12, 0x0, 0x0, 0x3a, 0xac, 0x1e, 0xcf, 0x42, 0xf4, 0x49, 0x25, 0x0, 0x4b, 0x12, 0x0,
    0x28, 0x39, 0x38, 0x5f, 0x0, 0x13, 0x41, 0xc0, 0x24, 0x0, 0x4b, 0x12, 0x0, 0x0, 0xbd, 0x81, 0xd8, 0xd1, 0xf4, 0x6, 0xc8, 0x68, 0x9f, 0x9c,
]);

/**
 * IEEE 802.15.4 Data, Src: 0x0000, Dst: Broadcast
 *   Frame Control Field: 0x8841, Frame Type: Data, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 93
 *   Destination PAN: 0x1a62
 *   Destination: 0xffff
 *   Source: 0x0000
 *   [Extended Source: SiliconLabor_ff:fe:77:be:10 (e0:79:8d:ff:fe:77:be:10)]
 *   TI CC24xx-format metadata: FCS OK
 *       FCS Valid: True
 *       RSSI: -53 dB
 *       LQI Correlation Value: 116
 *
 * ZigBee Network Layer Command, Dst: Broadcast, Src: 0x0000
 *   Frame Control Field: 0x1209, Frame Type: Command, Discover Route: Suppress, Security, Extended Source Command
 *       .... .... .... ..01 = Frame Type: Command (0x1)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...1 .... .... .... = Extended Source: True
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0xfffc
 *   Source: 0x0000
 *   Radius: 30
 *   Sequence Number: 237
 *   Extended Source: SiliconLabor_ff:fe:77:be:10 (e0:79:8d:ff:fe:77:be:10)
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 99044332
 *       Extended Source: SiliconLabor_ff:fe:77:be:10 (e0:79:8d:ff:fe:77:be:10)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 05f16ea7
 *   Command Frame: Route Request
 *       Command Identifier: Route Request (0x01)
 *       Command Options: 0x08, Many-to-One Discovery: With Source Routing
 *       Route ID: 45
 *       Destination: 0xfffc
 *       Path Cost: 0
 */
export const NETDEF_MTORR_FRAME_FROM_COORD = Buffer.from([
    0x41, 0x88, 0x5d, 0x62, 0x1a, 0xff, 0xff, 0x0, 0x0, 0x9, 0x12, 0xfc, 0xff, 0x0, 0x0, 0x1e, 0xed, 0x10, 0xbe, 0x77, 0xfe, 0xff, 0x8d, 0x79, 0xe0,
    0x28, 0xec, 0x4b, 0xe7, 0x5, 0x10, 0xbe, 0x77, 0xfe, 0xff, 0x8d, 0x79, 0xe0, 0x0, 0x1e, 0x53, 0x91, 0xe2, 0x77, 0x31, 0x5, 0xf1, 0x6e, 0xa7, 0xcb,
    0xf4,
]);

/**
 * IEEE 802.15.4 Data, Dst: Broadcast
 *   Frame Control Field: 0x0801, Frame Type: Data, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: None
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .0.. .... = PAN ID Compression: False
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       00.. .... .... .... = Source Addressing Mode: None (0x0)
 *   Sequence Number: 185
 *   Destination PAN: 0xffff
 *   Destination: 0xffff
 *
 * ZGP stub NWK header Data, GPD Src ID: 0x01719697
 *   Frame Control Field: 0x8c, Frame Type: Data, NWK Frame Extension Data
 *       .... ..00 = Frame Type: Data (0x0)
 *       ..00 11.. = Protocol Version: 3
 *       .0.. .... = Auto Commissioning: False
 *       1... .... = NWK Frame Extension: True
 *   Extended NWK Frame Control Field: 0x30, Application ID: Unknown, Security Level: Full frame counter and full MIC only, Security Key, Direction: From ZGPD
 *       .... .000 = Application ID: Unknown (0x0)
 *       ...1 0... = Security Level: Full frame counter and full MIC only (0x2)
 *       ..1. .... = Security Key: True
 *       .0.. .... = Rx After Tx: False
 *       0... .... = Direction: From ZGPD (0x0)
 *   Src ID: Unknown (0x01719697)
 *   Security Frame Counter: 185
 *   Command Frame: Recall Scene 0
 *       ZGPD Command ID: Recall Scene 0 (0x10)
 *   Security MIC: 0xd1fdebfe
 */
export const NETDEF_ZGP_FRAME_BCAST_RECALL_SCENE_0 = Buffer.from([
    // crafted end FCS
    0x01, 0x08, 0xb9, 0xff, 0xff, 0xff, 0xff, 0x8c, 0x30, 0x97, 0x96, 0x71, 0x01, 0xb9, 0x00, 0x00, 0x00, 0x10, 0xfe, 0xeb, 0xfd, 0xd1, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Dst: Broadcast
 *   Frame Control Field: 0x0801, Frame Type: Data, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: None
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .0.. .... = PAN ID Compression: False
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       00.. .... .... .... = Source Addressing Mode: None (0x0)
 *   Sequence Number: 70
 *   Destination PAN: 0xffff
 *   Destination: 0xffff
 *   TI CC24xx-format metadata: FCS OK
 *       FCS Valid: True
 *       RSSI: -24 dB
 *       LQI Correlation Value: 127
 *
 * ZGP stub NWK header Data, GPD Src ID: 0x0155f47a
 *    Frame Control Field: 0x0c, Frame Type: Data Data
 *        .... ..00 = Frame Type: Data (0x0)
 *        ..00 11.. = Protocol Version: 3
 *        .0.. .... = Auto Commissioning: False
 *        0... .... = NWK Frame Extension: False
 *    Src ID: Unknown (0x0155f47a)
 *    Command Frame: Commissioning
 *        ZGPD Command ID: Commissioning (0xe0)
 *        ZGPD Device ID: Generic: GP On/Off Switch (0x02)
 *        Options Field: 0x85, MAC Sequence number capability, Application information present, Extended Option Field
 *            .... ...1 = MAC Sequence number capability: True
 *            .... ..0. = RxOnCapability: False
 *            .... .1.. = Application information present: True
 *            ...0 .... = PANId request: False
 *            ..0. .... = GP Security Key Request: False
 *            .0.. .... = Fixed Location: False
 *            1... .... = Extended Option Field: True
 *        Extended Options Field: 0xf2, Key Type: Individual, out of the box GPD key, GPD Key Present, GPD Key Encryption, GPD Outgoing present
 *            .... ..10 = Security Level Capabilities: 0x2
 *            ...1 00.. = Key Type: Individual, out of the box GPD key (0x4)
 *            ..1. .... = GPD Key Present: True
 *            .1.. .... = GPD Key Encryption: True
 *            1... .... = GPD Outgoing present: True
 *        Security Key: c925821df46f458cf0e637aac3bab6aa
 *        GPD Key MIC: 0x111a8345
 *        GPD Outgoing Counter: 0x00002346
 *        Application information Field: 0x04, GP commands list present
 *            .... ...0 = Manufacturer ID present: False
 *            .... ..0. = Manufacturer Model ID present: False
 *            .... .1.. = GP commands list present: True
 *            .... 0... = Cluster reports present: False
 *        Number of GPD commands: 22
 *        GPD CommandID list
 *            ZGPD Command ID: Recall Scene 0 (0x10)
 *            ZGPD Command ID: Recall Scene 1 (0x11)
 *            ZGPD Command ID: Toggle (0x22)
 *            ZGPD Command ID: Release (0x23)
 *            ZGPD Command ID: Store Scene 0 (0x18)
 *            ZGPD Command ID: Store Scene 1 (0x19)
 *            ZGPD Command ID: Recall Scene 4 (0x14)
 *            ZGPD Command ID: Recall Scene 5 (0x15)
 *            ZGPD Command ID: Recall Scene 2 (0x12)
 *            ZGPD Command ID: Recall Scene 3 (0x13)
 *            ZGPD Command ID: Press 2 of 2 (0x64)
 *            ZGPD Command ID: Release 2 of 2 (0x65)
 *            ZGPD Command ID: Press 1 of 2 (0x62)
 *            ZGPD Command ID: Release 1 of 2 (0x63)
 *            ZGPD Command ID: Store Scene 6 (0x1e)
 *            ZGPD Command ID: Store Scene 7 (0x1f)
 *            ZGPD Command ID: Store Scene 4 (0x1c)
 *            ZGPD Command ID: Store Scene 5 (0x1d)
 *            ZGPD Command ID: Store Scene 2 (0x1a)
 *            ZGPD Command ID: Store Scene 3 (0x1b)
 *            ZGPD Command ID: Recall Scene 6 (0x16)
 *            ZGPD Command ID: Recall Scene 7 (0x17)
 *
 */
export const NETDEF_ZGP_COMMISSIONING = Buffer.from([
    // crafted end FCS
    0x1, 0x8, 0x46, 0xff, 0xff, 0xff, 0xff, 0xc, 0x7a, 0xf4, 0x55, 0x1, 0xe0, 0x2, 0x85, 0xf2, 0xc9, 0x25, 0x82, 0x1d, 0xf4, 0x6f, 0x45, 0x8c, 0xf0,
    0xe6, 0x37, 0xaa, 0xc3, 0xba, 0xb6, 0xaa, 0x45, 0x83, 0x1a, 0x11, 0x46, 0x23, 0x0, 0x0, 0x4, 0x16, 0x10, 0x11, 0x22, 0x23, 0x18, 0x19, 0x14, 0x15,
    0x12, 0x13, 0x64, 0x65, 0x62, 0x63, 0x1e, 0x1f, 0x1c, 0x1d, 0x1a, 0x1b, 0x16, 0x17, 0xff, 0xff,
]);

// #endregion

// #region NET1

// #endregion

// #region NET2

//---- Represents a succession of frames from a device leaving a network then doing an initial join, until confirm key

// export const NET2_TC_KEY = Buffer.from([0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39]);
export const NET2_PAN_ID = 0x1a64;
export const NET2_EXTENDED_PAN_ID = Buffer.from([0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd]);
// export const NET2_NETWORK_KEY = Buffer.from([0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0d]);
export const NET2_COORD_EUI64 = Buffer.from([0xf9, 0x99, 0x5, 0xfe, 0xff, 0x50, 0x4b, 0x80]);
export const NET2_COORD_EUI64_BIGINT = 9244571720516737529n;

export const NET2_NETWORK_KEY_HASHED = makeKeyedHashByType(ZigbeeKeyType.NWK, NETDEF_NETWORK_KEY); //Buffer.from([1,3,5,7,9,11,13,15,0,2,4,6,8,10,12,13]);
export const NET2_TC_TRANSPORT_HASHED = makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, NETDEF_TC_KEY); //Buffer.from([75,171,15,23,62,20,52,162,213,114,225,193,239,71,135,130]);
export const NET2_TC_LOAD_HASHED = makeKeyedHashByType(ZigbeeKeyType.LOAD, NETDEF_TC_KEY); //Buffer.from([197,164,112,53,195,50,204,191,37,21,113,216,186,222,209,136]);
export const NET2_TC_VERIFY_HASHED = makeKeyedHash(NETDEF_TC_KEY, 0x03); //Buffer.from([26,177,40,223,22,57,161,36,106,171,167,42,106,85,145,36]);

/**
 * IEEE 802.15.4 Data, Src: 0xa18f, Dst: Broadcast
 *   Frame Control Field: 0x8841, Frame Type: Data, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 237
 *   Destination PAN: 0x1a64
 *   Destination: 0xffff
 *   Source: 0xa18f
 *   [Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)]
 *
 * ZigBee Network Layer Command, Dst: Broadcast, Src: 0xa18f
 *   Frame Control Field: 0x1209, Frame Type: Command, Discover Route: Suppress, Security, Extended Source Command
 *       .... .... .... ..01 = Frame Type: Command (0x1)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...1 .... .... .... = Extended Source: True
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0xfffd
 *   Source: 0xa18f
 *   Radius: 1
 *   Sequence Number: 195
 *   Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 33483
 *       Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 508ebdc6
 *       [Key: 01030507090b0d0f00020406080a0c0d]
 *   Command Frame: Leave
 *       Command Identifier: Leave (0x04)
 *       ..0. .... = Rejoin: False
 *       .0.. .... = Request: False
 *       0... .... = Remove Children: False
 */
export const NET2_DEVICE_LEAVE_BROADCAST = Buffer.from([
    // crafted end FCS
    0x41, 0x88, 0xed, 0x64, 0x1a, 0xff, 0xff, 0x8f, 0xa1, 0x9, 0x12, 0xfd, 0xff, 0x8f, 0xa1, 0x1, 0xc3, 0xdf, 0xf, 0x28, 0x9b, 0x6d, 0x38, 0xc1, 0xa4,
    0x28, 0xcb, 0x82, 0x0, 0x0, 0xdf, 0xf, 0x28, 0x9b, 0x6d, 0x38, 0xc1, 0xa4, 0x0, 0x51, 0xcb, 0x50, 0x8e, 0xbd, 0xc6, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Command, Dst: Broadcast
 *   Frame Control Field: 0x0803, Frame Type: Command, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: None
 *       .... .... .... .011 = Frame Type: Command (0x3)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .0.. .... = PAN ID Compression: False
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       00.. .... .... .... = Source Addressing Mode: None (0x0)
 *   Sequence Number: 100
 *   Destination PAN: 0xffff
 *   Destination: 0xffff
 *   Command Identifier: Beacon Request (0x07)
 */
export const NET2_BEACON_REQ_FROM_DEVICE = Buffer.from([
    // crafted end FCS
    0x3, 0x8, 0x64, 0xff, 0xff, 0xff, 0xff, 0x7, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Beacon, Src: 0x0000
 *   Frame Control Field: 0x8000, Frame Type: Beacon, Destination Addressing Mode: None, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .000 = Frame Type: Beacon (0x0)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .0.. .... = PAN ID Compression: False
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 00.. .... .... = Destination Addressing Mode: None (0x0)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 186
 *   Source PAN: 0x1a64
 *   Source: 0x0000
 *   Superframe Specification: PAN Coordinator, Association Permit
 *       .... .... .... 1111 = Beacon Interval: 15
 *       .... .... 1111 .... = Superframe Interval: 15
 *       .... 1111 .... .... = Final CAP Slot: 15
 *       ...0 .... .... .... = Battery Extension: False
 *       .1.. .... .... .... = PAN Coordinator: True
 *       1... .... .... .... = Association Permit: True
 *   GTS
 *       GTS Descriptor Count: 0
 *       GTS Permit: False
 *   Pending Addresses: 0 Short and 0 Long
 *
 * ZigBee Beacon, ZigBee PRO, EPID: dd:dd:dd:dd:dd:dd:dd:dd
 *   Protocol ID: 0
 *   Beacon: Stack Profile: ZigBee PRO, Router Capacity, End Device Capacity
 *       .... .... .... 0010 = Stack Profile: ZigBee PRO (0x2)
 *       .... .... 0010 .... = Protocol Version: 2
 *       .... .1.. .... .... = Router Capacity: True
 *       .000 0... .... .... = Device Depth: 0
 *       1... .... .... .... = End Device Capacity: True
 *   Extended PAN ID: dd:dd:dd:dd:dd:dd:dd:dd (dd:dd:dd:dd:dd:dd:dd:dd)
 *   Tx Offset: 16777215
 *   Update ID: 0
 */
export const NET2_BEACON_RESP_FROM_COORD = Buffer.from([
    // crafted end FCS
    0x0, 0x80, 0xba, 0x64, 0x1a, 0x0, 0x0, 0xff, 0xcf, 0x0, 0x0, 0x0, 0x22, 0x84, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xff, 0xff, 0xff,
    0x0, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Command, Src: TelinkSemico_6d:9b:28:0f:df, Dst: 0x0000
 *   Frame Control Field: 0xc823, Frame Type: Command, Acknowledge Request, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Long/64-bit
 *       .... .... .... .011 = Frame Type: Command (0x3)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .0.. .... = PAN ID Compression: False
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       11.. .... .... .... = Source Addressing Mode: Long/64-bit (0x3)
 *   Sequence Number: 116
 *   Destination PAN: 0x1a64
 *   Destination: 0x0000
 *   Source PAN: 0xffff
 *   Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *   Command Identifier: Association Request (0x01)
 *   Association Request
 *       .... ...0 = Alternate PAN Coordinator: False
 *       .... ..1. = Device Type: FFD
 *       .... .1.. = Power Source: AC/Mains Power
 *       .... 1... = Receive On When Idle: True
 *       .0.. .... = Security Capability: False
 *       1... .... = Allocate Address: True
 */
export const NET2_ASSOC_REQ_FROM_DEVICE = Buffer.from([
    // crafted end FCS
    0x23, 0xc8, 0x74, 0x64, 0x1a, 0x0, 0x0, 0xff, 0xff, 0xdf, 0xf, 0x28, 0x9b, 0x6d, 0x38, 0xc1, 0xa4, 0x1, 0x8e, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Command, Src: SiliconLabor_ff:fe:05:99:f9, Dst: TelinkSemico_6d:9b:28:0f:df
 *   Frame Control Field: 0xcc63, Frame Type: Command, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Long/64-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Long/64-bit
 *       .... .... .... .011 = Frame Type: Command (0x3)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 11.. .... .... = Destination Addressing Mode: Long/64-bit (0x3)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       11.. .... .... .... = Source Addressing Mode: Long/64-bit (0x3)
 *   Sequence Number: 187
 *   Destination PAN: 0x1a64
 *   Destination: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *   Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)
 *   Command Identifier: Association Response (0x02)
 *   Association Response
 *       Short Address: 0xa18f
 *       Association Status: 0x00 (Association Successful)
 */
export const NET2_ASSOC_RESP_FROM_COORD = Buffer.from([
    // crafted end FCS
    0x63, 0xcc, 0xbb, 0x64, 0x1a, 0xdf, 0xf, 0x28, 0x9b, 0x6d, 0x38, 0xc1, 0xa4, 0xf9, 0x99, 0x5, 0xfe, 0xff, 0x50, 0x4b, 0x80, 0x2, 0x8f, 0xa1, 0x0,
    0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Src: 0x0000, Dst: 0xa18f
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 189
 *   Destination PAN: 0x1a64
 *   Destination: 0xa18f
 *   Source: 0x0000
 *   [Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)]
 *
 * ZigBee Network Layer Data, Dst: 0xa18f, Src: 0x0000
 *   Frame Control Field: 0x0008, Frame Type: Data, Discover Route: Suppress Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..0. .... .... = Security: False
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0xa18f
 *   Source: 0x0000
 *   Radius: 30
 *   Sequence Number: 161
 *   [Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)]
 *
 * ZigBee Application Support Layer Command
 *   Frame Control Field: Command (0x21)
 *       .... ..01 = Frame Type: Command (0x1)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ..1. .... = Security: True
 *       .0.. .... = Acknowledgement Request: False
 *       0... .... = Extended Header: False
 *   Counter: 106
 *   ZigBee Security Header
 *       Security Control Field: 0x30, Key Id: Key-Transport Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...1 0... = Key Id: Key-Transport Key (0x2)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 86022
 *       Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)
 *       Message Integrity Code: e8a75aff
 *       [Key: 5a6967426565416c6c69616e63653039]
 *   Command Frame: Transport Key
 *       Command Identifier: Transport Key (0x05)
 *       Key Type: Standard Network Key (0x01)
 *       Key: 01030507090b0d0f00020406080a0c0d
 *       Sequence Number: 0
 *       Extended Destination: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *       Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)
 */
export const NET2_TRANSPORT_KEY_NWK_FROM_COORD = Buffer.from([
    // crafted end FCS
    0x61, 0x88, 0xbd, 0x64, 0x1a, 0x8f, 0xa1, 0x0, 0x0, 0x8, 0x0, 0x8f, 0xa1, 0x0, 0x0, 0x1e, 0xa1, 0x21, 0x6a, 0x30, 0x6, 0x50, 0x1, 0x0, 0xf9, 0x99,
    0x5, 0xfe, 0xff, 0x50, 0x4b, 0x80, 0xde, 0x47, 0x3c, 0x64, 0xb5, 0x69, 0xca, 0xc6, 0x2c, 0x72, 0xac, 0x2f, 0xfd, 0x68, 0x2f, 0x57, 0x59, 0xb,
    0xaa, 0x2b, 0x6f, 0x1e, 0x3, 0x6, 0xf8, 0x24, 0xa5, 0xa9, 0x3, 0x58, 0xb2, 0x6c, 0x8e, 0x68, 0xe6, 0xe8, 0xa7, 0x5a, 0xff, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Src: 0xa18f, Dst: Broadcast
 *   Frame Control Field: 0x8841, Frame Type: Data, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 118
 *   Destination PAN: 0x1a64
 *   Destination: 0xffff
 *   Source: 0xa18f
 *   [Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)]
 *
 * ZigBee Network Layer Data, Dst: Broadcast, Src: 0xa18f
 *   Frame Control Field: 0x0208, Frame Type: Data, Discover Route: Suppress, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0xfffd
 *   Source: 0xa18f
 *   Radius: 30
 *   Sequence Number: 27
 *   [Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 33484
 *       Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 337383aa
 *       [Key: 01030507090b0d0f00020406080a0c0d]
 *
 * ZigBee Application Support Layer Data, Dst Endpt: 0, Src Endpt: 0
 *   Frame Control Field: Data (0x08)
 *       .... ..00 = Frame Type: Data (0x0)
 *       .... 10.. = Delivery Mode: Broadcast (0x2)
 *       ..0. .... = Security: False
 *       .0.. .... = Acknowledgement Request: False
 *       0... .... = Extended Header: False
 *   Destination Endpoint: 0
 *   Device Announcement (Cluster ID: 0x0013)
 *   Profile: ZigBee Device Profile (0x0000)
 *   Source Endpoint: 0
 *   Counter: 123
 *
 * ZigBee Device Profile, Device Announcement, Nwk Addr: 0xa18f, Ext Addr: TelinkSemico_6d:9b:28:0f:df
 *   Sequence Number: 0
 *   Nwk Addr of Interest: 0xa18f
 *   Extended Address: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *   Capability Information: 0x8e
 *       .... ...0 = Alternate Coordinator: False
 *       .... ..1. = Full-Function Device: True
 *       .... .1.. = AC Power: True
 *       .... 1... = Rx On When Idle: True
 *       .0.. .... = Security Capability: False
 *       1... .... = Allocate Short Address: True
 */
export const NET2_DEVICE_ANNOUNCE_BCAST = Buffer.from([
    // crafted end FCS
    0x41, 0x88, 0x76, 0x64, 0x1a, 0xff, 0xff, 0x8f, 0xa1, 0x8, 0x2, 0xfd, 0xff, 0x8f, 0xa1, 0x1e, 0x1b, 0x28, 0xcc, 0x82, 0x0, 0x0, 0xdf, 0xf, 0x28,
    0x9b, 0x6d, 0x38, 0xc1, 0xa4, 0x0, 0x64, 0xf9, 0xf0, 0xb0, 0xbb, 0xdc, 0x55, 0xe0, 0x24, 0x82, 0x91, 0x7e, 0x90, 0x38, 0x55, 0xba, 0xba, 0x56,
    0xd5, 0x79, 0x33, 0x73, 0x83, 0xaa, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Src: 0xa18f, Dst: 0x0000
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 128
 *   Destination PAN: 0x1a64
 *   Destination: 0x0000
 *   Source: 0xa18f
 *   [Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)]
 *
 * ZigBee Network Layer Data, Dst: 0x0000, Src: 0xa18f
 *   Frame Control Field: 0x0248, Frame Type: Data, Discover Route: Enable, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 01.. .... = Discover Route: Enable (0x1)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0x0000
 *   Source: 0xa18f
 *   Radius: 30
 *   Sequence Number: 37
 *   [Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 33494
 *       Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 6dcba80f
 *       [Key: 01030507090b0d0f00020406080a0c0d]
 *
 * ZigBee Application Support Layer Data, Dst Endpt: 0, Src Endpt: 0
 *   Frame Control Field: Data (0x40)
 *       .... ..00 = Frame Type: Data (0x0)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ..0. .... = Security: False
 *       .1.. .... = Acknowledgement Request: True
 *       0... .... = Extended Header: False
 *   Destination Endpoint: 0
 *   Node Descriptor Request (Cluster ID: 0x0002)
 *   Profile: ZigBee Device Profile (0x0000)
 *   Source Endpoint: 0
 *   Counter: 130
 *
 * ZigBee Device Profile, Node Descriptor Request, Nwk Addr: 0x0000
 *   Sequence Number: 1
 *   Nwk Addr of Interest: 0x0000
 */
export const NET2_NODE_DESC_REQ_FROM_DEVICE = Buffer.from([
    // crafted end FCS
    0x61, 0x88, 0x80, 0x64, 0x1a, 0x0, 0x0, 0x8f, 0xa1, 0x48, 0x2, 0x0, 0x0, 0x8f, 0xa1, 0x1e, 0x25, 0x28, 0xd6, 0x82, 0x0, 0x0, 0xdf, 0xf, 0x28,
    0x9b, 0x6d, 0x38, 0xc1, 0xa4, 0x0, 0x5b, 0x29, 0xff, 0xc3, 0x73, 0xcc, 0xdb, 0x31, 0x8c, 0x92, 0x1e, 0x6d, 0xcb, 0xa8, 0xf, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Src: 0xa18f, Dst: 0x0000
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 130
 *   Destination PAN: 0x1a64
 *   Destination: 0x0000
 *   Source: 0xa18f
 *   [Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)]
 *
 * ZigBee Network Layer Data, Dst: 0x0000, Src: 0xa18f
 *   Frame Control Field: 0x0248, Frame Type: Data, Discover Route: Enable, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 01.. .... = Discover Route: Enable (0x1)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0x0000
 *   Source: 0xa18f
 *   Radius: 30
 *   Sequence Number: 39
 *   [Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 33497
 *       Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 61efed10
 *       [Key: 01030507090b0d0f00020406080a0c0d]
 *
 * ZigBee Application Support Layer Command
 *   Frame Control Field: Command (0x21)
 *       .... ..01 = Frame Type: Command (0x1)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ..1. .... = Security: True
 *       .0.. .... = Acknowledgement Request: False
 *       0... .... = Extended Header: False
 *   Counter: 131
 *   ZigBee Security Header
 *       Security Control Field: 0x20, Key Id: Link Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 0... = Key Id: Link Key (0x0)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 33496
 *       Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *       Message Integrity Code: 7aaf0c60
 *       [Key: 5a6967426565416c6c69616e63653039]
 *   Command Frame: Request Key
 *       Command Identifier: Request Key (0x08)
 *       Key Type: Trust Center Link Key (0x04)
 *
 */
export const NET2_REQUEST_KEY_TC_FROM_DEVICE = Buffer.from([
    // crafted end FCS
    0x61, 0x88, 0x82, 0x64, 0x1a, 0x0, 0x0, 0x8f, 0xa1, 0x48, 0x2, 0x0, 0x0, 0x8f, 0xa1, 0x1e, 0x27, 0x28, 0xd9, 0x82, 0x0, 0x0, 0xdf, 0xf, 0x28,
    0x9b, 0x6d, 0x38, 0xc1, 0xa4, 0x0, 0x1b, 0x3, 0x94, 0x92, 0xf4, 0xe4, 0xec, 0x13, 0xa5, 0xa3, 0x5b, 0x8, 0x78, 0xaf, 0x46, 0x8e, 0x70, 0xa8, 0xe9,
    0x7d, 0xfe, 0x61, 0xef, 0xed, 0x10, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Src: 0x0000, Dst: 0xa18f
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 207
 *   Destination PAN: 0x1a64
 *   Destination: 0xa18f
 *   Source: 0x0000
 *   [Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)]
 *
 * ZigBee Network Layer Data, Dst: 0xa18f, Src: 0x0000
 *   Frame Control Field: 0x0208, Frame Type: Data, Discover Route: Suppress, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0xa18f
 *   Source: 0x0000
 *   Radius: 30
 *   Sequence Number: 185
 *   [Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 422014
 *       Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)
 *       Key Sequence Number: 0
 *       Message Integrity Code: c1559100
 *       [Key: 01030507090b0d0f00020406080a0c0d]
 *
 * ZigBee Application Support Layer Command
 *   Frame Control Field: Command (0x21)
 *       .... ..01 = Frame Type: Command (0x1)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ..1. .... = Security: True
 *       .0.. .... = Acknowledgement Request: False
 *       0... .... = Extended Header: False
 *   Counter: 114
 *   ZigBee Security Header
 *       Security Control Field: 0x38, Key Id: Key-Load Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...1 1... = Key Id: Key-Load Key (0x3)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 86023
 *       Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)
 *       Message Integrity Code: 6b7ce3d3
 *       [Key: 5a6967426565416c6c69616e63653039]
 *   Command Frame: Transport Key
 *       Command Identifier: Transport Key (0x05)
 *       Key Type: Trust Center Link Key (0x04)
 *       Key: 5a6967426565416c6c69616e63653039
 *       Extended Destination: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *       Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)
 */
export const NET2_TRANSPORT_KEY_TC_FROM_COORD = Buffer.from([
    // crafted end FCS
    0x61, 0x88, 0xcf, 0x64, 0x1a, 0x8f, 0xa1, 0x0, 0x0, 0x8, 0x2, 0x8f, 0xa1, 0x0, 0x0, 0x1e, 0xb9, 0x28, 0x7e, 0x70, 0x6, 0x0, 0xf9, 0x99, 0x5, 0xfe,
    0xff, 0x50, 0x4b, 0x80, 0x0, 0xa3, 0x9, 0x3b, 0x4f, 0x4, 0x92, 0xe2, 0xa1, 0x47, 0xb8, 0x8, 0xb8, 0xdd, 0x97, 0x49, 0xa8, 0xc9, 0xe0, 0xb6, 0xf2,
    0x57, 0x2f, 0x2e, 0x7e, 0xaf, 0xa3, 0x7f, 0x1d, 0x65, 0x92, 0xee, 0x33, 0x71, 0x33, 0x8f, 0xd7, 0x2a, 0x75, 0x12, 0xf6, 0x92, 0x54, 0x61, 0x2c,
    0xd0, 0xd6, 0x2c, 0x2b, 0x50, 0xe, 0x90, 0xc9, 0xdc, 0xc1, 0x55, 0x91, 0x0, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Src: 0xa18f, Dst: 0x0000
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 131
 *   Destination PAN: 0x1a64
 *   Destination: 0x0000
 *   Source: 0xa18f
 *   [Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)]
 *
 * ZigBee Network Layer Data, Dst: 0x0000, Src: 0xa18f
 *   Frame Control Field: 0x0248, Frame Type: Data, Discover Route: Enable, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 01.. .... = Discover Route: Enable (0x1)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0x0000
 *   Source: 0xa18f
 *   Radius: 30
 *   Sequence Number: 40
 *   [Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 33498
 *       Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 8290b7ec
 *       [Key: 01030507090b0d0f00020406080a0c0d]
 *
 * ZigBee Application Support Layer Command
 *   Frame Control Field: Command (0x01)
 *       .... ..01 = Frame Type: Command (0x1)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ..0. .... = Security: False
 *       .0.. .... = Acknowledgement Request: False
 *       0... .... = Extended Header: False
 *   Counter: 132
 *   Command Frame: Verify Key
 *       Command Identifier: Verify Key (0x0f)
 *       Key Type: Trust Center Link Key (0x04)
 *       Extended Source: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *       Key Hash: 1ab128df1639a1246aaba72a6a559124
 *
 */
export const NET2_VERIFY_KEY_TC_FROM_DEVICE = Buffer.from([
    // crafted end FCS
    0x61, 0x88, 0x83, 0x64, 0x1a, 0x0, 0x0, 0x8f, 0xa1, 0x48, 0x2, 0x0, 0x0, 0x8f, 0xa1, 0x1e, 0x28, 0x28, 0xda, 0x82, 0x0, 0x0, 0xdf, 0xf, 0x28,
    0x9b, 0x6d, 0x38, 0xc1, 0xa4, 0x0, 0x99, 0xcd, 0xde, 0xf, 0xd, 0xb6, 0x79, 0x4, 0x6e, 0x6e, 0xab, 0xc0, 0xf5, 0xba, 0x56, 0xd5, 0xd1, 0xbf, 0x8f,
    0x61, 0xe3, 0xd6, 0x57, 0x7d, 0x9a, 0x88, 0x79, 0xcb, 0x82, 0x90, 0xb7, 0xec, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Src: 0x0000, Dst: 0xa18f
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 208
 *   Destination PAN: 0x1a64
 *   Destination: 0xa18f
 *   Source: 0x0000
 *   [Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)]
 *
 * ZigBee Network Layer Data, Dst: 0xa18f, Src: 0x0000
 *   Frame Control Field: 0x0208, Frame Type: Data, Discover Route: Suppress, Security Data
 *       .... .... .... ..00 = Frame Type: Data (0x0)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...0 .... .... .... = Extended Source: False
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0xa18f
 *   Source: 0x0000
 *   Radius: 30
 *   Sequence Number: 186
 *   [Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)]
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 422015
 *       Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)
 *       Key Sequence Number: 0
 *       Message Integrity Code: e466e305
 *       [Key: 01030507090b0d0f00020406080a0c0d]
 *
 * ZigBee Application Support Layer Command
 *   Frame Control Field: Command (0x61)
 *       .... ..01 = Frame Type: Command (0x1)
 *       .... 00.. = Delivery Mode: Unicast (0x0)
 *       ..1. .... = Security: True
 *       .1.. .... = Acknowledgement Request: True
 *       0... .... = Extended Header: False
 *   Counter: 115
 *   ZigBee Security Header
 *       Security Control Field: 0x20, Key Id: Link Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 0... = Key Id: Link Key (0x0)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 86024
 *       Extended Source: SiliconLabor_ff:fe:05:99:f9 (80:4b:50:ff:fe:05:99:f9)
 *       Message Integrity Code: a6bdadce
 *       [Key: 5a6967426565416c6c69616e63653039]
 *   Command Frame: Confirm Key, SUCCESS
 *       Command Identifier: Confirm Key (0x10)
 *       Status: SUCCESS (0x00)
 *       Key Type: Trust Center Link Key (0x04)
 *       Extended Destination: TelinkSemico_6d:9b:28:0f:df (a4:c1:38:6d:9b:28:0f:df)
 *
 */
export const NET2_CONFIRM_KEY_TC_SUCCESS = Buffer.from([
    // crafted end FCS
    0x61, 0x88, 0xd0, 0x64, 0x1a, 0x8f, 0xa1, 0x0, 0x0, 0x8, 0x2, 0x8f, 0xa1, 0x0, 0x0, 0x1e, 0xba, 0x28, 0x7f, 0x70, 0x6, 0x0, 0xf9, 0x99, 0x5, 0xfe,
    0xff, 0x50, 0x4b, 0x80, 0x0, 0x5a, 0xe3, 0x32, 0xc5, 0x90, 0x61, 0x6c, 0x71, 0xb6, 0xb2, 0x3c, 0xb9, 0x3f, 0xf, 0x4, 0xf5, 0x73, 0x20, 0xdf, 0xe1,
    0xe9, 0x88, 0xb6, 0x75, 0xb5, 0x59, 0x70, 0x53, 0xcc, 0xa8, 0xe4, 0x66, 0xe3, 0x5, 0xff, 0xff,
]);

// #endregion

// #region NET3
// export const NET3_TC_KEY = Buffer.from([0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39]);
export const NET3_PAN_ID = 0x3607;
export const NET3_EXTENDED_PAN_ID = Buffer.from([0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd]);
export const NET3_NETWORK_KEY = Buffer.from([0xed, 0xc0, 0x6b, 0x9a, 0x9f, 0xdb, 0x8e, 0x01, 0x85, 0x35, 0x88, 0x92, 0xd7, 0xf1, 0xd4, 0x68]);
export const NET3_COORD_EUI64 = Buffer.from([0x0e, 0x5e, 0xd1, 0x26, 0x00, 0x4b, 0x12, 0x00]);
export const NET3_COORD_EUI64_BIGINT = 5149013604130318n;

export const NET3_NETWORK_KEY_HASHED = makeKeyedHashByType(ZigbeeKeyType.NWK, NET3_NETWORK_KEY); //Buffer.from([1,3,5,7,9,11,13,15,0,2,4,6,8,10,12,13]);
export const NET3_TC_TRANSPORT_HASHED = makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, NETDEF_TC_KEY); //Buffer.from([75,171,15,23,62,20,52,162,213,114,225,193,239,71,135,130]);
export const NET3_TC_LOAD_HASHED = makeKeyedHashByType(ZigbeeKeyType.LOAD, NETDEF_TC_KEY); //Buffer.from([197,164,112,53,195,50,204,191,37,21,113,216,186,222,209,136]);
export const NET3_TC_VERIFY_HASHED = makeKeyedHash(NETDEF_TC_KEY, 0x03); //Buffer.from([26,177,40,223,22,57,161,36,106,171,167,42,106,85,145,36]);

/**
 * IEEE 802.15.4 Data, Src: 0x0000, Dst: Broadcast
 *   Frame Control Field: 0x8841, Frame Type: Data, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 156
 *   Destination PAN: 0x3607
 *   Destination: 0xffff
 *   Source: 0x0000
 *   [Extended Source: TexasInstrum_00:26:d1:5e:0e (00:12:4b:00:26:d1:5e:0e)]
 *
 * ZigBee Network Layer Command, Dst: Broadcast, Src: 0x0000
 *   Frame Control Field: 0x1209, Frame Type: Command, Discover Route: Suppress, Security, Extended Source Command
 *       .... .... .... ..01 = Frame Type: Command (0x1)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...1 .... .... .... = Extended Source: True
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0xfffc
 *   Source: 0x0000
 *   Radius: 1
 *   Sequence Number: 138
 *   Extended Source: TexasInstrum_00:26:d1:5e:0e (00:12:4b:00:26:d1:5e:0e)
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 5033
 *       Extended Source: TexasInstrum_00:26:d1:5e:0e (00:12:4b:00:26:d1:5e:0e)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 62067984
 *       [Key: edc06b9a9fdb8e0185358892d7f1d468]
 *   Command Frame: Link Status
 *       Command Identifier: Link Status (0x08)
 *       .1.. .... = Last Frame: True
 *       ..1. .... = First Frame: True
 *       ...0 0001 = Link Status Count: 1
 *       Link 1
 *           Address: 0x3ab1
 *           .... .001 = Incoming Cost: 1
 *           .001 .... = Outgoing Cost: 1
 */
export const NET3_LINK_STATUS = Buffer.from([
    // crafted end FCS
    0x41, 0x88, 0x9c, 0x7, 0x36, 0xff, 0xff, 0x0, 0x0, 0x9, 0x12, 0xfc, 0xff, 0x0, 0x0, 0x1, 0x8a, 0xe, 0x5e, 0xd1, 0x26, 0x0, 0x4b, 0x12, 0x0, 0x28,
    0xa9, 0x13, 0x0, 0x0, 0xe, 0x5e, 0xd1, 0x26, 0x0, 0x4b, 0x12, 0x0, 0x0, 0xae, 0x96, 0x41, 0x84, 0xed, 0x62, 0x6, 0x79, 0x84, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Src: 0x0000, Dst: Broadcast
 *   Frame Control Field: 0x8841, Frame Type: Data, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..0. .... = Acknowledge Request: False
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 163
 *   Destination PAN: 0x3607
 *   Destination: 0xffff
 *   Source: 0x0000
 *   [Extended Source: TexasInstrum_00:26:d1:5e:0e (00:12:4b:00:26:d1:5e:0e)]
 *
 * ZigBee Network Layer Command, Dst: Broadcast, Src: 0x0000
 *   Frame Control Field: 0x1209, Frame Type: Command, Discover Route: Suppress, Security, Extended Source Command
 *       .... .... .... ..01 = Frame Type: Command (0x1)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 0... .... .... = Destination: False
 *       ...1 .... .... .... = Extended Source: True
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0xfffc
 *   Source: 0x0000
 *   Radius: 10
 *   Sequence Number: 145
 *   Extended Source: TexasInstrum_00:26:d1:5e:0e (00:12:4b:00:26:d1:5e:0e)
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 5040
 *       Extended Source: TexasInstrum_00:26:d1:5e:0e (00:12:4b:00:26:d1:5e:0e)
 *       Key Sequence Number: 0
 *       Message Integrity Code: d6218f99
 *       [Key: edc06b9a9fdb8e0185358892d7f1d468]
 *   Command Frame: Route Request
 *       Command Identifier: Route Request (0x01)
 *       Command Options: 0x08, Many-to-One Discovery: With Source Routing
 *           .0.. .... = Multicast: False
 *           ..0. .... = Extended Destination: False
 *           ...0 1... = Many-to-One Discovery: With Source Routing (0x1)
 *       Route ID: 4
 *       Destination: 0xfffc
 *       Path Cost: 0
 */
export const NET3_MTORR = Buffer.from([
    // crafted end FCS
    0x41, 0x88, 0xa3, 0x7, 0x36, 0xff, 0xff, 0x0, 0x0, 0x9, 0x12, 0xfc, 0xff, 0x0, 0x0, 0xa, 0x91, 0xe, 0x5e, 0xd1, 0x26, 0x0, 0x4b, 0x12, 0x0, 0x28,
    0xb0, 0x13, 0x0, 0x0, 0xe, 0x5e, 0xd1, 0x26, 0x0, 0x4b, 0x12, 0x0, 0x0, 0xac, 0xf4, 0x6d, 0x0, 0x29, 0xe, 0xd6, 0x21, 0x8f, 0x99, 0xff, 0xff,
]);

/**
 * IEEE 802.15.4 Data, Src: 0x3ab1, Dst: 0x0000
 *   Frame Control Field: 0x8861, Frame Type: Data, Acknowledge Request, PAN ID Compression, Destination Addressing Mode: Short/16-bit, Frame Version: IEEE Std 802.15.4-2003, Source Addressing Mode: Short/16-bit
 *       .... .... .... .001 = Frame Type: Data (0x1)
 *       .... .... .... 0... = Security Enabled: False
 *       .... .... ...0 .... = Frame Pending: False
 *       .... .... ..1. .... = Acknowledge Request: True
 *       .... .... .1.. .... = PAN ID Compression: True
 *       .... .... 0... .... = Reserved: False
 *       .... ...0 .... .... = Sequence Number Suppression: False
 *       .... ..0. .... .... = Information Elements Present: False
 *       .... 10.. .... .... = Destination Addressing Mode: Short/16-bit (0x2)
 *       ..00 .... .... .... = Frame Version: IEEE Std 802.15.4-2003 (0)
 *       10.. .... .... .... = Source Addressing Mode: Short/16-bit (0x2)
 *   Sequence Number: 134
 *   Destination PAN: 0x3607
 *   Destination: 0x0000
 *   Source: 0x3ab1
 *   [Extended Source: SiliconLabor_ff:fe:5e:70:ea (5c:c7:c1:ff:fe:5e:70:ea)]
 *
 * ZigBee Network Layer Command, Dst: 0x0000, Src: 0x3ab1
 *   Frame Control Field: 0x1a09, Frame Type: Command, Discover Route: Suppress, Security, Destination, Extended Source Command
 *       .... .... .... ..01 = Frame Type: Command (0x1)
 *       .... .... ..00 10.. = Protocol Version: 2
 *       .... .... 00.. .... = Discover Route: Suppress (0x0)
 *       .... ...0 .... .... = Multicast: False
 *       .... ..1. .... .... = Security: True
 *       .... .0.. .... .... = Source Route: False
 *       .... 1... .... .... = Destination: True
 *       ...1 .... .... .... = Extended Source: True
 *       ..0. .... .... .... = End Device Initiator: False
 *   Destination: 0x0000
 *   Source: 0x3ab1
 *   Radius: 30
 *   Sequence Number: 247
 *   Destination: TexasInstrum_00:26:d1:5e:0e (00:12:4b:00:26:d1:5e:0e)
 *   Extended Source: SiliconLabor_ff:fe:5e:70:ea (5c:c7:c1:ff:fe:5e:70:ea)
 *   ZigBee Security Header
 *       Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
 *           .... .000 = Security Level: 0x0
 *           ...0 1... = Key Id: Network Key (0x1)
 *           ..1. .... = Extended Nonce: True
 *           .0.. .... = Require Verified Frame Counter: 0x0
 *       Frame Counter: 4158
 *       Extended Source: SiliconLabor_ff:fe:5e:70:ea (5c:c7:c1:ff:fe:5e:70:ea)
 *       Key Sequence Number: 0
 *       Message Integrity Code: 0ec3defb
 *       [Key: edc06b9a9fdb8e0185358892d7f1d468]
 *   Command Frame: Route Record
 *       Command Identifier: Route Record (0x05)
 *       Relay Count: 0
 *
 */
export const NET3_ROUTE_RECORD = Buffer.from([
    // crafted end FCS
    0x61, 0x88, 0x86, 0x7, 0x36, 0x0, 0x0, 0xb1, 0x3a, 0x9, 0x1a, 0x0, 0x0, 0xb1, 0x3a, 0x1e, 0xf7, 0xe, 0x5e, 0xd1, 0x26, 0x0, 0x4b, 0x12, 0x0, 0xea,
    0x70, 0x5e, 0xfe, 0xff, 0xc1, 0xc7, 0x5c, 0x28, 0x3e, 0x10, 0x0, 0x0, 0xea, 0x70, 0x5e, 0xfe, 0xff, 0xc1, 0xc7, 0x5c, 0x0, 0x65, 0x88, 0xe, 0xc3,
    0xde, 0xfb, 0xff, 0xff,
]);
// #endregion
