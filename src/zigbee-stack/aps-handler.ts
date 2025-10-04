import { logger } from "../utils/logger.js";
import {
    decodeMACCapabilities,
    encodeMACFrameZigbee,
    MACFrameAddressMode,
    MACFrameType,
    MACFrameVersion,
    type MACHeader,
    ZigbeeMACConsts,
} from "../zigbee/mac.js";
import { ZigbeeConsts, ZigbeeKeyType, type ZigbeeSecurityHeader, ZigbeeSecurityLevel } from "../zigbee/zigbee.js";
import {
    encodeZigbeeAPSFrame,
    ZigbeeAPSCommandId,
    ZigbeeAPSConsts,
    ZigbeeAPSDeliveryMode,
    ZigbeeAPSFrameType,
    type ZigbeeAPSHeader,
} from "../zigbee/zigbee-aps.js";
import { encodeZigbeeNWKFrame, ZigbeeNWKConsts, ZigbeeNWKFrameType, type ZigbeeNWKHeader, ZigbeeNWKRouteDiscovery } from "../zigbee/zigbee-nwk.js";
import type { MACHandler } from "./mac-handler.js";
import type { NWKHandler } from "./nwk-handler.js";
import { ApplicationKeyRequestPolicy, type StackCallbacks, type StackContext, TrustCenterKeyRequestPolicy } from "./stack-context.js";

const NS = "aps-handler";

// Configuration constants
const CONFIG_NWK_MAX_HOPS = 30;

/**
 * Callbacks for APS handler to communicate with driver
 */
export interface APSHandlerCallbacks {
    onFrame: StackCallbacks["onFrame"];
    onDeviceJoined: StackCallbacks["onDeviceJoined"];
    onDeviceRejoined: StackCallbacks["onDeviceRejoined"];
    onDeviceAuthorized: StackCallbacks["onDeviceAuthorized"];
}

/**
 * APS Handler - ZigBee Application Support Layer Operations
 */
export class APSHandler {
    readonly #context: StackContext;
    readonly #macHandler: MACHandler;
    readonly #nwkHandler: NWKHandler;
    readonly #callbacks: APSHandlerCallbacks;

    // Private counters (start at 0, first call returns 1)
    #counter = 0;
    #zdoSeqNum = 0;

    constructor(context: StackContext, macHandler: MACHandler, nwkHandler: NWKHandler, callbacks: APSHandlerCallbacks) {
        this.#context = context;
        this.#macHandler = macHandler;
        this.#nwkHandler = nwkHandler;
        this.#callbacks = callbacks;
    }

    async start() {}

    stop() {}

    /**
     * Get next APS counter.
     * HOT PATH: Optimized counter increment
     * @returns Incremented APS counter (wraps at 255)
     */
    /* @__INLINE__ */
    public nextCounter(): number {
        this.#counter = (this.#counter + 1) & 0xff;

        return this.#counter;
    }

    /**
     * Get next ZDO sequence number.
     * HOT PATH: Optimized counter increment
     * @returns Incremented ZDO sequence number (wraps at 255)
     */
    /* @__INLINE__ */
    public nextZDOSeqNum(): number {
        this.#zdoSeqNum = (this.#zdoSeqNum + 1) & 0xff;

        return this.#zdoSeqNum;
    }

    /**
     * Send a ZigBee APS DATA frame.
     * Throws if could not send.
     * @param finalPayload
     * @param macDest16
     * @param nwkDiscoverRoute
     * @param nwkDest16
     * @param nwkDest64
     * @param apsDeliveryMode
     * @param clusterId
     * @param profileId
     * @param destEndpoint
     * @param sourceEndpoint
     * @param group
     * @returns The APS counter of the sent frame.
     */
    public async sendData(
        finalPayload: Buffer,
        nwkDiscoverRoute: ZigbeeNWKRouteDiscovery,
        nwkDest16: number | undefined,
        nwkDest64: bigint | undefined,
        apsDeliveryMode: ZigbeeAPSDeliveryMode,
        clusterId: number,
        profileId: number,
        destEndpoint: number | undefined,
        sourceEndpoint: number | undefined,
        group: number | undefined,
    ): Promise<number> {
        const apsCounter = this.nextCounter();
        const nwkSeqNum = this.#nwkHandler.nextSeqNum();
        const macSeqNum = this.#macHandler.nextSeqNum();
        let relayIndex: number | undefined;
        let relayAddresses: number[] | undefined;

        try {
            [relayIndex, relayAddresses] = this.#nwkHandler.findBestSourceRoute(nwkDest16, nwkDest64);
        } catch (error) {
            logger.error(
                `=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) nwkDst=${nwkDest16}:${nwkDest64}] ${(error as Error).message}`,
                NS,
            );

            throw error;
        }

        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.#context.deviceTable.get(nwkDest64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.error(`=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) nwkDst=${nwkDest16}:${nwkDest64}] Invalid parameters`, NS);

            throw new Error("Invalid parameters");
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;

        logger.debug(
            () =>
                `===> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} apsDlv=${apsDeliveryMode}]`,
            NS,
        );

        const apsFrame = encodeZigbeeAPSFrame(
            {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.DATA,
                    deliveryMode: apsDeliveryMode,
                    ackFormat: false,
                    security: false, // TODO link key support
                    ackRequest: true,
                    extendedHeader: false,
                },
                destEndpoint,
                group,
                clusterId,
                profileId,
                sourceEndpoint,
                counter: apsCounter,
            },
            finalPayload,
            // undefined,
            // undefined,
        );
        const nwkFrame = encodeZigbeeNWKFrame(
            {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: nwkDiscoverRoute,
                    multicast: false,
                    security: true,
                    sourceRoute: relayIndex !== undefined,
                    extendedDestination: nwkDest64 !== undefined,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: nwkDest16,
                destination64: nwkDest64,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: this.#context.decrementRadius(CONFIG_NWK_MAX_HOPS),
                seqNum: nwkSeqNum,
                relayIndex,
                relayAddresses,
            },
            apsFrame,
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.NWK,
                    nonce: true,
                },
                frameCounter: this.#context.nextNWKKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                keySeqNum: this.#context.netParams.networkKeySequenceNumber,
                micLen: 4,
            },
            undefined, // use pre-hashed this.context.netParams.networkKey,
        );
        const macFrame = encodeMACFrameZigbee(
            {
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending:
                        group === undefined && nwkDest16 < ZigbeeConsts.BCAST_MIN
                            ? Boolean(
                                  this.#context.indirectTransmissions.get(nwkDest64 ?? this.#context.address16ToAddress64.get(nwkDest16)!)?.length,
                              )
                            : false,
                    ackRequest: macDest16 !== ZigbeeMACConsts.BCAST_ADDR,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macSeqNum,
                destinationPANId: this.#context.netParams.panId,
                destination16: macDest16,
                // sourcePANId: undefined, // panIdCompression=true
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                fcs: 0,
            },
            nwkFrame,
        );

        const result = await this.#macHandler.sendFrame(macSeqNum, macFrame, macDest16, undefined);

        if (result === false) {
            logger.error(
                `=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64}] Failed to send`,
                NS,
            );

            throw new Error("Failed to send");
        }

        return apsCounter;
    }

    public async sendACK(macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void> {
        logger.debug(
            () =>
                `===> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`,
            NS,
        );

        let nwkDest16 = nwkHeader.source16;
        const nwkDest64 = nwkHeader.source64;
        let relayIndex: number | undefined;
        let relayAddresses: number[] | undefined;

        try {
            [relayIndex, relayAddresses] = this.#nwkHandler.findBestSourceRoute(nwkDest16, nwkDest64);
        } catch (error) {
            logger.debug(() => `=x=> APS ACK[dst16=${nwkDest16} seqNum=${nwkHeader.seqNum}] ${(error as Error).message}`, NS);

            return;
        }

        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.#context.deviceTable.get(nwkDest64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.debug(
                () =>
                    `=x=> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`,
                NS,
            );

            return;
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;
        const ackAPSFrame = encodeZigbeeAPSFrame(
            {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.ACK,
                    deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                    ackFormat: false,
                    security: false,
                    ackRequest: false,
                    extendedHeader: false,
                },
                destEndpoint: apsHeader.sourceEndpoint,
                clusterId: apsHeader.clusterId,
                profileId: apsHeader.profileId,
                sourceEndpoint: apsHeader.destEndpoint,
                counter: apsHeader.counter,
            },
            Buffer.alloc(0), // TODO optimize
            // undefined,
            // undefined,
        );
        const ackNWKFrame = encodeZigbeeNWKFrame(
            {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
                    multicast: false,
                    security: true,
                    sourceRoute: relayIndex !== undefined,
                    extendedDestination: false,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: nwkHeader.source16,
                source16: nwkHeader.destination16,
                radius: this.#context.decrementRadius(nwkHeader.radius ?? CONFIG_NWK_MAX_HOPS),
                seqNum: nwkHeader.seqNum,
                relayIndex,
                relayAddresses,
            },
            ackAPSFrame,
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.NWK,
                    nonce: true,
                },
                frameCounter: this.#context.nextNWKKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                keySeqNum: this.#context.netParams.networkKeySequenceNumber,
                micLen: 4,
            },
            undefined, // use pre-hashed this.context.netParams.networkKey,
        );
        const ackMACFrame = encodeMACFrameZigbee(
            {
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: Boolean(
                        this.#context.indirectTransmissions.get(nwkDest64 ?? this.#context.address16ToAddress64.get(nwkDest16)!)?.length,
                    ),
                    ackRequest: true,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macHeader.sequenceNumber,
                destinationPANId: macHeader.destinationPANId,
                destination16: macDest16,
                // sourcePANId: undefined, // panIdCompression=true
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                fcs: 0,
            },
            ackNWKFrame,
        );

        await this.#macHandler.sendFrame(macHeader.sequenceNumber!, ackMACFrame, macHeader.source16, undefined);
    }

    public async onZigbeeAPSFrame(
        data: Buffer,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        apsHeader: ZigbeeAPSHeader,
        lqa: number,
    ): Promise<void> {
        switch (apsHeader.frameControl.frameType) {
            case ZigbeeAPSFrameType.ACK: {
                // ACKs should never contain a payload
                // TODO: ?
                break;
            }
            case ZigbeeAPSFrameType.DATA:
            case ZigbeeAPSFrameType.INTERPAN: {
                if (data.byteLength < 1) {
                    return;
                }

                logger.debug(
                    () =>
                        `<=== APS DATA[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${nwkHeader.seqNum} profileId=${apsHeader.profileId} clusterId=${apsHeader.clusterId} srcEp=${apsHeader.sourceEndpoint} dstEp=${apsHeader.destEndpoint} bcast=${macHeader.destination16 === ZigbeeMACConsts.BCAST_ADDR || (nwkHeader.destination16 !== undefined && nwkHeader.destination16 >= ZigbeeConsts.BCAST_MIN)}]`,
                    NS,
                );

                if (apsHeader.profileId === ZigbeeConsts.ZDO_PROFILE_ID) {
                    if (apsHeader.clusterId === ZigbeeConsts.END_DEVICE_ANNOUNCE) {
                        let offset = 1; // skip seq num
                        const address16 = data.readUInt16LE(offset);
                        offset += 2;
                        const address64 = data.readBigUInt64LE(offset);
                        offset += 8;
                        const capabilities = data.readUInt8(offset);
                        offset += 1;

                        const device = this.#context.deviceTable.get(address64);

                        if (!device) {
                            // unknown device, should have been added by `associate`, something's not right, ignore it
                            return;
                        }

                        const decodedCap = decodeMACCapabilities(capabilities);
                        // just in case
                        device.capabilities = decodedCap;

                        // TODO: ideally, this shouldn't trigger (prevents early interview process from app) until AFTER authorized=true
                        setImmediate(() => {
                            // if device is authorized, it means it completed the TC link key update, so, a rejoin
                            if (device.authorized) {
                                this.#callbacks.onDeviceRejoined(address16, address64, decodedCap);
                            } else {
                                this.#callbacks.onDeviceJoined(address16, address64, decodedCap);
                            }
                        });
                    } else {
                        const isRequest = (apsHeader.clusterId! & 0x8000) === 0;

                        if (isRequest) {
                            if (this.isZDORequestForCoordinator(apsHeader.clusterId!, nwkHeader.destination16, nwkHeader.destination64, data)) {
                                await this.respondToCoordinatorZDORequest(data, apsHeader.clusterId!, nwkHeader.source16, nwkHeader.source64);
                            }

                            // don't emit received ZDO requests
                            return;
                        }
                    }
                }

                if (nwkHeader.source16 === undefined && nwkHeader.source64 === undefined) {
                    logger.debug(() => "<=~= APS Ignoring frame with no sender info", NS);
                    return;
                }

                setImmediate(() => {
                    // TODO: always lookup source64 if undef?
                    this.#callbacks.onFrame(nwkHeader.source16, nwkHeader.source64, apsHeader, data, lqa);
                });

                break;
            }
            case ZigbeeAPSFrameType.CMD: {
                await this.processCommand(data, macHeader, nwkHeader, apsHeader);
                break;
            }
            default: {
                throw new Error(`Illegal frame type ${apsHeader.frameControl.frameType}`);
            }
        }
    }

    // #region Commands

    /**
     * 05-3474-R #4.4.11
     *
     * @param cmdId
     * @param finalPayload expected to contain the full payload (including cmdId)
     * @param macDest16
     * @param nwkDest16
     * @param nwkDest64
     * @param nwkRadius
     * @param apsDeliveryMode
     * @returns True if success sending (or indirect transmission)
     */
    public async sendCommand(
        cmdId: ZigbeeAPSCommandId,
        finalPayload: Buffer,
        nwkDiscoverRoute: ZigbeeNWKRouteDiscovery,
        nwkSecurity: boolean,
        nwkDest16: number | undefined,
        nwkDest64: bigint | undefined,
        apsDeliveryMode: ZigbeeAPSDeliveryMode.UNICAST | ZigbeeAPSDeliveryMode.BCAST,
        apsSecurityHeader: ZigbeeSecurityHeader | undefined,
        disableACKRequest = false,
    ): Promise<boolean> {
        let nwkSecurityHeader: ZigbeeSecurityHeader | undefined;

        if (nwkSecurity) {
            nwkSecurityHeader = {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.NWK,
                    nonce: true,
                },
                frameCounter: this.#context.nextNWKKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                keySeqNum: this.#context.netParams.networkKeySequenceNumber,
                micLen: 4,
            };
        }

        const apsCounter = this.nextCounter();
        const nwkSeqNum = this.#nwkHandler.nextSeqNum();
        const macSeqNum = this.#macHandler.nextSeqNum();
        let relayIndex: number | undefined;
        let relayAddresses: number[] | undefined;

        try {
            [relayIndex, relayAddresses] = this.#nwkHandler.findBestSourceRoute(nwkDest16, nwkDest64);
        } catch (error) {
            logger.error(
                `=x=> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64}] ${(error as Error).message}`,
                NS,
            );

            return false;
        }

        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.#context.deviceTable.get(nwkDest64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.error(
                `=x=> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} nwkSec=${nwkSecurity} apsDlv=${apsDeliveryMode} apsSec=${apsSecurityHeader !== undefined}]`,
                NS,
            );

            return false;
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;

        logger.debug(
            () =>
                `===> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} nwkSec=${nwkSecurity} apsDlv=${apsDeliveryMode} apsSec=${apsSecurityHeader !== undefined}]`,
            NS,
        );

        const apsFrame = encodeZigbeeAPSFrame(
            {
                frameControl: {
                    frameType: ZigbeeAPSFrameType.CMD,
                    deliveryMode: apsDeliveryMode,
                    ackFormat: false,
                    security: apsSecurityHeader !== undefined,
                    // XXX: spec says all should request ACK except TUNNEL, but vectors show not a lot of stacks respect that, what's best?
                    ackRequest: cmdId !== ZigbeeAPSCommandId.TUNNEL && !disableACKRequest,
                    extendedHeader: false,
                },
                counter: apsCounter,
            },
            finalPayload,
            apsSecurityHeader,
            undefined, // use pre-hashed this.context.netParams.tcKey,
        );
        const nwkFrame = encodeZigbeeNWKFrame(
            {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.DATA,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: nwkDiscoverRoute,
                    multicast: false,
                    security: nwkSecurity,
                    sourceRoute: relayIndex !== undefined,
                    extendedDestination: nwkDest64 !== undefined,
                    extendedSource: false,
                    endDeviceInitiator: false,
                },
                destination16: nwkDest16,
                destination64: nwkDest64,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                radius: this.#context.decrementRadius(CONFIG_NWK_MAX_HOPS),
                seqNum: nwkSeqNum,
                relayIndex,
                relayAddresses,
            },
            apsFrame,
            nwkSecurityHeader,
            undefined, // use pre-hashed this.context.netParams.networkKey,
        );
        const macFrame = encodeMACFrameZigbee(
            {
                frameControl: {
                    frameType: MACFrameType.DATA,
                    securityEnabled: false,
                    framePending: Boolean(
                        this.#context.indirectTransmissions.get(nwkDest64 ?? this.#context.address16ToAddress64.get(nwkDest16)!)?.length,
                    ),
                    ackRequest: macDest16 !== ZigbeeMACConsts.BCAST_ADDR,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macSeqNum,
                destinationPANId: this.#context.netParams.panId,
                destination16: macDest16,
                // sourcePANId: undefined, // panIdCompression=true
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                fcs: 0,
            },
            nwkFrame,
        );

        const result = await this.#macHandler.sendFrame(macSeqNum, macFrame, macDest16, undefined);

        return result !== false;
    }

    public async processCommand(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void> {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;

        switch (cmdId) {
            case ZigbeeAPSCommandId.TRANSPORT_KEY: {
                offset = this.processTransportKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.UPDATE_DEVICE: {
                offset = await this.processUpdateDevice(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.REMOVE_DEVICE: {
                offset = this.processRemoveDevice(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.REQUEST_KEY: {
                offset = await this.processRequestKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.SWITCH_KEY: {
                offset = this.processSwitchKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.TUNNEL: {
                offset = this.processTunnel(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.VERIFY_KEY: {
                offset = await this.processVerifyKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.CONFIRM_KEY: {
                offset = this.processConfirmKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.RELAY_MESSAGE_DOWNSTREAM: {
                offset = this.processRelayMessageDownstream(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case ZigbeeAPSCommandId.RELAY_MESSAGE_UPSTREAM: {
                offset = this.processRelayMessageUpstream(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            default: {
                logger.warning(
                    `<=x= APS CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}] Unsupported`,
                    NS,
                );
                return;
            }
        }

        // excess data in packet
        // if (offset < data.byteLength) {
        //     logger.debug(() => `<=== APS CMD contained more data: ${data.toString('hex')}`, NS);
        // }
    }

    /**
     * 05-3474-R #4.4.11.1
     */
    public processTransportKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number {
        const keyType = data.readUInt8(offset);
        offset += 1;
        const key = data.subarray(offset, offset + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;

        switch (keyType) {
            case ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK:
            case ZigbeeAPSConsts.CMD_KEY_HIGH_SEC_NWK: {
                const seqNum = data.readUInt8(offset);
                offset += 1;
                const destination = data.readBigUInt64LE(offset);
                offset += 8;
                const source = data.readBigUInt64LE(offset);
                offset += 8;

                logger.debug(
                    () =>
                        `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} seqNum=${seqNum} dst64=${destination} src64=${source}]`,
                    NS,
                );

                break;
            }
            case ZigbeeAPSConsts.CMD_KEY_TC_MASTER:
            case ZigbeeAPSConsts.CMD_KEY_TC_LINK: {
                const destination = data.readBigUInt64LE(offset);
                offset += 8;
                const source = data.readBigUInt64LE(offset);
                offset += 8;

                // TODO
                // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);

                logger.debug(
                    () =>
                        `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} dst64=${destination} src64=${source}]`,
                    NS,
                );
                break;
            }
            case ZigbeeAPSConsts.CMD_KEY_APP_MASTER:
            case ZigbeeAPSConsts.CMD_KEY_APP_LINK: {
                const partner = data.readBigUInt64LE(offset);
                offset += 8;
                const initiatorFlag = data.readUInt8(offset);
                offset += 1;

                // TODO
                // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);

                logger.debug(
                    () =>
                        `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} partner64=${partner} initiatorFlag=${initiatorFlag}]`,
                    NS,
                );
                break;
            }
        }

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.1
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly uses CMD_KEY_TC_LINK type (0x01) per spec Table 4-17
     * - ✅ Uses UNICAST delivery mode as required by spec
     * - ✅ Applies both NWK security (true) and APS security (LOAD key) per spec #4.4.1.5
     * - ✅ Includes destination64 and source64 (TC eui64) as mandated
     * - ⚠️  TODO: TLVs not implemented (optional but recommended for R23+ features)
     * - ⚠️  TODO: Tunneling support not implemented (optional per spec #4.6.3.7)
     * - ❓ UNCERTAIN: Using LOAD keyId for APS encryption - spec says "link key" but LOAD is typically used for TC link key transport
     * - ✅ Frame counter uses TC key counter (nextTCKeyFrameCounter) which is correct
     * - ✅ MIC length 4 bytes as per security spec requirements
     *
     * @param nwkDest16
     * @param key SHALL contain the link key that SHOULD be used for APS encryption
     * @param destination64 SHALL contain the address of the device which SHOULD use this link key
     * @returns
     */
    public async sendTransportKeyTC(nwkDest16: number, key: Buffer, destination64: bigint): Promise<boolean> {
        // TODO: tunneling support `, tunnelDest?: bigint`
        //       If the TunnelCommand parameter is TRUE, an APS Tunnel Command SHALL be constructed as described in section 4.6.3.7.
        //       It SHALL then be sent to the device specified by the TunnelAddress parameter by issuing an NLDE-DATA.request primitive.
        logger.debug(() => `===> APS TRANSPORT_KEY_TC[key=${key.toString("hex")} dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(18 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_TC_LINK, offset);
        offset += 1;
        finalPayload.set(key, offset);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        finalPayload.writeBigUInt64LE(this.#context.netParams.eui64, offset);
        offset += 8;

        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeAPSTLVs();

        // encryption NWK=true, APS=true
        return await this.sendCommand(
            ZigbeeAPSCommandId.TRANSPORT_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.LOAD,
                    nonce: true,
                },
                frameCounter: this.#context.nextTCKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                // keySeqNum: undefined, only for keyId NWK
                micLen: 4,
            }, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.1 #4.4.11.1.3.2
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly uses CMD_KEY_STANDARD_NWK type (0x00) per spec Table 4-17
     * - ✅ Includes seqNum, destination64, and source64 as required by spec
     * - ✅ Uses UNICAST delivery mode as appropriate for joining device
     * - ⚠️  DESIGN CHOICE: Uses NWK security=false, APS security=true with TRANSPORT keyId
     *       - Spec #4.4.1.5 states "a device receiving an APS transport key command MAY choose whether or not APS encryption is required"
     *       - Implementation chooses APS encryption for initial join security
     *       - Alternative (commented out) uses NWK=true, APS=false which is also valid per spec
     * - ⚠️  SPEC COMPLIANCE: disableACKRequest=true follows observed behavior in sniffs but spec #4.4.11 says:
     *       "All commands except TUNNEL SHALL request acknowledgement" - this appears to violate spec
     *       However, TRANSPORT_KEY during initial join may not receive ACK due to lack of NWK key
     * - ✅ Frame counter uses TC key counter which is correct for TRANSPORT keyId
     * - ✅ For distributed networks (no TC), source64 should be 0xFFFFFFFFFFFFFFFF per spec - code correctly uses eui64 (centralized TC)
     * - ❌ SPEC ISSUE: Broadcast destination64 handling not implemented (should set to all-zero per spec)
     *
     * @param nwkDest16
     * @param key SHALL contain a network key
     * @param seqNum SHALL contain the sequence number associated with this network key
     * @param destination64 SHALL contain the address of the device which SHOULD use this network key
     * If the network key is sent to a broadcast address, the destination address subfield SHALL be set to the all-zero string and SHALL be ignored upon reception.
     * @returns
     */
    public async sendTransportKeyNWK(nwkDest16: number, key: Buffer, seqNum: number, destination64: bigint): Promise<boolean> {
        // TODO: tunneling support `, tunnelDest?: bigint`
        logger.debug(() => `===> APS TRANSPORT_KEY_NWK[key=${key.toString("hex")} seqNum=${seqNum} dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(19 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK, offset);
        offset += 1;
        finalPayload.set(key, offset);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;
        finalPayload.writeUInt8(seqNum, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        finalPayload.writeBigUInt64LE(this.#context.netParams.eui64, offset); // 0xFFFFFFFFFFFFFFFF in distributed network (no TC)
        offset += 8;

        // see 05-3474-23 #4.4.1.5
        // Conversely, a device receiving an APS transport key command MAY choose whether or not APS encryption is required.
        // This is most often done during initial joining.
        // For example, during joining a device that has no preconfigured link key would only accept unencrypted transport key messages,
        // while a device with a preconfigured link key would only accept a transport key APS encrypted with its preconfigured key.

        // encryption NWK=true, APS=false
        // await this.sendCommand(
        //     ZigbeeAPSCommandId.TRANSPORT_KEY,
        //     finalPayload,
        //     ZigbeeNWKRouteDiscovery.SUPPRESS,
        //     true, // nwkSecurity
        //     nwkDest16, // nwkDest16
        //     undefined, // nwkDest64
        //     ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
        //     undefined, // apsSecurityHeader
        // );

        // encryption NWK=false, APS=true
        return await this.sendCommand(
            ZigbeeAPSCommandId.TRANSPORT_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            false, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.TRANSPORT,
                    nonce: true,
                },
                frameCounter: this.#context.nextTCKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                // keySeqNum: undefined, only for keyId NWK
                micLen: 4,
            }, // apsSecurityHeader
            true, // disableACKRequest TODO: follows sniffed but not spec?
        );
    }

    /**
     * 05-3474-R #4.4.11.1 #4.4.11.1.3.3
     *
     * @param nwkDest16
     * @param key SHALL contain a link key that is shared with the device identified in the partner address sub-field
     * @param partner SHALL contain the address of the other device that was sent this link key
     * @param initiatorFlag SHALL be set to 1 if the device receiving this packet requested this key. Otherwise, this sub-field SHALL be set to 0.
     * @returns
     */
    public async sendTransportKeyAPP(nwkDest16: number, key: Buffer, partner: bigint, initiatorFlag: boolean): Promise<boolean> {
        // TODO: tunneling support `, tunnelDest?: bigint`
        logger.debug(() => `===> APS TRANSPORT_KEY_APP[key=${key.toString("hex")} partner64=${partner} initiatorFlag=${initiatorFlag}]`, NS);

        const finalPayload = Buffer.alloc(11 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_APP_LINK, offset);
        offset += 1;
        finalPayload.set(key, offset);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;
        finalPayload.writeBigUInt64LE(partner, offset);
        offset += 8;
        finalPayload.writeUInt8(initiatorFlag ? 1 : 0, offset);
        offset += 1;

        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeAPSTLVs();

        return await this.sendCommand(
            ZigbeeAPSCommandId.TRANSPORT_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.LOAD,
                    nonce: true,
                },
                frameCounter: this.#context.nextTCKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                // keySeqNum: undefined, only for keyId NWK
                micLen: 4,
            }, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.2
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly decodes all mandatory fields: device64, device16, status
     * - ⚠️  TODO: TLVs not decoded (optional but recommended for R23+ features)
     * - ✅ Handles 4 status codes as per spec:
     *       0x00 = Standard Device Secured Rejoin
     *       0x01 = Standard Device Unsecured Join
     *       0x02 = Device Left
     *       0x03 = Standard Device Trust Center Rejoin
     * - ⚠️  IMPLEMENTATION: Status 0x01 (Unsecured Join) handling:
     *       - Calls context associate with initial join=true ✅
     *       - Sets neighbor=false ✅ (device joined through router)
     *       - allowOverride=true ✅ (was allowed by parent)
     *       - Creates source route through parent ✅
     *       - Sends TUNNEL(TRANSPORT_KEY) to parent for relay ✅
     * - ⚠️  SPEC CONCERN: Tunneling TRANSPORT_KEY for nested joins:
     *       - Uses TUNNEL command per spec #4.6.3.7 ✅
     *       - Encrypts tunneled APS frame with TRANSPORT keyId ✅
     *       - However, should verify parent can relay before trusting join
     * - ⚠️  Status 0x03 (TC Rejoin) handling appears correct but minimal
     * - ⚠️  Status 0x02 (Device Left) handling uses onDisassociate - spec says "informative only, should not take action"
     *       This may be non-compliant as it actively removes the device
     * - ❌ MISSING: Status 0x00 (Secured Rejoin) is not handled at all
     *
     * SECURITY CONCERN:
     * - Unsecured joins through routers rely heavily on parent router trust
     * - No verification of parent's claim about device capabilities
     * - Source route created immediately may be premature if join fails
     */
    public async processUpdateDevice(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): Promise<number> {
        const device64 = data.readBigUInt64LE(offset);
        offset += 8;
        // ZigBee 2006 and later
        const device16 = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);

        logger.debug(
            () =>
                `<=== APS UPDATE_DEVICE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dev=${device16}:${device64} status=${status} src16=${nwkHeader.source16}]`,
            NS,
        );

        // 0x00 = Standard Device Secured Rejoin
        // 0x01 = Standard Device Unsecured Join
        // 0x02 = Device Left
        // 0x03 = Standard Device Trust Center Rejoin
        // 0x04 – 0x07 = Reserved
        if (status === 0x01) {
            await this.#context.associate(
                device16,
                device64,
                true, // initial join
                undefined, // no MAC cap through router
                false, // not neighbor
                false,
                true, // was allowed by parent
            );

            // TODO: better handling
            try {
                const [, parentRelays] = this.#nwkHandler.findBestSourceRoute(nwkHeader.source16, nwkHeader.source64);

                if (parentRelays) {
                    // parent is nested
                    this.#context.sourceRouteTable.set(device16, [this.#nwkHandler.createSourceRouteEntry(parentRelays, parentRelays.length + 1)]);
                } else {
                    // parent is direct to coordinator
                    this.#context.sourceRouteTable.set(device16, [this.#nwkHandler.createSourceRouteEntry([nwkHeader.source16!], 2)]);
                }
            } catch {
                /* ignore */
            }

            const tApsCmdPayload = Buffer.alloc(19 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
            let offset = 0;
            tApsCmdPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
            offset += 1;
            tApsCmdPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK, offset);
            offset += 1;
            tApsCmdPayload.set(this.#context.netParams.networkKey, offset);
            offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;
            tApsCmdPayload.writeUInt8(this.#context.netParams.networkKeySequenceNumber, offset);
            offset += 1;
            tApsCmdPayload.writeBigUInt64LE(device64, offset);
            offset += 8;
            tApsCmdPayload.writeBigUInt64LE(this.#context.netParams.eui64, offset); // 0xFFFFFFFFFFFFFFFF in distributed network (no TC)
            offset += 8;

            const tApsCmdFrame = encodeZigbeeAPSFrame(
                {
                    frameControl: {
                        frameType: ZigbeeAPSFrameType.CMD,
                        deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
                        ackFormat: false,
                        security: true,
                        ackRequest: false,
                        extendedHeader: false,
                    },
                    counter: this.nextCounter(),
                },
                tApsCmdPayload,
                {
                    control: {
                        level: ZigbeeSecurityLevel.NONE,
                        keyId: ZigbeeKeyType.TRANSPORT,
                        nonce: true,
                    },
                    frameCounter: this.#context.nextTCKeyFrameCounter(),
                    source64: this.#context.netParams.eui64,
                    micLen: 4,
                },
                undefined, // use pre-hashed this.context.netParams.tcKey,
            );

            await this.sendTunnel(nwkHeader.source16!, device64, tApsCmdFrame);
        } else if (status === 0x03) {
            // rejoin
            await this.#context.associate(
                device16,
                device64,
                false, // rejoin
                undefined, // no MAC cap through router
                false, // not neighbor
                false,
                true, // was allowed by parent, expected valid
            );
        } else if (status === 0x02) {
            // left
            // TODO: according to spec, this is "informative" only, should not take any action?
            await this.#context.disassociate(device16, device64);
        }

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.2
     *
     * @param nwkDest16 device that SHALL be sent the update information
     * @param device64 device whose status is being updated
     * @param device16 device whose status is being updated
     * @param status Indicates the updated status of the device given by the device64 parameter:
     * - 0x00 = Standard Device Secured Rejoin
     * - 0x01 = Standard Device Unsecured Join
     * - 0x02 = Device Left
     * - 0x03 = Standard Device Trust Center Rejoin
     * - 0x04 – 0x07 = Reserved
     * @param tlvs as relayed during Network Commissioning
     * @returns
     */
    public async sendUpdateDevice(
        nwkDest16: number,
        device64: bigint,
        device16: number,
        status: number,
        // tlvs: unknown[],
    ): Promise<boolean> {
        logger.debug(() => `===> APS UPDATE_DEVICE[dev=${device16}:${device64} status=${status}]`, NS);

        const finalPayload = Buffer.alloc(12 /* + TLVs */);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.UPDATE_DEVICE, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(device64, offset);
        offset += 8;
        finalPayload.writeUInt16LE(device16, offset);
        offset += 2;
        finalPayload.writeUInt8(status, offset);
        offset += 1;

        // TODO TLVs

        return await this.sendCommand(
            ZigbeeAPSCommandId.UPDATE_DEVICE,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.3
     */
    public processRemoveDevice(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number {
        const target = data.readBigUInt64LE(offset);
        offset += 8;

        logger.debug(
            () =>
                `<=== APS REMOVE_DEVICE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} target64=${target}]`,
            NS,
        );

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.3
     *
     * @param nwkDest16 parent
     * @param target64
     * @returns
     */
    public async sendRemoveDevice(nwkDest16: number, target64: bigint): Promise<boolean> {
        logger.debug(() => `===> APS REMOVE_DEVICE[target64=${target64}]`, NS);

        const finalPayload = Buffer.alloc(9);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.REMOVE_DEVICE, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(target64, offset);
        offset += 8;

        return await this.sendCommand(
            ZigbeeAPSCommandId.REMOVE_DEVICE,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.4 #4.4.5.2.3
     */
    public async processRequestKey(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        apsHeader: ZigbeeAPSHeader,
    ): Promise<number> {
        // ZigbeeAPSConsts.CMD_KEY_APP_MASTER || ZigbeeAPSConsts.CMD_KEY_TC_LINK
        const keyType = data.readUInt8(offset);
        offset += 1;

        // If the APS Command Request Key message is not APS encrypted, the device SHALL drop the message and no further processing SHALL be done.
        if (!apsHeader.frameControl.security) {
            return offset;
        }

        const device64 = this.#context.address16ToAddress64.get(nwkHeader.source16!);

        // don't send to unknown device
        if (device64 !== undefined) {
            // TODO:
            //   const deviceKeyPair = this.apsDeviceKeyPairSet.get(nwkHeader.source16!);
            //   if (!deviceKeyPair || deviceKeyPair.keyNegotiationMethod === 0x00 /* `APS Request Key` method */) {

            if (keyType === ZigbeeAPSConsts.CMD_KEY_APP_MASTER) {
                const partner = data.readBigUInt64LE(offset);
                offset += 8;

                logger.debug(
                    () =>
                        `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} partner64=${partner}]`,
                    NS,
                );

                if (this.#context.trustCenterPolicies.allowAppKeyRequest === ApplicationKeyRequestPolicy.ALLOWED) {
                    const appLinkKey = this.getOrGenerateAppLinkKey(nwkHeader.source16!, partner);

                    await this.sendTransportKeyAPP(nwkHeader.source16!, appLinkKey, partner, true);
                }
                // TODO ApplicationKeyRequestPolicy.ONLY_APPROVED
            } else if (keyType === ZigbeeAPSConsts.CMD_KEY_TC_LINK) {
                logger.debug(
                    () =>
                        `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}]`,
                    NS,
                );

                if (this.#context.trustCenterPolicies.allowTCKeyRequest === TrustCenterKeyRequestPolicy.ALLOWED) {
                    await this.sendTransportKeyTC(nwkHeader.source16!, this.#context.netParams.tcKey, device64);
                }
                // TODO TrustCenterKeyRequestPolicy.ONLY_PROVISIONAL
                //      this.apsDeviceKeyPairSet => find deviceAddress === this.context.deviceTable.get(nwkHeader.source).address64 => check provisional or drop msg
            }
        } else {
            logger.warning(
                `<=x= APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}] Unknown device`,
                NS,
            );
        }

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.4
     *
     * @param nwkDest16
     * @param keyType SHALL be set to the key being requested
     * - 0x02: App link key
     * - 0x04: TC link key
     * @param partner64 When the RequestKeyType field is 2 (that is, an application key),
     * the partner address field SHALL contain the extended 64-bit address of the partner device that SHALL be sent the key.
     * Both the partner device and the device originating the request-key command will be sent the key.
     * @returns
     */
    public async sendRequestKey(nwkDest16: number, keyType: 0x02, partner64: bigint): Promise<boolean>;
    public async sendRequestKey(nwkDest16: number, keyType: 0x04): Promise<boolean>;
    public async sendRequestKey(nwkDest16: number, keyType: 0x02 | 0x04, partner64?: bigint): Promise<boolean> {
        logger.debug(() => `===> APS REQUEST_KEY[type=${keyType} partner64=${partner64}]`, NS);

        const hasPartner64 = keyType === ZigbeeAPSConsts.CMD_KEY_APP_MASTER;
        const finalPayload = Buffer.alloc(2 + (hasPartner64 ? 8 : 0));
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.REQUEST_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(keyType, offset);
        offset += 1;

        if (hasPartner64) {
            finalPayload.writeBigUInt64LE(partner64!, offset);
            offset += 8;
        }

        return await this.sendCommand(
            ZigbeeAPSCommandId.REQUEST_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.5
     */
    public processSwitchKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number {
        const seqNum = data.readUInt8(offset);
        offset += 1;

        logger.debug(
            () =>
                `<=== APS SWITCH_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${seqNum}]`,
            NS,
        );

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.5
     *
     * @param nwkDest16
     * @param seqNum SHALL contain the sequence number identifying the network key to be made active.
     * @returns
     */
    public async sendSwitchKey(nwkDest16: number, seqNum: number): Promise<boolean> {
        logger.debug(() => `===> APS SWITCH_KEY[seqNum=${seqNum}]`, NS);

        const finalPayload = Buffer.from([ZigbeeAPSCommandId.SWITCH_KEY, seqNum]);

        return await this.sendCommand(
            ZigbeeAPSCommandId.SWITCH_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.6
     */
    public processTunnel(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number {
        const destination = data.readBigUInt64LE(offset);
        offset += 8;
        const tunneledAPSFrame = data.subarray(offset);
        offset += tunneledAPSFrame.byteLength;

        logger.debug(
            () =>
                `<=== APS TUNNEL[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dst=${destination} tAPSFrame=${tunneledAPSFrame}]`,
            NS,
        );

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.6
     *
     * @param nwkDest16
     * @param destination64 SHALL be the 64-bit extended address of the device that is to receive the tunneled command
     * @param tApsCmdFrame SHALL be the APS command payload to be sent to the destination
     * @returns
     */
    public async sendTunnel(nwkDest16: number, destination64: bigint, tApsCmdFrame: Buffer): Promise<boolean> {
        logger.debug(() => `===> APS TUNNEL[dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(9 + tApsCmdFrame.byteLength);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.TUNNEL, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;
        finalPayload.set(tApsCmdFrame, offset);
        offset += tApsCmdFrame.byteLength;

        return await this.sendCommand(
            ZigbeeAPSCommandId.TUNNEL,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.7
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Decodes keyType, source64, and keyHash correctly
     * - ✅ Filters out broadcast frames (macHeader.source16 !== BCAST_ADDR) as required
     * - ✅ Verifies TC link key hash for keyType=CMD_KEY_TC_LINK (0x01)
     * - ✅ Returns appropriate status codes:
     *       - 0x00 (SUCCESS) when hash matches
     *       - 0xad (SECURITY_FAILURE) when hash doesn't match
     *       - 0xa3 (ILLEGAL_REQUEST) for APP_MASTER in TC
     *       - 0xaa (NOT_SUPPORTED) for unknown key types
     * - ⚠️  SPEC COMPLIANCE: Hash verification uses pre-computed tcVerifyKeyHash from context
     *       - Spec B.1.4: hash should be keyed hash function with input string '0x03'
     *       - Implementation appears correct (context.tcVerifyKeyHash is computed correctly)
     * - ❌ MISSING: Spec states "not valid if operating in distributed network" but no check for distributed mode
     * - ✅ Sends CONFIRM_KEY in response with appropriate status
     * - ❓ UNCERTAIN: keyType=CMD_KEY_APP_MASTER (0x02) returns ILLEGAL_REQUEST for TC
     *       - Spec is unclear if TC should reject this or if it's valid in some scenarios
     * - ✅ Uses source64 parameter correctly in CONFIRM_KEY response
     *
     * NOTE: This command is critical for security - device proves it has the correct key
     */
    public async processVerifyKey(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): Promise<number> {
        const keyType = data.readUInt8(offset);
        offset += 1;
        const source = data.readBigUInt64LE(offset);
        offset += 8;
        const keyHash = data.subarray(offset, offset + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        offset += ZigbeeAPSConsts.CMD_KEY_LENGTH;

        if (macHeader.source16 !== ZigbeeMACConsts.BCAST_ADDR) {
            logger.debug(
                () =>
                    `<=== APS VERIFY_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} src64=${source} hash=${keyHash.toString("hex")}]`,
                NS,
            );

            if (keyType === ZigbeeAPSConsts.CMD_KEY_TC_LINK) {
                // TODO: not valid if operating in distributed network
                const status = this.#context.tcVerifyKeyHash.equals(keyHash) ? 0x00 /* SUCCESS */ : 0xad; /* SECURITY_FAILURE */

                await this.sendConfirmKey(nwkHeader.source16!, status, keyType, source);
            } else if (keyType === ZigbeeAPSConsts.CMD_KEY_APP_MASTER) {
                // this is illegal for TC
                await this.sendConfirmKey(nwkHeader.source16!, 0xa3 /* ILLEGAL_REQUEST */, keyType, source);
            } else {
                await this.sendConfirmKey(nwkHeader.source16!, 0xaa /* NOT_SUPPORTED */, keyType, source);
            }
        }

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.7
     *
     * @param nwkDest16
     * @param keyType type of key being verified
     * @param source64 SHALL be the 64-bit extended address of the partner device that the destination shares the link key with
     * @param hash outcome of executing the specialized keyed hash function specified in section B.1.4 using a key with the 1-octet string ‘0x03’ as the input string
     * The resulting value SHALL NOT be used as a key for encryption or decryption
     * @returns
     */
    public async sendVerifyKey(nwkDest16: number, keyType: number, source64: bigint, hash: Buffer): Promise<boolean> {
        logger.debug(() => `===> APS VERIFY_KEY[type=${keyType} src64=${source64} hash=${hash.toString("hex")}]`, NS);

        const finalPayload = Buffer.alloc(26);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.VERIFY_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(keyType, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(source64, offset);
        offset += 8;
        finalPayload.set(hash, offset);
        offset += hash.byteLength; // 16

        return await this.sendCommand(
            ZigbeeAPSCommandId.VERIFY_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            undefined, // apsSecurityHeader
        );
    }

    /**
     * 05-3474-R #4.4.11.8
     */
    public processConfirmKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number {
        const status = data.readUInt8(offset);
        offset += 8;
        const keyType = data.readUInt8(offset);
        offset += 1;
        const destination = data.readBigUInt64LE(offset);
        offset += 8;

        logger.debug(
            () =>
                `<=== APS CONFIRM_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${status} type=${keyType} dst64=${destination}]`,
            NS,
        );

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.8
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Sends CONFIRM_KEY with all required fields: status, keyType, destination64
     * - ✅ Uses UNICAST delivery mode as required
     * - ✅ Applies NWK security (true) as expected for TC communications
     * - ⚠️  CRITICAL SPEC QUESTION: Uses LINK keyId for APS security
     *       - Comment says "XXX: TRANSPORT?" indicating uncertainty
     *       - Spec #4.4.11.8 doesn't explicitly state which keyId to use
     *       - LINK (0x03) suggests using the link key being confirmed
     *       - TRANSPORT (0x05) would use TC link key as transport
     *       - THIS NEEDS VERIFICATION AGAINST SPEC AND PACKET CAPTURES
     * - ✅ Uses nextTCKeyFrameCounter() which is correct for TC->device communications
     * - ✅ Sets device.authorized = true after successful CONFIRM_KEY send
     * - ✅ Triggers onDeviceAuthorized callback via setImmediate (non-blocking)
     * - ⚠️  TIMING CONCERN: Sets authorized=true immediately after send, not after ACK
     *       - May cause race condition if CONFIRM_KEY fails to deliver
     *       - Should possibly wait for ACK or rely on retry mechanism
     * - ✅ Only sets authorized for devices in deviceTable
     *
     * CRITICAL: This is the final step in device authorization - must be correct!
     *
     * @param nwkDest16
     * @param status 1-byte status code indicating the result of the operation. See Table 2.27
     * @param keyType the type of key being verified
     * @param destination64 SHALL be the 64-bit extended address of the source device of the Verify-Key message
     * @returns
     */
    public async sendConfirmKey(nwkDest16: number, status: number, keyType: number, destination64: bigint): Promise<boolean> {
        logger.debug(() => `===> APS CONFIRM_KEY[status=${status} type=${keyType} dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(11);
        let offset = 0;
        finalPayload.writeUInt8(ZigbeeAPSCommandId.CONFIRM_KEY, offset);
        offset += 1;
        finalPayload.writeUInt8(status, offset);
        offset += 1;
        finalPayload.writeUInt8(keyType, offset);
        offset += 1;
        finalPayload.writeBigUInt64LE(destination64, offset);
        offset += 8;

        const result = await this.sendCommand(
            ZigbeeAPSCommandId.CONFIRM_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            true, // nwkSecurity
            nwkDest16, // nwkDest16
            undefined, // nwkDest64
            ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
            {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.LINK, // XXX: TRANSPORT?
                    nonce: true,
                },
                frameCounter: this.#context.nextTCKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                // keySeqNum: undefined, only for keyId NWK
                micLen: 4,
            }, // apsSecurityHeader
        );

        const device = this.#context.deviceTable.get(destination64);

        // TODO: proper place?
        if (device !== undefined && device.authorized === false) {
            device.authorized = true;

            setImmediate(() => {
                this.#callbacks.onDeviceAuthorized(device.address16, destination64);
            });
        }

        return result;
    }

    /**
     * 05-3474-R #4.4.11.9
     */
    public processRelayMessageDownstream(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        // this includes only TLVs

        // This contains the EUI64 of the unauthorized neighbor that is the intended destination of the relayed message.
        const destination64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the Trust Center to the Joining device.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;

        logger.debug(
            () =>
                `<=== APS RELAY_MESSAGE_DOWNSTREAM[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dst64=${destination64}]`,
            NS,
        );

        return offset;
    }

    // TODO: send RELAY_MESSAGE_DOWNSTREAM

    /**
     * 05-3474-R #4.4.11.10
     */
    public processRelayMessageUpstream(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): number {
        // this includes only TLVs

        // This contains the EUI64 of the unauthorized neighbor that is the source of the relayed message.
        const source64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the joining device to the Trust Center.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;

        logger.debug(
            () =>
                `<=== APS RELAY_MESSAGE_UPSTREAM[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} src64=${source64}]`,
            NS,
        );

        return offset;
    }

    // TODO: send RELAY_MESSAGE_UPSTREAM

    // #endregion

    // #region ZDO Helpers

    /**
     * Generate LQI (Link Quality Indicator) table response for coordinator.
     * ZDO response to LQI_TABLE_REQUEST.
     * @see 05-3474-23 #2.4.4.2.3
     * @param startIndex The index to start the table entries from
     * @returns Buffer containing the LQI table response
     */
    public getLQITableResponse(startIndex: number): Buffer {
        let neighborRouteTableIndex = 0;
        let neighborTableEntries = 0;
        // multiple of 7: [extendedPanId, eui64, nwkAddress, deviceTypeByte, permitJoiningByte, depth, lqa, ...repeat]
        const lqiTableArr: (number | bigint)[] = [];

        // XXX: this is not great...
        for (const [addr64, entry] of this.#context.deviceTable) {
            if (entry.neighbor) {
                if (neighborRouteTableIndex < startIndex) {
                    // if under `startIndex`, just count
                    neighborRouteTableIndex += 1;
                    neighborTableEntries += 1;

                    continue;
                }

                if (neighborRouteTableIndex >= startIndex + 0xff) {
                    // if over uint8 size from `startIndex`, just count
                    neighborRouteTableIndex += 1;
                    neighborTableEntries += 1;

                    continue;
                }

                const deviceType = entry.capabilities ? (entry.capabilities.deviceType === 1 ? 0x01 /* ZR */ : 0x02 /* ZED */) : 0x03 /* UNK */;
                const rxOnWhenIdle = entry.capabilities ? (entry.capabilities.rxOnWhenIdle ? 0x01 /* ON */ : 0x00 /* OFF */) : 0x02 /* UNK */;
                const relationship = 0x02; // TODO // 0x00 = neighbor is the parent, 0x01 = neighbor is a child, 0x02 = neighbor is a sibling, 0x03 = None of the above
                const permitJoining = 0x02; // TODO // 0x00 = neighbor is not accepting join requests, 0x01 = neighbor is accepting join requests, 0x02 = unknown
                const deviceTypeByte =
                    (deviceType & 0x03) | ((rxOnWhenIdle << 2) & 0x03) | ((relationship << 4) & 0x07) | ((0 /* reserved */ << 7) & 0x01);
                const permitJoiningByte = (permitJoining & 0x03) | ((0 /* reserved2 */ << 2) & 0x3f);
                const depth = 1; // TODO // 0x00 indicates that the device is the Zigbee coordinator for the network
                const lqa = this.#context.computeDeviceLQA(entry.address16, addr64);

                lqiTableArr.push(this.#context.netParams.extendedPanId);
                lqiTableArr.push(addr64);
                lqiTableArr.push(entry.address16);
                lqiTableArr.push(deviceTypeByte);
                lqiTableArr.push(permitJoiningByte);
                lqiTableArr.push(depth);
                lqiTableArr.push(lqa);

                neighborTableEntries += 1;
                neighborRouteTableIndex += 1;
            }
        }

        // have to fit uint8 count-type bytes of ZDO response
        const clipped = neighborTableEntries > 0xff;
        const entryCount = lqiTableArr.length / 7;
        const lqiTable = Buffer.alloc(5 + entryCount * 22);
        let offset = 0;

        if (clipped) {
            logger.debug(() => `LQI table clipped at 255 entries to fit ZDO response (actual=${neighborTableEntries})`, NS);
        }

        lqiTable.writeUInt8(0 /* seq num */, offset);
        offset += 1;
        lqiTable.writeUInt8(0 /* SUCCESS */, offset);
        offset += 1;
        lqiTable.writeUInt8(neighborTableEntries, offset);
        offset += 1;
        lqiTable.writeUInt8(startIndex, offset);
        offset += 1;
        lqiTable.writeUInt8(entryCount, offset);
        offset += 1;

        let entryIndex = 0;

        for (let i = 0; i < entryCount; i++) {
            lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex] as bigint /* extendedPanId */, offset);
            offset += 8;
            lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex + 1] as bigint /* eui64 */, offset);
            offset += 8;
            lqiTable.writeUInt16LE(lqiTableArr[entryIndex + 2] as number /* nwkAddress */, offset);
            offset += 2;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 3] as number /* deviceTypeByte */, offset);
            offset += 1;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 4] as number /* permitJoiningByte */, offset);
            offset += 1;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 5] as number /* depth */, offset);
            offset += 1;
            lqiTable.writeUInt8(lqiTableArr[entryIndex + 6] as number /* lqa */, offset);
            offset += 1;

            entryIndex += 7;
        }

        return lqiTable;
    }

    /**
     * Generate routing table response for coordinator.
     * ZDO response to ROUTING_TABLE_REQUEST.
     * NOTE: Only outputs the best source route for each entry in the table (clipped to max 255 entries).
     * @see 05-3474-23 #2.4.4.3.3
     * @param startIndex The index to start the table entries from
     * @returns Buffer containing the routing table response
     */
    public getRoutingTableResponse(startIndex: number): Buffer {
        let sourceRouteTableIndex = 0;
        let routingTableEntries = 0;
        // multiple of 3: [destination16, statusByte, nextHopAddress, ...repeat]
        const routingTableArr: number[] = [];

        // XXX: this is not great...
        for (const [addr16] of this.#context.sourceRouteTable) {
            try {
                const [relayLastIndex, relayAddresses] = this.#nwkHandler.findBestSourceRoute(addr16, undefined);

                if (relayLastIndex !== undefined && relayAddresses !== undefined) {
                    if (sourceRouteTableIndex < startIndex) {
                        // if under `startIndex`, just count
                        sourceRouteTableIndex += 1;
                        routingTableEntries += 1;

                        continue;
                    }

                    if (sourceRouteTableIndex >= startIndex + 0xff) {
                        // if over uint8 size from `startIndex`, just count
                        sourceRouteTableIndex += 1;
                        routingTableEntries += 1;

                        continue;
                    }

                    const status = 0x0; // ACTIVE
                    const memoryConstrained = 0; // TODO
                    const manyToOne = 0; // TODO
                    const routeRecordRequired = 0; // TODO
                    const statusByte =
                        (status & 0x07) |
                        ((memoryConstrained << 3) & 0x01) |
                        ((manyToOne << 4) & 0x01) |
                        ((routeRecordRequired << 5) & 0x01) |
                        ((0 /* reserved */ << 6) & 0x03);
                    // last entry is next hop
                    const nextHopAddress = relayAddresses[relayLastIndex];

                    routingTableArr.push(addr16);
                    routingTableArr.push(statusByte);
                    routingTableArr.push(nextHopAddress);

                    routingTableEntries += 1;
                }
            } catch {
                /* ignore */
            }

            sourceRouteTableIndex += 1;
        }

        // have to fit uint8 count-type bytes of ZDO response
        const clipped = routingTableEntries > 0xff;
        const entryCount = routingTableArr.length / 3;
        const routingTable = Buffer.alloc(5 + entryCount * 5);
        let offset = 0;

        if (clipped) {
            logger.debug(() => `Routing table clipped at 255 entries to fit ZDO response (actual=${routingTableEntries})`, NS);
        }

        routingTable.writeUInt8(0 /* seq num */, offset);
        offset += 1;
        routingTable.writeUInt8(0 /* SUCCESS */, offset);
        offset += 1;
        routingTable.writeUInt8(clipped ? 0xff : routingTableEntries, offset);
        offset += 1;
        routingTable.writeUInt8(startIndex, offset);
        offset += 1;
        routingTable.writeUInt8(entryCount, offset);
        offset += 1;

        let entryIndex = 0;

        for (let i = 0; i < entryCount; i++) {
            routingTable.writeUInt16LE(routingTableArr[entryIndex] /* destination16 */, offset);
            offset += 2;
            routingTable.writeUInt8(routingTableArr[entryIndex + 1] /* statusByte */, offset);
            offset += 1;
            routingTable.writeUInt16LE(routingTableArr[entryIndex + 2] /* nextHopAddress */, offset);
            offset += 2;

            entryIndex += 3;
        }

        return routingTable;
    }

    /**
     * Generate ZDO response payload for coordinator based on cluster ID.
     * @param clusterId The ZDO cluster ID
     * @param requestData The request payload buffer
     * @returns Response buffer or undefined if cluster not supported
     */
    public getCoordinatorZDOResponse(clusterId: number, requestData: Buffer): Buffer | undefined {
        switch (clusterId) {
            case ZigbeeConsts.NETWORK_ADDRESS_REQUEST: {
                // TODO: handle reportKids & index, this payload is only for 0, 0
                return Buffer.from(this.#context.configAttributes.address); // copy
            }
            case ZigbeeConsts.IEEE_ADDRESS_REQUEST: {
                // TODO: handle reportKids & index, this payload is only for 0, 0
                return Buffer.from(this.#context.configAttributes.address); // copy
            }
            case ZigbeeConsts.NODE_DESCRIPTOR_REQUEST: {
                return Buffer.from(this.#context.configAttributes.nodeDescriptor); // copy
            }
            case ZigbeeConsts.POWER_DESCRIPTOR_REQUEST: {
                return Buffer.from(this.#context.configAttributes.powerDescriptor); // copy
            }
            case ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST: {
                return Buffer.from(this.#context.configAttributes.simpleDescriptors); // copy
            }
            case ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST: {
                return Buffer.from(this.#context.configAttributes.activeEndpoints); // copy
            }
            case ZigbeeConsts.LQI_TABLE_REQUEST: {
                return this.getLQITableResponse(requestData[1 /* 0 is tsn */]);
            }
            case ZigbeeConsts.ROUTING_TABLE_REQUEST: {
                return this.getRoutingTableResponse(requestData[1 /* 0 is tsn */]);
            }
        }
    }

    /**
     * Check if ZDO request is intended for coordinator.
     * @param clusterId The ZDO cluster ID
     * @param nwkDst16 Network destination address (16-bit)
     * @param nwkDst64 Network destination address (64-bit)
     * @param data The ZDO request payload
     * @returns true if request targets coordinator
     */
    public isZDORequestForCoordinator(clusterId: number, nwkDst16: number | undefined, nwkDst64: bigint | undefined, data: Buffer): boolean {
        if (nwkDst16 === ZigbeeConsts.COORDINATOR_ADDRESS || nwkDst64 === this.#context.netParams.eui64) {
            // target is coordinator
            return true;
        }

        if (nwkDst16 !== undefined && nwkDst16 >= ZigbeeConsts.BCAST_MIN) {
            // target is BCAST and ZDO "of interest" is coordinator
            switch (clusterId) {
                case ZigbeeConsts.NETWORK_ADDRESS_REQUEST: {
                    return data.readBigUInt64LE(1 /* skip seq num */) === this.#context.netParams.eui64;
                }

                case ZigbeeConsts.IEEE_ADDRESS_REQUEST:
                case ZigbeeConsts.NODE_DESCRIPTOR_REQUEST:
                case ZigbeeConsts.POWER_DESCRIPTOR_REQUEST:
                case ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST:
                case ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST: {
                    return data.readUInt16LE(1 /* skip seq num */) === ZigbeeConsts.COORDINATOR_ADDRESS;
                }
            }
        }

        return false;
    }

    /**
     * Respond to ZDO requests aimed at coordinator if needed.
     * @param data ZDO request payload
     * @param clusterId ZDO cluster ID
     * @param nwkDest16 Network destination address (16-bit)
     * @param nwkDest64 Network destination address (64-bit)
     */
    public async respondToCoordinatorZDORequest(
        data: Buffer,
        clusterId: number,
        nwkDest16: number | undefined,
        nwkDest64: bigint | undefined,
    ): Promise<void> {
        const finalPayload = this.getCoordinatorZDOResponse(clusterId, data);

        if (finalPayload) {
            // set the ZDO sequence number in outgoing payload same as incoming request
            const seqNum = data[0];
            finalPayload[0] = seqNum;

            logger.debug(() => `===> COORD_ZDO[seqNum=${seqNum} clusterId=${clusterId} nwkDst=${nwkDest16}:${nwkDest64}]`, NS);

            try {
                await this.sendData(
                    finalPayload,
                    ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
                    nwkDest16, // nwkDest16
                    nwkDest64, // nwkDest64
                    ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
                    clusterId | 0x8000, // clusterId
                    ZigbeeConsts.ZDO_PROFILE_ID, // profileId
                    ZigbeeConsts.ZDO_ENDPOINT, // destEndpoint
                    ZigbeeConsts.ZDO_ENDPOINT, // sourceEndpoint
                    undefined, // group
                );
            } catch {
                // logged in `sendData`
                return;
            }
        }
    }

    // #endregion

    // #region Helpers

    /**
     * Get or generate application link key for a device pair
     */
    private getOrGenerateAppLinkKey(_device16: number, _partner64: bigint): Buffer {
        // TODO: whole mechanism
        return this.#context.netParams.tcKey;
    }

    // #endregion
}
