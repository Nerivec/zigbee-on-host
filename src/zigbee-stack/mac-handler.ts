import { logger } from "../utils/logger.js";
import {
    decodeMACCapabilities,
    encodeMACFrame,
    encodeMACZigbeeBeacon,
    MACAssociationStatus,
    MACCommandId,
    MACFrameAddressMode,
    MACFrameType,
    MACFrameVersion,
    type MACHeader,
    ZigbeeMACConsts,
} from "../zigbee/mac.js";
import { ZigbeeConsts } from "../zigbee/zigbee.js";
import { ZigbeeNWKConsts } from "../zigbee/zigbee-nwk.js";
import type { StackCallbacks, StackContext } from "./stack-context.js";

const NS = "mac-handler";

/**
 * Callbacks from MAC handler to parent layer
 */
export interface MACHandlerCallbacks {
    onFrame: StackCallbacks["onMACFrame"];
    /** Called to send property to RCP via Spinel */
    onSendFrame: (payload: Buffer) => Promise<void>;
    /** Called to send APS transport key after successful association */
    onAPSSendTransportKeyNWK: (address16: number, key: Buffer, keySeqNum: number, destination64: bigint) => Promise<void>;
    /** Called to mark route as successful */
    onMarkRouteSuccess: (destination16: number) => void;
    /** Called to mark route as failed */
    onMarkRouteFailure: (destination16: number) => void;
}

/**
 * MAC Handler - IEEE 802.15.4 MAC Layer Protocol Operations
 *
 * Responsibilities:
 * - MAC frame transmission (direct and indirect)
 * - MAC command processing (ASSOC_REQ, ASSOC_RSP, BEACON_REQ, DATA_RQ)
 * - Association/reassociation handling
 * - Pending association management
 * - Indirect transmission queue management
 */
export class MACHandler {
    readonly #context: StackContext;
    readonly #callbacks: MACHandlerCallbacks;

    /** Emit frames flag (for debugging) */
    #emitFrames: boolean;
    /** Code used in Error `cause` when sending throws because of MAC "no ACK" */
    #noACKCode: number;

    // Private counters (start at 0, first call returns 1)
    #seqNum = 0;

    constructor(context: StackContext, callbacks: MACHandlerCallbacks, noACKCode: number, emitFrames = false) {
        this.#context = context;
        this.#callbacks = callbacks;

        this.#emitFrames = emitFrames;
        this.#noACKCode = noACKCode;
    }

    // #region Getters/Setters

    get emitFrames(): boolean {
        return this.#emitFrames;
    }

    // #endregion

    async start() {}

    stop() {}

    /**
     * Get next MAC sequence number.
     * HOT PATH: Optimized counter increment
     * @returns Incremented MAC sequence number (wraps at 255)
     */
    /* @__INLINE__ */
    public nextSeqNum(): number {
        this.#seqNum = (this.#seqNum + 1) & 0xff;

        return this.#seqNum;
    }

    /**
     * Send 802.15.4 MAC frame without checking for need to use indirect transmission.
     * @param seqNum MAC sequence number
     * @param payload MAC frame payload
     * @param dest16 Destination 16-bit address
     * @param dest64 Destination 64-bit address
     * @returns True if success sending
     */
    public async sendFrameDirect(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean> {
        if (dest16 === undefined && dest64 !== undefined) {
            dest16 = this.#context.getDevice(dest64)?.address16;
        }

        try {
            logger.debug(() => `===> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}]`, NS);

            await this.#callbacks.onSendFrame(payload);

            if (this.#emitFrames) {
                setImmediate(() => {
                    this.#callbacks.onFrame(payload);
                });
            }

            if (dest16 !== undefined) {
                this.#context.macNoACKs.delete(dest16);
                this.#callbacks.onMarkRouteSuccess(dest16);
            }

            return true;
        } catch (error) {
            logger.debug(() => `=x=> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}] ${(error as Error).message}`, NS);

            if ((error as Error).cause === this.#noACKCode && dest16 !== undefined) {
                this.#context.macNoACKs.set(dest16, (this.#context.macNoACKs.get(dest16) ?? 0) + 1);
                this.#callbacks.onMarkRouteFailure(dest16);
            }

            return false;
        }
    }

    /**
     * Send 802.15.4 MAC frame.
     * Checks if indirect transmission is needed for devices with rxOnWhenIdle=false.
     * @param seqNum MAC sequence number
     * @param payload MAC frame payload
     * @param dest16 Destination 16-bit address
     * @param dest64 Destination 64-bit address
     * @returns True if success sending, undefined if set for indirect transmission
     */
    public async sendFrame(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean | undefined> {
        if (dest16 !== undefined || dest64 !== undefined) {
            if (dest64 === undefined && dest16 !== undefined) {
                dest64 = this.#context.getAddress64(dest16);
            }

            if (dest64 !== undefined) {
                const addrTXs = this.#context.indirectTransmissions.get(dest64);

                if (addrTXs) {
                    addrTXs.push({
                        sendFrame: this.sendFrameDirect.bind(this, seqNum, payload, dest16, dest64),
                        timestamp: Date.now(),
                    });

                    logger.debug(
                        () => `=|=> MAC[seqNum=${seqNum} dst=${dest16}:${dest64}] set for indirect transmission (count=${addrTXs.length})`,
                        NS,
                    );

                    return; // done
                }
            }
        }

        // just send the packet when:
        // - RX on when idle
        // - can't determine radio state
        // - no dest info
        return await this.sendFrameDirect(seqNum, payload, dest16, dest64);
    }

    // #region Commands

    /**
     * Send 802.15.4 MAC command
     * @param cmdId MAC command ID
     * @param dest16 Destination 16-bit address
     * @param dest64 Destination 64-bit address
     * @param extSource Use extended source address
     * @param payload Command payload
     * @returns True if success sending
     */
    public async sendCommand(
        cmdId: MACCommandId,
        dest16: number | undefined,
        dest64: bigint | undefined,
        extSource: boolean,
        payload: Buffer,
    ): Promise<boolean> {
        const macSeqNum = this.nextSeqNum();

        logger.debug(() => `===> MAC CMD[seqNum=${macSeqNum} cmdId=${cmdId} dst=${dest16}:${dest64} extSrc=${extSource}]`, NS);

        const macFrame = encodeMACFrame(
            {
                frameControl: {
                    frameType: MACFrameType.CMD,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: dest16 !== ZigbeeMACConsts.BCAST_ADDR,
                    panIdCompression: true,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: dest64 !== undefined ? MACFrameAddressMode.EXT : MACFrameAddressMode.SHORT,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: extSource ? MACFrameAddressMode.EXT : MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macSeqNum,
                destinationPANId: this.#context.netParams.panId,
                destination16: dest16,
                destination64: dest64,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                source64: this.#context.netParams.eui64,
                commandId: cmdId,
                fcs: 0,
            },
            payload,
        );

        return await this.sendFrameDirect(macSeqNum, macFrame, dest16, dest64);
    }

    /**
     * Process 802.15.4 MAC command.
     * @param data Command data
     * @param macHeader MAC header
     */
    public async processCommand(data: Buffer, macHeader: MACHeader): Promise<void> {
        let offset = 0;

        switch (macHeader.commandId!) {
            case MACCommandId.ASSOC_REQ: {
                offset = await this.processAssocReq(data, offset, macHeader);
                break;
            }
            case MACCommandId.ASSOC_RSP: {
                offset = this.processAssocRsp(data, offset, macHeader);
                break;
            }
            case MACCommandId.BEACON_REQ: {
                offset = await this.processBeaconReq(data, offset, macHeader);
                break;
            }
            case MACCommandId.DATA_RQ: {
                offset = await this.processDataReq(data, offset, macHeader);
                break;
            }
            // TODO: other cases?
            // DISASSOC_NOTIFY
            // PANID_CONFLICT
            // ORPHAN_NOTIFY
            // COORD_REALIGN
            // GTS_REQ
            default: {
                logger.error(`<=x= MAC CMD[cmdId=${macHeader.commandId} macSrc=${macHeader.source16}:${macHeader.source64}] Unsupported`, NS);
                return;
            }
        }

        // excess data in packet
        // if (offset < data.byteLength) {
        //     logger.debug(() => `<=== MAC CMD contained more data: ${data.toString('hex')}`, NS);
        // }
    }

    /**
     * Process 802.15.4 MAC association request.
     *
     * SPEC COMPLIANCE NOTES (IEEE 802.15.4-2015 #6.3.1):
     * - ✅ Correctly extracts capabilities byte from payload
     * - ✅ Validates presence of source64 (mandatory per spec)
     * - ✅ Calls context associate to handle higher-layer processing
     * - ✅ Determines initial join vs rejoin by checking if device is known
     * - ✅ Stores pending association in map for DATA_REQ retrieval
     * - ✅ Pending association includes sendResp callback and timestamp
     * - ⚠️  SPEC COMPLIANCE: Association response is indirect transmission
     *       - Per IEEE 802.15.4 #6.3.2, response SHALL be sent via indirect transmission
     *       - Implementation stores in pendingAssociations for DATA_REQ ✅
     *       - Respects macResponseWaitTime via timestamp check ✅
     * - ⚠️  TIMING: Uses Date.now() for timestamp - should align with MAC_INDIRECT_TRANSMISSION_TIMEOUT
     * - ✅ Sends TRANSPORT_KEY_NWK after successful association (ZigBee-specific)
     * - ✅ Uses MAC capabilities to determine device type correctly
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @returns New offset after processing
     */
    public async processAssocReq(data: Buffer, offset: number, macHeader: MACHeader): Promise<number> {
        const capabilities = data.readUInt8(offset);
        offset += 1;

        logger.debug(() => `<=== MAC ASSOC_REQ[macSrc=${macHeader.source16}:${macHeader.source64} cap=${capabilities}]`, NS);

        if (macHeader.source64 === undefined) {
            logger.debug(() => `<=x= MAC ASSOC_REQ[macSrc=${macHeader.source16}:${macHeader.source64} cap=${capabilities}] Invalid source64`, NS);
        } else {
            const address16 = this.#context.getDevice(macHeader.source64)?.address16;
            const decodedCap = decodeMACCapabilities(capabilities);
            const [status, newAddress16] = await this.#context.associate(
                address16,
                macHeader.source64,
                address16 === undefined /* initial join if unknown device, else rejoin */,
                decodedCap,
                true /* neighbor */,
            );

            this.#context.pendingAssociations.set(macHeader.source64, {
                sendResp: async () => {
                    await this.sendAssocRsp(macHeader.source64!, newAddress16, status);

                    if (status === MACAssociationStatus.SUCCESS) {
                        await this.#callbacks.onAPSSendTransportKeyNWK(
                            newAddress16,
                            this.#context.netParams.networkKey,
                            this.#context.netParams.networkKeySequenceNumber,
                            macHeader.source64!,
                        );
                    }
                },
                timestamp: Date.now(),
            });
        }

        return offset;
    }

    /**
     * Process 802.15.4 MAC association response.
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @returns New offset after processing
     */
    public processAssocRsp(data: Buffer, offset: number, macHeader: MACHeader): number {
        const address = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;

        logger.debug(
            () => `<=== MAC ASSOC_RSP[macSrc=${macHeader.source16}:${macHeader.source64} addr16=${address} status=${MACAssociationStatus[status]}]`,
            NS,
        );

        return offset;
    }

    /**
     * Send 802.15.4 MAC association response
     * @param dest64 Destination IEEE address
     * @param newAddress16 Assigned network address
     * @param status Association status
     * @returns True if success sending
     */
    public async sendAssocRsp(dest64: bigint, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean> {
        logger.debug(() => `===> MAC ASSOC_RSP[dst64=${dest64} newAddr16=${newAddress16} status=${status}]`, NS);

        const finalPayload = Buffer.alloc(3);
        let offset = 0;
        finalPayload.writeUInt16LE(newAddress16, offset);
        offset += 2;
        finalPayload.writeUInt8(status, offset);
        offset += 1;

        return await this.sendCommand(
            MACCommandId.ASSOC_RSP,
            undefined, // dest16
            dest64, // dest64
            true, // sourceExt
            finalPayload,
        );
    }

    /**
     * Process 802.15.4 MAC beacon request.
     *
     * SPEC COMPLIANCE NOTES (IEEE 802.15.4-2015 #5.3.3):
     * - ✅ Responds with BEACON frame as required
     * - ✅ Uses frameType=BEACON correctly
     * - ✅ Sets securityEnabled=false (beacons typically unsecured)
     * - ✅ Sets framePending=false (beacons never have pending data)
     * - ✅ Sets ackRequest=false per spec (beacons are not acknowledged)
     * - ✅ Sets panIdCompression=false (source PAN ID must be present)
     * - ✅ Uses destAddrMode=NONE (beacons have no destination)
     * - ✅ Uses sourceAddrMode=SHORT with coordinator address
     * - ⚠️  SUPERFRAME SPEC VALUES:
     *       - beaconOrder=0x0f: Non-beacon enabled PAN ✅ (correct for ZigBee PRO)
     *       - superframeOrder=0x0f: Matches beaconOrder ✅
     *       - finalCAPSlot=0x0f: Comment says "XXX: value from sniff, matches above"
     *         * Should be calculated based on GTS allocation per spec
     *         * Value 0x0f means no GTS, which is typical for ZigBee ✅
     * - ✅ Sets batteryExtension=false (coordinator is mains powered)
     * - ✅ Sets panCoordinator=true (this is the coordinator)
     * - ✅ Uses associationPermit flag from context
     * - ✅ Sets gtsInfo.permit=false (no GTS support - typical for ZigBee)
     * - ✅ Empty pendAddr (no pending address fields)
     * - ✅ ZigBee Beacon Payload:
     *       - protocolId=ZIGBEE_BEACON_PROTOCOL_ID (0x00) ✅
     *       - profile=0x2 (ZigBee PRO) ✅
     *       - version=VERSION_2007 ✅
     *       - routerCapacity=true ✅
     *       - deviceDepth=0 (coordinator) ✅
     *       - endDeviceCapacity=true ✅
     *       - extendedPANId matches context ✅
     *       - txOffset=0xffffff: Comment says "XXX: value from sniffed frames"
     *         * This is acceptable - indicates no time sync ✅
     *       - updateId from context ✅
     *
     * @param _data Command data (unused)
     * @param offset Current offset in data
     * @param _macHeader MAC header (unused)
     * @returns New offset after processing
     */
    public async processBeaconReq(_data: Buffer, offset: number, _macHeader: MACHeader): Promise<number> {
        logger.debug(() => "<=== MAC BEACON_REQ[]", NS);

        const macSeqNum = this.nextSeqNum();
        const macFrame = encodeMACFrame(
            {
                frameControl: {
                    frameType: MACFrameType.BEACON,
                    securityEnabled: false,
                    framePending: false,
                    ackRequest: false,
                    panIdCompression: false,
                    seqNumSuppress: false,
                    iePresent: false,
                    destAddrMode: MACFrameAddressMode.NONE,
                    frameVersion: MACFrameVersion.V2003,
                    sourceAddrMode: MACFrameAddressMode.SHORT,
                },
                sequenceNumber: macSeqNum,
                sourcePANId: this.#context.netParams.panId,
                source16: ZigbeeConsts.COORDINATOR_ADDRESS,
                superframeSpec: {
                    beaconOrder: 0x0f, // value from spec
                    superframeOrder: 0x0f, // value from spec
                    finalCAPSlot: 0x0f,
                    batteryExtension: false,
                    panCoordinator: true,
                    associationPermit: this.#context.associationPermit,
                },
                gtsInfo: { permit: false },
                pendAddr: {},
                fcs: 0,
            },
            encodeMACZigbeeBeacon({
                protocolId: ZigbeeMACConsts.ZIGBEE_BEACON_PROTOCOL_ID,
                profile: 0x2, // ZigBee PRO
                version: ZigbeeNWKConsts.VERSION_2007,
                routerCapacity: true,
                deviceDepth: 0, // coordinator
                endDeviceCapacity: true,
                extendedPANId: this.#context.netParams.extendedPanId,
                txOffset: 0xffffff, // XXX: value from sniffed frames
                updateId: this.#context.netParams.nwkUpdateId,
            }),
        );

        logger.debug(() => `===> MAC BEACON[seqNum=${macSeqNum}]`, NS);

        await this.sendFrame(macSeqNum, macFrame, undefined, undefined);

        return offset;
    }

    /**
     * Process 802.15.4 MAC data request.
     * Used by indirect transmission devices to retrieve information from parent.
     *
     * SPEC COMPLIANCE NOTES (IEEE 802.15.4-2015 #6.3.4):
     * - ✅ Handles both source64 and source16 addressing
     * - ✅ Checks pending associations first (higher priority)
     * - ✅ Validates timestamp against MAC_INDIRECT_TRANSMISSION_TIMEOUT
     * - ✅ Deletes pending association after processing (prevents stale entries)
     * - ✅ Handles indirect transmissions from indirectTransmissions map
     * - ✅ Uses shift() to get FIFO ordering (oldest frame first)
     * - ⚠️  SPEC COMPLIANCE: Timestamp validation
     *       - Checks (timestamp + timeout > Date.now()) ✅
     *       - Correctly expires old transmissions ✅
     *       - Iterates through queue to find non-expired frame ✅
     * - ⚠️  POTENTIAL ISSUE: No limit on queue length
     *       - Could accumulate many expired frames before cleanup
     *       - Should consider periodic cleanup or max queue size
     * - ✅ Calls sendFrame() which will send with appropriate MAC params
     * - ✅ No ACK for DATA_RQ itself (command will be ACKed at MAC layer if requested)
     *
     * Per spec #6.3.4: "Upon receipt of data request, coordinator checks if data pending.
     * If yes, sends frame. If no, sends ACK with framePending=false"
     * This is handled correctly by the indirect transmission mechanism.
     *
     * @param _data Command data (unused)
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @returns New offset after processing
     */
    public async processDataReq(_data: Buffer, offset: number, macHeader: MACHeader): Promise<number> {
        logger.debug(() => `<=== MAC DATA_RQ[macSrc=${macHeader.source16}:${macHeader.source64}]`, NS);

        let address64 = macHeader.source64;

        if (address64 === undefined && macHeader.source16 !== undefined) {
            address64 = this.#context.getAddress64(macHeader.source16);
        }

        if (address64 !== undefined) {
            const pendingAssoc = this.#context.pendingAssociations.get(address64);

            if (pendingAssoc) {
                if (pendingAssoc.timestamp + ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT > Date.now()) {
                    await pendingAssoc.sendResp();
                }

                // always delete, ensures no stale
                this.#context.pendingAssociations.delete(address64);
            } else {
                const addrTXs = this.#context.indirectTransmissions.get(address64);

                if (addrTXs !== undefined) {
                    let tx = addrTXs.shift();

                    // deal with expired tx by looking for first that isn't
                    do {
                        if (tx !== undefined && tx.timestamp + ZigbeeConsts.MAC_INDIRECT_TRANSMISSION_TIMEOUT > Date.now()) {
                            await tx.sendFrame();
                            break;
                        }

                        tx = addrTXs.shift();
                    } while (tx !== undefined);
                }
            }
        }

        return offset;
    }

    // #endregion
}
