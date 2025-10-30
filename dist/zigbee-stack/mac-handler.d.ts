import { MACAssociationStatus, MACCommandId, type MACHeader } from "../zigbee/mac.js";
import type { StackCallbacks, StackContext } from "./stack-context.js";
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
export declare class MACHandler {
    #private;
    constructor(context: StackContext, callbacks: MACHandlerCallbacks, noACKCode: number, emitFrames?: boolean);
    get emitFrames(): boolean;
    start(): Promise<void>;
    stop(): void;
    /**
     * Get next MAC sequence number.
     * HOT PATH: Optimized counter increment
     * @returns Incremented MAC sequence number (wraps at 255)
     */
    nextSeqNum(): number;
    /**
     * Send 802.15.4 MAC frame without checking for need to use indirect transmission.
     * @param seqNum MAC sequence number
     * @param payload MAC frame payload
     * @param dest16 Destination 16-bit address
     * @param dest64 Destination 64-bit address
     * @returns True if success sending
     */
    sendFrameDirect(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean>;
    /**
     * Send 802.15.4 MAC frame.
     * Checks if indirect transmission is needed for devices with rxOnWhenIdle=false.
     * @param seqNum MAC sequence number
     * @param payload MAC frame payload
     * @param dest16 Destination 16-bit address
     * @param dest64 Destination 64-bit address
     * @returns True if success sending, undefined if set for indirect transmission
     */
    sendFrame(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean | undefined>;
    /**
     * Send 802.15.4 MAC command
     * @param cmdId MAC command ID
     * @param dest16 Destination 16-bit address
     * @param dest64 Destination 64-bit address
     * @param extSource Use extended source address
     * @param payload Command payload
     * @returns True if success sending
     */
    sendCommand(cmdId: MACCommandId, dest16: number | undefined, dest64: bigint | undefined, extSource: boolean, payload: Buffer): Promise<boolean>;
    /**
     * Process 802.15.4 MAC command.
     * @param data Command data
     * @param macHeader MAC header
     */
    processCommand(data: Buffer, macHeader: MACHeader): Promise<void>;
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
     * - ✅ Sends TRANSPORT_KEY_NWK after successful association (Zigbee-specific)
     * - ✅ Uses MAC capabilities to determine device type correctly
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @returns New offset after processing
     */
    processAssocReq(data: Buffer, offset: number, macHeader: MACHeader): Promise<number>;
    /**
     * Process 802.15.4 MAC association response.
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @returns New offset after processing
     */
    processAssocRsp(data: Buffer, offset: number, macHeader: MACHeader): number;
    /**
     * Send 802.15.4 MAC association response
     * @param dest64 Destination IEEE address
     * @param newAddress16 Assigned network address
     * @param status Association status
     * @returns True if success sending
     */
    sendAssocRsp(dest64: bigint, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean>;
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
     *       - beaconOrder=0x0f: Non-beacon enabled PAN ✅ (correct for Zigbee PRO)
     *       - superframeOrder=0x0f: Matches beaconOrder ✅
     *       - finalCAPSlot=0x0f: Comment says "XXX: value from sniff, matches above"
     *         * Should be calculated based on GTS allocation per spec
     *         * Value 0x0f means no GTS, which is typical for Zigbee ✅
     * - ✅ Sets batteryExtension=false (coordinator is mains powered)
     * - ✅ Sets panCoordinator=true (this is the coordinator)
     * - ✅ Uses associationPermit flag from context
     * - ✅ Sets gtsInfo.permit=false (no GTS support - typical for Zigbee)
     * - ✅ Empty pendAddr (no pending address fields)
     * - ✅ Zigbee Beacon Payload:
     *       - protocolId=ZIGBEE_BEACON_PROTOCOL_ID (0x00) ✅
     *       - profile=0x2 (Zigbee PRO) ✅
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
    processBeaconReq(_data: Buffer, offset: number, _macHeader: MACHeader): Promise<number>;
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
    processDataReq(_data: Buffer, offset: number, macHeader: MACHeader): Promise<number>;
}
