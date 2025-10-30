import { type MACHeader } from "../zigbee/mac.js";
import { type ZigbeeSecurityHeader } from "../zigbee/zigbee.js";
import { ZigbeeAPSCommandId, ZigbeeAPSDeliveryMode, type ZigbeeAPSHeader } from "../zigbee/zigbee-aps.js";
import { type ZigbeeNWKHeader, ZigbeeNWKRouteDiscovery } from "../zigbee/zigbee-nwk.js";
import type { MACHandler } from "./mac-handler.js";
import type { NWKHandler } from "./nwk-handler.js";
import { type StackCallbacks, type StackContext } from "./stack-context.js";
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
 * APS Handler - Zigbee Application Support Layer Operations
 */
export declare class APSHandler {
    #private;
    constructor(context: StackContext, macHandler: MACHandler, nwkHandler: NWKHandler, callbacks: APSHandlerCallbacks);
    start(): Promise<void>;
    stop(): void;
    /**
     * Get next APS counter.
     * HOT PATH: Optimized counter increment
     * @returns Incremented APS counter (wraps at 255)
     */
    nextCounter(): number;
    /**
     * Get next ZDO sequence number.
     * HOT PATH: Optimized counter increment
     * @returns Incremented ZDO sequence number (wraps at 255)
     */
    nextZDOSeqNum(): number;
    /**
     * Send a Zigbee APS DATA frame.
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
    sendData(finalPayload: Buffer, nwkDiscoverRoute: ZigbeeNWKRouteDiscovery, nwkDest16: number | undefined, nwkDest64: bigint | undefined, apsDeliveryMode: ZigbeeAPSDeliveryMode, clusterId: number, profileId: number, destEndpoint: number | undefined, sourceEndpoint: number | undefined, group: number | undefined): Promise<number>;
    sendACK(macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void>;
    onZigbeeAPSFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader, lqa: number): Promise<void>;
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
    sendCommand(cmdId: ZigbeeAPSCommandId, finalPayload: Buffer, nwkDiscoverRoute: ZigbeeNWKRouteDiscovery, nwkSecurity: boolean, nwkDest16: number | undefined, nwkDest64: bigint | undefined, apsDeliveryMode: ZigbeeAPSDeliveryMode.UNICAST | ZigbeeAPSDeliveryMode.BCAST, apsSecurityHeader: ZigbeeSecurityHeader | undefined, disableACKRequest?: boolean): Promise<boolean>;
    processCommand(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void>;
    /**
     * 05-3474-R #4.4.11.1
     */
    processTransportKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
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
    sendTransportKeyTC(nwkDest16: number, key: Buffer, destination64: bigint): Promise<boolean>;
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
    sendTransportKeyNWK(nwkDest16: number, key: Buffer, seqNum: number, destination64: bigint): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.1 #4.4.11.1.3.3
     *
     * @param nwkDest16
     * @param key SHALL contain a link key that is shared with the device identified in the partner address sub-field
     * @param partner SHALL contain the address of the other device that was sent this link key
     * @param initiatorFlag SHALL be set to 1 if the device receiving this packet requested this key. Otherwise, this sub-field SHALL be set to 0.
     * @returns
     */
    sendTransportKeyAPP(nwkDest16: number, key: Buffer, partner: bigint, initiatorFlag: boolean): Promise<boolean>;
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
    processUpdateDevice(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): Promise<number>;
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
    sendUpdateDevice(nwkDest16: number, device64: bigint, device16: number, status: number): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes target IEEE address (childInfo)
     * - ✅ Validates source and logs removal
     * - ❌ NOT IMPLEMENTED: Actual device removal (only logs)
     * - ❌ MISSING: Should initiate LEAVE sequence to target device
     * - ❌ MISSING: Should notify parent to remove child
     * - ❌ MISSING: Parent router role handling
     *
     * IMPLEMENTATION GAP: Coordinator receives command but doesn't act on it.
     * Parent routers should send LEAVE to child and UPDATE_DEVICE(status 0x02) to TC.
     */
    processRemoveDevice(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * 05-3474-R #4.4.11.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Includes target IEEE address
     * - ✅ Applies NWK + APS LOAD encryption
     * - ✅ Unicast to parent router
     *
     * NOTE: Trust Center sends this to parent router, which should then remove child
     *
     * @param nwkDest16 parent
     * @param target64
     * @returns
     */
    sendRemoveDevice(nwkDest16: number, target64: bigint): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.4 #4.4.5.2.3
     */
    processRequestKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<number>;
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
    sendRequestKey(nwkDest16: number, keyType: 0x02, partner64: bigint): Promise<boolean>;
    sendRequestKey(nwkDest16: number, keyType: 0x04): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.5
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes sequence number
     * - ❌ NOT IMPLEMENTED: Actual key switching logic (CRITICAL)
     * - ❌ NOT IMPLEMENTED: Frame counter reset after key switch
     * - ❌ NOT IMPLEMENTED: Activation of new network key
     *
     * IMPACT: Network key rotation is non-functional - security risk for long-term deployments
     */
    processSwitchKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * 05-3474-R #4.4.11.5
     *
     * SPEC COMPLIANCE:
     * - ✅ Includes sequence number identifying network key
     * - ✅ Broadcast or unicast delivery
     * - ✅ Applies NWK security only (not APS)
     * - ❌ NOT IMPLEMENTED: Integration with actual key switching mechanism
     *
     * @param nwkDest16
     * @param seqNum SHALL contain the sequence number identifying the network key to be made active.
     * @returns
     */
    sendSwitchKey(nwkDest16: number, seqNum: number): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.6
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes destination address
     * - ✅ Extracts tunneled APS command frame
     * - ✅ Validates structure
     * - ❌ NOT IMPLEMENTED: Tunnel forwarding (only logs)
     * - ❌ MISSING: Should extract and forward tunneled command to destination
     * - ❌ MISSING: Security context validation
     *
     * IMPLEMENTATION: TC sends TUNNEL for nested joins (works), but coordinator
     * can't relay tunneled frames from routers (incomplete).
     */
    processTunnel(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * 05-3474-R #4.4.11.6
     *
     * SPEC COMPLIANCE:
     * - ✅ Includes destination64
     * - ✅ Encapsulates APS command frame
     * - ✅ Applies APS TRANSPORT encryption
     * - ✅ NO ACK request (per spec exception - TUNNEL is the only APS command without ACK)
     * - ✅ Used correctly for nested device joins (TRANSPORT_KEY delivery through routers)
     *
     * @param nwkDest16
     * @param destination64 SHALL be the 64-bit extended address of the device that is to receive the tunneled command
     * @param tApsCmdFrame SHALL be the APS command payload to be sent to the destination
     * @returns
     */
    sendTunnel(nwkDest16: number, destination64: bigint, tApsCmdFrame: Buffer): Promise<boolean>;
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
    processVerifyKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): Promise<number>;
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
    sendVerifyKey(nwkDest16: number, keyType: number, source64: bigint, hash: Buffer): Promise<boolean>;
    /**
     * 05-3474-R #4.4.11.8
     */
    processConfirmKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
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
    sendConfirmKey(nwkDest16: number, status: number, keyType: number, destination64: bigint): Promise<boolean>;
    /**
     * R23 FEATURE - 05-3474-R #4.4.11.9
     *
     * SPEC COMPLIANCE:
     * - ⚠️ R23 feature with minimal implementation
     * - ✅ Structure parsing exists (destination64)
     * - ❌ NOT IMPLEMENTED: Message relaying functionality
     * - ❌ NOT IMPLEMENTED: TLV processing
     * - ❌ NOT IMPLEMENTED: Fragment handling
     *
     * USE CASES: ZVD (Zigbee Virtual Devices), Zigbee Direct - NOT SUPPORTED
     *
     * NOTE: Non-critical for Zigbee 3.0 PRO networks
     */
    processRelayMessageDownstream(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * R23 FEATURE - 05-3474-R #4.4.11.10
     *
     * SPEC COMPLIANCE:
     * - ⚠️ R23 feature with minimal implementation
     * - ✅ Structure parsing exists (source64)
     * - ❌ NOT IMPLEMENTED: Message relaying functionality
     * - ❌ NOT IMPLEMENTED: TLV processing
     * - ❌ NOT IMPLEMENTED: Fragment handling
     *
     * USE CASES: ZVD (Zigbee Virtual Devices), Zigbee Direct - NOT SUPPORTED
     *
     * NOTE: Non-critical for Zigbee 3.0 PRO networks
     */
    processRelayMessageUpstream(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number;
    /**
     * Generate LQI (Link Quality Indicator) table response for coordinator.
     * ZDO response to LQI_TABLE_REQUEST.
     * @see 05-3474-23 #2.4.4.2.3
     * @param startIndex The index to start the table entries from
     * @returns Buffer containing the LQI table response
     */
    getLQITableResponse(startIndex: number): Buffer;
    /**
     * Generate routing table response for coordinator.
     * ZDO response to ROUTING_TABLE_REQUEST.
     * NOTE: Only outputs the best source route for each entry in the table (clipped to max 255 entries).
     * @see 05-3474-23 #2.4.4.3.3
     * @param startIndex The index to start the table entries from
     * @returns Buffer containing the routing table response
     */
    getRoutingTableResponse(startIndex: number): Buffer;
    /**
     * Generate ZDO response payload for coordinator based on cluster ID.
     * @param clusterId The ZDO cluster ID
     * @param requestData The request payload buffer
     * @returns Response buffer or undefined if cluster not supported
     */
    getCoordinatorZDOResponse(clusterId: number, requestData: Buffer): Buffer | undefined;
    /**
     * Check if ZDO request is intended for coordinator.
     * @param clusterId The ZDO cluster ID
     * @param nwkDst16 Network destination address (16-bit)
     * @param nwkDst64 Network destination address (64-bit)
     * @param data The ZDO request payload
     * @returns true if request targets coordinator
     */
    isZDORequestForCoordinator(clusterId: number, nwkDst16: number | undefined, nwkDst64: bigint | undefined, data: Buffer): boolean;
    /**
     * Respond to ZDO requests aimed at coordinator if needed.
     * @param data ZDO request payload
     * @param clusterId ZDO cluster ID
     * @param nwkDest16 Network destination address (16-bit)
     * @param nwkDest64 Network destination address (64-bit)
     */
    respondToCoordinatorZDORequest(data: Buffer, clusterId: number, nwkDest16: number | undefined, nwkDest64: bigint | undefined): Promise<void>;
    /**
     * Get or generate application link key for a device pair
     */
    private getOrGenerateAppLinkKey;
}
