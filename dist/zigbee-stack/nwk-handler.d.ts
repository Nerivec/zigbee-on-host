import { MACAssociationStatus, type MACCapabilities, type MACHeader } from "../zigbee/mac.js";
import { ZigbeeNWKCommandId, type ZigbeeNWKHeader, type ZigbeeNWKLinkStatus, ZigbeeNWKManyToOne, ZigbeeNWKStatus } from "../zigbee/zigbee-nwk.js";
import type { MACHandler } from "../zigbee-stack/mac-handler.js";
import type { SourceRouteTableEntry, StackCallbacks, StackContext } from "../zigbee-stack/stack-context.js";
/**
 * Callbacks for NWK handler to communicate with driver
 */
export interface NWKHandlerCallbacks {
    onDeviceRejoined: StackCallbacks["onDeviceRejoined"];
    /** Send APS TRANSPORT_KEY for network key */
    onAPSSendTransportKeyNWK: (destination16: number, networkKey: Buffer, keySequenceNumber: number, destination64: bigint) => Promise<void>;
}
/**
 * NWK Handler - Zigbee Network Layer Operations
 *
 * Handles all Zigbee NWK (Network) layer operations including:
 * - NWK command transmission and processing
 * - Route discovery and management
 * - Source routing
 * - Link status
 * - Leave and rejoin operations
 * - Network commissioning
 */
export declare class NWKHandler {
    #private;
    constructor(context: StackContext, macHandler: MACHandler, callbacks: NWKHandlerCallbacks);
    start(): Promise<void>;
    stop(): void;
    /**
     * Get next NWK sequence number.
     * HOT PATH: Optimized counter increment
     * @returns Incremented NWK sequence number (wraps at 255)
     */
    nextSeqNum(): number;
    /**
     * Get next route request ID.
     * HOT PATH: Optimized counter increment
     * @returns Incremented route request ID (wraps at 255)
     */
    nextRouteRequestId(): number;
    sendPeriodicZigbeeNWKLinkStatus(): Promise<void>;
    sendPeriodicManyToOneRouteRequest(): Promise<void>;
    /**
     * Finds the best source route to the destination.
     * Implements route aging, failure tracking, and intelligent route selection.
     * Entries with expired routes or too many failures will be purged.
     * Bails early if destination16 is broadcast.
     * Throws if both 16/64 are undefined or if destination is unknown (not in device table).
     * Throws if no route and device is not neighbor.
     *
     * SPEC COMPLIANCE NOTES (05-3474-23 #3.6.3):
     * - ✅ Returns early for broadcast addresses (no routing needed)
     * - ✅ Validates destination is known in device table
     * - ✅ Returns undefined arrays for direct communication (neighbor devices)
     * - ⚠️  ROUTE AGING: Implements custom aging mechanism
     *       - CONFIG_NWK_ROUTE_EXPIRY_TIME: 300000ms (5 minutes)
     *       - CONFIG_NWK_ROUTE_STALENESS_TIME: 120000ms (2 minutes)
     *       - These values are implementation-specific, not from spec
     * - ✅ Route failure tracking with blacklisting:
     *       - CONFIG_NWK_ROUTE_MAX_FAILURES: 3 consecutive failures
     *       - Marks routes as unusable after threshold ✅
     * - ⚠️  MULTI-CRITERIA ROUTE SELECTION:
     *       - Path cost (hop count) ✅
     *       - Staleness penalty (route age) ✅
     *       - Failure penalty (consecutive failures) ✅
     *       - Recency bonus (recently used routes) ✅
     *       - This is more sophisticated than spec requires
     * - ✅ Checks MAC NO_ACK tracking for relay validation
     *       - Filters out routes with unreliable relays ✅
     * - ✅ Triggers many-to-one route request when no valid routes
     *       - Uses setImmediate for non-blocking trigger ✅
     * - ⚠️  SPEC DEVIATION: Route table per spec should be:
     *       - Destination address
     *       - Status (active, discovery underway, validation underway, inactive)
     *       - Next hop address
     *       - Source route subframe (if source routing)
     *       Current implementation uses array of SourceRouteTableEntry per destination
     *       This allows multiple routes per destination (more flexible)
     * - ⚠️  ROUTE DISCOVERY: Triggers MTORR when needed
     *       - Spec #3.6.3.5: Route discovery should be used
     *       - Implementation uses many-to-one routing (concentrator) ✅
     *       - This is appropriate for coordinator as concentrator
     *
     * IMPORTANT: This is a critical performance path - called for every outgoing frame
     *
     * @param destination16
     * @param destination64
     * @returns
     * - request invalid (e.g. broadcast destination): [undefined, undefined, undefined]
     * - request valid and source route unavailable (unknown device or neighbor): [undefined, undefined, undefined]
     * - request valid and source route available and >=1 relay: [last index in relayAddresses, list of relay addresses, cost of the path]
     * - request valid and source route available and 0 relay: [undefined, undefined, cost of the path]
     */
    findBestSourceRoute(destination16: number | undefined, destination64: bigint | undefined): [relayIndex: number | undefined, relayAddresses: number[] | undefined, pathCost: number | undefined];
    /**
     * Mark a route as successfully used
     * @param destination16 Network address of the destination
     */
    markRouteSuccess(destination16: number): void;
    /**
     * Mark a route as failed and handle route repair if needed.
     * Consolidates failure tracking and MTORR triggering per Zigbee spec.
     *
     * @param destination16 Network address of the destination
     * @param triggerRepair If true, will purge routes using this destination as relay and trigger MTORR
     */
    markRouteFailure(destination16: number, triggerRepair?: boolean): void;
    /**
     * Create a new source route table entry
     */
    createSourceRouteEntry(relayAddresses: number[], pathCost: number): SourceRouteTableEntry;
    /**
     * Check if a source route already exists in the table
     */
    hasSourceRoute(address16: number, newEntry: SourceRouteTableEntry, existingEntries?: SourceRouteTableEntry[]): boolean;
    /**
     * @param cmdId
     * @param finalPayload expected to contain the full payload (including cmdId)
     * @param macDest16
     * @param nwkSource16
     * @param nwkDest16
     * @param nwkDest64
     * @param nwkRadius
     * @returns True if success sending (or indirect transmission)
     */
    sendCommand(cmdId: ZigbeeNWKCommandId, finalPayload: Buffer, nwkSecurity: boolean, nwkSource16: number, nwkDest16: number, nwkDest64: bigint | undefined, nwkRadius: number): Promise<boolean>;
    processCommand(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<void>;
    /**
     * 05-3474-R #3.4.1
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly decodes options, id, destination16, pathCost
     * - ✅ Extracts manyToOne flag from options byte
     * - ✅ Conditionally parses destination64 based on DEST_EXT flag
     * - ✅ Only sends ROUTE_REPLY if destination is unicast (< BCAST_MIN)
     * - ⚠️  SPEC BEHAVIOR: Coordinator always replies to route requests
     *       - This is correct for concentrator behavior ✅
     *       - Spec #3.6.3.5.2: concentrator SHALL issue ROUTE_REPLY
     * - ✅ Uses correct parameters for sendRouteReply:
     *       - requestDest1stHop16: first hop back to originator (macHeader.destination16)
     *       - requestRadius: from nwkHeader (for TTL management)
     *       - requestId: route request ID for correlation
     *       - originator16/64: source of ROUTE_REQ
     *       - responder16/64: this coordinator (destination of ROUTE_REQ)
     * - ⚠️  MISSING: No handling of pathCost accumulation
     *       - Spec requires incrementing pathCost at each hop
     *       - Coordinator doesn't forward ROUTE_REQ so this is acceptable
     * - ⚠️  MISSING: No route discovery table management
     *       - Spec requires tracking recent ROUTE_REQs to avoid loops
     *       - Since coordinator doesn't forward, this is less critical
     * - ❌ POTENTIAL ISSUE: No validation of source route if present
     *       - ROUTE_REQ may contain source route information
     *       - Should validate/store this information
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processRouteReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-R #3.4.1
     *
     * @param manyToOne
     * @param destination16 intended destination of the route request command frame
     * @param destination64 SHOULD always be added if it is known
     * @returns
     */
    sendRouteReq(manyToOne: ZigbeeNWKManyToOne, destination16: number, destination64?: bigint): Promise<boolean>;
    /**
     * 05-3474-R #3.4.2
     */
    processRouteReply(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.2, #3.6.4.5.2
     *
     * @param requestDest1stHop16 SHALL be set to the network address of the first hop in the path back to the originator of the corresponding route request command frame
     * @param requestRadius
     * @param requestId 8-bit sequence number of the route request to which this frame is a reply
     * @param originator16 SHALL contain the 16-bit network address of the originator of the route request command frame to which this frame is a reply
     * @param responder16 SHALL always be the same as the value in the destination address field of the corresponding route request command frame
     * @param originator64 SHALL be 8 octets in length and SHALL contain the 64-bit address of the originator of the route request command frame to which this frame is a reply.
     * This field SHALL only be present if the originator IEEE address sub-field of the command options field has a value of 1.
     * @param responder64 SHALL be 8 octets in length and SHALL contain the 64-bit address of the destination of the route request command frame to which this frame is a reply.
     * This field SHALL only be present if the responder IEEE address sub-field of the command options field has a value of 1.
     * @returns
     */
    sendRouteReply(requestDest1stHop16: number, requestRadius: number, requestId: number, originator16: number, responder16: number, originator64?: bigint, responder64?: bigint): Promise<boolean>;
    /**
     * 05-3474-R #3.4.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes status code
     * - ✅ Handles destination16 parameter for routing failures
     * - ✅ Marks route as failed and triggers MTORR
     * - ✅ Logs network status issues
     * - ⚠️ INCOMPLETE: Route repair not fully implemented (marked as WIP)
     * - ❌ NOT IMPLEMENTED: TLV processing (R23)
     * - ❌ NOT IMPLEMENTED: Network address update notification
     *
     * IMPACT: Receives status but minimal action beyond route marking
     */
    processStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Sends to appropriate destination (broadcast or unicast)
     * - ✅ Includes error codes (NO_ROUTE_AVAILABLE, LINK_FAILURE, etc.)
     * - ✅ No security applied (per spec)
     * - ✅ Optional destination16 for routing failures/address conflicts
     *
     * @param requestSource16
     * @param status
     * @param destination Destination address (only if status is LINK_FAILURE or ADDRESS_CONFLICT)
     * - in case of a routing failure, it SHALL contain the destination address from the data frame that encountered the failure
     * - in case of an address conflict, it SHALL contain the offending network address.
     * @returns
     */
    sendStatus(requestSource16: number, status: ZigbeeNWKStatus, destination?: number): Promise<boolean>;
    /**
     * 05-3474-R #3.4.4
     */
    processLeave(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-R #3.4.3
     *
     * NOTE: `request` option always true
     * NOTE: `removeChildren` option should not be used (mesh disruption)
     *
     * @param destination16
     * @param rejoin if true, the device that is leaving from its current parent will rejoin the network
     * @returns
     */
    sendLeave(destination16: number, rejoin: boolean): Promise<boolean>;
    /**
     * 05-3474-R #3.4.5
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly decodes relayCount and relay addresses
     * - ✅ Stores source route in sourceRouteTable
     * - ✅ Creates source route entry with relays and path cost (relayCount + 1)
     * - ✅ Handles missing source16 by looking up via source64
     * - ✅ Checks for duplicate routes before adding (hasSourceRoute)
     * - ⚠️  SPEC BEHAVIOR: ROUTE_RECORD provides path from source to coordinator
     *       - Relay list is in order from source toward coordinator ✅
     *       - Path cost calculation (relayCount + 1) is correct ✅
     * - ✅ Validates source16 is defined before adding to table
     * - ⚠️  ROUTE RECORD vs ROUTE REPLY difference:
     *       - ROUTE_RECORD: Unsolicited path advertisement (many-to-one routing)
     *       - ROUTE_REPLY: Response to ROUTE_REQUEST
     *       - Implementation handles both correctly
     * - ⚠️  MISSING: No timestamp on route record
     *       - Routes should have freshness indicator
     *       - Fixed by using createSourceRouteEntry which adds lastUpdated ✅
     * - ✅ Stores relay addresses in correct order for source routing
     *
     * IMPORTANT: Route records are sent by devices to establish reverse path to concentrator
     * This is correct for coordinator acting as concentrator.
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processRouteRecord(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.6
     * Optional
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly decodes capabilities byte
     * - ✅ Determines rejoin type based on frameControl.security:
     *       - security=false: Trust Center Rejoin (unsecured)
     *       - security=true: NWK rejoin (secured with NWK key)
     * - ⚠️  TRUST CENTER REJOIN HANDLING:
     *       - Checks if device is known and authorized ✅
     *       - Denies rejoin if device unknown or unauthorized ✅
     *       - SPEC WARNING in comment about unsecured packets from neighbors
     *         "Unsecured Packets at the network layer claiming to be from existing neighbors...
     *          must not rewrite legitimate data in nwkNeighborTable"
     *         This is a critical security requirement ✅
     * - ⚠️  SPEC COMPLIANCE: apsTrustCenterAddress check mentioned in comment
     *       - Should check if TC address is all-FF (distributed) or all-00 (pre-TRANSPORT_KEY)
     *       - If so, should reject with PAN_ACCESS_DENIED
     *       - NOT IMPLEMENTED ❌
     * - ✅ Calls context associate with correct parameters:
     *       - initialJoin=false (this is a rejoin) ✅
     *       - neighbor determined by comparing MAC and NWK source ✅
     *       - denyOverride based on security analysis ✅
     * - ✅ Sends REJOIN_RESP with assigned address and status
     * - ✅ Does not require VERIFY_KEY after rejoin per spec note
     * - ✅ Triggers onDeviceRejoined callback on SUCCESS
     *
     * SECURITY CONCERNS:
     * - Unsecured rejoin handling is critical for security
     * - Must validate device authorization before accepting
     * - Missing apsTrustCenterAddress validation is a security gap
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processRejoinReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-R #3.4.7
     * Optional
     */
    processRejoinResp(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.7
     * Optional
     *
     * @param requestSource16 new network address assigned to the rejoining device
     * @param newAddress16
     * @param status
     * @param capabilities
     * @returns
     */
    sendRejoinResp(requestSource16: number, newAddress16: number, status: MACAssociationStatus | number, capabilities: MACCapabilities): Promise<boolean>;
    /**
     * 05-3474-R #3.4.8
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly decodes options byte, link count, and link entries
     * - ✅ Parses firstFrame and lastFrame flags for multi-frame support
     * - ✅ Extracts linkCount from CMD_LINK_OPTION_COUNT_MASK
     * - ✅ Each link entry has: address, incomingCost, outgoingCost
     * - ✅ Marks device as neighbor if link to coordinator is reported
     * - ⚠️  SOURCE ROUTE CREATION FROM LINK STATUS:
     *       - Creates source route entry for each neighbor ✅
     *       - Uses incomingCost as pathCost (link quality from neighbor's perspective) ✅
     *       - For coordinator link: creates empty relay list (direct route) ✅
     *       - For other links: creates route through that address ✅
     * - ✅ Updates existing routes if already present (by matching relay list)
     * - ✅ Resets failureCount on route update (fresh link status = healthy link)
     * - ⚠️  SPEC QUESTION: Using link status to build source routes
     *       - Spec #3.4.8 describes link status for neighbor table maintenance
     *       - Using it to build source routes is an implementation optimization
     *       - This may not be fully spec-compliant but is pragmatic
     * - ❌ TODO MARKERS in comments:
     *       - "TODO: NeighborTableEntry.age = 0 // max 0xff"
     *       - "TODO: NeighborTableEntry.routerAge += 1 // max 0xffff"
     *       - "TODO: NeighborTableEntry.routerConnectivity = formula"
     *       - "TODO: NeighborTableEntry.routerNeighborSetDiversity = formula"
     *       - "TODO: if NeighborTableEntry does not exist, create one..."
     *       - These are all required per spec #3.6.1.5 for proper neighbor table management
     * - ❌ MISSING: No actual neighbor table - only device table
     *       - Spec requires separate neighbor table with different attributes
     *       - Current implementation uses deviceTable with neighbor flag
     *       - This is a significant spec deviation
     * - ⚠️  COST CALCULATION: Uses incoming cost directly as path cost
     *       - This may underestimate total path cost for multi-hop routes
     *       - Should consider accumulated path cost through intermediaries
     *
     * CRITICAL: Neighbor table management is incomplete per spec
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processLinkStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.8
     *
     * @param links set of link status entries derived from the neighbor table (SHALL be specific to the interface to be transmitted on)
     * Links are expected sorted in ascending order by network address.
     * - incoming cost contains device's estimate of the link cost for the neighbor
     * - outgoing cost contains value of outgoing cost from neighbor table
     */
    sendLinkStatus(links: ZigbeeNWKLinkStatus[]): Promise<void>;
    /**
     * 05-3474-R #3.4.9 (deprecated in R23)
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes options, EPID, updateID, panID
     * - ✅ Handles PAN ID conflict reports
     * - ✅ Logs report information
     * - ❌ NOT IMPLEMENTED: Channel update action
     * - ❌ NOT IMPLEMENTED: Network update propagation
     * - ❌ NOT IMPLEMENTED: PAN ID conflict resolution
     * - ❌ NOT IMPLEMENTED: TLV support (R23)
     *
     * NOTE: Deprecated in R23, should no longer be sent by R23 devices
     * IMPACT: Coordinator doesn't act on network reports
     */
    processReport(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.10
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes options, EPID, updateID, panID
     * - ✅ Handles PAN update information
     * - ✅ Logs update information
     * - ❌ NOT IMPLEMENTED: Channel update if updateID is newer
     * - ❌ NOT IMPLEMENTED: Network parameter updates
     * - ❌ NOT IMPLEMENTED: Update propagation
     * - ❌ NOT IMPLEMENTED: TLV support (R23)
     *
     * IMPACT: Coordinator doesn't act on network updates
     */
    processUpdate(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.11
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes requested timeout (0-14 scale)
     * - ✅ Validates device exists
     * - ✅ Returns appropriate status
     * - ⚠️ INCOMPLETE: Accepts requested timeout without validation/policy
     * - ❌ NOT IMPLEMENTED: Timeout table management
     * - ❌ NOT IMPLEMENTED: Keep-alive mechanism
     * - ❌ NOT IMPLEMENTED: Timeout expiration handling
     * - ❌ NOT IMPLEMENTED: TLV support (R23)
     *
     * IMPACT: Timeout values accepted but not enforced
     */
    processEdTimeoutRequest(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-R #3.4.12
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes status (SUCCESS, INCORRECT_VALUE, UNSUPPORTED_FEATURE)
     * - ✅ Decodes parent info (keepalive support, power negotiation)
     * - ✅ Logs timeout response information
     * - ❌ NOT IMPLEMENTED: Action on response (only logs)
     * - ❌ NOT IMPLEMENTED: TLV support (R23)
     *
     * NOTE: Coordinator typically doesn't receive this (sent to end devices)
     */
    processEdTimeoutResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-R #3.4.12
     *
     * SPEC COMPLIANCE:
     * - ✅ Includes status and timeout value
     * - ✅ Unicast to requester
     * - ✅ Applies NWK security
     * - ⚠️ TODO: parentInfo flags need proper implementation
     *
     * @param requestDest16
     * @param requestedTimeout Requested timeout enumeration [0-14] (mapping to actual timeout) @see processEdTimeoutRequest
     * @returns
     */
    sendEdTimeoutResponse(requestDest16: number, requestedTimeout: number): Promise<boolean>;
    /**
     * 05-3474-R #3.4.13
     *
     * SPEC COMPLIANCE:
     * - ✅ Decodes transmit power delta
     * - ✅ Logs power delta information
     * - ✅ Extracts nested TLVs (if present)
     * - ❌ NOT IMPLEMENTED: Power adjustment action
     * - ❌ NOT IMPLEMENTED: Feedback mechanism
     * - ❌ NOT IMPLEMENTED: R23 TLV processing
     *
     * IMPACT: Receives command but doesn't adjust transmit power
     */
    processLinkPwrDelta(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.14
     * Optional
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly decodes assocType and capabilities
     * - ⚠️  TODO: TLVs not decoded (may contain critical R23+ commissioning info)
     * - ✅ Determines initial join vs rejoin from assocType:
     *       - 0x00 = Initial Join ✅
     *       - 0x01 = Rejoin ✅
     * - ✅ Determines neighbor by comparing MAC and NWK source addresses
     * - ✅ Calls context associate with appropriate parameters
     * - ✅ Sends COMMISSIONING_RESPONSE with status and address
     * - ✅ Sends TRANSPORT_KEY_NWK on SUCCESS for initial join ✅
     * - ⚠️  SPEC QUESTION: Should also send TRANSPORT_KEY on rejoin if NWK key changed?
     *       - Comment says "TODO also for rejoin in case of nwk key change?"
     *       - Spec may require this in some scenarios ❓
     * - ⚠️  MISSING: No validation of commissioning TLVs
     *       - TLVs may contain security parameters
     *       - Should validate and process these
     * - ⚠️  SPEC NOTE: Comment about sending Remove Device CMD to deny join
     *       - Alternative to normal rejection mechanism
     *       - Not implemented here
     *
     * COMMISSIONING vs NORMAL JOIN:
     * - Commissioning is R23+ feature for network commissioning
     * - May have different security requirements than legacy join
     * - TLV support is critical for full R23 compliance
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processCommissioningRequest(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-23 #3.4.15
     * Optional
     */
    processCommissioningResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.15
     * Optional
     *
     * @param requestSource16
     * @param newAddress16 the new 16-bit network address assigned, may be same as `requestDest16`
     * @returns
     */
    sendCommissioningResponse(requestSource16: number, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean>;
}
