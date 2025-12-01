import { MACAssociationStatus, type MACHeader } from "../zigbee/mac.js";
import { ZigbeeNWKCommandId, type ZigbeeNWKHeader, type ZigbeeNWKLinkStatus, ZigbeeNWKManyToOne, ZigbeeNWKStatus } from "../zigbee/zigbee-nwk.js";
import type { MACHandler } from "../zigbee-stack/mac-handler.js";
import { type SourceRouteTableEntry, type StackContext } from "../zigbee-stack/stack-context.js";
/**
 * Callbacks for NWK handler to communicate with driver
 */
export interface NWKHandlerCallbacks {
    /** Send APS TRANSPORT_KEY for network key */
    onAPSSendTransportKeyNWK: (destination16: number, networkKey: Buffer, keySequenceNumber: number, destination64: bigint) => Promise<void>;
}
export declare const CONFIG_NWK_MAX_HOPS: number;
/** This is an index into Table 3-54. It indicates the default timeout in minutes for any end device that does not negotiate a different timeout value. */
export declare const CONFIG_NWK_ED_TIMEOUT_DEFAULT = 8;
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
    /**
     * 05-3474-23 #3.4.8 (Link Status command)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Sends periodic LINK_STATUS commands at 15s interval with jitter per spec guidance for link cost maintenance
     * - ✅ Derives incoming/outgoing cost from neighbor LQA and routing metrics (spec Table 3-20)
     * - ✅ Resets timer using refresh() to maintain continuous reporting while handler active
     * - ⚠️  Aggregated cost calculation includes implementation-specific LQA penalty (documented)
     * - ✅ Enforces CONFIG_NWK_ROUTER_AGE_LIMIT by zeroing costs after consecutive misses per spec
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
    sendPeriodicZigbeeNWKLinkStatus(ignoreStale?: boolean): Promise<void>;
    /**
     * 05-3474-23 #3.6.3.5.2 (Many-to-One Route Discovery)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Issues ROUTE_REQUEST with Many-to-One flag when concentrator timer elapses
     * - ✅ Enforces minimum spacing (CONFIG_NWK_CONCENTRATOR_MIN_TIME) to prevent flooding per spec guidance
     * - ✅ Uses WITH_SOURCE_ROUTING mode to advertise concentrator capability
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
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
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param destination16
     * @param destination64
     * @returns
     * - request invalid (e.g. broadcast destination): [undefined, undefined, undefined]
     * - request valid and source route unavailable (unknown device or neighbor): [undefined, undefined, undefined]
     * - request valid and source route available and >=1 relay: [last index in relayAddresses, list of relay addresses, cost of the path]
     * - request valid and source route available and 0 relay: [undefined, undefined, cost of the path]
     */
    findBestSourceRoute(destination16: number | undefined, destination64: bigint | undefined, ignoreStale?: boolean): [relayIndex: number | undefined, relayAddresses: number[] | undefined, pathCost: number | undefined];
    /**
     * 05-3474-23 #3.6.3.3
     *
     * Mark a route as successfully used
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Resets failure counter and updates last-used timestamp after successful forwarding
     * - ✅ Operates on currently selected best route entry to keep metrics coherent
     * - ⚠️  Multi-entry route table means only first entry updated; others remain untouched
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param destination16 Network address of the destination
     */
    markRouteSuccess(destination16: number): void;
    /**
     * 05-3474-23 #3.6.3.3
     *
     * Mark a route as failed and handle route repair if needed.
     * Consolidates failure tracking and MTORR triggering per Zigbee spec.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Increments failure counter and triggers Many-to-One route discovery after threshold
     * - ✅ Purges routes that rely on failed relay as required for repair
     * - ✅ Supports explicit repair trigger (e.g., NWK_STATUS link failure)
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param destination16 Network address of the destination
     * @param triggerRepair If true, will purge routes using this destination as relay and trigger MTORR
     */
    markRouteFailure(destination16: number, triggerRepair?: boolean): void;
    /**
     * 05-3474-23 #3.6.3.3 (Source routing tables)
     *
     * Create a new source route table entry
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Initializes relay list, path cost, and age information for source route maintenance
     * - ✅ Resets failure counters and last-used metadata per new measurement
     * - ⚠️  Implementation stores multiple route entries per destination (spec defines single entry with status)
     *       - Provides richer path selection but diverges from formal table layout
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
    createSourceRouteEntry(relayAddresses: number[], pathCost: number): SourceRouteTableEntry;
    /**
     * 05-3474-23 #3.6.3.3
     *
     * Check if a source route already exists in the table
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Compares relay hop list and cost to detect duplicate paths before insertion
     * - ✅ Accepts optional pre-fetched entry array to avoid redundant map lookups
     * - ⚠️  Formally spec route table holds single entry per destination; this helper assumes multi-entry model
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
    hasSourceRoute(address16: number, newEntry: SourceRouteTableEntry, existingEntries?: SourceRouteTableEntry[]): boolean;
    /**
     * 05-3474-23 #3.4 (NWK command frames)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Prepends Zigbee NWK header and optional security per caller (spec Table 3-5)
     * - ✅ Applies source routing when available via findBestSourceRoute (spec #3.6.3.3)
     * - ✅ Maps NWK destination to MAC destination with broadcast handling
     * - ⚠️  Relies on caller to ensure command-specific payload validity (e.g., TLVs)
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param cmdId Command identifier (first byte of payload)
     * @param finalPayload Fully encoded NWK command payload (including cmdId)
     * @param nwkSecurity Whether to enable NWK security header
     * @param nwkSource16 Source network address for header
     * @param nwkDest16 Destination network address
     * @param nwkDest64 Optional destination IEEE address (for concentrator routing)
     * @param nwkRadius Initial radius/TTL
     * @returns True if success sending (or indirect transmission)
     */
    sendCommand(cmdId: ZigbeeNWKCommandId, finalPayload: Buffer, nwkSecurity: boolean, nwkSource16: number, nwkDest16: number, nwkDest64: bigint | undefined, nwkRadius: number): Promise<boolean>;
    /**
     * 05-3474-23 #3.4 (NWK command processing)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Dispatches all mandatory NWK commands for coordinator role (ROUTE_REQ/REPLY, NWK_STATUS, LEAVE, LINK_STATUS, etc.)
     * - ✅ Maintains offset propagation between handlers to consume payload sequentially
     * - ✅ Logs unsupported command IDs per spec recommendation to ignore silently (kept as warning for diagnostics)
     * - ⚠️  Commissioning, Link Power Delta, ED Timeout handling partially implemented (documented TODOs)
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    processCommand(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<void>;
    /**
     * 05-3474-23 #3.4.1 (Route Request)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Decodes options, destination, and many-to-one fields per Table 3-12
     * - ✅ Sends ROUTE_REPLY when coordinator is destination (spec #3.6.3.5.2 requirement for concentrators)
     * - ✅ Preserves destination64 when provided to maintain IEEE correlation
     * - ⚠️  Path cost not incremented (acceptable for terminal node)
     * - ⚠️  Route discovery table not implemented (coordinator does not forward requests)
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processRouteReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-23 #3.4.1 (Route Request)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Encodes options bits for many-to-one and DEST_EXT addressing
     * - ✅ Uses modulo-256 route request identifier (nextRouteRequestId)
     * - ✅ Broadcasts discovery (dest=BCAST_DEFAULT) when acting as concentrator
     * - ⚠️  TLV payload not supported (optional R23 extension)
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param manyToOne
     * @param destination16 intended destination of the route request command frame
     * @param destination64 SHOULD always be added if it is known
     * @returns
     */
    sendRouteReq(manyToOne: ZigbeeNWKManyToOne, destination16: number, destination64?: bigint): Promise<boolean>;
    /**
     * 05-3474-23 #3.4.2 (Route Reply)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Decodes originator/responder addresses (short and extended) per options mask
     * - ✅ Reconstructs relay path including MAC next hop when coordinator originates discovery
     * - ✅ Normalizes zero path cost to hop-derived value to satisfy spec requirement (>0)
     * - ⚠️  TLVs and status-field failure indicators remain TODO
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
    processRouteReply(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.2 / #3.6.4.5.2 (Route Reply)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Encodes IEEE address presence bits and includes optional fields
     * - ✅ Sets path cost to 1 hop when coordinator responds directly
     * - ✅ Unicasts reply via first hop recorded in request MAC header
     * - ⚠️  TLV payload not encoded (optional R23 extension)
     * DEVICE SCOPE: Coordinator, routers (N/A)
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
     * 05-3474-23 #3.4.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes status code
     * - ✅ Handles destination16 parameter for routing failures
     * - ✅ Marks route as failed and schedules MTORR recovery
     * - ✅ Logs network status issues for diagnostics
     * - ❌ NOT IMPLEMENTED: TLV processing (R23)
     * - ✅ Issues REJOIN_RESP with address-conflict status to prompt device reassignment
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * IMPACT: Receives status but minimal action beyond route marking
     */
    processStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-23 #3.4.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Sends to appropriate destination (broadcast or unicast)
     * - ✅ Includes error codes (NO_ROUTE_AVAILABLE, LINK_FAILURE, etc.)
     * - ✅ No security applied (per spec)
     * - ✅ Optional destination16 for routing failures/address conflicts
     * DEVICE SCOPE: Coordinator, routers (N/A)
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
     * 05-3474-23 #3.4.4 (Leave command)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Parses removeChildren/request/rejoin flags from options byte (Table 3-16)
     * - ✅ Invokes disassociate when device signals final leave (request=false & rejoin=false)
     * - ⚠️ removeChildren flag purposely ignored (deprecated)
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    processLeave(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-23 #3.4.4 (Leave command)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Sets request bit (bit6) and optional rejoin bit based on caller input
     * - ✅ Forces removeChildren=0 to avoid unintended network disruption (spec allows but not typical for TC)
     * - ✅ Applies NWK security and unicasts to destination per coordinator requirements
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param destination16 Target network address
     * @param rejoin Whether device should rejoin after leave
     * @returns True if success sending (or indirect transmission)
     */
    sendLeave(destination16: number, rejoin: boolean): Promise<boolean>;
    /**
     * 05-3474-23 #3.4.5
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly decodes relayCount and relay addresses
     * - ✅ Stores source route in sourceRouteTable
     * - ✅ Creates source route entry with relays and path cost (relayCount + 1)
     * - ✅ Handles missing source16 by looking up via source64
     * - ✅ Checks for duplicate routes before adding (hasSourceRoute)
     * - ✅ ROUTE_RECORD provides path from source to coordinator
     *       - Relay list is in order from source toward coordinator ✅
     *       - Path cost calculation (relayCount + 1) is correct ✅
     * - ✅ Validates source16 is defined before adding to table
     * - ✅ Stores relay addresses in correct order for source routing
     *
     * IMPORTANT: Route records are sent by devices to establish reverse path to concentrator
     * This is correct for coordinator acting as concentrator.
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processRouteRecord(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.6
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
     * - ✅ Centralized Trust Center enforces coordinator EUI64; distributed/uninitialized modes not supported here (N/A)
     * - ✅ Calls context associate with correct parameters:
     *       - initialJoin=false (this is a rejoin) ✅
     *       - neighbor determined by comparing MAC and NWK source ✅
     *       - denyOverride based on security analysis ✅
     * - ✅ Sends REJOIN_RESP with assigned address and status
     * - ✅ Re-distributes current NWK key when rejoin requires key update
     * - ✅ Does not require VERIFY_KEY after rejoin per spec note
     *
     * SECURITY CONCERNS:
     * - Unsecured rejoin handling is critical for security
     * - Must validate device authorization before accepting
     * - Missing apsTrustCenterAddress validation is a security gap
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processRejoinReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-23 #3.4.7
     *
     * Optional
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Parses status and new short address per Table 3-19
     * - ✅ Logs success/failure for Trust Center auditing
     * - ⚠️  Does not currently update device tables; caller expected to handle
     * - ⚠️  TLV extensions (R23) not parsed yet
     * DEVICE SCOPE: Routers (N/A), end devices (N/A)
     */
    processRejoinResp(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.7 (Rejoin Response)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Returns new short address and status per Table 3-19
     * - ✅ Sends NWK-secured unicast response when NWK security is enabled
     * - ⚠️  Does not attach optional TLV extensions
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param requestSource16 Requestor network address
     * @param newAddress16 Assigned network address
     * @param status Rejoin status (MACAssociationStatus or NWK status)
     * @returns True if success sending (or indirect transmission)
     */
    sendRejoinResp(requestSource16: number, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean>;
    /**
     * 05-3474-23 #3.4.8
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly decodes options byte, link count, and link entries
     * - ✅ Parses firstFrame and lastFrame flags for multi-frame support
     * - ✅ Extracts linkCount from CMD_LINK_OPTION_COUNT_MASK
     * - ✅ Each link entry has: address, incomingCost, outgoingCost
     * - ✅ Marks device as neighbor if link to coordinator is reported
     * - ⚠️ SOURCE ROUTE CREATION FROM LINK STATUS:
     *       - Creates source route entry for each neighbor ✅
     *       - Uses incomingCost as pathCost (link quality from neighbor's perspective) ✅
     *       - For coordinator link: creates empty relay list (direct route) ✅
     *       - For other links: creates route through that address ✅
     * - ✅ Updates existing routes if already present (by matching relay list)
     * - ✅ Resets failureCount on route update (fresh link status = healthy link)
     * - ⚠️ SPEC QUESTION: Using link status to build source routes
     *       - Spec #3.4.8 describes link status for neighbor table maintenance
     *       - Using it to build source routes is an implementation optimization
     *       - This may not be fully spec-compliant but is pragmatic
     * - ⚠️ Neighbor table maintenance is purposely not implemented due to "unlimited" table size on host
     *       - No neighbor table present, only a flag in device table
     *       - This is a significant spec deviation
     * - ⚠️ COST CALCULATION: Uses incoming cost directly as path cost
     *       - This may underestimate total path cost for multi-hop routes
     *       - Should consider accumulated path cost through intermediaries
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processLinkStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.8 (Link Status command)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Fragments link list across multiple frames respecting MAX_PAYLOAD (27 entries per frame)
     * - ✅ Sets FIRST/LAST frame bits per Table 3-20 and repeats last link between frames as required
     * - ✅ Encodes incoming/outgoing cost nibble per spec definition
     * - ⚠️  Uses coordinator broadcast radius=1 as optimization (spec allows broader radius)
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * @param links Link status entries sorted ascending by address
     */
    sendLinkStatus(links: ZigbeeNWKLinkStatus[]): Promise<void>;
    /**
     * 05-3474-23 #3.4.9 (deprecated in R23)
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes options, EPID, updateID, panID
     * - ✅ Handles PAN ID conflict reports
     * - ✅ Logs report information
     * - ❌ NOT IMPLEMENTED: Channel update action
     * - ❌ NOT IMPLEMENTED: Network update propagation
     * - ❌ NOT IMPLEMENTED: PAN ID conflict resolution
     * - ❌ NOT IMPLEMENTED: TLV support (R23)
     * DEVICE SCOPE: Coordinator, routers (N/A)
     *
     * NOTE: Deprecated in R23, should no longer be sent by R23 devices
     * IMPACT: Coordinator doesn't act on network reports
     */
    processReport(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.10
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes options, EPID, updateID, panID
     * - ✅ Handles PAN update information
     * - ✅ Logs update information
     * - ❌ NOT IMPLEMENTED: Channel update if updateID is newer
     * - ❌ NOT IMPLEMENTED: Network parameter updates
     * - ❌ NOT IMPLEMENTED: Update propagation
     * - ❌ NOT IMPLEMENTED: TLV support (R23)
     * DEVICE SCOPE: Routers (N/A), end devices (N/A)
     */
    processUpdate(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.11
     *
     * SPEC COMPLIANCE:
     * - ✅ Decodes requested timeout index and configuration octet per spec Table 3-54
     * - ✅ Validates timeout against END_DEVICE_TIMEOUT_TABLE and device presence before accepting
     * - ✅ Updates StackContext end-device timeout metadata and responds with status codes (SUCCESS/INCORRECT_VALUE/UNSUPPORTED_FEATURE)
     * - ⚠️ Still lacks parent policy enforcement (e.g., max timeout per device class)
     * - ❌ NOT IMPLEMENTED: Keep-alive scheduling or timeout expiration handling
     * - ❌ NOT IMPLEMENTED: TLV processing for R23 extensions
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
    processEdTimeoutRequest(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-23 #3.4.12
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes status (SUCCESS, INCORRECT_VALUE, UNSUPPORTED_FEATURE)
     * - ✅ Decodes parent info (keepalive support, power negotiation)
     * - ✅ Logs timeout response information
     * - ❌ NOT IMPLEMENTED: Action on response (only logs)
     * - ❌ NOT IMPLEMENTED: TLV support (R23)
     * DEVICE SCOPE: End devices (N/A)
     *
     * NOTE: Coordinator typically doesn't receive this (sent to end devices)
     */
    processEdTimeoutResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.12
     *
     * SPEC COMPLIANCE:
     * - ✅ Populates status field with SUCCESS/INCORRECT_VALUE/UNSUPPORTED_FEATURE based on request validation
     * - ✅ Sends parent information bitmap indicating keep-alive support (defaults to DATA_POLL + REQUEST + POWER_NEGOTIATION)
     * - ✅ Applies NWK security and unicasts to requester as required
     * - ❌ NOT IMPLEMENTED: TLV extensions (R23)
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
    sendEdTimeoutResponse(requestDest16: number, requestedTimeout: number, statusOverride?: number, parentInfoOverride?: number): Promise<boolean>;
    /**
     * 05-3474-23 #3.4.13
     *
     * SPEC COMPLIANCE:
     * - ✅ Decodes transmit power delta
     * - ✅ Logs power delta information
     * - ✅ Extracts nested TLVs (if present)
     * - ❌ NOT IMPLEMENTED: Power adjustment action
     * - ❌ NOT IMPLEMENTED: Feedback mechanism
     * - ❌ NOT IMPLEMENTED: R23 TLV processing
     * DEVICE SCOPE: Coordinator, routers (N/A)
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
     * - ✅ Sends TRANSPORT_KEY_NWK on SUCCESS when required
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
     * DEVICE SCOPE: Coordinator
     *
     * @param data Command data
     * @param offset Current offset in data
     * @param macHeader MAC header
     * @param nwkHeader NWK header
     * @returns New offset after processing
     */
    processCommissioningRequest(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number>;
    /**
     * 05-3474-23 #3.4.15 (Commissioning Response) — Optional in R23
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Extracts assigned address and status value per Table 3-22
     * - ✅ Logs success vs failure for commissioning diagnostics
     * - ⚠️  TODO: Process optional TLVs (required for full Zigbee Direct compliance)
     * DEVICE SCOPE: Routers (N/A), end devices (N/A)
     */
    processCommissioningResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number;
    /**
     * 05-3474-23 #3.4.15 (Commissioning Response) — Optional in R23
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Sends commissioning response with STATUS + new address fields as defined in Table 3-22
     * - ✅ Uses NWK security=false (spec permits unsecured when join not completed)
     * - ✅ Applies default radius (CONFIG_NWK_MAX_HOPS) for reachability
     * - ⚠️  TLV payload not supported (TODO)
     * DEVICE SCOPE: Coordinator
     *
     * @param requestSource16 Destination device
     * @param newAddress16 Assigned address echoed back
     * @param status Commissioning status
     * @returns True if success sending (or indirect transmission)
     */
    sendCommissioningResponse(requestSource16: number, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean>;
}
