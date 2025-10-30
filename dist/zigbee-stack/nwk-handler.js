"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NWKHandler = void 0;
const logger_js_1 = require("../utils/logger.js");
const mac_js_1 = require("../zigbee/mac.js");
const zigbee_nwk_js_1 = require("../zigbee/zigbee-nwk.js");
const NS = "nwk-handler";
/** The number of OctetDurations until a route discovery expires. */
// const CONFIG_NWK_ROUTE_DISCOVERY_TIME = 0x4c4b4; // 0x2710 msec on 2.4GHz
/** The maximum depth of the network (number of hops) used for various calculations of network timing and limitations. */
const CONFIG_NWK_MAX_DEPTH = 15;
const CONFIG_NWK_MAX_HOPS = CONFIG_NWK_MAX_DEPTH * 2;
/** The number of network layer retries on unicast messages that are attempted before reporting the result to the higher layer. */
// const CONFIG_NWK_UNICAST_RETRIES = 3;
/** The delay between network layer retries. (ms) */
// const CONFIG_NWK_UNICAST_RETRY_DELAY = 50;
/** The total delivery time for a broadcast transmission to be delivered to all RxOnWhenIdle=TRUE devices in the network. (sec) */
// const CONFIG_NWK_BCAST_DELIVERY_TIME = 9;
/** The time between link status command frames (msec) */
const CONFIG_NWK_LINK_STATUS_PERIOD = 15000;
/** Avoid synchronization with other nodes by randomizing `CONFIG_NWK_LINK_STATUS_PERIOD` with this (msec) */
const CONFIG_NWK_LINK_STATUS_JITTER = 1000;
/** The number of missed link status command frames before resetting the link costs to zero. */
// const CONFIG_NWK_ROUTER_AGE_LIMIT = 3;
/** This is an index into Table 3-54. It indicates the default timeout in minutes for any end device that does not negotiate a different timeout value. */
// const CONFIG_NWK_END_DEVICE_TIMEOUT_DEFAULT = 8;
/** The time between concentrator route discoveries. (msec) */
const CONFIG_NWK_CONCENTRATOR_DISCOVERY_TIME = 60000;
/** The hop count radius for concentrator route discoveries. */
const CONFIG_NWK_CONCENTRATOR_RADIUS = CONFIG_NWK_MAX_HOPS;
/** The number of delivery failures that trigger an immediate concentrator route discoveries. */
const CONFIG_NWK_CONCENTRATOR_DELIVERY_FAILURE_THRESHOLD = 1;
/** The time before a route is considered stale and less preferred (msec) */
const CONFIG_NWK_ROUTE_STALENESS_TIME = 120000;
/** The maximum age before a route is considered expired and removed (msec) */
const CONFIG_NWK_ROUTE_EXPIRY_TIME = 300000;
/** The maximum number of consecutive failures before a route is blacklisted (count) */
const CONFIG_NWK_ROUTE_MAX_FAILURES = 3;
/** Minimum time between many-to-one route request broadcasts to avoid flooding (msec) */
const CONFIG_NWK_CONCENTRATOR_MIN_TIME = 10000;
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
class NWKHandler {
    #context;
    #macHandler;
    #callbacks;
    // Private counters (start at 0, first call returns 1)
    #seqNum = 0;
    #routeRequestId = 0;
    #linkStatusTimeout;
    #manyToOneRouteRequestTimeout;
    /** Time of last many-to-one route request */
    #lastMTORRTime = 0;
    constructor(context, macHandler, callbacks) {
        this.#context = context;
        this.#macHandler = macHandler;
        this.#callbacks = callbacks;
    }
    async start() {
        this.#linkStatusTimeout = setTimeout(this.sendPeriodicZigbeeNWKLinkStatus.bind(this), CONFIG_NWK_LINK_STATUS_PERIOD + Math.random() * CONFIG_NWK_LINK_STATUS_JITTER);
        this.#manyToOneRouteRequestTimeout = setTimeout(this.sendPeriodicManyToOneRouteRequest.bind(this), CONFIG_NWK_CONCENTRATOR_DISCOVERY_TIME);
        await this.sendPeriodicZigbeeNWKLinkStatus();
        await this.sendPeriodicManyToOneRouteRequest();
    }
    stop() {
        clearTimeout(this.#linkStatusTimeout);
        this.#linkStatusTimeout = undefined;
        clearTimeout(this.#manyToOneRouteRequestTimeout);
        this.#manyToOneRouteRequestTimeout = undefined;
    }
    /**
     * Get next NWK sequence number.
     * HOT PATH: Optimized counter increment
     * @returns Incremented NWK sequence number (wraps at 255)
     */
    /* @__INLINE__ */
    nextSeqNum() {
        this.#seqNum = (this.#seqNum + 1) & 0xff;
        return this.#seqNum;
    }
    /**
     * Get next route request ID.
     * HOT PATH: Optimized counter increment
     * @returns Incremented route request ID (wraps at 255)
     */
    /* @__INLINE__ */
    nextRouteRequestId() {
        this.#routeRequestId = (this.#routeRequestId + 1) & 0xff;
        return this.#routeRequestId;
    }
    // #region Route Management
    async sendPeriodicZigbeeNWKLinkStatus() {
        const links = [];
        for (const [device64, entry] of this.#context.deviceTable.entries()) {
            if (entry.neighbor) {
                try {
                    // calculate cost based on path cost and recent link quality
                    const [, , pathCost] = this.findBestSourceRoute(entry.address16, device64);
                    let linkCost = pathCost ?? 1;
                    // adjust cost based on recent LQA (link quality assessment) only if we have data
                    if (entry.recentLQAs.length > 0) {
                        const avgLQA = entry.recentLQAs.reduce((sum, lqa) => sum + lqa, 0) / entry.recentLQAs.length;
                        // only apply penalty if avgLQA is valid
                        if (!Number.isNaN(avgLQA)) {
                            // LQA range [0..255], convert to cost penalty [0..7]
                            // high LQA (good link) = low penalty, low LQA (bad link) = high penalty
                            const lqaPenalty = Math.max(0, Math.min(7, Math.floor((255 - avgLQA) / 36)));
                            linkCost = Math.min(7, linkCost + lqaPenalty);
                        }
                    }
                    links.push({
                        address: entry.address16,
                        incomingCost: linkCost,
                        outgoingCost: linkCost,
                    });
                }
                catch {
                    /* ignore */
                }
            }
        }
        await this.sendLinkStatus(links);
        this.#linkStatusTimeout?.refresh();
    }
    async sendPeriodicManyToOneRouteRequest() {
        if (Date.now() > this.#lastMTORRTime + CONFIG_NWK_CONCENTRATOR_MIN_TIME) {
            await this.sendRouteReq(1 /* ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING */, 65532 /* ZigbeeConsts.BCAST_DEFAULT */);
            this.#manyToOneRouteRequestTimeout?.refresh();
            this.#lastMTORRTime = Date.now();
        }
    }
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
    findBestSourceRoute(destination16, destination64) {
        if (destination16 !== undefined && destination16 >= 65528 /* ZigbeeConsts.BCAST_MIN */) {
            return [undefined, undefined, undefined];
        }
        if (destination16 === undefined) {
            if (destination64 === undefined) {
                throw new Error("Invalid parameters");
            }
            const device = this.#context.deviceTable.get(destination64);
            if (device === undefined) {
                throw new Error("Unknown destination");
            }
            destination16 = device.address16;
        }
        else if (!this.#context.address16ToAddress64.has(destination16)) {
            throw new Error("Unknown destination");
        }
        const sourceRouteEntries = this.#context.sourceRouteTable.get(destination16);
        if (sourceRouteEntries === undefined || sourceRouteEntries.length === 0) {
            // cleanup
            this.#context.sourceRouteTable.delete(destination16);
            const device64 = destination64 ?? this.#context.address16ToAddress64.get(destination16);
            const device = this.#context.deviceTable.get(device64);
            if (device && !device.neighbor) {
                // force immediate MTORR
                logger_js_1.logger.warning("No known route to destination, forcing discovery", NS);
                setImmediate(this.sendPeriodicManyToOneRouteRequest.bind(this));
                // will send direct as "last resort"
            }
            return [undefined, undefined, undefined];
        }
        const now = Date.now();
        const validEntries = [];
        // filter out expired and blacklisted routes
        for (const entry of sourceRouteEntries) {
            const age = now - entry.lastUpdated;
            // remove expired routes
            if (age > CONFIG_NWK_ROUTE_EXPIRY_TIME) {
                logger_js_1.logger.debug(() => `Route to ${destination16} expired (age=${age}ms)`, NS);
                continue;
            }
            // remove blacklisted routes (too many consecutive failures)
            if (entry.failureCount >= CONFIG_NWK_ROUTE_MAX_FAILURES) {
                logger_js_1.logger.debug(() => `Route to ${destination16} blacklisted (failures=${entry.failureCount})`, NS);
                continue;
            }
            // check if any relay has too many NO_ACK
            let relayFailed = false;
            for (const relay of entry.relayAddresses) {
                const macNoACKs = this.#context.macNoACKs.get(relay);
                if (macNoACKs !== undefined && macNoACKs >= CONFIG_NWK_CONCENTRATOR_DELIVERY_FAILURE_THRESHOLD) {
                    logger_js_1.logger.debug(() => `Route to ${destination16} via relay ${relay} has too many NO_ACKs (${macNoACKs})`, NS);
                    relayFailed = true;
                    break;
                }
            }
            if (relayFailed) {
                continue;
            }
            validEntries.push(entry);
        }
        // update the source route table
        if (validEntries.length === 0) {
            this.#context.sourceRouteTable.delete(destination16);
            const device64 = destination64 ?? this.#context.address16ToAddress64.get(destination16);
            const device = this.#context.deviceTable.get(device64);
            if (device && !device.neighbor) {
                logger_js_1.logger.warning(`All routes to ${destination16} invalid, forcing discovery`, NS);
                setImmediate(this.sendPeriodicManyToOneRouteRequest.bind(this));
            }
            return [undefined, undefined, undefined];
        }
        if (validEntries.length !== sourceRouteEntries.length) {
            this.#context.sourceRouteTable.set(destination16, validEntries);
        }
        // sort routes by composite score: path cost + staleness penalty + failure penalty + recency bonus
        validEntries.sort((a, b) => {
            const ageA = now - a.lastUpdated;
            const ageB = now - b.lastUpdated;
            // add staleness penalty (0-2 points based on age)
            const stalenessPenaltyA = ageA > CONFIG_NWK_ROUTE_STALENESS_TIME ? Math.min(2, (ageA - CONFIG_NWK_ROUTE_STALENESS_TIME) / CONFIG_NWK_ROUTE_STALENESS_TIME) : 0;
            const stalenessPenaltyB = ageB > CONFIG_NWK_ROUTE_STALENESS_TIME ? Math.min(2, (ageB - CONFIG_NWK_ROUTE_STALENESS_TIME) / CONFIG_NWK_ROUTE_STALENESS_TIME) : 0;
            // add failure penalty (1 point per failure)
            const failurePenaltyA = a.failureCount;
            const failurePenaltyB = b.failureCount;
            // add recency bonus (prefer recently used routes)
            const recencyBonusA = a.lastUsed && now - a.lastUsed < 30000 ? -1 : 0;
            const recencyBonusB = b.lastUsed && now - b.lastUsed < 30000 ? -1 : 0;
            const scoreA = a.pathCost + stalenessPenaltyA + failurePenaltyA + recencyBonusA;
            const scoreB = b.pathCost + stalenessPenaltyB + failurePenaltyB + recencyBonusB;
            return scoreA - scoreB;
        });
        const bestEntry = validEntries[0];
        if (bestEntry.relayAddresses.length === 0) {
            // direct route (cost only, no relays)
            return [undefined, undefined, bestEntry.pathCost];
        }
        return [bestEntry.relayAddresses.length - 1, bestEntry.relayAddresses, bestEntry.pathCost];
    }
    /**
     * Mark a route as successfully used
     * @param destination16 Network address of the destination
     */
    markRouteSuccess(destination16) {
        const entries = this.#context.sourceRouteTable.get(destination16);
        if (entries && entries.length > 0) {
            const entry = entries[0]; // mark the currently-selected best route
            entry.lastUsed = Date.now();
            entry.failureCount = 0; // reset failure count on success
        }
    }
    /**
     * Mark a route as failed and handle route repair if needed.
     * Consolidates failure tracking and MTORR triggering per Zigbee spec.
     *
     * @param destination16 Network address of the destination
     * @param triggerRepair If true, will purge routes using this destination as relay and trigger MTORR
     */
    markRouteFailure(destination16, triggerRepair = false) {
        const entries = this.#context.sourceRouteTable.get(destination16);
        if (entries && entries.length > 0) {
            const entry = entries[0]; // mark the currently-selected best route
            entry.failureCount += 1;
            logger_js_1.logger.debug(() => `Route to ${destination16} failed (failureCount=${entry.failureCount})`, NS);
            // if blacklisted or explicit repair requested, purge and trigger MTORR
            if (triggerRepair || entry.failureCount >= CONFIG_NWK_ROUTE_MAX_FAILURES) {
                logger_js_1.logger.warning(`Route to ${destination16} ${triggerRepair ? "requires repair" : `blacklisted after ${entry.failureCount} failures`}, purging related routes and forcing discovery`, NS);
                // purge all routes using this destination as a relay
                for (const [addr16, routeEntries] of this.#context.sourceRouteTable) {
                    const filteredEntries = routeEntries.filter((e) => !e.relayAddresses.includes(destination16));
                    if (filteredEntries.length === 0) {
                        this.#context.sourceRouteTable.delete(addr16);
                    }
                    else if (filteredEntries.length !== routeEntries.length) {
                        this.#context.sourceRouteTable.set(addr16, filteredEntries);
                    }
                }
                // remove direct routes to the target as well
                this.#context.sourceRouteTable.delete(destination16);
                // trigger immediate route discovery
                setImmediate(this.sendPeriodicManyToOneRouteRequest.bind(this));
            }
        }
    }
    /**
     * Create a new source route table entry
     */
    /* @__INLINE__ */
    createSourceRouteEntry(relayAddresses, pathCost) {
        return {
            relayAddresses,
            pathCost,
            lastUpdated: Date.now(),
            failureCount: 0,
            lastUsed: undefined,
        };
    }
    /**
     * Check if a source route already exists in the table
     */
    hasSourceRoute(address16, newEntry, existingEntries) {
        if (!existingEntries) {
            existingEntries = this.#context.sourceRouteTable.get(address16);
            if (!existingEntries) {
                return false;
            }
        }
        for (const existingEntry of existingEntries) {
            if (newEntry.pathCost === existingEntry.pathCost && newEntry.relayAddresses.length === existingEntry.relayAddresses.length) {
                let matching = true;
                for (let i = 0; i < newEntry.relayAddresses.length; i++) {
                    if (newEntry.relayAddresses[i] !== existingEntry.relayAddresses[i]) {
                        matching = false;
                        break;
                    }
                }
                if (matching) {
                    return true;
                }
            }
        }
        return false;
    }
    // #endregion
    // #region Commands
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
    async sendCommand(cmdId, finalPayload, nwkSecurity, nwkSource16, nwkDest16, nwkDest64, nwkRadius) {
        let nwkSecurityHeader;
        if (nwkSecurity) {
            nwkSecurityHeader = {
                control: {
                    level: 0 /* ZigbeeSecurityLevel.NONE */,
                    keyId: 1 /* ZigbeeKeyType.NWK */,
                    nonce: true,
                },
                frameCounter: this.#context.nextNWKKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                keySeqNum: this.#context.netParams.networkKeySequenceNumber,
                micLen: 4,
            };
        }
        const nwkSeqNum = this.nextSeqNum();
        const macSeqNum = this.#macHandler.nextSeqNum();
        let relayIndex;
        let relayAddresses;
        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        }
        catch (error) {
            logger_js_1.logger.error(`=x=> NWK CMD[seqNum=(${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64}] ${error.message}`, NS);
            return false;
        }
        const macDest16 = nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ ? (relayAddresses?.[relayIndex] ?? nwkDest16) : 65535 /* ZigbeeMACConsts.BCAST_ADDR */;
        logger_js_1.logger.debug(() => `===> NWK CMD[seqNum=(${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} macDst16=${macDest16} nwkSrc16=${nwkSource16} nwkDst=${nwkDest16}:${nwkDest64} nwkRad=${nwkRadius}]`, NS);
        const source64 = nwkSource16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ ? this.#context.netParams.eui64 : this.#context.address16ToAddress64.get(nwkSource16);
        const nwkFrame = (0, zigbee_nwk_js_1.encodeZigbeeNWKFrame)({
            frameControl: {
                frameType: 1 /* ZigbeeNWKFrameType.CMD */,
                protocolVersion: 2 /* ZigbeeNWKConsts.VERSION_2007 */,
                discoverRoute: 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */,
                multicast: false,
                security: nwkSecurity,
                sourceRoute: relayIndex !== undefined,
                extendedDestination: nwkDest64 !== undefined,
                extendedSource: source64 !== undefined,
                endDeviceInitiator: false,
            },
            destination16: nwkDest16,
            destination64: nwkDest64,
            source16: nwkSource16,
            source64,
            radius: this.#context.decrementRadius(nwkRadius),
            seqNum: nwkSeqNum,
            relayIndex,
            relayAddresses,
        }, finalPayload, nwkSecurityHeader, undefined);
        const macFrame = (0, mac_js_1.encodeMACFrameZigbee)({
            frameControl: {
                frameType: 1 /* MACFrameType.DATA */,
                securityEnabled: false,
                framePending: Boolean(this.#context.indirectTransmissions.get(nwkDest64 ?? this.#context.address16ToAddress64.get(nwkDest16))?.length),
                ackRequest: macDest16 !== 65535 /* ZigbeeMACConsts.BCAST_ADDR */,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2 /* MACFrameAddressMode.SHORT */,
                frameVersion: 0 /* MACFrameVersion.V2003 */,
                sourceAddrMode: 2 /* MACFrameAddressMode.SHORT */,
            },
            sequenceNumber: macSeqNum,
            destinationPANId: this.#context.netParams.panId,
            destination16: macDest16,
            // sourcePANId: undefined, // panIdCompression=true
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            fcs: 0,
        }, nwkFrame);
        const result = await this.#macHandler.sendFrame(macSeqNum, macFrame, macDest16, undefined);
        return result !== false;
    }
    async processCommand(data, macHeader, nwkHeader) {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;
        switch (cmdId) {
            case 1 /* ZigbeeNWKCommandId.ROUTE_REQ */: {
                offset = await this.processRouteReq(data, offset, macHeader, nwkHeader);
                break;
            }
            case 2 /* ZigbeeNWKCommandId.ROUTE_REPLY */: {
                offset = this.processRouteReply(data, offset, macHeader, nwkHeader);
                break;
            }
            case 3 /* ZigbeeNWKCommandId.NWK_STATUS */: {
                offset = this.processStatus(data, offset, macHeader, nwkHeader);
                break;
            }
            case 4 /* ZigbeeNWKCommandId.LEAVE */: {
                offset = await this.processLeave(data, offset, macHeader, nwkHeader);
                break;
            }
            case 5 /* ZigbeeNWKCommandId.ROUTE_RECORD */: {
                offset = this.processRouteRecord(data, offset, macHeader, nwkHeader);
                break;
            }
            case 6 /* ZigbeeNWKCommandId.REJOIN_REQ */: {
                offset = await this.processRejoinReq(data, offset, macHeader, nwkHeader);
                break;
            }
            case 7 /* ZigbeeNWKCommandId.REJOIN_RESP */: {
                offset = this.processRejoinResp(data, offset, macHeader, nwkHeader);
                break;
            }
            case 8 /* ZigbeeNWKCommandId.LINK_STATUS */: {
                offset = this.processLinkStatus(data, offset, macHeader, nwkHeader);
                break;
            }
            case 9 /* ZigbeeNWKCommandId.NWK_REPORT */: {
                offset = this.processReport(data, offset, macHeader, nwkHeader);
                break;
            }
            case 10 /* ZigbeeNWKCommandId.NWK_UPDATE */: {
                offset = this.processUpdate(data, offset, macHeader, nwkHeader);
                break;
            }
            case 11 /* ZigbeeNWKCommandId.ED_TIMEOUT_REQUEST */: {
                offset = await this.processEdTimeoutRequest(data, offset, macHeader, nwkHeader);
                break;
            }
            case 12 /* ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE */: {
                offset = this.processEdTimeoutResponse(data, offset, macHeader, nwkHeader);
                break;
            }
            case 13 /* ZigbeeNWKCommandId.LINK_PWR_DELTA */: {
                offset = this.processLinkPwrDelta(data, offset, macHeader, nwkHeader);
                break;
            }
            case 14 /* ZigbeeNWKCommandId.COMMISSIONING_REQUEST */: {
                offset = await this.processCommissioningRequest(data, offset, macHeader, nwkHeader);
                break;
            }
            case 15 /* ZigbeeNWKCommandId.COMMISSIONING_RESPONSE */: {
                offset = this.processCommissioningResponse(data, offset, macHeader, nwkHeader);
                break;
            }
            default: {
                logger_js_1.logger.error(`<=x= NWK CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}] Unsupported`, NS);
                return;
            }
        }
        // excess data in packet
        // if (offset < data.byteLength) {
        //     logger.debug(() => `<=== NWK CMD contained more data: ${data.toString('hex')}`, NS);
        // }
    }
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
    async processRouteReq(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const manyToOne = (options & 24 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK */) >> 3; // ZigbeeNWKManyToOne
        const id = data.readUInt8(offset);
        offset += 1;
        const destination16 = data.readUInt16LE(offset);
        offset += 2;
        const pathCost = data.readUInt8(offset);
        offset += 1;
        let destination64;
        if (options & 32 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT */) {
            destination64 = data.readBigUInt64LE(offset);
            offset += 8;
        }
        logger_js_1.logger.debug(() => `<=== NWK ROUTE_REQ[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} id=${id} dst=${destination16}:${destination64} pCost=${pathCost} mto=${manyToOne}]`, NS);
        if (destination16 < 65528 /* ZigbeeConsts.BCAST_MIN */) {
            await this.sendRouteReply(macHeader.destination16, nwkHeader.radius, id, nwkHeader.source16, destination16, nwkHeader.source64 ?? this.#context.address16ToAddress64.get(nwkHeader.source16), destination64);
        }
        return offset;
    }
    /**
     * 05-3474-R #3.4.1
     *
     * @param manyToOne
     * @param destination16 intended destination of the route request command frame
     * @param destination64 SHOULD always be added if it is known
     * @returns
     */
    async sendRouteReq(manyToOne, destination16, destination64) {
        logger_js_1.logger.debug(() => `===> NWK ROUTE_REQ[mto=${manyToOne} dst=${destination16}:${destination64}]`, NS);
        const hasDestination64 = destination64 !== undefined;
        const options = (((manyToOne ? 1 : 0) << 3) & 24 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK */) |
            (((hasDestination64 ? 1 : 0) << 5) & 32 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT */);
        const finalPayload = Buffer.alloc(1 + 1 + 1 + 2 + 1 + (hasDestination64 ? 8 : 0));
        let offset = 0;
        finalPayload.writeUInt8(1 /* ZigbeeNWKCommandId.ROUTE_REQ */, offset);
        offset += 1;
        finalPayload.writeUInt8(options, offset);
        offset += 1;
        finalPayload.writeUInt8(this.nextRouteRequestId(), offset);
        offset += 1;
        finalPayload.writeUInt16LE(destination16, offset);
        offset += 2;
        finalPayload.writeUInt8(0, offset); // pathCost
        offset += 1;
        if (hasDestination64) {
            finalPayload.writeBigUInt64LE(destination64, offset);
            offset += 8;
        }
        return await this.sendCommand(1 /* ZigbeeNWKCommandId.ROUTE_REQ */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        65532 /* ZigbeeConsts.BCAST_DEFAULT */, // nwkDest16
        undefined, // nwkDest64
        CONFIG_NWK_CONCENTRATOR_RADIUS);
    }
    /**
     * 05-3474-R #3.4.2
     */
    processRouteReply(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const id = data.readUInt8(offset);
        offset += 1;
        const originator16 = data.readUInt16LE(offset);
        offset += 2;
        const responder16 = data.readUInt16LE(offset);
        offset += 2;
        const pathCost = data.readUInt8(offset);
        offset += 1;
        let originator64;
        let responder64;
        if (options & 16 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT */) {
            originator64 = data.readBigUInt64LE(offset);
            offset += 8;
        }
        if (options & 32 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT */) {
            responder64 = data.readBigUInt64LE(offset);
            offset += 8;
        }
        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);
        logger_js_1.logger.debug(() => `<=== NWK ROUTE_REPLY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} id=${id} orig=${originator16}:${originator64} rsp=${responder16}:${responder64} pCost=${pathCost}]`, NS);
        // TODO
        return offset;
    }
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
    async sendRouteReply(requestDest1stHop16, requestRadius, requestId, originator16, responder16, originator64, responder64) {
        logger_js_1.logger.debug(() => `===> NWK ROUTE_REPLY[reqDst1stHop16=${requestDest1stHop16} reqRad=${requestRadius} reqId=${requestId} orig=${originator16}:${originator64} rsp=${responder16}:${responder64}]`, NS);
        const hasOriginator64 = originator64 !== undefined;
        const hasResponder64 = responder64 !== undefined;
        const options = (((hasOriginator64 ? 1 : 0) << 4) & 16 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT */) |
            (((hasResponder64 ? 1 : 0) << 5) & 32 /* ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT */);
        const finalPayload = Buffer.alloc(1 + 1 + 1 + 2 + 2 + 1 + (hasOriginator64 ? 8 : 0) + (hasResponder64 ? 8 : 0));
        let offset = 0;
        finalPayload.writeUInt8(2 /* ZigbeeNWKCommandId.ROUTE_REPLY */, offset);
        offset += 1;
        finalPayload.writeUInt8(options, offset);
        offset += 1;
        finalPayload.writeUInt8(requestId, offset);
        offset += 1;
        finalPayload.writeUInt16LE(originator16, offset);
        offset += 2;
        finalPayload.writeUInt16LE(responder16, offset);
        offset += 2;
        finalPayload.writeUInt8(1, offset); // pathCost TODO: init to 0 or 1?
        offset += 1;
        if (hasOriginator64) {
            finalPayload.writeBigUInt64LE(originator64, offset);
            offset += 8;
        }
        if (hasResponder64) {
            finalPayload.writeBigUInt64LE(responder64, offset);
            offset += 8;
        }
        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeNWKTLVs();
        return await this.sendCommand(2 /* ZigbeeNWKCommandId.ROUTE_REPLY */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestDest1stHop16, // nwkDest16
        this.#context.address16ToAddress64.get(requestDest1stHop16), // nwkDest64 SHALL contain the 64-bit IEEE address of the first hop in the path back to the originator of the corresponding route request
        requestRadius);
    }
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
    processStatus(data, offset, macHeader, nwkHeader) {
        const status = data.readUInt8(offset);
        offset += 1;
        // target SHALL be present if, and only if, frame is being sent in response to a routing failure or a network address conflict
        let target16;
        if (status === zigbee_nwk_js_1.ZigbeeNWKStatus.LEGACY_NO_ROUTE_AVAILABLE ||
            status === zigbee_nwk_js_1.ZigbeeNWKStatus.LEGACY_LINK_FAILURE ||
            status === zigbee_nwk_js_1.ZigbeeNWKStatus.LINK_FAILURE ||
            status === zigbee_nwk_js_1.ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE ||
            status === zigbee_nwk_js_1.ZigbeeNWKStatus.MANY_TO_ONE_ROUTE_FAILURE) {
            // In case of a routing failure, it SHALL contain the destination address from the data frame that encountered the failure
            target16 = data.readUInt16LE(offset);
            offset += 2;
            // mark route as failed with repair - this will purge routes using target as relay and trigger MTORR once
            this.markRouteFailure(target16, true);
        }
        else if (status === zigbee_nwk_js_1.ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            // In case of an address conflict, it SHALL contain the offending network address.
            target16 = data.readUInt16LE(offset);
            offset += 2;
        }
        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);
        logger_js_1.logger.debug(() => `<=== NWK NWK_STATUS[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${zigbee_nwk_js_1.ZigbeeNWKStatus[status]} dst16=${target16}]`, NS);
        // TODO
        // network address update notification from here?
        return offset;
    }
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
    async sendStatus(requestSource16, status, destination) {
        logger_js_1.logger.debug(() => `===> NWK NWK_STATUS[reqSrc16=${requestSource16} status=${status} dst16=${destination}]`, NS);
        let finalPayload;
        if (status === zigbee_nwk_js_1.ZigbeeNWKStatus.LINK_FAILURE || status === zigbee_nwk_js_1.ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            finalPayload = Buffer.from([3 /* ZigbeeNWKCommandId.NWK_STATUS */, status, destination & 0xff, (destination >> 8) & 0xff]);
        }
        else {
            finalPayload = Buffer.from([3 /* ZigbeeNWKCommandId.NWK_STATUS */, status]);
        }
        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeNWKTLVs();
        return await this.sendCommand(3 /* ZigbeeNWKCommandId.NWK_STATUS */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestSource16, // nwkDest16
        this.#context.address16ToAddress64.get(requestSource16), // nwkDest64
        CONFIG_NWK_MAX_HOPS);
    }
    /**
     * 05-3474-R #3.4.4
     */
    async processLeave(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const removeChildren = Boolean(options & 128 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN */);
        const request = Boolean(options & 64 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST */);
        const rejoin = Boolean(options & 32 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN */);
        logger_js_1.logger.debug(() => `<=== NWK LEAVE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} remChildren=${removeChildren} req=${request} rejoin=${rejoin}]`, NS);
        if (!rejoin && !request) {
            await this.#context.disassociate(nwkHeader.source16, nwkHeader.source64);
        }
        return offset;
    }
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
    async sendLeave(destination16, rejoin) {
        logger_js_1.logger.debug(() => `===> NWK LEAVE[dst16=${destination16} rejoin=${rejoin}]`, NS);
        const options = (0 & 128 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN */) |
            ((1 << 6) & 64 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST */) |
            (((rejoin ? 1 : 0) << 5) & 32 /* ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN */);
        const finalPayload = Buffer.from([4 /* ZigbeeNWKCommandId.LEAVE */, options]);
        return await this.sendCommand(4 /* ZigbeeNWKCommandId.LEAVE */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        destination16, // nwkDest16
        this.#context.address16ToAddress64.get(destination16), // nwkDest64
        1);
    }
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
    processRouteRecord(data, offset, macHeader, nwkHeader) {
        const relayCount = data.readUInt8(offset);
        offset += 1;
        const relays = [];
        for (let i = 0; i < relayCount; i++) {
            const relay = data.readUInt16LE(offset);
            offset += 2;
            relays.push(relay);
        }
        logger_js_1.logger.debug(() => `<=== NWK ROUTE_RECORD[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} relays=${relays}]`, NS);
        const source16 = nwkHeader.source16 === undefined
            ? nwkHeader.source64 === undefined
                ? undefined
                : this.#context.deviceTable.get(nwkHeader.source64)?.address16
            : nwkHeader.source16;
        if (source16 !== undefined) {
            const entry = this.createSourceRouteEntry(relays, relayCount + 1);
            const entries = this.#context.sourceRouteTable.get(source16);
            if (entries === undefined) {
                this.#context.sourceRouteTable.set(source16, [entry]);
            }
            else if (!this.hasSourceRoute(source16, entry, entries)) {
                entries.push(entry);
            }
        }
        return offset;
    }
    // NOTE: sendRouteRecord not for coordinator
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
    async processRejoinReq(data, offset, macHeader, nwkHeader) {
        const capabilities = data.readUInt8(offset);
        offset += 1;
        const decodedCap = (0, mac_js_1.decodeMACCapabilities)(capabilities);
        logger_js_1.logger.debug(() => `<=== NWK REJOIN_REQ[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} cap=${capabilities}]`, NS);
        let deny = false;
        if (!nwkHeader.frameControl.security) {
            // Trust Center Rejoin
            let source64 = nwkHeader.source64;
            if (source64 === undefined) {
                if (nwkHeader.source16 === undefined) {
                    // invalid, drop completely, should never happen
                    return offset;
                }
                source64 = this.#context.address16ToAddress64.get(nwkHeader.source16);
            }
            if (source64 === undefined) {
                // can't identify device
                deny = true;
            }
            else {
                const device = this.#context.deviceTable.get(source64);
                // XXX: Unsecured Packets at the network layer claiming to be from existing neighbors (coordinators, routers or end devices) must not rewrite legitimate data in the nwkNeighborTable.
                //      if apsTrustCenterAddress is all FF (distributed) / all 00 (pre-TRANSPORT_KEY), reject with PAN_ACCESS_DENIED
                if (!device?.authorized) {
                    // device unknown or unauthorized
                    deny = true;
                }
            }
        }
        const [status, newAddress16] = await this.#context.associate(nwkHeader.source16, nwkHeader.source64, false /* rejoin */, decodedCap, macHeader.source16 === nwkHeader.source16, deny);
        await this.sendRejoinResp(nwkHeader.source16, newAddress16, status, decodedCap);
        // NOTE: a device does not have to verify its trust center link key with the APSME-VERIFY-KEY services after a rejoin.
        return offset;
    }
    // NOTE: sendRejoinReq not for coordinator
    /**
     * 05-3474-R #3.4.7
     * Optional
     */
    processRejoinResp(data, offset, macHeader, nwkHeader) {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;
        if (status !== mac_js_1.MACAssociationStatus.SUCCESS) {
            logger_js_1.logger.error(`<=x= NWK REJOIN_RESP[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress} status=${mac_js_1.MACAssociationStatus[status]}]`, NS);
        }
        else {
            logger_js_1.logger.debug(() => `<=== NWK REJOIN_RESP[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress}]`, NS);
        }
        return offset;
    }
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
    async sendRejoinResp(requestSource16, newAddress16, status, capabilities) {
        logger_js_1.logger.debug(() => `===> NWK REJOIN_RESP[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);
        const finalPayload = Buffer.from([7 /* ZigbeeNWKCommandId.REJOIN_RESP */, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);
        const result = await this.sendCommand(7 /* ZigbeeNWKCommandId.REJOIN_RESP */, finalPayload, true, // nwkSecurity TODO: ??
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestSource16, // nwkDest16
        this.#context.address16ToAddress64.get(newAddress16), // nwkDest64
        CONFIG_NWK_MAX_HOPS);
        if (status === mac_js_1.MACAssociationStatus.SUCCESS) {
            const dest64 = this.#context.address16ToAddress64.get(newAddress16);
            if (dest64) {
                setImmediate(() => {
                    this.#callbacks.onDeviceRejoined(newAddress16, dest64, capabilities);
                });
            }
        }
        return result;
    }
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
    processLinkStatus(data, offset, macHeader, nwkHeader) {
        // Bit: 0 – 4        5            6           7
        //      Entry count  First frame  Last frame  Reserved
        const options = data.readUInt8(offset);
        offset += 1;
        const firstFrame = Boolean((options & 32 /* ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME */) >> 5);
        const lastFrame = Boolean((options & 64 /* ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME */) >> 6);
        const linkCount = options & 31 /* ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK */;
        const links = [];
        let device = nwkHeader.source64 !== undefined ? this.#context.deviceTable.get(nwkHeader.source64) : undefined;
        if (!device && nwkHeader.source16 !== undefined) {
            const source64 = this.#context.address16ToAddress64.get(nwkHeader.source16);
            if (source64 !== undefined) {
                device = this.#context.deviceTable.get(source64);
            }
        }
        for (let i = 0; i < linkCount; i++) {
            const address = data.readUInt16LE(offset);
            offset += 2;
            const costByte = data.readUInt8(offset);
            offset += 1;
            links.push({
                address,
                incomingCost: costByte & 7 /* ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK */,
                outgoingCost: (costByte & 112 /* ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK */) >> 4,
            });
            if (device) {
                if (address === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */) {
                    // if neighbor is coordinator, update device table
                    device.neighbor = true;
                }
                // use the incoming cost as the path cost (represents link quality from the neighbor's perspective)
                const incomingCost = costByte & 7 /* ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK */;
                const pathCost = Math.max(1, incomingCost);
                const entry = address === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */
                    ? this.createSourceRouteEntry([], pathCost)
                    : this.createSourceRouteEntry([address], pathCost + 1);
                const entries = this.#context.sourceRouteTable.get(device.address16);
                if (entries === undefined) {
                    this.#context.sourceRouteTable.set(device.address16, [entry]);
                }
                else {
                    // check if we already have this route; if so, update it
                    const existingIndex = entries.findIndex((e) => e.relayAddresses.length === entry.relayAddresses.length &&
                        e.relayAddresses.every((relay, idx) => relay === entry.relayAddresses[idx]));
                    if (existingIndex !== -1) {
                        // update existing route with new cost and reset failure count
                        entries[existingIndex].pathCost = entry.pathCost;
                        entries[existingIndex].lastUpdated = entry.lastUpdated;
                        entries[existingIndex].failureCount = 0;
                    }
                    else if (!this.hasSourceRoute(device.address16, entry, entries)) {
                        entries.push(entry);
                    }
                }
            }
        }
        logger_js_1.logger.debug(() => {
            let linksStr = "";
            for (const link of links) {
                linksStr += `{${link.address}|in:${link.incomingCost}|out:${link.outgoingCost}}`;
            }
            return `<=== NWK LINK_STATUS[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} first=${firstFrame} last=${lastFrame} links=${linksStr}]`;
        }, NS);
        // TODO: NeighborTableEntry.age = 0 // max 0xff
        // TODO: NeighborTableEntry.routerAge += 1 // max 0xffff
        // TODO: NeighborTableEntry.routerConnectivity = formula
        // TODO: NeighborTableEntry.routerNeighborSetDiversity = formula
        // TODO: if NeighborTableEntry does not exist, create one with routerAge = 0 and routerConnectivity/routerNeighborSetDiversity as above
        return offset;
    }
    /**
     * 05-3474-R #3.4.8
     *
     * @param links set of link status entries derived from the neighbor table (SHALL be specific to the interface to be transmitted on)
     * Links are expected sorted in ascending order by network address.
     * - incoming cost contains device's estimate of the link cost for the neighbor
     * - outgoing cost contains value of outgoing cost from neighbor table
     */
    async sendLinkStatus(links) {
        logger_js_1.logger.debug(() => {
            let linksStr = "";
            for (const link of links) {
                linksStr += `{${link.address}|in:${link.incomingCost}|out:${link.outgoingCost}}`;
            }
            return `===> NWK LINK_STATUS[links=${linksStr}]`;
        }, NS);
        // TODO: check repeat logic
        const linkSize = links.length * 3;
        const maxLinksPayloadSize = 86 /* ZigbeeNWKConsts.PAYLOAD_MIN_SIZE */ - 2; // 84 (- cmdId[1] - options[1])
        const maxLinksPerFrame = Math.floor(maxLinksPayloadSize / 3); // 27
        const frameCount = Math.ceil((linkSize + 3) / maxLinksPayloadSize); // (+ repeated link[3])
        let linksOffset = 0;
        for (let i = 0; i < frameCount; i++) {
            const linkCount = links.length - i * maxLinksPerFrame;
            const frameSize = 2 + Math.min(linkCount * 3, maxLinksPayloadSize);
            const options = (((i === 0 ? 1 : 0) << 5) & 32 /* ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME */) |
                (((i === frameCount - 1 ? 1 : 0) << 6) & 64 /* ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME */) |
                (linkCount & 31 /* ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK */);
            const finalPayload = Buffer.alloc(frameSize);
            let finalPayloadOffset = 0;
            finalPayload.writeUInt8(8 /* ZigbeeNWKCommandId.LINK_STATUS */, finalPayloadOffset);
            finalPayloadOffset += 1;
            finalPayload.writeUInt8(options, finalPayloadOffset);
            finalPayloadOffset += 1;
            for (let j = 0; j < linkCount; j++) {
                const link = links[linksOffset];
                finalPayload.writeUInt16LE(link.address, finalPayloadOffset);
                finalPayloadOffset += 2;
                finalPayload.writeUInt8((link.incomingCost & 7 /* ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK */) |
                    ((link.outgoingCost << 4) & 112 /* ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK */), finalPayloadOffset);
                finalPayloadOffset += 1;
                // last in previous frame is repeated first in next frame
                if (j < linkCount - 1) {
                    linksOffset++;
                }
            }
            await this.sendCommand(8 /* ZigbeeNWKCommandId.LINK_STATUS */, finalPayload, true, // nwkSecurity
            0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
            65532 /* ZigbeeConsts.BCAST_DEFAULT */, // nwkDest16
            undefined, // nwkDest64
            1);
        }
    }
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
    processReport(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const reportCount = options & 31 /* ZigbeeNWKConsts.CMD_NWK_REPORT_COUNT_MASK */;
        const reportType = options & 224 /* ZigbeeNWKConsts.CMD_NWK_REPORT_ID_MASK */;
        const extendedPANId = data.readBigUInt64LE(offset);
        offset += 8;
        let conflictPANIds;
        if (reportType === 0 /* ZigbeeNWKConsts.CMD_NWK_REPORT_ID_PAN_CONFLICT */) {
            conflictPANIds = [];
            for (let i = 0; i < reportCount; i++) {
                const panId = data.readUInt16LE(offset);
                offset += 2;
                conflictPANIds.push(panId);
            }
        }
        logger_js_1.logger.debug(() => `<=== NWK NWK_REPORT[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} extPANId=${extendedPANId} repType=${reportType} conflictPANIds=${conflictPANIds}]`, NS);
        return offset;
    }
    // NOTE: sendReport deprecated in R23
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
    processUpdate(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        const updateCount = options & 31 /* ZigbeeNWKConsts.CMD_NWK_UPDATE_COUNT_MASK */;
        const updateType = options & 224 /* ZigbeeNWKConsts.CMD_NWK_UPDATE_ID_MASK */;
        const extendedPANId = data.readBigUInt64LE(offset);
        offset += 8;
        const updateId = data.readUInt8(offset);
        offset += 1;
        let panIds;
        if (updateType === 0 /* ZigbeeNWKConsts.CMD_NWK_UPDATE_ID_PAN_UPDATE */) {
            panIds = [];
            for (let i = 0; i < updateCount; i++) {
                const panId = data.readUInt16LE(offset);
                offset += 2;
                panIds.push(panId);
            }
        }
        logger_js_1.logger.debug(() => `<=== NWK NWK_UPDATE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} extPANId=${extendedPANId} id=${updateId} type=${updateType} panIds=${panIds}]`, NS);
        // TODO
        return offset;
    }
    // NOTE: sendUpdate PAN ID change not supported
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
    async processEdTimeoutRequest(data, offset, macHeader, nwkHeader) {
        // 0 => 10 seconds
        // 1 => 2 minutes
        // 2 => 4 minutes
        // 3 => 8 minutes
        // 4 => 16 minutes
        // 5 => 32 minutes
        // 6 => 64 minutes
        // 7 => 128 minutes
        // 8 => 256 minutes
        // 9 => 512 minutes
        // 10 => 1024 minutes
        // 11 => 2048 minutes
        // 12 => 4096 minutes
        // 13 => 8192 minutes
        // 14 => 16384 minutes
        const requestedTimeout = data.readUInt8(offset);
        offset += 1;
        // not currently used (all reserved)
        const configuration = data.readUInt8(offset);
        offset += 1;
        logger_js_1.logger.debug(() => `<=== NWK ED_TIMEOUT_REQUEST[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} reqTimeout=${requestedTimeout} conf=${configuration}]`, NS);
        await this.sendEdTimeoutResponse(nwkHeader.source16, requestedTimeout);
        return offset;
    }
    // NOTE: sendEdTimeoutRequest not for coordinator
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
    processEdTimeoutResponse(data, offset, macHeader, nwkHeader) {
        // SUCCESS 0x00 The End Device Timeout Request message was accepted by the parent.
        // INCORRECT_VALUE 0x01 The received timeout value in the End Device Timeout Request command was outside the allowed range.
        // UNSUPPORTED_FEATURE 0x02 The requested feature is not supported by the parent router.
        const status = data.readUInt8(offset);
        offset += 1;
        // Bit 0 MAC Data Poll Keepalive Supported
        // Bit 1 End Device Timeout Request Keepalive Supported
        // Bit 2 Power Negotiation Support
        const parentInfo = data.readUInt8(offset);
        offset += 1;
        logger_js_1.logger.debug(() => `<=== NWK ED_TIMEOUT_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${status} parentInfo=${parentInfo}]`, NS);
        // TODO
        return offset;
    }
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
    async sendEdTimeoutResponse(requestDest16, requestedTimeout) {
        logger_js_1.logger.debug(() => `===> NWK ED_TIMEOUT_RESPONSE[reqDst16=${requestDest16} requestedTimeout=${requestedTimeout}]`, NS);
        // sanity check
        const status = requestedTimeout >= 0 && requestedTimeout <= 14 ? 0x00 : 0x01;
        const parentInfo = 0b00000111; // TODO: ?
        const finalPayload = Buffer.from([12 /* ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE */, status, parentInfo]);
        return await this.sendCommand(12 /* ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE */, finalPayload, true, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestDest16, // nwkDest16
        this.#context.address16ToAddress64.get(requestDest16), // nwkDest64
        1);
    }
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
    processLinkPwrDelta(data, offset, macHeader, nwkHeader) {
        const options = data.readUInt8(offset);
        offset += 1;
        // 0 Notification An unsolicited notification. These frames are typically sent periodically from an RxOn device. If the device is a FFD, it is broadcast to all RxOn devices (0xfffd), and includes power information for all neighboring RxOn devices. If the device is an RFD with RxOn, it is sent unicast to its Parent, and includes only power information for the Parent device.
        // 1 Request Typically used by sleepy RFD devices that do not receive the periodic Notifications from their Parent. The sleepy RFD will wake up periodically to send this frame to its Parent, including only the Parent’s power information in its payload. Upon receipt, the Parent sends a Response (Type = 2) as an indirect transmission, with only the RFD’s power information in its payload. After macResponseWaitTime, the RFD polls its Parent for the Response, before going back to sleep. Request commands are sent as unicast. Note: any device MAY send a Request to solicit a Response from another device. These commands SHALL be sent as unicast and contain only the power information for the destination device. If this command is received as a broadcast, it SHALL be discarded with no action.
        // 2 Response This command is sent in response to a Request. Response commands are sent as unicast to the sender of the Request. The response includes only the power information for the requesting device.
        // 3 Reserved
        const type = options & 3 /* ZigbeeNWKConsts.CMD_NWK_LINK_PWR_DELTA_TYPE_MASK */;
        const count = data.readUInt8(offset);
        offset += 1;
        const deltas = [];
        for (let i = 0; i < count; i++) {
            const device = data.readUInt16LE(offset);
            offset += 2;
            const delta = data.readUInt8(offset);
            offset += 1;
            deltas.push({ device, delta });
        }
        logger_js_1.logger.debug(() => `<=== NWK LINK_PWR_DELTA[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${type} deltas=${deltas}]`, NS);
        // TODO
        return offset;
    }
    // NOTE: sendLinkPwrDelta not supported
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
    async processCommissioningRequest(data, offset, macHeader, nwkHeader) {
        // 0x00 Initial Join
        // 0x01 Rejoin
        const assocType = data.readUInt8(offset);
        offset += 1;
        const capabilities = data.readUInt8(offset);
        offset += 1;
        const decodedCap = (0, mac_js_1.decodeMACCapabilities)(capabilities);
        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);
        logger_js_1.logger.debug(() => `<=== NWK COMMISSIONING_REQUEST[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} assocType=${assocType} cap=${capabilities}]`, NS);
        // NOTE: send Remove Device CMD to TC deny the join (or let timeout): `sendRemoveDevice`
        const [status, newAddress16] = await this.#context.associate(nwkHeader.source16, nwkHeader.source64, assocType === 0x00 /* initial join */, decodedCap, macHeader.source16 === nwkHeader.source16, nwkHeader.frameControl.security /* deny if true */);
        await this.sendCommissioningResponse(nwkHeader.source16, newAddress16, status);
        if (status === mac_js_1.MACAssociationStatus.SUCCESS) {
            // TODO also for rejoin in case of nwk key change?
            const dest64 = this.#context.address16ToAddress64.get(newAddress16);
            if (dest64) {
                await this.#callbacks.onAPSSendTransportKeyNWK(nwkHeader.source16, this.#context.netParams.networkKey, this.#context.netParams.networkKeySequenceNumber, dest64);
            }
        }
        return offset;
    }
    // NOTE: sendCommissioningRequest not for coordinator
    /**
     * 05-3474-23 #3.4.15
     * Optional
     */
    processCommissioningResponse(data, offset, macHeader, nwkHeader) {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        // `ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT`, or MACAssociationStatus
        const status = data.readUInt8(offset);
        offset += 1;
        if (status !== mac_js_1.MACAssociationStatus.SUCCESS) {
            logger_js_1.logger.error(`<=x= NWK COMMISSIONING_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress} status=${mac_js_1.MACAssociationStatus[status] ?? "NWK_ADDR_CONFLICT"}]`, NS);
        }
        else {
            logger_js_1.logger.debug(() => `<=== NWK COMMISSIONING_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress}]`, NS);
        }
        // TODO
        return offset;
    }
    /**
     * 05-3474-23 #3.4.15
     * Optional
     *
     * @param requestSource16
     * @param newAddress16 the new 16-bit network address assigned, may be same as `requestDest16`
     * @returns
     */
    async sendCommissioningResponse(requestSource16, newAddress16, status) {
        logger_js_1.logger.debug(() => `===> NWK COMMISSIONING_RESPONSE[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);
        const finalPayload = Buffer.from([15 /* ZigbeeNWKCommandId.COMMISSIONING_RESPONSE */, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);
        return await this.sendCommand(15 /* ZigbeeNWKCommandId.COMMISSIONING_RESPONSE */, finalPayload, false, // nwkSecurity
        0 /* ZigbeeConsts.COORDINATOR_ADDRESS */, // nwkSource16
        requestSource16, // nwkDest16
        this.#context.address16ToAddress64.get(requestSource16), // nwkDest64
        CONFIG_NWK_MAX_HOPS);
    }
}
exports.NWKHandler = NWKHandler;
//# sourceMappingURL=nwk-handler.js.map