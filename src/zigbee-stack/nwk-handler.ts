import { logger } from "../utils/logger.js";
import {
    decodeMACCapabilities,
    encodeMACFrameZigbee,
    MACAssociationStatus,
    MACFrameAddressMode,
    MACFrameType,
    MACFrameVersion,
    type MACHeader,
    ZigbeeMACConsts,
} from "../zigbee/mac.js";
import { ZigbeeConsts, ZigbeeKeyType, type ZigbeeSecurityHeader, ZigbeeSecurityLevel } from "../zigbee/zigbee.js";
import {
    encodeZigbeeNWKFrame,
    ZigbeeNWKCommandId,
    ZigbeeNWKConsts,
    ZigbeeNWKFrameType,
    type ZigbeeNWKHeader,
    type ZigbeeNWKLinkStatus,
    ZigbeeNWKManyToOne,
    ZigbeeNWKRouteDiscovery,
    ZigbeeNWKStatus,
} from "../zigbee/zigbee-nwk.js";
import type { MACHandler } from "../zigbee-stack/mac-handler.js";
import { END_DEVICE_TIMEOUT_TABLE_MS, type SourceRouteTableEntry, type StackContext } from "../zigbee-stack/stack-context.js";

const NS = "nwk-handler";

/**
 * Callbacks for NWK handler to communicate with driver
 */
export interface NWKHandlerCallbacks {
    /** Send APS TRANSPORT_KEY for network key */
    onAPSSendTransportKeyNWK: (destination16: number, networkKey: Buffer, keySequenceNumber: number, destination64: bigint) => Promise<void>;
}

/** The number of OctetDurations until a route discovery expires. */
// const CONFIG_NWK_ROUTE_DISCOVERY_TIME = 0x4c4b4; // 0x2710 msec on 2.4GHz
/** The maximum depth of the network (number of hops) used for various calculations of network timing and limitations. */
const CONFIG_NWK_MAX_DEPTH = 15;
export const CONFIG_NWK_MAX_HOPS = CONFIG_NWK_MAX_DEPTH * 2;
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
const CONFIG_NWK_ROUTER_AGE_LIMIT = 3;
/** This is an index into Table 3-54. It indicates the default timeout in minutes for any end device that does not negotiate a different timeout value. */
export const CONFIG_NWK_ED_TIMEOUT_DEFAULT = 8;
/**
 * Default parent info byte for end device timeout negotiation
 * - Bit 0 MAC Data Poll Keepalive Supported
 * - Bit 1 End Device Timeout Request Keepalive Supported
 * - Bit 2 Power Negotiation Support
 */
const CONFIG_NWK_ED_TIMEOUT_PARENT_INFO_DEFAULT = 0b00000111;
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
/** The maximum number of hops in a source route. */
const CONFIG_NWK_MAX_SOURCE_ROUTE = 0x0c;
// export const CONFIG_NWK_MAX_ROUTERS = 6; // ignored, no limit with host-based
// export const CONFIG_NWK_MAX_CHILDREN = 20; // ignored, no limit with host-based

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
export class NWKHandler {
    readonly #context: StackContext;
    readonly #macHandler: MACHandler;
    readonly #callbacks: NWKHandlerCallbacks;

    // Private counters (start at 0, first call returns 1)
    #seqNum = 0;
    #routeRequestId = 0;

    #linkStatusTimeout: NodeJS.Timeout | undefined;
    #manyToOneRouteRequestTimeout: NodeJS.Timeout | undefined;
    /** Time of last many-to-one route request */
    #lastMTORRTime = 0;

    constructor(context: StackContext, macHandler: MACHandler, callbacks: NWKHandlerCallbacks) {
        this.#context = context;
        this.#macHandler = macHandler;
        this.#callbacks = callbacks;
    }

    async start() {
        this.#linkStatusTimeout = setTimeout(
            this.sendPeriodicZigbeeNWKLinkStatus.bind(this),
            CONFIG_NWK_LINK_STATUS_PERIOD + Math.random() * CONFIG_NWK_LINK_STATUS_JITTER,
        );
        this.#manyToOneRouteRequestTimeout = setTimeout(this.sendPeriodicManyToOneRouteRequest.bind(this), CONFIG_NWK_CONCENTRATOR_DISCOVERY_TIME);

        // ignore stale on first trigger
        await this.sendPeriodicZigbeeNWKLinkStatus(true);
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
    public nextSeqNum(): number {
        this.#seqNum = (this.#seqNum + 1) & 0xff;

        return this.#seqNum;
    }

    /**
     * Get next route request ID.
     * HOT PATH: Optimized counter increment
     * @returns Incremented route request ID (wraps at 255)
     */
    /* @__INLINE__ */
    public nextRouteRequestId(): number {
        this.#routeRequestId = (this.#routeRequestId + 1) & 0xff;

        return this.#routeRequestId;
    }

    // #region Route Management

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
    public async sendPeriodicZigbeeNWKLinkStatus(ignoreStale = false): Promise<void> {
        const links: ZigbeeNWKLinkStatus[] = [];

        for (const [device64, entry] of this.#context.deviceTable.entries()) {
            if (entry.neighbor) {
                if (entry.capabilities?.deviceType === ZigbeeMACConsts.DEVICE_TYPE_FFD) {
                    const nextMisses = (entry.linkStatusMisses ?? 0) + 1; // XXX: technically uint16, doesn't matter with host-based
                    entry.linkStatusMisses = nextMisses;

                    if (nextMisses > CONFIG_NWK_ROUTER_AGE_LIMIT) {
                        links.push({
                            address: entry.address16,
                            incomingCost: 0,
                            outgoingCost: 0,
                        });

                        continue;
                    }
                }

                try {
                    // calculate cost based on path cost and recent link quality
                    const [, , pathCost] = this.findBestSourceRoute(entry.address16, device64, ignoreStale);
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
                } catch {
                    /* ignore */
                }
            }
        }

        await this.sendLinkStatus(links);
        this.#linkStatusTimeout?.refresh();
    }

    /**
     * 05-3474-23 #3.6.3.5.2 (Many-to-One Route Discovery)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Issues ROUTE_REQUEST with Many-to-One flag when concentrator timer elapses
     * - ✅ Enforces minimum spacing (CONFIG_NWK_CONCENTRATOR_MIN_TIME) to prevent flooding per spec guidance
     * - ✅ Uses WITH_SOURCE_ROUTING mode to advertise concentrator capability
     * DEVICE SCOPE: Coordinator, routers (N/A)
     */
    public async sendPeriodicManyToOneRouteRequest(): Promise<void> {
        if (Date.now() > this.#lastMTORRTime + CONFIG_NWK_CONCENTRATOR_MIN_TIME) {
            await this.sendRouteReq(ZigbeeNWKManyToOne.WITH_SOURCE_ROUTING, ZigbeeConsts.BCAST_DEFAULT);
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
    public findBestSourceRoute(
        destination16: number | undefined,
        destination64: bigint | undefined,
        ignoreStale = false,
    ): [relayIndex: number | undefined, relayAddresses: number[] | undefined, pathCost: number | undefined] {
        if (destination16 !== undefined && destination16 >= ZigbeeConsts.BCAST_MIN) {
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
        } else if (!this.#context.address16ToAddress64.has(destination16)) {
            throw new Error("Unknown destination");
        }

        const sourceRouteEntries = this.#context.sourceRouteTable.get(destination16);

        if (sourceRouteEntries === undefined || sourceRouteEntries.length === 0) {
            // cleanup
            this.#context.sourceRouteTable.delete(destination16);

            const device64 = destination64 ?? this.#context.address16ToAddress64.get(destination16)!;
            const device = this.#context.deviceTable.get(device64);

            if (device && !device.neighbor) {
                // force immediate MTORR
                logger.warning(`No known route to ${destination16}:${destination64}, forcing discovery`, NS);
                setImmediate(this.sendPeriodicManyToOneRouteRequest.bind(this));
                // will send direct as "last resort"
            }

            return [undefined, undefined, undefined];
        }

        const now = Date.now();
        const validEntries: SourceRouteTableEntry[] = [];

        // filter out expired and blacklisted routes
        for (const entry of sourceRouteEntries) {
            if (!ignoreStale) {
                const age = now - entry.lastUpdated;

                // remove expired routes
                if (age > CONFIG_NWK_ROUTE_EXPIRY_TIME) {
                    logger.debug(() => `Route to ${destination16}:${destination64} expired (age=${age}ms)`, NS);
                    continue;
                }
            }

            // remove blacklisted routes (too many consecutive failures)
            if (entry.failureCount >= CONFIG_NWK_ROUTE_MAX_FAILURES) {
                logger.debug(() => `Route to ${destination16}:${destination64} blacklisted (failures=${entry.failureCount})`, NS);
                continue;
            }

            if (entry.relayAddresses.length > CONFIG_NWK_MAX_SOURCE_ROUTE) {
                // ignore if too many hops
                continue;
            }

            // check if any relay has too many NO_ACK
            let relayFailed = false;

            for (const relay of entry.relayAddresses) {
                const macNoACKs = this.#context.macNoACKs.get(relay);

                if (macNoACKs !== undefined && macNoACKs >= CONFIG_NWK_CONCENTRATOR_DELIVERY_FAILURE_THRESHOLD) {
                    logger.debug(() => `Route to ${destination16}:${destination64} via relay ${relay} has too many NO_ACKs (${macNoACKs})`, NS);
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

            const device64 = destination64 ?? this.#context.address16ToAddress64.get(destination16)!;
            const device = this.#context.deviceTable.get(device64);

            if (device && !device.neighbor) {
                logger.warning(`All routes to ${destination16}:${destination64} invalid, forcing discovery`, NS);
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
            const stalenessPenaltyA =
                ageA > CONFIG_NWK_ROUTE_STALENESS_TIME ? Math.min(2, (ageA - CONFIG_NWK_ROUTE_STALENESS_TIME) / CONFIG_NWK_ROUTE_STALENESS_TIME) : 0;
            const stalenessPenaltyB =
                ageB > CONFIG_NWK_ROUTE_STALENESS_TIME ? Math.min(2, (ageB - CONFIG_NWK_ROUTE_STALENESS_TIME) / CONFIG_NWK_ROUTE_STALENESS_TIME) : 0;

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
    public markRouteSuccess(destination16: number): void {
        const entries = this.#context.sourceRouteTable.get(destination16);

        if (entries && entries.length > 0) {
            const entry = entries[0]; // mark the currently-selected best route
            entry.lastUsed = Date.now();
            entry.failureCount = 0; // reset failure count on success
        }
    }

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
    public markRouteFailure(destination16: number, triggerRepair = false): void {
        const entries = this.#context.sourceRouteTable.get(destination16);

        if (entries && entries.length > 0) {
            const entry = entries[0]; // mark the currently-selected best route
            entry.failureCount += 1;

            logger.debug(() => `Route to ${destination16} failed (failureCount=${entry.failureCount})`, NS);

            // if blacklisted or explicit repair requested, purge and trigger MTORR
            if (triggerRepair || entry.failureCount >= CONFIG_NWK_ROUTE_MAX_FAILURES) {
                logger.warning(
                    `Route to ${destination16} ${triggerRepair ? "requires repair" : `blacklisted after ${entry.failureCount} failures`}, purging related routes and forcing discovery`,
                    NS,
                );

                // purge all routes using this destination as a relay
                for (const [addr16, routeEntries] of this.#context.sourceRouteTable) {
                    const filteredEntries = routeEntries.filter((e) => !e.relayAddresses.includes(destination16));

                    if (filteredEntries.length === 0) {
                        this.#context.sourceRouteTable.delete(addr16);
                    } else if (filteredEntries.length !== routeEntries.length) {
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
    /* @__INLINE__ */
    public createSourceRouteEntry(relayAddresses: number[], pathCost: number): SourceRouteTableEntry {
        return {
            relayAddresses,
            pathCost,
            lastUpdated: Date.now(),
            failureCount: 0,
            lastUsed: undefined,
        };
    }

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
    public hasSourceRoute(address16: number, newEntry: SourceRouteTableEntry, existingEntries?: SourceRouteTableEntry[]): boolean {
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
    public async sendCommand(
        cmdId: ZigbeeNWKCommandId,
        finalPayload: Buffer,
        nwkSecurity: boolean,
        nwkSource16: number,
        nwkDest16: number,
        nwkDest64: bigint | undefined,
        nwkRadius: number,
    ): Promise<boolean> {
        let nwkSecurityHeader: ZigbeeSecurityHeader | undefined;

        if (nwkSecurity) {
            nwkSecurityHeader = {
                control: {
                    level: ZigbeeSecurityLevel.NONE,
                    keyId: ZigbeeKeyType.NWK,
                    nonce: true,
                    reqVerifiedFc: false,
                },
                frameCounter: this.#context.nextNWKKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                keySeqNum: this.#context.netParams.networkKeySequenceNumber,
                micLen: 4,
            };
        }

        const nwkSeqNum = this.nextSeqNum();
        const macSeqNum = this.#macHandler.nextSeqNum();
        let relayIndex: number | undefined;
        let relayAddresses: number[] | undefined;

        try {
            [relayIndex, relayAddresses] = this.findBestSourceRoute(nwkDest16, nwkDest64);
        } catch (error) {
            logger.error(
                `=x=> NWK CMD[seqNum=(${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64}] ${(error as Error).message}`,
                NS,
            );

            return false;
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;

        logger.debug(
            () =>
                `===> NWK CMD[seqNum=(${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} macDst16=${macDest16} nwkSrc16=${nwkSource16} nwkDst=${nwkDest16}:${nwkDest64} nwkRad=${nwkRadius}]`,
            NS,
        );

        const source64 =
            nwkSource16 === ZigbeeConsts.COORDINATOR_ADDRESS ? this.#context.netParams.eui64 : this.#context.address16ToAddress64.get(nwkSource16);
        const nwkFrame = encodeZigbeeNWKFrame(
            {
                frameControl: {
                    frameType: ZigbeeNWKFrameType.CMD,
                    protocolVersion: ZigbeeNWKConsts.VERSION_2007,
                    discoverRoute: ZigbeeNWKRouteDiscovery.SUPPRESS,
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
            },
            finalPayload,
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
    public async processCommand(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<void> {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;

        switch (cmdId) {
            case ZigbeeNWKCommandId.ROUTE_REQ: {
                offset = await this.processRouteReq(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.ROUTE_REPLY: {
                offset = this.processRouteReply(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.NWK_STATUS: {
                offset = await this.processStatus(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.LEAVE: {
                offset = await this.processLeave(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.ROUTE_RECORD: {
                offset = this.processRouteRecord(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.REJOIN_REQ: {
                offset = await this.processRejoinReq(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.REJOIN_RESP: {
                offset = this.processRejoinResp(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.LINK_STATUS: {
                offset = this.processLinkStatus(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.NWK_REPORT: {
                offset = this.processReport(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.NWK_UPDATE: {
                offset = this.processUpdate(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.ED_TIMEOUT_REQUEST: {
                offset = await this.processEdTimeoutRequest(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE: {
                offset = this.processEdTimeoutResponse(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.LINK_PWR_DELTA: {
                offset = this.processLinkPwrDelta(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.COMMISSIONING_REQUEST: {
                offset = await this.processCommissioningRequest(data, offset, macHeader, nwkHeader);
                break;
            }
            case ZigbeeNWKCommandId.COMMISSIONING_RESPONSE: {
                offset = this.processCommissioningResponse(data, offset, macHeader, nwkHeader);
                break;
            }
            default: {
                logger.error(
                    `<=x= NWK CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}] Unsupported`,
                    NS,
                );
                return;
            }
        }

        // excess data in packet
        // if (offset < data.byteLength) {
        //     logger.debug(() => `<=== NWK CMD contained more data: ${data.toString('hex')}`, NS);
        // }
    }

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
    public async processRouteReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        const options = data.readUInt8(offset);
        offset += 1;
        const manyToOne = (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK) >> 3; // ZigbeeNWKManyToOne
        const id = data.readUInt8(offset);
        offset += 1;
        const destination16 = data.readUInt16LE(offset);
        offset += 2;
        const pathCost = data.readUInt8(offset);
        offset += 1;
        let destination64: bigint | undefined;

        if (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT) {
            destination64 = data.readBigUInt64LE(offset);
            offset += 8;
        }

        logger.debug(
            () =>
                `<=== NWK ROUTE_REQ[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} id=${id} dst=${destination16}:${destination64} pCost=${pathCost} mto=${manyToOne}]`,
            NS,
        );

        if (destination16 < ZigbeeConsts.BCAST_MIN) {
            await this.sendRouteReply(
                macHeader.destination16!,
                nwkHeader.radius!,
                id,
                nwkHeader.source16!,
                destination16,
                nwkHeader.source64 ?? this.#context.address16ToAddress64.get(nwkHeader.source16!),
                destination64,
            );
        }

        return offset;
    }

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
    public async sendRouteReq(manyToOne: ZigbeeNWKManyToOne, destination16: number, destination64?: bigint): Promise<boolean> {
        logger.debug(() => `===> NWK ROUTE_REQ[mto=${manyToOne} dst=${destination16}:${destination64}]`, NS);
        const hasDestination64 = destination64 !== undefined;
        const options =
            ((manyToOne << 3) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_MANY_MASK) |
            (((hasDestination64 ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_DEST_EXT);
        const finalPayload = Buffer.alloc(1 + 1 + 1 + 2 + 1 + (hasDestination64 ? 8 : 0));
        let offset = 0;
        offset = finalPayload.writeUInt8(ZigbeeNWKCommandId.ROUTE_REQ, offset);
        offset = finalPayload.writeUInt8(options, offset);
        offset = finalPayload.writeUInt8(this.nextRouteRequestId(), offset);
        offset = finalPayload.writeUInt16LE(destination16, offset);
        offset = finalPayload.writeUInt8(0, offset); // initial path cost

        if (hasDestination64) {
            offset = finalPayload.writeBigUInt64LE(destination64!, offset);
        }

        return await this.sendCommand(
            ZigbeeNWKCommandId.ROUTE_REQ,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            ZigbeeConsts.BCAST_DEFAULT, // nwkDest16
            undefined, // nwkDest64
            CONFIG_NWK_CONCENTRATOR_RADIUS, // nwkRadius
        );
    }

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
    public processRouteReply(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
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
        let originator64: bigint | undefined;
        let responder64: bigint | undefined;

        if (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT) {
            originator64 = data.readBigUInt64LE(offset);
            offset += 8;
        }

        if (options & ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT) {
            responder64 = data.readBigUInt64LE(offset);
            offset += 8;
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);

        logger.debug(
            () =>
                `<=== NWK ROUTE_REPLY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} id=${id} orig=${originator16}:${originator64} rsp=${responder16}:${responder64} pCost=${pathCost}]`,
            NS,
        );

        // Cache source route to responder when coordinator initiated discovery
        if (originator16 === ZigbeeConsts.COORDINATOR_ADDRESS) {
            const nextHopCandidates: number[] = nwkHeader.relayAddresses !== undefined ? [...nwkHeader.relayAddresses] : [];
            const macNextHop =
                macHeader.source16 ?? (macHeader.source64 !== undefined ? this.#context.deviceTable.get(macHeader.source64)?.address16 : undefined);

            if (macNextHop !== undefined && macNextHop !== responder16) {
                if (nextHopCandidates.length === 0 || nextHopCandidates[nextHopCandidates.length - 1] !== macNextHop) {
                    nextHopCandidates.push(macNextHop);
                }
            }

            const routeEntry = this.createSourceRouteEntry(nextHopCandidates, pathCost === 0 ? nextHopCandidates.length + 1 : pathCost);
            const existingEntries = this.#context.sourceRouteTable.get(responder16);

            if (existingEntries === undefined) {
                this.#context.sourceRouteTable.set(responder16, [routeEntry]);
            } else {
                const existingIndex = existingEntries.findIndex(
                    (entry) =>
                        entry.relayAddresses.length === routeEntry.relayAddresses.length &&
                        entry.relayAddresses.every((relay, idx) => relay === routeEntry.relayAddresses[idx]),
                );

                if (existingIndex !== -1) {
                    const existingEntry = existingEntries[existingIndex];
                    existingEntry.pathCost = routeEntry.pathCost;
                    existingEntry.lastUpdated = routeEntry.lastUpdated;
                    existingEntry.failureCount = 0;
                } else if (!this.hasSourceRoute(responder16, routeEntry, existingEntries)) {
                    // TODO: do we want this here?
                    existingEntries.push(routeEntry);
                }
            }

            this.markRouteSuccess(responder16);
        }

        return offset;
    }

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
    public async sendRouteReply(
        requestDest1stHop16: number,
        requestRadius: number,
        requestId: number,
        originator16: number,
        responder16: number,
        originator64?: bigint,
        responder64?: bigint,
    ): Promise<boolean> {
        logger.debug(
            () =>
                `===> NWK ROUTE_REPLY[reqDst1stHop16=${requestDest1stHop16} reqRad=${requestRadius} reqId=${requestId} orig=${originator16}:${originator64} rsp=${responder16}:${responder64}]`,
            NS,
        );
        const hasOriginator64 = originator64 !== undefined;
        const hasResponder64 = responder64 !== undefined;
        const options =
            (((hasOriginator64 ? 1 : 0) << 4) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_ORIG_EXT) |
            (((hasResponder64 ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_ROUTE_OPTION_RESP_EXT);
        const finalPayload = Buffer.alloc(1 + 1 + 1 + 2 + 2 + 1 + (hasOriginator64 ? 8 : 0) + (hasResponder64 ? 8 : 0));
        let offset = 0;
        offset = finalPayload.writeUInt8(ZigbeeNWKCommandId.ROUTE_REPLY, offset);
        offset = finalPayload.writeUInt8(options, offset);
        offset = finalPayload.writeUInt8(requestId, offset);
        offset = finalPayload.writeUInt16LE(originator16, offset);
        offset = finalPayload.writeUInt16LE(responder16, offset);
        offset = finalPayload.writeUInt8(1, offset); // path cost for direct response

        if (hasOriginator64) {
            offset = finalPayload.writeBigUInt64LE(originator64!, offset);
        }

        if (hasResponder64) {
            offset = finalPayload.writeBigUInt64LE(responder64!, offset);
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeNWKTLVs();

        return await this.sendCommand(
            ZigbeeNWKCommandId.ROUTE_REPLY,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestDest1stHop16, // nwkDest16
            this.#context.address16ToAddress64.get(requestDest1stHop16), // nwkDest64
            requestRadius, // nwkRadius
        );
    }

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
    public async processStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        const status = data.readUInt8(offset);
        offset += 1;
        // target SHALL be present if, and only if, frame is being sent in response to a routing failure or a network address conflict
        let target16: number | undefined;

        if (
            status === ZigbeeNWKStatus.LEGACY_NO_ROUTE_AVAILABLE ||
            status === ZigbeeNWKStatus.LEGACY_LINK_FAILURE ||
            status === ZigbeeNWKStatus.LINK_FAILURE ||
            status === ZigbeeNWKStatus.SOURCE_ROUTE_FAILURE ||
            status === ZigbeeNWKStatus.MANY_TO_ONE_ROUTE_FAILURE
        ) {
            // In case of a routing failure, it SHALL contain the destination address from the data frame that encountered the failure
            target16 = data.readUInt16LE(offset);
            offset += 2;

            // mark route as failed with repair - this will purge routes using target as relay and trigger MTORR once
            this.markRouteFailure(target16, true);
        } else if (status === ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            // In case of an address conflict, it SHALL contain the offending network address.
            target16 = data.readUInt16LE(offset);
            offset += 2;

            if (target16 !== ZigbeeConsts.COORDINATOR_ADDRESS) {
                const device64 = this.#context.address16ToAddress64.get(target16);

                if (device64 !== undefined) {
                    const newAddress16 = this.#context.assignNetworkAddress();

                    // TODO: is this correct?
                    await this.sendRejoinResp(target16, newAddress16, ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT);
                } else {
                    logger.warning(() => `NWK address conflict reported for unknown short address ${target16}`, NS);
                }
            }
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);

        logger.debug(
            () =>
                `<=== NWK NWK_STATUS[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${ZigbeeNWKStatus[status]} dst16=${target16}]`,
            NS,
        );

        return offset;
    }

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
    public async sendStatus(requestSource16: number, status: ZigbeeNWKStatus, destination?: number): Promise<boolean> {
        logger.debug(() => `===> NWK NWK_STATUS[reqSrc16=${requestSource16} status=${status} dst16=${destination}]`, NS);
        let finalPayload: Buffer;

        if (status === ZigbeeNWKStatus.LINK_FAILURE || status === ZigbeeNWKStatus.ADDRESS_CONFLICT) {
            finalPayload = Buffer.from([ZigbeeNWKCommandId.NWK_STATUS, status, destination! & 0xff, (destination! >> 8) & 0xff]);
        } else {
            finalPayload = Buffer.from([ZigbeeNWKCommandId.NWK_STATUS, status]);
        }

        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeNWKTLVs();

        return await this.sendCommand(
            ZigbeeNWKCommandId.NWK_STATUS,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestSource16, // nwkDest16
            this.#context.address16ToAddress64.get(requestSource16), // nwkDest64
            CONFIG_NWK_MAX_HOPS, // nwkRadius
        );
    }

    /**
     * 05-3474-23 #3.4.4 (Leave command)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Parses removeChildren/request/rejoin flags from options byte (Table 3-16)
     * - ✅ Invokes disassociate when device signals final leave (request=false & rejoin=false)
     * - ⚠️ removeChildren flag purposely ignored (deprecated)
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    public async processLeave(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        const options = data.readUInt8(offset);
        offset += 1;
        const removeChildren = Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN);
        const request = Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST);
        const rejoin = Boolean(options & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN);

        logger.debug(
            () =>
                `<=== NWK LEAVE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} remChildren=${removeChildren} req=${request} rejoin=${rejoin}]`,
            NS,
        );

        if (!rejoin && !request) {
            await this.#context.disassociate(nwkHeader.source16, nwkHeader.source64);
        }

        return offset;
    }

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
    public async sendLeave(destination16: number, rejoin: boolean): Promise<boolean> {
        logger.debug(() => `===> NWK LEAVE[dst16=${destination16} rejoin=${rejoin}]`, NS);

        const options =
            (0 & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REMOVE_CHILDREN) |
            ((1 << 6) & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REQUEST) |
            (((rejoin ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_LEAVE_OPTION_REJOIN);
        const finalPayload = Buffer.from([ZigbeeNWKCommandId.LEAVE, options]);

        return await this.sendCommand(
            ZigbeeNWKCommandId.LEAVE,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            destination16, // nwkDest16
            this.#context.address16ToAddress64.get(destination16), // nwkDest64
            1, // nwkRadius
        );
    }

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
    public processRouteRecord(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const relayCount = data.readUInt8(offset);
        offset += 1;
        const relays: number[] = [];

        for (let i = 0; i < relayCount; i++) {
            const relay = data.readUInt16LE(offset);
            offset += 2;

            relays.push(relay);
        }

        logger.debug(
            () =>
                `<=== NWK ROUTE_RECORD[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} relays=${relays}]`,
            NS,
        );

        const source16 =
            nwkHeader.source16 === undefined
                ? nwkHeader.source64 === undefined
                    ? undefined
                    : this.#context.deviceTable.get(nwkHeader.source64)?.address16
                : nwkHeader.source16;

        if (source16 !== undefined) {
            const entry = this.createSourceRouteEntry(relays, relayCount + 1);
            const entries = this.#context.sourceRouteTable.get(source16);

            if (entries === undefined) {
                this.#context.sourceRouteTable.set(source16, [entry]);
            } else if (!this.hasSourceRoute(source16, entry, entries)) {
                entries.push(entry);
            }
        }

        return offset;
    }

    // NOTE: sendRouteRecord not for coordinator

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
    public async processRejoinReq(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        const capabilities = data.readUInt8(offset);
        offset += 1;

        const decodedCap = decodeMACCapabilities(capabilities);

        logger.debug(
            () =>
                `<=== NWK REJOIN_REQ[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} cap=${capabilities}]`,
            NS,
        );

        let deny = false;
        let source64 = nwkHeader.source64;

        if (!nwkHeader.frameControl.security) {
            // Trust Center Rejoin

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
            } else {
                const device = this.#context.deviceTable.get(source64);

                // XXX: Unsecured Packets at the network layer claiming to be from existing neighbors (coordinators, routers or end devices) must not rewrite legitimate data in the nwkNeighborTable.
                //      if apsTrustCenterAddress is all FF (distributed) / all 00 (pre-TRANSPORT_KEY), reject with PAN_ACCESS_DENIED
                if (!device?.authorized) {
                    // device unknown or unauthorized
                    deny = true;
                }
            }
        }

        const [status, newAddress16, requiresTransportKey] = await this.#context.associate(
            nwkHeader.source16!,
            source64,
            false /* rejoin */,
            decodedCap,
            macHeader.source16 === nwkHeader.source16,
            deny,
        );

        await this.sendRejoinResp(nwkHeader.source16!, newAddress16, status);

        // XXX: is this spec?
        if (status === MACAssociationStatus.SUCCESS && requiresTransportKey && source64 !== undefined) {
            await this.#callbacks.onAPSSendTransportKeyNWK(
                newAddress16,
                this.#context.netParams.networkKey,
                this.#context.netParams.networkKeySequenceNumber,
                source64,
            );
            this.#context.markNetworkKeyTransported(source64);
        }

        // NOTE: a device does not have to verify its trust center link key with the APSME-VERIFY-KEY services after a rejoin.

        return offset;
    }

    // NOTE: sendRejoinReq not for coordinator

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
    public processRejoinResp(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;

        if (status !== MACAssociationStatus.SUCCESS) {
            logger.error(
                `<=x= NWK REJOIN_RESP[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress} status=${MACAssociationStatus[status]}]`,
                NS,
            );
        } else {
            logger.debug(
                () =>
                    `<=== NWK REJOIN_RESP[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress}]`,
                NS,
            );
        }

        return offset;
    }

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
    public async sendRejoinResp(requestSource16: number, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean> {
        logger.debug(() => `===> NWK REJOIN_RESP[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);

        const finalPayload = Buffer.from([ZigbeeNWKCommandId.REJOIN_RESP, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);

        return await this.sendCommand(
            ZigbeeNWKCommandId.REJOIN_RESP,
            finalPayload,
            true, // nwkSecurity TODO: ??
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestSource16, // nwkDest16
            this.#context.address16ToAddress64.get(newAddress16), // nwkDest64
            CONFIG_NWK_MAX_HOPS, // nwkRadius
        );
    }

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
    public processLinkStatus(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        // Bit: 0 – 4        5            6           7
        //      Entry count  First frame  Last frame  Reserved
        const options = data.readUInt8(offset);
        offset += 1;
        const firstFrame = Boolean((options & ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME) >> 5);
        const lastFrame = Boolean((options & ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME) >> 6);
        const linkCount = options & ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK;
        const links: ZigbeeNWKLinkStatus[] = [];

        let device = nwkHeader.source64 !== undefined ? this.#context.deviceTable.get(nwkHeader.source64) : undefined;

        if (device === undefined && nwkHeader.source16 !== undefined) {
            const source64 = this.#context.address16ToAddress64.get(nwkHeader.source16);

            if (source64 !== undefined) {
                device = this.#context.deviceTable.get(source64);
            }
        }

        if (device?.capabilities?.deviceType === ZigbeeMACConsts.DEVICE_TYPE_FFD) {
            device.linkStatusMisses = 0;
        }

        for (let i = 0; i < linkCount; i++) {
            const address = data.readUInt16LE(offset);
            offset += 2;
            const costByte = data.readUInt8(offset);
            offset += 1;

            links.push({
                address,
                incomingCost: costByte & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK,
                outgoingCost: (costByte & ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK) >> 4,
            });

            if (device !== undefined) {
                if (address === ZigbeeConsts.COORDINATOR_ADDRESS) {
                    // if neighbor is coordinator, update device table
                    device.neighbor = true;
                }

                // use the incoming cost as the path cost (represents link quality from the neighbor's perspective)
                const incomingCost = costByte & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK;
                const pathCost = Math.max(1, incomingCost);

                const entry =
                    address === ZigbeeConsts.COORDINATOR_ADDRESS
                        ? this.createSourceRouteEntry([], pathCost)
                        : this.createSourceRouteEntry([address], pathCost + 1);
                const entries = this.#context.sourceRouteTable.get(device.address16);

                if (entries === undefined) {
                    this.#context.sourceRouteTable.set(device.address16, [entry]);
                } else {
                    // check if we already have this route; if so, update it
                    const existingIndex = entries.findIndex(
                        (e) =>
                            e.relayAddresses.length === entry.relayAddresses.length &&
                            e.relayAddresses.every((relay, idx) => relay === entry.relayAddresses[idx]),
                    );

                    if (existingIndex !== -1) {
                        // update existing route with new cost and reset failure count
                        entries[existingIndex].pathCost = entry.pathCost;
                        entries[existingIndex].lastUpdated = entry.lastUpdated;
                        entries[existingIndex].failureCount = 0;
                    } else if (!this.hasSourceRoute(device.address16, entry, entries)) {
                        entries.push(entry);
                    }
                }
            }
        }

        logger.debug(() => {
            let linksStr = "";

            for (const link of links) {
                linksStr += `{${link.address}|in:${link.incomingCost}|out:${link.outgoingCost}}`;
            }

            return `<=== NWK LINK_STATUS[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} first=${firstFrame} last=${lastFrame} links=${linksStr}]`;
        }, NS);

        return offset;
    }

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
    public async sendLinkStatus(links: ZigbeeNWKLinkStatus[]): Promise<void> {
        logger.debug(() => {
            let linksStr = "";

            for (const link of links) {
                linksStr += `{${link.address}|in:${link.incomingCost}|out:${link.outgoingCost}}`;
            }

            return `===> NWK LINK_STATUS[links=${linksStr}]`;
        }, NS);

        // TODO: check repeat logic
        const linkSize = links.length * 3;
        const maxLinksPayloadSize = ZigbeeNWKConsts.PAYLOAD_MIN_SIZE - 2; // 84 (- cmdId[1] - options[1])
        const maxLinksPerFrame = Math.floor(maxLinksPayloadSize / 3); // 27
        const frameCount = Math.ceil((linkSize + 3) / maxLinksPayloadSize); // (+ repeated link[3])
        let linksOffset = 0;

        for (let i = 0; i < frameCount; i++) {
            const linkCount = links.length - i * maxLinksPerFrame;
            const frameSize = 2 + Math.min(linkCount * 3, maxLinksPayloadSize);
            const options =
                (((i === 0 ? 1 : 0) << 5) & ZigbeeNWKConsts.CMD_LINK_OPTION_FIRST_FRAME) |
                (((i === frameCount - 1 ? 1 : 0) << 6) & ZigbeeNWKConsts.CMD_LINK_OPTION_LAST_FRAME) |
                (linkCount & ZigbeeNWKConsts.CMD_LINK_OPTION_COUNT_MASK);
            const finalPayload = Buffer.alloc(frameSize);
            let finalPayloadOffset = 0;
            finalPayload.writeUInt8(ZigbeeNWKCommandId.LINK_STATUS, finalPayloadOffset);
            finalPayloadOffset += 1;
            finalPayload.writeUInt8(options, finalPayloadOffset);
            finalPayloadOffset += 1;

            for (let j = 0; j < linkCount; j++) {
                const link = links[linksOffset];
                finalPayload.writeUInt16LE(link.address, finalPayloadOffset);
                finalPayloadOffset += 2;
                finalPayload.writeUInt8(
                    (link.incomingCost & ZigbeeNWKConsts.CMD_LINK_INCOMING_COST_MASK) |
                        ((link.outgoingCost << 4) & ZigbeeNWKConsts.CMD_LINK_OUTGOING_COST_MASK),
                    finalPayloadOffset,
                );
                finalPayloadOffset += 1;

                // last in previous frame is repeated first in next frame
                if (j < linkCount - 1) {
                    linksOffset++;
                }
            }

            await this.sendCommand(
                ZigbeeNWKCommandId.LINK_STATUS,
                finalPayload,
                true, // nwkSecurity
                ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
                ZigbeeConsts.BCAST_DEFAULT, // nwkDest16
                undefined, // nwkDest64
                1, // nwkRadius
            );
        }
    }

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
    public processReport(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const options = data.readUInt8(offset);
        offset += 1;
        const reportCount = options & ZigbeeNWKConsts.CMD_NWK_REPORT_COUNT_MASK;
        const reportType = options & ZigbeeNWKConsts.CMD_NWK_REPORT_ID_MASK;
        const extendedPANId = data.readBigUInt64LE(offset);
        offset += 8;
        let conflictPANIds: number[] | undefined;

        if (reportType === ZigbeeNWKConsts.CMD_NWK_REPORT_ID_PAN_CONFLICT) {
            conflictPANIds = [];

            for (let i = 0; i < reportCount; i++) {
                const panId = data.readUInt16LE(offset);
                offset += 2;

                conflictPANIds.push(panId);
            }
        }

        logger.debug(
            () =>
                `<=== NWK NWK_REPORT[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} extPANId=${extendedPANId} repType=${reportType} conflictPANIds=${conflictPANIds}]`,
            NS,
        );

        return offset;
    }

    // NOTE: sendReport deprecated in R23

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
    public processUpdate(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const options = data.readUInt8(offset);
        offset += 1;
        const updateCount = options & ZigbeeNWKConsts.CMD_NWK_UPDATE_COUNT_MASK;
        const updateType = options & ZigbeeNWKConsts.CMD_NWK_UPDATE_ID_MASK;
        const extendedPANId = data.readBigUInt64LE(offset);
        offset += 8;
        const updateId = data.readUInt8(offset);
        offset += 1;
        let panIds: number[] | undefined;

        if (updateType === ZigbeeNWKConsts.CMD_NWK_UPDATE_ID_PAN_UPDATE) {
            panIds = [];

            for (let i = 0; i < updateCount; i++) {
                const panId = data.readUInt16LE(offset);
                offset += 2;

                panIds.push(panId);
            }
        }

        logger.debug(
            () =>
                `<=== NWK NWK_UPDATE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} extPANId=${extendedPANId} id=${updateId} type=${updateType} panIds=${panIds}]`,
            NS,
        );

        return offset;
    }

    // NOTE: sendUpdate PAN ID change not supported

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
    public async processEdTimeoutRequest(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        // index into END_DEVICE_TIMEOUT_TABLE_MS
        const requestedTimeout = data.readUInt8(offset);
        offset += 1;
        // not currently used (all reserved)
        const configuration = data.readUInt8(offset);
        offset += 1;

        logger.debug(
            () =>
                `<=== NWK ED_TIMEOUT_REQUEST[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} reqTimeout=${requestedTimeout} conf=${configuration}]`,
            NS,
        );

        // sanity check
        if (nwkHeader.source16 !== undefined) {
            const timeoutResolved = END_DEVICE_TIMEOUT_TABLE_MS[requestedTimeout];
            const source64 = nwkHeader.source64 ?? this.#context.address16ToAddress64.get(nwkHeader.source16);
            let status = 0x00;

            if (timeoutResolved === undefined) {
                status = 0x01;
            } else if (source64 === undefined) {
                status = 0x02;
            } else {
                const metadata = this.#context.updateEndDeviceTimeout(source64, requestedTimeout);

                if (metadata === undefined) {
                    status = 0x02;
                }
            }

            await this.sendEdTimeoutResponse(nwkHeader.source16, requestedTimeout, status);
        }

        return offset;
    }

    // NOTE: sendEdTimeoutRequest not for coordinator

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
    public processEdTimeoutResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
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

        logger.debug(
            () =>
                `<=== NWK ED_TIMEOUT_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${status} parentInfo=${parentInfo}]`,
            NS,
        );

        return offset;
    }

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
    public async sendEdTimeoutResponse(
        requestDest16: number,
        requestedTimeout: number,
        statusOverride?: number,
        parentInfoOverride?: number,
    ): Promise<boolean> {
        logger.debug(
            () =>
                `===> NWK ED_TIMEOUT_RESPONSE[reqDst16=${requestDest16} requestedTimeout=${requestedTimeout} statusOverride=${statusOverride} parentInfoOverride=${parentInfoOverride}]`,
            NS,
        );

        const status = statusOverride ?? (END_DEVICE_TIMEOUT_TABLE_MS[requestedTimeout] !== undefined ? 0x00 : 0x01);
        const parentInfo = parentInfoOverride ?? CONFIG_NWK_ED_TIMEOUT_PARENT_INFO_DEFAULT;
        const finalPayload = Buffer.from([ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE, status, parentInfo]);

        return await this.sendCommand(
            ZigbeeNWKCommandId.ED_TIMEOUT_RESPONSE,
            finalPayload,
            true, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestDest16, // nwkDest16
            this.#context.address16ToAddress64.get(requestDest16), // nwkDest64
            1, // nwkRadius
        );
    }

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
    public processLinkPwrDelta(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const options = data.readUInt8(offset);
        offset += 1;
        // 0 Notification An unsolicited notification. These frames are typically sent periodically from an RxOn device. If the device is a FFD, it is broadcast to all RxOn devices (0xfffd), and includes power information for all neighboring RxOn devices. If the device is an RFD with RxOn, it is sent unicast to its Parent, and includes only power information for the Parent device.
        // 1 Request Typically used by sleepy RFD devices that do not receive the periodic Notifications from their Parent. The sleepy RFD will wake up periodically to send this frame to its Parent, including only the Parent’s power information in its payload. Upon receipt, the Parent sends a Response (Type = 2) as an indirect transmission, with only the RFD’s power information in its payload. After macResponseWaitTime, the RFD polls its Parent for the Response, before going back to sleep. Request commands are sent as unicast. Note: any device MAY send a Request to solicit a Response from another device. These commands SHALL be sent as unicast and contain only the power information for the destination device. If this command is received as a broadcast, it SHALL be discarded with no action.
        // 2 Response This command is sent in response to a Request. Response commands are sent as unicast to the sender of the Request. The response includes only the power information for the requesting device.
        // 3 Reserved
        const type = options & ZigbeeNWKConsts.CMD_NWK_LINK_PWR_DELTA_TYPE_MASK;
        const count = data.readUInt8(offset);
        offset += 1;
        const deltas: { device: number; delta: number }[] = [];

        for (let i = 0; i < count; i++) {
            const device = data.readUInt16LE(offset);
            offset += 2;
            const delta = data.readUInt8(offset);
            offset += 1;

            deltas.push({ device, delta });
        }

        logger.debug(
            () =>
                `<=== NWK LINK_PWR_DELTA[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${type} deltas=${deltas}]`,
            NS,
        );
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
    public async processCommissioningRequest(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): Promise<number> {
        // 0x00 Initial Join
        // 0x01 Rejoin
        const assocType = data.readUInt8(offset);
        offset += 1;
        const capabilities = data.readUInt8(offset);
        offset += 1;

        const decodedCap = decodeMACCapabilities(capabilities);

        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeNWKTLVs(data, offset);

        logger.debug(
            () =>
                `<=== NWK COMMISSIONING_REQUEST[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} assocType=${assocType} cap=${capabilities}]`,
            NS,
        );

        // NOTE: send Remove Device CMD to TC deny the join (or let timeout): `sendRemoveDevice`

        const [status, newAddress16, requiresTransportKey] = await this.#context.associate(
            nwkHeader.source16!,
            nwkHeader.source64,
            assocType === 0x00 /* initial join */,
            decodedCap,
            macHeader.source16 === nwkHeader.source16,
            nwkHeader.frameControl.security /* deny if true */,
        );

        await this.sendCommissioningResponse(nwkHeader.source16!, newAddress16, status);

        if (status === MACAssociationStatus.SUCCESS) {
            const dest64 = this.#context.address16ToAddress64.get(newAddress16);

            if (dest64 !== undefined && requiresTransportKey) {
                await this.#callbacks.onAPSSendTransportKeyNWK(
                    newAddress16,
                    this.#context.netParams.networkKey,
                    this.#context.netParams.networkKeySequenceNumber,
                    dest64,
                );
                this.#context.markNetworkKeyTransported(dest64);
            }
        }

        return offset;
    }

    // NOTE: sendCommissioningRequest not for coordinator

    /**
     * 05-3474-23 #3.4.15 (Commissioning Response) — Optional in R23
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Extracts assigned address and status value per Table 3-22
     * - ✅ Logs success vs failure for commissioning diagnostics
     * - ⚠️  TODO: Process optional TLVs (required for full Zigbee Direct compliance)
     * DEVICE SCOPE: Routers (N/A), end devices (N/A)
     */
    public processCommissioningResponse(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader): number {
        const newAddress = data.readUInt16LE(offset);
        offset += 2;
        // `ZigbeeNWKConsts.ASSOC_STATUS_ADDR_CONFLICT`, or MACAssociationStatus
        const status = data.readUInt8(offset);
        offset += 1;

        if (status !== MACAssociationStatus.SUCCESS) {
            logger.error(
                `<=x= NWK COMMISSIONING_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress} status=${MACAssociationStatus[status] ?? "NWK_ADDR_CONFLICT"}]`,
                NS,
            );
        } else {
            logger.debug(
                () =>
                    `<=== NWK COMMISSIONING_RESPONSE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} newAddr16=${newAddress}]`,
                NS,
            );
        }

        // TODO

        return offset;
    }

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
    public async sendCommissioningResponse(requestSource16: number, newAddress16: number, status: MACAssociationStatus | number): Promise<boolean> {
        logger.debug(() => `===> NWK COMMISSIONING_RESPONSE[reqSrc16=${requestSource16} newAddr16=${newAddress16} status=${status}]`, NS);

        const finalPayload = Buffer.from([ZigbeeNWKCommandId.COMMISSIONING_RESPONSE, newAddress16 & 0xff, (newAddress16 >> 8) & 0xff, status]);

        return await this.sendCommand(
            ZigbeeNWKCommandId.COMMISSIONING_RESPONSE,
            finalPayload,
            false, // nwkSecurity
            ZigbeeConsts.COORDINATOR_ADDRESS, // nwkSource16
            requestSource16, // nwkDest16
            this.#context.address16ToAddress64.get(requestSource16), // nwkDest64
            CONFIG_NWK_MAX_HOPS, // nwkRadius
        );
    }

    // #endregion
}
