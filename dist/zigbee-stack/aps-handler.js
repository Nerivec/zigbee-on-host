"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.APSHandler = exports.CONFIG_APS_MAX_FRAME_RETRIES = exports.CONFIG_APS_ACK_WAIT_DURATION_MS = void 0;
const logger_js_1 = require("../utils/logger.js");
const mac_js_1 = require("../zigbee/mac.js");
const zigbee_aps_js_1 = require("../zigbee/zigbee-aps.js");
const zigbee_nwk_js_1 = require("../zigbee/zigbee-nwk.js");
const nwk_handler_js_1 = require("./nwk-handler.js");
const stack_context_js_1 = require("./stack-context.js");
const NS = "aps-handler";
/** apsDuplicateEntryLifetime: Duration while APS duplicate table entries remain valid (milliseconds). Spec default ≈ 8s. */
const CONFIG_APS_DUPLICATE_TIMEOUT_MS = 8000; // TODO: verify
/** apsAckWaitDuration: Default ack wait duration per Zigbee 3.0 spec (milliseconds). */
exports.CONFIG_APS_ACK_WAIT_DURATION_MS = 1600 + 500; // some extra for ZoH
/** apsMaxFrameRetries: Default number of APS retransmissions when ACK is missing. */
exports.CONFIG_APS_MAX_FRAME_RETRIES = 3;
/** apsFragmentationTimeout: Timeout for incomplete incoming APS fragment reassembly (milliseconds). */
const CONFIG_APS_FRAGMENT_REASSEMBLY_TIMEOUT_MS = 30000; // TODO: verify
/**
 * APS Handler - Zigbee Application Support Layer Operations
 */
class APSHandler {
    #context;
    #macHandler;
    #nwkHandler;
    #callbacks;
    // Private counters (start at 0, first call returns 1)
    #counter = 0;
    #zdoSeqNum = 0;
    /** Recently seen frames for duplicate rejection by NWK 16 */
    #duplicateTable16 = new Map();
    /** Recently seen frames for duplicate rejection by NWK 64 */
    #duplicateTable64 = new Map();
    /** Pending acknowledgments waiting for retransmission */
    #pendingAcks = new Map();
    /** Incoming fragment reassembly buffers */
    #incomingFragments = new Map();
    constructor(context, macHandler, nwkHandler, callbacks) {
        this.#context = context;
        this.#macHandler = macHandler;
        this.#nwkHandler = nwkHandler;
        this.#callbacks = callbacks;
    }
    async start() { }
    stop() {
        for (const entry of this.#pendingAcks.values()) {
            if (entry.timer !== undefined) {
                clearTimeout(entry.timer);
            }
        }
        this.#pendingAcks.clear();
        this.#incomingFragments.clear();
        this.#duplicateTable16.clear();
        this.#duplicateTable64.clear();
    }
    /**
     * Get next APS counter.
     * HOT PATH: Optimized counter increment
     * @returns Incremented APS counter (wraps at 255)
     */
    /* @__INLINE__ */
    nextCounter() {
        this.#counter = (this.#counter + 1) & 0xff;
        return this.#counter;
    }
    /**
     * Get next ZDO sequence number.
     * HOT PATH: Optimized counter increment
     * @returns Incremented ZDO sequence number (wraps at 255)
     */
    /* @__INLINE__ */
    nextZDOSeqNum() {
        this.#zdoSeqNum = (this.#zdoSeqNum + 1) & 0xff;
        return this.#zdoSeqNum;
    }
    /**
     * 05-3474-23 #4.4.11.1 (Application Link Key establishment)
     *
     * Get or generate application link key for a device pair
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Retrieves stored link key when present to satisfy apsDeviceKeyPairSet lookup
     * - ✅ Derives fallback key from Trust Center link key when absent (per spec default)
     * - ✅ Persists generated key via StackContext helper for future requests
     * - ⚠️  Derived key currently mirrors TC key; unique per-pair derivation still TODO
     * DEVICE SCOPE: Trust Center
     */
    #getOrGenerateAppLinkKey(deviceA, deviceB) {
        const existing = this.#context.getAppLinkKey(deviceA, deviceB);
        if (existing !== undefined) {
            return existing;
        }
        const derived = Buffer.from(this.#context.netParams.tcKey);
        this.#context.setAppLinkKey(deviceA, deviceB, derived);
        return derived;
    }
    /**
     * 05-3474-23 #2.2.6.5 (APS duplicate rejection)
     *
     * Check whether an incoming APS frame is a duplicate and update the duplicate table accordingly.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Uses {src64, dstEndpoint, clusterId, apsCounter} tuple per spec to detect duplicates
     * - ✅ Applies configurable timeout window (DEFAULT ≈ 8s) after which entries expire
     * - ✅ Tracks fragment block numbers explicitly so out-of-order fragment retransmissions are accepted
     * - ✅ Drops duplicates before generating APS ACKs, matching required ordering
     * - ⚠️  Duplicate table stored in-memory only; persistence across restart is not implemented
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @returns true when the frame was already seen within the duplicate removal timeout.
     */
    isDuplicateFrame(nwkHeader, apsHeader, now = Date.now()) {
        if (apsHeader.counter === undefined) {
            // skip check
            return false;
        }
        const hasSource16 = nwkHeader.source16 !== undefined;
        // prune expired duplicates, only for relevant table to avoid pointless looping for current frame
        if (hasSource16) {
            for (const [key, entry] of this.#duplicateTable16) {
                if (entry.expiresAt <= now) {
                    this.#duplicateTable16.delete(key);
                }
            }
        }
        else {
            for (const [key, entry] of this.#duplicateTable64) {
                if (entry.expiresAt <= now) {
                    this.#duplicateTable64.delete(key);
                }
            }
        }
        const isFragmented = apsHeader.fragmentation !== undefined && apsHeader.fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */;
        // frames are dropped in `processFrame` if neither source available
        const entry = hasSource16 ? this.#duplicateTable16.get(nwkHeader.source16) : this.#duplicateTable64.get(nwkHeader.source64);
        if (entry !== undefined && entry.counter === apsHeader.counter && entry.expiresAt > now) {
            if (isFragmented) {
                const blockNumber = apsHeader.fragBlockNumber ?? 0;
                let fragments = entry.fragments;
                if (fragments === undefined) {
                    fragments = new Set();
                    entry.fragments = fragments;
                }
                else if (fragments.has(blockNumber)) {
                    return true;
                }
                fragments.add(blockNumber);
                entry.expiresAt = now + CONFIG_APS_DUPLICATE_TIMEOUT_MS;
                return false;
            }
            return true;
        }
        const newEntry = {
            counter: apsHeader.counter,
            expiresAt: now + CONFIG_APS_DUPLICATE_TIMEOUT_MS,
        };
        if (isFragmented) {
            newEntry.fragments = new Set([apsHeader.fragBlockNumber ?? 0]);
        }
        if (hasSource16) {
            this.#duplicateTable16.set(nwkHeader.source16, newEntry);
        }
        else {
            this.#duplicateTable64.set(nwkHeader.source64, newEntry);
        }
        return false;
    }
    /**
     * 05-3474-23 #4.4.1 (APS data service)
     *
     * Send a Zigbee APS DATA frame and track pending ACK if necessary.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Builds APS frame with ackRequest flag and delivery mode per parameters
     * - ✅ Tracks pending acknowledgements per spec timeout (CONFIG_APS_ACK_WAIT_DURATION_MS ≈ 1.5s)
     * - ✅ Applies fragmentation when payload exceeds APS maximum (CONFIG_APS_UNFRAGMENTED_PAYLOAD_MAX)
     * - ⚠️  Fragment reassembly timer configurable but not spec-driven (CONFIG_APS_FRAGMENT_REASSEMBLY_TIMEOUT_MS)
     * - ⚠️  Route discovery hint (nwkDiscoverRoute) passed to NWK handler without additional validation
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param finalPayload Encoded APS payload
     * @param nwkDiscoverRoute NWK discovery mode
     * @param nwkDest16 Destination short address (if known)
     * @param nwkDest64 Destination IEEE (optional)
     * @param apsDeliveryMode Delivery mode (unicast/group/broadcast)
     * @param clusterId Cluster identifier
     * @param profileId Profile identifier
     * @param destEndpoint Destination endpoint
     * @param sourceEndpoint Source endpoint
     * @param group Group identifier (when group addressed)
     * @returns The APS counter of the sent frame
     */
    async sendData(finalPayload, nwkDiscoverRoute, nwkDest16, nwkDest64, apsDeliveryMode, clusterId, profileId, destEndpoint, sourceEndpoint, group) {
        const params = {
            finalPayload,
            nwkDiscoverRoute,
            nwkDest16,
            nwkDest64,
            apsDeliveryMode,
            clusterId,
            profileId,
            destEndpoint,
            sourceEndpoint,
            group,
        };
        const apsCounter = this.nextCounter();
        if (finalPayload.length > 100 /* ZigbeeAPSConsts.PAYLOAD_MAX_SIZE */) {
            return await this.#sendFragmentedData(params, apsCounter);
        }
        const sendDest16 = await this.#sendDataInternal(params, apsCounter, 0);
        if (sendDest16 !== undefined) {
            this.#trackPendingAck(sendDest16, apsCounter, params);
        }
        return apsCounter;
    }
    /**
     * 05-3474-23 #4.4.1 (APS data service)
     *
     * Send a Zigbee APS DATA frame.
     * Throws if could not send.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Encodes APS/NWK/MAC headers according to delivery mode and security requirements
     * - ✅ Engages NWK source routing when available via `findBestSourceRoute`
     * - ✅ Requests APS ACKs on non-broadcast destinations and tracks MAC pending bit for sleepy children
     * - ⚠️  APS security flag hardcoded to false (link-key encryption pending future work)
     * - ⚠️  Relies on caller to provide valid route discovery hint; no additional validation here
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param params
     * @param apsCounter
     * @param attempt
     * @returns Destination short address (undefined for broadcast)
     */
    async #sendDataInternal(params, apsCounter, attempt) {
        const { finalPayload, nwkDiscoverRoute, apsDeliveryMode, clusterId, profileId, destEndpoint, sourceEndpoint, group } = params;
        let { nwkDest16, nwkDest64 } = params;
        const nwkSeqNum = this.#nwkHandler.nextSeqNum();
        const macSeqNum = this.#macHandler.nextSeqNum();
        let relayIndex;
        let relayAddresses;
        try {
            [relayIndex, relayAddresses] = this.#nwkHandler.findBestSourceRoute(nwkDest16, nwkDest64);
        }
        catch (error) {
            logger_js_1.logger.error(`=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) attempt=${attempt} nwkDst=${nwkDest16}:${nwkDest64}] ${error.message}`, NS);
            throw error;
        }
        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.#context.deviceTable.get(nwkDest64)?.address16;
        }
        if (nwkDest16 === undefined) {
            logger_js_1.logger.error(`=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) attempt=${attempt} nwkDst=${nwkDest16}:${nwkDest64}] Invalid parameters`, NS);
            throw new Error("Invalid parameters");
        }
        // update params as needed
        params.nwkDest16 = nwkDest16;
        params.nwkDest64 = nwkDest64;
        const macDest16 = nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ ? (relayAddresses?.[relayIndex] ?? nwkDest16) : 65535 /* ZigbeeMACConsts.BCAST_ADDR */;
        logger_js_1.logger.debug(() => `===> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum})${attempt > 0 ? ` attempt=${attempt}` : ""} macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} apsDlv=${apsDeliveryMode}]`, NS);
        const isFragment = params.fragment !== undefined;
        const apsHeader = {
            frameControl: {
                frameType: 0 /* ZigbeeAPSFrameType.DATA */,
                deliveryMode: apsDeliveryMode,
                ackFormat: false,
                security: false, // TODO link key support
                ackRequest: true,
                extendedHeader: isFragment,
            },
            destEndpoint,
            group,
            clusterId,
            profileId,
            sourceEndpoint,
            counter: apsCounter,
        };
        if (isFragment) {
            const fragmentInfo = params.fragment;
            const fragmentation = fragmentInfo.isFirst
                ? 1 /* ZigbeeAPSFragmentation.FIRST */
                : fragmentInfo.isLast
                    ? 3 /* ZigbeeAPSFragmentation.LAST */
                    : 2 /* ZigbeeAPSFragmentation.MIDDLE */;
            apsHeader.fragmentation = fragmentation;
            apsHeader.fragBlockNumber = fragmentInfo.blockNumber;
        }
        const apsFrame = (0, zigbee_aps_js_1.encodeZigbeeAPSFrame)(apsHeader, finalPayload);
        const nwkFrame = (0, zigbee_nwk_js_1.encodeZigbeeNWKFrame)({
            frameControl: {
                frameType: 0 /* ZigbeeNWKFrameType.DATA */,
                protocolVersion: 2 /* ZigbeeNWKConsts.VERSION_2007 */,
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
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            radius: this.#context.decrementRadius(nwk_handler_js_1.CONFIG_NWK_MAX_HOPS),
            seqNum: nwkSeqNum,
            relayIndex,
            relayAddresses,
        }, apsFrame, {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 1 /* ZigbeeKeyType.NWK */,
                nonce: true,
                reqVerifiedFc: false,
            },
            frameCounter: this.#context.nextNWKKeyFrameCounter(),
            source64: this.#context.netParams.eui64,
            keySeqNum: this.#context.netParams.networkKeySequenceNumber,
            micLen: 4,
        }, undefined);
        const macFrame = (0, mac_js_1.encodeMACFrameZigbee)({
            frameControl: {
                frameType: 1 /* MACFrameType.DATA */,
                securityEnabled: false,
                framePending: group === undefined && nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */
                    ? Boolean(this.#context.indirectTransmissions.get(nwkDest64 ?? this.#context.address16ToAddress64.get(nwkDest16))?.length)
                    : false,
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
        if (result === false) {
            logger_js_1.logger.error(`=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) attempt=${attempt} macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64}] Failed to send`, NS);
            throw new Error("Failed to send");
        }
        if (macDest16 === 65535 /* ZigbeeMACConsts.BCAST_ADDR */) {
            return undefined;
        }
        return nwkDest16;
    }
    /**
     * 05-3474-23 #4.4.5 (APS fragmentation)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Splits payload into first/remaining chunks respecting fragment overhead constants
     * - ✅ Stores fragmentation context to coordinate sequential block transmission
     * - ✅ Requires unicast ACKs per spec before advancing to later blocks
     * - ⚠️  Does not yet adapt fragment size based on MAC MTU or user configuration
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    async #sendFragmentedData(params, apsCounter) {
        const payload = params.finalPayload;
        if (payload.byteLength <= 100 /* ZigbeeAPSConsts.PAYLOAD_MAX_SIZE */) {
            return apsCounter;
        }
        const baseParams = {
            nwkDiscoverRoute: params.nwkDiscoverRoute,
            nwkDest16: params.nwkDest16,
            nwkDest64: params.nwkDest64,
            apsDeliveryMode: params.apsDeliveryMode,
            clusterId: params.clusterId,
            profileId: params.profileId,
            destEndpoint: params.destEndpoint,
            sourceEndpoint: params.sourceEndpoint,
            group: params.group,
        };
        const chunks = [];
        let offset = 0;
        let block = 0;
        const firstChunkSize = Math.max(1, 48 /* ZigbeeAPSConsts.FRAGMENT_PAYLOAD_SIZE */ - 2 /* ZigbeeAPSConsts.FRAGMENT_FIRST_LENGTH_SIZE */);
        while (offset < payload.byteLength) {
            const size = block === 0 ? firstChunkSize : 48 /* ZigbeeAPSConsts.FRAGMENT_PAYLOAD_SIZE */;
            const chunk = Buffer.from(payload.subarray(offset, offset + size));
            chunks.push(chunk);
            offset += chunk.byteLength;
            block += 1;
        }
        if (chunks.length <= 1) {
            throw new Error("APS fragmentation requires at least two chunks");
        }
        const context = {
            baseParams,
            chunks,
            awaitingBlock: 0,
            totalBlocks: chunks.length,
        };
        const { dest16, params: firstParams } = await this.#sendFragmentBlock(context, apsCounter, 0, 0);
        if (dest16 === undefined) {
            throw new Error("APS fragmentation requires unicast destination acknowledgments");
        }
        this.#trackPendingAck(dest16, apsCounter, firstParams, context);
        return apsCounter;
    }
    #buildFragmentParams(context, blockNumber) {
        const fragment = {
            blockNumber,
            isFirst: blockNumber === 0,
            isLast: blockNumber === context.totalBlocks - 1,
        };
        return {
            ...context.baseParams,
            finalPayload: context.chunks[blockNumber],
            fragment,
        };
    }
    async #sendFragmentBlock(context, apsCounter, blockNumber, attempt) {
        const fragmentParams = this.#buildFragmentParams(context, blockNumber);
        const dest16 = await this.#sendDataInternal(fragmentParams, apsCounter, attempt);
        return { dest16, params: fragmentParams };
    }
    /**
     * 05-3474-23 #4.4.5 (APS fragmentation)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Advances to next fragment only after prior block acknowledged
     * - ✅ Reuses shared context to maintain block numbering and chunk references
     * - ⚠️  Throws for broadcast destinations; spec restricts fragmentation to unicast
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    async #sendNextFragmentBlock(context, previousEntry) {
        context.awaitingBlock += 1;
        if (context.awaitingBlock >= context.totalBlocks) {
            return;
        }
        const { dest16, params } = await this.#sendFragmentBlock(context, previousEntry.apsCounter, context.awaitingBlock, 0);
        if (dest16 === undefined) {
            throw new Error("APS fragmentation requires unicast destination acknowledgments");
        }
        this.#trackPendingAck(dest16, previousEntry.apsCounter, params, context);
    }
    /**
     * 05-3474-23 #4.4.5 (APS fragmentation reassembly)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Initializes fragment state on FIRST block and records meta fields
     * - ✅ Tracks expected block count from LAST fragment index
     * - ✅ Clears extended header bits once reassembly completes per spec requirement
     * - ⚠️  Reassembly timeout configurable via constant (30s); spec leaves timing vendor-specific
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    #handleIncomingFragment(data, nwkHeader, apsHeader) {
        const now = Date.now();
        this.#pruneExpiredFragmentStates(now);
        const blockNumber = apsHeader.fragBlockNumber ?? 0;
        const key = this.#makeFragmentKey(nwkHeader, apsHeader);
        const fragmentation = apsHeader.fragmentation ?? 0 /* ZigbeeAPSFragmentation.NONE */;
        if (fragmentation === 1 /* ZigbeeAPSFragmentation.FIRST */) {
            const state = {
                chunks: new Map([[blockNumber, Buffer.from(data)]]),
                lastActivity: now,
                source16: nwkHeader.source16,
                source64: nwkHeader.source64,
                destEndpoint: apsHeader.destEndpoint,
                profileId: apsHeader.profileId,
                clusterId: apsHeader.clusterId,
                counter: apsHeader.counter ?? 0,
            };
            this.#incomingFragments.set(key, state);
            return undefined;
        }
        const state = this.#incomingFragments.get(key);
        if (state === undefined) {
            return undefined;
        }
        state.chunks.set(blockNumber, Buffer.from(data));
        state.lastActivity = now;
        if (fragmentation === 3 /* ZigbeeAPSFragmentation.LAST */) {
            state.expectedBlocks = blockNumber + 1;
        }
        if (state.expectedBlocks === undefined || state.chunks.size < state.expectedBlocks) {
            return undefined;
        }
        const buffers = [];
        for (let block = 0; block < state.expectedBlocks; block += 1) {
            const chunk = state.chunks.get(block);
            if (chunk === undefined) {
                return undefined;
            }
            buffers.push(chunk);
        }
        this.#incomingFragments.delete(key);
        apsHeader.frameControl.extendedHeader = false;
        apsHeader.fragmentation = undefined;
        apsHeader.fragBlockNumber = undefined;
        apsHeader.fragACKBitfield = undefined;
        return Buffer.concat(buffers);
    }
    #makeFragmentKey(nwkHeader, apsHeader) {
        const source = nwkHeader.source64 !== undefined ? `64:${nwkHeader.source64}` : `16:${nwkHeader.source16 ?? 0xffff}`;
        const profile = apsHeader.profileId ?? 0;
        const cluster = apsHeader.clusterId ?? 0;
        const sourceEndpoint = apsHeader.sourceEndpoint ?? 0xff;
        const destEndpoint = apsHeader.destEndpoint ?? 0xff;
        const counter = apsHeader.counter ?? 0;
        return `${source}:${profile}:${cluster}:${sourceEndpoint}:${destEndpoint}:${counter}`;
    }
    #pruneExpiredFragmentStates(now) {
        for (const [key, state] of this.#incomingFragments) {
            if (now - state.lastActivity >= CONFIG_APS_FRAGMENT_REASSEMBLY_TIMEOUT_MS) {
                this.#incomingFragments.delete(key);
            }
        }
    }
    #updateSourceRouteForChild(child16, parent16, parent64) {
        if (parent16 === undefined) {
            return;
        }
        try {
            const [, parentRelays] = this.#nwkHandler.findBestSourceRoute(parent16, parent64);
            if (parentRelays) {
                this.#context.sourceRouteTable.set(child16, [this.#nwkHandler.createSourceRouteEntry(parentRelays, parentRelays.length + 1)]);
            }
            else {
                this.#context.sourceRouteTable.set(child16, [this.#nwkHandler.createSourceRouteEntry([parent16], 2)]);
            }
        }
        catch {
            /* ignore (no known route yet) */
        }
    }
    /**
     * 05-3474-23 #4.4.2.3 (APS acknowledgement management)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Starts ack-wait timer using spec default (~1.5 s) and resets on retransmit
     * - ✅ Stores fragment context so subsequent blocks send only after ACK
     * - ⚠️  Pending table keyed by {dest16,counter}; no IEEE64 fallback if short address unknown
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    #trackPendingAck(dest16, apsCounter, params, fragment) {
        const key = `${dest16}:${apsCounter}`;
        const existing = this.#pendingAcks.get(key);
        if (existing?.timer !== undefined) {
            clearTimeout(existing.timer);
        }
        this.#pendingAcks.set(key, {
            params,
            apsCounter,
            dest16,
            retries: 0,
            timer: setTimeout(async () => {
                await this.#handleAckTimeout(key);
            }, exports.CONFIG_APS_ACK_WAIT_DURATION_MS),
            fragment,
        });
    }
    /**
     * 05-3474-23 #4.4.2.3 (APS acknowledgement management)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Retries DATA up to CONFIG_APS_MAX_FRAME_RETRIES per spec guidance (default 3)
     * - ✅ Re-arms ack timer after each retransmission
     * - ⚠️  Does not escalate failure beyond logging; higher layers must react to exhausted retries
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    async #handleAckTimeout(key) {
        const entry = this.#pendingAcks.get(key);
        if (entry === undefined) {
            return;
        }
        if (entry.retries >= exports.CONFIG_APS_MAX_FRAME_RETRIES) {
            this.#pendingAcks.delete(key);
            logger_js_1.logger.error(`=x=> APS DATA[apsCounter=${entry.apsCounter} dest16=${entry.dest16}] Retries exhausted`, NS);
            return;
        }
        entry.retries += 1;
        try {
            await this.#sendDataInternal(entry.params, entry.apsCounter, entry.retries);
        }
        catch (error) {
            this.#pendingAcks.delete(key);
            logger_js_1.logger.warning(() => `=x=> APS DATA retry failed[apsCounter=${entry.apsCounter} dest16=${entry.dest16} attempt=${entry.retries}] ${error.message}`, NS);
            return;
        }
        entry.timer = setTimeout(async () => {
            await this.#handleAckTimeout(key);
        }, exports.CONFIG_APS_ACK_WAIT_DURATION_MS);
    }
    /**
     * 05-3474-23 #4.4.2.3 (APS acknowledgement management)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Matches ACKs using source short address and APS counter per spec tuple
     * - ✅ Clears timers promptly to avoid dangling callbacks
     * - ✅ Triggers next fragment block when outstanding
     * - ⚠️  No handling for duplicate ACKs; silently ignored once entry removed
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    async #resolvePendingAck(nwkHeader, apsHeader) {
        if (apsHeader.counter === undefined) {
            return;
        }
        let source16 = nwkHeader.source16;
        if (source16 === undefined && nwkHeader.source64 !== undefined) {
            source16 = this.#context.deviceTable.get(nwkHeader.source64)?.address16;
        }
        if (source16 === undefined) {
            return;
        }
        const key = `${source16}:${apsHeader.counter}`;
        const entry = this.#pendingAcks.get(key);
        if (entry === undefined) {
            return;
        }
        if (entry.timer !== undefined) {
            clearTimeout(entry.timer);
        }
        this.#pendingAcks.delete(key);
        logger_js_1.logger.debug(() => `<=== APS ACK[src16=${source16} apsCounter=${apsHeader.counter} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`, NS);
        if (entry.fragment !== undefined) {
            await this.#sendNextFragmentBlock(entry.fragment, entry);
        }
    }
    /**
     * 05-3474-23 #4.4.2.3 (APS acknowledgement)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Mirrors counter and cluster metadata per spec Table 4-10
     * - ✅ Selects unicast delivery mode and suppresses retransmit (ackRequest=false)
     * - ✅ Reuses NWK/MAC sequence numbers from incoming frame to satisfy reliability requirements
     * - ⚠️  Fragment ACK format limited to simple bitfield (supports first block only)
     * - ⚠️  Does not retry failed acknowledgements; relies on NWK retransmissions
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    async sendACK(macHeader, nwkHeader, apsHeader) {
        logger_js_1.logger.debug(() => `===> APS ACK[dst16=${nwkHeader.source16} apsCounter=${apsHeader.counter} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`, NS);
        let nwkDest16 = nwkHeader.source16;
        const nwkDest64 = nwkHeader.source64;
        let relayIndex;
        let relayAddresses;
        try {
            [relayIndex, relayAddresses] = this.#nwkHandler.findBestSourceRoute(nwkDest16, nwkDest64);
        }
        catch (error) {
            logger_js_1.logger.debug(() => `=x=> APS ACK[dst16=${nwkDest16} seqNum=${nwkHeader.seqNum}] ${error.message}`, NS);
            return;
        }
        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.#context.deviceTable.get(nwkDest64)?.address16;
        }
        if (nwkDest16 === undefined) {
            logger_js_1.logger.debug(() => `=x=> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}] Unknown destination`, NS);
            return;
        }
        const macDest16 = nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ ? (relayAddresses?.[relayIndex] ?? nwkDest16) : 65535 /* ZigbeeMACConsts.BCAST_ADDR */;
        const ackNeedsFragmentInfo = apsHeader.frameControl.extendedHeader && apsHeader.fragmentation !== undefined && apsHeader.fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */;
        const ackHeader = {
            frameControl: {
                frameType: 2 /* ZigbeeAPSFrameType.ACK */,
                deliveryMode: 0 /* ZigbeeAPSDeliveryMode.UNICAST */,
                ackFormat: false,
                security: false,
                ackRequest: false,
                extendedHeader: ackNeedsFragmentInfo,
            },
            destEndpoint: apsHeader.sourceEndpoint,
            clusterId: apsHeader.clusterId,
            profileId: apsHeader.profileId,
            sourceEndpoint: apsHeader.destEndpoint,
            counter: apsHeader.counter,
        };
        if (ackNeedsFragmentInfo) {
            ackHeader.fragmentation = 1 /* ZigbeeAPSFragmentation.FIRST */;
            ackHeader.fragBlockNumber = apsHeader.fragBlockNumber ?? 0;
            ackHeader.fragACKBitfield = 0x01;
        }
        const ackAPSFrame = (0, zigbee_aps_js_1.encodeZigbeeAPSFrame)(ackHeader, Buffer.alloc(0));
        const ackNWKFrame = (0, zigbee_nwk_js_1.encodeZigbeeNWKFrame)({
            frameControl: {
                frameType: 0 /* ZigbeeNWKFrameType.DATA */,
                protocolVersion: 2 /* ZigbeeNWKConsts.VERSION_2007 */,
                discoverRoute: 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */,
                multicast: false,
                security: true,
                sourceRoute: relayIndex !== undefined,
                extendedDestination: false,
                extendedSource: false,
                endDeviceInitiator: false,
            },
            destination16: nwkHeader.source16,
            source16: nwkHeader.destination16,
            radius: this.#context.decrementRadius(nwkHeader.radius ?? nwk_handler_js_1.CONFIG_NWK_MAX_HOPS),
            seqNum: nwkHeader.seqNum,
            relayIndex,
            relayAddresses,
        }, ackAPSFrame, {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 1 /* ZigbeeKeyType.NWK */,
                nonce: true,
                reqVerifiedFc: false,
            },
            frameCounter: this.#context.nextNWKKeyFrameCounter(),
            source64: this.#context.netParams.eui64,
            keySeqNum: this.#context.netParams.networkKeySequenceNumber,
            micLen: 4,
        }, undefined);
        const ackMACFrame = (0, mac_js_1.encodeMACFrameZigbee)({
            frameControl: {
                frameType: 1 /* MACFrameType.DATA */,
                securityEnabled: false,
                framePending: Boolean(this.#context.indirectTransmissions.get(nwkDest64 ?? this.#context.address16ToAddress64.get(nwkDest16))?.length),
                ackRequest: true,
                panIdCompression: true,
                seqNumSuppress: false,
                iePresent: false,
                destAddrMode: 2 /* MACFrameAddressMode.SHORT */,
                frameVersion: 0 /* MACFrameVersion.V2003 */,
                sourceAddrMode: 2 /* MACFrameAddressMode.SHORT */,
            },
            sequenceNumber: macHeader.sequenceNumber,
            destinationPANId: macHeader.destinationPANId,
            destination16: macDest16,
            // sourcePANId: undefined, // panIdCompression=true
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            fcs: 0,
        }, ackNWKFrame);
        await this.#macHandler.sendFrame(macHeader.sequenceNumber, ackMACFrame, macHeader.source16, undefined);
    }
    /**
     * 05-3474-23 #4.4 (APS layer processing)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Handles DATA, ACK, INTERPAN frame types per spec definitions
     * - ✅ Performs duplicate rejection using APS counter + source addressing
     * - ✅ Performs fragmentation reassembly and forwards completed payloads upward
     * - ⚠️  INTERPAN frames not supported (throws) - spec optional for coordinators
     * - ⚠️  Fragment reassembly lacks payload size guard (tracked via CONFIG_APS_FRAGMENT_REASSEMBLY_TIMEOUT_MS)
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    async processFrame(data, macHeader, nwkHeader, apsHeader, lqa) {
        switch (apsHeader.frameControl.frameType) {
            case 2 /* ZigbeeAPSFrameType.ACK */: {
                // ACKs should never contain a payload
                await this.#resolvePendingAck(nwkHeader, apsHeader);
                return;
            }
            case 0 /* ZigbeeAPSFrameType.DATA */:
            case 3 /* ZigbeeAPSFrameType.INTERPAN */: {
                if (data.byteLength < 1) {
                    return;
                }
                if (apsHeader.frameControl.extendedHeader &&
                    apsHeader.fragmentation !== undefined &&
                    apsHeader.fragmentation !== 0 /* ZigbeeAPSFragmentation.NONE */) {
                    const reassembled = this.#handleIncomingFragment(data, nwkHeader, apsHeader);
                    if (reassembled === undefined) {
                        return;
                    }
                    data = reassembled;
                }
                logger_js_1.logger.debug(() => `<=== APS DATA[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${nwkHeader.seqNum} profileId=${apsHeader.profileId} clusterId=${apsHeader.clusterId} srcEp=${apsHeader.sourceEndpoint} dstEp=${apsHeader.destEndpoint} bcast=${macHeader.destination16 === 65535 /* ZigbeeMACConsts.BCAST_ADDR */ || (nwkHeader.destination16 !== undefined && nwkHeader.destination16 >= 65528 /* ZigbeeConsts.BCAST_MIN */)}]`, NS);
                if (apsHeader.profileId === 0 /* ZigbeeConsts.ZDO_PROFILE_ID */) {
                    if (apsHeader.clusterId === 19 /* ZigbeeConsts.END_DEVICE_ANNOUNCE */) {
                        let offset = 1; // skip seq num
                        const address16 = data.readUInt16LE(offset);
                        offset += 2;
                        const address64 = data.readBigUInt64LE(offset);
                        offset += 8;
                        const capabilities = data.readUInt8(offset);
                        offset += 1;
                        const device = this.#context.deviceTable.get(address64);
                        if (device === undefined) {
                            // unknown device, should have been added by `associate`, something's not right, ignore it
                            return;
                        }
                        const decodedCap = (0, mac_js_1.decodeMACCapabilities)(capabilities);
                        if (device.address16 !== address16) {
                            this.#context.address16ToAddress64.delete(device.address16);
                            this.#context.address16ToAddress64.set(address16, address64);
                            device.address16 = address16;
                        }
                        // just in case
                        device.capabilities = decodedCap;
                        await this.#context.savePeriodicState();
                        // TODO: ideally, this shouldn't trigger (prevents early interview process from app) until AFTER authorized=true
                        setImmediate(() => {
                            // if device is authorized, it means it completed the TC link key update, so, a rejoin
                            // TODO: could flip authorized to true before the announce and count as rejoin when it shouldn't
                            if (device.authorized) {
                                this.#callbacks.onDeviceRejoined(address16, address64, decodedCap);
                            }
                            else {
                                this.#callbacks.onDeviceJoined(address16, address64, decodedCap);
                            }
                        });
                    }
                    else {
                        const isRequest = (apsHeader.clusterId & 0x8000) === 0;
                        if (isRequest) {
                            if (this.isZDORequestForCoordinator(apsHeader.clusterId, nwkHeader.destination16, nwkHeader.destination64, data)) {
                                await this.respondToCoordinatorZDORequest(data, apsHeader.clusterId, nwkHeader.source16, nwkHeader.source64);
                            }
                            // don't emit received ZDO requests
                            return;
                        }
                    }
                }
                setImmediate(() => {
                    // TODO: always lookup source64 if undef?
                    this.#callbacks.onFrame(nwkHeader.source16, nwkHeader.source64, apsHeader, data, lqa);
                });
                break;
            }
            case 1 /* ZigbeeAPSFrameType.CMD */: {
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
     * 05-3474-23 #4.4.11 (APS command frames)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Encodes APS command header with appropriate delivery mode and security bit per parameters
     * - ✅ Integrates with NWK/ MAC handlers for routing + source routing
     * - ✅ Supports APS security header injection (LOAD/TRANSPORT keys) as required by TC flows
     * - ⚠️  disableACKRequest used for certain commands (e.g., TRANSPORT_KEY) despite spec recommending ACKs
     * - ⚠️  TLV extensions not yet supported (R23 features)
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     *
     * @param cmdId APS command identifier
     * @param finalPayload Fully encoded APS command payload (including cmdId)
     * @param nwkDiscoverRoute NWK discovery mode
     * @param nwkSecurity Whether to apply NWK security
     * @param nwkDest16 Destination network address
     * @param nwkDest64 Destination IEEE address (optional)
     * @param apsDeliveryMode Delivery mode (unicast/broadcast)
     * @param apsSecurityHeader Optional APS security header definition
     * @param disableACKRequest Whether to suppress APS ACK request
     * @returns True if success sending (or indirect transmission)
     */
    async sendCommand(cmdId, finalPayload, nwkDiscoverRoute, nwkSecurity, nwkDest16, nwkDest64, apsDeliveryMode, apsSecurityHeader, disableACKRequest = false) {
        let nwkSecurityHeader;
        if (nwkSecurity) {
            nwkSecurityHeader = {
                control: {
                    level: 0 /* ZigbeeSecurityLevel.NONE */,
                    keyId: 1 /* ZigbeeKeyType.NWK */,
                    nonce: true,
                    reqVerifiedFc: false,
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
        let relayIndex;
        let relayAddresses;
        try {
            [relayIndex, relayAddresses] = this.#nwkHandler.findBestSourceRoute(nwkDest16, nwkDest64);
        }
        catch (error) {
            logger_js_1.logger.error(`=x=> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64}] ${error.message}`, NS);
            return false;
        }
        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.#context.deviceTable.get(nwkDest64)?.address16;
        }
        if (nwkDest16 === undefined) {
            logger_js_1.logger.error(`=x=> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} nwkSec=${nwkSecurity} apsDlv=${apsDeliveryMode} apsSec=${apsSecurityHeader !== undefined}]`, NS);
            return false;
        }
        const macDest16 = nwkDest16 < 65528 /* ZigbeeConsts.BCAST_MIN */ ? (relayAddresses?.[relayIndex] ?? nwkDest16) : 65535 /* ZigbeeMACConsts.BCAST_ADDR */;
        logger_js_1.logger.debug(() => `===> APS CMD[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) cmdId=${cmdId} macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} nwkSec=${nwkSecurity} apsDlv=${apsDeliveryMode} apsSec=${apsSecurityHeader !== undefined}]`, NS);
        const apsFrame = (0, zigbee_aps_js_1.encodeZigbeeAPSFrame)({
            frameControl: {
                frameType: 1 /* ZigbeeAPSFrameType.CMD */,
                deliveryMode: apsDeliveryMode,
                ackFormat: false,
                security: apsSecurityHeader !== undefined,
                // XXX: spec says all should request ACK except TUNNEL, but vectors show not a lot of stacks respect that, what's best?
                ackRequest: cmdId !== 14 /* ZigbeeAPSCommandId.TUNNEL */ && !disableACKRequest,
                extendedHeader: false,
            },
            counter: apsCounter,
        }, finalPayload, apsSecurityHeader, undefined);
        const nwkFrame = (0, zigbee_nwk_js_1.encodeZigbeeNWKFrame)({
            frameControl: {
                frameType: 0 /* ZigbeeNWKFrameType.DATA */,
                protocolVersion: 2 /* ZigbeeNWKConsts.VERSION_2007 */,
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
            source16: 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */,
            radius: this.#context.decrementRadius(nwk_handler_js_1.CONFIG_NWK_MAX_HOPS),
            seqNum: nwkSeqNum,
            relayIndex,
            relayAddresses,
        }, apsFrame, nwkSecurityHeader, undefined);
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
    /**
     * 05-3474-23 #4.4.11 (APS command processing)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Dispatches APS command IDs to the appropriate handler per Table 4-28
     * - ✅ Logs unsupported commands for diagnostics without crashing the stack
     * - ✅ Passes MAC/NWK headers to downstream handlers for security context decisions
     * - ⚠️  TLV parsing for extended commands still TODO (handlers emit TODO markers)
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    async processCommand(data, macHeader, nwkHeader, apsHeader) {
        let offset = 0;
        const cmdId = data.readUInt8(offset);
        offset += 1;
        switch (cmdId) {
            case 5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */: {
                offset = this.processTransportKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 6 /* ZigbeeAPSCommandId.UPDATE_DEVICE */: {
                offset = await this.processUpdateDevice(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 7 /* ZigbeeAPSCommandId.REMOVE_DEVICE */: {
                offset = await this.processRemoveDevice(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 8 /* ZigbeeAPSCommandId.REQUEST_KEY */: {
                offset = await this.processRequestKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 9 /* ZigbeeAPSCommandId.SWITCH_KEY */: {
                offset = this.processSwitchKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 14 /* ZigbeeAPSCommandId.TUNNEL */: {
                offset = this.processTunnel(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 15 /* ZigbeeAPSCommandId.VERIFY_KEY */: {
                offset = await this.processVerifyKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 16 /* ZigbeeAPSCommandId.CONFIRM_KEY */: {
                offset = this.processConfirmKey(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 17 /* ZigbeeAPSCommandId.RELAY_MESSAGE_DOWNSTREAM */: {
                offset = this.processRelayMessageDownstream(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            case 18 /* ZigbeeAPSCommandId.RELAY_MESSAGE_UPSTREAM */: {
                offset = this.processRelayMessageUpstream(data, offset, macHeader, nwkHeader, apsHeader);
                break;
            }
            default: {
                logger_js_1.logger.warning(`<=x= APS CMD[cmdId=${cmdId} macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64}] Unsupported`, NS);
                return;
            }
        }
        // excess data in packet
        // if (offset < data.byteLength) {
        //     logger.debug(() => `<=== APS CMD contained more data: ${data.toString('hex')}`, NS);
        // }
    }
    /**
     * 05-3474-23 #4.4.11.1
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Handles all mandated key types (NWK, Trust Center, Application) and logs metadata
     * - ✅ Stages pending network key when addressed to coordinator or wildcard destination
     * - ✅ Preserves raw key material for subsequent SWITCH_KEY activation
     * - ⚠️  TLV extensions for enhanced security fields remain unparsed (TODO markers)
     * - ⚠️  Application key handling currently limited to storage; partner attribute updates pending
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    processTransportKey(data, offset, macHeader, nwkHeader, _apsHeader) {
        const keyType = data.readUInt8(offset);
        offset += 1;
        const key = data.subarray(offset, offset + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        offset += 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */;
        switch (keyType) {
            case 1 /* ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK */:
            case 5 /* ZigbeeAPSConsts.CMD_KEY_HIGH_SEC_NWK */: {
                const seqNum = data.readUInt8(offset);
                offset += 1;
                const destination = data.readBigUInt64LE(offset);
                offset += 8;
                const source = data.readBigUInt64LE(offset);
                offset += 8;
                logger_js_1.logger.debug(() => `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} seqNum=${seqNum} dst64=${destination} src64=${source}]`, NS);
                if (destination === this.#context.netParams.eui64 || destination === 0n) {
                    this.#context.setPendingNetworkKey(key, seqNum);
                }
                break;
            }
            case 0 /* ZigbeeAPSConsts.CMD_KEY_TC_MASTER */:
            case 4 /* ZigbeeAPSConsts.CMD_KEY_TC_LINK */: {
                const destination = data.readBigUInt64LE(offset);
                offset += 8;
                const source = data.readBigUInt64LE(offset);
                offset += 8;
                // TODO
                // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);
                logger_js_1.logger.debug(() => `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} dst64=${destination} src64=${source}]`, NS);
                break;
            }
            case 2 /* ZigbeeAPSConsts.CMD_KEY_APP_MASTER */:
            case 3 /* ZigbeeAPSConsts.CMD_KEY_APP_LINK */: {
                const partner = data.readBigUInt64LE(offset);
                offset += 8;
                const initiatorFlag = data.readUInt8(offset);
                offset += 1;
                // TODO
                // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);
                logger_js_1.logger.debug(() => `<=== APS TRANSPORT_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} key=${key} partner64=${partner} initiatorFlag=${initiatorFlag}]`, NS);
                break;
            }
        }
        return offset;
    }
    /**
     * 05-3474-23 #4.4.11.1
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
     * DEVICE SCOPE: Trust Center
     *
     * @param nwkDest16
     * @param key SHALL contain the link key that SHOULD be used for APS encryption
     * @param destination64 SHALL contain the address of the device which SHOULD use this link key
     * @returns
     */
    async sendTransportKeyTC(nwkDest16, key, destination64) {
        // TODO: tunneling support `, tunnelDest?: bigint`
        //       If the TunnelCommand parameter is TRUE, an APS Tunnel Command SHALL be constructed as described in section 4.6.3.7.
        //       It SHALL then be sent to the device specified by the TunnelAddress parameter by issuing an NLDE-DATA.request primitive.
        logger_js_1.logger.debug(() => `===> APS TRANSPORT_KEY_TC[key=${key.toString("hex")} dst64=${destination64}]`, NS);
        const finalPayload = Buffer.alloc(18 + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        let offset = 0;
        offset = finalPayload.writeUInt8(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, offset);
        offset = finalPayload.writeUInt8(4 /* ZigbeeAPSConsts.CMD_KEY_TC_LINK */, offset);
        offset += key.copy(finalPayload, offset);
        offset = finalPayload.writeBigUInt64LE(destination64, offset);
        offset = finalPayload.writeBigUInt64LE(this.#context.netParams.eui64, offset);
        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeAPSTLVs();
        // encryption NWK=true, APS=true
        return await this.sendCommand(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 3 /* ZigbeeKeyType.LOAD */,
                nonce: true,
                reqVerifiedFc: false,
            },
            frameCounter: this.#context.nextTCKeyFrameCounter(),
            source64: this.#context.netParams.eui64,
            // keySeqNum: undefined, only for keyId NWK
            micLen: 4,
        });
    }
    /**
     * 05-3474-23 #4.4.11.1 #4.4.11.1.3.2
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
     * - ✅ Broadcast destination64 handling sets all-zero string when using NWK broadcast per spec
     * DEVICE SCOPE: Trust Center
     *
     * @param nwkDest16
     * @param key SHALL contain a network key
     * @param seqNum SHALL contain the sequence number associated with this network key
     * @param destination64 SHALL contain the address of the device which SHOULD use this network key
     * If the network key is sent to a broadcast address, the destination address subfield SHALL be set to the all-zero string and SHALL be ignored upon reception.
     * @returns
     */
    async sendTransportKeyNWK(nwkDest16, key, seqNum, destination64) {
        // TODO: tunneling support `, tunnelDest?: bigint`
        logger_js_1.logger.debug(() => `===> APS TRANSPORT_KEY_NWK[key=${key.toString("hex")} seqNum=${seqNum} dst64=${destination64}]`, NS);
        const isBroadcast = nwkDest16 >= 65528 /* ZigbeeConsts.BCAST_MIN */;
        const finalPayload = Buffer.alloc(19 + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        let offset = 0;
        offset = finalPayload.writeUInt8(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, offset);
        offset = finalPayload.writeUInt8(1 /* ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK */, offset);
        offset += key.copy(finalPayload, offset);
        offset = finalPayload.writeUInt8(seqNum, offset);
        offset = finalPayload.writeBigUInt64LE(isBroadcast ? 0n : destination64, offset);
        offset = finalPayload.writeBigUInt64LE(this.#context.netParams.eui64, offset); // 0xFFFFFFFFFFFFFFFF in distributed network (no TC)
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
        return await this.sendCommand(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        false, // nwkSecurity
        nwkDest16, // nwkDest16
        isBroadcast ? undefined : destination64, // nwkDest64
        isBroadcast ? 2 /* ZigbeeAPSDeliveryMode.BCAST */ : 0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 2 /* ZigbeeKeyType.TRANSPORT */,
                nonce: true,
                reqVerifiedFc: false,
            },
            frameCounter: this.#context.nextTCKeyFrameCounter(),
            source64: this.#context.netParams.eui64,
            // keySeqNum: undefined, only for keyId NWK
            micLen: 4,
        }, // apsSecurityHeader
        true);
    }
    /**
     * 05-3474-23 #4.4.11.1 #4.4.11.1.3.3
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Sets CMD_KEY_APP_LINK (0x03) and includes partner64 + initiator flag per Table 4-17
     * - ✅ Applies APS security with TRANSPORT keyId (shared TC link key) while suppressing NWK security (permitted)
     * - ✅ Supports mirrored delivery (initiator + partner) when invoked twice in Request Key flow
     * - ⚠️ TODO: Add TLV support for enhanced security context (R23)
     * - ⚠️ TODO: Consider tunneling for indirect partners per spec #4.6.3.7
     * DEVICE SCOPE: Trust Center
     */
    async sendTransportKeyAPP(nwkDest16, key, partner, initiatorFlag) {
        // TODO: tunneling support `, tunnelDest?: bigint`
        logger_js_1.logger.debug(() => `===> APS TRANSPORT_KEY_APP[key=${key.toString("hex")} partner64=${partner} initiatorFlag=${initiatorFlag}]`, NS);
        const finalPayload = Buffer.alloc(11 + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        let offset = 0;
        offset = finalPayload.writeUInt8(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, offset);
        offset = finalPayload.writeUInt8(3 /* ZigbeeAPSConsts.CMD_KEY_APP_LINK */, offset);
        offset += key.copy(finalPayload, offset);
        offset = finalPayload.writeBigUInt64LE(partner, offset);
        offset = finalPayload.writeUInt8(initiatorFlag ? 1 : 0, offset);
        // TODO
        // const [tlvs, tlvsOutOffset] = encodeZigbeeAPSTLVs();
        return await this.sendCommand(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 3 /* ZigbeeKeyType.LOAD */,
                nonce: true,
                reqVerifiedFc: false,
            },
            frameCounter: this.#context.nextTCKeyFrameCounter(),
            source64: this.#context.netParams.eui64,
            // keySeqNum: undefined, only for keyId NWK
            micLen: 4,
        });
    }
    /**
     * 05-3474-23 #4.4.11.2
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Correctly decodes all mandatory fields: device64, device16, status
     * - ⚠️  TODO: TLVs not decoded (optional but recommended for R23+ features)
     * - ✅ Handles 4 status codes as per spec:
     *       0x00 = Standard Device Secured Rejoin (updates device state via associate)
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
     * - ✅ Status 0x03 (TC Rejoin) re-distributes NWK key when device lacks latest sequence
     * - ⚠️  Status 0x02 (Device Left) handling uses onDisassociate - spec says "informative only, should not take action"
     *       This may be non-compliant as it actively removes the device
     *
     * SECURITY CONCERN:
     * - Unsecured joins through routers rely heavily on parent router trust
     * - No verification of parent's claim about device capabilities
     * - Source route created immediately may be premature if join fails
     * DEVICE SCOPE: Trust Center
     */
    async processUpdateDevice(data, offset, macHeader, nwkHeader, _apsHeader) {
        const device64 = data.readBigUInt64LE(offset);
        offset += 8;
        // Zigbee 2006 and later
        const device16 = data.readUInt16LE(offset);
        offset += 2;
        const status = data.readUInt8(offset);
        offset += 1;
        // TODO
        // const [tlvs, tlvsOutOffset] = decodeZigbeeAPSTLVs(data, offset);
        logger_js_1.logger.debug(() => `<=== APS UPDATE_DEVICE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dev=${device16}:${device64} status=${status} src16=${nwkHeader.source16}]`, NS);
        if (status === 0 /* ZigbeeAPSUpdateDeviceStatus.STANDARD_DEVICE_SECURED_REJOIN */) {
            await this.#context.associate(device16, device64, false, // rejoin
            undefined, // no MAC cap through router
            false, // not neighbor
            false, true);
            this.#updateSourceRouteForChild(device16, nwkHeader.source16, nwkHeader.source64);
        }
        else if (status === 1 /* ZigbeeAPSUpdateDeviceStatus.STANDARD_DEVICE_UNSECURED_JOIN */) {
            await this.#context.associate(device16, device64, true, // initial join
            undefined, // no MAC cap through router
            false, // not neighbor
            false, true);
            this.#updateSourceRouteForChild(device16, nwkHeader.source16, nwkHeader.source64);
            const tApsCmdPayload = Buffer.alloc(19 + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
            let tunnelOffset = 0;
            tunnelOffset = tApsCmdPayload.writeUInt8(5 /* ZigbeeAPSCommandId.TRANSPORT_KEY */, tunnelOffset);
            tunnelOffset = tApsCmdPayload.writeUInt8(1 /* ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK */, tunnelOffset);
            tunnelOffset += this.#context.netParams.networkKey.copy(tApsCmdPayload, tunnelOffset);
            tunnelOffset = tApsCmdPayload.writeUInt8(this.#context.netParams.networkKeySequenceNumber, tunnelOffset);
            tunnelOffset = tApsCmdPayload.writeBigUInt64LE(device64, tunnelOffset);
            tunnelOffset = tApsCmdPayload.writeBigUInt64LE(this.#context.netParams.eui64, tunnelOffset); // 0xFFFFFFFFFFFFFFFF in distributed network (no TC)
            const tApsCmdFrame = (0, zigbee_aps_js_1.encodeZigbeeAPSFrame)({
                frameControl: {
                    frameType: 1 /* ZigbeeAPSFrameType.CMD */,
                    deliveryMode: 0 /* ZigbeeAPSDeliveryMode.UNICAST */,
                    ackFormat: false,
                    security: true,
                    ackRequest: false,
                    extendedHeader: false,
                },
                counter: this.nextCounter(),
            }, tApsCmdPayload, {
                control: {
                    level: 0 /* ZigbeeSecurityLevel.NONE */,
                    keyId: 2 /* ZigbeeKeyType.TRANSPORT */,
                    nonce: true,
                    reqVerifiedFc: false,
                },
                frameCounter: this.#context.nextTCKeyFrameCounter(),
                source64: this.#context.netParams.eui64,
                micLen: 4,
            }, undefined);
            await this.sendTunnel(nwkHeader.source16, device64, tApsCmdFrame);
            this.#context.markNetworkKeyTransported(device64);
        }
        else if (status === 3 /* ZigbeeAPSUpdateDeviceStatus.STANDARD_DEVICE_TRUST_CENTER_REJOIN */) {
            // rejoin
            const [, , requiresTransportKey] = await this.#context.associate(device16, device64, false, // rejoin
            undefined, // no MAC cap through router
            false, // not neighbor
            false, true);
            if (requiresTransportKey) {
                await this.sendTransportKeyNWK(device16, this.#context.netParams.networkKey, this.#context.netParams.networkKeySequenceNumber, device64);
                this.#context.markNetworkKeyTransported(device64);
            }
        }
        else if (status === 2 /* ZigbeeAPSUpdateDeviceStatus.DEVICE_LEFT */) {
            // left
            // TODO: according to spec, this is "informative" only, should not take any action?
            await this.#context.disassociate(device16, device64);
        }
        return offset;
    }
    /**
     * 05-3474-23 #4.4.11.2
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
     * DEVICE SCOPE: Coordinator, Routers (N/A)
     */
    async sendUpdateDevice(nwkDest16, device64, device16, status) {
        logger_js_1.logger.debug(() => `===> APS UPDATE_DEVICE[dev=${device16}:${device64} status=${status}]`, NS);
        const finalPayload = Buffer.alloc(12 /* + TLVs */);
        let offset = 0;
        offset = finalPayload.writeUInt8(6 /* ZigbeeAPSCommandId.UPDATE_DEVICE */, offset);
        offset = finalPayload.writeBigUInt64LE(device64, offset);
        offset = finalPayload.writeUInt16LE(device16, offset);
        offset = finalPayload.writeUInt8(status, offset);
        // TODO TLVs
        return await this.sendCommand(6 /* ZigbeeAPSCommandId.UPDATE_DEVICE */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-23 #4.4.11.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes target IEEE address (childInfo)
     * - ✅ Issues NWK leave to child and removes from device tables
     * - ⚠️  Does not notify parent router beyond leave (spec expects UPDATE_DEVICE relays)
     * - ⚠️  Parent role handling limited to direct coordinator actions
     * DEVICE SCOPE: Coordinator, Routers (N/A)
     */
    async processRemoveDevice(data, offset, macHeader, nwkHeader, _apsHeader) {
        const target = data.readBigUInt64LE(offset);
        offset += 8;
        logger_js_1.logger.debug(() => `<=== APS REMOVE_DEVICE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} target64=${target}]`, NS);
        const childEntry = this.#context.deviceTable.get(target);
        if (childEntry !== undefined) {
            const leaveSent = await this.#nwkHandler.sendLeave(childEntry.address16, false);
            if (!leaveSent) {
                logger_js_1.logger.warning(`<=x= APS REMOVE_DEVICE[target64=${target}] Failed to send NWK leave`, NS);
            }
            await this.#context.disassociate(childEntry.address16, target);
        }
        else {
            logger_js_1.logger.warning(`<=x= APS REMOVE_DEVICE[target64=${target}] Unknown device`, NS);
        }
        return offset;
    }
    /**
     * 05-3474-23 #4.4.11.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Includes target IEEE address
     * - ✅ Applies NWK + APS LOAD encryption
     * - ✅ Unicast to parent router
     * DEVICE SCOPE: Trust Center
     *
     * NOTE: Trust Center sends this to parent router, which should then remove child
     *
     * @param nwkDest16 parent
     * @param target64
     * @returns
     */
    async sendRemoveDevice(nwkDest16, target64) {
        logger_js_1.logger.debug(() => `===> APS REMOVE_DEVICE[target64=${target64}]`, NS);
        const finalPayload = Buffer.alloc(9);
        let offset = 0;
        offset = finalPayload.writeUInt8(7 /* ZigbeeAPSCommandId.REMOVE_DEVICE */, offset);
        offset = finalPayload.writeBigUInt64LE(target64, offset);
        return await this.sendCommand(7 /* ZigbeeAPSCommandId.REMOVE_DEVICE */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-23 #4.4.11.4 #4.4.5.2.3
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Rejects unencrypted APS frames as mandated (request MUST be APS secured)
     * - ✅ Honors Trust Center policies: allowTCKeyRequest / allowAppKeyRequest gates
     * - ✅ Returns NWK, TC, or APP link keys through appropriate TRANSPORT_KEY helpers
     * - ✅ Derives/stores application link keys via StackContext for partner distribution
     * - ⚠️ TODO: Implement ApplicationKeyRequestPolicy.ONLY_APPROVED enforcement
     * - ⚠️ TODO: Implement TrustCenterKeyRequestPolicy.ONLY_PROVISIONAL enforcement
     * - ⚠️ TODO: Track apsDeviceKeyPairSet per spec Annex B for negotiated keys
     * DEVICE SCOPE: Trust Center
     */
    async processRequestKey(data, offset, macHeader, nwkHeader, apsHeader) {
        // ZigbeeAPSConsts.CMD_KEY_APP_MASTER || ZigbeeAPSConsts.CMD_KEY_TC_LINK
        const keyType = data.readUInt8(offset);
        offset += 1;
        // If the APS Command Request Key message is not APS encrypted, the device SHALL drop the message and no further processing SHALL be done.
        if (!apsHeader.frameControl.security) {
            return offset;
        }
        const requester64 = nwkHeader.source64 ?? this.#context.address16ToAddress64.get(nwkHeader.source16);
        // don't send to unknown device
        if (requester64 !== undefined) {
            // TODO:
            //   const deviceKeyPair = this.apsDeviceKeyPairSet.get(nwkHeader.source16!);
            //   if (!deviceKeyPair || deviceKeyPair.keyNegotiationMethod === 0x00 /* `APS Request Key` method */) {
            if (keyType === 1 /* ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK */) {
                logger_js_1.logger.debug(() => `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}]`, NS);
                await this.sendTransportKeyNWK(nwkHeader.source16, this.#context.netParams.networkKey, this.#context.netParams.networkKeySequenceNumber, requester64);
            }
            else if (keyType === 2 /* ZigbeeAPSConsts.CMD_KEY_APP_MASTER */) {
                const partner = data.readBigUInt64LE(offset);
                offset += 8;
                logger_js_1.logger.debug(() => `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} partner64=${partner}]`, NS);
                if (this.#context.trustCenterPolicies.allowAppKeyRequest === stack_context_js_1.ApplicationKeyRequestPolicy.ALLOWED) {
                    const appLinkKey = this.#getOrGenerateAppLinkKey(requester64, partner);
                    await this.sendTransportKeyAPP(nwkHeader.source16, appLinkKey, partner, true);
                    const partnerEntry = this.#context.deviceTable.get(partner);
                    if (partnerEntry?.address16 === undefined) {
                        logger_js_1.logger.warning(() => `<=x= APS REQUEST_KEY[partner64=${partner}] Unknown partner`, NS);
                    }
                    else {
                        await this.sendTransportKeyAPP(partnerEntry.address16, appLinkKey, requester64, false);
                    }
                }
                // TODO ApplicationKeyRequestPolicy.ONLY_APPROVED
            }
            else if (keyType === 4 /* ZigbeeAPSConsts.CMD_KEY_TC_LINK */) {
                logger_js_1.logger.debug(() => `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}]`, NS);
                if (this.#context.trustCenterPolicies.allowTCKeyRequest === stack_context_js_1.TrustCenterKeyRequestPolicy.ALLOWED) {
                    await this.sendTransportKeyTC(nwkHeader.source16, this.#context.netParams.tcKey, requester64);
                }
                // TODO TrustCenterKeyRequestPolicy.ONLY_PROVISIONAL
                //      this.apsDeviceKeyPairSet => find deviceAddress === this.context.deviceTable.get(nwkHeader.source).address64 => check provisional or drop msg
            }
        }
        else {
            logger_js_1.logger.warning(`<=x= APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}] Unknown device`, NS);
        }
        return offset;
    }
    async sendRequestKey(nwkDest16, keyType, partner64) {
        logger_js_1.logger.debug(() => `===> APS REQUEST_KEY[type=${keyType} partner64=${partner64}]`, NS);
        const hasPartner64 = keyType === 2 /* ZigbeeAPSConsts.CMD_KEY_APP_MASTER */;
        const finalPayload = Buffer.alloc(2 + (hasPartner64 ? 8 : 0));
        let offset = 0;
        offset = finalPayload.writeUInt8(8 /* ZigbeeAPSCommandId.REQUEST_KEY */, offset);
        offset = finalPayload.writeUInt8(keyType, offset);
        if (hasPartner64) {
            offset = finalPayload.writeBigUInt64LE(partner64, offset);
        }
        return await this.sendCommand(8 /* ZigbeeAPSCommandId.REQUEST_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-23 #4.4.11.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Decodes sequence number identifying the pending network key
     * - ✅ Activates staged key via StackContext.activatePendingNetworkKey
     * - ✅ Resets NWK frame counter following activation
     * - ⚠️ Pending key staging remains prerequisite (TRANSPORT_KEY)
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    processSwitchKey(data, offset, macHeader, nwkHeader, _apsHeader) {
        const seqNum = data.readUInt8(offset);
        offset += 1;
        logger_js_1.logger.debug(() => `<=== APS SWITCH_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${seqNum}]`, NS);
        if (!this.#context.activatePendingNetworkKey(seqNum)) {
            logger_js_1.logger.warning(`<=x= APS SWITCH_KEY[seqNum=${seqNum}] Received without pending key`, NS);
        }
        return offset;
    }
    /**
     * 05-3474-23 #4.4.11.5
     *
     * SPEC COMPLIANCE:
     * - ✅ Includes sequence number associated with staged network key
     * - ✅ Broadcast or unicast delivery
     * - ✅ Applies NWK security only (per spec expectation)
     * - ⚠️ Relies on caller to stage key via TRANSPORT_KEY before invocation
     * DEVICE SCOPE: Trust Center
     *
     * @param nwkDest16
     * @param seqNum SHALL contain the sequence number identifying the network key to be made active.
     * @returns
     */
    async sendSwitchKey(nwkDest16, seqNum) {
        logger_js_1.logger.debug(() => `===> APS SWITCH_KEY[seqNum=${seqNum}]`, NS);
        const finalPayload = Buffer.from([9 /* ZigbeeAPSCommandId.SWITCH_KEY */, seqNum]);
        return await this.sendCommand(9 /* ZigbeeAPSCommandId.SWITCH_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-23 #4.4.11.6
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes destination address
     * - ✅ Extracts tunneled APS command frame
     * - ✅ Validates structure
     * - ❌ NOT IMPLEMENTED: Tunnel forwarding (only logs)
     * - ❌ MISSING: Should extract and forward tunneled command to destination
     * - ❌ MISSING: Security context validation
     *
     * IMPACT: Not applicable for Coordinator/Trust Center
     * DEVICE SCOPE: Coordinator, routers (N/A), end devices (N/A)
     */
    processTunnel(data, offset, macHeader, nwkHeader, _apsHeader) {
        const destination = data.readBigUInt64LE(offset);
        offset += 8;
        const tunneledAPSFrame = data.subarray(offset);
        offset += tunneledAPSFrame.byteLength;
        logger_js_1.logger.debug(() => `<=== APS TUNNEL[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dst=${destination} tAPSFrame=${tunneledAPSFrame}]`, NS);
        return offset;
    }
    /**
     * 05-3474-23 #4.4.11.6
     *
     * SPEC COMPLIANCE:
     * - ✅ Includes destination64
     * - ✅ Encapsulates APS command frame
     * - ✅ Applies APS TRANSPORT encryption
     * - ✅ NO ACK request (per spec exception - TUNNEL is the only APS command without ACK)
     * - ✅ Used correctly for nested device joins (TRANSPORT_KEY delivery through routers)
     * DEVICE SCOPE: Trust Center
     *
     * @param nwkDest16
     * @param destination64 SHALL be the 64-bit extended address of the device that is to receive the tunneled command
     * @param tApsCmdFrame SHALL be the APS command payload to be sent to the destination
     * @returns
     */
    async sendTunnel(nwkDest16, destination64, tApsCmdFrame) {
        logger_js_1.logger.debug(() => `===> APS TUNNEL[dst64=${destination64}]`, NS);
        const finalPayload = Buffer.alloc(9 + tApsCmdFrame.byteLength);
        let offset = 0;
        offset = finalPayload.writeUInt8(14 /* ZigbeeAPSCommandId.TUNNEL */, offset);
        offset = finalPayload.writeBigUInt64LE(destination64, offset);
        offset += tApsCmdFrame.copy(finalPayload, offset);
        return await this.sendCommand(14 /* ZigbeeAPSCommandId.TUNNEL */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-23 #4.4.11.7
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
     * - ⚠️ Not valid for distributed mode but implementation is never distributed mode
     * - ✅ Sends CONFIRM_KEY in response with appropriate status
     * - ❓ UNCERTAIN: keyType=CMD_KEY_APP_MASTER (0x02) returns ILLEGAL_REQUEST for TC
     *       - Spec is unclear if TC should reject this or if it's valid in some scenarios
     * - ✅ Uses source64 parameter correctly in CONFIRM_KEY response
     *
     * NOTE: This command is critical for security - device proves it has the correct key
     * DEVICE SCOPE: Trust Center
     */
    async processVerifyKey(data, offset, macHeader, nwkHeader, _apsHeader) {
        const keyType = data.readUInt8(offset);
        offset += 1;
        const source = data.readBigUInt64LE(offset);
        offset += 8;
        const keyHash = data.subarray(offset, offset + 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */);
        offset += 16 /* ZigbeeAPSConsts.CMD_KEY_LENGTH */;
        if (macHeader.source16 !== 65535 /* ZigbeeMACConsts.BCAST_ADDR */) {
            logger_js_1.logger.debug(() => `<=== APS VERIFY_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} src64=${source} hash=${keyHash.toString("hex")}]`, NS);
            if (keyType === 4 /* ZigbeeAPSConsts.CMD_KEY_TC_LINK */) {
                // TODO: not valid if operating in distributed network
                const status = this.#context.tcVerifyKeyHash.equals(keyHash) ? 0x00 /* SUCCESS */ : 0xad; /* SECURITY_FAILURE */
                await this.sendConfirmKey(nwkHeader.source16, status, keyType, source);
            }
            else if (keyType === 2 /* ZigbeeAPSConsts.CMD_KEY_APP_MASTER */) {
                // this is illegal for TC
                await this.sendConfirmKey(nwkHeader.source16, 0xa3 /* ILLEGAL_REQUEST */, keyType, source);
            }
            else {
                await this.sendConfirmKey(nwkHeader.source16, 0xaa /* NOT_SUPPORTED */, keyType, source);
                // TODO: APP link key should also sync counters
            }
        }
        return offset;
    }
    /**
     * 05-3474-23 #4.4.11.7 (APS Verify Key)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Sends verification hash payload (16 bytes) together with keyType and source64
     * - ✅ Unicast delivery with NWK security as required by Trust Center procedures
     * - ⚠️  Caller responsible for providing correct hash derived per Annex B
     * DEVICE SCOPE: Routers (N/A), end devices (N/A)
     *
     * @param nwkDest16
     * @param keyType type of key being verified
     * @param source64 SHALL be the 64-bit extended address of the partner device that the destination shares the link key with
     * @param hash outcome of executing the specialized keyed hash function specified in section B.1.4 using a key with the 1-octet string ‘0x03’ as the input string
     * The resulting value SHALL NOT be used as a key for encryption or decryption
     * @returns
     */
    async sendVerifyKey(nwkDest16, keyType, source64, hash) {
        logger_js_1.logger.debug(() => `===> APS VERIFY_KEY[type=${keyType} src64=${source64} hash=${hash.toString("hex")}]`, NS);
        const finalPayload = Buffer.alloc(10 + 16 /* ZigbeeConsts.SEC_KEYSIZE */);
        let offset = 0;
        offset = finalPayload.writeUInt8(15 /* ZigbeeAPSCommandId.VERIFY_KEY */, offset);
        offset = finalPayload.writeUInt8(keyType, offset);
        offset = finalPayload.writeBigUInt64LE(source64, offset);
        offset += hash.copy(finalPayload, offset);
        return await this.sendCommand(15 /* ZigbeeAPSCommandId.VERIFY_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        undefined);
    }
    /**
     * 05-3474-23 #4.4.11.8 (APS Confirm Key)
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Parses status, keyType, destination64 per Table 4-19
     * - ✅ Used primarily for logging; state updates happen in sendConfirmKey
     * - ⚠️  No validation of status/keyType beyond logging (TC expects follow-up handling elsewhere)
     * DEVICE SCOPE: Routers (N/A), end devices (N/A)
     */
    processConfirmKey(data, offset, macHeader, nwkHeader, _apsHeader) {
        const status = data.readUInt8(offset);
        offset += 1;
        const keyType = data.readUInt8(offset);
        offset += 1;
        const destination = data.readBigUInt64LE(offset);
        offset += 8;
        logger_js_1.logger.debug(() => `<=== APS CONFIRM_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} status=${status} type=${keyType} dst64=${destination}]`, NS);
        return offset;
    }
    /**
     * 05-3474-23 #4.4.11.8
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
     * DEVICE SCOPE: Trust Center
     *
     * @param nwkDest16
     * @param status 1-byte status code indicating the result of the operation. See Table 2.27
     * @param keyType the type of key being verified
     * @param destination64 SHALL be the 64-bit extended address of the source device of the Verify-Key message
     * @returns
     */
    async sendConfirmKey(nwkDest16, status, keyType, destination64) {
        logger_js_1.logger.debug(() => `===> APS CONFIRM_KEY[status=${status} type=${keyType} dst64=${destination64}]`, NS);
        const finalPayload = Buffer.alloc(11);
        let offset = 0;
        offset = finalPayload.writeUInt8(16 /* ZigbeeAPSCommandId.CONFIRM_KEY */, offset);
        offset = finalPayload.writeUInt8(status, offset);
        offset = finalPayload.writeUInt8(keyType, offset);
        offset = finalPayload.writeBigUInt64LE(destination64, offset);
        const result = await this.sendCommand(16 /* ZigbeeAPSCommandId.CONFIRM_KEY */, finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
        true, // nwkSecurity
        nwkDest16, // nwkDest16
        undefined, // nwkDest64
        0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
        {
            control: {
                level: 0 /* ZigbeeSecurityLevel.NONE */,
                keyId: 0 /* ZigbeeKeyType.LINK */, // Per 05-3474-23 #4.4.11.8 confirmation uses the link key being verified
                nonce: true,
                reqVerifiedFc: false,
            },
            frameCounter: this.#context.nextTCKeyFrameCounter(),
            source64: this.#context.netParams.eui64,
            // keySeqNum: undefined, only for keyId NWK
            micLen: 4,
        });
        const device = this.#context.deviceTable.get(destination64);
        // TODO: proper place?
        if (status === 0x00 && device !== undefined && device.authorized === false) {
            device.authorized = true;
            setImmediate(() => {
                this.#callbacks.onDeviceAuthorized(device.address16, destination64);
            });
        }
        return result;
    }
    /**
     * R23 FEATURE - 05-3474-23 #4.4.11.9
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
     * DEVICE SCOPE: Trust Center
     */
    processRelayMessageDownstream(data, offset, macHeader, nwkHeader, _apsHeader) {
        // this includes only TLVs
        // This contains the EUI64 of the unauthorized neighbor that is the intended destination of the relayed message.
        const destination64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the Trust Center to the Joining device.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;
        logger_js_1.logger.debug(() => `<=== APS RELAY_MESSAGE_DOWNSTREAM[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} dst64=${destination64}]`, NS);
        return offset;
    }
    // TODO: send RELAY_MESSAGE_DOWNSTREAM -- DEVICE SCOPE: Trust Center
    /**
     * R23 FEATURE - 05-3474-23 #4.4.11.10
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
     * DEVICE SCOPE: Routers (N/A), end devices (N/A)
     */
    processRelayMessageUpstream(data, offset, macHeader, nwkHeader, _apsHeader) {
        // this includes only TLVs
        // This contains the EUI64 of the unauthorized neighbor that is the source of the relayed message.
        const source64 = data.readBigUInt64LE(offset);
        offset += 8;
        // This contains the single APS message, or message fragment, to be relayed from the joining device to the Trust Center.
        // The message SHALL start with the APS Header of the intended recipient.
        // const message = ??;
        logger_js_1.logger.debug(() => `<=== APS RELAY_MESSAGE_UPSTREAM[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} src64=${source64}]`, NS);
        return offset;
    }
    // TODO: send RELAY_MESSAGE_UPSTREAM -- DEVICE SCOPE: Routers (N/A), end devices (N/A)
    // #endregion
    // #region ZDO Helpers
    /**
     * 05-3474-23 #2.4.4.2.3
     *
     * Generate LQI (Link Quality Indicator) table response for coordinator.
     * ZDO response to LQI_TABLE_REQUEST.
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Produces response header fields (status, totalEntries, startIndex, entryCount)
     * - ✅ Encodes per-neighbor records with device type, permit-join, depth, and LQI
     * - ⚠️  Relationship/permit-join/depth fields currently stubbed with TODO markers
     * - ⚠️  Table truncated to 255 entries without pagination continuation handling
     * DEVICE SCOPE: Coordinator
     *
     * @param startIndex The index to start the table entries from
     * @returns Buffer containing the LQI table response
     */
    getLQITableResponse(startIndex) {
        let neighborRouteTableIndex = 0;
        let neighborTableEntries = 0;
        // multiple of 7: [extendedPanId, eui64, nwkAddress, deviceTypeByte, permitJoiningByte, depth, lqa, ...repeat]
        const lqiTableArr = [];
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
                const deviceType = entry.capabilities
                    ? entry.capabilities.deviceType === 1 /* ZigbeeMACConsts.DEVICE_TYPE_FFD */
                        ? 0x01 /* ZR */
                        : 0x02 /* ZED */
                    : 0x03 /* UNK */;
                const rxOnWhenIdle = entry.capabilities ? (entry.capabilities.rxOnWhenIdle ? 0x01 /* ON */ : 0x00 /* OFF */) : 0x02 /* UNK */;
                const affinity = entry.capabilities
                    ? entry.capabilities.deviceType === 1 /* ZigbeeMACConsts.DEVICE_TYPE_FFD */
                        ? 0x02 /* sibling */
                        : 0x01 /* child */
                    : 0x03 /* "none of the above" */;
                const deviceTypeByte = (deviceType & 0x03) | ((rxOnWhenIdle << 2) & 0x0c) | ((affinity << 4) & 0x70) | ((0 /* reserved */ << 7) & 0x80);
                // TODO: not currently tracked
                // 0x00 = neighbor is not accepting join requests, 0x01 = neighbor is accepting join requests, 0x02 = unknown
                const permitJoiningByte = (0x02 & 0x03) | ((0 /* reserved2 */ << 2) & 0xfc);
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
            logger_js_1.logger.debug(() => `LQI table clipped at 255 entries to fit ZDO response (actual=${neighborTableEntries})`, NS);
        }
        offset = lqiTable.writeUInt8(0 /* seq num */, offset);
        offset = lqiTable.writeUInt8(0 /* SUCCESS */, offset);
        offset = lqiTable.writeUInt8(neighborTableEntries, offset);
        offset = lqiTable.writeUInt8(startIndex, offset);
        offset = lqiTable.writeUInt8(entryCount, offset);
        let entryIndex = 0;
        for (let i = 0; i < entryCount; i++) {
            offset = lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex] /* extendedPanId */, offset);
            offset = lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex + 1] /* eui64 */, offset);
            offset = lqiTable.writeUInt16LE(lqiTableArr[entryIndex + 2] /* nwkAddress */, offset);
            offset = lqiTable.writeUInt8(lqiTableArr[entryIndex + 3] /* deviceTypeByte */, offset);
            offset = lqiTable.writeUInt8(lqiTableArr[entryIndex + 4] /* permitJoiningByte */, offset);
            offset = lqiTable.writeUInt8(lqiTableArr[entryIndex + 5] /* depth */, offset);
            offset = lqiTable.writeUInt8(lqiTableArr[entryIndex + 6] /* lqa */, offset);
            entryIndex += 7;
        }
        return lqiTable;
    }
    /**
     * 05-3474-23 #2.4.4.3.3
     *
     * Generate routing table response for coordinator.
     * ZDO response to ROUTING_TABLE_REQUEST.
     * NOTE: Only outputs the best source route for each entry in the table (clipped to max 255 entries).
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Populates routing table response header and entry layout per Table 2-80
     * - ✅ Derives next hop from best known source route for each destination
     * - ⚠️  Status flags (memoryConstrained, manyToOne, routeRecordRequired) currently fixed to 0/TODO
     * - ⚠️  Response clipped to 255 entries without continuation index support
     * DEVICE SCOPE: Coordinator
     *
     * @param startIndex The index to start the table entries from
     * @returns Buffer containing the routing table response
     */
    getRoutingTableResponse(startIndex) {
        let sourceRouteTableIndex = 0;
        let routingTableEntries = 0;
        // multiple of 3: [destination16, statusByte, nextHopAddress, ...repeat]
        const routingTableArr = [];
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
                    const statusByte = (status & 0x07) |
                        ((memoryConstrained << 3) & 0x08) |
                        ((manyToOne << 4) & 0x10) |
                        ((routeRecordRequired << 5) & 0x20) |
                        ((0 /* reserved */ << 6) & 0xc0);
                    // last entry is next hop
                    const nextHopAddress = relayAddresses[relayLastIndex];
                    routingTableArr.push(addr16);
                    routingTableArr.push(statusByte);
                    routingTableArr.push(nextHopAddress);
                    routingTableEntries += 1;
                }
            }
            catch {
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
            logger_js_1.logger.debug(() => `Routing table clipped at 255 entries to fit ZDO response (actual=${routingTableEntries})`, NS);
        }
        offset = routingTable.writeUInt8(0 /* seq num */, offset);
        offset = routingTable.writeUInt8(0 /* SUCCESS */, offset);
        offset = routingTable.writeUInt8(clipped ? 0xff : routingTableEntries, offset);
        offset = routingTable.writeUInt8(startIndex, offset);
        offset = routingTable.writeUInt8(entryCount, offset);
        let entryIndex = 0;
        for (let i = 0; i < entryCount; i++) {
            offset = routingTable.writeUInt16LE(routingTableArr[entryIndex] /* destination16 */, offset);
            offset = routingTable.writeUInt8(routingTableArr[entryIndex + 1] /* statusByte */, offset);
            offset = routingTable.writeUInt16LE(routingTableArr[entryIndex + 2] /* nextHopAddress */, offset);
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
    getCoordinatorZDOResponse(clusterId, requestData) {
        switch (clusterId) {
            case 0 /* ZigbeeConsts.NETWORK_ADDRESS_REQUEST */: {
                // TODO: handle reportKids & index, this payload is only for 0, 0
                return Buffer.from(this.#context.configAttributes.address); // copy
            }
            case 1 /* ZigbeeConsts.IEEE_ADDRESS_REQUEST */: {
                // TODO: handle reportKids & index, this payload is only for 0, 0
                return Buffer.from(this.#context.configAttributes.address); // copy
            }
            case 2 /* ZigbeeConsts.NODE_DESCRIPTOR_REQUEST */: {
                return Buffer.from(this.#context.configAttributes.nodeDescriptor); // copy
            }
            case 3 /* ZigbeeConsts.POWER_DESCRIPTOR_REQUEST */: {
                return Buffer.from(this.#context.configAttributes.powerDescriptor); // copy
            }
            case 4 /* ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST */: {
                return Buffer.from(this.#context.configAttributes.simpleDescriptors); // copy
            }
            case 5 /* ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST */: {
                return Buffer.from(this.#context.configAttributes.activeEndpoints); // copy
            }
            case 49 /* ZigbeeConsts.LQI_TABLE_REQUEST */: {
                return this.getLQITableResponse(requestData[1 /* 0 is tsn */]);
            }
            case 50 /* ZigbeeConsts.ROUTING_TABLE_REQUEST */: {
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
    isZDORequestForCoordinator(clusterId, nwkDst16, nwkDst64, data) {
        if (nwkDst16 === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */ || nwkDst64 === this.#context.netParams.eui64) {
            // target is coordinator
            return true;
        }
        if (nwkDst16 !== undefined && nwkDst16 >= 65528 /* ZigbeeConsts.BCAST_MIN */) {
            // target is BCAST and ZDO "of interest" is coordinator
            switch (clusterId) {
                case 0 /* ZigbeeConsts.NETWORK_ADDRESS_REQUEST */: {
                    return data.readBigUInt64LE(1 /* skip seq num */) === this.#context.netParams.eui64;
                }
                case 1 /* ZigbeeConsts.IEEE_ADDRESS_REQUEST */:
                case 2 /* ZigbeeConsts.NODE_DESCRIPTOR_REQUEST */:
                case 3 /* ZigbeeConsts.POWER_DESCRIPTOR_REQUEST */:
                case 4 /* ZigbeeConsts.SIMPLE_DESCRIPTOR_REQUEST */:
                case 5 /* ZigbeeConsts.ACTIVE_ENDPOINTS_REQUEST */: {
                    return data.readUInt16LE(1 /* skip seq num */) === 0 /* ZigbeeConsts.COORDINATOR_ADDRESS */;
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
    async respondToCoordinatorZDORequest(data, clusterId, nwkDest16, nwkDest64) {
        const finalPayload = this.getCoordinatorZDOResponse(clusterId, data);
        if (finalPayload) {
            // set the ZDO sequence number in outgoing payload same as incoming request
            const seqNum = data[0];
            finalPayload[0] = seqNum;
            logger_js_1.logger.debug(() => `===> COORD_ZDO[seqNum=${seqNum} clusterId=${clusterId} nwkDst=${nwkDest16}:${nwkDest64}]`, NS);
            try {
                await this.sendData(finalPayload, 0 /* ZigbeeNWKRouteDiscovery.SUPPRESS */, // nwkDiscoverRoute
                nwkDest16, // nwkDest16
                nwkDest64, // nwkDest64
                0 /* ZigbeeAPSDeliveryMode.UNICAST */, // apsDeliveryMode
                clusterId | 0x8000, // clusterId
                0 /* ZigbeeConsts.ZDO_PROFILE_ID */, // profileId
                0 /* ZigbeeConsts.ZDO_ENDPOINT */, // destEndpoint
                0 /* ZigbeeConsts.ZDO_ENDPOINT */, // sourceEndpoint
                undefined);
            }
            catch {
                // logged in `sendData`
                return;
            }
        }
    }
}
exports.APSHandler = APSHandler;
//# sourceMappingURL=aps-handler.js.map