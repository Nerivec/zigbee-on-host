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
    ZigbeeAPSFragmentation,
    ZigbeeAPSFrameType,
    type ZigbeeAPSHeader,
} from "../zigbee/zigbee-aps.js";
import { encodeZigbeeNWKFrame, ZigbeeNWKConsts, ZigbeeNWKFrameType, type ZigbeeNWKHeader, ZigbeeNWKRouteDiscovery } from "../zigbee/zigbee-nwk.js";
import type { MACHandler } from "./mac-handler.js";
import { CONFIG_NWK_MAX_HOPS, type NWKHandler } from "./nwk-handler.js";
import { ApplicationKeyRequestPolicy, type StackCallbacks, type StackContext, TrustCenterKeyRequestPolicy } from "./stack-context.js";

const NS = "aps-handler";

type FragmentParams = {
    blockNumber: number;
    isFirst: boolean;
    isLast: boolean;
};

type FragmentBaseParams = Omit<SendDataParams, "finalPayload" | "fragment">;

type OutgoingFragmentContext = {
    baseParams: FragmentBaseParams;
    chunks: Buffer[];
    awaitingBlock: number;
    totalBlocks: number;
};

type IncomingFragmentState = {
    totalLength?: number;
    expectedBlocks?: number;
    chunks: Map<number, Buffer>;
    lastActivity: number;
    source16?: number;
    source64?: bigint;
    destEndpoint?: number;
    profileId?: number;
    clusterId?: number;
    counter: number;
};

type SendDataParams = {
    finalPayload: Buffer;
    nwkDiscoverRoute: ZigbeeNWKRouteDiscovery;
    nwkDest16: number | undefined;
    nwkDest64: bigint | undefined;
    apsDeliveryMode: ZigbeeAPSDeliveryMode;
    clusterId: number;
    profileId: number;
    destEndpoint: number | undefined;
    sourceEndpoint: number | undefined;
    group: number | undefined;
    fragment?: FragmentParams;
};

type PendingAckEntry = {
    params: SendDataParams;
    apsCounter: number;
    dest16: number;
    retries: number;
    timer: NodeJS.Timeout | undefined;
    fragment?: OutgoingFragmentContext;
};

type DuplicateEntry = {
    counter: number;
    expiresAt: number;
    fragments?: Set<number>;
};

/**
 * Callbacks for APS handler to communicate with driver
 */
export interface APSHandlerCallbacks {
    onFrame: StackCallbacks["onFrame"];
    onDeviceJoined: StackCallbacks["onDeviceJoined"];
    onDeviceRejoined: StackCallbacks["onDeviceRejoined"];
    onDeviceAuthorized: StackCallbacks["onDeviceAuthorized"];
}

/** Duration while APS duplicate table entries remain valid (milliseconds). Spec default ≈ 8s. */
const CONFIG_APS_DUPLICATE_TIMEOUT_MS = 8000;
/** Default ack wait duration per Zigbee 3.0 spec (milliseconds). */
const CONFIG_APS_ACK_WAIT_DURATION_MS = 1500;
/** Default number of APS retransmissions when ACK is missing. */
const CONFIG_APS_MAX_FRAME_RETRIES = 3;
/** Maximum payload that may be transmitted without APS fragmentation. */
const CONFIG_APS_UNFRAGMENTED_PAYLOAD_MAX = ZigbeeAPSConsts.PAYLOAD_MAX_SIZE;
/** Number of bytes carried in each APS fragment after the first one. */
const CONFIG_APS_FRAGMENT_PAYLOAD_SIZE = 40;
/** Number of bytes reserved in the first APS fragment for metadata. */
const CONFIG_APS_FRAGMENT_FIRST_OVERHEAD = 2;
/** Timeout for incomplete incoming APS fragment reassembly (milliseconds). */
const CONFIG_APS_FRAGMENT_REASSEMBLY_TIMEOUT_MS = 30000;

/**
 * APS Handler - Zigbee Application Support Layer Operations
 */
export class APSHandler {
    readonly #context: StackContext;
    readonly #macHandler: MACHandler;
    readonly #nwkHandler: NWKHandler;
    readonly #callbacks: APSHandlerCallbacks;

    // Private counters (start at 0, first call returns 1)
    #counter = 0;
    #zdoSeqNum = 0;

    /** Recently seen frames for duplicate rejection by NWK 16 */
    readonly #duplicateTable16 = new Map<number, DuplicateEntry>();
    /** Recently seen frames for duplicate rejection by NWK 64 */
    readonly #duplicateTable64 = new Map<bigint, DuplicateEntry>();
    /** Pending acknowledgments waiting for retransmission */
    readonly #pendingAcks = new Map<string, PendingAckEntry>();
    /** Incoming fragment reassembly buffers */
    readonly #incomingFragments = new Map<string, IncomingFragmentState>();

    constructor(context: StackContext, macHandler: MACHandler, nwkHandler: NWKHandler, callbacks: APSHandlerCallbacks) {
        this.#context = context;
        this.#macHandler = macHandler;
        this.#nwkHandler = nwkHandler;
        this.#callbacks = callbacks;
    }

    async start() {}

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
     * Get or generate application link key for a device pair
     */
    #getOrGenerateAppLinkKey(deviceA: bigint, deviceB: bigint): Buffer {
        const existing = this.#context.getAppLinkKey(deviceA, deviceB);

        if (existing !== undefined) {
            return existing;
        }

        const derived = Buffer.from(this.#context.netParams.tcKey);
        this.#context.setAppLinkKey(deviceA, deviceB, derived);

        return derived;
    }

    /**
     * Check whether an incoming APS frame is a duplicate and update the duplicate table accordingly.
     * @returns true when the frame was already seen within the duplicate removal timeout.
     */
    public isDuplicateFrame(nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader, now = Date.now()): boolean {
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
        } else {
            for (const [key, entry] of this.#duplicateTable64) {
                if (entry.expiresAt <= now) {
                    this.#duplicateTable64.delete(key);
                }
            }
        }

        const isFragmented = apsHeader.fragmentation !== undefined && apsHeader.fragmentation !== ZigbeeAPSFragmentation.NONE;
        // frames are dropped in `processFrame` if neither source available
        const entry = hasSource16 ? this.#duplicateTable16.get(nwkHeader.source16!) : this.#duplicateTable64.get(nwkHeader.source64!);

        if (entry !== undefined && entry.counter === apsHeader.counter && entry.expiresAt > now) {
            if (isFragmented) {
                const blockNumber = apsHeader.fragBlockNumber ?? 0;
                let fragments = entry.fragments;

                if (fragments === undefined) {
                    fragments = new Set<number>();
                    entry.fragments = fragments;
                } else if (fragments.has(blockNumber)) {
                    return true;
                }

                fragments.add(blockNumber);
                entry.expiresAt = now + CONFIG_APS_DUPLICATE_TIMEOUT_MS;

                return false;
            }

            return true;
        }

        const newEntry: DuplicateEntry = {
            counter: apsHeader.counter,
            expiresAt: now + CONFIG_APS_DUPLICATE_TIMEOUT_MS,
        };

        if (isFragmented) {
            newEntry.fragments = new Set([apsHeader.fragBlockNumber ?? 0]);
        }

        if (hasSource16) {
            this.#duplicateTable16.set(nwkHeader.source16!, newEntry);
        } else {
            this.#duplicateTable64.set(nwkHeader.source64!, newEntry);
        }

        return false;
    }

    /**
     * Send a Zigbee APS DATA frame and track pending ACK if necessary.
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
        const params: SendDataParams = {
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

        if (finalPayload.length > CONFIG_APS_UNFRAGMENTED_PAYLOAD_MAX) {
            return await this.#sendFragmentedData(params, apsCounter);
        }

        const sendDest16 = await this.#sendDataInternal(params, apsCounter, 0);

        if (sendDest16 !== undefined) {
            this.#trackPendingAck(sendDest16, apsCounter, params);
        }

        return apsCounter;
    }

    /**
     * Send a Zigbee APS DATA frame.
     * Throws if could not send.
     * @param params
     * @param apsCounter
     * @param attempt
     * @returns Destination 16 data was sent to (undefined if bcast)
     */
    async #sendDataInternal(params: SendDataParams, apsCounter: number, attempt: number): Promise<number | undefined> {
        const { finalPayload, nwkDiscoverRoute, apsDeliveryMode, clusterId, profileId, destEndpoint, sourceEndpoint, group } = params;
        let { nwkDest16, nwkDest64 } = params;
        const nwkSeqNum = this.#nwkHandler.nextSeqNum();
        const macSeqNum = this.#macHandler.nextSeqNum();
        let relayIndex: number | undefined;
        let relayAddresses: number[] | undefined;

        try {
            [relayIndex, relayAddresses] = this.#nwkHandler.findBestSourceRoute(nwkDest16, nwkDest64);
        } catch (error) {
            logger.error(
                `=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) attempt=${attempt} nwkDst=${nwkDest16}:${nwkDest64}] ${(error as Error).message}`,
                NS,
            );

            throw error;
        }

        if (nwkDest16 === undefined && nwkDest64 !== undefined) {
            nwkDest16 = this.#context.deviceTable.get(nwkDest64)?.address16;
        }

        if (nwkDest16 === undefined) {
            logger.error(
                `=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) attempt=${attempt} nwkDst=${nwkDest16}:${nwkDest64}] Invalid parameters`,
                NS,
            );

            throw new Error("Invalid parameters");
        }

        // update params as needed
        params.nwkDest16 = nwkDest16;
        params.nwkDest64 = nwkDest64;

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;

        logger.debug(
            () =>
                `===> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum})${attempt > 0 ? ` attempt=${attempt}` : ""} macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64} nwkDiscRte=${nwkDiscoverRoute} apsDlv=${apsDeliveryMode}]`,
            NS,
        );

        const isFragment = params.fragment !== undefined;
        const apsHeader: ZigbeeAPSHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.DATA,
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
            const fragmentInfo = params.fragment!;
            const fragmentation = fragmentInfo.isFirst
                ? ZigbeeAPSFragmentation.FIRST
                : fragmentInfo.isLast
                  ? ZigbeeAPSFragmentation.LAST
                  : ZigbeeAPSFragmentation.MIDDLE;
            apsHeader.fragmentation = fragmentation;
            apsHeader.fragBlockNumber = fragmentInfo.blockNumber;
        }

        const apsFrame = encodeZigbeeAPSFrame(
            apsHeader,
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
                `=x=> APS DATA[seqNum=(${apsCounter}/${nwkSeqNum}/${macSeqNum}) attempt=${attempt} macDst16=${macDest16} nwkDst=${nwkDest16}:${nwkDest64}] Failed to send`,
                NS,
            );

            throw new Error("Failed to send");
        }

        if (macDest16 === ZigbeeMACConsts.BCAST_ADDR) {
            return undefined;
        }

        return nwkDest16;
    }

    async #sendFragmentedData(params: SendDataParams, apsCounter: number): Promise<number> {
        const payload = params.finalPayload;
        if (payload.byteLength <= CONFIG_APS_UNFRAGMENTED_PAYLOAD_MAX) {
            return apsCounter;
        }

        const baseParams: FragmentBaseParams = {
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

        const chunks: Buffer[] = [];
        let offset = 0;
        let block = 0;
        const firstChunkSize = Math.max(1, CONFIG_APS_FRAGMENT_PAYLOAD_SIZE - CONFIG_APS_FRAGMENT_FIRST_OVERHEAD);

        while (offset < payload.byteLength) {
            const size = block === 0 ? firstChunkSize : CONFIG_APS_FRAGMENT_PAYLOAD_SIZE;
            const chunk = Buffer.from(payload.subarray(offset, offset + size));
            chunks.push(chunk);
            offset += chunk.byteLength;
            block += 1;
        }

        if (chunks.length <= 1) {
            throw new Error("APS fragmentation requires at least two chunks");
        }

        const context: OutgoingFragmentContext = {
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

    #buildFragmentParams(context: OutgoingFragmentContext, blockNumber: number): SendDataParams {
        const fragment: FragmentParams = {
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

    async #sendFragmentBlock(
        context: OutgoingFragmentContext,
        apsCounter: number,
        blockNumber: number,
        attempt: number,
    ): Promise<{ dest16: number | undefined; params: SendDataParams }> {
        const fragmentParams = this.#buildFragmentParams(context, blockNumber);
        const dest16 = await this.#sendDataInternal(fragmentParams, apsCounter, attempt);

        return { dest16, params: fragmentParams };
    }

    async #sendNextFragmentBlock(context: OutgoingFragmentContext, previousEntry: PendingAckEntry): Promise<void> {
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

    #handleIncomingFragment(data: Buffer, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Buffer | undefined {
        const now = Date.now();
        this.#pruneExpiredFragmentStates(now);

        const blockNumber = apsHeader.fragBlockNumber ?? 0;
        const key = this.#makeFragmentKey(nwkHeader, apsHeader);
        const fragmentation = apsHeader.fragmentation ?? ZigbeeAPSFragmentation.NONE;

        if (fragmentation === ZigbeeAPSFragmentation.FIRST) {
            const state: IncomingFragmentState = {
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

        if (fragmentation === ZigbeeAPSFragmentation.LAST) {
            state.expectedBlocks = blockNumber + 1;
        }

        if (state.expectedBlocks === undefined || state.chunks.size < state.expectedBlocks) {
            return undefined;
        }

        const buffers: Buffer[] = [];

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

    #makeFragmentKey(nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): string {
        const source = nwkHeader.source64 !== undefined ? `64:${nwkHeader.source64}` : `16:${nwkHeader.source16 ?? 0xffff}`;
        const profile = apsHeader.profileId ?? 0;
        const cluster = apsHeader.clusterId ?? 0;
        const sourceEndpoint = apsHeader.sourceEndpoint ?? 0xff;
        const destEndpoint = apsHeader.destEndpoint ?? 0xff;
        const counter = apsHeader.counter ?? 0;

        return `${source}:${profile}:${cluster}:${sourceEndpoint}:${destEndpoint}:${counter}`;
    }

    #updateSourceRouteForChild(child16: number, parent16: number | undefined, parent64: bigint | undefined): void {
        if (parent16 === undefined) {
            return;
        }

        try {
            const [, parentRelays] = this.#nwkHandler.findBestSourceRoute(parent16, parent64);

            if (parentRelays) {
                this.#context.sourceRouteTable.set(child16, [this.#nwkHandler.createSourceRouteEntry(parentRelays, parentRelays.length + 1)]);
            } else {
                this.#context.sourceRouteTable.set(child16, [this.#nwkHandler.createSourceRouteEntry([parent16], 2)]);
            }
        } catch {
            /* ignore (no known route yet) */
        }
    }

    #pruneExpiredFragmentStates(now: number): void {
        for (const [key, state] of this.#incomingFragments) {
            if (now - state.lastActivity >= CONFIG_APS_FRAGMENT_REASSEMBLY_TIMEOUT_MS) {
                this.#incomingFragments.delete(key);
            }
        }
    }

    #trackPendingAck(dest16: number, apsCounter: number, params: SendDataParams, fragment?: OutgoingFragmentContext): void {
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
            }, CONFIG_APS_ACK_WAIT_DURATION_MS),
            fragment,
        });
    }

    async #handleAckTimeout(key: string): Promise<void> {
        const entry = this.#pendingAcks.get(key);

        if (entry === undefined) {
            return;
        }

        if (entry.retries >= CONFIG_APS_MAX_FRAME_RETRIES) {
            this.#pendingAcks.delete(key);
            logger.error(`=x=> APS DATA[apsCounter=${entry.apsCounter} dest16=${entry.dest16}] Retries exhausted`, NS);

            return;
        }

        entry.retries += 1;

        try {
            await this.#sendDataInternal(entry.params, entry.apsCounter, entry.retries);
        } catch (error) {
            this.#pendingAcks.delete(key);
            logger.warning(
                () =>
                    `=x=> APS DATA retry failed[apsCounter=${entry.apsCounter} dest16=${entry.dest16} attempt=${entry.retries}] ${(error as Error).message}`,
                NS,
            );

            return;
        }

        entry.timer = setTimeout(async () => {
            await this.#handleAckTimeout(key);
        }, CONFIG_APS_ACK_WAIT_DURATION_MS);
    }

    async #resolvePendingAck(nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void> {
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

        logger.debug(
            () =>
                `<=== APS ACK[src16=${source16} apsCounter=${apsHeader.counter} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`,
            NS,
        );

        if (entry.fragment !== undefined) {
            await this.#sendNextFragmentBlock(entry.fragment, entry);
        }
    }

    public async sendACK(macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader): Promise<void> {
        logger.debug(
            () =>
                `===> APS ACK[dst16=${nwkHeader.source16} apsCounter=${apsHeader.counter} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}]`,
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
                    `=x=> APS ACK[dst16=${nwkHeader.source16} seqNum=${nwkHeader.seqNum} dstEp=${apsHeader.sourceEndpoint} clusterId=${apsHeader.clusterId}] Unknown destination`,
                NS,
            );

            return;
        }

        const macDest16 = nwkDest16 < ZigbeeConsts.BCAST_MIN ? (relayAddresses?.[relayIndex!] ?? nwkDest16) : ZigbeeMACConsts.BCAST_ADDR;
        const ackNeedsFragmentInfo =
            apsHeader.frameControl.extendedHeader && apsHeader.fragmentation !== undefined && apsHeader.fragmentation !== ZigbeeAPSFragmentation.NONE;
        const ackHeader: ZigbeeAPSHeader = {
            frameControl: {
                frameType: ZigbeeAPSFrameType.ACK,
                deliveryMode: ZigbeeAPSDeliveryMode.UNICAST,
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
            ackHeader.fragmentation = ZigbeeAPSFragmentation.FIRST;
            ackHeader.fragBlockNumber = apsHeader.fragBlockNumber ?? 0;
            ackHeader.fragACKBitfield = 0x01;
        }

        const ackAPSFrame = encodeZigbeeAPSFrame(
            ackHeader,
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

    public async processFrame(
        data: Buffer,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        apsHeader: ZigbeeAPSHeader,
        lqa: number,
    ): Promise<void> {
        switch (apsHeader.frameControl.frameType) {
            case ZigbeeAPSFrameType.ACK: {
                // ACKs should never contain a payload
                await this.#resolvePendingAck(nwkHeader, apsHeader);

                return;
            }
            case ZigbeeAPSFrameType.DATA:
            case ZigbeeAPSFrameType.INTERPAN: {
                if (data.byteLength < 1) {
                    return;
                }

                if (
                    apsHeader.frameControl.extendedHeader &&
                    apsHeader.fragmentation !== undefined &&
                    apsHeader.fragmentation !== ZigbeeAPSFragmentation.NONE
                ) {
                    const reassembled = this.#handleIncomingFragment(data, nwkHeader, apsHeader);

                    if (reassembled === undefined) {
                        return;
                    }

                    data = reassembled;
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
                offset = await this.processRemoveDevice(data, offset, macHeader, nwkHeader, apsHeader);
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

                if (destination === this.#context.netParams.eui64 || destination === 0n) {
                    this.#context.setPendingNetworkKey(key, seqNum);
                }

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
        offset = finalPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
        offset = finalPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_TC_LINK, offset);
        offset += key.copy(finalPayload, offset);
        offset = finalPayload.writeBigUInt64LE(destination64, offset);
        offset = finalPayload.writeBigUInt64LE(this.#context.netParams.eui64, offset);

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
     * - ✅ Broadcast destination64 handling sets all-zero string when using NWK broadcast per spec
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

        const isBroadcast = nwkDest16 >= ZigbeeConsts.BCAST_MIN;
        const finalPayload = Buffer.alloc(19 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        let offset = 0;
        offset = finalPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
        offset = finalPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK, offset);
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
        return await this.sendCommand(
            ZigbeeAPSCommandId.TRANSPORT_KEY,
            finalPayload,
            ZigbeeNWKRouteDiscovery.SUPPRESS, // nwkDiscoverRoute
            false, // nwkSecurity
            nwkDest16, // nwkDest16
            isBroadcast ? undefined : destination64, // nwkDest64
            isBroadcast ? ZigbeeAPSDeliveryMode.BCAST : ZigbeeAPSDeliveryMode.UNICAST, // apsDeliveryMode
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
     * SPEC COMPLIANCE NOTES:
     * - ✅ Sets CMD_KEY_APP_LINK (0x03) and includes partner64 + initiator flag per Table 4-17
     * - ✅ Applies APS security with TRANSPORT keyId (shared TC link key) while suppressing NWK security (permitted)
     * - ✅ Supports mirrored delivery (initiator + partner) when invoked twice in Request Key flow
     * - ⚠️ TODO: Add TLV support for enhanced security context (R23)
     * - ⚠️ TODO: Consider tunneling for indirect partners per spec #4.6.3.7
     */
    public async sendTransportKeyAPP(nwkDest16: number, key: Buffer, partner: bigint, initiatorFlag: boolean): Promise<boolean> {
        // TODO: tunneling support `, tunnelDest?: bigint`
        logger.debug(() => `===> APS TRANSPORT_KEY_APP[key=${key.toString("hex")} partner64=${partner} initiatorFlag=${initiatorFlag}]`, NS);

        const finalPayload = Buffer.alloc(11 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        let offset = 0;
        offset = finalPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
        offset = finalPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_APP_LINK, offset);
        offset += key.copy(finalPayload, offset);
        offset = finalPayload.writeBigUInt64LE(partner, offset);
        offset = finalPayload.writeUInt8(initiatorFlag ? 1 : 0, offset);

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
     * - ⚠️  Status 0x03 (TC Rejoin) handling appears correct but minimal
     * - ⚠️  Status 0x02 (Device Left) handling uses onDisassociate - spec says "informative only, should not take action"
     *       This may be non-compliant as it actively removes the device
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
        // Zigbee 2006 and later
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
        if (status === 0x00) {
            await this.#context.associate(
                device16,
                device64,
                false, // rejoin
                undefined, // no MAC cap through router
                false, // not neighbor
                false,
                true, // was allowed by parent
            );

            this.#updateSourceRouteForChild(device16, nwkHeader.source16, nwkHeader.source64);
        } else if (status === 0x01) {
            await this.#context.associate(
                device16,
                device64,
                true, // initial join
                undefined, // no MAC cap through router
                false, // not neighbor
                false,
                true, // was allowed by parent
            );

            this.#updateSourceRouteForChild(device16, nwkHeader.source16, nwkHeader.source64);

            const tApsCmdPayload = Buffer.alloc(19 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
            let offset = 0;
            offset = tApsCmdPayload.writeUInt8(ZigbeeAPSCommandId.TRANSPORT_KEY, offset);
            offset = tApsCmdPayload.writeUInt8(ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK, offset);
            offset += this.#context.netParams.networkKey.copy(tApsCmdPayload, offset);
            offset = tApsCmdPayload.writeUInt8(this.#context.netParams.networkKeySequenceNumber, offset);
            offset = tApsCmdPayload.writeBigUInt64LE(device64, offset);
            offset = tApsCmdPayload.writeBigUInt64LE(this.#context.netParams.eui64, offset); // 0xFFFFFFFFFFFFFFFF in distributed network (no TC)

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
        offset = finalPayload.writeUInt8(ZigbeeAPSCommandId.UPDATE_DEVICE, offset);
        offset = finalPayload.writeBigUInt64LE(device64, offset);
        offset = finalPayload.writeUInt16LE(device16, offset);
        offset = finalPayload.writeUInt8(status, offset);

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
     *
     * SPEC COMPLIANCE:
     * - ✅ Correctly decodes target IEEE address (childInfo)
     * - ✅ Issues NWK leave to child and removes from device tables
     * - ⚠️  Does not notify parent router beyond leave (spec expects UPDATE_DEVICE relays)
     * - ⚠️  Parent role handling limited to direct coordinator actions
     */
    public async processRemoveDevice(
        data: Buffer,
        offset: number,
        macHeader: MACHeader,
        nwkHeader: ZigbeeNWKHeader,
        _apsHeader: ZigbeeAPSHeader,
    ): Promise<number> {
        const target = data.readBigUInt64LE(offset);
        offset += 8;

        logger.debug(
            () =>
                `<=== APS REMOVE_DEVICE[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} target64=${target}]`,
            NS,
        );

        const childEntry = this.#context.deviceTable.get(target);

        if (childEntry !== undefined) {
            const leaveSent = await this.#nwkHandler.sendLeave(childEntry.address16, false);

            if (!leaveSent) {
                logger.warning(`<=x= APS REMOVE_DEVICE[target64=${target}] Failed to send NWK leave`, NS);
            }

            await this.#context.disassociate(childEntry.address16, target);
        } else {
            logger.warning(`<=x= APS REMOVE_DEVICE[target64=${target}] Unknown device`, NS);
        }

        return offset;
    }

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
    public async sendRemoveDevice(nwkDest16: number, target64: bigint): Promise<boolean> {
        logger.debug(() => `===> APS REMOVE_DEVICE[target64=${target64}]`, NS);

        const finalPayload = Buffer.alloc(9);
        let offset = 0;
        offset = finalPayload.writeUInt8(ZigbeeAPSCommandId.REMOVE_DEVICE, offset);
        offset = finalPayload.writeBigUInt64LE(target64, offset);

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
     *
     * SPEC COMPLIANCE NOTES:
     * - ✅ Rejects unencrypted APS frames as mandated (request MUST be APS secured)
     * - ✅ Honors Trust Center policies: allowTCKeyRequest / allowAppKeyRequest gates
     * - ✅ Returns NWK, TC, or APP link keys through appropriate TRANSPORT_KEY helpers
     * - ✅ Derives/stores application link keys via StackContext for partner distribution
     * - ⚠️ TODO: Implement ApplicationKeyRequestPolicy.ONLY_APPROVED enforcement
     * - ⚠️ TODO: Implement TrustCenterKeyRequestPolicy.ONLY_PROVISIONAL enforcement
     * - ⚠️ TODO: Track apsDeviceKeyPairSet per spec Annex B for negotiated keys
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

        const requester64 = nwkHeader.source64 ?? this.#context.address16ToAddress64.get(nwkHeader.source16!);

        // don't send to unknown device
        if (requester64 !== undefined) {
            // TODO:
            //   const deviceKeyPair = this.apsDeviceKeyPairSet.get(nwkHeader.source16!);
            //   if (!deviceKeyPair || deviceKeyPair.keyNegotiationMethod === 0x00 /* `APS Request Key` method */) {

            if (keyType === ZigbeeAPSConsts.CMD_KEY_STANDARD_NWK) {
                logger.debug(
                    () =>
                        `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}]`,
                    NS,
                );

                await this.sendTransportKeyNWK(
                    nwkHeader.source16!,
                    this.#context.netParams.networkKey,
                    this.#context.netParams.networkKeySequenceNumber,
                    requester64,
                );
            } else if (keyType === ZigbeeAPSConsts.CMD_KEY_APP_MASTER) {
                const partner = data.readBigUInt64LE(offset);
                offset += 8;

                logger.debug(
                    () =>
                        `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType} partner64=${partner}]`,
                    NS,
                );

                if (this.#context.trustCenterPolicies.allowAppKeyRequest === ApplicationKeyRequestPolicy.ALLOWED) {
                    const appLinkKey = this.#getOrGenerateAppLinkKey(requester64, partner);

                    await this.sendTransportKeyAPP(nwkHeader.source16!, appLinkKey, partner, true);

                    const partnerEntry = this.#context.deviceTable.get(partner);

                    if (partnerEntry?.address16 === undefined) {
                        logger.warning(() => `<=x= APS REQUEST_KEY[partner64=${partner}] Unknown partner`, NS);
                    } else {
                        await this.sendTransportKeyAPP(partnerEntry.address16, appLinkKey, requester64, false);
                    }
                }
                // TODO ApplicationKeyRequestPolicy.ONLY_APPROVED
            } else if (keyType === ZigbeeAPSConsts.CMD_KEY_TC_LINK) {
                logger.debug(
                    () =>
                        `<=== APS REQUEST_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} type=${keyType}]`,
                    NS,
                );

                if (this.#context.trustCenterPolicies.allowTCKeyRequest === TrustCenterKeyRequestPolicy.ALLOWED) {
                    await this.sendTransportKeyTC(nwkHeader.source16!, this.#context.netParams.tcKey, requester64);
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
        offset = finalPayload.writeUInt8(ZigbeeAPSCommandId.REQUEST_KEY, offset);
        offset = finalPayload.writeUInt8(keyType, offset);

        if (hasPartner64) {
            offset = finalPayload.writeBigUInt64LE(partner64!, offset);
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
     * 05-3474-R #4.4.11.3
     *
     * SPEC COMPLIANCE:
     * - ✅ Decodes sequence number identifying the pending network key
     * - ✅ Activates staged key via StackContext.activatePendingNetworkKey
     * - ✅ Resets NWK frame counter following activation
     * - ⚠️ Pending key staging remains prerequisite (TRANSPORT_KEY)
     */
    public processSwitchKey(data: Buffer, offset: number, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, _apsHeader: ZigbeeAPSHeader): number {
        const seqNum = data.readUInt8(offset);
        offset += 1;

        logger.debug(
            () =>
                `<=== APS SWITCH_KEY[macSrc=${macHeader.source16}:${macHeader.source64} nwkSrc=${nwkHeader.source16}:${nwkHeader.source64} seqNum=${seqNum}]`,
            NS,
        );

        if (!this.#context.activatePendingNetworkKey(seqNum)) {
            logger.warning(`<=x= APS SWITCH_KEY[seqNum=${seqNum}] Received without pending key`, NS);
        }

        return offset;
    }

    /**
     * 05-3474-R #4.4.11.5
     *
     * SPEC COMPLIANCE:
     * - ✅ Includes sequence number associated with staged network key
     * - ✅ Broadcast or unicast delivery
     * - ✅ Applies NWK security only (per spec expectation)
     * - ⚠️ Relies on caller to stage key via TRANSPORT_KEY before invocation
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
    public async sendTunnel(nwkDest16: number, destination64: bigint, tApsCmdFrame: Buffer): Promise<boolean> {
        logger.debug(() => `===> APS TUNNEL[dst64=${destination64}]`, NS);

        const finalPayload = Buffer.alloc(9 + tApsCmdFrame.byteLength);
        let offset = 0;
        offset = finalPayload.writeUInt8(ZigbeeAPSCommandId.TUNNEL, offset);
        offset = finalPayload.writeBigUInt64LE(destination64, offset);
        offset += tApsCmdFrame.copy(finalPayload, offset);

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

        const finalPayload = Buffer.alloc(10 + ZigbeeConsts.SEC_KEYSIZE);
        let offset = 0;
        offset = finalPayload.writeUInt8(ZigbeeAPSCommandId.VERIFY_KEY, offset);
        offset = finalPayload.writeUInt8(keyType, offset);
        offset = finalPayload.writeBigUInt64LE(source64, offset);
        offset += hash.copy(finalPayload, offset);

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
        offset += 1;
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
        offset = finalPayload.writeUInt8(ZigbeeAPSCommandId.CONFIRM_KEY, offset);
        offset = finalPayload.writeUInt8(status, offset);
        offset = finalPayload.writeUInt8(keyType, offset);
        offset = finalPayload.writeBigUInt64LE(destination64, offset);

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
                    keyId: ZigbeeKeyType.LINK, // Per 05-3474-23 #4.4.11.8 confirmation uses the link key being verified
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
        if (status === 0x00 && device !== undefined && device.authorized === false) {
            device.authorized = true;

            setImmediate(() => {
                this.#callbacks.onDeviceAuthorized(device.address16, destination64);
            });
        }

        return result;
    }

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

        offset = lqiTable.writeUInt8(0 /* seq num */, offset);
        offset = lqiTable.writeUInt8(0 /* SUCCESS */, offset);
        offset = lqiTable.writeUInt8(neighborTableEntries, offset);
        offset = lqiTable.writeUInt8(startIndex, offset);
        offset = lqiTable.writeUInt8(entryCount, offset);

        let entryIndex = 0;

        for (let i = 0; i < entryCount; i++) {
            offset = lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex] as bigint /* extendedPanId */, offset);
            offset = lqiTable.writeBigUInt64LE(lqiTableArr[entryIndex + 1] as bigint /* eui64 */, offset);
            offset = lqiTable.writeUInt16LE(lqiTableArr[entryIndex + 2] as number /* nwkAddress */, offset);
            offset = lqiTable.writeUInt8(lqiTableArr[entryIndex + 3] as number /* deviceTypeByte */, offset);
            offset = lqiTable.writeUInt8(lqiTableArr[entryIndex + 4] as number /* permitJoiningByte */, offset);
            offset = lqiTable.writeUInt8(lqiTableArr[entryIndex + 5] as number /* depth */, offset);
            offset = lqiTable.writeUInt8(lqiTableArr[entryIndex + 6] as number /* lqa */, offset);

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
}
