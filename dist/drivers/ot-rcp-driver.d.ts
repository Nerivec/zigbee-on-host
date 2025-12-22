import { SpinelCommandId } from "../spinel/commands.js";
import { SpinelPropertyId } from "../spinel/properties.js";
import { type SpinelFrame, type SpinelStreamRawMetadata, type StreamRawConfig } from "../spinel/spinel.js";
import { APSHandler } from "../zigbee-stack/aps-handler.js";
import { MACHandler } from "../zigbee-stack/mac-handler.js";
import { NWKGPHandler } from "../zigbee-stack/nwk-gp-handler.js";
import { NWKHandler } from "../zigbee-stack/nwk-handler.js";
import { type NetworkParameters, type StackCallbacks, StackContext } from "../zigbee-stack/stack-context.js";
import { OTRCPParser } from "./ot-rcp-parser.js";
import { OTRCPWriter } from "./ot-rcp-writer.js";
export declare class OTRCPDriver {
    #private;
    readonly writer: OTRCPWriter;
    readonly parser: OTRCPParser;
    /** Centralized stack context holding all shared state */
    readonly context: StackContext;
    /** MAC layer handler */
    readonly macHandler: MACHandler;
    /** NWK layer handler */
    readonly nwkHandler: NWKHandler;
    /** APS layer handler */
    readonly apsHandler: APSHandler;
    /** NWK GP layer handler */
    readonly nwkGPHandler: NWKGPHandler;
    constructor(callbacks: StackCallbacks, streamRawConfig: StreamRawConfig, netParams: NetworkParameters, saveDir: string, emitMACFrames?: boolean);
    get protocolVersionMajor(): number;
    get protocolVersionMinor(): number;
    get ncpVersion(): string;
    get interfaceType(): number;
    get rcpAPIVersion(): number;
    get rcpMinHostAPIVersion(): number;
    get currentSpinelTID(): number;
    /**
     * @returns increased TID offsetted by +1. [1-14] range for the "actually-used" value (0 is reserved)
     */
    private nextSpinelTID;
    waitForTID(tid: number, timeout: number): Promise<SpinelFrame>;
    /**
     * Logic optimizes code paths to try to avoid more parsing when frames will eventually get ignored by detecting as early as possible.
     * HOT PATH: This method is called for every incoming frame. Optimizations:
     * - Early bail-outs to minimize processing
     * - Inline-able operations
     * - Minimal allocations in critical paths
     */
    onStreamRawFrame(payload: Buffer, metadata: SpinelStreamRawMetadata | undefined): Promise<void>;
    onFrame(buffer: Buffer): Promise<void>;
    sendCommand(commandId: SpinelCommandId, buffer: Buffer, waitForResponse: false): Promise<undefined>;
    sendCommand(commandId: SpinelCommandId, buffer: Buffer, waitForResponse: true, timeout: number): Promise<SpinelFrame>;
    getProperty(propertyId: SpinelPropertyId, timeout?: number): ReturnType<typeof this.sendCommand>;
    setProperty(payload: Buffer, timeout?: number): Promise<void>;
    sendStreamRaw(payload: Buffer): Promise<void>;
    /**
     * @returns [SPINEL_PROTOCOL_VERSION_THREAD_MAJOR, SPINEL_PROTOCOL_VERSION_THREAD_MINOR]
     */
    getProtocolVersion(): Promise<[major: number, minor: number]>;
    /**
     * Recommended format: STACK-NAME/STACK-VERSION[BUILD_INFO][; OTHER_INFO]; BUILD_DATE_AND_TIME
     * Encoded as a zero-terminated UTF-8 string.
     */
    getNCPVersion(): Promise<string>;
    /**
     * @returns SPINEL_PROTOCOL_TYPE_*
     */
    getInterfaceType(): Promise<number>;
    getRCPAPIVersion(): Promise<number>;
    getRCPMinHostAPIVersion(): Promise<number>;
    /**
     * The CCA (clear-channel assessment) threshold.
     * NOTE: Currently not implemented in: ot-ti
     * @returns dBm (int8)
     */
    getPHYCCAThreshold(): Promise<number>;
    /**
     * The CCA (clear-channel assessment) threshold.
     * Set to -128 to disable.
     * The value will be rounded down to a value that is supported by the underlying radio hardware.
     * NOTE: Currently not implemented in: ot-ti
     * @param ccaThreshold dBm (>= -128 and <= 127)
     */
    setPHYCCAThreshold(ccaThreshold: number): Promise<void>;
    /**
     * The transmit power of the radio.
     * @returns dBm (int8)
     */
    getPHYTXPower(): Promise<number>;
    /**
     * The transmit power of the radio.
     * The value will be rounded down to a value that is supported by the underlying radio hardware.
     * @param txPower dBm (>= -128 and <= 127)
     */
    setPHYTXPower(txPower: number): Promise<void>;
    /**
     * The current RSSI (Received signal strength indication) from the radio.
     * This value can be used in energy scans and for determining the ambient noise floor for the operating environment.
     * @returns dBm (int8)
     */
    getPHYRSSI(): Promise<number>;
    /**
     * The radio receive sensitivity.
     * This value can be used as lower bound noise floor for link metrics computation.
     * @returns dBm (int8)
     */
    getPHYRXSensitivity(): Promise<number>;
    /**
     * Start an energy scan.
     * Cannot be used after state is loaded or network is up.
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.1
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#section-5.8.10
     * @param channels List of channels to scan
     * @param period milliseconds per channel
     * @param txPower
     */
    startEnergyScan(channels: number[], period: number, txPower: number): Promise<void>;
    stopEnergyScan(): Promise<void>;
    /**
     * Start sniffing.
     * Cannot be used after state is loaded or network is up.
     * WARNING: This is expected to run in the "run-and-quit" pattern as it overrides the `onStreamRawFrame` function.
     * @param channel The channel to sniff on
     */
    startSniffer(channel: number): Promise<void>;
    stopSniffer(): Promise<void>;
    get isNetworkUp(): boolean;
    /**
     * Set the Spinel properties required to start a 802.15.4 MAC network.
     *
     * Should be called after `start`.
     */
    formNetwork(): Promise<void>;
    /**
     * Remove the current state file and clear all related tables.
     *
     * Will throw if state already loaded (should be called before `start`).
     */
    resetNetwork(): Promise<void>;
    /**
     * Start the components of the Zigbee stack
     */
    startStack(): Promise<void>;
    /**
     * Stop the components of the Zigbee stack
     */
    stopStack(): void;
    waitForReset(): Promise<void>;
    /**
     * Get the basic info from the RCP firmware and reset it.
     * @see https://datatracker.ietf.org/doc/html/draft-rquattle-spinel-unified#appendix-C.1
     *
     * Should be called before `formNetwork` but after `resetNetwork` (if needed)
     */
    start(): Promise<void>;
    stop(): Promise<void>;
    /**
     * Performs a STACK reset after resetting a few PHY/MAC properties to default.
     * If up, will stop network before.
     */
    resetStack(): Promise<void>;
    /**
     * Performs a software reset into bootloader.
     * If up, will stop network before.
     */
    resetIntoBootloader(): Promise<void>;
    /**
     * Wraps Zigbee APS DATA sending for ZDO.
     * Throws if could not send.
     * @param payload
     * @param nwkDest16
     * @param nwkDest64
     * @param clusterId
     * @returns
     * - The APS counter of the sent frame.
     * - The ZDO counter of the sent frame.
     */
    sendZDO(payload: Buffer, nwkDest16: number, nwkDest64: bigint | undefined, clusterId: number): Promise<[number, number]>;
    /**
     * Wraps Zigbee APS DATA sending for unicast.
     * Throws if could not send.
     * @param payload
     * @param profileId
     * @param clusterId
     * @param dest16
     * @param dest64
     * @param destEp
     * @param sourceEp
     * @returns The APS counter of the sent frame.
     */
    sendUnicast(payload: Buffer, profileId: number, clusterId: number, dest16: number, dest64: bigint | undefined, destEp: number, sourceEp: number): Promise<number>;
    /**
     * Wraps Zigbee APS DATA sending for groupcast.
     * Throws if could not send.
     * @param payload
     * @param profileId
     * @param clusterId
     * @param group The group to send to
     * @param destEp
     * @param sourceEp
     * @returns The APS counter of the sent frame.
     */
    sendGroupcast(payload: Buffer, profileId: number, clusterId: number, group: number, sourceEp: number): Promise<number>;
    /**
     * Wraps Zigbee APS DATA sending for broadcast.
     * Throws if could not send.
     * @param payload
     * @param profileId
     * @param clusterId
     * @param dest16 The broadcast address to send to [0xfff8..0xffff]
     * @param destEp
     * @param sourceEp
     * @returns The APS counter of the sent frame.
     */
    sendBroadcast(payload: Buffer, profileId: number, clusterId: number, dest16: number, destEp: number, sourceEp: number): Promise<number>;
}
