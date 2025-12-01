# Zigbee on Host - Architecture Documentation

**Document Version:** 1.2
**Last Updated:** November 27, 2025
**Maintainer:** Nerivec
**License:** GPL-3.0-or-later

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Layer Responsibilities](#layer-responsibilities)
4. [Data Flow](#data-flow)
5. [State Management](#state-management)
6. [Performance Characteristics](#performance-characteristics)

## Overview

Zigbee on Host is a host-based Zigbee stack implementation that communicates with OpenThread RCP (Radio Co-Processor) firmware via the Spinel protocol. The architecture follows a clean layered design aligned with the Zigbee specification structure.

### Key Design Principles

1. **Layered Architecture** - Clear separation between MAC, NWK, and APS layers
2. **Direct Method Calls** - No event-based communication between layers (performance optimization)
3. **Single Source of Truth** - StackContext owns all shared state
4. **Zero Production Dependencies** - Only Node.js built-in modules
5. **TypeScript Zero-Cost Abstractions** - Interfaces, const enums, type aliases
6. **Host-Guided Routing Heuristics** - Routing decisions leverage host-only scoring (LQA, staleness, MAC feedback) to keep concentrator behavior deterministic

### Technology Stack

- **Runtime:** Node.js
- **Language:** TypeScript (esnext)
- **Testing:** Vitest
- **Linting:** Biome
- **Module System:** ES Modules (NodeNext)

## System Architecture

### High-Level Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                      External Consumers                           │
│                  (Zigbee2MQTT, Applications)                      │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             │ Public API
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│                            OTRCPDriver                            │
│                   Main Entry Point & Orchestration                │
│                                                                   │
│ • Public API: sendZDO, sendUnicast, sendGroupcast, etc.           │
│ • EventEmitter: deviceJoined, frame, fatalError, etc.             │
│ • Lifecycle: start(), stop(), reset()                             │
│ • Frame Dispatch: Routes incoming frames to handlers              │
└────┬──────────────┬──────────────┬──────────────┬─────────────────┘
     │              │              │              │
     │              │              │              │
┌────▼──────────┐ ┌─▼──────────┐ ┌─▼──────────┐ ┌─▼──────────────┐
│  MACHandler   │ │ NWKHandler │ │NWKGPHandler│ │  APSHandler    │
└────┬──────────┘ └─┬──────────┘ └─┬──────────┘ └─┬──────────────┘
     │              │              │              │
     │              │              │              │
     └──────────────┴──────────────┴──────────────┘
                     │
                     │ Shared State & Operations
                     ▼
┌───────────────────────────────────────────────────────────────────┐
│                           StackContext                            │
│                      Single Source of Truth                       │
│                                                                   │
│ • Network Parameters (EUI64, PAN ID, keys, etc.)                  │
│ • Device Table (device entries, capabilities, LQA tracking)       │
│ • Routing Tables (source routes, routing table)                   │
│ • Sequence Counters (MAC, NWK, APS, ZDO)                          │
│ • Configuration (coordinator descriptors, policies)               │
│ • Helper Methods (computeLQA, computeDeviceLQA)                   │
│ • State Persistence (saveState, loadState)                        │
│ • Trust Center: (-dis-allowJoins, -dis-associate)                 │
└───────────────────────────────────────────────────────────────────┘
                     │
                     │ Transport Layer
                     ▼
┌───────────────────────────────────────────────────────────────────┐
│                     OTRCPParser + OTRCPWriter                     │
│                        Spinel/HDLC Layer                          │
│                                                                   │
│ • Frame Encoding/Decoding (HDLC, Spinel)                          │
│ • Property Management (get/set Spinel properties)                 │
│ • Stream Raw Interface (IEEE 802.15.4 frames)                     │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             │ Serial Communication
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│                      OpenThread RCP Firmware                      │
│                (Silicon Labs, TI, Nordic chipsets)                │
└───────────────────────────────────────────────────────────────────┘
```

### File Structure

```
src/
├── drivers/
│   ├── ot-rcp-driver.ts   - Main entry point
│   ├── ot-rcp-parser.ts   - Spinel parser
│   ├── ot-rcp-writer.ts   - Spinel writer
│   └── wip.ts             - Work in progress features
├── zigbee-stack/          - Zigbee protocol stack handlers
│   ├── stack-context.ts   - Shared state
│   ├── descriptors.ts     - Coordinator descriptors
│   ├── mac-handler.ts     - MAC layer
│   ├── nwk-handler.ts     - NWK layer
│   ├── nwk-gp-handler.ts  - Green Power
│   └── aps-handler.ts     - APS layer
├── spinel/                - Spinel protocol implementation
├── zigbee/                - Zigbee protocol utilities
└── utils/                 - Shared utilities
```

## Layer Responsibilities

### OTRCPDriver (Main Entry Point)

**Responsibility:** Public API and orchestration

**Functions:**

**Key Methods:**
```typescript
// Network Management
public async formNetwork(): Promise<void>
public async resetNetwork(): Promise<void>

// Data Transmission
public async sendZDO(payload: Buffer, nwkDest16: number, nwkDest64: bigint | undefined, clusterId: number): Promise<[number, number]>
public async sendUnicast(payload: Buffer, profileId: number, clusterId: number, dest16: number, dest64: bigint | undefined, destEp: number, sourceEp: number): Promise<number>
public async sendGroupcast(payload: Buffer, profileId: number, clusterId: number, group: number, sourceEp: number): Promise<number>
public async sendBroadcast(payload: Buffer, profileId: number, clusterId: number, dest16: number, sourceEp: number, options?: {radius?: number}): Promise<number>

// Properties
readonly context: StackContext
readonly macHandler: MACHandler
readonly nwkHandler: NWKHandler
readonly apsHandler: APSHandler
readonly nwkGPHandler: NWKGPHandler
```

**Callbacks from External Consumers (StackCallbacks):**
```typescript
interface StackCallbacks {
    onFatalError: (message: string) => void;
    /** Only triggered if MAC `emitFrames===true` */
    onMACFrame: (payload: Buffer, rssi?: number) => void;
    onFrame: (sender16: number | undefined, sender64: bigint | undefined, apsHeader: ZigbeeAPSHeader, apsPayload: Buffer, lqa: number) => void;
    onGPFrame: (cmdId: number, payload: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, lqa: number) => void;
    onDeviceJoined: (source16: number, source64: bigint, capabilities: MACCapabilities) => void;
    onDeviceRejoined: (source16: number, source64: bigint, capabilities: MACCapabilities) => void;
    onDeviceLeft: (source16: number, source64: bigint) => void;
    onDeviceAuthorized: (source16: number, source64: bigint) => void;
}
```

### Frame Handler (Ingress Pipeline)

**Responsibility:** Decode inbound IEEE 802.15.4 frames and dispatch to the correct stack layer

**Functions:**
- Parse MAC frame control, header, and payload (CMD vs DATA)
- Filter frames by PAN ID and destination addressing (broadcast vs coordinator)
- Route MAC commands to `MACHandler.processCommand`
- Detect Green Power frames and forward to `NWKGPHandler`
- Decode Zigbee NWK frames, enforce replay protection, and forward to `NWKHandler`
- Decode Zigbee APS frames, emit APS ACKs, and delegate to `APSHandler`

**Key Methods:**
```typescript
export async function processFrame(
    payload: Buffer,
    context: StackContext,
    macHandler: MACHandler,
    nwkHandler: NWKHandler,
    nwkGPHandler: NWKGPHandler,
    apsHandler: APSHandler,
    rssi?: number,
): Promise<void>
```

### MACHandler (MAC Layer)

**Responsibility:** IEEE 802.15.4 MAC layer operations

**Functions:**
- Handle MAC frame transmission/reception
- Process association requests/responses
- Manage beacon handling
- Handle data requests
- Maintain indirect transmission queue
- Process MAC commands
- Update per-destination NO_ACK counters (`StackContext.macNoACKs`) to feed NWK routing heuristics

**Key Methods:**
```typescript
public async sendFrame(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean | undefined>
public async sendFrameDirect(seqNum: number, payload: Buffer, dest16: number | undefined, dest64: bigint | undefined): Promise<boolean>
```

**MAC Commands Handled:**
- Association Request/Response
- Data Request
- Beacon Request/Response
- Disassociation Notification

**Callbacks to Driver (MACHandlerCallbacks):**
```typescript
interface MACHandlerCallbacks {
    /** Process MAC frame at upper layers */
    onMACFrame: (payload: Buffer, rssi?: number) => Promise<void>;
    /** Send Spinel property to RCP */
    onSendFrame: (payload: Buffer) => Promise<void>;
    /** Send APS TRANSPORT_KEY for network key */
    onAPSSendTransportKeyNWK: (address16: number, key: Buffer, keySeqNum: number, destination64: bigint) => Promise<void>;
    /** Mark route as successful */
    onMarkRouteSuccess: (destination16: number) => void;
    /** Mark route as failed */
    onMarkRouteFailure: (destination16: number) => void;
}
```

### NWKHandler (Network Layer)

**Responsibility:** Zigbee Network layer operations

**Functions:**
- Handle NWK frame transmission/reception
- Manage routing (discovery, repair, source routes)
- Process link status frames
- Handle leave/rejoin operations
- Implement many-to-one routing
- Process route record frames
- Handle all NWK commands
- Score candidate routes with host-only heuristics (path cost, staleness penalty, MAC NO_ACK counters, recency bonus)

The handler now keeps multiple source-route entries per destination and ranks them every time `findBestSourceRoute` runs. Expired or blacklisted paths are purged eagerly, remaining entries are sorted by a composite score (path cost + penalties + recency bonus), and any relay that has accumulated too many MAC NO_ACK events is skipped entirely. When no usable path is left the handler immediately triggers a concentrator (many-to-one) refresh so the coordinator can rebuild routing knowledge.

**Key Methods:**
```typescript
public async onZigbeeNWKFrame(macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, nwkPayload: ZigbeeNWKPayload, rssi?: number): Promise<void>
public findBestSourceRoute(destination16: number | undefined, destination64: bigint | undefined): [relayIndex: number | undefined, relayAddresses: number[] | undefined, pathCost: number | undefined]
public markRouteSuccess(destination16: number, relayIndex?: number): void
public markRouteFailure(destination16: number, triggerMTORR: boolean, relayIndex?: number): void
public async sendPeriodicZigbeeNWKLinkStatus(): Promise<void>
public async sendPeriodicManyToOneRouteRequest(): Promise<void>
```

**NWK Commands Handled:**
- Route Request/Reply
- Network Status
- Leave/Rejoin Request/Response
- Link Status
- Route Record
- Many-to-One Route Request
- End Device Timeout Request/Response
- Network Report
- Network Update
- Link Power Delta
- Commissioning Request/Response

**Callbacks to Driver (NWKHandlerCallbacks):**
```typescript
interface NWKHandlerCallbacks {
    /** Send APS TRANSPORT_KEY for network key */
    onAPSSendTransportKeyNWK: (destination16: number, networkKey: Buffer, keySequenceNumber: number, destination64: bigint) => Promise<void>;
}
```

### NWKGPHandler (Green Power)

**Responsibility:** Zigbee Green Power frame processing

**Functions:**
- Process Green Power frames
- Handle GP commissioning
- Forward GP data frames to application
- Process GP commands
- Track duplicates per GPD security frame counter with bounded cache

**Key Methods:**
```typescript
public processFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader, lqa: number): void
public enterCommissioningMode(commissioningWindow?: number): void
public exitCommissioningMode(): void
public isDuplicateFrame(macHeader: MACHeader, nwkHeader: ZigbeeNWKGPHeader): boolean
```

**Callbacks to Driver (NWKGPHandlerCallbacks):**
```typescript
interface NWKGPHandlerCallbacks {
    /** Handle Green Power frame */
    onGPFrame: (source64: bigint, commandId: number, framePayload: Buffer, srcId: number, gppShortAddress: number, gpdLink: number) => void;
}
```

### APSHandler (Application Support Layer)

**Responsibility:** Zigbee APS layer and ZDO operations

**Functions:**
- Handle APS frame transmission/reception
- Apply/verify APS security
- Process ZDO requests for coordinator
- Generate ZDO responses (LQI table, routing table, descriptors)
- Handle APS commands (transport, verify/confirm key, etc.)
- Support APS fragmentation and reassembly with duplicate suppression

**Key Methods:**
```typescript
public async sendData(finalPayload: Buffer, nwkDiscoverRoute: ZigbeeNWKRouteDiscovery, nwkDest16: number | undefined, nwkDest64: bigint | undefined, apsDeliveryMode: ZigbeeAPSDeliveryMode, clusterId: number, profileId: number, destEndpoint: number | undefined, sourceEndpoint: number | undefined, group: number | undefined): Promise<number>
public async onZigbeeAPSFrame(data: Buffer, macHeader: MACHeader, nwkHeader: ZigbeeNWKHeader, apsHeader: ZigbeeAPSHeader, lqa: number): Promise<void>
public isZDORequestForCoordinator(clusterId: number, nwkDst16: number | undefined, nwkDst64: bigint | undefined, data: Buffer): boolean
public async respondToCoordinatorZDORequest(data: Buffer, clusterId: number, nwkDest16: number | undefined, nwkDest64: bigint | undefined): Promise<void>
public getCoordinatorZDOResponse(clusterId: number, requestData: Buffer): Buffer | undefined
public getLQITableResponse(startIndex: number): Buffer
public getRoutingTableResponse(startIndex: number): Buffer
```

**Callbacks to Driver (APSHandlerCallbacks):**
```typescript
interface APSHandlerCallbacks {
    /** Handle APS frame */
    onFrame: (sender16: number | undefined, sender64: bigint | undefined, apsHeader: ZigbeeAPSHeader, apsPayload: Buffer, lqa: number) => void;
    /** Handle device join */
    onDeviceJoined: (source16: number, source64: bigint, capabilities: MACCapabilities) => void;
    /** Handle device rejoin */
    onDeviceRejoined: (source16: number, source64: bigint, capabilities: MACCapabilities) => void;
    /** Handle device authorization */
    onDeviceAuthorized: (source16: number, source64: bigint) => void;
}
```

### StackContext (Shared State)

**Responsibility:** Single source of truth for all state

**State Managed:**
- Network parameters (EUI64, PAN ID, extended PAN ID, network key, etc.)
- Device table (device entries with capabilities, LQA tracking, authorization)
- Address mappings (16-bit ↔ 64-bit)
- Routing tables (source routes)
- Source route table entries with timestamps + failure counts (multiple per destination allowed)
- Application link key table (pair-wise TC/app link keys)
- Install code metadata and derived link keys
- Key frame counters
- Pending network key staging (pre-SWITCH_KEY activate)
- End-device timeout metadata and runtime NWK frame counters
- MAC NO_ACK counters (per-destination delivery health used by NWK heuristics)
- Trust center policies (join policies, key policies)
- Coordinator configuration attributes
- Pending associations (awaiting DATA_RQ from device)
- Indirect transmissions (for devices with rxOnWhenIdle=false)

**Key Methods:**
```typescript
// State management
public nextNWKKeyFrameCounter(): number
public nextTCKeyFrameCounter(): number
public computeLQA(signalStrength: number, signalQuality?: number): number
public computeDeviceLQA(address16: number | undefined, address64: bigint | undefined, signalStrength?: number, signalQuality?: number, maxRecent?: number): number
public getDevice(address: bigint | number): DeviceTableEntry | undefined
public getAddress64(address16: number): bigint | undefined
public getAddress16(address64: bigint): number | undefined
public updateIncomingNWKFrameCounter(address64: bigint | undefined, frameCounter: number): boolean
public async saveState(): Promise<void>
public async readNetworkState(): Promise<NetworkParameters | undefined>
public async loadState(): Promise<void>

// Trust Center operations
public allowJoins(duration: number, macAssociationPermit: boolean): void
public disallowJoins(): void
public async associate(source16: number | undefined, source64: bigint | undefined, initialJoin: boolean, capabilities: MACCapabilities | undefined, neighbor: boolean, denyOverride?: boolean, allowOverride?: boolean): Promise<[status: MACAssociationStatus | number, newAddress16: number]>
public async disassociate(source16: number | undefined, source64: bigint | undefined): Promise<void>
```

**Callbacks to Driver (StackContextCallbacks):**
```typescript
interface StackContextCallbacks {
    /** Handle post-disassociate */
    onDeviceLeft: (source16: number, source64: bigint) => void;
}
```

## Data Flow

### Incoming Frame Processing

```
Serial Port
    ↓
[OTRCPParser.onData()]
HDLC Decoding
    ↓
Spinel Frame Extraction
    ↓
STREAM_RAW Property Handler
    ↓
IEEE 802.15.4 MAC Frame + Metadata (RSSI, LQI)
    ↓
frame.processFrame()
    ├─ MAC Frame Type Detection
    │     ├─ MAC Command → MACHandler.processCommand()
    │     └─ MAC Data → Validate PAN/destination
    │
    ├─ Green Power Frames → NWKGPHandler.processFrame()
    │     └─ Duplicate filtering via NWKGPHandler.isDuplicateFrame() with per-GPD counters and MAC-seq fallback
    │
    └─ Zigbee NWK Frames
          ↓
      Broadcast loopback guard (drop coordinator echoes)
          ↓
      NWK Security
          └─ StackContext.updateIncomingNWKFrameCounter()
          ↓
      Frame Type Detection
          ├─ NWK Command → NWKHandler.processCommand()
          └─ NWK Data → decode APS payload
                 ↓
             APS ACK (when requested)
                 ↓
             APS Duplicate Filtering → APSHandler.isDuplicateFrame()
                 ↓
             APSHandler.processFrame()
    └─ MAC Beacon → TODO: PAN ID conflict detection / beacon parsing

[NWKHandler.onZigbeeNWKFrame()]
NWK Frame Type Detection
    ├─ NWK Command → NWKHandler.processCommand()
    │                 ├─ Route Request → Send route reply
    │                 ├─ Route Reply → Update routing table
    │                 ├─ Leave → Remove device
    │                 └─ Link Status → Update routing costs
    │
    └─ NWK Data → Decrypt if secured
                   ↓
               Extract NWK header + APS payload
                   ↓
               [APSHandler.onZigbeeAPSFrame()]

[APSHandler.onZigbeeAPSFrame()]
APS Frame Processing
    ├─ ZDO Request → isZDORequestForCoordinator()?
    │                 └─ Yes → respondToCoordinatorZDORequest()
    │                           (Don't emit - handled internally)
    │
    └─ APS Data → Decrypt if secured
                   ↓
               Send APS ACK when requested
                   ↓
               Duplicate filtering via APSHandler.isDuplicateFrame()
                   ↓
               Emit 'frame' event to application

[NWKGPHandler.onZigbeeNWKGPFrame()]
Green Power Frame Processing
    ├─ Duplicate filtering via NWKGPHandler.isDuplicateFrame()
    └─ Extract GP data
        ↓
    Emit 'gpFrame' event to application
```

### Outgoing Frame Processing

```
Application API Call
(e.g., sendUnicast)
    ↓
[OTRCPDriver.sendUnicast()]
    ↓
[APSHandler.sendData()]
    ├─ Get counters from StackContext (APS, NWK, MAC sequence numbers)
    ├─ Find best source route via NWKHandler.findBestSourceRoute()
    ├─ Encode APS frame (header + payload)
    ├─ Encode NWK frame (header + APS frame + NWK security)
    ├─ Encode MAC frame (header + NWK frame)
    └─ Call MACHandler.sendFrame()
        ↓
[MACHandler.sendFrame()]
    ├─ Check if indirect transmission needed (for RxOnWhenIdle=false devices)
    │   ├─ Yes → Queue for indirect transmission (wait for Data Request)
    │   └─ No → Call sendFrameDirect()
    │
[MACHandler.sendFrameDirect()]
    ├─ Build Spinel STREAM_RAW property (MAC frame)
    ├─ Call callbacks.onSendFrame()
    ├─ ACK success → clear `macNoACKs` entry + `NWKHandler.markRouteSuccess()`
    └─ NO_ACK error → increment `macNoACKs` + `NWKHandler.markRouteFailure()`
        ↓
[OTRCPDriver.setProperty()]
    ├─ Encode as Spinel frame
    └─ Call OTRCPWriter
        ↓
[OTRCPWriter.writeMACFrame()]
    ├─ Frame with HDLC
    └─ Send to serial port
        ↓
Serial Port → RCP Firmware → Radio Transmission
```

### Routing Feedback Loop (Extra Pass Focus)

Recent refactors introduced a closed-loop routing controller that keeps concentrator behavior stable even when radio quality fluctuates:

1. **MAC delivery feedback** – Every unicast tracks whether the RCP reported an ACK. Success clears the destination entry in `StackContext.macNoACKs`, while a NO_ACK increments it and immediately calls `NWKHandler.markRouteFailure()`.
2. **Source-route scoring** – `NWKHandler.findBestSourceRoute()` re-sorts all candidate paths on every lookup. The score combines hop count, staleness penalty, failure penalty, a recency bonus, and a hard filter that rejects any relay currently above the NO_ACK threshold.
3. **Automatic recovery** – When the handler purges all routes (expired, blacklisted, or unhealthy relays), it schedules a many-to-one route discovery so the coordinator re-advertises itself and rebuilds source routes.
4. **Link status integration** – Periodic link-status frames piggyback the same computed path costs so neighbors receive up-to-date metrics derived from LQA + routing penalties.

Together these steps ensure routing decisions remain deterministic and reflect the host's richer telemetry without waiting for devices to age routes out on their own.

## State Management

### State Persistence

State is persisted to a `zoh.save` file in TLV (Tag-Length-Value) format, similar to NCP NVRAM.

**State Components Saved:**
1. Network parameters (PAN ID, extended PAN ID, channel, keys, pending key staging, etc.)
2. Device data (capabilities, authorization, neighbor flag, LQA history, source routes, timeout metadata)
3. Frame counters (NWK key, TC key)
4. Application link key entries (pair-wise keys between coordinator and devices)

**Save Format:**
```
[Tag: 1 byte][Length: 2 bytes LE][Value: Length bytes] ...
```

### State Loading

On driver start:
1. Load state from `zoh.save` if exists
2. Register hashed keys for crypto operations
3. Initialize RCP firmware
4. Restore network parameters
5. Rebuild device table, routing tables, end-device timeout metadata, and app link key cache

## Performance Characteristics

### Memory Characteristics

**Data Structures:**
- **Device Table**: `Map<bigint, DeviceTableEntry>`
  - Complexity: O(1) lookup by IEEE address
  - Memory per device: ~80-120 bytes (depends on LQA history size)
  - Components: address16 (2B), capabilities (1B), flags (2B), recentLQAs array (variable)
  
- **Address Lookup Maps**: 
  - `address16ToAddress64`: `Map<number, bigint>` - O(1) reverse lookup
  - Memory per entry: ~16 bytes
  
- **Source Route Table**: `Map<number, SourceRouteTableEntry[]>`
  - Complexity: O(1) lookup, O(n) route selection where n = alternate routes per destination
  - Memory per route: ~48 bytes + (relay count × 2 bytes)
  - Components: relayAddresses array, pathCost (4B), timestamps (16B), failureCount (4B)
  - Route aging: Stale after 2 minutes, expired after 5 minutes
  
- **Indirect Transmission Queue**: `Map<bigint, IndirectTxContext[]>`
  - Complexity: O(1) lookup by device IEEE address
  - Memory per queued frame: ~32 bytes + frame buffer size
  - Automatically cleaned on device poll (Data Request)

- **Configuration Attributes**: Pre-encoded ZDO response buffers
  - Address response: ~10 bytes
  - Node descriptor: ~13 bytes  
  - Power descriptor: ~3 bytes
  - Active endpoints list: ~43 bytes
  - Simple descriptors: ~256 bytes

**Total Memory Footprint (estimated for typical network):**
- Base overhead: ~2-3 MB (Node.js runtime + stack)
- Per device: ~100-200 bytes
- 50 devices: ~3-4 MB
- 200 devices: ~4-6 MB
- No memory pooling (relies on V8 garbage collection)

### Throughput Characteristics

**Protocol Overhead:**
- MAC header: 9-25 bytes (depending on addressing mode)
- NWK header: 8-20 bytes (with/without source routing)
- NWK security: 14 bytes (auxiliary header + 4-byte MIC)
- APS header: 8-10 bytes
- APS security: 14 bytes (when enabled)
- Total overhead: 35-80 bytes per frame

**Frame Processing:**
- HDLC decoding: <30 µs per frame
- Spinel parsing: <20 µs per frame
- MAC/NWK/APS decoding: <100 µs per frame (combined)
- Crypto operations (AES-CCM): ~200-500 µs per frame
- Total incoming path: <1 ms (MAC frame → application event)
- Total outgoing path: <1.5 ms (application call → radio transmission)

**Network Timings:**
- Link Status broadcast: Every 15 seconds (±1s jitter)
- Many-to-One Route Request: Every 60 seconds (on-demand, throttled to min 10s)
- Route staleness: 2 minutes (route becomes less preferred)
- Route expiry: 5 minutes (route removed from table)
- State persistence: Every 60 seconds (to `zoh.save`)
- Broadcast delivery time: 9 seconds (network-wide propagation)

**Serial Communication:**
- HDLC chunk size: 2048 bytes
- Stream high-water mark: 8192 bytes (4 × chunk size)
- Typical baud rate: 921600 bps (115,200 bytes/s)
- Max theoretical throughput: ~110 KB/s (accounting for ~5% HDLC overhead - escaping, flags, FCS)

### Latency Characteristics

**End-to-End Latency (typical values):**
- Direct neighbor unicast: 5-10 ms
- 1-hop routed unicast: 15-25 ms
- 2-hop routed unicast: 25-40 ms
- 3-hop routed unicast: 35-55 ms
- Broadcast (network-wide): 50-150 ms (depending on network size)
- ZDO response (coordinator): <5 ms (generated locally)

**Component Latencies:**
- Serial port write: <0.5 ms
- RCP processing: 1-3 ms
- Radio transmission (2.4 GHz): 2-4 ms per hop
- MAC ACK timeout: 50-100 ms (if no ACK received)
- APS ACK timeout: Configured per profile (typically 1-3 seconds)

### Scalability Characteristics

**Network Limits:**
- Max network depth: 15 hops
- Max network radius: 30 hops (2 × depth)
- Max devices: Limited by available 16-bit addresses (~64,000 theoretical)
- Practical device limit: 200-300 devices (depending on traffic patterns)
- Max source route relays: Unlimited in table, practical limit ~10 per route

**Routing Scalability:**
- Route discovery: Exponential network flooding (resource intensive)
- Many-to-One routing: Scalable to large networks (routes stored at edges)
- Source routing: O(1) lookup, eliminates per-hop route discovery
- Route table growth: O(n) where n = number of devices with active routes

**State Persistence:**
- Save format: TLV (Tag-Length-Value)
- Typical save file size: 1-10 KB for small networks, 50-100 KB for large networks
- Save operation: <10 ms (async file write)
- Load operation: <50 ms (file read + parsing + key registration)

### CPU Characteristics

**Hot Paths (performance-critical):**
- Frame encoding/decoding: Inline buffer operations, minimal allocations
- HDLC escape detection: Simple comparison (no branching)
- FCS calculation: Lookup table (pre-computed)
- Crypto operations: Uses Node.js native crypto (native C++ bindings)
- Logger: Lazy evaluation with lambdas (no string operations if debug disabled)

**Optimization Strategies:**
- Zero-copy buffer operations where possible (subarray/slice)
- Pre-hashed security keys (computed once at startup)
- Pre-encoded coordinator descriptors
- Early bail-outs in validation paths
- Direct method calls between layers (no event emitter overhead)
- Const enums (compile-time constants, zero runtime cost)

**CPU Usage (typical):**
- Idle: <1% CPU
- Light traffic (1-5 msg/s): 1-3% CPU
- Moderate traffic (10-20 msg/s): 3-8% CPU  
- Heavy traffic (50+ msg/s): 10-20% CPU
- Values are approximate and vary with message size, routing complexity, and crypto operations
