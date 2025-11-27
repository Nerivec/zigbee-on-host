# GitHub Copilot Instructions

## Priority Guidelines

When generating code for this repository:

1. **Version Compatibility**: Always detect and respect the exact versions of languages, frameworks, and libraries used in this project
2. **Codebase Patterns**: Scan the codebase for established patterns before generating any code
3. **Architectural Consistency**: Maintain layered architecture with clear boundaries between drivers, protocol layers, and utilities
4. **Code Quality**: Prioritize performance, maintainability, and security in all generated code
5. **Zero Dependencies**: Never suggest external production dependencies - this project maintains zero production dependencies by design

## Technology Version Detection

This project uses the following exact technology versions:

### Core Technologies

- **Node.js** (prefer v24)
- **TypeScript**
  - Target: esnext
  - Module: NodeNext
  - Module Resolution: NodeNext
  - Strict mode enabled
- **Package Manager**: npm

Refer to [../package.json](../package.json) for versions.

### Development Dependencies

- **@biomejs/biome**: linting and formatting
- **vitest**: testing framework
- **@vitest/coverage-v8**: coverage provider
- **serialport**: dev dependency only
- **@types/node**: typing

Refer to [../package.json](../package.json) for versions.

### Critical Version Constraints

- **NodeNext modules**: Always use `.js` extensions in imports (e.g., `from "./spinel.js"` not `from "./spinel"`)
- **Strict TypeScript**: All strict type-checking options enabled
- **No external production dependencies**: Use only Node.js built-in modules for production code

## Project Architecture

### Layered Architecture

This project follows a strict layered architecture. Refer to [../docs/architecture.md](../docs/architecture.md)

### Build Configurations

- **Development build**: `npm run build` (includes src/dev/)
- **Production build**: `npm run build:prod` (excludes src/dev/)
- Always use production build for library distribution

## Code Style Standards

### Formatting (Biome Configuration)

- **Indentation**: 4 spaces (never tabs)
- **Line width**: 150 characters maximum
- **Line endings**: LF (Unix-style)
- **Quote style**: Double quotes (`"string"` not `'string'`)
- **Self-closing elements**: Required for JSX-like syntax

### Naming Conventions

Based on actual codebase patterns:

#### TypeScript Types and Interfaces

```typescript
// Types: PascalCase
export type NetworkParameters = { ... };
export type ZigbeeAPSHeader = { ... };
export type MACCapabilities = { ... };

// Interfaces: PascalCase with descriptive names
interface AdapterDriverEventMap { ... }
export interface Logger { ... }
```

#### Enums

```typescript
// Enum names: PascalCase
// Enum members: CONSTANT_CASE (enforced by Biome)
export enum InstallCodePolicy {
    NOT_SUPPORTED = 0x00,
    NOT_REQUIRED = 0x01,
    REQUIRED = 0x02,
}

// Const enums allowed for compile-time constants
export const enum ZigbeeConsts {
    COORDINATOR_ADDRESS = 0x0000,
    BCAST_DEFAULT = 0xfffc,
    HA_ENDPOINT = 0x01,
}
```

#### Functions and Variables

```typescript
// Functions: camelCase with descriptive names
function encodeSpinelFrame(): HdlcFrame { ... }
function decodeMACHeader(): MACHeader { ... }
function makeKeyedHashByType(): KeyedHash { ... }

// Variables: camelCase
const frameCounter = 0;
let securityHeader: ZigbeeSecurityHeader;
const NS = "ot-rcp-driver"; // namespace constant

// Constants: SCREAMING_SNAKE_CASE for file-level
const HDLC_TX_CHUNK_SIZE = 256;
const SPINEL_HEADER_FLG_SPINEL = 0x02;
```

#### File Names

```typescript
// Kebab-case with descriptive names
// ot-rcp-driver.ts
// ot-rcp-parser.ts
// zigbee-aps.ts
// zigbee-nwk.ts
// zigbee-nwkgp.ts
```

### Import/Export Patterns

#### Import Order and Style

```typescript
// 1. Node.js built-in modules (with node: prefix)
import EventEmitter from "node:events";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

// 2. External dependencies (none in production code)
// (dev dependencies only in src/dev/ and test/)

// 3. Internal imports (always with .js extension)
import { SpinelCommandId } from "../spinel/commands.js";
import { decodeHdlcFrame, type HdlcFrame } from "../spinel/hdlc.js";
import { logger } from "../utils/logger.js";

// 4. Relative imports
import { OTRCPParser } from "./ot-rcp-parser.js";
```

#### Export Patterns

```typescript
// Named exports preferred
export type NetworkParameters = { ... };
export enum InstallCodePolicy { ... }
export function encodeSpinelFrame(): HdlcFrame { ... }

// Const enums for compile-time constants
export const enum ZigbeeConsts { ... }

// Type-only imports/exports when appropriate
import type { HdlcFrame } from "./hdlc.js";
export type { ZigbeeAPSHeader };
```

### Type Annotations

```typescript
// Always provide explicit return types for public functions
export function encodeSpinelFrame(frame: SpinelFrame): HdlcFrame { ... }

// Use type annotations for complex variables
const header: SpinelFrameHeader = { tid, nli, flg };

// Infer simple types
const count = 0; // inferred as number
const isValid = true; // inferred as boolean

// Use as const for literal types
const COMMANDS = {
    RESET: 0x01,
    SAVE: 0x02,
} as const;

// Never use inferrable types (enforced by Biome)
// ❌ const count: number = 0;
// ✅ const count = 0;
```

### Comments and Documentation

#### Inline Comments

```typescript
// Brief, descriptive comments for non-obvious logic
// Used sparingly, code should be self-documenting

// XXX: marker for known issues needing attention
// TODO: marker for future improvements
// HACK: marker for temporary workarounds
// @deprecated: marker for deprecated features
```

#### Block Comments for Complex Structures

```typescript
/**
 * Spinel data types:
 *
 * +----------+----------------------+---------------------------------+
 * |   Char   | Name                 | Description                     |
 * +----------+----------------------+---------------------------------+
 * |   "."    | DATATYPE_VOID        | Empty data type. Used           |
 * |          |                      | internally.                     |
 * ...
 */

/**
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * |  FLG  |  NLI  |      TID      |
 * +---+---+---+---+---+---+---+---+
 */
type SpinelFrameHeader = { ... };
```

#### Type Documentation

```typescript
/**
 * The Network Link Identifier (NLI) is a number between 0 and 3, which
 * is associated by the OS with one of up to four IPv6 zone indices
 * corresponding to conceptual IPv6 interfaces on the NCP.
 */
nli: number;
```

## Performance Best Practices

### Critical Performance Rules

This is a performance-critical Zigbee stack. Always follow these patterns:

#### 1. No Expensive Operations in Hot Paths

```typescript
// ❌ BAD: JSON.stringify in logging
logger.debug(`Frame: ${JSON.stringify(frame)}`, NS);

// ✅ GOOD: Lazy evaluation with lambda
logger.debug(() => `Frame: ${frame.header.tid}`, NS);
```

#### 2. Early Bail-outs

```typescript
// ✅ Check conditions early and return
if (buffer.length < HEADER_SIZE) {
    return undefined;
}

// Process only if needed
const payload = decodePayload(buffer);
```

#### 3. Avoid Unnecessary Allocations

```typescript
// ✅ Reuse buffers when possible
const buffer = Buffer.allocUnsafe(size);

// ✅ Use slice views instead of copying
const view = buffer.subarray(offset, offset + length);
```

#### 4. Efficient Buffer Operations

```typescript
// ✅ Use Buffer methods directly
buffer.writeUInt8(value, offset);
buffer.writeUInt16LE(value, offset);

// ✅ Read in sequence without allocating intermediate values
let offset = 0;
const header = buffer.readUInt8(offset++);
const length = buffer.readUInt16LE(offset);
offset += 2;
```

### Logger Pattern

```typescript
// Logger interface (from src/utils/logger.ts)
export interface Logger {
    debug: (messageOrLambda: () => string, namespace: string) => void;
    info: (messageOrLambda: string | (() => string), namespace: string) => void;
    warning: (messageOrLambda: string | (() => string), namespace: string) => void;
    error: (messageOrLambda: string, namespace: string) => void;
}

// Usage pattern
const NS = "module-name"; // namespace constant at top of file

logger.debug(() => `Expensive computation: ${complexObject.toString()}`, NS);
logger.info("Simple message", NS);
logger.error(`Error: ${message}`, NS);
```

## Error Handling Patterns

### Throwing Errors

```typescript
// Always use new Error() with descriptive messages
throw new Error("APS fragmentation not supported");
throw new Error(`Invalid APS delivery mode ${frameControl.deliveryMode}`);
throw new Error("Auth tag mismatch while decrypting Zigbee payload");

// ❌ Never throw plain strings
// throw "Error message";
```

### Error Context

```typescript
// Include context in error messages
throw new Error(`Invalid MAC frame: destination address mode ${frameControl.destAddrMode}`);
throw new Error(`Unsupported key ID ${keyId}`);

// Be specific about what failed
throw new Error("Unable to decrypt Zigbee payload");
throw new Error("Zigbee NWK GP frame without payload");
```

### Validation Patterns

```typescript
// Validate inputs early
if (buffer.length < HEADER_MIN_SIZE) {
    throw new Error("Invalid NWK frame: no payload");
}

// Use assert for internal consistency checks (from node:assert)
assert(frameType === MACFrameType.DATA, "Expected DATA frame");
```

## Security Patterns

### Cryptographic Operations

```typescript
// Use Node.js crypto module for all cryptographic operations
import { createCipheriv } from "node:crypto";

// Always validate security headers before decryption
if (!securityHeader) {
    throw new Error("Unable to decrypt Zigbee payload");
}

// Verify authentication tags
if (!authTagMatches) {
    throw new Error("Auth tag mismatch while decrypting Zigbee payload");
}
```

### Sensitive Data Handling

```typescript
// Keys are stored as Buffer objects
const networkKey = Buffer.alloc(ZigbeeConsts.SEC_KEYSIZE);

// Use keyed hash for security operations
const keyedHash = makeKeyedHashByType(ZigbeeKeyType.NWK, networkKey);
```

## Testing Patterns

### Test Structure (Vitest)

```typescript
import { beforeAll, describe, expect, it } from "vitest";

describe("Module Name", () => {
    beforeAll(() => {
        // Setup that runs once before all tests
        registerDefaultHashedKeys(/* ... */);
    });

    it("describes what the test does", () => {
        // Arrange
        const input = createTestInput();
        
        // Act
        const result = functionUnderTest(input);
        
        // Assert
        expect(result).toStrictEqual(expectedOutput);
    });
});
```

### Test Data

```typescript
// Test data in separate file (test/data.ts)
export const NET2_ASSOC_REQ_FROM_DEVICE = Buffer.from("...");
export const NET2_COORD_EUI64_BIGINT = 0x00124b001234567n;
export const NETDEF_NETWORK_KEY = Buffer.from("...");
```

### Assertions

```typescript
// Always use toStrictEqual for deep equality, primitive values or boolean checks
expect(decodedValue).toStrictEqual(expectedValue);
```

### Coverage Requirements

- Statements: 85%+
- Functions: 85%+
- Branches: 80%+
- Lines: 85%+

## Biome Linter Rules

### Enforced Rules

```typescript
// ✅ Use throw new Error() syntax
throw new Error("message");

// ✅ Use as const assertions where appropriate
const VALUES = { A: 1, B: 2 } as const;

// ✅ Default parameters last
function func(required: string, optional: number = 0) { }

// ✅ Initialize all enum members
enum Status {
    SUCCESS = 0,
    FAILURE = 1,
}

// ✅ Single variable declarator
const a = 1;
const b = 2;
// ❌ const a = 1, b = 2;

// ✅ Use Number namespace
Number.isNaN(value);
// ❌ isNaN(value);

// ✅ No unused template literals
const str = "plain string";
// ❌ const str = `plain string`;

// ✅ No useless else
if (condition) {
    return value;
}
return otherValue;

// ✅ Use await in async functions
async function process() {
    await operation();
}
```

### Allowed Patterns

```typescript
// ✅ Non-null assertions allowed (use sparingly)
const value = maybeValue!;

// ✅ Parameter reassignment allowed
function process(value: number) {
    value = value * 2; // allowed but use carefully
}

// ✅ Const enums allowed
export const enum Constants {
    VALUE = 0x01,
}
```

### Prohibited Patterns

```typescript
// ❌ No barrel files (index.ts re-exporting everything)
// ❌ No re-export all
// export * from "./module";

// ❌ No unused imports (auto-fixed)
// ❌ No unused variables (warning)
```

## Buffer and Binary Operations

### Buffer Handling Patterns

```typescript
// Allocate buffers efficiently
const buffer = Buffer.allocUnsafe(size); // for temporary buffers
const buffer = Buffer.alloc(size); // for zero-initialized buffers
const buffer = Buffer.from(array); // from existing data

// Read operations (little-endian default in Zigbee)
const uint8 = buffer.readUInt8(offset);
const uint16 = buffer.readUInt16LE(offset);
const uint32 = buffer.readUInt32LE(offset);
const bigint64 = buffer.readBigUInt64LE(offset);

// Write operations
buffer.writeUInt8(value, offset);
buffer.writeUInt16LE(value, offset);
buffer.writeUInt32LE(value, offset);
buffer.writeBigUInt64LE(value, offset);

// Slicing and views
const view = buffer.subarray(start, end); // creates a view (no copy)
const copy = buffer.subarray(start, end); // only copy if needed
```

### Bitwise Operations

```typescript
// Use const enums for bit masks
export const enum ZigbeeAPSConsts {
    FCF_FRAME_TYPE = 0x03,
    FCF_DELIVERY_MODE = 0x0c,
    FCF_SECURITY = 0x20,
    FCF_ACK_REQ = 0x40,
}

// Extract bit fields
const frameType = (fcf & ZigbeeAPSConsts.FCF_FRAME_TYPE) >> 0;
const deliveryMode = (fcf & ZigbeeAPSConsts.FCF_DELIVERY_MODE) >> 2;
const security = (fcf & ZigbeeAPSConsts.FCF_SECURITY) !== 0;

// Set bit fields
let fcf = 0;
fcf |= (frameType << 0) & ZigbeeAPSConsts.FCF_FRAME_TYPE;
fcf |= (deliveryMode << 2) & ZigbeeAPSConsts.FCF_DELIVERY_MODE;
if (security) {
    fcf |= ZigbeeAPSConsts.FCF_SECURITY;
}
```

### Hexadecimal Formatting

```typescript
// Use hex for protocol values
const panId = 0x1a62;
const address16 = 0xfffc;
const commandId = 0x05;

// Format as hex in error messages
throw new Error(`Invalid frame type: 0x${frameType.toString(16).padStart(2, "0")}`);
```

## Callback Pattern for Handlers

Handlers use callback interfaces to communicate with the driver instead of emitting events. This provides better type safety and clearer dependencies.

**Handler callback interfaces:**
- `MACHandlerCallbacks` - MAC layer to driver
- `NWKHandlerCallbacks` - NWK layer to driver
- `NWKGPHandlerCallbacks` - Green Power to driver
- `APSHandlerCallbacks` - APS layer to driver
- `StackContextCallbacks` - Stack context to driver

### Driver Callbacks (External Communication)

The driver communicates with external consumers (e.g., Zigbee2MQTT) through the `StackCallbacks` interface:

```typescript
// StackCallbacks interface
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

// Usage in OTRCPDriver constructor
constructor(callbacks: StackCallbacks, streamRawConfig: StreamRawConfig, netParams: NetworkParameters, saveDir: string, emitMACFrames = false) {
    this.#callbacks = callbacks;
    // ...
}

// Calling external consumer
this.#callbacks.onDeviceJoined(source16, source64, capabilities);
```

## Zigbee-Specific Patterns

### Address Handling

```typescript
// 16-bit addresses as numbers
const coordinator16 = ZigbeeConsts.COORDINATOR_ADDRESS; // 0x0000
const broadcast16 = ZigbeeConsts.BCAST_DEFAULT; // 0xfffc

// 64-bit addresses as bigint
const ieee64 = 0x00124b0012345678n;

// Check broadcast addresses
if (destAddress >= ZigbeeConsts.BCAST_MIN) {
    // Broadcast destination
}
```

### Frame Encoding/Decoding Pattern

```typescript
// Consistent pattern across all protocol layers
export function encodeXxxFrame(header: XxxHeader, payload?: Buffer): Buffer {
    // 1. Calculate size
    const size = calculateFrameSize(header, payload);
    
    // 2. Allocate buffer
    const buffer = Buffer.allocUnsafe(size);
    
    // 3. Write header fields
    let offset = 0;
    buffer.writeUInt8(header.field1, offset++);
    buffer.writeUInt16LE(header.field2, offset);
    offset += 2;
    
    // 4. Write payload if present
    if (payload) {
        payload.copy(buffer, offset);
    }
    
    return buffer;
}

export function decodeXxxHeader(buffer: Buffer): XxxHeader {
    // 1. Validate size
    if (buffer.length < MIN_SIZE) {
        throw new Error("Invalid frame: too short");
    }
    
    // 2. Read header fields
    let offset = 0;
    const field1 = buffer.readUInt8(offset++);
    const field2 = buffer.readUInt16LE(offset);
    offset += 2;
    
    // 3. Return structured header
    return { field1, field2 };
}
```

## Module Organization

### File Responsibilities

Each file should have a single, clear responsibility:

- **Encoding functions**: Convert structured data to Buffer
- **Decoding functions**: Convert Buffer to structured data
- **Constants**: Protocol-specific const enums and constants
- **Types**: TypeScript interfaces and types for the protocol

### Const Enum for Constants

```typescript
// Use const enum for protocol constants to avoid runtime overhead
export const enum ZigbeeConsts {
    COORDINATOR_ADDRESS = 0x0000,
    HA_ENDPOINT = 0x01,
    ZDO_ENDPOINT = 0x00,
    SEC_KEYSIZE = 16,
}
```

## Project-Specific Guidelines

### Zero Production Dependencies Policy

```typescript
// ✅ ALWAYS use Node.js built-in modules
import { readFile } from "node:fs/promises";
import { createCipheriv } from "node:crypto";
import EventEmitter from "node:events";

// ❌ NEVER add external production dependencies
// import thirdPartyLib from "some-package";

// Exception: src/dev/ and test/ can use dev dependencies
```

### State Management

```typescript
// Network state saved to zoh.save file (similar to NCP NVRAM)
// State includes:
// - Network configuration
// - Device tables
// - Security keys
// - Frame counters

// State file structure defined by SaveConsts enum
const enum SaveConsts {
    NETWORK_DATA_SIZE = 1024,
    DEVICE_DATA_SIZE = 512,
    FRAME_COUNTER_JUMP_OFFSET = 1024,
}
```

### Routing Feedback Loop (keep MAC/NWK changes in sync)

- `MACHandler.sendFrameDirect()` **must** clear `StackContext.macNoACKs` and call `NWKHandler.markRouteSuccess()` when a unicast ACK succeeds, and increment `macNoACKs` plus call `markRouteFailure()` when a NO_ACK error occurs.
- `StackContext.sourceRouteTable` stores **multiple** `SourceRouteTableEntry` objects per destination; `NWKHandler.findBestSourceRoute()` re-sorts them on every lookup using: path cost + staleness penalty + failure penalty − recency bonus, and filters out relays whose `macNoACKs` entry exceeds `CONFIG_NWK_CONCENTRATOR_DELIVERY_FAILURE_THRESHOLD`.
- Whenever all routes are purged (expired/blacklisted) the NWK handler must immediately trigger `sendPeriodicManyToOneRouteRequest()` so the coordinator refreshes routes.
- Link-status frames reuse the computed path costs so any tweak to the heuristic must stay consistent across `sendPeriodicZigbeeNWKLinkStatus()` and the source-route scorer.

### Wireshark Compatibility

```typescript
// Property names should match Wireshark for debugging
// Example: "sourceAddress" not "srcAddr"
// This aids in correlating code with packet captures
```

### Trust Center Focus

```typescript
// This implementation focuses on "Centralized Trust Center"
// When implementing security features, prioritize Trust Center operations
```

## Anti-Patterns to Avoid

```typescript
// ❌ Don't use default exports
// export default function something() { }

// ❌ Don't use barrel files (index.ts)
// export * from "./module1";
// export * from "./module2";

// ❌ Don't use re-export all
// export * from "./other-module";

// ❌ Don't use magic numbers without const enums
// if (value === 0x05) { // what is 0x05?

// ✅ Use const enums
// if (value === ZigbeeAPSCommandId.TRANSPORT_KEY) {

// ❌ Don't stringify objects in hot paths
// logger.debug(`Object: ${JSON.stringify(obj)}`, NS);

// ✅ Use lazy evaluation
// logger.debug(() => `Object: ${formatObject(obj)}`, NS);

// ❌ Don't use inferrable type annotations
// const count: number = 0;

// ✅ Let TypeScript infer
// const count = 0;
```

## Development vs Production Code

### Development Code (src/dev/)

- Excluded from production builds via tsconfig.prod.json
- Can use dev dependencies (serialport, etc.)
- Can have relaxed performance requirements
- Used for CLI tools, testing utilities, data conversion

### Production Code (src/drivers/, src/zigbee-stack/, src/spinel/, src/zigbee/, src/utils/)

- Must work with zero external dependencies
- Must meet strict performance requirements
- Must follow all architectural guidelines
- Included in npm package distribution

## Version Control and CI

### Pre-commit Checks

```bash
npm run check           # Auto-fix linting issues
npm test:cov            # Run tests with coverage check
npm run build:prod      # Verify production build
```

### CI Pipeline Requirements

All code must pass:

1. Production build: `npm run build:prod`
2. Linting: `npm run check:ci`
3. Tests: `npm run test:cov` (with coverage thresholds)
4. Benchmarks: `npm run bench`

## Summary

When generating code for this project:

1. **Use `.js` extensions** in all imports (NodeNext modules)
2. **Follow naming conventions** - PascalCase types, CONSTANT_CASE enums, camelCase functions
3. **No external dependencies** in production code
4. **Performance first** - no expensive operations in hot paths, early bail-outs
5. **Use const enums** for protocol constants
6. **Throw new Error()** with descriptive messages
7. **4-space indentation**, 150-char lines, double quotes
8. **Match architectural layers** - respect boundaries between drivers, protocols, utilities
9. **Prioritize consistency** with existing code over external "best practices"

Before generating any code, scan similar files in the codebase to understand existing patterns and follow them exactly.
