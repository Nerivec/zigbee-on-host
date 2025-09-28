# ZigBee on Host - Copilot Instructions

You are helping with the `zigbee-on-host` project, an open-source ZigBee stack designed to run on a host and communicate with a radio co-processor (RCP) using OpenThread.

## Project Overview

This is a TypeScript/Node.js project that implements:
- ZigBee 3.0 stack for host-based implementations
- OpenThread RCP (Radio Co-Processor) driver integration
- Spinel protocol communication
- Network formation, joining, and management
- Device discovery and communication
- Wireshark integration for debugging

## Development Environment

- **Node.js**: `^20.19.0 || >=22.12.0`
- **TypeScript**: ES2022 target, NodeNext module system
- **Linter**: Biome (configuration in `biome.json`)
- **Testing**: Vitest with coverage support
- **Build**: TypeScript compiler with composite project structure

## Code Style and Architecture Guidelines

### Core Principles
- **Zero external production dependencies** - Keep the core lightweight
- **Performance-focused** - No expensive calls, bail early, optimize for speed
- **ZigBee 3.0 compliance** - Follow the specification but allow host-driven optimizations
- **Centralized Trust Center** - Focus on this implementation pattern
- **Wireshark compatibility** - Keep MAC/ZigBee property naming aligned for debugging

### Code Style
- Use strict TypeScript settings
- 4-space indentation, 150 character line width
- Double quotes for strings
- Organize imports automatically
- Use `TODO`, `XXX`, `@deprecated` markers for quick access
- CONSTANT_CASE for enum members
- Descriptive variable and function names

### File Structure
```
src/
├── dev/           # Development utilities and CLI tools
├── drivers/       # RCP driver implementations (main: ot-rcp-driver)
├── spinel/        # Spinel protocol implementation
├── utils/         # Shared utilities
└── zigbee/        # ZigBee protocol stack implementation
```

## Build and Test Workflow

### Commands
- `npm run build` - Full TypeScript compilation
- `npm run build:prod` - Production build (excludes `src/dev`)
- `npm run test` - Run Vitest test suite
- `npm run test:cov` - Run tests with coverage
- `npm run check` - Run Biome linter with fixes
- `npm run check:ci` - Run Biome linter (CI mode)
- `npm run clean` - Remove build artifacts

### Development Tools
- `npm run dev:cli help` - CLI utilities for testing and development
- Configuration via `dist/dev/conf.json` and environment variables
- Wireshark integration for protocol debugging

## Key Technical Concepts

### Protocols and Standards
- **ZigBee 3.0**: Application layer protocol for IoT devices
- **OpenThread**: Thread networking protocol implementation
- **Spinel**: Host-RCP communication protocol
- **IEEE 802.15.4**: Underlying radio standard

### Core Components
- **OTRCPDriver**: Main driver for OpenThread RCP communication
- **Spinel**: Protocol handling for host-RCP communication
- **MAC/Network layers**: ZigBee network management
- **Security**: Key management and encryption
- **CLI tools**: Development and debugging utilities

### Testing Approach
- Unit tests with Vitest
- Mock RCP responses for driver testing
- Protocol frame validation
- Network formation and device communication scenarios

## Common Development Patterns

### Error Handling
```typescript
// Use descriptive error messages
throw new Error(`Failed to form network: ${reason}`);

// Validate inputs early
if (!config.networkKey || config.networkKey.length !== 16) {
    throw new Error("Network key must be 16 bytes");
}
```

### Protocol Implementation
```typescript
// Follow ZigBee/OpenThread naming conventions
interface ZigBeeApsFrame {
    frameControl: ZigBeeApsFrameControl;
    profileId: number;
    clusterId: number;
    sourceEndpoint: number;
    destEndpoint: number;
}
```

### Performance Considerations
```typescript
// Bail early to avoid unnecessary processing
if (!this.isNetworkUp) {
    return Promise.resolve();
}

// Avoid expensive operations in hot paths
// Use efficient data structures for routing tables
```

## Testing Guidelines

- Test protocol compliance and edge cases
- Mock RCP communication for unit tests
- Validate frame parsing and generation
- Test network formation and device management scenarios
- Include performance benchmarks for critical paths

## Contributing Context

When making changes:
1. Maintain compatibility with ZigBee 3.0 specification
2. Ensure OpenThread RCP communication remains stable
3. Keep performance optimizations in mind
4. Add appropriate test coverage
5. Update documentation for public APIs
6. Follow existing code patterns and naming conventions

## Debugging and Development

- Use Wireshark integration for protocol debugging
- CLI tools provide network formation and sniffing capabilities
- Environment variables can override configuration
- Incremental TypeScript compilation for faster builds
- Test coverage reports help identify gaps

## Special Considerations

- Handle different RCP firmware variations (Texas Instruments, Silicon Labs, etc.)
- Support for both development and production builds
- Docker development environment available
- Security key management and frame counters
- Network topology and routing table management