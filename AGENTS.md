# AGENTS.md

## Project Overview

ZigBee on Host is an open-source ZigBee stack designed to run on a host and communicate with a radio co-processor (RCP). The implementation targets compatibility with OpenThread RCP firmware, supporting multiple chip manufacturers (Silabs, TI, Nordic) through the Spinel protocol's `STREAM_RAW` mechanism.

**Architecture:**
- **Host-based ZigBee stack** with RCP communication
- **Language:** TypeScript (~7,000 lines of source code)
- **Runtime:** Node.js ^20.19.0 || >=22.12.0
- **License:** GPL-3.0-or-later
- **Module system:** NodeNext (ES modules)
- **Zero production dependencies** - lightweight core

**Key Components:**
- `src/drivers/` - RCP communication drivers (main: `ot-rcp-driver.ts`)
- `src/spinel/` - Spinel protocol implementation (HDLC framing, properties)
- `src/zigbee/` - ZigBee protocol layers (MAC, NWK, APS, Green Power)
- `src/dev/` - Development tools (excluded from production builds)
- `src/utils/` - Shared utilities (logging framework)

## Setup Commands

**Prerequisites:**
- Node.js version >=22.12.0 (also supports ^20.19.0)
- npm 10.8.2+

**Initial setup:**
```bash
npm ci                    # Install dependencies (~10s)
```

**Production build (RECOMMENDED for reliability):**
```bash
npm run build:prod        # Build without dev tools (~5-10s)
```

**Development build (needed for dev:* commands):**
```bash
npm run build            # Build with dev tools (~5-10s)
```

**Clean build (if encountering issues):**
```bash
npm run clean            # Remove dist/ and *.tsbuildinfo
npm run build:prod       # Rebuild
```

## Development Workflow

### Build System

**Two build configurations:**
- `npm run build` - Development build (includes `src/dev/` directory)
- `npm run build:prod` - Production build (excludes `src/dev/` directory) ⭐ **Use this by default**

**Configuration files:**
- `tsconfig.json` - Development TypeScript config (includes src/dev/)
- `tsconfig.prod.json` - Production config (excludes src/dev/)

**Critical notes:**
- Always use `build:prod` unless you specifically need dev CLI tools
- Use `npm run clean` if TypeScript incremental compilation issues occur
- Build outputs to `dist/` directory
- Entry point: `dist/drivers/ot-rcp-driver.js`

### Development CLI Tools

After running `npm run build` (not build:prod), these commands are available:

```bash
npm run dev:cli help                           # Show CLI commands
npm run dev:z2z ./path/to/data/               # Convert Z2M data to zoh.save
npm run dev:z2r ./path/to/data/               # Print readable zoh.save content
```

**CLI configuration:** `dist/dev/conf.json` (auto-generated after build)

**Environment variables:**
- `ADAPTER_PATH` - Serial port path
- `ADAPTER_BAUDRATE` - Baud rate (default: 460800)
- `ADAPTER_RTSCTS` - Hardware flow control (true/false)

### State Management

- **State file:** `zoh.save` contains network state (similar to NCP NVRAM)
- **Config file:** `dist/dev/conf.json` for adapter/network settings (development only)
- Located in the working directory or data folder

## Testing Instructions

**Run all tests:**
```bash
npm test                # Run test suite (~2s)
```

**Run tests with coverage:**
```bash
npm run test:cov        # Run tests with coverage report (~2.5s)
```

**Coverage requirements:**
- Statements: 70%+
- Functions: 75%+
- Branches: 75%+
- Lines: 70%+

**Coverage details:**
- Provider: v8
- Reports: text and HTML (in `coverage/` directory)
- Excludes: `src/dev/**` directory
- Only tests `.ts` files in `src/**`

**Run benchmarks:**
```bash
npm run bench           # Performance benchmarks (~27s)
```

**Test files location:**
- `test/*.test.ts` - Test suites (Vitest framework)
- `test/*.bench.ts` - Performance benchmarks
- `test/vitest.config.mts` - Test runner configuration

**Note:** Some Wireshark integration tests may be environment-dependent and could be skipped.

## Code Style Guidelines

### Linting and Formatting

**Fix issues automatically:**
```bash
npm run check           # Auto-fix linting/formatting (~0.5s)
```

**Check only (CI mode):**
```bash
npm run check:ci        # Check without fixing
```

**Formatter:** Biome (configuration in `biome.json`)

### Style Rules

**Indentation and formatting:**
- 4 spaces for indentation
- 150 character line width
- LF line endings
- Double quotes for strings
- Self-closing elements required

**Naming conventions:**
- `CONSTANT_CASE` for enum members
- ASCII characters required
- Not strict case enforcement (flexible)

**TypeScript specifics:**
- No unused imports (error)
- No inferrable types (error)
- Use `as const` assertions
- Use default parameters last
- Enum initializers required
- Single var declarator per statement
- Use number namespace
- Use await in async functions

**Prohibited patterns:**
- Non-null assertions allowed (`!`)
- Parameter reassignment allowed
- Const enums allowed
- Template literals without substitution (error)

**Performance rules:**
- No barrel files (error)
- No re-export all (error)

**Code organization:**
- No expensive calls (stringify, etc.) in hot paths
- Early bail-outs for performance
- Zero external production dependencies policy

### File Organization

**Source structure:**
```
src/
├── drivers/          # RCP communication
├── spinel/           # Spinel protocol
├── zigbee/           # ZigBee layers (MAC, NWK, APS, GP)
├── dev/              # Development tools (excluded from prod)
└── utils/            # Shared utilities
```

**Test structure:**
```
test/
├── *.test.ts         # Test files
├── *.bench.ts        # Benchmark files
├── data.ts           # Test data
└── vitest.config.mts # Configuration
```

## Build and Deployment

### Build Process

**Production build (npm package):**
```bash
npm run prepack        # Automatically runs: clean + build:prod
```

**Build outputs:**
- Directory: `dist/`
- Main entry: `dist/drivers/ot-rcp-driver.js`
- Type definitions: `dist/drivers/ot-rcp-driver.d.ts`
- Package includes: `./dist` only

**Build artifacts (ignored by git):**
- `dist/` - Compiled JavaScript and type definitions
- `*.tsbuildinfo` - TypeScript incremental compilation cache
- `*.save` - State files (e.g., `zoh.save`)
- `coverage/` - Test coverage reports

### TypeScript Configuration

**Compiler settings:**
- Target: ES2022
- Module: NodeNext
- Module resolution: NodeNext
- Composite project enabled
- JSON module resolution enabled
- Root directory: `src/`

## CI/CD Pipeline

### GitHub Actions Workflow

**Triggers:**
- Push to `main` branch
- Pull requests (except `built-main` branch)

**Jobs:**

**1. Checks job (ubuntu-latest):**
```bash
npm ci                  # Install dependencies
npm run build:prod      # Production build
npm run check:ci        # Lint check
npm run bench          # Benchmarks with comparison to main
```

**2. Tests job (matrix):**
- **OS matrix:** ubuntu-latest, macos-latest, windows-latest
- **Node versions:** 20, 22, 24
- **Steps:**
```bash
npm ci                  # Install dependencies
npm run build:prod      # Production build
npm run test:cov        # Tests with coverage
```

**Coverage thresholds enforced:**
- See Testing Instructions section above

### Local CI Validation

**Replicate CI checks locally:**
```bash
npm ci
npm run build:prod
npm run check:ci
npm run test:cov
npm run bench           # Optional, takes ~27s
```

**Quick validation before commit:**
```bash
npm run check           # Fix linting issues
npm test                # Run tests quickly
```

## Pull Request Guidelines

### Before Submitting

**Required checks:**
```bash
npm run check           # Fix linting and formatting
npm run test:cov        # Ensure tests pass with coverage
npm run build:prod      # Verify production build works
```

**Code quality:**
- Add or update tests for code changes
- Maintain or improve coverage thresholds (70%+ statements, 75%+ functions/branches)
- Follow Biome linting rules (see Code Style Guidelines)
- Search for `TODO`, `XXX`, `@deprecated` markers if modifying related code

**Commit message format:**
- Clear, concise descriptions
- Reference issue numbers if applicable

### PR Requirements

- All CI checks must pass (linting, tests, benchmarks)
- Coverage thresholds must be met
- Production build must succeed on all platforms (ubuntu, macos, windows)
- Tests must pass on Node.js 20, 22, and 24

## Docker Development

### Setup

**Start development container:**
```bash
docker compose -f docker-dev/compose.yaml up -d --pull never
```

**Install dependencies and build:**
```bash
docker compose -f docker-dev/compose.yaml exec zigbee-on-host npm ci
docker compose -f docker-dev/compose.yaml exec zigbee-on-host npm run build
```

**Cleanup:**
```bash
docker compose -f docker-dev/compose.yaml down
```

## ZigBee Protocol Implementation

### Current Implementation Status

**Implemented features:**
- ✅ Spinel & HDLC protocol encoding/decoding
- ✅ MAC frame encoding/decoding
- ✅ ZigBee NWK frame encoding/decoding
- ✅ ZigBee NWK GP (Green Power) frames
- ✅ ZigBee APS frame encoding/decoding
- ✅ Network forming
- ✅ Network state saving (backups)
- ✅ Network state reset
- ✅ Joining/Rejoining mechanisms
- ✅ APS TC link key update (global)
- ✅ Direct child router/end device
- ✅ Nested device support
- ✅ Indirect transmission mechanism
- ✅ Source routing
- ✅ Coordinator LQI/Routing tables
- ✅ LQI reporting

**Work in progress:**
- ⚠️ Route repairing
- ⚠️ Install codes
- ⚠️ APS APP link keys
- ⚠️ InterPAN / Touchlink
- ⚠️ R23 support
- ⚠️ Security refinement
- ⚠️ Metrics/Statistics

**Notes:**
- 112 TODO/HACK/XXX markers in codebase
- Focus on "Centralized Trust Center" implementation
- Lacking reference sniffs for multicast (group)

### Protocol Layers

**Spinel Protocol (`src/spinel/`):**
- `spinel.ts` - Core protocol (~400 lines)
- `hdlc.ts` - HDLC framing
- `properties.ts` - Spinel properties (2,800 lines)
- `commands.ts` - Spinel commands
- `statuses.ts` - Status codes

**ZigBee Layers (`src/zigbee/`):**
- `mac.ts` - IEEE 802.15.4 MAC layer
- `zigbee-nwk.ts` - Network layer
- `zigbee-aps.ts` - Application Support layer
- `zigbee-nwkgp.ts` - Green Power
- `zigbee.ts` - Main ZigBee utilities

**Driver (`src/drivers/`):**
- `ot-rcp-driver.ts` - Main RCP driver (4,700 lines)
- `ot-rcp-parser.ts` - Frame parsing
- `ot-rcp-writer.ts` - Frame writing
- `descriptors.ts` - Device descriptors

### Firmware Compatibility

**OpenThread RCP firmware supported:**
- **Silicon Labs:** https://github.com/Nerivec/silabs-firmware-builder/releases
- **Texas Instruments:** https://github.com/Koenkk/OpenThread-TexasInstruments-firmware/releases
- **Nordic Semiconductor:** Pending (see discussions)

**Known limitations:**
- Texas Instruments: Does not implement `PHY_CCA_THRESHOLD` (cannot read or write)

## Debugging and Troubleshooting

### Common Issues

**Build issues:**
- Run `npm run clean` to remove stale build artifacts
- Ensure Node.js version is >=22.12.0 (or ^20.19.0)
- Check TypeScript incremental compilation cache (*.tsbuildinfo)

**Dev commands not available:**
- Ensure you ran `npm run build` (not `build:prod`)
- Check that `dist/dev/` directory exists
- Verify `dist/dev/conf.json` was generated

**Test failures:**
- Some Wireshark tests may be environment-dependent
- Check coverage thresholds in `test/vitest.config.mts`
- Run with `--reporter=verbose` for detailed output

**Runtime issues:**
- Check `zoh.save` state file exists and is valid
- Verify RCP firmware version compatibility
- Check serial port permissions and path
- Validate environment variables (ADAPTER_PATH, etc.)

### Logging

**Logger framework:** `src/utils/logger.ts`

**Performance considerations:**
- No expensive calls in hot paths
- Early bail-outs for efficiency
- Avoid stringify operations in critical paths

### Wireshark Integration

**ZEP Support:** Built-in ZigBee Encapsulation Protocol (ZEP) support for packet capture analysis

**Dev tool:** `src/dev/wireshark.ts` provides Wireshark integration utilities

## Additional Context

### Project Metadata

- **Repository:** https://github.com/Nerivec/zigbee-on-host
- **npm package:** zigbee-on-host
- **Version:** 0.1.13 (work in progress, expect breaking changes)
- **Author:** Nerivec

### Key Files

- `package.json` - Dependencies, scripts, metadata
- `README.md` - User-facing documentation
- `CONTRIBUTING.md` - Contribution guidelines
- `CODE_OF_CONDUCT.md` - Community standards
- `LICENSE` - GPL-3.0-or-later
- `biome.json` - Linter/formatter configuration
- `.vscode/settings.json` - Recommended editor settings

### Performance Focus

- **Design philosophy:** Performance-critical ZigBee stack
- **No expensive operations** in hot code paths
- **Early bail-outs** to minimize processing
- **Lean bundle:** Zero external production dependencies
- **Benchmarking:** Continuous performance monitoring via CI

### Integration with Zigbee2MQTT

- Supported from version 2.1.3-dev onwards
- Use `adapter: zoh` in configuration.yaml
- Recommend using `latest-dev` (edge) for testing
- `zoh.save` replaces traditional NCP NVRAM
- No `coordinator_backup.json` is created

### Use Cases

- **Production:** IoT device control via ZigBee networks
- **Development:** Building ZigBee applications
- **Pentesting:** ZigBee network security testing (craft custom payloads at any layer)
- **Research:** Study ZigBee protocol implementations

### Contributing

- Submit sniffs/captures to help improve compatibility
- Search for `TODO`, `HACK`, `XXX` markers for areas needing work
- Maintain zero production dependencies policy
- Align with ZigBee 3.0 specification
- Use Wireshark property names for consistency

### Testing Status

- **CI:** ~70% coverage
- **Stress-testing:** Pending
- **Firmware stability:** Silicon Labs and TI ongoing, Nordic pending
- **Test networks:** Ongoing validation
- **Live networks:** Pending validation
