# ZigBee on Host - Copilot Instructions

## Repository Overview

ZigBee on Host is an open-source ZigBee stack designed to run on a host and communicate with a radio co-processor (RCP). The project provides compatibility with OpenThread RCP firmware, supporting multiple chip manufacturers (Silabs, TI, Nordic) through the Spinel protocol's `STREAM_RAW` mechanism.

**Key Stats:**
- Language: TypeScript (20 source files)
- Runtime: Node.js ^20.19.0 || >=22.12.0  
- Size: ~7,000 lines of source code with 112 TODO/HACK/XXX markers
- License: GPL-3.0-or-later
- Architecture: Host-based ZigBee stack with RCP communication

## Build Instructions

### Prerequisites
- Node.js version ^20.19.0 || >=22.12.0
- npm (tested with 10.8.2+)

### Essential Build Commands

**ALWAYS use production build for reliability:**
```bash
npm ci                    # Install dependencies (~10s)
npm run build:prod        # Production build (~5-10s) - RECOMMENDED
```

**Development build (needed for dev:* commands):**
```bash
npm ci
npm run build            # Development build (~5-10s) - includes src/dev/
```

**If build issues occur:**
```bash
npm run clean            # Remove dist/ and *.tsbuildinfo files
npm run build:prod       # Then rebuild
```

> **Critical:** Running `npm run build:prod` omits the `src/dev` directory. If you need `dev:*` commands, use `npm run build` instead.

### Validation Commands

**Linting (~0.5s):**
```bash
npm run check           # Fix issues automatically
npm run check:ci        # Check only (CI mode)
```

**Testing (~2s):**
```bash
npm test                # Run tests
npm run test:cov        # Run tests with coverage (~2.5s)
```

**Benchmarking (~27s):**
```bash
npm run bench           # Performance benchmarks
```

### Development CLI Tools

After `npm run build` (not build:prod):
```bash
npm run dev:cli help                           # Show CLI commands
npm run dev:z2z ./path/to/data/               # Convert Z2M data to zoh.save
npm run dev:z2r ./path/to/data/               # Print readable zoh.save content
```

CLI configuration: `dist/dev/conf.json` (auto-generated after build)
Environment variables: `ADAPTER_PATH`, `ADAPTER_BAUDRATE`, `ADAPTER_RTSCTS`

### Docker Development

**Setup:**
```bash
docker compose -f docker-dev/compose.yaml up -d --pull never
docker compose -f docker-dev/compose.yaml exec zigbee-on-host npm ci
docker compose -f docker-dev/compose.yaml exec zigbee-on-host npm run build
```

**Cleanup:**
```bash
docker compose -f docker-dev/compose.yaml down
```

## Project Architecture

### Key Directories
```
src/
├── drivers/           # RCP communication drivers
│   ├── ot-rcp-driver.ts     # Main driver (4,700 lines)
│   ├── ot-rcp-parser.ts     # Frame parsing
│   └── ot-rcp-writer.ts     # Frame writing
├── spinel/           # Spinel protocol implementation  
│   ├── spinel.ts           # Core protocol (~400 lines)
│   ├── hdlc.ts            # HDLC framing
│   └── properties.ts       # Spinel properties (2,800 lines)
├── zigbee/           # ZigBee protocol layers
│   ├── mac.ts             # IEEE 802.15.4 MAC layer
│   ├── zigbee-nwk.ts      # Network layer
│   ├── zigbee-aps.ts      # Application Support layer
│   └── zigbee-nwkgp.ts    # Green Power
├── dev/              # Development tools (excluded from production)
│   ├── cli.ts            # Development CLI
│   ├── conf.json         # CLI configuration
│   └── minimal-adapter.ts # Testing adapter
└── utils/            # Shared utilities
    └── logger.ts         # Logging framework
```

### Configuration Files
- `tsconfig.json` - Development TypeScript config (includes src/dev/)
- `tsconfig.prod.json` - Production config (excludes src/dev/)
- `biome.json` - Linting and formatting rules
- `test/vitest.config.mts` - Test configuration
- `.gitignore` - Excludes dist/, *.tsbuildinfo, *.save files

### Entry Points
- **Library:** `dist/drivers/ot-rcp-driver.js` (main export)
- **CLI:** `dist/dev/cli.js` (development only)
- **Utils:** `dist/dev/z2mdata-to-zohsave.js`, `dist/dev/zohsave-to-readable.js`

## Continuous Integration

### GitHub Actions Workflow (`.github/workflows/ci.yaml`)
```yaml
# Triggered on: push to main, PRs (except built-main branch)
# Matrix: ubuntu/macos/windows × Node 20/22/24

1. Install dependencies: npm ci
2. Build: npm run build:prod      # Production build required
3. Lint: npm run check:ci         # Biome linting
4. Benchmark: npm run bench       # Performance tests  
5. Test: npm run test:cov        # Tests with coverage
```

**Coverage Requirements:** 70%+ statements, 75%+ functions/branches, 70%+ lines

### Local Validation
```bash
# Replicate CI checks locally:
npm ci
npm run build:prod
npm run check:ci  
npm run test:cov
npm run bench     # Optional, takes ~27s
```

## Important Notes

### Build System Caveats
- **Development vs Production:** Always use `build:prod` unless you specifically need dev tools
- **Clean builds:** Use `npm run clean` if encountering TypeScript incremental compilation issues  
- **Dependencies:** No external production dependencies (keeps bundle lean)

### Development Guidelines
- **Performance focused:** No expensive calls (stringify, etc.), early bail-outs
- **ZigBee compliance:** Align with ZigBee 3.0 specification and Wireshark property names
- **Code markers:** Search for `TODO`, `XXX`, `@deprecated` for active development areas
- **Trust Center:** Focus on "Centralized Trust Center" implementation

### Runtime Environment
- **State file:** `zoh.save` contains network state (similar to NCP NVRAM)
- **Config file:** Development CLI uses `dist/dev/conf.json` for adapter/network settings
- **Wireshark integration:** Built-in ZEP (ZigBee Encapsulation Protocol) support

### Testing
- **Test files:** `test/*.test.ts` using Vitest framework
- **Benchmarks:** `test/*.bench.ts` for performance testing  
- **Coverage:** Stored in `coverage/` directory (excluded from git)
- **Skipped tests:** Some Wireshark integration tests are environment-dependent

## File Locations Reference

**Main Source Files:**
- `src/drivers/ot-rcp-driver.ts` - Primary adapter driver
- `src/spinel/spinel.ts` - Core protocol implementation  
- `src/zigbee/zigbee.ts` - Main ZigBee utilities
- `package.json` - Dependencies and scripts
- `README.md` - User documentation

**Configuration:**
- `biome.json` - Linter/formatter config (4-space indents, 150 char lines)
- `tsconfig.json` - TypeScript compiler settings
- `.vscode/settings.json` - Recommended Biome formatter settings

**Testing:**
- `test/vitest.config.mts` - Test runner configuration
- Coverage thresholds defined, v8 provider

## Trust These Instructions

These instructions have been validated by testing all documented commands. Only search for additional information if these instructions are incomplete or contain errors. The build and test commands have been verified to work correctly in the current environment.