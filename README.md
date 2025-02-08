# ZigBee on Host

Open Source ZigBee stack designed to run on a host and communicate with a radio co-processor (RCP).

Current implementation aims for compatibility with OpenThread RCP firmware. That base provides compatibility with any chip manufacturer that supports it (Silabs, TI, etc.) with the only requirements being proper implementation of the STREAM_RAW mechanism of the Spinel protocol (which allows to send raw 802.15.4 frames, including... ZigBee!) and hardware MAC ACKing (much faster).

_This library can also serve as a base for pentesting ZigBee networks thanks to the ability to easily craft various payloads at any layer of the specification and send them through the raw stream using any network parameters._

> [!IMPORTANT]
> Work in progress! Expect breaking changes without backwards compatibility for a while!

## Development

### Guidelines

Some quick guidelines to keep the codebase maintainable:

- No external production dependencies
- Mark `TODO` / `XXX` / `@deprecated` in code as needed for quick access
- Performance in mind (with the goal to eventually bring the appropriate layers to a lower language as needed)
  - No expensive calls (stringify, etc.)
  - Bail as early as possible (no unnecessary parsing, holding waiters, etc.)
  - Ability to no-op expensive "optional" features
  - And the usuals...
- Keep MAC/ZigBee property naming mostly in line with Wireshark for easier debugging
- Keep in line with the ZigBee 3.0 specification, but allow optimization due to the host-driven nature and removal of unnecessary features that won't impact compatibility
- Focus on "Centralized Trust Center" implementation (at least at first)

### Current status

> [~] Partial feature, [?] Uncertain feature

- [x] Encoding/decoding of Spinel & HDLC protocols
- [x] Encoding/decoding of MAC frames
- [x] Encoding/decoding of ZigBee NWK frames
  - [ ] lacking reference sniffs for multicast (group)
- [x] Encoding/decoding of ZigBee NWK GP frames
  - [ ] lacking reference sniffs, needs full re-check
  - [ ] FULLENCR & auth tag checking codepaths
- [x] Encoding/decoding of ZigBee NWK APS frames
- [x] Network forming
- [~] Network state saving (de facto backups)
  - [ ] Deal with frame counters (avoiding too many writes, but preventing mismatch issues)
  - [ ] Runtime changing of network parameters (ZDO channel, PAN ID...)
- [~] Joining/Rejoining
  - [x] APS TC link key update mechanism (global)
  - [x] Direct child router
  - [x] Direct child end device
  - [ ] Nested device
- [x] Indirect transmission mechanism
  - _Crude implementation_
  - [ ] Deal with devices lying on `rxOnWhenIdle` property (bad firmware, resulting in transmission type mismatch)
- [ ] Routing
  - [ ] Source routing
  - [?] Regular routing
- [ ] Coordinator binding
- [ ] InterPAN / Touchlink
- [ ] LQI reporting in messages
- [ ] Install codes
- [?] APS APP link keys
- [ ] R23 (need reference sniffs...)
- [ ] Security
- [ ] Metrics/Statistics
- [ ] Big cleanup of unused / never will use!
- [ ] Loads of testing!
- [ ] Optimize firmware building for this usage

And likely more, and of course a bunch of `TODO`s in the code!

### Testing

Use the appropriate OpenThread RCP firmware:
- Silabs adapters: https://github.com/Nerivec/silabs-firmware-builder/releases
- TI adapters: https://github.com/Koenkk/OpenThread-TexasInstruments-firmware/releases

#### CLI

Install dev dependencies and build:

```bash
npm install
npm run build
```

Configure parameters in `dist/dev/conf.json` then start CLI (next start will use `zoh.save` file, if not removed):

```bash
npm run dev:cli
```

_Currently, the CLI is output-only._

> [!TIP]
> Running `npm run build:prod` omits the `src/dev` directory.

> [!TIP]
> If having issues with building, try removing the `*.tsbuildinfo` incremental compilation files.

> [!TIP]
> For testing purposes, you can create a network with a regular NCP, then take it over with the RCP by copying all network settings. This allows to bypass the join steps as needed.

#### Zigbee2MQTT

Stay tuned...
