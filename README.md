# ZigBee on Host

[![Version](https://img.shields.io/npm/v/zigbee-on-host.svg)](https://npmjs.org/package/zigbee-on-host)
[![CI](https://github.com/Nerivec/zigbee-on-host/actions/workflows/ci.yaml/badge.svg)](https://github.com/Nerivec/zigbee-on-host/actions/workflows/ci.yaml)
[![CodeQL](https://github.com/Nerivec/zigbee-on-host/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Nerivec/zigbee-on-host/actions/workflows/github-code-scanning/codeql)

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
  - [ ] Lacking reference sniffs for multicast (group)
    - [Submit some](https://github.com/Nerivec/zigbee-on-host/discussions/14)
- [x] Encoding/decoding of ZigBee NWK GP frames
- [x] Encoding/decoding of ZigBee NWK APS frames
- [x] Network forming
- [x] Network state saving (de facto backups)
- [x] Network state reset
- [x] Joining/Rejoining
  - [x] APS TC link key update mechanism (global)
  - [x] Direct child router
  - [x] Direct child end device
  - [x] Nested device
- [x] Indirect transmission mechanism
- [x] Source routing
- [ ] Coordinator LQI/Routing tables (for network map data on coordinator side)
- [ ] LQI reporting in messages (currently showing RSSI - in dBm)
- [ ] Install codes
- [?] APS APP link keys
- [ ] InterPAN / Touchlink
- [ ] R23 (need reference sniffs...)
- [ ] Security
- [ ] Metrics/Statistics
- [ ] Big cleanup of unused / never will use!
- [ ] Loads of testing!
- [ ] Firmware stability testing
- [ ] Optimize firmware building for this usage

And likely more, and of course a bunch of `TODO`s in the code!

## Testing

Use the appropriate OpenThread RCP firmware:
- Silicon Labs adapters: https://github.com/Nerivec/silabs-firmware-builder/releases
- Texas Instruments adapters: https://github.com/Koenkk/OpenThread-TexasInstruments-firmware/releases
- Nordic Semiconductor adapters: https://github.com/Nerivec/zigbee-on-host/discussions/18

### Zigbee2MQTT

Zigbee2MQTT 2.1.3-dev (after [PR #26742](https://github.com/Koenkk/zigbee2mqtt/pull/26742)) and later versions should allow the use of the `zoh` adapter.
Make sure you followed the above steps to get the proper firmware, then configure your `configuration.yaml`, including:

> [!TIP]
> It is currently recommended you use Zigbee2MQTT `latest-dev` (`edge`) to get the latest fixes when testing this implementation!

```yaml
serial:
  port: /dev/serial/by-id/my-device-id-here
  adapter: zoh
  # unused for TCP-based coordinator
  baudrate: 460800
  # as appropriate for your coordinator/firmware, unused for TCP-based coordinator
  rtscts: true
```

> [!TIP]
> ZigBee on Host saves the current state of the network in the file `zoh.save`. _It is similar to the NVRAM of an NCP coordinator._
> This file contains everything needed to re-establish the network on start, hence, a `coordinator_backup.json` is never created by Zigbee2MQTT. It is located alongside the `database.db` in the `data` folder.

> [!TIP]
> The EUI64 (IEEE address) in the firmware of the coordinator is ignored in this mode. A static one is used instead (set by Zigbee2MQTT), allowing you to change coordinators at will on the same network (although you may encounter device-related troubles when radio specs vary wildly).

### CLI & Utils

Clone the repository.

```bash
git clone https://github.com/Nerivec/zigbee-on-host
cd zigbee-on-host
```

Install dev dependencies and build:

```bash
npm ci
npm run build
```

> [!IMPORTANT]
> Running `npm run build:prod` omits the `src/dev` directory (for production). If you do, you will not be able to use `dev:*` commands.

> [!TIP]
> If having issues with building, try removing the `*.tsbuildinfo` incremental compilation files (or run `npm run clean` first).

#### Minimal adapter

> This is intended for developers to quickly test specific features, like joining. Currently, the CLI is output-only.

Configure parameters in `dist/dev/conf.json` then start CLI (next start will use `zoh.save` file, if not removed):

```bash
npm run dev:cli
```

#### Utils

##### Create a 'zoh.save' from the content of a Zigbee2MQTT data folder

```bash
npm run dev:z2z ./path/to/data/
```

> [!TIP]
> This allows you to quickly take over a network created with `zstack` or `ember`. You then just need to change the `configuration.yaml` to `adapter: zoh` and `baudrate: 460800` (and `port` as appropriate).

##### Print and save the content of the 'zoh.save' in the given directory in human-readable format (as JSON, in same directory)

```bash
npm run dev:z2r ./path/to/data/
```

##### Using 'Docker.dev' and 'compose.dev.yaml'

###### Pre-requisites

```bash
git clone https://github.com/Nerivec/zigbee-on-host
cd zigbee-on-host
docker compose -f docker/compose.dev.yaml up -d --pull never
docker compose -f docker/compose.dev.yaml exec zigbee-on-host npm ci
docker compose -f docker/compose.dev.yaml exec zigbee-on-host npm run build
```

###### Running util commands

Create 'zoh.save' (details above):

```bash
docker compose -f docker/compose.dev.yaml exec zigbee-on-host npm run dev:z2z ./path/to/data
```

Print readable 'zoh.save' content (details above):

```bash
docker compose -f docker/compose.dev.yaml exec zigbee-on-host npm run dev:z2r ./path/to/data
```

###### Stopping & removing the container

```bash
docker compose -f docker/compose.dev.yaml down
```
