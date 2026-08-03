export declare const enum SpinelPropertyId {
    /** Format: `i` - Read-only
     *
     * Describes the status of the last operation. Encoded as a packed
     * unsigned integer (see `SPINEL_STATUS_*` for list of values).
     *
     * This property is emitted often to indicate the result status of
     * pretty much any Host-to-NCP operation.
     *
     * It is emitted automatically at NCP startup with a value indicating
     * the reset reason. It is also emitted asynchronously on an error (
     * e.g., NCP running out of buffer).
     */
    LAST_STATUS = 0,
    /** Format: `ii` - Read-only
     *
     * Describes the protocol version information. This property contains
     * two fields, each encoded as a packed unsigned integer:
     *   `i`: Major Version Number
     *   `i`: Minor Version Number
     *
     * The version number is defined by `SPINEL_PROTOCOL_VERSION_THREAD_MAJOR`
     * and `SPINEL_PROTOCOL_VERSION_THREAD_MINOR`.
     *
     * This specification describes major version 4, minor version 3.
     */
    PROTOCOL_VERSION = 1,
    /** Format: `U` - Read-only
     *
     * Contains a string which describes the firmware currently running on
     * the NCP. Encoded as a zero-terminated UTF-8 string.
     */
    NCP_VERSION = 2,
    /** Format: 'i' - Read-only
     *
     * This value identifies what the network protocol for this NCP.
     * The valid protocol type values are defined by enumeration
     * `SPINEL_PROTOCOL_TYPE_*`:
     *
     *   `SPINEL_PROTOCOL_TYPE_BOOTLOADER` = 0
     *   `SPINEL_PROTOCOL_TYPE_ZIGBEE_IP`  = 2,
     *   `SPINEL_PROTOCOL_TYPE_THREAD`     = 3,
     *
     * OpenThread NCP supports only `SPINEL_PROTOCOL_TYPE_THREAD`
     */
    INTERFACE_TYPE = 3,
    /** Format: 'i` - Read-only
     *
     * Vendor ID. Zero for unknown.
     */
    VENDOR_ID = 4,
    /** Format: 'A(i)` - Read-only
     *
     * Describes the supported capabilities of this NCP. Encoded as a list of
     * packed unsigned integers.
     *
     * The capability values are specified by SPINEL_CAP_* enumeration.
     */
    CAPS = 5,
    /** Format: 'C` - Read-only
     *
     * Provides number of interfaces.
     */
    INTERFACE_COUNT = 6,
    POWER_STATE = 7,///< PowerState [C] (deprecated, use `MCU_POWER_STATE` instead).
    /** Format: 'E` - Read-only
     *
     * The static EUI64 address of the device, used as a serial number.
     */
    HWADDR = 8,
    LOCK = 9,///< PropLock [b] (not supported)
    HBO_MEM_MAX = 10,///< Max offload mem [S] (not supported)
    HBO_BLOCK_MAX = 11,///< Max offload block [S] (not supported)
    /** Format: 'C`
     *
     * Describes the current power state of the host. This property is used
     * by the host to inform the NCP when it has changed power states. The
     * NCP can then use this state to determine which properties need
     * asynchronous updates. Enumeration `spinel_host_power_state_t` defines
     * the valid values (`SPINEL_HOST_POWER_STATE_*`):
     *
     *   `HOST_POWER_STATE_OFFLINE`: Host is physically powered off and
     *   cannot be woken by the NCP. All asynchronous commands are
     *   squelched.
     *
     *   `HOST_POWER_STATE_DEEP_SLEEP`: The host is in a low power state
     *   where it can be woken by the NCP but will potentially require more
     *   than two seconds to become fully responsive. The NCP MUST
     *   avoid sending unnecessary property updates, such as child table
     *   updates or non-critical messages on the debug stream. If the NCP
     *   needs to wake the host for traffic, the NCP MUST first take
     *   action to wake the host. Once the NCP signals to the host that it
     *   should wake up, the NCP MUST wait for some activity from the
     *   host (indicating that it is fully awake) before sending frames.
     *
     *   `HOST_POWER_STATE_RESERVED`:  This value MUST NOT be set by the host. If
     *   received by the NCP, the NCP SHOULD consider this as a synonym
     *   of `HOST_POWER_STATE_DEEP_SLEEP`.
     *
     *   `HOST_POWER_STATE_LOW_POWER`: The host is in a low power state
     *   where it can be immediately woken by the NCP. The NCP SHOULD
     *   avoid sending unnecessary property updates, such as child table
     *   updates or non-critical messages on the debug stream.
     *
     *   `HOST_POWER_STATE_ONLINE`: The host is awake and responsive. No
     *   special filtering is performed by the NCP on asynchronous updates.
     *
     *   All other values are RESERVED. They MUST NOT be set by the
     *   host. If received by the NCP, the NCP SHOULD consider the value as
     *   a synonym of `HOST_POWER_STATE_LOW_POWER`.
     *
     * After setting this power state, any further commands from the host to
     * the NCP will cause `HOST_POWER_STATE` to automatically revert to
     * `HOST_POWER_STATE_ONLINE`.
     *
     * When the host is entering a low-power state, it should wait for the
     * response from the NCP acknowledging the command (with `CMD_VALUE_IS`).
     * Once that acknowledgment is received the host may enter the low-power
     * state.
     *
     * If the NCP has the `CAP_UNSOL_UPDATE_FILTER` capability, any unsolicited
     * property updates masked by `PROP_UNSOL_UPDATE_FILTER` should be honored
     * while the host indicates it is in a low-power state. After resuming to the
     * `HOST_POWER_STATE_ONLINE` state, the value of `PROP_UNSOL_UPDATE_FILTER`
     * MUST be unchanged from the value assigned prior to the host indicating
     * it was entering a low-power state.
     */
    HOST_POWER_STATE = 12,
    /** Format: 'C`
     *  Required capability: CAP_MCU_POWER_SAVE
     *
     * This property specifies the desired power state of NCP's micro-controller
     * (MCU) when the underlying platform's operating system enters idle mode (i.e.,
     * all active tasks/events are processed and the MCU can potentially enter a
     * energy-saving power state).
     *
     * The power state primarily determines how the host should interact with the NCP
     * and whether the host needs an external trigger (a "poke") to NCP before it can
     * communicate with the NCP or not. After a reset, the MCU power state MUST be
     * SPINEL_MCU_POWER_STATE_ON.
     *
     * Enumeration `spinel_mcu_power_state_t` defines the valid values
     * (`SPINEL_MCU_POWER_STATE_*` constants):
     *
     *   `SPINEL_MCU_POWER_STATE_ON`: NCP's MCU stays on and active all the time.
     *   When the NCP's desired power state is set to this value, host can send
     *   messages to NCP without requiring any "poke" or external triggers. MCU is
     *   expected to stay on and active. Note that the `ON` power state only
     *   determines the MCU's power mode and is not related to radio's state.
     *
     *   `SPINEL_MCU_POWER_STATE_LOW_POWER`: NCP's MCU can enter low-power
     *   (energy-saving) state. When the NCP's desired power state is set to
     *   `LOW_POWER`, host is expected to "poke" the NCP (e.g., an external trigger
     *   like an interrupt) before it can communicate with the NCP (send a message
     *   to the NCP). The "poke" mechanism is determined by the platform code (based
     *   on NCP's interface to the host).
     *   While power state is set to `LOW_POWER`, NCP can still (at any time) send
     *   messages to host. Note that receiving a message from the NCP does NOT
     *   indicate that the NCP's power state has changed, i.e., host is expected to
     *   continue to "poke" NCP when it wants to talk to the NCP until the power
     *   state is explicitly changed (by setting this property to `ON`).
     *   Note that the `LOW_POWER` power state only determines the MCU's power mode
     *   and is not related to radio's state.
     *
     *   `SPINEL_MCU_POWER_STATE_OFF`: NCP is fully powered off.
     *   An NCP hardware reset (via a RESET pin) is required to bring the NCP back
     *   to `SPINEL_MCU_POWER_STATE_ON`. RAM is not retained after reset.
     */
    MCU_POWER_STATE = 13,
    /** Format: `A(CCU)`
     *  Type: Read-Only (Optionally Read-write using `CMD_PROP_VALUE_INSERT`)
     *
     * An array of structures which contain the following fields:
     *
     * *   `C`: GPIO Number
     * *   `C`: GPIO Configuration Flags
     * *   `U`: Human-readable GPIO name
     *
     * GPIOs which do not have a corresponding entry are not supported.
     *
     * The configuration parameter contains the configuration flags for the
     * GPIO:
     *
     *       0   1   2   3   4   5   6   7
     *     +---+---+---+---+---+---+---+---+
     *     |DIR|PUP|PDN|TRIGGER|  RESERVED |
     *     +---+---+---+---+---+---+---+---+
     *             |O/D|
     *             +---+
     *
     * *   `DIR`: Pin direction. Clear (0) for input, set (1) for output.
     * *   `PUP`: Pull-up enabled flag.
     * *   `PDN`/`O/D`: Flag meaning depends on pin direction:
     *     *   Input: Pull-down enabled.
     *     *   Output: Output is an open-drain.
     * *   `TRIGGER`: Enumeration describing how pin changes generate
     *     asynchronous notification commands (TBD) from the NCP to the host.
     *     *   0: Feature disabled for this pin
     *     *   1: Trigger on falling edge
     *     *   2: Trigger on rising edge
     *     *   3: Trigger on level change
     * *   `RESERVED`: Bits reserved for future use. Always cleared to zero
     *     and ignored when read.
     *
     * As an optional feature, the configuration of individual pins may be
     * modified using the `CMD_PROP_VALUE_INSERT` command. Only the GPIO
     * number and flags fields MUST be present, the GPIO name (if present)
     * would be ignored. This command can only be used to modify the
     * configuration of GPIOs which are already exposed---it cannot be used
     * by the host to add additional GPIOs.
     */
    GPIO_CONFIG = 4096,
    /** Format: `D`
     *  Type: Read-Write
     *
     * Contains a bit field identifying the state of the GPIOs. The length of
     * the data associated with these properties depends on the number of
     * GPIOs. If you have 10 GPIOs, you'd have two bytes. GPIOs are numbered
     * from most significant bit to least significant bit, so 0x80 is GPIO 0,
     * 0x40 is GPIO 1, etc.
     *
     * For GPIOs configured as inputs:
     *
     * *   `CMD_PROP_VALUE_GET`: The value of the associated bit describes the
     *     logic level read from the pin.
     * *   `CMD_PROP_VALUE_SET`: The value of the associated bit is ignored
     *     for these pins.
     *
     * For GPIOs configured as outputs:
     *
     * *   `CMD_PROP_VALUE_GET`: The value of the associated bit is
     *     implementation specific.
     * *   `CMD_PROP_VALUE_SET`: The value of the associated bit determines
     *     the new logic level of the output. If this pin is configured as an
     *     open-drain, setting the associated bit to 1 will cause the pin to
     *     enter a Hi-Z state.
     *
     * For GPIOs which are not specified in `PROP_GPIO_CONFIG`:
     *
     * *   `CMD_PROP_VALUE_GET`: The value of the associated bit is
     *     implementation specific.
     * *   `CMD_PROP_VALUE_SET`: The value of the associated bit MUST be
     *     ignored by the NCP.
     *
     * When writing, unspecified bits are assumed to be zero.
     */
    GPIO_STATE = 4098,
    /** Format: `D`
     *  Type: Write-Only
     *
     * Allows for the state of various output GPIOs to be set without affecting
     * other GPIO states. Contains a bit field identifying the output GPIOs that
     * should have their state set to 1.
     *
     * When writing, unspecified bits are assumed to be zero. The value of
     * any bits for GPIOs which are not specified in `PROP_GPIO_CONFIG` MUST
     * be ignored.
     */
    GPIO_STATE_SET = 4099,
    /** Format: `D`
     *  Type: Write-Only
     *
     * Allows for the state of various output GPIOs to be cleared without affecting
     * other GPIO states. Contains a bit field identifying the output GPIOs that
     * should have their state cleared to 0.
     *
     * When writing, unspecified bits are assumed to be zero. The value of
     * any bits for GPIOs which are not specified in `PROP_GPIO_CONFIG` MUST
     * be ignored.
     */
    GPIO_STATE_CLEAR = 4100,
    TRNG_32 = 4101,
    TRNG_128 = 4102,
    TRNG_RAW_32 = 4103,
    /** Format: `A(I)`
     *  Type: Read-Write (optional Insert-Remove)
     *  Required capability: `CAP_UNSOL_UPDATE_FILTER`
     *
     * Contains a list of properties which are excluded from generating
     * unsolicited value updates. This property is empty after reset.
     * In other words, the host may opt-out of unsolicited property updates
     * for a specific property by adding that property id to this list.
     * Hosts SHOULD NOT add properties to this list which are not
     * present in `PROP_UNSOL_UPDATE_LIST`. If such properties are added,
     * the NCP ignores the unsupported properties.
     */
    UNSOL_UPDATE_FILTER = 4104,
    /** Format: `A(I)`
     *  Type: Read-Only
     *  Required capability: `CAP_UNSOL_UPDATE_FILTER`
     *
     * Contains a list of properties which are capable of generating
     * unsolicited value updates. This list can be used when populating
     * `PROP_UNSOL_UPDATE_FILTER` to disable all unsolicited property
     * updates.
     *
     * This property is intended to effectively behave as a constant
     * for a given NCP firmware.
     */
    UNSOL_UPDATE_LIST = 4105,
    /** Format: `b` */
    PHY_ENABLED = 32,
    /** Format: `C` */
    PHY_CHAN = 33,
    /** Format: `A(C)` */
    PHY_CHAN_SUPPORTED = 34,
    /** kHz Format: `L` */
    PHY_FREQ = 35,
    /** dBm Format: `c` */
    PHY_CCA_THRESHOLD = 36,
    /** Format: `c` */
    PHY_TX_POWER = 37,
    /** dBm Format: `c` */
    PHY_RSSI = 38,
    /** dBm Format: `c` */
    PHY_RX_SENSITIVITY = 39,
    /** Format: `b` */
    PHY_PCAP_ENABLED = 40,
    /** Format: `A(C)` */
    PHY_CHAN_PREFERRED = 41,
    /** dBm Format: `c` */
    PHY_FEM_LNA_GAIN = 42,
    /** Format: `Cc`
     *
     * First byte is the channel then the max transmit power, write-only.
     */
    PHY_CHAN_MAX_POWER = 43,
    /** Format: `S`
     *
     * The ascii representation of the ISO 3166 alpha-2 code.
     */
    PHY_REGION_CODE = 44,
    /** Format: `A(Csd)` - Insert/Set
     *
     *  The `Insert` command on the property inserts a calibration power entry to the calibrated power table.
     *  The `Set` command on the property with empty payload clears the calibrated power table.
     *
     * Structure Parameters:
     *  `C`: Channel.
     *  `s`: Actual power in 0.01 dBm.
     *  `d`: Raw power setting.
     */
    PHY_CALIBRATED_POWER = 45,
    /** Format: `t(Cs)` - Write only
     *
     * Structure Parameters:
     *  `C`: Channel.
     *  `s`: Target power in 0.01 dBm.
     */
    PHY_CHAN_TARGET_POWER = 46,
    /** Format: `b`
     *
     * Indicates if jamming detection is enabled or disabled. Set to true
     * to enable jamming detection.
     */
    JAM_DETECT_ENABLE = 4608,
    /** Format: `b` (Read-Only)
     *
     * Set to true if radio jamming is detected. Set to false otherwise.
     *
     * When jamming detection is enabled, changes to the value of this
     * property are emitted asynchronously via `CMD_PROP_VALUE_IS`.
     */
    JAM_DETECTED = 4609,
    /** Format: `c`
     *  Units: dBm
     *
     * This parameter describes the threshold RSSI level (measured in
     * dBm) above which the jamming detection will consider the
     * channel blocked.
     */
    JAM_DETECT_RSSI_THRESHOLD = 4610,
    /** Format: `C`
     *  Units: Seconds (1-63)
     *
     * This parameter describes the window period for signal jamming
     * detection.
     */
    JAM_DETECT_WINDOW = 4611,
    /** Format: `C`
     *  Units: Seconds (1-63)
     *
     * This parameter describes the number of aggregate seconds within
     * the detection window where the RSSI must be above
     * `PROP_JAM_DETECT_RSSI_THRESHOLD` to trigger detection.
     *
     * The behavior of the jamming detection feature when `PROP_JAM_DETECT_BUSY`
     * is larger than `PROP_JAM_DETECT_WINDOW` is undefined.
     */
    JAM_DETECT_BUSY = 4612,
    /** Format: `X` (read-only)
     *
     * This value provides information about current state of jamming detection
     * module for monitoring/debugging purpose. It returns a 64-bit value where
     * each bit corresponds to one second interval starting with bit 0 for the
     * most recent interval and bit 63 for the oldest intervals (63 sec earlier).
     * The bit is set to 1 if the jamming detection module observed/detected
     * high signal level during the corresponding one second interval.
     */
    JAM_DETECT_HISTORY_BITMAP = 4613,
    /** Format: `L` (read-only)
     *  Units: Milliseconds
     *
     * Required capability: SPINEL_CAP_CHANNEL_MONITOR
     *
     * If channel monitoring is enabled and active, every sample interval, a
     * zero-duration Energy Scan is performed, collecting a single RSSI sample
     * per channel. The RSSI samples are compared with a pre-specified RSSI
     * threshold.
     */
    CHANNEL_MONITOR_SAMPLE_INTERVAL = 4614,
    /** Format: `c` (read-only)
     *  Units: dBm
     *
     * Required capability: SPINEL_CAP_CHANNEL_MONITOR
     *
     * This value specifies the threshold used by channel monitoring module.
     * Channel monitoring maintains the average rate of RSSI samples that
     * are above the threshold within (approximately) a pre-specified number
     * of samples (sample window).
     */
    CHANNEL_MONITOR_RSSI_THRESHOLD = 4615,
    /** Format: `L` (read-only)
     *  Units: Number of samples
     *
     * Required capability: SPINEL_CAP_CHANNEL_MONITOR
     *
     * The averaging sample window length (in units of number of channel
     * samples) used by channel monitoring module. Channel monitoring will
     * sample all channels every sample interval. It maintains the average rate
     * of RSSI samples that are above the RSSI threshold within (approximately)
     * the sample window.
     */
    CHANNEL_MONITOR_SAMPLE_WINDOW = 4616,
    /** Format: `L` (read-only)
     *  Units: Number of samples
     *
     * Required capability: SPINEL_CAP_CHANNEL_MONITOR
     *
     * Total number of RSSI samples (per channel) taken by the channel
     * monitoring module since its start (since Thread network interface
     * was enabled).
     */
    CHANNEL_MONITOR_SAMPLE_COUNT = 4617,
    /** Format: `A(t(CU))` (read-only)
     *
     * Required capability: SPINEL_CAP_CHANNEL_MONITOR
     *
     * Data per item is:
     *
     *  `C`: Channel
     *  `U`: Channel occupancy indicator
     *
     * The channel occupancy value represents the average rate/percentage of
     * RSSI samples that were above RSSI threshold ("bad" RSSI samples) within
     * (approximately) sample window latest RSSI samples.
     *
     * Max value of `0xffff` indicates all RSSI samples were above RSSI
     * threshold (i.e. 100% of samples were "bad").
     */
    CHANNEL_MONITOR_CHANNEL_OCCUPANCY = 4618,
    /** Format: `i` (read-only)
     *
     * Data per item is:
     *
     *  `i`: Radio Capabilities.
     */
    RADIO_CAPS = 4619,
    /** Format: t(LLLLLLLL)t(LLLLLLLLL)bL  (Read-only)
     *
     * Required capability: SPINEL_CAP_RADIO_COEX
     *
     * The contents include two structures and two common variables, first structure corresponds to
     * all transmit related coex counters, second structure provides the receive related counters.
     *
     * The transmit structure includes:
     *   'L': NumTxRequest                       (The number of tx requests).
     *   'L': NumTxGrantImmediate                (The number of tx requests while grant was active).
     *   'L': NumTxGrantWait                     (The number of tx requests while grant was inactive).
     *   'L': NumTxGrantWaitActivated            (The number of tx requests while grant was inactive that were
     *                                            ultimately granted).
     *   'L': NumTxGrantWaitTimeout              (The number of tx requests while grant was inactive that timed out).
     *   'L': NumTxGrantDeactivatedDuringRequest (The number of tx requests that were in progress when grant was
     *                                            deactivated).
     *   'L': NumTxDelayedGrant                  (The number of tx requests that were not granted within 50us).
     *   'L': AvgTxRequestToGrantTime            (The average time in usec from tx request to grant).
     *
     * The receive structure includes:
     *   'L': NumRxRequest                       (The number of rx requests).
     *   'L': NumRxGrantImmediate                (The number of rx requests while grant was active).
     *   'L': NumRxGrantWait                     (The number of rx requests while grant was inactive).
     *   'L': NumRxGrantWaitActivated            (The number of rx requests while grant was inactive that were
     *                                            ultimately granted).
     *   'L': NumRxGrantWaitTimeout              (The number of rx requests while grant was inactive that timed out).
     *   'L': NumRxGrantDeactivatedDuringRequest (The number of rx requests that were in progress when grant was
     *                                            deactivated).
     *   'L': NumRxDelayedGrant                  (The number of rx requests that were not granted within 50us).
     *   'L': AvgRxRequestToGrantTime            (The average time in usec from rx request to grant).
     *   'L': NumRxGrantNone                     (The number of rx requests that completed without receiving grant).
     *
     * Two common variables:
     *   'b': Stopped        (Stats collection stopped due to saturation).
     *   'L': NumGrantGlitch (The number of of grant glitches).
     */
    RADIO_COEX_METRICS = 4620,
    /** Format: `b`
     *
     * Required capability: SPINEL_CAP_RADIO_COEX
     *
     * Indicates if radio coex is enabled or disabled. Set to true to enable radio coex.
     */
    RADIO_COEX_ENABLE = 4621,
    /** Format: `C`
     *
     * Possible values are from enumeration `spinel_scan_state_t`.
     *
     *   SCAN_STATE_IDLE
     *   SCAN_STATE_BEACON
     *   SCAN_STATE_ENERGY
     *   SCAN_STATE_DISCOVER
     *
     * Set to `SCAN_STATE_BEACON` to start an active scan.
     * Beacons will be emitted from `PROP_MAC_SCAN_BEACON`.
     *
     * Set to `SCAN_STATE_ENERGY` to start an energy scan.
     * Channel energy result will be reported by emissions
     * of `PROP_MAC_ENERGY_SCAN_RESULT` (per channel).
     *
     * Set to `SCAN_STATE_DISCOVER` to start a Thread MLE discovery
     * scan operation. Discovery scan result will be emitted from
     * `PROP_MAC_SCAN_BEACON`.
     *
     * Value switches to `SCAN_STATE_IDLE` when scan is complete.
     */
    MAC_SCAN_STATE = 48,
    /** Format: `A(C)`
     *
     * List of channels to scan.
     */
    MAC_SCAN_MASK = 49,
    /** Format: `S`
     *  Unit: milliseconds per channel
     */
    MAC_SCAN_PERIOD = 50,
    /** Format `Cct(ESSc)t(iCUdd)` - Asynchronous event only
     *
     * Scan beacons have two embedded structures which contain
     * information about the MAC layer and the NET layer. Their
     * format depends on the MAC and NET layer currently in use.
     * The format below is for an 802.15.4 MAC with Thread:
     *
     *  `C`: Channel
     *  `c`: RSSI of the beacon
     *  `t`: MAC layer properties (802.15.4 layer)
     *    `E`: Long address
     *    `S`: Short address
     *    `S`: PAN-ID
     *    `c`: LQI
     *  NET layer properties
     *    `i`: Protocol Number (SPINEL_PROTOCOL_TYPE_* values)
     *    `C`: Flags (SPINEL_BEACON_THREAD_FLAG_* values)
     *    `U`: Network Name
     *    `d`: XPANID
     *    `d`: Steering data
     *
     * Extra parameters may be added to each of the structures
     * in the future, so care should be taken to read the length
     * that prepends each structure.
     */
    MAC_SCAN_BEACON = 51,
    /** Format: `E`
     *
     * The 802.15.4 long address of this node.
     */
    MAC_15_4_LADDR = 52,
    /** Format: `S`
     *
     * The 802.15.4 short address of this node.
     */
    MAC_15_4_SADDR = 53,
    /** Format: `S`
     *
     * The 802.15.4 PANID this node is associated with.
     */
    MAC_15_4_PANID = 54,
    /** Format: `b`
     *
     * Set to true to enable raw MAC frames to be emitted from
     * `PROP_STREAM_RAW`.
     */
    MAC_RAW_STREAM_ENABLED = 55,
    /** Format: `C`
     *
     * Possible values are from enumeration
     * `SPINEL_MAC_PROMISCUOUS_MODE_*`:
     *
     *   `SPINEL_MAC_PROMISCUOUS_MODE_OFF`
     *        Normal MAC filtering is in place.
     *
     *   `SPINEL_MAC_PROMISCUOUS_MODE_NETWORK`
     *        All MAC packets matching network are passed up
     *        the stack.
     *
     *   `SPINEL_MAC_PROMISCUOUS_MODE_FULL`
     *        All decoded MAC packets are passed up the stack.
     */
    MAC_PROMISCUOUS_MODE = 56,
    /** Format: `Cc` - Asynchronous event only
     *
     * This property is emitted during energy scan operation
     * per scanned channel with following format:
     *
     *   `C`: Channel
     *   `c`: RSSI (in dBm)
     */
    MAC_ENERGY_SCAN_RESULT = 57,
    /** Format: `L`
     *  Unit: millisecond
     * The (user-specified) data poll (802.15.4 MAC Data Request) period
     * in milliseconds. Value zero means there is no user-specified
     * poll period, and the network stack determines the maximum period
     * based on the MLE Child Timeout.
     *
     * If the value is non-zero, it specifies the maximum period between
     * data poll transmissions. Note that the network stack may send data
     * request transmissions more frequently when expecting a control-message
     * (e.g., when waiting for an MLE Child ID Response).
     */
    MAC_DATA_POLL_PERIOD = 58,
    /** Format: `b`
     *
     * Set to true to enable RxOnWhenIdle or false to disable it.
     * When True, the radio is expected to stay in receive state during
     * idle periods. When False, the radio is expected to switch to sleep
     * state during idle periods.
     */
    MAC_RX_ON_WHEN_IDLE_MODE = 59,
    /** Format: `S`
     *
     * The 802.15.4 alternate short address.
     */
    MAC_15_4_ALT_SADDR = 60,
    /** Format: `XLC`
     *
     * Schedule a radio reception window at a specific time and duration.
     *
     *   `X`: The receive window start time.
     *   `L`: The receive window duration.
     *   `C`: The receive channel.
     */
    MAC_RX_AT = 61,
    /** Format: `A(t(Ec))`
     * Required capability: `CAP_MAC_ALLOWLIST`
     *
     * Structure Parameters:
     *
     *  `E`: EUI64 address of node
     *  `c`: Optional RSSI-override value. The value 127 indicates
     *       that the RSSI-override feature is not enabled for this
     *       address. If this value is omitted when setting or
     *       inserting, it is assumed to be 127. This parameter is
     *       ignored when removing.
     */
    MAC_ALLOWLIST = 4864,
    /** Format: `b`
     * Required capability: `CAP_MAC_ALLOWLIST`
     */
    MAC_ALLOWLIST_ENABLED = 4865,
    /** Format: `E`
     *
     *  Specified by Thread. Randomly-chosen, but non-volatile EUI-64.
     */
    MAC_EXTENDED_ADDR = 4866,
    /** Format: `b`
     * Required Capability: SPINEL_CAP_MAC_RAW or SPINEL_CAP_CONFIG_RADIO
     *
     * Set to true to enable radio source matching or false to disable it.
     * The source match functionality is used by radios when generating
     * ACKs. The short and extended address lists are used for setting
     * the Frame Pending bit in the ACKs.
     */
    MAC_SRC_MATCH_ENABLED = 4867,
    /** Format: `A(S)`
     * Required Capability: SPINEL_CAP_MAC_RAW or SPINEL_CAP_CONFIG_RADIO
     */
    MAC_SRC_MATCH_SHORT_ADDRESSES = 4868,
    /** Format: `A(E)`
     *  Required Capability: SPINEL_CAP_MAC_RAW or SPINEL_CAP_CONFIG_RADIO
     */
    MAC_SRC_MATCH_EXTENDED_ADDRESSES = 4869,
    /** Format: `A(t(E))`
     * Required capability: `CAP_MAC_ALLOWLIST`
     *
     * Structure Parameters:
     *
     *  `E`: EUI64 address of node
     */
    MAC_DENYLIST = 4870,
    /** Format: `b`
     *  Required capability: `CAP_MAC_ALLOWLIST`
     */
    MAC_DENYLIST_ENABLED = 4871,
    /** Format: `A(t(Ec))`
     * Required capability: `CAP_MAC_ALLOWLIST`
     *
     * Structure Parameters:
     *
     * * `E`: Optional EUI64 address of node. Set default RSS if not included.
     * * `c`: Fixed RSS. 127 means not set.
     */
    MAC_FIXED_RSS = 4872,
    /** Format: `S`
     *
     * This property provides the current CCA (Clear Channel Assessment) failure rate.
     *
     * Maximum value `0xffff` corresponding to 100% failure rate.
     */
    MAC_CCA_FAILURE_RATE = 4873,
    /** Format: `C`
     *
     * The maximum (user-specified) number of direct frame transmission retries.
     */
    MAC_MAX_RETRY_NUMBER_DIRECT = 4874,
    /** Format: `C`
     * Required capability: `SPINEL_CAP_CONFIG_FTD`
     *
     * The maximum (user-specified) number of indirect frame transmission retries.
     */
    MAC_MAX_RETRY_NUMBER_INDIRECT = 4875,
    /** Format: `b` - Read only
     *
     * Returns true if there is a network state stored/saved.
     */
    NET_SAVED = 64,
    /** Format `b` - Read-write
     *
     * Network interface up/down status. Write true to bring
     * interface up and false to bring interface down.
     */
    NET_IF_UP = 65,
    /** Format `b` - Read-write
     *
     * Thread stack operational status. Write true to start
     * Thread stack and false to stop it.
     */
    NET_STACK_UP = 66,
    /** Format `C` - Read-write
     *
     * Possible values are from enumeration `spinel_net_role_t`
     *
     *  SPINEL_NET_ROLE_DETACHED = 0,
     *  SPINEL_NET_ROLE_CHILD    = 1,
     *  SPINEL_NET_ROLE_ROUTER   = 2,
     *  SPINEL_NET_ROLE_LEADER   = 3,
     *  SPINEL_NET_ROLE_DISABLED = 4,
     */
    NET_ROLE = 67,
    /** Format `U` - Read-write
     */
    NET_NETWORK_NAME = 68,
    /** Format `D` - Read-write
     */
    NET_XPANID = 69,
    /** Format `D` - Read-write
     */
    NET_NETWORK_KEY = 70,
    /** Format `L` - Read-write
     */
    NET_KEY_SEQUENCE_COUNTER = 71,
    /** Format `L` - Read-write
     *
     * The partition ID of the partition that this node is a
     * member of.
     */
    NET_PARTITION_ID = 72,
    /** Format: `b`
     *  Default Value: `false`
     *
     * This flag is typically used for nodes that are associating with an
     * existing network for the first time. If this is set to `true` before
     * `PROP_NET_STACK_UP` is set to `true`, the
     * creation of a new partition at association is prevented. If the node
     * cannot associate with an existing partition, `PROP_LAST_STATUS` will
     * emit a status that indicates why the association failed and
     * `PROP_NET_STACK_UP` will automatically revert to `false`.
     *
     * Once associated with an existing partition, this flag automatically
     * reverts to `false`.
     *
     * The behavior of this property being set to `true` when
     * `PROP_NET_STACK_UP` is already set to `true` is undefined.
     */
    NET_REQUIRE_JOIN_EXISTING = 73,
    /** Format `L` - Read-write
     */
    NET_KEY_SWITCH_GUARDTIME = 74,
    /** Format `D` - Read-write
     */
    NET_PSKC = 75,
    /** Format Empty - Write only
     */
    NET_LEAVE_GRACEFULLY = 76,
    /** Format `6` - Read only
     */
    THREAD_LEADER_ADDR = 80,
    /** Format: `ESLccCCCCC` - Read only
     *
     *  `E`: Extended address
     *  `S`: RLOC16
     *  `L`: Age (seconds since last heard from)
     *  `c`: Average RSS (in dBm)
     *  `c`: Last RSSI (in dBm)
     *  `C`: Link Quality In
     *  `C`: Link Quality Out
     *  `C`: Version
     *  `C`: CSL clock accuracy
     *  `C`: CSL uncertainty
     */
    THREAD_PARENT = 81,
    /** Format: [A(t(ESLLCCcCc)] - Read only
     *
     * Data per item is:
     *
     *  `E`: Extended address
     *  `S`: RLOC16
     *  `L`: Timeout (in seconds)
     *  `L`: Age (in seconds)
     *  `L`: Network Data version
     *  `C`: Link Quality In
     *  `c`: Average RSS (in dBm)
     *  `C`: Mode (bit-flags)
     *  `c`: Last RSSI (in dBm)
     */
    THREAD_CHILD_TABLE = 82,
    /** Format `C` - Read only
     *
     * The router-id of the current leader.
     */
    THREAD_LEADER_RID = 83,
    /** Format `C` - Read only
     *
     * The leader weight of the current leader.
     */
    THREAD_LEADER_WEIGHT = 84,
    /** Format `C` - Read only
     *
     * The leader weight of this node.
     */
    THREAD_LOCAL_LEADER_WEIGHT = 85,
    /** Format `D` - Read only
     */
    THREAD_NETWORK_DATA = 86,
    /** Format `C` - Read only
     */
    THREAD_NETWORK_DATA_VERSION = 87,
    /** Format `D` - Read only
     */
    THREAD_STABLE_NETWORK_DATA = 88,
    /** Format `C` - Read only
     */
    THREAD_STABLE_NETWORK_DATA_VERSION = 89,
    /** Format: `A(t(6CbCbSC))`
     *
     * Data per item is:
     *
     *  `6`: IPv6 Prefix
     *  `C`: Prefix length in bits
     *  `b`: Stable flag
     *  `C`: TLV flags (SPINEL_NET_FLAG_* definition)
     *  `b`: "Is defined locally" flag. Set if this network was locally
     *       defined. Assumed to be true for set, insert and replace. Clear if
     *       the on mesh network was defined by another node.
     *       This field is ignored for INSERT and REMOVE commands.
     *  `S`: The RLOC16 of the device that registered this on-mesh prefix entry.
     *       This value is not used and ignored when adding an on-mesh prefix.
     *       This field is ignored for INSERT and REMOVE commands.
     *  `C`: TLV flags extended (additional field for Thread 1.2 features).
     */
    THREAD_ON_MESH_NETS = 90,
    /** Format: [A(t(6CbCbb))]
     *
     * Data per item is:
     *
     *  `6`: Route Prefix
     *  `C`: Prefix length in bits
     *  `b`: Stable flag
     *  `C`: Route flags (SPINEL_ROUTE_FLAG_* and SPINEL_ROUTE_PREFERENCE_* definitions)
     *  `b`: "Is defined locally" flag. Set if this route info was locally
     *       defined as part of local network data. Assumed to be true for set,
     *       insert and replace. Clear if the route is part of partition's network
     *       data.
     *  `b`: "Next hop is this device" flag. Set if the next hop for the
     *       route is this device itself (i.e., route was added by this device)
     *       This value is ignored when adding an external route. For any added
     *       route the next hop is this device.
     *  `S`: The RLOC16 of the device that registered this route entry.
     *       This value is not used and ignored when adding a route.
     */
    THREAD_OFF_MESH_ROUTES = 91,
    /** Format `A(S)`
     *
     * Array of port numbers.
     */
    THREAD_ASSISTING_PORTS = 92,
    /** Format `b` - Read-write
     *
     * Set to true before changing local net data. Set to false when finished.
     * This allows changes to be aggregated into a single event.
     */
    THREAD_ALLOW_LOCAL_NET_DATA_CHANGE = 93,
    /** Format: `C`
     *
     *  This property contains the value of the mode
     *  TLV for this node. The meaning of the bits in this
     *  bit-field are defined by section 4.5.2 of the Thread
     *  specification.
     *
     * The values `SPINEL_THREAD_MODE_*` defines the bit-fields
     */
    THREAD_MODE = 94,
    /** Format: `L`
     *  Unit: Seconds
     *
     *  Used when operating in the Child role.
     */
    THREAD_CHILD_TIMEOUT = 5376,
    /** Format: `S`
     */
    THREAD_RLOC16 = 5377,
    /** Format: `C`
     */
    THREAD_ROUTER_UPGRADE_THRESHOLD = 5378,
    /** Format: `L`
     */
    THREAD_CONTEXT_REUSE_DELAY = 5379,
    /** Format: `C`
     */
    THREAD_NETWORK_ID_TIMEOUT = 5380,
    /** Format: `A(C)`
     *
     * Note that some implementations may not support CMD_GET_VALUE
     * router ids, but may support CMD_REMOVE_VALUE when the node is
     * a leader.
     */
    THREAD_ACTIVE_ROUTER_IDS = 5381,
    /** Format: `b`
     *
     * Allow host to directly observe all IPv6 packets received by the NCP,
     * including ones sent to the RLOC16 address.
     *
     * Default is false.
     */
    THREAD_RLOC16_DEBUG_PASSTHRU = 5382,
    /** Format `b`
     *
     * Allows host to indicate whether or not the router role is enabled.
     * If current role is a router, setting this property to `false` starts
     * a re-attach process as an end-device.
     */
    THREAD_ROUTER_ROLE_ENABLED = 5383,
    /** Format: `C`
     */
    THREAD_ROUTER_DOWNGRADE_THRESHOLD = 5384,
    /** Format: `C`
     */
    THREAD_ROUTER_SELECTION_JITTER = 5385,
    /** Format: `C` - Write only
     *
     * Specifies the preferred Router Id. Upon becoming a router/leader the node
     * attempts to use this Router Id. If the preferred Router Id is not set or
     * if it can not be used, a randomly generated router id is picked. This
     * property can be set only when the device role is either detached or
     * disabled.
     */
    THREAD_PREFERRED_ROUTER_ID = 5386,
    /** Format: `A(t(ESLCcCbLLc))` - Read only
     *
     * Data per item is:
     *
     *  `E`: Extended address
     *  `S`: RLOC16
     *  `L`: Age (in seconds)
     *  `C`: Link Quality In
     *  `c`: Average RSS (in dBm)
     *  `C`: Mode (bit-flags)
     *  `b`: `true` if neighbor is a child, `false` otherwise.
     *  `L`: Link Frame Counter
     *  `L`: MLE Frame Counter
     *  `c`: The last RSSI (in dBm)
     */
    THREAD_NEIGHBOR_TABLE = 5387,
    /** Format: `C`
     *
     * Specifies the maximum number of children currently allowed.
     * This parameter can only be set when Thread protocol operation
     * has been stopped.
     */
    THREAD_CHILD_COUNT_MAX = 5388,
    /** Format: `D` - Read only
     */
    THREAD_LEADER_NETWORK_DATA = 5389,
    /** Format: `D` - Read only
     */
    THREAD_STABLE_LEADER_NETWORK_DATA = 5390,
    /** Format `A(T(ULE))`
     *  PSKd, joiner timeout, eui64 (optional)
     *
     * This property is being deprecated by MESHCOP_COMMISSIONER_JOINERS.
     */
    THREAD_JOINERS = 5391,
    /** Format `b`
     *
     * Default value is `false`.
     *
     * This property is being deprecated by MESHCOP_COMMISSIONER_STATE.
     */
    THREAD_COMMISSIONER_ENABLED = 5392,
    /** Format `b`
     * Required capability: `SPINEL_CAP_THREAD_TMF_PROXY`
     *
     * This property is deprecated.
     */
    THREAD_TMF_PROXY_ENABLED = 5393,
    /** Format `dSS`
     * Required capability: `SPINEL_CAP_THREAD_TMF_PROXY`
     *
     * This property is deprecated. Please see `THREAD_UDP_FORWARD_STREAM`.
     */
    THREAD_TMF_PROXY_STREAM = 5394,
    /** Format `b`
     *
     * This property defines the Joiner Flag value in the Discovery Request TLV.
     *
     * Default value is `false`.
     */
    THREAD_DISCOVERY_SCAN_JOINER_FLAG = 5395,
    /** Format `b`
     *
     * Default value is `false`
     */
    THREAD_DISCOVERY_SCAN_ENABLE_FILTERING = 5396,
    /** Format: `S`
     *
     * Default value is 0xffff (Broadcast PAN) to disable PANID filtering
     */
    THREAD_DISCOVERY_SCAN_PANID = 5397,
    /** Format `E` - Write only
     *
     * Required capability: SPINEL_CAP_OOB_STEERING_DATA.
     *
     * Writing to this property allows to set/update the MLE
     * Discovery Response steering data out of band.
     *
     *  - All zeros to clear the steering data (indicating that
     *    there is no steering data).
     *  - All 0xFFs to set steering data/bloom filter to
     *    accept/allow all.
     *  - A specific EUI64 which is then added to current steering
     *    data/bloom filter.
     */
    THREAD_STEERING_DATA = 5398,
    /** Format: `A(t(ESCCCCCCb)` - Read only
     *
     * Data per item is:
     *
     *  `E`: IEEE 802.15.4 Extended Address
     *  `S`: RLOC16
     *  `C`: Router ID
     *  `C`: Next hop to router
     *  `C`: Path cost to router
     *  `C`: Link Quality In
     *  `C`: Link Quality Out
     *  `C`: Age (seconds since last heard)
     *  `b`: Link established with Router ID or not.
     */
    THREAD_ROUTER_TABLE = 5399,
    /** Format: `A(t(iD))` - Read-Write
     *
     * This property provides access to current Thread Active Operational Dataset. A Thread device maintains the
     * Operational Dataset that it has stored locally and the one currently in use by the partition to which it is
     * attached. This property corresponds to the locally stored Dataset on the device.
     *
     * Operational Dataset consists of a set of supported properties (e.g., channel, network key, network name, PAN id,
     * etc). Note that not all supported properties may be present (have a value) in a Dataset.
     *
     * The Dataset value is encoded as an array of structs containing pairs of property key (as `i`) followed by the
     * property value (as `D`). The property value must follow the format associated with the corresponding property.
     *
     * On write, any unknown/unsupported property keys must be ignored.
     *
     * The following properties can be included in a Dataset list:
     *
     *   DATASET_ACTIVE_TIMESTAMP
     *   PHY_CHAN
     *   PHY_CHAN_SUPPORTED (Channel Mask Page 0)
     *   NET_NETWORK_KEY
     *   NET_NETWORK_NAME
     *   NET_XPANID
     *   MAC_15_4_PANID
     *   IPV6_ML_PREFIX
     *   NET_PSKC
     *   DATASET_SECURITY_POLICY
     */
    THREAD_ACTIVE_DATASET = 5400,
    /** Format: `A(t(iD))` - Read-Write
     *
     * This property provide access to current locally stored Pending Operational Dataset.
     *
     * The formatting of this property follows the same rules as in THREAD_ACTIVE_DATASET.
     *
     * In addition supported properties in THREAD_ACTIVE_DATASET, the following properties can also
     * be included in the Pending Dataset:
     *
     *   DATASET_PENDING_TIMESTAMP
     *   DATASET_DELAY_TIMER
     */
    THREAD_PENDING_DATASET = 5401,
    /** Format: `A(t(iD))` - Write only
     *
     * The formatting of this property follows the same rules as in THREAD_ACTIVE_DATASET.
     *
     * This is write-only property. When written, it triggers a MGMT_ACTIVE_SET meshcop command to be sent to leader
     * with the given Dataset. The spinel frame response should be a `LAST_STATUS` with the status of the transmission
     * of MGMT_ACTIVE_SET command.
     *
     * In addition to supported properties in THREAD_ACTIVE_DATASET, the following property can be
     * included in the Dataset (to allow for custom raw TLVs):
     *
     *    DATASET_RAW_TLVS
     */
    THREAD_MGMT_SET_ACTIVE_DATASET = 5402,
    /** Format: `A(t(iD))` - Write only
     *
     * This property is similar to THREAD_PENDING_DATASET and follows the same format and rules.
     *
     * In addition to supported properties in THREAD_PENDING_DATASET, the following property can be
     * included the Dataset (to allow for custom raw TLVs to be provided).
     *
     *    DATASET_RAW_TLVS
     */
    THREAD_MGMT_SET_PENDING_DATASET = 5403,
    /** Format: `X` - No direct read or write
     *
     * It can only be included in one of the Dataset related properties below:
     *
     *   THREAD_ACTIVE_DATASET
     *   THREAD_PENDING_DATASET
     *   THREAD_MGMT_SET_ACTIVE_DATASET
     *   THREAD_MGMT_SET_PENDING_DATASET
     *   THREAD_MGMT_GET_ACTIVE_DATASET
     *   THREAD_MGMT_GET_PENDING_DATASET
     */
    DATASET_ACTIVE_TIMESTAMP = 5404,
    /** Format: `X` - No direct read or write
     *
     * It can only be included in one of the Pending Dataset properties:
     *
     *   THREAD_PENDING_DATASET
     *   THREAD_MGMT_SET_PENDING_DATASET
     *   THREAD_MGMT_GET_PENDING_DATASET
     */
    DATASET_PENDING_TIMESTAMP = 5405,
    /** Format: `L` - No direct read or write
     *
     * Delay timer (in ms) specifies the time renaming until Thread devices overwrite the value in the Active
     * Operational Dataset with the corresponding values in the Pending Operational Dataset.
     *
     * It can only be included in one of the Pending Dataset properties:
     *
     *   THREAD_PENDING_DATASET
     *   THREAD_MGMT_SET_PENDING_DATASET
     *   THREAD_MGMT_GET_PENDING_DATASET
     */
    DATASET_DELAY_TIMER = 5406,
    /** Format: `SD` - No direct read or write
     *
     * It can only be included in one of the Dataset related properties below:
     *
     *   THREAD_ACTIVE_DATASET
     *   THREAD_PENDING_DATASET
     *   THREAD_MGMT_SET_ACTIVE_DATASET
     *   THREAD_MGMT_SET_PENDING_DATASET
     *   THREAD_MGMT_GET_ACTIVE_DATASET
     *   THREAD_MGMT_GET_PENDING_DATASET
     *
     * Content is
     *   `S` : Key Rotation Time (in units of hour)
     *   `C` : Security Policy Flags (as specified in Thread 1.1 Section 8.10.1.15)
     *   `C` : Optional Security Policy Flags extension (as specified in Thread 1.2 Section 8.10.1.15).
     *         0xf8 is used if this field is missing.
     */
    DATASET_SECURITY_POLICY = 5407,
    /** Format: `D` - No direct read or write
     *
     * This property defines extra raw TLVs that can be added to an Operational DataSet.
     *
     * It can only be included in one of the following Dataset properties:
     *
     *   THREAD_MGMT_SET_ACTIVE_DATASET
     *   THREAD_MGMT_SET_PENDING_DATASET
     *   THREAD_MGMT_GET_ACTIVE_DATASET
     *   THREAD_MGMT_GET_PENDING_DATASET
     */
    DATASET_RAW_TLVS = 5408,
    /** Format: `A(t(ESA(6)))` - Read only
     *
     * This property provides the list of all addresses associated with every child
     * including any registered IPv6 addresses.
     *
     * Data per item is:
     *
     *  `E`: Extended address of the child
     *  `S`: RLOC16 of the child
     *  `A(6)`: List of IPv6 addresses registered by the child (if any)
     */
    THREAD_CHILD_TABLE_ADDRESSES = 5409,
    /** Format: `A(t(ESSScc))`
     *  Required capability: `CAP_ERROR_RATE_TRACKING`
     *
     * This property provides link quality related info including
     * frame and (IPv6) message error rates for all neighbors.
     *
     * With regards to message error rate, note that a larger (IPv6)
     * message can be fragmented and sent as multiple MAC frames. The
     * message transmission is considered a failure, if any of its
     * fragments fail after all MAC retry attempts.
     *
     * Data per item is:
     *
     *  `E`: Extended address of the neighbor
     *  `S`: RLOC16 of the neighbor
     *  `S`: Frame error rate (0 -> 0%, 0xffff -> 100%)
     *  `S`: Message error rate (0 -> 0%, 0xffff -> 100%)
     *  `c`: Average RSSI (in dBm)
     *  `c`: Last RSSI (in dBm)
     */
    THREAD_NEIGHBOR_TABLE_ERROR_RATES = 5410,
    /** Format `A(t(6SCCt(bL6)t(bSS)))
     *
     * This property provides Thread EID address cache table.
     *
     * Data per item is:
     *
     *  `6` : Target IPv6 address
     *  `S` : RLOC16 of target
     *  `C` : Age (order of use, 0 indicates most recently used entry)
     *  `C` : Entry state (values are defined by enumeration `SPINEL_ADDRESS_CACHE_ENTRY_STATE_*`).
     *
     *  `t` : Info when state is `SPINEL_ADDRESS_CACHE_ENTRY_STATE_CACHED`
     *    `b` : Indicates whether last transaction time and ML-EID are valid.
     *    `L` : Last transaction time
     *    `6` : Mesh-local EID
     *
     *  `t` : Info when state is other than `SPINEL_ADDRESS_CACHE_ENTRY_STATE_CACHED`
     *    `b` : Indicates whether the entry can be evicted.
     *    `S` : Timeout in seconds
     *    `S` : Retry delay (applicable if in query-retry state).
     */
    THREAD_ADDRESS_CACHE_TABLE = 5411,
    /** Format `dS6S`
     * Required capability: `SPINEL_CAP_THREAD_UDP_FORWARD`
     *
     * This property helps exchange UDP packets with host.
     *
     *  `d`: UDP payload
     *  `S`: Remote UDP port
     *  `6`: Remote IPv6 address
     *  `S`: Local UDP port
     */
    THREAD_UDP_FORWARD_STREAM = 5412,
    /** Format: `A(t(iD))` - Write only
     *
     * The formatting of this property follows the same rules as in THREAD_MGMT_SET_ACTIVE_DATASET. This
     * property further allows the sender to not include a value associated with properties in formatting of `t(iD)`,
     * i.e., it should accept either a `t(iD)` or a `t(i)` encoding (in both cases indicating that the associated
     * Dataset property should be requested as part of MGMT_GET command).
     *
     * This is write-only property. When written, it triggers a MGMT_ACTIVE_GET meshcop command to be sent to leader
     * requesting the Dataset related properties from the format. The spinel frame response should be a `LAST_STATUS`
     * with the status of the transmission of MGMT_ACTIVE_GET command.
     *
     * In addition to supported properties in THREAD_MGMT_SET_ACTIVE_DATASET, the following property can be
     * optionally included in the Dataset:
     *
     *    DATASET_DEST_ADDRESS
     */
    THREAD_MGMT_GET_ACTIVE_DATASET = 5413,
    /** Format: `A(t(iD))` - Write only
     *
     * The formatting of this property follows the same rules as in THREAD_MGMT_GET_ACTIVE_DATASET.
     *
     * This is write-only property. When written, it triggers a MGMT_PENDING_GET meshcop command to be sent to leader
     * with the given Dataset. The spinel frame response should be a `LAST_STATUS` with the status of the transmission
     * of MGMT_PENDING_GET command.
     */
    THREAD_MGMT_GET_PENDING_DATASET = 5414,
    /** Format: `6` - No direct read or write
     *
     * This property specifies the IPv6 destination when sending MGMT_GET command for either Active or Pending Dataset
     * if not provided, Leader ALOC address is used as default.
     *
     * It can only be included in one of the MGMT_GET Dataset properties:
     *
     *   THREAD_MGMT_GET_ACTIVE_DATASET
     *   THREAD_MGMT_GET_PENDING_DATASET
     */
    DATASET_DEST_ADDRESS = 5415,
    /** Format: `A(t(iD))` - Read only - FTD build only
     *
     * This property allows host to request NCP to create and return a new Operation Dataset to use when forming a new
     * network.
     *
     * Operational Dataset consists of a set of supported properties (e.g., channel, network key, network name, PAN id,
     * etc). Note that not all supported properties may be present (have a value) in a Dataset.
     *
     * The Dataset value is encoded as an array of structs containing pairs of property key (as `i`) followed by the
     * property value (as `D`). The property value must follow the format associated with the corresponding property.
     *
     * The following properties can be included in a Dataset list:
     *
     *   DATASET_ACTIVE_TIMESTAMP
     *   PHY_CHAN
     *   PHY_CHAN_SUPPORTED (Channel Mask Page 0)
     *   NET_NETWORK_KEY
     *   NET_NETWORK_NAME
     *   NET_XPANID
     *   MAC_15_4_PANID
     *   IPV6_ML_PREFIX
     *   NET_PSKC
     *   DATASET_SECURITY_POLICY
     */
    THREAD_NEW_DATASET = 5416,
    /** Format: `L`
     * Required capability: `SPINEL_CAP_THREAD_CSL_RECEIVER`
     *
     * The CSL period in microseconds. Value of 0 indicates that CSL should be disabled.
     *
     * The CSL period MUST be a multiple of 160 (which is 802.15 "ten symbols time").
     */
    THREAD_CSL_PERIOD = 5417,
    /** Format: `L`
     * Required capability: `SPINEL_CAP_THREAD_CSL_RECEIVER`
     *
     * The CSL timeout in seconds.
     */
    THREAD_CSL_TIMEOUT = 5418,
    /** Format: `C`
     * Required capability: `SPINEL_CAP_THREAD_CSL_RECEIVER`
     *
     * The CSL channel as described in chapter 4.6.5.1.2 of the Thread v1.2.0 Specification.
     * Value of 0 means that CSL reception (if enabled) occurs on the Thread Network channel.
     * Value from range [11,26] is an alternative channel on which a CSL reception occurs.
     */
    THREAD_CSL_CHANNEL = 5419,
    /** Format `U` - Read-write
     * Required capability: `SPINEL_CAP_NET_THREAD_1_2`
     *
     * This property is available since Thread 1.2.0.
     * Write to this property succeeds only when Thread protocols are disabled.
     */
    THREAD_DOMAIN_NAME = 5420,
    /** Format: `6CC` - Write-Only
     *
     * Required capability: `SPINEL_CAP_THREAD_LINK_METRICS`
     *
     * `6` : IPv6 destination address
     * `C` : Series id (0 for Single Probe)
     * `C` : List of requested metric ids encoded as bit fields in single byte
     *
     *   +---------------+----+
     *   |    Metric     | Id |
     *   +---------------+----+
     *   | Received PDUs |  0 |
     *   | LQI           |  1 |
     *   | Link margin   |  2 |
     *   | RSSI          |  3 |
     *   +---------------+----+
     *
     * If the query succeeds, the NCP will send a result to the Host using
     * @see THREAD_LINK_METRICS_QUERY_RESULT.
     */
    THREAD_LINK_METRICS_QUERY = 5421,
    /** Format: `6Ct(A(t(CD)))` - Unsolicited notifications only
     *
     * Required capability: `SPINEL_CAP_THREAD_LINK_METRICS`
     *
     * `6` : IPv6 destination address
     * `C` : Status
     * `t(A(t(CD)))` : Array of structs encoded as following:
     *   `C` : Metric id
     *   `D` : Metric value
     *
     *   +---------------+----+----------------+
     *   |    Metric     | Id |  Value format  |
     *   +---------------+----+----------------+
     *   | Received PDUs |  0 | `L` (uint32_t) |
     *   | LQI           |  1 | `C` (uint8_t)  |
     *   | Link margin   |  2 | `C` (uint8_t)  |
     *   | RSSI          |  3 | `c` (int8_t)   |
     *   +---------------+----+----------------+
     */
    THREAD_LINK_METRICS_QUERY_RESULT = 5422,
    /** Format `6CC` - Write only
     * Required capability: `SPINEL_CAP_THREAD_LINK_METRICS`
     *
     * Send a MLE Link Probe message to the peer.
     *
     * `6` : IPv6 destination address
     * `C` : The Series ID for which this Probe message targets at
     * `C` : The length of the Probe message, valid range: [0, 64]
     */
    THREAD_LINK_METRICS_PROBE = 5423,
    /** Format: 6Cd - Write only
     *
     * Required capability: `SPINEL_CAP_THREAD_LINK_METRICS`
     *
     * `6` : IPv6 destination address
     * `C` : Indicate whether to register or clear the probing. `0` - clear, `1` - register
     * `C` : List of requested metric ids encoded as bit fields in single byte
     *
     *   +---------------+----+
     *   |    Metric     | Id |
     *   +---------------+----+
     *   | LQI           |  1 |
     *   | Link margin   |  2 |
     *   | RSSI          |  3 |
     *   +---------------+----+
     *
     * Result of configuration is reported asynchronously to the Host using the
     * @see THREAD_LINK_METRICS_MGMT_RESPONSE.
     *
     * Whenever Enh-ACK IE report is received it is passed to the Host using the
     * @see THREAD_LINK_METRICS_MGMT_ENH_ACK_IE property.
     */
    THREAD_LINK_METRICS_MGMT_ENH_ACK = 5424,
    /** Format: SEA(t(CD)) - Unsolicited notifications only
     *
     * Required capability: `SPINEL_CAP_THREAD_LINK_METRICS`
     *
     * `S` : Short address of the Probing Subject
     * `E` : Extended address of the Probing Subject
     * `t(A(t(CD)))` : Struct that contains array of structs encoded as following:
     *   `C` : Metric id
     *   `D` : Metric value
     *
     *   +---------------+----+----------------+
     *   |    Metric     | Id |  Value format  |
     *   +---------------+----+----------------+
     *   | LQI           |  1 | `C` (uint8_t)  |
     *   | Link margin   |  2 | `C` (uint8_t)  |
     *   | RSSI          |  3 | `c` (int8_t)   |
     *   +---------------+----+----------------+
     */
    THREAD_LINK_METRICS_MGMT_ENH_ACK_IE = 5425,
    /** Format: 6CCC - Write only
     *
     * Required capability: `SPINEL_CAP_THREAD_LINK_METRICS`
     *
     * `6` : IPv6 destination address
     * `C` : Series id
     * `C` : Tracked frame types encoded as bit fields in single byte, if equal to zero,
     *       accounting is stopped and a series is removed
     * `C` : Requested metric ids encoded as bit fields in single byte
     *
     *   +------------------+----+
     *   |    Frame type    | Id |
     *   +------------------+----+
     *   | MLE Link Probe   |  0 |
     *   | MAC Data         |  1 |
     *   | MAC Data Request |  2 |
     *   | MAC ACK          |  3 |
     *   +------------------+----+
     *
     *   +---------------+----+
     *   |    Metric     | Id |
     *   +---------------+----+
     *   | Received PDUs |  0 |
     *   | LQI           |  1 |
     *   | Link margin   |  2 |
     *   | RSSI          |  3 |
     *   +---------------+----+
     *
     * Result of configuration is reported asynchronously to the Host using the
     * @see THREAD_LINK_METRICS_MGMT_RESPONSE.
     */
    THREAD_LINK_METRICS_MGMT_FORWARD = 5426,
    /** Format: 6C - Unsolicited notifications only
     *
     * Required capability: `SPINEL_CAP_THREAD_LINK_METRICS`
     *
     * `6` : IPv6 source address
     * `C` : Received status
     */
    THREAD_LINK_METRICS_MGMT_RESPONSE = 5427,
    /** Format `t(A(6))A(t(CD))` - Write-only
     * Required capability: `SPINEL_CAP_NET_THREAD_1_2`
     *
     * `t(A(6))`: Array of IPv6 multicast addresses
     * `A(t(CD))`: Array of structs holding optional parameters as follows
     *   `C`: Parameter id
     *   `D`: Parameter value
     *
     *   +----------------------------------------------------------------+
     *   | Id:   SPINEL_THREAD_MLR_PARAMID_TIMEOUT                        |
     *   | Type: `L`                                                      |
     *   | Description: Timeout in seconds. If this optional parameter is |
     *   |   omitted, the default value of the BBR will be used.          |
     *   | Special values:                                                |
     *   |   0 causes given addresses to be removed                       |
     *   |   0xFFFFFFFF is permanent and persistent registration          |
     *   +----------------------------------------------------------------+
     *
     * Write to this property initiates update of Multicast Listeners Table on the primary BBR.
     * If the write succeeded, the result of network operation will be notified later by the
     * THREAD_MLR_RESPONSE property. If the write fails, no MLR.req is issued and
     * notification through the THREAD_MLR_RESPONSE property will not occur.
     */
    THREAD_MLR_REQUEST = 5428,
    /** Format `CCt(A(6))` - Unsolicited notifications only
     * Required capability: `SPINEL_CAP_NET_THREAD_1_2`
     *
     * `C`: Status
     * `C`: MlrStatus (The Multicast Listener Registration Status)
     * `A(6)`: Array of IPv6 addresses that failed to be updated on the primary BBR
     *
     * This property is notified asynchronously when the NCP receives MLR.rsp following
     * previous write to the THREAD_MLR_REQUEST property.
     */
    THREAD_MLR_RESPONSE = 5429,
    /** Format: `A(C)` - Read-write
     *
     *   `A(C)`: Interface Identifier (8 bytes).
     *
     * Required capability: SPINEL_CAP_DUA
     *
     * If write to this property is performed without specified parameter
     * the Interface Identifier of the Thread Domain Unicast Address will be cleared.
     * If the DUA Interface Identifier is cleared on the NCP device,
     * the get spinel property command will be returned successfully without specified parameter.
     */
    THREAD_DUA_ID = 5430,
    /** Format: `SSLC` - Read-Only
     *
     * Required capability: `SPINEL_CAP_NET_THREAD_1_2`
     *
     * `S`: Server.
     * `S`: Reregistration Delay (in seconds).
     * `L`: Multicast Listener Registration Timeout (in seconds).
     * `C`: Sequence Number.
     */
    THREAD_BACKBONE_ROUTER_PRIMARY = 5431,
    /** Format: `C` - Read-Write
     *
     * Required capability: `SPINEL_CAP_THREAD_BACKBONE_ROUTER`
     *
     * The valid values are specified by SPINEL_THREAD_BACKBONE_ROUTER_STATE_<state> enumeration.
     * Backbone functionality will be disabled if SPINEL_THREAD_BACKBONE_ROUTER_STATE_DISABLED
     * is written to this property, enabled otherwise.
     */
    THREAD_BACKBONE_ROUTER_LOCAL_STATE = 5432,
    /** Format: SLC - Read-Write
     *
     * Required capability: `SPINEL_CAP_THREAD_BACKBONE_ROUTER`
     *
     * `S`: Reregistration Delay (in seconds).
     * `L`: Multicast Listener Registration Timeout (in seconds).
     * `C`: Sequence Number.
     */
    THREAD_BACKBONE_ROUTER_LOCAL_CONFIG = 5433,
    /** Format: Empty (Write only).
     *
     * Required capability: `SPINEL_CAP_THREAD_BACKBONE_ROUTER`
     *
     * Writing to this property (with any value) will register local Backbone Router configuration.
     */
    THREAD_BACKBONE_ROUTER_LOCAL_REGISTER = 5434,
    /** Format: `C` - Read-Write
     *
     * Required capability: `SPINEL_CAP_THREAD_BACKBONE_ROUTER`
     *
     * `C`: Backbone Router registration jitter.
     */
    THREAD_BACKBONE_ROUTER_LOCAL_REGISTRATION_JITTER = 5435,
    /** Format: `D` - Read-Write
     *
     * This property provides access to the current Thread Active Operational Dataset. A Thread device maintains the
     * Operational Dataset that it has stored locally and the one currently in use by the partition to which it is
     * attached. This property corresponds to the locally stored Dataset on the device.
     *
     * On write, any unknown/unsupported TLVs must be ignored.
     */
    THREAD_ACTIVE_DATASET_TLVS = 5436,
    /** Format: `D` - Read-Write
     *
     * This property provides access to the current locally stored Pending Operational Dataset.
     *
     * The formatting of this property follows the same rules as in THREAD_ACTIVE_DATASET_TLVS.
     *
     * On write, any unknown/unsupported TLVs must be ignored.
     */
    THREAD_PENDING_DATASET_TLVS = 5437,
    /** Format: `D` - Write only
     *
     * This is write-only property. When written, it triggers a MGMT_PENDING_SET meshcop command to be sent to leader
     * with the given Dataset.
     *
     * When setting this property, the spinel frame response will be:
     * 1. A `LAST_STATUS` with the status of the transmission of MGMT_PENDING_SET command if it fails.
     * 2. A `THREAD_MGMT_SET_PENDING_DATASET_TLVS` with no content.
     *
     * On response reception or timeout, another notification will be sent to the host:
     * A `THREAD_MGMT_SET_PENDING_DATASET_TLVS` with a spinel_status_t indicating
     * the result of MGMT_SET_PENDING.
     *
     * On write, any unknown/unsupported TLVs must be ignored.
     */
    THREAD_MGMT_SET_PENDING_DATASET_TLVS = 5438,
    /** Format: `C`
     *
     * The Wake-up sample channel. Channel value should be `0` (Set Wake-up Channel unspecified,
     * which means the device will use the PAN channel) or within the range [1, 10] (if 915-MHz
     * supported) and [11, 26] (if 2.4 GHz supported).
     */
    THREAD_WAKEUP_CHANNEL = 5439,
    /** Format: `6` - Read only
     */
    IPV6_LL_ADDR = 96,///< [6]
    /** Format: `6` - Read only
     */
    IPV6_ML_ADDR = 97,
    /** Format: `6C` - Read-write
     *
     * Provides Mesh Local Prefix
     *
     *   `6`: Mesh local prefix
     *   `C` : Prefix length (64 bit for Thread).
     */
    IPV6_ML_PREFIX = 98,
    /** Format: `A(t(6CLLC))`
     *
     * This property provides all unicast addresses.
     *
     * Array of structures containing:
     *
     *  `6`: IPv6 Address
     *  `C`: Network Prefix Length (in bits)
     *  `L`: Preferred Lifetime
     *  `L`: Valid Lifetime
     */
    IPV6_ADDRESS_TABLE = 99,
    IPV6_ROUTE_TABLE = 100,
    /** Format: `b`
     *
     * Allow the NCP to directly respond to ICMP ping requests. If this is
     * turned on, ping request ICMP packets will not be passed to the host.
     *
     * Default value is `false`.
     */
    IPV6_ICMP_PING_OFFLOAD = 101,
    /** Format: `A(t(6))`
     *
     * This property provides all multicast addresses.
     */
    IPV6_MULTICAST_ADDRESS_TABLE = 102,
    /** Format: `C`
     *
     * Allow the NCP to directly respond to ICMP ping requests. If this is
     * turned on, ping request ICMP packets will not be passed to the host.
     *
     * This property allows enabling responses sent to unicast only, multicast
     * only, or both. The valid value are defined by enumeration
     * `spinel_ipv6_icmp_ping_offload_mode_t`.
     *
     *   SPINEL_IPV6_ICMP_PING_OFFLOAD_DISABLED       = 0
     *   SPINEL_IPV6_ICMP_PING_OFFLOAD_UNICAST_ONLY   = 1
     *   SPINEL_IPV6_ICMP_PING_OFFLOAD_MULTICAST_ONLY = 2
     *   SPINEL_IPV6_ICMP_PING_OFFLOAD_ALL            = 3
     *   SPINEL_IPV6_ICMP_PING_OFFLOAD_RLOC_ALOC_ONLY = 4
     *
     * Default value is `NET_IPV6_ICMP_PING_OFFLOAD_DISABLED`.
     */
    IPV6_ICMP_PING_OFFLOAD_MODE = 103,///< [b]
    /** Format: `U` (stream, read only)
     *
     * This property is a streaming property, meaning that you cannot explicitly
     * fetch the value of this property. The stream provides human-readable debugging
     * output which may be displayed in the host logs.
     *
     * The location of newline characters is not assumed by the host: it is
     * the NCP's responsibility to insert newline characters where needed,
     * just like with any other text stream.
     *
     * To receive the debugging stream, you wait for `CMD_PROP_VALUE_IS`
     * commands for this property from the NCP.
     */
    STREAM_DEBUG = 112,
    /** Format: `dD` (stream, read only)
     *  Required Capability: SPINEL_CAP_MAC_RAW or SPINEL_CAP_CONFIG_RADIO
     *
     * This stream provides the capability of sending and receiving raw 15.4 frames
     * to and from the radio. The exact format of the frame metadata and data is
     * dependent on the MAC and PHY being used.
     *
     * This property is a streaming property, meaning that you cannot explicitly
     * fetch the value of this property. To receive traffic, you wait for
     * `CMD_PROP_VALUE_IS` commands with this property id from the NCP.
     *
     * The general format of this property is:
     *
     *    `d` : frame data
     *    `D` : frame meta data
     *
     * The frame meta data is optional. Frame metadata MAY be empty or partially
     * specified. Partially specified metadata MUST be accepted. Default values
     * are used for all unspecified fields.
     *
     * The frame metadata field consists of the following fields:
     *
     *   `c` : Received Signal Strength (RSSI) in dBm - default is -128
     *   `c` : Noise floor in dBm - default is -128
     *   `S` : Flags (see below).
     *   `d` : PHY-specific data/struct
     *   `d` : Vendor-specific data/struct
     *
     * Flags fields are defined by the following enumeration bitfields:
     *
     *   SPINEL_MD_FLAG_TX       = 0x0001 :  Packet was transmitted, not received.
     *   SPINEL_MD_FLAG_BAD_FCS  = 0x0004 :  Packet was received with bad FCS
     *   SPINEL_MD_FLAG_DUPE     = 0x0008 :  Packet seems to be a duplicate
     *   SPINEL_MD_FLAG_RESERVED = 0xFFF2 :  Flags reserved for future use.
     *
     * The format of PHY-specific data for a Thread device contains the following
     * optional fields:

     *   `C` : 802.15.4 channel
     *   `C` : IEEE 802.15.4 LQI
     *   `X` : The timestamp in microseconds
     *
     * Frames written to this stream with `CMD_PROP_VALUE_SET` will be sent out
     * over the radio. This allows the caller to use the radio directly.
     *
     * The frame meta data for the `CMD_PROP_VALUE_SET` contains the following
     * fields.  Default values are used for all unspecified fields.
     *
     *  `C` : Channel (for frame tx) - MUST be included.
     *  `C` : Maximum number of backoffs attempts before declaring CCA failure
     *        (use Thread stack default if not specified)
     *  `C` : Maximum number of retries allowed after a transmission failure
     *        (use Thread stack default if not specified)
     *  `b` : Set to true to enable CSMA-CA for this packet, false otherwise.
     *        (default true).
     *  `b` : Set to true to indicate if header is updated - related to
     *        `mIsHeaderUpdated` in `otRadioFrame` (default false).
     *  `b` : Set to true to indicate it is a retransmission - related to
     *        `mIsARetx` in `otRadioFrame` (default false).
     *  `b` : Set to true to indicate security was processed on tx frame
     *        `mIsSecurityProcessed` in `otRadioFrame` (default false).
     *  `L` : TX delay interval used for CSL - related to `mTxDelay` in
     *        `otRadioFrame` (default zero).
     *  `L` : TX delay based time used for CSL - related to `mTxDelayBaseTime`
     *        in `otRadioFrame` (default zero).
     *  `C` : RX channel after TX done (default assumed to be same as
     *        channel in metadata)
     */
    STREAM_RAW = 113,
    /** Format: `dD` (stream, read only)
     *
     * This stream provides the capability of sending and receiving (IPv6)
     * data packets to and from the currently attached network. The packets
     * are sent or received securely (encryption and authentication).
     *
     * This property is a streaming property, meaning that you cannot explicitly
     * fetch the value of this property. To receive traffic, you wait for
     * `CMD_PROP_VALUE_IS` commands with this property id from the NCP.
     *
     * To send network packets, you call `CMD_PROP_VALUE_SET` on this property with
     * the value of the packet.
     *
     * The general format of this property is:
     *
     *    `d` : packet data
     *    `D` : packet meta data
     *
     * The packet metadata is optional. Packet meta data MAY be empty or partially
     * specified. Partially specified metadata MUST be accepted. Default values
     * are used for all unspecified fields.
     *
     * For OpenThread the meta data is currently empty.
     */
    STREAM_NET = 114,
    /** Format: `dD` (stream, read only)
     *
     * This stream provides the capability of sending and receiving unencrypted
     * and unauthenticated data packets to and from nearby devices for the
     * purposes of device commissioning.
     *
     * This property is a streaming property, meaning that you cannot explicitly
     * fetch the value of this property. To receive traffic, you wait for
     * `CMD_PROP_VALUE_IS` commands with this property id from the NCP.
     *
     * To send network packets, you call `CMD_PROP_VALUE_SET` on this property with
     * the value of the packet.
     *
     * The general format of this property is:
     *
     *    `d` : packet data
     *    `D` : packet meta data
     *
     * The packet metadata is optional. Packet meta data MAY be empty or partially
     * specified. Partially specified metadata MUST be accepted. Default values
     * are used for all unspecified fields.
     *
     * For OpenThread the meta data is currently empty.
     */
    STREAM_NET_INSECURE = 115,
    /** Format: `UD` (stream, read only)
     *
     * This property is a read-only streaming property which provides
     * formatted log string from NCP. This property provides asynchronous
     * `CMD_PROP_VALUE_IS` updates with a new log string and includes
     * optional meta data.
     *
     *   `U`: The log string
     *   `D`: Log metadata (optional).
     *
     * Any data after the log string is considered metadata and is OPTIONAL.
     * Presence of `SPINEL_CAP_OPENTHREAD_LOG_METADATA` capability
     * indicates that OpenThread log metadata format is used as defined
     * below:
     *
     *    `C`: Log level (as per definition in enumeration
     *         `SPINEL_NCP_LOG_LEVEL_<level>`)
     *    `i`: OpenThread Log region (as per definition in enumeration
     *         `SPINEL_NCP_LOG_REGION_<region>).
     *    `X`: Log timestamp = <timestamp_base> + <current_time_ms>
     */
    STREAM_LOG = 116,
    /** Format `C` - Read Only
     *
     * Required capability: SPINEL_CAP_THREAD_JOINER
     *
     * The valid values are specified by `spinel_meshcop_joiner_state_t` (`SPINEL_MESHCOP_JOINER_STATE_<state>`)
     * enumeration.
     */
    MESHCOP_JOINER_STATE = 128,///<[C]
    /** Format `b` or `bU(UUUUU)` (fields in parenthesis are optional) - Write Only
     *
     * This property starts or stops Joiner's commissioning process
     *
     * Required capability: SPINEL_CAP_THREAD_JOINER
     *
     * Writing to this property starts/stops the Joiner commissioning process.
     * The immediate `VALUE_IS` response indicates success/failure of the starting/stopping
     * the Joiner commissioning process.
     *
     * After a successful start operation, the join process outcome is reported through an
     * asynchronous `VALUE_IS(LAST_STATUS)` update with one of the following error status values:
     *
     *     - SPINEL_STATUS_JOIN_SUCCESS     the join process succeeded.
     *     - SPINEL_STATUS_JOIN_SECURITY    the join process failed due to security credentials.
     *     - SPINEL_STATUS_JOIN_NO_PEERS    no joinable network was discovered.
     *     - SPINEL_STATUS_JOIN_RSP_TIMEOUT if a response timed out.
     *     - SPINEL_STATUS_JOIN_FAILURE     join failure.
     *
     * Frame format:
     *
     *  `b` : Start or stop commissioning process (true to start).
     *
     * Only if the start commissioning.
     *
     *  `U` : Joiner's PSKd.
     *
     * The next fields are all optional. If not provided, OpenThread default values would be used.
     *
     *  `U` : Provisioning URL (use empty string if not required).
     *  `U` : Vendor Name. If not specified or empty string, use OpenThread default (PACKAGE_NAME).
     *  `U` : Vendor Model. If not specified or empty string, use OpenThread default (OPENTHREAD_CONFIG_PLATFORM_INFO).
     *  `U` : Vendor Sw Version. If not specified or empty string, use OpenThread default (PACKAGE_VERSION).
     *  `U` : Vendor Data String. Will not be appended if not specified.
     */
    MESHCOP_JOINER_COMMISSIONING = 129,
    /** Format `C`
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * The valid values are specified by SPINEL_MESHCOP_COMMISSIONER_STATE_<state> enumeration.
     */
    MESHCOP_COMMISSIONER_STATE = 130,
    /** Format `A(t(t(E|CX)UL))` - get, insert or remove.
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * Data per array entry is:
     *
     *  `t()` | `t(E)` | `t(CX)` : Joiner info struct (formatting varies).
     *
     *   -  `t()` or empty struct indicates any joiner.
     *   -  `t(E)` specifies the Joiner EUI-64.
     *   -  `t(CX) specifies Joiner Discerner, `C` is Discerner length (in bits), and `X` is Discerner value.
     *
     * The struct is followed by:
     *
     *  `L` : Timeout after which to remove Joiner (when written should be in seconds, when read is in milliseconds)
     *  `U` : PSKd
     *
     * For CMD_PROP_VALUE_REMOVE the timeout and PSKd are optional.
     */
    MESHCOP_COMMISSIONER_JOINERS = 131,
    /** Format `U`
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     */
    MESHCOP_COMMISSIONER_PROVISIONING_URL = 132,
    /** Format `S` - Read only
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     */
    MESHCOP_COMMISSIONER_SESSION_ID = 133,
    /** Format `CX`  - Read-write
     *
     * Required capability: SPINEL_CAP_THREAD_JOINER
     *
     * This property represents a Joiner Discerner.
     *
     * The Joiner Discerner is used to calculate the Joiner ID used during commissioning/joining process.
     *
     * By default (when a discerner is not provided or cleared), Joiner ID is derived as first 64 bits of the result
     * of computing SHA-256 over factory-assigned IEEE EUI-64. Note that this is the main behavior expected by Thread
     * specification.
     *
     * Format:
     *
     *   'C' : The Joiner Discerner bit length (number of bits).
     *   `X` : The Joiner Discerner value (64-bit unsigned)  - Only present/applicable when length is non-zero.
     *
     * When writing to this property, the length can be set to zero to clear any previously set Joiner Discerner value.
     *
     * When reading this property if there is no currently set Joiner Discerner, zero is returned as the length (with
     * no value field).
     */
    MESHCOP_JOINER_DISCERNER = 134,
    /** Format `LCS6` - Write only
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * Writing to this property sends an Announce Begin message with the specified parameters. Response is a
     * `LAST_STATUS` update with status of operation.
     *
     *   `L` : Channel mask
     *   `C` : Number of messages per channel
     *   `S` : The time between two successive MLE Announce transmissions (milliseconds)
     *   `6` : IPv6 destination
     */
    MESHCOP_COMMISSIONER_ANNOUNCE_BEGIN = 6144,
    /** Format `LCSS6` - Write only
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * Writing to this property sends an Energy Scan Query message with the specified parameters. Response is a
     * `LAST_STATUS` with status of operation. The energy scan results are emitted asynchronously through
     * `MESHCOP_COMMISSIONER_ENERGY_SCAN_RESULT` updates.
     *
     * Format is:
     *
     *   `L` : Channel mask
     *   `C` : The number of energy measurements per channel
     *   `S` : The time between energy measurements (milliseconds)
     *   `S` : The scan duration for each energy measurement (milliseconds)
     *   `6` : IPv6 destination.
     */
    MESHCOP_COMMISSIONER_ENERGY_SCAN = 6145,
    /** Format `Ld` - Asynchronous event only
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * This property provides asynchronous `CMD_PROP_VALUE_INSERTED` updates to report energy scan results for a
     * previously sent Energy Scan Query message (please see `MESHCOP_COMMISSIONER_ENERGY_SCAN`).
     *
     * Format is:
     *
     *   `L` : Channel mask
     *   `d` : Energy measurement data (note that `d` encoding includes the length)
     */
    MESHCOP_COMMISSIONER_ENERGY_SCAN_RESULT = 6146,
    /** Format `SL6` - Write only
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * Writing to this property sends a PAN ID Query message with the specified parameters. Response is a
     * `LAST_STATUS` with status of operation. The PAN ID Conflict results are emitted asynchronously through
     * `MESHCOP_COMMISSIONER_PAN_ID_CONFLICT_RESULT` updates.
     *
     * Format is:
     *
     *   `S` : PAN ID to query
     *   `L` : Channel mask
     *   `6` : IPv6 destination
     */
    MESHCOP_COMMISSIONER_PAN_ID_QUERY = 6147,
    /** Format `SL` - Asynchronous event only
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * This property provides asynchronous `CMD_PROP_VALUE_INSERTED` updates to report PAN ID conflict results for a
     * previously sent PAN ID Query message (please see `MESHCOP_COMMISSIONER_PAN_ID_QUERY`).
     *
     * Format is:
     *
     *   `S` : The PAN ID
     *   `L` : Channel mask
     */
    MESHCOP_COMMISSIONER_PAN_ID_CONFLICT_RESULT = 6148,
    /** Format `d` - Write only
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * Writing to this property sends a MGMT_COMMISSIONER_GET message with the specified parameters. Response is a
     * `LAST_STATUS` with status of operation.
     *
     * Format is:
     *
     *   `d` : List of TLV types to get
     */
    MESHCOP_COMMISSIONER_MGMT_GET = 6149,
    /** Format `d` - Write only
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * Writing to this property sends a MGMT_COMMISSIONER_SET message with the specified parameters. Response is a
     * `LAST_STATUS` with status of operation.
     *
     * Format is:
     *
     *   `d` : TLV encoded data
     */
    MESHCOP_COMMISSIONER_MGMT_SET = 6150,
    /** Format: `UUd` - Write only
     *
     * Required capability: SPINEL_CAP_THREAD_COMMISSIONER
     *
     * Writing to this property allows user to generate PSKc from a given commissioning pass-phrase, network name,
     * extended PAN Id.
     *
     * Written value format is:
     *
     *   `U` : The commissioning pass-phrase.
     *   `U` : Network Name.
     *   `d` : Extended PAN ID.
     *
     * The response on success would be a `VALUE_IS` command with the PSKc with format below:
     *
     *   `D` : The PSKc
     *
     * On a failure a `LAST_STATUS` is emitted with the error status.
     */
    MESHCOP_COMMISSIONER_GENERATE_PSKC = 6151,
    /** Format: `C` (read-write)
     *
     * Required capability: SPINEL_CAP_CHANNEL_MANAGER
     *
     * Setting this property triggers the Channel Manager to start
     * a channel change process. The network switches to the given
     * channel after the specified delay (see `CHANNEL_MANAGER_DELAY`).
     *
     * A subsequent write to this property will cancel an ongoing
     * (previously requested) channel change.
     */
    CHANNEL_MANAGER_NEW_CHANNEL = 6400,
    /** Format 'S'
     *  Units: seconds
     *
     * Required capability: SPINEL_CAP_CHANNEL_MANAGER
     *
     * This property specifies the delay (in seconds) to be used for
     * a channel change request.
     *
     * The delay should preferably be longer than maximum data poll
     * interval used by all sleepy-end-devices within the Thread
     * network.
     */
    CHANNEL_MANAGER_DELAY = 6401,
    /** Format 'A(C)'
     *
     * Required capability: SPINEL_CAP_CHANNEL_MANAGER
     *
     * This property specifies the list of supported channels.
     */
    CHANNEL_MANAGER_SUPPORTED_CHANNELS = 6402,
    /** Format 'A(C)'
     *
     * Required capability: SPINEL_CAP_CHANNEL_MANAGER
     *
     * This property specifies the list of favored channels (when `ChannelManager` is asked to select channel)
     */
    CHANNEL_MANAGER_FAVORED_CHANNELS = 6403,
    /** Format 'b'
     *
     * Required capability: SPINEL_CAP_CHANNEL_MANAGER
     *
     * Writing to this property triggers a request on `ChannelManager` to select a new channel.
     *
     * Once a Channel Select is triggered, the Channel Manager will perform the following 3 steps:
     *
     * 1) `ChannelManager` decides if the channel change would be helpful. This check can be skipped if in the input
     *    boolean to this property is set to `true` (skipping the quality check).
     *    This step uses the collected link quality metrics on the device such as CCA failure rate, frame and message
     *    error rates per neighbor, etc. to determine if the current channel quality is at the level that justifies
     *    a channel change.
     *
     * 2) If first step passes, then `ChannelManager` selects a potentially better channel. It uses the collected
     *    channel quality data by `ChannelMonitor` module. The supported and favored channels are used at this step.
     *
     * 3) If the newly selected channel is different from the current channel, `ChannelManager` requests/starts the
     *    channel change process.
     *
     * Reading this property always yields `false`.
     */
    CHANNEL_MANAGER_CHANNEL_SELECT = 6404,
    /** Format 'b'
     *
     * Required capability: SPINEL_CAP_CHANNEL_MANAGER
     *
     * This property indicates if auto-channel-selection functionality is enabled/disabled on `ChannelManager`.
     *
     * When enabled, `ChannelManager` will periodically checks and attempts to select a new channel. The period interval
     * is specified by `CHANNEL_MANAGER_AUTO_SELECT_INTERVAL`.
     */
    CHANNEL_MANAGER_AUTO_SELECT_ENABLED = 6405,
    /** Format 'L'
     *  units: seconds
     *
     * Required capability: SPINEL_CAP_CHANNEL_MANAGER
     *
     * This property specifies the auto-channel-selection check interval (in seconds).
     */
    CHANNEL_MANAGER_AUTO_SELECT_INTERVAL = 6406,
    /** Format: `Xc` - Read only
     *
     * Data per item is:
     *
     *  `X`: The Thread network time, in microseconds.
     *  `c`: Time synchronization status.
     */
    THREAD_NETWORK_TIME = 6407,
    /** Format: `S` - Read-Write
     *
     * Data per item is:
     *
     *  `S`: Time synchronization period, in seconds.
     */
    TIME_SYNC_PERIOD = 6408,
    /** Format: `S` - Read-Write
     *
     * Data per item is:
     *
     *  `S`: The XTAL accuracy threshold for Router, in PPM.
     */
    TIME_SYNC_XTAL_THRESHOLD = 6409,
    /** Format: `S` - Read-Write
     *  Units: Seconds
     *
     * Required capability: `SPINEL_CAP_CHILD_SUPERVISION`
     *
     * The child supervision interval (in seconds). Zero indicates that child supervision is disabled.
     *
     * When enabled, Child supervision feature ensures that at least one message is sent to every sleepy child within
     * the given supervision interval. If there is no other message, a supervision message (a data message with empty
     * payload) is enqueued and sent to the child.
     *
     * This property is available for FTD build only.
     */
    CHILD_SUPERVISION_INTERVAL = 6410,
    /** Format: `S` - Read-Write
     *  Units: Seconds
     *
     * Required capability: `SPINEL_CAP_CHILD_SUPERVISION`
     *
     * The child supervision check timeout interval (in seconds). Zero indicates supervision check on the child is
     * disabled.
     *
     * Supervision check is only applicable on a sleepy child. When enabled, if the child does not hear from its parent
     * within the specified check timeout, it initiates a re-attach process by starting an MLE Child Update
     * Request/Response exchange with the parent.
     *
     * This property is available for FTD and MTD builds.
     */
    CHILD_SUPERVISION_CHECK_TIMEOUT = 6411,
    /** Format `U` - Read only
     *
     * Required capability: SPINEL_CAP_POSIX
     *
     * This property gives the version string of RCP (NCP in radio mode) which is being controlled by a POSIX
     * application. It is available only in "POSIX" platform (i.e., `OPENTHREAD_PLATFORM_POSIX` is enabled).
     */
    RCP_VERSION = 6412,
    /** Format: `ESccCCCb` - Asynchronous event only
     *
     *  `E`: Extended address
     *  `S`: RLOC16
     *  `c`: Instant RSSI
     *  'c': Parent Priority
     *  `C`: Link Quality3
     *  `C`: Link Quality2
     *  `C`: Link Quality1
     *  'b': Is the node receiving parent response frame attached
     *
     * This property sends Parent Response frame information to the Host.
     * This property is available for FTD build only.
     */
    PARENT_RESPONSE_INFO = 6413,
    /** Format `b` - Read-Write
     *  Required capability: `SPINEL_CAP_SLAAC`
     *
     * This property allows the host to enable/disable SLAAC module on NCP at run-time. When SLAAC module is enabled,
     * SLAAC addresses (based on on-mesh prefixes in Network Data) are added to the interface. When SLAAC module is
     * disabled any previously added SLAAC address is removed.
     */
    SLAAC_ENABLED = 6414,
    /**
     * Format `A(i)` - Read only
     *
     * This property returns list of supported radio links by the device itself. Enumeration `SPINEL_RADIO_LINK_{TYPE}`
     * values indicate different radio link types.
     */
    SUPPORTED_RADIO_LINKS = 6415,
    /** Format: `A(t(ESA(t(iC))))` - Read only
     * Required capability: `SPINEL_CAP_MULTI_RADIO`.
     *
     * Each item represents info about a neighbor:
     *
     *  `E`: Neighbor's Extended Address
     *  `S`: Neighbor's RLOC16
     *
     *  This is then followed by an array of radio link info structures indicating which radio links are supported by
     *  the neighbor:
     *
     *    `i` : Radio link type (enumeration `SPINEL_RADIO_LINK_{TYPE}`).
     *    `C` : Preference value associated with radio link.
     */
    NEIGHBOR_TABLE_MULTI_RADIO_INFO = 6416,
    /** Format: `b(6Sb)` - Write only
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     *
     * Writing to this property allows user to start or stop the SRP client operation with a given SRP server.
     *
     * Written value format is:
     *
     *   `b` : TRUE to start the client, FALSE to stop the client.
     *
     * When used to start the SRP client, the following fields should also be included:
     *
     *   `6` : SRP server IPv6 address.
     *   `U` : SRP server port number.
     *   `b` : Boolean to indicate whether or not to emit SRP client events (using `SRP_CLIENT_EVENT`).
     */
    SRP_CLIENT_START = 6417,
    /** Format: `L` - Read/Write
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     *
     * The lease interval used in SRP update requests (in seconds).
     */
    SRP_CLIENT_LEASE_INTERVAL = 6418,
    /** Format: `L` - Read/Write
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     *
     * The key lease interval used in SRP update requests (in seconds).
     */
    SRP_CLIENT_KEY_LEASE_INTERVAL = 6419,
    /** Format: `UCt(A(6))` - Read only
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     *
     * Format is:
     *
     *   `U`       : The host name.
     *   `C`       : The host state (values from `spinel_srp_client_item_state_t`).
     *   `t(A(6))` : Structure containing array of host IPv6 addresses.
     */
    SRP_CLIENT_HOST_INFO = 6420,
    /** Format: `U` - Read/Write
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     */
    SRP_CLIENT_HOST_NAME = 6421,
    /** Format: `A(6)` - Read/Write
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     */
    SRP_CLIENT_HOST_ADDRESSES = 6422,
    /** Format: `A(t(UUSSSd))` - Read/Insert/Remove
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     *
     * This property provides a list/array of services.
     *
     * Data per item for `SPINEL_CMD_PROP_VALUE_GET` and/or `SPINEL_CMD_PROP_VALUE_INSERT` operation is as follows:
     *
     *   `U` : The service name labels (e.g., "_chip._udp", not the full domain name.
     *   `U` : The service instance name label (not the full name).
     *   `S` : The service port number.
     *   `S` : The service priority.
     *   `S` : The service weight.
     *
     * For `SPINEL_CMD_PROP_VALUE_REMOVE` command, the following format is used:
     *
     *   `U` : The service name labels (e.g., "_chip._udp", not the full domain name.
     *   `U` : The service instance name label (not the full name).
     *   `b` : Indicates whether to clear the service entry (optional).
     *
     * The last boolean (`b`) field is optional. When included it indicates on `true` to clear the service (clear it
     * on client immediately with no interaction to server) and on `false` to remove the service (inform server and
     * wait for the service entry to be removed on server). If it is not included, the value is `false`.
     */
    SRP_CLIENT_SERVICES = 6423,
    /** Format: `bb` : Write only
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     *
     * Writing to this property with starts the remove process of the host info and all services.
     * Please see `otSrpClientRemoveHostAndServices()` for more details.
     *
     * Format is:
     *
     *    `b` : A boolean indicating whether or not the host key lease should also be cleared.
     *    `b` : A boolean indicating whether or not to send update to server when host info is not registered.
     */
    SRP_CLIENT_HOST_SERVICES_REMOVE = 6424,
    /** Format: Empty : Write only
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     *
     * Writing to this property clears all host info and all the services.
     * Please see `otSrpClientClearHostAndServices()` for more details.
     */
    SRP_CLIENT_HOST_SERVICES_CLEAR = 6425,
    /** Format: t() : Asynchronous event only
     * Required capability: `SPINEL_CAP_SRP_CLIENT`.
     *
     * This property is asynchronously emitted when there is an event from SRP client notifying some state changes or
     * errors.
     *
     * The general format of this property is as follows:
     *
     *    `S` : Error code (see `spinel_srp_client_error_t` enumeration).
     *    `d` : Host info data.
     *    `d` : Active services.
     *    `d` : Removed services.
     *
     * The host info data contains:
     *
     *   `U`       : The host name.
     *   `C`       : The host state (values from `spinel_srp_client_item_state_t`).
     *   `t(A(6))` : Structure containing array of host IPv6 addresses.
     *
     * The active or removed services data is an array of services `A(t(UUSSSd))` with each service format:
     *
     *   `U` : The service name labels (e.g., "_chip._udp", not the full domain name.
     *   `U` : The service instance name label (not the full name).
     *   `S` : The service port number.
     *   `S` : The service priority.
     *   `S` : The service weight.
     *   `d` : The encoded TXT-DATA.
     */
    SRP_CLIENT_EVENT = 6426,
    /** Format `b` : Read-Write
     * Required capability: `SPINEL_CAP_SRP_CLIENT` & `SPINEL_CAP_REFERENCE_DEVICE`.
     *
     * This boolean property indicates whether the "service key record inclusion" mode is enabled or not.
     *
     * When enabled, SRP client will include KEY record in Service Description Instructions in the SRP update messages
     * that it sends.
     *
     * KEY record is optional in Service Description Instruction (it is required and always included in the Host
     * Description Instruction). The default behavior of SRP client is to not include it. This function is intended to
     * override the default behavior for testing only.
     */
    SRP_CLIENT_SERVICE_KEY_ENABLED = 6427,
    /** Format `b` - Read-write
     *
     * Required capability: SPINEL_CAP_THREAD_SERVICE
     *
     * Set to true before changing local server net data. Set to false when finished.
     * This allows changes to be aggregated into a single event.
     */
    SERVER_ALLOW_LOCAL_DATA_CHANGE = 160,
    /** Format: `A(t(LdbdS))`
     *
     * This property provides all services registered on the device
     *
     * Required capability: SPINEL_CAP_THREAD_SERVICE
     *
     * Array of structures containing:
     *
     *  `L`: Enterprise Number
     *  `d`: Service Data
     *  `b`: Stable
     *  `d`: Server Data
     *  `S`: RLOC
     */
    SERVER_SERVICES = 161,
    /** Format: `A(t(CLdbdS))`
     *
     * This property provides all services registered on the leader
     *
     * Array of structures containing:
     *
     *  `C`: Service ID
     *  `L`: Enterprise Number
     *  `d`: Service Data
     *  `b`: Stable
     *  `d`: Server Data
     *  `S`: RLOC
     */
    SERVER_LEADER_SERVICES = 162,
    /** Format: `i` (read-only)
     *
     * Required capability: SPINEL_CAP_RADIO and SPINEL_CAP_RCP_API_VERSION.
     *
     * This property gives the RCP API Version number.
     *
     * Please see "Spinel definition compatibility guideline" section.
     */
    RCP_API_VERSION = 176,
    /** Format: `i` (read-only)
     *
     * Required capability: SPINEL_CAP_RADIO and SPINEL_CAP_RCP_MIN_HOST_API_VERSION.
     *
     * This property gives the minimum host RCP API Version number.
     *
     * Please see "Spinel definition compatibility guideline" section.
     */
    RCP_MIN_HOST_API_VERSION = 177,
    /** Format: Empty : Write only
     *
     * Required capability: SPINEL_CAP_RADIO and SPINEL_CAP_RCP_LOG_CRASH_DUMP.
     *
     * Writing to this property instructs the RCP to log a crash dump if available.
     */
    RCP_LOG_CRASH_DUMP = 178,
    /** Format: `L`
     *
     *  If the NCP is using a UART to communicate with the host,
     *  this property allows the host to change the bitrate
     *  of the serial connection. The value encoding is `L`,
     *  which is a little-endian 32-bit unsigned integer.
     *  The host should not assume that all possible numeric values
     *  are supported.
     *
     *  If implemented by the NCP, this property should be persistent
     *  across software resets and forgotten upon hardware resets.
     *
     *  This property is only implemented when a UART is being
     *  used for Spinel. This property is optional.
     *
     *  When changing the bitrate, all frames will be received
     *  at the previous bitrate until the response frame to this command
     *  is received. Once a successful response frame is received by
     *  the host, all further frames will be transmitted at the new
     *  bitrate.
     */
    UART_BITRATE = 256,
    /** Format: `b`
     *
     *  If the NCP is using a UART to communicate with the host,
     *  this property allows the host to determine if software flow
     *  control (XON/XOFF style) should be used and (optionally) to
     *  turn it on or off.
     *
     *  This property is only implemented when a UART is being
     *  used for Spinel. This property is optional.
     */
    UART_XON_XOFF = 257,
    IEEE_802_15_4_PIB_PHY_CHANNELS_SUPPORTED = 1025,///< [A(L)]
    IEEE_802_15_4_PIB_MAC_PROMISCUOUS_MODE = 1105,///< [b]
    IEEE_802_15_4_PIB_MAC_SECURITY_ENABLED = 1117,///< [b]
    /** Format: Empty (Write only).
     *
     * Writing to this property (with any value) will reset all MAC, MLE, IP, and NCP counters to zero.
     */
    CNTR_RESET = 1280,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_TOTAL = 1281,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_ACK_REQ = 1282,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_ACKED = 1283,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_NO_ACK_REQ = 1284,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_DATA = 1285,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_DATA_POLL = 1286,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_BEACON = 1287,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_BEACON_REQ = 1288,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_OTHER = 1289,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_RETRY = 1290,
    /** Format: `L` (Read-only) */
    CNTR_TX_ERR_CCA = 1291,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_UNICAST = 1292,
    /** Format: `L` (Read-only) */
    CNTR_TX_PKT_BROADCAST = 1293,
    /** Format: `L` (Read-only) */
    CNTR_TX_ERR_ABORT = 1294,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_TOTAL = 1380,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_DATA = 1381,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_DATA_POLL = 1382,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_BEACON = 1383,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_BEACON_REQ = 1384,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_OTHER = 1385,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_FILT_WL = 1386,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_FILT_DA = 1387,
    /** Format: `L` (Read-only) */
    CNTR_RX_ERR_EMPTY = 1388,
    /** Format: `L` (Read-only) */
    CNTR_RX_ERR_UKWN_NBR = 1389,
    /** Format: `L` (Read-only) */
    CNTR_RX_ERR_NVLD_SADDR = 1390,
    /** Format: `L` (Read-only) */
    CNTR_RX_ERR_SECURITY = 1391,
    /** Format: `L` (Read-only) */
    CNTR_RX_ERR_BAD_FCS = 1392,
    /** Format: `L` (Read-only) */
    CNTR_RX_ERR_OTHER = 1393,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_DUP = 1394,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_UNICAST = 1395,
    /** Format: `L` (Read-only) */
    CNTR_RX_PKT_BROADCAST = 1396,
    /** Format: `L` (Read-only) */
    CNTR_TX_IP_SEC_TOTAL = 1480,
    /** Format: `L` (Read-only) */
    CNTR_TX_IP_INSEC_TOTAL = 1481,
    /** Format: `L` (Read-only) */
    CNTR_TX_IP_DROPPED = 1482,
    /** Format: `L` (Read-only) */
    CNTR_RX_IP_SEC_TOTAL = 1483,
    /** Format: `L` (Read-only) */
    CNTR_RX_IP_INSEC_TOTAL = 1484,
    /** Format: `L` (Read-only) */
    CNTR_RX_IP_DROPPED = 1485,
    /** Format: `L` (Read-only) */
    CNTR_TX_SPINEL_TOTAL = 1580,
    /** Format: `L` (Read-only) */
    CNTR_RX_SPINEL_TOTAL = 1581,
    /** Format: `L` (Read-only) */
    CNTR_RX_SPINEL_ERR = 1582,
    /** Format: `L` (Read-only) */
    CNTR_RX_SPINEL_OUT_OF_ORDER_TID = 1583,
    /** Format: `L` (Read-only) */
    CNTR_IP_TX_SUCCESS = 1584,
    /** Format: `L` (Read-only) */
    CNTR_IP_RX_SUCCESS = 1585,
    /** Format: `L` (Read-only) */
    CNTR_IP_TX_FAILURE = 1586,
    /** Format: `L` (Read-only) */
    CNTR_IP_RX_FAILURE = 1587,
    /** Format: `SSSSSSSSSSSSSSSS` (Read-only)
     *      `S`, (TotalBuffers)           The number of buffers in the pool.
     *      `S`, (FreeBuffers)            The number of free message buffers.
     *      `S`, (6loSendMessages)        The number of messages in the 6lo send queue.
     *      `S`, (6loSendBuffers)         The number of buffers in the 6lo send queue.
     *      `S`, (6loReassemblyMessages)  The number of messages in the 6LoWPAN reassembly queue.
     *      `S`, (6loReassemblyBuffers)   The number of buffers in the 6LoWPAN reassembly queue.
     *      `S`, (Ip6Messages)            The number of messages in the IPv6 send queue.
     *      `S`, (Ip6Buffers)             The number of buffers in the IPv6 send queue.
     *      `S`, (MplMessages)            The number of messages in the MPL send queue.
     *      `S`, (MplBuffers)             The number of buffers in the MPL send queue.
     *      `S`, (MleMessages)            The number of messages in the MLE send queue.
     *      `S`, (MleBuffers)             The number of buffers in the MLE send queue.
     *      `S`, (ArpMessages)            The number of messages in the ARP send queue.
     *      `S`, (ArpBuffers)             The number of buffers in the ARP send queue.
     *      `S`, (CoapMessages)           The number of messages in the CoAP send queue.
     *      `S`, (CoapBuffers)            The number of buffers in the CoAP send queue.
     */
    MSG_BUFFER_COUNTERS = 1680,
    /** Format: t(A(L))t(A(L))
     *
     * The contents include two structs, first one corresponds to
     * all transmit related MAC counters, second one provides the
     * receive related counters.
     *
     * The transmit structure includes:
     *
     *   'L': TxTotal                  (The total number of transmissions).
     *   'L': TxUnicast                (The total number of unicast transmissions).
     *   'L': TxBroadcast              (The total number of broadcast transmissions).
     *   'L': TxAckRequested           (The number of transmissions with ack request).
     *   'L': TxAcked                  (The number of transmissions that were acked).
     *   'L': TxNoAckRequested         (The number of transmissions without ack request).
     *   'L': TxData                   (The number of transmitted data).
     *   'L': TxDataPoll               (The number of transmitted data poll).
     *   'L': TxBeacon                 (The number of transmitted beacon).
     *   'L': TxBeaconRequest          (The number of transmitted beacon request).
     *   'L': TxOther                  (The number of transmitted other types of frames).
     *   'L': TxRetry                  (The number of retransmission times).
     *   'L': TxErrCca                 (The number of CCA failure times).
     *   'L': TxErrAbort               (The number of frame transmission failures due to abort error).
     *   'L': TxErrBusyChannel         (The number of frames that were dropped due to a busy channel).
     *   'L': TxDirectMaxRetryExpiry   (The number of expired retransmission retries for direct message).
     *   'L': TxIndirectMaxRetryExpiry (The number of expired retransmission retries for indirect message).
     *
     * The receive structure includes:
     *
     *   'L': RxTotal                  (The total number of received packets).
     *   'L': RxUnicast                (The total number of unicast packets received).
     *   'L': RxBroadcast              (The total number of broadcast packets received).
     *   'L': RxData                   (The number of received data).
     *   'L': RxDataPoll               (The number of received data poll).
     *   'L': RxBeacon                 (The number of received beacon).
     *   'L': RxBeaconRequest          (The number of received beacon request).
     *   'L': RxOther                  (The number of received other types of frames).
     *   'L': RxAddressFiltered        (The number of received packets filtered by address filter
     *                                  (allowlist or denylist)).
     *   'L': RxDestAddrFiltered       (The number of received packets filtered by destination check).
     *   'L': RxDuplicated             (The number of received duplicated packets).
     *   'L': RxErrNoFrame             (The number of received packets with no or malformed content).
     *   'L': RxErrUnknownNeighbor     (The number of received packets from unknown neighbor).
     *   'L': RxErrInvalidSrcAddr      (The number of received packets whose source address is invalid).
     *   'L': RxErrSec                 (The number of received packets with security error).
     *   'L': RxErrFcs                 (The number of received packets with FCS error).
     *   'L': RxErrOther               (The number of received packets with other error).
     *
     * Writing to this property with any value would reset all MAC counters to zero.
     */
    CNTR_ALL_MAC_COUNTERS = 1681,
    /** Format: `SSSSSSSSS`
     *
     *   'S': DisabledRole                  (The number of times device entered OT_DEVICE_ROLE_DISABLED role).
     *   'S': DetachedRole                  (The number of times device entered OT_DEVICE_ROLE_DETACHED role).
     *   'S': ChildRole                     (The number of times device entered OT_DEVICE_ROLE_CHILD role).
     *   'S': RouterRole                    (The number of times device entered OT_DEVICE_ROLE_ROUTER role).
     *   'S': LeaderRole                    (The number of times device entered OT_DEVICE_ROLE_LEADER role).
     *   'S': AttachAttempts                (The number of attach attempts while device was detached).
     *   'S': PartitionIdChanges            (The number of changes to partition ID).
     *   'S': BetterPartitionAttachAttempts (The number of attempts to attach to a better partition).
     *   'S': ParentChanges                 (The number of times device changed its parents).
     *
     * Writing to this property with any value would reset all MLE counters to zero.
     */
    CNTR_MLE_COUNTERS = 1682,
    /** Format: `t(LL)t(LL)`
     *
     * The contents include two structs, first one corresponds to
     * all transmit related MAC counters, second one provides the
     * receive related counters.
     *
     * The transmit structure includes:
     *   'L': TxSuccess (The number of IPv6 packets successfully transmitted).
     *   'L': TxFailure (The number of IPv6 packets failed to transmit).
     *
     * The receive structure includes:
     *   'L': RxSuccess (The number of IPv6 packets successfully received).
     *   'L': RxFailure (The number of IPv6 packets failed to receive).
     *
     * Writing to this property with any value would reset all IPv6 counters to zero.
     */
    CNTR_ALL_IP_COUNTERS = 1683,
    /** Format: t(A(L))t(A(L))
     *
     * Required capability: SPINEL_CAP_MAC_RETRY_HISTOGRAM
     *
     * The contents include two structs, first one is histogram which corresponds to retransmissions number of direct
     * messages, second one provides the histogram of retransmissions for indirect messages.
     *
     * The first structure includes:
     *   'L': DirectRetry[0]                   (The number of packets after 0 retry).
     *   'L': DirectRetry[1]                   (The number of packets after 1 retry).
     *    ...
     *   'L': DirectRetry[n]                   (The number of packets after n retry).
     *
     * The size of the array is OPENTHREAD_CONFIG_MAC_RETRY_SUCCESS_HISTOGRAM_MAX_SIZE_COUNT_DIRECT.
     *
     * The second structure includes:
     *   'L': IndirectRetry[0]                   (The number of packets after 0 retry).
     *   'L': IndirectRetry[1]                   (The number of packets after 1 retry).
     *    ...
     *   'L': IndirectRetry[m]                   (The number of packets after m retry).
     *
     * The size of the array is OPENTHREAD_CONFIG_MAC_RETRY_SUCCESS_HISTOGRAM_MAX_SIZE_COUNT_INDIRECT.
     *
     * Writing to this property with any value would reset MAC retry histogram.
     */
    CNTR_MAC_RETRY_HISTOGRAM = 1684,
    /** Format: `CCddd`.
     *
     *  `C`: MAC key ID mode
     *  `C`: MAC key ID
     *  `d`: previous MAC key material data
     *  `d`: current MAC key material data
     *  `d`: next MAC key material data
     *
     * The Spinel property is used to set/get MAC key materials to and from RCP.
     */
    RCP_MAC_KEY = 2048,
    /** Format: `L` for read and `Lb` or `L` for write
     *
     *  `L`: MAC frame counter
     *  'b': Optional boolean used only during write. If not provided, `false` is assumed.
     *       If `true` counter is set only if the new value is larger than current value.
     *       If `false` the new value is set as frame counter independent of the current value.
     *
     * The Spinel property is used to set MAC frame counter to RCP.
     */
    RCP_MAC_FRAME_COUNTER = 2049,
    /** Format: `X`.
     *
     *  `X`: Spinel frame transmit timestamp
     *
     * The Spinel property is used to get timestamp from RCP to calculate host and RCP timer difference.
     */
    RCP_TIMESTAMP = 2050,
    /** Format: `SEC` (Write-only).
     *
     * `S`: Short address
     * `E`: Extended address
     * `C`: List of requested metric ids encoded as bit fields in single byte
     *
     *   +---------------+----+
     *   |    Metric     | Id |
     *   +---------------+----+
     *   | Received PDUs |  0 |
     *   | LQI           |  1 |
     *   | Link margin   |  2 |
     *   | RSSI          |  3 |
     *   +---------------+----+
     *
     * Enable/disable or update Enhanced-ACK Based Probing in radio for a specific Initiator.
     */
    RCP_ENH_ACK_PROBING = 2051,
    /** Format: `C`
     * Required capability: `SPINEL_CAP_NET_THREAD_1_2`
     *
     * The current CSL rx/tx scheduling drift, in units of ± ppm.
     */
    RCP_CSL_ACCURACY = 2052,
    /** Format: `C`
     * Required capability: `SPINEL_CAP_NET_THREAD_1_2`
     *
     * The current uncertainty, in units of 10 us, of the clock used for scheduling CSL operations.
     */
    RCP_CSL_UNCERTAINTY = 2053,
    /** Format: `C`
     * Type: Read-Write
     *
     * `C`: b[0-1] - Interface id.
     *      b[7]   - 1: Complete pending radio operation, 0: immediate(force) switch.
     *
     * This feature gets or sets the radio interface to be used in multipan configuration
     *
     * Default value: 0
     */
    MULTIPAN_ACTIVE_INTERFACE = 2304,
    /** Format: `LbA(6)`
     * Type: Write
     *
     * `L`: The infrastructure interface index.
     * `b`: If the infrastructure interface is running.
     * `A(6)`: The IPv6 addresses of the infrastructure interface.
     *
     * If the InfraIf hasn't been set up on NCP or the InfraIf changes, NCP will re-initialize
     * the border routing module. NCP will compare the infrastructure interface index and decide
     * whether to re-initialize the border routing module. Otherwise, NCP will simply update the
     * InfraIf state and addresses.
     */
    INFRA_IF_STATE = 2321,
    /** Format: `L6d`
     * Type: Write-only
     *
     * `L`: The infrastructure interface index.
     * `6`: The IP6 source address of the ICMPv6 packet.
     * `d`: The data of the ICMPv6 packet. The host MUST ensure the hoplimit is 255.
     */
    INFRA_IF_RECV_ICMP6 = 2322,
    /** Format: `L6d`
     * Type: Unsolicited notifications only
     *
     * `L`: The infrastructure interface index.
     * `6`: The IP6 destination address of the message to send.
     * `d`: The data of the message to send.
     */
    INFRA_IF_SEND_ICMP6 = 2323,
    /** Format `b`
     * Type: Read-Write
     *
     * `b`: Whether to enable or disable the SRP server.
     */
    SRP_SERVER_ENABLED = 2337,
    /** Format `b`
     * Type: Read-Write
     *
     * `b`: A boolean that indicates the SRP server auto enable mode.
     */
    SRP_SERVER_AUTO_ENABLE_MODE = 2338,
    /** Format `C`: Write-only
     *
     * `C`: The dnssd state.
     */
    DNSSD_STATE = 2353,
    /** Format `CLD`: Write
     *
     * `C` : The result of the request. A unsigned int8 corresponds to otError.
     * `L` : The Dnssd Request ID.
     * `D` : The context of the request. (A pointer to the callback for the request)
     *
     * Host uses this property to notify the NCP of the result of NCP's DNS-SD request.
     */
    DNSSD_REQUEST_RESULT = 2354,
    /** Format `USA(6)LD`: Inserted/Removed
     *
     * `U`    : The host name.
     * `S`    : The count of IPv6 addresses.
     * `A(6)` : The IPv6 addresses of the host.
     * `L`    : The Dnssd Request ID.
     * `D`    : The context of the request. (A pointer to the callback for the request)
     *
     * NCP uses this property to register/unregister a DNS-SD host.
     */
    DNSSD_HOST = 2355,
    /**
     * Format `UUUt(A(U))dSSSSLD`: Inserted/Removed
     *
     * `U`       : The host name (does not include domain name).
     * `U`       : The service instance name label (not the full name).
     * `U`       : The service type (e.g., "_mt._udp", does not include domain name).
     * `t(A(U))` : Array of sub-type labels (can be empty array if no label).
     * `d`       : Encoded TXT data bytes.
     * `S`       : The service port number.
     * `S`       : The service priority.
     * `S`       : The service weight.
     * `L`       : The service TTL in seconds.
     * `L`       : The Dnssd Request ID.
     * `D`       : The context of the request. (A pointer to the callback for the request)
     *
     * NCP uses this property to register/unregister a DNS-SD service.
     */
    DNSSD_SERVICE = 2356,
    /**
     * Format `Ut(U)dSSLD`: Inserted/Removed
     *
     * `U`    : A host or a service instance name (does not include domain name).
     * `t(U)` : The service type if key is for a service (does not include domain name).
     * `d`    : Byte array containing the key record data.
     * `S`    : The resource record class.
     * `L`    : The TTL in seconds.
     * `L`    : The Dnssd Request ID.
     * `D`    : The context of the request. (A pointer to the callback for the request)
     *
     * NCP uses this property to register/unregister a DNS-SD key record.
     */
    DNSSD_KEY_RECORD = 2357,
    NEST_STREAM_MFG = 15296,
    /** Format: 'D'
     *
     * This property is deprecated.
     */
    NEST_LEGACY_ULA_PREFIX = 15297,
    /** Format: 'E'
     *
     * This property is deprecated.
     */
    NEST_LEGACY_LAST_NODE_JOINED = 15298,
    /** Format: 'b' (read-only)
     *
     * Reading this property will cause an assert on the NCP. This is intended for testing the assert functionality of
     * underlying platform/NCP. Assert should ideally cause the NCP to reset, but if this is not supported a `false`
     * boolean is returned in response.
     */
    DEBUG_TEST_ASSERT = 16384,
    /** Format: `C` */
    DEBUG_NCP_LOG_LEVEL = 16385,
    /** Format: Empty  (read-only)
     *
     * Reading this property will causes NCP to start a `while(true) ;` loop and thus triggering a watchdog.
     *
     * This is intended for testing the watchdog functionality on the underlying platform/NCP.
     */
    DEBUG_TEST_WATCHDOG = 16386,
    /** Format: X (write-only)
     *
     * This property controls the time base value that is used for logs timestamp field calculation.
     */
    DEBUG_LOG_TIMESTAMP_BASE = 16387,
    /** Format `b` (read-write)
     *
     * This property is intended for testing TREL (Thread Radio Encapsulation Link) radio type only (during simulation).
     * It allows the TREL interface to be temporarily disabled and (re)enabled.  While disabled all traffic through
     * TREL interface is dropped silently (to emulate a radio/interface down scenario).
     *
     * This property is only available when the TREL radio link type is supported.
     */
    DEBUG_TREL_TEST_MODE_ENABLE = 16388
}
