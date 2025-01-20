export enum SpinelStatus {
    /** Operation has completed successfully. */
    OK = 0,
    /** Operation has failed for some undefined reason. */
    FAILURE = 1,
    /** Given operation has not been implemented. */
    UNIMPLEMENTED = 2,
    /** An argument to the operation is invalid. */
    INVALID_ARGUMENT = 3,
    /** This operation is invalid for the current device state. */
    INVALID_STATE = 4,
    /** This command is not recognized. */
    INVALID_COMMAND = 5,
    /** This interface is not supported. */
    INVALID_INTERFACE = 6,
    /** An internal runtime error has occurred. */
    INTERNAL_ERROR = 7,
    /** A security/authentication error has occurred. */
    SECURITY_ERROR = 8,
    /** A error has occurred while parsing the command. */
    PARSE_ERROR = 9,
    /** This operation is in progress. */
    IN_PROGRESS = 10,
    /** Operation prevented due to memory pressure. */
    NOMEM = 11,
    /** The device is currently performing a mutually exclusive operation */
    BUSY = 12,
    /** The given property is not recognized. */
    PROP_NOT_FOUND = 13,
    /** A/The packet was dropped. */
    DROPPED = 14,
    /** The result of the operation is empty. */
    EMPTY = 15,
    /** The command was too large to fit in the internal buffer. */
    CMD_TOO_BIG = 16,
    /** The packet was not acknowledged. */
    NO_ACK = 17,
    /** The packet was not sent due to a CCA failure. */
    CCA_FAILURE = 18,
    /** The operation is already in progress. */
    ALREADY = 19,
    /** The given item could not be found. */
    ITEM_NOT_FOUND = 20,
    /** The given command cannot be performed on this property. */
    INVALID_COMMAND_FOR_PROP = 21,
    /** The neighbor is unknown. */
    UNKNOWN_NEIGHBOR = 22,
    /** The target is not capable of handling requested operation. */
    NOT_CAPABLE = 23,
    /** No response received from remote node */
    RESPONSE_TIMEOUT = 24,
    /** Radio interface switch completed successfully (SPINEL_PROP_MULTIPAN_ACTIVE_INTERFACE) */
    SWITCHOVER_DONE = 25,
    /** Radio interface switch failed (SPINEL_PROP_MULTIPAN_ACTIVE_INTERFACE) */
    SWITCHOVER_FAILED = 26,

    /**
     * Generic failure to associate with other peers.
     *
     *  This status error should not be used by implementers if
     *  enough information is available to determine that one of the
     *  later join failure status codes would be more accurate.
     *
     *  \sa SPINEL_PROP_NET_REQUIRE_JOIN_EXISTING
     *  \sa SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING
     */
    JOIN_FAILURE = 104,

    /**
     * The node found other peers but was unable to decode their packets.
     *
     *  Typically this error code indicates that the network
     *  key has been set incorrectly.
     *
     *  \sa SPINEL_PROP_NET_REQUIRE_JOIN_EXISTING
     *  \sa SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING
     */
    JOIN_SECURITY = 105,

    /**
     * The node was unable to find any other peers on the network.
     *
     *  \sa SPINEL_PROP_NET_REQUIRE_JOIN_EXISTING
     *  \sa SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING
     */
    JOIN_NO_PEERS = 106,

    /**
     * The only potential peer nodes found are incompatible.
     *
     *  \sa SPINEL_PROP_NET_REQUIRE_JOIN_EXISTING
     */
    JOIN_INCOMPATIBLE = 107,

    /**
     * No response in expecting time.
     *
     *  \sa SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING
     */
    JOIN_RSP_TIMEOUT = 108,

    /**
     * The node succeeds in commissioning and get the network credentials.
     *
     *  \sa SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING
     */
    JOIN_SUCCESS = 109,

    RESET_POWER_ON = 112,
    RESET_EXTERNAL = 113,
    RESET_SOFTWARE = 114,
    RESET_FAULT = 115,
    RESET_CRASH = 116,
    RESET_ASSERT = 117,
    RESET_OTHER = 118,
    RESET_UNKNOWN = 119,
    RESET_WATCHDOG = 120,
}
