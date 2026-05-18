"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpinelStatus = void 0;
var SpinelStatus;
(function (SpinelStatus) {
    /** Operation has completed successfully. */
    SpinelStatus[SpinelStatus["OK"] = 0] = "OK";
    /** Operation has failed for some undefined reason. */
    SpinelStatus[SpinelStatus["FAILURE"] = 1] = "FAILURE";
    /** Given operation has not been implemented. */
    SpinelStatus[SpinelStatus["UNIMPLEMENTED"] = 2] = "UNIMPLEMENTED";
    /** An argument to the operation is invalid. */
    SpinelStatus[SpinelStatus["INVALID_ARGUMENT"] = 3] = "INVALID_ARGUMENT";
    /** This operation is invalid for the current device state. */
    SpinelStatus[SpinelStatus["INVALID_STATE"] = 4] = "INVALID_STATE";
    /** This command is not recognized. */
    SpinelStatus[SpinelStatus["INVALID_COMMAND"] = 5] = "INVALID_COMMAND";
    /** This interface is not supported. */
    SpinelStatus[SpinelStatus["INVALID_INTERFACE"] = 6] = "INVALID_INTERFACE";
    /** An internal runtime error has occurred. */
    SpinelStatus[SpinelStatus["INTERNAL_ERROR"] = 7] = "INTERNAL_ERROR";
    /** A security/authentication error has occurred. */
    SpinelStatus[SpinelStatus["SECURITY_ERROR"] = 8] = "SECURITY_ERROR";
    /** A error has occurred while parsing the command. */
    SpinelStatus[SpinelStatus["PARSE_ERROR"] = 9] = "PARSE_ERROR";
    /** This operation is in progress. */
    SpinelStatus[SpinelStatus["IN_PROGRESS"] = 10] = "IN_PROGRESS";
    /** Operation prevented due to memory pressure. */
    SpinelStatus[SpinelStatus["NOMEM"] = 11] = "NOMEM";
    /** The device is currently performing a mutually exclusive operation */
    SpinelStatus[SpinelStatus["BUSY"] = 12] = "BUSY";
    /** The given property is not recognized. */
    SpinelStatus[SpinelStatus["PROP_NOT_FOUND"] = 13] = "PROP_NOT_FOUND";
    /** A/The packet was dropped. */
    SpinelStatus[SpinelStatus["DROPPED"] = 14] = "DROPPED";
    /** The result of the operation is empty. */
    SpinelStatus[SpinelStatus["EMPTY"] = 15] = "EMPTY";
    /** The command was too large to fit in the internal buffer. */
    SpinelStatus[SpinelStatus["CMD_TOO_BIG"] = 16] = "CMD_TOO_BIG";
    /** The packet was not acknowledged. */
    SpinelStatus[SpinelStatus["NO_ACK"] = 17] = "NO_ACK";
    /** The packet was not sent due to a CCA failure. */
    SpinelStatus[SpinelStatus["CCA_FAILURE"] = 18] = "CCA_FAILURE";
    /** The operation is already in progress. */
    SpinelStatus[SpinelStatus["ALREADY"] = 19] = "ALREADY";
    /** The given item could not be found. */
    SpinelStatus[SpinelStatus["ITEM_NOT_FOUND"] = 20] = "ITEM_NOT_FOUND";
    /** The given command cannot be performed on this property. */
    SpinelStatus[SpinelStatus["INVALID_COMMAND_FOR_PROP"] = 21] = "INVALID_COMMAND_FOR_PROP";
    /** The neighbor is unknown. */
    SpinelStatus[SpinelStatus["UNKNOWN_NEIGHBOR"] = 22] = "UNKNOWN_NEIGHBOR";
    /** The target is not capable of handling requested operation. */
    SpinelStatus[SpinelStatus["NOT_CAPABLE"] = 23] = "NOT_CAPABLE";
    /** No response received from remote node */
    SpinelStatus[SpinelStatus["RESPONSE_TIMEOUT"] = 24] = "RESPONSE_TIMEOUT";
    /** Radio interface switch completed successfully (SPINEL_PROP_MULTIPAN_ACTIVE_INTERFACE) */
    SpinelStatus[SpinelStatus["SWITCHOVER_DONE"] = 25] = "SWITCHOVER_DONE";
    /** Radio interface switch failed (SPINEL_PROP_MULTIPAN_ACTIVE_INTERFACE) */
    SpinelStatus[SpinelStatus["SWITCHOVER_FAILED"] = 26] = "SWITCHOVER_FAILED";
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
    SpinelStatus[SpinelStatus["JOIN_FAILURE"] = 104] = "JOIN_FAILURE";
    /**
     * The node found other peers but was unable to decode their packets.
     *
     *  Typically this error code indicates that the network
     *  key has been set incorrectly.
     *
     *  \sa SPINEL_PROP_NET_REQUIRE_JOIN_EXISTING
     *  \sa SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING
     */
    SpinelStatus[SpinelStatus["JOIN_SECURITY"] = 105] = "JOIN_SECURITY";
    /**
     * The node was unable to find any other peers on the network.
     *
     *  \sa SPINEL_PROP_NET_REQUIRE_JOIN_EXISTING
     *  \sa SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING
     */
    SpinelStatus[SpinelStatus["JOIN_NO_PEERS"] = 106] = "JOIN_NO_PEERS";
    /**
     * The only potential peer nodes found are incompatible.
     *
     *  \sa SPINEL_PROP_NET_REQUIRE_JOIN_EXISTING
     */
    SpinelStatus[SpinelStatus["JOIN_INCOMPATIBLE"] = 107] = "JOIN_INCOMPATIBLE";
    /**
     * No response in expecting time.
     *
     *  \sa SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING
     */
    SpinelStatus[SpinelStatus["JOIN_RSP_TIMEOUT"] = 108] = "JOIN_RSP_TIMEOUT";
    /**
     * The node succeeds in commissioning and get the network credentials.
     *
     *  \sa SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING
     */
    SpinelStatus[SpinelStatus["JOIN_SUCCESS"] = 109] = "JOIN_SUCCESS";
    SpinelStatus[SpinelStatus["RESET_POWER_ON"] = 112] = "RESET_POWER_ON";
    SpinelStatus[SpinelStatus["RESET_EXTERNAL"] = 113] = "RESET_EXTERNAL";
    SpinelStatus[SpinelStatus["RESET_SOFTWARE"] = 114] = "RESET_SOFTWARE";
    SpinelStatus[SpinelStatus["RESET_FAULT"] = 115] = "RESET_FAULT";
    SpinelStatus[SpinelStatus["RESET_CRASH"] = 116] = "RESET_CRASH";
    SpinelStatus[SpinelStatus["RESET_ASSERT"] = 117] = "RESET_ASSERT";
    SpinelStatus[SpinelStatus["RESET_OTHER"] = 118] = "RESET_OTHER";
    SpinelStatus[SpinelStatus["RESET_UNKNOWN"] = 119] = "RESET_UNKNOWN";
    SpinelStatus[SpinelStatus["RESET_WATCHDOG"] = 120] = "RESET_WATCHDOG";
})(SpinelStatus || (exports.SpinelStatus = SpinelStatus = {}));
//# sourceMappingURL=statuses.js.map