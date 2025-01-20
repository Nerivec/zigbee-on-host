export const enum SpinelCommandId {
    /**
     * No-Operation command (Host -> NCP)
     *
     * Encoding: Empty
     *
     * Induces the NCP to send a success status back to the host. This is
     * primarily used for liveliness checks. The command payload for this
     * command SHOULD be empty.
     *
     * There is no error condition for this command.
     */
    NOOP = 0,

    /**
     * Reset NCP command (Host -> NCP)
     *
     * Encoding: Empty or `C`
     *
     * Causes the NCP to perform a software reset. Due to the nature of
     * this command, the TID is ignored. The host should instead wait
     * for a `CMD_PROP_VALUE_IS` command from the NCP indicating
     * `PROP_LAST_STATUS` has been set to `STATUS_RESET_SOFTWARE`.
     *
     * The optional command payload specifies the reset type, can be
     * `SPINEL_RESET_PLATFORM`, `SPINEL_RESET_STACK`, or
     * `SPINEL_RESET_BOOTLOADER`.
     *
     * Defaults to stack reset if unspecified.
     *
     * If an error occurs, the value of `PROP_LAST_STATUS` will be emitted
     * instead with the value set to the generated status code for the error.
     */
    RESET = 1,

    /**
     * Get property value command (Host -> NCP)
     *
     * Encoding: `i`
     *   `i` : Property Id
     *
     * Causes the NCP to emit a `CMD_PROP_VALUE_IS` command for the
     * given property identifier.
     *
     * The payload for this command is the property identifier encoded
     * in the packed unsigned integer format `i`.
     *
     * If an error occurs, the value of `PROP_LAST_STATUS` will be emitted
     * instead with the value set to the generated status code for the error.
     */
    PROP_VALUE_GET = 2,

    /**
     * Set property value command (Host -> NCP)
     *
     * Encoding: `iD`
     *   `i` : Property Id
     *   `D` : Value (encoding depends on the property)
     *
     * Instructs the NCP to set the given property to the specific given
     * value, replacing any previous value.
     *
     * The payload for this command is the property identifier encoded in the
     * packed unsigned integer format, followed by the property value. The
     * exact format of the property value is defined by the property.
     *
     * On success a `CMD_PROP_VALUE_IS` command is emitted either for the
     * given property identifier with the set value, or for `PROP_LAST_STATUS`
     * with value `LAST_STATUS_OK`.
     *
     * If an error occurs, the value of `PROP_LAST_STATUS` will be emitted
     * with the value set to the generated status code for the error.
     */
    PROP_VALUE_SET = 3,

    /**
     * Insert value into property command (Host -> NCP)
     *
     * Encoding: `iD`
     *   `i` : Property Id
     *   `D` : Value (encoding depends on the property)
     *
     * Instructs the NCP to insert the given value into a list-oriented
     * property without removing other items in the list. The resulting order
     * of items in the list is defined by the individual property being
     * operated on.
     *
     * The payload for this command is the property identifier encoded in the
     * packed unsigned integer format, followed by the value to be inserted.
     * The exact format of the value is defined by the property.
     *
     * If the type signature of the property consists of a single structure
     * enclosed by an array `A(t(...))`, then the contents of value MUST
     * contain the contents of the structure (`...`) rather than the
     * serialization of the whole item (`t(...)`).  Specifically, the length
     * of the structure MUST NOT be prepended to value. This helps to
     * eliminate redundant data.
     *
     * On success, either a `CMD_PROP_VALUE_INSERTED` command is emitted for
     * the given property, or a `CMD_PROP_VALUE_IS` command is emitted of
     * property `PROP_LAST_STATUS` with value `LAST_STATUS_OK`.
     *
     * If an error occurs, the value of `PROP_LAST_STATUS` will be emitted
     * with the value set to the generated status code for the error.
     */
    PROP_VALUE_INSERT = 4,

    /**
     * Remove value from property command (Host -> NCP)
     *
     * Encoding: `iD`
     *   `i` : Property Id
     *   `D` : Value (encoding depends on the property)

     * Instructs the NCP to remove the given value from a list-oriented property,
     * without affecting other items in the list. The resulting order of items
     * in the list is defined by the individual property being operated on.
     *
     * Note that this command operates by value, not by index!
     *
     * The payload for this command is the property identifier encoded in the
     * packed unsigned integer format, followed by the value to be removed. The
     * exact format of the value is defined by the property.
     *
     * If the type signature of the property consists of a single structure
     * enclosed by an array `A(t(...))`, then the contents of value MUST contain
     * the contents of the structure (`...`) rather than the serialization of the
     * whole item (`t(...)`).  Specifically, the length of the structure MUST NOT
     * be prepended to `VALUE`. This helps to eliminate redundant data.
     *
     * On success, either a `CMD_PROP_VALUE_REMOVED` command is emitted for the
     * given property, or a `CMD_PROP_VALUE_IS` command is emitted of property
     * `PROP_LAST_STATUS` with value `LAST_STATUS_OK`.
     *
     * If an error occurs, the value of `PROP_LAST_STATUS` will be emitted
     * with the value set to the generated status code for the error.
     */
    PROP_VALUE_REMOVE = 5,

    /**
     * Property value notification command (NCP -> Host)
     *
     * Encoding: `iD`
     *   `i` : Property Id
     *   `D` : Value (encoding depends on the property)
     *
     * This command can be sent by the NCP in response to a previous command
     * from the host, or it can be sent by the NCP in an unsolicited fashion
     * to notify the host of various state changes asynchronously.
     *
     * The payload for this command is the property identifier encoded in the
     * packed unsigned integer format, followed by the current value of the
     * given property.
     */
    PROP_VALUE_IS = 6,

    /**
     * Property value insertion notification command (NCP -> Host)
     *
     * Encoding:`iD`
     *   `i` : Property Id
     *   `D` : Value (encoding depends on the property)
     *
     * This command can be sent by the NCP in response to the
     * `CMD_PROP_VALUE_INSERT` command, or it can be sent by the NCP in an
     * unsolicited fashion to notify the host of various state changes
     * asynchronously.
     *
     * The payload for this command is the property identifier encoded in the
     * packed unsigned integer format, followed by the value that was inserted
     * into the given property.
     *
     * If the type signature of the property specified by property id consists
     * of a single structure enclosed by an array (`A(t(...))`), then the
     * contents of value MUST contain the contents of the structure (`...`)
     * rather than the serialization of the whole item (`t(...)`). Specifically,
     * the length of the structure MUST NOT be prepended to `VALUE`. This
     * helps to eliminate redundant data.
     *
     * The resulting order of items in the list is defined by the given
     * property.
     */
    PROP_VALUE_INSERTED = 7,

    /**
     * Property value removal notification command (NCP -> Host)
     *
     * Encoding: `iD`
     *   `i` : Property Id
     *   `D` : Value (encoding depends on the property)
     *
     * This command can be sent by the NCP in response to the
     * `CMD_PROP_VALUE_REMOVE` command, or it can be sent by the NCP in an
     * unsolicited fashion to notify the host of various state changes
     * asynchronously.
     *
     * Note that this command operates by value, not by index!
     *
     * The payload for this command is the property identifier encoded in the
     * packed unsigned integer format described in followed by the value that
     * was removed from the given property.
     *
     * If the type signature of the property specified by property id consists
     * of a single structure enclosed by an array (`A(t(...))`), then the
     * contents of value MUST contain the contents of the structure (`...`)
     * rather than the serialization of the whole item (`t(...)`).  Specifically,
     * the length of the structure MUST NOT be prepended to `VALUE`. This
     * helps to eliminate redundant data.
     *
     * The resulting order of items in the list is defined by the given
     * property.
     */
    PROP_VALUE_REMOVED = 8,

    NET_SAVE = 9, // Deprecated

    /**
     * Clear saved network settings command (Host -> NCP)
     *
     * Encoding: Empty
     *
     * Erases all network credentials and state from non-volatile memory.
     *
     * This operation affects non-volatile memory only. The current network
     * information stored in volatile memory is unaffected.
     *
     * The response to this command is always a `CMD_PROP_VALUE_IS` for
     * `PROP_LAST_STATUS`, indicating the result of the operation.
     */
    NET_CLEAR = 10,

    NET_RECALL = 11, // Deprecated

    /**
     * Host buffer offload is an optional NCP capability that, when
     * present, allows the NCP to store data buffers on the host processor
     * that can be recalled at a later time.
     *
     * The presence of this feature can be detected by the host by
     * checking for the presence of the `CAP_HBO`
     * capability in `PROP_CAPS`.
     *
     * This feature is not currently supported on OpenThread.
     */

    HBO_OFFLOAD = 12,
    HBO_RECLAIM = 13,
    HBO_DROP = 14,
    HBO_OFFLOADED = 15,
    HBO_RECLAIMED = 16,
    HBO_DROPPED = 17,

    /**
     * Peek command (Host -> NCP)
     *
     * Encoding: `LU`
     *   `L` : The address to peek
     *   `U` : Number of bytes to read
     *
     * This command allows the NCP to fetch values from the RAM of the NCP
     * for debugging purposes. Upon success, `CMD_PEEK_RET` is sent from the
     * NCP to the host. Upon failure, `PROP_LAST_STATUS` is emitted with
     * the appropriate error indication.
     *
     * The NCP MAY prevent certain regions of memory from being accessed.
     *
     * This command requires the capability `CAP_PEEK_POKE` to be present.
     */
    PEEK = 18,

    /**
     * Peek return command (NCP -> Host)
     *
     * Encoding: `LUD`
     *   `L` : The address peeked
     *   `U` : Number of bytes read
     *   `D` : Memory content
     *
     * This command contains the contents of memory that was requested by
     * a previous call to `CMD_PEEK`.
     *
     * This command requires the capability `CAP_PEEK_POKE` to be present.
     */
    PEEK_RET = 19,

    /**
     * Poke command (Host -> NCP)
     *
     * Encoding: `LUD`
     *   `L` : The address to be poked
     *   `U` : Number of bytes to write
     *   `D` : Content to write
     *
     * This command writes the bytes to the specified memory address
     * for debugging purposes.
     *
     * This command requires the capability `CAP_PEEK_POKE` to be present.
     */
    POKE = 20,

    PROP_VALUE_MULTI_GET = 21,
    PROP_VALUE_MULTI_SET = 22,
    PROP_VALUES_ARE = 23,
}
