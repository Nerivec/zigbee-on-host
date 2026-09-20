# Contributing

> [!NOTE]
> Contributions get harder to review with increased size, and the potential for breaks increases drastically.
> Try to keep contributions on same aspect, and as small as possible.
> For larger contributions, split into multiple pull requests when possible.

> [!IMPORTANT]
> On the use of AI:
> - AI-aided: OK - understanding a pull request's goal/changes is a must
> - AI-coded: NO - will be ignored/rejected

## Guidelines

Some quick guidelines to keep the codebase maintainable:

- No external production dependencies
- Mark `TODO` / `XXX` / `@deprecated` in code as needed for quick access
- Performance in mind (with the goal to eventually bring the appropriate layers to a lower language as needed)
  - No expensive calls (stringify, etc.)
  - Bail as early as possible (no unnecessary parsing, holding waiters, etc.)
  - Ability to no-op expensive "optional" features
  - And the usuals...
- Keep MAC/Zigbee property naming mostly in line with Wireshark for easier debugging
- Keep in line with the Zigbee 3.0 specification, but allow optimization due to the host-driven nature and removal of unnecessary features that won't impact compatibility
- Focus on "Centralized Trust Center" implementation (at least at first)
