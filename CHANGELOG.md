# Changelog

## [0.6.2] - 2020-10-18

### Changed

- Lowered priority of non-essential, protocol-related and internal log messages (#53).

### Fixed

- Do not use PID in Netlink sockets in order to avoid issues with duplicated PIDs, e.g., when Docker is used.
- Prevent exceptions due to invalid incoming messages.
- HTTP server address family wrong when interface address is added (#62)
- Error when interface address is removed (#62)

## [0.6.1] - 2020-06-28

### Fixed

- Error when unknown interface index is received from Netlink socket on Linux (#45)
- HTTP requests not passed to wsdd, preventing hosts to be discovered (#49)

## [0.6] - 2020-06-06

### Added

- Discovery mode to search for other hosts with Windows, wsdd, or compatible services
- Socket-based API to query and manipulate the discovered hosts
- Documentation on installation for some distros.

### Changed

- Addresses are not only enumerated on startup, but changes to addresses are also dynamically handled
- The program does not stop anymore when no IP address is available (see Fixes as well)
- Code significantly refactored

### Fixed

- Running at system startup without IP address does not cause wsdd to terminate anymore
- Support international domain names when `chroot`ing (#44)
- Skip empty routing attribute returned from Netlink socket (#42)
- Correct handling of invalid messages (#43)
