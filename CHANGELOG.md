# Changelog

## Unreleased

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
