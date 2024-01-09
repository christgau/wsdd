# Changelog

## Unreleased

### Added

- Support for OpenBSD (tested on riscv64 with OpenBSD 7.4)
- Configuration files for firewalld (#186). Thanks to Ondrej Holy.
- Show device type and allow filtering in API's `list` command (#189). Thanks to Ondrej Holy.
- Add option `--metadata-timeout` to set the timeout for the HTTP-based metadata exchange (closes #83)

### Changed

- The employed UUID is now read from `/etc/{machine-id,hostid}` before falling by back to the UUID derivation from the host name.

### Fixed

- Handle addresses with zone id by ignoring the interface part (#184)
- Do not crash with asyncio future when non-existing interface is provided (#201)

## [0.7.1] - 2023-03-04

### Added

- GitHub workflow for static analyses added (syntax, format, and type checks are performed).
- Added EnvironmentFile and according example for systemd-based distros.
- Make wsdd work (again) on MacOS (#139). Thanks to Eugene Gershnik.
- Application profile for UFW has been added (#169)

### Fixed

- Use of implicitly present async I/O loop instead created one for API servers. Fixes regression due to changed API in Python 3.10 (see #162)

### Changed

- Source code is spiced with type hints now.
- man page moved to section 8.

## [0.7.0] - 2021-11-20

### Added

- Using the server interface it is now possible to start and stop the host functionality (discoverable device) without terminating and restarting the daemon.

### Fixed

- Support multiple IP addresses in 'hello' messages from other hosts (#89)
- Support interfaces with IPv6-only configuration (#94)
- Re-enable 'probe' command of API (#116)
- Removed code marked as deprecated starting with Python 3.10.

### Changed

- The example systemd unit file now uses `DynamicUser` instead of the unsafe nobody:nobody combination.
  It also employs the rundir as chroot directory.
- Code changed to use asyncio instead of selector-based
- The server interface does not close connections after each command anymore.
- For the 'list' command of the server interface, the list of discovered devices is terminated with a line containing only a single dot ('.')
- Log device discovery only once per address and interface

## [0.6.4] - 2021-02-06

### Added

- Introduce `-v`/`--version` command line switch to show program version.

### Fixed

- HTTP status code 404 is sent in case of an non-existing path (#79).
- Data is now sent correctly again on FreeBSD as well as on Linux (#80).

### Changed

- Send HTTP 400 in case of wrong content type.

## [0.6.3] - 2021-01-10

### Added

- Include instructions for adding repository keys under Debian/Ubuntu in README.

### Fixed

- Skip Netlink messages smaller than 4 bytes correctly (#77, and maybe #59)
- Messages are sent via the correct socket to comply with the intended/specified message flow. This also eases the firewall configuration (#72).

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
