# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2020-09-30

### Added
- Add option to use an API URL instead of host and port
- Add option to limit the number of separate check results that will be printed to the check output

### Changed
- Check and entity labels options in the plugin relate to the check and entity names in Sensu Go
- When the user provides entity labels, events are collected using separate API calls based on entity and check names
- Changes the check output to show the result of each separete check, limited to a number of checks

## [0.1.4] - 2020-04-28

### Changed
- Fix slice out of bounds error

## [0.1.3] - 2020-04-21

### Changed
- Fixed GitHub release to use sha512 checksums
- Offer better error failure messages, necessary for debugging deployments

## [0.1.2] - 2020-04-13

### Changed
- Fixed GitHub release to build with Golang 1.14.x

## [0.1.1] - 2020-04-13

### Changed
- Fixed goreleaser

## [0.1.0] - 2020-04-13

### Added
- Add options to support secure API connections
- Add support for using API key in place of username/password

### Changed
- Move to the new Sensu SDK
- Move to Go modules
- Move from Travis to GitHub actions

## [0.0.7] - 2019-08-14

### Added

Open sourced this Asset.

## [0.0.6] - 2019-03-22

### Fixed
- Fixed readme markdown for Bonsai

## [0.0.5] - 2019-03-22

### Added
- Added an OK STDOUT message ("Everything is OK")

## [0.0.4] - 2019-03-22

### Fixed
- Fixed percent calculation

## [0.0.3] - 2019-03-22

### Fixed
- Fixed build tars, added a goreleaser config

## [0.0.2] - 2019-03-21

### Added
- Releasing to Bonsai

## [0.0.1] - 2019-03-21

### Added
- Initial release
