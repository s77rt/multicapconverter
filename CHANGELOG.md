# Changelog

All notable changes to this project (multicapconverter) will be documented in this file.

## [0.1.7] - 29/01/2020
### Added
- Export as hccap (--export hccap) (hashcat mode = 2500 (legacy))

## [0.1.6] - 18/01/2020
### Fixed
- Errors were not being reported

### Added
- --ignore-ts option (Ignore timestamps check)

## [0.1.5] - 16/01/2020
### Changed
- PMKIDs found in EAPOL-M1 won't be exported unless the user specify the --ignore-ie option

### Added
- --ignore-ie option (Ignore information element (AKM Check))

## [0.1.4] - 14/01/2020
### Fixed
- PMKIDs were not being exported if the station that holds those pmkids have no other M1,M2,M3,M4 frames captured

### Added
- --do-not-clean option

## [0.1.3] - 12/01/2020
### Fixed
- Some PMKIDs in (RE)ASSOC_REQ where not being extracted properly

### Added
- Extract PMKIDs from EAPOL-M2

## [0.1.2] - 08/01/2020
### Fixed
- Windows multiprocessing compatibility issue(s)

## [0.1.1] - 05/01/2020
### Added
- New export format hcpmkid (hashcat mode: 16800)

## [0.1.0] - 29/12/2019
- Initial Release
___
Date format: DD/MM/YYYY
