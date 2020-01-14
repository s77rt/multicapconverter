# Changelog

All notable changes to this project (multicapconverter) will be documented in this file.

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
