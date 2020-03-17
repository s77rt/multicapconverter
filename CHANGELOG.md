# Changelog

All notable changes to this project (multicapconverter) will be documented in this file.

## [0.2.1] - 17/03/2020
### Fixed
- LE/BE/NC detection issues
- EAPOL messages with zeroed nonce weren't being counted
- EAPOL messages with duplicated data were being skipped

### Changed
- Packets with mismatched replay counter will be ignored

### Added
- Time Gap calculations for better analysis

## [0.2.0] - 16/03/2020
### Fixed
- Incorrect timestamps extraction for pcapng
- Incorrect timestamps resolutions check for pcapng

### Added
- Extract wordlist / AP-LESS possible passwords option (--wordlist wordlist)
- Better info about each network

## [0.1.9] - 05/02/2020
### Fixed
- Incorrect auth packet size calculation

## [0.1.8] - 01/02/2020
### Changed
- PMKIDs that are not PSK/PSK256 related won't be exported unless the user specify the --ignore-ie option
- PMKIDs found in EAPOL-M1 won't be exported unless the keyver is 1, 2 or 3 (or if the user specify the --ignore-ie option)

### Added
- Support for WPA3
- Export as hceapmd5 (--export hceapmd5) (hashcat mode = 4800)
- Export as hceapleap (--export hceapleap) (hashcat mode = 5500)

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
