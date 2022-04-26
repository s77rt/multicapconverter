# multicapconverter.py
Tool used to Convert a cap/pcap/pcapng capture file to a hashcat hcwpax/hccapx/hccap/hcpmkid/hceapmd5/hceapleap file (re)written in Python (based on [c version]( https://github.com/hashcat/hashcat-utils/blob/master/src/cap2hccapx.c))
```
usage: multicapconverter.py [--input capture.pcapng]
                            [--export {hcwpax,hccapx,hccap,hcpmkid,hceapmd5,hceapleap}]
                            [--output capture.hcwpax] [--all] [--filter-by filter value]
                            [--group-by {none,bssid,essid,handshake}] [--ignore-ie]
                            [--ignore-ts] [--overwrite-essid ESSID] [--wordlist wordlist.txt]
                            [--do-not-clean] [--quiet] [--update-oui] [--about] [--version]
                            [--help]

Convert a cap/pcap/pcapng capture file to a hashcat
hcwpax/hccapx/hccap/hcpmkid/hceapmd5/hceapleap file

options:
  --input capture.pcapng, -i capture.pcapng
  --export {hcwpax,hccapx,hccap,hcpmkid,hceapmd5,hceapleap}, -x {hcwpax,hccapx,hccap,hcpmkid,hceapmd5,hceapleap}
  --output capture.hcwpax, -o capture.hcwpax

filter options:
  --all, -a             export all handshakes even unauthenticated ones
  --filter-by filter value, -f filter value
                        valid filters: bssid and essid
  --group-by {none,bssid,essid,handshake}, -g {none,bssid,essid,handshake}

advanced options:
  --ignore-ie           ignore information element (AKM Check) (Not Recommended)
  --ignore-ts           ignore timestamps check (Not Recommended)
  --overwrite-essid ESSID
                        overwrite ESSID tags (useful for cloaked ESSID) (DANGEROUS)

miscellaneous options:
  --wordlist wordlist.txt, -E wordlist.txt
                        extract wordlist / AP-LESS possible passwords (autohex enabled on non
                        ASCII characters)
  --do-not-clean        do not clean output
  --quiet, -q           enable quiet mode (print only output files/data)
  --update-oui          update OUI Database

info:
  --about               show program's about and exit
  --version, -v         show program's version number and exit
  --help, -h            show this help message and exit
```

## Features
- Supports cap/pcap/pcapng
- Supports combined cap/pcap/pcapng files
- Supports gz compressed cap/pcap/pcapng files
- Supports hcxdumptool
- Export as hccap (hashcat mode = 2500 (legacy))
- Export as hccapx (hashcat mode = 2500)
- Export as hcpmkid (hashcat mode = 16800)
- Export as hcwpax (hashcat mode = 22000)
- Export as hceapmd5 (hashcat mode = 4800)
- Export as hceapleap (hashcat mode = 5500)
- Export only authenticated handshakes or all handshakes
- Output files can be filtered/grouped
- Extract wordlist / AP-LESS possible passwords
- MAC Address Vendor Lookup

## Usage Examples
We have a capture file 'capture.cap' which includes 4 handshakes:

| # | BSSID             | ESSID    | AUTHENTICATED |
|---|-------------------|----------|---------------|
| 1 | 00:00:00:00:AA:AA | Wifi     |       N       |
| 2 | 00:00:00:00:AA:AA | Wifi     |       Y       |
| 3 | 00:00:00:00:BB:BB | Internet |       Y       |
| 4 | 00:00:00:00:CC:CC | Wifi     |       Y       |

#### 1) Extract each handshake into a separated file (Auth Only)
```
python multicapconverter.py -i capture.cap --group-by handshake -x hccapx
...
Output hccapx files:
00-00-00-00-AA-AA_0.hccapx // 2
00-00-00-00-BB-BB_0.hccapx // 3
00-00-00-00-CC-CC_0.hccapx // 4
```
#### 2) Extract each handshake into a separated file (All)
```
python multicapconverter.py -i capture.cap --group-by handshake -x hccapx --all
...
Output hccapx files:
00-00-00-00-AA-AA_0.hccapx // 1
00-00-00-00-AA-AA_1.hccapx // 2
00-00-00-00-BB-BB_0.hccapx // 3
00-00-00-00-CC-CC_0.hccapx // 4
```
#### 3) Extract all handshakes into one file (just like the old c version)
```
python multicapconverter.py -i capture.cap --group-by none -x hccapx --all
...
Output hccapx files:
capture.hccapx // 1, 2, 3 and 4
```
#### 4) Extract handshakes based on BSSID
```
python multicapconverter.py -i capture.cap --group-by bssid -x hccapx --all
...
Output hccapx files:
00-00-00-00-AA-AA.hccapx // 1 and 2
00-00-00-00-BB-BB.hccapx // 3
00-00-00-00-CC-CC.hccapx // 4
```
#### 5) Extract handshakes based on ESSID
```
python multicapconverter.py -i capture.cap --group-by essid -x hccapx --all
...
Output hccapx files:
Wifi.hccapx // 1, 2 and 4
Internet.hccapx // 3
```
#### 6) Extract handshakes based on ESSID having a specific BSSID
```
python multicapconverter.py -i capture.cap --group-by essid --filter-by bssid 00:00:00:00:CC:CC -x hccapx --all
...
Output hccapx files:
Wifi.hccapx // 4
```
## Miscellaneous
 - Extract wordlist `--wordlist wordlist.txt`
 - Update OUI Database `--update-oui`

## Notes
 - Time Gap is in microseconds
 - `--group-by` works only for hccap and hccapx output
 - `--all` works only for hccap, hccapx and hcwpax (WPA\*02) output
 - by default, if a capture have both WPA\*01 and WPA\*02 (hcwpax format), WPA\*02 will be ignored on the exportation process. If you want to export both, use `--do-not-clean`
 - by default, multicapconverter ignores packets with zeroed timestamps. If you want to process such packets, use `--ignore-ts` (Not Recommended)
 - by default, multicapconverter exports only pmkids that are PSK/PSK256 related (AKM check). If you want to ignore AKM check, use `--ignore-ie` (Not Recommended)

## TIPS
 - run `--update-oui` at first time to use the MAC Address Vendor Lookup feature
 - use `--quiet` for better performance
