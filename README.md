# multicapconverter.py
Tool used to Convert a cap/pcap/pcapng capture file to a hashcat hcwpax/hccapx/hccap/hcpmkid/hceapmd5/hceapleap file (re)written in Python (based on [c version]( https://github.com/hashcat/hashcat-utils/blob/master/src/cap2hccapx.c))
```
usage: multicapconverter.py --input capture.cap --export
                            {hcwpax,hccapx,hccap,hcpmkid,hceapmd5,hceapleap}
                            [--output capture.hcwpax] [--all]
                            [--filter-by filter-by filter]
                            [--group-by {none,bssid,essid,handshake}]
                            [--wordlist wordlist.txt] [--do-not-clean]
                            [--ignore-ie] [--ignore-ts] [--quiet]
                            [--update-oui] [--locate] [--version] [--help]

Convert a cap/pcap/pcapng capture file to a hashcat
hcwpax/hccapx/hccap/hcpmkid/hceapmd5/hceapleap file

required arguments:
  --input capture.cap, -i capture.cap
                        Input capture file
  --export {hcwpax,hccapx,hccap,hcpmkid,hceapmd5,hceapleap}, -x {hcwpax,hccapx,hccap,hcpmkid,hceapmd5,hceapleap}

optional arguments:
  --output capture.hcwpax, -o capture.hcwpax
                        Output file
  --all, -a             Export all handshakes even unauthenticated ones
  --filter-by filter-by filter, -f filter-by filter
                        --filter-by {bssid XX:XX:XX:XX:XX:XX, essid ESSID}
  --group-by {none,bssid,essid,handshake}, -g {none,bssid,essid,handshake}
  --wordlist wordlist.txt, -E wordlist.txt
                        Extract wordlist / AP-LESS possible passwords (autohex
                        enabled on non ASCII characters)
  --do-not-clean        Do not clean output
  --ignore-ie           Ignore information element (AKM Check) (Not
                        Recommended)
  --ignore-ts           Ignore timestamps check (Not Recommended)
  --quiet, -q           Enable quiet mode (print only output files/data)
  --update-oui          Update OUI Database
  --locate              Locate networks geolocations
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
- MAC VENDOR LOOKUP
- MAC GEOLOCATION LOOKUP (requires [hashC](https://hashc.co.uk/) API)

## Configuration
### Setting hashC_APIKEY
(only required for MAC GEOLOCATION LOOKUP)  
After getting your api key from hashC (via [website](https://hashc.co.uk/) or [email](mailto:support@hashc.co.uk))
Open your command prompt / terminal and execute:
#### For Linux
`export hashC_APIKEY=YOUR_APIKEY_HERE`
#### For Mac
`export hashC_APIKEY=YOUR_APIKEY_HERE`
#### For Windows
`set hashC_APIKEY=YOUR_APIKEY_HERE`

## Usage Examples
We have a capture file 'capture.cap' which includes 4 handshakes:

| # | BSSID             | ESSID    | AUTHENTICATED |
|---|-------------------|----------|---------------|
| 1 | 00:00:00:00:AA:AA | Wifi     |       N       |
| 2 | 00:00:00:00:AA:AA | Wifi     |       Y       |
| 3 | 00:00:00:00:BB:BB | Internet |       Y       |
| 4 | 00:00:00:00:CC:CC | Wifi     |       Y       |

By default the original c version write all the hccapx into one file no matter what. 
If you need a single separated handshake you will have to use a hex editor and take the required 393 bytes by yourself.. Well not anymore

Also the original c version export all the handshakes even if they are not authenticated, in this python version it's a bit different, as the default is to ignore unauthenticated handshakes but can be exported by using the --all flag

#### 1) Extract each handshake into a separated file (Auth Only)
```
python3 multicapconverter.py -i capture.cap --group-by handshake -x hccapx
...
Output hccapx files:
00-00-00-00-AA-AA_0.hccapx // 2
00-00-00-00-BB-BB_0.hccapx // 3
00-00-00-00-CC-CC_0.hccapx // 4
```
#### 2) Extract each handshake into a separated file (All)
```
python3 multicapconverter.py -i capture.cap --group-by handshake -x hccapx --all
...
Output hccapx files:
00-00-00-00-AA-AA_0.hccapx // 1
00-00-00-00-AA-AA_1.hccapx // 2
00-00-00-00-BB-BB_0.hccapx // 3
00-00-00-00-CC-CC_0.hccapx // 4
```
#### 3) Extract all handshakes into one file (just like the old c version)
```
python3 multicapconverter.py -i capture.cap --group-by none -x hccapx --all
...
Output hccapx files:
capture.hccapx // 1, 2, 3 and 4
```
#### 4) Extract handshakes based on BSSID
```
python3 multicapconverter.py -i capture.cap --group-by bssid -x hccapx --all
...
Output hccapx files:
00-00-00-00-AA-AA.hccapx // 1 and 2
00-00-00-00-BB-BB.hccapx // 3
00-00-00-00-CC-CC.hccapx // 4
```
#### 5) Extract handshakes based on ESSID
```
python3 multicapconverter.py -i capture.cap --group-by essid -x hccapx --all
...
Output hccapx files:
Wifi.hccapx // 1, 2 and 4
Internet.hccapx // 3
```
#### 6) Extract handshakes based on ESSID having a specific BSSID
```
python3 multicapconverter.py -i capture.cap --group-by essid --filter-by bssid 00:00:00:00:CC:CC -x hccapx --all
...
Output hccapx files:
Wifi.hccapx // 4
```
## Miscellaneous
 - Extract wordlist `--wordlist wordlist.txt`
 - Update OUI Database `--update-oui`
 - Locate networks locations `--locate`

## Notes
 - Time Gap is in microseconds
 - --group-by works only for hccap and hccapx output
 - --all works only for hccap, hccapx and hcwpax (WPA\*02) output
 - --locate and --update-oui works only if -q/--quiet is not set
 - by default, if a capture have both WPA\*01 and WPA\*02 (hcwpax format), WPA\*02 will be ignored on the exportation process. If you want to export both, use --do-not-clean
 - by default, multicapconverter ignores packets with zeroed timestamps. If you want to process such packets, use --ignore-ts (Not Recommended)
 - by default, multicapconverter exports only pmkids that are PSK/PSK256 related (AKM check). If you want to ignore AKM check, use --ignore-ie (Not Recommended)

## TIPS
 - use --quiet for better performance
