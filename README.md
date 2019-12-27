# cap2hccapx.py
Tool used to Convert a WPA cap/pcap/pcapng capture file to a hashcat hcwpax/hccapx file (re)written in Python ([c version]( https://github.com/hashcat/hashcat-utils/blob/master/src/cap2hccapx.c))
```
usage: cap2hccapx.py [-h] --input capture.cap --export {hcwpax,hccapx}
                     [--output capture.hccapx] [--all]
                     [--filter-by filter-by filter]
                     [--group-by {none,bssid,essid,handshake}] [--quiet]

Convert a WPA cap/pcap/pcapng capture file to a hashcat hcwpax/hccapx file

required arguments:
  --input capture.cap, -i capture.cap
                        Input capture file
  --export {hcwpax,hccapx}, -x {hcwpax,hccapx}

optional arguments:
  -h, --help            show this help message and exit
  --output capture.hccapx, -o capture.hccapx
                        Output hccapx file
  --all, -a             Export all handshakes even unauthenticated ones
  --filter-by filter-by filter, -f filter-by filter
                        --filter-by {bssid XX:XX:XX:XX:XX:XX, essid ESSID}
  --group-by {none,bssid,essid,handshake}, -g {none,bssid,essid,handshake}
  --quiet, -q           Enable quiet mode (print only output files/data)
```

## Features
- Supports cap/pcap/pcapng
- Supports combined cap/pcap/pcapng files
- Supports gz compressed cap/pcap/pcapng files
- Export as hccapx (hashcat mode = 2500)
- Export as hcwpax (hashcat mode = 22000)
- Export only authenticated handshakes or all handshakes
- Output files can be filtered/grouped
- Supports hcxdumptool

## Examples
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
python3 cap2hccapx.py -i capture.cap --group-by handshake -x hccapx
...
Output files:
00-00-00-00-AA-AA_0.hccapx // 2
00-00-00-00-BB-BB_0.hccapx // 3
00-00-00-00-CC-CC_0.hccapx // 4
```
#### 2) Extract each handshake into a separated file (All)
```
python3 cap2hccapx.py -i capture.cap --group-by handshake -x hccapx --all
...
Output files:
00-00-00-00-AA-AA_0.hccapx // 1
00-00-00-00-AA-AA_1.hccapx // 2
00-00-00-00-BB-BB_0.hccapx // 3
00-00-00-00-CC-CC_0.hccapx // 4
```
#### 3) Extract all handshakes into one file (just like the old c version)
```
python3 cap2hccapx.py -i capture.cap --group-by none -x hccapx --all
...
Output files:
capture.hccapx // 1, 2, 3 and 4
```
#### 4) Extract handshakes based on BSSID
```
python3 cap2hccapx.py -i capture.cap --group-by bssid -x hccapx --all
...
Output files:
00-00-00-00-AA-AA.hccapx // 1 and 2
00-00-00-00-BB-BB.hccapx // 3
00-00-00-00-CC-CC.hccapx // 4
```
#### 5) Extract handshakes based on ESSID
```
python3 cap2hccapx.py -i capture.cap --group-by essid -x hccapx --all
...
Output files:
Wifi.hccapx // 1, 2 and 4
Internet.hccapx // 3
```
#### 6) Extract handshakes based on ESSID having a specific BSSID
```
python3 cap2hccapx.py -i capture.cap --group-by essid --filter-by bssid 00:00:00:00:CC:CC -x hccapx --all
...
Output files:
Wifi.hccapx // 4
```
## Notes
 - --group-by does not effect hcwpax (WPA\*01 & WPA\*02) output
 - --all does not effect hcwpax (WPA\*01) output

## TODO
 - Enhance performance and the way the script deals with structures
 - Fix performance issues when dealing with big capture files
 - Custom output file formats
