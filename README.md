# cap2hccapx.py
Tool used to Convert a WPA pcap capture file to a hashcat capture file (re)written in Python ([c version]( https://github.com/hashcat/hashcat-utils/blob/master/src/cap2hccapx.c))
```
usage: cap2hccapx.py [-h] --input capture.cap [--output capture.hccapx]
                     [--all] [--filter-by filter-by filter]
                     [--group-by {none,bssid,essid,handshake}]

Convert a WPA pcap capture file to a hashcat capture file

required arguments:
  --input capture.cap, -i capture.cap
                        Input capture file

optional arguments:
  -h, --help            show this help message and exit
  --output capture.hccapx, -o capture.hccapx
                        Output hccapx file
  --all, -a             Export all handshakes even unauthenticated ones
  --filter-by filter-by filter, -f filter-by filter
                        --filter-by {bssid XX:XX:XX:XX:XX:XX, essid ESSID}
  --group-by {none,bssid,essid,handshake}, -g {none,bssid,essid,handshake}

```

## Features
- Supports combined .cap files
- Output hccapx files can be grouped
- Output hccapx files can be filtered
- Output only authentication handshakes or all handshakes

## Examples
Assume we have a capture file 'capture.cap' which includes 4 handshakes:

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
python3 cap2hccapx.py -i capture.cap --group-by handshake
...
Output files:
00-00-00-00-AA-AA_0.hccapx // 2
00-00-00-00-BB-BB_0.hccapx // 3
00-00-00-00-CC-CC_0.hccapx // 4
```
#### 2) Extract each handshake into a separated file (All)
```
python3 cap2hccapx.py -i capture.cap --group-by handshake --all
...
Output files:
00-00-00-00-AA-AA_0.hccapx // 1
00-00-00-00-AA-AA_1.hccapx // 2
00-00-00-00-BB-BB_0.hccapx // 3
00-00-00-00-CC-CC_0.hccapx // 4
```
#### 3) Extract all handshakes into one file (just like the old c version)
```
python3 cap2hccapx.py -i capture.cap --group-by none --all
...
Output files:
capture.hccapx // 1, 2, 3 and 4
```
#### 4) Extract handshakes based on BSSID
```
python3 cap2hccapx.py -i capture.cap --group-by bssid --all
...
Output files:
00-00-00-00-AA-AA.hccapx // 1 and 2
00-00-00-00-BB-BB.hccapx // 3
00-00-00-00-CC-CC.hccapx // 4
```
#### 5) Extract handshakes based on ESSID
```
python3 cap2hccapx.py -i capture.cap --group-by essid --all
...
Output files:
Wifi.hccapx // 1, 2 and 4
Internet.hccapx // 3
```
#### 6) Extract handshakes based on ESSID having a specific BSSID
```
python3 cap2hccapx.py -i capture.cap --group-by essid --filter-by bssid 00:00:00:00:CC:CC --all
...
Output files:
Wifi.hccapx // 4
```
## TODO
 - Enhance performance and the way the script deals with structures
 - Custom output file formats

