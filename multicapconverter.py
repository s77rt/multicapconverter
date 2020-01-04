#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Abdelhafidh Belalia (s77rt)"
__credits__ = ['Jens Steube <jens.steube@gmail.com>', 'Philipp "philsmd" Schmidt <philsmd@hashcat.net>', 'ZerBea (https://github.com/ZerBea)', 'RealEnder (https://github.com/RealEnder)']
__license__ = "MIT"
__maintainer__ = "Abdelhafidh Belalia (s77rt)"
__email__ = "admin@abdelhafidh.com"
__version__ = "0.1.1"
__github__ = "https://github.com/s77rt/multicapconverter/"

import os
import sys
import argparse
import struct
import errno
import re
import gzip
from collections import namedtuple
from operator import itemgetter
from itertools import groupby, islice
from enum import Enum
from multiprocessing import Process, Manager

### Endianness ###
if sys.byteorder == "big":
	BIG_ENDIAN_HOST = True
	xprint("WARNING! Endianness is not well tested on BIG_ENDIAN_HOST!")
else:
	BIG_ENDIAN_HOST = False
###

### WBIT ###
def WBIT(n):
	return (1 << (n))
###

### Constants ###
HCCAPX_VERSION   =  4
HCCAPX_SIGNATURE = 0x58504348 # HCPX

HCWPAX_SIGNATURE = "WPA"

TCPDUMP_MAGIC  = 0xa1b2c3d4
TCPDUMP_CIGAM  = 0xd4c3b2a1

PCAPNG_MAGIC = 0x1A2B3C4D
PCAPNG_CIGAM = 0xD4C3B2A1

TCPDUMP_DECODE_LEN  = 65535

DLT_NULL         = 0   #  BSD loopback encapsulation 
DLT_EN10MB       = 1   #  Ethernet (10Mb) 
DLT_EN3MB        = 2   #  Experimental Ethernet (3Mb) 
DLT_AX25         = 3   #  Amateur Radio AX.25 
DLT_PRONET       = 4   #  Proteon ProNET Token Ring 
DLT_CHAOS        = 5   #  Chaos 
DLT_IEEE802      = 6   #  IEEE 802 Networks 
DLT_ARCNET       = 7   #  ARCNET, with BSD-style header 
DLT_SLIP         = 8   #  Serial Line IP 
DLT_PPP          = 9   #  Point-to-point Protocol 
DLT_FDDI         = 10  #  FDDI 
DLT_RAW          = 12  #  Raw headers (no link layer) 
DLT_RAW2         = 14
DLT_RAW3         = 101

DLT_IEEE802_11   = 105 #  IEEE 802.11 wireless 
DLT_IEEE802_11_PRISM    = 119
DLT_IEEE802_11_RADIO    = 127
DLT_IEEE802_11_PPI_HDR  = 192

IEEE80211_FCTL_FTYPE         = 0x000c
IEEE80211_FCTL_STYPE         = 0x00f0
IEEE80211_FCTL_TODS          = 0x0100
IEEE80211_FCTL_FROMDS        = 0x0200

IEEE80211_FTYPE_MGMT         = 0x0000
IEEE80211_FTYPE_DATA         = 0x0008

IEEE80211_STYPE_ASSOC_REQ      = 0x0000
IEEE80211_STYPE_ASSOC_RESP     = 0x0010
IEEE80211_STYPE_REASSOC_REQ    = 0x0020
IEEE80211_STYPE_REASSOC_RESP   = 0x0030
IEEE80211_STYPE_PROBE_REQ      = 0x0040
IEEE80211_STYPE_PROBE_RESP     = 0x0050
IEEE80211_STYPE_BEACON         = 0x0080
IEEE80211_STYPE_QOS_DATA       = 0x0080
IEEE80211_STYPE_ATIM           = 0x0090
IEEE80211_STYPE_DISASSOC       = 0x00A0
IEEE80211_STYPE_AUTH           = 0x00B0
IEEE80211_STYPE_DEAUTH         = 0x00C0
IEEE80211_STYPE_ACTION         = 0x00D0

IEEE80211_LLC_DSAP               = 0xAA
IEEE80211_LLC_SSAP               = 0xAA
IEEE80211_LLC_CTRL               = 0x03
IEEE80211_DOT1X_AUTHENTICATION   = 0x8E88

MFIE_TYPE_SSID       = 0
MFIE_TYPE_RATES      = 1
MFIE_TYPE_FH_SET     = 2
MFIE_TYPE_DS_SET     = 3
MFIE_TYPE_CF_SET     = 4
MFIE_TYPE_TIM        = 5
MFIE_TYPE_IBSS_SET   = 6
MFIE_TYPE_CHALLENGE  = 16
MFIE_TYPE_ERP        = 42
MFIE_TYPE_RSN        = 48
MFIE_TYPE_RATES_EX   = 50
MFIE_TYPE_GENERIC    = 221

SIZE_OF_pcap_pkthdr_t = 16
SIZE_OF_pcap_file_header_t = 24
SIZE_OF_prism_header_t = 144
SIZE_OF_ieee80211_radiotap_header_t = 8
SIZE_OF_ppi_packet_header_t = 8
SIZE_OF_ieee80211_hdr_3addr_t = 24
SIZE_OF_ieee80211_qos_hdr_t = 26
SIZE_OF_beacon_t = 12
SIZE_OF_assocreq_t = 4
SIZE_OF_reassocreq_t = 10
SIZE_OF_ieee80211_llc_snap_header_t = 8
SIZE_OF_auth_packet_t = 99
SIZE_OF_EAPOL = 256

BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'
MAX_ESSID_LEN =  32
EAPOL_TTL = 1
TEST_REPLAYCOUNT = 0
ZERO = (0,)

WPA_KEY_INFO_TYPE_MASK = (WBIT(0) | WBIT(1) | WBIT(2))
WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 = WBIT(0)
WPA_KEY_INFO_TYPE_HMAC_SHA1_AES = WBIT(1)
WPA_KEY_INFO_KEY_TYPE = WBIT(3) #  1 = Pairwise, 0 = Group key 
WPA_KEY_INFO_KEY_INDEX_MASK = (WBIT(4) | WBIT(5))
WPA_KEY_INFO_KEY_INDEX_SHIFT = 4
WPA_KEY_INFO_INSTALL = WBIT(6)  #  pairwise 
WPA_KEY_INFO_TXRX = WBIT(6) #  group 
WPA_KEY_INFO_ACK = WBIT(7)
WPA_KEY_INFO_MIC = WBIT(8)
WPA_KEY_INFO_SECURE = WBIT(9)
WPA_KEY_INFO_ERROR = WBIT(10)
WPA_KEY_INFO_REQUEST = WBIT(11)
WPA_KEY_INFO_ENCR_KEY_DATA = WBIT(12) #  IEEE 802.11i/RSN only 

ESSID_SOURCE_USER           = 1
ESSID_SOURCE_REASSOC        = 2
ESSID_SOURCE_ASSOC          = 3
ESSID_SOURCE_PROBE          = 4
ESSID_SOURCE_DIRECTED_PROBE = 5
ESSID_SOURCE_BEACON         = 6

EXC_PKT_NUM_1 = 1
EXC_PKT_NUM_2 = 2
EXC_PKT_NUM_3 = 3
EXC_PKT_NUM_4 = 4

MESSAGE_PAIR_M12E2 = 0
MESSAGE_PAIR_M14E4 = 1
MESSAGE_PAIR_M32E2 = 2
MESSAGE_PAIR_M32E3 = 3
MESSAGE_PAIR_M34E3 = 4
MESSAGE_PAIR_M34E4 = 5

MESSAGE_PAIR_APLESS = 0b00010000
MESSAGE_PAIR_LE		= 0b00100000
MESSAGE_PAIR_BE		= 0b01000000
MESSAGE_PAIR_NC 	= 0b10000000

Interface_Description_Block = 0x00000001
Packet_Block                = 0x00000002
Simple_Packet_Block         = 0x00000003
Name_Resolution_Block       = 0x00000004
Interface_Statistics_Block  = 0x00000005
Enhanced_Packet_Block       = 0x00000006
IRIG_Timestamp_Block        = 0x00000007
Arinc_429_in_AFDX_Encapsulation_Information_Block = 0x00000008
Section_Header_Block = 0x0A0D0D0A
Custom_Block = 0x0000000bad
Custom_Option_Codes = [2988, 2989, 19372, 19373]
if_tsresol_code = 9
opt_endofopt = 0

HCXDUMPTOOL_PEN = 0x2a, 0xce, 0x46, 0xa1
HCXDUMPTOOL_MAGIC_NUMBER = 0x2a, 0xce, 0x46, 0xa1, 0x79, 0xa0, 0x72, 0x33, 0x83, 0x37, 0x27, 0xab, 0x59, 0x33, 0xb3, 0x62, 0x45, 0x37, 0x11, 0x47, 0xa7, 0xcf, 0x32, 0x7f, 0x8d, 0x69, 0x80, 0xc0, 0x89, 0x5e, 0x5e, 0x98
HCXDUMPTOOL_OPTIONCODE_MACAP		= 0xf29b
HCXDUMPTOOL_OPTIONCODE_RC			= 0xf29c
HCXDUMPTOOL_OPTIONCODE_ANONCE		= 0xf29d
HCXDUMPTOOL_OPTIONCODE_MACCLIENT	= 0xf29e
HCXDUMPTOOL_OPTIONCODE_SNONCE		= 0xf29f
HCXDUMPTOOL_OPTIONCODE_WEAKCANDIDATE	= 0xf2a0
HCXDUMPTOOL_OPTIONCODE_NMEA			    = 0xf2a1

SUITE_OUI = 0x00, 0x0f, 0xac
CS_WEP40 = 1
CS_TKIP = 2
CS_WRAP = 3
CS_CCMP = 4
CS_WEP104 = 5
CS_BIP = 6
CS_NOT_ALLOWED = 7
AK_PMKSA = 1
AK_PSK = 2
AK_FT = 3
AK_FT_PSK = 4
AK_PMKSA256 = 5
AK_PSKSHA256 = 6
AK_TDLS = 7
AK_SAE_SHA256 = 8
AK_FT_SAE = 9

DB_ESSID_MAX  = 50000
DB_EXCPKT_MAX = 100000
MAX_WORK_PER_PROCESS = 100

CHUNK_SIZE = 8192
###

### Structures-Like ###
pcap_file_header_t = namedtuple( \
	'pcap_file_header', '\
	  magic \
	  version_major \
	  version_minor \
	  thiszone \
	  sigfigs \
	  snaplen \
	  linktype \
')
pcap_pkthdr_t = namedtuple( \
	'pcap_pkthdr', '\
	  tv_sec \
	  tv_usec \
	  caplen \
	  len \
')
ieee80211_hdr_3addr_t = namedtuple( \
	'ieee80211_hdr_3addr', '\
	  frame_control \
	  duration_id \
	  addr1 \
	  addr2 \
	  addr3 \
	  seq_ctrl \
')
ieee80211_qos_hdr_t = namedtuple( \
	'ieee80211_qos_hdr', '\
	  frame_control \
	  duration_id \
	  addr1 \
	  addr2 \
	  addr3 \
	  seq_ctrl \
	  qos_ctrl \
')
ieee80211_llc_snap_header_t = namedtuple( \
	'ieee80211_llc_snap_header', '\
	  dsap \
	  ssap \
	  ctrl \
	  oui \
	  ethertype \
')
prism_item_t = namedtuple( \
	'prism_item', '\
	  did \
	  status \
	  len \
	  data \
')
prism_header_t = namedtuple( \
	'prism_header', '\
	  msgcode \
	  msglen \
	  devname \
	  hosttime \
	  mactime \
	  channel \
	  rssi \
	  sq \
	  signal \
	  noise \
	  rate \
	  istx \
	  frmlen \
')
ieee80211_radiotap_header_t = namedtuple( \
	'ieee80211_radiotap_header', '\
	  it_version \
	  it_pad \
	  it_len \
	  it_present \
')
ppi_packet_header_t = namedtuple( \
	'ppi_packet_header', '\
	  pph_version \
	  pph_flags \
	  pph_len \
	  pph_dlt \
')
beacon_t = namedtuple( \
	'beaconinfo', '\
	  beacon_timestamp \
	  beacon_interval \
	  beacon_capabilities \
')
assocreq_t = namedtuple( \
	'associationreqf', '\
	  client_capabilities \
	  client_listeninterval \
')
reassocreq_t = namedtuple( \
	'reassociationreqf', '\
	  client_capabilities \
	  client_listeninterval \
	  addr \
')
auth_packet_t = namedtuple( \
	'auth_packet', '\
	  version \
	  type \
	  length \
	  key_descriptor \
	  key_information \
	  key_length \
	  replay_counter \
	  wpa_key_nonce \
	  wpa_key_iv \
	  wpa_key_rsc \
	  wpa_key_id \
	  wpa_key_mic \
	  wpa_key_data_length \
')
hccapx_t = namedtuple( \
	'hccapx', '\
	  signature \
	  version \
	  message_pair \
	  essid_len \
	  essid \
	  keyver \
	  keymic \
	  mac_ap \
	  nonce_ap \
	  mac_sta \
	  nonce_sta \
	  eapol_len \
	  eapol \
')
pcapng_general_block_structure = namedtuple( \
	'pcapng_general_block', '\
	  block_type \
	  block_total_length \
	  block_body \
	  block_total_length_2 \
')
###

### H-Functions ###
def byte_swap_16(n):
	return (n & 0xff00) >> 8 \
	| (n & 0x00ff) << 8
def byte_swap_32(n):
	return (n & 0xff000000) >> 24 \
	| (n & 0x00ff0000) >>  8 \
	| (n & 0x0000ff00) <<  8 \
	| (n & 0x000000ff) << 24
def byte_swap_64(n):
	return (n & 0xff00000000000000) >> 56 \
	| (n & 0x00ff000000000000) >> 40 \
	| (n & 0x0000ff0000000000) >> 24 \
	| (n & 0x000000ff00000000) >>  8 \
	| (n & 0x00000000ff000000) <<  8 \
	| (n & 0x0000000000ff0000) << 24 \
	| (n & 0x000000000000ff00) << 40 \
	| (n & 0x00000000000000ff) << 56
def to_signed_32(n):
	n = n & 0xffffffff
	return (n ^ 0x80000000) - 0x80000000
def pymemcpy(src, count):
	dest = src[:count]
	if isinstance(dest, bytes):
		dest += b'\x00'*(count - len(dest))
	elif isinstance(dest, (list,tuple)):
		dest += (0,)*(count - len(dest))
	if len(dest) != count:
		raise ValueError('pymemcpy failed')
	return dest
#
def get_valid_bssid(bssid):
	bssid = bssid.lower()
	bssid = re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", bssid)
	if bssid:
		return bssid[0].replace(':', '').replace('-', '')
def get_valid_filename(s, r='_'):
	s = str(s).strip().replace(' ', '_')
	return re.sub(r'(?u)[^-\w.\@]', r, s)
def xprint(text="", end='\n', flush=True):
	print(text, end=end, flush=flush)
###

### Database-Like ###
## Tables:
class essids(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, value)
		elif value['essid_source'] > self[key]['essid_source']:
			self[key]['essid_source'] = value['essid_source']
class excpkts(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, value)
		else:
			subkey = list(value.keys())[0]
			if subkey not in self[key]:
				self[key].__setitem__(subkey, list(value.values())[0])
			else:
				subsubkey = list(list(value.values())[0].keys())[0]
				if subsubkey not in self[key][subkey]:
					self[key][subkey].__setitem__(subsubkey, list(list(value.values())[0].values())[0])
				else:
					self[key][subkey][subsubkey].append(list(list(value.values())[0].values())[0][0])
class hccapxs(list):
	def __init__(self):
		list.__init__(self)
class hcwpaxs(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, value)
class hcpmkids(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, value)
class pmkids(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, value)
		else:
			self[key]['pmkid'] = value['pmkid']
class pcapng_info(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, [value])
		else:
			self[key].append(value)
## Database:
class Database(object):
	def __init__(self):
		super(Database, self).__init__()
		self.essids = essids()
		self.excpkts = excpkts()
		self.hccapxs = hccapxs()
		self.hcwpaxs = hcwpaxs()
		self.hcpmkids = hcpmkids()
		self.pmkids = pmkids()
		self.pcapng_info = pcapng_info()
	def essid_add(self, bssid, essid, essid_len, essid_source):
		if len(self.essids) == DB_ESSID_MAX:
			raise ValueError('DB_ESSID_MAX Exceeded!')
		if essid_len == 0 or not essid:
			return
		key = pymemcpy(bssid, 6)
		self.essids.__setitem__(key, {
			'bssid': pymemcpy(bssid, 6),
			'essid': essid,
			'essid_len': essid_len,
			'essid_source': essid_source
		})
	def excpkt_add(self, excpkt_num, tv_sec, tv_usec, replay_counter, mac_ap, mac_sta, nonce, eapol_len, eapol, keyver, keymic):
		if len(self.excpkts) == DB_EXCPKT_MAX:
			raise ValueError('DB_EXCPKT_MAX Exceeded!')
		key = pymemcpy(mac_ap, 6)
		subkey = pymemcpy(mac_sta, 6)
		subsubkey = 'ap' if excpkt_num in [EXC_PKT_NUM_1, EXC_PKT_NUM_3] else 'sta'
		check = self.excpkts.get(key, {}).get(subkey, {}).get(subsubkey, {})
		for c in check:
			if c['eapol'] == eapol:
				return
		self.excpkts.__setitem__(key, {subkey: {subsubkey: [{
			'excpkt_num': excpkt_num,
			'tv_sec': tv_sec,
			'tv_usec': tv_usec,
			'replay_counter': replay_counter,
			'mac_ap': pymemcpy(mac_ap, 6),
			'mac_sta': pymemcpy(mac_sta, 6),
			'nonce': pymemcpy(nonce, 32),
			'eapol_len': eapol_len,
			'eapol': eapol,
			'keyver': keyver,
			'keymic': keymic
		}]}})
	def hccapx_add(self, bssid, essid, raw_data):
		self.hccapxs.append({ \
			'bssid': bssid, \
			'essid': essid, \
			'raw_data': raw_data \
		})
	def hccapx_groupby(self, group_by):
		if group_by is None or group_by == "none":
			self.hccapxs = [{'key': 'none', 'raw_data': [v['raw_data'] for v in self.hccapxs]}]
		elif group_by == "handshake":
			self.hccapxs = [{'key': v['bssid']+"_"+str(k), 'raw_data': [v['raw_data']]} for k, v in enumerate(self.hccapxs)]
		else:
			self.hccapxs.sort(key=itemgetter(group_by))
			self.hccapxs = groupby(self.hccapxs, key=itemgetter(group_by))
			self.hccapxs = [{'key': k, 'raw_data': [x['raw_data'] for x in v]} for k, v in self.hccapxs]
	def hcwpaxs_add(self, signature, ftype, pmkid_or_mic, mac_ap, mac_sta, essid, anonce=None, eapol=None, message_pair=None):
		if ftype == "01":
			key = pmkid_or_mic
			self.hcwpaxs.__setitem__(key, { \
				'signature': signature, \
				'type': ftype, \
				'pmkid_or_mic': pmkid_or_mic, \
				'mac_ap': bytes(mac_ap).hex(), \
				'mac_sta': bytes(mac_sta).hex(), \
				'essid': bytes(essid).hex(), \
				'anonce': '', \
				'eapol': '', \
				'message_pair': '' \
			})
		else:
			key = hash((pmkid_or_mic, message_pair))
			self.hcwpaxs.__setitem__(key, { \
				'signature': signature, \
				'type': ftype, \
				'pmkid_or_mic': bytes(pmkid_or_mic).hex(), \
				'mac_ap': bytes(mac_ap).hex(), \
				'mac_sta': bytes(mac_sta).hex(), \
				'essid': bytes(essid).hex(), \
				'anonce': bytes(anonce).hex(), \
				'eapol': bytes(eapol).hex(), \
				'message_pair': '{:02x}'.format(message_pair) \
			})
	def hcpmkid_add(self, pmkid, mac_ap, mac_sta, essid):
		key = pmkid
		self.hcpmkids.__setitem__(key, { \
			'pmkid': pmkid, \
			'mac_ap': bytes(mac_ap).hex(), \
			'mac_sta': bytes(mac_sta).hex(), \
			'essid': bytes(essid).hex() \
		})
	def pmkid_add(self, mac_ap, mac_sta, pmkid):
		key = hash(mac_ap+mac_sta)
		self.pmkids.__setitem__(key, {
			'mac_ap': bytes(mac_ap).hex(),
			'mac_sta': bytes(mac_sta).hex(),
			'pmkid': pmkid
		})
	def pcapng_info_add(self, key, info):
		self.pcapng_info.__setitem__(key, info)
DB = Database()
###

### STATUS ###
class Status(object):
	def __init__(self):
		super(Status, self).__init__()
		self.total_filesize = 0
		self.current_filepos = 0
		self.current_packet = 0
	def set_filesize(self, filesize):
		self.total_filesize = filesize
	def step_packet(self):
		self.current_packet += 1
	def set_filepos(self, filepos):
		self.current_filepos = filepos
STATUS = Status()
###

### HX-Functions ###
def get_essid_from_tag(packet, header, length_skip):
	if length_skip > header['caplen']:
		return -1, None
	length = header['caplen'] - length_skip
	beacon = packet[length_skip:length_skip+length]
	cur = 0
	end = len(beacon)
	while cur < end:
		if (cur + 2) >= end:
			break
		tagtype = beacon[cur]
		cur += 1
		taglen  = beacon[cur]
		cur += 1
		if (cur + taglen) >= end:
			break
		if tagtype == MFIE_TYPE_SSID:
			if taglen < MAX_ESSID_LEN:
				essid = {}
				essid['essid'] = pymemcpy(beacon[cur:cur+taglen], MAX_ESSID_LEN)
				essid['essid_len'] = taglen
				return 0, essid
		cur += taglen
	return -1, None

def get_pmkid_from_packet(packet, source):
	if source == "EAPOL-M1":
		if packet:
			pos = 0
			while True:
				try:
					tag_id = packet[pos]
					tag_len = packet[pos+1]
					tag_data = packet[pos+2:pos+2+tag_len]
					if tag_id == 221:
						if tag_data[0:3] == bytes(SUITE_OUI):
							pmkid = tag_data[4:].hex()
							if pmkid != '0'*32:
								yield pmkid
					pos = pos+2+tag_len
				except:
					break
		return
	elif source == IEEE80211_STYPE_ASSOC_REQ:
		pos = 28
	elif source == IEEE80211_STYPE_REASSOC_REQ:
		pos = 34
	else:
		return
	while True:
		try:
			tag_id = packet[pos]
			tag_len = packet[pos+1]
			tag_data = packet[pos+2:pos+2+tag_len]
			if tag_id == 48:
				#tag_version = tag_data[0:2]
				#tag_group_cipher_suite = tag_data[2:6]
				# Pairwise Cipher Suite
				tag_pairwise_suite_count = struct.unpack('=H', tag_data[6:8])[0]
				if BIG_ENDIAN_HOST:
					tag_pairwise_suite_count = byte_swap_16(tag_pairwise_suite_count)
				#tag_pairwise_suite = []
				pos = 8
				#for i in range(0, tag_pairwise_suite_count):
				#	pos += (4*i)+4
				#	tag_pairwise_suite.append(tag_data[pos-4:pos])
				pos += (4*tag_pairwise_suite_count)+4
				# AKM Suite
				tag_authentication_suite_count = struct.unpack('=H', tag_data[pos:pos+2])[0]
				if BIG_ENDIAN_HOST:
					tag_authentication_suite_count = byte_swap_16(tag_authentication_suite_count)
				#tag_authentication_suite = []
				pos = pos+2
				skip = 0
				for i in range(0, tag_authentication_suite_count):
					pos += (4*i)+4
					akm = tag_data[pos-4:pos]
					if akm[0:3] != bytes(SUITE_OUI) or akm[3] not in [AK_PSK, AK_PSKSHA256]:
						skip = 1
				if skip == 1:
					break
				###############
				#tag_capabilities = tag_data[pos:pos+2]
				##############################
				try:
					pmkid_count = struct.unpack('=H', tag_data[pos+2:pos+4])[0]
					if BIG_ENDIAN_HOST:
						pmkid_count = byte_swap_16(pmkid_count)
					pos = pos+4
					for i in range(0, pmkid_count):
						pos += (16*i)+16
						pmkid = tag_data[pos-16:pos].hex()
						if pmkid != '0'*32:
							yield pmkid
				except:
					break
				##############################
			pos = pos+2+tag_len
		except:
			break

def handle_llc(ieee80211_llc_snap_header):
	if ieee80211_llc_snap_header['dsap'] != IEEE80211_LLC_DSAP:
		return -1
	if ieee80211_llc_snap_header['ssap'] != IEEE80211_LLC_SSAP:
		return -1
	if ieee80211_llc_snap_header['ctrl'] != IEEE80211_LLC_CTRL:
		return -1
	if ieee80211_llc_snap_header['ethertype'] != IEEE80211_DOT1X_AUTHENTICATION:
		return -1
	return 0

def handle_auth(auth_packet, auth_packet_copy, rest_packet, pkt_offset, pkt_size):
	ap_length               = byte_swap_16(auth_packet['length'])
	ap_key_information      = byte_swap_16(auth_packet['key_information'])
	ap_replay_counter       = byte_swap_64(auth_packet['replay_counter'])
	ap_wpa_key_data_length  = byte_swap_16(auth_packet['wpa_key_data_length'])
	if ap_length == 0:
		return -1, None
	if ap_key_information & WPA_KEY_INFO_ACK:
		if ap_key_information & WPA_KEY_INFO_INSTALL:
			excpkt_num = EXC_PKT_NUM_3
		else:
			excpkt_num = EXC_PKT_NUM_1
	else:
		if ap_key_information & WPA_KEY_INFO_SECURE:
			excpkt_num = EXC_PKT_NUM_4
		else:
			excpkt_num = EXC_PKT_NUM_2
	if auth_packet['wpa_key_nonce'] == ZERO*32:
		return -1, None
	excpkt = {}
	excpkt['nonce'] = pymemcpy(auth_packet['wpa_key_nonce'], 32)
	excpkt['replay_counter'] = ap_replay_counter
	excpkt['excpkt_num'] = excpkt_num
	excpkt['eapol_len'] = SIZE_OF_auth_packet_t + ap_wpa_key_data_length
	if (pkt_offset + excpkt['eapol_len']) > pkt_size:
		return -1, None
	if (SIZE_OF_auth_packet_t + ap_wpa_key_data_length) > SIZE_OF_EAPOL:
		return -1, None
	auth_packet_copy_packed = struct.pack('=BBHBHHQ32B16B8B8B16BH', *auth_packet_copy)
	excpkt['eapol'] = pymemcpy(auth_packet_copy_packed, SIZE_OF_auth_packet_t)
	excpkt['eapol'] += pymemcpy(rest_packet[:ap_wpa_key_data_length], SIZE_OF_EAPOL-SIZE_OF_auth_packet_t)
	excpkt['keymic'] = pymemcpy(auth_packet['wpa_key_mic'], 16)
	excpkt['keyver'] = ap_key_information & WPA_KEY_INFO_TYPE_MASK
	if (excpkt_num == EXC_PKT_NUM_3) or (excpkt_num == EXC_PKT_NUM_4):
		excpkt['replay_counter'] -= 1
	return 0, excpkt
###

### PCAPNG ONLY ###
def read_blocks(pcapng):
	while True:
		piece = pcapng.read(8)
		if not piece:
			break
		block_total_length = struct.unpack('=II', piece)[1]
		if BIG_ENDIAN_HOST:
			block_total_length = byte_swap_32(block_total_length)
		block_body_length = block_total_length - 12
		body_unpacked = struct.unpack('=II{}BI'.format(block_body_length), piece+pcapng.read(block_body_length+4))
		block_type = body_unpacked[0]
		block_length = body_unpacked[1]
		block_body = body_unpacked[2:2+block_body_length]
		if BIG_ENDIAN_HOST:
			block_type = byte_swap_32(block_type)
			block_length = byte_swap_32(block_length)
		block = (dict(pcapng_general_block_structure._asdict(pcapng_general_block_structure._make(( \
			block_type, \
			block_length, \
			block_body, \
			block_length \
		)))))
		yield block

def read_options(options_block, bitness):
	while True:
		option = {}
		try:
			option['code'] = struct.unpack("H",struct.pack('2B', *options_block[0:2]))[0]
			option['length'] = struct.unpack("H",struct.pack('2B', *options_block[2:4]))[0]
		except:
			break
		if BIG_ENDIAN_HOST:
			option['code'] = byte_swap_16(option['code'])
			option['length'] = byte_swap_16(option['length'])
		if bitness:
			option['code'] = byte_swap_16(option['code'])
			option['length'] = byte_swap_16(option['length'])
		if option['code'] == opt_endofopt:
			break
		option_length = option['length'] + (-(option['length'])%4)
		option['value'] = options_block[4:4+option_length]
		if option['code'] in Custom_Option_Codes:
			pen = option['value'][0:4]
			if pen == HCXDUMPTOOL_PEN:
				magic = option['value'][4:36]
				if magic == HCXDUMPTOOL_MAGIC_NUMBER:
					for custom_option in read_options(option['value'][36:], bitness):
						yield custom_option
			options_block = options_block[4+option_length:]
		else:
			option['value'] = bytes(option['value'])
			options_block = options_block[4+option_length:]
			yield option

def read_custom_block(custom_block, bitness):
	name, data, options = None, None, None
	pen = custom_block[0:4]
	if pen == HCXDUMPTOOL_PEN:
		magic = custom_block[4:36]
		if magic == HCXDUMPTOOL_MAGIC_NUMBER:
			name = 'hcxdumptool'
			data = None
			options = []
			for option in read_options(custom_block[36:], bitness):
				if option['code'] == HCXDUMPTOOL_OPTIONCODE_RC:
					option['value'] = byte_swap_64(int(option['value'].hex(), 16))
					if BIG_ENDIAN_HOST:
						option['value'] = byte_swap_64(option['value'])
					if bitness:
						option['value'] = byte_swap_64(option['value'])
				options.append(option)
	return name, data, options
###

######################### READ FILE #########################

def get_filesize(file):
	old_file_pos = file.tell()
	file.seek(0, os.SEEK_END)
	filesize = file.tell()
	file.seek(old_file_pos, os.SEEK_SET)
	return filesize

def read_file(file):
	if file.lower().endswith('.gz'):
		return gzip.open(file, 'rb')
	return open(file, 'rb')

def read_pcap_file_header(pcap):
	try:
		pcap_file_header =  dict(pcap_file_header_t._asdict(pcap_file_header_t._make(struct.unpack('=IHHIIII', pcap.read(SIZE_OF_pcap_file_header_t)))))
	except struct.error:
		raise ValueError('Could not read pcap header')
	if BIG_ENDIAN_HOST:
		pcap_file_header['magic']          = byte_swap_32(pcap_file_header['magic'])
		pcap_file_header['version_major']  = byte_swap_16(pcap_file_header['version_major'])
		pcap_file_header['version_minor']  = byte_swap_16(pcap_file_header['version_minor'])
		pcap_file_header['thiszone']       = byte_swap_32(pcap_file_header['thiszone'])
		pcap_file_header['sigfigs']        = byte_swap_32(pcap_file_header['sigfigs'])
		pcap_file_header['snaplen']        = byte_swap_32(pcap_file_header['snaplen'])
		pcap_file_header['linktype']       = byte_swap_32(pcap_file_header['linktype'])
	if pcap_file_header['magic'] == TCPDUMP_MAGIC:
		bitness = 0
	elif pcap_file_header['magic'] == TCPDUMP_CIGAM:
		bitness = 1
		xprint("WARNING Endianness(big) is not well tested!")
	else:
		raise ValueError('Invalid pcap header')
	if (pcap_file_header['linktype'] != DLT_IEEE802_11) \
	  and (pcap_file_header['linktype'] != DLT_IEEE802_11_PRISM) \
	  and (pcap_file_header['linktype'] != DLT_IEEE802_11_RADIO) \
	  and (pcap_file_header['linktype'] != DLT_IEEE802_11_PPI_HDR):
		raise ValueError('Unsupported linktype detected')
	return pcap_file_header, bitness

def read_pcapng_file_header(pcapng):
	blocks = read_blocks(pcapng)
	for block in blocks:
		if block['block_type'] == Section_Header_Block:
			try:
				interface = next(blocks)
			except:
				break
			pcapng_file_header = {}
			pcapng_file_header['magic'] = block['block_body'][:4]
			pcapng_file_header['version_major'] = block['block_body'][4:6]
			pcapng_file_header['version_minor'] = block['block_body'][6:8]
			pcapng_file_header['thiszone'] = 0
			pcapng_file_header['sigfigs'] = 0
			pcapng_file_header['snaplen'] = interface['block_body'][2:4]
			pcapng_file_header['linktype'] = interface['block_body'][0]
			if BIG_ENDIAN_HOST:
				pcapng_file_header['magic'] = byte_swap_32(pcapng_file_header['magic'])
				pcapng_file_header['version_major'] = byte_swap_16(pcapng_file_header['version_major'])
				pcapng_file_header['version_minor'] = byte_swap_16(pcapng_file_header['version_minor'])
				pcapng_file_header['thiszone'] = byte_swap_32(pcapng_file_header['thiszone'])
				pcapng_file_header['sigfigs'] = byte_swap_32(pcapng_file_header['sigfigs'])
				pcapng_file_header['snaplen'] = byte_swap_32(pcapng_file_header['snaplen'])
				pcapng_file_header['linktype'] = byte_swap_32(pcapng_file_header['linktype'])
			if struct.unpack("I", struct.pack("4B", *pcapng_file_header['magic']))[0] == PCAPNG_MAGIC:
				bitness = 0
			elif struct.unpack("I", struct.pack("4B", *pcapng_file_header['magic']))[0] == PCAPNG_CIGAM:
				pcapng_file_header['magic'] = byte_swap_32(pcapng_file_header['magic'])
				pcapng_file_header['version_major'] = byte_swap_16(pcapng_file_header['version_major'])
				pcapng_file_header['version_minor'] = byte_swap_16(pcapng_file_header['version_minor'])
				pcapng_file_header['thiszone'] = byte_swap_32(pcapng_file_header['thiszone'])
				pcapng_file_header['sigfigs'] = byte_swap_32(pcapng_file_header['sigfigs'])
				pcapng_file_header['snaplen'] = byte_swap_32(pcapng_file_header['snaplen'])
				pcapng_file_header['linktype'] = byte_swap_32(pcapng_file_header['linktype'])
				bitness = 1
				xxprint("WARNING Endianness(big) is not well tested!")
			else:
				continue
			pcapng_file_header['section_options'] = []
			for option in read_options(block['block_body'][16:], bitness):
				pcapng_file_header['section_options'].append(option)
			if_tsresol = 6
			pcapng_file_header['interface_options'] = []
			for option in read_options(interface['block_body'][8:], bitness):
				if option['code'] == if_tsresol_code:
					if_tsresol = option['code']
					## currently only supports if_tsresol = 6
					if if_tsresol != 6:
						xprint("Unsupported if_tsresol")
						continue
				pcapng_file_header['interface_options'].append(option)
			if (pcapng_file_header['linktype'] != DLT_IEEE802_11) \
			  and (pcapng_file_header['linktype'] != DLT_IEEE802_11_PRISM) \
			  and (pcapng_file_header['linktype'] != DLT_IEEE802_11_RADIO) \
			  and (pcapng_file_header['linktype'] != DLT_IEEE802_11_PPI_HDR):
				continue
			yield pcapng_file_header, bitness, if_tsresol, blocks

######################### PROCESS PACKETS #########################

def process_packet(packet, header):
	xprint("Reading file: {}/{} ({} packets)".format(STATUS.current_filepos, STATUS.total_filesize, STATUS.current_packet), end='\r')
	if (header['caplen'] < SIZE_OF_ieee80211_hdr_3addr_t):
		return
	unpacked_packet = struct.unpack('=HH6B6B6BH', packet[:SIZE_OF_ieee80211_hdr_3addr_t])
	ieee80211_hdr_3addr = dict(ieee80211_hdr_3addr_t._asdict(ieee80211_hdr_3addr_t._make(( \
		unpacked_packet[0], \
		unpacked_packet[1], \
		(unpacked_packet[2], unpacked_packet[3], unpacked_packet[4], unpacked_packet[5], unpacked_packet[6], unpacked_packet[7]), \
		(unpacked_packet[8], unpacked_packet[9], unpacked_packet[10], unpacked_packet[11], unpacked_packet[12], unpacked_packet[13]), \
		(unpacked_packet[14], unpacked_packet[15], unpacked_packet[16], unpacked_packet[17], unpacked_packet[18], unpacked_packet[19]), \
		unpacked_packet[20] \
	))))
	if BIG_ENDIAN_HOST:
		ieee80211_hdr_3addr['frame_control'] = byte_swap_16(ieee80211_hdr_3addr['frame_control'])
		ieee80211_hdr_3addr['duration_id']   = byte_swap_16(ieee80211_hdr_3addr['duration_id'])
		ieee80211_hdr_3addr['seq_ctrl']      = byte_swap_16(ieee80211_hdr_3addr['seq_ctrl'])
	frame_control = ieee80211_hdr_3addr['frame_control']
	if frame_control & IEEE80211_FCTL_FTYPE == IEEE80211_FTYPE_MGMT:
		if bytes(ieee80211_hdr_3addr['addr3']) == BROADCAST_MAC:
			return
		stype = frame_control & IEEE80211_FCTL_STYPE
		if stype == IEEE80211_STYPE_BEACON:
			length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_beacon_t
			rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
			if rc_beacon == -1:
				return
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_BEACON)
		elif stype == IEEE80211_STYPE_PROBE_REQ:
			length_skip = SIZE_OF_ieee80211_hdr_3addr_t
			rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
			if rc_beacon == -1:
				return
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_PROBE)
		elif stype == IEEE80211_STYPE_PROBE_RESP:
			length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_beacon_t
			rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
			if rc_beacon == -1:
				return
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_PROBE)
		elif stype == IEEE80211_STYPE_ASSOC_REQ:
			mac_ap = ieee80211_hdr_3addr['addr3']
			if mac_ap == ieee80211_hdr_3addr['addr1']:
				mac_sta = ieee80211_hdr_3addr['addr2']
			else:
				mac_sta = ieee80211_hdr_3addr['addr1']
			for pmkid in get_pmkid_from_packet(packet, stype):
				DB.pmkid_add(mac_ap=mac_ap, mac_sta=mac_sta, pmkid=pmkid)
			length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_assocreq_t
			rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
			if rc_beacon == -1:
				return
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_ASSOC)
		elif stype == IEEE80211_STYPE_REASSOC_REQ:
			mac_ap = ieee80211_hdr_3addr['addr3']
			if mac_ap == ieee80211_hdr_3addr['addr1']:
				mac_sta = ieee80211_hdr_3addr['addr2']
			else:
				mac_sta = ieee80211_hdr_3addr['addr1']
			for pmkid in get_pmkid_from_packet(packet, stype):
				DB.pmkid_add(mac_ap=mac_ap, mac_sta=mac_sta, pmkid=pmkid)
			length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_reassocreq_t
			rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
			if rc_beacon == -1:
				return
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_REASSOC)
	elif frame_control & IEEE80211_FCTL_FTYPE == IEEE80211_FTYPE_DATA:
		addr4_exist = ((frame_control & (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)) == (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS))
		if (frame_control & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_QOS_DATA:
			llc_offset = SIZE_OF_ieee80211_qos_hdr_t
		else:
			llc_offset = SIZE_OF_ieee80211_hdr_3addr_t
		if header['caplen'] < (llc_offset + SIZE_OF_ieee80211_llc_snap_header_t):
			return
		if addr4_exist:
			llc_offset += 6
		unpacked_packet = struct.unpack('=BBB3BH', packet[llc_offset:(llc_offset+SIZE_OF_ieee80211_llc_snap_header_t)])
		ieee80211_llc_snap_header = dict(ieee80211_llc_snap_header_t._asdict(ieee80211_llc_snap_header_t._make(( \
			unpacked_packet[0], \
			unpacked_packet[1], \
			unpacked_packet[2], \
			(unpacked_packet[3], unpacked_packet[4], unpacked_packet[5]), \
			unpacked_packet[6] \
		))))
		if BIG_ENDIAN_HOST:
			ieee80211_llc_snap_header['ethertype'] = byte_swap_16(ieee80211_llc_snap_header['ethertype'])
		rc_llc = handle_llc(ieee80211_llc_snap_header)
		if rc_llc == -1:
			return
		auth_offset = llc_offset + SIZE_OF_ieee80211_llc_snap_header_t
		if header['caplen'] < (auth_offset + SIZE_OF_auth_packet_t):
			return
		unpacked_packet = struct.unpack('=BBHBHHQ32B16B8B8B16BH', packet[auth_offset:auth_offset+SIZE_OF_auth_packet_t])
		auth_packet = dict(auth_packet_t._asdict(auth_packet_t._make(( \
			unpacked_packet[0], \
			unpacked_packet[1], \
			unpacked_packet[2], \
			unpacked_packet[3], \
			unpacked_packet[4], \
			unpacked_packet[5], \
			unpacked_packet[6], \
			(unpacked_packet[7], unpacked_packet[8], unpacked_packet[9], unpacked_packet[10], unpacked_packet[11], unpacked_packet[12], unpacked_packet[13], unpacked_packet[14], unpacked_packet[15], unpacked_packet[16], unpacked_packet[17], unpacked_packet[18], unpacked_packet[19], unpacked_packet[20], unpacked_packet[21], unpacked_packet[22], unpacked_packet[23], unpacked_packet[24], unpacked_packet[25], unpacked_packet[26], unpacked_packet[27], unpacked_packet[28], unpacked_packet[29], unpacked_packet[30], unpacked_packet[31], unpacked_packet[32], unpacked_packet[33], unpacked_packet[34], unpacked_packet[35], unpacked_packet[36], unpacked_packet[37], unpacked_packet[38]), \
			(unpacked_packet[39], unpacked_packet[40], unpacked_packet[41], unpacked_packet[42], unpacked_packet[43], unpacked_packet[44], unpacked_packet[45], unpacked_packet[46], unpacked_packet[47], unpacked_packet[48], unpacked_packet[49], unpacked_packet[50], unpacked_packet[51], unpacked_packet[52], unpacked_packet[53], unpacked_packet[54]), \
			(unpacked_packet[55], unpacked_packet[56], unpacked_packet[57], unpacked_packet[58], unpacked_packet[59], unpacked_packet[60], unpacked_packet[61], unpacked_packet[62]), \
			(unpacked_packet[63], unpacked_packet[64], unpacked_packet[65], unpacked_packet[66], unpacked_packet[67], unpacked_packet[68], unpacked_packet[69], unpacked_packet[70]), \
			(unpacked_packet[71], unpacked_packet[72], unpacked_packet[73], unpacked_packet[74], unpacked_packet[75], unpacked_packet[76], unpacked_packet[77], unpacked_packet[78], unpacked_packet[79], unpacked_packet[80], unpacked_packet[81], unpacked_packet[82], unpacked_packet[83], unpacked_packet[84], unpacked_packet[85], unpacked_packet[86]), \
			unpacked_packet[87] \
		))))
		auth_packet_copy = ( \
			unpacked_packet[0], \
			unpacked_packet[1], \
			unpacked_packet[2], \
			unpacked_packet[3], \
			unpacked_packet[4], \
			unpacked_packet[5], \
			unpacked_packet[6], \
			unpacked_packet[7], unpacked_packet[8], unpacked_packet[9], unpacked_packet[10], unpacked_packet[11], unpacked_packet[12], unpacked_packet[13], unpacked_packet[14], unpacked_packet[15], unpacked_packet[16], unpacked_packet[17], unpacked_packet[18], unpacked_packet[19], unpacked_packet[20], unpacked_packet[21], unpacked_packet[22], unpacked_packet[23], unpacked_packet[24], unpacked_packet[25], unpacked_packet[26], unpacked_packet[27], unpacked_packet[28], unpacked_packet[29], unpacked_packet[30], unpacked_packet[31], unpacked_packet[32], unpacked_packet[33], unpacked_packet[34], unpacked_packet[35], unpacked_packet[36], unpacked_packet[37], unpacked_packet[38], \
			unpacked_packet[39], unpacked_packet[40], unpacked_packet[41], unpacked_packet[42], unpacked_packet[43], unpacked_packet[44], unpacked_packet[45], unpacked_packet[46], unpacked_packet[47], unpacked_packet[48], unpacked_packet[49], unpacked_packet[50], unpacked_packet[51], unpacked_packet[52], unpacked_packet[53], unpacked_packet[54], \
			unpacked_packet[55], unpacked_packet[56], unpacked_packet[57], unpacked_packet[58], unpacked_packet[59], unpacked_packet[60], unpacked_packet[61], unpacked_packet[62], \
			unpacked_packet[63], unpacked_packet[64], unpacked_packet[65], unpacked_packet[66], unpacked_packet[67], unpacked_packet[68], unpacked_packet[69], unpacked_packet[70], \
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
			unpacked_packet[87] \
		)
		if BIG_ENDIAN_HOST:
			auth_packet['length']              = byte_swap_16(auth_packet['length'])
			auth_packet['key_information']     = byte_swap_16(auth_packet['key_information'])
			auth_packet['key_length']          = byte_swap_16(auth_packet['key_length'])
			auth_packet['replay_counter']      = byte_swap_64(auth_packet['replay_counter'])
			auth_packet['wpa_key_data_length'] = byte_swap_16(auth_packet['wpa_key_data_length'])
			auth_packet_copy[2]				   = byte_swap_16(auth_packet_copy[2])
			auth_packet_copy[4]				   = byte_swap_16(auth_packet_copy[4])
			auth_packet_copy[5]				   = byte_swap_16(auth_packet_copy[5])
			auth_packet_copy[6]				   = byte_swap_64(auth_packet_copy[6])
			auth_packet_copy[12]			   = byte_swap_16(auth_packet_copy[12])
		rest_packet = packet[auth_offset+SIZE_OF_auth_packet_t:]
		rc_auth, excpkt = handle_auth(auth_packet, auth_packet_copy, rest_packet, auth_offset, header['caplen'])
		if rc_auth == -1:
			return
		if excpkt['excpkt_num'] == EXC_PKT_NUM_1 or excpkt['excpkt_num'] == EXC_PKT_NUM_3:
			DB.excpkt_add(excpkt_num=excpkt['excpkt_num'], tv_sec=header['tv_sec'], tv_usec=header['tv_usec'], replay_counter=excpkt['replay_counter'], mac_ap=ieee80211_hdr_3addr['addr2'], mac_sta=ieee80211_hdr_3addr['addr1'], nonce=excpkt['nonce'], eapol_len=excpkt['eapol_len'], eapol=excpkt['eapol'], keyver=excpkt['keyver'], keymic=excpkt['keymic'])
			if excpkt['excpkt_num'] == EXC_PKT_NUM_1 and byte_swap_16(auth_packet['key_information']) == 0x008a:
				for pmkid in get_pmkid_from_packet(rest_packet, "EAPOL-M1"):
					DB.pmkid_add(mac_ap=ieee80211_hdr_3addr['addr2'], mac_sta=ieee80211_hdr_3addr['addr1'], pmkid=pmkid)
		elif excpkt['excpkt_num'] == EXC_PKT_NUM_2 or excpkt['excpkt_num'] == EXC_PKT_NUM_4:
			DB.excpkt_add(excpkt_num=excpkt['excpkt_num'], tv_sec=header['tv_sec'], tv_usec=header['tv_usec'], replay_counter=excpkt['replay_counter'], mac_ap=ieee80211_hdr_3addr['addr1'], mac_sta=ieee80211_hdr_3addr['addr2'], nonce=excpkt['nonce'], eapol_len=excpkt['eapol_len'], eapol=excpkt['eapol'], keyver=excpkt['keyver'], keymic=excpkt['keymic'])

######################### READ PACKETS #########################

def read_pcap_packets(cap_file, pcap_file_header, bitness):
	header_count = 0
	header_error = None
	packet_count = 0
	packet_error = None
	chunk = None
	def read(n_bytes):
		nonlocal cap_file
		nonlocal chunk
		try:
			m1 = bytes(islice(chunk, n_bytes))
			if len(m1) == n_bytes:
				return m1
		except:
			m1 = b''
		chunk = iter(m1 +cap_file.read(CHUNK_SIZE))
		m2 = bytes(islice(chunk, n_bytes))
		if len(m2) == n_bytes:
			return m2
		while True:
			chunk = iter(m2 +cap_file.read(CHUNK_SIZE))
			m2_tmp = bytes(islice(chunk, n_bytes))
			if not m2_tmp or m2 == m2_tmp:
				break
			m2 = m2_tmp
			if len(m2) == n_bytes:
				return m2
		return b''	
	while True:
		pcap_pkthdr = read(SIZE_OF_pcap_pkthdr_t)
		if not pcap_pkthdr:
			break
		try:
			header_error = None
			header = dict(pcap_pkthdr_t._asdict(pcap_pkthdr_t._make(struct.unpack('=IIII', pcap_pkthdr))))
			if BIG_ENDIAN_HOST:
				header['tv_sec']   = byte_swap_32(header['tv_sec'])
				header['tv_usec']  = byte_swap_32(header['tv_usec'])
				header['caplen']   = byte_swap_32(header['caplen'])
				header['len']      = byte_swap_32(header['len'])
			if bitness:
				header['tv_sec']   = byte_swap_32(header['tv_sec'])
				header['tv_usec']  = byte_swap_32(header['tv_usec'])
				header['caplen']   = byte_swap_32(header['caplen'])
				header['len']      = byte_swap_32(header['len'])
			if header['tv_sec'] == 0 and header['tv_usec'] == 0:
				header_error = 'Zero value timestamps detected'
				raise ValueError(header_error)
			if header['caplen'] >= TCPDUMP_DECODE_LEN or to_signed_32(header['caplen']) < 0:
				header_error = 'Oversized packet detected'
				raise ValueError(header_error)
			header_count += 1
			try:
				packet_error = None
				packet = read(header['caplen'])
				if pcap_file_header['linktype'] == DLT_IEEE802_11_PRISM:
					if header['caplen'] < SIZE_OF_prism_header_t:
						packet_error = 'Could not read prism header'
						raise ValueError(packet_error)
					unpacked_packet = struct.unpack('=II16cIHHIIHHIIHHIIHHIIHHIIHHIIHHIIHHIIHHIIHHI', packet[:SIZE_OF_prism_header_t])
					prism_header = dict(prism_header_t._asdict(prism_header_t._make(( \
						unpacked_packet[0], \
						unpacked_packet[1], \
						(unpacked_packet[2], unpacked_packet[3], unpacked_packet[4], unpacked_packet[5], unpacked_packet[6], unpacked_packet[7], unpacked_packet[8], unpacked_packet[9], unpacked_packet[10], unpacked_packet[11], unpacked_packet[12], unpacked_packet[13], unpacked_packet[14], unpacked_packet[15], unpacked_packet[16], unpacked_packet[17]), \
						dict(prism_item_t(unpacked_packet[18], unpacked_packet[19], unpacked_packet[20], unpacked_packet[21])._asdict()), \
						dict(prism_item_t(unpacked_packet[22], unpacked_packet[23], unpacked_packet[24], unpacked_packet[25])._asdict()), \
						dict(prism_item_t(unpacked_packet[26], unpacked_packet[27], unpacked_packet[28], unpacked_packet[29])._asdict()), \
						dict(prism_item_t(unpacked_packet[30], unpacked_packet[31], unpacked_packet[32], unpacked_packet[33])._asdict()), \
						dict(prism_item_t(unpacked_packet[34], unpacked_packet[35], unpacked_packet[36], unpacked_packet[37])._asdict()), \
						dict(prism_item_t(unpacked_packet[38], unpacked_packet[39], unpacked_packet[40], unpacked_packet[41])._asdict()), \
						dict(prism_item_t(unpacked_packet[42], unpacked_packet[43], unpacked_packet[44], unpacked_packet[45])._asdict()), \
						dict(prism_item_t(unpacked_packet[46], unpacked_packet[47], unpacked_packet[48], unpacked_packet[49])._asdict()), \
						dict(prism_item_t(unpacked_packet[50], unpacked_packet[51], unpacked_packet[52], unpacked_packet[53])._asdict()), \
						dict(prism_item_t(unpacked_packet[54], unpacked_packet[55], unpacked_packet[56], unpacked_packet[57])._asdict()), \
					))))
					if BIG_ENDIAN_HOST:
						prism_header['msgcode'] = byte_swap_32(prism_header['msgcode'])
						prism_header['msglen']  = byte_swap_32(prism_header['msglen'])
					if (to_signed_32(prism_header['msglen']) < 0):
						packet_error = 'Oversized packet detected'
						raise ValueError(packet_error)
					if (to_signed_32(header['caplen'] - prism_header['msglen']) < 0):
						packet_error = 'Oversized packet detected'
						raise ValueError(packet_error)
					packet = packet[prism_header['msglen']:]
					header['caplen'] -= prism_header['msglen']
					header['len']    -= prism_header['msglen']
				elif pcap_file_header['linktype'] == DLT_IEEE802_11_RADIO:
					if header['caplen'] < SIZE_OF_ieee80211_radiotap_header_t:
						packet_error = 'Could not read radiotap header'
						raise ValueError(packet_error)
					ieee80211_radiotap_header = dict(ieee80211_radiotap_header_t._asdict(ieee80211_radiotap_header_t._make(struct.unpack('=BBHI', packet[:SIZE_OF_ieee80211_radiotap_header_t]))))
					if BIG_ENDIAN_HOST:
						ieee80211_radiotap_header['it_len']     = byte_swap_16(ieee80211_radiotap_header['it_len'])
						ieee80211_radiotap_header['it_present'] = byte_swap_32(ieee80211_radiotap_header['it_present'])
					if ieee80211_radiotap_header['it_version'] != 0:
						packet_error = 'Invalid radiotap header'
						raise ValueError(packet_error)
					packet = packet[ieee80211_radiotap_header['it_len']:]
					header['caplen'] -= ieee80211_radiotap_header['it_len']
					header['len']    -= ieee80211_radiotap_header['it_len']
				elif pcap_file_header['linktype'] == DLT_IEEE802_11_PPI_HDR:
					if header['caplen'] < SIZE_OF_ppi_packet_header_t:
						packet_error = 'Could not read ppi header'
						raise ValueError(packet_error)
					ppi_packet_header = dict(ppi_packet_header_t._asdict(ppi_packet_header_t._make(struct.unpack('=BBHI', packet[:SIZE_OF_ppi_packet_header_t]))))
					if BIG_ENDIAN_HOST:
						ppi_packet_header['pph_len']    = byte_swap_16(ppi_packet_header['pph_len'])
					packet = packet[ppi_packet_header['pph_len']:]
					header['caplen'] -= ppi_packet_header['pph_len']
					header['len']    -= ppi_packet_header['pph_len']
				packet_count += 1
			except:
				packet_error = 'Could not read pcap packet data'
				raise ValueError(packet_error)
		except (ValueError, struct.error):
			continue
		else:
			try:
				STATUS.step_packet()
				STATUS.set_filepos(cap_file.tell())
				process_packet(packet, header)
			except (ValueError, struct.error):
				continue
	if header_count == 0 or packet_count == 0:
		if header_error:
			raise ValueError(header_error)
		elif packet_error:
			raise ValueError(packet_error)
		else:
			raise ValueError('Something went wrong')

def read_pcapng_packets(cap_file, pcapng, pcapng_file_header, bitness, if_tsresol):
	header_count = 0
	header_error = None
	packet_count = 0
	packet_error = None
	while True:
		try:
			header_error = None
			try:
				header_block = next(pcapng)
			except:
				header_block = None
			if not header_block:
				break
			if header_block['block_type'] == Enhanced_Packet_Block:
				pass
			elif header_block['block_type'] == Custom_Block:
				name, data, options = read_custom_block(header_block['block_body'], bitness)
				if name == 'hcxdumptool':
					DB.pcapng_info_add('hcxdumptool', options)
				continue
			elif header_block['block_type'] == Section_Header_Block:
				cap_file.seek(cap_file.tell()-header_block['block_total_length'])
				break
			else:
				continue
			header = {}
			timestamp_high = struct.unpack("I", struct.pack("4B", *header_block['block_body'][4:8]))[0]
			timestamp_low = struct.unpack("I", struct.pack("4B", *header_block['block_body'][8:12]))[0]
			timestamp_high, timestamp_low = byte_swap_32(timestamp_high), timestamp_low
			header['caplen']   = byte_swap_32(struct.unpack("I", struct.pack("4B", *header_block['block_body'][12:16]))[0])
			header['len']      = byte_swap_32(struct.unpack("I", struct.pack("4B", *header_block['block_body'][16:20]))[0])
			header['caplen']   = byte_swap_32(header['caplen'])
			header['len']      = byte_swap_32(header['len'])
			if BIG_ENDIAN_HOST:
				timestamp_high, timestamp_low = byte_swap_32(timestamp_high), timestamp_low
				header['caplen']   = byte_swap_32(header['caplen'])
				header['len']      = byte_swap_32(header['len'])
			if bitness:
				timestamp_high, timestamp_low = byte_swap_32(timestamp_high), timestamp_low
				header['caplen']   = byte_swap_32(header['caplen'])
				header['len']      = byte_swap_32(header['len'])
			header['tv_sec'], header['tv_usec'] = timestamp_high, timestamp_low
			if header['tv_sec'] == 0 and header['tv_usec'] == 0:
				header_error = 'Zero value timestamps detected'
				raise ValueError(header_error)
			if header['caplen'] >= TCPDUMP_DECODE_LEN or to_signed_32(header['caplen']) < 0:
				header_error = 'Oversized packet detected'
				raise ValueError(header_error)
			header_count += 1
			try:
				packet_error = None
				packet = bytes(header_block['block_body'][20:20+header['caplen']])
				if pcapng_file_header['linktype'] == DLT_IEEE802_11_PRISM:
					if header['caplen'] < SIZE_OF_prism_header_t:
						packet_error = 'Could not read prism header'
						raise ValueError(packet_error)
					unpacked_packet = struct.unpack('=II16cIHHIIHHIIHHIIHHIIHHIIHHIIHHIIHHIIHHIIHHI', packet[:SIZE_OF_prism_header_t])
					prism_header = dict(prism_header_t._asdict(prism_header_t._make(( \
						unpacked_packet[0], \
						unpacked_packet[1], \
						(unpacked_packet[2], unpacked_packet[3], unpacked_packet[4], unpacked_packet[5], unpacked_packet[6], unpacked_packet[7], unpacked_packet[8], unpacked_packet[9], unpacked_packet[10], unpacked_packet[11], unpacked_packet[12], unpacked_packet[13], unpacked_packet[14], unpacked_packet[15], unpacked_packet[16], unpacked_packet[17]), \
						dict(prism_item_t(unpacked_packet[18], unpacked_packet[19], unpacked_packet[20], unpacked_packet[21])._asdict()), \
						dict(prism_item_t(unpacked_packet[22], unpacked_packet[23], unpacked_packet[24], unpacked_packet[25])._asdict()), \
						dict(prism_item_t(unpacked_packet[26], unpacked_packet[27], unpacked_packet[28], unpacked_packet[29])._asdict()), \
						dict(prism_item_t(unpacked_packet[30], unpacked_packet[31], unpacked_packet[32], unpacked_packet[33])._asdict()), \
						dict(prism_item_t(unpacked_packet[34], unpacked_packet[35], unpacked_packet[36], unpacked_packet[37])._asdict()), \
						dict(prism_item_t(unpacked_packet[38], unpacked_packet[39], unpacked_packet[40], unpacked_packet[41])._asdict()), \
						dict(prism_item_t(unpacked_packet[42], unpacked_packet[43], unpacked_packet[44], unpacked_packet[45])._asdict()), \
						dict(prism_item_t(unpacked_packet[46], unpacked_packet[47], unpacked_packet[48], unpacked_packet[49])._asdict()), \
						dict(prism_item_t(unpacked_packet[50], unpacked_packet[51], unpacked_packet[52], unpacked_packet[53])._asdict()), \
						dict(prism_item_t(unpacked_packet[54], unpacked_packet[55], unpacked_packet[56], unpacked_packet[57])._asdict()), \
					))))
					if BIG_ENDIAN_HOST:
						prism_header['msgcode'] = byte_swap_32(prism_header['msgcode'])
						prism_header['msglen']  = byte_swap_32(prism_header['msglen'])
					if (to_signed_32(prism_header['msglen']) < 0):
						packet_error = 'Oversized packet detected'
						raise ValueError(packet_error)
					if (to_signed_32(header['caplen'] - prism_header['msglen']) < 0):
						packet_error = 'Oversized packet detected'
						raise ValueError(packet_error)
					packet = packet[prism_header['msglen']:]
					header['caplen'] -= prism_header['msglen']
					header['len']    -= prism_header['msglen']
				elif pcapng_file_header['linktype'] == DLT_IEEE802_11_RADIO:
					if header['caplen'] < SIZE_OF_ieee80211_radiotap_header_t:
						packet_error = 'Could not read radiotap header'
						raise ValueError(packet_error)
					ieee80211_radiotap_header = dict(ieee80211_radiotap_header_t._asdict(ieee80211_radiotap_header_t._make(struct.unpack('=BBHI', packet[:SIZE_OF_ieee80211_radiotap_header_t]))))
					if BIG_ENDIAN_HOST:
						ieee80211_radiotap_header['it_len']     = byte_swap_16(ieee80211_radiotap_header['it_len'])
						ieee80211_radiotap_header['it_present'] = byte_swap_32(ieee80211_radiotap_header['it_present'])
					if ieee80211_radiotap_header['it_version'] != 0:
						packet_error = 'Invalid radiotap header'
						raise ValueError(packet_error)
					packet = packet[ieee80211_radiotap_header['it_len']:]
					header['caplen'] -= ieee80211_radiotap_header['it_len']
					header['len']    -= ieee80211_radiotap_header['it_len']
				elif pcapng_file_header['linktype'] == DLT_IEEE802_11_PPI_HDR:
					if header['caplen'] < SIZE_OF_ppi_packet_header_t:
						packet_error = 'Could not read ppi header'
						raise ValueError(packet_error)
					ppi_packet_header = dict(ppi_packet_header_t._asdict(ppi_packet_header_t._make(struct.unpack('=BBHI', packet[:SIZE_OF_ppi_packet_header_t]))))
					if BIG_ENDIAN_HOST:
						ppi_packet_header['pph_len']    = byte_swap_16(ppi_packet_header['pph_len'])
					packet = packet[ppi_packet_header['pph_len']:]
					header['caplen'] -= ppi_packet_header['pph_len']
					header['len']    -= ppi_packet_header['pph_len']
				packet_count += 1
			except:
				packet_error = 'Could not read pcap packet data'
				raise ValueError(packet_error)
		except (ValueError, struct.error):
			continue
		else:
			try:
				STATUS.step_packet()
				STATUS.set_filepos(cap_file.tell())
				process_packet(packet, header)
			except (ValueError, struct.error):
				continue
	if header_count == 0 or packet_count == 0:
		if header_error:
			raise ValueError(header_error)
		elif packet_error:
			raise ValueError(packet_error)
		else:
			raise ValueError('Something went wrong')

######################### OUTPUT #########################

def build(export, export_unauthenticated=False, filters=None, group_by=None):
	# Workers Manager
	manager = Manager()

	# Lists were we store requested DB operations from our workers
	DB_hcwpaxs_add_list = manager.list()
	DB_hccapx_add_list = manager.list()
	DB_hccapx_groupby_list = manager.list()
	DB_hcpmkid_add_list = manager.list()

	# Helper functions to store each DB req to the right list
	def DB_hcwpaxs_add(**kwords):
		DB_hcwpaxs_add_list.append(kwords)
	def DB_hccapx_add(**kwords):
		DB_hccapx_add_list.append(kwords)
	def DB_hccapx_groupby(**kwords):
		if DB_hccapx_groupby_list:
			return
		DB_hccapx_groupby_list.append(kwords)
	def DB_hcpmkid_add(**kwords):
		DB_hcpmkid_add_list.append(kwords)

	# The work (building)
	def build_chunk(essid_list, DB_hcwpaxs_add_list, DB_hccapx_add_list, DB_hccapx_groupby_list):
		nonlocal export
		nonlocal export_unauthenticated
		nonlocal filters
		nonlocal group_by
		for essid in essid_list.values():
			bssid = bytes(essid['bssid']).hex()
			essidf = essid['essid'].decode(encoding='utf-8', errors='ignore').rstrip('\x00')
			bssidf = ':'.join(bssid[i:i+2] for i in range(0,12,2))
			xprint('\n[*] BSSID={} ESSID={} (Length: {}){}'.format( \
				bssidf, \
				essidf, \
				essid['essid_len'], \
				' [Skipped]' if (filters[0] == "essid" and filters[1] != essidf) or (filters[0] == "bssid" and filters[1] != bssid) else '' \
			))
			### FILTER ###
			if (filters[0] == "essid" and filters[1] != essidf) or (filters[0] == "bssid" and filters[1] != bssid):
				continue
			##############
			excpkts_AP_ = DB.excpkts.get(essid['bssid'])
			if excpkts_AP_:
				for excpkts_AP_STA_ in excpkts_AP_.values():
					excpkts_AP_STA_ap = excpkts_AP_STA_.get('ap')
					if not excpkts_AP_STA_ap:
						continue
					for excpkt_ap in excpkts_AP_STA_ap:
						### PMKID ###
						if export == "hcwpax":
							pmkid = DB.pmkids.get(hash(excpkt_ap['mac_ap']+excpkt_ap['mac_sta']))
							if pmkid:
								DB_hcwpaxs_add(signature=HCWPAX_SIGNATURE, ftype="01", pmkid_or_mic=pmkid['pmkid'], mac_ap=excpkt_ap['mac_ap'], mac_sta=excpkt_ap['mac_sta'], essid=essid['essid'][:essid['essid_len']])
								mac_sta = bytes(excpkt_ap['mac_sta']).hex()
								xprint(' --> STA={} [PMKID {}]'.format( \
									':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
									pmkid['pmkid'] \
								))
								break
						elif export == "hcpmkid":
							pmkid = DB.pmkids.get(hash(excpkt_ap['mac_ap']+excpkt_ap['mac_sta']))
							if pmkid:
								DB_hcpmkid_add(pmkid=pmkid['pmkid'], mac_ap=excpkt_ap['mac_ap'], mac_sta=excpkt_ap['mac_sta'], essid=essid['essid'][:essid['essid_len']])
								mac_sta = bytes(excpkt_ap['mac_sta']).hex()
								xprint(' --> STA={} [PMKID {}]'.format( \
									':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
									pmkid['pmkid'] \
								))
							break
						#############
						excpkts_AP_STA_sta = excpkts_AP_STA_.get('sta')
						if not excpkts_AP_STA_sta:
							continue
						for excpkt_sta in excpkts_AP_STA_sta:
							valid_replay_counter = True if (excpkt_ap['replay_counter'] == excpkt_sta['replay_counter']) else False
							if excpkt_ap['excpkt_num'] < excpkt_sta['excpkt_num']:
								if excpkt_ap['tv_sec'] > excpkt_sta['tv_sec']:
									continue
								if (excpkt_ap['tv_sec'] + EAPOL_TTL) < excpkt_sta['tv_sec']:
									continue
							else:
								if excpkt_sta['tv_sec'] > excpkt_ap['tv_sec']:
									continue
								if (excpkt_sta['tv_sec'] + EAPOL_TTL) < excpkt_ap['tv_sec']:
									continue
							message_pair = 255
							if (excpkt_ap['excpkt_num'] == EXC_PKT_NUM_1) and (excpkt_sta['excpkt_num'] == EXC_PKT_NUM_2):
								if excpkt_sta['eapol_len'] > 0:
									message_pair = MESSAGE_PAIR_M12E2
								else:
									continue
							elif (excpkt_ap['excpkt_num'] == EXC_PKT_NUM_1) and (excpkt_sta['excpkt_num'] == EXC_PKT_NUM_4):
								if excpkt_sta['eapol_len'] > 0:
									message_pair = MESSAGE_PAIR_M14E4
								else:
									continue
							elif (excpkt_ap['excpkt_num'] == EXC_PKT_NUM_3) and (excpkt_sta['excpkt_num'] == EXC_PKT_NUM_2):
								if excpkt_sta['eapol_len'] > 0:
									message_pair = MESSAGE_PAIR_M32E2
								elif excpkt_ap['eapol_len'] > 0:
									message_pair = MESSAGE_PAIR_M32E3
								else:
									continue
							elif (excpkt_ap['excpkt_num'] == EXC_PKT_NUM_3) and (excpkt_sta['excpkt_num'] == EXC_PKT_NUM_4):
								if excpkt_ap['eapol_len'] > 0:
									message_pair = MESSAGE_PAIR_M34E3
								elif excpkt_sta['eapol_len'] > 0:
									message_pair = MESSAGE_PAIR_M34E4
								else:
									continue
							else:
								xprint('[!] BUG! AP:{} STA:{}'.format(excpkt_ap['excpkt_num'], excpkt_sta['excpkt_num']))
							skip = 0
							auth = 1
							ap_less = 0
							if message_pair == MESSAGE_PAIR_M32E3 or message_pair == MESSAGE_PAIR_M34E3:
								skip = 1
							if message_pair == MESSAGE_PAIR_M12E2:
								auth = 0
								### HCXDUMPTOOL (AP-LESS) ###
								if DB.pcapng_info.get('hcxdumptool'):
									for pcapng_info in DB.pcapng_info['hcxdumptool']:
										check_1 = False
										check_2 = False
										for info in pcapng_info:
											if info['code'] == HCXDUMPTOOL_OPTIONCODE_RC:
												if excpkt_ap['replay_counter'] == info['value']:
													check_1 = True
											elif info['code'] == HCXDUMPTOOL_OPTIONCODE_ANONCE:
												if bytes(excpkt_ap['nonce']) == info['value']:
													check_2 = True
										if check_1 and check_2 and message_pair & MESSAGE_PAIR_APLESS != MESSAGE_PAIR_APLESS:
											ap_less = 1
											message_pair |= MESSAGE_PAIR_APLESS
											break
								#############################
							### LE/BE/NC ###
							for excpkt_sta_k in excpkts_AP_STA_sta:
								if (excpkt_ap['nonce'][:28] == excpkt_sta_k['nonce'][:28]) and (excpkt_ap['nonce'][28:] != excpkt_sta_k['nonce'][28:]):
									if message_pair & MESSAGE_PAIR_NC != MESSAGE_PAIR_NC:
										message_pair |= MESSAGE_PAIR_NC
									if excpkt_ap['nonce'][31] != excpkt_sta_k['nonce'][31]:
										if message_pair & MESSAGE_PAIR_LE != MESSAGE_PAIR_LE:
											message_pair |= MESSAGE_PAIR_LE
									elif excpkt_ap['nonce'][28] != excpkt_sta_k['nonce'][28]:
										if message_pair & MESSAGE_PAIR_BE != MESSAGE_PAIR_BE:
											message_pair |= MESSAGE_PAIR_BE
							if not valid_replay_counter and message_pair & MESSAGE_PAIR_NC != MESSAGE_PAIR_NC:
								message_pair |= MESSAGE_PAIR_NC
							################
							mac_sta = bytes(excpkt_sta['mac_sta']).hex()
							if skip == 0:
								if auth == 1:
									xprint(' --> STA={}, Message Pair={}, Replay Counter={}, Authenticated=Y'.format( \
										':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
										message_pair, \
										excpkt_sta['replay_counter'] \
									))
								else:
									xprint(' --> STA={}, Message Pair={}, Replay Counter={}, Authenticated=N{}{}'.format( \
										':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
										message_pair, \
										excpkt_sta['replay_counter'], \
										'' if export_unauthenticated else ' [Skipped]', \
										' (AP-LESS)' if ap_less else '' \
									))
									if not export_unauthenticated:
										continue
							else:
								xprint(' --> STA={}, Message Pair={} [Skipped]'.format( \
									':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
									message_pair \
								))
								continue
							hccapx_to_pack = {}
							hccapx_to_pack['signature'] = HCCAPX_SIGNATURE
							hccapx_to_pack['version'] = HCCAPX_VERSION
							hccapx_to_pack['message_pair'] = message_pair
							hccapx_to_pack['essid_len'] = essid['essid_len']
							hccapx_to_pack['essid'] = essid['essid']
							hccapx_to_pack['mac_ap'] = excpkt_ap['mac_ap']
							hccapx_to_pack['nonce_ap'] = excpkt_ap['nonce']
							hccapx_to_pack['mac_sta'] = excpkt_sta['mac_sta']
							hccapx_to_pack['nonce_sta'] = excpkt_sta['nonce']
							if excpkt_sta['eapol_len'] > 0:
								hccapx_to_pack['keyver'] = excpkt_sta['keyver']
								hccapx_to_pack['keymic'] = excpkt_sta['keymic']
								hccapx_to_pack['eapol_len'] = excpkt_sta['eapol_len']
								hccapx_to_pack['eapol'] = excpkt_sta['eapol']
							else:
								hccapx_to_pack['keyver'] = excpkt_ap['keyver']
								hccapx_to_pack['keymic'] = excpkt_ap['keymic']
								hccapx_to_pack['eapol_len'] = excpkt_ap['eapol_len']
								hccapx_to_pack['eapol'] = excpkt_ap['eapol']
							hccapx_to_pack['essid'] = struct.unpack('=32B', hccapx_to_pack['essid'])
							hccapx_to_pack['eapol'] = struct.unpack('=256B', hccapx_to_pack['eapol'])
							if BIG_ENDIAN_HOST:
								hccapx_to_pack['signature']  = byte_swap_32(hccapx_to_pack['signature'])
								hccapx_to_pack['version']    = byte_swap_32(hccapx_to_pack['version'])
								hccapx_to_pack['eapol_len']  = byte_swap_16(hccapx_to_pack['eapol_len'])
							if export == "hccapx":
								hccapx = struct.pack('=IIBB32BB16B6B32B6B32BH256B',	\
									hccapx_to_pack['signature'], \
									hccapx_to_pack['version'], \
									hccapx_to_pack['message_pair'], \
									hccapx_to_pack['essid_len'], \
									*hccapx_to_pack['essid'], \
									hccapx_to_pack['keyver'], \
									*hccapx_to_pack['keymic'], \
									*hccapx_to_pack['mac_ap'], \
									*hccapx_to_pack['nonce_ap'], \
									*hccapx_to_pack['mac_sta'], \
									*hccapx_to_pack['nonce_sta'], \
									hccapx_to_pack['eapol_len'], \
									*hccapx_to_pack['eapol'] \
								)
								DB_hccapx_add(bssid=bssidf.replace(':', '-').upper(), essid=essidf, raw_data=hccapx)
							elif export == "hcwpax":
								DB_hcwpaxs_add(signature=HCWPAX_SIGNATURE, ftype="02", pmkid_or_mic=hccapx_to_pack['keymic'], mac_ap=hccapx_to_pack['mac_ap'], mac_sta=hccapx_to_pack['mac_sta'], essid=hccapx_to_pack['essid'][:hccapx_to_pack['essid_len']], anonce=hccapx_to_pack['nonce_ap'], eapol=hccapx_to_pack['eapol'][:hccapx_to_pack['eapol_len']], message_pair=hccapx_to_pack['message_pair'])
		if export == "hccapx":
			DB_hccapx_groupby(group_by=group_by)
	
	# Generate tasks
	task_list = []
	for jq in range(0, len(DB.essids), MAX_WORK_PER_PROCESS):
		task = Process(target=build_chunk, args=[dict(list(DB.essids.items())[jq:jq+MAX_WORK_PER_PROCESS]), DB_hcwpaxs_add_list, DB_hccapx_add_list, DB_hccapx_groupby_list])
		task_list.append(task)
	for task in task_list:
		task.start()
	for task in task_list:
		task.join()

	# For each returned DB operation request, perform that operation
	for DB_hcwpaxs_add in DB_hcwpaxs_add_list:
		DB.hcwpaxs_add(**DB_hcwpaxs_add)
	for DB_hccapx_add in DB_hccapx_add_list:
		DB.hccapx_add(**DB_hccapx_add)
	if DB_hccapx_groupby_list:
		DB.hccapx_groupby(**DB_hccapx_groupby_list[0])
	for DB_hcpmkid_add in DB_hcpmkid_add_list:
		DB.hcpmkid_add(**DB_hcpmkid_add)

######################### MAIN #########################

def main():
	if os.path.isfile(args.input):
		cap_file = read_file(args.input)
		STATUS.set_filesize(get_filesize(cap_file))
		try:
			if args.input.lower().endswith('.pcapng') or args.input.lower().endswith('.pcapng.gz'):
				try:
					for pcapng_file_header, bitness, if_tsresol, pcapng in read_pcapng_file_header(cap_file):
						read_pcapng_packets(cap_file, pcapng, pcapng_file_header, bitness, if_tsresol)
				except:
					cap_file.seek(0)
					pcap_file_header, bitness = read_pcap_file_header(cap_file)
					read_pcap_packets(cap_file, pcap_file_header, bitness)
			else:
				try:
					pcap_file_header, bitness = read_pcap_file_header(cap_file)
					read_pcap_packets(cap_file, pcap_file_header, bitness)
				except:
					cap_file.seek(0)
					for pcapng_file_header, bitness, if_tsresol, pcapng in read_pcapng_file_header(cap_file):
						read_pcapng_packets(cap_file, pcapng, pcapng_file_header, bitness, if_tsresol)
		except (ValueError, struct.error) as error:
			xprint(str(error))
			exit()
		else:
			cap_file.close()
			xprint(' '*77, end='\r')

			if len(DB.essids) == 0:
				xprint("No Networks found\n")
				exit()

			xprint("Networks detected: {}".format(len(DB.essids)))
			build(export=args.export, export_unauthenticated=args.all, filters=args.filter_by, group_by=args.group_by)
			if args.export == "hccapx" and len(DB.hccapxs):
				written = 0
				xprint("\nOutput hccapx files:")
				for hccapx in DB.hccapxs:
					if args.output:
						hccapx_filename = (re.sub('\\.hccap(x?)$', '', args.output, flags=re.IGNORECASE)) + get_valid_filename("{}.hccapx".format("_"+str(hccapx['key']) if hccapx['key'] != "none" else ''))
					else:
						if hccapx['key'] == "none":
							hccapx_filename = re.sub('\\.(p?)cap((ng)?)((\\.gz)?)$', '', args.input, flags=re.IGNORECASE) + ".hccapx"
						else:
							hccapx_filename = get_valid_filename("{}.hccapx".format(str(hccapx['key'])))
					print(hccapx_filename)
					hccapx_file = open(hccapx_filename, 'wb')
					hccapx_file.write(b''.join(hccapx['raw_data']))
					hccapx_file.close()
					written += len(hccapx['raw_data'])
				if written:
					xprint("\nWritten {} WPA Handshakes to {} files".format(written, len(DB.hccapxs)), end='')
			elif args.export == "hcwpax" and len(DB.hcwpaxs):
				if args.output:
					written = 0
					xprint("\nOutput hcwpax files:")
					hcwpax_filename = args.output
					print(hcwpax_filename)
					hcwpax_file = open(args.output, 'w')
					for hcwpax in DB.hcwpaxs.values():
						hcwpax_line = '*'.join(hcwpax.values())
						hcwpax_file.write(hcwpax_line+"\n")
						written += 1
					hcwpax_file.close()
					if written:
						xprint("\nWritten {} WPA Handshakes to 1 files".format(written), end='')
				else:
					xprint("\nhcWPAx:")
					for hcwpax in DB.hcwpaxs.values():
						hcwpax_line = '*'.join(hcwpax.values())
						print(hcwpax_line)
			elif args.export == "hcpmkid" and len(DB.hcpmkids):
				if args.output:
					written = 0
					xprint("\nOutput hcpmkid files:")
					hcpmkid_filename = args.output
					print(hcpmkid_filename)
					hcpmkid_file = open(args.output, 'w')
					for hcpmkid in DB.hcpmkids.values():
						hcpmkid_line = '*'.join(hcpmkid.values())
						hcpmkid_file.write(hcpmkid_line+"\n")
						written += 1
					hcpmkid_file.close()
					if written:
						xprint("\nWritten {} WPA Handshakes to 1 files".format(written), end='')
				else:
					xprint("\nhcPMKID:")
					for hcpmkid in DB.hcpmkids.values():
						hcpmkid_line = '*'.join(hcpmkid.values())
						print(hcpmkid_line)
			else:
				xprint("\nNothing exported. You may want to: "+ \
					("\n- Try a different export format (-x/--export)")+ \
					("\n- Use -a/--all to export unauthenticated handshakes" if not args.all else "")+ \
					("\n- Remove the filter (-f/--filter-by)" if args.filter_by != [None, None] else "") \
				)
			xprint()
	else:
		xprint(FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), args.input))
		exit()

#########################
#########################

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Convert a WPA cap/pcap/pcapng capture file to a hashcat hcwpax/hccapx/hcpmkid file', add_help=False)
	required = parser.add_argument_group('required arguments')
	optional = parser.add_argument_group('optional arguments')
	required.add_argument("--input", "-i", help="Input capture file", metavar="capture.cap", required=True)
	required.add_argument("--export", "-x", choices=['hcwpax', 'hccapx', 'hcpmkid'], required=True)
	optional.add_argument("--output", "-o", help="Output file", metavar="capture.hcwpax")
	optional.add_argument("--all", "-a", help="Export all handshakes even unauthenticated ones", action="store_true")
	optional.add_argument("--filter-by", "-f", nargs=2, metavar=('filter-by', 'filter'), help="--filter-by {bssid XX:XX:XX:XX:XX:XX, essid ESSID}", default=[None, None])
	optional.add_argument("--group-by", "-g", choices=['none', 'bssid', 'essid', 'handshake'], default='bssid')
	optional.add_argument("--quiet", "-q", help="Enable quiet mode (print only output files/data)", action="store_true")
	optional.add_argument("--version", "-v", action='version', version=__version__)
	optional.add_argument("--help", "-h", action='help', default=argparse.SUPPRESS,	help='show this help message and exit')
	args = parser.parse_args()
	if args.filter_by[0]:
		if args.filter_by[0] not in ['bssid', 'essid']:
			argparse.ArgumentParser.error(parser, 'argument --filter-by/-f: must be either bssid XX:XX:XX:XX:XX:XX or essid ESSID')
		elif args.filter_by[0] == "bssid": 
			args.filter_by[1] = get_valid_bssid(args.filter_by[1])
			if not args.filter_by[1]:
				argparse.ArgumentParser.error(parser, 'in argument --filter-by/-f: bssid is not valid')
	if args.quiet:
		def xprint(text="", end='\n', flush=True):
			pass
	main()
