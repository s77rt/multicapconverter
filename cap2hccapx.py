#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Abdelhafidh Belalia (s77rt)"
__credits__ = ['Jens Steube <jens.steube@gmail.com>', 'Philipp "philsmd" Schmidt <philsmd@hashcat.net>']
__license__ = "MIT"
__maintainer__ = "Abdelhafidh Belalia (s77rt)"
__email__ = "admin@abdelhafidh.com"

import os
import sys
import argparse
import struct
import copy
import errno
import re
import gzip
from collections import namedtuple
from operator import itemgetter
from itertools import groupby, islice
from enum import Enum

### Endianness ###
if sys.byteorder == "big":
	BIG_ENDIAN_HOST = True
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

TCPDUMP_MAGIC  = 0xa1b2c3d4
TCPDUMP_CIGAM  = 0xd4c3b2a1

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

DB_ESSID_MAX  = 50000
DB_EXCPKT_MAX = 100000

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
###

### Enum-Like ###
class essid_source_t(Enum):
	ESSID_SOURCE_USER           = 1
	ESSID_SOURCE_REASSOC        = 2
	ESSID_SOURCE_ASSOC          = 3
	ESSID_SOURCE_PROBE          = 4
	ESSID_SOURCE_DIRECTED_PROBE = 5
	ESSID_SOURCE_BEACON         = 6
class exc_pkt_num_t(Enum):
	EXC_PKT_NUM_1 = 1
	EXC_PKT_NUM_2 = 2
	EXC_PKT_NUM_3 = 3
	EXC_PKT_NUM_4 = 4
class message_pair_t(Enum):
	MESSAGE_PAIR_M12E2 = 0
	MESSAGE_PAIR_M14E4 = 1
	MESSAGE_PAIR_M32E2 = 2
	MESSAGE_PAIR_M32E3 = 3
	MESSAGE_PAIR_M34E3 = 4
	MESSAGE_PAIR_M34E4 = 5
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
def flatten(l, ltypes=(list, tuple)):
	ltype = type(l)
	l = list(l)
	i = 0
	while i < len(l):
		while isinstance(l[i], ltypes):
			if not l[i]:
				l.pop(i)
				i -= 1
				break
			else:
				l[i:i + 1] = l[i]
		i += 1
	return ltype(l)
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
class hccapxs(list):
	def __init__(self):
		list.__init__(self)
## Database:
class Database(object):
	def __init__(self):
		super(Database, self).__init__()
		self.essids = essids()
		self.excpkts = excpkts()
		self.hccapxs = hccapxs()
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
		key = hash((excpkt_num, pymemcpy(nonce, 32), pymemcpy(mac_ap, 6), pymemcpy(mac_sta, 6), replay_counter))
		self.excpkts.__setitem__(key, {
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
		})
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
DB = Database()
###

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
	else:
		raise ValueError('Invalid pcap header')
	if (pcap_file_header['linktype'] != DLT_IEEE802_11) \
	  and (pcap_file_header['linktype'] != DLT_IEEE802_11_PRISM) \
	  and (pcap_file_header['linktype'] != DLT_IEEE802_11_RADIO) \
	  and (pcap_file_header['linktype'] != DLT_IEEE802_11_PPI_HDR):
		raise ValueError('Unsupported linktype detected')
	return pcap_file_header, bitness

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

def handle_auth(auth_packet, rest_packet, pkt_offset, pkt_size):
	ap_length               = byte_swap_16(auth_packet['length'])
	ap_key_information      = byte_swap_16(auth_packet['key_information'])
	ap_replay_counter       = byte_swap_64(auth_packet['replay_counter'])
	ap_wpa_key_data_length  = byte_swap_16(auth_packet['wpa_key_data_length'])
	if ap_length == 0:
		return -1, None
	if ap_key_information & WPA_KEY_INFO_ACK:
		if ap_key_information & WPA_KEY_INFO_INSTALL:
			excpkt_num = exc_pkt_num_t.EXC_PKT_NUM_3.value
		else:
			excpkt_num = exc_pkt_num_t.EXC_PKT_NUM_1.value
	else:
		if ap_key_information & WPA_KEY_INFO_SECURE:
			excpkt_num = exc_pkt_num_t.EXC_PKT_NUM_4.value
		else:
			excpkt_num = exc_pkt_num_t.EXC_PKT_NUM_2.value
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
	auth_packet_orig = copy.deepcopy(auth_packet)
	if BIG_ENDIAN_HOST:
		auth_packet_orig['length']              = byte_swap_16(auth_packet_orig['length'])
		auth_packet_orig['key_information']     = byte_swap_16(auth_packet_orig['key_information'])
		auth_packet_orig['key_length']          = byte_swap_16(auth_packet_orig['key_length'])
		auth_packet_orig['replay_counter']      = byte_swap_64(auth_packet_orig['replay_counter'])
		auth_packet_orig['wpa_key_data_length'] = byte_swap_16(auth_packet_orig['wpa_key_data_length'])
	auth_packet_orig['wpa_key_mic'] = ZERO*16
	auth_packet_orig_topack = flatten(tuple(auth_packet_orig.values()))
	auth_packet_orig_packed = struct.pack('=BBHBHHQ32B16B8B8B16BH', *auth_packet_orig_topack)
	excpkt['eapol'] = pymemcpy(auth_packet_orig_packed, SIZE_OF_auth_packet_t)
	excpkt['eapol'] += pymemcpy(rest_packet[:ap_wpa_key_data_length], SIZE_OF_EAPOL-SIZE_OF_auth_packet_t)
	excpkt['keymic'] = pymemcpy(auth_packet['wpa_key_mic'], 16)
	excpkt['keyver'] = ap_key_information & WPA_KEY_INFO_TYPE_MASK
	if (excpkt_num == exc_pkt_num_t.EXC_PKT_NUM_3.value) or (excpkt_num == exc_pkt_num_t.EXC_PKT_NUM_4.value):
		excpkt['replay_counter'] -= 1
	return 0, excpkt

def process_packet(packet, header):
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
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=essid_source_t.ESSID_SOURCE_BEACON.value)
		elif stype == IEEE80211_STYPE_PROBE_REQ:
			length_skip = SIZE_OF_ieee80211_hdr_3addr_t
			rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
			if rc_beacon == -1:
				return
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=essid_source_t.ESSID_SOURCE_PROBE.value)
		elif stype == IEEE80211_STYPE_PROBE_RESP:
			length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_beacon_t
			rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
			if rc_beacon == -1:
				return
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=essid_source_t.ESSID_SOURCE_PROBE.value)
		elif stype == IEEE80211_STYPE_ASSOC_REQ:
			length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_assocreq_t
			rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
			if rc_beacon == -1:
				return
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=essid_source_t.ESSID_SOURCE_ASSOC.value)
		elif stype == IEEE80211_STYPE_REASSOC_REQ:
			length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_reassocreq_t
			rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
			if rc_beacon == -1:
				return
			DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=essid_source_t.ESSID_SOURCE_REASSOC.value)
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
		if BIG_ENDIAN_HOST:
			auth_packet['length']              = byte_swap_16(auth_packet['length'])
			auth_packet['key_information']     = byte_swap_16(auth_packet['key_information'])
			auth_packet['key_length']          = byte_swap_16(auth_packet['key_length'])
			auth_packet['replay_counter']      = byte_swap_64(auth_packet['replay_counter'])
			auth_packet['wpa_key_data_length'] = byte_swap_16(auth_packet['wpa_key_data_length'])
		rest_packet = packet[auth_offset+SIZE_OF_auth_packet_t:]
		rc_auth, excpkt = handle_auth(auth_packet, rest_packet, auth_offset, header['caplen'])
		if rc_auth == -1:
			return
		if excpkt['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_1.value or excpkt['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_3.value:
			DB.excpkt_add(excpkt_num=excpkt['excpkt_num'], tv_sec=header['tv_sec'], tv_usec=header['tv_usec'], replay_counter=excpkt['replay_counter'], mac_ap=ieee80211_hdr_3addr['addr2'], mac_sta=ieee80211_hdr_3addr['addr1'], nonce=excpkt['nonce'], eapol_len=excpkt['eapol_len'], eapol=excpkt['eapol'], keyver=excpkt['keyver'], keymic=excpkt['keymic'])
		elif excpkt['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_2.value or excpkt['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_4.value:
			DB.excpkt_add(excpkt_num=excpkt['excpkt_num'], tv_sec=header['tv_sec'], tv_usec=header['tv_usec'], replay_counter=excpkt['replay_counter'], mac_ap=ieee80211_hdr_3addr['addr1'], mac_sta=ieee80211_hdr_3addr['addr2'], nonce=excpkt['nonce'], eapol_len=excpkt['eapol_len'], eapol=excpkt['eapol'], keyver=excpkt['keyver'], keymic=excpkt['keymic'])

def read_packets(pcap, pcap_file_header, bitness):
	header_count = 0
	header_error = None
	packet_count = 0
	packet_error = None
	chunk = None
	def read(n_bytes):
		nonlocal pcap
		nonlocal chunk
		try:
			m1 = bytes(islice(chunk, n_bytes))
			if len(m1) == n_bytes:
				return m1
		except:
			m1 = b''
		chunk = iter(m1 +pcap.read(CHUNK_SIZE))
		m2 = bytes(islice(chunk, n_bytes))
		if len(m2) == n_bytes:
			return m2
		while True:
			chunk = iter(m2 +pcap.read(CHUNK_SIZE))
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
		except (ValueError, struct.error) as error:
			#print("@"+str(pcap.tell()+X)+" --> "+str(error))
			continue
		else:
			try:
				process_packet(packet, header)
			except (ValueError, struct.error) as error:
				#print("@"+str(pcap.tell()+X)+" --> "+str(error))
				continue
	if header_count == 0 or packet_count == 0:
		if header_error:
			raise ValueError(header_error)
		elif packet_error:
			raise ValueError(packet_error)
		else:
			raise ValueError('Something went wrong')

def build_hccapx(export_unauthenticated=False, filters=None, group_by=None):
	for essid in DB.essids.values():
		bssid = bytes(essid['bssid']).hex()
		essidf = essid['essid'].decode(encoding='utf-8', errors='ignore').rstrip('\x00')
		bssidf = ':'.join(bssid[i:i+2] for i in range(0,12,2))
		print('\n[*] BSSID={} ESSID={} (Length: {}){}'.format( \
			bssidf, \
			essidf, \
			essid['essid_len'], \
			' [Skipped]' if (filters[0] == "essid" and filters[1] != essidf) or (filters[0] == "bssid" and filters[1] != bssid) else '' \
		))
		if (filters[0] == "essid" and filters[1] != essidf) or (filters[0] == "bssid" and filters[1] != bssid):
			continue
		for excpkt_ap in DB.excpkts.values():
			if excpkt_ap['excpkt_num'] != exc_pkt_num_t.EXC_PKT_NUM_1.value and excpkt_ap['excpkt_num'] != exc_pkt_num_t.EXC_PKT_NUM_3.value:
				continue
			if excpkt_ap['mac_ap'] != essid['bssid']:
				continue
			for excpkt_sta in DB.excpkts.values():
				if excpkt_sta['excpkt_num'] != exc_pkt_num_t.EXC_PKT_NUM_2.value and excpkt_sta['excpkt_num'] != exc_pkt_num_t.EXC_PKT_NUM_4.value:
					continue
				if excpkt_sta['mac_ap'] != excpkt_ap['mac_ap']:
					continue
				if excpkt_sta['mac_sta'] != excpkt_ap['mac_sta']:
					continue
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
				if (excpkt_ap['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_1.value) and (excpkt_sta['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_2.value):
					if excpkt_sta['eapol_len'] > 0:
						message_pair = message_pair_t.MESSAGE_PAIR_M12E2.value
					else:
						continue
				elif (excpkt_ap['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_1.value) and (excpkt_sta['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_4.value):
					if excpkt_sta['eapol_len'] > 0:
						message_pair = message_pair_t.MESSAGE_PAIR_M14E4.value
					else:
						continue
				elif (excpkt_ap['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_3.value) and (excpkt_sta['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_2.value):
					if excpkt_sta['eapol_len'] > 0:
						message_pair = message_pair_t.MESSAGE_PAIR_M32E2.value
					elif excpkt_ap['eapol_len'] > 0:
						message_pair = message_pair_t.MESSAGE_PAIR_M32E3.value
					else:
						continue
				elif (excpkt_ap['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_3.value) and (excpkt_sta['excpkt_num'] == exc_pkt_num_t.EXC_PKT_NUM_4.value):
					if excpkt_ap['eapol_len'] > 0:
						message_pair = message_pair_t.MESSAGE_PAIR_M34E3.value
					elif excpkt_sta['eapol_len'] > 0:
						message_pair = message_pair_t.MESSAGE_PAIR_M34E4.value
					else:
						continue
				else:
					print('[!] BUG! AP:{} STA:{}'.format(excpkt_ap['excpkt_num'], excpkt_sta['excpkt_num']))
				ok = 1
				auth = 1
				if message_pair == message_pair_t.MESSAGE_PAIR_M32E3.value or message_pair == message_pair_t.MESSAGE_PAIR_M34E3.value:
					ok = 0
				if message_pair == message_pair_t.MESSAGE_PAIR_M12E2.value:
					auth = 0
				mac_sta = bytes(excpkt_sta['mac_sta']).hex()
				if ok == 1:
					if auth == 1:
						print(' --> STA={}, Message Pair={}, Replay Counter={}, Authenticated=Y'.format( \
							':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
							message_pair, \
							excpkt_sta['replay_counter'] \
						))
					else:
						print(' --> STA={}, Message Pair={}, Replay Counter={}, Authenticated=N{}'.format( \
							':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
							message_pair, \
							excpkt_sta['replay_counter'], \
							'' if export_unauthenticated else ' [Skipped]' \
						))
						if not export_unauthenticated:
							continue
				else:
					print(' --> STA={}, Message Pair={} [Skipped]'.format( \
						':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
						message_pair \
					))
					continue
				hccapx_to_pack = {}
				hccapx_to_pack['signature'] = HCCAPX_SIGNATURE
				hccapx_to_pack['version'] = HCCAPX_VERSION
				if not valid_replay_counter:
					message_pair |= 0x80
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
				if BIG_ENDIAN_HOST:
					hccapx_to_pack['signature']  = byte_swap_32(hccapx_to_pack['signature'])
					hccapx_to_pack['version']    = byte_swap_32(hccapx_to_pack['version'])
					hccapx_to_pack['eapol_len']  = byte_swap_16(hccapx_to_pack['eapol_len'])
				hccapx = struct.pack('=IIBB32BB16B6B32B6B32BH256B',	\
					hccapx_to_pack['signature'], \
					hccapx_to_pack['version'], \
					hccapx_to_pack['message_pair'], \
					hccapx_to_pack['essid_len'], \
					*flatten(struct.unpack('=32B', hccapx_to_pack['essid'])), \
					hccapx_to_pack['keyver'], \
					*flatten(hccapx_to_pack['keymic']), \
					*flatten(hccapx_to_pack['mac_ap']), \
					*flatten(hccapx_to_pack['nonce_ap']), \
					*flatten(hccapx_to_pack['mac_sta']), \
					*flatten(hccapx_to_pack['nonce_sta']), \
					hccapx_to_pack['eapol_len'], \
					*flatten(struct.unpack('=256B', hccapx_to_pack['eapol'])) \
				)
				DB.hccapx_add(bssid=bssidf.replace(':', '-').upper(), essid=essidf, raw_data=hccapx)
	DB.hccapx_groupby(group_by)

def main():
	if os.path.isfile(args.input):
		pcap = read_file(args.input)
		try:
			pcap_file_header, bitness = read_pcap_file_header(pcap)
			read_packets(pcap, pcap_file_header, bitness)
		except (ValueError, struct.error) as error:
			exit(str(error))
		else:
			pcap.close()
			if len(DB.essids) == 0:
				exit("No Networks found\n")

			print("Networks detected: {}".format(len(DB.essids)))
			build_hccapx(export_unauthenticated=args.all, filters=args.filter_by, group_by=args.group_by)

			written = 0
			if len(DB.hccapxs):
				print("\nOutput files:")
				for key in DB.hccapxs:
					if args.output:
						hccapx_filename = (re.sub('\\.hccap(x?)$', '', args.output, flags=re.IGNORECASE)) + get_valid_filename("{}.hccapx".format("_"+str(key['key']) if key['key'] != "none" else ''))
					else:
						if key['key'] == "none":
							hccapx_filename = re.sub('\\.(p?)cap((\\.gz)?)$', '', args.input, flags=re.IGNORECASE) + ".hccapx"
						else:
							hccapx_filename = get_valid_filename("{}.hccapx".format(str(key['key'])))
					print(hccapx_filename)
					hccapx = open(hccapx_filename, 'wb')
					hccapx.write(b''.join(key['raw_data']))
					hccapx.close()
					written += len(key['raw_data'])
				if written:
					print("\nWritten {} WPA Handshakes to {} files".format(written, len(DB.hccapxs)), end='')
			print()
	else:
		exit(FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), args.input))

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'Convert a WPA pcap capture file to a hashcat capture file', add_help=False)
	required = parser.add_argument_group('required arguments')
	optional = parser.add_argument_group('optional arguments')
	optional.add_argument(
		'-h',
		'--help',
		action='help',
		default=argparse.SUPPRESS,
		help='show this help message and exit'
	)
	required.add_argument("--input", "-i", help="Input capture file", metavar="capture.cap", required=True)
	optional.add_argument("--output", "-o", help="Output hccapx file", metavar="capture.hccapx")
	optional.add_argument("--all", "-a", help="Export all handshakes even unauthenticated ones", action="store_true")
	optional.add_argument("--filter-by", "-f", nargs=2, metavar=('filter-by', 'filter'), help="--filter-by {bssid XX:XX:XX:XX:XX:XX, essid ESSID}", default=[None, None])
	optional.add_argument("--group-by", "-g", choices=['none', 'bssid', 'essid', 'handshake'], default='bssid')
	args = parser.parse_args()
	if args.filter_by[0]:
		if args.filter_by[0] not in ['bssid', 'essid']:
			argparse.ArgumentParser.error(parser, 'argument --filter-by/-f: must be either bssid XX:XX:XX:XX:XX:XX or essid ESSID')
		elif args.filter_by[0] == "bssid": 
			args.filter_by[1] = get_valid_bssid(args.filter_by[1])
			if not args.filter_by[1]:
				argparse.ArgumentParser.error(parser, 'in argument --filter-by/-f: bssid is not valid')
	main()
