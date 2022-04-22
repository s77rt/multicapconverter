#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Abdelhafidh Belalia (s77rt)"
__credits__ = ['Jens Steube <jens.steube@gmail.com>', 'Philipp "philsmd" Schmidt <philsmd@hashcat.net>', 'ZerBea (https://github.com/ZerBea)', 'RealEnder (https://github.com/RealEnder)', 'Carmix (https://github.com/gcarmix)']
__license__ = "MIT"
__maintainer__ = "Abdelhafidh Belalia (s77rt)"
__email__ = "admin@abdelhafidh.com"
__version__ = "1.1.2"
__github__ = "https://github.com/s77rt/multicapconverter/"

import os
import sys
import argparse
import errno
import re
import gzip
import requests
import time
from operator import itemgetter
from itertools import groupby
from multiprocessing import Process, Manager

###### User Configurations #####
""" The api key below is temporarily
Get your api key from https://hashc.co.uk/
Or contact support@hashc.co.uk
IMPORTANT: DO NOT change the api key below, instead use the environment variable: hashC_APIKEY
"""
hashC_APIKEY = os.environ.get('hashC_APIKEY', 'TESTxQfS8hIKcALYZIfYz14IYGxbWQbJ0mKLFE7e0hIbIIt4J3K7Ce5Xcdshqngr')
################################

### Endianness ###
if sys.byteorder == "big":
	BIG_ENDIAN_HOST = True
	xprint("WARNING! Endianness is not well tested on BIG_ENDIAN_HOST.")
else:
	BIG_ENDIAN_HOST = False
###

### Constants ###
OUI_DB_FILE = os.path.join(os.path.expanduser('~'), "oui.csv")
OUI_DB_URL = "http://standards-oui.ieee.org/oui/oui.csv"

HCCAPX_VERSION   =  4
HCCAPX_SIGNATURE = 0x58504348 # HCPX

HCWPAX_SIGNATURE = "WPA"

TCPDUMP_MAGIC  = 0xa1b2c3d4
TCPDUMP_CIGAM  = 0xd4c3b2a1

PCAPNG_MAGIC = 0x1A2B3C4D
PCAPNG_CIGAM = 0xD4C3B2A1

TCPDUMP_DECODE_LEN  = 65535

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
IEEE80211_STYPE_REASSOC_REQ    = 0x0020
IEEE80211_STYPE_PROBE_REQ      = 0x0040
IEEE80211_STYPE_PROBE_RESP     = 0x0050
IEEE80211_STYPE_BEACON         = 0x0080
IEEE80211_STYPE_QOS_DATA       = 0x0080

IEEE80211_LLC_DSAP               = 0xAA
IEEE80211_LLC_SSAP               = 0xAA
IEEE80211_LLC_CTRL               = 0x03
IEEE80211_DOT1X_AUTHENTICATION   = 0x8E88

MFIE_TYPE_SSID       = 0
MFIE_TYPE_RATES      = 1

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
SIZE_OF_EAPOL = 256

AUTH_EAP = 0
AUTH_EAPOL = 3
AUTH_EAP_MD5 = 4
AUTH_EAP_LEAP = 17

BROADCAST_MAC = (255, 255, 255, 255, 255, 255)
MAX_ESSID_LEN =  32
EAPOL_TTL = 1
ZERO = b'\x00'

WPA_KEY_INFO_TYPE_MASK = 7
WPA_KEY_INFO_INSTALL = 64
WPA_KEY_INFO_ACK = 128
WPA_KEY_INFO_SECURE = 512

ESSID_SOURCE_REASSOC        = 20
ESSID_SOURCE_ASSOC          = 30
ESSID_SOURCE_PROBE          = 40
ESSID_SOURCE_BEACON         = 60

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

Enhanced_Packet_Block       = 0x00000006
Section_Header_Block = 0x0A0D0D0A
Custom_Block = 0x0000000bad
Custom_Option_Codes = [2988, 2989, 19372, 19373]
if_tsresol_code = 9
opt_endofopt = 0

HCXDUMPTOOL_PEN = bytes([0x2a, 0xce, 0x46, 0xa1])
HCXDUMPTOOL_MAGIC_NUMBER = bytes([0x2a, 0xce, 0x46, 0xa1, 0x79, 0xa0, 0x72, 0x33, 0x83, 0x37, 0x27, 0xab, 0x59, 0x33, 0xb3, 0x62, 0x45, 0x37, 0x11, 0x47, 0xa7, 0xcf, 0x32, 0x7f, 0x8d, 0x69, 0x80, 0xc0, 0x89, 0x5e, 0x5e, 0x98])
HCXDUMPTOOL_OPTIONCODE_RC			= 0xf29c
HCXDUMPTOOL_OPTIONCODE_ANONCE		= 0xf29d

SUITE_OUI = b'\x00\x0f\xac'
AK_PSK = 2
AK_PSKSHA256 = 6
AK_SAFE = -1

DB_ESSID_MAX  = 50000
DB_EXCPKT_MAX = 100000
MAX_WORK_PER_PROCESS = 100

custom_essid = b''

# Log Levels
INFO = 10
WARNING = 20
ERROR = 30
CRITICAL = 40
DEBUG = 50
###

### LOGGER ###
class l_messages(dict):
	def log(self, key, value=1):
		"""
		key => message
		value => counter of message
		"""
		if key not in self:
			dict.__setitem__(self, key, value)
		else:
			self[key] += value
class Logger(object):
	def __init__(self):
		super(Logger, self).__init__()
		self.info = l_messages()
		self.warning = l_messages()
		self.error = l_messages()
		self.critical = l_messages()
		self.debug = l_messages()
	def log(self, message, level):
		if level >= DEBUG:
			self.debug.log(message)
		elif level >= CRITICAL:
			self.critical.log(message)
		elif level >= ERROR:
			self.error.log(message)
		elif level >= WARNING:
			self.warning.log(message)
		else:
			self.info.log(message)
LOGGER = Logger()
###

### H-Functions ###
def GetUint16(b):
	return b[0] | b[1] << 8
def GetUint32(b):
	return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24
def GetUint64(b):
	return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24 | b[4] << 32 | b[5] << 40 | b[6] << 48 | b[7] << 56
def PutUint16(v):
	return ((v & 0x00ff), (v & 0xff00) >> 8)
def PutUint32(v):
	return ((v & 0x000000ff), (v & 0x0000ff00) >> 8, (v & 0x00ff0000) >> 16, (v & 0xff000000) >> 24)
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
#
def get_valid_bssid(bssid):
	bssid = re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", bssid.lower())
	if bssid:
		return bssid[0].replace(':', '').replace('-', '')
def get_valid_filename(s, r='_'):
	s = str(s).strip().replace(' ', '_')
	return re.sub(r'(?u)[^-\w.\@]', r, s)
def xprint(text="", end='\n', flush=True):
	print(text, end=end, flush=flush)
###

### MAC LOOKUP ###
# VENDOR LOOKUP
class MAC_VENDOR_LOOKUP(object):
	def __init__(self, db):
		super(MAC_VENDOR_LOOKUP, self).__init__()
		self.db_isUpdated = False
		if not os.path.isfile(db):
			self.download_db(db)
		self.db = db
		self.data = {}
		self.load_data()
	def download_db(self, db):
		if self.db_isUpdated:
			return
		if os.path.isfile(db):
			os.remove(db)
		xprint("[i] Downloading OUI Database...", end='\r', flush=True)
		response = requests.get(OUI_DB_URL, stream=True)
		filesize_total = int(response.headers.get('content-length', 1))
		filesize_downloaded = 0
		prev_time = time.time()
		with open(db+'.tmp', "wb") as handle:
			for data in response.iter_content():
				filesize_downloaded += len(data)
				if time.time() - prev_time > 1:
					if filesize_total > 1:
						xprint('[i] Downloading OUI Database...{:05.2f}%'.format((filesize_downloaded/filesize_total)*100), end='\r', flush=True)
					prev_time = time.time()
				handle.write(data)
		os.rename(db+'.tmp', db)
		self.db_isUpdated = True
		xprint("[i] Downloading OUI Database.......OK", flush=True)
	def load_data(self):
		with open(self.db, 'r') as dbfile:
			for line in dbfile:
				try:
					vendor = re.search(r',([0-9A-F]{6}),(?:(?:"(.+?)",)|(.+?),)', line)
					self.data[vendor.group(1)] = vendor.group(2) or vendor.group(3)
				except:
					pass
	def lookup(self, mac):
		return self.data.get(mac[:6].upper(), 'N/A')
# GEOLOCATION LOOKUP
class MAC_GEO_LOOKUP(object):
	def __init__(self):
		super(MAC_GEO_LOOKUP, self).__init__()
		self.bbox = {
			'Afghanistan': [29.3772, 38.4910682, 60.5176034, 74.889862],
			'Aland Islands': [59.4541578, 60.87665, 19.0832098, 21.3456556],
			'Albania': [39.6448625, 42.6610848, 19.1246095, 21.0574335],
			'Algeria': [18.968147, 37.2962055, -8.668908, 11.997337],
			'American Samoa': [-14.7608358, -10.8449746, -171.2951296, -167.9322899],
			'Andorra': [42.4288238, 42.6559357, 1.4135781, 1.7863837],
			'Angola': [-18.038945, -4.3880634, 11.4609793, 24.0878856],
			'Anguilla': [18.0615454, 18.7951194, -63.6391992, -62.7125449],
			'Antarctica': [-85.0511287, -60.0, -180.0, 180.0],
			'Antigua and Barbuda': [16.7573901, 17.929, -62.5536517, -61.447857],
			'Argentina': [-55.1850761, -21.781168, -73.5600329, -53.6374515],
			'Armenia': [38.8404775, 41.300712, 43.4471395, 46.6333087],
			'Aruba': [12.1702998, 12.8102998, -70.2809842, -69.6409842],
			'Australia': [-55.3228175, -9.0882278, 72.2460938, 168.2249543],
			'Austria': [46.3722761, 49.0205305, 9.5307487, 17.160776],
			'Azerbaijan': [38.3929551, 41.9502947, 44.7633701, 51.0090302],
			'Bahamas': [20.7059846, 27.4734551, -80.7001941, -72.4477521],
			'Bahrain': [25.535, 26.6872444, 50.2697989, 50.9233693],
			'Bangladesh': [20.3756582, 26.6382534, 88.0075306, 92.6804979],
			'Barbados': [12.845, 13.535, -59.8562115, -59.2147175],
			'Belarus': [51.2575982, 56.17218, 23.1783344, 32.7627809],
			'Belgium': [49.4969821, 51.5516667, 2.3889137, 6.408097],
			'Belize': [15.8857286, 18.496001, -89.2262083, -87.3098494],
			'Benin': [6.0398696, 12.4092447, 0.776667, 3.843343],
			'Bermuda': [32.0469651, 32.5913693, -65.1232222, -64.4109842],
			'Bhutan': [26.702016, 28.246987, 88.7464724, 92.1252321],
			'Bolivia': [-22.8982742, -9.6689438, -69.6450073, -57.453],
			'Bosnia and Herzegovina': [42.5553114, 45.2764135, 15.7287433, 19.6237311],
			'Botswana': [-26.9059669, -17.778137, 19.9986474, 29.375304],
			'Bouvet Island': [-54.654, -54.187, 2.9345531, 3.7791099],
			'Brazil': [-33.8689056, 5.2842873, -73.9830625, -28.6341164],
			'British Indian Ocean Territory': [-7.6454079, -5.037066, 71.036504, 72.7020157],
			'British Virgin Islands': [17.623468, 18.464984, -65.159094, -64.512674],
			'Brunei': [4.002508, 5.1011857, 114.0758734, 115.3635623],
			'Bulgaria': [41.2353929, 44.2167064, 22.3571459, 28.8875409],
			'Burkina Faso': [9.4104718, 15.084, -5.5132416, 2.4089717],
			'Burundi': [-4.4693155, -2.3096796, 29.0007401, 30.8498462],
			'Cambodia': [9.4752639, 14.6904224, 102.3338282, 107.6276788],
			'Cameroon': [1.6546659, 13.083333, 8.3822176, 16.1921476],
			'Canada': [41.6765556, 83.3362128, -141.00275, -52.3231981],
			'Cape Verde': [14.8031546, 17.2053108, -25.3609478, -22.6673416],
			'Cayman Islands': [19.0620619, 19.9573759, -81.6313748, -79.5110954],
			'Central African Republic': [2.2156553, 11.001389, 14.4155426, 27.4540764],
			'Chad': [7.44107, 23.4975, 13.47348, 24.0],
			'Chile': [-56.725, -17.4983998, -109.6795789, -66.0753474],
			'China': [8.8383436, 53.5608154, 73.4997347, 134.7754563],
			'Christmas Island': [-10.5698515, -10.4123553, 105.5336422, 105.7130159],
			'Cocos Islands': [-12.4055983, -11.6213132, 96.612524, 97.1357343],
			'Colombia': [-4.2316872, 16.0571269, -82.1243666, -66.8511907],
			'Comoros': [-12.621, -11.165, 43.025305, 44.7451922],
			'Cook Islands': [-22.15807, -8.7168792, -166.0856468, -157.1089329],
			'Costa Rica': [5.3329698, 11.2195684, -87.2722647, -82.5060208],
			'Croatia': [42.1765993, 46.555029, 13.2104814, 19.4470842],
			'Cuba': [19.6275294, 23.4816972, -85.1679702, -73.9190004],
			'Cyprus': [34.4383706, 35.913252, 32.0227581, 34.8553182],
			'Czech Republic': [48.5518083, 51.0557036, 12.0905901, 18.859216],
			'Democratic Republic of the Congo': [-13.459035, 5.3920026, 12.039074, 31.3056758],
			'Denmark': [54.4516667, 57.9524297, 7.7153255, 15.5530641],
			'Djibouti': [10.9149547, 12.7923081, 41.7713139, 43.6579046],
			'Dominica': [15.0074207, 15.7872222, -61.6869184, -61.0329895],
			'Dominican Republic': [17.2701708, 21.303433, -72.0574706, -68.1101463],
			'East Timor': [-9.5642775, -8.0895459, 124.0415703, 127.5335392],
			'Ecuador': [-5.0159314, 1.8835964, -92.2072392, -75.192504],
			'Egypt': [22.0, 31.8330854, 24.6499112, 37.1153517],
			'El Salvador': [12.976046, 14.4510488, -90.1790975, -87.6351394],
			'Equatorial Guinea': [-1.6732196, 3.989, 5.4172943, 11.3598628],
			'Eritrea': [12.3548219, 18.0709917, 36.4333653, 43.3001714],
			'Estonia': [57.5092997, 59.9383754, 21.3826069, 28.2100175],
			'Ethiopia': [3.397448, 14.8940537, 32.9975838, 47.9823797],
			'Falkland Islands': [-53.1186766, -50.7973007, -61.7726772, -57.3662367],
			'Faroe Islands': [61.3915553, 62.3942991, -7.6882939, -6.2565525],
			'Fiji': [-21.9434274, -12.2613866, 172.0, -178.5],
			'Finland': [59.4541578, 70.0922939, 19.0832098, 31.5867071],
			'France': [41.2632185, 51.268318, -5.4534286, 9.8678344],
			'French Guiana': [2.112222, 5.7507111, -54.60278, -51.6346139],
			'French Polynesia': [-28.0990232, -7.6592173, -154.9360599, -134.244799],
			'French Southern Territories': [-50.2187169, -11.3139928, 39.4138676, 77.8494974],
			'Gabon': [-4.1012261, 2.3182171, 8.5002246, 14.539444],
			'Gambia': [13.061, 13.8253137, -17.0288254, -13.797778],
			'Georgia': [41.0552922, 43.5864294, 39.8844803, 46.7365373],
			'Germany': [47.2701114, 55.099161, 5.8663153, 15.0419319],
			'Ghana': [4.5392525, 11.1748562, -3.260786, 1.2732942],
			'Gibraltar': [36.100807, 36.180807, -5.3941295, -5.3141295],
			'Greece': [34.7006096, 41.7488862, 19.2477876, 29.7296986],
			'Greenland': [59.515387, 83.875172, -74.1250416, -10.0288759],
			'Grenada': [11.786, 12.5966532, -62.0065868, -61.1732143],
			'Guadeloupe': [15.8320085, 16.5144664, -61.809764, -61.0003663],
			'Guam': [13.182335, 13.706179, 144.563426, 145.009167],
			'Guatemala': [13.6345804, 17.8165947, -92.3105242, -88.1755849],
			'Guernsey': [49.4155331, 49.5090776, -2.6751703, -2.501814],
			'Guinea': [7.1906045, 12.67563, -15.5680508, -7.6381993],
			'Guinea-Bissau': [10.6514215, 12.6862384, -16.894523, -13.6348777],
			'Guyana': [1.1710017, 8.6038842, -61.414905, -56.4689543],
			'Haiti': [17.9099291, 20.2181368, -75.2384618, -71.6217461],
			'Heard Island and McDonald Islands': [-53.394741, -52.7030677, 72.2460938, 74.1988754],
			'Honduras': [12.9808485, 17.619526, -89.3568207, -82.1729621],
			'Hong Kong': [22.1193278, 22.4393278, 114.0028131, 114.3228131],
			'Hungary': [45.737128, 48.585257, 16.1138867, 22.8977094],
			'Iceland': [63.0859177, 67.353, -25.0135069, -12.8046162],
			'India': [6.5546079, 35.6745457, 68.1113787, 97.395561],
			'Indonesia': [-11.2085669, 6.2744496, 94.7717124, 141.0194444],
			'Iran': [24.8465103, 39.7816502, 44.0318908, 63.3332704],
			'Iraq': [29.0585661, 37.380932, 38.7936719, 48.8412702],
			'Ireland': [51.222, 55.636, -11.0133788, -5.6582363],
			'Isle of Man': [54.0539576, 54.4178705, -4.7946845, -4.3076853],
			'Israel': [29.4533796, 33.3356317, 34.2674994, 35.8950234],
			'Italy': [35.2889616, 47.0921462, 6.6272658, 18.7844746],
			'Ivory Coast': [4.1621205, 10.740197, -8.601725, -2.493031],
			'Jamaica': [16.5899443, 18.7256394, -78.5782366, -75.7541143],
			'Japan': [20.2145811, 45.7112046, 122.7141754, 154.205541],
			'Jersey': [49.1625179, 49.2621288, -2.254512, -2.0104193],
			'Jordan': [29.183401, 33.3750617, 34.8844372, 39.3012981],
			'Kazakhstan': [40.5686476, 55.4421701, 46.4932179, 87.3156316],
			'Kenya': [-4.8995204, 4.62, 33.9098987, 41.899578],
			'Kiribati': [-7.0516717, 7.9483283, -179.1645388, -164.1645388],
			'Kuwait': [28.5243622, 30.1038082, 46.5526837, 49.0046809],
			'Kyrgyzstan': [39.1728437, 43.2667971, 69.2649523, 80.2295793],
			'Laos': [13.9096752, 22.5086717, 100.0843247, 107.6349989],
			'Latvia': [55.6746505, 58.0855688, 20.6715407, 28.2414904],
			'Lebanon': [33.0479858, 34.6923543, 34.8825667, 36.625],
			'Lesotho': [-30.6772773, -28.570615, 27.0114632, 29.4557099],
			'Liberia': [4.1555907, 8.5519861, -11.6080764, -7.367323],
			'Libya': [19.5008138, 33.3545898, 9.391081, 25.3770629],
			'Liechtenstein': [47.0484291, 47.270581, 9.4716736, 9.6357143],
			'Lithuania': [53.8967893, 56.4504213, 20.653783, 26.8355198],
			'Luxembourg': [49.4969821, 50.430377, 4.9684415, 6.0344254],
			'Macao': [22.0766667, 22.2170361, 113.5281666, 113.6301389],
			'Macedonia': [40.8536596, 42.3735359, 20.4529023, 23.034051],
			'Madagascar': [-25.6071002, -11.9519693, 43.2202072, 50.4862553],
			'Malawi': [-17.1296031, -9.3683261, 32.6703616, 35.9185731],
			'Malaysia': [-5.1076241, 9.8923759, 105.3471939, 120.3471939],
			'Maldives': [-0.9074935, 7.3106246, 72.3554187, 73.9700962],
			'Mali': [10.147811, 25.001084, -12.2402835, 4.2673828],
			'Malta': [35.6029696, 36.2852706, 13.9324226, 14.8267966],
			'Marshall Islands': [-0.5481258, 14.4518742, 163.4985095, 178.4985095],
			'Martinique': [14.3948596, 14.8787029, -61.2290815, -60.8095833],
			'Mauritania': [14.7209909, 27.314942, -17.068081, -4.8333344],
			'Mauritius': [-20.725, -10.138, 56.3825151, 63.7151319],
			'Mayotte': [-13.0210119, -12.6365902, 45.0183298, 45.2999917],
			'Mexico': [14.3886243, 32.7186553, -118.59919, -86.493266],
			'Micronesia': [0.827, 10.291, 137.2234512, 163.2364054],
			'Moldova': [45.4674139, 48.4918695, 26.6162189, 30.1636756],
			'Monaco': [43.7247599, 43.7519311, 7.4090279, 7.4398704],
			'Mongolia': [41.5800276, 52.1496, 87.73762, 119.931949],
			'Montenegro': [41.7495999, 43.5585061, 18.4195781, 20.3561641],
			'Montserrat': [16.475, 17.0152978, -62.450667, -61.9353818],
			'Morocco': [21.3365321, 36.0505269, -17.2551456, -0.998429],
			'Mozambique': [-26.9209427, -10.3252149, 30.2138197, 41.0545908],
			'Myanmar': [9.4399432, 28.547835, 92.1719423, 101.1700796],
			'Namibia': [-28.96945, -16.9634855, 11.5280384, 25.2617671],
			'Nauru': [-0.5541334, -0.5025906, 166.9091794, 166.9589235],
			'Nepal': [26.3477581, 30.446945, 80.0586226, 88.2015257],
			'Netherlands': [50.7295671, 53.7253321, 1.9193492, 7.2274985],
			'Netherlands Antilles': [12.1544542, 12.1547472, -68.940593, -68.9403518],
			'New Caledonia': [-23.2217509, -17.6868616, 162.6034343, 167.8109827],
			'New Zealand': [-52.8213687, -29.0303303, -179.059153, 179.3643594],
			'Nicaragua': [10.7076565, 15.0331183, -87.901532, -82.6227023],
			'Niger': [11.693756, 23.517178, 0.1689653, 15.996667],
			'Nigeria': [4.0690959, 13.885645, 2.676932, 14.678014],
			'Niue': [-19.3548665, -18.7534559, -170.1595029, -169.5647229],
			'Norfolk Island': [-29.333, -28.796, 167.6873878, 168.2249543],
			'North Korea': [37.5867855, 43.0089642, 124.0913902, 130.924647],
			'Northern Mariana Islands': [14.036565, 20.616556, 144.813338, 146.154418],
			'Norway': [57.7590052, 71.3848787, 4.0875274, 31.7614911],
			'Oman': [16.4649608, 26.7026737, 52, 60.054577],
			'Pakistan': [23.5393916, 37.084107, 60.872855, 77.1203914],
			'Palau': [2.748, 8.222, 131.0685462, 134.7714735],
			'Palestinian Territory': [31.2201289, 32.5521479, 34.0689732, 35.5739235],
			'Panama': [7.0338679, 9.8701757, -83.0517245, -77.1393779],
			'Papua New Guinea': [-13.1816069, 1.8183931, 136.7489081, 151.7489081],
			'Paraguay': [-27.6063935, -19.2876472, -62.6442036, -54.258],
			'Peru': [-20.1984472, -0.0392818, -84.6356535, -68.6519906],
			'Philippines': [4.2158064, 21.3217806, 114.0952145, 126.8072562],
			'Pitcairn': [-25.1306736, -23.8655769, -130.8049862, -124.717534],
			'Poland': [49.0020468, 55.0336963, 14.1229707, 24.145783],
			'Portugal': [29.8288021, 42.1543112, -31.5575303, -6.1891593],
			'Puerto Rico': [17.9268695, 18.5159789, -67.271492, -65.5897525],
			'Qatar': [24.4707534, 26.3830212, 50.5675, 52.638011],
			'Republic of the Congo': [-5.149089, 3.713056, 11.0048205, 18.643611],
			'Reunion': [-21.3897308, -20.8717136, 55.2164268, 55.8366924],
			'Romania': [43.618682, 48.2653964, 20.2619773, 30.0454257],
			'Russia': [41.1850968, 82.0586232, 19.6389, 180],
			'Rwanda': [-2.8389804, -1.0474083, 28.8617546, 30.8990738],
			'Saint Barthelemy': [17.670931, 18.1375569, -63.06639, -62.5844019],
			'Saint Helena': [-16.23, -15.704, -5.9973424, -5.4234153],
			'Saint Kitts and Nevis': [16.895, 17.6158146, -63.051129, -62.3303519],
			'Saint Lucia': [13.508, 14.2725, -61.2853867, -60.6669363],
			'Saint Martin': [17.8963535, 18.1902778, -63.3605643, -62.7644063],
			'Saint Pierre and Miquelon': [46.5507173, 47.365, -56.6972961, -55.9033333],
			'Saint Vincent and the Grenadines': [12.5166548, 13.583, -61.6657471, -60.9094146],
			'Samoa': [-14.2770916, -13.2381892, -173.0091864, -171.1929229],
			'San Marino': [43.8937002, 43.992093, 12.4033246, 12.5160665],
			'Sao Tome and Principe': [-0.2135137, 1.9257601, 6.260642, 7.6704783],
			'Saudi Arabia': [16.29, 32.1543377, 34.4571718, 55.6666851],
			'Senegal': [12.2372838, 16.6919712, -17.7862419, -11.3458996],
			'Serbia': [42.2322435, 46.1900524, 18.8142875, 23.006309],
			'Seychelles': [-10.4649258, -3.512, 45.9988759, 56.4979396],
			'Sierra Leone': [6.755, 9.999973, -13.5003389, -10.271683],
			'Singapore': [1.1304753, 1.4504753, 103.6920359, 104.0120359],
			'Slovakia': [47.7314286, 49.6138162, 16.8331891, 22.56571],
			'Slovenia': [45.4214242, 46.8766816, 13.3754696, 16.5967702],
			'Solomon Islands': [-13.2424298, -4.81085, 155.3190556, 170.3964667],
			'Somalia': [-1.8031969, 12.1889121, 40.98918, 51.6177696],
			'South Africa': [-47.1788335, -22.1250301, 16.3335213, 38.2898954],
			'South Georgia and the South Sandwich Islands': [-59.684, -53.3500755, -42.354739, -25.8468303],
			'South Korea': [32.9104556, 38.623477, 124.354847, 132.1467806],
			'Spain': [27.4335426, 43.9933088, -18.3936845, 4.5918885],
			'Sri Lanka': [5.719, 10.035, 79.3959205, 82.0810141],
			'Sudan': [8.685278, 22.224918, 21.8145046, 39.0576252],
			'Suriname': [1.8312802, 6.225, -58.070833, -53.8433358],
			'Svalbard and Jan Mayen': [70.6260825, 81.028076, -9.6848146, 34.6891253],
			'Swaziland': [-27.3175201, -25.71876, 30.7908, 32.1349923],
			'Sweden': [55.1331192, 69.0599699, 10.5930952, 24.1776819],
			'Switzerland': [45.817995, 47.8084648, 5.9559113, 10.4922941],
			'Syria': [32.311354, 37.3184589, 35.4714427, 42.3745687],
			'Taiwan': [10.374269, 26.4372222, 114.3599058, 122.297],
			'Tajikistan': [36.6711153, 41.0450935, 67.3332775, 75.1539563],
			'Tanzania': [-11.761254, -0.9854812, 29.3269773, 40.6584071],
			'Thailand': [5.612851, 20.4648337, 97.3438072, 105.636812],
			'Togo': [5.926547, 11.1395102, -0.1439746, 1.8087605],
			'Tokelau': [-9.6442499, -8.3328631, -172.7213673, -170.9797586],
			'Tonga': [-24.1034499, -15.3655722, -179.3866055, -173.5295458],
			'Trinidad and Tobago': [9.8732106, 11.5628372, -62.083056, -60.2895848],
			'Tunisia': [30.230236, 37.7612052, 7.5219807, 11.8801133],
			'Turkey': [35.8076804, 42.297, 25.6212891, 44.8176638],
			'Turkmenistan': [35.129093, 42.7975571, 52.335076, 66.6895177],
			'Turks and Caicos Islands': [20.9553418, 22.1630989, -72.6799046, -70.8643591],
			'Tuvalu': [-9.9939389, -5.4369611, 175.1590468, 178.7344938],
			'U.S. Virgin Islands': [17.623468, 18.464984, -65.159094, -64.512674],
			'Uganda': [-1.4823179, 4.2340766, 29.573433, 35.000308],
			'Ukraine': [44.184598, 52.3791473, 22.137059, 40.2275801],
			'United Arab Emirates': [22.6444, 26.2822, 51.498, 56.3834],
			'United Kingdom': [49.674, 61.061, -14.015517, 2.0919117],
			'United States': [24.9493, 49.5904, -125.0011, -66.9326],
			'United States Minor Outlying Islands': [6.1779744, 6.6514388, -162.6816297, -162.1339885],
			'Uruguay': [-35.7824481, -30.0853962, -58.4948438, -53.0755833],
			'Uzbekistan': [37.1821164, 45.590118, 55.9977865, 73.1397362],
			'Vanuatu': [-20.4627425, -12.8713777, 166.3355255, 170.449982],
			'Vatican': [41.9002044, 41.9073912, 12.4457442, 12.4583653],
			'Venezuela': [0.647529, 15.9158431, -73.3529632, -59.5427079],
			'Vietnam': [8.1790665, 23.393395, 102.14441, 114.3337595],
			'Wallis and Futuna': [-14.5630748, -12.9827961, -178.3873749, -175.9190391],
			'Western Sahara': [20.556883, 27.6666834, -17.3494721, -8.666389],
			'Yemen': [11.9084802, 19.0, 41.60825, 54.7389375],
			'Zambia': [-18.0765945, -8.2712822, 21.9993509, 33.701111],
			'Zimbabwe': [-22.4241096, -15.6097033, 25.2373, 33.0683413]
		}
	def ReverseGeocoding(self, lat, lng):
		countries = []
		for country, box in self.bbox.items():
			if lat >= box[0] and lat <= box[1] and lng >= box[2] and lng <= box[3]:
				countries.append(country)
		if not countries:
			return "Earth"
		else:
			return '/'.join(countries)
	def lookup(self, mac):
		url = "https://hashc.co.uk/api/locate/mac/"
		data = {
			'apikey': hashC_APIKEY,
			'mac': mac
		}
		try:
			response = requests.post(url, data=data, timeout=30)
			response_json = response.json()
			lat, lng = response_json.get('lat'), response_json.get('lng')
			if lat and lng:
				return '{} ({}, {})'.format(self.ReverseGeocoding(lat, lng), lat, lng)
			return response_json
		except:
			return {}
##################

### Database-Like ###
## Tables:
class statistics(dict):
	"""
	Convention:
	statistics[bssid][X] = Number of frames type X in bssid
	where X is a cosnt int (ESSID_SOURCE_* / EXC_PKT_NUM_*)
	Examples:
	statistics[bssid][1] = 5; means bssid packets contains 5 eapol-m1 frames
	statistics[bssid][40] = 3; means bssid packets contains 3 undirected probe frames
	"""
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, {value: 1})
		else:
			if value not in self[key]:
				self[key].__setitem__(value, 1)
			else:
				self[key][value] += 1
class passwords(list):
	def __init__(self):
		list.__init__(self)
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
class eapmd5s(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, value)
		else:
			subkey = list(value.keys())[0]
			if subkey not in self[key]:
				self[key].__setitem__(subkey, list(value.values())[0])
			else:
				if not self[key][subkey]['hash'] and list(value.values())[0]['hash']:
					self[key][subkey]['hash'] = list(value.values())[0]['hash']
				if not self[key][subkey]['salt'] and list(value.values())[0]['salt']:
					self[key][subkey]['salt'] = list(value.values())[0]['salt']
class eapleaps(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, value)
		else:
			subkey = list(value.keys())[0]
			if subkey not in self[key]:
				self[key].__setitem__(subkey, list(value.values())[0])
			else:
				if not self[key][subkey]['resp1'] and list(value.values())[0]['resp1']:
					self[key][subkey]['resp1'] = list(value.values())[0]['resp1']
				if not self[key][subkey]['resp2'] and list(value.values())[0]['resp2']:
					self[key][subkey]['resp2'] = list(value.values())[0]['resp2']
class hccaps(list):
	def __init__(self):
		list.__init__(self)
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
class hceapmd5s(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, value)
class hceapleaps(dict):
	def __setitem__(self, key, value):
		if key not in self:
			dict.__setitem__(self, key, value)
## Database:
class Database(object):
	def __init__(self):
		super(Database, self).__init__()
		self.statistics = statistics()
		self.passwords = passwords()
		self.essids = essids()
		self.excpkts = excpkts()
		self.eapmd5s = eapmd5s()
		self.eapleaps = eapleaps()
		self.hccaps = hccaps()
		self.hccapxs = hccapxs()
		self.hcwpaxs = hcwpaxs()
		self.hcpmkids = hcpmkids()
		self.pmkids = pmkids()
		self.pcapng_info = pcapng_info()
		self.hceapmd5s = hceapmd5s()
		self.hceapleaps = hceapleaps()
	def statistic_add(self, bssid, data):
		self.statistics.__setitem__(bssid, data)
	def password_add(self, password):
		for char in password:
			if char < 0x20 or char > 0x7e:
				self.passwords.append("$HEX[{}]".format(password.hex()))
				return
		self.passwords.append(password.decode('ascii'))
	def essid_add(self, bssid, essid, essid_len, essid_source):
		# Init
		key = bssid
		# Record data to statistics
		self.statistic_add(key, essid_source)
		# Check
		if essid_len == 0 or not essid:
			return
		if len(self.essids) == DB_ESSID_MAX:
			LOGGER.log('DB_ESSID_MAX Exceeded!', CRITICAL)
			raise ValueError('DB_ESSID_MAX Exceeded!')
		# Add
		self.essids.__setitem__(key, {
			'bssid': key,
			'essid': essid,
			'essid_len': essid_len,
			'essid_source': essid_source
		})
	def excpkt_add(self, excpkt_num, tv_sec, tv_usec, replay_counter, mac_ap, mac_sta, nonce, eapol_len, eapol, keyver, keymic):
		# Init
		key = mac_ap
		subkey = mac_sta
		subsubkey = 'ap' if excpkt_num in [EXC_PKT_NUM_1, EXC_PKT_NUM_3] else 'sta'
		# Record data to statistics
		self.statistic_add(key, excpkt_num)
		# Check
		if nonce == ZERO*32:
			return
		if len(self.excpkts) == DB_EXCPKT_MAX:
			LOGGER.log('DB_EXCPKT_MAX Exceeded!', CRITICAL)
			raise ValueError('DB_EXCPKT_MAX Exceeded!')
		# Add
		self.excpkts.__setitem__(key, {subkey: {subsubkey: [{
			'excpkt_num': excpkt_num,
			'tv_sec': tv_sec,
			'tv_usec': tv_usec,
			'tv_abs': (tv_sec*1000*1000)+tv_usec,
			'replay_counter': replay_counter,
			'mac_ap': key,
			'mac_sta': subkey,
			'nonce': nonce,
			'eapol_len': eapol_len,
			'eapol': eapol,
			'keyver': keyver,
			'keymic': keymic
		}]}})
	def eapmd5_add(self, auth_id, mac_ap, mac_sta, auth_hash, auth_salt):
		key = mac_ap
		subkey = hash(auth_id+bytes(mac_ap+mac_sta).hex())
		self.eapmd5s.__setitem__(key, {subkey: {
			'id': auth_id,
			'mac_ap': mac_ap,
			'mac_sta': mac_sta,
			'hash': auth_hash,
			'salt': auth_salt
		}})
	def eapleap_add(self, auth_id, mac_ap, mac_sta, auth_resp1, auth_resp2, auth_name):
		key = mac_ap
		subkey = hash(auth_id+bytes(mac_ap+mac_sta).hex())
		self.eapleaps.__setitem__(key, {subkey: {
			'id': auth_id,
			'mac_ap': mac_ap,
			'mac_sta': mac_sta,
			'resp1': auth_resp1,
			'resp2': auth_resp2,
			'name': auth_name,
		}})
	def hccap_add(self, bssid, essid, raw_data):
		self.hccaps.append({ \
			'bssid': bssid, \
			'essid': essid, \
			'raw_data': raw_data \
		})
	def hccap_groupby(self, group_by):
		if group_by is None or group_by == "none":
			self.hccaps = [{'key': 'none', 'raw_data': [v['raw_data'] for v in self.hccaps]}]
		elif group_by == "handshake":
			self.hccaps = [{'key': v['bssid']+"_"+str(k), 'raw_data': [v['raw_data']]} for k, v in enumerate(self.hccaps)]
		else:
			self.hccaps.sort(key=itemgetter(group_by))
			self.hccaps = groupby(self.hccaps, key=itemgetter(group_by))
			self.hccaps = [{'key': k, 'raw_data': [x['raw_data'] for x in v]} for k, v in self.hccaps]
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
				'mac_ap': mac_ap, \
				'mac_sta': mac_sta, \
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
			'mac_ap': mac_ap, \
			'mac_sta': mac_sta, \
			'essid': bytes(essid).hex() \
		})
	def pmkid_add(self, mac_ap, mac_sta, pmkid, akm):
		key = hash(mac_ap+mac_sta)
		self.pmkids.__setitem__(key, {
			'mac_ap': bytes(mac_ap).hex(),
			'mac_sta': bytes(mac_sta).hex(),
			'pmkid': pmkid,
			'akm': akm
		})
	def pcapng_info_add(self, key, info):
		self.pcapng_info.__setitem__(key, info)
	def hceapmd5_add(self, auth_id, auth_hash, auth_salt):
		if not (auth_id and auth_hash and auth_salt):
			return
		key = hash(auth_id+auth_hash+auth_salt)
		self.hceapmd5s.__setitem__(key, { \
			'auth_hash': auth_hash, \
			'auth_salt': auth_salt, \
			'auth_id': auth_id \
		})
	def hceapleap_add(self, auth_resp1, auth_resp2, auth_name):
		if not (auth_resp1 and auth_resp2 and auth_name):
			return
		key = hash(auth_resp1+auth_resp2+auth_name)
		self.hceapleaps.__setitem__(key, { \
			'auth_name': auth_name, \
			'unused1': '', \
			'unused2': '', \
			'unused3': '', \
			'resp1': auth_resp1, \
			'resp2': auth_resp2 \
		})
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
###

### HX-Functions ###
def get_essid_from_tag(packet, header, length_skip):
	global custom_essid
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
			if taglen <= MAX_ESSID_LEN:
				essid = {}
				if len(custom_essid) > 0:
					essid['essid'] = custom_essid
					essid['essid_len'] = len(essid['essid'])
				else:
					essid['essid'] = beacon[cur:cur+taglen]
					essid['essid'] += b'\x00'*(MAX_ESSID_LEN - len(essid['essid']))
					essid['essid_len'] = taglen	
				return 0, essid
		cur += taglen
	return -1, None

def get_pmkid_from_packet(packet, source):
	if source == "EAPOL-M1":
		akm = None # Unknown AKM
		if packet:
			pos = 0
			while True:
				try:
					tag_id = packet[pos]
					tag_len = packet[pos+1]
					tag_data = packet[pos+2:pos+2+tag_len]
					if tag_id == 221:
						if tag_data[0:3] == SUITE_OUI:
							pmkid = tag_data[4:].hex()
							if pmkid != '0'*32:
								yield pmkid, akm
					pos = pos+2+tag_len
				except:
					break
		return
	elif source == "EAPOL-M2":
		pos = 0
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
				tag_pairwise_suite_count = GetUint16(tag_data[6:8])
				if BIG_ENDIAN_HOST:
					tag_pairwise_suite_count = byte_swap_16(tag_pairwise_suite_count)
				#tag_pairwise_suite = []
				pos = 8
				#for i in range(0, tag_pairwise_suite_count):
				#	pos += (4*i)+4
				#	tag_pairwise_suite.append(tag_data[pos-4:pos])
				pos += 4*tag_pairwise_suite_count
				# AKM Suite
				tag_authentication_suite_count = GetUint16(tag_data[pos:pos+2])
				if BIG_ENDIAN_HOST:
					tag_authentication_suite_count = byte_swap_16(tag_authentication_suite_count)
				#tag_authentication_suite = []
				pos = pos+2
				skip = 0
				for i in range(0, tag_authentication_suite_count):
					pos += (4*i)+4
					akm = tag_data[pos-4:pos]
					if akm[0:3] != SUITE_OUI:
						skip = 1
						break
				if skip == 1:
					break
				###############
				#tag_capabilities = tag_data[pos:pos+2]
				##############################
				try:
					pmkid_count = GetUint16(tag_data[pos+2:pos+4])
					if BIG_ENDIAN_HOST:
						pmkid_count = byte_swap_16(pmkid_count)
					pos = pos+4
					for i in range(0, pmkid_count):
						pos += (16*i)+16
						pmkid = tag_data[pos-16:pos].hex()
						if pmkid != '0'*32:
							yield pmkid, akm[3]
				except:
					break
				##############################
				break
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

def handle_auth(auth_packet, auth_packet_copy, auth_packet_t_size, keymic_size, rest_packet, pkt_offset, pkt_size):
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
	excpkt = {}
	excpkt['nonce'] = auth_packet['wpa_key_nonce']
	excpkt['nonce'] += b'\x00'*(32 - len(excpkt['nonce']))
	excpkt['replay_counter'] = ap_replay_counter
	excpkt['excpkt_num'] = excpkt_num
	excpkt['eapol_len'] = auth_packet_t_size + ap_wpa_key_data_length
	if (pkt_offset + excpkt['eapol_len']) > pkt_size:
		return -1, None
	if (auth_packet_t_size + ap_wpa_key_data_length) > SIZE_OF_EAPOL:
		return -1, None
	excpkt['eapol'] = auth_packet_copy
	excpkt['eapol'] += b'\x00'*(auth_packet_t_size - len(excpkt['eapol']))
	excpkt['eapol'] += rest_packet[:ap_wpa_key_data_length]
	excpkt['eapol'] += b'\x00'*(SIZE_OF_EAPOL - len(excpkt['eapol']))
	excpkt['keymic'] = auth_packet['wpa_key_mic']
	excpkt['keyver'] = ap_key_information & WPA_KEY_INFO_TYPE_MASK
	if (excpkt_num == EXC_PKT_NUM_3) or (excpkt_num == EXC_PKT_NUM_4):
		excpkt['replay_counter'] -= 1
	return 0, excpkt
###

### PCAPNG ONLY ###
def read_blocks(pcapng):
	while True:
		block_type, block_length = GetUint32(pcapng.read(4)), GetUint32(pcapng.read(4))
		if BIG_ENDIAN_HOST:
			block_type = byte_swap_32(block_type)
			block_length = byte_swap_32(block_length)
		block_body_length = max(block_length - 12, 0)
		block = {
			'block_type': block_type, \
			'block_length': block_length, \
			'block_body': pcapng.read(block_body_length), \
			'block_length_2': GetUint32(pcapng.read(4)) \
		}
		yield block

def read_options(options_block, bitness):
	while True:
		option = {}
		try:
			option['code'] = GetUint16(options_block[0:2])
			option['length'] = GetUint16(options_block[2:4])
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
					option['value'] = GetUint64(option['value'])
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
		pcap_header = pcap.read(SIZE_OF_pcap_file_header_t)
		pcap_file_header = {
			'magic': GetUint32(pcap_header[:4]), \
			#version_major
			#version_minor
			#thiszone
			#sigfigs
			#snaplen
			'linktype': GetUint32(pcap_header[20:24]), \
		}
	except IndexError:
		LOGGER.log('Could not read pcap header', WARNING)
		raise ValueError('Could not read pcap header')
	if BIG_ENDIAN_HOST:
		pcap_file_header['magic']          = byte_swap_32(pcap_file_header['magic'])
		pcap_file_header['linktype']       = byte_swap_32(pcap_file_header['linktype'])
	if pcap_file_header['magic'] == TCPDUMP_MAGIC:
		bitness = 0
	elif pcap_file_header['magic'] == TCPDUMP_CIGAM:
		bitness = 1
		pcap_file_header['linktype']       = byte_swap_32(pcap_file_header['linktype'])
		xprint("WARNING! BigEndian (Endianness) files are not well tested.")
	else:
		LOGGER.log('Invalid pcap header', WARNING)
		raise ValueError('Invalid pcap header')
	if (pcap_file_header['linktype'] != DLT_IEEE802_11) \
	  and (pcap_file_header['linktype'] != DLT_IEEE802_11_PRISM) \
	  and (pcap_file_header['linktype'] != DLT_IEEE802_11_RADIO) \
	  and (pcap_file_header['linktype'] != DLT_IEEE802_11_PPI_HDR):
		LOGGER.log('Unsupported linktype detected', WARNING)
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
			pcapng_file_header['linktype'] = interface['block_body'][0]
			if BIG_ENDIAN_HOST:
				pcapng_file_header['magic'] = byte_swap_32(pcapng_file_header['magic'])
				pcapng_file_header['linktype'] = byte_swap_32(pcapng_file_header['linktype'])
			magic = GetUint32(pcapng_file_header['magic'])
			if magic == PCAPNG_MAGIC:
				bitness = 0
			elif magic == PCAPNG_CIGAM:
				bitness = 1
				pcapng_file_header['linktype'] = byte_swap_32(pcapng_file_header['linktype'])
				xprint("WARNING! BigEndian (Endianness) files are not well tested.")
			else:
				continue
			pcapng_file_header['section_options'] = []
			for option in read_options(block['block_body'][16:], bitness):
				pcapng_file_header['section_options'].append(option)
			if_tsresol = 6
			pcapng_file_header['interface_options'] = []
			for option in read_options(interface['block_body'][8:], bitness):
				if option['code'] == if_tsresol_code:
					if_tsresol = ord(option['value'][:option['length']])
					## currently only supports if_tsresol = 6
					if if_tsresol != 6:
						LOGGER.log('Unsupported if_tsresol', WARNING)
						continue
				pcapng_file_header['interface_options'].append(option)
			if (pcapng_file_header['linktype'] != DLT_IEEE802_11) \
			and (pcapng_file_header['linktype'] != DLT_IEEE802_11_PRISM) \
			and (pcapng_file_header['linktype'] != DLT_IEEE802_11_RADIO) \
			and (pcapng_file_header['linktype'] != DLT_IEEE802_11_PPI_HDR):
				continue
			yield pcapng_file_header, bitness, if_tsresol, blocks

######################### PROCESS PACKETS #########################

def process_packet(packet, header, Q):
	if not Q:
		xprint("Reading file: {}/{} ({} packets)".format(STATUS.current_filepos, STATUS.total_filesize, STATUS.current_packet), end='\r')
	if (header['caplen'] < SIZE_OF_ieee80211_hdr_3addr_t):
		return
	try:
		ieee80211_hdr_3addr = {
			'frame_control': GetUint16(packet[:2]), \
			#duration_id
			'addr1': (packet[4], packet[5], packet[6], packet[7], packet[8], packet[9]), \
			'addr2': (packet[10], packet[11], packet[12], packet[13], packet[14], packet[15]), \
			'addr3': (packet[16], packet[17], packet[18], packet[19], packet[20], packet[21]), \
			#seq_ctrl
		}
		if BIG_ENDIAN_HOST:
			ieee80211_hdr_3addr['frame_control'] = byte_swap_16(ieee80211_hdr_3addr['frame_control'])
		frame_control = ieee80211_hdr_3addr['frame_control']
		if frame_control & IEEE80211_FCTL_FTYPE == IEEE80211_FTYPE_MGMT:
			stype = frame_control & IEEE80211_FCTL_STYPE
			if stype == IEEE80211_STYPE_BEACON:
				length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_beacon_t
				rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
				if rc_beacon == -1:
					return
				DB.password_add(essid['essid'][:essid['essid_len']]) # AP-LESS
				if ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC:
					return
				DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_BEACON)
			elif stype == IEEE80211_STYPE_PROBE_REQ:
				length_skip = SIZE_OF_ieee80211_hdr_3addr_t
				rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
				if rc_beacon == -1:
					return
				DB.password_add(essid['essid'][:essid['essid_len']]) # AP-LESS
				if ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC:
					return
				DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_PROBE)
			elif stype == IEEE80211_STYPE_PROBE_RESP:
				length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_beacon_t
				rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
				if rc_beacon == -1:
					return
				DB.password_add(essid['essid'][:essid['essid_len']]) # AP-LESS
				if ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC:
					return
				DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_PROBE)
			elif stype == IEEE80211_STYPE_ASSOC_REQ:
				length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_assocreq_t
				rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
				if rc_beacon == -1:
					return
				DB.password_add(essid['essid'][:essid['essid_len']]) # AP-LESS
				if ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC:
					return
				DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_ASSOC)
				mac_ap = ieee80211_hdr_3addr['addr3']
				if mac_ap == ieee80211_hdr_3addr['addr1']:
					mac_sta = ieee80211_hdr_3addr['addr2']
				else:
					mac_sta = ieee80211_hdr_3addr['addr1']
				for pmkid, akm in get_pmkid_from_packet(packet, stype):
					DB.pmkid_add(mac_ap=mac_ap, mac_sta=mac_sta, pmkid=pmkid, akm=akm)
			elif stype == IEEE80211_STYPE_REASSOC_REQ:
				length_skip = SIZE_OF_ieee80211_hdr_3addr_t + SIZE_OF_reassocreq_t
				rc_beacon, essid = get_essid_from_tag(packet, header, length_skip)
				if rc_beacon == -1:
					return
				DB.password_add(essid['essid'][:essid['essid_len']]) # AP-LESS
				if ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC:
					return
				DB.essid_add(bssid=ieee80211_hdr_3addr['addr3'], essid=essid['essid'], essid_len=essid['essid_len'], essid_source=ESSID_SOURCE_REASSOC)
				mac_ap = ieee80211_hdr_3addr['addr3']
				if mac_ap == ieee80211_hdr_3addr['addr1']:
					mac_sta = ieee80211_hdr_3addr['addr2']
				else:
					mac_sta = ieee80211_hdr_3addr['addr1']
				for pmkid, akm in get_pmkid_from_packet(packet, stype):
					DB.pmkid_add(mac_ap=mac_ap, mac_sta=mac_sta, pmkid=pmkid, akm=akm)
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
			ieee80211_llc_snap_header = {
				'dsap': packet[llc_offset], \
				'ssap': packet[llc_offset+1], \
				'ctrl': packet[llc_offset+2], \
				#'oui': (packet[llc_offset+3], packet[llc_offset+4], packet[llc_offset+5]), \
				'ethertype': GetUint16(packet[llc_offset+6:llc_offset+8]) \
			}
			if BIG_ENDIAN_HOST:
				ieee80211_llc_snap_header['ethertype'] = byte_swap_16(ieee80211_llc_snap_header['ethertype'])
			rc_llc = handle_llc(ieee80211_llc_snap_header)
			if rc_llc == -1:
				return
			auth_offset = llc_offset + SIZE_OF_ieee80211_llc_snap_header_t
			auth_head_version, auth_head_type, auth_head_length = packet[auth_offset], packet[auth_offset+1], GetUint16(packet[auth_offset+2:auth_offset+4])
			if auth_head_type == AUTH_EAPOL:
				if len(packet[auth_offset:]) < 107:
					keymic_size = 16
					auth_packet_t_size = 99
				else:
					l1 = GetUint16(packet[auth_offset+97:auth_offset+99])
					l2 = GetUint16(packet[auth_offset+105:auth_offset+107])
					if BIG_ENDIAN_HOST:
						auth_head_length = byte_swap_16(auth_head_length)
						l1 = byte_swap_16(l1)
						l2 = byte_swap_16(l2)
					auth_head_length = byte_swap_16(auth_head_length)
					l1 = byte_swap_16(l1)
					l2 = byte_swap_16(l2)
					if l1 + 99 == auth_head_length+4:
						keymic_size = 16
						auth_packet_t_size = 99
					elif l2 + 107 == auth_head_length+4:
						keymic_size = 24
						auth_packet_t_size = 107
						LOGGER.log('Keymic is 24 bytes (hccap(x) can\'t handle this)', WARNING)
					else:
						return
				if header['caplen'] < (auth_offset + auth_packet_t_size):
					return
				if keymic_size == 16:
					auth_packet = {
						#'version': packet[auth_offset], \
						#'type': packet[auth_offset+1], \
						'length': GetUint16(packet[auth_offset+2:auth_offset+4]), \
						#'key_descriptor': packet[auth_offset+4], \
						'key_information': GetUint16(packet[auth_offset+5:auth_offset+7]), \
						#'key_length': GetUint16(packet[auth_offset+7:auth_offset+9]), \
						'replay_counter': GetUint64(packet[auth_offset+9:auth_offset+17]), \
						'wpa_key_nonce': packet[auth_offset+17:auth_offset+49], \
						#'wpa_key_iv': packet[auth_offset+49:auth_offset+65], \
						#'wpa_key_rsc': packet[auth_offset+65:auth_offset+73], \
						#'wpa_key_id': packet[auth_offset+73:auth_offset+81], \
						'wpa_key_mic': packet[auth_offset+81:auth_offset+97], \
						'wpa_key_data_length': GetUint16(packet[auth_offset+97:auth_offset+99]) \
					}
					auth_packet_copy = bytes((*packet[auth_offset:auth_offset+81], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, *packet[auth_offset+97:auth_offset+99]))
				elif keymic_size == 24:
					auth_packet = {
						#'version': packet[auth_offset], \
						#'type': packet[auth_offset+1], \
						'length': GetUint16(packet[auth_offset+2:auth_offset+4]), \
						#'key_descriptor': packet[auth_offset+4], \
						'key_information': GetUint16(packet[auth_offset+5:auth_offset+7]), \
						#'key_length': GetUint16(packet[auth_offset+7:auth_offset+9]), \
						'replay_counter': GetUint64(packet[auth_offset+9:auth_offset+17]), \
						'wpa_key_nonce': packet[auth_offset+17:auth_offset+49], \
						#'wpa_key_iv': packet[auth_offset+49:auth_offset+65], \
						#'wpa_key_rsc': packet[auth_offset+65:auth_offset+73], \
						#'wpa_key_id': packet[auth_offset+73:auth_offset+81], \
						'wpa_key_mic': packet[auth_offset+81:auth_offset+105], \
						'wpa_key_data_length': GetUint16(packet[auth_offset+105:auth_offset+107]) \
					}
					auth_packet_copy = bytes((*packet[auth_offset:auth_offset+81], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, *packet[auth_offset+105:auth_offset+107]))
				else:
					return
				if BIG_ENDIAN_HOST:
					auth_packet['length']              = byte_swap_16(auth_packet['length'])
					auth_packet['key_information']     = byte_swap_16(auth_packet['key_information'])
					#auth_packet['key_length']          = byte_swap_16(auth_packet['key_length'])
					auth_packet['replay_counter']      = byte_swap_64(auth_packet['replay_counter'])
					auth_packet['wpa_key_data_length'] = byte_swap_16(auth_packet['wpa_key_data_length'])
				rest_packet = packet[auth_offset+auth_packet_t_size:]
				rc_auth, excpkt = handle_auth(auth_packet, auth_packet_copy, auth_packet_t_size, keymic_size, rest_packet, auth_offset, header['caplen'])
				if rc_auth == -1:
					return
				if excpkt['excpkt_num'] == EXC_PKT_NUM_1 or excpkt['excpkt_num'] == EXC_PKT_NUM_3:
					DB.excpkt_add(excpkt_num=excpkt['excpkt_num'], tv_sec=header['tv_sec'], tv_usec=header['tv_usec'], replay_counter=excpkt['replay_counter'], mac_ap=ieee80211_hdr_3addr['addr2'], mac_sta=ieee80211_hdr_3addr['addr1'], nonce=excpkt['nonce'], eapol_len=excpkt['eapol_len'], eapol=excpkt['eapol'], keyver=excpkt['keyver'], keymic=excpkt['keymic'])
					if excpkt['excpkt_num'] == EXC_PKT_NUM_1:
						for pmkid, akm in get_pmkid_from_packet(rest_packet, "EAPOL-M1"):
							if akm is None and excpkt['keyver'] in [1, 2, 3]:
								akm = AK_SAFE
							DB.pmkid_add(mac_ap=ieee80211_hdr_3addr['addr2'], mac_sta=ieee80211_hdr_3addr['addr1'], pmkid=pmkid, akm=akm)
				elif excpkt['excpkt_num'] == EXC_PKT_NUM_2 or excpkt['excpkt_num'] == EXC_PKT_NUM_4:
					DB.excpkt_add(excpkt_num=excpkt['excpkt_num'], tv_sec=header['tv_sec'], tv_usec=header['tv_usec'], replay_counter=excpkt['replay_counter'], mac_ap=ieee80211_hdr_3addr['addr1'], mac_sta=ieee80211_hdr_3addr['addr2'], nonce=excpkt['nonce'], eapol_len=excpkt['eapol_len'], eapol=excpkt['eapol'], keyver=excpkt['keyver'], keymic=excpkt['keymic'])
					if excpkt['excpkt_num'] == EXC_PKT_NUM_2:
						for pmkid, akm in get_pmkid_from_packet(rest_packet, "EAPOL-M2"):
							if akm is None and excpkt['keyver'] in [1, 2, 3]:
								akm = AK_SAFE
							DB.pmkid_add(mac_ap=ieee80211_hdr_3addr['addr1'], mac_sta=ieee80211_hdr_3addr['addr2'], pmkid=pmkid, akm=akm)
			elif auth_head_type == AUTH_EAP:
				if packet[auth_offset+4] in [1, 2]:
					auth_id = packet[auth_offset+5:auth_offset+5+1].hex()
					auth_type = packet[auth_offset+8]
					if auth_type == AUTH_EAP_MD5:
						if packet[auth_offset+4] == 1: # Request
							auth_hash = ''
							auth_salt = packet[auth_offset+10:auth_offset+10+packet[auth_offset+9]].hex()
							mac_ap = ieee80211_hdr_3addr['addr3']
							mac_sta = ieee80211_hdr_3addr['addr1'] if ieee80211_hdr_3addr['addr3'] != ieee80211_hdr_3addr['addr1'] else ieee80211_hdr_3addr['addr2']
						else: # Response
							auth_hash = packet[auth_offset+10:auth_offset+10+packet[auth_offset+9]].hex()
							auth_salt = ''
							mac_ap = ieee80211_hdr_3addr['addr3']
							mac_sta = ieee80211_hdr_3addr['addr1'] if ieee80211_hdr_3addr['addr3'] != ieee80211_hdr_3addr['addr1'] else ieee80211_hdr_3addr['addr2']
						DB.eapmd5_add(auth_id=auth_id, mac_ap=mac_ap, mac_sta=mac_sta, auth_hash=auth_hash, auth_salt=auth_salt)
					elif auth_type == AUTH_EAP_LEAP:
						if packet[auth_offset+4] == 1: # Request
							auth_resp1 = ''
							auth_resp2 = packet[auth_offset+12:auth_offset+12+packet[auth_offset+11]].hex()
							auth_name = packet[auth_offset+12+packet[auth_offset+11]:].decode(encoding='utf-8', errors='ignore').rstrip('\x00')
							mac_ap = ieee80211_hdr_3addr['addr3']
							mac_sta = ieee80211_hdr_3addr['addr1'] if ieee80211_hdr_3addr['addr3'] != ieee80211_hdr_3addr['addr1'] else ieee80211_hdr_3addr['addr2']
						else: # Response
							auth_resp1 = packet[auth_offset+12:auth_offset+12+packet[auth_offset+11]].hex()
							auth_resp2 = ''
							auth_name = packet[auth_offset+12+packet[auth_offset+11]:].decode(encoding='utf-8', errors='ignore').rstrip('\x00')
							mac_ap = ieee80211_hdr_3addr['addr3']
							mac_sta = ieee80211_hdr_3addr['addr1'] if ieee80211_hdr_3addr['addr3'] != ieee80211_hdr_3addr['addr1'] else ieee80211_hdr_3addr['addr2']
						DB.eapleap_add(auth_id=auth_id, mac_ap=mac_ap, mac_sta=mac_sta, auth_resp1=auth_resp1, auth_resp2=auth_resp2, auth_name=auth_name)
	except:
		LOGGER.log('Packet processing error', WARNING)

######################### READ PACKETS #########################

def read_pcap_packets(cap_file, pcap_file_header, bitness, ignore_ts=False, Q=True):
	header_count = 0
	header_error = None
	packet_count = 0
	packet_error = None
	while True:
		pcap_pkthdr = cap_file.read(SIZE_OF_pcap_pkthdr_t)
		if not pcap_pkthdr:
			break
		try:
			header_error = None
			header = {
				'tv_sec': GetUint32(pcap_pkthdr[:4]), \
				'tv_usec': GetUint32(pcap_pkthdr[4:8]), \
				'caplen': GetUint32(pcap_pkthdr[8:12]), \
				'len': GetUint32(pcap_pkthdr[12:16]), \
			}
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
				if not ignore_ts:
					raise ValueError(header_error)
				else:
					LOGGER.log(header_error, WARNING)
			if header['caplen'] >= TCPDUMP_DECODE_LEN or to_signed_32(header['caplen']) < 0:
				header_error = 'Oversized packet detected'
				raise ValueError(header_error)
			header_count += 1
			try:
				packet_error = None
				packet = cap_file.read(max(header['caplen'], 0))
				if pcap_file_header['linktype'] == DLT_IEEE802_11_PRISM:
					if header['caplen'] < SIZE_OF_prism_header_t:
						packet_error = 'Could not read prism header'
						raise ValueError(packet_error)
					prism_header = {
						'msgcode': GetUint32(packet[:4]), \
						'msglen': GetUint32(packet[4:8]), \
						#devname
						#hosttime
						#mactime
						#channel
						#rssi
						#sq
						#signal
						#noise
						#rate
						#istx
						#frmlen
					}
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
					ieee80211_radiotap_header = {
						'it_version': packet[0], \
						#it_pad
						'it_len': GetUint16(packet[2:4]), \
						'it_present': GetUint32(packet[4:8]), \
					}
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
					ppi_packet_header = {
						#pph_version
						#pph_flags
						'pph_len': GetUint16(packet[2:4]), \
						#pph_dlt
					}
					if BIG_ENDIAN_HOST:
						ppi_packet_header['pph_len']    = byte_swap_16(ppi_packet_header['pph_len'])
					packet = packet[ppi_packet_header['pph_len']:]
					header['caplen'] -= ppi_packet_header['pph_len']
					header['len']    -= ppi_packet_header['pph_len']
				packet_count += 1
			except:
				packet_error = 'Could not read pcap packet data'
				raise ValueError(packet_error)
		except IndexError:
			continue
		except ValueError as e:
			LOGGER.log(str(e), WARNING)
			continue
		else:
			try:
				if not Q:
					STATUS.step_packet()
					STATUS.set_filepos(cap_file.tell())
				process_packet(packet, header, Q)
			except ValueError as e:
				LOGGER.log(str(e), WARNING)
				continue
	if header_count == 0 or packet_count == 0:
		if header_error:
			raise ValueError(header_error)
		elif packet_error:
			raise ValueError(packet_error)
		else:
			raise ValueError('Something went wrong')

def read_pcapng_packets(cap_file, pcapng, pcapng_file_header, bitness, if_tsresol, ignore_ts=False, Q=True):
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
				cap_file.seek(cap_file.tell()-header_block['block_length'])
				break
			else:
				continue
			header = {}
			timestamp = (header_block['block_body'][8]) | (header_block['block_body'][9])<<8 | (header_block['block_body'][10])<<16 | (header_block['block_body'][11])<<24 | (header_block['block_body'][4])<<32 | (header_block['block_body'][5])<<40 | (header_block['block_body'][6])<<48 | (header_block['block_body'][7])<<56
			header['caplen']   = GetUint32(header_block['block_body'][12:16])
			header['len']      = GetUint32(header_block['block_body'][16:20])
			if BIG_ENDIAN_HOST:
				timestamp          = byte_swap_64(timestamp)
				header['caplen']   = byte_swap_32(header['caplen'])
				header['len']      = byte_swap_32(header['len'])
			if bitness:
				timestamp          = byte_swap_64(timestamp)
				header['caplen']   = byte_swap_32(header['caplen'])
				header['len']      = byte_swap_32(header['len'])
			header['tv_sec'], header['tv_usec'] = (timestamp//1000000), (timestamp%1000000)
			if header['tv_sec'] == 0 and header['tv_usec'] == 0:
				header_error = 'Zero value timestamps detected'
				if not ignore_ts:
					raise ValueError(header_error)
				else:
					LOGGER.log(header_error, WARNING)
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
					prism_header = {
						'msgcode': GetUint32(packet[:4]), \
						'msglen': GetUint32(packet[4:8]), \
						#devname
						#hosttime
						#mactime
						#channel
						#rssi
						#sq
						#signal
						#noise
						#rate
						#istx
						#frmlen
					}
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
					ieee80211_radiotap_header = {
						'it_version': packet[0], \
						#it_pad
						'it_len': GetUint16(packet[2:4]), \
						'it_present': GetUint32(packet[4:8]), \
					}
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
					ppi_packet_header = {
						#pph_version
						#pph_flags
						'pph_len': GetUint16(packet[2:4]), \
						#pph_dlt
					}
					if BIG_ENDIAN_HOST:
						ppi_packet_header['pph_len']    = byte_swap_16(ppi_packet_header['pph_len'])
					packet = packet[ppi_packet_header['pph_len']:]
					header['caplen'] -= ppi_packet_header['pph_len']
					header['len']    -= ppi_packet_header['pph_len']
				packet_count += 1
			except:
				packet_error = 'Could not read pcapng packet data'
				raise ValueError(packet_error)
		except IndexError:
			continue
		except ValueError as e:
			LOGGER.log(str(e), WARNING)
			continue
		else:
			try:
				if not Q:
					STATUS.step_packet()
					STATUS.set_filepos(cap_file.tell())
				process_packet(packet, header, Q)
			except ValueError as e:
				LOGGER.log(str(e), WARNING)
				continue
	if header_count == 0 or packet_count == 0:
		if header_error:
			raise ValueError(header_error)
		elif packet_error:
			raise ValueError(packet_error)
		else:
			raise ValueError('Something went wrong')

######################### OUTPUT #########################

def __xbuild__(Builder, DB, essid_list):
	"""
	Takes 3 arguments:
	Builder: Our Builder object (from class Builder)
	DB: Global DB to read Database contents (for Linux this is not required, but for Windows it is)
	essid_list: a list of essids that a single worker is conserned with
	"""
	Builder.__build__(DB, essid_list)

class Builder(object):
	def __init__(self, export, export_unauthenticated=False, filters=None, group_by=None, do_not_clean=False, ignore_ie=False, locate=False, Q=True):
		super(Builder, self).__init__()
		self.export = export
		self.export_unauthenticated = export_unauthenticated
		self.filters = filters
		self.group_by = group_by
		self.do_not_clean = do_not_clean
		self.ignore_ie = ignore_ie
		self.locate = locate
		self.Q = Q
		# Workers Manager
		manager = Manager()
		# Lists were we store requested DB operations from our workers
		self.DB_hcwpaxs_add_list = manager.list()
		self.DB_hccap_add_list = manager.list()
		self.DB_hccap_groupby_list = manager.list()
		self.DB_hccapx_add_list = manager.list()
		self.DB_hccapx_groupby_list = manager.list()
		self.DB_hcpmkid_add_list = manager.list()
		self.DB_hceapmd5_add_list = manager.list()
		self.DB_hceapleap_add_list = manager.list()

	# Helper functions to store each DB req to the right list
	def DB_hcwpaxs_add(self, **kwords):
		self.DB_hcwpaxs_add_list.append(kwords)
	def DB_hccap_add(self, **kwords):
		self.DB_hccap_add_list.append(kwords)
	def DB_hccap_groupby(self, **kwords):
		if self.DB_hccap_groupby_list:
			return
		self.DB_hccap_groupby_list.append(kwords)
	def DB_hccapx_add(self, **kwords):
		self.DB_hccapx_add_list.append(kwords)
	def DB_hccapx_groupby(self, **kwords):
		if self.DB_hccapx_groupby_list:
			return
		self.DB_hccapx_groupby_list.append(kwords)
	def DB_hcpmkid_add(self, **kwords):
		self.DB_hcpmkid_add_list.append(kwords)
	def DB_hceapmd5_add(self, **kwords):
		self.DB_hceapmd5_add_list.append(kwords)
	def DB_hceapleap_add(self, **kwords):
		self.DB_hceapleap_add_list.append(kwords)

	# The work (building)
	def __build__(self, DB, essid_list):
		for essid in essid_list.values():
			bssid = bytes(essid['bssid']).hex()
			essidf = essid['essid'].decode(encoding='utf-8', errors='ignore').rstrip('\x00')
			bssidf = ':'.join(bssid[i:i+2] for i in range(0,12,2))
			if not self.Q:
				xprint('\n|*| BSSID={} ESSID={} ({}){}'.format( \
					bssidf, \
					essidf, \
					MAC_VENDOR.lookup(bssid), \
					' [Skipped]' if (self.filters[0] == "essid" and self.filters[1] != essidf) or (self.filters[0] == "bssid" and self.filters[1] != bssid) else '' \
				))
			### FILTER ###
			if (self.filters[0] == "essid" and self.filters[1] != essidf) or (self.filters[0] == "bssid" and self.filters[1] != bssid):
				continue
			##############
			### STATS (1/2) ###
			if not self.Q:
				FRAMES_EAPOL_M1 = DB.statistics[essid['bssid']].get(EXC_PKT_NUM_1, 0)
				FRAMES_EAPOL_M2 = DB.statistics[essid['bssid']].get(EXC_PKT_NUM_2, 0)
				FRAMES_EAPOL_M3 = DB.statistics[essid['bssid']].get(EXC_PKT_NUM_3, 0)
				FRAMES_EAPOL_M4 = DB.statistics[essid['bssid']].get(EXC_PKT_NUM_4, 0)
				FRAMES_BEACON = DB.statistics[essid['bssid']].get(ESSID_SOURCE_BEACON, 0)
				FRAMES_ASSOC = DB.statistics[essid['bssid']].get(ESSID_SOURCE_ASSOC, 0)
				FRAMES_REASSOC = DB.statistics[essid['bssid']].get(ESSID_SOURCE_REASSOC, 0)
				FRAMES_PROBE = DB.statistics[essid['bssid']].get(ESSID_SOURCE_PROBE, 0)
				if self.locate:
					xprint('| | GEOLOCATION: {}'.format(MAC_GEO.lookup(bssidf)))
				xprint('| | EAPOL-M1: {}, EAPOL-M2: {}, EAPOL-M3: {}, EAPOL-M4: {}'.format(FRAMES_EAPOL_M1, FRAMES_EAPOL_M2, FRAMES_EAPOL_M3, FRAMES_EAPOL_M4))
				xprint('| | BEACON: {}, ASSOC: {}, REASSOC: {}, PROBE: {}'.format(FRAMES_BEACON, FRAMES_ASSOC, FRAMES_REASSOC, FRAMES_PROBE))
			###################
			if self.export not in ['hceapmd5', 'hceapleap']:
				### STATS (2/2) ###
				if not self.Q:
					if FRAMES_EAPOL_M1 < 2:
						xprint('| ! WARNING! Not enough EAPOL-M1 frames. This makes it impossible to calculate nonce-error-correction values.')
					if (FRAMES_ASSOC + FRAMES_REASSOC) == 0:
						xprint('| ! WARNING! Missing important frames (ASSOC, REASSOC). This makes it hard to recover the PSK.')
					if FRAMES_PROBE == 0:
						xprint('| ! WARNING! Missing undirected probe frames (PROBE). This makes it hard to recover the PSK.')
				###################
				excpkts_AP_ = DB.excpkts.get(essid['bssid'])
				if excpkts_AP_ and self.export != "hcpmkid":
					for excpkts_AP_STA_ in excpkts_AP_.values():
						excpkts_AP_STA_ap = excpkts_AP_STA_.get('ap')
						if not excpkts_AP_STA_ap:
							continue
						for excpkt_ap in excpkts_AP_STA_ap:
							### CLEAN ###
							# SKIP EAPOL IF WE HAVE PMKID (HCWPAX ONLY)
							if self.export == "hcwpax" and not self.do_not_clean:
								pmkid = DB.pmkids.get(hash(excpkt_ap['mac_ap']+excpkt_ap['mac_sta']))
								if pmkid:
									if self.ignore_ie or pmkid['akm'] in [AK_PSK, AK_PSKSHA256, AK_SAFE]:
										break
							#############
							excpkts_AP_STA_sta = excpkts_AP_STA_.get('sta')
							if not excpkts_AP_STA_sta:
								continue
							for excpkt_sta in excpkts_AP_STA_sta:
								if (excpkt_ap['replay_counter'] != excpkt_sta['replay_counter']):
									continue
								if excpkt_ap['excpkt_num'] < excpkt_sta['excpkt_num']:
									if excpkt_ap['tv_abs'] > excpkt_sta['tv_abs']:
										continue
									if (excpkt_ap['tv_abs'] + (EAPOL_TTL*1000*1000)) < excpkt_sta['tv_abs']:
										continue
								else:
									if excpkt_sta['tv_abs'] > excpkt_ap['tv_abs']:
										continue
									if (excpkt_sta['tv_abs'] + (EAPOL_TTL*1000*1000)) < excpkt_ap['tv_abs']:
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
									xprint('| ! BUG! AP:{} STA:{}'.format(excpkt_ap['excpkt_num'], excpkt_sta['excpkt_num']))
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
											if check_1 and check_2:
												ap_less = 1
												message_pair |= MESSAGE_PAIR_APLESS
												break
									#############################
								### LE/BE/NC ###
								for excpkt_ap_k in excpkts_AP_STA_ap:
									if (excpkt_ap['nonce'][:28] == excpkt_ap_k['nonce'][:28]) and (excpkt_ap['nonce'][28:] != excpkt_ap_k['nonce'][28:]):
										message_pair |= MESSAGE_PAIR_NC
										if excpkt_ap['nonce'][31] != excpkt_ap_k['nonce'][31]:
											message_pair |= MESSAGE_PAIR_LE
										elif excpkt_ap['nonce'][28] != excpkt_ap_k['nonce'][28]:
											message_pair |= MESSAGE_PAIR_BE
								for excpkt_sta_k in excpkts_AP_STA_sta:
									if (excpkt_sta['nonce'][:28] == excpkt_sta_k['nonce'][:28]) and (excpkt_sta['nonce'][28:] != excpkt_sta_k['nonce'][28:]):
										message_pair |= MESSAGE_PAIR_NC
										if excpkt_sta['nonce'][31] != excpkt_sta_k['nonce'][31]:
											message_pair |= MESSAGE_PAIR_LE
										elif excpkt_sta['nonce'][28] != excpkt_sta_k['nonce'][28]:
											message_pair |= MESSAGE_PAIR_BE
								################
								mac_sta = bytes(excpkt_sta['mac_sta']).hex()
								if skip == 0:
									if auth == 1:
										if not self.Q:
											xprint('| > STA={}, Message Pair={}, Replay Counter={}, Time Gap={}, Authenticated=Y'.format( \
												':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
												message_pair, \
												excpkt_sta['replay_counter'], \
												abs(excpkt_ap['tv_abs'] - excpkt_sta['tv_abs']) \
											))
									else:
										if not self.Q:
											xprint('| > STA={}, Message Pair={}, Replay Counter={}, Time Gap={}, Authenticated=N{}{}'.format( \
												':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
												message_pair, \
												excpkt_sta['replay_counter'], \
												abs(excpkt_ap['tv_abs'] - excpkt_sta['tv_abs']), \
												' (AP-LESS)' if ap_less else '', \
												'' if self.export_unauthenticated else ' [Skipped]' \
											))
										if not self.export_unauthenticated:
											continue
								else:
									if not self.Q:
										xprint('| > STA={}, Message Pair={} [Skipped]'.format( \
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
								if BIG_ENDIAN_HOST:
									hccapx_to_pack['signature']  = byte_swap_32(hccapx_to_pack['signature'])
									hccapx_to_pack['version']    = byte_swap_32(hccapx_to_pack['version'])
									hccapx_to_pack['eapol_len']  = byte_swap_16(hccapx_to_pack['eapol_len'])
								if self.export == "hcwpax":
									self.DB_hcwpaxs_add(signature=HCWPAX_SIGNATURE, ftype="02", pmkid_or_mic=hccapx_to_pack['keymic'], mac_ap=hccapx_to_pack['mac_ap'], mac_sta=hccapx_to_pack['mac_sta'], essid=hccapx_to_pack['essid'][:hccapx_to_pack['essid_len']], anonce=hccapx_to_pack['nonce_ap'], eapol=hccapx_to_pack['eapol'][:hccapx_to_pack['eapol_len']], message_pair=hccapx_to_pack['message_pair'])
								elif self.export == "hccapx":
									if len(hccapx_to_pack['keymic']) != 16:
										continue
									hccapx = (
										bytes(PutUint32(hccapx_to_pack['signature']))+ \
										bytes(PutUint32(hccapx_to_pack['version']))+ \
										bytes([hccapx_to_pack['message_pair']])+ \
										bytes([hccapx_to_pack['essid_len']])+ \
										hccapx_to_pack['essid']+ \
										bytes([hccapx_to_pack['keyver']])+ \
										hccapx_to_pack['keymic']+ \
										bytes(hccapx_to_pack['mac_ap'])+ \
										hccapx_to_pack['nonce_ap']+ \
										bytes(hccapx_to_pack['mac_sta'])+ \
										hccapx_to_pack['nonce_sta']+ \
										bytes(PutUint16(hccapx_to_pack['eapol_len']))+ \
										hccapx_to_pack['eapol'] \
									)
									self.DB_hccapx_add(bssid=bssidf.replace(':', '-').upper(), essid=essidf, raw_data=hccapx)
								elif self.export == "hccap":
									if len(hccapx_to_pack['keymic']) != 16:
										continue
									hccap_essid = (hccapx_to_pack['essid']+b'\x00\x00\x00\x00')
									hccap = (
										hccap_essid+ \
										bytes(hccapx_to_pack['mac_ap'])+ \
										bytes(hccapx_to_pack['mac_sta'])+ \
										hccapx_to_pack['nonce_sta']+ \
										hccapx_to_pack['nonce_ap']+ \
										hccapx_to_pack['eapol']+ \
										bytes(PutUint32(hccapx_to_pack['eapol_len']))+ \
										bytes(PutUint32(hccapx_to_pack['keyver']))+ \
										hccapx_to_pack['keymic'] \
									)
									self.DB_hccap_add(bssid=bssidf.replace(':', '-').upper(), essid=essidf, raw_data=hccap)
				### PMKID ###
				if self.export == "hcwpax":
					for pmkid in DB.pmkids.values():
						if pmkid['mac_ap'] == bssid and (self.ignore_ie or pmkid['akm'] in [AK_PSK, AK_PSKSHA256, AK_SAFE]):
							self.DB_hcwpaxs_add(signature=HCWPAX_SIGNATURE, ftype="01", pmkid_or_mic=pmkid['pmkid'], mac_ap=pmkid['mac_ap'], mac_sta=pmkid['mac_sta'], essid=essid['essid'][:essid['essid_len']])
							mac_sta = pmkid['mac_sta']
							if not self.Q:
								xprint('| > STA={} [PMKID {}]'.format( \
									':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
									pmkid['pmkid'] \
								))
				elif self.export == "hcpmkid":
					for pmkid in DB.pmkids.values():
						if pmkid['mac_ap'] == bssid and (self.ignore_ie or pmkid['akm'] in [AK_PSK, AK_PSKSHA256, AK_SAFE]):
							self.DB_hcpmkid_add(pmkid=pmkid['pmkid'], mac_ap=pmkid['mac_ap'], mac_sta=pmkid['mac_sta'], essid=essid['essid'][:essid['essid_len']])
							mac_sta = pmkid['mac_sta']
							if not self.Q:
								xprint('| > STA={} [PMKID {}]'.format( \
									':'.join(mac_sta[i:i+2] for i in range(0,12,2)), \
									pmkid['pmkid'] \
								))
				#############
			### EAP-MD5 ###
			elif self.export == "hceapmd5":
				eapmd5s_AP_ = DB.eapmd5s.get(essid['bssid'])
				if eapmd5s_AP_:
					for eapmd5s_AP_STA_ in eapmd5s_AP_.values():
						if not self.Q:
							xprint('| > STA={}, ID={}'.format( \
								':'.join(bytes(eapmd5s_AP_STA_['mac_sta']).hex()[i:i+2] for i in range(0,12,2)), \
								eapmd5s_AP_STA_['id'] \
							))
						self.DB_hceapmd5_add(auth_id=eapmd5s_AP_STA_['id'], auth_hash=eapmd5s_AP_STA_['hash'], auth_salt=eapmd5s_AP_STA_['salt'])
			###############
			### EAP-LEAP ###
			elif self.export == "hceapleap":
				eapleaps_AP_ = DB.eapleaps.get(essid['bssid'])
				if eapleaps_AP_:
					for eapleaps_AP_STA_ in eapleaps_AP_.values():
						if not self.Q:
							xprint('| > STA={}, ID={}, NAME={}'.format( \
								':'.join(bytes(eapleaps_AP_STA_['mac_sta']).hex()[i:i+2] for i in range(0,12,2)), \
								eapleaps_AP_STA_['id'], \
								eapleaps_AP_STA_['name'] \
							))
						self.DB_hceapleap_add(auth_resp1=eapleaps_AP_STA_['resp1'], auth_resp2=eapleaps_AP_STA_['resp2'], auth_name=eapleaps_AP_STA_['name'])
			###############
		if self.export == "hccapx":
			self.DB_hccapx_groupby(group_by=self.group_by)
		elif self.export == "hccap":
			self.DB_hccap_groupby(group_by=self.group_by)

	def _pre_build(self):
		pass

	def _build(self):
		# Generate tasks
		task_list = []
		for jq in range(0, len(DB.essids), MAX_WORK_PER_PROCESS):
			task = Process(target=__xbuild__, args=[self, DB, dict(list(DB.essids.items())[jq:jq+MAX_WORK_PER_PROCESS])])
			task_list.append(task)
		for task in task_list:
			task.start()
		for task in task_list:
			task.join()
		# For each returned DB operation request, perform that operation
		for DB_hcwpaxs_add in self.DB_hcwpaxs_add_list:
			DB.hcwpaxs_add(**DB_hcwpaxs_add)
		for DB_hccap_add in self.DB_hccap_add_list:
			DB.hccap_add(**DB_hccap_add)
		if self.DB_hccap_groupby_list:
			DB.hccap_groupby(**self.DB_hccap_groupby_list[0])
		for DB_hccapx_add in self.DB_hccapx_add_list:
			DB.hccapx_add(**DB_hccapx_add)
		if self.DB_hccapx_groupby_list:
			DB.hccapx_groupby(**self.DB_hccapx_groupby_list[0])
		for DB_hcpmkid_add in self.DB_hcpmkid_add_list:
			DB.hcpmkid_add(**DB_hcpmkid_add)
		for DB_hceapmd5_add in self.DB_hceapmd5_add_list:
			DB.hceapmd5_add(**DB_hceapmd5_add)
		for DB_hceapleap_add in self.DB_hceapleap_add_list:
			DB.hceapleap_add(**DB_hceapleap_add)

	def _post_build(self):
		if self.export == "hceapmd5":
			## In case we have EAP-MD5 but no essid has been detected
			for key, value in DB.eapmd5s.items():
				if not DB.essids.get(key):
					bssid = bytes(key).hex()
					bssidf = ':'.join(bssid[i:i+2] for i in range(0,12,2))
					xprint('\n|*| BSSID={} ({}) (Undetected)'.format(bssidf, MAC_VENDOR.lookup(bssid)), end='')
					if (self.filters[0] == "essid") or (self.filters[0] == "bssid" and self.filters[1] != bssid):
						xprint(' [Skipped]')
						continue
					xprint()
					for v in value.values():
						xprint('| > STA={}, ID={}'.format( \
							':'.join(bytes(v['mac_sta']).hex()[i:i+2] for i in range(0,12,2)), \
							v['id'] \
						))
						DB.hceapmd5_add(auth_id=v['id'], auth_hash=v['hash'], auth_salt=v['salt'])
		if self.export == "hceapleap":
			## In case we have EAP-LEAP but no essid has been detected
			for key, value in DB.eapleaps.items():
				if not DB.essids.get(key):
					bssid = bytes(key).hex()
					bssidf = ':'.join(bssid[i:i+2] for i in range(0,12,2))
					xprint('\n|*| BSSID={} ({}) (Undetected)'.format(bssidf, MAC_VENDOR.lookup(bssid)), end='')
					if (self.filters[0] == "essid") or (self.filters[0] == "bssid" and self.filters[1] != bssid):
						xprint(' [Skipped]')
						continue
					xprint()
					for v in value.values():
						xprint('| > STA={}, ID={}, NAME={}'.format( \
							':'.join(bytes(v['mac_sta']).hex()[i:i+2] for i in range(0,12,2)), \
							v['id'], \
							v['name'] \
						))
						DB.hceapleap_add(auth_resp1=v['resp1'], auth_resp2=v['resp2'], auth_name=v['name'])

	def build(self):
		self._pre_build()
		self._build()
		self._post_build()

######################### MAIN #########################

def main(Q):
	global custom_essid
	if args.essid:
		custom_essid = bytes(args.essid,'utf-8')
	if os.path.isfile(args.input):
		cap_file = read_file(args.input)
		if not Q:
			STATUS.set_filesize(get_filesize(cap_file))
		try:
			if args.input.lower().endswith('.pcapng') or args.input.lower().endswith('.pcapng.gz'):
				try:
					for pcapng_file_header, bitness, if_tsresol, pcapng in read_pcapng_file_header(cap_file):
						read_pcapng_packets(cap_file, pcapng, pcapng_file_header, bitness, if_tsresol, args.ignore_ts, Q)
				except:
					cap_file.seek(0)
					pcap_file_header, bitness = read_pcap_file_header(cap_file)
					read_pcap_packets(cap_file, pcap_file_header, bitness, args.ignore_ts, Q)
			else:
				try:
					pcap_file_header, bitness = read_pcap_file_header(cap_file)
					read_pcap_packets(cap_file, pcap_file_header, bitness, args.ignore_ts, Q)
				except:
					cap_file.seek(0)
					for pcapng_file_header, bitness, if_tsresol, pcapng in read_pcapng_file_header(cap_file):
						read_pcapng_packets(cap_file, pcapng, pcapng_file_header, bitness, if_tsresol, args.ignore_ts, Q)
		except ValueError as error:
			xprint(str(error))
			exit()
		else:
			cap_file.close()
			if not Q:
				xprint(' '*77, end='\r')
				if len(DB.essids) == 0 and len(DB.excpkts) == 0 and len(DB.eapmd5s) == 0 and len(DB.eapleaps) == 0:
					xprint("[!] No Networks found\n")
					exit()

				xprint("[i] Networks detected: {}".format(len(DB.essids)))

				for message, count in LOGGER.info.items():
					xprint('[i] {}: {}'.format(message, count))
				for message, count in LOGGER.warning.items():
					xprint('[!] {}: {}'.format(message, count))
				for message, count in LOGGER.error.items():
					xprint('[!] {}: {}'.format(message, count))
				for message, count in LOGGER.critical.items():
					xprint('[!] {}: {}'.format(message, count))
				for message, count in LOGGER.debug.items():
					xprint('[@] {}: {}'.format(message, count))

			Builder(export=args.export, export_unauthenticated=args.all, filters=args.filter_by, group_by=args.group_by, do_not_clean=args.do_not_clean, ignore_ie=args.ignore_ie, locate=args.locate, Q=Q).build()

			if args.wordlist and len(DB.passwords):
				xprint("\nMiscellaneous:")
				# AP-LESS possible passwords
				DB.passwords = list(set(DB.passwords)) # Remove duplicates
				wordlist_file = open(args.wordlist, 'w')
				wordlist_file.write('\n'.join(DB.passwords)+'\n')
				wordlist_file.close()
				xprint("Extracted {} AP-LESS possible passwords to {}\n".format(len(DB.passwords), args.wordlist), end='')
			if args.export == "hccap" and len(DB.hccaps):
				written = 0
				xprint("\nOutput hccap files:")
				for hccap in DB.hccaps:
					if args.output:
						hccap_filename = (re.sub('\\.hccap(x?)$', '', args.output, flags=re.IGNORECASE)) + get_valid_filename("{}.hccap".format("_"+str(hccap['key']) if hccap['key'] != "none" else ''))
					else:
						if hccap['key'] == "none":
							hccap_filename = re.sub('\\.(p?)cap((ng)?)((\\.gz)?)$', '', args.input, flags=re.IGNORECASE) + ".hccap"
						else:
							hccap_filename = get_valid_filename("{}.hccap".format(str(hccap['key'])))
					print(hccap_filename)
					hccap_file = open(hccap_filename, 'wb')
					hccap_file.write(b''.join(hccap['raw_data']))
					hccap_file.close()
					written += len(hccap['raw_data'])
				if written:
					xprint("\nWritten {} WPA Handshakes to {} files".format(written, len(DB.hccaps)), end='')
			elif args.export == "hccapx" and len(DB.hccapxs):
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
						hcpmkid_line = ':'.join(hcpmkid.values())
						hcpmkid_file.write(hcpmkid_line+"\n")
						written += 1
					hcpmkid_file.close()
					if written:
						xprint("\nWritten {} WPA Handshakes to 1 files".format(written), end='')
				else:
					xprint("\nhcPMKID:")
					for hcpmkid in DB.hcpmkids.values():
						hcpmkid_line = ':'.join(hcpmkid.values())
						print(hcpmkid_line)
			elif args.export == "hceapmd5" and len(DB.hceapmd5s):
				if args.output:
					written = 0
					xprint("\nOutput hceapmd5 files:")
					hceapmd5_filename = args.output
					print(hceapmd5_filename)
					hceapmd5_file = open(args.output, 'w')
					for hceapmd5 in DB.hceapmd5s.values():
						hceapmd5_line = ':'.join(hceapmd5.values())
						hceapmd5_file.write(hceapmd5_line+"\n")
						written += 1
					hceapmd5_file.close()
					if written:
						xprint("\nWritten {} EAP-MD5 Authentications to 1 files".format(written), end='')
				else:
					xprint("\nhcEAP-MD5:")
					for hceapmd5 in DB.hceapmd5s.values():
						hceapmd5_line = ':'.join(hceapmd5.values())
						print(hceapmd5_line)
			elif args.export == "hceapleap" and len(DB.hceapleaps):
				if args.output:
					written = 0
					xprint("\nOutput hceapleap files:")
					hceapleap_filename = args.output
					print(hceapleap_filename)
					hceapleap_file = open(args.output, 'w')
					for hceapleap in DB.hceapleaps.values():
						hceapleap_line = ':'.join(hceapleap.values())
						hceapleap_file.write(hceapleap_line+"\n")
						written += 1
					hceapleap_file.close()
					if written:
						xprint("\nWritten {} EAP-LEAP Authentications to 1 files".format(written), end='')
				else:
					xprint("\nhcEAP-LEAP:")
					for hceapleap in DB.hceapleaps.values():
						hceapleap_line = ':'.join(hceapleap.values())
						print(hceapleap_line)
			elif not Q:
				xprint("\nNothing exported. You may want to: "+ \
					("\n- Try a different export format (-x/--export)")+ \
					("\n- Use -a/--all to export unauthenticated handshakes" if not args.all else "")+ \
					("\n- Use --ignore-ie to ignore ie (AKM Check) (Not Recommended)" if not args.ignore_ie else "")+ \
					("\n- Use --ignore-ts to ignore timestamps check (Not Recommended)" if (not args.ignore_ts and LOGGER.warning.get('Zero value timestamps detected')) else "")+ \
					("\n- Remove the filter (-f/--filter-by)" if args.filter_by != [None, None] else "") \
				)
			xprint()
	else:
		xprint(FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), args.input))
		exit()

#########################
#########################

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Convert a cap/pcap/pcapng capture file to a hashcat hcwpax/hccapx/hccap/hcpmkid/hceapmd5/hceapleap file', add_help=False)
	required = parser.add_argument_group('required arguments')
	optional = parser.add_argument_group('optional arguments')
	required.add_argument("--input", "-i", help="Input capture file", metavar="capture.cap", required=True)
	required.add_argument("--export", "-x", choices=['hcwpax', 'hccapx', 'hccap', 'hcpmkid', 'hceapmd5', 'hceapleap'], required=True)
	optional.add_argument("--output", "-o", help="Output file", metavar="capture.hcwpax")
	optional.add_argument("--essid","-e",help="led user add ESSID to beacon when missing (cloaked ESSID)")
	optional.add_argument("--all", "-a", help="Export all handshakes even unauthenticated ones", action="store_true")
	optional.add_argument("--filter-by", "-f", nargs=2, metavar=('filter-by', 'filter'), help="--filter-by {bssid XX:XX:XX:XX:XX:XX, essid ESSID}", default=[None, None])
	optional.add_argument("--group-by", "-g", choices=['none', 'bssid', 'essid', 'handshake'], default='bssid')
	optional.add_argument("--wordlist", "-E", help="Extract wordlist / AP-LESS possible passwords (autohex enabled on non ASCII characters)", metavar="wordlist.txt")
	optional.add_argument("--do-not-clean", help="Do not clean output", action="store_true")
	optional.add_argument("--ignore-ie", help="Ignore information element (AKM Check) (Not Recommended)", action="store_true")
	optional.add_argument("--ignore-ts", help="Ignore timestamps check (Not Recommended)", action="store_true")
	optional.add_argument("--quiet", "-q", help="Enable quiet mode (print only output files/data)", action="store_true")
	optional.add_argument("--update-oui", help="Update OUI Database", action="store_true")
	optional.add_argument("--locate", help="Locate networks geolocations", action="store_true")
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
		Q = True
		def xprint(text="", end='\n', flush=True):
			pass
	else:
		Q = False
		STATUS = Status()
		MAC_VENDOR = MAC_VENDOR_LOOKUP(OUI_DB_FILE)
		if args.update_oui:
			MAC_VENDOR.download_db(OUI_DB_FILE)
			MAC_VENDOR.load_data()
		if args.locate:
			MAC_GEO = MAC_GEO_LOOKUP()
	main(Q)
