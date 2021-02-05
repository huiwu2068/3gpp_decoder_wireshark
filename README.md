# 3gpp_decoder_wireshark

3gpp_decoder_wireshark is a free open source python wrapper to decode 3GPP PDUs(Protocol Data Units) via Wireshark.

You can use 3gpp_decoder_wireshark decode 3GPP NR, LTE, UMTS and GSM messages for RRC, NAS, S1AP, RANAP, X2AP ,MAC and RLC.

# Usage

python 3gpp_decoder.py [-h] [-l] decode_type hex_string

positional arguments:
  decode_type  decode type
  hex_string   the hex string to be decoded

optional arguments:
  -h, --help   show this help message and exit
  -l, --list   list decode types

# Example
python 3gpp_decoder.py mac-nr.ul-sch "34 1e 4e 8c 47 2e 46 3f 00 00 00 00"
python 3gpp_decoder.py nr-rrc.ul.ccch "00 3e 40 8f 65 c8"
python 3gpp_decoder.py mac-nr.dl-sch.rar "52 00 20 33 73 86 46 bb 00 00 00 00"
