hex_input = "70 61 73 73 77 6f 72 64" # hex ascii dump
hex_input = hex_input.replace(' ', '')
dec_output = [chr(int(hex_input[i:i+2],16)) for i in range(0,len(hex_input),2)]
print(dec_output)

line = b'1. \\Device\\NPF_{FB4F7F32-9DBB-4876-A438-E6D3D7DC69F3} (VirtualBox Host-Only Network)\r\n'
print(str(line).split(' ')[1])

import re
print(re.findall(r"\([A-Za-z\-\s]*\)", str(line)))

r"""
def sniffer():
  print("Using Scapy")
  from scapy.all import sniff
  packets = sniff(count=50, filter="http.request.get", timeout=10)#, prn=lambda pkt: pkt.summary())
  print(packets.show())


def _tshark():
  print("Using pyshark")
  import pyshark
  print(pyshark.packet.packet.Packet())

"""


r"""
1.  tshark -D any
2.  tshark -i \device\NPF_{60FE7949-85D0-4534-9DD2-9C0BFD4DF0D5} -Y http.request.method==POST -Tfields -e text -e ip.dst
	tshark -Y http.request.method==POST -Tfields -e http.file_data -e ip.dst
	tshark -Y http.request.method==POST -Tfields -e text -e ip.dst





This got much easier with Wireshark 2.x or so. At least the following works for me with Wireshark 2.2.5 from Debian 9 but not with Wireshark 1.8.x from RHEL 6:

tshark -Y http.request.method==POST -Tfields -e http.file_data
I though would still be interested in a nice solution for Wireshark 1.8. Neither

tshark -Y http.request.method==POST -Tfields -e data.data
nor

tshark -Y http.request.method==POST -Tfields -e text
are really useful without further manual decoding.


"""

r"""

"C:\Program Files\Wireshark\tshark.exe" -i \Device\NPF_{266049D1-BF10-4E23-A716-93BD8060709C} -Y http.request.method==POST -Tfields -e http.file_
data


"""
