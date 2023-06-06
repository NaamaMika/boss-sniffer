import ipaddress
import socket
import urllib

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.all import sr1
from scapy.sendrecv import *
import scapy
import json
import time
import subprocess
import requests
URL = "http://ip-api.com/json/?fields=country"


SERVER_IP = "localhost"
SERVER_PORT = 34567


def tcp_udp_ip(packet):
    """ Checks if the packet has layer ip and tcp or udp
    :param packet: sniffed packet
    :return: True/False
    """
    return IP in packet and UDP in packet or TCP in packet


def find_other_ip(packet):
    """ Finds the  ip we talk to in this packet
    :param packet: sniffed packet
    :return: True/ False
    """
    if packet.haslayer(IP):
        if traffic_in_or_out(packet):
            return packet[IP].dst
        else:
            return packet[IP].src


def traffic_in_or_out(packet):
    """ Checks if the traffic in the packet is in or out
    :param packet: sniffed packet
    :return: True / False
    """
    if IP in packet:
        return ipaddress.ip_address(packet[IP].src).is_private
        # true if its going, I was the one to send the packet


def dst_port(packet):
    """ Finds the destination port of the packet
    :param packet: sniffed packet
    :return: destination port of the packet
    """
    dst = ""
    if IP in packet:
        if TCP in packet:
            dst = packet[TCP].dport
        elif UDP in packet:
            dst = packet[UDP].dport
    return dst


def size_packet(packet):
    """Return the length of the packet
    :param packet: sniffed packet
    :return: the length of the packet
    """
    return len(packet)


def netstat_nb():
    """Return the netstat -nb command like in cmd
    :return: netstat -nb command as list
    """
    program_str = subprocess.run(["netstat", "-nb"], stdout=subprocess.PIPE).stdout.decode("utf-8")
    info = program_str[86::]
    lis = info.split("\n")
    ls = [i.strip() for i in lis]
    return ls


def extract_ip(ls):
    """Extract the ip from the netstat -nb list
    :param ls: netstat -nb list
    :return: list of ip
    """
    list_ips = []
    for i in range(len(ls)):
        if ":" in ls[i]:
            index_points_1 = ls[i].find(":")
            txt = ls[i][index_points_1 + 9::]
            # print(txt)
            index_points_2 = txt.find(":")
            ip = txt[0:index_points_2]
            if "." in ip:
                list_ips.append(ip)
    list_ips = [i.replace("       ", "") for i in list_ips]
    list_ips = [i.replace("  ", "") for i in list_ips]
    list_ips = [i.replace(" ", "") for i in list_ips]
    return list_ips


def extract_software(ls):
    """Extract the software from the netstat -nb list
    :param ls: netstat -nb list
    :return: list of softwares
    """
    list_softwares = []
    for i in range(len(ls) - 1):
        if i % 2 == 1 and "TCP" not in ls[i] and "UDP" not in ls[i]:
            if "[" in ls[i]:
                list_softwares.append(ls[i][1:-1])
            else:
                list_softwares.append(ls[i])
    return list_softwares


def create_dct(ips, softwares):
    """Create dict that arrange the ips and their softwares
    :param ips: list of ips from the netstat -nb command
    :param softwares: list of softwares from the netstat -nb command
    :return: dict: [ip]:[software]
    """
    if len(softwares) < len(ips):
        dct = {ips[i]: softwares[i] for i in range(len(softwares))}
    elif len(softwares) > len(ips):
        dct = {ips[i]: softwares[i] for i in range(len(ips))}
    else:
        dct = {ips[i]: softwares[i] for i in range(len(ips))}
    return dct


def get_software(ip,dct):
    """ return the software of the given ip (ip it exist)
    :param ip: given ip
    :param dct: dict: [ip]:[software]
    :return: if the ip's software exist - the software , otherwise "Unknown"
    """
    if ip in dct.keys():
        return dct[ip]
    else:
        return "Unknown"


def http_request(ip):
    """Send http request and get answer
    :param ip: given ip
    :return: answer from the website
    """
    URL = "http://ip-api.com/json/"+str(ip)+"?fields=country"
    res = urllib.request.urlopen(URL)
    html = res.read()
    return html.decode()[12:-2]


def list_ips(packets):
    """ Arrange the required ips in list
    :param packets: sniffed packets
    :return: list of ips
    """

    ips = []
    for packet in packets:
        if tcp_udp_ip(packet) and traffic_in_or_out(packet):
            if find_other_ip(packet) not in ips:
                ips.append(find_other_ip(packet))
    return ips


def create_dct_country_ip(ips):
    """Arrange the ips and their countries in dict
    :param ips: list of ips
    :return: dict: [ip]:[country]
    """
    dct = {ips[i]: http_request(ips[i]) for i in range(len(ips))}
    return dct


def get_country(ip, dct):
    """Get the country from the dict with given ip(if the ip is not private)
    :param ip: given ip
    :param dct: dict: [ip]:[country]
    :return: the country/"Private ip"
    Note: there are public ips that the website returns to them ""
    """
    if ip in dct.keys():
        return dct[ip]
    else:
        return "Private ip"


def send(msg):
    """Send the message to the manager
    :param msg: the message that will send to the server
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = ("localhost", 34567)
        sock.sendto(msg.encode(), server_address)
    except ConnectionRefusedError:
        print("the port isn't recognized make sure its the right one or the server isn't available")
    except TimeoutError:
        print("The ip address is unknown")
    except Exception:
         print("Unknown error")


# NEED TO CLOSE THE SOCKET


def information_json(packets, dct):
    """Arrange the relevant information into data base - json and call to the send function
    :param dct: dict of software and ips
    :param packets: sniffed packets
    """
    ips = list_ips(packets)
    dct_country_ip = create_dct_country_ip(ips)
    text = {"IP": 0, "Port": 0, "Traffic": 0, "Length": 0, "Software": "Unknown","Country":"your location"}
    for packet in packets:
        ip = find_other_ip(packet)
        if ip is not None:
            text["IP"] = ip
            text["Port"] = dst_port(packet)
            text["Traffic"] = traffic_in_or_out(packet)
            text["Length"] = size_packet(packet)
            text["Software"] = get_software(ip,dct)
            text["Country"] = get_country(ip, dct_country_ip)
            json_object = json.dumps(text)
            print(json_object)
            send(json_object)


def main():
    ls = netstat_nb()
    ips = extract_ip(ls)
    softwares = extract_software(ls)
    dct = create_dct(ips, softwares)
    while True:
        packets = sniff(count=100, lfilter=tcp_udp_ip)
        information_json(packets, dct)
        time.sleep(2)  # wait before continue


if __name__ == '__main__':
    main()
