import socket
import json
import datetime
import time
from scapy.layers.inet import *
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.all import sr1
from scapy.sendrecv import *
from scapy.all import *

LISTEN_SOCK = 34567
USER_NAME = "Naama.Biton"


def read_file(file):
    """Read the file into list
    :param file: given file
    :return: list of the info that the file includes
    """
    input_file = open(file, "r")
    info_list = input_file.read().split("\n")
    input_file.close()
    return info_list


def extract_black_list(info):
    """Extract the "black list" from the given information of the file
    :param info: information of the file ("settings.dat")
    :return: dict [ip]:[website/name]
    """
    relevant = ""
    dct = {}
    for line in info:
        if "BLACKLIST" in line:
            relevant = line[12::]
    length = relevant.count(",") + 1
    for i in range(length):
        index_points = relevant.find(":") + 1
        index_comma = relevant.find(",")
        ip = relevant[0:index_points]
        name = relevant[index_points::]
        dct[ip] = name
        relevant = relevant[index_comma + 1::]
    return dct


def extract_workers(info_file):
    """ Extract the relevant information from the data of the file
    :param info_file: the data of the file
    :return: dict of the workers and their ip
    """
    relevant = ""
    dct = {}
    for line in info_file:
        if "WORKERS" in line:
            relevant = line[10::]
    length = relevant.count(",") + 1
    for i in range(length):
        index_points = relevant.find(":") + 1
        index_comma = relevant.find(",")
        name = relevant[0:index_points]
        ip = relevant[index_points:index_comma]
        dct[ip] = name[0:-1]
        relevant = relevant[index_comma + 1::]
    return dct


def incoming_traffic_per_agent(client_data, client_adress, dct, dt_in):
    """Calculating the incoming traffic from the agents/worker
    :param client_data: the data we received from the agent/worker
    :param client_adress: the adress of the agent/worker
    :param dct: dict [ips]:[workers]
    :param dt_in: empty dict to fill
    :return: dict [agent/worker]:[traffic]
    """
    dt = json.loads(client_data.decode())
    ip = client_adress[0]
    ips = list(dct.keys())
    if ip in ips:
        if dt["Traffic"] == "false":
            dt_in[ip] += dt["Length"]
    return dt_in


def outcoming_traffic_per_agent(client_data, client_adress, dct, dt_out):
    """Calculating the outcoming traffic from the agents/worker
    :param client_data: the data we received from the agent/worker
    :param client_adress: the adress of the agent/worker
    :param dct: dict [ips]:[workers]
    :param dt_out: empty dict to fill
    :return: dict [agent/worker]:[traffic]
    """
    dt = json.loads(client_data.decode())
    ip = client_adress[0]
    ips = list(dct.keys())
    if ip in ips:
        if dt["Traffic"] == "true":
            dt_out[ip] += dt["Length"]
    return dt_out


def traffic_per_country(client_data, dt_country):
    """Calculating the traffic per country
    :param client_data: the data we received from the agent/worker
    :param dt_country: empty dict to fill
    :return: dict[country][traffic]
    """
    dt = json.loads(client_data.decode())
    if dt["Country"] not in dt_country:
        dt_country[dt["Country"]] = dt["Length"]
    else:
        dt_country[dt["Country"]] += dt["Length"]
    return dt_country


def traffic_per_ip(client_data, dt_ip):
    """Calculating the traffic per ip
    :param client_data: the data we received from the agent/worker
    :param dt_ip: empty dict to fill
    :return: dict[ip]:[traffic]
    """
    dt = json.loads(client_data.decode())
    if dt["IP"] not in dt_ip.keys():
        dt_ip[dt["IP"]] = dt["Length"]
    else:
        dt_ip[dt["IP"]] += dt["Length"]
    return dt_ip


def traffic_per_app(client_data, dt_software):
    """Calculating the traffic per application(software)
    :param client_data: the data we received from the agent/worker
    :param dt_software: empty dict to fill
    :return: dict[software]:[traffic]
    """
    dt = json.loads(client_data.decode())
    if dt["Software"] not in dt_software.keys():
        dt_software[dt["Software"]] = dt["Length"]
    else:
        dt_software[dt["Software"]] += dt["Length"]
    return dt_software


def traffic_per_port(client_data, dt_port):
    """Calculating the traffic per port
    :param client_data: the data we received from the agent/worker
    :param dt_port: empty dict to fill
    :return: dict[port]:[traffic]
    """
    dt = json.loads(client_data.decode())
    if dt["Port"] not in dt_port.keys():
        dt_port[dt["Port"]] = dt["Length"]
    else:
        dt_port[dt["Port"]] += dt["Length"]
    return dt_port


def alerts(info):
    """Returns the black list
    :param info: information of the file ("settings.dat")
    :return: the black list
    """
    return extract_black_list(info)


def open_html(file):
    """Open the given html file and extract the information to list
    :param file: given html file
    :return: extracted information
    """
    f = open(file, "r")
    list = f.read().split("\n")
    return list


def get_current_time():
    """Gets the current time
    :return: the current time
    """
    e = datetime.now()
    return e.strftime("%d-%m-%Y, %H:%M")


def update_html_last_update(html_code, date):
    """Update the current date in the html file
    :param html_code: the code of the html file
    :param date: the current date
    :return: the updated code of the html file
    """
    updated_list = []
    for line in html_code:
        if "Last update:" in line:
            index = line.find("Last update:")
            s = line[0:index + 12]
            index_end = line.find("</p>")
            s += date
            s += line[index_end::]
            updated_list.append(s)
        else:
            updated_list.append(line)
    return updated_list


def update_html_alerts(updated_html_code, black_list):
    """Update the Alerts section of the html file
    :param updated_html_code: the html code of the file
    :param black_list: the alerts that will added
    :return: the updated html code
    """
    updated_list = []
    for line in updated_html_code:
        if "%%ALERTS%%" in line:
            updated_list.append(black_list)
        else:
            updated_list.append(line)
    return updated_list


def indexs_in_agents(update_html_code):
    """Return two indexs that will help to set the incoming agent information
    :param update_html_code: html code
    :return: two indexs
    """
    index_keys = 0
    index_values = 0
    for i in range(len(update_html_code)):
        if "labels: %%AGENTS_IN_KEYS%%" in update_html_code[i]:
            index_keys = i
        if "data: %%AGENTS_IN_VALUES%%" in update_html_code[i]:
            index_values = i
    return index_keys, index_values


def indexs_out_agents(update_html_code):
    """Return two indexs that will help to set the outcoming agent information
    :param update_html_code: html code
    :return: two indexs
    """
    index_keys = 0
    index_values = 0
    for i in range(len(update_html_code)):
        if "labels: %%AGENTS_OUT_KEYS%%" in update_html_code[i]:
            index_keys = i
        if "data: %%AGENTS_OUT_VALUES%%" in update_html_code[i]:
            index_values = i
    return index_keys, index_values


def indexs_countries(update_html_code):
    """Find two indexs that will help set the relevant information of the countries
    :param update_html_code: html code
    :return: indexs
    """
    index_keys = 0
    index_values = 0
    for i in range(len(update_html_code)):
        if " labels: %%COUNTRIES_KEYS%%" in update_html_code[i]:
            index_keys = i
        if "data: %%COUNTRIES_VALUES%%" in update_html_code[i]:
            index_values = i
    return index_keys, index_values


def indexs_ip(update_html_code):
    """Find two indexs to set the information of the ips
    :param update_html_code: html code
    :return: two indexs
    """
    index_keys = 0
    index_values = 0
    for i in range(len(update_html_code)):
        if "labels: %%IPS_KEYS%%" in update_html_code[i]:
            index_keys = i
        if "data: %%IPS_VALUES%%" in update_html_code[i]:
            index_values = i
    return index_keys, index_values


def indexs_app(update_html_code):
    """Find two indexs to set the information of the applications(softwares)
    :param update_html_code: html code
    :return: two indexs
    """
    index_keys = 0
    index_values = 0
    for i in range(len(update_html_code)):
        if "labels: %%APPS_KEYS%%" in update_html_code[i]:
            index_keys = i
        if "data: %%APPS_VALUES%%" in update_html_code[i]:
            index_values = i
    return index_keys, index_values


def indexs_port(update_html_code):
    """Find two indexs to set the information of the ports
    :param update_html_code: html code
    :return: two indexs
    """
    index_keys = 0
    index_values = 0
    for i in range(len(update_html_code)):
        if "labels: %%PORTS_KEYS%%," in update_html_code[i]:
            index_keys = i
        if "%%PORTS_VALUES%%" in update_html_code[i]:
            index_values = i
    return index_keys, index_values


def update_incoming_agent_keys_data(update_html_code, dct, dt_in, indexs):
    """ Update the incoming agent data in the html code
    :param update_html_code: html code
    :param dct: dict[ip]:[worker/agent]
    :param dt_in: dict[ip]:[traffic]
    :param indexs: two indexs that will help set the html code and update it
    :return: updated html code
    """
    updated_list = []
    index_keys = indexs["in_agent"][0]
    index_values = indexs["in_agent"][1]
    names = list(dct.values())
    ips = list(dct.keys())
    traffic = list(dt_in.values())
    for i in range(len(update_html_code)):
        if i == index_keys:
            index_1 = update_html_code[i].find(":") + 1
            m = update_html_code[i][0:index_1] + " " + str(names) + ','
            updated_list.append(m)
        elif i == index_values:
            index_1 = update_html_code[i].find(":") + 1
            l = update_html_code[i][0:index_1] + str(traffic)
            l += str(traffic)
            l += ","
            updated_list.append(l)
        else:
            updated_list.append(update_html_code[i])
    return updated_list


def update_outcoming_agent_keys_data(update_html_code, dct, dt_out, indexs):
    """Update the outcoming agent traffic in  the html code
    :param update_html_code: html code
    :param dct: dict[ip]:[worker]
    :param dt_out: dict[ip]:[traffic]
    :param indexs: two indexs that will help set the html code and update it
    :return: updated html code
    """
    updated_list = []
    index_keys = indexs["out_agent"][0]
    index_values = indexs["out_agent"][1]
    names = list(dct.values())
    ips = list(dct.keys())
    traffic = list(dt_out.values())
    for i in range(len(update_html_code)):
        if i == index_keys:
            index_1 = update_html_code[i].find(":") + 1
            m = update_html_code[i][0:index_1] + " " + str(names).replace("""\"""", '') + ','
            updated_list.append(m)
        elif i == index_values:
            index_1 = update_html_code[i].find(":") + 1
            l = update_html_code[i][0:index_1] + str(traffic)
            l += str(traffic)
            l += ","
            updated_list.append(m)
        else:
            updated_list.append(update_html_code[i])
    return updated_list


def update_countries(update_html_code, dt_country, indexs):
    """ Update the countries traffic in the html code
    :param update_html_code: html code
    :param dt_country: dict [country]:[traffic]
    :param indexs: two indexs that will help set the html code and update it
    :return: update html code
    """
    updated_list = []
    index_keys = indexs["countries"][0]
    index_values = indexs["countries"][1]
    countries = list(dt_country.keys())
    traffic = list(dt_country.values())
    for i in range(len(update_html_code)):
        if i == index_keys:
            index = update_html_code[i].find(":") + 1
            k = update_html_code[i][0:index]
            k += str(countries)
            k += ","
            updated_list.append(k)
        elif i == index_values:
            index = update_html_code[i].find(":") + 1
            q = update_html_code[i][0:index]
            q += str(traffic)
            q += ","
            updated_list.append(q)
        else:
            updated_list.append(update_html_code[i])
    return updated_list


def update_ip(update_html_code, dt_ip, indexs):
    """ Update the ip traffic in the html code
    :param update_html_code: html code
    :param dt_ip: dict [ip]:[traffic]
    :param indexs: two indexs that will help set the html code and update it
    :return: updates html code
    """
    updated_list = []
    index_keys = indexs["ips"][0]
    index_values = indexs["ips"][1]
    ips = list(dt_ip.keys())
    traffic = list(dt_ip.values())
    for i in range(len(update_html_code)):
        if i == index_keys:
            index = update_html_code[i].find(":") + 1
            k = update_html_code[i][0:index]
            k += " " + str(ips).replace("""\"""", '')
            k += ","
            updated_list.append(k)
        elif i == index_values:
            index = update_html_code[i].find(":") + 1
            q = update_html_code[i][0:index]
            q += str(traffic)
            q += ","
            updated_list.append(q)
        else:
            updated_list.append(update_html_code[i])
    return updated_list


def update_apps(update_html_code, dt_app, indexs):
    """ Update the softwares traffic in the html code
    :param update_html_code: html code
    :param dt_app: dict[software/app]:[traffic]
    :param indexs: two indexs that will help set the html code and update it
    :return: updated html code
    """
    updated_list = []
    index_keys = indexs["apps"][0]
    index_values = indexs["apps"][1]
    apps = list(dt_app.keys())
    traffic = list(dt_app.values())
    for i in range(len(update_html_code)):
        if i == index_keys:
            index = update_html_code[i].find(":") + 1
            k = update_html_code[i][0:index]
            k += " " + str(apps)
            k += ","
            updated_list.append(k)
        elif i == index_values:
            index = update_html_code[i].find(":") + 1
            q = update_html_code[i][0:index]
            q += str(traffic)
            q += ","
            updated_list.append(q)
        else:
            updated_list.append(update_html_code[i])
    return updated_list


def update_ports(update_html_code, dt_port, indexs):
    """ Update the ports traffic in the html code
    :param update_html_code: html code
    :param dt_port: dict[port]:[traffic]
    :param indexs: two indexs that will help set the html code and update it
    :return: updated html code
    """
    updated_list = []
    index_keys = indexs["ports"][0]
    index_values = indexs["ports"][1]
    ports = list(dt_port.keys())
    traffic = list(dt_port.values())
    for i in range(len(update_html_code)):
        if i == index_keys:
            index = update_html_code[i].find(":") + 1
            k = update_html_code[i][0:index]
            k += " " + str(ports) + ","
            updated_list.append(k)
        elif i == index_values:
            index = update_html_code[i].find(":") + 1
            q = update_html_code[i][0:index]
            q += str(traffic) + ","
            updated_list.append(q)
        else:
            updated_list.append(update_html_code[i])
    return updated_list


def update_html_code(html_code, indexs, black_list, dct_workers, dt_in, dt_out, dt_country, dt_ip, dt_app, dt_port):
    """ Update the html code (altogether)
    :param html_code: the original html code
    :param indexs: dict[type(list ips)]:[two indexs that will help set the html code and update it]
    :param black_list: dict of the alerts [ip]:[software]
    :param dct_workers: dict [ip]:[worker]
    :param dt_in: dict [agent]:[incoming traffic]
    :param dt_out: dict [agent]:[outcoming traffic]
    :param dt_country: dict [country]:[traffic]
    :param dt_ip: dict [ip]:[traffic]
    :param dt_app: dict [software]:[traffic]
    :param dt_port: dict [port]:[traffic]
    :return: the final html code
    """
    date = get_current_time()
    lst1 = update_html_last_update(html_code, date)
    print(lst1)
    lst2 = update_html_alerts(lst1, black_list)
    print(lst2)
    lst3 = update_incoming_agent_keys_data(lst2, dct_workers, dt_in, indexs)
    lst4 = update_outcoming_agent_keys_data(lst3, dct_workers, dt_out, indexs)
    lst5 = update_countries(lst4, dt_country, indexs)
    lst6 = update_ip(lst5, dt_ip, indexs)
    print(lst6)
    lst7 = update_apps(lst6, dt_app, indexs)
    the_final_code = update_ports(lst7, dt_port, indexs)
    return the_final_code


def updating_the_html_page(file, html_code, indexs, black_list, dct_workers, dt_in, dt_out, dt_country, dt_ip, dt_app,
                           dt_port):
    """ Update the html file and upload it to the boss sniffer
    :param file: file to update
    :param html_code: original html code
    :param indexs: dict[type(list ips)]:[two indexs that will help set the html code and update it]
    :param black_list: dict of the alerts [ip]:[software]
    :param dct_workers: dict [ip]:[worker]
    :param dt_in: dict [agent]:[incoming traffic]
    :param dt_out: dict [agent]:[outcoming traffic]
    :param dt_country:  dict [country]:[traffic]
    :param dt_ip: dict [ip]:[traffic]
    :param dt_app: dict [software]:[traffic]
    :param dt_port: dict [port]:[traffic]
    :return: updated file
    """
    html_code = update_html_code(html_code, indexs, black_list, dct_workers, dt_in, dt_out, dt_country, dt_ip, dt_app,
                                 dt_port)
    f = open(file, "w")
    for line in html_code:
        f.write(str(line))
    f.close()
    upload_files(file)
    return f


def upload_files(file):
    """Upload the file to boss sniffer
    :param file: html file
    """
    packet1 = Ether() / IP(dst="52.35.198.18") / TCP(sport=20, dport=8808) / USER_NAME
    packet2 = Ether() / IP(dst="52.35.198.18") / TCP(sport=20, dport=8808) / file
    answer1 = srp1(packet1, verbose=0)
    # answer1.show()
    answer2 = srp1(packet2, verbose=0)
    # answer2.show()


def info_from_agent(dct_workers, dt_out, dt_in, dt_country, dt_ip, dt_software, dt_port, indexs, file, html_code,
                    black_list):
    """ Gets the information from the agent and print it with the name of the worker
    that sent the information (if he exist) if not, with the ip of the sender
    :param dt_country:
    :param dct: dict of workers and their ip
    """

    listening_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listening_sock.bind(('', LISTEN_SOCK))
    try:
        while True:
            (client_data, client_address) = listening_sock.recvfrom(4096)
            ip = client_address[0]
            if ip in dct_workers:
                print("The report was received from:", dct_workers[ip])
            else:
                print("The report was received from:", ip)
            print(client_data.decode())
            for i in range(19):
                (client_data, client_address) = listening_sock.recvfrom(4096)
                print(client_data.decode())
                dt_in = incoming_traffic_per_agent(client_data, client_address, dct_workers, dt_in)
                dt_out = outcoming_traffic_per_agent(client_data, client_address, dct_workers, dt_out)
                dt_country = traffic_per_country(client_data, dt_country)
                dt_ip = traffic_per_ip(client_data, dt_ip)
                dt_software = traffic_per_app(client_data, dt_software)
                dt_port = traffic_per_port(client_data, dt_port)
            updating_the_html_page(file, html_code, indexs, black_list, dct_workers, dt_in, dt_out, dt_country, dt_ip,
                                   dt_software, dt_port)
            # upload_files(file)
            time.sleep(10)

    except OSError:
        print("the port isn't available")
    except Exception:
        print("Unknown error")
    listening_sock.close()


# NOTE : try to moudle the indexs so it wont hurt the page
def main():
    info = read_file("settings.dat")
    dct = extract_workers(info)
    black_list = extract_black_list(info)
    ips = list(dct.keys())
    # creating dicts to extract the traffic count and save it in all the rounds:
    dt_in = {ips[i]: 0 for i in range(len(dct.values()))}
    dt_out = {ips[i]: 0 for i in range(len(dct.values()))}
    dt_country = {}
    dt_ip = {}
    dt_software = {}
    dt_port = {}
    # ends of dict
    # start of html: (1) open the file and extract the required indexs:
    file = "last.html"
    information_html = open_html(file)
    print(information_html)
    indexs = {"in_agent": indexs_in_agents(information_html), "out_agent": indexs_out_agents(information_html),
              "countries": indexs_countries(information_html),
              "ips": indexs_ip(information_html), "apps": indexs_app(information_html),
              "ports": indexs_port(information_html)}
    # end of required indexs
    # start processing
    info_from_agent(dct, dt_in, dt_out, dt_country, dt_ip, dt_software, dt_port, indexs, file, information_html,
                    black_list)
    upload_files(file)   # upload the file


# 52.35.198.18
if __name__ == '__main__':
    main()
