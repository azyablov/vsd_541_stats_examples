import requests
import json
import urllib3
import base64
import logging
from pprint import pprint
from typing import Union, List, Tuple
from urllib3.exceptions import InsecureRequestWarning
import vspk.utils as utils
import vspk.v5_0 as vspk
import bambou
from datetime import datetime, timedelta, timezone
import ipdb

# Disable exceptions related to incorrect SSL certificates
urllib3.disable_warnings(category=InsecureRequestWarning)


def nu_get_supported_api_versions(base_url: str) -> Union[bool, List[str]]:
    """ The function requests all possible api versions and selects CURRENT one.
    If something goes wrong empty list is returned.
    :param base_url: URL string
    :return list
    """

    http_session = requests.session()
    http_resp = http_session.get(url=base_url, verify=False)
    ver_supp = False
    if http_resp.ok:
        json_obj = http_resp.json()
    else:
        return ver_supp

    ver_supp = [None]
    # Go throughout list of dicts and extract CURRENT versions
    for item in json_obj['versions']:
        if item['status'] == 'CURRENT':
            # ver_supp.append(item['version'].upper())
            ver_supp[0] = item['version'].upper()
        if item['status'] == 'DEPRECATED':
            ver_supp.append(item['version'].upper())
    # Let's return most recent version as [0]
    ver_supp.sort(reverse=True)
    return ver_supp


def slice_stats_data(stats_o: vspk.NUStatistics) -> List[Tuple[str, List]]:
    return [(st_type_type, stats_o.stats_data[st_type_type][0:5])
            for st_type_type, st_type_data in stats_o.stats_data.items()]

def nu_build_api_url(host_base: str, current: bool = True) -> str:
    if current:
        return f"{host_base}/nuage/api/{nu_get_supported_api_versions(host_base + '/nuage')[0].replace('.', '_')}"
    else:
        return f"{host_base}/nuage/api/{nu_get_supported_api_versions(host_base + '/nuage')[1].replace('.', '_')}"


def base64_auth(login: str, secret: str) -> str:
    auth_str = f"{login}:{secret}"
    auth_b64 = base64.b64encode(auth_str.encode(encoding='utf-8'))
    pprint(auth_b64.decode())
    return auth_b64.decode()


if __name__ == "__main__":

    # Below section to be replaced with argparse
    ip = "172.17.10.129"
    my_login = "csproot"
    my_password = "csproot"
    vsd_url = 'https://' + ip + ':8443'

    # Setting up main logger and logger for NuAPI
    log_main = logging.getLogger(__name__)
    fl_hdl = logging.FileHandler('log/' + __name__ + '.log', mode='w')
    fl_hdl.setLevel(logging.DEBUG)
    fl_hdl.setFormatter(logging.Formatter('%(asctime)s - %(processName)s - %(levelname)s: %(message)s'))
    log_main.addHandler(fl_hdl)
    log_main.setLevel(logging.DEBUG)
    utils.set_log_level(logging.DEBUG, logging.FileHandler('log/' + 'nu_api.log', mode='w'))
    log_main.debug("***  START  ***")

    # Identifying current API base
    api_base = nu_build_api_url(vsd_url)
    log_main.info('API base: ' + api_base)

    api_session = vspk.NUVSDSession(username=my_login, password=my_password, enterprise='csp',
                                    api_url=vsd_url)

    # Actively connecting to the VSD API
    try:
        # Start session and get API key
        api_session.start()
        log_main.info(f"Session has been started.API key: {api_session.user.api_key}")
    except bambou.exceptions.BambouHTTPError as err:
        response = err.connection.response
        if response.status_code == 409:
            # The entity probably already exists, so we just ignore this error:
            pass
        else:
            log_main.error("Failed to start session!")
            # re-raise the exception
            raise

    root = api_session.user
    if not isinstance(root, vspk.nume.NUMe):
        log_main.error("root object is not an instance of vspk.nume.NUMe! Closing.")
        exit(1)

    pprint(root.statistics_enabled)

    log_main.info(f"Stastics colleciton status: {root.statistics_enabled}")

    # https://172.17.10.129:8443/nuage/api/v5_0/systemconfigs
    sys_config = root.system_configs.get_first()
    stats_attr = [att for att in dir(sys_config) if att.startswith('stats_')]
    # ipdb.set_trace()
    for sa in stats_attr:
        print(f"{sa.upper()}: {getattr(sys_config, sa)}")

    # How extract needed vports from enterprise opbject
    ipdb.set_trace()

    # Get enterprise object
    my_stats_ent = root.enterprises.get_first(filter='name is "first"')

    # Get object of domain dom1
    stats_dom: vspk.NUDomain = my_stats_ent.domains.get_first(filter='name is "dom1"')

    # Let's say I want to see traffic on those two VMs
    my_vms = {"10.1.1.235": {}, "10.2.1.121": {}}

    # Get all vports directly from enterprise
    stats_vports = stats_dom.vports.get()
    for vport in stats_vports:
        vport: vspk.NUVPort  # Type hinting
        vport.fetch()
        vminf = vport.vm_interfaces.get_first()
        pprint(f"My vport ID: "
               f"{vport.to_dict()}")
        if vminf.ip_address in my_vms.keys():
            print(f"Match for {vminf.ip_address} found!")
            my_vms[vminf.ip_address]["domain_name"] = vminf.domain_name
            my_vms[vminf.ip_address]["zone_name"] = vminf.zone_name
            my_vms[vminf.ip_address]["subnet_name"] = vminf.network_name
            my_vms[vminf.ip_address]["vport"] = vport
    print("Data structure used for test VMs:")
    pprint(my_vms)

    ipdb.set_trace()
    # Now try to lookup necessary vport/vm interface using hierarchy
    # Get zone
    stats_zone: vspk.NUZone = stats_dom.zones.get_first(filter='name is "z1"')
    stats_zone.fetch()
    # pprint(f"Zone name: {stats_zone.name}")
    # Get needed subnet
    s11: vspk.NUSubnet = stats_zone.subnets.get_first(filter='name is "s11"')
    s11.fetch()
    # Lookup needed vport info)
    for vport in s11.vports.get():
        vport.fetch()
        vminf = vport.vm_interfaces.get_first(filter='IPAddress is "10.1.1.235"')
        # vminf = vport.vm_interfaces.get_first()
        if vminf:
            print(f"vport location of vm with ip {vminf.ip_address} in VSD domain:")
            print(f"Domain name: {vminf.domain_name} / {vminf.domain_id}")
            print(f"Zone name: {vminf.zone_name} / {vminf.zone_id}")
            print(f"Network name: {vminf.network_name} / {vminf.parent_id}")
            pprint(vminf.to_dict())  # If you want to work with data in more flexible way

    # STATISTICS policy
    ipdb.set_trace()
    # Statistics policy creation
    # stpol_s11 = vspk.NUStatisticsPolicy()
    # stpol_s11.description = "My nice policy."
    # stpol_s11.data_collection_frequency = 5
    # stpol_s11.name = "Stats_policy_for_s11"
    # stpol_s11.parent_types
    # stats_sub_s11.create_child(stpol_s11)

    # Let see stats policy applied on the subnet
    print("Get configures statistic collection policy object:")
    configured_sub_s11_spol: vspk.NUStatisticsPolicy = s11.statistics_policies.get_first()
    pprint("Object repr:")
    pprint(configured_sub_s11_spol)
    pprint("Permanent resource URL:")
    pprint(configured_sub_s11_spol.get_resource_url())
    pprint("Name and REST name:")
    pprint(configured_sub_s11_spol.name)
    pprint(configured_sub_s11_spol.rest_name)
    pprint("Or just print all attrs as dict")
    pprint(configured_sub_s11_spol.to_dict())

    # Now copy policy and apply it on the s21 and let's say I want to apply the same
    ipdb.set_trace()
    new_s21_spol: vspk.NUStatisticsPolicy = configured_sub_s11_spol.copy()
    # if you will try to create the same policy again you should get somehting like
    # ** *bambou.exceptions.BambouHTTPError: [HTTP 409(Conflict)][{'property': '', 'descriptions': [
    #    {'title': 'Duplicate statistics policy', 'description': 'Statistics policy already exists'}]}]
    new_s21_spol.name = "Copy of s11 spol for s12"
    s21 = stats_dom.subnets.get_first(filter="name == 's21'")
    # Check if policy exists and apply new one if nothing there
    ret_val = None
    s21_spol = s21.statistics_policies.get_first()
    if not s21_spol:
        ret_val = s21.create_child(new_s21_spol)  # ret_val is tuple of created object and
        # <bambou.nurest_connection.NURESTConnection object at 0x7fa019f0dc50>
    else:
        print("Overriding existing policy!")
        pprint(s21_spol.delete())
        ret_val = s21.create_child(new_s21_spol)

    # Important! If you will create object with wrong parent you should see error 409
    # How to check correct parent
    pprint(ret_val[0].to_dict()["parentType"])



    # and update policy for s11 and save in VSD policy DB
    configured_sub_s11_spol.data_collection_frequency = 60
    configured_sub_s11_spol.save()

    # See VSD Arch GUI and set it back to 5 sec
    ipdb.set_trace()
    configured_sub_s11_spol.data_collection_frequency = 5
    configured_sub_s11_spol.save()

    ipdb.set_trace()



    # Now extract actual statistics data
    # Calculate time intervals
    t_now = datetime.now(timezone.utc)  # Current time
    t_delta = timedelta(hours=1)  # Interval for stats
    t_start = t_now - t_delta  # Start time
    ts_start = int(t_start.timestamp() // 1)  # Start in seconds
    ts_end = int(t_now.timestamp() // 1)  # End in seconds
    # num_data_points = 60  # Based on default interval


    # Generally this is what possible to collect now from Telenor's VSD for vport
    vport_full_stats_types: List[str] = [
        'BYTES_IN',
        'BYTES_OUT',
        'EGRESS_BYTE_COUNT',
        'EGRESS_PACKET_COUNT',
        'INGRESS_BYTE_COUNT',
        'INGRESS_PACKET_COUNT',
        'PACKETS_DROPPED_BY_RATE_LIMIT',
        'PACKETS_IN',
        'PACKETS_IN_DROPPED',
        'PACKETS_IN_ERROR',
        'PACKETS_OUT',
        'PACKETS_OUT_DROPPED',
        'PACKETS_OUT_ERROR'
    ]
    vport_neeeded_stats_types: List[str] = [
        'BYTES_IN',
        'BYTES_OUT',
        'PACKETS_IN',
        'PACKETS_OUT'
    ]
    ipdb.set_trace()
    # Extract statistics for interested vports
    for vport in [vm["vport"] for vm in my_vms.values()]:
        vport: vspk.NUVPort
        vport_subnet: vspk.NUSubnet = stats_dom.subnets.get_first(filter=f"ID == '{vport.parent_id}'")
        vport.fetch()
        vport_subnet.fetch()
        num_data_points = int((t_delta.total_seconds() / int(configured_sub_s11_spol.data_collection_frequency)) // 1)
        print(f"num_data_points: {num_data_points}")
        p_stat: vspk.nustatistics.NUStatistics = vport.statistics.get_first(query_parameters={
            'startTime': ts_start,
            'endTime': ts_end,
            'numberOfDataPoints': num_data_points,
            'metricTypes': ','.join(vport_neeeded_stats_types)
        })
        #pprint(p_stat.stats_data)
        print("=== Stats data for the for the first 5 datapoints for each index ===")
        pprint([(st_type_type, p_stat.stats_data[st_type_type][0:5]) for st_type_type, st_type_data in p_stat.stats_data.items()])

    # Extract CPU statistics for VSC
    ipdb.set_trace()

    vsd_sysmon: vspk.NUVSP = root.vsps.get_first()
    # For sake of simplicity we will take just first VSC
    vsc_needed_stats_types: List[str] = [
        'CPU',
        'MEMORY',
    ]
    vsc: vspk.NUVSC = vsd_sysmon.vscs.get_first()
    cpu_stats: vspk.nustatistics.NUStatistics = vsc.statistics.get_first(query_parameters={
            'startTime': ts_start,
            'endTime': ts_end,
            'numberOfDataPoints': 60,
            'metricTypes': ','.join(vsc_needed_stats_types)
        })
    # pprint(cpu_stats.stats_data) # Full data
    pprint(slice_stats_data(cpu_stats))

    api_session.requests_session.close()
