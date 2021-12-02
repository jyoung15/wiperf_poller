from socket import gethostbyname_ex
import subprocess
import re
import sys
from wiperf_poller.helpers.os_cmds import IP_CMD

def is_ipv4(ip_address):
    """
    Check if an address is in ivp4 format
    """
    return re.search(r'\d+.\d+.\d+.\d+', ip_address)


def is_ipv6(ip_address):
    """
    Check if an address is in ivp6 format
    """
    return re.search(r'[abcdf0123456789]+:', ip_address)


def resolve_name(hostname, file_logger):
    """
    if hostname passed, DNS lookup, otherwise, return unchanged IP address
    always returns a list (empty if error)
    """
    if is_ipv4(hostname) or is_ipv6(hostname):
        return [hostname]

    try:
        # hostname might return multiple IPs (DNS load-balancing, etc)
        ip_addresses = gethostbyname_ex(hostname)[2]
        file_logger.info("  DNS hostname lookup : {}. Result: {}".format(hostname, ip_addresses))
        return ip_addresses
    except Exception as ex:
        file_logger.error("  Issue looking up host {} (DNS Issue?): {}".format(hostname, ex))
        return []


def get_test_traffic_interface(config_vars, file_logger):
    """
    Return the interface name used for testing traffic, based on the probe mode
    """
    probe_mode = config_vars['probe_mode']

    if probe_mode == "wireless": return config_vars['wlan_if']
    if probe_mode == "ethernet": return config_vars['eth_if']

    file_logger.error("  Unknown probe mode: {} (exiting)".format(probe_mode))
    sys.exit()


def get_first_ipv4_route_to_dest(ip_address, file_logger, ip_ver=''):
    """
    Check the routes to a specific ip destination & return first entry
    """

    ip_addresses = resolve_name(ip_address, file_logger)

    return_val = []
    for ip_address in ip_addresses:

        # get specific route details of path that will be used by kernel (cannot be used to modify routing entry)
        ip_route_cmd = "{} {} route get ".format(IP_CMD, ip_ver) + ip_address + " | head -n 1"

        try:
            route_detail = subprocess.check_output(ip_route_cmd, stderr=subprocess.STDOUT, shell=True).decode()
            file_logger.info("  Checked interface route to : {}. Result: {}".format(ip_address, route_detail.strip()))
            return_val.append(route_detail.strip())
        except subprocess.CalledProcessError as exc:
            output = exc.output.decode()
            file_logger.error("  Issue looking up route (route cmd syntax?): {} (command used: {})".format(str(output), ip_route_cmd))
            return []
    return return_val

def get_first_ipv6_route_to_dest(ip_address, file_logger):
    """
    Check the routes to a specific ipv6 destination & return first entry
    """
    return get_first_ipv4_route_to_dest(ip_address, file_logger, '-6')


def get_route_used_to_dest(ip_address, file_logger):

    ip_addresses = resolve_name(ip_address, file_logger)

    return_val = []
    for ip_address in ip_addresses:

        # get first raw routing entry, otherwise show route that will actually be chosen by kernel
        ip_route_cmd = "{} route show to match ".format(IP_CMD) + ip_address + " | head -n 1"

        try:
            route_detail = subprocess.check_output(ip_route_cmd, stderr=subprocess.STDOUT, shell=True).decode()
            file_logger.info("  Checked interface route to : {}. Result: {}".format(ip_address, route_detail.strip()))
            return_val.append(route_detail.strip())
        except subprocess.CalledProcessError as exc:
            output = exc.output.decode()
            file_logger.error("  Issue looking up route (route cmd syntax?): {} (command used: {})".format(str(output), ip_route_cmd))
            return []
    return return_val


def check_correct_ipv4_mgt_interface(mgt_ip, mgt_interface, file_logger):
    """
    Check that the correct interface is being used for mgt traffic for a specific IP v4 target
    """
    file_logger.info("  Checking we will send mgt traffic over configured interface '{}' mode.".format(mgt_interface))
    routes_to_dest = get_first_ipv4_route_to_dest(mgt_ip, file_logger)

    return_val = True
    for route_to_dest in routes_to_dest:

        if mgt_interface in route_to_dest:
            file_logger.info("  Mgt interface route looks good.")
            return_val &= True
        else:
            file_logger.info("  Mgt interface will be routed over wrong interface: {}".format(route_to_dest))
            return_val &= False
    return return_val


def check_correct_ipv6_mgt_interface(mgt_ip, mgt_interface, file_logger):
    """
    Check that the correct interface is being used for mgt traffic for a specific IP v6 target
    """
    return check_correct_ipv4_mgt_interface(mgt_ip, mgt_interface, file_logger)


def check_correct_mgt_interface(mgt_host, mgt_interface, file_logger):
    """
    This function checks if the correct interface is being used for mgt traffic
    """

    # figure out mgt_ip (in case hostname passed)
    mgt_ips = resolve_name(mgt_host, file_logger)

    return_val = True
    for mgt_ip in mgt_ips:

        if is_ipv4(mgt_ip):
            return_val &= check_correct_ipv4_mgt_interface(mgt_ip, mgt_interface, file_logger)
        elif is_ipv6(mgt_ip):
            return_val &= check_correct_ipv6_mgt_interface(mgt_ip, mgt_interface, file_logger)
        else:
            file_logger.error("  Unknown mgt IP address format '{}' mode.".format(mgt_ip))
    return return_val



def check_correct_mode_interface(ip_address, config_vars, file_logger):
    """
    This function checks whether we use the expected interface for testing traffic,
    depending on which mode the probe is operating.

    Modes:
        ethernet : we expect to get to the Internet over the eth interface (usually eth0)
        wireless : we expect to get to the Internet over the WLAN interface (usually wlan0)

    args:
        ip_address: IP address of target out on the test domain (usually the Internet)
        config_vars: dict of all config vars
        file_logger: file logger object so that we can log operations
    """

    # check test traffic will go via correct interface depending on mode
    test_traffic_interface= get_test_traffic_interface(config_vars, file_logger)

    # get i/f name for route
    routes_to_dest = get_first_ipv4_route_to_dest(ip_address, file_logger)

    return_val = True
    for route_to_dest in routes_to_dest:

        if test_traffic_interface in route_to_dest:
            return_val &= True
        else:
            return_val &= False
    return return_val


def inject_default_route(ip_address, config_vars, file_logger):

    """
    This function will attempt to inject a default route to attempt correct
    routing issues caused by path cost if the ethernet interface is up and
    is preferred to the WLAN interface.

    Scenario:

    This function is called as it has been determined that the route used for
    testing traffic is not the required interface. An attempt will be made to
    fix the routing by increasing the metric of the exsiting default route and
    then adding a new deault route that uses the interface required for testing
    (which will have a lower metrc and be used in preference to the original
    default route)

    Process flow:

    1. Get route to the destination IP address
    2. If it's not a default route entry, we can't fix this, exit
    3. Delete the existing default route
    4. Re-add the same default route with an metric increased to 500
    5. Figure out the interface over which testing traffic should be sent
    6. Add a new default route entry for that interface
    """

    # get the default route to our destination
    routes_to_dest = get_route_used_to_dest(ip_address, file_logger)

    return_val = True
    for route_to_dest in routes_to_dest:

        # This fix relies on the retrieved route being a default route in the
        # format: default via 192.168.0.1 dev eth0

        if not "default" in route_to_dest:
            # this isn't a default route, so we can't fix this
            file_logger.error('  [Route Injection] Route is not a default route entry...cannot resove this routing issue: {}'.format(route_to_dest))
            return_val &= False
            continue

        # delete and re-add route with a new metric
        try:
            del_route_cmd = "{} route del ".format(IP_CMD) + route_to_dest
            subprocess.run(del_route_cmd, shell=True)
            file_logger.info("  [Route Injection] Deleting route: {}".format(route_to_dest))
        except subprocess.CalledProcessError as proc_exc:
            file_logger.error('  [Route Injection] Route deletion failed!: {}'.format(proc_exc))
            return_val &= False
            continue

        try:
            modified_route = route_to_dest + " metric 500"
            add_route_cmd = "{} route replace  ".format(IP_CMD) + modified_route
            subprocess.run(add_route_cmd, shell=True)
            file_logger.info("  [Route Injection] Re-adding deleted route with new metric: {}".format(modified_route))
        except subprocess.CalledProcessError as proc_exc:
            file_logger.error('  [Route Injection] Route addition failed!')
            return_val &= False
            continue

        # figure out what our required interface is for testing traffic
        probe_mode = config_vars['probe_mode']
        file_logger.info("  [Route Injection] Checking probe mode: '{}' ".format(probe_mode))
        test_traffic_interface= get_test_traffic_interface(config_vars, file_logger)

        # inject a new route with the required interface
        try:
            new_route = "default dev {}".format(test_traffic_interface)
            add_route_cmd = "{} route replace  ".format(IP_CMD) + new_route
            subprocess.run(add_route_cmd, shell=True)
            file_logger.info("  [Route Injection] Adding new route: {}".format(new_route))
        except subprocess.CalledProcessError as proc_exc:
            file_logger.error('  [Route Injection] Route addition failed!')
            return_val &= False
            continue

        file_logger.info("  [Route Injection] Route injection complete")
        return_val &= True
    return return_val


def _inject_static_route(ip_address, req_interface, traffic_type, file_logger, ip_ver=""):

    """
    This function will attempt to inject a static route to correct
    routing issues for specific targets that will not be reached via
    the intended interface without the addition of this route.

    A static route will be inserted in to the probe route table to send
    matched traffic over a specific interface
    """

    file_logger.info("  [Route Injection] Attempting static route insertion to fix routing issue")
    try:
        gateway_check_cmd = '{} route list exact default dev {}'.format(IP_CMD, req_interface)
        gateway_line = subprocess.check_output(gateway_check_cmd, stderr=subprocess.STDOUT, shell=True).decode().strip()
        file_logger.debug("  [Route Injection] checking for default gateway IP: {}".format(gateway_line))
        if match := re.search(r'^default via (?P<gw>\d+\.\d+\.\d+\.\d+)', gateway_line):
            default_gw = match['gw']
            file_logger.debug('  [Route Injection] default gateway IP found: {}'.format(default_gw))
            new_route = "{} via {} dev {}".format(ip_address, default_gw, req_interface)
        else:
            new_route = "{} dev {}".format(ip_address, req_interface)
        add_route_cmd = "{} {} route replace  ".format(IP_CMD, ip_ver) + new_route
        file_logger.debug("  [Route Injection] {}".format(add_route_cmd))
        subprocess.run(add_route_cmd, shell=True)
        file_logger.info("  [Route Injection] Adding new {} traffic route: {}".format(traffic_type, new_route))
    except subprocess.CalledProcessError as proc_exc:
        output = proc_exc.output.decode()
        file_logger.error('  [Route Injection] Route addition ({})failed! ({})'.format(traffic_type, output))
        return False

    file_logger.info("  [Route Injection] Route injection ({})complete".format(traffic_type))
    return True


def _inject_ipv6_static_route(ip_address, req_interface, traffic_type, file_logger):
    # use ipv4 function, but pass in -6 version number
    # see https://www.tldp.org/HOWTO/Linux+IPv6-HOWTO/ch07s04.html
    return _inject_static_route(ip_address, req_interface, traffic_type, file_logger, "-6")


def inject_mgt_static_route(ip_address, config_vars, file_logger):
    """
    Inject a static route to correct routing issue for mgt traffic
    """
    # figure out mgt_ip (in case hostname passed)
    mgt_ips = resolve_name(ip_address, file_logger)

    return_val = True
    for mgt_ip in mgt_ips:

        mgt_interface = config_vars['mgt_if']

        if is_ipv6(mgt_ip):
            return_val &= _inject_ipv6_static_route(mgt_ip, mgt_interface, "mgt", file_logger)
        else:
            return_val &= _inject_static_route(mgt_ip, mgt_interface, "mgt", file_logger)
    return return_val


def inject_test_traffic_static_route(ip_address, config_vars, file_logger):
    """
    Inject a static route to correct routing issue for specific test traffic
    destination (e.g. iperf)
    """
    probe_mode = config_vars['probe_mode']
    file_logger.info("  [Route Injection] Checking probe mode: '{}' ".format(probe_mode))
    test_traffic_interface= get_test_traffic_interface(config_vars, file_logger)

    # if route injection works, check that route is now over correct interface
    if _inject_static_route(ip_address, test_traffic_interface, "test traffic", file_logger):

       if check_correct_mode_interface(ip_address, config_vars, file_logger):

           return True

    # Something went wrong...
    return False
