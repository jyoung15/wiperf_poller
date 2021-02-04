import re
import subprocess
import sys
import time
from wiperf_poller.helpers.os_cmds import IWCONFIG_CMD, IW_CMD, IF_CONFIG_CMD, ROUTE_CMD, IF_DOWN_CMD, IF_UP_CMD, IP_CMD
from wiperf_poller.helpers.networkadapter import NetworkAdapter


class WirelessAdapter(NetworkAdapter):

    '''
    A class to monitor and manipulate the wireless adapter for the WLANPerfAgent
    '''

    def __init__(self, if_name, file_logger):

        self.if_name = if_name
        self.file_logger = file_logger

        self.ssid = ''  # str
        self.bssid = ''  # str
        self.freq = 0.0  # float
        self.center_freq = 0.0  # float
        self.channel = 0  # int
        self.channel_width = 0  # int
        self.tx_bit_rate = 0.0  # float
        self.rx_bit_rate = 0.0  # float
        self.tx_mcs = 0  # int
        self.rx_mcs = 0  # int

        self.signal_level = 0.0  # float
        self.tx_retries = 0  # int

        self.ip_addr = ''  # str
        self.ip_addr_ipv6 = ''  # str
        self.def_gw = ''  # str

        self.file_logger.debug("#### Initialized WirelessAdapter instance... ####")
    

    def channel_lookup(self, freq):

        channels = {
            '2.412': 1,
            '2.417': 2,
            '2.422': 3,
            '2.427': 4,
            '2.432': 5,
            '2.437': 6,
            '2.442': 7,
            '2.447': 8,
            '2.452': 9,
            '2.457': 10,
            '2.462': 11,
            '2.467': 12,
            '2.472': 13,
            '2.484': 14,
            '5.18':  36,
            '5.2':  40,
            '5.22':  44,
            '5.24':  48,
            '5.26':  52,
            '5.28':  56,
            '5.3':   60,
            '5.32':  64,
            '5.5':   100,
            '5.52':  104,
            '5.54':  108,
            '5.56':  112,
            '5.58':  116,
            '5.6':   120,
            '5.62':  124,
            '5.64':  128,
            '5.66':  132,
            '5.68':  136,
            '5.7':   140,
            '5.72':  144,
            '5.745': 149,
            '5.765': 153,
            '5.785': 157,
            '5.805': 161,
            '5.825': 165,
        }

        return channels.get(freq, 'unknown')

    def iwconfig(self):

        ####################################################################
        # Get wireless interface IP address info using the iwconfig command
        ####################################################################
        try:
            cmd = "{} {}".format(IWCONFIG_CMD, self.if_name)
            iwconfig_info = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode()
        except subprocess.CalledProcessError as exc:
            output = exc.output.decode()
            error_descr = "Issue getting interface info using iwconfig command: {}".format(output)

            self.file_logger.error("{}".format(error_descr))
            self.file_logger.error("Returning error...")
            return False

        self.file_logger.debug("Wireless interface config info: {}".format(iwconfig_info))

        # Extract SSID
        if not self.ssid:
            pattern = r'ESSID\:\"(.*?)\"'
            field_name = "ssid"
            extraction = self.field_extractor(
                field_name, pattern, iwconfig_info)
            if extraction:
                self.ssid = extraction

        # Extract BSSID (Note that if WLAN adapter not associated, "Access Point: Not-Associated")
        if not self.bssid:
            pattern = r'Access Point[\=|\:] (..\:..\:..\:..\:..\:..)'
            field_name = "bssid"
            extraction = self.field_extractor(
                field_name, pattern, iwconfig_info)
            if extraction:
                self.bssid = extraction

        # Extract Frequency
        if not self.freq:
            pattern = r'Frequency[\:|\=](\d+\.\d+) '
            field_name = "freq"
            extraction = self.field_extractor(
                field_name, pattern, iwconfig_info)
            if extraction:
                self.freq = float(extraction)

        # lookup channel number from freq
        self.channel = self.channel_lookup(str(self.freq))

        # Extract Tx Bit Rate (e.g. Bit Rate=144.4 Mb/s)
        if not self.tx_bit_rate:
            pattern = r'Bit Rate[\=|\:]([\d|\.]+) '
            field_name = "tx_bit_rate"
            extraction = self.field_extractor(
                field_name, pattern, iwconfig_info)
            if extraction:
                self.tx_bit_rate = float(extraction)

        # Extract Signal Level
        if not self.signal_level:
            pattern = r'Signal level[\=|\:](.+?) dBm'
            field_name = "signal_level"
            extraction = self.field_extractor(
                field_name, pattern, iwconfig_info)
            if extraction:
                self.signal_level = float(extraction)

        # Extract tx retries
        if not self.tx_retries:
            pattern = r'Tx excessive retries[\=|\:](\d+?) '
            field_name = "tx_retries"
            extraction = self.field_extractor(
                field_name, pattern, iwconfig_info)
            if extraction:
                self.tx_retries = int(extraction)

        return True

    def iw_info(self):

         #############################################################################
        # Get wireless interface IP address info using the iw dev wlanX info command
        #############################################################################
        try:
            cmd = "{} {} info".format(IW_CMD, self.if_name)
            iw_info = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode()
        except subprocess.CalledProcessError as exc:
            output = exc.output.decode()
            error_descr = "Issue getting interface info using iw info command: {}".format(
                output)

            self.file_logger.error("{}".format(error_descr))
            self.file_logger.error("Returning error...")
            return False

        self.file_logger.debug("Wireless interface config info (iw dev wlanX info): {}".format(iw_info))

        # Extract channel width
        if not self.channel_width:
            pattern = r'width\: (\d+) MHz'
            field_name = "channel_width"
            extraction = self.field_extractor(
                field_name, pattern, iw_info)
            if extraction:
                self.channel_width = int(extraction)

        # Extract center freq
        if not self.center_freq:
            pattern = r'center1\: (\d+) MHz'
            field_name = "center_freq"
            extraction = self.field_extractor(
                field_name, pattern, iw_info)
            if extraction:
                self.center_freq = float(extraction)/1000

        # Extract frequency
        if not self.freq:
            pattern = r'channel \d+ \((\d+) MHz\)'
            field_name = "freq"
            extraction = self.field_extractor(
                field_name, pattern, iw_info)
            if extraction:
                self.freq = float(extraction)/1000

        return True

    def iw_link(self):

         #############################################################################
        # Get wireless interface IP address info using the iw dev wlanX link command
        #############################################################################
        try:
            cmd = "{} {} link".format(IW_CMD, self.if_name)
            iw_link = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode()
        except subprocess.CalledProcessError as exc:
            output = exc.output.decode()
            error_descr = "Issue getting interface info using iw link command: {}".format(output)

            self.file_logger.error("{}".format(error_descr))
            self.file_logger.error("Returning error...")
            return False

        self.file_logger.debug("Wireless interface config info (iw dev wlanX link): {}".format(iw_link))

        # Extract channel width
        if not self.channel_width:
            pattern = r' (\d+)MHZ '
            field_name = "channel_width"
            extraction = self.field_extractor(
                field_name, pattern, iw_link)
            if extraction:
                self.channel_width = int(extraction)

        # Extract Signal Level
        if not self.signal_level:
            pattern = r'signal: (\-\d+) dBm'
            field_name = "signal_level"
            extraction = self.field_extractor(
                field_name, pattern, iw_link)
            if extraction:
                self.signal_level = float(extraction)

        # Extract Tx Bit Rate (e.g. tx bitrate: 150.0 MBit/s)
        if not self.tx_bit_rate:
            pattern = r'tx bitrate: ([\d|\.]+) MBit/s'
            field_name = "tx_bit_rate"
            extraction = self.field_extractor(
                field_name, pattern, iw_link)
            if extraction:
                self.tx_bit_rate = float(extraction)

        # Extract MCS value (e.g. tx bitrate: 150.0 MBit/s MCS 7 40MHz short GI)
        if not self.tx_mcs:
            pattern = r' MCS (\d+) '
            field_name = "tx_mcs"
            extraction = self.field_extractor(
                field_name, pattern, iw_link)
            if extraction:
                self.tx_mcs = int(extraction)

        return True

    def iw_station(self):

         #####################################################################################
        # Get wireless interface IP address info using the iw dev wlanX station dump command
        ######################################################################################
        try:
            cmd = "{} {} station dump".format(IW_CMD, self.if_name)
            iw_station = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode()
        except subprocess.CalledProcessError as exc:
            output = exc.output.decode()
            error_descr = "Issue getting interface info using iw station command: {}".format(output)

            self.file_logger.error("{}".format(error_descr))
            self.file_logger.error("Returning error...")
            return False

        self.file_logger.debug("Wireless interface config info (iw dev wlanX station dump): {}".format(iw_station))

        # Extract channel width
        if not self.channel_width:
            pattern = r'rx bitrate\:.*?(\d+)MHz'
            field_name = "channel_width"
            extraction = self.field_extractor(field_name, pattern, iw_station)
            if extraction:
                self.channel_width = int(extraction)

        # Extract Tx Bit Rate (e.g. tx bitrate:     72.2 MBit/s MCS 7 short GI)
        if not self.tx_bit_rate:
            pattern = r'tx bitrate\:.*?([\d|\.]+) MBit/s'
            field_name = "tx_bit_rate"
            extraction = self.field_extractor(field_name, pattern, iw_station)
            if extraction:
                self.tx_bit_rate = float(extraction)

        # Extract Rx Bit Rate (e.g. rx bitrate:     121.5 MBit/s MCS 6 40MHz)
        if not self.rx_bit_rate:
            pattern = r'rx bitrate\:.*?([\d|\.]+) MBit/s'
            field_name = "rx_bit_rate"
            extraction = self.field_extractor(field_name, pattern, iw_station)
            if extraction:
                self.rx_bit_rate = float(extraction)

        # Extract Tx MCS value (e.g. tx bitrate:     72.2 MBit/s MCS 7 short GI)
        if not self.tx_mcs:
            pattern = r'tx bitrate\:.*?MCS (\d+) '
            field_name = "tx_mcs"
            extraction = self.field_extractor(field_name, pattern, iw_station)
            if extraction:
                self.tx_mcs = int(extraction)

        # Extract Rx MCS value (e.g. rx bitrate:     121.5 MBit/s MCS 6 40MHz)
        if not self.rx_mcs:
            pattern = r'rx bitrate\:.*?MCS (\d+)'
            field_name = "rx_mcs"
            extraction = self.field_extractor(field_name, pattern, iw_station)
            if extraction:
                self.rx_mcs = int(extraction)

        return True

    def get_wireless_info(self):
        '''
        This function will look for various pieces of information from the
        wireless adapter which will be bundled with the speedtest results.

        It is a wrapper around the following commands, so will no doubt break at
        some stage:
            - iwconfig wlan0
            - iw dev wlan0 link
            - iw dev wlan0 info
            - iw dev wlan0 station dump

        The information provided may vary slightly between adapters and drivers, so is
        not guaranteed to be available in sall instances.

        We cannot assume all of the parameters below are available (sometimes
        they are missing for some reason until device is rebooted). Only
        provide info if they are available, otherwise replace with "NA"

        '''

        self.file_logger.debug("Getting wireless adapter info...")

        # get info using iwconfig cmd
        if self.iwconfig() == False:
            return False

        # get info using iw info
        if self.iw_info() == False:
            return False

        # get info using iw link
        if self.iw_link() == False:
            return False

        # get info using iw station
        if self.iw_station() == False:
            return False

        # get the values extracted and return in a list
        results_list = [self.ssid, self.bssid, self.freq, self.tx_bit_rate,
                        self.signal_level, self.tx_retries, self.channel]

        self.file_logger.debug("Results list: {}".format(results_list))

        return results_list


    def get_ssid(self):
        return self.ssid

    def get_bssid(self):
        return self.bssid

    def get_freq(self):
        return self.freq

    def get_center_freq(self):
        return self.center_freq

    def get_channel(self):
        return self.channel

    def get_channel_width(self):
        return self.channel_width

    def get_tx_bit_rate(self):
        return self.tx_bit_rate

    def get_rx_bit_rate(self):
        return self.rx_bit_rate

    def get_tx_mcs(self):
        return self.tx_mcs

    def get_rx_mcs(self):
        return self.rx_mcs

    def get_signal_level(self):
        return self.signal_level

    def get_tx_retries(self):
        return self.tx_retries
    
    def get_ipaddr_ipv4(self):
        return self.ip_addr
    
    def get_ipaddr_ipv6(self):
        return self.ip_addr_ipv6
