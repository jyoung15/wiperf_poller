import datetime
import sys
from functools import reduce
from wiperf_poller.helpers.timefunc import time_synced, now_as_msecs

# module import vars
influx_modules = True
import_err = ''

try:
    from influxdb import InfluxDBClient
except ImportError as error:
    influx_modules = False
    import_err = error

# TODO: Error checking if write to Influx fails
# TODO: convert to class

def time_lookup():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")


def influxexporter(localhost, host, port, username, password, database, use_ssl, dict_data, source, file_logger, tag_keys):

    if not influx_modules:
        file_logger.error(" ********* MAJOR ERROR ********** ")
        file_logger.error("One or more Influx Python .are not installed on this system. Influx export failed, exiting")
        file_logger.error("(Execute the following command from the command line of the WLAN Pi: 'sudo pip3 install influxdb')")
        file_logger.error(import_err)
        sys.exit()

    client = InfluxDBClient(host, port, username, password, database, ssl=use_ssl, verify_ssl=False, timeout=100)
    file_logger.debug("Creating InfluxDB API client...")
    file_logger.debug("Remote host: -{}-".format(host))
    file_logger.debug("Port: -{}-".format(port))
    file_logger.debug("Database: -{}-".format(database))
    file_logger.debug("User: -{}-".format(username))

    # this partitions dict_data into two dicts based on tag_keys
    tags, fields = reduce(
        lambda d, i: (d[0] | {i[0]: i[1]}, d[1]) if i[0] in tag_keys else (d[0], d[1] | {i[0]: i[1]}),
        dict_data.items(),
        ({}, {})
    )

    # put results data in to payload to send to Influx
    data_point = {
        "measurement": source,
        "tags": tags | { "host": localhost },
        "fields": fields,
    }

    # if time-source sync'ed, add timestamp
    if time_synced():
        data_point['time'] = dict_data['time']

    # send to Influx
    try:
        if client.write_points([data_point], time_precision='ms'):
            file_logger.info("Data sent to influx OK")
        else:
            file_logger.info("Issue with sending data sent to influx...")
            return False

    except Exception as err:
        file_logger.error("Issue sending data to Influx: {}".format(err))
        return False

    # close the http session
    client.close()

    file_logger.debug("Data structure sent to Influx:")
    file_logger.debug(data_point)

    return True
