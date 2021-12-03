import datetime
import sys
from functools import reduce

# module import vars
influx_modules = True
import_err = ''

try:
    import influxdb_client
    from influxdb_client import InfluxDBClient, Point
    from influxdb_client.client.write_api import SYNCHRONOUS
except ImportError as error:
    influx_modules = False
    import_err = error

# TODO: Error checking if write to Influx fails
# TODO: convert to class

def time_lookup():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def influxexporter2(localhost, url, token, bucket, org, dict_data, source, file_logger, tag_keys):

    if not influx_modules:
        file_logger.error(" ********* MAJOR ERROR ********** ")
        file_logger.error("One or more Influx Python .are not installed on this system. Influx export failed, exiting")
        file_logger.error(import_err)
        sys.exit()

    client = InfluxDBClient(url=url, token=token, org=org, timeout=5000)
    file_logger.debug("Creating InfluxDB2 API client...")
    file_logger.debug("URL: -{}-".format(url))
    file_logger.debug("Token: -{}-".format(token))
    file_logger.debug("Org: -{}-".format(org))

    try:
        write_api = client.write_api(write_options=SYNCHRONOUS)
    except Exception as err:
        file_logger.error("Error creating InfluxDB2 API client: {}".format(err))
        return False

    now = time_lookup()

    # construct data structure to send to InFlux
    dict_data.pop("time", None)

    # this partitions dict_data into two dicts based on tag_keys
    tags, fields = reduce(
        lambda d, i: (d[0] | {i[0]: i[1]}, d[1]) if i[0] in tag_keys else (d[0], d[1] | {i[0]: i[1]}),
        dict_data.items(),
        ({}, {})
    )

    data = [
        {
            "measurement": source,
            "time": now,
            "tags": tags | { "host": localhost },
            "fields": fields,
        }
    ]

    # send to Influx
    file_logger.debug("Data structure sent to Influx:")
    file_logger.debug(data)
    try:
        write_api.write(bucket, org, data)
        file_logger.info("Data sent to InfluxDB2. (bucket: {})".format(bucket))
    except Exception as err:
        file_logger.error("Error sending data to InfluxDB2: {}".format(err))
        return False

    return True
