""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
import requests
from time import sleep
import arrow

try:
    from integrations.crudhub import trigger_ingest_playbook
except:
    # ignore. lower FSR version
    pass

logger = get_logger('blocklist_de-feed')

SERVICE_MAPPING = {
    "All": "all",
    "SSH": 'ssh',
    "Mail": 'mail',
    "Apache": 'apache',
    "IMAP": 'imap',
    "FTP": 'ftp',
    "SIP": 'sip',
    "VOIP": "voip",  # not added
    "Bots": 'bots',
    "IRC Bot": "ircbot",
    "Strong IPs": 'strongips',
    "Brute Force Login": 'bruteforcelogin'
}
MAX_ATTEMPTS = 3


def validate_response(response):
    if response.ok:
        result = response.text
        if 'text/plain' in response.headers["Content-Type"] and 'error' not in result.lower():
            return result
    logger.exception('Fail To request API {0} response is : {1}'.
                     format(str(response.url), str(response.content)))
    raise ConnectorError(
        'Fail To request API {0} response is : {1}'.format(str(response.url), str(response.content)))


def make_request(config, url, parameters=None, method='GET'):
    verify_ssl = config.get('verify_ssl')
    attempt = 1
    status_code = 404
    api_response = None
    while attempt <= MAX_ATTEMPTS:
        try:
            api_response = requests.request(method=method, url=url, params=parameters, verify=verify_ssl, timeout=90)
            if api_response.ok or api_response.status_code == status_code:
                return api_response
        except Exception as e:
            logger.exception(e)
            if 'read timed out' in str(e).lower():
                attempt += 1
                sleep(1)
                continue
            raise ConnectorError(e)
        attempt += 1
        sleep(1)
    return api_response


def convert_to_unixtime(last_added_time):
    try:
        date_time = arrow.get(last_added_time).strftime("%Y-%m-%dT%H:%M:%S")
        return date_time
    except Exception as Err:
        logger.exception('{0}'.format(str(Err)))
        raise ConnectorError('{0}'.format(str(Err)))


def fetch_indicators(config, params=None, **kwargs):
    try:

        service = params.get('service', 'strongips')
        output_mode = params.get('output_mode')
        last_added_time = params.get('time', None)
        create_pb_id = params.get("create_pb_id")
        query_param = {}
        if last_added_time:
            new_time = convert_to_unixtime(last_added_time)
            url = 'https://api.blocklist.de/getlast.php?time={last_added_time}'.format(
                last_added_time=new_time) + '&service={service}'.format(service=SERVICE_MAPPING.get(service))
        else:
            server_url = config.get('server_url')
            url = server_url.strip('/') + '/lists/{service}.txt'.format(service=SERVICE_MAPPING.get(service))
        api_response = make_request(config, url, parameters=query_param)
        res = validate_response(api_response)
        ips = list(map(lambda x: x.strip(''), res.strip().split("\n"))) if res else []
        if output_mode == 'Create as Feed Records in FortiSOAR':
            trigger_ingest_playbook(ips, create_pb_id, parent_env=kwargs.get('env', {}), batch_size=1000)
            return 'Successfully triggered playbooks to create feed records'
        else:
            return ips
    except Exception as e:
        raise ConnectorError(str(e))


def _check_health(config):
    try:
        params = {'service': 'Bots'}
        res = fetch_indicators(config, params=params)
        if res:
            return True
    except Exception as e:
        raise ConnectorError(str(e))


operations = {
    'fetch_indicators': fetch_indicators
}
