import os
import dotenv
import base64
import logging
import time
import re
import pandas
import sys

import swagger_client
from swagger_client import configuration
from swagger_client.rest import ApiException
from pprint import pprint

def build_config():
    # TODO - Cleanup: add params to this call and pass in env_vars
    """ Build Config object from environment variables """
    config = configuration.Configuration()
    config.password = os.getenv('PASSWORD')
    del os.environ['PASSWORD']
    config.username = os.getenv('USER')
    config.host = os.getenv('INSIGHTVM_HOST')
    config.verify_ssl = False

    return config

def find_asset(api_client, identifier ={}):
    """ 
    Look up if the host is in InsightVM

    Returns resources found in InsightVM

    :param obj api_client: Instance of swagger_client.ApiClient
    :param dict identifier: dict of filter field and value values
    :return
    :rtype list[resources]
    """
    api_instance = swagger_client.AssetApi(api_client)

    filters = []
    if os.getenv('FILTERS'):
        # TODO - Make this work if we ever want to validate more than the hostname
        # which we do already because we want to know if the IP is the same as what
        # is in InsightVM as the base image will go up and down
        for f in os.environ['FILTERS']:
            pprint(f)

    else:
        for key in identifier:
            filters.append(
                {
                    'field': key,
                    'operator': 'is-like',
                    'value': identifier[key],
                }
            )

    body = swagger_client.SearchCriteria(match='all', filters=filters)

    try:
        api_response = api_instance.find_assets(body, page=os.environ['PAGE'], size=os.environ['SIZE'])
        logging.debug(api_response.resources)
    except ApiException as e:
        logging.error("Exception when calling AssetApi->find_assets: %s\n" % e)

    return api_response.resources

def get_asset(api_client, asset_id):
    """
    Proxy for AssetAPI.get_asset()

    Returns asset with id provided

    :params obj api_client: Instance of swagger_client.ApiClient
    :params int asset_id: ID of asset looking for
    """
    
    api_instance = swagger_client.AssetApi(api_client)

    try:
        # Asset
        api_response = api_instance.get_asset(asset_id)
    except ApiException as e:
        print("Exception when calling AssetApi->get_asset: %s\n" % e)
    
    return api_response

def add_or_update_asset(api_client, site_id, hostname, ip):
    """
    Update resource with current asset ip

    :param api_client: A valid InsightVM client
    :param site_id: the site the asset does/should be in
    :param ip: the current IP of the asset
    """

    api_instance = swagger_client.AssetApi(api_client)
    
    date = pandas.Timestamp.now('UTC')
    pprint(date)
    
    body = swagger_client.AssetCreate(host_name=hostname, ip=ip, _date="")
    try:
        api_response = api_instance.create_asset(site_id, body=body)
        pprint(api_response)
    except ApiException as e:
        logging.error("Exception when calling AssetApi->create_asset: %s\n" % e)
        sys.exit()

    

def scan_host(api_client, site_id, asset):
    """
    Run security scan on the host

    :param obj api_client: The api_client object as returned by InstightVM
    :param int site_id: the InsightVM site_id where the asset to be scan presides
    :param dict asset: Single asset to scan as returned by InsightVM
    
    Returns scan results
    """

    # TODO - check for a running scan
    # but maybe we don't need this as we checked to see if recently_scanned()
    api_instance = swagger_client.ScanApi(api_client)
    body = swagger_client.AdhocScan() # AdhocScan | The details for the scan. (optional)

    try:
        api_response = api_instance.start_scan(site_id, body=body)
        logging.debug('Response: {}'.format(api_response))
    except ApiException as e:
        logging.error("Exception when calling ScanApi->start_scan: %s\n" % e)

    scan_id = api_response.id
    poll_scan(api_client, scan_id)

    return api_response

def poll_scan(api_client, id =""):
    """
    Polls the scan_id every 5 seconds until scan is complete

    Returns completed data
    """
    status = ""

    logging.debug('Checking status of scan {}'.format(id))
    while status != 'finished':
        api_instance = swagger_client.ScanApi(api_client)

        try:
            api_response = api_instance.get_scan(id)
            status = api_response.status
            logging.info('Scan {} is in {} status'.format(id, status))
            time.sleep(5)
        except ApiException as e:
            print("Exception when calling ScanApi->get_scan: %s\n" % e)

    return api_response

def validate_hostname(asset, search_term):
    """
    Validate the hostname matches what is on the asset

    :param dict asset: The assest as returned by InsightVM
    :param str hostname: The hostname you are looking to match
    """
    matching_assets = []

    for hostname in asset.host_names:
        if re.search(search_term, hostname.name):
            logging.info('Found {} in list of hostnames'.format(hostname))
            matching_assets.append(asset)

    return matching_assets

# TODO - Cleanup: Change default period to 7200 or 2 hours in seconds
def recently_scanned(asset, period =30):
    """
    Validate if asset has been scanned within a period
    
    :param dict asset: An asset as returned by InsightVM
    :param int period: The period in seconds which scan is to be considered recent default 2 hours

    retuns true only if finds scan within period
    """
    for event in asset.history:
        event_time = pandas.Timestamp(event._date)
        current_time = pandas.Timestamp.now('UTC')
        delta = current_time - event_time

        # TODO - Cleanup: check if we need an additional conditional on the if statement
        # event.status != 'finished'
        # This might indicate there is a scan currently running
        if int(delta.total_seconds()) < period and event.type != 'SCAN':
            return True

    return False

def validate_asset(assets, search_term, ip_to_scan):
    """
    Validate the asset returned is in fact the host we are looking for
    :param list asset: assets returned by the SearchAPI call
    :param str search_term: name of host used to search with
    :param str ip_to_scan: ip address of the host desiring to scan
    Returns single asset
    """
    valid_assets = []
    for asset in assets:
        # Asset hostname correct?
        if search_term and not validate_hostname(asset, search_term):
            logging.error("There are not assets that match {}".format(search_term))

        # IP matches vm to test?
        if ip_to_scan and not asset.ip == ip_to_scan:
            logging.info('The address in InsightVM ({}) and the address needing scanned ({}) are not the same'.format(asset.ip, ip_to_scan))
            # TODO - Feature: add_or_update_host if IP doesn't match
            # update_asset(api_client, asset.id, ip)

        valid_assets.append(asset)

    if len(valid_assets) > 1:
        logging.debug('Multiple assets were found and duped our validation.\nBe more specific in your search/n{}'.format(assets))
        exit

    asset = valid_assets[0]
    return asset

def main():
    # TODO - Feature: accept IP address as argument
    ENV_FILE = dotenv.find_dotenv()
    if ENV_FILE:
        dotenv.load_dotenv(ENV_FILE, override=True)

    # TODO - Cleanup: move to const.py file
    host = os.getenv('HOST')
    SITE_ID = os.environ['SITE_ID']
    IP = os.environ['IP']
    config = build_config()

    api_client = swagger_client.ApiClient(config)
 
    assets = find_asset(api_client, {'host-name': host})

    if not assets:
        logging.warning("{} was not found".format(host))
        logging.info("Adding {} to InsigthVM".format(host))
        # sys.exit()
        # TODO - Feature: add host if it doesn't exist
        add_or_update_asset(api_client, SITE_ID, host, IP)

    if assets:
        validated_asset = validate_asset(assets, host, os.getenv('IP'))

    if validated_asset and not recently_scanned(validated_asset):
        api_response = scan_host(api_client, SITE_ID, validated_asset.id)
        scan_results = get_asset(api_client, validated_asset.id)

    if scan_results and scan_results.vulnerabilities.total > 0:
        logging.error('Scan id:{} came back with vulnerabilities: {}'.format(scan_results.id, api_response))

    # TODO - Cleanup: exit gracefully
    print("We Passed!")

if __name__ == '__main__':
    main()