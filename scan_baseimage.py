import os
import dotenv
import base64
import logging
import time
import re
import pandas
import sys
import json

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

def get_scanned_assets(api_client, site_id, scan_id):
    """
    Get assets in a site by id
    Returns assets in site

    :param obj api_client: 
    :param int site_id: Site id to retrieve assets from
    :param int scan_id: Scan ID we just completed
    """
    scanned_assets = []

    api_instance = swagger_client.SiteApi(api_client)

    try:
        api_response = api_instance.get_site_assets(site_id)
        logging.debug('Response to get_site_assets is %s' % api_response)
    except ApiException as e:
        print("Exception when calling SiteApi->get_site_assets: %s\n" % e)
 
    for asset in api_response.resources:
        for event in asset.history:
            if event.type == 'SCAN' and event.scan_id == scan_id:
                logging.info('Found asset:{} that was scanned in scan_id:{}'.format(asset.host_name, scan_id))
                scanned_assets.append(asset)
            continue
    return scanned_assets

def add_or_update_asset(api_client, site_id, hostname, ip):
    """
    Update resource with current asset ip

    :param api_client: A valid InsightVM client
    :param site_id: the site the asset does/should be in
    :param ip: the current IP of the asset
    """

    api_instance = swagger_client.AssetApi(api_client)
        
    body = swagger_client.AssetCreate(host_name=hostname, ip=ip, _date="")
    try:
        api_response = api_instance.create_asset(site_id, body=body)
        logging.debug(api_response)
    except ApiException as e:
        logging.error("Exception when calling AssetApi->create_asset: %s\n" % e)
        sys.exit()
    
    return ""

def scan_site(api_client, site_id):
    """
    Scan a site that is defined in InsightVM by site_id
    Returns ...
    :param int site_id: Site ID taken from GUI
    """
    api_instance = swagger_client.ScanApi(api_client)
    
    try:
        api_response = api_instance.start_scan(site_id)
        logging.debug('Results of ScanApi->start_scan of site {} are:\n{}'.format(site_id, api_response))
    except ApiException as e:
        logging.error("Exception when calling ScanApi->start_scan: %s\n" % e)

    poll_scan(api_client, api_response.id)

    return api_response.id

def scan_host(api_client, site_id, asset):
    """
    Run security scan on the host

    :param obj api_client: The api_client object as returned by InstightVM
    :param int site_id: the InsightVM site_id where the asset to be scan presides
    :param dict asset: Single asset to scan as returned by InsightVM
    
    Returns scan results
    """

    # TODO - check for a running scan
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
    
    if api_response.assets == 0:
        logging.error("No assets were scanned in scan {}".format(api_response.id))
        sys.exit()

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
        logging.error('Multiple assets were found and duped our validation.\nBe more specific in your search/n{}'.format(assets))
        sys.exit()

    asset = valid_assets[0]
    return asset

def sort_site_assets(assets):
    """
    Sort assets from a site into two lists: Has vulns and no vulns 
    Returns dictionary with haves and havenots

    :param list assets: list of assets in a Site Scan
    """
    sorted_assets = {
        'haves': [],
        'havenots': [],
    }

    for asset in assets:
        if asset.vulnerabilities.total == 0:
            sorted_assets['havenots'].append(asset.host_name)
        else:
            sorted_assets['haves'].append(asset.host_name)
    
    return sorted_assets

def main():
    ENV_FILE = dotenv.find_dotenv()
    if ENV_FILE:
        dotenv.load_dotenv(ENV_FILE, override=True)

    # TODO - Cleanup: move to const.py file
    SITE_ID = os.environ['SITE_ID']
    config = build_config()

    api_client = swagger_client.ApiClient(config)

    # Scan baseimage site
    scan_id = scan_site(api_client, SITE_ID)

    # Get resources from site
    scanned_assets = get_scanned_assets(api_client, SITE_ID, scan_id)

    sorted_assets = sort_site_assets(scanned_assets)

    print(json.dumps(sorted_assets))

    # Jenkins - Create AMI from successful scans
    # Jenkins - Report Failed scans

if __name__ == '__main__':
    main()