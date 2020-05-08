'''Veracode API endpoints'''

from concurrent.futures import as_completed
import xml.etree.ElementTree as ET
import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from requests_futures.sessions import FuturesSession


BASE_URL = "https://api.veracode.com/appsec"
PAGE_SIZE = 500


def call_url(url):
    '''Call a URL'''
    response = requests.get(url, auth=RequestsAuthPluginVeracodeHMAC())
    if not response.ok:
        print(f"HTTP error: status {response.status_code}")
        if response.status_code == 401:
            print("There was an authentication error when calling the Veracode API.")
            print("Have you checked your credentials? https://help.veracode.com/go/c_api_credentials3")
        raise requests.HTTPError
    return response

def iterate_endpoint(object_key, start_url):
    '''Iterate an endpoint to get all objects'''
    if "?" in start_url:
        suffix_format_string = "&size={}&page={}"
    else:
        suffix_format_string = "?size={}&page={}"
    all_objects = []
    response = call_url(start_url + suffix_format_string.format(PAGE_SIZE, 0))
    objects = response.json()
    all_objects.extend(objects.get("_embedded", {}).get(object_key, []))

    with FuturesSession(max_workers=2) as session:
        session.auth = RequestsAuthPluginVeracodeHMAC()
        futures = [session.get(start_url + suffix_format_string.format(PAGE_SIZE, i)) for i in range(1, objects["page"]["total_pages"])]
        for future in as_completed(futures):
            response = future.result()
            objects = response.json()
            all_objects.extend(objects.get("_embedded", {}).get(object_key, []))

    return all_objects

def get_applications():
    '''Get all applications'''
    start_url = f"{BASE_URL}/v1/applications"
    return iterate_endpoint("applications", start_url)

def get_sandboxes(application_guid):
    '''Get all sandboxes'''
    start_url = f"{BASE_URL}/v1/applications/{application_guid}/sandboxes"
    return iterate_endpoint("sandboxes", start_url)

def get_findings(application_guid, sandbox_guid=None):
    '''Get all findings'''
    start_url = f"{BASE_URL}/v2/applications/{application_guid}/findings?scan_type=static"
    if sandbox_guid is not None:
        start_url = f"{start_url}&context={sandbox_guid}"
    return iterate_endpoint("findings", start_url)

def get_sandbox_list(app_id):
    '''Get sandbox list for an app'''
    sandbox_list_xml = call_url(f"https://analysiscenter.veracode.com/api/5.0/getsandboxlist.do?app_id={app_id}").text
    return ET.fromstring(sandbox_list_xml)
