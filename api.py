'''Veracode API endpoints'''

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


BASE_URL = "https://api.veracode.com/appsec"


def call_url(url):
    '''Call a URL'''
    response = requests.get(url, auth=RequestsAuthPluginVeracodeHMAC())
    if not response.ok:
        print(f"HTTP error: status {response.status_code}")
        if response.status_code == 401:
            print("There was an authentication error when calling the Veracode API.")
            print("Have you checked your credentials? https://help.veracode.com/go/c_api_credentials3")
        raise requests.HTTPError
    return response.json()

def iterate_endpoint(object_key, start_url):
    '''Iterate an endpoint to get all objects'''
    all_objects = []
    objects = call_url(start_url)
    all_objects.extend(objects.get("_embedded", {}).get(object_key, []))
    while objects["_links"].get("next"):
        objects = call_url(objects["_links"].get("next"))
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
    page_size = 500
    start_url = f"{BASE_URL}/v2/applications/{application_guid}/findings?size={page_size}&scan_type=static"
    if sandbox_guid is not None:
        start_url = f"{start_url}&context={sandbox_guid}"
    return iterate_endpoint("findings", start_url)
