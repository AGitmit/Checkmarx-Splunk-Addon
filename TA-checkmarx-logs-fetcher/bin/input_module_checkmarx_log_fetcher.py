# encoding = utf-8

import requests
import os
import sys
import time
import datetime
from datetime import timedelta
from datetime import datetime as dt
import json
import re
import pickle

def setPermissions(location, group='splunkadm', permissions='755'):
    os.system(f'chmod -R {permissions} {location}')
    os.system(f'chgrp -R {group} {location}')        

# find latest scan ID to be used as checkpoint for the program
def findLatestCp(cpFile):
    if os.path.exists(cpFile):
        try:
            with open(cpFile, 'rb') as fn:
                return str(pickle.load(fn))
        except:
            return "0"
    else:
        with open(cpFile, 'wb') as fn:
            pickle.dump("0", fn)
            return "0"

def gen_token(dns, proxies, verify_ssl, helper):
    c_id = helper.get_arg('client_id')
    c_secret = helper.get_arg('client_secret')
    username = helper.get_arg('username')
    password = helper.get_arg('password')
    url = f'{dns}/cxrestapi/auth/identity/connect/token'
    data = {
        'grant_type': 'password',
        'scope': 'sast_rest_api',
        'client_id': c_id,
        'client_secret': c_secret,
        'username': username,
        'password': password
        }
    response = requests.post(url, data=data, proxies=proxies, verify=verify_ssl)
    token = json.loads(response.text)['access_token']
    return token

# update checkpoint using a given file name and checkpoint value 
def updateCp(filename,latest_cp):
    with open(filename, 'wb') as fn:
        pickle.dump(latest_cp, fn)


# compare scan id's; this is used to find new scans to write as new events
def check_ids(id_cp, scan_id):
    if int(id_cp) < int(scan_id):
        id_cp = scan_id
        return id_cp
    else:
        return False
        

def getData(dns, token, cp, proxies, verify_ssl, helper, ew):
    endpoints_list = ['/cxrestapi/sast/scans']
    for endpoint in endpoints_list:
        url = dns + endpoint
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {token}'
            }
        response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
        resData = json.loads(response.text)
        
        # iterate i value backwards (stop = -1 , step = -1)
        # the response comes in DESC order - from newest to oldest - so to write events from oldest to newest we need to iterate backwards.
        for i in range((len(resData)-1), -1, -1):
            new_id = check_ids(cp, resData[i]['id'])
            if new_id: 
                cp = new_id
                log_data = json.dumps(resData[i])
                # write a new Splunk event
                new_event = helper.new_event(str(log_data), time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
                ew.write_event(new_event)
        # get current time to write as checkpoint for this endpoint request
        time_now = dt.now().strftime('%Y-%m-%d %H:%M:%S')
        
    # !! make sure the order matches the cp_files order !!
    returned_checkpoints = {
        "time_cp": time_now,
        "id_cp":cp,
        }
        
    return returned_checkpoints
   
# this function is mandatory by Splunk - DO NOT delete it.
def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # client_id = definition.parameters.get('client_id', None)
    # client_secret = definition.parameters.get('client_secret', None)
    # username = definition.parameters.get('username', None)
    # password = definition.parameters.get('password', None)
    # dns = definition.parameters.get('dns', None)
    pass

# this function is mandatory by Splunk - DO NOT delete it.
def collect_events(helper, ew):
    should_verify = helper.get_arg("verify_ssl")
    dns = helper.get_arg('dns')
    local_path = helper.get_arg('local_path')
    
    # !!make sure the order matches the returned_checkpoints order!!
    cp_files = {
        "time_cp_filename": f"{local_path}cp_timestamp.pk",
        "id_cp_filename": f"{local_path}cp_id.pk"
        }
    
    proxies = {}
    try:
        proxy_settings = helper.get_proxy()
        
        if proxy_settings['proxy_url']: 
            proxies['https'] = f"http://{proxy_settings['proxy_url']}:{proxy_settings['proxy_port']}"
        else:
            proxies = None

    except:
        proxies = None
    
    # verify permissions
    setPermissions(local_path)
    
    # set checkpoint variables
    latest_id_cp = findLatestCp(cp_files["id_cp_filename"])
    
    try:
        latest_time_cp = dt.strptime(findLatestCp(cp_files["time_cp_filename"]),'%Y-%m-%d %H:%M:%S').strftime('%s')
    except Exception as e:
        latest_time_cp = dt.strptime(findLatestCp(cp_files["time_cp_filename"]),'%S').strftime('%s')

    token = gen_token(dns, proxies, should_verify, helper)
    
    # get data; write new Splunk events; set an updated checkpoint value (returned from the function)
    updated_cp = (getData(dns, token, latest_id_cp, proxies, should_verify, helper, ew))
    
    # update multiple checkpoints
    for cpfile, cp in zip(cp_files.values(), updated_cp.values()):
        updateCp(cpfile, cp)
    
