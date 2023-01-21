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

# a function that changes permissions and group for a given path location
def setPermissions(location, group='splunkadm', permissions='755'):
    os.system(f'chmod -R {permissions} {location}')
    os.system(f'chgrp -R {group} {location}')        

# find latest scan ID to be used as checkpoint for the program
def findLatestCp(cpFile):
        # check if id cp already exists and read it - if not, create a new one.
    if os.path.exists(cpFile):
        try:
            # try to read the cp
            with open(cpFile, 'rb') as fn:
                return str(pickle.load(fn))
        except:
            # couldnt read from the cp file. treated as first run.
            return "0"
    else:
        with open(cpFile, 'wb') as fn:
            # dumps the data into the file
            pickle.dump("0", fn)
            return "0"

# generate bearer token with POST request
def gen_token(dns, proxies, verify_ssl, helper):
    # generates the token, the token is valid for 3600 seconds = 1 hour
    c_id = helper.get_arg('client_id')
    c_secret = helper.get_arg('client_secret')
    username = helper.get_arg('username')
    password = helper.get_arg('password')
    # set url for the request
    url = f'{dns}/cxrestapi/auth/identity/connect/token'
    # define body data to send with the request
    data = {
        'grant_type': 'password',
        'scope': 'sast_rest_api',
        'client_id': c_id,
        'client_secret': c_secret,
        'username': username,
        'password': password
        }
    #  make the request and extract the token from the response
    response = requests.post(url, data=data, proxies=proxies, verify=verify_ssl)
    token = json.loads(response.text)['access_token']
    return token

# update checkpoint using a given file name and checkpoint value 
def updateCp(filename,latest_cp):
    # save a checkpoint of latest timestamp fetched from logs
    with open(filename, 'wb') as fn:
        # dumps the data into the file
        pickle.dump(latest_cp, fn)


# compare scan id's; this is used to find new scans to write as new events
def check_ids(id_cp, scan_id):
    if int(id_cp) < int(scan_id):
        id_cp = scan_id
        return id_cp
    else:
        return False
        

# fetch data using a GET request
def getData(dns, token, cp, proxies, verify_ssl, helper, ew):
    # you can add multiple endpoints for multiple get requests using this variable:
    endpoints_list = ['/cxrestapi/sast/scans']
    # iterate through all endpoints and fetch data
    for endpoint in endpoints_list:
        # build the endpoint url
        url = dns + endpoint
        # set headers for the request
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {token}'
            }
        # make the HTTP request
        response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
        # store the response as json data
        resData = json.loads(response.text)
        
        # iterate i value backwards (stop = -1 , step = -1)
        # the response comes in DESC order - from newest to oldest - so to write events from oldest to newest we need to iterate backwards.
        for i in range((len(resData)-1), -1, -1):
            # check for newer id than the id checkpoint
            new_id = check_ids(cp, resData[i]['id'])
            # if new_id == True
            if new_id: 
                # update the cp
                cp = new_id
                # 'Jsonify' the log
                log_data = json.dumps(resData[i])
                # write a new Splunk event
                new_event = helper.new_event(str(log_data), time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
                ew.write_event(new_event)
        # get current time to write as checkpoint for this endpoint request
        time_now = dt.now().strftime('%Y-%m-%d %H:%M:%S')
        
    # return cp to save as id latest checkpoint
    # return multiple checkpoints by adding different cp's to this dict to return as checkpoints
    # !!make sure the order matches the cp_files order!!
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
# this is the main function called by Splunk.
def collect_events(helper, ew):
    # define arguments from user input
    # should verify ssl:
    should_verify = helper.get_arg("verify_ssl")
    # set the domain 
    dns = helper.get_arg('dns')
    # set local path of the add-on files
    local_path = helper.get_arg('local_path')
    
    # set file path for checkpoimt files
    # !!make sure the order matches the returned_checkpoints order!!
    cp_files = {
        "time_cp_filename": f"{local_path}cp_timestamp.pk",
        "id_cp_filename": f"{local_path}cp_id.pk"
        }
    
    # check if proxy is enabled; if True - set proxy parameters; for False send None (default)
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
    
    # load and format time checkpoint
    try:
        latest_time_cp = dt.strptime(findLatestCp(cp_files["time_cp_filename"]),'%Y-%m-%d %H:%M:%S').strftime('%s')
    # if loading failed or time_cp file doesnt exist - initiate as 0 epoch time
    except Exception as e:
        latest_time_cp = dt.strptime(findLatestCp(cp_files["time_cp_filename"]),'%S').strftime('%s')

    # generate bearer token
    token = gen_token(dns, proxies, should_verify, helper)
    
    # get data; write new Splunk events; set an updated checkpoint value (returned from the function)
    updated_cp = (getData(dns, token, latest_id_cp, proxies, should_verify, helper, ew))
    
    # update multiple checkpoints
    for cpfile, cp in zip(cp_files.values(), updated_cp.values()):
        updateCp(cpfile, cp)
    