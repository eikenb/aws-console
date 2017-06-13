#!/usr/bin/env python

"""
Author: John Eikenberry <jae@zhar.net>
License: CC0 <http://creativecommons.org/publicdomain/zero/1.0/>

Python 2 and Python 3 compatible.

Requires base python install + boto + requests module.
http://docs.pythonboto.org/
http://python-requests.org
"""

from __future__ import print_function

import argparse
import json
import os
import requests
import webbrowser
import time
import boto.iam
from boto.sts import STSConnection

import urllib
# Python 3 compatibility (python 3 has urlencode in parse sub-module)
urlencode = getattr(urllib, 'parse', urllib).urlencode

# Requires this role to exist.
ROLE_NAME = "StsConsoleAccess"

def parseArgs():
    """ Do the argument parsing and return arg dict.
    """
    browser_name = webbrowser.get().name
    parser = argparse.ArgumentParser(description="Open " +
            browser_name + " to AWS console of account based on credentials." +
            " Credentials should be stored in standard environment variables.")
    parser.add_argument('-i', '--incognito', action='store_true',
            help='open browser in incognito/private mode.')
    parser.add_argument('-r', '--region', action='store', default='us-west-2',
            help='region for region-specific commands (us-west-2)')
    parser.add_argument('-c', '--create-role', action='store_true',
            help="create required role in account if it doesn't exist")
    parser.add_argument('-n', '--role-name', action='store',
            default=ROLE_NAME,
            help="name of required role to create/use (" + ROLE_NAME + ")")
    parser.add_argument('-t', '--temp-role', action='store_true',
            help="Create role only for this connection, then delete it.")

    return parser.parse_args()

_arg_cache = []
def getArgs():
    """ Return ArgumentParser Namespace instance for parsed arguments.
    """
    cache = _arg_cache
    if not cache:
        cache.append(parseArgs())
    return cache[0]

_conn_cache = []
def iamConn():
    """ Return boto IAM connection object. Cache to limit redundant calls.
    """
    cache = _conn_cache
    if not cache:
        cache.append(boto.iam.connect_to_region(getArgs().region))
    return cache[0]

def accountId():
    """ Return account-id based on credentials in environment.
    """
    # save the lookup if we set the account to the environment
    if "AWS_ACCOUNT_ID" in os.environ:
        return os.environ["AWS_ACCOUNT_ID"]
    conn = iamConn()
    funcs = [
        lambda: conn.get_user().get('get_user_response')\
            .get('get_user_result').get('user').get('arn'),
        lambda: conn.list_roles(max_items=1).get('list_roles_response')\
            .get('list_roles_result').get('roles')[0].get('arn'),
    ]
    for func in funcs:
        try:
            arn = func()
            break
        except (boto.exception.BotoServerError, IndexError):
            pass
    return arn.split(':')[4]

def hasRole():
    """ Does AWS account have the role for STS/assume-role?
    """
    conn = iamConn()
    try:
        conn.get_role(getArgs().role_name)
        return True
    except boto.exception.BotoServerError:
        return False

# json strings used in createRole()
admin_policy = """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}"""
assume_role_policy = """
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "",
      "Effect": "Allow",
      "Principal": {{
        "AWS": "arn:aws:iam::{0}:root"
      }},
      "Action": "sts:AssumeRole"
    }}
  ]
}}"""

def createRole():
    """ Create STS/assume-role policy and role.
    """
    if hasRole(): return False
    conn = iamConn()
    role = getArgs().role_name
    conn.create_role(role, assume_role_policy.strip().format(accountId()))
    conn.put_role_policy(role, 'Admin', admin_policy.strip())
    print("Role created:", role)
    return True

def removeRole():
    """ Removes STS/assume-role role.
    """
    if not hasRole(): return False
    conn = iamConn()
    role = getArgs().role_name
    conn.delete_role_policy(role, 'Admin')
    conn.delete_role(role)
    print("Role deleted:", role)
    return True

def openConsole():
    """ Get STS token and open AWS console.
    """
    # Create an ARN out of the information provided by the user.
    role_arn = "arn:aws:iam::" + accountId() + ":role/" + getArgs().role_name

    # Connect to AWS STS and then call AssumeRole.
    # Returns temporary security credentials.
    sts_connection = STSConnection()
    assumed_role_object = sts_connection.assume_role(
        role_arn=role_arn,
        role_session_name="AssumeRoleSession"
    )

    # Format resulting credentials into a JSON block.
    tmp_creds = {
        "sessionId": assumed_role_object.credentials.access_key,
        "sessionKey": assumed_role_object.credentials.secret_key,
        "sessionToken": assumed_role_object.credentials.session_token,
    }
    json_temp_credentials = json.dumps(tmp_creds)

    # Make a request to the AWS federation endpoint to get a sign-in
    # token, passing parameters in the query string.
    params = {
        "Action": "getSigninToken",
            "Session": json_temp_credentials,
    }
    request_url = "https://signin.aws.amazon.com/federation"
    r = requests.get(request_url, params=params)

    # The return value from the federation endpoint, the token.
    sign_in_token = json.loads(r.text)["SigninToken"]
    # Token is good for 15 minutes.

    # Create the URL to the console with token.
    params = {
        "Action": "login",
        "Issuer": "",
        "Destination": "https://console.aws.amazon.com/",
        "SigninToken": sign_in_token,
    }
    request_url = "https://signin.aws.amazon.com/federation?"
    request_url += urlencode(params)

    # Use the default browser to sign in to the console using the
    # generated URL.
    browser = webbrowser.get()
    if getArgs().incognito:
        webbrowser.Chromium.raise_opts = ["", "--incognito"]
        webbrowser.Chrome.raise_opts = ["", "--incognito"]
        webbrowser.Mozilla.remote_args = ['--private-window', '%s']
    browser.open(request_url, new=1)

if __name__ == "__main__":
    if getArgs().create_role:
        createRole()
    elif getArgs().temp_role:
        if createRole():
            print("Waiting for role to propagate.")
        count = 0
        while True:
            count += 1
            try:
                openConsole()
                break
            except boto.exception.BotoServerError:
                time.sleep(1) # time for role to get ready
                if count > 5: raise
        raw_input("Press any key to remove role and end session...")
        removeRole()
    else:
        openConsole()

