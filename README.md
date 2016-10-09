Open AWS consoles from CLI using only your key pair
---------------------------------------------------

This script is for developers who have AWS API keys for development and need
the occasional console access. It gives them console access using only the keys
and a special role. So  with this script you no longer have to worry about
password/multi-factor auth or anything other than your API key pair that you
already have.

The script is entirely self contained so you run it once (with a flag) to setup
the role and from that point on you can just run it and your console should pop
up in your browser.

It is compatible with python2 and python3.
Requires standard lib + [boto](http://docs.pythonboto.org/) +
[requests](http://python-requests.org).

Usage
-----
Create the role:

    $ aws-console -c
    Role created: StsConsoleAccess

Get your console:

    $ aws-console
    [browser window pops open with console loaded]

Help Output
-----------

    usage: aws-console [-h] [-i] [-r REGION] [-c] [-n ROLE_NAME]

    Open chrome to AWS console of account based on credentials. Credentials
    should be stored in standard environment variables.

    optional arguments:
      -h, --help          show this help message and exit
      -i, --incognito     open browser in incognito/private mode.
      -r REGION, --region REGION
                          region for region-specific commands (us-west-2)
      -c, --create-role   create required role in account if it doesn't exist
      -n ROLE_NAME, --role-name ROLE_NAME
                          name of required role to create/use (StsConsoleAccess)

Notes
-----
Includes both aws_console.py, named for python import friendliness, and
aws-console, named for cli friendliness.
