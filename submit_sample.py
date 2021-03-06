#!/usr/bin/env python
#
# submit_sample.py - Script that sends a file of suspected malware for 
# analysis to Symantec. Requires a Business Critical Support ID Number.
#
# USAGE: ./submit_sample.py [-u URL | -f FILE]
#
# All code Copyright (c) 2013, Ben Jackson and Mayhemic Labs -
# bbj@mayhemiclabs.com. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# * Neither the name of the author nor the names of contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os, requests, argparse, random, hashlib, cStringIO, sys
from ConfigParser import SafeConfigParser

#Read the configuration file
config = SafeConfigParser()
config.read('config.ini')

#Read the command line arguments
parser = argparse.ArgumentParser()

#The user needs to specify iether a URL or a filename
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-u', '--url', action='store')
group.add_argument('-f', '--file', action='store')

parser.add_argument("-v", "--verbose", help="Increase logging verbosity", action="store_true")
parser.add_argument("-s", "--severe", help="Flag Submission as High Severity", action="store_true", default=0)
parser.add_argument("-c", "--comments", help="Comments to Send With File", action="store", default='')
parser.add_argument('args', nargs=argparse.REMAINDER)
args = parser.parse_args()
 
if args.file is None:

    #If user has told us it's a URL download it

    print "Downloading " + args.url + "..."

    #Set up some random User Agents and choose one...

    useragent_list = (
        'Mozilla/5.0 (X11; Linux i686; rv:17.0) Gecko/17.0 Firefox/17.0',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:17.0) Gecko/17.0 Firefox/17.0',
        'Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1',
        'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
        'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)'
    )

    req_headers = {
        'User-Agent': random.choice(useragent_list),
        'Referer': 'http://www.google.com/trends/hottrends'
    }


    #Make the request

    sample_request = requests.get(args.url, headers=req_headers)

    if sample_request.status_code == 200:

        #If we grabbed it, dump it into a StringIO object so we can use it

        holdingfile = cStringIO.StringIO()
        holdingfile.write(sample_request.content)

        #Put the file into the variable and generate a hash for the filename

        file = sample_request.content
        filename = hashlib.sha256(sample_request.content).hexdigest()

    else:

        #If it doesn't return a 200, abort....

        print args.url + " did not return HTTP 200..."
        sys.exit(1)
else:

    #If it's a file read it in and 

    file = open(args.file, 'rb')
    filename = os.path.basename(args.file)

#OK, let's submit this bad mamma jamma

print "Submitting File..."

#Symantec BCS URL

submission_url = "https://submit.symantec.com/websubmit/bcs.cgi"

#Generate the payload of the POST request from the config.ini settings

payload = {'mode' : '2',
           'fname' : config.get('symantec_bcs', 'first_name'),
           'lname' : config.get('symantec_bcs', 'last_name'), 
           'cname' : config.get('symantec_bcs', 'company_name'),
           'email' : config.get('symantec_bcs', 'email_address'),
           'email2' : config.get('symantec_bcs', 'email_address'),
           'pin' : config.get('symantec_bcs', 'bcs_id'),
           'critical' : args.severe,
           'comments' : args.comments

}

#...and attach the file

files = {'upfile' : (filename, file)}

#Submit the request

r = requests.post(submission_url, payload, files=files)

#FIXME: Print out the Page

print r.text
