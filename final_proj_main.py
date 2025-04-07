#
# Client-side python app for benford app, which is calling
# a set of lambda functions in AWS through API Gateway.
# The overall purpose of the app is to process a PDF and
# see if the numeric values in the PDF adhere to Benford's
# law. This version adds authentication with user names, 
# passwords, and login tokens.
#
# Authors:
#   << YOUR NAME >>
#
#   Prof. Joe Hummel (initial template)
#   Northwestern University
#   CS 310
#

import requests
import jsons

import uuid
import pathlib
import logging
import sys
import os
import base64
import time

from configparser import ConfigParser
from getpass import getpass


############################################################
#
# classes
#
class User:

  def __init__(self, row):
    self.userid = row[0]
    self.username = row[1]
    self.pwdhash = row[2]


class Job:

  def __init__(self, row):
    self.jobid = row[0]
    self.userid = row[1]
    self.status = row[2]
    self.originaldatafile = row[3]
    self.datafilekey = row[4]
    self.resultsfilekey = row[5]


###################################################################
#
# web_service_get
#
# When calling servers on a network, calls can randomly fail. 
# The better approach is to repeat at least N times (typically 
# N=3), and then give up after N tries.
#
def web_service_get(url, token = None):
  """
  Submits a GET request to a web service at most 3 times, since 
  web services can fail to respond e.g. to heavy user or internet 
  traffic. If the web service responds with status code 200, 400 
  or 500, we consider this a valid response and return the response.
  Otherwise we try again, at most 3 times. After 3 attempts the 
  function returns with the last response.
  
  Parameters
  ----------
  url: url for calling the web service
  
  Returns
  -------
  response received from web service
  """

  try:
    retries = 0
    
    while True:
      if token != None:
        req_header = {'Authentication': token}
        response = requests.get(url, headers=req_header)
      else:
        response = requests.get(url)
        
      if response.status_code in [200, 400, 480, 481, 482, 500]:
        #
        # we consider this a successful call and response
        #
        break;

      #
      # failed, try again?
      #
      retries = retries + 1
      if retries < 3:
        # try at most 3 times
        time.sleep(retries)
        continue
          
      #
      # if get here, we tried 3 times, we give up:
      #
      break

    return response

  except Exception as e:
    print("**ERROR**")
    logging.error("web_service_get() failed:")
    logging.error("url: " + url)
    logging.error(e)
    return None
    

############################################################
#
# prompt
#
def prompt():
  """
  Prompts the user and returns the command number

  Parameters
  ----------
  None

  Returns
  -------
  Command number entered by user (0, 1, 2, ...)
  """
  try:
      print()
      print(">> Enter a command:")
      print("   0 => end")
      print("   1 => users")
      print("   2 => jobs")
      print("   3 => reset database")
      print("   4 => upload pdf")
      print("   5 => download results")
      print("   6 => upload and poll")
      print("   7 => login")
      print("   8 => authenticate token")
      print("   9 => upload audio")
      print("  10 => logout")

      cmd = input()

      if cmd == "":
        cmd = -1
      elif not cmd.isnumeric():
        cmd = -1
      else:
        cmd = int(cmd)

      return cmd

  except Exception as e:
      print("**ERROR")
      print("**ERROR: invalid input")
      print("**ERROR")
      return -1


############################################################
#
# users
#
def users(baseurl):
  """
  Prints out all the users in the database

  Parameters
  ----------
  baseurl: baseurl for web service

  Returns
  -------
  nothing
  """

  try:
    #
    # call the web service:
    #
    api = '/users'
    url = baseurl + api

    # res = requests.get(url)
    res = web_service_get(url)

    #
    # let's look at what we got back:
    #
    if res.status_code == 200: #success
      pass
    else:
      # failed:
      print("**ERROR: failed with status code:", res.status_code)
      print("url: " + url)
      if res.status_code == 500:
        # we'll have an error message
        body = res.json()
        print("Error message:", body)
      #
      return

    #
    # deserialize and extract users:
    #
    body = res.json()

    #
    # let's map each row into a User object:
    #
    users = []
    for row in body:
      user = User(row)
      users.append(user)
    #
    # Now we can think OOP:
    #
    if len(users) == 0:
      print("no users...")
      return

    for user in users:
      print(user.userid)
      print(" ", user.username)
      print(" ", user.pwdhash)
    #
    return

  except Exception as e:
    logging.error("**ERROR: users() failed:")
    logging.error("url: " + url)
    logging.error(e)
    return


############################################################
#
# jobs
#
def jobs(baseurl, token):
  """
  Prints out all the jobs in the database

  Parameters
  ----------
  baseurl: baseurl for web service

  Returns
  -------
  nothing
  """

  try:
    if token == None:
      print("No current token, please login")
      return
    
    #
    # call the web service:
    #
    api = '/jobs'
    url = baseurl + api

    #
    # make request:
    #
    # res = requests.get(url)
    res = web_service_get(url, token)
    #
    # let's look at what we got back:
    #
    if res.status_code == 200: #success
      pass
    else:
      # failed:
      print("**ERROR: failed with status code:", res.status_code)
      print("url: " + url)
      if res.status_code == 401:
        # we'll have an error message
        body = res.json()
        print(body)
        return

      elif res.status_code in [400,500]:
        # we'll have an error message
        body = res.json()
        print("ERROR:", body)

      else:
        print("ERROR:", res.status_code)
      #
      return

    #
    # deserialize and extract jobs:
    #
    body = res.json()
    #
    # let's map each row into an Job object:
    #
    jobs = []
    for row in body:
      job = Job(row)
      jobs.append(job)
    #
    # Now we can think OOP:
    #
    if len(jobs) == 0:
      print("no jobs...")
      return

    for job in jobs:
      print(job.jobid)
      print(" ", job.userid)
      print(" ", job.status)
      print(" ", job.originaldatafile)
      print(" ", job.datafilekey)
      print(" ", job.resultsfilekey)
    #
    return

  except Exception as e:
    logging.error("**ERROR: jobs() failed:")
    logging.error("url: " + url)
    logging.error(e)
    return


############################################################
#
# reset
#
def reset(baseurl):
  """
  Resets the database back to initial state.

  Parameters
  ----------
  baseurl: baseurl for web service

  Returns
  -------
  nothing
  """

  try:
    #
    # call the web service:
    #
    api = '/reset'
    url = baseurl + api

    res = requests.delete(url)

    #
    # let's look at what we got back:
    #
    if res.status_code == 200: #success
      pass
    else:
      # failed:
      print("**ERROR: failed with status code:", res.status_code)
      print("url: " + url)
      if res.status_code == 500:
        # we'll have an error message
        body = res.json()
        print("Error message:", body)
      #
      return

    #
    # deserialize and print message
    #
    body = res.json()

    msg = body

    print(msg)
    return

  except Exception as e:
    logging.error("**ERROR: reset() failed:")
    logging.error("url: " + url)
    logging.error(e)
    return


############################################################
#
# upload
#
def upload(baseurl):
  """
  Prompts the user for a local filename and user id, 
  and uploads that asset (PDF) to S3 for processing. 

  Parameters
  ----------
  baseurl: baseurl for web service

  Returns
  -------
  nothing
  """
  try:
    print("Enter PDF filename>")
    local_filename = input()

    if not pathlib.Path(local_filename).is_file():
      print("PDF file '", local_filename, "' does not exist...")
      return

    print("Enter user id>")
    userid = input()
    
    #
    # build the data packet:
    #
    infile = open(local_filename, "rb")
    bytes = infile.read()
    infile.close()

    #
    # now encode the pdf as base64. Note b64encode returns
    # a bytes object, not a string. So then we have to convert
    # (decode) the bytes -> string, and then we can serialize
    # the string as JSON for upload to server:
    #
    data = base64.b64encode(bytes)
    datastr = data.decode()

    data = {"filename": local_filename, "data": datastr}

    #
    # call the web service:
    #
    api = '/pdf'
    url = baseurl + api + "/" + userid

    res = requests.post(url, json=data)

    #
    # let's look at what we got back:
    #
    if res.status_code == 200: #success
      pass
    elif res.status_code == 400: # no such user
      body = res.json()
      print(body)
      return
    else:
      # failed:
      print("**ERROR: failed with status code:", res.status_code)
      print("url: " + url)
      if res.status_code == 500:
        # we'll have an error message
        body = res.json()
        print("Error message:", body)
      #
      return

    #
    # success, extract jobid:
    #
    body = res.json()

    jobid = body

    print("PDF uploaded, job id =", jobid)
    return

  except Exception as e:
    logging.error("**ERROR: upload() failed:")
    logging.error("url: " + url)
    logging.error(e)
    return


############################################################
#
# download
#
def download(baseurl):
  """
  Prompts the user for the job id, and downloads
  that asset (PDF).

  Parameters
  ----------
  baseurl: baseurl for web service

  Returns
  -------
  nothing
  """
  try:
    print("Enter job id>")
    jobid = input()
    
    #
    # call the web service:
    #
    api = '/results'
    url = baseurl + api + '/' + jobid

    # res = requests.get(url)
    res = web_service_get(url)

    #
    # let's look at what we got back:
    #
    if res.status_code == 200: #success
      pass
    elif res.status_code == 400: # no such job
      body = res.json()
      print(body)
      return
    elif res.status_code in [480, 481, 482]:  # uploaded
      msg = res.json()
      print("No results available yet...")
      print("Job status:", msg)
      return
    else:
      # failed:
      print("**ERROR: failed with status code:", res.status_code)
      print("url: " + url)
      if res.status_code == 500:
        # we'll have an error message
        body = res.json()
        print("Error message:", body)
      #
      return

    #
    # if we get here, status code was 200, so we
    # have results to deserialize and display:
    #
    body = res.json()

    datastr = body

    base64_bytes = datastr.encode()
    bytes = base64.b64decode(base64_bytes)
    results = bytes.decode()

    print(results)
    return

  except Exception as e:
    logging.error("**ERROR: download() failed:")
    logging.error("url: " + url)
    logging.error(e)
    return


############################################################
#
# upload_and_poll
#
def upload_and_poll(baseurl):
  """
  Prompts the user for a local filename and user id, 
  and uploads that asset (PDF) to S3 for processing. 

  Parameters
  ----------
  baseurl: baseurl for web service

  Returns
  -------
  nothing
  """
  
  print()
  print("** function not provided **")
  print()


############################################################
#
# login
#
def login(auth_url):
  """
  Prompts the user for a username and password, then tries
  to log them in. If successful, returns the token returned
  by the authentication service.

  Parameters
  ----------
  auth_url: url for auth web service

  Returns
  -------
  token if successful, None if not
  """
  try:
    username = input("username: ")
    password = getpass()
    duration = input("# of minutes before expiration? [ENTER for default] ")

    #
    # build message:
    #
    if duration == "":  # use default
      data = {"username": username, "password": password}
    else:
      data = {"username": username, "password": password, "duration": duration}

    #
    # call the web service to upload the PDF:
    #
    api = '/auth'
    url = auth_url + api
    print(url)

    res = requests.post(url, json=data)

    #
    # clear password variable:
    #
    password = None

    #
    # let's look at what we got back:
    #
    if res.status_code == 401:
      #
      # authentication failed:
      #
      body = res.json()
      print(body)
      return None

    if res.status_code == 200: #success
      pass
    elif res.status_code in [400, 500]:
      # we'll have an error message
      body = res.json()
      print("**Error:", body)
      return
    else:
      # failed:
      print("**ERROR: Failed with status code:", res.status_code)
      print("url: " + url)
      return

    #
    # success, extract token:
    #
    body = res.json()

    token = body

    print("logged in, token:", token)
    return token

  except Exception as e:
    logging.error("**ERROR: login() failed:")
    logging.error("url: " + url)
    logging.error(e)
    return None


############################################################
#
# authenticate
#
def authenticate(auth_url, token):
  """
  Since tokens expire, this function authenticates the 
  current token to see if still valid. Outputs the result.

  Parameters
  ----------
  auth_url: url for auth web service

  Returns
  -------
  nothing
  """
  try:
    if token is None:
      print("No current token, please login")
      return

    print("token:", token)

    #
    # build message:
    #
    data = {"token": token}

    #
    # call the web service to upload the PDF:
    #
    api = '/auth'
    url = auth_url + api

    res = requests.post(url, json=data)

    #
    # let's look at what we got back:
    #
    if res.status_code == 401:
      #
      # authentication failed:
      #
      body = res.json()
      print(body)
      return

    if res.status_code == 200: #success
      pass
    elif res.status_code in [400, 500]:
      # we'll have an error message
      body = res.json()
      print("**Error:", body)
      return
    else:
      # failed:
      print("**ERROR: Failed with status code:", res.status_code)
      print("url: " + url)
      return

    #
    # success, token is valid:
    #
    print("token is valid!")
    return

  except Exception as e:
    logging.error("**ERROR: authenticate() failed:")
    logging.error("url: " + url)
    logging.error(e)
    return


############################################################
#
# check_url
#
def check_url(baseurl):
  """
  Performs some checks on the given url, which is read from a config file.
  Returns updated url if it needs to be modified.

  Parameters
  ----------
  baseurl: url for a web service

  Returns
  -------
  same url or an updated version if it contains an error
  """

  #
  # make sure baseurl does not end with /, if so remove:
  #
  if len(baseurl) < 16:
    print("**ERROR: baseurl '", baseurl, "' is not nearly long enough...")
    sys.exit(0)

  if baseurl == "https://YOUR_GATEWAY_API.amazonaws.com":
    print("**ERROR: update config file with your gateway endpoint")
    sys.exit(0)

  if baseurl.startswith("http:"):
    print("**ERROR: your URL starts with 'http', it should start with 'https'")
    sys.exit(0)

  lastchar = baseurl[len(baseurl) - 1]
  if lastchar == "/":
    baseurl = baseurl[:-1]
    
  return baseurl


def upload_audio(baseurl):
  """
  Prompts the user for a local filename and user id, 
  and uploads that asset (PDF) to S3 for processing. 

  Parameters
  ----------
  baseurl: baseurl for web service

  Returns
  -------
  nothing
  """

  try:
    print("Enter mp3 filename>")
    local_filename = input()

    if not pathlib.Path(local_filename).is_file():
      print("mp3 file '", local_filename, "' does not exist...")
      return
    

    print("Enter user id>")
    userid = input()

    infile = open(local_filename, "rb")
    bytes = infile.read()
    infile.close()

    data = base64.b64encode(bytes)
    datastr = data.decode()
    data = {"filename": local_filename, "data": datastr}

    #
    # call the web service:
    #
    url = baseurl + "/mp3/" + userid
    res = requests.post(url, json = data)

    #
    # let's look at what we got back:
    #
    if res.status_code == 200: #success
      pass
    elif res.status_code == 400: # no such user
      body = res.json()
      print(body)
      return
    else:
      # failed:
      print("Failed with status code:", res.status_code)
      print("url: " + url)
      if res.status_code == 500:
        # we'll have an error message
        body = res.json()
        print("Error message:", body)
      #
      return

    #
    # success, extract jobid:
    #
    body = res.json()

    jobid = body

    print("PDF uploaded, job id =", jobid)
    return

  except Exception as e:
    logging.error("**ERROR: upload() failed:")
    logging.error("url: " + url)
    logging.error(e)
    return
  

############################################################
# main
#
try:
  print('** Welcome to BenfordApp with Authentication **')
  print()

  # eliminate traceback so we just get error message:
  sys.tracebacklimit = 0

  #
  # we have two config files:
  # 
  #    1. benfordapp API endpoint
  #    2. authentication service API endpoint
  #
  #
  benfordapp_config_file = 'benfordapp-client-config.ini'
  authsvc_config_file = 'authsvc-client-config.ini'

  print("First, enter name of BenfordApp config file to use...")
  print("Press ENTER to use default, or")
  print("enter config file name>")
  s = input()

  if s == "":  # use default
    pass  # already set
  else:
    benfordapp_config_file = s

  #
  # does config file exist?
  #
  if not pathlib.Path(benfordapp_config_file).is_file():
    print("**ERROR: benfordapp config file '", benfordapp_config_file, "' does not exist, exiting")
    sys.exit(0)

  #
  # setup base URL to web service:
  #
  configur = ConfigParser()
  configur.read(benfordapp_config_file)
  baseurl = configur.get('client', 'webservice')
  
  baseurl = check_url(baseurl)
  
  #
  # now we need to process the 2nd config file:
  #
  print("Second, enter name of Auth Service config file to use...")
  print("Press ENTER to use default, or")
  print("enter config file name>")
  s = input()

  if s == "":  # use default
    pass  # already set
  else:
    authsvc_config_file = s

  #
  # does config file exist?
  #
  if not pathlib.Path(authsvc_config_file).is_file():
    print("**ERROR: authsvc config file '", authsvc_config_file, "' does not exist, exiting")
    sys.exit(0)

  #
  # setup base URL to web service:
  #
  configur.read(authsvc_config_file)
  auth_url = configur.get('client', 'webservice')
  
  auth_url = check_url(auth_url)

  #
  # initialize login token:
  #
  token = None

  #
  # main processing loop:
  #
  cmd = prompt()

  while cmd != 0:
    #
    if cmd == 1:
      users(baseurl)
    elif cmd == 2:
      jobs(baseurl, token)
    elif cmd == 3:
      reset(baseurl)
    elif cmd == 4:
      upload(baseurl)
    elif cmd == 5:
      download(baseurl)
    elif cmd == 6:
      upload_and_poll(baseurl)
    elif cmd == 7:
      token = login(auth_url)
    elif cmd == 8:
      authenticate(auth_url, token)
    elif cmd == 9:
      upload_audio(baseurl)
    elif cmd == 10:
      #
      # logout
      #
      token = None
    else:
      print("** Unknown command, try again...")
    #
    cmd = prompt()

  #
  # done
  #
  print()
  print('** done **')
  sys.exit(0)

except Exception as e:
  logging.error("**ERROR: main() failed:")
  logging.error(e)
  sys.exit(0)
