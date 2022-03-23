# Workaround for CVE-2019-16729
# https://sourceforge.net/p/pam-python/tickets/8/
import site
site.main()

from OpenSSL import SSL
from os import path
# Future functionality
#import pyqrcode
import json
import random
import socket
import requests

def debug(line):
    with open('/var/log/pam_websso.log', 'a') as f:
        f.write(line+"\n")

def pam_sm_authenticate(pamh, flags, argv):
  # debugging to /var/log/pam_websso.log
  #debug("Test")

  # Load client port from settings
  my_base = path.dirname(path.realpath(__file__))
  filename = my_base + "/pam_websso.json"
  json_data_file = open(filename, 'r')
  settings = json.load(json_data_file)

  try:
    user = pamh.get_user()
    pamh.env['user'] = user
  except pamh.exception as e:
    return e.pam_result

  # It is not (yet) possible in OpenSSH to
  # alter PAM_USER during pam_sm_authenticate
  # https://bugzilla.mindrot.org/show_bug.cgi?id=2877
  #if user != 'websso':
    #pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Not websso"))
    #return pamh.PAM_IGNORE

  hostname = socket.gethostname()
  uid = user+"@"+hostname
  payload = {'user': uid }
  try:
    r = requests.post(url = settings['sso_server'] + '/req', data = payload, timeout=1)
  except:
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Fail! %s" % (user)))
    return pamh.PAM_AUTH_ERR

  r = json.loads(r.text)

  nonce = r['nonce']
  pin = r['pin']
  hot = r['hot']
  challenge = r['challenge']
  result = "FAIL"

  if not hot:
    msg_type = pamh.PAM_PROMPT_ECHO_OFF
    response = pamh.conversation(pamh.Message(msg_type, challenge.encode('ascii')))
    resp = response.resp

    if resp != pin:
      pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Fail! %s" % (user)))
      return pamh.PAM_AUTH_ERR

    payload = { 'nonce': nonce }

    try:
      r = requests.post(url = settings['sso_server'] + '/auth', data = payload, timeout=300)
    except:
      pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Fail! %s" % (user)))
      return pamh.PAM_AUTH_ERR

    msg = json.loads(r.text)

    result = msg['result']
    uid = msg['uid']
    pamh.env['result'] = result.encode('ascii')

  pamh.env['uid'] = uid.encode('ascii')

  if hot or result == 'SUCCESS':
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Success! %s" % (user)))
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, " Env: {}".format({key:val for key,val in pamh.env.iteritems()})))
    return pamh.PAM_SUCCESS
  else:
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Fail! %s" % (user)))
    return pamh.PAM_AUTH_ERR

def pam_sm_setcred(pamh, flags, argv):
  # We need to return PAM_SUCCESS on setcred
  # to enable pubkey + passwordless keyboard-interactive
  return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
  return pamh.PAM_IGNORE

def pam_sm_open_session(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
  return pamh.PAM_IGNORE

def pam_sm_end(pamh):
  # OpenSSH does not call pam_sm_end
  return pamh.PAM_SUCCESS

