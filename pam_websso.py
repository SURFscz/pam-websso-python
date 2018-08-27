from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver
from twisted.protocols.policies import TimeoutProtocol, TimeoutFactory
from twisted.internet import reactor, ssl
from OpenSSL import SSL
from os import path
# Future functionality
#import pyqrcode
import time
import json
import random
import socket

def debug(line):
    with open('/var/log/pam_websso.log', 'a') as f:
        f.write(line+"\n")

class WebSSOClient(LineReceiver, TimeoutProtocol):
  answer = None
  pamh = None
  settings = None
  pin = None
  resp = None
  state = 'start'

  def __init__(self, pamh, settings):
    chars = '1234567890'
    length = 4
    self.pamh = pamh
    self.settings = settings
    self.pin = ''.join([str(random.choice(chars)) for i in range(length)])
    self.user = pamh.get_user()

  def connectionMade(self):
    self.timeoutCall = reactor.callLater(60, self.transport.loseConnection)
    hostname = socket.gethostname()
    msg = {'pin': self.pin, 'user': self.user+"@"+hostname }
    self.sendLine(json.dumps(msg))

  def connectionLost(self, reason):
    if self.resp == self.pin:
      self.state = 'end'
    if self.timeoutCall.active():
      self.timeoutCall.cancel()
      self.timeoutCall = None

  def lineReceived(self, line):
    debug(line)
    self.answer = json.loads(line)
    if self.state == 'start':
      self.state = 'failed'
      url = self.answer.get('url')
      # Future functionality
      #qrcode = pyqrcode.create(url)
      #msg = "Visit {} to login\nand press <enter> to continue.{}".format(url,qrcode.terminal(quiet_zone=1))
      msg = "Visit {} to login and enter PIN\nor press <enter> to skip websso: ".format(url)
      msg_type = self.pamh.PAM_PROMPT_ECHO_OFF
      response = self.pamh.conversation(self.pamh.Message(msg_type, msg))
      self.resp = response.resp
      # This line makes WebSSO fall-through immediately if user presses enter before login
      self.transport.loseConnection()
    else:
      self.transport.loseConnection()

class WebSSOFactory(ClientFactory, TimeoutFactory):
  pamh = None
  client = None

  def __init__(self, pamh, settings):
    self.pamh = pamh
    self.settings = settings

  def clientConnectionFailed(self, connector, reason):
    reactor.stop()

  def clientConnectionLost(self, connector, reason):
    reactor.stop()

  def buildProtocol(self, addr):
    client = WebSSOClient(self.pamh, self.settings)
    self.client = client
    return client

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
  except pamh.exception, e:
    return e.pam_result

  # It is not (yet) possible in OpenSSH to
  # alter PAM_USER during pam_sm_authenticate
  # https://bugzilla.mindrot.org/show_bug.cgi?id=2877
  #if user != 'websso':
    #pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Not websso"))
    #return pamh.PAM_IGNORE

  #debug("Test")

  websso = WebSSOFactory(pamh, settings)
  #reactor.connectTCP(settings['sso_server'], settings['ports']['clients'], websso)
  reactor.connectSSL(settings['sso_server'], settings['ports']['clients'], websso, ssl.ClientContextFactory())
  reactor.run()
  state = 'failed'
  result = 'FAILED'
  uid = 'failed'
  try:
    #(auth, result) = websso.client.line.split(" ")
    state = websso.client.state
    result = websso.client.answer.get('result')
    uid = websso.client.answer.get('uid')
  except:
    pass

  #debug('state: {} {} {}'.format(uid, result, state))
  pamh.env['state'] = state
  pamh.env['result'] = result.encode('ascii')
  pamh.env['uid'] = uid.encode('ascii')

  if result == 'SUCCESS' and uid == user and state == 'end':
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Success! %s" % (user)))
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, " Env: {}".format({key:val for key,val in pamh.env.iteritems()})))
    return pamh.PAM_SUCCESS
  else:
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Fail! %s" % (user)))
    return pamh.PAM_AUTH_ERR

def pam_sm_setcred(pamh, flags, argv):
  return pamh.PAM_IGNORE

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
  #pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, " Env: {}".format({key:val for key,val in pamh.env.iteritems()})))
  #pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, " user: {}".format(pamh.get_user(None))))
  return pamh.PAM_SUCCESS

