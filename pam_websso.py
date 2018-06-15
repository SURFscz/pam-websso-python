from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver
from twisted.protocols.policies import TimeoutProtocol, TimeoutFactory
from twisted.internet import reactor
from os import path
import time

class WebSSOClient(LineReceiver, TimeoutProtocol):
  line = None
  pamh = None
  state = 'start'

  def __init__(self, pamh):
    self.pamh = pamh

  def connectionMade(self):
    self.timeoutCall = reactor.callLater(30, self.transport.loseConnection)

  def connectionLost(self, reason):
    if self.timeoutCall.active():
      self.timeoutCall.cancel()
      self.timeoutCall = None

  def lineReceived(self, line):
    self.line = line
    if self.state == 'start':
      msg_type = self.pamh.PAM_PROMPT_ECHO_OFF
      #msg_type = self.pamh.PAM_TEXT_INFO
      self.pamh.conversation(self.pamh.Message(msg_type, "Visit http://syncope.vm.scz-vm.net:8125/login/%s to login\nand press <enter> to continue." % line))
      self.state = None
    else:
      self.state = 'end'
      self.transport.loseConnection()

class WebSSOFactory(ClientFactory, TimeoutFactory):
  pamh = None
  client = None

  def clientConnectionFailed(self, connector, reason):
    reactor.stop()

  def __init__(self, pamh):
    self.pamh = pamh

  def clientConnectionLost(self, connector, reason):
    reactor.stop()

  def buildProtocol(self, addr):
    client = WebSSOClient(self.pamh)
    self.client = client
    return client

def pam_sm_authenticate(pamh, flags, argv):

  # Load client port from settings
  my_base = path.dirname(path.realpath(__file__))
  filename = my_base + "/settings.json"
  json_data_file = open(filename, 'r')
  settings = json.load(json_data_file)

  try:
    user = pamh.get_user("Get User")
    pamh.env['user'] = user
  except pamh.exception, e:
    return e.pam_result

  # It is not (yet) possible in OpenSSH to
  # alter PAM_USER during pam_sm_authenticate
  # https://bugzilla.mindrot.org/show_bug.cgi?id=2877
  #if user != 'websso':
    #pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Not websso"))
    #return pamh.PAM_IGNORE

  websso = WebSSOFactory(pamh)
  reactor.connectTCP(settings['sso_server'], settings['ports']['clients'], websso)
  reactor.run()
  if websso.client.state == 'end':
    (user, result) = websso.client.line.split(" ")
  else:
    user = 'fail'
    result = 'FAILED'

  pamh.env['reply'] = result
  pamh.user = user

  if result == 'SUCCESS':
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Success! %s" % (user)))
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, " Env: {}".format({key:val for key,val in pamh.env.iteritems()})))
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, " user: {}".format(pamh.get_user(None))))
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
  #pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, " Env: {}".format({key:val for key,val in pamh.env.iteritems()})))
  #pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, " user: {}".format(pamh.get_user(None))))
  return pamh.PAM_SUCCESS

