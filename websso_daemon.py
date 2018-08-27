from zope.interface import Interface, Attribute, implementer
from twisted.python.components import registerAdapter
from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineReceiver
from twisted.web.resource import Resource, NoResource
from twisted.internet import reactor, endpoints
from twisted.web import server
from twisted.web.server import Session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from os import path
import random
import json

class INonce(Interface):
    code = Attribute("The original nonce")

@implementer(INonce)
class Nonce(object):
    def __init__(self, sesion):
        self.code = 0

registerAdapter(Nonce, Session, INonce)

class Client(LineReceiver):

    def __init__(self, url):
        self.name = None
        self.pin = None
        self.user = None
        self.url = url

    def connectionMade(self):
        #self.remote = self.transport.getPeer().host
        msg = { 'url': self.url }
        self.sendLine(json.dumps(msg))

    def lineReceived(self, line):
        print(line)
        #(self.pin, self.user) = line.split(" ")
        answer = json.loads(line)
        self.pin = answer['pin']
        self.user = answer['user']

    def handleCommand(self, line):
        #message = "%s" % line
        self.sendLine(line)
        self.transport.loseConnection()

class ClientFactory(Factory):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    settings = None

    def _nonce(self, length=8):
      return ''.join([str(random.choice(self.chars)) for i in range(length)])

    def __init__(self, settings):
        self.users = {} # maps user nonces to Client instances
        self.settings = settings

    def buildProtocol(self, addr):
        nonce = self._nonce()
        url = self.settings['url'] % nonce
        print("Create %s" % nonce)
        user = Client(url)
        self.users[nonce] = user
        return user

class Command(LineReceiver):

    def __init__(self, ClientFactory):
        self.client = ClientFactory

    def connectionMade(self):
        print("Command connection")
        for user in self.client.users:
          self.sendLine("%s" % user)

    def lineReceived(self, line):
        #print("Command lineReceived()")
        try:
          (nonce, command) = line.split(":")
          (uid, result) = command.split(" ")
          msg = { 'uid': uid, 'result': result }
          self.client.users[nonce].handleCommand(json.dumps(msg))
          self.client.users.pop(nonce)
          print("Destroy %s" % nonce)
        except Exception as e:
          print(e)
        self.transport.loseConnection()

class CommandFactory(Factory):

    def __init__(self, ClientFactory):
        self.clientfactory = ClientFactory

    def buildProtocol(self, addr):
        return Command(self.clientfactory)

class Metadata(Resource):

    def __init__(self):
        Resource.__init__(self)
        my_base = path.dirname(path.realpath(__file__))
        filename = my_base + "/websso_daemon.json"
        json_data_file = open(filename, 'r')
        self.settings = json.load(json_data_file)

    def _prepare_from_twisted_request(self, request):
        return {
            'http_host': request.getHost().host,
            'script_name': request.path,
            'server_port': request.getHost().port,
            'get_data': request.args,
        }

    def render_GET(self, request):
        request.setHeader(b"content-type", b"text/plain")
        req = self._prepare_from_twisted_request(request)
        auth = OneLogin_Saml2_Auth(req, old_settings=self.settings)
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        if len(errors) == 0:
            content = metadata
        else:
            content = "Error found on Metadata: %s" % (', '.join(errors))
        return content.encode("ascii")

class Login(Resource):

    def __init__(self, clientfactory):
        Resource.__init__(self)
        self.clientfactory = clientfactory

    def getChild(self, name, request):
        if name:
            return loginCode(name, self.clientfactory)
        else:
            return self

    def render_GET(self, request):
        request.setHeader(b"content-type", b"text/plain")
        content = u"no Code\n"
        return content.encode("ascii")


class loginCode(Resource):
    isLeaf = True
    code = None
    client = None
    settings = None

    def __init__(self, code, client):
        Resource.__init__(self)
        self.code = code
        self.client = client
        my_base = path.dirname(path.realpath(__file__))
        filename = my_base + "/websso_daemon.json"
        json_data_file = open(filename, 'r')
        self.settings = json.load(json_data_file)
        print("loginCode: {}".format(code))

    def _simplify_args(self, args):
        return { key: val[0] for key, val in args.iteritems() }

    def _prepare_from_twisted_request(self, request):
        return {
            'http_host': request.getHost().host,
            'script_name': request.path,
            'server_port': request.getHost().port,
            'get_data': request.args,
            'post_data': self._simplify_args(request.args)
        }

    def render_GET(self, request):
        session = request.getSession()
        nonce = INonce(session)
        nonce.code = self.code
        client = self.client.users.get(self.code)
        request.setHeader(b"content-type", b"text/html")
        if client:
          content =  u"<html>\n<body>\n<form method=POST>\n"
          content += u"Please authorize SSH login for user {}<br />\n".format(client.user)
          #content += u"PIN: {} ".format(client.pin)
          content += u"<input name=action type=submit value=login>\n"
          content += u"</body>\n</html>\n"
        else:
          content = u"<html>\n<body>\nUnkown error\n</body>\n</html>\n"
        return content.encode("ascii")

    def render_POST(self, request):
        session = request.getSession()
        nonce = INonce(session)
        code = nonce.code
        args = request.args
        client = self.client.users.get(code)
        if client:
            pin = client.pin
        else:
            return "<html><body>Unknown Error</body></html>"
        if args.get('action'):
            if 'login' in args.get('action'):
                req = self._prepare_from_twisted_request(request)
                auth = OneLogin_Saml2_Auth(req, old_settings=self.settings)
                redirect = auth.login()
                request.redirect(redirect)
                request.finish()
                return server.NOT_DONE_YET
            else:
                self.client.users[code].handleCommand(" FAIL")
                return "<html><body>PIN failed!</body></html>"

        req = self._prepare_from_twisted_request(request)
        auth = OneLogin_Saml2_Auth(req, old_settings=self.settings)
        auth.process_response()
        errors = auth.get_errors()
        msg = { 'uid': '', 'result': 'FAIL' }
        if auth.is_authenticated():
            attributes = auth.get_attributes()
            print("attributes: {}".format(attributes))
            uid_attr = attributes.get(self.settings.get('user_attribute'))
            if uid_attr:
                msg['uid'] = uid_attr[0]
                msg['result'] = 'SUCCESS'
        self.client.users[code].handleCommand(json.dumps(msg))

        print("Destroy %s" % code)
        self.client.users.pop(code)
        request.setHeader(b"content-type", b"text/html")
        content =  u"<html>\n<body>\n"
        content += u"{}/{} successfully authenticated<br />\n".format(code, msg['uid'])
        content += u"PIN: {}<br />\n".format(pin)
        content += u"This window may be closed\n"
        content += u"</body>\n</html>\n"
        return content.encode("ascii")

class Server:

    def __init__(self):
        my_base = path.dirname(path.realpath(__file__))
        filename = my_base + "/websso_daemon.json"
        json_data_file = open(filename, 'r')
        self.settings = json.load(json_data_file)
        self.clients = ClientFactory(self.settings)
        self.command = CommandFactory(self.clients)
        root = NoResource()
        root.putChild('login', Login(self.clients))
        root.putChild('md', Metadata())
        self.web = server.Site(root)

    def start(self):
        reactor.listenTCP(self.settings['ports']['clients'], self.clients)
        reactor.listenTCP(self.settings['ports']['command'], self.command, interface='localhost')
        reactor.listenTCP(self.settings['ports']['web'], self.web)
        reactor.run()

Server().start()
