from zope.interface import Interface, Attribute, implementer
from twisted.python.components import registerAdapter
from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineReceiver
from twisted.web.resource import Resource, NoResource
from twisted.internet import reactor
from twisted.web import server
#from onelogin.saml2.auth import OneLogin_Saml2_Auth
#from onelogin.saml2.settings import OneLogin_Saml2_Settings
#from onelogin.saml2.utils import OneLogin_Saml2_Utils
from os import path
from threading import Timer
import random
import json

class ISession(Interface):
    nonce = Attribute("The original nonce")

@implementer(ISession)
class Session(object):
    def __init__(self, sesion):
        self.nonce = 0

registerAdapter(Session, server.Session, ISession)

class Client(Resource, object):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    numbers = '1234567890'
    settings = None
    url = None
    clients = {}
    auths = {}
    hots = {}

    def __init__(self, settings):
        Resource.__init__(self)
        self.settings = settings
        self.url = settings['url']

    def _nonce(self, length=8):
      return ''.join([str(random.choice(self.chars)) for i in range(length)])

    def _pin(self, length=4):
      return ''.join([str(random.choice(self.numbers)) for i in range(length)])

    def getChild(self, name, request):
        if name == 'req':
            return self
        elif name == 'auth':
            print("args: {}".format(request.args))
            nonce = request.args.get('nonce', [None])[0]
            auth = self._pop_auth(nonce)
            print("auth: {}".format(auth))
            if auth.get('result') == "SUCCESS":
                user = auth.get('uid')
                self.hots[user] = True
                Timer(60, self._pop_hot, [user]).start()
                return ClientAuth(auth)
            else:
                return ClientError()
        else:
            return ClientError()

    def _pop_auth(self, nonce):
        print("pop auth {}".format(nonce))
        return self.auths.pop(nonce, {})

    def _pop_hot(self, user):
        print("pop hot {}".format(user))
        self.hots.pop(user, None)

    def handleCommand(self, nonce, msg):
        self.auths[nonce] = msg
        Timer(60, self._pop_auth, [nonce]).start()

    def render_POST(self, request):
        #print("Client render_POST")
        nonce = self._nonce()
        pin = self._pin()
        challenge  = 'Visit ' + self.url + 'login/%s' % nonce + ' to log in and enter PIN\n'
        challenge += 'or press <enter> to skip websso: '
        msg = { 'challenge': challenge, 'nonce': nonce, 'pin': pin, 'hot': False }
        user = request.args.get('user')[0]
        self.clients[nonce] = { 'user': user, 'pin': pin }
        hot = self.hots.get(user)
        if hot:
            msg['hot'] = True
        Timer(60, lambda: self.clients.pop(nonce, None)).start()
        print("msg: {}".format(msg))
        return json.dumps(msg).encode("ascii")

class ClientError(Resource, object):

    def __init__(self):
        Resource.__init__(self)

    def render(self, request):
        request.setResponseCode(400, b'Something went wrong!')
        return "Error"

class ClientAuth(Resource, object):
    isLeaf = True

    def __init__(self, auth):
        Resource.__init__(self)
        print("ClientAuth __init__ {}".format(auth))
        self.auth = auth

    def render_POST(self, request):
        #print("ClientAuth render_POST")
        return json.dumps(self.auth)

class Login(Resource):

    def __init__(self, client):
        Resource.__init__(self)
        self.client = client

    def getChild(self, name, request):
        if name:
            return loginCode(name, self.client)
        else:
            return self

    def render_GET(self, request):
        request.setHeader(b"content-type", b"text/plain")
        content = u"no Code\n"
        return content.encode("ascii")


class loginCode(Resource):
    isLeaf = True
    nonce = None
    client = None
    settings = None

    def __init__(self, nonce, client):
        Resource.__init__(self)
        self.nonce = nonce
        self.client = client
        my_base = path.dirname(path.realpath(__file__))
        filename = my_base + "/websso_daemon.json"
        json_data_file = open(filename, 'r')
        self.settings = json.load(json_data_file)

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
        s = ISession(session)
        s.nonce = self.nonce
        print("loginCode: {}".format(s.nonce))
        client = self.client.clients.get(self.nonce, None)
        user = client['user'] if client else "Error"
        request.setHeader(b"content-type", b"text/html")
        if client:
          content =  u"<html>\n<body>\n<form method=POST>\n"
          content += u"Please authorize SSH login for user {}<br />\n".format(user)
          content += u"<input name=action type=submit value=login>\n"
          content += u"</body>\n</html>\n"
        else:
          content = u"<html>\n<body>\nUnkown error\n</body>\n</html>\n"
        return content.encode("ascii")

    def render_POST(self, request):
        session = request.getSession()
        s = ISession(session)
        nonce = s.nonce
        args = request.args
        client = self.client.clients.get(nonce)
        if client:
            pin = client['pin']
            user = client['user']
        else:
            return "<html><body>Unknown Error</body></html>"

        msg = { 'uid': user, 'result': 'SUCCESS' }
        self.client.handleCommand(nonce, msg)

        request.setHeader(b"content-type", b"text/html")
        content =  u"<html>\n<body>\n"
        content += u"{}/{} successfully authenticated<br />\n".format(nonce, user)
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

        # Client channel
        client = Client(self.settings)
        self.clients = server.Site(client)

        # WebSSO channel
        root = client
        root.putChild(b'login', Login(client))
        self.web = server.Site(root)

    def start(self):
        reactor.listenTCP(self.settings['ports']['clients'], self.clients)
        reactor.run()

Server().start()
