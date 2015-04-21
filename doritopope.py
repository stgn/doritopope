from twisted.application import internet, service
from twisted.web import server, resource
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.defer import inlineCallbacks
import txmongo

import struct, msgpack
from io import BytesIO

from os import urandom
from hmac import HMAC
from socket import inet_aton

from datetime import datetime

mongo = txmongo.MongoConnection()
db = mongo.doritopope

class MsgType:
    challenge_request, \
    challenge_response, \
    association_request, \
    info_request, \
    info_response, \
    join_request, \
    join_response = xrange(7)

class SIXProtocol(DatagramProtocol):
    '''A server for the session information exchange protocol (SIXP)'''
    
    def __init__(self):
        self.handlers = {
            MsgType.association_request: self.handle_association_request,
            MsgType.info_response: self.handle_info_response
        }
        self.secret = urandom(16)
    
    def datagramReceived(self, data, (host, port)):
        bio = BytesIO(data)
        magic, version, flags = struct.unpack('4sBB', bio.read(6))
        if magic != 'SIXP':
            return
            
        if flags & 0x1: # split
            raise NotImplementedError
        else:
            msg = bio.read()
        type, msgdata = ord(msg[0]), msg[1:]
        try:
            self.handlers[type](host, port, msgdata)
        except KeyError:
            print 'No handler for SIXP type {}'.format(type)
    
    def sixp_send(self, msg, dest):
        if len(msg) > 1024:
            raise NotImplementedError # needs splitting
        else:
            self.transport.write('SIXP\0\0' + msg, dest)
    
    def generate_challenge(self, data):
        return HMAC(self.secret, data).digest()[:4]
    
    def handle_association_request(self, host, port, data):
        print 'Association request from {}:{}'.format(host, port)
        if len(data) != 4:
            print 'Invalid association request data'
            return
        output = data + self.generate_challenge(inet_aton(host))
        self.sixp_send(chr(MsgType.info_request) + output, (host, port))
    
    @inlineCallbacks    
    def handle_info_response(self, host, port, data):
        challenge = data[:4]
        if challenge != self.generate_challenge(inet_aton(host)):
            return
        info = msgpack.unpackb(data[4:], use_list=False)
        print 'Info response from {}:{} - {}'.format(host, port, info)
        yield db.servers.update({'host': host, 'port': port},
            {'$set': {'announced': datetime.utcnow(), 'info': info}}, upsert=True)

class SessionList(resource.Resource):
    isLeaf = True
    
    def __init__(self):
        @inlineCallbacks
        def setup_db():
            f = txmongo.filter
            yield db.servers.create_index(f.sort(f.ASCENDING('host') + f.ASCENDING('port')), unique=True)
            yield db.servers.create_index(f.sort(f.ASCENDING('announced')), expireAfterSeconds=180)
        setup_db()
    
    def render_GET(self, request):
        request.setHeader('Content-Type', 'application/octet-stream')
        def render(res):
            servers = ''.join(struct.pack('4sH', inet_aton(s['host']), s['port']) for s in res)
            request.setHeader('Content-Length', len(servers))
            request.write(servers)
            request.finish()
        d = db.servers.find(fields=['host', 'port'], limit=1024)
        d.addCallback(render)
        return server.NOT_DONE_YET

master = service.MultiService()
internet.TCPServer(8080, server.Site(SessionList())).setServiceParent(master)
internet.UDPServer(8080, SIXProtocol()).setServiceParent(master)
        
application = service.Application('DoritoPope master server')
master.setServiceParent(application)