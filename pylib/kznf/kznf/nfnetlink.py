import socket
import struct
import binascii

class NfRootException(Exception):
    def __init__(self, detail):
        self.what = ''
        self.detail = detail

    def __str__(self):
        return '%s: %s' % (self.what, self.detail)

class NfnetlinkException(NfRootException):
    def __init__(self, detail):
        super(NfRootException, self).__init__(detail)
        self.what = 'nfnetlink error'
        self.detail = detail

class PacketException(NfRootException):
    def __init__(self, detail):
        super(NfRootException, self).__init__(detail)
        self.what = 'packet parsing error'

# netlink message type values
NLM_F_REQUEST = 1
NLM_F_MULTI = 2
NLM_F_ACK = 4
NLM_F_ECHO = 8

# modifiers to GET request
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_ATOMIC = 0x400
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

# modifiers to NEW request
NLM_F_REPLACE = 0x100
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLM_F_APPEND = 0x800

# netlink generic message types
NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLMSG_OVERRUN = 4

# nfnetlink subsystems
NFNL_SUBSYS_NONE = 0
NFNL_SUBSYS_CTNETLINK = 1
NFNL_SUBSYS_CTNETLINK_EXP = 2
NFNL_SUBSYS_QUEUE = 3
NFNL_SUBSYS_ULOG = 4
NFNL_SUBSYS_CTHELPER = 5
NFNL_SUBSYS_KZORP = 6

NETLINK_NETFILTER = 12

# attribute alignment
NFA_ALIGNTO = 4

MAX_NLMSGSIZE = 65535

def nfa_align(len):
        return (len + NFA_ALIGNTO - 1) & ~(NFA_ALIGNTO - 1)

class NfnetlinkAttribute(object):

        def __init__(self, type, data):
                self.type = type
                self.__buf = data

        def get_data(self):
                return self.__buf

        def dump(self):
                alen = nfa_align(len(self.__buf))
                flen = alen - len(self.__buf)
                header = struct.pack('HH', alen + 4, self.type)
                return "".join((header, self.__buf, '\0' * flen))

class NfnetlinkMessage(object):

        def __init__(self, family, version, res_id, data="", parent = None):
                self.family = family
                self.version = version
                self.res_id = res_id
                self.__buf = data

        def get_attributes(self):
                i = 0
                attributes = {}
                while i < len(self.__buf):
                        header = self.__buf[i:i + 4]
                        if len(header) < 4:
                                raise PacketException, "message too short to contain an attribute header"
                        (length, type) = struct.unpack('HH', header)
                        if length < 4:
                                raise PacketException, "invalid attribute length specified in attribute header: too short to contain the header itself"
                        data = self.__buf[i + 4:i + length]
                        if len(data) + 4!= length:
                                raise PacketException, "message too short to contain an attribute of the specified size"
                        i = i + nfa_align(length)
                        if attributes.has_key(type):
                                raise PacketException, "message contains multiple attributes of the same type"
                        attributes[type] = NfnetlinkAttribute(type, data)
                return attributes

        def append_attribute(self, attribute):
                self.__buf = "".join((self.__buf, attribute.dump()))

        def dump(self):
                header = struct.pack('BBH', self.family, self.version, self.res_id)
                return "".join((header, self.__buf))

class NetlinkMessage(object):

        def __init__(self, type, flags, seq, pid, data):
                self.type = type
                self.flags = flags
                self.seq = seq
                self.pid = pid
                self.__buf = data

        def get_nfmessage(self):
                if len(self.__buf) < 4:
                        raise PacketException, "message too short to contain an nfnetlink header"
                (family, version, res_id) = struct.unpack('BBH', self.__buf[:4])
                return NfnetlinkMessage(family, version, res_id, self.__buf[4:], self)

        def get_errorcode(self):
                # the error message consists of an error code plus the header of the
                # message triggering the error
                if len(self.__buf) < (4 + 16):
                        raise PacketException, "message too short to contain an error header"
                (error,) = struct.unpack('i', self.__buf[:4])
                return error

        def set_nfmessage(self, nfmessage):
                self.child = nfmessage
                self.__buf = nfmessage.dump()

        def dump(self):
                if not self.child:
                        raise PacketException, "cannot dump an incomplete netlink message"
                nfmsg = self.child.dump()
                # length of generic netlink message header is 16 bytes
                length = len(nfmsg) + 16
                header = struct.pack('IHHII', length, self.type, self.flags, self.seq, self.pid)
                return "".join((header, nfmsg))

class PacketIn(object):

        def __init__(self, s):
                self.set_contents(s)

        def dump(self):
                return self.__buf

        def set_contents(self, s):
                self.__buf = s

        def get_messages(self):
                i = 0
                messages = []
                while i < len(self.__buf):
                        header = self.__buf[i:i + 16]
                        i = i + 16
                        if len(header) < 16:
                                raise PacketException, "packet too short to contain a netlink message header"
                        (length, type, flags, seq, pid) = struct.unpack('IHHII', header)
                        if (length < 16):
                                raise PacketException, "invalid length specified in netlink header: too short to contain a netlink message header"
                        length = length - 16
                        data = self.__buf[i:i + length]
                        i = i + length

                        # length check
                        if len(data) < length:
                                raise PacketException, "packet too short to contain a message of the specified size"
                        messages.append(NetlinkMessage(type, flags, seq, pid, data))
                return messages


class Subsystem(object):

        def __init__(self, id):
                self.id = id
                self.handle = None
                self.seq = 0
                self.__callbacks = {}

        def next_seq(self):
                s = self.seq
                self.seq = self.seq + 1
                return s

        def register_callback(self, type, callback):
                if not callable(callback):
                        raise ValueError, "nfnetlink subsystem callback must be callable"
                self.__callbacks[type] = callback

        def unregister_callback(self, type):
                if self.__callbacks.has_key(type):
                        del self.__callbacks[type]

        def dispatch(self, message):
                m_type = message.type & 255
                if self.__callbacks.has_key(m_type):
                        self.__callbacks[m_type](message)

class Handle(object):

        def __init__(self):
                # subsystems
                self.__subsystems = {}
                # socket
                fd = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
                fd.bind((0, 0))
                self.fd = fd
                # local address
                self.local = fd.getsockname()

        def close(self):
                self.fd.close()

        def register_subsystem(self, s):
                if self.__subsystems.has_key(s.id):
                        raise NfnetlinkException, "subsystem already registered"
                self.__subsystems[s.id] = s
                s.handle = self

        def unregister_subsystem(self, s):
                if self.__subsystems.has_key(s.id):
                        self.__subsystems[s.id].handle = None
                        del self.__subsystems[s.id]
                else:
                        raise NfnetlinkException, "subsystem has not been registered"

        def process_packet(self, packet):
                messages = packet.get_messages()
                for m in messages:
                        self.dispatch(m)

        def dispatch(self, message):
                m_subsys = message.type >> 8
                m_type = message.type & 0xff
                if self.__subsystems.has_key(m_subsys):
                        self.__subsystems[m_subsys].dispatch(message)

        def create_message(self, subsys, type, flags = 0, data = ''):
                if not self.__subsystems.has_key(subsys):
                        raise NfnetlinkException, "no such subsystem registered"
                s = self.__subsystems[subsys]
                return NetlinkMessage((subsys << 8) + type, flags, s.next_seq(), self.local[0], data)

        def send(self, message, to):
                self.fd.sendto(message.dump(), to)

        def listen(self, handler):
                quit = False
                status = 0
                while not quit:
                        (answer, peer) = self.fd.recvfrom(MAX_NLMSGSIZE)
                        packet = PacketIn(answer)
                        messages = packet.get_messages()
                        for m in messages:
                                # check for special messages
                                if m.type == NLMSG_DONE:
                                        quit = True
                                        break
                                if m.type == NLMSG_ERROR:
                                        quit = True
                                        status = m.get_errorcode()
                                        break
                                # call handler
                                if callable(handler):
                                        handler(m)
                return status

        def talk(self, message, to, handler):
                self.fd.sendto(message.dump(), to)
                return self.listen(handler)

