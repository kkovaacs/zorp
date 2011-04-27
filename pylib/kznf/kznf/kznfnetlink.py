import struct
from nfnetlink import *
import pprint

# message types
KZNL_MSG_START = 0
KZNL_MSG_COMMIT = 1
KZNL_MSG_FLUSH_ZONE = 2
KZNL_MSG_ADD_ZONE = 3
KZNL_MSG_ADD_ZONE_SVC_IN = 4
KZNL_MSG_ADD_ZONE_SVC_OUT = 5
KZNL_MSG_GET_ZONE = 6
KZNL_MSG_FLUSH_SERVICE = 7
KZNL_MSG_ADD_SERVICE = 8
KZNL_MSG_ADD_SERVICE_NAT_SRC = 9
KZNL_MSG_ADD_SERVICE_NAT_DST = 10
KZNL_MSG_GET_SERVICE = 11
KZNL_MSG_FLUSH_DISPATCHER = 12
KZNL_MSG_ADD_DISPATCHER = 13
KZNL_MSG_ADD_DISPATCHER_CSS = 14
KZNL_MSG_GET_DISPATCHER = 15
KZNL_MSG_COPY_ZONE_DAC = 16
KZNL_MSG_QUERY = 17
KZNL_MSG_ADD_RULE = 18
KZNL_MSG_ADD_RULE_ENTRY = 19
KZNL_MSG_MAX = 19

# attribute types
KZA_INVALID = 0
KZA_INSTANCE_NAME = 1
KZA_TR_PARAMS = 2
KZA_ZONE_PARAMS = 3
KZA_ZONE_NAME = 4
KZA_ZONE_UNAME = 5
KZA_ZONE_PNAME = 6
KZA_ZONE_RANGE = 7
KZA_SVC_PARAMS = 8
KZA_SVC_NAME = 9
KZA_SVC_ROUTER_DST = 10
KZA_SVC_NAT_SRC = 11
KZA_SVC_NAT_DST = 12
KZA_SVC_NAT_MAP = 13
KZA_SVC_SESSION_CNT = 14
KZA_DPT_PARAMS = 15
KZA_DPT_NAME = 16
KZA_DPT_BIND_ADDR = 17
KZA_DPT_BIND_IFACE = 18
KZA_DPT_BIND_IFGROUP = 19
KZA_DPT_CSS_CZONE = 20
KZA_DPT_CSS_SZONE = 21
KZA_DPT_CSS_SERVICE = 22
KZA_QUERY_PARAMS = 23
KZA_QUERY_CLIENT_ZONE = 24
KZA_QUERY_SERVER_ZONE = 25
KZA_DISPATCHER_N_DIMENSION_PARAMS = 26
KZA_N_DIMENSION_RULE_ID = 27
KZA_N_DIMENSION_RULE_SERVICE = 28
KZA_N_DIMENSION_AUTH = 29
KZA_N_DIMENSION_IFACE = 30
KZA_N_DIMENSION_PROTO = 31
KZA_N_DIMENSION_SRC_PORT = 32
KZA_N_DIMENSION_DST_PORT = 33
KZA_N_DIMENSION_SRC_IP = 34
KZA_N_DIMENSION_SRC_ZONE = 35
KZA_N_DIMENSION_DST_IP = 36
KZA_N_DIMENSION_DST_ZONE = 37
KZA_N_DIMENSION_IFGROUP = 38
KZA_N_DIMENSION_MAX = KZA_N_DIMENSION_IFGROUP
KZA_CONFIG_COOKIE = 39
KZA_MAX = 39

# name of global instance
KZ_INSTANCE_GLOBAL = ".global"

# transaction types
KZ_TR_TYPE_INVALID = 0
KZ_TR_TYPE_ZONE = 1
KZ_TR_TYPE_SERVICE = 2
KZ_TR_TYPE_DISPATCHER = 3

# zone flags
KZF_ZONE_UMBRELLA = 1

# service types
KZ_SVC_INVALID = 0
KZ_SVC_PROXY = 1
KZ_SVC_FORWARD = 2

# service flags
KZF_SVC_TRANSPARENT = 1
KZF_SVC_FORGE_ADDR = 2

# service NAT entry flags
KZ_SVC_NAT_MAP_IPS = 1
KZ_SVC_NAT_MAP_PROTO_SPECIFIC = 2

# dispatcher types
KZ_DPT_TYPE_INVALID = 0
KZ_DPT_TYPE_INET = 1
KZ_DPT_TYPE_IFACE = 2
KZ_DPT_TYPE_IFGROUP = 3
KZ_DPT_TYPE_N_DIMENSION = 4

# dispatcher flags
KZF_DPT_TRANSPARENT = 1
KZF_DPT_FOLLOW_PARENT = 2

# dispatcher bind address port ranges
KZF_DPT_PORT_RANGE_SIZE = 8

###########################################################################
# helper functions to create/parse kzorp attributes
###########################################################################
def create_name_attr(type, name):
        data = "".join((struct.pack('>H', len(name)), name))
        return NfnetlinkAttribute(type, data)

def parse_name_attr(attr):
        (len,) = struct.unpack('>H', attr.get_data()[:2])
        (name,) = struct.unpack(str(len) + 's', attr.get_data()[2 : 2 + len])
        return name

def create_int8_attr(type, value):
        return NfnetlinkAttribute(type, struct.pack('B', value))

def parse_int8_attr(attr):
        (value,) = struct.unpack('B', attr.get_data()[0])
        return value

def create_int16_attr(type, value):
        return NfnetlinkAttribute(type, struct.pack('>H', value))

def parse_int16_attr(attr):
        (value,) = struct.unpack('>H', attr.get_data()[0])
        return value

def create_int32_attr(type, value):
        return NfnetlinkAttribute(type, struct.pack('>I', value))

def parse_int32_attr(attr):
        (value,) = struct.unpack('>I', attr.get_data()[:4])
        return value

def create_int64_attr(type, value):
        return NfnetlinkAttribute(type, struct.pack('>Q', value))

def parse_int64_attr(attr):
        (value,) = struct.unpack('>Q', attr.get_data()[:8])
        return value

def create_inet_range_attr(type, address, mask):
        return NfnetlinkAttribute(type, struct.pack('>II', address, mask))

def parse_inet_range_attr(attr):
        return struct.unpack('>II', attr.get_data()[:8])

def create_port_range_attr(type, range_from, range_to):
        return NfnetlinkAttribute(type, struct.pack('>HH', range_from, range_to))

def parse_port_range_attr(attr):
        return struct.unpack('>HH', attr.get_data()[:4])

def create_nat_range_attr(type, flags, min_ip, max_ip, min_port, max_port):
        data = struct.pack('>IIIHH', flags, min_ip, max_ip, min_port, max_port)
        return NfnetlinkAttribute(type, data)

def parse_nat_range_attr(attr):
        return struct.unpack('>IIIHH', attr.get_data()[:16])

def create_address_attr(type, proto, ip, port):
        return NfnetlinkAttribute(type, struct.pack('>IHB', ip, port, proto))

def parse_address_attr(attr):
        return struct.unpack('>IHB', attr.get_data()[:7])

def create_bind_addr_attr(type, proto, ip, ports):
        if len(ports) > KZF_DPT_PORT_RANGE_SIZE:
                raise ValueError, "bind address contains too many port ranges, %s allowed" % KZF_DPT_PORT_RANGE_SIZE
        data = struct.pack('>I', ip)
        for r in ports:
                data = "".join((data, struct.pack('>HH', r[0], r[1])))
        if len(ports) < KZF_DPT_PORT_RANGE_SIZE:
                data = "".join((data, "\0" * 4 * (KZF_DPT_PORT_RANGE_SIZE - len(ports))))
        data = "".join((data, struct.pack('BB', len(ports), proto)))
        return NfnetlinkAttribute(type, data)

def parse_bind_addr_attr(attr):
        (addr,) = struct.unpack('>I', attr.get_data()[:4])
        (num_ports, proto) = struct.unpack('BB', attr.get_data()[36:38])
        ports = []
        for i in range(num_ports):
                (start, end) = struct.unpack('>HH', attr.get_data()[4 + 4 * i : 8 + 4 * i])
                ports.append((start, end))
        return (proto, addr, ports)

def create_bind_iface_attr(type, proto, iface, ports, pref_addr):
        if len(ports) > KZF_DPT_PORT_RANGE_SIZE:
                raise ValueError, "bind address contains too many port ranges, %s allowed" % KZF_DPT_PORT_RANGE_SIZE
        data = struct.pack('>I', pref_addr)
        for r in ports:
                data = "".join((data, struct.pack('>HH', r[0], r[1])))
        if len(ports) < KZF_DPT_PORT_RANGE_SIZE:
                data = "".join((data, "\0" * 4 * (KZF_DPT_PORT_RANGE_SIZE - len(ports))))

        data = "".join((data, struct.pack('BB', len(ports), proto), iface, "\0" * (16 - len(iface))))
        return NfnetlinkAttribute(type, data)

def parse_bind_iface_attr(attr):
        (pref_addr,) = struct.unpack('>I', attr.get_data()[:4])
        (num_ports, proto) = struct.unpack('BB', attr.get_data()[36:38])
        ports = []
        for i in range(num_ports):
                (start, end) = struct.unpack('>HH', attr.get_data()[4 + 4 * i : 8 + 4 * i])
                ports.append((start, end))
        iface = attr.get_data()[38:].rstrip("\0")
        return (proto, iface, ports, pref_addr)

def create_bind_ifgroup_attr(type, proto, group, mask, ports, pref_addr):
        if len(ports) > KZF_DPT_PORT_RANGE_SIZE:
                raise ValueError, "bind address contains too many port ranges, %s allowed" & KZF_DPT_PORT_RANGE_SIZE
        data = struct.pack('>III', group, mask, pref_addr)
        for r in ports:
                data = "".join((data, struct.pack('>HH', r[0], r[1])))
        if len(ports) < KZF_DPT_PORT_RANGE_SIZE:
                data = "".join((data, "\0" * 4 * (KZF_DPT_PORT_RANGE_SIZE - len(ports))))

        data = "".join((data, struct.pack('BB', len(ports), proto)))
        return NfnetlinkAttribute(type, data)

def parse_bind_ifgroup_attr(attr):
        (group, mask, pref_addr) = struct.unpack('>III', attr.get_data()[:12])
        (num_ports, proto) = struct.unpack('BB', attr.get_data()[44:46])
        ports = []
        for i in range(num_ports):
                (start, end) = struct.unpack('>HH', attr.get_data()[12 + 4 * i : 16 + 4 * i])
                ports.append((start, end))
        return (proto, group, mask, ports, pref_addr)

def parse_n_dimension_attr(attr):
        (num_rules, ) = struct.unpack('>I', attr.get_data()[:4])
        return num_rules

def parse_rule_attrs(attr):
        (rule_id, ) = struct.unpack('>I', attr[KZA_N_DIMENSION_RULE_ID].get_data()[:4])
        service = parse_name_attr(attr[KZA_N_DIMENSION_RULE_SERVICE])
        rules = {}

        for dim_type in xrange(KZA_N_DIMENSION_AUTH, KZA_N_DIMENSION_MAX + 1):
          if attr and attr.has_key(dim_type):
            data = attr[dim_type].get_data()
	    value = struct.unpack('>I', data[:4])
            rules[dim_type] = value

        return (rule_id, service, rules)

def parse_rule_entry_attrs(attr):
        (rule_id, ) = struct.unpack('>I', attr[KZA_N_DIMENSION_RULE_ID].get_data()[:4])
        rule_entries = {}

        for dim_type in xrange(KZA_N_DIMENSION_AUTH, KZA_N_DIMENSION_MAX + 1):
          if attr and attr.has_key(dim_type):
            data = attr[dim_type].get_data()

            if dim_type == KZA_N_DIMENSION_AUTH or \
               dim_type == KZA_N_DIMENSION_PROTO:
              value = struct.unpack('>B', data[:1])
            elif dim_type == KZA_N_DIMENSION_DST_PORT or \
                 dim_type == KZA_N_DIMENSION_SRC_PORT:
              value = parse_port_range_attr(attr[dim_type])
            elif dim_type == KZA_N_DIMENSION_DST_IP or \
                 dim_type == KZA_N_DIMENSION_SRC_IP:
              value = parse_inet_range_attr(attr[dim_type])
            elif dim_type == KZA_N_DIMENSION_IFGROUP:
              value =struct.unpack('>I',  data[:4])
            elif dim_type == KZA_N_DIMENSION_IFACE    or \
                 dim_type == KZA_N_DIMENSION_DST_ZONE or \
                 dim_type == KZA_N_DIMENSION_SRC_ZONE:
              value = (parse_name_attr(attr[dim_type]), )
            else:
                raise ValueError, "dispatcher dimension type is invalid; type='%d'" % dim_type
            rule_entries[dim_type] = value

        return (rule_id, rule_entries)

def create_dispatcher_params_attr(type, dpt_type, dpt_flags, proxy_port):
        return NfnetlinkAttribute(type, struct.pack('>IHB', dpt_flags, proxy_port, dpt_type))

def parse_dispatcher_params_attr(attr):
        return struct.unpack('>IHB', attr.get_data()[:7])

def create_service_params_attr(type, svc_type, svc_flags):
        return NfnetlinkAttribute(type, struct.pack('>IB', svc_flags, svc_type))

def parse_service_params_attr(attr):
        return struct.unpack('>IB', attr.get_data()[:5])

def create_query_params_attr(type, proto, saddr, sport, daddr, dport, iface):
        data = struct.pack('>IIHH', saddr, daddr, sport, dport)
        data = "".join((data, iface, "\0" * (16 - len(iface)), struct.pack('>B', proto)))
        return NfnetlinkAttribute(type, data)


###########################################################################
# helper functions to assemble kzorp messages
###########################################################################
def create_start_msg(type, name, config_cookie=0):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_name_attr(KZA_INSTANCE_NAME, name))
        m.append_attribute(create_int8_attr(KZA_TR_PARAMS, type))
        if (config_cookie > 0):
                m.append_attribute(create_int64_attr(KZA_CONFIG_COOKIE, config_cookie))
        return m

def create_commit_msg():
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        return m
        
def create_flush_msg():
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        return m

# service
def create_add_proxyservice_msg(name):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_service_params_attr(KZA_SVC_PARAMS, KZ_SVC_PROXY, 0))
        m.append_attribute(create_name_attr(KZA_SVC_NAME, name))
        return m

def create_add_pfservice_msg(name, flags, dst_ip = None, dst_port = None):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_service_params_attr(KZA_SVC_PARAMS, KZ_SVC_FORWARD, flags))
        m.append_attribute(create_name_attr(KZA_SVC_NAME, name))
        if dst_ip and dst_port:
                m.append_attribute(create_address_attr(KZA_SVC_ROUTER_DST, 0, dst_ip, dst_port))
        return m

def create_add_service_nat_msg(name, mapping):
        # mapping is a tuple: (src, dst, map)
        # elements are tuples: (flags, min_ip, max_ip, min_port, max_port)
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_name_attr(KZA_SVC_NAME, name))
        (src, dst, map) = mapping
        m.append_attribute(create_nat_range_attr(KZA_SVC_NAT_SRC, src[0], src[1], src[2], src[3], src[4]))
        if dst:
                m.append_attribute(create_nat_range_attr(KZA_SVC_NAT_DST, dst[0], dst[1], dst[2], dst[3], dst[4]))
        m.append_attribute(create_nat_range_attr(KZA_SVC_NAT_MAP, map[0], map[1], map[2], map[3], map[4]))
        return m

def create_get_service_msg(name):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        if name:
                m.append_attribute(create_name_attr(KZA_SVC_NAME, name))
        return m


# zone
def create_add_zone_msg(name, flags, address = None, mask = None, uname = None, pname = None):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_int32_attr(KZA_ZONE_PARAMS, flags))
        m.append_attribute(create_name_attr(KZA_ZONE_NAME, name))
        if uname != None:
                m.append_attribute(create_name_attr(KZA_ZONE_UNAME, uname))
        if pname != None:
                m.append_attribute(create_name_attr(KZA_ZONE_PNAME, pname))
        if address != None and mask != None:
                m.append_attribute(create_inet_range_attr(KZA_ZONE_RANGE, address, mask))
        return m

def create_add_zone_svc_msg(name, service):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_name_attr(KZA_ZONE_UNAME, name))
        m.append_attribute(create_name_attr(KZA_SVC_NAME, service))
        return m

def create_get_zone_msg(name):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        if name:
                m.append_attribute(create_name_attr(KZA_ZONE_UNAME, name))
        return m

# dispatcher
def create_add_dispatcher_sabind_msg(name, flags, proto, proxy_port, rule_addr, rule_ports):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_dispatcher_params_attr(KZA_DPT_PARAMS, KZ_DPT_TYPE_INET, flags, proxy_port))
        m.append_attribute(create_name_attr(KZA_DPT_NAME, name))
        m.append_attribute(create_bind_addr_attr(KZA_DPT_BIND_ADDR, proto, rule_addr, rule_ports))
        return m
        
def create_add_dispatcher_ifacebind_msg(name, flags, proto, proxy_port, ifname, rule_ports, pref_addr = None):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_dispatcher_params_attr(KZA_DPT_PARAMS, KZ_DPT_TYPE_IFACE, flags, proxy_port))
        m.append_attribute(create_name_attr(KZA_DPT_NAME, name))
        if not pref_addr:
                pref_addr = 0
        m.append_attribute(create_bind_iface_attr(KZA_DPT_BIND_IFACE, proto, ifname, rule_ports, pref_addr))
        return m

def create_add_dispatcher_ifgroupbind_msg(name, flags, proto, proxy_port, ifgroup, ifmask, rule_ports, pref_addr = None):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_dispatcher_params_attr(KZA_DPT_PARAMS, KZ_DPT_TYPE_IFGROUP, flags, proxy_port))
        m.append_attribute(create_name_attr(KZA_DPT_NAME, name))
        if not pref_addr:
                pref_addr = 0
        m.append_attribute(create_bind_ifgroup_attr(KZA_DPT_BIND_IFGROUP, proto, ifgroup, ifmask, rule_ports, pref_addr))
        return m

def create_add_dispatcher_n_dimension(name, flags, proxy_port, num_rules):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_dispatcher_params_attr(KZA_DPT_PARAMS, KZ_DPT_TYPE_N_DIMENSION, flags, proxy_port))
        m.append_attribute(create_name_attr(KZA_DPT_NAME, name))
        m.append_attribute(create_int32_attr(KZA_DISPATCHER_N_DIMENSION_PARAMS, num_rules))
        return m

def create_add_n_dimension_rule_msg(dpt_name, rule_id, service, entry_nums):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_name_attr(KZA_DPT_NAME, dpt_name))
        m.append_attribute(create_int32_attr(KZA_N_DIMENSION_RULE_ID, rule_id))
        m.append_attribute(create_name_attr(KZA_N_DIMENSION_RULE_SERVICE, service))

        for dim_type in xrange(KZA_N_DIMENSION_AUTH, KZA_N_DIMENSION_MAX + 1):
          if entry_nums and entry_nums.has_key(dim_type):
            dim_size = entry_nums[dim_type]
	    m.append_attribute(create_int32_attr(dim_type, dim_size))

        return m

def create_add_n_dimension_rule_entry_msg(dpt_name, rule_id, entry_values):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_name_attr(KZA_DPT_NAME, dpt_name))
        m.append_attribute(create_int32_attr(KZA_N_DIMENSION_RULE_ID, rule_id))

        for dim_type, value in entry_values.items():
          if dim_type == KZA_N_DIMENSION_AUTH or \
             dim_type == KZA_N_DIMENSION_PROTO:
            m.append_attribute(create_int8_attr(dim_type, value))
          elif dim_type == KZA_N_DIMENSION_DST_PORT or \
               dim_type == KZA_N_DIMENSION_SRC_PORT:
            m.append_attribute(create_port_range_attr(dim_type, value[0], value[1]))
          elif dim_type == KZA_N_DIMENSION_DST_IP or \
               dim_type == KZA_N_DIMENSION_SRC_IP:
            m.append_attribute(create_inet_range_attr(dim_type, value[0], value[1]))
          elif dim_type == KZA_N_DIMENSION_IFGROUP:
            m.append_attribute(create_int32_attr(dim_type, value))
          elif dim_type == KZA_N_DIMENSION_IFACE    or \
               dim_type == KZA_N_DIMENSION_DST_ZONE or \
               dim_type == KZA_N_DIMENSION_SRC_ZONE:
            m.append_attribute(create_name_attr(dim_type, value))
          else:
            raise ValueError, "dispatcher dimension type is invalid; type='%d'" % dim_type

        return m

def create_add_dispatcher_css_msg(name, service, czone = None, szone = None):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_name_attr(KZA_DPT_NAME, name))
        if czone and czone != '*':
                m.append_attribute(create_name_attr(KZA_DPT_CSS_CZONE, czone))
        if szone and szone != '*':
                m.append_attribute(create_name_attr(KZA_DPT_CSS_SZONE, szone))
        m.append_attribute(create_name_attr(KZA_DPT_CSS_SERVICE, service))
        return m

def create_get_dispatcher_msg(name):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        if name:
                m.append_attribute(create_name_attr(KZA_DPT_NAME, name))
        return m

def create_query_msg(proto, saddr, sport, daddr, dport, iface):
        m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
        m.append_attribute(create_query_params_attr(KZA_QUERY_PARAMS, proto, saddr, sport, daddr, dport, iface))
        return m
