import socket

error = 'test error'

def test_attr_ro(o, attr_name, default_value):
        if getattr(o, attr_name) != default_value:
                print "bad default value for attr %s, value %s, default %s" % (attr_name, getattr(o, attr_name), default_value)
                raise error

def test_attr_rw(o, attr_name, default_value, mod_value):
        test_attr_ro(o, attr_name, default_value)

        setattr(o, attr_name, mod_value)

        if getattr(o, attr_name) != mod_value:
                print "bad changed value for attr %s, value %s, default %s" % (attr_name, getattr(o, attr_name), mod_value)
                raise error


def test_sockaddr(sa):

        test_attr_ro(sa, 'family', 2)
        test_attr_ro(sa, 'type', 'inet')
        test_attr_ro(sa, 'ip', socket.htonl(0xc0a80101))
        test_attr_rw(sa, 'ip_s', '192.168.1.1', '192.168.2.1')
        test_attr_ro(sa, 'ip', socket.htonl(0xc0a80201))
        test_attr_rw(sa, 'port', 59999, 60000)

        try:
                sa.type = 'qqq'
                raise error
        except AttributeError:
                pass
        try:
                sa.family = 5
                raise error
        except AttributeError:
                pass
        if sa.format() != 'AF_INET(192.168.2.1:60000)':
                return 0
        
        if sa.clone(0).format() != 'AF_INET(192.168.2.1:60000)':
                return 0
        
        clone = sa.clone(0)
                
        if not sa.equal(clone):
                return 0
                
        clone.port = 55555

        if sa.equal(clone):
                return 0
        
        return 1
        
def test_dict(d):
        test_attr_rw(d, 'simple_int', 55555, 44444)
        test_attr_rw(d, 'literal_int', 66666, 77777)
        test_attr_rw(d, 'simple_str', 'abcdef', 'kukutyin1')
        test_attr_rw(d, 'literal_str', 'abrakadabra', 'kukutyin2')
        test_attr_rw(d, 'simple_cstr', 'huligan', 'kukutyin3')
        test_attr_ro(d, 'literal_cstr_ro', 'viharkeszulodik')
        test_attr_rw(d, 'literal_cstr', 'viharkeszulodik2', 'kismacska3')
        test_attr_rw(d, 'simple_ip', socket.htonl(0xc0a80506), socket.htonl(0xc0a80508))
        test_attr_rw(d, 'simple_ip_str', '192.168.5.8', '192.168.8.9')
        test_attr_ro(d, 'simple_ip', socket.htonl(0xc0a80809))
        test_attr_rw(d, 'alias', 'kukutyin1', 'masvalami')

        test_sockaddr(d.simple_obj)


        if not (d.custom == 0 and d.custom == 1 and d.custom == 2):
                raise error
        d.custom = 55
        if not (d.custom == 0 and d.custom == 1 and d.custom == 2):
                raise error
        

        return 1


