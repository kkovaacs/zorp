#ifndef _IP_CONNTRACK_DYNEXPECT_H
#define _IP_CONNTRACK_DYNEXPECT_H

#define SO_DYNEXPECT_MAP 11281
#define SO_DYNEXPECT_EXPECT 11282
#define SO_DYNEXPECT_DESTROY 11283
#define SO_DYNEXPECT_MARK 11284

struct ip_ct_dynexpect_map
{
	u_int32_t mapping_id;
	u_int32_t orig_ip;
	u_int32_t new_ip;
	u_int16_t orig_port;
	u_int16_t n_ports;
	u_int16_t new_port;
	u_int8_t proto;
	u_int32_t n_active;
};

struct ip_ct_dynexpect_expect
{
	u_int32_t mapping_id;
	u_int32_t peer_ip;
	u_int16_t peer_port;
};

struct ip_ct_dynexpect_destroy
{
	u_int32_t mapping_id;
};

struct ip_ct_dynexpect_mark
{
	u_int32_t mapping_id;
	u_int32_t mark;
};

/* nat helper private information */
struct ip_ct_dyn_expect
{
	u_int32_t mapping_id;
};

#endif /* _IP_CONNTRACK_DYNEXPECT_H */
