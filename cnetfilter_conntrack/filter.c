#include "filter.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

int
cnetfilter_filter(struct nf_conntrack *ct, struct filter_t *filter)
{
    uint8_t proto3, proto4;
    unsigned int i;
    if (filter->drop_time_wait) {
        proto4 = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
        if (proto4 == IPPROTO_TCP) {
            uint16_t tcp_state = nfct_get_attr_u16(ct, ATTR_TCP_STATE);
            tcp_state = ntohs(tcp_state);
            if (tcp_state == TCP_CONNTRACK_TIME_WAIT)
                return 1;
        }
    }
    proto3 = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
    if (proto3 == AF_INET) {
        uint32_t ipv4 = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
        ipv4 = ntohl(ipv4);
        for (i=0; i<filter->nb_ipv4; i++) {
            if (filter->ipv4[i].first.s_addr <= ipv4 && ipv4 <= filter->ipv4[i].last.s_addr) {
                return 1;
            }
        }
    }
    return 0;
}

