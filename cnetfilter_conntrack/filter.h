#ifndef CNETFILTER_CONNTRACK_FILTER_H
#define CNETFILTER_CONNTRACK_FILTER_H

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define UNUSED(arg) arg __attribute__((unused))

struct filter_ipv4_t {
    struct in_addr first;
    struct in_addr last;
};

struct sort_t {
    int enabled;
    int order;
    int attrid;
};

struct filter_t {
    int drop_time_wait;

    unsigned int nb_ipv4;
    struct filter_ipv4_t *ipv4;

#if 0
    unsigned int nb_ipv6;
#endif
};

#endif
