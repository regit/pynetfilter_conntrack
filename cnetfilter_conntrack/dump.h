#ifndef CNETFILTER_CONNTRACK_DUMP_H
#define CNETFILTER_CONNTRACK_DUMP_H

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <Python.h>

struct filter_t;
struct sort_t;

PyObject*
cnetfilter_dump_table(
    struct nfct_handle *handle, u_int8_t family,
    unsigned long start, unsigned long size,
    struct filter_t *filter, struct sort_t *sort);

#endif

