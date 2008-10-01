#ifndef CNETFILTER_CONNTRACK_DUMP_H
#define CNETFILTER_CONNTRACK_DUMP_H

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <Python.h>

struct filter_t;

PyObject*
cnetfilter_dump_table(struct nfct_handle *handle, struct filter_t *filter, u_int8_t family);

#endif

