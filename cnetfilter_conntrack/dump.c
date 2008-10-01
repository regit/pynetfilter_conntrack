#include "dump.h"
#include "filter.h"   /* UNUSED */
#include <stdlib.h>   /* qsort() */

/* prototypes */
int cnetfilter_filter(struct nf_conntrack *ct, struct filter_t *filter);
PyObject* cnetfilter_serialize(struct nf_conntrack **conntracks, unsigned long size);

/* FIXME: This is not thread safe! */
struct sort_t* global_sort;

struct dump_table_t {
    struct filter_t* filter;
    int err;
    unsigned long list_size;
    unsigned long list_alloc;
    struct nf_conntrack **list;
};

static int
callback(enum nf_conntrack_msg_type UNUSED(type), struct nf_conntrack *ct, void *data)
{
    struct dump_table_t *dump = data;
    unsigned long index;

    if (cnetfilter_filter(ct, dump->filter)) {
        /* drop the connection */
        return NFCT_CB_CONTINUE;
    }

    index = dump->list_size;
    dump->list_size += 1;
    if (dump->list_alloc < dump->list_size) {
        struct nf_conntrack **newlist;
        dump->list_alloc = dump->list_size * 3 / 2;
        newlist = PyMem_Realloc(dump->list, sizeof(dump->list[0]) * dump->list_alloc);
        if (!newlist) {
            PyErr_NoMemory();
            goto error;
        }
        dump->list = newlist;
    }

    dump->list[index] = ct;
    return NFCT_CB_STOLEN;

error:
    dump->err = 1;
    return NFCT_CB_STOP;
}

int sort_compare(const void *a, const void* b)
{
    int attrid = global_sort->attrid;
    int order = global_sort->order;
    const struct nf_conntrack *cta = *(const struct nf_conntrack **)a;
    const struct nf_conntrack *ctb = *(const struct nf_conntrack **)b;
    if (attrid == ATTR_ORIG_IPV4_SRC || attrid == ATTR_ORIG_IPV4_DST) {
        uint32_t ipa, ipb;
        ipa = nfct_get_attr_u32(cta, attrid);
        ipa = ntohl(ipa);
        ipb = nfct_get_attr_u32(ctb, attrid);
        ipb = ntohl(ipb);
        if (ipa < ipb)
            return -order;
        else if (ipa > ipb)
            return order;
    }
    return 0;
}

PyObject*
cnetfilter_dump_table(
    struct nfct_handle *handle, u_int8_t family,
    unsigned long start, unsigned long maxsize,
    struct filter_t *filter, struct sort_t *sort)
{
    int event_type = NFCT_T_ALL;
    int ret;
    PyObject* result;
    struct dump_table_t dump;
    unsigned long size;

    /* prepare our object */
    dump.filter = filter;
    dump.err = 0;
    dump.list_size = 0;
    dump.list_alloc = 16;
    dump.list = PyMem_Malloc(sizeof(dump.list[0]) * dump.list_alloc);
    if (!dump.list) {
        PyErr_NoMemory();
        return NULL;
    }

    /*
     * create a list of handles (PyLong objects),
     * filter unwanted connections during the creation
     */
    (void)nfct_callback_register(handle, event_type, callback, &dump);
    ret = nfct_query(handle, NFCT_Q_DUMP, &family);
    if (dump.err) {
        goto error;
    }
    if (ret != 0) {
        PyErr_Format(PyExc_ValueError, "nfct_query() failure: %s", strerror(errno));
        goto error;
    }
    (void)nfct_callback_unregister(handle);

    /* sort */
    if (sort->enabled) {
        global_sort = sort;
        qsort(dump.list, dump.list_size, sizeof(dump.list[0]), sort_compare);
        global_sort = NULL;
    }

    /* list of handles => list of dict */
    if (dump.list_size < start) {
        start = 0;
        size = 0;
    } else if (start + maxsize < dump.list_size) {
        size = maxsize;
    } else {
        size = dump.list_size - start;
    }
    result = cnetfilter_serialize(&dump.list[start], size);
    if (!result)
        goto error;

    PyMem_Free(dump.list);
    return Py_BuildValue("(Ok)", result, dump.list_size);

error:
    PyMem_Free(dump.list);
    return NULL;
}

