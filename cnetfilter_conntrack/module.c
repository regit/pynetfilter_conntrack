#include "filter.h"
#include "dump.h"
#include <Python.h>

char dump_table_ipv4_DOCSTR[] =
"dump_table_ipv4(handle, drop_networks=None, sort=None, reverse=False) -> connection table\r\n"
"drop_networks is a tuple of (first_ip, last_ip) tuples where ips are long integers.\r\n"
"sort is a string in: \"orig_ipv4_src\", \"orig_ipv4_dst\".\r\n"
"Raise a ValueError on error.\r\n"
"Returns a list a dict.\r\n";

struct sort_attr_t {
    const char* name;
    int attrid;
} sort_attributes[] = {
    {"orig_ipv4_src", ATTR_ORIG_IPV4_SRC},
    {"orig_ipv4_dst", ATTR_ORIG_IPV4_DST},
    {NULL, 0}
};

static int
parse_networks(struct filter_t *filter, PyObject* networks)
{
    unsigned int index;
    PyObject *item;
    PyObject *firstobj;
    PyObject *lastobj;
    unsigned long ip;
    int err;

    if (networks == Py_None)
        return 0;

    if (!PyTuple_Check(networks)) {
        PyErr_Format(PyExc_TypeError,
                "networks should be a tuple");
        return 1;
    }
    filter->nb_ipv4 = PyTuple_Size(networks);
    if (!filter->nb_ipv4)
        return 0;
    filter->ipv4 = PyMem_Malloc(sizeof(filter->ipv4[0]) * filter->nb_ipv4);
    if (!filter->ipv4) {
        PyErr_NoMemory();
        return 1;
    }
    for (index=0; index < filter->nb_ipv4; index++) {
        item = PyTuple_GetItem(networks, index);
        if (!item)
            goto error;
        if (PyTuple_Check(item) && PyTuple_Size(item) == 2) {
            err = 0;
            firstobj = PyTuple_GetItem(item, 0);
            if (!firstobj)
                err = 1;
            else if (!PyLong_Check(firstobj))
                err = 1;
            else
                err = 0;
            if (!err) {
                lastobj = PyTuple_GetItem(item, 1);
                if (!lastobj)
                    err = 1;
                else if (!PyLong_Check(lastobj))
                    err = 1;
                else
                    err = 0;
            }
        } else {
            err = 1;
        }
        if (err) {
            PyErr_Format(PyExc_TypeError,
                    "network #%u is not a tuple of 2 long integers",
                    index);
            return 1;
        }
        ip = PyLong_AsUnsignedLong(firstobj);
        if (ip == (unsigned long)-1 && PyErr_Occurred())
            return 1;
        filter->ipv4[index].first.s_addr = ip;

        ip = PyLong_AsUnsignedLong(lastobj);
        if (ip == (unsigned long)-1 && PyErr_Occurred())
            return 1;
        filter->ipv4[index].last.s_addr = ip;
    }
    return 0;

error:
    PyMem_Free(filter->ipv4);
    filter->ipv4 = NULL;
    return 1;
}

static PyObject*
dump_table_ipv4(PyObject* UNUSED(self), PyObject* args, PyObject* kwargs)
{
    struct nfct_handle *handle = NULL;
    PyObject* networks = NULL;
    struct filter_t filter;
    struct sort_t sort;
    PyObject *result;
    int reverse;
    unsigned long start;
    unsigned long size;
    const char* sort_name = NULL;
    struct sort_attr_t *sort_it;
    static char* kwnames[] = { "handle", "start", "size", "drop_networks", "sort", "reverse", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
    "I|kkOsI:dump_table_ipv4", kwnames,
    &handle, &start, &size, &networks, &sort_name, &reverse))
        return NULL;

    filter.drop_time_wait = 1;
    if (networks) {
        if (parse_networks(&filter, networks))
            return NULL;
    } else {
        filter.nb_ipv4 = 0;
        filter.ipv4 = NULL;
    }

    sort.enabled = 0;
    if (reverse)
        sort.order = -1;
    else
        sort.order = 1;
    if (sort_name) {
        for (sort_it=sort_attributes; sort_it->name; sort_it++) {
            if (strcmp(sort_it->name, sort_name) == 0) {
                sort.enabled = 1;
                sort.attrid = sort_it->attrid;
                break;
            }
        }
        if (!sort.enabled) {
            PyErr_Format(PyExc_ValueError, "unknown sort attribute: \"%s\"", sort_name);
            return NULL;
        }
    }

    result = cnetfilter_dump_table(handle, AF_INET, start, size, &filter, &sort);
    PyMem_Free(filter.ipv4);
    return result;
}

static PyMethodDef moduleMethods[] = {
    {"dump_table_ipv4", (PyCFunction)dump_table_ipv4, METH_VARARGS | METH_KEYWORDS, dump_table_ipv4_DOCSTR},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initcnetfilter_conntrack(void)
{
    (void)Py_InitModule3(
        "cnetfilter_conntrack",
        moduleMethods,
        "Python binding of libnetfilter_conntrack written in C");
}

