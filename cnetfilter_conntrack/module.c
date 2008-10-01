#include "filter.h"
#include "dump.h"
#include <Python.h>

char dump_table_DOCSTR[] =
"dump_table(handle, family=AF_INET) -> connection table\r\n"
"Raise a ValueError on error.\r\n"
"Returns a list a dict.\r\n";

static int
parse_networks(struct filter_t *filter, PyObject* networks)
{
    unsigned int index;
    PyObject *item;
    PyObject *firstobj;
    PyObject *lastobj;
    unsigned long ip;
    int err;

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

        printf("NETWORK #%u: %u..%u\n", index, filter->ipv4[index].first.s_addr, filter->ipv4[index].last.s_addr);
    }
    printf("TOTAL: %u\n", filter->nb_ipv4);
    return 0;

error:
    PyMem_Free(filter->ipv4);
    filter->ipv4 = NULL;
    return 1;
}

static PyObject*
dump_table_ipv4(PyObject* UNUSED(self), PyObject* args)
{
    struct nfct_handle *handle = NULL;
    PyObject* networks = NULL;
    struct filter_t filter;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "I|O:dump_table_ipv4", &handle, &networks))
        return NULL;

    filter.drop_time_wait = 1;
    if (networks) {
        if (parse_networks(&filter, networks))
            return NULL;
    } else {
        filter.nb_ipv4 = 0;
        filter.ipv4 = NULL;
    }

    result = cnetfilter_dump_table(handle, &filter, AF_INET);
    PyMem_Free(filter.ipv4);
    return result;
}

static PyMethodDef moduleMethods[] = {
    {"dump_table_ipv4", (PyCFunction)dump_table_ipv4, METH_VARARGS, dump_table_DOCSTR},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initcnetfilter_conntrack(void)
{
    (void)Py_InitModule3(
        "cnetfilter_conntrack",
        moduleMethods,
        "Python binding of libnetfilter_conntrack written in C");
}

