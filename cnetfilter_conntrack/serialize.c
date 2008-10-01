#include <Python.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

/* from Objects/longobject.c */
#define IS_LITTLE_ENDIAN (int)*(unsigned char*)&one

static PyObject*
get_attr8(struct nf_conntrack *ct, int attrid)
{
    uint8_t value;
    value = nfct_get_attr_u8(ct, attrid);
    return PyLong_FromUnsignedLong(value);
}

static PyObject*
get_attr16(struct nf_conntrack *ct, int attrid, int ntoh)
{
    uint16_t value;
    value = nfct_get_attr_u16(ct, attrid);
    if (ntoh)
        value = ntohs(value);
    return PyLong_FromUnsignedLong(value);
}

static PyObject*
get_attr32(struct nf_conntrack *ct, int attrid, int ntoh)
{
    uint32_t value;
    value = nfct_get_attr_u32(ct, attrid);
    if (ntoh)
        value = ntohl(value);
    return PyLong_FromUnsignedLong(value);
}

static PyObject*
get_attr64(struct nf_conntrack *ct, int attrid)
{
    const int one = 1;
    const unsigned char *bytes;
    bytes = nfct_get_attr(ct, attrid);
    return _PyLong_FromByteArray(bytes, 8, IS_LITTLE_ENDIAN, 0);
}

static PyObject*
get_attr128(struct nf_conntrack *ct, int attrid)
{
    const int one = 1;
    const unsigned char *bytes;
    bytes = nfct_get_attr(ct, attrid);
    return _PyLong_FromByteArray(bytes, 16, IS_LITTLE_ENDIAN, 0);
}

static int
add_key(PyObject *dict, const char* name, PyObject* value)
{
    int err;
    if (!value)
        return 1;
    err = PyDict_SetItemString(dict, name, value);
    Py_DECREF(value);
    return err;
}

static PyObject*
serialize_connection(struct nf_conntrack *ct)
{
    PyObject *dict;
    uint8_t proto3, proto4;

    dict = PyDict_New();
    if (!dict)
        goto error;

    if (add_key(dict, "handle", PyLong_FromVoidPtr(ct)))
        goto error;

    proto3 = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
    if (add_key(dict, "orig_l3proto", PyLong_FromUnsignedLong(proto3)))
        goto error;

    if (proto3 == AF_INET) {
        if (add_key(dict, "orig_ipv4_src", get_attr32(ct, ATTR_ORIG_IPV4_SRC, 1)))
            goto error;
        if (add_key(dict, "orig_ipv4_dst", get_attr32(ct, ATTR_ORIG_IPV4_DST, 1)))
            goto error;
#ifdef EXTRAFIELDS
        if (add_key(dict, "repl_ipv4_src", get_attr32(ct, ATTR_REPL_IPV4_SRC, 1)))
            goto error;
        if (add_key(dict, "repl_ipv4_dst", get_attr32(ct, ATTR_REPL_IPV4_DST, 1)))
            goto error;
#endif
    } else if (proto3 == AF_INET6) {
        if (add_key(dict, "orig_ipv6_src", get_attr128(ct, ATTR_ORIG_IPV6_SRC)))
            goto error;
        if (add_key(dict, "orig_ipv6_dst", get_attr128(ct, ATTR_ORIG_IPV6_DST)))
            goto error;
#ifdef EXTRAFIELDS
        if (add_key(dict, "repl_ipv6_src", get_attr128(ct, ATTR_REPL_IPV6_SRC)))
            goto error;
        if (add_key(dict, "repl_ipv6_dst", get_attr128(ct, ATTR_REPL_IPV6_DST)))
            goto error;
#endif
    }

    proto4 = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    if (add_key(dict, "orig_l4proto", PyLong_FromUnsignedLong(proto4)))
        goto error;
    if (proto4 == IPPROTO_TCP || proto4 == IPPROTO_UDP) {
        if (add_key(dict, "orig_port_src", get_attr16(ct, ATTR_ORIG_PORT_SRC, 1)))
            goto error;
        if (add_key(dict, "orig_port_dst", get_attr16(ct, ATTR_ORIG_PORT_DST, 1)))
            goto error;
#ifdef EXTRAFIELDS
        if (add_key(dict, "repl_port_src", get_attr16(ct, ATTR_REPL_PORT_SRC, 1)))
            goto error;
        if (add_key(dict, "repl_port_dst", get_attr16(ct, ATTR_REPL_PORT_DST, 1)))
            goto error;
#endif
        if (proto4 == IPPROTO_TCP) {
            if (add_key(dict, "tcp_state", get_attr16(ct, ATTR_TCP_STATE, 1)))
                goto error;
#ifdef EXTRAFIELDS
            if (add_key(dict, "tcp_flags_orig", get_attr8(ct, ATTR_TCP_FLAGS_ORIG)))
                goto error;
            if (add_key(dict, "tcp_flags_repl", get_attr8(ct, ATTR_TCP_FLAGS_REPL)))
                goto error;
            if (add_key(dict, "tcp_mask_orig", get_attr8(ct, ATTR_TCP_MASK_ORIG)))
                goto error;
            if (add_key(dict, "tcp_mask_repl", get_attr8(ct, ATTR_TCP_MASK_REPL)))
                goto error;
#endif
        }
    } else if (proto4 == IPPROTO_ICMP || proto4 == IPPROTO_ICMPV6) {
        if (add_key(dict, "icmp_type", get_attr8(ct, ATTR_ICMP_TYPE)))
            goto error;
        if (add_key(dict, "icmp_code", get_attr8(ct, ATTR_ICMP_CODE)))
            goto error;
#ifdef EXTRAFIELDS
        if (add_key(dict, "icmp_id", get_attr16(ct, ATTR_ICMP_ID, 1)))
            goto error;
#endif
    }

    if (add_key(dict, "timeout", get_attr32(ct, ATTR_TIMEOUT, 0)))
        goto error;
    if (add_key(dict, "mark", get_attr32(ct, ATTR_MARK, 0)))
        goto error;

    if (add_key(dict, "orig_counter_packets", get_attr32(ct, ATTR_ORIG_COUNTER_PACKETS, 0)))
        goto error;
    if (add_key(dict, "repl_counter_packets", get_attr32(ct, ATTR_REPL_COUNTER_PACKETS, 0)))
        goto error;
    if (add_key(dict, "orig_counter_bytes", get_attr64(ct, ATTR_ORIG_COUNTER_BYTES)))
        goto error;
    if (add_key(dict, "repl_counter_bytes", get_attr64(ct, ATTR_REPL_COUNTER_BYTES)))
        goto error;

#ifdef EXTRAFIELDS
    if (add_key(dict, "use", get_attr32(ct, ATTR_USE, 1)))
        goto error;

    if (add_key(dict, "status", get_attr32(ct, ATTR_STATUS, 0)))
        goto error;
#endif

#if 0
    if (add_key(dict, "id", get_attr32(ct, ATTR_ID, 1)))
        goto error;
#endif

/*
 * TODO:
	ATTR_TCP_STATE
	ATTR_SNAT_IPV4
	ATTR_DNAT_IPV4
	ATTR_SNAT_PORT
	ATTR_DNAT_PORT

	ATTR_MASTER_IPV4_SRC
	ATTR_MASTER_IPV4_DST
	ATTR_MASTER_IPV6_SRC
	ATTR_MASTER_IPV6_DST
	ATTR_MASTER_PORT_SRC
	ATTR_MASTER_PORT_DST
	ATTR_MASTER_L3PROTO
	ATTR_MASTER_L4PROTO
	ATTR_SECMARK
	ATTR_ORIG_NAT_SEQ_CORRECTION_POS
	ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE
	ATTR_ORIG_NAT_SEQ_OFFSET_AFTER
	ATTR_REPL_NAT_SEQ_CORRECTION_POS
	ATTR_REPL_NAT_SEQ_OFFSET_BEFORE
	ATTR_REPL_NAT_SEQ_OFFSET_AFTER
 */

    return dict;

error:
    Py_XDECREF(dict);
    return NULL;
}

PyObject*
cnetfilter_serialize(struct nf_conntrack **conntracks, unsigned long size)
{
    PyObject *list;
    PyObject *item;
    unsigned long index;

    list = PyList_New(0);
    if (!list)
        return NULL;

    for (index=0; index < size; index++) {
        item = serialize_connection(conntracks[index]);
        if (!item)
            goto error;

        if (PyList_Append(list, item))
            goto error;
        Py_DECREF(item);
    }

    return list;

error:
    Py_DECREF(list);
    return NULL;
}

