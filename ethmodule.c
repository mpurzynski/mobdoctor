#include <python3.7m/Python.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <stdint.h>

static PyObject * send_cmd(char *data, char *ifname)
{
    uint32_t skfd = 0;
    struct ifreq ifr;

    if (( skfd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 )
    {
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)-1);
    ifr.ifr_data = data;
    
    if (ioctl(skfd, SIOCETHTOOL, &ifr) < 0)
    {
        PyErr_SetFromErrno(PyExc_IOError);
        close(skfd);
        return NULL;
    }
}

static PyObject * eth_stat(PyObject *self, PyObject *args)
{
    uint32_t i = 0;
    uint32_t err = 0;
    uint32_t skfd;
    uint32_t n_stats = 0;
    uint64_t sz_str;
    uint64_t sz_stats;
    char *ifname;
    struct ethtool_drvinfo drvinfo;
    struct ethtool_gstrings *strings = NULL;
    struct ethtool_stats *stats = NULL;
    struct ethtool_value values;
    struct ethtool_ringparam ringinfo;
    struct ethtool_pauseparam pauseinfo;
    struct ethtool_channels queuesinfo;
    struct ifreq ifr;
    char *data = NULL;
    uint32_t eth_num_cmds = 7;
    int offload_cmds[] = {ETHTOOL_GTSO, ETHTOOL_GUFO, ETHTOOL_GGSO, ETHTOOL_GGRO, ETHTOOL_GSG, ETHTOOL_GRXCSUM, ETHTOOL_GLINK};
    char *offload_names[] = {"tso", "ufo", "gso", "gro", "sg", "checksum", "link"};
    PyObject *k = NULL;
    PyObject *v = NULL;

    if (!PyArg_ParseTuple(args, "s", &ifname))
    	return NULL;
    
    PyObject *d = PyDict_New();

    // Any socket will do
    if (( skfd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 )
    {
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)-1);

    drvinfo.cmd = ETHTOOL_GDRVINFO;
    data = (caddr_t) &drvinfo;
    send_cmd(data, ifname);

    n_stats = drvinfo.n_stats;
    sz_str = n_stats * ETH_GSTRING_LEN;
    sz_stats = n_stats * sizeof(uint64_t);
    // FIXME exception handling - return python no memory
    strings = calloc(1, sz_str + sizeof(struct ethtool_gstrings));
    stats = calloc(1, sz_stats + sizeof(struct ethtool_stats));

    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_STATS;
    strings->len = n_stats;
    data = (caddr_t) strings;
    send_cmd(data, ifname);

    stats->cmd = ETHTOOL_GSTATS;
    stats->n_stats = n_stats;
    data = (caddr_t) stats;
    send_cmd(data, ifname);

    for (i = 0; i < n_stats; i++) {
    	k = PyUnicode_FromString((char *)&strings->data[i * ETH_GSTRING_LEN]);
    	v = PyLong_FromUnsignedLongLong(stats->data[i]);
    	PyDict_SetItem(d, k, v);
    }

    for (i = 0; i < eth_num_cmds; i++) {
        values.cmd = offload_cmds[i];
	ifr.ifr_data = (caddr_t) &values;
	ioctl(skfd, SIOCETHTOOL, &ifr);

        k = PyUnicode_FromString(offload_names[i]);
        v = PyLong_FromUnsignedLongLong(values.data);
        PyDict_SetItem(d, k, v);
    }

    values.cmd = ETHTOOL_GFLAGS;
    ifr.ifr_data = (caddr_t) &values;
    ioctl(skfd, SIOCETHTOOL, &ifr);
    k = PyUnicode_FromString("lro");
    v = PyLong_FromUnsignedLongLong(0);
    if (values.data & ETH_FLAG_LRO)
    {
        v = PyLong_FromUnsignedLongLong(1);
    }
    PyDict_SetItem(d, k, v);

    ringinfo.cmd = ETHTOOL_GRINGPARAM;
    ifr.ifr_data = (caddr_t) &ringinfo;
    ioctl(skfd, SIOCETHTOOL, &ifr);
    k = PyUnicode_FromString("rx_max_pending");
    v = PyLong_FromUnsignedLongLong(ringinfo.rx_max_pending);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("rx_pending");
    v = PyLong_FromUnsignedLongLong(ringinfo.rx_pending);
    PyDict_SetItem(d, k, v);

    pauseinfo.cmd = ETHTOOL_GPAUSEPARAM;
    ifr.ifr_data = (caddr_t) &pauseinfo;
    ioctl(skfd, SIOCETHTOOL, &ifr);
    k = PyUnicode_FromString("rx_pause");
    v = PyLong_FromUnsignedLongLong(pauseinfo.rx_pause);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("tx_pause");
    v = PyLong_FromUnsignedLongLong(pauseinfo.tx_pause);
    PyDict_SetItem(d, k, v);

    queuesinfo.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (caddr_t) &queuesinfo;
    ioctl(skfd, SIOCETHTOOL, &ifr);
    k = PyUnicode_FromString("queues_max_rx");
    v = PyLong_FromUnsignedLongLong(queuesinfo.max_rx);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("queues_max_tx");
    v = PyLong_FromUnsignedLongLong(queuesinfo.max_tx);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("queues_max_other");
    v = PyLong_FromUnsignedLongLong(queuesinfo.max_other);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("queues_max_combined");
    v = PyLong_FromUnsignedLongLong(queuesinfo.max_combined);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("queues_current_rx");
    v = PyLong_FromUnsignedLongLong(queuesinfo.rx_count);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("queues_current_tx");
    v = PyLong_FromUnsignedLongLong(queuesinfo.tx_count);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("queues_current_other");
    v = PyLong_FromUnsignedLongLong(queuesinfo.other_count);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("queues_current_combined");
    v = PyLong_FromUnsignedLongLong(queuesinfo.combined_count);
    PyDict_SetItem(d, k, v);

    close(skfd);

    return d;
}

static PyMethodDef eth_methods[] = {
    {"stat", (PyCFunction)eth_stat, METH_VARARGS | METH_KEYWORDS,
     "Print a lovely skit to standard output."},
    {NULL, NULL, 0, NULL}   /* sentinel */
};

static struct PyModuleDef eth =
{
    PyModuleDef_HEAD_INIT,
    "eth", /* name of module */
    "usage: eth.stat(interface_name)\n", /* module documentation, may be NULL */
    -1,   /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    eth_methods
};

PyMODINIT_FUNC PyInit_eth(void)
{
    return PyModule_Create(&eth);
}
