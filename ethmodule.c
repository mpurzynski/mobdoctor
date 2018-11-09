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

static PyObject * eth_stat(PyObject *self, PyObject *args)
{
    uint32_t i = 0;
    uint32_t skfd;
    uint32_t n_stats = 0;
    uint64_t sz_str;
    uint64_t sz_stats;
    char * ifname;
    struct ethtool_drvinfo drvinfo;
    struct ethtool_gstrings *strings = NULL;
    struct ethtool_stats *stats = NULL;
    struct ethtool_value values;
    struct ethtool_ringparam ringinfo;
    struct ifreq ifr;
    uint32_t eth_num_cmds = 6;
    int offload_cmds[] = {ETHTOOL_GTSO, ETHTOOL_GUFO, ETHTOOL_GGSO, ETHTOOL_GGRO, ETHTOOL_GSG, ETHTOOL_GRXCSUM};
    char * offload_names[] = {"tso", "ufo", "gso", "gro", "sg", "checksum"};

    if (!PyArg_ParseTuple(args, "s", &ifname))
    	return NULL;

    // Any socket will do
    if (( skfd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 )
    {
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)-1);

    drvinfo.cmd = ETHTOOL_GDRVINFO;
    ifr.ifr_data = (caddr_t) &drvinfo;
                                                                                
    if (ioctl(skfd, SIOCETHTOOL, &ifr) == -1)
    {
        return NULL;
    }
    n_stats = drvinfo.n_stats;

    // allocate memory for stat names and values
    sz_str = n_stats * ETH_GSTRING_LEN;
    sz_stats = n_stats * sizeof(uint64_t);
    strings = calloc(1, sz_str + sizeof(struct ethtool_gstrings));
    stats = calloc(1, sz_stats + sizeof(struct ethtool_stats));

    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_STATS;
    strings->len = n_stats;
    ifr.ifr_data = (caddr_t) strings;
    ioctl(skfd, SIOCETHTOOL, &ifr);

    stats->cmd = ETHTOOL_GSTATS;
    stats->n_stats = n_stats;
    ifr.ifr_data = (caddr_t) stats;
    ioctl(skfd, SIOCETHTOOL, &ifr);

    PyObject *d = PyDict_New();

    for (i = 0; i < eth_num_cmds; i++) {
        values.cmd = offload_cmds[i];
	ifr.ifr_data = (caddr_t) &values;
	ioctl(skfd, SIOCETHTOOL, &ifr);

        PyObject *k = PyUnicode_FromString(offload_names[i]);
        PyObject *v = PyLong_FromUnsignedLongLong(values.data);
        PyDict_SetItem(d, k, v);
    }

    ringinfo.cmd = ETHTOOL_GRINGPARAM;
    ifr.ifr_data = (caddr_t) &ringinfo;
    ioctl(skfd, SIOCETHTOOL, &ifr);
    PyObject *k = PyUnicode_FromString("rx_max_pending");
    PyObject *v = PyLong_FromUnsignedLongLong(ringinfo.rx_max_pending);
    PyDict_SetItem(d, k, v);
    k = PyUnicode_FromString("rx_pending");
    v = PyLong_FromUnsignedLongLong(ringinfo.rx_pending);
    PyDict_SetItem(d, k, v);
    
    for (i = 0; i < n_stats; i++) {
    	PyObject *k = PyUnicode_FromString((char *)&strings->data[i * ETH_GSTRING_LEN]);
    	PyObject *v = PyLong_FromUnsignedLongLong(stats->data[i]);
    	PyDict_SetItem(d, k, v);
    }

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
