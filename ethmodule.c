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
    uint32_t skfd = 0;
    uint32_t n_stats = 0;
    uint64_t sz_stats = 0;
    uint64_t sz_str = 0;
    char * ifname = NULL;
    struct ethtool_gstrings *strings = NULL;
    struct ethtool_stats *stats = NULL;
    struct ethtool_drvinfo drvinfo;
    struct ifreq ifr;

    if (!PyArg_ParseTuple(args, "s", &ifname))
    {
    	return NULL;
    }

    // Any socket will do
    if (( skfd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 )
    {
        return NULL;
    }

    // FIXME - exception handling
    memset(&ifr, 0, sizeof(ifr));
    // FIXME - exception handling
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)-1);

    drvinfo.cmd = ETHTOOL_GDRVINFO;
    ifr.ifr_data = (caddr_t) &drvinfo;
                                                                                
    if (ioctl(skfd, SIOCETHTOOL, &ifr) < 0)
    {
        return NULL;
    }
    n_stats = drvinfo.n_stats;

    // allocate memory for stat names and values
    sz_str = n_stats * ETH_GSTRING_LEN;
    sz_stats = n_stats * sizeof(uint64_t);
    // FIXME - exception handling
    strings = calloc(1, sz_str + sizeof(struct ethtool_gstrings));
    // FIXME - exception handling
    stats = calloc(1, sz_stats + sizeof(struct ethtool_stats));

    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_STATS;
    strings->len = n_stats;
    ifr.ifr_data = (caddr_t) strings;
    if (ioctl(skfd, SIOCETHTOOL, &ifr) < 0)
    {
        return NULL;
    }

    stats->cmd = ETHTOOL_GSTATS;
    stats->n_stats = n_stats;
    ifr.ifr_data = (caddr_t) stats;
    if (ioctl(skfd, SIOCETHTOOL, &ifr) < 0)
    {
        return NULL;
    }

    /*for (i = 0; i < n_stats; i++) {
        printf("%s\t%i\n", (char *)&strings->data[i * ETH_GSTRING_LEN], stats->data[i]);
    }*/

    close(skfd);

    PyObject *d = PyDict_New();
    for (i = 0; i < n_stats; i++) {
    	PyObject *k = PyUnicode_FromString((char *)&strings->data[i * ETH_GSTRING_LEN]);
    	PyObject *v = PyLong_FromUnsignedLongLong(stats->data[i]);
    	PyDict_SetItem(d, k, v);
    }

    /*PyObject *d = PyDict_New();
    PyObject *k = PyUnicode_FromString("counters");
    PyObject *v = PyLong_FromUnsignedLongLong(n_stats);
    PyDict_SetItem(d, k, v);*/
    // return Py_BuildValue("i", n_stats);

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