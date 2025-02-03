/*
 * Copyright 2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <Python.h>
#include <libxml/tree.h>

#include <pacemaker.h>

/* This file defines a c-based low level module that wraps libpacemaker
 * functions and returns python objects.  This is necessary because most
 * libpacemaker functions return an xmlNode **, which needs to be coerced
 * through the PyCapsule type into something that libxml2's python
 * bindings can work with.
 */

/* Base exception class for any errors in the _pcmksupport module */
static PyObject *PacemakerError;

PyMODINIT_FUNC PyInit__pcmksupport(void);

static PyObject *
py_list_standards(PyObject *self, PyObject *args)
{
    int rc;
    xmlNodePtr xml = NULL;

    if (!PyArg_ParseTuple(args, "")) {
        return NULL;
    }

    rc = pcmk_list_standards(&xml);
    if (rc != pcmk_rc_ok) {
        PyErr_SetString(PacemakerError, pcmk_rc_str(rc));
        return NULL;
    }

    return PyCapsule_New(xml, "xmlNodePtr", NULL);
}

static PyMethodDef pcmksupportMethods[] = {
    { "list_standards", py_list_standards, METH_VARARGS, NULL },
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_pcmksupport",
    NULL,
    -1,
    pcmksupportMethods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit__pcmksupport(void)
{
    PyObject *module = PyModule_Create(&moduledef);

    if (module == NULL) {
        return NULL;
    }

    /* Add the base exception to the module */
    PacemakerError = PyErr_NewException("_pcmksupport.PacemakerError", NULL, NULL);

    /* FIXME: When we can support Python >= 3.10, we can use PyModule_AddObjectRef */
    if (PyModule_AddObject(module, "PacemakerError", PacemakerError) < 0) {
        Py_XDECREF(PacemakerError);
        return NULL;
    }

    return module;
}
