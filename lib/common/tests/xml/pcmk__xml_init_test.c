/*
 * Copyright 2023-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <libxml/tree.h>                    // xmlNode, etc.
#include <libxml/xmlstring.h>               // xmlChar

#include <crm/common/xml.h>
#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

#include "crmcommon_private.h"

/* Copied from lib/common/xml.c */
#define XML_DOC_PRIVATE_MAGIC   0x81726354UL
#define XML_NODE_PRIVATE_MAGIC  0x54637281UL

static int
setup(void **state) {
    pcmk__xml_init();
    return 0;
}

static int
teardown(void **state) {
    pcmk__xml_cleanup();
    return 0;
}

static void
buffer_scheme_test(void **state) {
    assert_int_equal(XML_BUFFER_ALLOC_DOUBLEIT, xmlGetBufferAllocationScheme());
}

/* These functions also serve as unit tests of the static new_private_data
 * function.  We can't test free_private_data because libxml will call that as
 * part of freeing everything else.  By the time we'd get back into a unit test
 * where we could check that private members are NULL, the structure containing
 * the private data would have been freed.
 *
 * This could probably be tested with a lot of function mocking, but that
 * doesn't seem worth it.
 */

static void
create_document_node(void **state) {
    xml_doc_private_t *docpriv = NULL;
    xmlDocPtr doc = xmlNewDoc(PCMK__XML_VERSION);

    /* Double check things */
    assert_non_null(doc);
    assert_int_equal(doc->type, XML_DOCUMENT_NODE);

    /* Check that the private data is initialized correctly */
    docpriv = doc->_private;
    assert_non_null(docpriv);
    assert_int_equal(docpriv->check, XML_DOC_PRIVATE_MAGIC);
    assert_true(pcmk_all_flags_set(docpriv->flags, pcmk__xf_dirty|pcmk__xf_created));

    /* Clean up */
    xmlFreeDoc(doc);
}

static void
create_element_node(void **state) {
    xml_doc_private_t *docpriv = NULL;
    xml_node_private_t *priv = NULL;
    xmlDocPtr doc = xmlNewDoc(PCMK__XML_VERSION);
    xmlNodePtr node = xmlNewDocNode(doc, NULL, (const xmlChar *) "test", NULL);

    /* Adding a node to the document marks it as dirty */
    docpriv = doc->_private;
    assert_true(pcmk_all_flags_set(docpriv->flags, pcmk__xf_dirty));

    /* Double check things */
    assert_non_null(node);
    assert_int_equal(node->type, XML_ELEMENT_NODE);

    /* Check that the private data is initialized correctly */
    priv = node->_private;
    assert_non_null(priv);
    assert_int_equal(priv->check, XML_NODE_PRIVATE_MAGIC);
    assert_true(pcmk_all_flags_set(priv->flags, pcmk__xf_dirty|pcmk__xf_created));

    /* Clean up */
    xmlFreeNode(node);
    xmlFreeDoc(doc);
}

static void
create_attr_node(void **state) {
    xml_doc_private_t *docpriv = NULL;
    xml_node_private_t *priv = NULL;
    xmlDocPtr doc = xmlNewDoc(PCMK__XML_VERSION);
    xmlNodePtr node = xmlNewDocNode(doc, NULL, (const xmlChar *) "test", NULL);
    xmlAttrPtr attr = xmlNewProp(node, (const xmlChar *) PCMK_XA_NAME,
                                 (const xmlChar *) "dummy-value");

    /* Adding a node to the document marks it as dirty */
    docpriv = doc->_private;
    assert_true(pcmk_all_flags_set(docpriv->flags, pcmk__xf_dirty));

    /* Double check things */
    assert_non_null(attr);
    assert_int_equal(attr->type, XML_ATTRIBUTE_NODE);

    /* Check that the private data is initialized correctly */
    priv = attr->_private;
    assert_non_null(priv);
    assert_int_equal(priv->check, XML_NODE_PRIVATE_MAGIC);
    assert_true(pcmk_all_flags_set(priv->flags, pcmk__xf_dirty|pcmk__xf_created));

    /* Clean up */
    xmlFreeNode(node);
    xmlFreeDoc(doc);
}

static void
create_comment_node(void **state) {
    xml_doc_private_t *docpriv = NULL;
    xml_node_private_t *priv = NULL;
    xmlDocPtr doc = xmlNewDoc(PCMK__XML_VERSION);
    xmlNodePtr node = xmlNewDocComment(doc, (const xmlChar *) "blahblah");

    /* Adding a node to the document marks it as dirty */
    docpriv = doc->_private;
    assert_true(pcmk_all_flags_set(docpriv->flags, pcmk__xf_dirty));

    /* Double check things */
    assert_non_null(node);
    assert_int_equal(node->type, XML_COMMENT_NODE);

    /* Check that the private data is initialized correctly */
    priv = node->_private;
    assert_non_null(priv);
    assert_int_equal(priv->check, XML_NODE_PRIVATE_MAGIC);
    assert_true(pcmk_all_flags_set(priv->flags, pcmk__xf_dirty|pcmk__xf_created));

    /* Clean up */
    xmlFreeNode(node);
    xmlFreeDoc(doc);
}

static void
create_text_node(void **state) {
    xml_doc_private_t *docpriv = NULL;
    xml_node_private_t *priv = NULL;
    xmlDocPtr doc = xmlNewDoc(PCMK__XML_VERSION);
    xmlNodePtr node = xmlNewDocText(doc, (const xmlChar *) "blahblah");

    /* Adding a node to the document marks it as dirty */
    docpriv = doc->_private;
    assert_true(pcmk_all_flags_set(docpriv->flags, pcmk__xf_dirty));

    /* Double check things */
    assert_non_null(node);
    assert_int_equal(node->type, XML_TEXT_NODE);

    /* Check that no private data was created */
    priv = node->_private;
    assert_null(priv);

    /* Clean up */
    xmlFreeNode(node);
    xmlFreeDoc(doc);
}

static void
create_dtd_node(void **state) {
    xml_doc_private_t *docpriv = NULL;
    xml_node_private_t *priv = NULL;
    xmlDocPtr doc = xmlNewDoc(PCMK__XML_VERSION);
    xmlDtdPtr dtd = xmlNewDtd(doc, (const xmlChar *) PCMK_XA_NAME,
                              (const xmlChar *) "externalId",
                              (const xmlChar *) "systemId");

    /* Adding a node to the document marks it as dirty */
    docpriv = doc->_private;
    assert_true(pcmk_all_flags_set(docpriv->flags, pcmk__xf_dirty));

    /* Double check things */
    assert_non_null(dtd);
    assert_int_equal(dtd->type, XML_DTD_NODE);

    /* Check that no private data was created */
    priv = dtd->_private;
    assert_null(priv);

    /* Clean up */
    /* If you call xmlFreeDtd before xmlFreeDoc, you get a segfault */
    xmlFreeDoc(doc);
}

static void
create_cdata_node(void **state) {
    xml_doc_private_t *docpriv = NULL;
    xml_node_private_t *priv = NULL;
    xmlDocPtr doc = xmlNewDoc(PCMK__XML_VERSION);
    xmlNodePtr node = xmlNewCDataBlock(doc, (const xmlChar *) "blahblah", 8);

    /* Adding a node to the document marks it as dirty */
    docpriv = doc->_private;
    assert_true(pcmk_all_flags_set(docpriv->flags, pcmk__xf_dirty));

    /* Double check things */
    assert_non_null(node);
    assert_int_equal(node->type, XML_CDATA_SECTION_NODE);

    /* Check that no private data was created */
    priv = node->_private;
    assert_null(priv);

    /* Clean up */
    xmlFreeNode(node);
    xmlFreeDoc(doc);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(buffer_scheme_test),
                cmocka_unit_test(create_document_node),
                cmocka_unit_test(create_element_node),
                cmocka_unit_test(create_attr_node),
                cmocka_unit_test(create_comment_node),
                cmocka_unit_test(create_text_node),
                cmocka_unit_test(create_dtd_node),
                cmocka_unit_test(create_cdata_node));
