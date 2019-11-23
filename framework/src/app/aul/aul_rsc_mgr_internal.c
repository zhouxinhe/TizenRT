/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>

#include <dlog.h>
#include <bundle.h>

#include "aul_rsc_mgr_internal.h"
#include "aul_rsc_mgr_schema.h"

static char *__get_attribute(xmlNode *xml_node, const char *name)
{
	xmlChar *val;
	char *attr = NULL;

	val = xmlGetProp(xml_node, (const xmlChar *)name);
	if (val) {
		attr = strdup((const char *)val);
		xmlFree(val);
	}

	return attr;
}

static void __get_attribute_into_bundle(xmlNode *xml_node, const char *name,
		bundle *b)
{
	char *attr;

	attr = __get_attribute(xml_node, name);
	if (attr) {
		bundle_add_str(b, name, attr);
		free(attr);
	}
}

static int __parse_node(xmlNode *xml_node, GList **nodes)
{
	resource_node_t *node;

	if (strcmp((char *)xml_node->name, "node"))
		return -1;

	node = calloc(1, sizeof(resource_node_t));
	if (!node) {
		LOGE("Out of memory");
		return -1;
	}

	node->folder = __get_attribute(xml_node, "folder");
	/* why we should use bundle here? */
	node->attr = bundle_create();
	if (node->attr == NULL) {
		LOGE("Out of memory");
		free(node->folder);
		free(node);
		return -1;
	}

	__get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_DPI,
			node->attr);
	__get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_DPI_RANGE,
			node->attr);
	__get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_WIDTH_RANGE,
			node->attr);
	__get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_LARGE,
			node->attr);
	__get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_BPP,
			node->attr);
	__get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_PLATFORM_VER,
			node->attr);
	__get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_LANGUAGE,
			node->attr);

	*nodes = g_list_append(*nodes, node);

	return 0;
}

static char *_get_group_type(xmlNode *xml_node)
{
	static const char delim[] = "-";
	char *str;
	char *tok;
	char *ptr;

	/* copy original string */
	str = strdup((const char *)xml_node->name);
	if (str == NULL) {
		LOGE("Out of memory");
		return NULL;
	}

	tok = strtok_r(str, delim, &ptr);
	/* not a group element */
	if (tok == NULL || strcmp(tok, "group"))
		return NULL;
	tok = strtok_r(NULL, delim, &ptr);
	/* invalid element */
	if (tok == NULL)
		return NULL;
	ptr = strdup(tok);
	free(str);

	return ptr;
}

static int __parse_group(xmlNode *xml_node, GList **groups)
{
	xmlNode *tmp;
	char *type;
	resource_group_t *group;

	type = _get_group_type(xml_node);
	if (type == NULL)
		return -1;

	group = calloc(1, sizeof(resource_group_t));
	if (group == NULL) {
		LOGE("Out of memory");
		free(type);
		return -1;
	}

	group->type = type;
	group->folder = __get_attribute(xml_node, "folder");

	for (tmp = xml_node->children; tmp; tmp = tmp->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;
		if (__parse_node(tmp, &group->node_list))
			continue;
	}

	*groups = g_list_append(*groups, group);

	return 0;
}

static int __parse_resource(xmlNode *xml_node, resource_data_t **data)
{
	xmlNode *tmp;

	*data = calloc(1, sizeof(resource_data_t));
	if (*data == NULL) {
		LOGE("out of memory");
		return -1;
	}

	for (tmp = xml_node->children; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE)
			continue;
		__parse_group(tmp, &(*data)->group_list);
	}

	return 0;
}

static int __validate_schema(const char *path)
{
	xmlSchemaParserCtxt *parser_ctxt;
	xmlSchema *schema;
	xmlSchemaValidCtxt *valid_ctxt;
	int ret;

	parser_ctxt = xmlSchemaNewMemParserCtxt(res_schema, sizeof(res_schema));
	if (parser_ctxt == NULL) {
		LOGE("failed to create parser context");
		return -1;
	}

	schema = xmlSchemaParse(parser_ctxt);
	if (schema == NULL) {
		LOGE("failed to create schema");
		xmlSchemaFreeParserCtxt(parser_ctxt);
		return -1;
	}

	valid_ctxt = xmlSchemaNewValidCtxt(schema);
	if (valid_ctxt == NULL) {
		LOGE("failed to create valid context");
		xmlSchemaFree(schema);
		xmlSchemaFreeParserCtxt(parser_ctxt);
		return -1;
	}

	ret = xmlSchemaValidateFile(valid_ctxt, path, 0);
	if (ret)
		LOGE("%s: validation failed(%d)", path, ret);

	xmlSchemaFreeValidCtxt(valid_ctxt);
	xmlSchemaFree(schema);
	xmlSchemaFreeParserCtxt(parser_ctxt);

	return ret;
}

int _resource_open(const char *path, resource_data_t **data)
{
	int ret;
	xmlDoc *doc;
	xmlNode *root;

	if (__validate_schema(path))
		return -1;
	doc = xmlReadFile(path, NULL, 0);
	if (doc == NULL)
		return -1;
	root = xmlDocGetRootElement(doc);

	ret = __parse_resource(root, data);

	xmlFreeDoc(doc);

	return ret;
}

static void __free_resource_node(gpointer data)
{
	resource_node_t *node = (resource_node_t *)data;

	free(node->folder);
	bundle_free(node->attr);
	free(node);
}

static void __free_resource_group(gpointer data)
{
	resource_group_t *group = (resource_group_t *)data;

	free(group->folder);
	free(group->type);

	g_list_free_full(group->node_list, __free_resource_node);

	free(group);
}

int _resource_close(resource_data_t *data)
{
	/*
	free(data->package);
	*/
	g_list_free_full(data->group_list, __free_resource_group);

	free(data);

	return 0;
}
