// SPDX-License-Identifier: GPL-2.0
/*
 * Debug helpers for the parser and the encoder
 *
 * Copyright (C) 2025, Google LLC.
 */
#ifndef KFUZZTEST_BRIDGE_DEBUG_H
#define KFUZZTEST_BRIDGE_DEBUG_H

#include <stdio.h>
#include "input_lexer.h"
#include "input_parser.h"

// Forward declaration for the recursive helper function
static void visualize_node(struct ast_node *node, int indent);

/**
 * @brief Prints a simple text representation of the AST.
 * @param node The root node of the AST to visualize.
 */
static void visualize_ast(struct ast_node *node)
{
	if (!node) {
		printf("AST is NULL.\n");
		return;
	}
	visualize_node(node, 0);
}

/**
 * @brief Recursive helper to print a node and its children.
 * @param node The current node to print.
 * @param indent The current indentation level.
 */
static void visualize_node(struct ast_node *node, int indent)
{
	// 1. Print the indentation for the current level
	for (int i = 0; i < indent; i++) {
		printf("  ");
	}

	if (!node) {
		printf("(NULL Node)\n");
		return;
	}

	// 2. Switch on the node type to print its details
	switch (node->type) {
	case NODE_PROGRAM: {
		struct ast_program *prog = &node->data.program;
		printf("Program (%zu regions):\n", prog->num_members);
		for (size_t i = 0; i < prog->num_members; i++) {
			visualize_node(prog->members[i], indent + 1);
		}
		break;
	}
	case NODE_REGION: {
		struct ast_region *region = &node->data.region;
		printf("Region '%s' (%zu members):\n", region->name, region->num_members);
		for (size_t i = 0; i < region->num_members; i++) {
			visualize_node(region->members[i], indent + 1);
		}
		break;
	}
	case NODE_POINTER: {
		struct ast_pointer *ptr = &node->data.pointer;
		printf("Pointer -> '%s'\n", ptr->points_to);
		break;
	}
	case NODE_PRIMITIVE: {
		struct ast_primitive *prim = &node->data.primitive;
		printf("Primitive (width: %d)\n", prim->byte_width);
		break;
	}
	case NODE_ARRAY: {
		struct ast_array *arr = &node->data.array;
		printf("array (num_elems: %zu, width: %d))\n", arr->num_elems, arr->elem_size);
		break;
	}
	// Add cases for NODE_ARRAY etc. as you implement them
	default:
		printf("Unknown Node Type\n");
		break;
	}
}

static void print_bytes(const char *bytes, size_t num_bytes)
{
	int i;

	for (i = 0; i < num_bytes; i++) {
		if (i % 4 == 0 && i != 0)
			printf("\n");
		printf("0x%02x ", (unsigned char)bytes[i]);
	}
	printf("\n");
}
#endif /* KFUZZTEST_BRIDGE_DEBUG_H */
