#ifndef KFUZZTEST_ENCODER_H
#define KFUZZTEST_ENCODER_H

#include "kfuzztest_input_parser.h"
#include "rand_stream.h"

int encode(struct ast_node *top_level, struct rand_stream *r, size_t *num_bytes, struct byte_buffer **ret);

#endif /* KFUZZTEST_ENCODER_H */
