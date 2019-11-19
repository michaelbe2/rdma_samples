/*
 * Copyright (c) 2019 Mellanox Technologies, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _RC_WRITE_COMMON_H_
#define _RC_WRITE_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

/*                                       addr             size     rkey     gpu_addr         gpu_rkey qpn    gid */
#define EXCHANGE_STRING_LENGTH  (sizeof "0102030405060708:01020304:01020304:0102030405060708:01020304:010203:0102030405060708090a0b0c0d0e0f10")
#define EXCHANGE_STRING_NO_GID_LENGTH  (sizeof "0102030405060708:01020304:01020304:0102030405060708:01020304:010203")

/*
 * rdma_device object holds the RDMA resources of the local RDMA device,
 * of a Targte or a Source
 */
struct rdma_device;

struct rdma_device *rdma_open_device_target(struct sockaddr *addr); /* client */
struct rdma_device *rdma_open_device_source(struct sockaddr *addr); /* server */
void rdma_close_device(struct rdma_device *rdma_dev);
int rdma_buffer_reg(struct rdma_device *rdma_dev, size_t length, int use_cuda, const char *bdf);
void rdma_buffer_dereg(struct rdma_device *rdma_dev, int use_cuda);
int fill_exchange_string(struct rdma_device *rdma_dev, char *exch_string, size_t length);
int parse_exchange_string(struct rdma_device *rdma_dev, char *exch_string);
int rdma_write_to_peer(struct rdma_device *rdma_dev, uint64_t wr_id, int to_gpu);
int rdma_poll_completions(struct rdma_device *rdma_dev);

int modify_target_qp_to_rtr(struct rdma_device *rdma_dev);
int modify_source_qp_to_rtr_and_rts(struct rdma_device *rdma_dev);

#ifdef __cplusplus
}
#endif

#endif /* _RC_WRITE_COMMON_H_ */

