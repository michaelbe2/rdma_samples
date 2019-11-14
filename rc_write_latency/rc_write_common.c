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

#define _LOG_ENABLE_VARS_DEFINE
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <time.h>

#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>

#include "ibv_helper.h"
#include "rc_write_common.h"
#include "utils.h"

int init_enable  = 0;
int trace_enable = 0;
int debug_enable = 0;

#define LATENCY_ARR_SIZE    (1<<10) /*should be power of 2*/
#define CQ_DEPTH            64
#define SEND_Q_DEPTH        4
#define MAX_SEND_SGE        10
#define TC_PRIO             3

#ifdef PRINT_LATENCY
struct wr_latency {
    uint64_t    wr_start_ts;
    uint64_t    wr_after_ts;
    uint64_t    completion_ts;
    uint64_t    read_comp_ts;
};
#endif /*PRINT_LATENCY*/

#ifdef PRINT_LATENCY
    #define MY_RDMA_DEV_CQ(DEV)     ibv_cq_ex_to_cq(DEV->virt_cq.cq_ex)
#else
    #define MY_RDMA_DEV_CQ(DEV)     DEV->virt_cq.cq
#endif /*PRINT_LATENCY*/


struct rdma_device {
    struct rdma_event_channel *cm_channel;
    struct rdma_cm_id *cm_id;
    
    struct ibv_context *context;
    struct ibv_pd      *pd;

    union {
        struct ibv_cq       *cq;
        struct ibv_cq_ex    *cq_ex; //to use #ifdef PRINT_LATENCY
    } virt_cq;
    
    struct ibv_qp   *qps[MAX_NUM_OF_QPS];
    
    /* Remote side attributes */
    uint32_t            rem_qpns[MAX_NUM_OF_QPS];
    unsigned long long  rem_buf_addr;
    unsigned long       rem_buf_rkey;
    union ibv_gid       rem_gid;
    
    /* Address handler (port info) relateed fields */
    int              ib_port;
    int              gidx;
    union ibv_gid    gid;
//    uint16_t            lid;
    enum ibv_mtu     mtu;

    /* Buffer Related fields */
    void            *buf_addr;   //uint64_t  addr;
    size_t           buf_size;   //uint32_t  size;
    /* MR Related fields */
    struct ibv_mr   *mr;
    
#ifdef PRINT_LATENCY
    uint64_t            hca_core_clock_kHz;
    struct wr_latency   latency[LATENCY_ARR_SIZE];
    uint64_t    measure_index;
    uint64_t    wr_send_latency_sum;    /*from wr_start_ts*/
    uint64_t    completion_latency_sum; /*from wr_start_ts*/
    uint64_t    read_comp_latency_sum;  /*from completion_ts*/
    uint64_t    min_wr_send_latency;
    uint64_t    min_completion_latency;
    uint64_t    min_read_comp_latency;
    uint64_t    max_wr_send_latency;
    uint64_t    max_completion_latency;
    uint64_t    max_read_comp_latency;
#endif /*PRINT_LATENCY*/
};


//============================================================================================
static struct ibv_context *open_ib_device_by_addr(struct rdma_device *rdma_dev, struct sockaddr *addr)
{
    int ret;
    uint16_t sin_port;
    char str[INET_ADDRSTRLEN];

    rdma_dev->cm_channel = rdma_create_event_channel();
    if (!rdma_dev->cm_channel) {
        LOG_INIT("rdma_create_event_channel() failure");
        return NULL;
    }

    ret = rdma_create_id(rdma_dev->cm_channel, &rdma_dev->cm_id, rdma_dev, RDMA_PS_UDP);
    if (ret) {
        LOG_INIT("rdma_create_id() failure");
        goto out1;
    }

    ret = rdma_bind_addr(rdma_dev->cm_id, addr);
    if (ret) {
        LOG_INIT("rdma_bind_addr() failure");
        goto out2;
    }

    if (addr->sa_family == AF_INET) {
        sin_port = ((struct sockaddr_in *)addr)->sin_port;
        inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), str, INET_ADDRSTRLEN);
    } else {
        sin_port = ((struct sockaddr_in6 *)addr)->sin6_port;
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr)->sin6_addr), str, INET_ADDRSTRLEN);
    }

    if (rdma_dev->cm_id->verbs == NULL) {
        LOG_INIT("Failed to bind to an RDMA device, exiting... <%s, %d>\n", str, ntohs(sin_port));
        goto out2;
    }

    rdma_dev->ib_port = rdma_dev->cm_id->port_num;
    rdma_dev->gidx = -1;

    LOG_INIT("bound to RDMA device name:%s, port:%d, based on '%s'\n",
              rdma_dev->cm_id->verbs->device->name, rdma_dev->cm_id->port_num, str); 

    return rdma_dev->cm_id->verbs;

out2:
    rdma_destroy_id(rdma_dev->cm_id);
out1:
    rdma_destroy_event_channel(rdma_dev->cm_channel);
    return NULL;

}

static void close_ib_device(struct rdma_device *rdma_dev)
{
    int ret;

    if (rdma_dev->cm_channel) {

        /* if we are using RDMA_CM then we just referance the cma's ibv_context */
        rdma_dev->context = NULL;

        if (rdma_dev->cm_id) {
            LOG_INIT("rdma_destroy_id(%p)\n", rdma_dev->cm_id);
            ret = rdma_destroy_id(rdma_dev->cm_id);
            if (ret) {
                fprintf(stderr, "failure in rdma_destroy_id(), error %d\n", ret);
            }
        }

        LOG_INIT("rdma_destroy_event_channel(%p)\n", rdma_dev->cm_id);
        rdma_destroy_event_channel(rdma_dev->cm_channel);
    }

    if (rdma_dev->context) {
        LOG_INIT("ibv_close_device(%p)\n", rdma_dev->context);
        ret = ibv_close_device(rdma_dev->context);
        if (ret) {
            fprintf(stderr, "failure in ibv_close_device(), error %d\n", ret);
        }
    }
}

/***********************************************************************************
 * Fill portinfo structure, get lid and gid from portinfo
 * Return value: 0 - success, 1 - error
 ****************************************************************************************/
static int rdma_set_lid_gid_from_port_info(struct rdma_device *rdma_dev)
{
    struct ibv_port_attr    portinfo;
    int    ret_val;

    ret_val = ibv_query_port(rdma_dev->context, rdma_dev->ib_port, &portinfo);
    if (ret_val) {
        fprintf(stderr, "Couldn't get port info\n");
        return 1;
    }

    rdma_dev->mtu = portinfo.active_mtu;
    if (portinfo.link_layer != IBV_LINK_LAYER_ETHERNET) {
        fprintf(stderr, "Link layer is not Ethernet, IB link is not supported\n");
        return 1;
    }

    if (rdma_dev->cm_id && portinfo.link_layer == IBV_LINK_LAYER_ETHERNET) {
        rdma_dev->gidx = ibv_find_sgid_type(rdma_dev->context, rdma_dev->ib_port, 
        IBV_GID_TYPE_ROCE_V2, rdma_dev->cm_id->route.addr.src_addr.sa_family);
    }
    
    if (rdma_dev->gidx < 0) {
        if (portinfo.link_layer == IBV_LINK_LAYER_ETHERNET) {
            fprintf(stderr, "Wrong GID index (%d) for ETHERNET port\n", rdma_dev->gidx);
            return 1;
        } else {
            memset(&(rdma_dev->gid), 0, sizeof rdma_dev->gid);
        }
    } else /* rdma_dev->gidx >= 0*/ {
        ret_val = ibv_query_gid(rdma_dev->context, rdma_dev->ib_port, rdma_dev->gidx, &(rdma_dev->gid));
        if (ret_val) {
            fprintf(stderr, "can't read GID of index %d, error code %d\n", rdma_dev->gidx, ret_val);
            return 1;
        }
        LOG_INIT("my gid idx: %d, value:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", rdma_dev->gidx,
                 rdma_dev->gid.raw[0], rdma_dev->gid.raw[1], rdma_dev->gid.raw[2], rdma_dev->gid.raw[3],
                 rdma_dev->gid.raw[4], rdma_dev->gid.raw[5], rdma_dev->gid.raw[6], rdma_dev->gid.raw[7], 
                 rdma_dev->gid.raw[8], rdma_dev->gid.raw[9], rdma_dev->gid.raw[10], rdma_dev->gid.raw[11],
                 rdma_dev->gid.raw[12], rdma_dev->gid.raw[13], rdma_dev->gid.raw[14], rdma_dev->gid.raw[15] );
    }

    LOG_INIT("link_layer:%s, MTU:%d Bytes\n",
             (portinfo.link_layer == IBV_LINK_LAYER_ETHERNET ? "ETH" : "IB"),
             (256<<(rdma_dev->mtu - 1)));

    return 0;
}

//============================================================================================
struct rdma_device *rdma_open_device_target(struct sockaddr *addr) /* client */
{
    struct rdma_device *rdma_dev;
    int                 ret_val;

    rdma_dev = calloc(1, sizeof *rdma_dev);
    if (!rdma_dev) {
        fprintf(stderr, "rdma_device memory allocation failed\n");
        return NULL;
    }

    /****************************************************************************************************
     * In the next function we let rdma_cm find a IB device that matches the IP address of a the local netdev,
     * if yes, we return a pointer to that ib context
     * The result of this function is ib_dev - initialized pointer to the relevant struct ibv_device
     ****************************************************************************************************/
    rdma_dev->context = open_ib_device_by_addr(rdma_dev, addr);
    if (!rdma_dev->context){
        goto clean_rdma_dev;
    }

    ret_val = rdma_set_lid_gid_from_port_info(rdma_dev);
    if (ret_val) {
        goto clean_device;
    }

    /****************************************************************************************************/
    
    LOG_INIT ("ibv_alloc_pd(ibv_context = %p)\n", rdma_dev->context);
    rdma_dev->pd = ibv_alloc_pd(rdma_dev->context);
    if (!rdma_dev->pd) {
        fprintf(stderr, "Couldn't allocate PD\n");
        goto clean_device;
    }
    LOG_INIT("created pd %p\n", rdma_dev->pd);

    /* **********************************  Create CQ  ********************************** */
#ifdef PRINT_LATENCY
	struct ibv_cq_init_attr_ex cq_attr_ex;
	
    memset(&cq_attr_ex, 0, sizeof(cq_attr_ex));
	cq_attr_ex.cqe = CQ_DEPTH;
	cq_attr_ex.cq_context = rdma_dev;
	cq_attr_ex.channel = NULL;
	cq_attr_ex.comp_vector = 0;
	cq_attr_ex.wc_flags = IBV_WC_EX_WITH_COMPLETION_TIMESTAMP;

    LOG_INIT ("ibv_create_cq_ex(rdma_dev->context = %p, &cq_attr_ex)\n", rdma_dev->context);
	rdma_dev->virt_cq.cq_ex = ibv_create_cq_ex(rdma_dev->context, &cq_attr_ex);
    if (!rdma_dev->virt_cq.cq_ex) {
        fprintf(stderr, "Couldn't create CQ ex\n");
        goto clean_pd;
    }
    LOG_INIT("created cq_ex %p\n", rdma_dev->virt_cq.cq_ex);
#else /*PRINT_LATENCY*/
    LOG_INIT ("ibv_create_cq(%p, %d, NULL, NULL, 0)\n", rdma_dev->context, CQ_DEPTH);
    rdma_dev->virt_cq.cq = ibv_create_cq(rdma_dev->context, CQ_DEPTH, NULL, NULL /*comp. events channel*/, 0);
    if (!rdma_dev->virt_cq.cq) {
        fprintf(stderr, "Couldn't create CQ\n");
        goto clean_pd;
    }
    LOG_INIT("created cq %p\n", rdma_dev->virt_cq.cq);
#endif /*PRINT_LATENCY*/

    /* **********************************  Create QP  ********************************** */
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_type = IBV_QPT_RC,
        .send_cq = MY_RDMA_DEV_CQ(rdma_dev),
        .recv_cq = MY_RDMA_DEV_CQ(rdma_dev),
        .cap     = {
            .max_send_wr  = 1, /*actually, we don't send or receive WRs*/
            .max_recv_wr  = 1,
            .max_send_sge = 1,
            .max_recv_sge = 1
        },
    };
    int i;
    for (i = 0; i < MAX_NUM_OF_QPS; i++) {
        rdma_dev->qps[i] = ibv_create_qp(rdma_dev->pd, &qp_init_attr);
        if (!rdma_dev->qps[i])  {
            fprintf(stderr, "Couldn't create QP %d\n", i);
            goto clean_cq;
        }
        LOG_DEBUG("ibv_create_qp qps[%d] completed: qp_num = 0x%lx\n", i, rdma_dev->qps[i]->qp_num);
    }
    LOG_INIT("Creating %d QPs completed\n", MAX_NUM_OF_QPS);

    /* - - - - - - -  Modify QP to INIT  - - - - - - - */
    struct ibv_qp_attr qp_attr = {
        .qp_state        = IBV_QPS_INIT,
        .pkey_index      = 0,
        .port_num        = rdma_dev->ib_port,
        .qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE
    };
    enum ibv_qp_attr_mask attr_mask = IBV_QP_STATE      |
                                      IBV_QP_PKEY_INDEX |
                                      IBV_QP_PORT       |
                                      IBV_QP_ACCESS_FLAGS;
    LOG_INIT("ibv_modify_qp for %d QPs, qp_attr.qp_state = %d, attr_mask = 0x%x)\n",
               MAX_NUM_OF_QPS, qp_attr.qp_state, attr_mask);
    for (i = 0; i < MAX_NUM_OF_QPS; i++) {
        ret_val = ibv_modify_qp(rdma_dev->qps[i], &qp_attr, attr_mask);
        if (ret_val) {
            fprintf(stderr, "Failed to modify QP %i to INIT, error %d\n", i, ret_val);
            goto clean_qp;
        }
        LOG_DEBUG("ibv_modify_qp of qps[%i] to state %d completed: qp_num = 0x%lx\n",
                  i, qp_attr.qp_state, rdma_dev->qps[i]->qp_num);
    }
    LOG_INIT("ibv_modify_qp for %d QPs to state %d completed\n", MAX_NUM_OF_QPS, qp_attr.qp_state);

    return rdma_dev;

clean_qp:
    for (i = 0; i < MAX_NUM_OF_QPS; i++) {
        if (rdma_dev->qps[i])  {
            ibv_destroy_qp(rdma_dev->qps[i]);
        }
    }

clean_cq:
    if (rdma_dev->virt_cq.cq) {
        ibv_destroy_cq(MY_RDMA_DEV_CQ(rdma_dev));
    }

clean_pd:
    if (rdma_dev->pd) {
        ibv_dealloc_pd(rdma_dev->pd);
    }

clean_device:
    close_ib_device(rdma_dev);
    
clean_rdma_dev:
    free(rdma_dev);

    return NULL;
}

//============================================================================================
struct rdma_device *rdma_open_device_source(struct sockaddr *addr) /* server */
{
    struct rdma_device *rdma_dev;
    int                 ret_val;

    rdma_dev = calloc(1, sizeof *rdma_dev);
    if (!rdma_dev) {
        fprintf(stderr, "rdma_device memory allocation failed\n");
        return NULL;
    }

    /****************************************************************************************************
     * In the next function we let rdma_cm find a IB device that matches the IP address of a the local netdev,
     * if yes, we return a pointer to that ib context
     * The result of this function is ib_dev - initialized pointer to the relevant struct ibv_device
     ****************************************************************************************************/
    rdma_dev->context = open_ib_device_by_addr(rdma_dev, addr);
    if (!rdma_dev->context){
        goto clean_rdma_dev;
    }
    
    ret_val = rdma_set_lid_gid_from_port_info(rdma_dev);
    if (ret_val) {
        goto clean_device;
    }

    /****************************************************************************************************/

    LOG_INIT ("ibv_alloc_pd(ibv_context = %p)\n", rdma_dev->context);
    rdma_dev->pd = ibv_alloc_pd(rdma_dev->context);
    if (!rdma_dev->pd) {
        fprintf(stderr, "Couldn't allocate PD\n");
        goto clean_device;
    }
    LOG_INIT("created pd %p\n", rdma_dev->pd);

    /* We don't create completion events channel (ibv_create_comp_channel), we prefer working in polling mode */
    
    /* **********************************  Create CQ  ********************************** */
#ifdef PRINT_LATENCY
	struct ibv_cq_init_attr_ex cq_attr_ex;
	
    memset(&cq_attr_ex, 0, sizeof(cq_attr_ex));
	cq_attr_ex.cqe = CQ_DEPTH;
	cq_attr_ex.cq_context = rdma_dev;
	cq_attr_ex.channel = NULL;
	cq_attr_ex.comp_vector = 0;
	cq_attr_ex.wc_flags = IBV_WC_EX_WITH_COMPLETION_TIMESTAMP;

    LOG_INIT ("ibv_create_cq_ex(rdma_dev->context = %p, &cq_attr_ex)\n", rdma_dev->context);
	rdma_dev->virt_cq.cq_ex = ibv_create_cq_ex(rdma_dev->context, &cq_attr_ex);
    if (!rdma_dev->virt_cq.cq_ex) {
        fprintf(stderr, "Couldn't create CQ ex\n");
        goto clean_pd;
    }
    LOG_INIT("created cq_ex %p\n", rdma_dev->virt_cq.cq_ex);
#else /*PRINT_LATENCY*/
    LOG_INIT ("ibv_create_cq(%p, %d, NULL, NULL, 0)\n", rdma_dev->context, CQ_DEPTH);
    rdma_dev->virt_cq.cq = ibv_create_cq(rdma_dev->context, CQ_DEPTH, NULL, NULL /*comp. events channel*/, 0);
    if (!rdma_dev->virt_cq.cq) {
        fprintf(stderr, "Couldn't create CQ\n");
        goto clean_pd;
    }
    LOG_INIT("created cq %p\n", rdma_dev->virt_cq.cq);
#endif /*PRINT_LATENCY*/

    /* **********************************  Create QP  ********************************** */
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_type = IBV_QPT_RC,
        .send_cq = MY_RDMA_DEV_CQ(rdma_dev),
        .recv_cq = MY_RDMA_DEV_CQ(rdma_dev),
        .cap     = {
            .max_send_wr  = SEND_Q_DEPTH,
            .max_recv_wr  = 1,
            .max_send_sge = MAX_SEND_SGE,
            .max_recv_sge = 1
        },
    };
    int i;
    for (i = 0; i < MAX_NUM_OF_QPS; i++) {
        rdma_dev->qps[i] = ibv_create_qp(rdma_dev->pd, &qp_init_attr);
        if (!rdma_dev->qps[i])  {
            fprintf(stderr, "Couldn't create QP %d\n", i);
            goto clean_cq;
        }
        LOG_DEBUG("ibv_create_qp qps[%d] completed: qp_num = 0x%lx\n", i, rdma_dev->qps[i]->qp_num);
    }
    LOG_INIT("Creating %d QPs completed\n", MAX_NUM_OF_QPS);
    
    /* - - - - - - -  Modify QP to INIT  - - - - - - - */
    struct ibv_qp_attr qp_attr = {
        .qp_state        = IBV_QPS_INIT,
        .pkey_index      = 0,
        .port_num        = rdma_dev->ib_port,
        .qp_access_flags = IBV_ACCESS_LOCAL_WRITE
    };
    enum ibv_qp_attr_mask attr_mask = IBV_QP_STATE      |
                                      IBV_QP_PKEY_INDEX |
                                      IBV_QP_PORT       |
                                      IBV_QP_ACCESS_FLAGS;
    LOG_INIT("ibv_modify_qp for %d QPs, qp_attr.qp_state = %d, attr_mask = 0x%x)\n",
               MAX_NUM_OF_QPS, qp_attr.qp_state, attr_mask);
    for (i = 0; i < MAX_NUM_OF_QPS; i++) {
        ret_val = ibv_modify_qp(rdma_dev->qps[i], &qp_attr, attr_mask);
        if (ret_val) {
            fprintf(stderr, "Failed to modify QP %i to INIT, error %d\n", i, ret_val);
            goto clean_qp;
        }
        LOG_DEBUG("ibv_modify_qp of qps[%i] to state %d completed: qp_num = 0x%lx\n",
                  i, qp_attr.qp_state, rdma_dev->qps[i]->qp_num);
    }
    LOG_INIT("ibv_modify_qp for %d QPs to state %d completed\n", MAX_NUM_OF_QPS, qp_attr.qp_state);
    
#ifdef PRINT_LATENCY
    struct ibv_device_attr_ex           device_attr_ex = {};
    //struct ibv_query_device_ex_input    query_device_ex_input = {
    //    .comp_masc = ...
    //}
    
    ret_val = ibv_query_device_ex(rdma_dev->context, /*struct ibv_query_device_ex_input*/NULL, &device_attr_ex);
    if (ret_val) {
        fprintf(stderr, "ibv_query_device_ex failed\n");
        goto clean_qp;
    }
    if (!device_attr_ex.hca_core_clock) {
        fprintf(stderr, "hca_core_clock = 0\n");
        goto clean_qp;
    }

    rdma_dev->hca_core_clock_kHz = device_attr_ex.hca_core_clock;
    LOG_INIT("hca_core_clock = %d kHz\n", rdma_dev->hca_core_clock_kHz);

    rdma_dev->min_wr_send_latency    = 0x8FFFFFFFFFFFFFFF;
    rdma_dev->min_completion_latency = 0x8FFFFFFFFFFFFFFF;
    rdma_dev->min_read_comp_latency  = 0x8FFFFFFFFFFFFFFF;
#endif /*PRINT_LATENCY*/
    
    return rdma_dev;

clean_qp:
    for (i = 0; i < MAX_NUM_OF_QPS; i++) {
        if (rdma_dev->qps[i])  {
            ibv_destroy_qp(rdma_dev->qps[i]);
        }
    }

clean_cq:
    if (rdma_dev->virt_cq.cq) {
        ibv_destroy_cq(MY_RDMA_DEV_CQ(rdma_dev));
    }
    
clean_pd:
    if (rdma_dev->pd) {
        ibv_dealloc_pd(rdma_dev->pd);
    }

clean_device:
    close_ib_device(rdma_dev);

clean_rdma_dev:
    free(rdma_dev);
    
    return NULL;
}

//============================================================================================
void rdma_close_device(struct rdma_device *rdma_dev)
{
    int ret_val;

#ifdef PRINT_LATENCY
    if (rdma_dev->measure_index) {
        LOG_INIT("PRINT_LATENCY: %6lu wr-s, wr_sent latency: min %8lu, max %8lu, avg %8lu (nSec)\n",
                  rdma_dev->measure_index,
                  rdma_dev->min_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->max_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->wr_send_latency_sum / rdma_dev->measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_INIT("PRINT_LATENCY:   completion latency        : min %8lu, max %8lu, avg %8lu (nSec)\n",
                  rdma_dev->min_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->max_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->completion_latency_sum / rdma_dev->measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_INIT("PRINT_LATENCY:   read_comp latency         : min %8lu, max %8lu, avg %8lu (nSec)\n",
                  rdma_dev->min_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->max_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->read_comp_latency_sum / rdma_dev->measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        fflush(stdout);
    }
#endif /*PRINT_LATENCY*/
    LOG_INIT("ibv_destroy_qp: %d QPs\n", MAX_NUM_OF_QPS);
    int i;
    for (i = 0; i < MAX_NUM_OF_QPS; i++) {
        if (rdma_dev->qps[i])  {
            ret_val = ibv_destroy_qp(rdma_dev->qps[i]);
            if (ret_val) {
                fprintf(stderr, "Couldn't destroy QP %d: error %d\n", i, ret_val);
                return;
            }
        }
    }

    LOG_INIT("ibv_destroy_cq(%p)\n", rdma_dev->virt_cq.cq);
    if (rdma_dev->virt_cq.cq) {
        ret_val = ibv_destroy_cq(MY_RDMA_DEV_CQ(rdma_dev));
    }
    if (ret_val) {
        fprintf(stderr, "Couldn't destroy CQ, error %d\n", ret_val);
        return;
    }

    LOG_INIT("ibv_dealloc_pd(%p)\n", rdma_dev->pd);
    ret_val = ibv_dealloc_pd(rdma_dev->pd);
    if (ret_val) {
        fprintf(stderr, "Couldn't deallocate PD, error %d\n", ret_val);
        return;
    }

    close_ib_device(rdma_dev);

    free(rdma_dev);

    return;
}

/****************************************************************************************
 * Memory buffer allocation, registration mr
 * Return value: 0 - success, 1 - error
 ****************************************************************************************/
int rdma_buffer_reg(struct rdma_device *rdma_dev, size_t length)
{
    struct rdma_buffer *rdma_buff;
    int    ret_val;

    /* CPU memory buffer allocation */
    rdma_dev->buf_addr = work_buffer_alloc(length);
    if (!rdma_dev->buf_addr) {
        return 1;
    }
    rdma_dev->buf_size = length;
    
    enum ibv_access_flags   access_flags =  IBV_ACCESS_LOCAL_WRITE |
                                            IBV_ACCESS_REMOTE_WRITE;
    /*In the case of local buffer we can use IBV_ACCESS_LOCAL_WRITE only flag*/
    LOG_INIT("ibv_reg_mr(pd %p, buf %p, size = %lu, access_flags = 0x%08x\n",
             rdma_dev->pd, rdma_dev->buf_addr, rdma_dev->buf_size, access_flags);
    rdma_dev->mr = ibv_reg_mr(rdma_dev->pd, rdma_dev->buf_addr, rdma_dev->buf_size, access_flags);
    if (!rdma_dev->mr) {
        fprintf(stderr, "Couldn't register GPU MR\n");
        free(rdma_dev->buf_addr);
        return 1;
    }
    LOG_INIT("ibv_reg_mr completed: rkey = 0x%08x\n", rdma_dev->mr->rkey);

    return 0;
}

//============================================================================================
void rdma_buffer_dereg(struct rdma_device *rdma_dev)
{
    int ret_val;

    LOG_INIT("ibv_dereg_mr(%p)\n", rdma_dev->mr);
    if (rdma_dev->mr) {
        ret_val = ibv_dereg_mr(rdma_dev->mr);
        if (ret_val) {
            fprintf(stderr, "Couldn't deregister MR, error %d\n", ret_val);
            return;
        }
    }
    if (rdma_dev->buf_addr) {
        LOG_INIT("Free memory buffer (%p)\n", rdma_dev->buf_addr);
        free(rdma_dev->buf_addr);
        rdma_dev->buf_addr = NULL;
    }
}

//============================================================================================
static void wire_gid_to_gid(const char *wgid, union ibv_gid *gid)
{
    char tmp[9];
    uint32_t v32;
    uint32_t *raw = (uint32_t *)gid->raw;
    int i;

    for (tmp[8] = 0, i = 0; i < 4; ++i) {
        memcpy(tmp, wgid + i * 8, 8);
        sscanf(tmp, "%x", &v32);
        raw[i] = ntohl(v32);
    }
}

void gid_to_wire_gid(const union ibv_gid *gid, char wgid[])
{
    int i;
    uint32_t *raw = (uint32_t *)gid->raw;

    for (i = 0; i < 4; ++i)
        sprintf(&wgid[i * 8], "%08x", htonl(raw[i]));
}

//============================================================================================
int fill_exchange_string(struct rdma_device *rdma_dev, int qps, char *exch_string, size_t length)
{
    char *iter = exch_string;

    if (qps > MAX_NUM_OF_QPS) {
        fprintf(stderr, "QPs number (%i) is greater than maximum (%i)\n",
                  qps, MAX_NUM_OF_QPS);
        return 0;
    }
    if (length < (sizeof "0102030405060708:01020304:01020304:0102030405060708090a0b0c0d0e0f10:01020304") + (qps * sizeof "010203")) {
        fprintf(stderr, "exchange string length (%lu) is less than required (%lu) for sending data\n",
                length,
                (sizeof "0102030405060708:01020304:01020304:0102030405060708090a0b0c0d0e0f10:01020304") + (qps * sizeof "010203") );
        return 0;
    }
    /*       addr             size     rkey
            "0102030405060708:01020304:01020304" */
    sprintf(iter, "%016llx:%08lx:%08x:",
            (unsigned long long)rdma_dev->buf_addr,
            (unsigned long)rdma_dev->buf_size,
            rdma_dev->mr->rkey);
    iter += sizeof "0102030405060708:01020304:01020304";
    gid_to_wire_gid(&rdma_dev->gid, iter);
    iter += sizeof "0102030405060708090a0b0c0d0e0f10" - 1;
    sprintf(iter, ":%08x", qps);
    iter += sizeof "01020304";

    int i;
    for (i = 0; i < qps; i++) {
        sprintf(iter, ":%06x", rdma_dev->qps[i]->qp_num);
        iter += sizeof "010203";
    }
    iter[0] = '\0';
    
    return (strlen(exch_string) + 1)/*including the terminating null character*/;
}

int parse_exchange_string(struct rdma_device *rdma_dev, char *exch_string)
{
    char *iter = exch_string;
    int   ret_val;
    int   qps;
    unsigned long   rem_buf_size;

    /*       addr             size     rkey
            "0102030405060708:01020304:01020304" */
    ret_val = sscanf(iter, "%llx:%lx:%lx",
                     &rdma_dev->rem_buf_addr,
                     &rem_buf_size,
                     &rdma_dev->rem_buf_rkey);
    if (ret_val < 3) {
        iter[sizeof "0102030405060708:01020304:01020304"] = '\0';
        fprintf(stderr, "Failed to extract rem_buf_addr, rem_buf_size and rem_buf_rkey from %s\n",
                  iter);
        return 1;
    }
    if (rem_buf_size < rdma_dev->buf_size) {
        LOG_INIT("Remote size %lu < local size %lu, changing the local size to %lu\n",
                 rem_buf_size, rdma_dev->buf_size, rem_buf_size);
        rdma_dev->buf_size = rem_buf_size;
    }
    iter += sizeof "0102030405060708:01020304:01020304";
    wire_gid_to_gid(iter, &rdma_dev->rem_gid);
    iter += sizeof "0102030405060708090a0b0c0d0e0f10";
    ret_val = sscanf(iter, "%x", &qps);
    if (ret_val < 1) {
        iter[sizeof "01020304"] = '\0';
        fprintf(stderr, "Failed to extract qps from %s\n",
                  iter);
        return 1;
    }
    if (qps > MAX_NUM_OF_QPS) {
        fprintf(stderr, "QPs number (%i) is greater than maximum (%i)\n",
                  qps, MAX_NUM_OF_QPS);
        return 1;
    }
    iter += sizeof "01020304";

    int i;
    for (i = 0; i < qps; i++) {
        ret_val = sscanf(iter, "%x", &(rdma_dev->rem_qpns[i]));
        if (ret_val < 1) {
            iter[sizeof "010203"] = '\0';
            fprintf(stderr, "Failed to extract rem_qpns[%d] from %s\n",
                      i, iter);
            return 1;
        }
        iter += sizeof "010203";
    }
    
    return 0;
}

int parse_exchange_string_no_qps_array(struct rdma_device *rdma_dev, char *exch_string, int *p_qps)
{
    char *iter = exch_string;
    int   ret_val;
    unsigned long   rem_buf_size;

    /*       addr             size     rkey
            "0102030405060708:01020304:01020304" */
    ret_val = sscanf(iter, "%llx:%lx:%lx",
                     &rdma_dev->rem_buf_addr,
                     &rem_buf_size,
                     &rdma_dev->rem_buf_rkey);
    if (ret_val < 3) {
        iter[sizeof "0102030405060708:01020304:01020304"] = '\0';
        fprintf(stderr, "Failed to extract rem_buf_addr, rem_buf_size and rem_buf_rkey from %s\n",
                  iter);
        return 1;
    }
    if (rem_buf_size < rdma_dev->buf_size) {
        LOG_INIT("Remote size %lu < local size %lu, changing the local size to %lu\n",
                 rem_buf_size, rdma_dev->buf_size, rem_buf_size);
        rdma_dev->buf_size = rem_buf_size;
    }

    iter += sizeof "0102030405060708:01020304:01020304";
    LOG_DEBUG("parse_exchange_string_no_qps_array: before wire_gid_to_gid: iter %s\n", iter);
    wire_gid_to_gid(iter, &rdma_dev->rem_gid);
    iter += sizeof "0102030405060708090a0b0c0d0e0f10";
    LOG_DEBUG("parse_exchange_string_no_qps_array: before scan qps: iter %s\n", iter);
    ret_val = sscanf(iter, "%x", p_qps);
    if (ret_val < 1) {
        iter[sizeof "01020304"] = '\0';
        fprintf(stderr, "Failed to extract qps from %s\n",
                  iter);
        return 1;
    }
    LOG_DEBUG("parse_exchange_string_no_qps_array: qps = %d\n", *p_qps);
    if (*p_qps > MAX_NUM_OF_QPS) {
        fprintf(stderr, "QPs number (%i) is greater than maximum (%i)\n",
                  *p_qps, MAX_NUM_OF_QPS);
        return 1;
    }
    
    return 0;
}

int parse_exchange_string_qps_array_only(struct rdma_device *rdma_dev, char *exch_string, int qps)
{
    char *iter = exch_string;
    int   ret_val;
    int i;
    
    for (i = 0; i < qps; i++) {
        ret_val = sscanf(iter, "%x", &(rdma_dev->rem_qpns[i]));
        if (ret_val < 1) {
            iter[sizeof "010203"] = '\0';
            fprintf(stderr, "Failed to extract rem_qpns[%d] from %s\n",
                      i, iter);
            return 1;
        }
        iter += sizeof "010203";
    }
    
    return 0;
}

//============================================================================================
int rdma_write_to_peer(struct rdma_device *rdma_dev, int qp_cnt, uint64_t wr_id)
{
    LOG_DEBUG("rdma_write_to_peer: qp_cnt = %d, wr_id = %lu\n", qp_cnt, wr_id);
    int    ret_val;
	struct ibv_sge sg_list = {
		.addr	= (uint64_t)rdma_dev->buf_addr,
		.length = (uint32_t)rdma_dev->buf_size,
		.lkey	= rdma_dev->mr->lkey
	};
	struct ibv_send_wr send_wr = {
		.wr_id	    = wr_id,
		.sg_list    = &sg_list,
		.num_sge    = 1,
		.opcode     = IBV_WR_RDMA_WRITE,
		.send_flags = IBV_SEND_SIGNALED,
	};
	struct ibv_send_wr *bad_wr;

    send_wr.wr.rdma.remote_addr = (uint64_t)(rdma_dev->rem_buf_addr);
    send_wr.wr.rdma.rkey = (uint32_t)rdma_dev->rem_buf_rkey;

#ifdef PRINT_LATENCY
    struct ibv_values_ex ts_values = {
        .comp_mask = IBV_VALUES_MASK_RAW_CLOCK,
        .raw_clock = {} /*struct timespec*/
    };

    ret_val = ibv_query_rt_values_ex(rdma_dev->context, &ts_values);
    if (ret_val) {
        fprintf(stderr, "ibv_query_rt_values_ex failed before ibv_post_send call\n");
        return 1;
    }

    unsigned int latency_idx = (unsigned int)(wr_id & (LATENCY_ARR_SIZE-1));

    rdma_dev->latency[latency_idx].wr_start_ts = ts_values.raw_clock.tv_nsec; /*the value in hca clocks*/
#endif /*PRINT_LATENCY*/
    
    LOG_DEBUG("rdma_write_to_peer: ibv_post_send: qp_num = %06x, wr_id = %lu, linked send cq = %p\n",
              rdma_dev->qps[qp_cnt]->qp_num, send_wr.wr_id, rdma_dev->qps[qp_cnt]->send_cq);
    ret_val = ibv_post_send(rdma_dev->qps[qp_cnt], &send_wr, &bad_wr);
    if (ret_val) {
        fprintf(stderr, "ibv_post_send failed\n");
        return 1;
    }
    
#ifdef PRINT_LATENCY
    ret_val = ibv_query_rt_values_ex(rdma_dev->context, &ts_values);
    if (ret_val) {
        fprintf(stderr, "ibv_query_rt_values_ex failed after ibv_post_send call\n");
        return 1;
    }
    rdma_dev->latency[latency_idx].wr_after_ts = ts_values.raw_clock.tv_nsec; /*the value in hca clocks*/
#endif /*PRINT_LATENCY*/
    
    return ret_val;
}

//============================================================================================
int rdma_poll_completions(struct rdma_device *rdma_dev)
{
    /* Polling completion queue */
    LOG_DEBUG("Polling completion queue: ibv_poll_cq\n");

#ifdef PRINT_LATENCY
    struct ibv_poll_cq_attr cq_attr = {};
    uint64_t comp_ts;
    int      ret_val;

    /* Infinite loop untill we succeed to poll completion entry */
    do {
        ret_val = ibv_start_poll(rdma_dev->virt_cq.cq_ex, &cq_attr);
    } while (ret_val == ENOENT);

    if (ret_val) {
        fprintf(stderr, "poll CQ failed %d\n", ret_val);
        return ret_val;
    }
    
    unsigned int latency_idx = (unsigned int)(rdma_dev->virt_cq.cq_ex->wr_id & (LATENCY_ARR_SIZE-1));

    rdma_dev->latency[latency_idx].completion_ts = ibv_wc_read_completion_ts(rdma_dev->virt_cq.cq_ex);
    
    struct ibv_values_ex ts_values = {
        .comp_mask = IBV_VALUES_MASK_RAW_CLOCK,
        .raw_clock = {} /*struct timespec*/
    };

    ret_val = ibv_query_rt_values_ex(rdma_dev->context, &ts_values);
    if (ret_val) {
        fprintf(stderr, "ibv_query_rt_values_ex failed after ibv_wr_start call\n");
        ts_values.raw_clock.tv_nsec = 0;
    }
    rdma_dev->latency[latency_idx].read_comp_ts = ts_values.raw_clock.tv_nsec;

    uint64_t    wr_send_latency    = rdma_dev->latency[latency_idx].wr_after_ts   - rdma_dev->latency[latency_idx].wr_start_ts;
    uint64_t    completion_latency = rdma_dev->latency[latency_idx].completion_ts - rdma_dev->latency[latency_idx].wr_start_ts;
    uint64_t    read_comp_latency  = rdma_dev->latency[latency_idx].read_comp_ts  - rdma_dev->latency[latency_idx].completion_ts;
    
    rdma_dev->measure_index++;
    rdma_dev->wr_send_latency_sum    += wr_send_latency;
    rdma_dev->completion_latency_sum += completion_latency;
    rdma_dev->read_comp_latency_sum  += read_comp_latency;

    rdma_dev->min_wr_send_latency    = (wr_send_latency < rdma_dev->min_wr_send_latency)?
                                       wr_send_latency: rdma_dev->min_wr_send_latency;
    rdma_dev->min_completion_latency = (completion_latency < rdma_dev->min_completion_latency)?
                                       completion_latency: rdma_dev->min_completion_latency;
    rdma_dev->min_read_comp_latency  = (read_comp_latency < rdma_dev->min_read_comp_latency)?
                                       read_comp_latency: rdma_dev->min_read_comp_latency;
    
    rdma_dev->max_wr_send_latency    = (wr_send_latency > rdma_dev->max_wr_send_latency)?
                                       wr_send_latency: rdma_dev->max_wr_send_latency;
    rdma_dev->max_completion_latency = (completion_latency > rdma_dev->max_completion_latency)?
                                       completion_latency: rdma_dev->max_completion_latency;
    rdma_dev->max_read_comp_latency  = (read_comp_latency > rdma_dev->max_read_comp_latency)?
                                       read_comp_latency: rdma_dev->max_read_comp_latency;
    
    LOG_TRACE("PRINT_LATENCY: wr_id = %6lu, wr_sent latency: current %8lu, min %8lu, max %8lu, avg %8lu (nSec)\n",
              rdma_dev->virt_cq.cq_ex->wr_id,
              wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
              rdma_dev->min_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
              rdma_dev->max_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
              rdma_dev->wr_send_latency_sum / rdma_dev->measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

    LOG_TRACE("PRINT_LATENCY:   completion latency           : current %8lu, min %8lu, max %8lu, avg %8lu (nSec)\n",
              completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
              rdma_dev->min_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
              rdma_dev->max_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
              rdma_dev->completion_latency_sum / rdma_dev->measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);
    
    LOG_TRACE("PRINT_LATENCY:   read_comp latency            : current %8lu, min %8lu, max %8lu, avg %8lu (nSec)\n",
              read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
              rdma_dev->min_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
              rdma_dev->max_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
              rdma_dev->read_comp_latency_sum / rdma_dev->measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

    /* ret_val = ibv_next_poll(rdma_dev->cq); - we don't need next_poll, just one completion expected */
    
    ibv_end_poll(rdma_dev->virt_cq.cq_ex);

    if (rdma_dev->virt_cq.cq_ex->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Failed status \"%s\" (%d) for wr_id %d\n",
                ibv_wc_status_str(rdma_dev->virt_cq.cq_ex->status),
                rdma_dev->virt_cq.cq_ex->status, (int) rdma_dev->virt_cq.cq_ex->wr_id);
        return -1;
    }
#else /*PRINT_LATENCY*/
    
    struct ibv_wc wc[10]; /*should be less than CQ_DEPTH*/
    int    i, wcn;
    
    do {
        wcn = ibv_poll_cq(rdma_dev->virt_cq.cq, 1, wc);
        if (wcn < 0) {
            fprintf(stderr, "poll CQ failed %d\n", wcn);
            return -1;
        }
        LOG_DEBUG("ibv_poll_cq: %p, 1 - returned %d)\n", rdma_dev->virt_cq.cq, wcn);
        if (wcn == 0) {
            sleep(1/*Sec*/);
        }
    } while (wcn < 1);
    
    for (i = 0; i < wcn; ++i) {
        if (wc[i].status != IBV_WC_SUCCESS) {
            fprintf(stderr, "Failed status \"%s\" (%d) for wr_id %d\n",
                    ibv_wc_status_str(wc[i].status),
                    wc[i].status, (int) wc[i].wr_id);
            return -1;
        }
    }
#endif /*PRINT_LATENCY*/
    return 0;
}

/****************************************************************************************
 * Modify target QPs state to RTR (on the client side)
 * Return value: 0 - success, 1 - error
 ****************************************************************************************/
int modify_target_qps_to_rtr(struct rdma_device *rdma_dev, int qps)
{
    struct ibv_qp_attr      qp_attr;
    enum ibv_qp_attr_mask   attr_mask;

    memset(&qp_attr, 0, sizeof qp_attr);
    
    /* - - - - - - -  Modify QP to RTR  - - - - - - - */
    qp_attr.qp_state           = IBV_QPS_RTR;
    qp_attr.path_mtu           = rdma_dev->mtu;
    //qp_attr.rq_psn             = 0;
    qp_attr.max_dest_rd_atomic = 1;
    qp_attr.min_rnr_timer      = 16;

    qp_attr.ah_attr.port_num       = rdma_dev->ib_port;
    qp_attr.ah_attr.is_global      = 1;
    qp_attr.ah_attr.grh.hop_limit  = 1;
    qp_attr.ah_attr.grh.sgid_index = rdma_dev->gidx;
    qp_attr.ah_attr.grh.dgid       = rdma_dev->rem_gid;
    qp_attr.ah_attr.grh.traffic_class = TC_PRIO << 5; // <<3 for dscp2prio, <<2 for ECN bits
    
    attr_mask = IBV_QP_STATE              |
                IBV_QP_AV                 |
                IBV_QP_PATH_MTU           |
                IBV_QP_DEST_QPN           |
                IBV_QP_RQ_PSN             |
                IBV_QP_MAX_DEST_RD_ATOMIC |
                IBV_QP_MIN_RNR_TIMER;
    
    int i;
    LOG_INIT("ibv_modify_qp: %d QPs to qp_state = %d, attr_mask = 0x%x)\n",
             qps, qp_attr.qp_state, attr_mask);
    for (i = 0; i < qps; i++) {
        qp_attr.dest_qp_num = rdma_dev->rem_qpns[i];
        if (ibv_modify_qp(rdma_dev->qps[i], &qp_attr, attr_mask)) {
            fprintf(stderr, "Failed to modify QP %d to RTR\n", i);
            return 1;
        }
        LOG_DEBUG("ibv_modify_qp qps[%d] to RTR completed qp_num 0x%lx -> remote qp_num 0x%lx\n",
                  i, rdma_dev->qps[i]->qp_num, rdma_dev->rem_qpns[i]);
    }
    LOG_INIT("Modify %d QPs to RTR completed\n", qps);
    
    return 0;
}

/****************************************************************************************
 * Modify source QPs state to RTR and then to RTS (on the server side)
 * Return value: 0 - success, 1 - error
 ****************************************************************************************/
int modify_source_qps_to_rtr_and_rts(struct rdma_device *rdma_dev, int qps)
{
    struct ibv_qp_attr      qp_attr;
    enum ibv_qp_attr_mask   attr_mask;

    memset(&qp_attr, 0, sizeof qp_attr);
    
    /* - - - - - - -  Modify QP to RTR  - - - - - - - */
    qp_attr.qp_state           = IBV_QPS_RTR;
    qp_attr.path_mtu           = rdma_dev->mtu;
    //qp_attr.rq_psn             = 0;
    qp_attr.max_dest_rd_atomic = 1;
    qp_attr.min_rnr_timer      = 16;

    qp_attr.ah_attr.port_num       = rdma_dev->ib_port;
    qp_attr.ah_attr.is_global      = 1;
    qp_attr.ah_attr.grh.hop_limit  = 1;
    qp_attr.ah_attr.grh.sgid_index = rdma_dev->gidx;
    qp_attr.ah_attr.grh.dgid       = rdma_dev->rem_gid;
    qp_attr.ah_attr.grh.traffic_class = TC_PRIO << 5; // <<3 for dscp2prio, <<2 for ECN bits
    
    attr_mask = IBV_QP_STATE              |
                IBV_QP_AV                 |
                IBV_QP_PATH_MTU           |
                IBV_QP_DEST_QPN           |
                IBV_QP_RQ_PSN             |
                IBV_QP_MAX_DEST_RD_ATOMIC |
                IBV_QP_MIN_RNR_TIMER;
    
    int i;
    LOG_INIT("ibv_modify_qp: %d QPs to qp_state = %d, attr_mask = 0x%x)\n",
             qps, qp_attr.qp_state, attr_mask);
    for (i = 0; i < qps; i++) {
        qp_attr.dest_qp_num = rdma_dev->rem_qpns[i];
        if (ibv_modify_qp(rdma_dev->qps[i], &qp_attr, attr_mask)) {
            fprintf(stderr, "Failed to modify QP %d to RTR\n", i);
            return 1;
        }
        LOG_DEBUG("ibv_modify_qp qps[%d] to RTR completed qp_num 0x%lx -> remote qp_num 0x%lx\n",
                  i, rdma_dev->qps[i]->qp_num, rdma_dev->rem_qpns[i]);
    }
    LOG_INIT("Modify %d QPs to RTR completed\n", qps);
    

    /* - - - - - - -  Modify QP to RTS  - - - - - - - */
    qp_attr.qp_state      = IBV_QPS_RTS;
    qp_attr.timeout       = 16;
    qp_attr.retry_cnt     = 7;
    qp_attr.rnr_retry     = 7;
    //qp_attr.sq_psn        = 0;
    qp_attr.max_rd_atomic = 1;

    attr_mask = IBV_QP_STATE            |
                IBV_QP_TIMEOUT          |
                IBV_QP_RETRY_CNT        |
                IBV_QP_RNR_RETRY        |
                IBV_QP_SQ_PSN           |
                IBV_QP_MAX_QP_RD_ATOMIC ;
    
    LOG_INIT("ibv_modify_qp: %d QPs to qp_state = %d, attr_mask = 0x%x)\n",
             qps, qp_attr.qp_state, attr_mask);
    for (i = 0; i < qps; i++) {
        if (ibv_modify_qp(rdma_dev->qps[i], &qp_attr, attr_mask)) {
            fprintf(stderr, "Failed to modify QP %d to RTS\n", i);
            return 1;
        }
        LOG_DEBUG("ibv_modify_qp qps[%d] to RTS completed\n", i);
    }
    LOG_INIT("Modify %d QPs to RTS completed\n", qps);
    
    return 0;
}

//============================================================================================


