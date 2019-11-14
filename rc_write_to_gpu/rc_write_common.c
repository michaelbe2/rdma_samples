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

#define LATENCY_ARR_SIZE    (1<<8) /*should be power of 2*/
#define CQ_DEPTH            16
#define SEND_Q_DEPTH        4
#define MAX_SEND_SGE        8
#define TC_PRIO             3

struct wr_ts_data {
    uint64_t    wr_start_ts;
    uint64_t    wr_after_ts;
    uint64_t    completion_ts;
    uint64_t    read_comp_ts;
};

struct wr_latency_data {
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
};

struct rdma_device {
    struct rdma_event_channel *cm_channel;
    struct rdma_cm_id *cm_id;
    
    struct ibv_context *context;
    struct ibv_pd      *pd;

    struct ibv_cq_ex   *cq_ex; /*We need ibv_cq_ex and not ibv_cq to get completion timestamp*/
    struct ibv_qp      *qp;
    
    /* Remote side attributes */
    uint32_t    rem_qpn;
    uint64_t    rem_cpu_buf_addr;
    uint64_t    rem_gpu_buf_addr;
    uint32_t    rem_cpu_buf_rkey;
    uint32_t    rem_gpu_buf_rkey;
            /* We don't need rem_buf_size, we use the same
               buf_size for both local and remote sides */
    union ibv_gid       rem_gid;
    
    /* Address handler (port info) relateed fields */
    int             ib_port;
    int             gidx;
    union ibv_gid   gid;
    enum ibv_mtu    mtu;

    /* Buffer Related fields */
    void           *cpu_buf_addr;   //uint64_t  addr;
    void           *gpu_buf_addr;   //uint64_t  addr;
    uint32_t        buf_size;
    /* MR Related fields */
    struct ibv_mr  *mr_cpu;
    struct ibv_mr  *mr_gpu;
    
    /* Print Latency Related fields */
    uint64_t            hca_core_clock_kHz;
    struct wr_ts_data   ts_data[LATENCY_ARR_SIZE];
    struct wr_latency_data  w_to_cpu_lat;
    struct wr_latency_data  w_to_gpu_lat;
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
	struct ibv_cq_init_attr_ex cq_attr_ex;
	
    memset(&cq_attr_ex, 0, sizeof(cq_attr_ex));
	cq_attr_ex.cqe = CQ_DEPTH;
	cq_attr_ex.cq_context = rdma_dev;
	cq_attr_ex.channel = NULL;
	cq_attr_ex.comp_vector = 0;
	cq_attr_ex.wc_flags = IBV_WC_EX_WITH_COMPLETION_TIMESTAMP;

    LOG_INIT ("ibv_create_cq_ex(rdma_dev->context = %p, &cq_attr_ex)\n", rdma_dev->context);
	rdma_dev->cq_ex = ibv_create_cq_ex(rdma_dev->context, &cq_attr_ex);
    if (!rdma_dev->cq_ex) {
        fprintf(stderr, "Couldn't create CQ ex\n");
        goto clean_pd;
    }
    LOG_INIT("created cq_ex %p\n", rdma_dev->cq_ex);

    /* **********************************  Create QP  ********************************** */
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_type = IBV_QPT_RC,
        .send_cq = ibv_cq_ex_to_cq(rdma_dev->cq_ex),
        .recv_cq = ibv_cq_ex_to_cq(rdma_dev->cq_ex),
        .cap     = {
            .max_send_wr  = 1, /*actually, we don't send or receive WRs*/
            .max_recv_wr  = 1,
            .max_send_sge = 1,
            .max_recv_sge = 1
        },
    };
    rdma_dev->qp = ibv_create_qp(rdma_dev->pd, &qp_init_attr);
    if (!rdma_dev->qp)  {
        fprintf(stderr, "Couldn't create QP\n");
        goto clean_cq;
    }
    LOG_INIT("ibv_create_qp completed: qp_num = 0x%06x\n", rdma_dev->qp->qp_num);

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
    LOG_INIT("ibv_modify_qp, qp_attr.qp_state = %d (INIT), attr_mask = 0x%x\n",
             qp_attr.qp_state, attr_mask);
    ret_val = ibv_modify_qp(rdma_dev->qp, &qp_attr, attr_mask);
    if (ret_val) {
        fprintf(stderr, "Failed to modify QP to INIT, error %d\n", ret_val);
        goto clean_qp;
    }
    LOG_DEBUG("ibv_modify_qp to INIT state completed, qp_num 0x%06x\n",
              rdma_dev->qp->qp_num);

    return rdma_dev;

clean_qp:
    if (rdma_dev->qp)  {
        ibv_destroy_qp(rdma_dev->qp);
    }

clean_cq:
    if (rdma_dev->cq_ex) {
        ibv_destroy_cq(ibv_cq_ex_to_cq(rdma_dev->cq_ex));
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
	struct ibv_cq_init_attr_ex cq_attr_ex;
	
    memset(&cq_attr_ex, 0, sizeof(cq_attr_ex));
	cq_attr_ex.cqe = CQ_DEPTH;
	cq_attr_ex.cq_context = rdma_dev;
	cq_attr_ex.channel = NULL;
	cq_attr_ex.comp_vector = 0;
	cq_attr_ex.wc_flags = IBV_WC_EX_WITH_COMPLETION_TIMESTAMP;

    LOG_INIT ("ibv_create_cq_ex(rdma_dev->context = %p, &cq_attr_ex)\n", rdma_dev->context);
	rdma_dev->cq_ex = ibv_create_cq_ex(rdma_dev->context, &cq_attr_ex);
    if (!rdma_dev->cq_ex) {
        fprintf(stderr, "Couldn't create CQ ex\n");
        goto clean_pd;
    }
    LOG_INIT("created cq_ex %p\n", rdma_dev->cq_ex);

    /* **********************************  Create QP  ********************************** */
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_type = IBV_QPT_RC,
        .send_cq = ibv_cq_ex_to_cq(rdma_dev->cq_ex),
        .recv_cq = ibv_cq_ex_to_cq(rdma_dev->cq_ex),
        .cap     = {
            .max_send_wr  = SEND_Q_DEPTH,
            .max_recv_wr  = 1,
            .max_send_sge = MAX_SEND_SGE,
            .max_recv_sge = 1
        },
    };
    rdma_dev->qp = ibv_create_qp(rdma_dev->pd, &qp_init_attr);
    if (!rdma_dev->qp)  {
        fprintf(stderr, "Couldn't create QP\n");
        goto clean_cq;
    }
    LOG_INIT("ibv_create_qp completed: qp_num = 0x%06x\n", rdma_dev->qp->qp_num);
    
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
    LOG_INIT("ibv_modify_qp, qp_attr.qp_state = %d (INIT), attr_mask = 0x%x\n",
             qp_attr.qp_state, attr_mask);
    ret_val = ibv_modify_qp(rdma_dev->qp, &qp_attr, attr_mask);
    if (ret_val) {
        fprintf(stderr, "Failed to modify QP to INIT, error %d\n", ret_val);
        goto clean_qp;
    }
    LOG_DEBUG("ibv_modify_qp to INIT state completed, qp_num 0x%06x\n",
              rdma_dev->qp->qp_num);
    
    struct ibv_device_attr_ex           device_attr_ex = {};
    
    /* Init Print Latency related attributes */
    ret_val = ibv_query_device_ex(rdma_dev->context, NULL, &device_attr_ex);
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

    rdma_dev->w_to_cpu_lat.min_wr_send_latency    = 0x8FFFFFFFFFFFFFFF;
    rdma_dev->w_to_cpu_lat.min_completion_latency = 0x8FFFFFFFFFFFFFFF;
    rdma_dev->w_to_cpu_lat.min_read_comp_latency  = 0x8FFFFFFFFFFFFFFF;
    
    rdma_dev->w_to_gpu_lat.min_wr_send_latency    = 0x8FFFFFFFFFFFFFFF;
    rdma_dev->w_to_gpu_lat.min_completion_latency = 0x8FFFFFFFFFFFFFFF;
    rdma_dev->w_to_gpu_lat.min_read_comp_latency  = 0x8FFFFFFFFFFFFFFF;
    
    return rdma_dev;

clean_qp:
    if (rdma_dev->qp)  {
        ibv_destroy_qp(rdma_dev->qp);
    }

clean_cq:
    if (rdma_dev->cq_ex) {
        ibv_destroy_cq(ibv_cq_ex_to_cq(rdma_dev->cq_ex));
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

    /* Print Latancy at the end of run (before destroying device) */
    if (rdma_dev->w_to_cpu_lat.measure_index) {
        LOG_INIT("Print Write to CPU Latency %6lu wr-s:\n", rdma_dev->w_to_cpu_lat.measure_index);
        LOG_INIT("    wr_sent latency   : min %8lu, max %8lu, avg %8lu (nSec)\n",
                 rdma_dev->w_to_cpu_lat.min_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_cpu_lat.max_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_cpu_lat.wr_send_latency_sum / rdma_dev->w_to_cpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_INIT("    completion latency: min %8lu, max %8lu, avg %8lu (nSec)\n",
                 rdma_dev->w_to_cpu_lat.min_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_cpu_lat.max_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_cpu_lat.completion_latency_sum / rdma_dev->w_to_cpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_INIT("    read_comp latency : min %8lu, max %8lu, avg %8lu (nSec)\n",
                 rdma_dev->w_to_cpu_lat.min_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_cpu_lat.max_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_cpu_lat.read_comp_latency_sum / rdma_dev->w_to_cpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);
        //fflush(stdout);
    }
    if (rdma_dev->w_to_gpu_lat.measure_index) {
        LOG_INIT("Print Write to GPU Latency %6lu wr-s:\n", rdma_dev->w_to_gpu_lat.measure_index);
        LOG_INIT("    wr_sent latency   : min %8lu, max %8lu, avg %8lu (nSec)\n",
                 rdma_dev->w_to_gpu_lat.min_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_gpu_lat.max_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_gpu_lat.wr_send_latency_sum / rdma_dev->w_to_gpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_INIT("    completion latency: min %8lu, max %8lu, avg %8lu (nSec)\n",
                 rdma_dev->w_to_gpu_lat.min_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_gpu_lat.max_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_gpu_lat.completion_latency_sum / rdma_dev->w_to_gpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_INIT("    read_comp latency : min %8lu, max %8lu, avg %8lu (nSec)\n",
                 rdma_dev->w_to_gpu_lat.min_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_gpu_lat.max_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                 rdma_dev->w_to_gpu_lat.read_comp_latency_sum / rdma_dev->w_to_gpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);
        fflush(stdout);
    }

    LOG_INIT("ibv_destroy_qp\n");
    if (rdma_dev->qp)  {
        ret_val = ibv_destroy_qp(rdma_dev->qp);
        if (ret_val) {
            fprintf(stderr, "Couldn't destroy QP, error %d\n", ret_val);
            return;
        }
    }

    if (rdma_dev->cq_ex) {
        LOG_INIT("ibv_destroy_cq(%p)\n", rdma_dev->cq_ex);
        ret_val = ibv_destroy_cq(ibv_cq_ex_to_cq(rdma_dev->cq_ex));
        if (ret_val) {
            fprintf(stderr, "Couldn't destroy CQ, error %d\n", ret_val);
            return;
        }
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
int rdma_buffer_reg(struct rdma_device *rdma_dev, size_t length, int use_cuda, const char *bdf)
{
    struct rdma_buffer *rdma_buff;
    int    ret_val;

    /* CPU memory buffer allocation */
    rdma_dev->cpu_buf_addr = work_buffer_alloc(length, 0, NULL);
    if (!rdma_dev->cpu_buf_addr) {
        return 1;
    }
    /* GPU memory buffer allocation - TODO*/
    rdma_dev->gpu_buf_addr = work_buffer_alloc(length, use_cuda, bdf);
    if (!rdma_dev->gpu_buf_addr) {
        work_buffer_free(rdma_dev->cpu_buf_addr, 0);
        rdma_dev->cpu_buf_addr = NULL;
        return 1;
    }
    rdma_dev->buf_size = length;
    
    enum ibv_access_flags   access_flags =  IBV_ACCESS_LOCAL_WRITE |
                                            IBV_ACCESS_REMOTE_WRITE;
    /*In the case of local buffer we can use IBV_ACCESS_LOCAL_WRITE only flag*/
    LOG_INIT("ibv_reg_mr(pd %p, buf %p, size = %lu, access_flags = 0x%08x\n",
             rdma_dev->pd, rdma_dev->cpu_buf_addr, rdma_dev->buf_size, access_flags);
    rdma_dev->mr_cpu = ibv_reg_mr(rdma_dev->pd, rdma_dev->cpu_buf_addr, rdma_dev->buf_size, access_flags);
    if (!rdma_dev->mr_cpu) {
        fprintf(stderr, "Couldn't register CPU MR\n");
        work_buffer_free(rdma_dev->cpu_buf_addr, 0);
        work_buffer_free(rdma_dev->gpu_buf_addr, use_cuda);
        rdma_dev->cpu_buf_addr = NULL;
        rdma_dev->gpu_buf_addr = NULL;
        return 1;
    }
    LOG_INIT("ibv_reg_mr completed for CPU buffer: rkey = 0x%08x\n", rdma_dev->mr_cpu->rkey);

    LOG_INIT("ibv_reg_mr(pd %p, buf %p, size = %lu, access_flags = 0x%08x\n",
             rdma_dev->pd, rdma_dev->gpu_buf_addr, rdma_dev->buf_size, access_flags);
    rdma_dev->mr_gpu = ibv_reg_mr(rdma_dev->pd, rdma_dev->gpu_buf_addr, rdma_dev->buf_size, access_flags);
    if (!rdma_dev->mr_gpu) {
        fprintf(stderr, "Couldn't register GPU MR\n");
        ibv_dereg_mr(rdma_dev->mr_cpu);
        work_buffer_free(rdma_dev->cpu_buf_addr, 0);
        work_buffer_free(rdma_dev->gpu_buf_addr, use_cuda);
        rdma_dev->cpu_buf_addr = NULL;
        rdma_dev->gpu_buf_addr = NULL;
        return 1;
    }
    LOG_INIT("ibv_reg_mr completed for GPU buffer: rkey = 0x%08x\n", rdma_dev->mr_gpu->rkey);

    return 0;
}

//============================================================================================
void rdma_buffer_dereg(struct rdma_device *rdma_dev, int use_cuda)
{
    int ret_val;

    LOG_INIT("ibv_dereg_mr(%p)\n", rdma_dev->mr_cpu);
    if (rdma_dev->mr_cpu) {
        ret_val = ibv_dereg_mr(rdma_dev->mr_cpu);
        if (ret_val) {
            fprintf(stderr, "Couldn't deregister MR, error %d\n", ret_val);
            return;
        }
    }
    if (rdma_dev->cpu_buf_addr) {
        LOG_INIT("Free memory buffer (%p)\n", rdma_dev->cpu_buf_addr);
        work_buffer_free(rdma_dev->gpu_buf_addr, 0);
        free(rdma_dev->cpu_buf_addr);
        rdma_dev->gpu_buf_addr = NULL;
    }

    LOG_INIT("ibv_dereg_mr(%p)\n", rdma_dev->mr_gpu);
    if (rdma_dev->mr_gpu) {
        ret_val = ibv_dereg_mr(rdma_dev->mr_gpu);
        if (ret_val) {
            fprintf(stderr, "Couldn't deregister MR, error %d\n", ret_val);
            return;
        }
    }
    if (rdma_dev->gpu_buf_addr) {
        LOG_INIT("Free memory buffer (%p)\n", rdma_dev->gpu_buf_addr);
        work_buffer_free(rdma_dev->gpu_buf_addr, use_cuda);
        rdma_dev->gpu_buf_addr = NULL;
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
int fill_exchange_string(struct rdma_device *rdma_dev, char *exch_string, size_t length)
{
    if (length < EXCHANGE_STRING_LENGTH) {
        fprintf(stderr, "exchange string length (%lu) is less than required (%lu) for sending data\n",
                length, EXCHANGE_STRING_LENGTH );
        return 0;
    }
    /*       addr             size     rkey     gpu_addr         gpu_rkey qpn   
            "0102030405060708:01020304:01020304:0102030405060708:01020304:010203" */
    sprintf(exch_string, "%016lx:%08x:%08x:%016lx:%08x:%06x:",
            rdma_dev->cpu_buf_addr, rdma_dev->buf_size, rdma_dev->mr_cpu->rkey,
            rdma_dev->gpu_buf_addr, rdma_dev->mr_gpu->rkey, rdma_dev->qp->qp_num);
    
    char *gid_start = exch_string + EXCHANGE_STRING_NO_GID_LENGTH;
    
    gid_to_wire_gid(&rdma_dev->gid, gid_start);

    exch_string[EXCHANGE_STRING_LENGTH-1] = '\0';
    
    return (strlen(exch_string) + 1)/*including the terminating null character*/;
}

int parse_exchange_string(struct rdma_device *rdma_dev, char *exch_string)
{
    int             ret_val;
//    unsigned long   rem_buf_size = 0;
    unsigned int    rem_buf_size = 0;

    /*       addr             size     rkey     gpu_addr         gpu_rkey qpn
            "0102030405060708:01020304:01020304:0102030405060708:01020304:010203" */
    ret_val = sscanf(exch_string, "%lx:%x:%x:%x:%lx:%x",
                     &rdma_dev->rem_cpu_buf_addr,
                     &rem_buf_size,
                     &rdma_dev->rem_cpu_buf_rkey,
                     &rdma_dev->rem_gpu_buf_addr,
                     &rdma_dev->rem_gpu_buf_rkey,
                     &rdma_dev->rem_qpn);
    if (ret_val < 6) {
        fprintf(stderr, "Failed to extract rem_cpu/gpu_buf_addr, rem_buf_size, rem_cpu/gpu_buf_rkey and rem_qpn from %s, ret_val %d\n",
                exch_string, ret_val);
        return 1;
    }
    LOG_DEBUG("rem_buf_size = %u\n", rem_buf_size);
    if (rem_buf_size < rdma_dev->buf_size) {
        LOG_INIT("Remote size %lu < local size %lu, changing the local size to %lu\n",
                 rem_buf_size, rdma_dev->buf_size, rem_buf_size);
        rdma_dev->buf_size = rem_buf_size;
    }
    char *gid_start = exch_string + EXCHANGE_STRING_NO_GID_LENGTH;
    wire_gid_to_gid(gid_start, &rdma_dev->rem_gid);
    
    return 0;
}

//============================================================================================
int rdma_write_to_peer(struct rdma_device *rdma_dev, uint64_t wr_id, int to_gpu)
{
    LOG_DEBUG("rdma_write_to_peer: wr_id = %lu\n", wr_id);
    int    ret_val;
	struct ibv_sge sg_list = {
		.addr	= (uint64_t)rdma_dev->cpu_buf_addr,
		.length = (uint32_t)rdma_dev->buf_size,
		.lkey	= rdma_dev->mr_cpu->lkey
	};
	struct ibv_send_wr send_wr = {
		.wr_id	    = wr_id,
		.sg_list    = &sg_list,
		.num_sge    = 1,
		.opcode     = IBV_WR_RDMA_WRITE,
		.send_flags = IBV_SEND_SIGNALED,
	};
	struct ibv_send_wr *bad_wr;

    send_wr.wr.rdma.remote_addr = to_gpu? rdma_dev->rem_gpu_buf_addr: rdma_dev->rem_cpu_buf_addr;
    send_wr.wr.rdma.rkey        = to_gpu? rdma_dev->rem_gpu_buf_rkey: rdma_dev->rem_cpu_buf_rkey;

    /* Read Start timestamp for latency calculation */
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

    rdma_dev->ts_data[latency_idx].wr_start_ts = ts_values.raw_clock.tv_nsec; /*the value in hca clocks*/
    /* --------------------------------------------- */
    
    LOG_DEBUG("rdma_write_to_peer: ibv_post_send: qp_num = %06x, wr_id = %lu, linked send cq = %p\n",
              rdma_dev->qp->qp_num, send_wr.wr_id, rdma_dev->qp->send_cq);
    ret_val = ibv_post_send(rdma_dev->qp, &send_wr, &bad_wr);
    if (ret_val) {
        fprintf(stderr, "ibv_post_send failed\n");
        return 1;
    }
    
    /* Read after "post send" call timestamp for latency calculation */
    ret_val = ibv_query_rt_values_ex(rdma_dev->context, &ts_values);
    if (ret_val) {
        fprintf(stderr, "ibv_query_rt_values_ex failed after ibv_post_send call\n");
        return 1;
    }
    rdma_dev->ts_data[latency_idx].wr_after_ts = ts_values.raw_clock.tv_nsec; /*the value in hca clocks*/
    
    return ret_val;
}

//============================================================================================
int rdma_poll_completions(struct rdma_device *rdma_dev)
{
    /* Polling completion queue */
    LOG_DEBUG("Polling completion queue: ibv_poll_cq\n");

    struct ibv_poll_cq_attr cq_attr = {};
    uint64_t comp_ts;
    int      ret_val;

    /* Infinite loop untill we succeed to poll completion entry */
    do {
        ret_val = ibv_start_poll(rdma_dev->cq_ex, &cq_attr);
    } while (ret_val == ENOENT);

    if (ret_val) {
        fprintf(stderr, "poll CQ failed %d\n", ret_val);
        return ret_val;
    }
    if (rdma_dev->cq_ex->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Failed status \"%s\" (%d) for wr_id %d\n",
                ibv_wc_status_str(rdma_dev->cq_ex->status),
                rdma_dev->cq_ex->status, (int) rdma_dev->cq_ex->wr_id);
        ibv_end_poll(rdma_dev->cq_ex);
        return -1;
    }
    
    unsigned int latency_idx = (unsigned int)(rdma_dev->cq_ex->wr_id & (LATENCY_ARR_SIZE-1));

    rdma_dev->ts_data[latency_idx].completion_ts = ibv_wc_read_completion_ts(rdma_dev->cq_ex);
    
    struct ibv_values_ex ts_values = {
        .comp_mask = IBV_VALUES_MASK_RAW_CLOCK,
        .raw_clock = {} /*struct timespec*/
    };

    ret_val = ibv_query_rt_values_ex(rdma_dev->context, &ts_values);
    if (ret_val) {
        fprintf(stderr, "ibv_query_rt_values_ex failed after ibv_wr_start call\n");
        ts_values.raw_clock.tv_nsec = 0;
    }
    rdma_dev->ts_data[latency_idx].read_comp_ts = ts_values.raw_clock.tv_nsec;

    uint64_t wr_send_latency    = rdma_dev->ts_data[latency_idx].wr_after_ts   - rdma_dev->ts_data[latency_idx].wr_start_ts;
    uint64_t completion_latency = rdma_dev->ts_data[latency_idx].completion_ts - rdma_dev->ts_data[latency_idx].wr_start_ts;
    uint64_t read_comp_latency  = rdma_dev->ts_data[latency_idx].read_comp_ts  - rdma_dev->ts_data[latency_idx].completion_ts;
    
    if ((latency_idx & 0x1) == 0) {
        /* even wr_id - Write to CPU*/
        rdma_dev->w_to_cpu_lat.measure_index++;
        rdma_dev->w_to_cpu_lat.wr_send_latency_sum    += wr_send_latency;
        rdma_dev->w_to_cpu_lat.completion_latency_sum += completion_latency;
        rdma_dev->w_to_cpu_lat.read_comp_latency_sum  += read_comp_latency;

        rdma_dev->w_to_cpu_lat.min_wr_send_latency    = (wr_send_latency < rdma_dev->w_to_cpu_lat.min_wr_send_latency)?
                                                        wr_send_latency: rdma_dev->w_to_cpu_lat.min_wr_send_latency;
        rdma_dev->w_to_cpu_lat.min_completion_latency = (completion_latency < rdma_dev->w_to_cpu_lat.min_completion_latency)?
                                                        completion_latency: rdma_dev->w_to_cpu_lat.min_completion_latency;
        rdma_dev->w_to_cpu_lat.min_read_comp_latency  = (read_comp_latency < rdma_dev->w_to_cpu_lat.min_read_comp_latency)?
                                                        read_comp_latency: rdma_dev->w_to_cpu_lat.min_read_comp_latency;

        rdma_dev->w_to_cpu_lat.max_wr_send_latency    = (wr_send_latency > rdma_dev->w_to_cpu_lat.max_wr_send_latency)?
                                                        wr_send_latency: rdma_dev->w_to_cpu_lat.max_wr_send_latency;
        rdma_dev->w_to_cpu_lat.max_completion_latency = (completion_latency > rdma_dev->w_to_cpu_lat.max_completion_latency)?
                                                        completion_latency: rdma_dev->w_to_cpu_lat.max_completion_latency;
        rdma_dev->w_to_cpu_lat.max_read_comp_latency  = (read_comp_latency > rdma_dev->w_to_cpu_lat.max_read_comp_latency)?
                                                        read_comp_latency: rdma_dev->w_to_cpu_lat.max_read_comp_latency;
        LOG_TRACE("Print Latency for wr_id = %6lu\n"
                  "    wr_sent latency   : current %8lu, min %8lu, max %8lu, avg %8lu (nSec)\n",
                  rdma_dev->cq_ex->wr_id,
                  wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_cpu_lat.min_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_cpu_lat.max_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_cpu_lat.wr_send_latency_sum / rdma_dev->w_to_cpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_TRACE("    completion latency: current %8lu, min %8lu, max %8lu, avg %8lu (nSec)\n",
                  completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_cpu_lat.min_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_cpu_lat.max_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_cpu_lat.completion_latency_sum / rdma_dev->w_to_cpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_TRACE("    read_comp latency : current %8lu, min %8lu, max %8lu, avg %8lu (nSec)\n",
                  read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_cpu_lat.min_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_cpu_lat.max_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_cpu_lat.read_comp_latency_sum / rdma_dev->w_to_cpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);
    } else {
        /* odd wr_id - Write to GPU*/
        rdma_dev->w_to_gpu_lat.measure_index++;
        rdma_dev->w_to_gpu_lat.wr_send_latency_sum    += wr_send_latency;
        rdma_dev->w_to_gpu_lat.completion_latency_sum += completion_latency;
        rdma_dev->w_to_gpu_lat.read_comp_latency_sum  += read_comp_latency;

        rdma_dev->w_to_gpu_lat.min_wr_send_latency    = (wr_send_latency < rdma_dev->w_to_gpu_lat.min_wr_send_latency)?
                                                        wr_send_latency: rdma_dev->w_to_gpu_lat.min_wr_send_latency;
        rdma_dev->w_to_gpu_lat.min_completion_latency = (completion_latency < rdma_dev->w_to_gpu_lat.min_completion_latency)?
                                                        completion_latency: rdma_dev->w_to_gpu_lat.min_completion_latency;
        rdma_dev->w_to_gpu_lat.min_read_comp_latency  = (read_comp_latency < rdma_dev->w_to_gpu_lat.min_read_comp_latency)?
                                                        read_comp_latency: rdma_dev->w_to_gpu_lat.min_read_comp_latency;

        rdma_dev->w_to_gpu_lat.max_wr_send_latency    = (wr_send_latency > rdma_dev->w_to_gpu_lat.max_wr_send_latency)?
                                                        wr_send_latency: rdma_dev->w_to_gpu_lat.max_wr_send_latency;
        rdma_dev->w_to_gpu_lat.max_completion_latency = (completion_latency > rdma_dev->w_to_gpu_lat.max_completion_latency)?
                                                        completion_latency: rdma_dev->w_to_gpu_lat.max_completion_latency;
        rdma_dev->w_to_gpu_lat.max_read_comp_latency  = (read_comp_latency > rdma_dev->w_to_gpu_lat.max_read_comp_latency)?
                                                        read_comp_latency: rdma_dev->w_to_gpu_lat.max_read_comp_latency;
        LOG_TRACE("Print Latency for wr_id = %6lu\n"
                  "    wr_sent latency   : current %8lu, min %8lu, max %8lu, avg %8lu (nSec)\n",
                  rdma_dev->cq_ex->wr_id,
                  wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_gpu_lat.min_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_gpu_lat.max_wr_send_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_gpu_lat.wr_send_latency_sum / rdma_dev->w_to_gpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_TRACE("    completion latency: current %8lu, min %8lu, max %8lu, avg %8lu (nSec)\n",
                  completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_gpu_lat.min_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_gpu_lat.max_completion_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_gpu_lat.completion_latency_sum / rdma_dev->w_to_gpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);

        LOG_TRACE("    read_comp latency : current %8lu, min %8lu, max %8lu, avg %8lu (nSec)\n",
                  read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_gpu_lat.min_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_gpu_lat.max_read_comp_latency * 1000000 / rdma_dev->hca_core_clock_kHz,
                  rdma_dev->w_to_gpu_lat.read_comp_latency_sum / rdma_dev->w_to_gpu_lat.measure_index * 1000000 / rdma_dev->hca_core_clock_kHz);
    }

    /* ret_val = ibv_next_poll(rdma_dev->cq); - we don't need next_poll, just one completion expected */
    
    ibv_end_poll(rdma_dev->cq_ex);

    return 0;
}

/****************************************************************************************
 * Modify target QP state to RTR (on the client side)
 * Return value: 0 - success, 1 - error
 ****************************************************************************************/
int modify_target_qp_to_rtr(struct rdma_device *rdma_dev)
{
    struct ibv_qp_attr      qp_attr;
    enum ibv_qp_attr_mask   attr_mask;
    int                     ret_val;

    memset(&qp_attr, 0, sizeof qp_attr);
    
    /* - - - - - - -  Modify QP to RTR  - - - - - - - */
    qp_attr.qp_state           = IBV_QPS_RTR;
    qp_attr.path_mtu           = rdma_dev->mtu;
    qp_attr.dest_qp_num        = rdma_dev->rem_qpn;
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
    
    LOG_INIT("ibv_modify_qp, qp_attr.qp_state = %d (RTR), attr_mask = 0x%x\n",
             qp_attr.qp_state, attr_mask);
    ret_val = ibv_modify_qp(rdma_dev->qp, &qp_attr, attr_mask);
    if (ret_val) {
        fprintf(stderr, "Failed to modify QP to RTR, error %d\n", ret_val);
        return 1;
    }
    LOG_DEBUG("ibv_modify_qp to RTR state completed, qp_num 0x%06x -> remote qp_num 0x%06x\n",
              rdma_dev->qp->qp_num, rdma_dev->rem_qpn);
    
    return 0;
}

/****************************************************************************************
 * Modify source QP state to RTR and then to RTS (on the server side)
 * Return value: 0 - success, 1 - error
 ****************************************************************************************/
int modify_source_qp_to_rtr_and_rts(struct rdma_device *rdma_dev)
{
    struct ibv_qp_attr      qp_attr;
    enum ibv_qp_attr_mask   attr_mask;
    int                     ret_val;

    memset(&qp_attr, 0, sizeof qp_attr);
    
    /* - - - - - - -  Modify QP to RTR  - - - - - - - */
    qp_attr.qp_state           = IBV_QPS_RTR;
    qp_attr.path_mtu           = rdma_dev->mtu;
    qp_attr.dest_qp_num        = rdma_dev->rem_qpn;
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
    
    LOG_INIT("ibv_modify_qp, qp_attr.qp_state = %d (RTR), attr_mask = 0x%x\n",
             qp_attr.qp_state, attr_mask);
    ret_val = ibv_modify_qp(rdma_dev->qp, &qp_attr, attr_mask);
    if (ret_val) {
        fprintf(stderr, "Failed to modify QP to RTR, error %d\n", ret_val);
        return 1;
    }
    LOG_DEBUG("ibv_modify_qp to RTR state completed, qp_num 0x%06x -> remote qp_num 0x%06x\n",
              rdma_dev->qp->qp_num, rdma_dev->rem_qpn);

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
    
    LOG_INIT("ibv_modify_qp, qp_attr.qp_state = %d (RTS), attr_mask = 0x%x\n",
             qp_attr.qp_state, attr_mask);
    ret_val = ibv_modify_qp(rdma_dev->qp, &qp_attr, attr_mask);
    if (ret_val) {
        fprintf(stderr, "Failed to modify QP to RTS, error %d\n", ret_val);
        return 1;
    }
    LOG_DEBUG("ibv_modify_qp to RTS state completed, qp_num 0x%06x\n",
              rdma_dev->qp->qp_num);
    
    return 0;
}

//============================================================================================


