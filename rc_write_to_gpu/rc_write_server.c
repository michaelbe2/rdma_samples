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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#include "utils.h"
#include "rc_write_common.h"

struct user_params {

    int                 port;
    unsigned long       size;
    int                 iters;
    struct sockaddr     hostaddr;
};

/****************************************************************************************
 * Open temporary socket connection on the server side, listening to the client.
 * Accepting connection from the client and closing temporary socket.
 * If success, return the accepted socket file descriptor ID
 * Return value: socket fd - success, -1 - error
 ****************************************************************************************/
static int open_server_socket(int port)
{
    struct addrinfo *res, *t;
    struct addrinfo hints = {
        .ai_flags    = AI_PASSIVE,
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };
    char   *service;
    int     ret_val;
    int     sockfd;
    int     tmp_sockfd = -1;

    ret_val = asprintf(&service, "%d", port);
    if (ret_val < 0)
        return -1;

    ret_val = getaddrinfo(NULL, service, &hints, &res);
    if (ret_val < 0) {
        fprintf(stderr, "%s for port %d\n", gai_strerror(ret_val), port);
        free(service);
        return -1;
    }

    for (t = res; t; t = t->ai_next) {
        tmp_sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (tmp_sockfd >= 0) {
            int optval = 1;

            setsockopt(tmp_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

            if (!bind(tmp_sockfd, t->ai_addr, t->ai_addrlen))
                break;
            close(tmp_sockfd);
            tmp_sockfd = -1;
        }
    }

    freeaddrinfo(res);
    free(service);

    if (tmp_sockfd < 0) {
        fprintf(stderr, "Couldn't listen to port %d\n", port);
        return -1;
    }

    listen(tmp_sockfd, 1);
    sockfd = accept(tmp_sockfd, NULL, 0);
    close(tmp_sockfd);
    if (sockfd < 0) {
        fprintf(stderr, "accept() failed\n");
        return -1;
    } 
    
    return sockfd;
}

//============================================================================================
/* Data Format:
 addr             size     rkey     qpn    gid                             
"0102030405060708:01020304:01020304:010203:0102030405060708090a0b0c0d0e0f10"
*/
static int server_data_exchange(struct rdma_device *rdma_dev, int sockfd)
{
    int     ret_val,
            ret_size;
    char    exch_string[EXCHANGE_STRING_LENGTH];

    exch_string[EXCHANGE_STRING_LENGTH-1] = '\0';
    LOG_DEBUG("Start receiving remote data string from socket\n");
    ret_size = recv(sockfd, exch_string, sizeof exch_string, MSG_WAITALL);
    if (ret_size != sizeof exch_string) {
        fprintf(stderr, "FAILURE: Couldn't read remote data strind from socket, recv data size %d (errno=%d '%m')\n",
                ret_size, errno);
        return 1;
    }
    LOG_DEBUG("Received remote data string from socket:\n%s\n", exch_string);

    ret_val = parse_exchange_string(rdma_dev, exch_string);
    if (ret_val) {
        return 1;
    }
    
    ret_size = fill_exchange_string(rdma_dev, exch_string, sizeof exch_string);
    if (!ret_size) {
        return 1;
    }

    LOG_DEBUG("Send local data string to socket:\n%s\n", exch_string);
    ret_size = write(sockfd, exch_string, sizeof exch_string);
    if (ret_size != sizeof exch_string) {
        fprintf(stderr, "FAILURE: Couldn't send local data string to socket, write data size %d (errno=%d '%m')\n",
                  ret_size, errno);
        return 1;
    }

    return 0;
}

//============================================================================================
static void usage(const char *argv0)
{
    printf("Usage:\n");
    printf("  %s            start a server and wait for connection\n", argv0);
    printf("\n");
    printf("Options:\n");
    printf("  -a, --addr=<ipaddr>       ip address of the local host net device <ipaddr v4> (mandatory)\n");
    printf("  -p, --port=<port>         listen on/connect to port <port> (default 18515)\n");
    printf("  -s, --size=<size>         size of message to exchange (default 1024)\n");
    printf("  -n, --iters=<iters>       number of exchanges (default 1000)\n");
    printf("  -L, --Log-mask=<mask>     Log bitmask: bit 0 - init log enable,\n"
           "                                         bit 1 - trace log enable,\n"
           "                                         bit 2 - debug log enable\n");
}

static int parse_command_line(int argc, char *argv[], struct user_params *usr_par)
{
    memset(usr_par, 0, sizeof *usr_par);
    /*Set defaults*/
    usr_par->port       = 18515;
    usr_par->size       = 1024;
    usr_par->iters      = 1000;

    while (1) {
        int c;

        static struct option long_options[] = {
            { .name = "addr",          .has_arg = 1, .val = 'a' },
            { .name = "port",          .has_arg = 1, .val = 'p' },
            { .name = "size",          .has_arg = 1, .val = 's' },
            { .name = "iters",         .has_arg = 1, .val = 'n' },
            { .name = "debug-mask",    .has_arg = 1, .val = 'L' },
            { 0 }
        };

        c = getopt_long(argc, argv, "a:p:s:n:L:",
                        long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        
        case 'a':
            convert_addr_string_to_sockaddr(optarg, (struct sockaddr *) &usr_par->hostaddr);
            break;

        case 'p':
            usr_par->port = strtol(optarg, NULL, 0);
            if (usr_par->port < 0 || usr_par->port > 65535) {
                usage(argv[0]);
                return 1;
            }
            break;

        case 's':
            usr_par->size = strtol(optarg, NULL, 0);
            break;

        case 'n':
            usr_par->iters = strtol(optarg, NULL, 0);
            break;

        case 'L':
            init_enable  = (strtol(optarg, NULL, 0) >> 0) & 1; /*bit 0*/;
            trace_enable = (strtol(optarg, NULL, 0) >> 1) & 1; /*bit 1*/;
            debug_enable = (strtol(optarg, NULL, 0) >> 2) & 1; /*bit 2*/;
            break;

        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (optind < argc) {
        usage(argv[0]);
        return 1;
    }

    if (!usr_par->hostaddr.sa_family) {
        fprintf(stderr, "FAILURE: host ip address is missing in the command line.\n");
        usage(argv[0]);
        return 1;
    }

    return 0;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    struct rdma_device     *rdma_dev;
    struct timeval          start;
    struct user_params      usr_par;
    int                     ret_val = 0;
    int                     sockfd;
    srand48(getpid() * time(NULL));


    ret_val = parse_command_line(argc, argv, &usr_par);
    if (ret_val) {
        return ret_val;
    }

    printf("Listening to remote client...\n");
    sockfd = open_server_socket(usr_par.port);
    if (sockfd < 0) {
        return 1;
    }
    printf("Connection accepted.\n");

    rdma_dev = rdma_open_device_source(&usr_par.hostaddr); /* server */
    if (!rdma_dev) {
        ret_val = 1;
        goto clean_socket;
    }
    
    /* Memorty allocation and MR registration */
    ret_val = rdma_buffer_reg(rdma_dev, usr_par.size);
    if (ret_val) {
        ret_val = 1;
        goto clean_device;
    }

    ret_val = server_data_exchange(rdma_dev, sockfd);
    if (ret_val) {
        ret_val = 1;
        goto clean_rdma_buff;
    }

    ret_val = modify_source_qp_to_rtr_and_rts(rdma_dev);
    if (ret_val) {
        ret_val = 1;
        goto clean_rdma_buff;
    }

    char msg[256];
    int  ret_size;
    
    /* Wating for "command Start" message from the socket that the server completed the test */
    ret_size = recv(sockfd, msg, sizeof "Start", MSG_WAITALL);
    if (ret_size != sizeof "Start") {
        fprintf(stderr, "FAILURE: Couldn't receive \"command Start\" message, recv data size %d (errno=%d '%m')\n",
                ret_size, errno);
        ret_val = 1;
        goto clean_rdma_buff;
    }
    LOG_INIT("Command Start received\n");
    
    if (gettimeofday(&start, NULL)) {
        fprintf(stderr, "FAILURE: gettimeofday (errno=%d '%m')", errno);
        ret_val = 1;
        goto clean_rdma_buff;
    }

    /****************************************************************************************************
     * The main loop where the server writes data to the client in "iters" number of messages
     */
    int         it_cnt = 0;
    uint64_t    wr_id = 0;
    
    for (it_cnt = 0; it_cnt < usr_par.iters; it_cnt++) {
        wr_id++;
        LOG_TRACE("Single write data to peer\n");
        ret_val = rdma_write_to_peer(rdma_dev, wr_id);
        if (ret_val) {
            goto clean_rdma_buff;
        }
        LOG_TRACE("Polling completion queue\n");
        ret_val = rdma_poll_completions(rdma_dev);
        if (ret_val) {
            goto clean_rdma_buff;
        }
        LOG_TRACE("Finished polling\n");
    }
    /****************************************************************************************************/

    sprintf(msg, "Completed");
    ret_size = write(sockfd, msg, sizeof "Completed");
    if (ret_size != sizeof "Completed") {
        fprintf(stderr, "FAILURE: Couldn't send \"Completed\" message, write data size %d (errno=%d '%m')\n",
                ret_size, errno);
        ret_val = 1;
        goto clean_rdma_buff;
    }
    LOG_INIT("Test Completed confirmation sent\n");
    
    ret_val = print_run_time(start);
    if (ret_val) {
        goto clean_rdma_buff;
    }

clean_rdma_buff:
    rdma_buffer_dereg(rdma_dev);

clean_device:
    rdma_close_device(rdma_dev);

clean_socket:
    close(sockfd);

    return ret_val;
}


