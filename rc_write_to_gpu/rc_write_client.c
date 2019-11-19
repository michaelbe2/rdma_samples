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
#include <sys/time.h>
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
    int                 use_cuda;
    char               *bdf;
    char               *servername;
    struct sockaddr     hostaddr;
};

/****************************************************************************************
 * Open socket connection on the client side, try to connect to the server by the given
 * IP address (servername). If success, return the connected socket file descriptor ID
 * Return value: socket fd - success, -1 - error
 ****************************************************************************************/
static int open_client_socket(const char *servername,
                              int         port)
{
    struct addrinfo *res,
                    *t;
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };
    char   *service;
    int     ret_val;
    int     sockfd;

    if (asprintf(&service, "%d", port) < 0)
        return -1;

    ret_val = getaddrinfo(servername, service, &hints, &res);

    if (ret_val < 0) {
        fprintf(stderr, "FAILURE: %s for %s:%d\n", gai_strerror(ret_val), servername, port);
        free(service);
        return -1;
    }

    for (t = res; t; t = t->ai_next) {
        sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sockfd >= 0) {
            if (!connect(sockfd, t->ai_addr, t->ai_addrlen))
                break;
            close(sockfd);
            sockfd = -1;
        }
    }

    freeaddrinfo(res);
    free(service);

    if (sockfd < 0) {
        fprintf(stderr, "FAILURE: Couldn't connect to %s:%d\n", servername, port);
        return -1;
    }

    return sockfd;
}

/*============================================================================================
 Data Format:
 addr             size     rkey     gpu_addr         gpu_rkey qpn    gid
"0102030405060708:01020304:01020304:0102030405060708:01020304:010203:0102030405060708090a0b0c0d0e0f10"
*/
static int client_data_exchange(struct rdma_device *rdma_dev, int sockfd)
{
    int     ret_val,
            ret_size,
            string_size;
    char    exch_string[EXCHANGE_STRING_LENGTH];

    string_size = fill_exchange_string(rdma_dev, exch_string, sizeof exch_string);
    if (string_size != sizeof exch_string) {
        fprintf(stderr, "ERROR: fill_exchange_string retutned size %d != expected %d\n",
                string_size, sizeof exch_string);
        return 1;
    }

    LOG_DEBUG("Send local data string to socket:\n%s\n", exch_string);
    ret_size = write(sockfd, exch_string, string_size);
    if (ret_size != string_size) {
        fprintf(stderr, "FAILURE: Couldn't send local data string to socket, write data size %d (errno=%d '%m')\n",
                ret_size, errno);
        return 1;
    }

    ret_size = recv(sockfd, exch_string, string_size, MSG_WAITALL);
    if (ret_size != string_size) {
        fprintf(stderr, "FAILURE: Couldn't read remote data strind from socket, recv data size %d (errno=%d '%m')\n",
                ret_size, errno);
        return 1;
    }
    LOG_DEBUG("Received remote data string from socket:\n%s\n", exch_string);

    ret_val = parse_exchange_string(rdma_dev, exch_string);
    if (ret_val) {
        return 1;
    }
    
    return 0;
}

//============================================================================================
static void usage(const char *argv0)
{
    printf("Usage:\n");
    printf("  %s <host>     connect to server at <host>\n", argv0);
    printf("\n");
    printf("Options:\n");
    printf("  -a, --addr=<ipaddr>       ip address of the local host net device <ipaddr v4> (mandatory)\n");
    printf("  -p, --port=<port>         listen on/connect to port <port> (default 18515)\n");
    printf("  -s, --size=<size>         size of message to exchange (default 1024)\n");
    printf("  -u, --use-cuda=<BDF>      use CUDA pacage (work with GPU memoty),\n"
           "                            BDF corresponding to CUDA device, for example, \"3e:02.0\"\n");
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

    while (1) {
        int c;

        static struct option long_options[] = {
            { .name = "addr",          .has_arg = 1, .val = 'a' },
            { .name = "port",          .has_arg = 1, .val = 'p' },
            { .name = "size",          .has_arg = 1, .val = 's' },
            { .name = "use-cuda",      .has_arg = 1, .val = 'u' },
            { .name = "debug-mask",    .has_arg = 1, .val = 'L' },
            { 0 }
        };

        c = getopt_long(argc, argv, "a:p:s:u:L:",
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

        case 'u':
            usr_par->use_cuda = 1;
            usr_par->bdf = calloc(1, strlen(optarg)+1);
            if (!usr_par->bdf){
                fprintf(stderr, "FAILURE: BDF mem alloc failure (errno=%d '%m')", errno);
                return 1;
            }
            strcpy(usr_par->bdf, optarg);
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

    if (optind == argc) {
        fprintf(stderr, "FAILURE: Server name is missing in the commant line.\n");
        usage(argv[0]);
        return 1;
    } else if (optind == argc - 1) {
        //usr_par->servername = strdupa(argv[optind]);
        usr_par->servername = calloc(1, strlen(argv[optind])+1);
        if (!usr_par->servername){
            fprintf(stderr, "FAILURE: servername mem alloc failure (errno=%d '%m')\n", errno);
            return 1;
        }
        strcpy(usr_par->servername, argv[optind]);
    }
    else if (optind < argc) {
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
        ret_val = 1;
        /* We don't exit here, because when parse_command_line failed, probably
           some of memory allocations were completed, so we need to free them */
        goto clean_usr_par;
    }
    
    printf("Connecting to remote server \"%s:%d\"\n", usr_par.servername, usr_par.port);
    sockfd = open_client_socket(usr_par.servername, usr_par.port);
    free(usr_par.servername);

    if (sockfd < 0) {
        ret_val = 1;
        goto clean_usr_par;
    }

    printf("Opening rdma device\n");
    rdma_dev = rdma_open_device_target(&usr_par.hostaddr); /* client */
    if (!rdma_dev) {
        ret_val = 1;
        goto clean_socket;
    }
    
    /* Memorty allocation and MR registration */
    ret_val = rdma_buffer_reg(rdma_dev, usr_par.size, usr_par.use_cuda, usr_par.bdf);
    if (ret_val) {
        ret_val = 1;
        goto clean_device;
    }
    /* We don't need bdf any more, sio we can free this. */
    if (usr_par.bdf) {
        free(usr_par.bdf);
        usr_par.bdf = NULL;
    }

    ret_val = client_data_exchange(rdma_dev, sockfd);
    if (ret_val) {
        ret_val = 1;
        goto clean_rdma_buff;
    }

    ret_val = modify_target_qp_to_rtr(rdma_dev);
    if (ret_val) {
        ret_val = 1;
        goto clean_rdma_buff;
    }
    
    char msg[256];
    int  ret_size;
    sprintf(msg, "Start");
    ret_size = write(sockfd, msg, sizeof "Start");
    if (ret_size != sizeof "Start") {
        fprintf(stderr, "FAILURE: Couldn't send \"Start\" message, write data size %d (errno=%d '%m')\n",
                ret_size, errno);
        ret_val = 1;
        goto clean_rdma_buff;
    }
    LOG_INIT("Command Start sent\n");
    
    if (gettimeofday(&start, NULL)) {
        fprintf(stderr, "FAILURE: gettimeofday (errno=%d '%m')", errno);
        ret_val = 1;
        goto clean_rdma_buff;
    }

    /* Wating for confirmation message from the socket that the server completed the test */
    ret_size = recv(sockfd, msg, sizeof "Completed", MSG_WAITALL);
    if (ret_size != sizeof "Completed") {
        fprintf(stderr, "FAILURE: Couldn't receive \"Completed\" message, recv data size %d (errno=%d '%m')\n",
                ret_size, errno);
        ret_val = 1;
        goto clean_rdma_buff;
    }
    LOG_INIT("Test Completed confirmation received\n");
    
    ret_val = print_run_time(start);
    if (ret_val) {
        goto clean_rdma_buff;
    }

clean_rdma_buff:
    rdma_buffer_dereg(rdma_dev, usr_par.use_cuda);

clean_device:
    rdma_close_device(rdma_dev);

clean_socket:
    close(sockfd);

clean_usr_par:
    if (usr_par.bdf) {
        free(usr_par.bdf);
    }
    
    return ret_val;
}


