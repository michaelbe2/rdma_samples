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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <time.h>

#include "utils.h"

/****************************************************************************************
 * Memory allocation on CPU or GPU according to HAVE_CUDA pre-compile option and use_cuda flag
 * Return value: Allocated buffer pointer (if success), NULL (if error)
 ****************************************************************************************/
void *work_buffer_alloc(size_t length)
{
    void    *buff = NULL;

    /* Mem allocation on CPU */
    int page_size = sysconf(_SC_PAGESIZE);
    buff = memalign(page_size, length);
    if (!buff) {
        fprintf(stderr, "Couldn't allocate work buffer on CPU.\n");
        return NULL;
    }
    LOG_INIT("memory buffer(%p) allocated\n", buff);

    return buff;
}

/****************************************************************************************
 * Convert IP address from text format to sockaddr structure
 * Return value: 0 if it succeeds, or one of nonzero error codes (see getaddrinfo manual)
 ****************************************************************************************/
int convert_addr_string_to_sockaddr(char *addr_string, struct sockaddr *addr)
{
    struct addrinfo *res_addr;
    int ret_val;
    
    ret_val = getaddrinfo(addr_string, NULL, NULL, &res_addr);
    if (ret_val) {
        printf("getaddrinfo failed (%s) - invalid hostname or IP address\n", gai_strerror(ret_val));
        return ret_val;
    }
    
    if (res_addr->ai_family == PF_INET) {
        memcpy(addr, res_addr->ai_addr, sizeof(struct sockaddr_in));
    }
    else if (res_addr->ai_family == PF_INET6) {
        memcpy(addr, res_addr->ai_addr, sizeof(struct sockaddr_in6));
    } else {
        ret_val = -1;
    }
    
    freeaddrinfo(res_addr);

    return ret_val;
}

/****************************************************************************************/
int print_run_time(struct timeval start)
{
    struct timeval  end;
    float           usec;

    if (gettimeofday(&end, NULL)) {
        perror("gettimeofday");
        return 1;
    }

    usec  = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);

    printf("Run time %.2f seconds\n", usec / 1000000.);
    return 0;
}

/****************************************************************************************/

