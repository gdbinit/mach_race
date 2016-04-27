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
 * utils.h
 *
 */

#ifndef __server__utils__
#define __server__utils__

#include <stdio.h>

kern_return_t readmem(mach_port_t port, void *buffer, const uint64_t target_addr, const size_t size);
mach_vm_address_t find_task_base_address(mach_port_t target_port);
kern_return_t find_entrypoint(char *target, mach_vm_address_t *entrypoint);

#endif /* defined(__server__utils__) */
