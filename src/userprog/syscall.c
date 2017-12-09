/* 
 * This file is derived from source code for the Pintos
 * instructional operating system which is itself derived
 * from the Nachos instructional operating system. The 
 * Nachos copyright notice is reproduced in full below. 
 *
 * Copyright (C) 1992-1996 The Regents of the University of California.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose, without fee, and
 * without written agreement is hereby granted, provided that the
 * above copyright notice and the following two paragraphs appear
 * in all copies of this software.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
 * ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
 * AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
 * HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
 * BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * Modifications Copyright (C) 2017 David C. Harrison. All rights reserved.
 */

#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>

#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/umem.h"

struct fd_entry {
    int fd;
    struct file *file;
    struct list_elem el;
};

static struct fd_entry* fd_entry_get(int fd);

static void syscall_handler(struct intr_frame *);

static void read_handler(struct intr_frame *);
static void write_handler(struct intr_frame *);
static void exit_handler(struct intr_frame *);
static void exec_handler(struct intr_frame *);
static void create_handler(struct intr_frame *);
static void remove_handler(struct intr_frame *);
static void filesize_handler(struct intr_frame *);
static void open_handler(struct intr_frame *);
static void close_handler(struct intr_frame *);

void
syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
    int syscall;
    ASSERT(sizeof (syscall) == 4); // assuming x86

    // The system call number is in the 32-bit word at the caller's stack pointer.
    umem_read(f->esp, &syscall, sizeof (syscall));

    // Store the stack pointer esp, which is needed in the page fault handler.
    // Do NOT remove this line
    thread_current()->current_esp = f->esp;

    switch (syscall) {
        case SYS_HALT:
            shutdown_power_off();
            break;
        case SYS_EXIT:
            exit_handler(f);
            break;
        case SYS_READ:
            read_handler(f);
            break;
        case SYS_WRITE:
            write_handler(f);
            break;
            //
        case SYS_CREATE:
            create_handler(f);
            break;
            //        case SYS_REMOVE:
            //            remove_handler(f);
            //            break;
            //
        case SYS_OPEN:
            open_handler(f);
            break;
        case SYS_CLOSE:
            close_handler(f);
            break;
            //            
            //        case SYS_EXEC:
            //            exec_handler(f);
            //            break;
        case SYS_FILESIZE:
            filesize_handler(f);
            break;
        default:
            printf("[ERROR] system call %d is unimplemented!\n", syscall);
            thread_exit();
            break;
    }
}

/****************** System Call Implementations ********************/

// *****************************************************************
// CMPS111 Lab 3 : Put your new system call implementatons in your 
// own source file. Define them in your header file and include 
// that .h in this .c file.
// *****************************************************************

void sys_exit(int status)
{
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}

/*
 * BUFFER+0 and BUFFER+size should be valid user adresses
 */
static uint32_t sys_write(int fd, const void *buffer, unsigned size)
{
    umem_check((const uint8_t*) buffer);
    umem_check((const uint8_t*) buffer + size - 1);

    int ret = -1;

    if (fd == 1) { // write to stdout
        putbuf(buffer, size);
        ret = size;
    } else {
        struct fd_entry* fde = fd_entry_get(fd);
        if (fde != NULL) {
            ret = file_write(fde->file, buffer, size);
        }
    }

    return (uint32_t) ret;
}

static uint32_t sys_read(int fd, void*buffer, unsigned size)
{
    if (fd == STDOUT_FILENO) return -1;
    //    if (fd == STDIN_FILENO) {
    //        uint8_t *uint_buffer = (uint8_t *) buffer;
    //        for (unsigned i = 0; i < size; ++i) {
    //            *uint_buffer = input_getc();
    //        }
    //    }
    struct fd_entry* en = fd_entry_get(fd);
    if (en != NULL) {
        return file_read(en->file, buffer, size);
    }
    return 0;
}

static void read_handler(struct intr_frame *f)
{
    int fd;
    void *buffer;
    unsigned size;

    umem_read(f->esp + 4, &fd, sizeof (fd));
    umem_read(f->esp + 8, &buffer, sizeof (buffer));
    umem_read(f->esp + 12, &size, sizeof (size));

    //    printf("READ fd %d\n", fd);
    int ret = 0;

    struct fd_entry* en = fd_entry_get(fd);
    if (en != NULL) {
        ret = file_read(en->file, buffer, size);
    }
    f->eax = ret;
}

static void write_handler(struct intr_frame *f)
{
    int fd;
    const void *buffer;
    unsigned size;

    umem_read(f->esp + 4, &fd, sizeof (fd));
    umem_read(f->esp + 8, &buffer, sizeof (buffer));
    umem_read(f->esp + 12, &size, sizeof (size));

    //    printf("WRITE fd %d\n", fd);
    f->eax = sys_write(fd, buffer, size);
}

static void create_handler(struct intr_frame *f)
{
    char* str;
    unsigned size;
    umem_read(f->esp + 4, &str, sizeof (str));
    umem_read(f->esp + 8, &size, sizeof (size));
    f->eax = (int) filesys_create(str, size, false);
}

static void remove_handler(struct intr_frame *f)
{
    char* str;
    umem_read(f->esp + 4, &str, sizeof (str));
    filesys_remove(str);
}

static void open_handler(struct intr_frame *f)
{
    char* str;
    umem_read(f->esp + 4, &str, sizeof (str));
    struct file* file = filesys_open(str);
    if (file == NULL) {
        f->eax = -1;
    } else {
        struct fd_entry *fde = (struct fd_entry *) malloc(sizeof (struct fd_entry));

        struct list *fd_list = &thread_current()->fd_table;
        fde->fd = thread_current()->fd_count++;
        fde->file = file;

        //        printf("OPEN fd %d\n", fde->fd);
        list_push_back(fd_list, &fde->el);
        f->eax = fde->fd;
    }
    //    f->eax = fde->fd;
}

static void close_handler(struct intr_frame *f)
{
    int fd;
    umem_read(f->esp + 4, &fd, sizeof (fd));

    struct fd_entry* fde = fd_entry_get(fd);
    //    printf("CLOSE fd %d\n", fd);

    if (fde == NULL) {
        f->eax = 0;
    } else {
        list_remove(&fde->el);
        file_close(fde->file);
        free(fde);
        f->eax = 0;
    }
}

static void search_thread(struct thread *t, tid_t tid)
{
    if (t->tid == tid) {
        
    }
}

static void exec_handler(struct intr_frame * f)
{
    char* cmd;
    umem_read(f->esp + 4, &cmd, sizeof (cmd));
    tid_t tid = -1;
    tid = process_execute(cmd);
    f->eax = tid;
    thread_foreach(search_thread, tid);
}

static void filesize_handler(struct intr_frame *f)
{
    int fd;
    umem_read(f->esp + 4, &fd, sizeof (fd));
    struct fd_entry* fde = fd_entry_get(fd);
    if (fde == NULL) {
        sys_exit(-1);
    }
    f->eax = file_length(fde->file);
}

static void exit_handler(struct intr_frame *f)
{
    int exitcode;
    umem_read(f->esp + 4, &exitcode, sizeof (exitcode));

    sys_exit(exitcode);
}

static struct fd_entry* fd_entry_get(int fd)
{
    struct list *fd_table = &thread_current()->fd_table;
    struct fd_entry* en = NULL;
    for (struct list_elem* e = list_begin(fd_table);
        e != list_end(fd_table);
        e = list_next(e)) {
        struct fd_entry* entr = list_entry(e, struct fd_entry, el);
        if (entr->fd == fd) {
            en = entr;
            break;
        }
    }
    return en;
}
