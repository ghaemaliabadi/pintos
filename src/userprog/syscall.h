#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"

void syscall_init (void);

void sys_exit (int);

#ifdef VM
// expose munmap() so that it can be call in sys_exit();
bool sys_munmap (mmapid_t);
#endif

/* Encryption system calls */
bool sys_encrypt_file (const char *filename, const char *password);
bool sys_is_file_encrypted (const char *filename);
bool sys_change_file_password (const char *filename, const char *old_password, const char *new_password);

#endif /* userprog/syscall.h */
