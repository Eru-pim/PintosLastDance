#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/vm.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

struct lock filesys_lock;

static void terminate_process(void);

void
syscall_init (void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
    lock_init(&filesys_lock);
}

/* Helper functions */
static void
terminate_process(void) {
    struct thread *curr = thread_current();
    curr->exit_num = -1;
    thread_exit();
}

static void
check_addr(const void *addr) {
    if (addr == NULL || addr >= (void *)KERN_BASE) {
        terminate_process();
    }
}

static int find_idx(struct thread *t, int fd) {
    for (int idx = 0; idx < MAX_FILE; idx++) {
        if (t->fd_table[idx].fd == fd) {
            return idx;
        }
    }
    return -1;
}

static int get_free_fd(struct thread *t) {
    for (int fd = 0; fd < MAX_FILE; fd++) {
        if (!t->fd_status[fd]) {
            return fd;
        }
    }
    return -1;
}

static void
check_user_buffer(const void *buffer, unsigned size, bool to_write) {
    if (size == 0) {
        return;
    }

    check_addr(buffer);

    uintptr_t start = (uintptr_t) buffer;
    uintptr_t end = start + size;
    if (end < start) {
        terminate_process();
    }

    uintptr_t page_addr = (uintptr_t) pg_round_down((void *) start);
    while (page_addr < end) {
        check_addr((void *) page_addr);
#ifdef VM
        struct page *page = spt_find_page(&thread_current()->spt, (void *) page_addr);
        if (page == NULL) {
            bool handled = vm_try_handle_fault(NULL, (void *) page_addr, false,
                    to_write, true);
            if (!handled)
                terminate_process();
            page = spt_find_page(&thread_current()->spt, (void *) page_addr);
            if (page == NULL)
                terminate_process();
        }
        if (to_write && !page->writable && !page->is_cow)
            terminate_process();
#endif
        page_addr += PGSIZE;
    }
}

// true if file exist in fd_table
static bool check_file(struct thread *t, struct file *file) {
    for (int i = 0; i < MAX_FILE; i++) {
        if (t->fd_table[i].file == file) {
            return true;
        }
    }
    return false;
}

/* syscall functions */
static void syscall_halt(void) {
    power_off();
}

static void syscall_exit(int status) {
    struct thread *t = thread_current();

    t->exit_num = status;
    thread_exit();
}

static tid_t syscall_fork(const char *thread_name,
                struct intr_frame *f) {
    check_addr(thread_name);
    return process_fork(thread_name, f);
}

static void syscall_exec(const char *cmd_line) {
    check_addr(cmd_line);

    char *fn_copy = palloc_get_page(0);
    if (fn_copy == NULL) {
        thread_current()->exit_num = -1;
        thread_exit();
    }

    strlcpy(fn_copy, cmd_line, PGSIZE);
    process_exec(fn_copy);

    thread_current()->exit_num = -1;
    thread_exit();
}

static int syscall_wait(tid_t pid) {
    return process_wait(pid);
}

static bool syscall_create(const char *file, unsigned initial_size) {
    check_addr(file);

    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return success;
}

static bool syscall_remove(const char *file) {
    check_addr(file);

    return filesys_remove(file);
}

static int syscall_open(struct thread *t, const char *file) {
    check_addr(file);
    
    int idx = find_idx(t, NULL_FD);
    int free_fd = get_free_fd(t);

    if (idx == -1 || free_fd == -1) {
        return -1;
    }

    lock_acquire(&filesys_lock);
    struct file *file_ptr = filesys_open(file);
    lock_release(&filesys_lock);
    if (file_ptr == NULL) {
        return -1;
    } else {
        t->fd_table[idx].fd = free_fd;
        t->fd_table[idx].file = file_ptr;
        t->fd_status[free_fd] = true;
    }

    return free_fd;
}

static int syscall_filesize(struct thread *t, int fd) {
    if (fd < 0) {
        return -1;
    }
    
    int idx = find_idx(t, fd);

    if (idx == -1) {
        return -1;
    } else if (t->fd_table[idx].file <= STDOUT_FILE) {
        return -1;
    } else {
        return (int)file_length(t->fd_table[idx].file);
    }
}

static int syscall_read(struct thread *t, int fd, char *buffer, unsigned size) {
    check_user_buffer(buffer, size, true);
    
    if (fd < 0) {
        return -1;
    }

    int idx = find_idx(t, fd);
    int bytes_read = -1;

    if (idx == -1 || t->fd_table[idx].file == STDOUT_FILE) {
        return -1;
    } else if (t->fd_table[idx].file == STDIN_FILE) {
        lock_acquire(&filesys_lock);
        for (unsigned i = 0; i < size; i++) {
            *buffer = input_getc();
            buffer++;
        }
        bytes_read = size;
        lock_release(&filesys_lock);
    } else {
        lock_acquire(&filesys_lock);
        bytes_read = (int)file_read(t->fd_table[idx].file, buffer, size);
        lock_release(&filesys_lock);
    }

    return bytes_read;
}

static int syscall_write(struct thread *t, int fd, const char *buffer, unsigned size) {
    check_user_buffer(buffer, size, false);
    
    if (fd < 0) {
        return -1;
    }

    int idx = find_idx(t, fd);
    int bytes_written = -1;

    if (idx == -1 || t->fd_table[idx].file == STDIN_FILE) {
        return -1;
    } else if (t->fd_table[idx].file == STDOUT_FILE) {
        putbuf((char *)buffer, size);
        bytes_written = size;
    } else {
        lock_acquire(&filesys_lock);
        bytes_written = (int)file_write(t->fd_table[idx].file, buffer, size);
        lock_release(&filesys_lock);
    }

    return bytes_written;
}

static void syscall_seek(struct thread *t, int fd, unsigned position) {
    if (fd < 0) {
        return;
    }

    int idx = find_idx(t, fd);

    if (idx == -1 || t->fd_table[idx].file <= STDOUT_FILE) {
        ;
    } else {
        file_seek(t->fd_table[idx].file, position);
    }
}

static unsigned syscall_tell(struct thread *t, int fd) {
    if (fd < 0) {
        return 0;
    }

    int idx = find_idx(t, fd);

    if (idx == -1 || t->fd_table[idx].file <= STDOUT_FILE) {
        return 0;
    } else {
        return file_tell(t->fd_table[idx].file);
    }
}

static void syscall_close(struct thread *t, int fd) {
    if (fd < 0) {
        return ;
    }

    int idx = find_idx(t, fd);

    if (idx == -1) {
        return;
    }

    struct file *file = t->fd_table[idx].file;
    t->fd_table[idx].fd = NULL_FD;
    t->fd_table[idx].file = NULL;
    if (fd >= 0 && fd < MAX_FILE) {
        t->fd_status[fd] = false;
    }

    if (file > STDOUT_FILE && !check_file(t, file)) {
        file_close(file);
    }
}

static int syscall_dup2(struct thread *t, int oldfd, int newfd) {
    if (oldfd < 0 || newfd < 0) {
        return -1;
    }

    int old_idx = find_idx(t, oldfd);
    int new_idx = find_idx(t, newfd);
    int free_fd = get_free_fd(t);
    struct file *file;

    if (old_idx == -1) {
        return -1;
    } else if (oldfd == newfd) {
        return newfd;
    } else if (new_idx == -1) {
        t->fd_table[free_fd].fd = newfd;
        t->fd_table[free_fd].file = t->fd_table[old_idx].file;
        t->fd_status[free_fd] = true;
        return newfd;
    } else {
        if (t->fd_table[new_idx].file > STDOUT_FILE) {
            file = t->fd_table[new_idx].file;
            t->fd_table[new_idx].file = NULL;
            if (!check_file(t, file)) {
                file_close(file);
            }
        }
        t->fd_table[new_idx].file = t->fd_table[old_idx].file;
        return newfd;
    }
}

static void *syscall_mmap (struct thread *t, void *addr, size_t length, int writable, int fd, off_t offset){
    int idx = find_idx(t, fd);
    struct file *file = t->fd_table[idx].file;
    
    return do_mmap(addr, length, writable, file, offset);
}

static void syscall_munmap (void *addr){
    do_munmap(addr);
}

/* Arguments order: %rdi, %rsi, %rdx, %r10, %r8, %r9 */
/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
    struct thread *t = thread_current();
    t->user_rsp = f->rsp;
    switch (f->R.rax) {
        // project 2
        case SYS_HALT:
            syscall_halt();
            NOT_REACHED();
            break;

        case SYS_EXIT:
            syscall_exit((int)f->R.rdi);
            NOT_REACHED();
            break;
        
        case SYS_FORK:
            f->R.rax = syscall_fork((char *)f->R.rdi, f);
            break;

        case SYS_EXEC:
            syscall_exec((char *)f->R.rdi);
            NOT_REACHED();
            break;
        
        case SYS_WAIT:
            f->R.rax = syscall_wait((tid_t)f->R.rdi);
            break;
        
        case SYS_CREATE:
            f->R.rax = syscall_create((char *)f->R.rdi, (unsigned)f->R.rsi);
            break;

        case SYS_REMOVE:
            f->R.rax = syscall_remove((char *)f->R.rdi);
            break;

        case SYS_OPEN:
            f->R.rax = syscall_open(t, (char *)f->R.rdi);
            break;
        
        case SYS_FILESIZE:
            f->R.rax = syscall_filesize(t, (int)f->R.rdi);
            break;

        case SYS_READ:
            f->R.rax = syscall_read(t, (int)f->R.rdi, (char *)f->R.rsi, (unsigned)f->R.rdx);
            break;

        case SYS_WRITE:
            f->R.rax = syscall_write(t, (int)f->R.rdi, (char *)f->R.rsi, (unsigned)f->R.rdx);
            break;
        
        case SYS_SEEK:
            syscall_seek(t, (int)f->R.rdi, (unsigned)f->R.rsi);
            break;

        case SYS_TELL:
            f->R.rax = syscall_tell(t, (int)f->R.rdi);
            break;
        
        case SYS_CLOSE:
            syscall_close(t, (int)f->R.rdi);
            break;
        
        // project 2 EXTRA
        case SYS_DUP2:
            f->R.rax = syscall_dup2(t, (int)f->R.rdi, (int)f->R.rsi);
            break;

        case SYS_MMAP:
            f->R.rax = syscall_mmap(t, (void *)f->R.rdi, (size_t)f->R.rsi, (int)f->R.rdx, (int)f->R.r10, (off_t)f->R.r8);
            break;

        case SYS_MUNMAP:
            syscall_munmap((void *)f->R.rdi);
            break;
        
        default:
            NOT_REACHED();
    }
}
