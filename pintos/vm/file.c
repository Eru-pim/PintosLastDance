/* file.c: Implementation of memory backed file object (mmaped object). */

#include <string.h>
#include <hash.h>
#include "vm/vm.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

static struct lock filesys_lock;

struct mmap_aux{
    struct file *file;
    off_t offset;
    size_t page_read_bytes;
    size_t page_zero_bytes;
    bool writable;
};

/* The initializer of file vm */
void
vm_file_init (void) {
    lock_init(&filesys_lock);
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &file_ops;
    struct mmap_aux *aux = page->uninit.aux;
    if (aux == NULL)
        return false;

    struct file_page *file_page = &page->file;
    file_page->file = aux->file;
    file_page->offset = aux->offset;
    file_page->page_read_bytes = aux->page_read_bytes;
    file_page->page_zero_bytes = aux->page_zero_bytes;
    file_page->writable = aux->writable;
    return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
}

static bool
check_mmap(void *addr, size_t length, struct file *file, off_t offset){
    struct thread *t = thread_current();

    if (!file || file_length(file) == 0 || length == 0 || offset % PGSIZE != 0)
        return false;
    if (file == STDIN_FILE || file == STDOUT_FILE)
        return false;
    void * end_addr = (uint8_t *)addr + length -1;
    if (!addr || (uintptr_t)addr % PGSIZE != 0 || !is_user_vaddr(addr) || !is_user_vaddr(end_addr))
        return false;

    uintptr_t start = pg_round_down((uintptr_t)addr);
    uintptr_t end = pg_round_down((uintptr_t)addr + (uintptr_t)length - 1) + PGSIZE;
    for(uintptr_t p = start ; p < end; p += PGSIZE){
        if(spt_find_page(&t->spt, (void *)p)){
            return false;
            break;
        }
    }

    return true;
}

static bool
lazy_mmap_segment(struct page *page, void *mmap_aux){
    struct mmap_aux *aux = mmap_aux;
    struct file *file = aux->file;
    off_t offset = aux->offset;
    size_t page_read_bytes = aux->page_read_bytes;
    size_t page_zero_bytes = aux->page_zero_bytes;
    bool writable = aux->writable;

    void *kpage = page->frame->kva;

    lock_acquire(&filesys_lock);
    file_seek(file, offset);
    int bytes = file_read(file, kpage, page_read_bytes);
    lock_release(&filesys_lock);
    if (bytes != (int)page_read_bytes)
        return false;

    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    free(aux);
    return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
        struct file *file, off_t offset) {
    if (!check_mmap(addr, length, file, offset))
        goto err;
    struct file *re_file = file_reopen(file);
    if (!re_file)
        goto err;
    void *va = pg_round_down(addr);
    
    struct mmu *mmu = malloc(sizeof(struct mmu));
    mmu->file = re_file;
    mmu->length = length;
    mmu->start = va;
    
    // 변경
    size_t read_bytes = length > file_length(file) - offset ? file_length(file) - offset : length;
    size_t zero_bytes = 0;
    while(read_bytes > 0 || zero_bytes > 0){
        size_t page_read_bytes = read_bytes > PGSIZE ? PGSIZE : read_bytes;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct mmap_aux *aux = malloc(sizeof(struct mmap_aux));
        aux->file = re_file;
        aux->offset = offset;
        aux->page_read_bytes = page_read_bytes;
        aux->page_zero_bytes = page_zero_bytes;
        aux->writable = writable;

        if (!vm_alloc_page_with_initializer(VM_FILE, va, writable, lazy_mmap_segment, aux)){
            free(aux);
            goto err;
        }

        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        offset += page_read_bytes;
        va = (uint8_t *)va + PGSIZE;   
    }

    hash_insert(&thread_current()->mmu_hash_list, &mmu->hash_elem);
    return addr;
err:
    if(re_file != NULL)
        file_close(re_file);
    return NULL;
}

static void delete_mmu(struct mmu *mmu){
    hash_delete(&thread_current()->mmu_hash_list, &mmu->hash_elem);
    file_close(mmu->file);
    free(mmu);
}

/* Do the munmap */
void
do_munmap (void *addr) {
    addr = pg_round_down(addr);

    struct hash_iterator i;
    struct mmu *mmu = mmu_lookup(&thread_current()->mmu_hash_list, addr);
    ASSERT(mmu!=NULL);
    uintptr_t start = (uintptr_t) mmu->start;
    uintptr_t end = start + (uintptr_t)mmu->length;

    for (uintptr_t p = start; p < end; p +=PGSIZE){
        struct page *page = spt_find_page(&thread_current()->spt, (void *)p);
        ASSERT(page!=NULL);
        
        struct file_page file_page = page->file;
        struct file *file = file_page.file;
        off_t offset = file_page.offset;
        size_t page_read_bytes = file_page.page_read_bytes;
        size_t page_zero_bytes = file_page.page_zero_bytes;
        bool writable = file_page.writable;

        if (writable && page->frame && pml4_is_dirty(thread_current()->pml4, p)){
            lock_acquire(&filesys_lock);
            file_write_at(file, page->frame->kva, page_read_bytes, offset);
            lock_release(&filesys_lock);
        }
        lock_acquire(&filesys_lock);
        spt_remove_page(&thread_current()->spt, page);
        lock_release(&filesys_lock);
    }
    delete_mmu(mmu);
}
