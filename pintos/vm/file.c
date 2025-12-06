/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
static bool lazy_load_file (struct page *page, void *aux);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;
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

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
        struct file *file, off_t offset) {
    struct thread *curr = thread_current();
    void *addr_original = addr;
    
    /* NULL check start */
    if (addr == NULL || length == 0 || is_kernel_vaddr(addr)) {
        return NULL;
    }

    if (pg_ofs(addr) || pg_ofs(offset)) {
        return NULL;
    }

    void *end_addr = addr + length;
    if (end_addr <= addr || is_kernel_vaddr(end_addr)) {
        return NULL;
    }

    size_t file_len = file_length(file);
    if (file_len == 0) {
        return NULL;
    }

    int check_page = (length + PGSIZE - 1) / PGSIZE;

    for (int i = 0; i < check_page; i++) {
        void *va = addr + i * PGSIZE;

        if (spt_find_page(&curr->spt, va) != NULL) {
            return NULL;
        }
    }
    /* NULL check end */

    size_t read_bytes = length;
    if (file_len - offset < read_bytes) {
        read_bytes = file_len - offset;
    }

    struct file *file_re = file_reopen(file);

    while (read_bytes > 0) {
        size_t page_read_bytes = (read_bytes < PGSIZE) ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct lazy_aux *aux = malloc(sizeof(struct lazy_aux));
        if (aux == NULL) {
            file_close(file_re);
            return NULL;
        }

        aux->file = file_re;
        aux->ofs = offset;
        aux->page_read_bytes = page_read_bytes;
        aux->page_zero_bytes = page_zero_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_file, aux)) {
            free(aux);
            file_close(file_re);
            return NULL;
        }

        read_bytes -= page_read_bytes;
        offset += page_read_bytes;
        addr += PGSIZE;
    }

    return addr_original;
}

/* Do the munmap */
void
do_munmap (void *addr) {
    
}

static bool lazy_load_file (struct page *page, void *aux) {
    struct lazy_aux *lazy_aux = aux;
    struct file *file = lazy_aux->file;
    off_t ofs = lazy_aux->ofs;
    size_t page_read_bytes = lazy_aux->page_read_bytes;
    size_t page_zero_bytes = lazy_aux->page_zero_bytes;

    file_seek(file, ofs);
    uint8_t *kpage = page->frame->kva;

    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
        free(lazy_aux);
        return false;
    }

    page->file.file = lazy_aux->file;
    page->file.ofs = lazy_aux->ofs;
    page->file.read_bytes = lazy_aux->page_read_bytes;
    page->file.zero_bytes = lazy_aux->page_zero_bytes;

    memset(kpage + page_read_bytes, 0, page_zero_bytes);
    free(lazy_aux);

    return true;
}