/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/thread.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &file_ops;
    // change from uninit -> vm_file
    // struct lazy_load_info *aux = page->uninit.aux;

    struct file_page *file_page = &page->file;
    file_page->file = NULL;
    file_page->ofs = 0;
    file_page->length = 0;
    return true;
}

/* Swap in the page by read contents from the file. */
// swap_in:  Disk → Memory (mark slot as free)
static bool
file_backed_swap_in(struct page *page, void *kva)
{
    struct file_page *file_page = &page->file;

    file_seek(file_page->file, file_page->ofs);
    off_t bytes_read = file_read(file_page->file, kva, PGSIZE);
    if (bytes_read != PGSIZE)
        memset(kva + bytes_read, 0, PGSIZE - bytes_read);
    return true;
}

/* Swap out the page by writeback contents to the file. */
// swap_out: Memory → Disk (mark slot as used)
static bool
file_backed_swap_out(struct page *page)
{
    struct file_page *file_page = &page->file;
    if (page->frame != NULL && file_page->file != NULL && pml4_is_dirty(thread_current()->pml4, page->va) && (page->is_page_writable == true))
        file_write_at(file_page->file, page->frame->kva, PGSIZE, page->file.ofs);
    pml4_clear_page(thread_current()->pml4, page->va);
    page->frame = NULL;
    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page)
{
    if (page->frame != NULL)
    {
        lock_acquire(&frame_lock);
        if (page->frame->page_table_elem.prev != NULL)
            list_remove(&page->frame->page_table_elem);
        lock_release(&frame_lock);
        // pml4_clear_page(thread_current()->pml4, page->va); -- in dunmap
        // palloc_free_page(page->frame->kva); -- pml4-destory
        free(page->frame);
        page->frame = NULL;
    }
    // hash_delete(&thread_current()->spt.spt_hash, &page->hash_elem); - in dumap

    return;
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
        struct file *file, off_t offset)
{
    // maps length bytes the file open as the fd
    // get actual size needed to mmap
    // if the range of pages mapped overlaps any existing set of mapped pages
    // check overlaps with the stack
    struct thread *t = thread_current();
    size_t file_size = file_length(file);
    void *temp_addr = addr;
    bool isFirstPage = true;
    // 먼저 모든 필요한 page들이 다 비어있는지 확인
    void *check_addr = addr;
    while (check_addr < (addr + length))
    {
        if (spt_find_page(&t->spt, check_addr) != NULL)
            return NULL;
        check_addr += PGSIZE;
    }
    while (temp_addr < (addr + length))
    {

        struct lazy_load_info *aux = calloc(1, sizeof(struct lazy_load_info));
        if (aux == NULL)
            return NULL;
        aux->file = file_reopen(file);
        if (aux->file == NULL)
        {
            file_close(file);
            free(aux);
            return NULL;
        }
        aux->ofs = offset + (temp_addr - addr);
        size_t page_offset_in_file = aux->ofs;
        size_t bytes_left_in_file = (file_size > page_offset_in_file) ? (file_size - page_offset_in_file) : 0;

        aux->read_bytes = (bytes_left_in_file < PGSIZE) ? bytes_left_in_file : PGSIZE;
        aux->zero_bytes = PGSIZE - aux->read_bytes;
        aux->total_length = isFirstPage ? length : 0;
        isFirstPage = false;
        // Memory-mapped pages should be also allocated in a lazy manner
        if (!vm_alloc_page_with_initializer(VM_FILE, temp_addr, writable, lazy_load_segment, aux))
        {
            free(aux);
            return NULL;
        }
        struct page *page = spt_find_page(&t->spt, temp_addr);
        list_push_back(&t->mmap_list, &page->mmap_elem);
        temp_addr += PGSIZE;
    }
    file_close(file);
    return (addr);
}

/* Do the munmap */
void do_munmap(void *addr)
{
    struct thread *t = thread_current();
    struct page *first_page = spt_find_page(&t->spt, addr);
    if (first_page == NULL || first_page->operations->type != VM_FILE)
        return;
    uint32_t total_length = first_page->file.length;
    size_t num_pages = (uint64_t)pg_round_up(total_length) / PGSIZE;

    // munmap the pages
    for (size_t i = 0; i < num_pages; i++)
    {
        void *temp_addr = addr + (i * PGSIZE);
        struct page *page = spt_find_page(&t->spt, temp_addr);
        if (page == NULL)
            continue;
        void *kva_to_free = (page->frame != NULL) ? page->frame->kva : NULL;

        if (page->frame != NULL)
            pml4_clear_page(t->pml4, page->va);

        struct file *file = NULL;
        if (page->operations->type == VM_UNINIT)
        {
            struct lazy_load_info *aux = page->uninit.aux;
            list_remove(&page->mmap_elem);
            hash_delete(&t->spt.spt_hash, &page->hash_elem); // Remove first
            vm_dealloc_page(page);
        }
        else if (page->operations->type == VM_FILE)
        {
            file = page->file.file;
            // write back if the page is dirty
            if (page->frame != NULL && file != NULL && pml4_is_dirty(t->pml4, temp_addr) && (page->is_page_writable == true))
                file_write_at(file, page->frame->kva, PGSIZE, page->file.ofs);
            list_remove(&page->mmap_elem);
            hash_delete(&t->spt.spt_hash, &page->hash_elem); // Remove first
            vm_dealloc_page(page);
        }
        // if (kva_to_free != NULL)
        // {
        //     palloc_free_page(kva_to_free); // Free explicitly during munmap
        // }
        if (file != NULL)
            file_close(file);
    }
    return;
}
