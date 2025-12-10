/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/vaddr.h"
#include "bitmap.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "threads/thread.h"
/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

// swap in and out
struct bitmap *swap_table;
struct lock swap_lock;
/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void)
{
    swap_disk = disk_get(1, 1);
    // swap_sector - 512 bytes per sector
    disk_sector_t swap_sector = disk_size(swap_disk);
    size_t swap_page_count = swap_sector / (PGSIZE / DISK_SECTOR_SIZE);
    // bitmap table for tracking the swap slots
    swap_table = bitmap_create(swap_page_count);
    lock_init(&swap_lock);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
    // TODO: 나 - you may modify this according to your needs
    /* Set up the handler */
    page->operations = &anon_ops;
    struct anon_page *anon_page = &page->anon;
    anon_page->swap_slot = -1;  // Initialize to invalid slot
    return true;
}

/* Swap in the page by read contents from the swap disk. */
// swap_in:  Disk → Memory (mark slot as free)
static bool
anon_swap_in(struct page *page, void *kva)
{
    struct anon_page *anon_page = &page->anon;
    size_t swap_slot = anon_page->swap_slot;
    disk_sector_t sector = swap_slot * (PGSIZE / DISK_SECTOR_SIZE);
    for (int i = 0; i < (PGSIZE / DISK_SECTOR_SIZE); i++)
    {
        disk_read(swap_disk, sector + i, kva + (i * DISK_SECTOR_SIZE));
    }
    lock_acquire(&swap_lock);
    bitmap_flip(swap_table, swap_slot);
    lock_release(&swap_lock);
    return true;
}

/* Swap out the page by writing contents to the swap disk. */
// swap_out: Memory → Disk (mark slot as used)
static bool
anon_swap_out(struct page *page)
{
    struct anon_page *anon_page = &page->anon;
    // find a slot
    lock_acquire(&swap_lock);
    size_t swap_slot = bitmap_scan_and_flip(swap_table, 0, 1, false);
    lock_release(&swap_lock);
    if (swap_slot == BITMAP_ERROR)
        return false;

    // write page INTO the disk
    // sector 찾기 - 항상 *8 - 이유는 swap_slot이 8의 배수 - 즉 swap_slot마다 8개의 섹터
    disk_sector_t sector = swap_slot * (PGSIZE / DISK_SECTOR_SIZE);

    // disk에 저장하기
    for (int i = 0; i < (PGSIZE / DISK_SECTOR_SIZE); i++)
    {
        disk_write(swap_disk, sector + i, page->frame->kva + (i * DISK_SECTOR_SIZE));
    }
    anon_page->swap_slot = swap_slot;

    // clear the existing page
    pml4_clear_page(thread_current()->pml4, page->va);
    page->frame = NULL;
    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy(struct page *page)
{
    struct anon_page *anon_page = &page->anon;

    if (page->frame != NULL)
    {
        lock_acquire(&frame_lock);
        if (page->frame->page_table_elem.prev != NULL)

            list_remove(&page->frame->page_table_elem);
        lock_release(&frame_lock);
        // pml4_clear_page(thread_current()->pml4, page->va);
        // palloc_free_page(page->frame->kva);
        free(page->frame);
        page->frame = NULL;
    }
    // hash_delete(&thread_current()->spt.spt_hash, &page->hash_elem);

    return;
}
