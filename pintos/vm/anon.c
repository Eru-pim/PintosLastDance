/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

struct bitmap *swap_table;
/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
    /* TODO: Set up the swap_disk. */
    swap_disk = disk_get(1, 1);
    swap_table = bitmap_create(disk_size(swap_disk) / (PGSIZE / DISK_SECTOR_SIZE));
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;
    anon_page->swap_slot = -1;

    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;
    size_t slot = anon_page->swap_slot;

    if (slot == (size_t)-1) {
        return true;
    }

    for (int i = 0; i < (PGSIZE / DISK_SECTOR_SIZE); i++) {
        disk_read(swap_disk,
                  slot * (PGSIZE / DISK_SECTOR_SIZE) + i,
                  kva + i * DISK_SECTOR_SIZE);
    }

    bitmap_reset(swap_table, slot);
    anon_page->swap_slot = -1;

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
    struct anon_page *anon_page = &page->anon;

    size_t slot = bitmap_scan_and_flip(swap_table, 0, 1, false);
    if (slot == BITMAP_ERROR) {
        return false;
    }

    for (int i = 0; i < (PGSIZE / DISK_SECTOR_SIZE); i++) {
        disk_write(swap_disk,
                   slot * (PGSIZE / DISK_SECTOR_SIZE) + i,
                   page->frame->kva + i * DISK_SECTOR_SIZE);
    }

    anon_page->swap_slot = slot;

    pml4_clear_page(page->owner->pml4, page->va);

    page->frame = NULL;
    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
    struct anon_page *anon_page = &page->anon;

    if (anon_page->swap_slot != -1) {
        bitmap_reset(swap_table, anon_page->swap_slot);
    }

    if (page->frame != NULL) {
        pml4_clear_page(thread_current()->pml4, page->va);

        lock_acquire(&page->frame->ref_lock);
        page->frame->ref_count--;

        if (page->frame->ref_count == 0) {
            lock_release(&page->frame->ref_lock);

            lock_acquire(&frame_lock);
            list_remove(&page->frame->elem);
            lock_release(&frame_lock);

            palloc_free_page(page->frame->kva);
            free(page->frame);
        } else {
            lock_release(&page->frame->ref_lock);
        }
        
        page->frame = NULL;
    }
}
