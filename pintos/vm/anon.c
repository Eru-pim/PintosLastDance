/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include <bitmap.h>

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

static struct bitmap *swap_table;
static struct lock anon_lock;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
    /* TODO: Set up the swap_disk. */
    if ((swap_disk = disk_get(1, 1)) == NULL)
        PANIC("Swap disk is not found.");

    lock_init(&anon_lock);

    size_t bit_cnt = disk_size(swap_disk) / (PGSIZE / DISK_SECTOR_SIZE);
    swap_table = bitmap_create(bit_cnt);
    if (swap_table == NULL)
        PANIC("Failed to create swap table.");
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;
    anon_page->bit_idx = -1;
    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;
    size_t swap_idx = anon_page->bit_idx;

    if(swap_idx == BITMAP_ERROR)
        return false;

    disk_sector_t sec_no = swap_idx * (PGSIZE / DISK_SECTOR_SIZE);
    for (int i = 0 ; i < (PGSIZE / DISK_SECTOR_SIZE); i++) {
        void *buffer = kva + (DISK_SECTOR_SIZE * i);
        disk_read(swap_disk, sec_no + i, buffer);
    }

    lock_acquire(&anon_lock);
    bitmap_flip(swap_table, swap_idx);
    lock_release(&anon_lock);
    anon_page->bit_idx = -1;

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
    struct anon_page *anon_page = &page->anon;

    lock_acquire(&anon_lock);
    size_t idx = bitmap_scan_and_flip(swap_table, 0, 1, false);
    lock_release(&anon_lock);

    if (idx == BITMAP_ERROR){
        PANIC("Swap table is full.");
    }
    else{
        anon_page->bit_idx = idx;
    }
    
    disk_sector_t sec_no = idx * (PGSIZE / DISK_SECTOR_SIZE);
    for (int i = 0; i < PGSIZE / DISK_SECTOR_SIZE; i++){
        void *buffer = page->frame->kva + (DISK_SECTOR_SIZE * i);
        disk_write(swap_disk, sec_no + i, buffer);
    }

    page->frame = NULL;
    pml4_clear_page(thread_current()->pml4, page->va);

    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
    struct anon_page *anon_page = &page->anon;

    if(anon_page->bit_idx != -1){
        lock_acquire(&anon_lock);
        bitmap_flip(swap_table, anon_page->bit_idx);
        lock_release(&anon_lock);
    }

    anon_page->bit_idx = -1;
}
