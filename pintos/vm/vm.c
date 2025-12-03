/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"
#include <string.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/uninit.h"
#include "vm/inspect.h"

struct list frame_table;
struct lock frame_lock;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
    vm_anon_init ();
    vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
    pagecache_init ();
#endif
    register_inspect_intr ();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
    list_init(&frame_table);
    lock_init(&frame_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
    int ty = VM_TYPE (page->operations->type);
    switch (ty) {
        case VM_UNINIT:
            return VM_TYPE (page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
static void page_destory(struct hash_elem *e, void *aux);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
        vm_initializer *init, void *aux) {

    ASSERT (VM_TYPE(type) != VM_UNINIT)

    bool (*initializer)(struct page *, enum vm_type, void *);
    if (VM_TYPE(type) == VM_ANON) {
        initializer = anon_initializer;
    } else if (VM_TYPE(type) == VM_FILE) {
        initializer = file_backed_initializer;
    } else {
        PANIC("asdf");
    }

    struct supplemental_page_table *spt = &thread_current ()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page (spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        struct page *page = malloc(sizeof(struct page));

        uninit_new(page, upage, init, type, aux, initializer);
        
        page->writable = writable;
        /* TODO: Insert the page into the spt. */
        if (!spt_insert_page(spt, page)) {
            free(page);
            goto err;
        }
    }

    return true;

err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
    ASSERT(spt != NULL);
    /* TODO: Fill this function. */
    struct page page;
    page.va = pg_round_down(va);
    
    struct hash_elem *e = hash_find(&spt->spt_hash, &page.hash_elem);

    if (!e) {
        return NULL;
    }

    return hash_entry(e, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
                 struct page *page) {
    ASSERT(spt != NULL);
    /* TODO: Fill this function. */
    return(hash_insert(&spt->spt_hash, &page->hash_elem) == NULL);
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
    vm_dealloc_page (page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
    struct frame *victim = NULL;
     /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
    struct frame *victim UNUSED = vm_get_victim ();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
    /* TODO: Fill this function. */
    struct frame *frame = malloc(sizeof(struct frame));
    ASSERT(frame != NULL);
    
    if (!(frame->kva = palloc_get_page(PAL_USER | PAL_ZERO))) {
        free(frame);
        frame = vm_evict_frame();
        frame->page = NULL;
    } else {
        frame->page = NULL;
        list_push_back(&frame_table, &frame->elem);
    }

    ASSERT (frame != NULL);
    ASSERT (frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth (void *addr) {
    void *page_addr = pg_round_down(addr);
    if (!vm_alloc_page(VM_ANON | VM_MARKER_0, page_addr, true)) {
        return false;
    }
    return vm_claim_page(page_addr);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
                     bool user, bool write, bool not_present) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page;
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    if (addr == NULL || is_kernel_vaddr(addr)) {
        return false;
    }

    page = spt_find_page(spt, addr);
    if (page == NULL) {
        void *rsp = f->rsp;
        void *fault_page = pg_round_down(addr);
        
        if (addr < USER_STACK &&
            addr >= rsp - 8 &&
            (((void *)USER_STACK - fault_page)) <= (1 << 20)) {
            
            for (void *page_addr = fault_page;
                 page_addr < USER_STACK;
                 page_addr += PGSIZE) {
                
                if (spt_find_page(spt, page_addr) != NULL)
                    continue;
                
                if (!vm_stack_growth(page_addr))
                    return false;
            }
            return true;
        }
        return false;
    }

    if (write && !page->writable) {
        return false;
    }

    return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
    destroy (page);
    free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
    /* TODO: Fill this function */
    struct thread *curr = thread_current();
    struct page *page = spt_find_page(&curr->spt, va);
    if (!page) {
        return false;
    }
    return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
    struct frame *frame = vm_get_frame ();
    struct thread *curr = thread_current();
    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    if (!pml4_set_page(curr->pml4, page->va, frame->kva, page->writable)) {
        return false;
    }
    return swap_in (page, frame->kva);
}

unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

bool page_less(const struct hash_elem *a_,
               const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);
    return a->va < b->va;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
    hash_init(&spt->spt_hash, page_hash, page_less, NULL);
    lock_init(&spt->spt_lock);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
                              struct supplemental_page_table *src) {
    ASSERT(dst && src && hash_empty(&dst->spt_hash));

    struct hash_iterator iter;
    struct page *dst_page, *src_page;
    
    hash_first (&iter, &src->spt_hash);
    while (hash_next(&iter)) {
        src_page = hash_entry(hash_cur(&iter), struct page, hash_elem);
        
        if (VM_TYPE(src_page->operations->type) == VM_UNINIT) {
            struct uninit_page *uninit = &src_page->uninit;
            struct lazy_aux *src_aux = uninit->aux;
            struct lazy_aux *dst_aux = NULL;

            if (src_aux) {
                dst_aux = malloc(sizeof(struct lazy_aux));
                if (!dst_aux) {
                    goto err;
                }

                dst_aux->file = file_duplicate(src_aux->file);
                dst_aux->ofs = src_aux->ofs;
                dst_aux->page_read_bytes = src_aux->page_read_bytes;
                dst_aux->page_zero_bytes = src_aux->page_zero_bytes;
            }

            if (!vm_alloc_page_with_initializer(page_get_type(src_page), src_page->va,
                                                src_page->writable, uninit->init, dst_aux)) {
                goto err;
            }

            if (!vm_claim_page(src_page->va))
                goto err;
        } else {
            if (!vm_alloc_page(page_get_type(src_page), src_page->va, src_page->writable)) {
                goto err;
            }

            if (!vm_claim_page(src_page->va))
                goto err;

            dst_page = spt_find_page(dst, src_page->va);
            memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
        }
    }

    return true;

err:
    supplemental_page_table_kill(dst);
    return false;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_destroy(&spt->spt_hash, page_destory);
}

static void page_destory(struct hash_elem *e, void *aux UNUSED) {
    struct page *page = hash_entry(e, struct page, hash_elem);
    vm_dealloc_page(page);
}