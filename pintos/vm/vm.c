/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include <hash.h>
#include <string.h>

static struct list frame_table;
static struct lock frame_lock;
static struct lock hash_lock;

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
    lock_init(&hash_lock);
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
static void page_destructor(struct hash_elem *e, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
        vm_initializer *init, void *aux) {

    ASSERT (VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current ()->spt;
    struct page *page = malloc(sizeof(struct page));

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page (spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        if (page == NULL)
            goto err;
        switch(VM_TYPE(type)){
            case VM_ANON :
                uninit_new(page, upage, init, type, aux, anon_initializer);
                break;
            case VM_FILE:
                uninit_new(page, upage, init, type, aux, file_backed_initializer);
                break;
            default:
                goto err;
        }
        page->writable = writable;
        /* TODO: Insert the page into the spt. */
        if(!spt_insert_page(spt, page))
            goto err;
        return true;
    }
err:
    if(page != NULL)
        free(page);
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    struct page *page = NULL;
    /* TODO: Fill this function. */
    page = page_lookup(spt, va);

    return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
        struct page *page UNUSED) {
    int succ = false;
    /* TODO: Fill this function. */
    lock_acquire(&hash_lock);
    if (hash_insert(&spt->hash_table, &page->hash_elem) == NULL)
        succ = true;
    lock_release(&hash_lock);

    return succ;
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
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
    frame = malloc(sizeof(struct frame));
    if (frame == NULL)
        goto err;
	frame->kva = palloc_get_page(PAL_USER);
	if(frame->kva == NULL){
		goto err;
	}
    frame->page = NULL;
	lock_acquire(&frame_lock);
	list_push_back(&frame_table, &frame->frame_elem);
	lock_release(&frame_lock);

	return frame;
err:
    if(frame != NULL)
        free(frame);
    // 나중에 evict 들어가는 자리
    PANIC("todo\n");
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
    if (!vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true))
        thread_exit();
    if (!vm_claim_page(addr))
        thread_exit();
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
        bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
    struct page *page = NULL;
    addr = pg_round_down(addr);
    uintptr_t rsp;
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    if (addr != NULL && not_present && addr<USER_STACK){
        if(user){
            page = spt_find_page(spt, addr);
            if (page != NULL)
                return vm_claim_page(addr);
            rsp = f->rsp;
            thread_current()->user_rsp = rsp;
            if (rsp-PGSIZE <= addr && (uint8_t *)USER_STACK - (uint8_t *)addr <= MAX_STACK_SIZE){
                vm_stack_growth(addr);
                return true;
            }
        }
        else{
            page = spt_find_page(spt, addr);
            if (page != NULL)
                return vm_claim_page(addr);
            if(!thread_current()->user_rsp)
                return false;
            rsp = thread_current()->user_rsp;
            if (rsp-PGSIZE <= addr && (uint8_t *)USER_STACK - (uint8_t *)addr <= MAX_STACK_SIZE){
                vm_stack_growth(addr);
                return true;
            }
        }
    }
    return false;
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
vm_claim_page (void *va UNUSED) {
    struct page *page = NULL;
    /* TODO: Fill this function */
    page = page_lookup(&thread_current()->spt, va);

    return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
    struct frame *frame = vm_get_frame ();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page(thread_current()->pml4 , page->va, frame->kva, page->writable))
        goto err;
    
    if (!swap_in (page, frame->kva))
        goto err;
	
    return true;
err:
    lock_acquire(&frame_lock);
    list_remove(&frame->frame_elem);
    lock_release(&frame_lock);
    frame->page = NULL;
    page->frame = NULL;
    palloc_free_page(frame->kva);
    free(frame);
    vm_dealloc_page(page);
    return false;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
    hash_init(&spt->hash_table, page_hash, page_less, NULL);
}

struct aux {
    struct file *file;
    off_t ofs;
    size_t page_read_bytes;
    size_t page_zero_bytes;
    bool writable;
};

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
        struct supplemental_page_table *src UNUSED) {
    struct hash_iterator i;
    hash_first(&i, &src->hash_table);
    while(hash_next(&i)){
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        if (src_page == NULL)
            goto err;
        enum vm_type src_type = src_page->operations->type;
        switch(src_type) {
            case VM_UNINIT:{
                struct aux *src_aux = src_page->uninit.aux;
                struct aux *dst_aux = malloc(sizeof(struct aux));
                if (src_aux == NULL || dst_aux == NULL)
                    goto err;
                if (src_aux->file != NULL)
                    dst_aux->file = file_reopen(src_aux->file);
                else
                    dst_aux->file = NULL;
                dst_aux->ofs = src_aux->ofs;
                dst_aux->page_read_bytes = src_aux->page_read_bytes;
                dst_aux->page_zero_bytes = src_aux->page_zero_bytes;
                dst_aux->writable = src_aux->writable;

                if (!vm_alloc_page_with_initializer(src_page->uninit.type, src_page->va, src_page->writable, src_page->uninit.init, dst_aux))
                    goto err;
                // if (!vm_claim_page(src_page->va))
                //     goto err;
                break;
            }
            case VM_ANON:{
                if (!vm_alloc_page(src_type, src_page->va, src_page->writable))
                    goto err;
                if (!vm_claim_page(src_page->va))
                    goto err;
                
                struct page *dst_page = spt_find_page(dst, src_page->va);
                if (dst_page == NULL)
                    goto err;
                // frame->kva가 NULL일 경우 swap에서 읽어와야 함
                if (src_page->frame->kva != NULL)
                    memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
                break;
            }
            case VM_FILE:
                break;
            default:
                break;
        }
    }
    return true;
err :
    return false;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    // 이거 넣으면 바로 문제 일어남
    hash_destroy(&spt->hash_table, page_destructor);
}

static void // 타입별로 따로 처리해줘야 함. writeback은 일단 나중에
page_destructor(struct hash_elem *e, void *aux UNUSED){
    struct page *page = hash_entry(e, struct page, hash_elem);
    vm_dealloc_page(page);
}

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry (p_, struct page, hash_elem);
    return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
        const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry (a_, struct page, hash_elem);
    const struct page *b = hash_entry (b_, struct page, hash_elem);

    return a->va < b->va;
}

/* Returns the page containing the given virtual address, or NULL. */
struct page *
page_lookup (const struct supplemental_page_table *spt, const void *address) {
    struct page p;
    struct hash_elem *e;

    address = pg_round_down (address);
    p.va = (void *) address;
    e = hash_find (&spt->hash_table, &p.hash_elem);
    return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}