/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "hash.h"
#include "threads/mmu.h"
#include <string.h>
#include "userprog/process.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is not occupied. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* Create the page, fetch the initialier according to the VM type,
		 * and then create "uninit" page struct by calling uninit_new. You
		 * should modify the field after calling the uninit_new. */
		struct page *new_page = malloc(sizeof(struct page));
		if (new_page == NULL)
			goto err;
		memset(new_page, 0, sizeof(struct page));
		if (VM_TYPE(type) == VM_ANON)
		{
			uninit_new(new_page, upage, init, type, aux, anon_initializer);
		}
		else if (VM_TYPE(type) == VM_FILE)
		{
			uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
		}
		new_page->is_page_writable = writable;

		if (!spt_insert_page(&thread_current()->spt, new_page))
		{
			free(new_page);
			goto err;
		}
	}
	return true;
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
	struct page temp_page;
	memset(&temp_page, 0, sizeof(struct page));
	temp_page.va = pg_round_down(va);

	struct hash_elem *actual_hash_elem = hash_find(&spt->spt_hash, &temp_page.hash_elem);
	if (actual_hash_elem == NULL)
		return NULL;

	struct page *page = hash_entry(actual_hash_elem, struct page, hash_elem);

	return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt,
					 struct page *page)
{
	// there do exist a page
	if (spt_find_page(spt, page->va) != NULL)
		return false;

	if (hash_insert(&spt->spt_hash, &page->hash_elem) == NULL)
	{
		return true;
	}
	return false;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	// hash_delete(&spt->spt_hash, &page->hash_elem);
	vm_dealloc_page(page);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	// kernel virtual memory - kernel pool
	struct frame *frame = malloc(sizeof(struct frame));
	if (frame == NULL)
		PANIC("비상");

	// kernel virtual memory - user pool
	void *kva = palloc_get_page(PAL_USER);
	if (kva == NULL)
	{
		// TODO: try to evict a page to get a frame
		PANIC("todo");
	}

	frame->kva = kva;
	frame->page = NULL;

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr,
						 bool user, bool write, bool not_present)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	/* Validate the fault */
	if (addr == NULL || is_kernel_vaddr(addr))
		return false;
	// spt는 항상 시작 주소를 저장하기 때문에 page_round_down
	void *page_addr = pg_round_down(addr);
	// check validation of the fault_addr
	struct page *page = spt_find_page(spt, page_addr);
	if (page == NULL)
		return false;
	if (write && !page->is_page_writable)
		return false;

	// define the new page handler and call it
	return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va)
{
	// Does this va exists? If yes, get its page
	struct page *page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
		return false;
	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	// get physical frame
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->is_page_writable))
	{
		return false;
	}

	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->spt_hash, &supplemental_page_table_hash_func, &supplemental_page_table_hash_less, NULL);
}
// bucket 값 구하기
uint64_t supplemental_page_table_hash_func(const struct hash_elem *e, void *aux)
{
	struct page *p = hash_entry(e, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof(p->va));
}
bool supplemental_page_table_hash_less(const struct hash_elem *a,
									   const struct hash_elem *b,
									   void *aux)
{
	struct page *page_a = hash_entry(a, struct page, hash_elem);
	struct page *page_b = hash_entry(b, struct page, hash_elem);
	if (page_a->va < page_b->va)
		return true;
	return false;
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
	struct thread *current = thread_current();
	struct file *child_exec_file = NULL;

	// Iterate through each page in the src's supplemental page table
	struct hash_iterator i;
	hash_first(&i, &src->spt_hash);
	struct hash_elem *e;
	while ((e = hash_next(&i)) != NULL)
	{
		// src page
		struct page *p = hash_entry(e, struct page, hash_elem);

		// Duplicate aux for pages with file backing
		void *aux = NULL;
		enum vm_type type = page_get_type(p);

		// Check if this is a VM_UNINIT page with file backing
		if (p->operations->type == VM_UNINIT && p->uninit.aux != NULL)
		{
			struct lazy_load_info *parent_aux = (struct lazy_load_info *)p->uninit.aux;
			struct lazy_load_info *child_aux = calloc(1, sizeof(struct lazy_load_info));
			if (child_aux == NULL)
				return false;

			// Reopen the parent's file for the child
			if (parent_aux->file != NULL)
			{
				// 중요! - 항상 reopen / 추가로 thread_exec도 복사함 (process.c)
				child_aux->file = file_reopen(parent_aux->file);
				if (child_aux->file == NULL)
				{
					free(child_aux);
					return false;
				}
			}
			else
			{
				child_aux->file = NULL;
			}
			child_aux->ofs = parent_aux->ofs;
			child_aux->read_bytes = parent_aux->read_bytes;
			child_aux->zero_bytes = parent_aux->zero_bytes;
			aux = child_aux;
		}

		// Make a copy of the entry in the dst's supplemental page table

		// If parent's page is already in memory, copy the content
		if (p->frame != NULL)
		{
			if (!vm_alloc_page_with_initializer(type, p->va, p->is_page_writable, NULL, NULL))
				return false;
			// dst page
			struct page *new_page = spt_find_page(dst, p->va);
			if (!vm_do_claim_page(new_page))
				return false;
			memcpy(new_page->frame->kva, p->frame->kva, PGSIZE);
		}
		else
		{
			if (!vm_alloc_page_with_initializer(type, p->va, p->is_page_writable, p->uninit.init, aux))
			{
				if (aux != NULL)
					free(aux);
				return false;
			}
		}
	}

	return true;
}

void spt_destroy_func(struct hash_elem *h_elem, void *aux UNUSED)
{
	struct page *p = hash_entry(h_elem, struct page, hash_elem);
	if (p)
		destroy(p);
	free(p);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt)
{
	/* Destroy all the supplemental_page_table hold by thread and
	 * writeback all the modified contents to the storage. */
	hash_destroy(&spt->spt_hash, spt_destroy_func);
	return;
}