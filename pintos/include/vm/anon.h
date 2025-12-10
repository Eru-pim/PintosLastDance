#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
struct page;
enum vm_type;

struct anon_page
{
    size_t swap_slot;
};

void vm_anon_init(void);
bool anon_initializer(struct page *page, enum vm_type type, void *kva);

// Exposed for fork to copy swap slots
struct bitmap;
struct lock;
extern struct bitmap *swap_table;
extern struct lock swap_lock;

#endif
