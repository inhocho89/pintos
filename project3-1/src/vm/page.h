#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/disk.h"

struct page{
  void *uaddr;                 /* user virtual address */
  void *kaddr;                 /* mapped kernel virtual address */
  bool isSwapped;              /* Whether is page is swapped or not */
  disk_sector_t swap_location; /* The position of page in swap disk */
  struct hash_elem elem;       /* hash element */
}; 

/* initialize page */
void page_init (void);

/* find page whose uaddr is uaddr_ */
struct page *page_lookup (void *uaddr_, struct thread *t);

/* page lock */
struct lock page_lock;

/* Destroy page table */
void ptable_destroy (struct hash *h);

/* insert a page to the page table */
bool page_insert (void *uaddr, void *kaddr, bool writable);

#endif
