#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/disk.h"
#include "filesys/off_t.h"

struct page{
  void *uaddr;                 /* user virtual address */
  void *kaddr;                 /* mapped kernel virtual address */
  bool onFrame;                /* Whether this page is on the frame or not */
  int swap_location;           /* The position of page in swap disk */
  struct file *mapped_file;    /* memory-mapped file */
  off_t offset;                /* Offset of memory-mapped file */
  struct hash_elem elem;       /* hash element */
}; 

/* initialize page */
void page_init (void);

/* find page whose uaddr is uaddr_ */
struct page *page_lookup (void *uaddr_, struct thread *t);

/* Destroy page table */
void ptable_destroy (struct hash *h);

/* create a page and insert into the supplement page table */
struct page *page_create (void *uaddr_, void *kaddr_);

/* free page p */
void page_free (struct page *p);

#endif
