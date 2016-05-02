#ifndef VM_MMAP_H
#define VM_MMAP_H
#include <hash.h>
#include "threads/thread.h"

struct mmap {
  int mmap_id;
  struct file *file;
  void *base_addr;
  struct hash_elem elem;  
};

/* initalize mmap table */
void mmap_init (void);

/* look for previously memory-mapped file with map_id */
struct mmap *mmap_lookup (int map_id, struct thread *t);

/* insert memory-mapped file */
int mmap_insert (struct file *f, void *addr);

/* unmap memmory-mapped file */
void mmap_unmap (struct hash_elem *he, void *aux UNUSED);

/* destroy mmap_table */
void mmap_table_destroy (struct hash *h);

#endif
