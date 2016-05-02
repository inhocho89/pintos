#include "mmap.h"
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"

unsigned mmap_hash (const struct hash_elem *p_, void *aux);
bool mmap_less (const struct hash_elem *a_, const struct hash_elem *b_,
                void *aux);

/* Initialize mmap */
void mmap_init (void)
{
  struct thread *t = thread_current ();
  lock_init (&t->mmap_lock);
  hash_init (&t->mmap_table, mmap_hash, mmap_less, NULL);
}

/* Return the mmap where map_id belongs. Return NULL if such a mmap
 * doesn't exist */
struct mmap *mmap_lookup (int map_id, struct thread *t)
{
  struct mmap m;
  struct hash_elem *e;

  m.mmap_id = map_id;
  e = hash_find (&t->mmap_table, &m.elem);

  return e != NULL ? hash_entry (e, struct mmap, elem) : NULL;
}

/* Returns a hash value for mmap */
unsigned mmap_hash (const struct hash_elem *m_, void *aux UNUSED)
{
  struct mmap *m = hash_entry (m_, struct mmap, elem);
  return hash_bytes (&m->mmap_id, sizeof(m->mmap_id));
}

/* Returns true if mmap a precedes mmap b */
bool mmap_less (const struct hash_elem *a_, const struct hash_elem *b_,
                void *aux UNUSED)
{
  struct mmap *a = hash_entry (a_, struct mmap, elem);
  struct mmap *b = hash_entry (b_, struct mmap, elem);

  return a->mmap_id < b->mmap_id;
}

/* insert memory-mapped file */
int mmap_insert(struct file *f, void *addr)
{
  struct thread *t = thread_current ();
  struct mmap *m = (struct mmap *) malloc (sizeof(struct mmap));
  int mmap_id = 0;
  void *uaddr;
  struct file *file = file_reopen (f);
  int count = 0;

  while (mmap_lookup (mmap_id, t))
    mmap_id++;

  m->mmap_id = mmap_id;
  m->file = file;
  m->base_addr = addr;

  hash_insert(&t->mmap_table, &m->elem);
  uaddr = addr;
  while (uaddr < addr + file_length (file))
    {
      struct page *p = page_create (uaddr, NULL);
      p->mapped_file = file;
      p->offset = count * PGSIZE;
      uaddr += PGSIZE;
      count++;
    }
   
  return mmap_id;
}

/* unmap memeory-mapped file */
void mmap_unmap (struct hash_elem *he, void *aux UNUSED)
{
  struct thread *t = thread_current ();
  struct mmap *m = hash_entry (he, struct mmap, elem); 
  void *addr = m->base_addr;
  off_t file_left = file_length (m->file);

  while (file_left > 0)
    {
      int byte_write = file_left < PGSIZE ? file_left : PGSIZE;
      struct page *p = page_lookup (addr, t);
      if (p->onFrame)
        {
          if (p->onFrame && pagedir_is_dirty (t->pagedir, addr))
            file_write_at (p->mapped_file, p->kaddr, byte_write, p->offset);
          ffree(p->kaddr);
        }
      pagedir_clear_page (t->pagedir, addr);
      page_free (p);

      /* Advance */
      file_left -= byte_write;
      addr += PGSIZE;
    }
  file_close (m->file);
}

void mmap_table_destroy (struct hash *h)
{
  hash_destroy (h, mmap_unmap);
}
