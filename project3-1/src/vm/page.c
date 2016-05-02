#include "page.h"
#include <stdio.h>
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/swap.h"

unsigned page_hash (const struct hash_elem *p_, void *aux);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_,
                void *aux);
void ptable_free (struct hash_elem *he, void *aux UNUSED);

/* initialize page */
void page_init (void)
{
  struct thread *t = thread_current ();
  lock_init (&page_lock);
  hash_init(&t->ptable, page_hash, page_less, NULL);
}

/* Return the the page where uaddr_ belongs. Return NULL if such a page
   doesn't exist */
struct page *page_lookup (void *uaddr_, struct thread *t)
{
  struct page p;
  struct hash_elem *e;
  bool lockTaken = false;

  if (lock_held_by_current_thread (&page_lock))
    lockTaken = true;

  if(!lockTaken)
    lock_acquire (&page_lock);
  p.uaddr = pg_round_down(uaddr_);
  e = hash_find(&t->ptable, &p.elem);
  if(!lockTaken)
    lock_release (&page_lock);

  return e != NULL ? hash_entry (e, struct page, elem) : NULL;
}

/* insert a page to the page table */
bool page_insert (void *uaddr_, void *kaddr_, bool writable_)
{
  struct page *p;
  struct thread *t = thread_current ();
  struct hash_elem *he;

  lock_acquire (&page_lock);
  if((p = page_lookup(uaddr_, t)))
    {
      free (p);
      pagedir_clear_page(t->pagedir, uaddr_);
    }
  
  p = (struct page *) malloc (sizeof (struct page));

  if(p == NULL)
    return false;

  p->uaddr = uaddr_;
  p->kaddr = kaddr_;
  p->isSwapped = false;
  p->swap_location = 0;

  he = hash_insert(&t->ptable, &p->elem);
  if(he)
    {
      free(p);
      lock_release (&page_lock);
      return false;
    }
  if (pagedir_get_page (t->pagedir, uaddr_)
      || !pagedir_set_page (t->pagedir, uaddr_, kaddr_, writable_))
    {  /* fail to update page table */
      free(p);
      lock_release (&page_lock);
      return false;
    }
  lock_release (&page_lock);
  return true;
}

void ptable_free (struct hash_elem *he, void *aux UNUSED)
{
  struct page *p = hash_entry (he, struct page, elem);

  if(p->isSwapped)
    swap_remove (p);
  free(p);
}

void ptable_destroy (struct hash *h)
{
  bool lockTaken = false;
  
  if(lock_held_by_current_thread (&page_lock))
    lockTaken = true;

  if(!lockTaken)
    lock_acquire (&page_lock);
  hash_destroy (h, ptable_free);
  if(!lockTaken)
    lock_release (&page_lock);
}

/* Returns a hash value for page */
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  struct page *p = hash_entry (p_, struct page, elem);
  return hash_bytes (&p->uaddr, sizeof(p->uaddr));
}

/* Returns true if page a precedes page b. */
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_,
                void *aux UNUSED)
{
  struct page *a = hash_entry (a_, struct page, elem);
  struct page *b = hash_entry (b_, struct page, elem);

  return a->uaddr < b->uaddr;
}
