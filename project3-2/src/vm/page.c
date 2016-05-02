#include "page.h"
#include <stdio.h>
#include <hash.h>
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/swap.h"
#include "vm/frame.h"

unsigned page_hash (const struct hash_elem *p_, void *aux);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_,
                void *aux);
void ptable_free (struct hash_elem *he, void *aux UNUSED);

/* initialize page */
void page_init (void)
{
  struct thread *t = thread_current ();
  lock_init (&t->page_lock);
  hash_init (&t->ptable, page_hash, page_less, NULL);
}

/* Return the page where uaddr_ belongs. Return NULL if such a page
   doesn't exist */
struct page *page_lookup (void *uaddr_, struct thread *t)
{
  struct page p;
  struct hash_elem *e;

  p.uaddr = pg_round_down (uaddr_);
  e = hash_find (&t->ptable, &p.elem);

  return e != NULL ? hash_entry (e, struct page, elem) : NULL;
}

struct page *page_create (void *uaddr_, void *kaddr_)
{
  struct thread *t = thread_current ();
  struct page *p; 
  
  if((p = page_lookup (uaddr_, t)))
    {
      page_free (p);
      pagedir_clear_page (t->pagedir, uaddr_);
    }

  p = (struct page *) malloc (sizeof (struct page));
  p->uaddr = uaddr_;
  p->kaddr = kaddr_;
  p->onFrame = false;
  p->swap_location = -1;
  p->mapped_file = NULL;
  p->offset = 0; 

  if(hash_insert(&t->ptable, &p->elem))
    {
      free (p);
      return NULL;
    }

  return p;
}

void page_free (struct page *p)
{
  struct thread *t = thread_current ();
  hash_delete (&t->ptable, &p->elem);
  free (p);
}

void ptable_free (struct hash_elem *he, void *aux UNUSED)
{
  struct thread *t = thread_current ();
  if(!lock_held_by_current_thread (&swap_lock))
    lock_acquire (&swap_lock);
  if(!lock_held_by_current_thread (&t->page_lock))
    lock_acquire (&t->page_lock);
  struct page *p = hash_entry (he, struct page, elem);

  if(!p->onFrame && !p->mapped_file)
    swap_remove (p); 

  free(p);
  lock_release (&swap_lock);
  lock_release (&t->page_lock);
}

void ptable_destroy (struct hash *h)
{
  struct thread *t = thread_current ();
  if(!lock_held_by_current_thread (&t->page_lock))
    lock_acquire (&t->page_lock);

  hash_destroy (h, ptable_free);
 
  if(lock_held_by_current_thread (&t->page_lock))
    lock_release (&t->page_lock);
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
