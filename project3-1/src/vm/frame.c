#include <stdio.h>
#include <debug.h>
#include <string.h>
#include "frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"

struct frame *frameToEvict (void);

/* Initialize frame related variables */
void frame_init0(unsigned nframe, uint8_t *base_addr){
  frame_limit = nframe;
  frame_base_addr = base_addr;  
}

/* Allocate memory for frame table and initialize struct frame */
void frame_init (void)
{
  unsigned i;
  
  lock_init (&frame_lock); 
  ftable = (struct frame *) malloc (frame_limit*sizeof(struct frame));
  
  for(i=0; i < frame_limit; ++i)
    {
      ftable[i].uaddr = NULL;
      ftable[i].owner = NULL;
    }
}

/* allocate frame */
void *falloc(void *uaddr_, bool zero_filled)
{
  void *kpage;
  struct frame *f = NULL;

  if(!lock_held_by_current_thread (&frame_lock))
    lock_acquire (&frame_lock);
  if(!lock_held_by_current_thread (&page_lock))
    lock_acquire (&page_lock);
  kpage = palloc_get_page (PAL_USER | (zero_filled ? PAL_ZERO : 0));

  if(kpage == NULL)
    {
      lock_acquire (&swap_lock);
      /* Need to swap out pages */
      f = frameToEvict ();
      
      ASSERT (f != NULL);
      
      /* get victim page */
      struct page *p = page_lookup(f->uaddr, f->owner);

      ASSERT (p != NULL); 
      /* get kernel virtual address */
      kpage = p->kaddr;
      
      /* swap out! */
      if(!swap_write(p))
        {
          lock_release (&frame_lock);
          lock_release (&swap_lock);
          lock_release (&page_lock);
          return NULL;
        }
       
       /* set "not present" to evicted page */
       if(f->owner->pagedir != NULL)
         pagedir_clear_page (f->owner->pagedir, f->uaddr);       

       /* if zero_filled required */
       if(zero_filled)
           memset(kpage,0,PGSIZE);
       lock_release (&swap_lock);
    }
  else
    f = getFrame(kpage);
  
  f->uaddr = uaddr_;
  f->owner = thread_current ();

  if (lock_held_by_current_thread (&frame_lock))
    lock_release (&frame_lock);

  if (lock_held_by_current_thread (&page_lock))
    lock_release (&page_lock);
  return kpage;
}

/* free frame */
void ffree(void *kvaddr)
{
  ASSERT(is_kernel_vaddr(kvaddr));
  struct frame *f;

  if(!lock_held_by_current_thread (&frame_lock))
      lock_acquire (&frame_lock);
  f = getFrame (kvaddr);

  if(f->uaddr != NULL)
    palloc_free_page(kvaddr);
  f->uaddr = NULL;
  f->owner = NULL;

  lock_release (&frame_lock);
}

/* Return frame to be evicted using second chance algorithm */
struct frame *frameToEvict (void)
{
  static unsigned cur_frame_idx = 0;  

  while(true)
    {
      struct frame *f = &ftable[cur_frame_idx];
      if(f->uaddr != NULL && f->owner->pagedir != NULL)
        {
          if(!pagedir_is_accessed (f->owner->pagedir, f->uaddr))
            { 
              cur_frame_idx = (cur_frame_idx + 1) % frame_limit;
              return f;
            }
          pagedir_set_accessed (f->owner->pagedir, f->uaddr, false);
        }
      cur_frame_idx = (cur_frame_idx + 1) % frame_limit;
    }

  NOT_REACHED ();
}

/* return frame mapped with kvaddr. */
struct frame *getFrame(void *kvaddr)
{
  ASSERT(is_kernel_vaddr(kvaddr));

  unsigned idx = ((unsigned)pg_round_down(kvaddr) 
                 - (unsigned)frame_base_addr)/PGSIZE;
  return &ftable[idx];
}
