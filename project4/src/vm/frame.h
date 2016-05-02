#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "vm/page.h"

/* total number of user frame */
extern unsigned frame_limit;

/* virtual address of very first user frame */
extern uint8_t *frame_base_addr;

/* lock for the frame operation */
extern struct lock frame_lock;

/* frame table */
extern struct frame *ftable;

struct frame {
  void *uaddr;           /* user page virtual address of the frame */
  struct thread *owner;  /* the thread who own this frame */
};

/* Initialize varialbes when system boots */
void frame_init0(unsigned nframe, uint8_t *base_addr);

/* Initialize frame table */
void frame_init (void);

/* allocate frame which will be mapped to uaddr. */
void *falloc(void *uaddr_, bool zero_filled);

/* free frame */
void ffree(void *kvaddr);

/* clear frame */
void fclear (void *kaddr);

/* get frame from the kernel virtual address */
struct frame *getFrame(void *kvaddr);

unsigned getFrameNumber (void *kaddr);

#endif
