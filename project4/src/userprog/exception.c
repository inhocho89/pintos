#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */
  bool growStack;    /* Whether this page fault need to extend stack. */
  struct thread *t;

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;
  
  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  t = thread_current ();

  /* tried to access kernel address */
  /* tried to write read-only page */
  if(is_kernel_vaddr (fault_addr) || (!not_present && write))
    syscall_exit (-1);

  /* if esp is below the code segment */
  if(user && (unsigned)f->esp < 0x08048000)
    syscall_exit (-1);

  struct page *p = page_lookup (fault_addr, t);

  /* In case of file-mapped page */
  if(p!= NULL && p->mapped_file != NULL)
    {
      /* read memory from file */
      uint8_t *kpage = falloc (p->uaddr, true);
      if(!pagedir_set_page (t->pagedir, p->uaddr, kpage, true))
        {
          ffree (kpage);
          syscall_exit (-1);
        }

      p->kaddr = kpage;
      file_read_at (p->mapped_file, kpage, PGSIZE, p->offset);
      p->onFrame = true;

      return; 
    }

  /* In case of page fault because of not present page */
  if(p != NULL && p->onFrame == false)
    {
      /* Time to swap in! */
      uint8_t *kpage;
      kpage = falloc (p->uaddr, false); 

      if (kpage == NULL)
        syscall_exit (-1);
      if(!pagedir_set_page (t->pagedir, p->uaddr, kpage, true))
        {
          ffree (kpage);
          syscall_exit (-1);
        }

      p->kaddr = kpage;

      if(!swap_read(p))
        {
          ffree (kpage);
          syscall_exit (-1);
        }
      p->onFrame = true;
      return;
    } 

  /* Grow stack if necessary */
  growStack = false;

  /* User context */
  /* Run out of stack space! - Normal Case */
  if (user && is_user_vaddr (fault_addr) && not_present && fault_addr >= f->esp)
    growStack = true;

  /* Run out of stack space! - pusha */
  if (is_user_vaddr (fault_addr) && not_present && (*(uint8_t *)f->eip == 0x60)
	  && (f->esp - fault_addr == 32))
    growStack = true;

  /* Kernel Context */
  /* Run out of stack space! - Normal Case */
  if (!user && is_user_vaddr (fault_addr) && not_present && fault_addr >= t->esp)
    growStack = true;

  if(growStack)
    {
      uint8_t *kpage;
      uint8_t *upage = (uint8_t *) pg_round_down (fault_addr);
      struct page *p;
      kpage = falloc (upage, true);

      if(kpage == NULL) // fail to get page
        syscall_exit (-1);

      // insert page to the supplement page table
      lock_acquire (&t->page_lock);

      p = page_create (upage, kpage);
      if (!install_page (upage, kpage, true))
        {
          page_free (p);
          lock_release (&t->page_lock);
          syscall_exit (-1);
        }
      p->onFrame = true;
      lock_release (&t->page_lock);
      
      return;
    } 

  if (is_kernel_vaddr (fault_addr) || not_present == true)
    syscall_exit (-1);

  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. */
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f);
}

