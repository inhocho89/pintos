#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <hash.h>
#include "filesys/file.h"
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* fixed point real arithmetic. F = 2^Q */
#define FIXED_Q 14
#define FIXED_F 16384

/* Maximum file descripter that one thread can hold */
#define MAX_NUM_FD 128

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                           /* Thread identifier. */
    enum thread_status status;           /* Thread state. */
    char name[16];                       /* Name (for debugging purposes). */
    uint8_t *stack;                      /* Saved stack pointer. */
    int priority;                        /* Priority. */
    int priority_org;                    /* Original Priority */

    bool load_success;                     /* Whether it success to load child */
    int exit_status;                       /* Exit Status */
    struct list locks;                     /* List of holding locks */
    struct lock *waiting_lock;             /* The lock waiting for */
    
    /* Shared between thread.c and synch.c. */
    struct list_elem elem;                 /* List element. */
    struct list_elem valid_elem;           /* List element for valid_list */

    /* List of child processes */
    struct list child_list;
    /* Used for child_list */
    struct list_elem child_elem;

    /* the tick when thread need to be waken up */
    int64_t expire_tick;

    /* file descripter table */
    struct file *fd_table[MAX_NUM_FD];

    /* Parent Thread(process) */
    struct thread *parent;

    /* Program Execution Semaphore */
    struct semaphore exec_sema;

    /* Semaphore used for WAIT */
    struct semaphore wait_sema;

    /* Executing binary file */
    struct file *exec_file;
#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                     /* Page directory. */
#endif

    /* Lock for accessing ptable */
    struct lock page_lock;

    /* supplementary page table */
    struct hash ptable;

    /* Lock for accessing mmap table */
    struct lock mmap_lock;

    /* mmap table */
    struct hash mmap_table;

    /* Owned by thread.c. */
    unsigned magic;                        /* Detects stack overflow. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

bool thread_expire_less_func (const struct list_elem *a,
            const struct list_elem *b, void *aux UNUSED);

bool thread_priority_less_func (const struct list_elem *a,
            const struct list_elem *b, void *aux UNUSED);

void thread_init (void);
void thread_start (void);

void thread_tick (int64_t ticks);
void thread_second (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);
void thread_update_priority (void);
void thread_update_mlfqs_priority (struct thread *t);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void thread_sleep(int64_t ticks);

#endif /* threads/thread.h */
