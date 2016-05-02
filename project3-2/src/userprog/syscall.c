#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "vm/page.h"
#include "vm/mmap.h"

static void syscall_handler (struct intr_frame *);
int syscall_exec (const char *cmd_line);
int syscall_wait (int pid);
bool syscall_create (const char *file_name, unsigned initial_size);
bool syscall_remove (const char *file_name);
int syscall_open (const char *file_name);
int syscall_filesize (int fd);
int syscall_read (int fd, void *buffer, unsigned size);
int syscall_write (int fd, const void *buffer, unsigned size);
void syscall_seek (int fd, unsigned position);
unsigned syscall_tell (int fd);
void syscall_close (int fd);
int syscall_mmap (int fd, void *addr);
void syscall_munmap (int mapping);

void
syscall_init (void) 
{
  lock_init (&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  // SYSTEMCALL NUMBER
  int syscall_number = *((int *)f->esp);

  switch (syscall_number)
  {
    case SYS_HALT : 
      power_off ();
      break;

    case SYS_EXIT :
      if(is_kernel_vaddr (f->esp +4))
        syscall_exit(-1);
      syscall_exit(*(int *)(f->esp+4));
      break;

    case SYS_EXEC :
      f->eax = syscall_exec (*(char **)(f->esp+4));
      break;

    case SYS_WAIT:
      f->eax = syscall_wait (*(int *)(f->esp+4));
      break;

    case SYS_CREATE :
      lock_acquire (&file_lock);
      f->eax = syscall_create (*(char **)(f->esp+4), *(unsigned *)(f->esp+8)); 
      lock_release (&file_lock);
      break;

    case SYS_REMOVE :
      lock_acquire (&file_lock);
      f->eax = syscall_remove (*(char **)(f->esp+4));
      lock_release (&file_lock);
      break;

    case SYS_OPEN :
      lock_acquire (&file_lock);
      f->eax = syscall_open (*(char **)(f->esp+4));
      lock_release (&file_lock); 
      break;

    case SYS_FILESIZE : 
      lock_acquire (&file_lock);
      f->eax = syscall_filesize (*(int *)(f->esp+4));
      lock_release (&file_lock);
      break;

    case SYS_READ :
      lock_acquire (&file_lock);
      f->eax = syscall_read (*(int *)(f->esp+4), 
                    *(void **)(f->esp+8), *(unsigned *)(f->esp+12));
      lock_release (&file_lock);
      break;

    case SYS_WRITE :
      lock_acquire (&file_lock);
      f->eax = syscall_write (*(int *)(f->esp+4), 
                    *(void **)(f->esp+8), *(unsigned *)(f->esp+12)); 
      lock_release (&file_lock);
      break;

    case SYS_SEEK :
      lock_acquire (&file_lock);
      syscall_seek (*(int *)(f->esp+4),*(unsigned *)(f->esp+8));
      lock_release (&file_lock);
      break;

    case SYS_TELL :
      lock_acquire (&file_lock);
      syscall_tell (*(int *)(f->esp+4));
      lock_release (&file_lock);
      break;

    case SYS_CLOSE :
      lock_acquire (&file_lock);
      syscall_close (*(int *)(f->esp+4));
      lock_release (&file_lock);
      break;

    case SYS_MMAP :
      f->eax = syscall_mmap (*(int *)(f->esp+4), *(void **)(f->esp+8));
      break;

    case SYS_MUNMAP :
      syscall_munmap (*(int *)(f->esp+4));
      break;

    case SYS_CHDIR :
      break;

    case SYS_MKDIR :
      break;

    case SYS_READDIR :
      break;

    case SYS_ISDIR :
      break;

    case SYS_INUMBER :
      break;
  }

}

/* Handles system call EXIT */
void syscall_exit (int status)
{
  struct thread *t = thread_current ();
  
  t->exit_status = status;
  printf("%s: exit(%d)\n",t->name,status);
  //sema_up(&t->wait_sema);
  if(!lock_held_by_current_thread (&file_lock))
    lock_acquire (&file_lock);
  mmap_table_destroy (&t->mmap_table);
  lock_release (&file_lock); 
  thread_exit ();
}

/* Handles system call EXEC */
int syscall_exec (const char *cmd_line)
{
  return process_execute (cmd_line);
}

/* Handles system call WAIT */
int syscall_wait (int pid)
{
  int result = process_wait (pid);
  return result;
}

/* Handles system call CREATE */
bool syscall_create (const char *file_name, unsigned initial_size)
{

  if (file_name == NULL || *file_name == '\0' || is_kernel_vaddr (file_name))
      syscall_exit(-1);

  return filesys_create(file_name, initial_size);
}

/* Handles system call REMOVE */
bool syscall_remove (const char *file_name)
{
  return filesys_remove (file_name);
}

/* Handles system call OPEN */
int syscall_open (const char *file_name)
{
  int fd;
  struct thread *t = thread_current ();
  struct file *file; 
 
  if (file_name == NULL || *file_name == '\0')
    return -1;

  for (fd = 0; fd < MAX_NUM_FD; fd++)
    {
      if(t->fd_table[fd] == NULL)
        break;
    }

  ASSERT (fd < MAX_NUM_FD);
  /* Current fd is for indexing array. actual fd is fd+2 */
  /* because 0, 1 are not used for fd */

  file = filesys_open (file_name);
  if (file == NULL) // fails to open file
    return -1;
      
  // success to open file
  t->fd_table[fd] = file;
  return fd+2;
}


/* Handles system call FILESIZE */
int syscall_filesize (int fd)
{
  struct thread *t = thread_current ();
  struct file *file;
  fd = fd - 2;
  file = t->fd_table[fd];
  return file_length (file);
}

/* Handles system call READ */
int syscall_read (int fd, void *buffer, unsigned size)
{
  unsigned i;
  char *read_buf = buffer;
  struct thread *t;
  struct file *file;
  if(is_kernel_vaddr (buffer))
    syscall_exit (-1);

  if (fd == 1 || size == 0)
    return 0;
  else if (fd == 0)
    {
      for (i=0; i < size; i++)
        {
          read_buf[i] = input_getc ();
        }
      return size;
    }
  else 
    {
      fd = fd - 2; // file descripter for indexing
      if (fd < 0 || fd > MAX_NUM_FD)
        syscall_exit(-1);
      t = thread_current ();
      file = t->fd_table[fd];
      if (file != NULL)
          return file_read (file, buffer, size);
      else
        return 0;
    }
}

/* Handles system call WRITE */
int syscall_write (int fd, const void *buffer, unsigned size)
{
  if (is_kernel_vaddr (buffer))
    syscall_exit (-1);

  if (fd == 0 || size == 0)
    return 0;
  else if (fd == 1)
    {
      putbuf(buffer,size);
      return size;
    }
  else
    {
      struct thread *t = thread_current ();
      struct file *file;
      fd = fd - 2; // file descripter for indexing
      if (fd < 0 || fd > MAX_NUM_FD)
        syscall_exit(-1);
      file = t->fd_table[fd];
      if (fd < 0 || fd >= MAX_NUM_FD)
        return 0;
      return file_write (file, buffer, size);
    }
}

/* Handles system call SEEK */
void syscall_seek (int fd, unsigned position)
{
  struct file *file = thread_current ()->fd_table[fd-2];
  file_seek (file, position);
}

/* Handles system call TELL */
unsigned syscall_tell (int fd)
{
  struct file *file = thread_current ()->fd_table[fd-2];
  return file_tell (file);
}

/* Handles system call CLOSE */
void syscall_close (int fd)
{
  struct thread *t;
  struct file *file;
  fd = fd - 2; // fd for indexing
  if(fd < 0 || fd >= MAX_NUM_FD)
    return;
  t = thread_current ();
  file = t->fd_table[fd];
  if(file != NULL)
    file_close(file);
  t->fd_table[fd] = 0;
}

/* mapping file into the memory */
int syscall_mmap (int fd, void *addr){
  struct thread *t = thread_current ();
  struct file *file;
  void *uaddr;

  // validate fd
  fd = fd - 2; // fd for indexing
  if (fd < 0 || fd >= MAX_NUM_FD)
    return -1;

  file = t->fd_table[fd];
  if (file == NULL || file_length (file) == 0)
    return -1;

  //validate addr
  if (is_kernel_vaddr (addr) || addr == NULL)
    return -1;
  if (pg_round_down (addr) != addr)
    return -1;

  // check whether pages are unmapped.
  uaddr = addr;
  while (uaddr < addr + file_length (file))
    {
      if (page_lookup (uaddr, t))
        return -1;
      uaddr += PGSIZE;
    }
  return mmap_insert (file, addr);
}

/* ummap memory-mapped file */
void syscall_munmap (int mapping)
{
  struct thread *t = thread_current ();
  struct mmap *m;
 
  m = mmap_lookup (mapping, t);
  if(m == NULL)
    return;

  mmap_unmap (&m->elem,NULL);
  hash_delete (&t->mmap_table, &m->elem);

  return;
}
