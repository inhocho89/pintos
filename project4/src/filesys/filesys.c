#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "devices/disk.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_disk = disk_get (0, 1);
  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  inode_init ();
  free_map_init ();

  buffer_cache_init (); 
  if (format) 
    do_format ();

  free_map_open ();
  thread_current ()->dir = dir_open_root ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  buffer_cache_free ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  char *name_copy;
  char *filename;
  disk_sector_t new_sector = 0;
  struct dir *pdir;
  struct file *pfile;
  bool success;

  name_copy = malloc (strlen (name) + 1);
  strlcpy (name_copy, name, strlen(name) + 1);

  filename = strrchr (name_copy,'/');

  if (filename != NULL) // some path exists
    {
      *filename = '\0';
      filename += 1;

      pfile = filesys_open (name_copy);
      if (pfile == NULL)
        {
          free (name_copy);
          return false;
        }
      if (inode_is_removed (file_get_inode (pfile)))
        return NULL;

      pdir = dir_open (inode_reopen (file_get_inode (pfile)));
      file_close (pfile);
    }
  else // just file name is given
    {
      if (inode_is_removed (dir_get_inode (thread_current ()->dir)))
        return NULL;
      pdir = dir_reopen (thread_current ()->dir);
      filename = name_copy;
    }

  success = (pdir != NULL
             && free_map_allocate (1, &new_sector)
             && inode_create (new_sector, initial_size, false)
             && dir_add (pdir, filename, new_sector, false));

  if (!success && new_sector > 0)
    free_map_release (new_sector, 1);
  dir_close (pdir);
  free (name_copy);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  char *name_copy;
  struct dir *dir;
  struct inode *inode = NULL;
  char *token;
  char *save_ptr;

  name_copy = (char *) malloc (strlen(name)+1);
  strlcpy (name_copy, name, strlen(name)+1);

  if (*name == '/') // Absolute Address
    inode = inode_open (ROOT_DIR_SECTOR);
  else // Relative Address
    {
      if (thread_current ()->dir == NULL)
        return NULL;

      if (inode_is_removed (dir_get_inode (thread_current ()->dir)))
        return NULL;

      inode = inode_reopen (dir_get_inode (thread_current ()->dir));
    }
  token = strtok_r (name_copy, "/", &save_ptr);

  while (token != NULL)
    {
      dir = dir_open(inode);

      if (dir == NULL || inode_is_removed (dir_get_inode (dir)))
        {
          free (name_copy);
          return NULL;
        }

      dir_lookup (dir, token, &inode);
      dir_close (dir);      

      if (inode == NULL)
        {
          free (name_copy);
          return NULL;
        }

      token = strtok_r (NULL, "/", &save_ptr);
    }

  free (name_copy);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char *name_copy;
  char *filename;
  struct dir *dir;
  struct file *dirfile;
  bool success;

  name_copy = (char *) malloc (strlen(name) + 1);
  strlcpy (name_copy, name, strlen(name) + 1);

  filename = strrchr (name_copy,'/');

  if (filename != NULL)
    { 
      *filename = '\0';
      filename += 1;
      
      if (filename == (name_copy + 1))
        {
          dir = dir_open_root ();
        }
      else
        {
          dirfile = filesys_open (name_copy);
          if (dirfile == NULL)
            {
              free (name_copy);
              return false;
            }
          dir = dir_open (inode_reopen (file_get_inode (dirfile)));
          file_close (dirfile);
        }
    }
  else // just file name is given
    {
      dir = dir_reopen (thread_current ()->dir);
      filename = name_copy;
    }
  success = (dir != NULL
             && dir_remove (dir, filename));

  free (name_copy);
  dir_close (dir);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
