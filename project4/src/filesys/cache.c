#include "filesys/cache.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "filesys/filesys.h"

struct cache *buffer_cache;

// Initialize Buffer Cache
void buffer_cache_init (void)
{
  int i;
  buffer_cache 
        = (struct cache *) malloc (NUM_BUF_CACHE * sizeof(struct cache));
  for (i=0;i<NUM_BUF_CACHE;++i)
    {
      buffer_cache[i].sector_pos = -1;
      lock_init (&buffer_cache[i].cache_lock);
    } 
  
}

// Lookup and return the index of buffer cache if exists
// return index of buffer cache or -1 if doesn't exist
int buffer_cache_lookup (disk_sector_t sec)
{
  int i;
  for(i=0;i<NUM_BUF_CACHE;++i)
    {
      lock_acquire (&buffer_cache[i].cache_lock);

      if (buffer_cache[i].sector_pos == (int)sec)
        {
          lock_release (&buffer_cache[i].cache_lock);
          return i;
        }      

      lock_release (&buffer_cache[i].cache_lock);
    }

  return -1;
}

unsigned buffer_cache_to_evict (void)
{
  static unsigned cur_cache_idx = 0;
  unsigned victim_idx;
  while(true)
    {
      lock_acquire (&buffer_cache[cur_cache_idx].cache_lock);
      if (!buffer_cache[cur_cache_idx].accessed)
        {
          victim_idx = cur_cache_idx;
          cur_cache_idx = (cur_cache_idx + 1) % NUM_BUF_CACHE;
          return victim_idx;
        }
      buffer_cache[cur_cache_idx].accessed = false;
      lock_release (&buffer_cache[cur_cache_idx].cache_lock);
      cur_cache_idx = (cur_cache_idx + 1) % NUM_BUF_CACHE;
    }
  NOT_REACHED ();
}

void buffer_cache_write_back (unsigned idx)
{
  ASSERT (lock_held_by_current_thread (&buffer_cache[idx].cache_lock));
  if (buffer_cache[idx].dirty)
    disk_write (filesys_disk, buffer_cache[idx].sector_pos, 
                                                buffer_cache[idx].buf);
  buffer_cache[idx].sector_pos = -1;
}

unsigned buffer_cache_alloc (disk_sector_t sec)
{
  int i;
  int idx = -1;

  for (i=0;i<NUM_BUF_CACHE;++i)
    {
      lock_acquire (&buffer_cache[i].cache_lock);
      if (buffer_cache[i].sector_pos == -1)
        {
          idx = i;
          break;
        }
      lock_release (&buffer_cache[i].cache_lock);
    }

  if (idx == -1) // There is no free buffer cache. eviction required
    {
      idx = buffer_cache_to_evict ();
      buffer_cache_write_back (idx);
    }

  buffer_cache[idx].sector_pos = sec;
  buffer_cache[idx].accessed = false;
  buffer_cache[idx].dirty = false;
  lock_release (&buffer_cache[idx].cache_lock);

  return (unsigned)idx;  
}

// Read from the disk sector 'sec' into buffer
void buffer_cache_read (disk_sector_t sec, void *buffer)
{
  int idx;
  idx = buffer_cache_lookup (sec);

  if (idx > -1)
    { // sector exists in the buffer cache 
      lock_acquire (&buffer_cache[idx].cache_lock);
      memcpy (buffer, buffer_cache[idx].buf, DISK_SECTOR_SIZE);
      buffer_cache[idx].accessed = true;
      lock_release (&buffer_cache[idx].cache_lock);
    }
  else
    { // sector doesn't exist in the buffer cache
      // need to read from the disk
      idx = buffer_cache_alloc (sec);
      lock_acquire (&buffer_cache[idx].cache_lock);
      disk_read (filesys_disk, sec, buffer_cache[idx].buf);
      memcpy (buffer, buffer_cache[idx].buf, DISK_SECTOR_SIZE);
      buffer_cache[idx].accessed = true;
      lock_release (&buffer_cache[idx].cache_lock);
    }
}

// Write to the buffer cache with sector 'sec' from buffer
void buffer_cache_write (disk_sector_t sec, void *buffer)
{
  int idx;
  
  idx = buffer_cache_lookup (sec);
  if (idx > -1)
    { // sector exists in the buffer cache
      lock_acquire (&buffer_cache[idx].cache_lock);
      memcpy (buffer_cache[idx].buf, buffer, DISK_SECTOR_SIZE);
      buffer_cache[idx].accessed = true;
      buffer_cache[idx].dirty = true;
      lock_release (&buffer_cache[idx].cache_lock);
    }
  else
    { // sector doesn't exist in the buffer cache
      // need to read from the disk
      idx = buffer_cache_alloc (sec);
      lock_acquire (&buffer_cache[idx].cache_lock);
      memcpy (buffer_cache[idx].buf, buffer, DISK_SECTOR_SIZE);
      buffer_cache[idx].accessed = true;
      buffer_cache[idx].dirty = true;
      lock_release (&buffer_cache[idx].cache_lock);
    }
}

void buffer_cache_remove (disk_sector_t sec)
{
  int idx = buffer_cache_lookup (sec);

  if (idx > -1)
    buffer_cache[idx].sector_pos = -1; 
}

void buffer_cache_free (void)
{
  int i;

  for (i=0;i<NUM_BUF_CACHE;++i)
    {
      // write back to the disk
      lock_acquire (&buffer_cache[i].cache_lock);
      if (buffer_cache[i].sector_pos > -1)
        {
          buffer_cache_write_back (i);
        }
      lock_release (&buffer_cache[i].cache_lock);
    }
  free (buffer_cache);
}
