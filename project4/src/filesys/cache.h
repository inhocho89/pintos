#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/disk.h"
#include "threads/synch.h"
#include <stdbool.h>

#define NUM_BUF_CACHE 64

struct cache
{
  int sector_pos;  
  char buf[DISK_SECTOR_SIZE];
  bool accessed;
  bool dirty;
  struct lock cache_lock;
};

extern struct cache *buffer_cache;

void buffer_cache_init (void);
int buffer_cache_lookup (disk_sector_t sec);
unsigned buffer_cache_to_evict (void);
void buffer_cache_write_back (unsigned idx);
unsigned buffer_cache_alloc (disk_sector_t sec);
void buffer_cache_read (disk_sector_t sec, void *buffer);
void buffer_cache_write (disk_sector_t sec, void *buffer);
void buffer_cache_remove (disk_sector_t sec);
void buffer_cache_free (void);

#endif
