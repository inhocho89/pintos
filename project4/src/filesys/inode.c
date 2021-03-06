#include "filesys/inode.h"
#include <list.h>
#include <stdio.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define MIN(A,B) ((A<B)?A:B)

/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    disk_sector_t direct[10];           /* Direct blocks  */
    disk_sector_t indirect;             /* Indirect blocks */
    disk_sector_t dindirect;            /* Double indirect blocks */ 
    off_t length;                       /* File size in bytes. */
    bool is_directory;                  /* Whether this inode is directory or not */
    unsigned magic;                     /* Magic number. */
    uint32_t unused[113];               /* Not used. */
  };

/* On-disk map which is used for indirect & double indirect */
struct block_map
  {
    disk_sector_t blocks[128];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    disk_sector_t sector;               /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    return inode_get_dsector (inode, pos/DISK_SECTOR_SIZE);
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  struct inode inode;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = 0;
      disk_inode->is_directory = is_dir;
      disk_inode->magic = INODE_MAGIC;

      inode.data = *disk_inode;
      inode.sector = sector;
      inode.removed = false;

      if (length > 0 && !inode_expand_data (&inode, length))
        return false;
      else if (length == 0)
        buffer_cache_write (inode.sector, disk_inode);

      free (disk_inode);
    }
  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          if (inode->removed)
            return NULL;
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  buffer_cache_read (inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Write it to disk */
      buffer_cache_write (inode->sector, &inode->data);
      //disk_write (filesys_disk, inode->sector, &inode->data);

      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          size_t i;
          free_map_release (inode->sector, 1);
          buffer_cache_remove (inode->sector);
          for(i=0;i<bytes_to_sectors (inode->data.length);++i)
            {
              disk_sector_t sec = inode_get_dsector (inode,i);
              free_map_release (sec, 1);
              buffer_cache_remove (sec);
            }
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      //disk_sector_t sector_idx = byte_to_sector (inode, offset);
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Read full sector directly into caller's buffer. */
          buffer_cache_read (sector_idx, buffer + bytes_read); 
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
           *              into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          buffer_cache_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (!inode_expand_data (inode, offset+size))
    return 0;

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Write full sector directly to disk. */
          buffer_cache_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            buffer_cache_read (sector_idx, bounce);
          else
            memset (bounce, 0, DISK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          buffer_cache_write (sector_idx, bounce); 
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

/* Get sector number of num-th data block of inode */
disk_sector_t
inode_get_dsector (const struct inode *inode, off_t num)
{
  if (num < 10)
    return inode->data.direct[num];

  num -= 10;
  if (num < 128)
    {
      struct block_map map; 
      buffer_cache_read (inode->data.indirect, &map);
      return map.blocks[num];
    }

  num -= 128;
  if (num < 128*128)
    {
      struct block_map map1;
      struct block_map map2;
      buffer_cache_read (inode->data.dindirect, &map1);
      buffer_cache_read (map1.blocks[(num/128)], &map2);
      return map2.blocks[(num%128)];
    }
  return -1;
}

/* Expand inode's data sectors up to LENGTH bytes
 * return false if fails */
bool
inode_expand_data (struct inode *inode, off_t length)
{
  size_t num_block = bytes_to_sectors(length);
  disk_sector_t last_block = bytes_to_sectors(inode->data.length);
  size_t i;
  static char zeros[DISK_SECTOR_SIZE];

  if (num_block > 16522)
    return false;

  if (inode->data.length >= length)
    return true;

  i = last_block;
  
  // Direct Block
  while (i < MIN(10,num_block))
    {
      if (free_map_allocate (1, &inode->data.direct[i]))
        buffer_cache_write (inode->data.direct[i],zeros);
      else
        return false;
      i++;
    }
 
  if (i < MIN(138,num_block))
    { // Indirect Block
      struct block_map map;

      // map loading...
      if (i == 10) // I'm first indirect block
        {
          if (!free_map_allocate (1, &inode->data.indirect))
            return false;
           memset (&map, 0, sizeof (struct block_map));
        }
      else
        buffer_cache_read (inode->data.indirect, &map);

      while (i < MIN(138,num_block))
        {
          if (free_map_allocate (1, &map.blocks[i-10]))
            buffer_cache_write (map.blocks[i-10], zeros);
          else
            return false;

          i++;
        }
      buffer_cache_write (inode->data.indirect, &map);
    }

  if (i < MIN(16522,num_block))
    { // Doubly Indirect Block
      struct block_map map1;
      
      // map layer 1 loading ...
      if (i == 138)
        {
          if (!free_map_allocate (1, &inode->data.dindirect))
            return false;
          memset (&map1, 0, sizeof (struct block_map));
        }
      else
        buffer_cache_read (inode->data.dindirect, &map1);

      while (i < MIN(16522,num_block))
        {
          struct block_map map2;
          size_t map1_idx = (i-138)/128;

          // map layer 2 loading ...
          if ((i-138) % 128 == 0)
            {
              if (!free_map_allocate (1, &map1.blocks[map1_idx]))
                return false;
              memset (&map2, 0, sizeof (struct block_map));
            }
          else
            buffer_cache_read (map1.blocks[map1_idx],&map2);

          while (i < MIN(16522,num_block) && ((i-138)/128) == map1_idx)
            {
              if (free_map_allocate (1, &map2.blocks[((i-138)%128)]))
                buffer_cache_write (map2.blocks[((i-138)%128)], &zeros);
              else
                return false;
              i++;
            }
          buffer_cache_write (map1.blocks[map1_idx], &map2);
        }
      
      buffer_cache_write (inode->data.dindirect, &map1);
    }
  inode->data.length = length;
  buffer_cache_write (inode->sector, &inode->data);

  return true;
}

bool inode_is_directory (struct inode *inode)
{
  return inode->data.is_directory;
}

bool inode_is_removed (struct inode *inode)
{
  return inode->removed;
}
