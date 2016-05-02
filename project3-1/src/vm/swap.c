#include "swap.h"
#include <stdio.h>

/* Initialize swap */
void swap_init (void)
{
  swap_disk = disk_get (1,1);
  swap_bitmap = bitmap_create (disk_size(swap_disk));
  lock_init(&swap_lock);
}

/* Write page to the disk */
bool swap_write (struct page *p)
{
  int i;
  size_t location;
  bool lockTaken= false;;

  if (lock_held_by_current_thread (&swap_lock))
    lockTaken = true;

  ASSERT (p->isSwapped == false);
  if(!lockTaken)
    lock_acquire (&swap_lock);
  location = bitmap_scan_and_flip (swap_bitmap, 0, SECTORS_PER_PAGE, false);
  
  if(location == BITMAP_ERROR){
    lock_release (&swap_lock);
    return false;
  }

  for(i=0;i<SECTORS_PER_PAGE;++i)
    {
      disk_write(swap_disk, location + i, p->kaddr + i * DISK_SECTOR_SIZE);
    }

  p->swap_location = location;
  p->isSwapped = true;

  if(!lockTaken)
    lock_release (&swap_lock);
  return true;
}

/* Read page from the disk */
bool swap_read (struct page *p)
{
  int i;

  ASSERT (p->isSwapped == true);

  lock_acquire (&swap_lock);
  for(i=0;i<SECTORS_PER_PAGE;++i)
    {
      disk_read(swap_disk, p->swap_location + i, p->kaddr + i * DISK_SECTOR_SIZE);
    }
  bitmap_set_multiple (swap_bitmap, p->swap_location, SECTORS_PER_PAGE, false);
  p->isSwapped = false;
  lock_release (&swap_lock);

  return true;
}

void swap_remove (struct page *p)
{
  lock_acquire (&swap_lock);
  bitmap_set_multiple (swap_bitmap, p->swap_location, SECTORS_PER_PAGE, false);
  lock_release (&swap_lock);
}
