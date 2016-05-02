#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <hash.h>
#include <bitmap.h>
#include "devices/disk.h"
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#define SECTORS_PER_PAGE (PGSIZE/DISK_SECTOR_SIZE)

/* Pointer to swap disk */
struct disk *swap_disk;

/* Bitmap for swap disk */
struct bitmap *swap_bitmap;

/* Lock for swap */
struct lock swap_lock;

/* Initialize swap */
void swap_init (void);

/* Write page to the swap disk */
bool swap_write (struct page *p);

/* Read page from swap disk */
bool swap_read (struct page *p);

/* Remove page from swap disk */
void swap_remove (struct page *p);

#endif
