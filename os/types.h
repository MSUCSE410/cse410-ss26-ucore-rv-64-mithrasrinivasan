#ifndef TYPES_H
#define TYPES_H

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;
typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned long uint64;

typedef struct {
	uint64 dev;   // device number
	uint64 ino;   // inode number
	uint32 mode;  // file type
	uint32 nlink; // hard link count
	uint64 pad[7];
} Stat;


#endif // TYPES_H