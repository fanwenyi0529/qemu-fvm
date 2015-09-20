/*
 * win_types.h
 *
 *  Created on: 2012-10-23
 *      Author: fw1
 */

#ifndef WIN_TYPES_H_
#define WIN_TYPES_H_


#include <windows.h>

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;

typedef unsigned long long u64;
typedef signed long long s64;

typedef unsigned long long __u64;
typedef signed long long __s64;

#ifdef HOST_X86_64
//#define long long long
#define ul ull
#define UL ULL
typedef unsigned long pteval_t;
typedef unsigned long long ulong;
#elif defined(HOST_I386)
typedef unsigned long pteval_t;
typedef unsigned long ulong;
#else
#error "unsupported host!"
#endif //HOST_X86_64

typedef int __sig_atomic_t;
typedef int sig_atomic_t;

typedef u8 uint8_t;
typedef u16 uint16_t;
typedef u32 uint32_t;
typedef u64 uint64_t;

typedef s8 int8_t;
typedef s16 int16_t;
typedef s32 int32_t;
typedef s64 int64_t;

/*#undef _IO
#undef _IOR
#undef _IOW
#undef _IOWR*/

#define VMMR3_IO(a, b)         	 CTL_CODE(FILE_DEVICE_UNKNOWN,b,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define VMMR3_IOR(a, b, c)       CTL_CODE(FILE_DEVICE_UNKNOWN,b,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define VMMR3_IOW(a, b, c)       CTL_CODE(FILE_DEVICE_UNKNOWN,b,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define VMMR3_IOWR(a, b, c)      CTL_CODE(FILE_DEVICE_UNKNOWN,b,METHOD_BUFFERED,FILE_ANY_ACCESS)


#endif /* WIN_TYPES_H_ */
