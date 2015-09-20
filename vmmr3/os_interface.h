/*
 * os_interface.h
 *
 *  Created on: 2012-10-23
 *      Author: fw1
 */

#ifndef OS_INTERFACE_H_
#define OS_INTERFACE_H_

#include "config-host.h"

#ifdef CONFIG_LINUX
#include <linux/types.h>
#include <linux/ioctl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#define VMMR3_IO				_IO
#define VMMR3_IOR				_IOR
#define VMMR3_IOW				_IOW
#define VMMR3_IOWR				_IOWR

#include "qemu-common.h"

#elif defined(CONFIG_WIN32)
#include "vmmr3/win_types.h"
#include <winioctl.h>
#include "vmmr3/errno.h"

//mingw headers
#include <sys/types.h>
#else
#error "unsupported host!"
#endif

#endif /* OS_INTERFACE_H_ */
