/*
 * vmmr3_call_r0.h
 *
 *  Created on: 2012-10-29
 *      Author: fw1
 */

#ifndef VMMR3_CALL_R0_H_
#define VMMR3_CALL_R0_H_

#ifdef CONFIG_LINUX

#define VMMModuleName 			"/dev/vmmr0"

static inline int vmmr3_open(void)
{
	return qemu_open(VMMModuleName, O_RDWR);
}

static inline int vmmr3_close(int fd)
{
	return close(fd);
}

static inline int vmmr3_ioctl(int fd , int req, void *data)
{
	return ioctl(fd, req, data);
}

static inline int vmmr3_vm_ioctl(int fd , int req, void *data)
{
	return ioctl(fd, req, data);
}

static inline int vmmr3_vcpu_ioctl(int fd , int req, void *data)
{
	return ioctl(fd, req, data);
}

static inline struct kvm_run* vmmr3_get_vmmr0_run(KVMState *s, int kvm_fd)
{
	long mmap_size;
	struct kvm_run* kvm_run;
	mmap_size = kvm_ioctl(s, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size < 0)
	{
		DPRINTF("KVM_GET_VCPU_MMAP_SIZE failed\n");
		return NULL;
	}

	kvm_run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, kvm_fd, 0);
	if (kvm_run == MAP_FAILED)
	{
		return NULL;
	}
	return kvm_run;
}

static inline void* vmmr3_get_coalesced_mmio(KVMState *s, int kvm_fd, void* run)
{
	return run + s->coalesced_mmio * PAGE_SIZE;
}

#elif defined(CONFIG_WIN32)

#define VMMModuleName 			"\\\\.\\vmmr0"
#define VMMR0ServiceName 		"vmmr0"
#define VMMR0ServicePath 		"vmmr0.sys"
#define NT_DEVICE_NAME           L"\\Device\\vmmr0"
#define DOS_DEVICE_NAME          L"\\DosDevices\\vmmr0"

HANDLE vmmr0_handle = 0;

static inline HANDLE vmmr3_get_vmmr0_handle(void)
{
	HANDLE ret = CreateFile(
			VMMModuleName,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

	return ret;
}

static inline HANDLE vmmr3_open(void)
{
	vmmr0_handle = vmmr3_get_vmmr0_handle();
	return vmmr0_handle;
}

static inline int vmmr3_close(HANDLE fd)
{
	CloseHandle(fd);
	return 0;
}

typedef struct ioctl_arg
{
	void* arg;
	int fd;
}ioctl_arg;

static inline int vmmr3_ioctl(HANDLE fd, unsigned long IoCtlCode, void* pBufferIn)
{
	ULONG returned;
	int ret = -1;
	struct ioctl_arg arg;
	arg.fd = 0;
	arg.arg = pBufferIn;
	if(!DeviceIoControl(fd,IoCtlCode,&arg,sizeof(arg),&ret,sizeof(ret),&returned,NULL))
	{
		return -1;
	}
	return ret;
}

static inline int vmmr3_vm_ioctl(int fd, unsigned long IoCtlCode, void* pBufferIn)
{
	ULONG returned;
	int ret = -1;
	struct ioctl_arg arg;
	arg.fd = fd;
	arg.arg = pBufferIn;
	if(!DeviceIoControl(vmmr0_handle,IoCtlCode,&arg,sizeof(arg),&ret,sizeof(ret),&returned,NULL))
	{
		return -1;
	}
	return ret;
}

static inline int vmmr3_vcpu_ioctl(int fd, HANDLE handle, unsigned long IoCtlCode, void* pBufferIn)
{
	ULONG returned;
	int ret = -1;
	struct ioctl_arg arg;
	arg.fd = fd;
	arg.arg = pBufferIn;
	if(!DeviceIoControl(handle,IoCtlCode,&arg,sizeof(arg),&ret,sizeof(ret),&returned,NULL))
	{
		return -1;
	}
	return ret;
}

static inline struct kvm_run* vmmr3_get_vmmr0_run(KVMState *s, int kvm_fd)
{
	ULONG returned;
	struct kvm_run* kvm_run = 0;
	struct ioctl_arg arg;
	arg.fd = kvm_fd;
	arg.arg = 0;
	if(!DeviceIoControl(vmmr0_handle,KVM_GET_KVM_RUN,&arg,sizeof(arg),&kvm_run,sizeof(kvm_run),&returned,NULL))
	{
		return 0;
	}
	return kvm_run;
}

static inline int vmmr3_put_vmmr0_run(KVMState *s, int kvm_fd, struct kvm_run* kvm_run)
{
	ULONG returned;
	struct ioctl_arg arg;
	arg.fd = kvm_fd;
	arg.arg = kvm_run;
	if(!DeviceIoControl(vmmr0_handle,KVM_PUT_KVM_RUN,&arg,sizeof(arg),&kvm_run,sizeof(kvm_run),&returned,NULL))
	{
		return -1;
	}
	return 0;
}

static inline void* vmmr3_get_coalesced_mmio(KVMState *s, int kvm_fd, void* run)
{
	ULONG returned;
	struct kvm_run* kvm_run = 0;
	struct ioctl_arg arg;
	arg.fd = kvm_fd;
	arg.arg = 0;
	if(!DeviceIoControl(vmmr0_handle,KVM_GET_KVM_COALESCED_MMIO,&arg,sizeof(arg),&kvm_run,sizeof(kvm_run),&returned,NULL))
	{
		return 0;
	}
	return kvm_run;
}

static inline HANDLE vmmr3_get_kick_event(KVMState *s, int kvm_fd)
{
	ULONG returned;
	struct ioctl_arg arg;
	HANDLE kick_event = CreateEvent(NULL, false, false, NULL); 
	arg.fd = kvm_fd;
	arg.arg = &kick_event;
	if(!DeviceIoControl(vmmr0_handle,KVM_BIND_EVENT,&arg,sizeof(arg),NULL,0,&returned,NULL))
	{
		return 0;
	}
	return kick_event;
}

static inline BOOL vmmr3_set_lock_pages_privilege(HANDLE proc_handle, BOOL enable)
{
	struct
	{
		DWORD nr;
		LUID_AND_ATTRIBUTES privilege[1];
	}info;

	HANDLE token_handle;
	BOOL r;

	r = OpenProcessToken(proc_handle, TOKEN_ADJUST_PRIVILEGES, &token_handle);

	if(r != TRUE)
	{
		fprintf(stderr, "error opening process token\n");
		goto out_error;
	}

	//open/cancel

	info.nr = 1;
	if(enable)
	{
		info.privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		info.privilege[0].Attributes = 0;
	}

	r = LookupPrivilegeValue (NULL, SE_LOCK_MEMORY_NAME, &(info.privilege[0].Luid));

	if(r != TRUE)
	{
		fprintf(stderr, "error getting privilege for %s\n", SE_LOCK_MEMORY_NAME);
		goto out_error;
	}

	r = AdjustTokenPrivileges(token_handle, FALSE, (PTOKEN_PRIVILEGES)&info, 0, NULL, NULL);

	if(r != TRUE)
	{
		fprintf(stderr, "error adjusting token privileges,error code (%u)\n", (unsigned int)GetLastError() );
		goto out_error;
	}
	else
	{
		if(GetLastError() != ERROR_SUCCESS)
		{
			fprintf(stderr, "cant enable the SE_LOCK_MEMORY_NAME privilege, check the local policy.\n");
			goto out_error;
		}
	}
	CloseHandle(token_handle);
	return TRUE;
	out_error:
	return FALSE;
}

static inline void* vmmr3_awe_alloc(size_t size)
{
	BOOL r;
	ULONG_PTR nr_pages;
	ULONG_PTR nr_pages_initial;
	ULONG_PTR *pfn;
	PVOID ret;
	SYSTEM_INFO sys_info;
	INT pfn_size;

	GetSystemInfo(&sys_info);
	nr_pages = size/sys_info.dwPageSize;
	pfn_size = nr_pages * sizeof (ULONG_PTR);
	pfn = (ULONG_PTR *)HeapAlloc(GetProcessHeap(), 0, pfn_size);

	if (pfn == NULL)
	{
		goto out_nomem;
	}

	if(!vmmr3_set_lock_pages_privilege(GetCurrentProcess(), TRUE))
	{
		goto out_nomem;
	}
	nr_pages_initial = nr_pages;
	r = AllocateUserPhysicalPages(GetCurrentProcess(), &nr_pages, pfn);

	if(r != TRUE)
	{
		fprintf(stderr, "error allocating physical pages,error code (%u)\n", (unsigned int)GetLastError() );
		goto out_nomem;
	}

	if(nr_pages != nr_pages_initial)
	{
		fprintf(stderr, "required %p pages, but only can alloc %p pages.\n",(void*)nr_pages_initial, (void*)nr_pages);
		goto out_nomem;
	}

	ret = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE);

	if(ret == NULL)
	{
		goto out_nomem;
	}
	r = MapUserPhysicalPages(ret, nr_pages, pfn);

	if(r != TRUE)
	{
		fprintf(stderr, "MapUserPhysicalPages failed, error code (%u)\n", (unsigned int)GetLastError() );
		goto out_nomem;
	}
	return ret;
	out_nomem:
	ret = 0;
	return ret;
}

typedef struct kmap_map
{
	u64 addr_virt;
	u64 size;
}kmap_map;

static inline void* vmmr3_alloc_kmem(size_t size)
{
	ULONG returned;
	void* mem = 0;
	u64 ret = 0;
	struct ioctl_arg arg;
	struct kmap_map kmap_map;
	mem = vmmr3_awe_alloc(size);
	if(!mem)
	{
		goto out_nomem;
	}
	kmap_map.addr_virt = (u64)mem;
	kmap_map.size = (u64)size;
	arg.fd = 0;
	arg.arg = (void*)&kmap_map;
	if(!DeviceIoControl(vmmr0_handle,KVM_ALLOC_KMEM,&arg,sizeof(arg),&ret,sizeof(ret),&returned,NULL))
	{
		return 0;
	}
	return mem;

	out_nomem:
	exit(-ENOMEM);
}

static inline void vmmr3_free_kmem(void* ptr)
{
	ULONG returned;
	int ret = -1;
	struct ioctl_arg arg;
	arg.fd = 0;
	arg.arg = (void*)ptr;
	if(!DeviceIoControl(vmmr0_handle,KVM_FREE_KMEM,&arg,sizeof(arg),&ret,sizeof(ret),&returned,NULL))
	{
		return;
	}
}

#endif

#endif /* VMMR3_CALL_R0_H_ */
