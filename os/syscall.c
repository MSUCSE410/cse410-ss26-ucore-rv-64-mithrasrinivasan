#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"

int sys_task_info(uint64 ti_va);
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd);
uint64 sys_munmap(uint64 start, uint64 len);

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}


/**
 * Returns the current time to user space in seconds and microseconds.
 * Builds a TimeVal in the kernel and copies it out to the user address.
 */
uint64 sys_gettimeofday(uint64 val_va, int _tz)
{
	struct proc *p = curr_proc();
	TimeVal val;

	uint64 cycle = get_cycle();
	val.sec = cycle / CPU_FREQ;
	val.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;

	if (copyout(p->pagetable, val_va, (char *)&val, sizeof(val)) < 0)
		return -1;
	return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
/*
* LAB1: you may need to define sys_task_info here
*/

/**
 * Maps an internal process state to the TaskStatus enum used by user programs.
 */
static TaskStatus map_state(enum procstate s) {
    switch (s) {
    case UNUSED:  return UnInit;
    case RUNNING: return Running;
    case ZOMBIE:  return Exited;
    default:      return Ready;   // USED, SLEEPING, RUNNABLE
    }
}


/**
 * Returns task information to user space, including status, syscall counts,
 * and elapsed running time in milliseconds.
 */
int sys_task_info(uint64 ti_va)
{
	struct proc *p = curr_proc();
	TaskInfo ti;

	ti.status = map_state(p->state);

	for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
		ti.syscall_times[i] = p->syscall_times[i];
	}

	uint64 now = get_cycle() / (CPU_FREQ / 1000);
	ti.time = (p->start_time_ms == 0) ? 0 : (int)(now - p->start_time_ms);

	if (copyout(p->pagetable, ti_va, (char *)&ti, sizeof(ti)) < 0)
		return -1;
	return 0;
}


/**
 * Maps a range of user virtual memory pages with the requested permissions.
 * Validates the request, allocates physical pages, and inserts page mappings.
 */
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
	struct proc *p = curr_proc();
	(void)flag;
	(void)fd;

	if (len == 0)
		return 0;
	if (len > (1UL << 30))
		return -1;
	if ((port & ~0x7) != 0)
		return -1;
	if ((port & 0x7) == 0)
		return -1;
	if (start % PGSIZE != 0)
		return -1;
	if (start + len < start)
		return -1;

	uint64 end = PGROUNDUP(start + len);

	for (uint64 va = start; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) != 0)
			return -1;
	}

	int perm = PTE_U;
	if (port & 0x1) perm |= PTE_R;
	if (port & 0x2) perm |= PTE_W;
	if (port & 0x4) perm |= PTE_X;

	uint64 mapped = 0;
	for (uint64 va = start; va < end; va += PGSIZE) {
		void *mem = kalloc();
		if (mem == 0) {
			if (mapped > 0)
				uvmunmap(p->pagetable, start, mapped, 1);
			return -1;
		}

		memset(mem, 0, PGSIZE);

		if (mappages(p->pagetable, va, PGSIZE, (uint64)mem, perm) < 0) {
			kfree(mem);
			if (mapped > 0)
				uvmunmap(p->pagetable, start, mapped, 1);
			return -1;
		}
		mapped++;
	}

	return 0;
}

/**
 * Unmaps a range of user virtual memory pages and frees the backing memory.
 * Fails if any page in the requested range is not currently mapped.
 */
uint64 sys_munmap(uint64 start, uint64 len)
{
	struct proc *p = curr_proc();

	if (len == 0)
		return 0;
	if (start % PGSIZE != 0)
		return -1;
	if (start + len < start)
		return -1;

	uint64 end = PGROUNDUP(start + len);
	uint64 npages = (end - start) / PGSIZE;

	for (uint64 va = start; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) == 0)
			return -1;
	}

	uvmunmap(p->pagetable, start, npages, 1);
	return 0;
}

extern char trap_page[];


/**
 * Dispatches a user syscall, updates syscall statistics, and returns
 * the result through the current trapframe.
 */
void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
        curr_proc()->syscall_times[id]++;
    }
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/

	case SYS_taskinfo:
		ret = sys_task_info(args[0]);
  		break;

	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;

	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;

	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
