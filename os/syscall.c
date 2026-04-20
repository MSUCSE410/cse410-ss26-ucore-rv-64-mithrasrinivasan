#include "syscall.h"
#include "console.h"
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
	debugf("sys_write fd = %d str = %x, len = %d", fd, va, len);
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

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	debugf("sys_read fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDIN)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
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

static TaskStatus map_state(enum procstate s)
{
	switch (s) {
	case UNUSED:  return UnInit;
	case RUNNING: return Running;
	case ZOMBIE:  return Exited;
	default:      return Ready;
	}
}

uint64 sys_gettimeofday(uint64 val_va, int _tz)
{
	struct proc *p = curr_proc();
	TimeVal t;

	uint64 cycle = get_cycle();
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;

	if (copyout(p->pagetable, val_va, (char *)&t, sizeof(TimeVal)) < 0)
		return -1;
	return 0;
}

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


uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!\n");
	return fork();
}

uint64 sys_exec(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);
	debugf("sys_exec %s\n", name);
	return exec(name);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}


/**
 * Create a new child process and immediately execute the requested program.
 * Reads the program name from user space, 
 * creates a child process, loads the target program into it,
 * marks it runnable, and returns the child PID.
 * va is the virtual address of the program
 */
uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();   // Get the currently running parent process
	struct proc *np;                // Pointer for the new child process
	char name[200];                 // Buffer to store the program name from user space

	// Copy the program name string from user space into the kernel buffer.
	// If the user address is invalid or the copy fails, return -1.
	if (copyinstr(p->pagetable, name, va, sizeof(name)) < 0)
		return -1;

	// Look up the application ID that matches the requested program name.
	// If the filename is invalid or not found, return -1.
	int id = get_id_by_name(name);
	if (id < 0)
		return -1;

	// Allocate a new process control block for the child.
	// If no process slot is available, return -1.
	np = allocproc();
	if (np == 0)
		return -1;

	// Set the parent-child relationship.
	np->parent = p;

	// Load the requested program into the child process's address space.
	loader(id, np);

	// Mark the child as runnable so the scheduler can run it later.
	np->state = RUNNABLE;

	// Return the child's PID to the parent process.
	return np->pid;
}

/**
 * Set the scheduling priority of the current process.
 * If the requested priority is valid (>= 2), update the process priority,
 * recompute its stride increment, and return the new priority.
 */
uint64 sys_set_priority(long long prio)
{
	struct proc *p = curr_proc();   // Get the currently running process

	// Reject invalid priorities. Stride scheduling only allows priorities >= 2.
	if (prio < 2)
		return -1;

	// Update this process's priority.
	p->priority = prio;

	// Recompute the pass value used by stride scheduling.
	// Higher priority => smaller pass => process runs more often.
	p->pass = BIG_STRIDE / p->priority;

	// Return the new priority to indicate success.
	return prio;
}



extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
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
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;

	case SYS_taskinfo:
		ret = sys_task_info(args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	case SYS_setpriority:
		ret = sys_set_priority(args[0]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
