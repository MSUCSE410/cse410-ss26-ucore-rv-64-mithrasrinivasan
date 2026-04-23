#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"
#include "fs.h"

static TaskStatus map_state(enum procstate s);

int sys_task_info(uint64 ti_va);
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd);
uint64 sys_munmap(uint64 start, uint64 len);

uint64 sys_spawn(uint64 va);
uint64 sys_set_priority(long long prio);

int sys_fstat(int fd, uint64 stat);
int sys_linkat(int olddirfd, uint64 oldpath, int newdirfd, uint64 newpath, uint64 flags);
int sys_unlinkat(int dirfd, uint64 name, uint64 flags);

uint64 console_write(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	tracef("write size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return len;
}

uint64 console_read(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	tracef("read size = %d", len);
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

uint64 sys_write(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE - 1)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_write(va, len);
	case FD_INODE:
		return inodewrite(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE - 1)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_read(va, len);
	case FD_INODE:
		return inoderead(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
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


static TaskStatus map_state(enum procstate s)
{
	switch (s) {
	case UNUSED:  return UnInit;
	case RUNNING: return Running;
	case ZOMBIE:  return Exited;
	default:      return Ready;
	}
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
	debugf("fork!");
	return fork();
}

static inline uint64 fetchaddr(pagetable_t pagetable, uint64 va)
{
	uint64 *addr = (uint64 *)useraddr(pagetable, va);
	return *addr;
}

uint64 sys_exec(uint64 path, uint64 uargv)
{
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	copyinstr(p->pagetable, name, path, MAX_STR_LEN);
	uint64 arg;
	static char strpool[MAX_ARG_NUM][MAX_STR_LEN];
	char *argv[MAX_ARG_NUM];
	int i;
	for (i = 0; uargv && (arg = fetchaddr(p->pagetable, uargv));
	     uargv += sizeof(char *), i++) {
		copyinstr(p->pagetable, (char *)strpool[i], arg, MAX_STR_LEN);
		argv[i] = (char *)strpool[i];
	}
	argv[i] = NULL;
	return exec(name, (char **)argv);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();
	struct proc *np;
	struct inode *ip;
	char name[MAX_STR_LEN];

	if (copyinstr(p->pagetable, name, va, MAX_STR_LEN) < 0)
		return -1;

	if ((ip = namei(name)) == 0)
		return -1;

	np = allocproc();
	if (np == 0) {
		iput(ip);
		return -1;
	}

	np->parent = p;

	if (init_stdio(np) < 0) {
		iput(ip);
		freeproc(np);
		return -1;
	}

	bin_loader(ip, np);
	iput(ip);

	np->trapframe->a0 = 0;
	np->state = RUNNABLE;

	return np->pid;
}

uint64 sys_set_priority(long long prio)
{
	struct proc *p = curr_proc();

	if (prio < 2)
		return -1;

	p->priority = prio;
	p->pass = BIG_STRIDE / p->priority;
	return prio;
}



uint64 sys_openat(uint64 va, uint64 omode, uint64 _flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, va, 200);
	return fileopen(path, omode);
}

uint64 sys_close(int fd)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE - 1)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d", fd);
		return -1;
	}
	fileclose(f);
	p->files[fd] = 0;
	return 0;
}

/**
 * Return file metadata for an open file descriptor.
 * This validates the file descriptor, checks that it refers to an inode-backed file,
 * fills a Stat structure with inode information, copies it to user space, and
 * returns 0 on success or -1 on error.
 */
int sys_fstat(int fd, uint64 stat)
{
	struct proc *p = curr_proc(); // Get the currently running process
	struct file *f;               // Pointer to the file object for this file descriptor
	Stat st;                      // Temporary Stat structure to return to user space

	// Reject invalid file descriptor numbers.
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;

	// Look up the file object from the current process's file table.
	f = p->files[fd];
	if (f == 0)
		return -1;

	// fstat only works on inode-backed files in this project.
	if (f->type != FD_INODE || f->ip == 0)
		return -1;

	// Make sure the inode's metadata has been loaded from disk.
	ivalid(f->ip);

	// Clear the Stat structure before filling it.
	memset(&st, 0, sizeof(st));

	// Copy inode metadata into the Stat structure.
	st.dev = f->ip->dev;
	st.ino = f->ip->inum;
	st.nlink = f->ip->nlink;

	// Set the file mode based on whether this inode is a directory or a regular file.
	if (f->ip->type == T_DIR)
		st.mode = 0x040000;
	else
		st.mode = 0x100000;

	// Copy the completed Stat structure back to user space.
	if (copyout(p->pagetable, stat, (char *)&st, sizeof(st)) < 0)
		return -1;

	// Return success.
	return 0;
}

/**
 * Create a hard link so a new pathname points to the same inode as an old pathname.
 * creates another name pointing to the same inode and increments nlink
 * This copies in both path strings, finds the original inode, creates a new directory
 * entry for the new name, increments the inode's link count, and returns 0 on success.
 */
int sys_linkat(int olddirfd, uint64 oldpath, int newdirfd, uint64 newpath, uint64 flags)
{
	struct inode *ip, *dp;              // ip = original file inode, dp = directory inode
	struct proc *p = curr_proc();       // Current process making the syscall
	char oldname[MAXPATH], newname[MAXPATH]; // Buffers for old and new file names

	// These compatibility arguments are ignored 
	(void)olddirfd;
	(void)newdirfd;
	(void)flags;

	// Copy the old and new path strings from user space into kernel buffers.
	if (copyinstr(p->pagetable, oldname, oldpath, MAXPATH) < 0)
		return -1;
	if (copyinstr(p->pagetable, newname, newpath, MAXPATH) < 0)
		return -1;

	// Reject attempts to link a file using the same name.
	if (strncmp(oldname, newname, MAXPATH) == 0)
		return -1;

	// Find the inode for the original file.
	ip = namei(oldname);
	if (ip == 0)
		return -1;

	// Ensure the inode metadata is loaded from disk.
	ivalid(ip);

	// Get the root directory inode, since this project only uses a simple root directory.
	dp = root_dir();
	if (dp == 0) {
		iput(ip);
		return -1;
	}

	// Create a new directory entry that points to the same inode number.
	if (dirlink(dp, newname, ip->inum) < 0) {
		iput(dp);
		iput(ip);
		return -1;
	}

	// Increase the hard-link count because one more name now points to this inode.
	ip->nlink++;
	iupdate(ip);

	// Drop references to the directory inode and file inode.
	iput(dp);
	iput(ip);

	// Return success.
	return 0;
}

/**
 * Remove one pathname from a file.
 * This removes the directory entry for the given name, decreases the inode's
 * hard-link count, updates the inode on disk, and returns 0 on success.
 * The inode's data is only fully freed later when nlink reaches 0 and iput runs.
 */
int sys_unlinkat(int dirfd, uint64 name, uint64 flags)
{
	struct inode *ip, *dp;        // ip = file inode, dp = directory inode
	struct proc *p = curr_proc(); // Current process making the syscall
	char path[MAXPATH];           // Buffer for the pathname copied from user space

	// These compatibility arguments are ignored in this project.
	(void)dirfd;
	(void)flags;

	// Copy the pathname from user space into a kernel buffer.
	if (copyinstr(p->pagetable, path, name, MAXPATH) < 0)
		return -1;

	// Get the root directory inode.
	dp = root_dir();
	if (dp == 0)
		return -1;

	// Look up the inode referenced by this pathname.
	ip = dirlookup(dp, path, 0);
	if (ip == 0) {
		iput(dp);
		return -1;
	}

	// Ensure the inode metadata is loaded from disk.
	ivalid(ip);

	// Remove the directory entry for this pathname.
	if (dirunlink(dp, path) < 0) {
		iput(ip);
		iput(dp);
		return -1;
	}

	// Decrease the hard-link count because one name was removed.
	if (ip->nlink > 0)
		ip->nlink--;

	// Write the updated link count back to disk.
	iupdate(ip);

	// Drop references. If nlink is now 0, iput will later free the file.
	iput(dp);
	iput(ip);

	// Return success.
	return 0;
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
	case SYS_openat:
		ret = sys_openat(args[0], args[1], args[2]);
		break;
	case SYS_close:
		ret = sys_close(args[0]);
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
		ret = sys_exec(args[0], args[1]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_fstat:
	    ret = sys_fstat(args[0],args[1]);
		break;
	case SYS_linkat:
	    ret = sys_linkat(args[0],args[1],args[2],args[3],args[4]);
		break;
	case SYS_unlinkat:
	    ret = sys_unlinkat(args[0],args[1],args[2]);
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
