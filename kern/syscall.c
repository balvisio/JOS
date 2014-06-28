/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

	user_mem_assert(curenv, s, len, PTE_U | PTE_P);

	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.

	

	/*
	* How is it that child returns 0 but parent returns child's id?
	* This function is never executed by the child process
	* It is only executed by the parent. In this function PARENT alloc
	* a new environment (CHILD) and copy the register set of the TRAP FRAME 
	* of the PARENT (not the CURRENT REGISTERS or EIP of the PARENT)
	* Thus the register set of the new child process gets loaded with
	* eip = 0x8001a8 that is the instruction right after the interrupt
	* instruction (when the trap happened) that the parent executed to get here. (0x8001a8) is on 	
	* the sys_exofork (on the lib side, define as inlined in lib.h).
	* We are modifying %eax and the FIRST INSTRUCTION that the child
	* executes is the instruction close to return from (lib side) exo_fork 	
	* (defined in lib.h). In other words, the very first function that
	* child executes is sys_exofork in lib.h (not all of it, only 		
	* after it returns from kernel) and since %eax is set to zero, it
	*  sys_exofork (lib side) will return 0.
	*/	
	struct Env *newenv_store;
	int error = env_alloc(&newenv_store, curenv->env_id);
	if(error)
	{
		return error;
	}

	//We set the env to NON_RUNNABLE
	newenv_store->env_status = ENV_NOT_RUNNABLE;
	
	//Copy register set 	
	memcpy((void*) (&(newenv_store->env_tf)),(const void*) (&(curenv->env_tf)), sizeof(struct Trapframe));		

	//We tweak %eax
	newenv_store->env_tf.tf_regs.reg_eax = 0x0;

	return newenv_store->env_id;
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int
sys_env_set_status(envid_t envid, int status)
{
	
	if(status != ENV_RUNNABLE && status != ENV_NOT_RUNNABLE)
	{
		return -E_INVAL;
	}	

	struct Env* new_env;
	if(envid2env(envid, &new_env, 0x1))
	{
		return -E_BAD_ENV;
	}

	new_env->env_status = status;

	return 0;
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3) with interrupts enabled.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	
	// Remember to check whether the user has supplied us with a good
	// address!
	struct Env* new_env;
	int r;

	if((r = envid2env(envid, &new_env, 0x1)) < 0)
	{
		return r;
	}

	new_env->env_tf = *tf;
	
	return 0;
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	struct Env* env;

	//'envid2env' function from kern/env.c
	int error = envid2env(envid, &env, true);
	if(error)
	{
		return error;
	}
	
	//Set page fault upcall
	env->env_pgfault_upcall = func;

	return 0;
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{

	struct Env *env_store;
	int error = envid2env(envid, &env_store, true);
	if(error)
	{
		return error;
	}
	
	// -E_INVAL if va >= UTOP, or va is not page-aligned.
	if((uintptr_t) va != ROUNDUP(((uintptr_t)va), PGSIZE) || ((uintptr_t)va) >= UTOP)
	{
		return -E_INVAL;
	}
	
	// -E_INVAL if perm is inappropriate (see above).
	if((perm & (PTE_U | PTE_P)) == 0 || (perm & (~PTE_SYSCALL)) != 0x0)
	{
		return -E_INVAL;
	}
	
	// Allocate a page of memory
	struct PageInfo *phys_page = page_alloc(ALLOC_ZERO);
	if(!phys_page)
	{
		return -E_NO_MEM;
	}

	//page_insert(pde_t *pgdir, struct PageInfo *pp, void *va, int perm)
	error = page_insert(env_store->env_pgdir, phys_page, va, perm);
	if(error)
	{
		page_free(phys_page);
		return error;
	}
	return 0;
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	//This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.

	//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
	//	or the caller doesn't have permission to change one of them.
	struct Env *env_src;
	int error = envid2env(srcenvid, &env_src, true);
	if(error)
	{
		return error;
	}

	struct Env *env_dst;
	error = envid2env(dstenvid, &env_dst, true);
	if(error)
	{
		return error;
	}

	//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
	//	or dstva >= UTOP or dstva is not page-aligned.
	if((uintptr_t) srcva != ROUNDUP(((uintptr_t)srcva), PGSIZE) 
	|| ((uintptr_t)srcva) >= UTOP
	|| (uintptr_t) dstva != ROUNDUP(((uintptr_t)dstva), PGSIZE) 
	|| ((uintptr_t)dstva) >= UTOP)
	{
		return -E_INVAL;
	}

	// -E_INVAL if perm is inappropriate (see sys_page_alloc).
	if((perm & (~PTE_SYSCALL)) != 0x0)
	{
		return -E_INVAL;
	}

	//-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
	// address space.
	//struct PageInfo * page_lookup(pde_t *pgdir, void *va, pte_t **pte_store)
	pte_t *src_pt_entry;
	struct PageInfo *phys_page = page_lookup(env_src->env_pgdir, srcva, &src_pt_entry);
	
	// -E_INVAL is srcva is not mapped in srcenvid's address space.
	if(!phys_page)
	{
		return -E_INVAL;
	}

	if(!src_pt_entry || ((perm & PTE_W) && !(*src_pt_entry & PTE_W)))
	{
		return -E_INVAL;
	}
	
	//-E_NO_MEM if there's no memory to allocate any necessary page tables.
	//page_insert(pde_t *pgdir, struct PageInfo *pp, void *va, int perm)
	error = page_insert(env_dst->env_pgdir, phys_page, dstva, perm);

	if(error)
	{
		return error;
	}

	return 0;
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// This function is a wrapper around page_remove().
	struct Env *env;
	int error = envid2env(envid, &env, true);
	if(error)
	{
		return error;
	}

	if((uintptr_t) va != ROUNDUP(((uintptr_t)va), PGSIZE) 
	|| ((uintptr_t)va) >= UTOP)
	{
		return -E_INVAL;
	}

	page_remove(env->env_pgdir, va);
	return 0;

}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{

	struct Env *dst_env;
	int r;
	if((r = envid2env(envid, &dst_env, false)) < 0){
		return r;
	}

	if(dst_env->env_ipc_recving == false){
		return -E_IPC_NOT_RECV;
	}

	if((uintptr_t) srcva < UTOP)
	{
		if(srcva != ROUNDDOWN(srcva, PGSIZE))
		{
			return -E_INVAL;
		}
		
		// -E_INVAL if perm is inappropriate (see page alloc).
		if(((perm & (PTE_U | PTE_P)) == 0 || (perm & (~PTE_SYSCALL)) != 0x0))
		{
			return -E_INVAL;
		}

		//-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
		//address space.
		pte_t *src_pte; 
		struct PageInfo *pp = page_lookup(curenv->env_pgdir, srcva, &src_pte);
		if(!pp)
		{
			return -E_INVAL;
		}

		//-E_INVAL if (perm & PTE_W), but srcva is read-only in the
		//current environment's address space.
		if((perm & PTE_W) && !(*src_pte & PTE_W))
		{
			return -E_INVAL;
		}	

		//-E_NO_MEM if there's not enough memory to map srcva in envid's
		//address space.
	
		if((uintptr_t) dst_env->env_ipc_dstva < UTOP)
		{
			if((r = page_insert(dst_env->env_pgdir, pp, dst_env->env_ipc_dstva, perm)) < 0)
			{
				return r;
			}
		}else
		{
			perm = 0x0;
		}
	}else{
		perm = 0x0;
	}	
	//Send succeeds
	//env_ipc_recving is set to 0 to block future sends;
	dst_env->env_ipc_recving = false;
	//env_ipc_from is set to the sending envid;
	dst_env->env_ipc_from = curenv->env_id;
	//env_ipc_value is set to the 'value' parameter;
	dst_env->env_ipc_value = value;
	//env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
	dst_env->env_ipc_perm = perm;
	// The target environment is marked runnable again, 
	dst_env->env_status = ENV_RUNNABLE;
	
	dst_env->env_tf.tf_regs.reg_eax = 0x0;

	return 0;
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	curenv->env_ipc_dstva = (void *) UTOP;
	
	if((uintptr_t) dstva < UTOP && dstva != ROUNDDOWN(dstva, PGSIZE))
	{
		return -E_INVAL;
	}

	if((uintptr_t) dstva < UTOP)
	{
		curenv->env_ipc_dstva = dstva;
	}

	curenv->env_ipc_recving = true;
	curenv->env_status = ENV_NOT_RUNNABLE;
	sched_yield();

	return 0;

}

// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.

	switch (syscallno) {
		case SYS_cputs:
		{
			sys_cputs((const char *) a1, (size_t) a2);
			return 0;
		}
		case SYS_cgetc:
		{
			return sys_cgetc();
		}
		case SYS_getenvid:
		{
			return sys_getenvid(); 
		}		
		case SYS_env_destroy:
		{
			return sys_env_destroy(a1);
		}
		case SYS_yield:
		{
			sys_yield();
			return 0;
		}
		case SYS_page_alloc:
		{
			return sys_page_alloc((envid_t) a1, (void *) a2, (int) a3);
		}
		case SYS_page_map:
		{
			return sys_page_map((envid_t) a1, (void *)a2, (envid_t) a3, (void *)a4, (int) a5);
		}
		case SYS_page_unmap:
		{
			return sys_page_unmap((envid_t) a1, (void *)a2);
		}
		case SYS_exofork:
		{
			return sys_exofork();
		}
		case SYS_env_set_status:
		{
			return sys_env_set_status((envid_t) a1, (int) a2);
		}
		case SYS_env_set_trapframe:
		{
			return sys_env_set_trapframe((envid_t) a1, (struct Trapframe *) a2);
		}
		case SYS_env_set_pgfault_upcall:
		{
			return sys_env_set_pgfault_upcall((envid_t) a1, (void *) a2);
		}
		case SYS_ipc_try_send:
		{
			return sys_ipc_try_send((envid_t) a1, (uint32_t) a2, (void *) a3, (unsigned) a4);
		}
		case SYS_ipc_recv:
		{
			return sys_ipc_recv((void *) a1);
		}
		default:
			return -E_NO_SYS;
	}
}

