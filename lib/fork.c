// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	if(err == FEC_WR && !(uvpt[PGNUM(addr)] & PTE_COW))
	{
		panic("error not FEC_WR or page not COW addr: %x, error: %x\n", addr, err);
	}
	
	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	uintptr_t align_addr = (uintptr_t) ROUNDDOWN((uintptr_t) addr, PGSIZE);

	if ((r = sys_page_alloc(0, (void *) PFTEMP, PTE_P|PTE_U|PTE_W)) < 0)
		panic("sys_page_alloc: Error: %e, addr: %x", r, addr);
	//dst, src, len
	memmove((void*) PFTEMP, (void*) align_addr, PGSIZE);

	//Move it from PFTEMP to addr
	if ((r = sys_page_map(0, (void *)PFTEMP, 0, (void *)align_addr, PTE_P|PTE_U|PTE_W)) < 0)
		panic("sys_page_map: %e", r);

	if ((r = sys_page_unmap(0, (void *)PFTEMP)) < 0)
		panic("sys_page_unmap: %e", r);
	
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	/*
	* dupppage should map the page copy-on-write into the address space of the child and 
	* then remap the page copy-on-write in its own address space. 
	* duppage sets both PTEs so that the page is not writeable, 
	* and to contain PTE_COW in the "avail" field to distinguish 
	* copy-on-write pages from genuine read-only pages.
	*/
	uintptr_t addr = (uintptr_t) pn*PGSIZE;
	
	if (uvpt[pn] & PTE_SHARE){	
		int permissions = uvpt[pn] & PTE_SYSCALL;
		if((r = sys_page_map(0, (void *) addr, envid, (void *) addr, permissions)) < 0)
		{
			panic("Error %e when mapping pages to child environment: %x, addr: %x\n", r, envid, addr);
		}
		return 0;
	}

	if (!(uvpt[pn] & PTE_W)){	
		int permissions = PTE_U | PTE_P;
		if((r = sys_page_map(0, (void *) addr, envid, (void *) addr, permissions)) < 0)
		{
			panic("Error %e when mapping pages to child environment: %x, addr: %x\n", r, envid, addr);
		}
	}

	if(uvpt[pn] & (PTE_COW | PTE_W))
	{
		int permissions = PTE_COW | PTE_U | PTE_P;
	
		if((r = sys_page_map(0, (void *) addr, envid, (void *) addr, permissions)) < 0)
		{
			panic("Error %e when mapping pages to child environment: %x, addr: %x\n", r, envid, addr);
		}
	
		//Remap ourselves
		if((r = sys_page_map(0, (void *) addr, 0, (void *) addr, permissions)) < 0)
		{
			panic("Error %e when remapping pages\n", r);
		}		
	}
	return 0;
	
	
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
//
envid_t
fork(void)
{	
	//1. Set up page fault handler
	set_pgfault_handler(pgfault);

	//2. Create a child. Allocate a new child environment.
	envid_t envid;
	envid = sys_exofork();
	if (envid < 0)
		panic("sys_exofork: %e", envid);
	if (envid == 0) {
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid (it refers to the parent!).
		// Fix it and return 0.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	//We are the parent
	/* For each writable or copy-on-write page in its address
	* space below UTOP, the parent calls duppage, which should map 
	* the page copy-on-write into the address space of the child and 
	* then remap the page copy-on-write in its own address space.
	*
	* balvisio: We cannot just loop directly through all the pte entries
	* because they might not even exist in memory. We need to
	* iterate through the directory and if that entry is present
	* then we can start reading the pte entries.
	*/
	unsigned i = 0;
	for (i = 0; i < PDX(UTOP); i++) //Loop through PDir Entries	
	{
		if((uvpd[i] & PTE_P) && (uvpd[i] & PTE_U))
		{
			unsigned j = 0;
			for(j = 0; j < NPTENTRIES; j++)
			{
				if((uvpt[NPDENTRIES*i + j] & PTE_P) && (uvpt[NPDENTRIES*i + j] & PTE_U))
				{
					if((NPDENTRIES*i + j)*PGSIZE != UXSTACKTOP - PGSIZE)
					{
						duppage(envid, NPDENTRIES*i + j);					
					}			
				}
			}	
		}
	}


	/* 
	 * Neither user exception stack should ever be marked copy-on-write,
	 * so you must allocate a new page for the child's user exception stack.
 	 */
	int r;
	int perm = PTE_P | PTE_U | PTE_W;
	if ((r = sys_page_alloc(envid, (void *) (UXSTACKTOP - PGSIZE), perm)) < 0)
		panic("sys_page_alloc: %e for child exception stack\n", r);
	
	if((r = sys_page_map(envid, (void *) (UXSTACKTOP - PGSIZE), 0, (void *) PFTEMP, perm)) < 0)
		panic("sys_page_map: %e when copying excetion stack for envid: %x\n", r, envid);
	
	memmove((void *) PFTEMP, (void *) (UXSTACKTOP - PGSIZE), PGSIZE);

	if ((r = sys_page_unmap(0, (void *) PFTEMP)) < 0)
		panic("sys_page_unmap: %e when unmapping exception stack\n", r);


	//Set the pagefault upcall in the child
	if ((r = sys_env_set_pgfault_upcall(envid, thisenv->env_pgfault_upcall)) < 0)
		panic("sys_env_set_pgfault_upcall: %e for envid: %x\n", r, envid);

	//Mark the child as runnable and return
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e\n", r);

	return envid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
