// User-level IPC library routines

#include <inc/lib.h>

// Receive a value via IPC and return it.
// If 'pg' is nonnull, then any page sent by the sender will be mapped at
//	that address.
// If 'from_env_store' is nonnull, then store the IPC sender's envid in
//	*from_env_store.
// If 'perm_store' is nonnull, then store the IPC sender's page permission
//	in *perm_store (this is nonzero iff a page was successfully
//	transferred to 'pg').
// If the system call fails, then store 0 in *fromenv and *perm (if
//	they're nonnull) and return the error.
// Otherwise, return the value sent by the sender
//

int32_t
ipc_recv(envid_t *from_env_store, void *pg, int *perm_store)
{
	int r;
	if(!pg)
	{
		r = sys_ipc_recv((void *) UTOP);
	}else{
		r = sys_ipc_recv(pg);
	}
	
	if(r < 0)
	{
		*from_env_store = 0x0;
		*perm_store = 0x0;
		return r;
	}

	if(from_env_store)
	{
		*from_env_store = thisenv->env_ipc_from;
	}

	if(perm_store)
	{
		*perm_store = thisenv->env_ipc_perm;
	}

	return thisenv->env_ipc_value;
}

// Send 'val' (and 'pg' with 'perm', if 'pg' is nonnull) to 'toenv'.
// This function keeps trying until it succeeds.
// It should panic() on any error other than -E_IPC_NOT_RECV.
//
void
ipc_send(envid_t to_env, uint32_t val, void *pg, int perm)
{
	while(1)
	{
		int r;
		if(!pg){
			r = sys_ipc_try_send(to_env, val, (void *) UTOP, perm);
		}else
		{
			r = sys_ipc_try_send(to_env, val, pg, perm);
		}
		
		if(r == 0)
		{
			return;
		}else{
			if(r != -E_IPC_NOT_RECV)
			{
				panic("Error: %e in ipc_send. Params: envid: %x, val: %x, pgaddr: %x, perm: %x\n", r, to_env, val, pg, perm);
			}
		}
		sys_yield();
	}
}

// Find the first environment of the given type.  We'll use this to
// find special environments.
// Returns 0 if no such environment exists.
envid_t
ipc_find_env(enum EnvType type)
{
	int i;
	for (i = 0; i < NENV; i++)
		if (envs[i].env_type == type)
			return envs[i].env_id;
	return 0;
}
