#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>

static struct Taskstate ts;

/* For debugging, print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}

void handler_T_DIVIDE();
void handler_T_DEBUG();
void handler_T_NMI();
void handler_T_BRKPT();
void handler_T_OFLOW();
void handler_T_BOUND();
void handler_T_ILLOP();
void handler_T_DEVICE();
void handler_T_DBLFLT();
void handler_T_TSS();
void handler_T_SEGNP();
void handler_T_STACK();
void handler_T_GPFLT();
void handler_T_PGFLT();	
void handler_T_FPERR();
void handler_T_ALIGN();
void handler_T_MCHK();
void handler_T_SIMDERR();
void handler_T_SYSCALL();

void handler_IRQ_TIMER();
void handler_IRQ_KBD();
void handler_IRQ_SERIAL();
void handler_IRQ_SPURIOUS();
void handler_IRQ_IDE();
void handler_IRQ_ERROR();


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	
	/*balvisio: Set gate is defined in mmu.h
	* global descriptor table is an array
	* of segment descriptors (struct Segdesc)defined in mmu.h
	*/
	

	//1. We need to build (or fill in) the gates for the idt
	// The idt defined above is an array of GateDescriptors
	// so in SETGATE: gate should be an index of the idt.
	SETGATE(idt[T_DIVIDE], 0x0, GD_KT, &handler_T_DIVIDE, 0x0)
	SETGATE(idt[T_DEBUG] , 0x0, GD_KT, &handler_T_DEBUG, 0x0)
	SETGATE(idt[T_NMI], 0x0, GD_KT, &handler_T_NMI, 0x0)
	
	//balvisio: Since the BRKPT interrupt can be called from
	// user space we should set Privilege Level to 3. For
	// example panic calls int3 (bkpt)
	SETGATE(idt[T_BRKPT], 0x0, GD_KT, &handler_T_BRKPT, 0x3)
	SETGATE(idt[T_OFLOW], 0x0, GD_KT, &handler_T_OFLOW, 0x0)
	SETGATE(idt[T_BOUND], 0x0, GD_KT, &handler_T_BOUND, 0x0)
	
	SETGATE(idt[T_ILLOP], 0x0, GD_KT, &handler_T_ILLOP, 0x0)
	SETGATE(idt[T_DEVICE], 0x0, GD_KT, &handler_T_DEVICE, 0x0)
	SETGATE(idt[T_DBLFLT], 0x0, GD_KT, &handler_T_DBLFLT, 0x0)
	SETGATE(idt[T_TSS], 0x0, GD_KT, &handler_T_TSS, 0x0)
	SETGATE(idt[T_SEGNP], 0x0, GD_KT, &handler_T_SEGNP, 0x0)
	SETGATE(idt[T_STACK], 0x0, GD_KT, &handler_T_STACK, 0x0)

	SETGATE(idt[T_GPFLT], 0x0, GD_KT, &handler_T_GPFLT, 0x0)
	SETGATE(idt[T_PGFLT], 0x0, GD_KT, &handler_T_PGFLT, 0x0)
	SETGATE(idt[T_FPERR], 0x0, GD_KT, &handler_T_FPERR, 0x0)
	SETGATE(idt[T_ALIGN], 0x0, GD_KT, &handler_T_ALIGN, 0x0)
	SETGATE(idt[T_MCHK], 0x0, GD_KT, &handler_T_MCHK, 0x0)
	SETGATE(idt[T_SIMDERR], 0x0, GD_KT, &handler_T_SIMDERR, 0x0)

	//balvisio:add system call interrupt
	SETGATE(idt[T_SYSCALL], 0x0, GD_KT, &handler_T_SYSCALL, 0x3)

	/*
	 * Added balvisio
	 *
	 * Second argument is 0x0 to make sure we 
	 * reset the IF flag when we are in the kernel.
	 * Do we want to change IF flag is trap ocurred?
	 */
	SETGATE(idt[IRQ_OFFSET + IRQ_TIMER], 0x0, GD_KT, &handler_IRQ_TIMER, 0x0)
	SETGATE(idt[IRQ_OFFSET + IRQ_KBD], 0x0, GD_KT, &handler_IRQ_KBD, 0x0)
	SETGATE(idt[IRQ_OFFSET + IRQ_SERIAL], 0x0, GD_KT, &handler_IRQ_SERIAL, 0x0)
	SETGATE(idt[IRQ_OFFSET + IRQ_SPURIOUS], 0x0, GD_KT, &handler_IRQ_SPURIOUS, 0x0)
	SETGATE(idt[IRQ_OFFSET + IRQ_IDE], 0x0, GD_KT, &handler_IRQ_IDE, 0x0)
	SETGATE(idt[IRQ_OFFSET + IRQ_ERROR], 0x0, GD_KT, &handler_IRQ_ERROR, 0x0)
	
	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	
	/* balvisio:
	* ts is a taskState and is defined in mmu.h
	* Now instead of using the ts structure we will
	* use the ts structure that inside the struct
	* CpuInfo defined in cpu.h
	*/



	uintptr_t cpu_kernel_stack = KSTACKTOP - cpunum() * (KSTKSIZE + KSTKGAP);
	thiscpu->cpu_ts.ts_esp0 = cpu_kernel_stack;
	thiscpu->cpu_ts.ts_ss0 = GD_KD;

	// Initialize the TSS slot of the gdt. 
	/* balvisio: SEG16 generate a TSS Descriptor (Segdesc struct). (mmu.h)
	* and we are passing the address in memory of where 
	* the TSS itself resides
	*/
	
	gdt[(GD_TSS0 >> 3) + cpunum()] = SEG16(STS_T32A, (uint32_t) (&(thiscpu->cpu_ts)),
					sizeof(struct Taskstate), 0);
	gdt[(GD_TSS0 >> 3) + cpunum()].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	
	/* balvisio: ltr (Load Task Register) 
	* LTR loads the special x86 task register with a segment
	* selector that points to a task state segment. After executing
	* the LTR instruction, the TSS pointed to by the argument 
	* is marked busy, but no hardware task switch occurs.
	*/

	ltr(((GD_TSS0 >> 3) + cpunum()) << 3);
	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	//balvisio
	switch(tf->tf_trapno)
	{
		case T_BRKPT:
		{
			monitor(tf);
			return;
		}
		case T_PGFLT:
		{
			page_fault_handler(tf);
			return;
		}	
		case T_SYSCALL:
		{
			int32_t r = syscall(tf->tf_regs.reg_eax, tf->tf_regs.reg_edx, tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx, tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
			//Return the value in %eax
			tf->tf_regs.reg_eax = r;
			return;
		}
		
		// Handle spurious interrupts
		// The hardware sometimes raises these because of noise on the
		// IRQ line or other reasons. We don't care.
		case (IRQ_OFFSET + IRQ_SPURIOUS):
		{
			cprintf("Spurious interrupt on irq 7\n");
			print_trapframe(tf);
			return;
		}
		// Handle clock interrupts. Don't forget to acknowledge the
		// interrupt using lapic_eoi() before calling the scheduler!
		/*
		* Added balvisio
		*/
		case(IRQ_OFFSET + IRQ_TIMER):
		{
			lapic_eoi();
			sched_yield();
			return;
		}

		// Handle keyboard and serial interrupts.
		case (IRQ_OFFSET + IRQ_KBD):
		{
			kbd_intr();
			return;
		}

		case (IRQ_OFFSET + IRQ_SERIAL):
		{
			kbd_intr();
			return;
		}
	}

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		assert(curenv);

		lock_kernel();
	
		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();
	
	// Handle kernel-mode page faults.

	/*balvisio: Check that the page fault
	* doesn't happen in kernel mode
	*/
	if(!(tf->tf_cs & 3)) //Lower two bits of cs are 0 if we are in kernel mode.
	{
		print_trapframe(tf);
		panic("kernel pagefault at addr %x\n", fault_va);
		return;
	}
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	
	//1. Check that there's page fault upcall
	if(curenv->env_pgfault_upcall == 0x0)
	{
		// Destroy the environment that caused the fault.
		cprintf("[%08x] user fault va %08x ip %08x\n",
			curenv->env_id, fault_va, tf->tf_eip);
		print_trapframe(tf);
		env_destroy(curenv);
	}

	
	uintptr_t base;

	/*2. Check if we are already running in the EXCEPTION Stack */
	if (tf->tf_esp <= UXSTACKTOP - 1 && tf->tf_esp >= UXSTACKTOP - PGSIZE)
	{
		base = tf->tf_esp - 4;
	}else{ //non Recursive case
		base = UXSTACKTOP; //We set the Stack Pointer 
	}
	

	/*
	* 3. Checks that environment 'env' is allowed to access the range 
	* of memory for the USER EXCEPTION STACK
	* UXSTACKTOP = 0x eec0 0000
	*/
	user_mem_assert(curenv, (void *)(base - sizeof(struct UTrapframe)), sizeof(struct UTrapframe), PTE_W | PTE_U | PTE_P);

	/*
	* 4. Create the struct UTrapFrame for the handler. (defined in /inc/trap.h)
	*/
	struct UTrapframe *utf = (struct UTrapframe *) (base - sizeof(struct UTrapframe));
	utf->utf_fault_va = fault_va;
	utf->utf_err = tf->tf_err;
	utf->utf_regs = tf->tf_regs;
	utf->utf_eip = tf->tf_eip;
	utf->utf_eflags = tf->tf_eflags;
	utf->utf_esp = tf->tf_esp;


	curenv->env_tf.tf_esp = (uintptr_t) utf;	
	/*
	* 5. Change env instruction pointer and run upcall
	*/
	
	curenv->env_tf.tf_eip = (uintptr_t) curenv->env_pgfault_upcall;	
	
	env_run(curenv);
}

