---
layout: post
title: 32C3 CTF sandbox writeup
author: tukan
tags:
- 32c3
- ctf
- sandbox
---

[Sandbox][4] was an exploitation challenge for 300 points from 32C3, that executes our shellcode in something very similar to the old [seccomp-legacy sandbox][2] in Chromium. It was mostly me working on it, with some help from [@kt][1]. Even though we didn't manage to solve the challenge during the ctf, it was surprisingly enjoyable. There are two possible solutions, both will be covered.

[1]: https://twitter.com/koczkatamas
[2]: https://www.imperialviolet.org/2009/08/26/seccomp.html
[4]: https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/sandbox-300

# Rough sandbox arch

The basic idea is to set `PR_SET_NO_NEW_PRIVS` and `PR_SET_SECCOMP` via prctl to confine the sandboxed process.



> `PR_SET_NO_NEW_PRIVS`
> With no\_new\_privs set, execve promises not to grant the privilege to do anything that could not have been done without the execve call.  For example, the setuid and setgid bits will no longer change the uid or gid; file capabilities will not add to the permitted set

> `PR_SET_SECCOMP`
> With arg2 set to SECCOMP\_MODE\_STRICT, the only system calls that the thread is permitted to make are read(2), write(2), _exit(2), and sigreturn(2). Other system calls result in the delivery of a SIGKILL signal. Strict secure computing mode is useful for number-crunching applications that may need to execute untrusted byte code, perhaps obtained by reading from a pipe or socket. 


This limits the process to those 4 syscalls without the ability to gain new privs via execve. If it needs anything else, it must make a request to its parent process using some form of IPC (shared memory and pipes in this case). The parent verifies the syscall number and arguments, then does the syscall. The problem is, there are operations that the parent cannot do for its child, like allocating memory. To overcome this, there is a trusted thread alongside the sandboxed one, which isn't restricted by seccomp. The trusted thread runs in a hostile environment because the sandboxed thread has access to its address space. Therefore, the trusted thread only uses CPU registers and executes carefully handwritten assembly code.

The hierarchy is the following:

1. `parent process` unconfined, clones child-process (sandboxee) and enters a loop waiting for syscall requests
2. `child process` 
  * `sandboxee thread` created by parent, creates the `trusted` thread, sets seccomp mode and executes our shellcode 
  * `trusted thread` handwritten assembly routine executing the syscalls requests verified  by `parent`


## Communication

The parent process mmaps two 4096-byte regions, **mmap1** and **mmap2**, both shared with the children, which are used to pass syscall requests back and forth. 

1. `mmap1` is read-write in the children, `sandboxee` can request a syscall by placing the syscall number/arguments here and signaling `parent`. 

2. `mmap2` is read-only in the children, the parent process places the syscall information here after validation and signals `trusted` to execute the syscall.

The signaling happens via pipes, there are three, **p0**, **p1** and **p2**, used for the sandboxee->parent, parent->trusted and trusted->sandboxie directions, respectively. No actual data is sent through the pipes.

The syscall structure passed in mmap1 and mmap2 can be seen below.


```
00000000 syscall         struc ; (sizeof=0x38, mappedto_10)
00000000 rax_            dq ? 
00000008 rdi_            dq ?                    
00000010 rsi_            dq ?                    
00000018 rdx_            dq ?                    
00000020 rcx_            dq ?                    
00000028 r8_             dq ?                    
00000030 r9_             dq ?                    
```

## Parent

After initialization, `parent` enters a loop. It reads on the **p0** pipe, when read returns, makes a local copy of the syscall struct in mmap1 to prevent us from messing with it. It then checks the syscall number against a list of verifiers. Extracting the syscall numbers and matching it up with names via a simple python script gave the following [list of allowed syscalls][3]. If the requested syscall is not in the list or the verification function fails, `parent` kills the children and quits. If verification succeeds, `parent` copies the local syscall struct to mmap2. The verifier for most of these simply allows the call, only two, `open` and `chdir` have a common handler that checks whether the path to open/chdir contains **dev**, **proc** or **sys**. 

[3]: https://gist.github.com/andigena/c5b72639b4b225da971f


## Trusted

The code that `trusted` executes (seen below) is a simple loop of waiting for signaling on the **p1** pipe, filling up the registers from the syscall struct in mmap2, executing the syscall, storing the return value and signaling `sandboxee` via **p3**. The code seems robust, even considering our access to the address space in which it executes. It doesn't use anything of interest from writable locations, doesn't call library functions, only syscalls, and exits without returning on a failure.

{% highlight nasm %}
loc_4015BB:                             
                lea     r15, mmap2
                mov     r15, [r15]
                lea     r14, child2_syscall_retval
                lea     r13, p1_from_parent ; parent has the write end
                mov     r13, [r13+0]
                lea     r12, p2_write
                mov     r12, [r12]

loc_4015E6:                             ; CODE XREF: create_child_thread_loopit+F0
                mov     rax, 0
                mov     rdi, r13        ; from parent
                lea     rsi, child2_readbuf
                mov     rdx, 1
                syscall                 ; read
                dec     rax
                jnz     short loc_40165C
                mov     eax, [r15]
                add     r15, 8
                mov     rdi, [r15]
                add     r15, 8
                mov     rsi, [r15]
                add     r15, 8
                mov     rdx, [r15]
                add     r15, 8
                mov     r10, [r15]
                add     r15, 8
                mov     r8, [r15]
                add     r15, 8
                mov     r9, [r15]
                sub     r15, 30h
                syscall
                mov     [r14], rax
                mov     rax, 1
                mov     rdi, r12        ; p2_write
                lea     rsi, child2_readbuf
                mov     rdx, 1
                syscall                 ; write
                dec     rax
                jz      short loc_4015E6

loc_40165C:                             ; CODE XREF: create_child_thread_loopit+9A
                mov     rax, 0E7h
                mov     rdi, 1
                syscall                 ; exit_group
{% endhighlight %}

## Sandboxee

The thread executing our shellcode, restricted by `PR_SET_NO_NEW_PRIVS` and `SECCOMP_MODE_STRICT`. Before our code is executed, `sandboxee` requests an open syscall for the file ready.txt, reads its contents and writes them to stdout, presenting how the sandbox works and how to request syscalls from `parent`.

An obvious way to break out would be to modify the code of the `trusted` thread. This would however require changing page protection attributes and `parent` won't let mprotect syscalls through. However...



# Solution I: overflow in the open/chdir handler

The decompiled code of the handler can be seen below. The check for the path containing **proc** should hint at a possible direction to take: somehow bypass it and open **/proc/self/mem** for writing. This would allow us to modify the code of `trusted` from `sandboxee` and break out. 


{% highlight C %}
signed __int64 __fastcall handler_of_open_and_chdir_syscall_reqs(syscall *sc)
{
  syscall *v1; // rbx@1
  char *filename_ptr; // rax@1
  char *shared_mapping_end; // rdx@2
  char *v4; // rbp@3
  signed __int64 v5; // rdi@4
  char v6; // cl@6
  char lbuf[4104]; // [sp+0h] [bp-1028h]@3
  __int64 v9; // [sp+1008h] [bp-20h]@1

  v1 = sc;
  v9 = *MK_FP(__FS__, 40LL);
  filename_ptr = (char *)sc->rdi_;
  if ( filename_ptr < mmap1 )
    return 0LL;
  shared_mapping_end = mmap1 + 4096;
  if ( filename_ptr >= mmap1 + 4096 )
    return 0LL;
  v4 = lbuf;
  lbuf[0] = *filename_ptr;
  if ( lbuf[0] )
  {
    v5 = lbuf - filename_ptr;
    while ( shared_mapping_end != ++filename_ptr )
    {
      v6 = *filename_ptr;
      v4 = lbuf;
      filename_ptr[v5] = *filename_ptr;         // writes to lbuf
      if ( !v6 )
        goto LABEL_7;
    }
    return 0LL;
  }
LABEL_7:
  if ( strstr(v4, "dev") )
    return 0LL;
  if ( strstr(v4, "proc") || strstr(v4, "sys") )
    return 0LL;
  strcpy(mmap2 + 56, v4);
  v1->rdi_ = (__int64)(mmap2 + 56);
  return 1LL;
}
{% endhighlight %}


Looking at the code, there is a rather simple buffer overflow. The handler checks that rdi (the path arg of the syscall) points inside the mmap1 region but at the end of the function copies it to `mmap2+56` via strcpy. Both mmap1 and mmap2 are 4096 bytes big, so we could make the filename point to `mmap1+16` for example and have a long string starting there. Since mmap2 is mmapped right after mmap1, it will be placed right under it in memory, meaning we overflow back into mmap1. At first, this doesn't buy us much, considering that `parent` has already made a copy of the syscall struct from mmap1. What we get however is the ability to modify the end of the path, since mmap1 is writable by us and the path overflows into it. So by requesting a **chdir** into a long path consisting only of '/.'s, the checks will pass and we might be able to append /proc to the path before `trusted` executes the syscall. But we don't even need to win a race, since `trusted` and `sandboxee` share file descriptors and `parent` lets **pipe**, **dup** and **dup2** through without validation. This means we can take over the pipe on which `trusted` waits for the signal from `parent` to execute a syscall and trigger it at our leisure.

Once we have **/proc/self/mem** open for writing, we modify `trusted` to simply jump to our code and spawn a shell. Executing the final [exploit][5] (the live services were still up at the time of writing this):

[5]: /public/sandbox/sandbox_overflow.py

{% highlight bash %}
tukan@tukan-VirtualBox:/media/sf_shared/ctf/32c3_15/sandbox# python /media/sf_shared/exploits/32ccc15/sandbox_overflow.py 
[+] Opening connection to 136.243.194.42 on port 1024: Done
Please enter your shellcode, end with 8x NOP (\x90
[*] Switching to interactive mode

Thank you.
The sandbox is ready, have fun.
$ pwd
/proc
$ cd /home
$ ls
challenge
$ cd challenge
$ ls
challenge
challenge_
flag
read_flag
ready.txt
$ ./read_flag
Flag: 32C3_aihee0Laeleekah9De5eipah7ethepie

$ exit
{% endhighlight %}

# Solution II: a race condition

There is a tight race when `parent` starts copying a newly verified syscall struct over the previous one in mmap2. This was used by [ricky][6] in his [exploit][7]. The steps are the following:

1. Request an unverified syscall with the arguments that you want for open/chdir, e.g. getpid("/proc")
2. Request an open/chdir with bogus arguments, e.g. chdir("/")
3. Hope the scheduler will be nice to you and preempts `parent` at just the right time after it has written the syscall number of open/chdir into mmap2 (0x00401294 in the binary) but before it writes the new arguments so that `trusted` ends up executing chdir("/proc")
4. "It takes quite a lot of tries."

[6]: https://twitter.com/riczho
[7]: https://rzhou.org/~ricky/32c3/sandbox/