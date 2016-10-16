---
layout: post
title: scraps of notes on ptmalloc metadata corruptions
author: tukan
tags:
- ptmalloc
- memory corruption
- exploitation
- heap
- glibc
---

Welcome to the third episode of the [ptmalloc fanzine]({% post_url 2016-07-26-ptmalloc-fanzine %}). This will be a shorter one, a collection of notes concerning the exploitation of heap corruptions in a ptmalloc/Linux environment that don't warrant their own episode. 


# TLDR

We touch on the following subjects:

* **forcing calloc to return unitialized memory**. By setting the `IS_MMAPPED` bit of a free chunk, `calloc` may return unitialized memory.
* **Reverse House of Mind**, mixing chunks of other arenas into the bins of the main arena.
* **an overview of some of the heap-related challenges from the HITCON 2016 qualifier**.
* **conjuring addresses for leaks**. Free chunks may have pointers to the heap and libc and we also look at the other possible directions between some interesting memory areas (binary, heap, libc, stack) for leaks.
* **corruption targets in libc**. We have leaked the address of libc, now what?
* **surviving free on controlled data**.

As usual, glibc source links and platform-dependent information all pertain to Ubuntu 16.04 on x86-64, unless stated otherwise.


# Forcing calloc to return unitialized memory

There's a special case in calloc for when `_int_malloc` [returns an mmapped chunk][41]. Those are assumed to be zeroed, so memsetting them isn't needed. `_int_malloc` ignores the `IS_MMAPPED` bit, so setting it for a chunk already in the freelist by corruption, then requesting a calloc of that size won't cause problems, and calloc will skip the memset, returning uninitialized data. This might be useful to leak addresses or other sensitive information and to ease the exploitation of some use-after-free bugs.
The victim chunk can be in the fastbins, smallbins or the unsorted bin but the rounded request-size has to be an exact match for the size of the victim chunk. Otherwise, the malloc code will set the size of the returned chunk explicitly, clearing the `IS_MMAPPED` bit as a side-effect. Running the [uninitialized_calloc.c][42] example shows this in action:

[41]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3261
[42]: https://github.com/andigena/ptmalloc-fanzine/blob/master/03-scraps/uninitialized_calloc.c

{% highlight ocaml %}
tukan@farm:/ptmalloc-fanzine/03-scraps$ ./uninitialized_calloc
allocated victim chunk with requested size 0x100, victim->size == 0x111
allocated another chunk to prevent victim from being coalesced into top
freeing victim chunk
emulating corruption of the IS_MMAPPED bit of victim->size
making a calloc request for an exact size match
the first 2 qwords of the returned region:
0x7ffff7dd1c78 0x7ffff7dd1c78
tukan@farm:/ptmalloc-fanzine/03-scraps$ 
{% endhighlight %}


# Reverse House of Mind

The House of Mind starts by growing the brk heap above a heap size boundary so that setting the `NON_MAIN_ARENA` bit of a chunk will result in free looking for the corresponding arena in attacker-controlled data. The `NON_MAIN_ARENA` bit can be of interest the other way around, by clearing it for a chunk in an mmapped heap before freeing it. Free will enter it into the freelists of the main arena, making it possible to have mallocs from the main arena return chunks in other arenas. This may be useful in situations where e.g. there are worker threads with vulnerable buffers but no worthwhile targets on their heaps and a main thread which allocates/deallocates interesting objects.
The [reverse_mind.c][52] example shows this:

{% highlight ocaml %}
tukan@farm:/ptmalloc-fanzine/03-scraps$ ./reverse_mind
brk heap is around: 0x55e1915bd010
allocated victim chunk in thread arena with requested size 0x40, victim->size == 0x55
emulating corruption of the NON_MAIN_ARENA bit of victim->size
freeing victim chunk, entering it into a fastbin of the main arena
making a malloc request in the main thread
the address of the chunk returned in the main thread: 0x7fab500008c0
{% endhighlight %}

However, this will only work for fastbin-sized chunks. Others will fail the next chunk arena [boundary checks][51], since mmapped heaps are way up higher in the address space than the brk heap. While this may be circumvented by spraying the address space with large mappings so that an mmapped heap ends up below the brk heap, it doesn't really seem to worth the trouble.


[51]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3982
[52]: https://github.com/andigena/ptmalloc-fanzine/blob/master/03-scraps/reverse_mind.c


# HITCON 2016 qualifier

This year's HITCON qual had some really nice heap exploitation challenges, here's a very short synopsis of the tricks required for some of them:

* [Secret Holder][21]: allocating and freeing a chunk of 400000 will set the dynamic mmap threshold to 400000, meaning the next time we request a malloc for that size, it will be allocated on the brk heap. Writeup by meh, the challenge creator [here][23].
* [Sleepy Holder][22]: forcing a chunk in a fastbin into the corresponding smallbin via `malloc_consolidate` to allow for a double free of said chunk without failing the fastbin double free check and for its effect of unsetting `PREV_INUSE` of the next chunk, leading to unlink abuse. [Writeup][24] by meh.
* [Babyheap][25]: scanf ("hidden" out of sight in the exit menu option) allocates a file buffer on the heap with malloc(0x1000), the contents of which we can control. Also, its size is rounded to 0x1010 by malloc and this displaces the other allocations just right. I'm not familiar with libio in libc and didn't really look into this to find out which other functions do this.
* [House of Orange][26]: there are no free calls in the binary but sysmalloc may call `_int_free` upon top expansion. Control flow is hijacked via the `_IO_list_all` global `_IO_FILE` ptr. Writeup by angelboy [here][27].

[21]: https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/secret-holder-100
[22]: https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/sleepy-holder-300
[23]: https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SecretHolder
[24]: https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder
[25]: https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/baby-heap-300
[26]: https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500
[27]: http://4ngelboy.blogspot.hu/2016/10/hitcon-ctf-qual-2016-house-of-orange.html


# Conjuring addresses for leaks

Free chunks may contain different addresses in their `bk` and `fd` members, depending on their size and position in the freelist, which make them appealing targets for leaks:

* **fastbin**: since fastbins are singly-linked, the `fd` pointer may contain a heap address, or NULL in case of the last chunk in the list.
* **unsorted and smallbin**: doubly linked freelists, the first and last chunks in the bins contain pointers into the `malloc_state` struct (the arena). In case of the main arena, this is a global in the malloc code, so the **address of libc base can be calculated** from it. While the `malloc_state` structure of other arenas reside on mmapped regions, if we can read from arbitrary addresses, the circular linked list of arenas (`malloc_state->next`) can be traversed to eventually find the main arena. It will likely have the highest address (and lowest `top` pointer). It may also be possible to calculate the address of libc directly from the address on an mmapped arena due to the rather predictable way mappings are placed but this would require recreating the target environment very precisely.
* **largebin**: similar to the unsorted and smallbin case but free chunks also include the `fd_nextsize` and `bk_nextsize` members for the largebin skiplist. These are used to skip over same-sized chunks in the ordered largebins to allow faster traversal and will only contain heap pointers.

Some other directions:

* libc has pointers to:
    * the **stack**: `environ`, `program_invocation_short_name`, `program_invocation_name`
	* the **heap**: `main_arena->top`
* the stack has plenty of pointers, e.g. to:
    * the **binary and libc** at the top of the call stack. `__libc_start_main` calls main, which likely calls other functions, so return addresses into both will be on the stack.
    * the **binary** (`AT_ENTRY`), the **dynamic loader** (`AT_BASE`), the **stack** (`AT_RANDOM`), the **vdso** (`AT_SYSINFO_EHDR`) in the auxiliary vector.
    * the **stack** itself via the frame pointers, `__libc_start_main` also has a parameter for the argv array.
    * the **heap**, likely, via	function arguments
* the binary:
    * to **libc** via the .GOT and the standard file handles in .bss 

	
# Corruption targets in libc

Libc has a lot of interesting targets for corruption: 

* the **[libio file vtables][1]**, which have seen [multiple][2] [proposals][3] for hardening and the second one by Florian Weimer actually [landed][4] in June. Since Ubuntu 16.04 is on glibc 2.23, these vtables might be good targets for a while. It's important to note that this requires some indirection to take over control flow: we corrupt a file handle pointer, set up a fake file object somewhere, set it's vtable pointer and place a fake vtable somewhere. See [here][6] for more thorough description and the [House of Orange][27] HITCON challenge.
* **malloc hooks**. The malloc code supports [hooks][5] for most of its public functions, including malloc, free and realloc, which are simple globals in libc. They're called on every invocation of the corresponding function if they're non-null. Calculating their address from a libc leak and a known libc binary is trivial and they're not mangled, so they are ideal targets for corruption.
* the `__morecore` [variable][7], which is a function pointer in the malloc code, pointing to `__default_morecore` by default that's basically  a wrapper around `sbrk`. __morecore is called by `sysmalloc` (and `systrim`) when the main heap needs to be extended, i.e. when top is insufficient to serve a request.
* the [`atfork_mem`][9] [fork handler][8] looks interesting, though it seems to have been removed from glibc since the release of 2.23. I didn't look into this further.

[1]: https://sourceware.org/glibc/wiki/LibioVtables
[2]: https://sourceware.org/ml/libc-alpha/2016-05/msg00602.html
[3]: https://sourceware.org/ml/libc-alpha/2016-05/msg00740.html
[4]: https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51
[5]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L1835
[6]: https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/
[7]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L412
[8]: https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/nptl/fork.h;h=76762d4b1ed75e7d1a5a9689f03241cd2ca39ae9;hb=cc6a8d74575e36e2c9da8454dd1d23000c5455dd#l31
[9]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/arena.c#L403


# Surviving free on controlled data

There are cases when you already did all the necessary corruptions but there are still a couple of free calls, possibly on corrupted chunks, before control flow is hijacked. Setting up a region on which free will operate without crashing isn't a really difficult task:

* creating a **fake mmapped chunk**. As we discussed in the [first episode]({% post_url 2016-07-27-munmap-madness %}), `_int_free` is completely bypassed for chunks with the `IS_MMAPPED` bit set. As a reminder, here is how the address to munmap is calculated: 

{% highlight C %}
uintptr_t block = (uintptr_t) p - p->prev_size;
size_t total_size = p->prev_size + size;

if (__builtin_expect (((block | total_size) & (GLRO (dl_pagesize) - 1)) != 0, 0))
  {
    malloc_printerr (check_action, "munmap_chunk(): invalid pointer", chunk2mem (p), NULL);
    return;
  }
{% endhighlight %}

The only thing needed is the offset of our chunk into its page, then it's possible to use the `prev_size` field to point `block` outside the mapped ranges and ensure page-alignment and the `size` field to make the `total_size` value small. Since there's no check on the return value of `munmap`, we're good to go. 

* passing the region off as a fastbin-sized chunk. This has the same requirements as the fake chunk in the House of Spirit:
    * the chunksize has to be between `MINSIZE` (32) and `global_max_fast` (128), while also being 16-byte aligned. The `PREV_INUSE` bit doesn't matter, while the other two should be unset.
    * the size of the next chunk has to be bigger than 16 and smaller than `av->system_mem` (at least 128KB).


# Closing words

That's about it, hope you found this educational. As usual, comments of any nature are welcome, hit me up on freenode or twitter.

Special thanks to [gym][56] again for the rigorous proofreading.


[56]: https://twitter.com/gymiru