---
layout: post
title: once upon a realloc()
author: tukan
tags:
- ptmalloc
- memory corruption
- exploitation
- heap
- glibc
---

Welcome to the fourth episode of the [ptmalloc fanzine]({% post_url 2016-07-26-ptmalloc-fanzine %}), in which we explore the possibilities arising from corrupting a chunk that is subsequently passed into realloc.

# TLDR

We touch on the following subjects:

* **creating overlapping chunks with realloc** 
    * by **corrupting the IS_MMAPPED bit** of the old chunk and setting up its `size` and `prev_size` fields appropriately, it's possible to force realloc to return the old chunk regardless of the requested new size, thus **arranging for overlapping chunks**.
    * by growing the old chunk via corruption to **encompass other chunks**. Upon realloc, the old chunk will be **extended into those chunks**.
* **a wild memcpy appears.** An unsigned underflow can be triggered when calculating the size argument of the memcpy call which copies over the contents of the old chunk to the new location.
* **abusing mremap**. A theoretical overview of the implications of triggering mremap calls with near-arbitrary parameters as a result of a realloc call on a corrupted chunk.

As usual, glibc source links and platform-dependent information all pertain to Ubuntu 16.04 on x86-64, unless stated otherwise.


# Overlapping chunks via the IS\_MMAPPED path of __libc_realloc

Let's take a look at the parts of `__libc_realloc` [concerning mmapped chunks][11]:

{% highlight C %}
  const mchunkptr oldp = mem2chunk (oldmem);
  const INTERNAL_SIZE_T oldsize = chunksize (oldp);

...

  if (__builtin_expect ((uintptr_t) oldp > (uintptr_t) -oldsize, 0) || __builtin_expect (misaligned_chunk (oldp), 0))
    {
      malloc_printerr (check_action, "realloc(): invalid pointer", oldmem, ar_ptr);
      return NULL;
    }

  checked_request2size (bytes, nb);

  if (chunk_is_mmapped (oldp))
    {
      void *newmem;

#if HAVE_MREMAP
      newp = mremap_chunk (oldp, nb);
      if (newp)
        return chunk2mem (newp);
#endif
      /* Note the extra SIZE_SZ overhead. */
      if (oldsize - SIZE_SZ >= nb)
        return oldmem;                     /* do nothing */

      /* Must alloc, copy, free. */
      newmem = __libc_malloc (bytes);
      if (newmem == 0)
        return 0;              /* propagate failure */

      memcpy (newmem, oldmem, oldsize - 2 * SIZE_SZ);
      munmap_chunk (oldp);
      return newmem;
    }                       
{% endhighlight %}

The only integrity checks are for wrapping and alignment of the old chunk, then we enter the mmap path if the chunksize has the `IS_MMAPPED` bit set. Linux supports `mremap`, so `mremap_chunk` (abbreviated code below) will be called and its result returned if successful. Otherwise, if the size of the old chunk is big enough, the old chunk is returned. If it is not, the alloc, copy, free part follows.

{% highlight C %}
static mchunkptr
internal_function
mremap_chunk (mchunkptr p, size_t new_size)
{
  size_t pagesize = GLRO (dl_pagesize);
  INTERNAL_SIZE_T offset = p->prev_size;
  INTERNAL_SIZE_T size = chunksize (p);
  char *cp;

  assert (chunk_is_mmapped (p));
  assert (((size + offset) & (GLRO (dl_pagesize) - 1)) == 0);

  /* Note the extra SIZE_SZ overhead as in mmap_chunk(). */
  new_size = ALIGN_UP (new_size + offset + SIZE_SZ, pagesize);

/* No need to remap if the number of pages does not change.*/
  if (size + offset == new_size)
    return p;

  cp = (char *) __mremap ((char *) p - offset, size + offset, new_size, MREMAP_MAYMOVE);

  if (cp == MAP_FAILED)
    return 0;

...
}
{% endhighlight %}

`mremap_chunk` only checks if the sum of `size` and `prev_size` is page-aligned (see the [first episode]({% post_url 2016-07-27-munmap-madness %}) for more information on mmapped chunks). Also, **if the aligned request size equals the size of the mmapped chunk, it's returned without remapping**.

Assuming a corruption of a chunk later passed into `realloc` with the intent of growing it, there are two possible ways to **force `realloc` to return the old chunk unchanged and thus arranging for overlapping chunks**:

* by corrupting the `size` and `prev_size` fields of the chunk so that they pass the wrapping and alignment checks but cause `mremap` to fail. `size` also needs to be grown to ensure that it will be perceived by `realloc` as large enough to accommodate the requested size. There are many ways to achieve this, e.g. by setting `prev_size` to a huge value, while also growing `size`. The end result will be that after the failed remap attempt, `__libc_realloc` will return the original chunk because its corrupted `size` field is larger than the requested size. The [realloc_noop.c][12] example shows this in action:

{% highlight ocaml %}
tukan@farm:/ptmalloc-fanzine/04-realloc$ ./realloc_noop
allocated victim chunk with requested size 0x400 at 0x5646edd19010,  victim->size == 0x411
allocated another chunk at 0x5646edd19830, so that victim won't simply be grown  from top 
emulating corruption of prev_size and size of victim
reallocating victim with size 0x1600
realloc returned: 0x5646edd19010
tukan@farm:/ptmalloc-fanzine/04-realloc$ 
{% endhighlight %}

* another option is to set the `size` and `prev_size` fields so that they will satisfy the `size + offset == new_size` branch in `mremap_chunk`(while still passing the integrity checks of course). For this to work, we have to know the request size aligned up to the nearest page boundary, which seems reasonable. See [realloc_noop_mremap_exact.c][13] for an example.


[11]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3022
[12]: https://github.com/andigena/ptmalloc-fanzine/blob/master/04-realloc/realloc_noop.c
[13]: https://github.com/andigena/ptmalloc-fanzine/blob/master/04-realloc/realloc_noop_mremap_exact.c


# A wild memcpy appears

What happens when remapping fails and oldsize is not sufficiently large to hold the requested bytes? `__libc_malloc` is called to allocate a chunk of appropriate size, then the contents of the old chunk are copied over via `memcpy`.  To calculate the copy length, `2*SIZE_SZ` is subtracted from the oldsize, meaning a value under 16 will cause an underflow. However, the sizes that can appear there by design from an attacker are limited: the `chunksize` macro masks out the flag bits, which leaves us with 0 or 8 as possible corrupted sizes to trigger the underflow. 

If we set the size to 0, the check for a wrapping chunk, `(uintptr_t) oldp > (uintptr_t) -oldsize`, will fail, since `oldp` will definitely be above -0. So we are left with 8 (10, to be precise, since IS_MMAPPED needs to be set). **8 will avoid returning early in the `if (oldsize - SIZE_SZ >= nb)` branch and also trigger the underflow**. Executing the [wild_memcpy.c][21] example:

{% highlight ocaml %}
tukan@farm:/ptmalloc-fanzine/04-realloc$ gdb ./wild_memcpy
pwndbg> r
Starting program: /media/SSD2/virtual/shared/work/ptmalloc-fanzine/04-realloc/wild_memcpy 
allocated victim chunk with requested size 0x400 at 0x555555756010,  victim->size == 0x411
allocated another chunk at 0x555555756830, so that victim won't simply be grown  from top 
emulating corruption of prev_size and size of victim
reallocating victim with size 0x1600

Program received signal SIGSEGV, Segmentation fault.
__memcpy_sse2 () at ../sysdeps/x86_64/multiarch/../memcpy.S:437
437		movq	%rax,   (%rdi)
...
 ► f 0     7ffff7aa1bc9 __memcpy_sse2+777
   f 1     7ffff7a9312e realloc_hook_ini+734
   f 2     7ffff7a9312e realloc_hook_ini+734
   f 3     7ffff7a91d3f realloc+559
   f 4     5555555548e5 main+181
   f 5     7ffff7a2e830 __libc_start_main+240
Program received signal SIGSEGV (fault address 0x555555777000)
...
pwndbg> address $rdi
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
pwndbg> address $rdi-1
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555756000     0x555555777000 rw-p    21000 0      [heap]
{% endhighlight %}

Leveraging this for anything useful would be rather tricky, maybe in a multithreaded target, e.g. if the `__libc_malloc` call returns an mmapped chunk which is below a thread stack. There is [some][22] [history][23] of exploits for similar primitives but I believe it would be more useful for an attacker to go the overlapping chunks way instead of this.

[21]: https://github.com/andigena/ptmalloc-fanzine/blob/master/04-realloc/wild_memcpy.c
[22]: https://googleprojectzero.blogspot.hu/2015/03/taming-wild-copy-parallel-thread.html
[23]: http://www.halfdog.net/Security/2011/ApacheModSetEnvIfIntegerOverflow/DemoExploit.html


# Overlapping chunks via _int_realloc

If the `IS_MMAPPED` bit isn't set for the chunk, we enter the `_int_realloc` function. It begins with the [size][31] and [next-size][32] checks known from free. Then the interesting parts follow:

* if the old chunk is [large enough][33], use it and [free the remainder][35] via `_int_free`.
* if the [next chunk is the wilderness][34], expand into it and return.
* if the next chunk is free and its size combined with the old size fits the request, [try to expand][37] into it.
* otherwise do the allocate/copy/free dance.

The **first two paths can both be used to create overlapping chunks**. By corrupting the size of a chunk that is later passed into realloc, the same location will be returned for a request larger than the original size. Some things to consider:

* making top the next chunk is a bit friendlier, as there will be no call to `int_free` if the requested size is less than our fake size, top will simply be [moved back][38] `chunk_at_offset (oldp, nb)`. 
* if the remainder is [less than MINSIZE][36], free won't be called. This may be helpful if we cannot grow the corrupted chunk to a valid chunk boundary, since as mentioned before, `_int_realloc` only has the size and next-size checks, while free has considerably more.

The [int_realloc_grow_into_top.c][39] and [int_realloc_encompass_valid_boundary.c][40] show these techniques. The first produces the output below:

{% highlight ocaml %}
tukan@farm:/media/SSD2/virtual/shared/work/ptmalloc-fanzine/04-realloc$ ./int_realloc_grow_into_top
the goal of this example is to create overlapping chunks via the corruption of the size field of a chunk passed into realloc, making top its next chunk 
allocated victim chunk with requested size 0x400 at 0x562c953da420, victim->size == 0x411
allocated target chunk at 0x562c953da830, residing between victim and top
emulating corruption of the size of victim so that top appears to be its next chunk
reallocating victim with size 0x1000
realloc returned: 0x562c953da420
tukan@farm:/media/SSD2/virtual/shared/work/ptmalloc-fanzine/04-realloc$ 
{% endhighlight %}


[31]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4249
[32]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4265
[33]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4272
[34]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4282
[35]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4378
[36]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4373
[37]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4294
[38]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4287
[39]: https://github.com/andigena/ptmalloc-fanzine/blob/master/04-realloc/int_realloc_grow_into_top.c
[40]: https://github.com/andigena/ptmalloc-fanzine/blob/master/04-realloc/int_realloc_encompass_valid_boundary.c


# Abusing mremap

Looking at the code of `mremap_chunk` above, the `mremap` call promises a primitive similar to the `munmap` one from the [first episode]({% post_url 2016-07-27-munmap-madness %}). I'll assume familiarity with that post and keep this short and theoretical.

`mremap_chunk` has the same check to verify that the sum `prev_size` and `size` is page-aligned, and the kernel ensures that the `old_address` parameter of `mremap` is page-aligned, so the restrictions appear the same at first. 

However, in `mremap_chunk`, the `prev_size` field is used to calculate the target of the remapping, the old size, and the new size, while the `size` field of the old chunk has to pass the alignment check in `libc_realloc`. It seems that if we also control the request size of the realloc call, these obstacles can be avoided and most things can be reused from the first episode. Some random notes on mremap:

* if we make the `old_size` parameter of mremap zero, it won't unmap the area at `old_address` but will do the remapping.
* remapping a file based executable mapping (e.g. the binary itself) with a larger `new_size` and a zero `old_size` will create an executable mapping of the binary, including its .data and other sections. This is of questionable usefulness, since it can be expected that after a realloc, the program will try to write to the returned chunk, which will cause a crash in this case.


# Closing words

Comments of any nature are welcome, hit me up on freenode or twitter.

Special thanks to [gym][56] again for the rigorous proofreading.


[56]: https://twitter.com/gymiru