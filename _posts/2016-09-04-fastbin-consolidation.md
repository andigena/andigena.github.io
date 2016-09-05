---
layout: post
title: fastbin consolidation
author: tukan
tags:
- ptmalloc
- memory corruption
- exploitation
- heap
- glibc
---

This post deals with the consolidation of fastbin chunks and is the second episode of the [ptmalloc fanzine]({% post_url 2016-07-26-ptmalloc-fanzine %}). Prepare for even more obscure malloc trivia and internal details you never wanted to know, all in the name of modest gains. Glibc source links and statements like "the default stack size is 8MB" that are obviously platform-dependent all pertain to Ubuntu 16.04 on x86-64, unless stated otherwise.


# TLDR

We'll look at the possible ways to leverage fastbin chunk corruption via fastbin consolidation. Three distinct avenues present themselves:

* following in the footsteps of [The Forgotten Chunks paper][31], **it's possible to arrange for overlapping chunks**. Also, there are circumstances under which we can simply reuse those techniques by first entering the fastbin chunks into the unsorted bin via `malloc_consolidate`.
* by poisoning the singly linked list of a fastbin, we may **enter fake chunks into the unsorted bin**. This is similar to [fastbin_dup_into_stack.c from how2heap][33] but with different (and overall, more) constraints on the fake chunk. Still, it may prove useful under the right conditions.
* it's also possible to abuse `malloc_consolidate` for **direct memory corruption** via the unsorted bin linking code. We'll look at the special case of leveraging this to overwrite the `check_action` global that controls the action taken on many ptmalloc integrity check failures. By clearing its lower bits, we can **turn aborts on such failures into no-ops** and even gain some new abilities, including the **revival of the classic unlink primitive**.

An extension prototype to [pwndbg][36] will also be presented that helps identifying fake chunk candidates in the address space of a process. At the end, we'll touch on a possible way to harden `malloc_consolidate`.


# A small victory for chunk consolidation equality

I've read many times that even though a fastbin chunk and another chunk might love each other very much, they'll never be coalesced together. I consider this unfair for multiple reasons. The good news is that, looking around a bit in the ptmalloc code, there's a loophole. It's called `malloc_consolidate` and it's rather easy to reach. Let's see what the source comments have to say about it:

> malloc_consolidate is a specialized version of free() that tears down chunks held in fastbins.  Free itself cannot be used for this purpose since, among other things, it might place chunks back onto fastbins.  So, instead, we need to use a minor variant of the same code.

> Remove each chunk from fast bin and consolidate it, placing it then in unsorted bin. Among other reasons for doing placing in unsorted bin avoids needing to calculate actual bins until malloc is sure that chunks aren't immediately going to be reused anyway.

> Also, because this routine needs to be called the first time through malloc anyway, it turns out to be the perfect place to trigger initialization code.

That is very promising. Its somewhat abbreviated [source code][10] looks like this:

{% highlight C %}
static void malloc_consolidate(mstate av)
{
  ...
  if (get_max_fast () != 0) {
    clear_fastchunks(av);

    unsorted_bin = unsorted_chunks(av);

    maxfb = &fastbin (av, NFASTBINS - 1);
    fb = &fastbin (av, 0);
    do {
      p = atomic_exchange_acq (fb, 0);
      if (p != 0) {
	do {
	  check_inuse_chunk(av, p);
	  nextp = p->fd;

	  /* Slightly streamlined version of consolidation code in free() */
	  size = p->size & ~(PREV_INUSE|NON_MAIN_ARENA);
	  nextchunk = chunk_at_offset(p, size);
	  nextsize = chunksize(nextchunk);

	  if (!prev_inuse(p)) {
	    prevsize = p->prev_size;
	    size += prevsize;
	    p = chunk_at_offset(p, -((long) prevsize));
	    unlink(av, p, bck, fwd);
	  }

	  if (nextchunk != av->top) {
	    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	    if (!nextinuse) {
	      size += nextsize;
	      unlink(av, nextchunk, bck, fwd);
	    } else
	      clear_inuse_bit_at_offset(nextchunk, 0);

	    first_unsorted = unsorted_bin->fd;
	    unsorted_bin->fd = p;
	    first_unsorted->bk = p;

	    if (!in_smallbin_range (size)) {
	      p->fd_nextsize = NULL;
	      p->bk_nextsize = NULL;
	    }

	    set_head(p, size | PREV_INUSE);
	    p->bk = unsorted_bin;
	    p->fd = first_unsorted;
	    set_foot(p, size);
	  }

	  else {
	    size += nextsize;
	    set_head(p, size | PREV_INUSE);
	    av->top = p;
	  }

	} while ( (p = nextp) != 0);

      }
    } while (fb++ != maxfb);
  }
}
{% endhighlight %}

So basically it walks all the [fastbins][11], consolidating [forward][12] and [backward][13] when appropriate and links the resulting chunks into the [unsorted bin][14]. There's also some [special treatment][15] for top, as expected. Note that **this is the only way fastbin-sized chunks may enter the unsorted bin**.

Let's see how we can trigger it. There are four interesting call sites in the code, three in `_int_malloc` and one in `_int_free`, let's look at them in order:

* [M1][16]: this one is only for the first malloc call and does initialization. Uninteresting from an offensive perspective. 
* [M2][17]: triggered for largebin sized malloc requests, probably the most universal way to reach `malloc_consolidate`.
* [M3][18]: this one allows a call to `malloc_consolidate` for a small request but is quite tricky to arrange for intentionally. This call site is just before the second iteration of the [outer binning loop][19] is started and I will let the source comment speak:

>   The outer loop here is needed because we might not realize until near the end of malloc that we should have consolidated, so must do so and retry. This happens at most once, and only when we would otherwise need to expand memory to service a "small" request. 

* [F1][20]: another easy one, assuming we can free chunks larger than FASTBIN_CONSOLIDATION_THRESHOLD ([64KB][21]).


So, back to the code above. What catches the eye immediately is the **lack of integrity checks**. This hints at a few options if we can corrupt a chunk in one of the fastbins, e.g. entering it into the unsorted bin as grown/shrunk chunk or memory write primitives via the linking code. The only immediate obstacle is the classic unlink hardening encountered during forward and backward consolidation. Another possibly limiting factor is the loop responsible for binning unsorted chunks in *malloc*. After **M2** and **M3**, we run right into it and after **F1**, it might be triggered on the next malloc request, so it's important to understand it.


# The binning code in malloc

On every *malloc* request that **cannot be served from the fastbins or smallbins by an exact fit**, the unsorted bin is traversed to place its chunks into the correct bins. The code is rather long, so it won't be reproduced here but the description will be littered with links to the actual source. `victim` refers to the currently binned chunk.

* right away, the [size of victim is checked][22] to be `between 2*SIZE_Z and av->system_mem`. `av->system_mem` is the sum of memory allocated from the system (via brk or mmap) for the specific arena and can be expected to be at least 128KB. 
* then some [special treatment][23] for the last remainder chunk that doesn't concern us.
* [remove victim][24] from from the unsorted bin.
* [return victim][25] if it's an exact fit.
* if victim is smallbin-sized, [place it in the appropriate smallbin][26]. Note that because of the way [in_smallbin_range works][35], this also applies to fastbin-sized chunks that ended up in the unsorted bin due to malloc_consolidate.
* otherwise (meaning it's largebin-sized), find the [right bin][27] and its [place within the bin][28].

The takeaway for what follows is that **chunks in the unsorted bin must have sizes between 2\*SIZE_Z and av->system_mem**, otherwise we are aborting. I'm going to refer to chunks with such a size as **binnable**. There are two exceptions, though:

* one binning run is limited to [10000][29] chunks.
* if the binning code hits an exact fit before reaching the invalid unsorted chunk, it's returned immediately and the binning isn't continued.

The second one seems more useful in a generic context, as it allows to survive a few malloc calls involving consolidation if we can place exact matches for the requested sizes before the corrupted chunks in the unsorted bin.


# Constraints on chunks processed by malloc_consolidate

While there are no explicit integrity checks in the consolidation code, there are some constraints we have to satisfy in order to avoid crashing the code. To understand their relevance, it's important to touch on the possible ways to leverage a fastbin entry corruption via `malloc_consolidate`:

* one avenue of exploitation is to grow/shrink the size of the corrupted chunk. There's an assumption here that we control the fields of the corrupted chunk which makes the following constraints rather easy to satisfy. 
* another option is to make `malloc_conslidate` operate on a fake chunk by altering the fd pointer of the corrupted chunk. We may have very limited or zero direct control over this fake chunk, therefore this is a substantially harder task.


## Unlinking

First we should consider the possibly **troublesome unlinks in the backward and forward consolidation cases** in the `malloc_consolidate` code. If we control the size field of the chunk, setting the PREV_INUSE bit avoids the first unlink call. The forward case is trickier, some possibilities are:

* if we know the size of the next chunk, or the distance of a valid chunk, we can increase the size of the corrupted chunk so that malloc_consolidate operates on valid next and next-next chunks.
* a way to avoid the unlinking altogether is by supplying a size value for the corrupted chunk so that the next-next chunk size has the `PREV_INUSE` bit set (so it's an odd number). The location of the next-next chunk is calculated by adding the corrupted chunk size to the chunk pointer to obtain the next chunk, and adding the size field there to the next chunk pointer. Note that `malloc_consolidate` only masks out the `PREV_INUSE` and `NON_MAIN_ARENA` bits from the current chunk size but all three lower bits are masked from the nextsize. 
  * because of the lack of integrity checks, it's enough to find a size\_t with a value of 1, 3, 5, or 7 within a reasonable distance and **forward coalescing will be avoided** if we set up the size of the corrupted chunk so that the size of the next chunk will be one of those values. In this case the next and next-next chunk calculated by `malloc_consolidate` will be the same and no unlink call will happen, since the `PREV_INUSE` bit is set in that fake chunk.
  * in a similar vein, if we set the corrupted chunk size to 1 or 5, both the next and the next-next chunk pointers calculated will point to the corrupted chunk itself. This seems useless at first, since the chunk with this unbinnable, small size is entered into the unsorted bin and the binning code will **abort upon reaching it**. See the House of Cards below for a lengthy treatment of this case.


## Looping

The fact that traversing is continued until a null fd pointer may easily lead to crashes, especially if we are trying to link a fake chunk into a fastbin.


## Alignment

Another thing to keep in mind is that while neither `malloc_consolidate` nor `malloc` cares about alignment, free aborts [early on][52] in case of a misaligned chunk address or chunk size (16 bytes on x86-64).


## Recap

Let's recap what's needed of a chunk to survive the `malloc_consolidate` code operating on it. 
`p` refers to the current chunk. Note that the size of the current chunk is calculated by `size = p->size & ~(PREV_INUSE|NON_MAIN_ARENA);` while the size of the nextchunk is calculated by `nextsize = chunksize(nextchunk);`

* **coalescing**
  * backward: `p->size & PREV_INUSE`
  * forward: `nextnextchunk->size & PREV_INUSE`
* **looping**: `p->fd == 0`
* **binning**: `2*SIZE_Z < p->size < av->system_mem`
* **alignment**: `(p & MALLOC_ALIGN_MASK == 0) && (p->size & MALLOC_ALIGN_MASK == 0)`

Satisfying the binning constraint may not be necessary, assuming we can achieve our goal before a binning run reaches the corrupt chunk. Similarly, a chunk can be misaligned if it won't get passed to free.

After this lengthy introduction, let's see what an attacker might gain from corrupting a fastbin entry, then triggering consolidation.


# Forgotten chunks, fastbin edition

Growing (or shrinking) the target chunk by corrupting its size field is an interesting option. The [overlapping_fastchunk.c][32] example shows this in practice:

{% highlight C %}
    ...
    malloc(1);

    void *m1 = malloc(0x20);
    void *m2 = malloc(0x100);
	
    // allocate another chunk to avoid the top-handling special case
    void *m3 = malloc(0x100);
    ...
   
    free(m1);

    printf("emulating corruption of p1\n");
    p1->size += p2->size & ~PREV_INUSE;

    printf("triggering malloc_consolidate via allocation for large chunk\n");
    malloc(0x400);
    printf("after consolidation malloc(0x%x) returns %p\n", 0x100, malloc(0x100));
{% endhighlight %}

{% highlight ocaml %}
tukan@farm:/ptmalloc-fanzine/02-consolidate$ ./overlapping_fastchunk
allocated fastbin-sized (0x31) chunk p1: 0x55d814f89030
allocated small (0x111) chunk p2: 0x55d814f89060
freeing p1
emulating corruption of p1
triggering malloc_consolidate via allocation for large chunk
after consolidation malloc(0x100) returns 0x55d814f89030
{% endhighlight %}

Note how closely related this is to some of the techniques in the [forgotten chunks paper][31] (also showcased in [overlapping_chunks.c from how2heap][30]). Here, we corrupt a chunk in a fastbin and enter it into the unsorted bin via `malloc_consolidate`. In overlapping_chunks.c, a chunk already in the unsorted bin is corrupted. Let's compare the two:

* both are bound by the size checks at the beginning of the binning loop, meaning the corrupted chunks need to remain **binnable**
* if we can't control the length of the corruption precisely enough, we can crash in the binning code when using the forgotten chunks methods. To avoid crashes, we must either keep the double-linked list of the unsorted bin intact by avoiding corruption of the bk pointer of the target chunk or by placing an edible chunk pointer there (preferably to the unsorted bin in the arena to stop the loop). In this case, corrupting a fastbin entry and consolidating it might be preferable, since malloc_consolidate only loops over a fastbin until a null fd pointer is encountered.
* the forward coalescing problem of `malloc_consolidate` is absent when corrupting unsorted chunks directly.
* as mentioned previously, fastbin-sized chunks normally don't enter the unsorted bin. If we are able to trigger `malloc_consolidate` (an assumption this whole post is based on), we can simply force the target fastbin chunk into the unsorted bin before corrupting it and **reuse almost everything from the forgotten chunks paper**. However, the *M2* and *M3* triggers for `malloc_consolidate` (see above) start the binning process right away, so unless we can prematurely end it (also see above), the chunk will end up in the [appropriate **smallbin**][34]. The **F1** trigger provides a much better opportunity for this, as binning may only happen on the next malloc call.


# Entering a near-arbitrary* chunk into the unsorted bin

If you are familiar with fastbin poisoning (maybe not by that name), as shown in [fastbin_dup_into_stack.c from how2heap][33], your first thought when looking at `malloc_consolidate` might have been: the same could be achieved here. In fastbin_dup_into_stack.c, the fd pointer of a fastbin chunk is corrupted (via fastbin duplication but that's irrelevant) to point to a fake chunk. The fake chunk needs a size of the same fastbin index as the corrupted chunk, so a controlled, small value is needed at a known location. Then eventually a subsequent malloc call of the same size returns the fake chunk. Some possible locations for the controlled value are the stack, heap, .data.

Can we do the same via `malloc_consolidate`?

* the obvious drawbacks of `malloc_consolidate` are the coalescing and the loop-termination problems. **Both means more constraints on our fake chunk**.
* the original fastbin poisoning requires quite precise control over the size of the fake chunk. Due to the lacking integrity checks, poisoning via `malloc_consolidate` is less restricted in this sense but backward/forward coalescing and binnability (nice word) should still be kept in mind.
* misaligned chunks are fine for both techniques until free is called on them.

Intuitively, the `malloc_consolidate` method seems significantly more limited but to evaluate if it's usable at all for poisoning, I've written a gdb script ([github here][53], based on the excellent [pwndbg][36]) that searches the address space of a process for fake chunk candidates satisfying the constraints required for `malloc_consolidate`. It adds a new command, `consolidate_poison`, to gdb. Its help string is self-explanatory enough I hope.

{% highlight ocaml %}
pwndbg> consolidate_poison -h
usage: consolidate_poison [-h] [-l] [-m] [-u] [-y SYSTEM_MEM] [mapping]

Search memory for fake fasbin chunk candidates, usable in malloc_consolidate related techniques. 
Note that specifying -u -m and -l together might be very slow.

positional arguments:
  mapping               Mapping to search [e.g. libc]

optional arguments:
  -h, --help            show this help message and exit
  -l, --lookup-symbols  Explore the symbols contained by the candidates (SLOW!) (default: False)
  -m, --misaligned      Include misaligned candidates (default: False)
  -u, --unbinnable      Include unbinnable candidates (default: False)
  -y SYSTEM_MEM, --system-mem SYSTEM_MEM
                        Value of av->system_mem, used for binnability checks (default: 131072)
{% endhighlight %}

Part of the output of `consolidate_poison -m -l` on a vim instance with python support can be seen below. Fake chunk candidates are grouped by mapping name and binnability. From left to right, the following information is printed about a candidate: 

**address start - address end (chunk size->next size->next next size[/CROSS-MAP]): the first then symbols enclosed by the chunk**

`CROSS-MAP` means that the chunk spans multiple memory maps.

![gdb][54]


# Memory corruption via unbinnable fake chunks

Both previous techniques required binnable chunk sizes but the `malloc_consolidate` code also has potential to corrupt memory via unbinnable fake chunks. There are [writes done upon linking the current chunk into the unsorted bin and setting the boundary tags][37], as in:

{% highlight C %}
set_head(p, size | PREV_INUSE);                                                                
p->bk = unsorted_bin;
p->fd = first_unsorted;
set_foot(p, size);
{% endhighlight %}

The constraints to leverage this corruption in the simplest case (other chunk sizes would also work, assuming they satisfy the **coalescing** and **looping** constraints but let's stick with the simple case):

* `p->fd == NULL`
* `p->size == 1` \|\| `p->size == 5`

The above four lines will:

* set `p->prev_size` to `p->size` (zero) via set_foot
* corrupt `p->fd` and `p->bk` with pointers

Of course, the next binning run that hits this unbinnable fake chunk will abort, so besides choosing the right target for corruption, we also have to be quick. Unless...


## House of Cards

The pieces for the House of Cards fell together while I was looking for a worthwhile corruption target that satisfies the constraints above. It's somewhat reminiscent of the House of Prime in that the binary layout of libc plays a significant role in its applicability. The main idea is to use the above memory corruption primitive to disable integrity checks in the ptmalloc code. Its name draws on the sheer amount of happenstance that makes it viable. The following pertains to Ubuntu 14.04.5 LTS on x86-64.


### Aborts, how do they work?

The binning code in `malloc` calls `malloc_printerr` on invalid chunk sizes, like this:
{% highlight C %}
if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
    || __builtin_expect (victim->size > av->system_mem, 0))
  malloc_printerr (check_action, "malloc(): memory corruption",
                   chunk2mem (victim));
{% endhighlight %}

`check_action` is a global defaulting to 1 on 14.04 (and 3 on 16.04). `malloc_printerr` is used in most places where an unrecoverable error is encountered. Let's take a look at its source:

{% highlight C %}
static void
malloc_printerr (int action, const char *str, void *ptr)
{
  if ((action & 5) == 5)
    __libc_message (action & 2, "%s\n", str);
  else if (action & 1)
    {
      char buf[2 * sizeof (uintptr_t) + 1];

      buf[sizeof (buf) - 1] = '\0';
      char *cp = _itoa_word ((uintptr_t) ptr, &buf[sizeof (buf) - 1], 16, 0);
      while (cp > buf)
        *--cp = '0';

      /* always abort (action & 1) and (on linux) if bit 1 is set, emit backtrace */
      __libc_message (action & 3, "*** Error in `%s': %s: 0x%s ***\n", __libc_argv[0] ? : "<unknown>", str, cp);
    }
  else if (action & 2)
    abort ();
}
{% endhighlight %}

So, if we could corrupt `check_action` to unset its lower bits, we could effectively turn many integrity checks of the ptmalloc code into no-ops. 


### A lucky constellation of global variables

The memory layout of the libc .so on 14.04.5 looks promising:

{% highlight ocaml %}
pwndbg> p &check_action
$29 = (int *) 0x7ffff7dd3190 <check_action>
pwndbg> x/8gx 0x7ffff7dd3190-0x20
0x7ffff7dd3170 <__libc_malloc_initialized>:	0x0000000000000001	0x0000000000000000
0x7ffff7dd3180 <narenas>:	0x0000000000000001	0x0000000000000000
0x7ffff7dd3190 <check_action>:	0x0000000000000001	0x0000000000000000
0x7ffff7dd31a0 <mp_>:	0x0000000000020000	0x0000000000020000
pwndbg> x/8gx 0x7ffff7dd3190-0x28
0x7ffff7dd3168:	0x0000000000000000	0x0000000000000001
0x7ffff7dd3178:	0x0000000000000000	0x0000000000000001
0x7ffff7dd3188:	0x0000000000000000	0x0000000000000001
0x7ffff7dd3198:	0x0000000000000000	0x0000000000020000
pwndbg> p *(mchunkptr)(((char*)&check_action)-0x18)
$33 = {
  prev_size = 0x0, 
  size = 0x1, 
  fd = 0x0, 
  bk = 0x1, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x20000
}
pwndbg> p &((mchunkptr)(((char*)&check_action)-0x18))->prev_size
$40 = (size_t *) 0x7ffff7dd3178
pwndbg> p &((mchunkptr)(((char*)&check_action)-0x18))->size
$41 = (size_t *) 0x7ffff7dd3180 <narenas>
pwndbg> p &((mchunkptr)(((char*)&check_action)-0x18))->fd
$42 = (struct malloc_chunk **) 0x7ffff7dd3188
pwndbg> p &((mchunkptr)(((char*)&check_action)-0x18))->bk
$43 = (struct malloc_chunk **) 0x7ffff7dd3190 <check_action>
{% endhighlight %}

So, the global integers `narenas` (which is the number of arenas) and `check_action` are 16-byte aligned, and assuming there's only 1 arena (single threaded application), or there are 5 arenas, there is a fake chunk there that satisfies the constrains. If we link this fake chunk into a fastbin via the corruption of the fd pointer of a free fast chunk, the following happens:

* prev_size is set to 0 (it's just uninteresting alignment bytes)
* fd and bk are set to some pointers, bk being `check_action`. 

Since these pointers are at least 8-byte aligned, the lower bits will be unset, **rendering all `malloc_printerr` calls that use `check_action` (most use it) no-ops**. 

This helps with the burning problem of aborting immediately in the binning code on this unbinnable fake chunk but there's another issue. The binning code is not equipped to handle a 0-sized chunk, so `smallbin_index` will [return 0][39] and as the comment before `bin_at` cautions: **note that bin_at(0) does not exist**. The end result is that we underindex av->bins and end up [corrupting av->top with the address of the fake chunk][40]. The problem with this is that malloc calls in the future reaching the [use\_top][41] part will crash because top is considered small, sysmalloc gets called and an [assert][42] ends our journey. [HoC\_aborting.c][43] showcases this. 

{% highlight ocaml %}
tukan@tukan-vb-14045:/ptmalloc$ gdb ./HoC_aborting
pwndbg> start
...
pwndbg> p &check_action 
$59 = (int *) 0x7ffff7dd3190 <check_action>
pwndbg> start 0x7ffff7dd3190
pwndbg> c
Continuing.
HoC_aborting: malloc.c:2372: sysmalloc: Assertion `(old_top == (((mbinptr) (((char *) &((av)->bins[((1) - 1) * 2])) - __builtin_offsetof (struct malloc_chunk, fd)))) && old_size == 0) || ((unsigned long) (old_size) >= (unsigned long)((((__builtin_offsetof (struct malloc_chunk, fd_nextsize))+((2 *(sizeof(size_t))) - 1)) & ~((2 *(sizeof(size_t))) - 1))) && ((old_top)->size & 0x1) && ((unsigned long) old_end & pagemask) == 0)' failed.

Program received signal SIGABRT, Aborted.
{% endhighlight %}


To get around this, our best course of action would be to create a large free chunk that can be used by the [next largest bin code][44], so that we can avoid triggering the top code until exploitation is complete. [HoC\_surviving.c][55] shows this in action.

{% highlight ocaml %}
pwndbg> start 0x7ffff7dd3190
pwndbg> p check_action
$2 = 0x1
pwndbg> finish
Run till exit from #0  main (argc=0x2, argv=0x7fffffffde88) at HoC_surviving.c:15
...
Value returned is $3 = 0x0
pwndbg> p check_action
$4 = 0xf7dd37a8
{% endhighlight %}


### Terms and conditions may apply 

A ptmalloc without integrity checks sounds interesting but there's a catch: most call sites of `malloc_printerr` are on dedicated error paths that return immediately, like in the case of `_int_free`, where we can see the definition of the `errout` label and its use, too:

{% highlight C %}
if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
    || __builtin_expect (misaligned_chunk (p), 0))
  {
    errstr = "free(): invalid pointer";
  errout:
    if (!have_lock && locked)
      (void) mutex_unlock (&av->mutex);
    malloc_printerr (check_action, errstr, chunk2mem (p));
    return;
  }
/* We know that each chunk is at least MINSIZE bytes in size or a
   multiple of MALLOC_ALIGNMENT.  */
if (__builtin_expect (size < MINSIZE || !aligned_OK (size), 0))
  {
    errstr = "free(): invalid size";
    goto errout;
  }
{% endhighlight %}

So even though `malloc_printerr` wouldn't abort, `_int_free` would return immediately. While this is useful for avoiding unintended crashes, it doesn't buy us much in terms of additional primitives. There are a few *naked* call sites of `malloc_printerr` which do not have an immediate return:

* after the [size checks][45] in the binning loop. This allowed us to corrupt `check_action` via a `malloc_consolidate` of a fake fastbin chunk and get away with it. Abusing the same primitive for the corruption of other targets is a possibility, but the limited control over the contents of the writes has to be kept in mind.
* two in the `unlink` macro
  * first after failing the  [`FD->bk != P || BK->fd != P` check][46], which effectively turns `unlink` calls on chunks with corrupted double-links into no-ops
  * second, after failing the [skip-list integrity check][47] for large chunks. This is more interesting, as it allows us to revive the classic unlink technique once again. Last time it was via missing asserts in the Fedora build of glibc published by [P0][48].


### House of Cards recap

Summarizing the requirements for the technique:

* proper binary layout for a fake chunk around `check_action`. Ubuntu 14.04.5 has it with the right number (1 or 5) of arenas, 16.04 doesn't.
* ability to corrupt the fd pointer of a fastbin chunk.
* a leak from libc to calculate the address of `check_action`.
* ability to trigger `malloc_consolidate`.
* `av->top` will be point to the fake chunk around `check_action`, so future allocations  from top will crash. If this is a concern, some heap massaging is required to set up free chunks able to serve requests until exploitation is complete.


### check_action as a general target

There are two reasons why the House of Cards won't work on 16.04:

* 16.04 switched back to glibc from eglibc, and the binary layout is different. 
* `malloc_printerr` also got an additional parameter, the arena ptr, which is used to [set the `ARENA_CORRUPTION_BIT`][49]. Once this bit is set for an arena, it is no longer used for allocations and its previously allocated chunks are not freed. A different arena will be assigned to the thread or a new one created. If we reach the arena limit and each one ends up with the `ARENA_CORRUPTION_BIT`, `_int_malloc` [falls back][50] to `sysmalloc`/mmap.

I would say that `check_action` might be a worthwhile target for corruption in general, outside the context of the House of Cards, especially if the write contents are not well controlled and the stability of the heap cannot be ensured otherwise.


# Mitigation

A simple way to harden `malloc_consolidate` would be to add a size-check similar to the [one on the fastbin path][51] of `_int_malloc` to ensure that the traversed fastbin contains only chunks of the appropriate size. This would kill the overlapping chunks and the direct memory corruption via unbinnable chunks techniques while also severely limiting the ability to enter fake chunks into the unsorted bin via the poisoning method.


# Closing words

That's all folks, hope you enjoyed reading this. As usual, comments of any nature are welcome, hit me up on freenode or twitter.

Special thanks to [gym][56] for the rigorous proofreading.



[10]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4123
[11]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4161
[12]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4183
[13]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4174
[14]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4189
[15]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4205

[16]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3414
[17]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3452
[18]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3816
[19]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3468
[20]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4077
[21]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L1622

[22]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3474
[23]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3488
[24]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3517
[25]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3522
[26]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3535
[27]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3541
[28]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3554
[29]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3596


[30]: https://github.com/shellphish/how2heap/blob/master/overlapping_chunks.c
[31]: http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf
[32]: https://github.com/andigena/ptmalloc-fanzine/blob/master/02-consolidate/overlapping_fastchunk.c
[33]: https://github.com/shellphish/how2heap/blob/master/fastbin_dup_into_stack.c
[34]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3537
[35]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L1477
[36]: https://github.com/pwndbg/pwndbg

[37]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4198
[38]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4989
[39]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3536
[40]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3592
[41]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3778
[42]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L2393


[43]: https://github.com/andigena/ptmalloc-fanzine/blob/master/02-consolidate/HoC_aborting.c
[44]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3668
[45]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3476
[46]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L1419
[47]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L1427
[48]: https://googleprojectzero.blogspot.hu/2014/08/the-poisoned-nul-byte-2014-edition.html
[49]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L4995
[50]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3355
[51]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3384
[52]: https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c#L3863
[53]: https://github.com/andigena/pwndbg/blob/fanzine/pwndbg/commands/heap.py#L202
[54]: /public/consolidate/gdb.png
[55]: https://github.com/andigena/ptmalloc-fanzine/blob/master/02-consolidate/HoC_surviving.c
[56]: https://twitter.com/gymiru