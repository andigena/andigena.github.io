---
layout: post
title: Hack.lu 2015 bookstore writeup
author: tukan
tags:
- hack.lu
- bookstore
- ctf
- heap
- format-string
---

An [exploitation challenge][1] from Hack.lu 2015 that, upon a cursory glance, promised some lighthearted heap-based entertainment. Internals of the glibc malloc implementation won't be covered in depth, if you find the writeup hard to follow, [this link might help][5].

[1]: https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore
[5]: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

# Overview

The program is very simple, it allows us to edit 2 orders, arbitrarily call free on both of them and submit our orders. The abbreviated decompilation of `main`  is shown below. There are three buffers allocated at the beginning, which will be adjacent in memory due to the malloc implementation of glibc. 

{% highlight C %}
  order1b = (char *)malloc(0x80uLL);
  order2b = (char *)malloc(0x80uLL);
  dest = (char *)malloc(0x80uLL);
  if ( order1buf && order2buf && dest )
  {
    v5 = 0;

    while ( 1 )
    {
      if ( v5 )
      {
        printf("%s", submitBuf);
        printf(dest);
        result = 0;
        goto LABEL_16;
      }
      puts("1: Edit order 1");
      puts("2: Edit order 2");
      puts("3: Delete order 1");
      puts("4: Delete order 2");
      puts("5: Submit");
      fgets(s, 128, stdin);
      switch ( s[0] )
      {
        case '1':
          puts("Enter first order:");
          gets(order1b);
          strcpy(dest, "Your order is submitted!\n");
          continue;
        case '2':
          puts("Enter second order:");
          gets(order2b);
          strcpy(dest, "Your order is submitted!\n");
          continue;
        case '3':
          free2(order1b, 128LL);
          continue;
        case '4':
          free2(order2b, 128LL);
          continue;
        case '5':
          submitBuf = (char *)malloc(0x140uLL);
          if ( !submitBuf )
          {
            fwrite("Something failed!\n", 1uLL, 0x12uLL, stderr);
            result = 1;
            goto LABEL_16;
          }
          orderConcat(submitBuf, order1b, order2b);
          v5 = 1;
          break;
        default:
          continue;
      }
    }
{% endhighlight %}

Multiple vulnerabilities can be seen:

* heap overflows when editing any of the orders
* a possible format string bug when submitting an order
* calling free on the order buffers arbitrarily
* bonus: the `orderConcat` function also contains a heap overflow when writing the orders to submitBuf (ugly decompilation below)

{% highlight C %}
__int64 __fastcall orderConcat(char *submitBuf, const char *order1b, char *order2b)
{
  const char *order2bl; // ST08_8@1
  __int64 v4; // ST28_8@1
  size_t len_order1; // rdx@1
  char *v6; // rax@1
  size_t len_order2; // rdx@1

  order2bl = order2b;
  *(_QWORD *)submitBuf = ':1 redrO';
  *((_WORD *)submitBuf + 4) = ' ';
  len_order1 = strlen(order1b);
  strncat(submitBuf, order1b, len_order1);
  v6 = &submitBuf[strlen(submitBuf)];
  *(_QWORD *)v6 = '2 redrO\n';
  *((_WORD *)v6 + 4) = ' :';
  v6[10] = '\0';
  len_order2 = strlen(order2bl);
  strncat(submitBuf, order2bl, len_order2);
  *(_WORD *)&submitBuf[strlen(submitBuf)] = '\n';
}
{% endhighlight %}


Mitigation-wise, the binary looks like this:

`No RELRO / Canary found / NX enabled / No PIE`

First I was looking at the possibility of some complicated heap metadata corruption but eventually realized that for 200 points (the hardest challenge was for 500 points), the format string bug must be it. The problem is, when editing the orders and possibly placing our format string payload into `dest` via the `gets` calls, it gets overwritten right away by the `strcpy` calls. `orderConcat` also contains an overflow but it's destination, `submitBuf` will be placed after `dest`. Even if we free both order buffers before submitting, as shown below (created using [villoc][2]), the heap layout won't change favorably.

![bookstore villoc][3]

[2]: https://github.com/wapiflapi/villoc
[3]: /public/bookstore/bookstore_villoc.png


# The Plan

Well, the plan is rather simple after putting the pieces together: make the malloc of `submitBuf` return an address before `dest` by convincing it that there's a big enough free chunk, then use the bonus overflow in `orderConcat` to trigger the format string bug. With the powerful primitives we have, this is not a hard task. The thing to keep in mind is that allocated heap chunks are preceded by their size (and the lower three bits of the chunk size are used as flags), so could overwrite the length in the chunk header of `order2b`:

* before freeing it, so that it will enter the unsorted bin as a bigger chunk
* after freeing it, to essentially the same effect

Now when `submitBuf` is allocated, malloc will travel the unsorted bin and return the address previously used for `oder2b`. During the CTF I used the first approach, realizing only later that the second is actually less painful. This is due to the bookkeeping free does, like visiting the next and previous chunks to see if they need to be coalesced with the freshly freed chunk and to set the flags. Going through these with a corrupted size may cause a failure so some precautions must be taken. In the exploit (linked at the end). I've used 337  as the new size, the only important thing here is that it's bigger than the size the `submitBuf` allocation with the malloc overhead (~336 bytes) and the LSB is set, which is used as the PREV_INUSE flag to indicate that the previous chunk isn't free.

We need to store the addresses for the format string on the stack. Luckily the program is nice enough to read 128 bytes into a stack buffer to get our menu choice, which is plenty. For format string bugs, .GOT entries are common targets. However, after the vulnerable `printf` is triggered, `main` returns without calling any library functions, so overwriting only a .GOT entry will not cut it. To take over execution, we need to compromise an entry in the .fini table, too, which contains functions called on process termination. By overwriting the lower bytes of the first .fini function, execution can be redirected to the beginning of main, effectively restarting the program. For the .GOT overwrite, *free* seems to be the best candidate, it's called directly with our input. By replacing its entry with the address of system, we can *almost* execute code.

So far so good, except for ASLR and the fact that we've no idea about the libc version used on the server. By leaking addresses from the stack that point into libc, it's possible to establish its version. I was pleasantly surprised to find that it's the same as mine (well, not so surprising considering I ran the same Ubuntu version as the organizers). Looking at the offsets of free and system, the lower three bytes of the free .GOT entry needed to be overwritten to reach system. That's 12 bits of entropy, considering the lowest 12 bits are fixed because images are loaded at page boundaries. I decided that this is a reasonable amount of brute-force and didn't bother checking into leaking addresses.

Executing the (CTF-)quality [exploit][4] eventually yields a shell and the flag:
```flag{heres_5_dollar_gift_card_hope_that_was_worth_it}```
Yup, definitely.

[4]: /public/bookstore/bookstore_brute.py
