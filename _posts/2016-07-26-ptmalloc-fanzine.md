---
layout: post
title: ptmalloc fanzine
author: tukan
tags:
- ptmalloc
- heap-meta
- glibc
---

This post is intended to be the parent-page of the ptmalloc fanzine episodes, as well as a collection of resources related to glibc heap meta-data corruptions. 


# The zine

The zine deals with some peculiarities of ptmalloc meta-data attacks, mostly from an offensive perspective. Familiarity with the glibc malloc implementation and the different techniques for leveraging corruptions is assumed, see below for introductory resources.

* **episode 01**: [munmap madness]({% post_url 2016-07-27-munmap-madness %})
* **episode 02**: [fastbin consolidation]({% post_url 2016-09-04-fastbin-consolidation %})


# External resources

* [glibc wiki malloc internals][20]: high-level overview of ptmalloc
* [sploitfun][21]: describes ptmalloc and the different attacks
* [how2heap][22]: nice practical examples of the currently relevant techniques, as well as a collection of other resources
* [GB_MASTER'S /DEV/NULL][23]: explores each technique in the Malloc Maleficarum

[20]: https://sourceware.org/glibc/wiki/MallocInternals
[21]: https://sploitfun.wordpress.com/archives/
[22]: https://github.com/shellphish/how2heap
[23]: https://gbmaster.wordpress.com/