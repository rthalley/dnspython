# Copyright (C) 2009 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import time

class EntropyPool(object):
    def __init__(self, seed=None):
        self.pool_index = 0
        self.digest = None
        self.next_byte = 0
        if seed is None:
            try:
                r = file('/dev/random')
                try:
                    seed = r.read(16)
                finally:
                    r.close()
            except:
                seed = str(time.time())
        try:
            import hashlib
            self.hash = hashlib.sha1()
            self.hash_len = 20
        except:
            try:
                import sha
                self.hash = sha.new()
                self.hash_len = 20
            except:
                import md5
                self.hash = md5.new()
                self.hash_len = 16
        self.pool = '\0' * self.hash_len
        self.stir(seed)

    def stir(self, entropy):
        bytes = [ord(c) for c in self.pool]
        for c in entropy:
            if self.pool_index == self.hash_len:
                self.pool_index = 0
            b = ord(c) & 0xff
            bytes[self.pool_index] ^= b
            self.pool_index += 1
        self.pool = ''.join([chr(c) for c in bytes])

    def random_8(self):
        if self.digest is None or self.next_byte == self.hash_len:
            self.hash.update(self.pool)
            self.digest = self.hash.digest()
            self.stir(self.digest)
            self.next_byte = 0
        value = ord(self.digest[self.next_byte])
        self.next_byte += 1
        return value

    def random_16(self):
        return self.random_8() * 256 + self.random_8()

    def random_32(self):
        return self.random_16() * 65536 + self.random_16()

    def random_between(self, first, last):
        size = last - first + 1
        if size > 4294967296L:
            raise ValueError, 'too big'
        if size > 65536:
            rand = self.random_32
            max = 4294967295L
        elif size > 256:
            rand = self.random_16
            max = 65535
        else:
            rand = self.random_8
            max = 255
	return (first + size * rand() // (max + 1))

pool = EntropyPool()

def random_16():
    return pool.random_16()

def between(first, last):
    return pool.random_between(first, last)
