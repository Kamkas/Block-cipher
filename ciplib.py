import hashlib
from itertools import cycle
from random import Random
import numpy as np
from numpy import linalg


class SubsCipherAlgo:
    def __init__(self, key):
        self.key = key
        self.table = list()
        self.clean_rand = Random()

    def gen_table(self, bytes_number, cols):
        r = Random()
        r.seed(self.key)
        table = list(range(1, (2 ** (bytes_number * 8)) * cols))
        r.shuffle(table)
        self.table = [table[index: index + cols] for index in range(0, len(table), cols)]

    def encrypt(self, block, round_key):
        self.clean_rand.seed(round_key)
        return chr(self.clean_rand.choice(self.table[block]))

    def decrypt(self, enc_block, round_key):
        dec_block = 0
        while dec_block < len(self.table):
            if enc_block in self.table[dec_block]:
                break
            dec_block += 1
        return dec_block


class MatrixCipher:
    def __init__(self, key, side):
        key_list = [ord(ch) for ch in key]
        self.key_matrix = np.array(key_list).reshape(side, side)

    def encrypt(self, input_matrix):
        return np.matmul(self.key_matrix, input_matrix.reshape(4, 1))

    def decrypt(self, input_matrix):
        return np.matmul(linalg.inv(self.key_matrix), input_matrix)


class VigenerCipher:
    def __init__(self):
        self.alph_size = 2 ** 16

    def encrypt(self, block_item, sub_key):
        return (block_item + sub_key) % self.alph_size

    def decrypt(self, block_item, sub_key):
        return (block_item - sub_key) % self.alph_size


class StandartEncryptionModes:
    def __init__(self, key, block_len):
        self.key = self.key256(str(key).encode('utf-8'))
        self.block_len = block_len

    def __get_iter_key(self):
        key_cycle = cycle(iter(self.key))
        for sub_key in key_cycle:
            yield ord(sub_key)

    def __get_block_stream(self, text_stream):
        iter_flag = True
        while iter_flag:
            block = []
            try:
                for i in range(self.block_len):
                    block.append(next(text_stream))
            except StopIteration:
                while len(block) < self.block_len and len(block) is not 0:
                    block.append(32)
                iter_flag = False
            if len(block) is not 0:
                yield block

    def ecb_crypt(self, text_stream, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        yield from [subc_f(item, next(kstream)) for block in bstream for item in block]

    def cbc_encrypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        temp = None
        for block in bstream:
            temp = [subc_f(item, next(kstream))
                          for item in [(item1 ^ item2) for item1, item2 in zip(init_block, block)]]
            init_block = iter(temp)
            yield from temp

    def cbc_decrypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        for block in bstream:
            yield from [item1 ^ item2
                        for item1, item2 in zip(init_block, [subc_f(item, next(kstream)) for item in block])]
            init_block = block

    def cfb_encrypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        for block in bstream:
            init_block = [item1 ^ item2
                          for item1, item2 in zip(block, [subc_f(item, next(kstream)) for item in init_block])]
            yield from init_block

    def cfb_decrypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        for block in bstream:
            yield from [item1 ^ item2
                        for item1, item2 in zip(block, [subc_f(item, next(kstream)) for item in init_block])]
            init_block = block

    def ofb_crypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        for block in bstream:
            init_block = [subc_f(item, next(kstream)) for item in init_block]
            yield from [item1 ^ item2 for item1, item2 in zip(block, init_block)]

    @staticmethod
    def key256(key):
        return hashlib.sha256(key).hexdigest()


class FeistelNet:
    def __init__(self, key, block_len, rounds_number, sub_cipher):
        self.key = self.key256(str(key).encode('utf-8'))
        self.block_len = block_len
        self.rounds_number = rounds_number
        # self.sub_cipher = MatrixCipher(self.key[0:(block_len // 2) ** 2], self.block_len // 2)
        self.sub_cipher = sub_cipher

    def f_round(self, prev_lblock, prev_rblock, sub_key, func):
        next_rblock = prev_lblock
        next_lblock = [item1 ^ item2
                       for item1, item2 in zip(prev_rblock, [func(item, sub_key) for item in prev_lblock])]
        return next_lblock, next_rblock

    def __get_block_stream(self, text_stream):
        iter_flag = True
        while iter_flag:
            block = []
            try:
                for i in range(self.block_len):
                    block.append(next(text_stream))
            except StopIteration:
                while len(block) < self.block_len and len(block) is not 0:
                    block.append(32)
                iter_flag = False
            if len(block) is not 0:
                yield block

    def __get_iter_key(self):
        key_cycle = cycle(iter(self.key))
        for sub_key in key_cycle:
            yield ord(sub_key)

    def __get_reversed_iter_key(self):
        key_stream = self.__get_iter_key()
        reversed_key_stream = [next(key_stream) for _ in range(self.rounds_number)]
        yield from reversed(reversed_key_stream)

    def encrypt(self, text_stream):
        bstream = self.__get_block_stream(text_stream)
        kstream = self.__get_iter_key()
        for block in bstream:
            prev_lblock, prev_rblock = block[0: self.block_len // 2], block[self.block_len // 2: self.block_len]
            for index in range(1, self.rounds_number + 1):
                prev_lblock, prev_rblock = self.f_round(prev_lblock, prev_rblock, next(kstream), self.sub_cipher.encrypt)
            yield from (prev_lblock + prev_rblock)

    def decrypt(self, enc_text_stream):
        enc_block_stream = self.__get_block_stream(enc_text_stream)
        kstream = self.__get_reversed_iter_key()
        for block in enc_block_stream:
            prev_lblock, prev_rblock = block[0: self.block_len // 2], block[self.block_len // 2: self.block_len]
            for index in range(self.rounds_number - 1, 0, -1):
                prev_lblock, prev_rblock = self.f_round(prev_lblock, prev_rblock, next(kstream), self.sub_cipher.encrypt)
            yield (prev_lblock + prev_rblock)

    @staticmethod
    def key256(key):
        return hashlib.sha256(key).hexdigest()


if __name__ == '__main__':
    key = 'a'
    bytes_number = 2
    rounds = 2
    cols = 6
    text = 'AB'
    t = iter(map(ord, text))
    vc = VigenerCipher()
    f = FeistelNet(key, bytes_number, rounds, vc)

    print(f.key, len(f.key))
    # enc_t = f.encrypt(t)
    # et = [_ for _ in enc_t]
    # dec_t = f.decrypt(iter(et))
    #
    # dt = [_ for _ in dec_t]

    # orig_text = ''.join([chr(item) for item in dt])
    pass
