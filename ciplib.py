import hashlib
from random import Random


class SubsCipherAlgo:
    def __init__(self, key):
        self.key = key
        self.table = list()
        self.clean_rand = Random()

    def gen_table(self, bytes_number, cols):
        r = Random()
        r.seed(self.key)
        table = r.shuffle(range(1, (2 ** (bytes_number * 8)) * cols))
        self.table = [table[index: index + cols] for index in range(start=0, stop=len(table), step=cols)]

    def encrypt(self, block):
        return self.clean_rand.choice(self.table[block])

    def decrypt(self, enc_block):
        dec_block = 0
        while dec_block < len(self.table):
            if enc_block in self.table[dec_block]:
                break
            dec_block += 1
        return dec_block


class FeistelNet:
    def __init__(self, key, block_len, rounds_number):
        self.key = self.key256(key)
        self.block_len = block_len
        self.rounds_number = rounds_number

    def encrypt(self, text, func):
        text_blocks = [text[index: index + self.block_len] for index in range(0, len(text), self.block_len)]
        encrypt_text = list()
        len_last_block = len(text_blocks[len(text_blocks) - 1])
        if len_last_block < self.block_len:
            for i in range(len_last_block, self.block_len):
                text_blocks[len(text_blocks) - 1] += " "
        for block in text_blocks:
            lblocks, rblocks = list(), list()
            lblocks[0], rblocks[0] = block[0: self.block_len / 2], block[self.block_len / 2: self.block_len]
            for index in range(1, self.rounds_number + 1):
                rblocks[index] = lblocks[index - 1]
                round_key = self.sub_key(rblocks[index], self.key)
                if index is 1:
                    round_key = self.key
                lblocks[index] = func(lblocks[index - 1], round_key)
                lblocks[index] = self.xor(lblocks[index], rblocks[index - 1])
            encrypt_text.append(lblocks[self.rounds_number] + rblocks[self.rounds_number])
        return "".join(encrypt_text)

    def decrypt(self, encrypt_text, func):
        enc_text_blocks = [
            encrypt_text[index: index + self.block_len] for index in range(0, len(encrypt_text), self.block_len)]
        text = list()
        for block in enc_text_blocks:
            lblocks, rblocks = [""] * (self.rounds_number + 1), [""] * (self.rounds_number + 1)
            lblocks[self.rounds_number] = block[0: self.block_len / 2]
            rblocks[self.rounds_number] = block[self.block_len / 2: self.block_len]
            for index in range(self.rounds_number, 0, -1):
                rblocks[index] = lblocks[index + 1]
                round_key = self.sub_key(rblocks[index], self.key)
                if index is 1:
                    round_key = self.key
                lblocks[index] = func(lblocks[index + 1], round_key)
                lblocks[index] = self.xor(lblocks[index], rblocks[index + 1])
            text.append(lblocks[0] + rblocks[0])
        return "".join(text)

    # def feistel_round(self, lblock, rblock, sub_key, func):
    #     new_rblock = lblock
    #     new_lblock = func(lblock, sub_key)
    #     new_lblock = self.xor(new_lblock, rblock)
    #     return new_lblock, new_rblock

    @staticmethod
    def key256(key):
        return hashlib.sha256(key).hexdigest()

    @staticmethod
    def sub_key(str1, str2):
        return hashlib.sha256(str1 + str2).hexdigest()

    @staticmethod
    def xor(str1, str2):
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(str1, str2))
