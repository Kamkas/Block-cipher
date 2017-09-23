import hashlib


class SubsCipherAlgo(object):

    def __init__(self, key):
        self.key = key
        self.table = list()

    def gen_table(self, bytes_number, cols):
        if not self.table:
            for i in range(2**(bytes_number * 8)):
                self.table.append([i * cols + j for j in range(cols)])


class FeistelNet(object):
    """docstring for FeistelNet"""

    def __init__(self, key, block_len, rounds_number):
        super(FeistelNet, self).__init__()
        self.key = self.key256(key)
        self.block_len = block_len
        self.rounds_number = rounds_number

    def encrypt(self, text):
        for i in range():

    def f_round(self, lblock, rblock, sub_key, func):
        new_rblock = lblock

    def key256(self, key):
        return hashlib.sha256(key).hexdigest()

    @staticmethod
    def sub_key(str1, str2):
        return hashlib.sha256(str1 + str2).hexdigest()

    @staticmethod
    def str_to_bin(str1):
    	return ''.join('{:016b}'.format(ord(c)) for c in s)

    @staticmethod
    def bin_to_int(str1):
    	return int(str1, 2)

    @staticmethod
    def xor(str1, str2):
    	return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(str1, str2))

    @staticmethod
    def scramble(str1, i, sub_key):
    	str1 = str_to_bin(str(str1))
    	sub_key = str_to_bin(sub_key)

    @staticmethod
    def bin_to_str(binary):
    	