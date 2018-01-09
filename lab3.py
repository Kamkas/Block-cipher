import datetime
import os
import random
import sys

from ciplib import VigenerCipher, StandartEncryptionModes


class BlockCipherUtil:
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.text_len = os.stat(input_file).st_size
        self.exec_time = 0

    @staticmethod
    def progress_bar(count, total, suffix=''):
        bar_len = 60
        filled_len = int(round(bar_len * count / float(total)))
        percents = round(100.0 * count / float(total), 1)
        bar = '=' * filled_len + '-' * (bar_len - filled_len)
        sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', suffix))
        sys.stdout.flush()

    def read_from_file(self, mode='r'):
        text = ""
        with open(self.input_file, mode, newline='') as f:
            text = iter(map(ord, f.read()))
            f.close()
        return text

    def write_to_file(self, text, mode='w+'):
        start = datetime.datetime.now()
        with open(self.output_file, mode, newline='') as f:
            for index, ch in enumerate(text):
                f.write(ch)
                self.progress_bar(index, self.text_len)
            f.close()
        end = datetime.datetime.now()
        self.exec_time = end - start

    def check_pass(self, key):
        first64_chars = self.read_from_file('r')
        from_file_key = ''.join([chr(next(first64_chars)) for _ in range(64)])
        check_flag = False
        if key == from_file_key:
            check_flag = True
        return first64_chars, check_flag


if __name__ == '__main__':
    print("Block cipher Encryption/Decryption utility.\n Using Vigener Cipher.\nQuit - Ctrl+C\n")
    while True:
        try:
            vc = VigenerCipher()
            print("""
        Enter cipher mode of operation:
            1. ECB
            2. CBC
            3. CFB
            4. OFB
                """)
            mode = int(input("Enter cipher mode: "))
            print("""
        Encrypt/Decrypt:
            encrypt - 'e', decrypt - 'd'
                """)
            crypt_direction = input("Enter (e/d): ")
            key = input("Enter key: ")
            block_len = int(input("Enter block length (>= 1): "))
            input_file_name = input("Enter input file name:")
            output_file_name = input("Enter output file name:")
            stm = StandartEncryptionModes(key, block_len)
            mode_dict = {
                'e': {
                    1: [stm.ecb_crypt, vc.encrypt],
                    2: [stm.cbc_encrypt, vc.encrypt],
                    3: [stm.cfb_encrypt, vc.encrypt],
                    4: [stm.ofb_crypt, vc.encrypt],
                },
                'd': {
                    1: [stm.ecb_crypt, vc.decrypt],
                    2: [stm.cbc_decrypt, vc.decrypt],
                    3: [stm.cfb_decrypt, vc.encrypt],
                    4: [stm.ofb_crypt, vc.encrypt],
                }
            }
            bcu = BlockCipherUtil(input_file_name, output_file_name)
            r_init = random.Random()
            r_init.seed(stm.key)
            init_block = (r_init.randint(1, 256) for _ in range(stm.block_len))

            if crypt_direction is 'e':
                print("Start encryption...")
                bcu.write_to_file(iter(stm.key), 'w')
                text = bcu.read_from_file()
                enc_stream = None
                if mode is 1:
                    enc_stream = mode_dict[crypt_direction][mode][0](text, mode_dict[crypt_direction][mode][1])
                else:
                    enc_stream = mode_dict[crypt_direction][mode][0](text, init_block,
                                                                     mode_dict[crypt_direction][mode][1])
                bcu.write_to_file(iter(map(chr, enc_stream)), 'a+')
                print("\nEnd encryption.")
                print("\nEncryption speed: {0} chars/ms".format(
                        (bcu.exec_time.seconds * 10 ** 6 + bcu.exec_time.microseconds) / bcu.text_len))
            if crypt_direction is 'd':
                print("Start decryption...")
                text, is_pass = bcu.check_pass(stm.key)
                dec_stream = None
                if is_pass:
                    if mode is 1:
                        dec_stream = mode_dict[crypt_direction][mode][0](text, mode_dict[crypt_direction][mode][1])
                    else:
                        dec_stream = mode_dict[crypt_direction][mode][0](text, init_block,
                                                                         mode_dict[crypt_direction][mode][1])
                    bcu.write_to_file(iter(map(chr, dec_stream)))
                    print("\nEnd decryption.")
                    print("\nDecryption speed: {0} chars/ms".format(
                        (bcu.exec_time.seconds * 10 ** 6 + bcu.exec_time.microseconds) / bcu.text_len))
                else:
                    print("\nPassword you\'ve entered is wrong!")
            else:
                print("\nWrong crypt mode!")
        except KeyboardInterrupt:
            print("\nQuit!")
            break
        except FileNotFoundError as fnf_err:
            print("\n" + fnf_err.filename + "not found!")
