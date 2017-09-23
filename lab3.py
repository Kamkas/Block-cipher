import sys, datetime

class BlockCipherUtil():

    def __init__(self, key, block_size, input_file, output_file):
        self.key = key
        self.input_file = input_file
        self.output_file = output_file
        self.block_size = block_size

    @staticmethod
    def progress_bar(count, total, suffix=''):
        bar_len = 60
        filled_len = int(round(bar_len * count / float(total)))
        percents = round(100.0 * count / float(total), 1)
        bar = '=' * filled_len + '-' * (bar_len - filled_len)

        sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', suffix))
        sys.stdout.flush()

    def read_from_file(self):
        text = ""
        with open(self.input_file, 'r') as f:
            text = f.read()
            f.close()
        return text

    def write_to_file(self, text):
        with open(self.output_file, 'w+') as f:
            f.write(text)
            f.close()

    