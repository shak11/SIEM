import csv


# Basic file IO
class FileIO:

    def __init__(self, file_name, mode):
        self.f = open(file_name, mode, newline='')
        self.w = csv.writer(self. f)

    def write_to_file(self, line):
        self.w.writerow(line)

    def close_file(self):
        self.f.close()
