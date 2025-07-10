import io
import zipfile
import gzip

# 192.168.56.10  236db34b-f482-470f-bcd8-8c8670259d4c    file    \\192.168.56.10\testfile.txt  2023-07-18 11:10:20.061370      4070    4.0KiB          None
def parse_fileobj(f:io.TextIOWrapper):
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            target, _, otype, path, _, size, _, _ = line.split()
            yield (target, otype, path, size)
        except Exception as e:
            print(f"Error parsing line: {line}")
            print(f"Error: {e}")
            continue
        

def parse_zip(file_path):
    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        for file in zip_ref.namelist():
            with zip_ref.open(file) as binary_file:
                # Convert binary file to text mode
                text_file = io.TextIOWrapper(binary_file, encoding='utf-8')
                yield from parse_fileobj(text_file)
            
            
def parse_gzip(file_path):
    with gzip.open(file_path, 'rt') as f:
        yield from parse_fileobj(f)
        
def parse_tsv(file_path):
    with open(file_path, 'r') as f:
        yield from parse_fileobj(f)

def parse_file(file_path):
    if file_path.endswith('.zip'):
        return parse_zip
    elif file_path.endswith('.gz'):
        return parse_gzip
    elif file_path.endswith('.tsv'):
        return parse_tsv
    else:
        raise ValueError(f"Unsupported file extension: {file_path}. Please use .zip, .gz, or .tsv")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, required=True)
    args = parser.parse_args()
    for result in parse_file(args.file):
        print(result)

if __name__ == "__main__":
    main()

