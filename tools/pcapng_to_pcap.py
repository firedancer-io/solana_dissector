#!/usr/bin/env python3

import argparse
import struct


def recover_pcapng(output_file, input_file):
    output_file.write(struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65603, 147))

    endian = "!"
    while True:
        start = input_file.tell()
        data = input_file.read(8)
        if not data:
            break
        block_type, block_sz = struct.unpack(endian + "II", data)
        if block_type == 0x0A0D0D0A:
            endian_magic = struct.unpack("!I", input_file.read(4))[0]
            input_file.seek(-8, 1)
            if endian_magic == 0x1A2B3C4D:
                endian = "!"
            else:
                endian = "<"
            block_sz = struct.unpack(endian + "I", input_file.read(4))[0]
        end = start + block_sz
        if start == end:
            raise ValueError("small block_sz")
        if block_type == 3:
            len = struct.unpack(endian + "I", input_file.read(4))[0]
            payload = input_file.read(len)
            output_file.write(struct.pack("!IIII", 0, 0, len, len))
            output_file.write(payload)
        input_file.seek(end, 0)


def check_input_file(inf):
    magic_number = inf.read(4)
    if magic_number != b"\x0a\x0d\x0d\x0a":
        raise ValueError("Input file is not a valid pcapng file")
    inf.seek(0)
    pass


def main():
    parser = argparse.ArgumentParser(description="Recover corrupt pcapng file (lossy)")
    parser.add_argument(
        "--input", type=str, required=True, help="Path to pcapng input file"
    )
    parser.add_argument(
        "--output", type=str, required=True, help="Path to pcap output file"
    )
    args = parser.parse_args()

    with open(args.input, "rb") as input_file:
        check_input_file(input_file)
        with open(args.output, "wb") as output_file:
            recover_pcapng(output_file, input_file)


if __name__ == "__main__":
    main()
