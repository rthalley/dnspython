#!/usr/bin/python
import argparse
import sys

import dns.exception
import dns.message


def main():
    parser = argparse.ArgumentParser(
        description="Read sequence of DNS wire formats prefixed with 2-byte "
        "length field - like from TCP socket - and print the messages. This "
        "format is used e.g. by dnsperf -B option and dnsgen."
    )
    parser.add_argument("infile")
    args = parser.parse_args()
    ok_msgs = 0
    bad_msgs = 0

    with open(args.infile, "rb") as infile:
        while True:
            offset = infile.tell()
            len_wire = infile.read(2)
            if len(len_wire) == 0:  # end of file - expected
                break
            if len(len_wire) == 1:
                raise ValueError("incomplete length preamble, offset", offset)
            len_msg = int.from_bytes(len_wire, byteorder="big", signed=False)
            print(f"; msg offset 0x{offset + 2:x}, length {len_msg} bytes")
            msg_wire = infile.read(len_msg)
            if len(msg_wire) != len_msg:
                raise ValueError(
                    f"incomplete message: expected {len_msg} != got {len(msg_wire)}, "
                    f"length field offset 0x{offset:x}",
                )
            try:
                msg = dns.message.from_wire(msg_wire)
                ok_msgs += 1
                print(msg)
            except dns.exception.DNSException as ex:
                print(f"; invalid message, skipping: {ex}")
                bad_msgs += 1
        print(f"; read {ok_msgs} valid and {bad_msgs} invalid messages")
        if bad_msgs:
            sys.exit(1)


if __name__ == "__main__":
    main()
