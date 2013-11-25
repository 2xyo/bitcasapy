#!/usr/bin/env python
# coding: utf-8

from __future__ import unicode_literals, print_function


import argparse
import os
import sys
import re

from pprint import pprint
from bitcasa import BitcasaClient
from path import path


def wordlist_to_regex(words):
    escaped = map(re.escape, words)
    combined = '|'.join(sorted(escaped, key=len, reverse=True))
    return re.compile(combined)


def filename_is_compliant(filename):
    if filename.name.startswith("."):
        return False

    r = wordlist_to_regex(["<", ">", ":", "\"", "/", "\\", "|", "?", "*"])

    if r.search(filename.name):
        return False

    return True


def get_path(bitcasa, dst_path):
    dst = path(dst_path)
    if not str(dst).startswith("/"):
        print("Destination name must be absolute.")
        print("/cats/dogs")
        sys.exit(0)

    bitcasa_path = "/"
    virtual_path = ""
    for d in dst.abspath().splitall():
        if str(d) == "/":
            continue
        r = bitcasa.post(
            'folders' + bitcasa_path, data="folder_name=" + str(d))
        bitcasa_path = r.json()['result']['items'][0]['path']
        virtual_path += "/" + str(d)
        print(virtual_path + " > " + bitcasa_path)

    return bitcasa_path


def uplaod(bitcasa, src_path, dst_path):

    for f in src_path.listdir():
        if filename_is_compliant(f.name):
            if f.isfile():
                with f.open() as fo:
                    print("Upload {} in {} ".format(f, dst_path))
                    r = bitcasa.put(
                        'files' + dst_path, files={"file": (fo.name, fo)})
                    pprint(r)

            elif f.isdir():
                print("Create {} in {} ".format(f, dst_path))
                r = bitcasa.post(
                    'folders' + dst_path, data="folder_name=" + f.name)
                pprint(r)
                uplaod(bitcasa, f, r.json()['result']['items'][0]['path'])
            else:
                print('Error {}'.format(f))


def main():
    client_id = os.environ.get("BITCASA_CLIENT_ID", "")
    client_secret = os.environ.get("BITCASA_CLIENT_SECRET", "")
    access_token = os.environ.get("BITCASA_ACCESS_TOKEN", "")

    assert client_id, 'Please set "BITCASA_CLIENT_ID".'
    assert client_secret, 'Please set "BITCASA_CLIENT_SECRET".'
    assert access_token, 'Please set "BITCASA_ACCESS_TOKEN".'

    bitcasa = BitcasaClient(client_id, client_secret, access_token)

    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('src', nargs=1, help='Source directory or filename')
    parser.add_argument('dst', nargs=1, help='Destination directory')
    args = parser.parse_args()

    src = path(args.src[0])
    dst = get_path(bitcasa, path(args.dst[0]))

    uplaod(bitcasa, src, dst)


if __name__ == '__main__':
    sys.exit(main())
