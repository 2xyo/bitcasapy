#!/usr/bin/env python
# coding: utf-8

from __future__ import unicode_literals, print_function

import argparse
import os
import re
import sys

if sys.version_info.major == 3:
    print("Python 3.x is not supported (thanks to poster)")
    sys.exit(1)

from bitcasa import BitcasaClient
from path import path
from poster.encode import multipart_encode, MultipartParam, encode_and_quote
from poster.streaminghttp import register_openers
from pprint import pprint
from urllib2 import urlopen
from urllib2 import Request
from urllib2 import HTTPError, URLError


path_cache = {}


class MultipartParamFixed(MultipartParam):

    def __init__(self, *args, **kwargs):
        super(MultipartParamFixed, self).__init__(*args, **kwargs)

    def encode_hdr(self, boundary):
        """Returns the header of the encoding of this parameter"""
        boundary = encode_and_quote(boundary)

        headers = ["--%s" % boundary]

        disposition = 'form-data; name="file"; filename="%s"' % self.name

        headers.append("Content-Disposition: %s" % disposition)

        headers.append("")
        headers.append("")

        return "\r\n".join(headers)


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

    try:
        return path_cache[dst_path]
    except KeyError:
        pass

    dst = path(dst_path)
    if not str(dst).startswith("/"):
        print("Destination name must be absolute.")
        print("/cats/dogs")
        sys.exit(1)

    bitcasa_path = "/"
    virtual_path = ""

    for d in dst.abspath().splitall():
        if str(d) == "/":
            continue
        r = bitcasa.post(
            'folders' + bitcasa_path, data="folder_name=" + str(d))
        bitcasa_path = r.json()['result']['items'][0]['path']
        virtual_path += "/" + str(d)
        path_cache[virtual_path] = bitcasa_path
        print("Get path {} > {}".format(virtual_path, bitcasa_path))

    return bitcasa_path


def upload_file(bitcasa, f, dst_path, r):

    register_openers()

    datagen, headers = multipart_encode(
        [MultipartParamFixed(f.name, fileobj=f.open("rb"))])

    url = "https://files.api.bitcasa.com/v1/files{}?access_token={}".format(get_path(bitcasa, dst_path), r.request.headers['Authorization'].split()[1])
    request = Request(url, datagen, headers)
    request.add_header('Authorization', r.request.headers['Authorization'])

    try:
        resp = urlopen(request)
        print("Upload file OK {} > {}/{}".format(f, dst_path, f.name))
    except (HTTPError, URLError) as e:
        print("Upload file KO {} > {}/{}".format(f, dst_path, f.name))
        pprint(e.__dict__)


def upload(bitcasa, src_path, dst_path):

    print("Upload {} > {}".format(src_path, dst_path))

    r = bitcasa.get('folders/')

    for f in src_path.abspath().listdir():
        if filename_is_compliant(f.name):
            if f.isfile():
                upload_file(bitcasa, f, dst_path, r)
            elif f.isdir():
                slash = "/" if not dst_path.abspath().endswith("/") else ""
                remote = dst_path.abspath() + slash + f.name
                print('Upload dir  > {}'.format(remote))
                upload(bitcasa, f, remote)
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
    dst = path(args.dst[0])

    upload(bitcasa, src, dst)


if __name__ == '__main__':
    sys.exit(main())
