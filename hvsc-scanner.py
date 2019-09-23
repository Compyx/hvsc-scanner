#!/usr/bin/env python3
# vim: set et ts=4 sw=4 sts=4 fdm=marker:

"""
A simple tool to scan the High Voltage SID Collection for SIDs that match
certain specifications.
"""

import argparse
import os
import os.path
from pprint import pprint
import sys


class HVSCReader(dict):
    """
    Scans the HVSC for SID files
    """

    # Header constants
    #
    # All words and dwords are big-endian, unless otherwise noted

    _HDR_LENGTH = 0x7c

    _HDR_MAGIC = 0x00       # Header magic
    _HDR_MAGIC_LEN = 4      # Length of header magic
    _HDR_VERSION = 0x04     # PSID/RSID version number (word)
    _HDR_OFFSET = 0x06      # Offset in .sid file of binary data
    _HDR_LOAD = 0x08        # SID load address (word)
    _HDR_INIT = 0x0a        # SID init address (word)
    _HDR_PLAY = 0x0c        # SID play address (word)
    _HDR_SONGS = 0x0e       # Number of songs in the SID
    _HDR_START_SONG = 0x10  # Starting song (word)
    _HDR_SPEED = 0x12       # Speed bits (dword)

    # These fields are 32 bytes, padding with 0x00, but not 0x00-terminated
    # in case a string happens to be 32 bytes

    _HDR_NAME = 0x16        # SID title field
    _HDR_NAME_LEN = 32      # Length of SID title field
    _HDR_AUTHOR = 0x36      # SID author field
    _HDR_AUTHOR_LEN = 32    # Length of SID author field
    _HDR_RELEASED = 0x56    # Released/Copyright field
    _HDR_RELEASED_LEN = 32  # Length of Released/Copyright field

    # PSID v2+ ONLY
    _HDR_FLAGS = 0x76       # Extra information:
                            #
                            # bit 0:    musplayer binary data format
                            #           (0 = built-in player, 1 = MUS data)
                            # bit 1:    PlaySID specific



    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, value):
        self._debug = value

    @debug.deleter
    def debug(self):
        del self._debug


    def __init__(self, hvsc_root):
        super().__init__()
        self._hvsc_root = hvsc_root
        self._sids = dict()
        self._data = None
        self._header = None
        self._debug = False

    def _get_word_be(self, offset):
        return self._data[offset + 0] * 256 + self._data[offset + 1]

    def _get_word_le(self, offset):
        return self._data[offset + 1] * 256 + self._data[offset + 0]

    def _get_dword_be(self, offset):
        return (self._data[offset + 0] * 256 * 256 * 256 +
                self._data[offset + 1] * 256 * 256 +
                self._data[offset + 2] * 256 +
                self._data[offset + 3])


    def _get_load_addr(self):
        load = self._get_word_be(self._HDR_LOAD)
        if load > 0:
            return load
        return self._get_word_le(self._header['dataOffset'])

    def _get_binary_size(self, path):
        """
        Determine size of SID binary (without 2-byte load address)
        """
        # get total size of .sid file
        size = os.path.getsize(path)
        # subtract header size
        size -= self._header['dataOffset']
        # subtract load address if in binary
        if self._get_word_be(self._HDR_LOAD) == 0:
            size -= 2
        return size

    def _parse_sid_header(self, f):
        """
        Parse SID header

        :param f: file

        :return dict with SID header data
        """
        with open(f, "rb") as sid:
            # read header and a possible load address in the binary data
            self._data = sid.read(self._HDR_LENGTH + 2)
            self._header = {
                    'path': f,
                    'magicID': self._data[self._HDR_MAGIC:
                        self._HDR_MAGIC + self._HDR_MAGIC_LEN],
                    'version': self._get_word_be(self._HDR_VERSION),
                    'dataOffset': self._get_word_be(self._HDR_OFFSET),
            }
            self._header['loadAddress'] = self._get_load_addr()
            self._header['initAddress'] = self._get_word_be(self._HDR_INIT)
            self._header['playAddress'] = self._get_word_be(self._HDR_PLAY)
            self._header['size'] = self._get_binary_size(f)
            self._header['songs'] = self._get_word_be(self._HDR_SONGS)
            self._header['startSong'] = self._get_word_be(self._HDR_START_SONG)
            self._header['speed'] = self._get_dword_be(self._HDR_SPEED)

            self._header['name'] = self._data[self._HDR_NAME:
                    self._HDR_NAME + self._HDR_NAME_LEN]
            self._header['author'] = self._data[self._HDR_AUTHOR:
                    self._HDR_AUTHOR + self._HDR_AUTHOR_LEN]
            return self._header


    def scan(self):
        if self._debug:
            print("scanning {} for SIDs".format(self._hvsc_root))
        for root, dirs, files in os.walk(self._hvsc_root):
            if self._debug:
                print(".. scanning '{}'".format(root))
            for f in files:
                if f[-4:] == '.sid':
                    path = os.path.join(root, f)
                    self._sids[path] = self._parse_sid_header(path)

        if self._debug:
            print("Got {} SIDS.".format(len(self._sids)))



    def _filter_dimensions(self, p, load, end, size):
        """
        Filter out SIDs
        """
        sid = self._sids[p]
        #if self.debug:
        #    print(".... checking '{}'".format(p))

        binsize = sid['size']

        if size > 0:
            if binsize > size:
                return False

        binend = sid['loadAddress'] + binsize

        #print("binsize = ${:04x}, binend = ${:04x}".format(binsize, binend))

        if load > 0:
            if self._debug:
                print("matching load ${:04x} against sid['loadAddress'] ${:04x}".format(load, sid['loadAddress']))

            if sid['loadAddress'] < load:
                return False

        if end > 0:
            if self._debug:
                print("matching end ${:04x} against bined ${:04x}".format(
                    end, binend))

            if  binend > end:
                return False

        return True

    def print_sid(self, p):
        sid = self._sids[p]
        print("${:04x}-${:04x}\t{}".format(
            sid['loadAddress'],
            sid['loadAddress'] + sid['size'] - 1,
            p))


    def filter(self, args):
        """
        Filter out SIDs
        """
        for p in self._sids:
            match = True

            # filter on load/end/size?
            if args.load > 0 or args.end > 0 or args.size > 0:
                if not self._filter_dimensions(p, args.load, args.end, args.size):
                    match = False


            if match:
                self.print_sid(p)


def main():
    """
    Program driver
    """

    # setup command line parser
    parser = argparse.ArgumentParser()

    # Path to scan
    parser.add_argument(
            '-p', '--path',
            help="Path to SID files",
            default='D:\C64Music',
            action='store')

    # Debug mode
    parser.add_argument(
            '-d', '--debug',
            help="output debugging info",
            default=False,
            action='store_true')
    # Load address, 0 = unspecified
    parser.add_argument(
            '-l', '--load',
            help="set load address",
            type=lambda x: int(x, 0),
            default=0,
            action='store')
    # End address, 0 = unspecified
    parser.add_argument(
            '-e', '--end',
            help="set end address",
            type=lambda x: int(x, 0),
            default=0,
            action='store')
    # Size, 0 = unspecified
    parser.add_argument(
            '-s', '--size',
            help="set binary size",
            type=lambda x: int(x, 0),
            default=0,
            action='store')

    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()

    parser.parse_args()

    args = parser.parse_args()
    pprint(args)

    # TODO: check args for invalid situations


    hvsc = HVSCReader(args.path)
    hvsc.debug = args.debug
    hvsc.scan()
    hvsc.filter(args)


if __name__ == '__main__':
    main()
