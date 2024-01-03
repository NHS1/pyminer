#!/usr/bin/python
#
# Copyright 2011 Jeff Garzik
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#

import time
import json
import pprint
import hashlib
import struct
import re
import base64
import http.client
import sys
from multiprocessing import Process

ERR_SLEEP = 15
MAX_NONCE = 1000000

settings = {}
pp = pprint.PrettyPrinter(indent=4)

class BitcoinRPC:
    OBJID = 1

    def __init__(self, host, port, username, password):
        authpair = "{}:{}".format(username, password)
        authhdr = "Basic {}".format(base64.b64encode(authpair.encode()).decode())
        self.conn = http.client.HTTPConnection(host, port, False, 30)
        self.authhdr = {'Authorization': authhdr, 'Content-type': 'application/json'}

    def rpc(self, method, params=None):
        BitcoinRPC.OBJID += 1
        obj = {'version': '1.1', 'method': method, 'id': BitcoinRPC.OBJID}

        if params is None:
            obj['params'] = []
        else:
            obj['params'] = params

        self.conn.request('POST', '/', json.dumps(obj), self.authhdr)
        resp = self.conn.getresponse()

        if resp is None:
            print("JSON-RPC: no response")
            return None

        body = resp.read()
        resp_obj = json.loads(body.decode())
        if resp_obj is None:
            print("JSON-RPC: cannot JSON-decode body")
            return None

        if 'error' in resp_obj and resp_obj['error'] is not None:
            return resp_obj['error']

        if 'result' not in resp_obj:
            print("JSON-RPC: no result in object")
            return None

        return resp_obj['result']

    def getblockcount(self):
        return self.rpc('getblockcount')

    def getwork(self, data=None):
        return self.rpc('getwork', data)

def uint32(x):
    return x & 0xffffffff

def bytereverse(x):
    return uint32(((x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24)))

def bufreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        word = struct.unpack('@I', in_buf[i:i + 4])[0]
        out_words.append(struct.pack('@I', bytereverse(word)))
    return b''.join(out_words)

def wordreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        out_words.append(in_buf[i:i + 4])
    out_words.reverse()
    return b''.join(out_words)

class Miner:
    def __init__(self, id):
        self.id = id
        self.max_nonce = MAX_NONCE

    def work(self, datastr, targetstr):
        static_data = bytes.fromhex(datastr)
        static_data = bufreverse(static_data)
        blk_hdr = static_data[:76]

        targetbin = bytes.fromhex(targetstr)[::-1]
        targetbin_str = targetbin.hex()
        target = int(targetbin_str, 16)

        static_hash = hashlib.sha256()
        static_hash.update(blk_hdr)

        for nonce in range(self.max_nonce):
            nonce_bin = struct.pack("<I", nonce)
            hash1_o = static_hash.copy()
            hash1_o.update(nonce_bin)
            hash1 = hash1_o.digest()

            hash_o = hashlib.sha256()
            hash_o.update(hash1)
            hash_val = hash_o.digest()

            if hash_val[-4:] != b'\0\0\0\0':
                continue

            hash_val = bufreverse(hash_val)
            hash_val = wordreverse(hash_val)

            hash_str = hash_val.hex()
            l = int(hash_str, 16)

            if l < target:
                print(time.asctime(), "PROOF-OF-WORK found: %064x" % (l,))
                return nonce + 1, nonce_bin
            else:
                print(time.asctime(), "PROOF-OF-WORK false positive %064x" % (l,))

        return nonce + 1, None

    def submit_work(self, rpc, original_data, nonce_bin):
        nonce_bin = bufreverse(nonce_bin)
        nonce = nonce_bin.hex()
        solution = original_data[:152] + nonce + original_data[160:256]
        param_arr = [solution]
        result = rpc.getwork(param_arr)
        print(time.asctime(), "--> Upstream RPC result:", result)

    def iterate(self, rpc):
        work = rpc.getwork()
        if work is None:
            time.sleep(ERR_SLEEP)
            return
        if 'data' not in work or 'target' not in work:
            time.sleep(ERR_SLEEP)
            return

        time_start = time.time()

        hashes_done, nonce_bin = self.work(work['data'], work['target'])

        time_end = time.time()
        time_diff = time_end - time_start

        self.max_nonce = int((hashes_done * settings['scantime']) / time_diff)
        if self.max_nonce > 0xfffffffa:
            self.max_nonce = 0xfffffffa

        if settings['hashmeter']:
            print("HashMeter({}): {} hashes, {:.2f} Khash/sec".format(
                self.id, hashes_done, (hashes_done / 1000.0) / time_diff))

        if nonce_bin is not None:
            self.submit_work(rpc, work['data'], nonce_bin)

    def loop(self):
        rpc = BitcoinRPC(settings['host'], settings['port'], settings['rpcuser'], settings['rpcpass'])
        if rpc is None:
            return

        while True:
            self.iterate(rpc)

def miner_thread(id):
    miner = Miner(id)
    miner.loop()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: pyminer.py CONFIG-FILE")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        for line in f:
            m = re.search('^\s*#', line)
            if m:
                continue

            m = re.search('^(\w+)\s*=\s*(\S.*)$', line)
            if m is None:
                continue
            settings[m.group(1)] = m.group(2)

    if 'host' not in settings:
        settings['host'] = '127.0.0.1'
    if 'port' not in settings:
        settings['port'] = 8332
    if 'threads' not in settings:
        settings['threads'] = 1
    if 'hashmeter' not in settings:
        settings['hashmeter'] = 0
    if 'scantime' not in settings:
        settings['scantime'] = 30
    if 'rpcuser' not in settings or 'rpcpass' not in settings:
        print("Missing username and/or password in cfg file")
        sys.exit(1)

    settings['port'] = int(settings['port'])
    settings['threads'] = int(settings['threads'])
    settings['hashmeter'] = int(settings['hashmeter'])
    settings['scantime'] = int(settings['scantime'])

    thr_list = []
    for thr_id in range(settings['threads']):
        p = Process(target=miner_thread, args=(thr_id,))
        p.start()
        thr_list.append(p)
        time.sleep(1)

    print("{} mining threads started".format(settings['threads']))

    print(time.asctime(), "Miner Starts - {}:{}".format(settings['host'], settings['port']))
    try:
        for thr_proc in thr_list:
            thr_proc.join()
    except KeyboardInterrupt:
        pass
    print(time.asctime(), "Miner Stops - {}:{}".format(settings['host'], settings['port']))
