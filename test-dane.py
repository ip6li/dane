#!/usr/bin/env python3

from subprocess import run, Popen, PIPE, STDOUT, TimeoutExpired
import sys, os
import re

def get_tlsa(query):
  cmd = [
    "host",
    "-t",
    "tlsa",
    query
  ]
  tlsa_rr = re.compile(query + '\s+has TLSA record\s+(.+)')
  process = Popen(cmd, shell=False, stdout=PIPE, stderr=PIPE)
  try:
    reply, err = process.communicate(timeout=15)
    process.terminate()
    m = tlsa_rr.search(reply.decode("utf-8"))
    return m.group(1)
  except TimeoutExpired:
    proc.kill()
    reply, errs = proc.communicate()
    print("error")

def test_tlsa(host, port, proto, openssl_args):
  query = "_" + str(port) + "._" + proto + "." + host
  tlsa_rr = get_tlsa(query)
  cmd = [
    "openssl",
    "s_client",
    "-servername",
    host,
    "-connect",
    host + ":" + str(port),
    "-showcerts",
    "-dane_tlsa_domain",
    host,
    "-dane_tlsa_rrdata",
    tlsa_rr
  ]
  for arg in openssl_args:
    cmd.append(arg)

  process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
  try:
    reply, err = process.communicate(b"\n", timeout=15)
    process.terminate()
    return reply.decode("utf-8")
  except TimeoutExpired:
    proc.kill()
    reply, errs = proc.communicate()

host = sys.argv[1]
port = sys.argv[2]
args = sys.argv[3:]
res = test_tlsa(host, port, "tcp", args)
print(res)

