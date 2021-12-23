#!/usr/bin/env python3

from subprocess import run, Popen, PIPE, STDOUT, TimeoutExpired
import sys, os
import re
import tempfile

def main(host, port, proto, openssl_args):
  cmd = [
    "openssl",
    "s_client",
    "-servername",
    host,
    "-connect",
    host + ":" + str(port),
    "-showcerts"
  ]
  for arg in openssl_args:
    cmd.append(arg)

  process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
  try:
    reply, err = process.communicate(b"\n", timeout=15)
    process.terminate()
    process_data(reply.decode("utf-8"), host, port, proto)
  except TimeoutExpired:
    proc.kill()
    reply, errs = proc.communicate()


def process_data(cert_data, host, port, proto):
  begin = re.compile('-----BEGIN CERTIFICATE-----')
  end = re.compile('-----END CERTIFICATE-----')
  pem = None
  loadcert = None
  for line in cert_data.splitlines():
    line = line.strip()
    if begin.match(line):
      loadcert = True
      pem = "-----BEGIN CERTIFICATE-----\n"
    elif end.match(line):
      loadcert = False
      pem += "-----END CERTIFICATE-----\n"
      analyze(isCa(pem), pem, host, port, proto)
    elif loadcert != None:
      pem += line + "\n";

def analyze(ca, pem, host, port, proto):
  cmd = [
    "openssl",
    "x509",
    "-noout",
    "--pubkey"
  ]
  pubkeyFile = None
  process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
  try:
    reply, err = process.communicate(str.encode(pem), timeout=15)
    process.terminate()
    fp = tempfile.NamedTemporaryFile(delete=False)
    pubkeyFile = fp.name
    fp.write(reply)
    fp.close()
  except TimeoutExpired:
    proc.kill()
    reply, errs = proc.communicate()

  cmd = [
    "danetool",
    "--tlsa-rr",
    "--host=" + host,
    "--port",
    str(port),
    "--proto=" + proto,
    "--load-pubkey=" + pubkeyFile
  ]
  if ca:
    cmd.append("--ca")
  process = Popen(cmd, shell=False, stdout=PIPE, stderr=PIPE)
  try:
    reply, err = process.communicate(timeout=15)
    process.terminate()
    if reply != None:
      print("RR: " + reply.decode("utf-8").strip())
  except TimeoutExpired:
    proc.kill()
    reply, errs = proc.communicate()
  os.remove(pubkeyFile)

def isCa(pem):
  cmd = [
    "openssl",
    "x509",
    "-noout",
    "-text"
  ]
  process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
  try:
    reply, err = process.communicate(str.encode(pem), timeout=15)
    process.terminate()
    ca_true = re.compile('CA:TRUE')
    ca_false = re.compile('CA:FALSE')
    for line in reply.decode("utf-8").splitlines():
      if ca_true.match(line.strip()):
        return True
      elif ca_false.match(line.strip()):
        return False
  except TimeoutExpired:
    proc.kill()
    reply, errs = proc.communicate()
    return False

host=sys.argv[1]
port=sys.argv[2]
args=sys.argv[3:]
main(host, port, "tcp", args)

