#!/usr/bin/env python3
import os, hashlib

def blake2b_file(path, size=64):
  """return a blake2b hex digest"""
  h = hashlib.blake2b(digest_size=size)
  with open(path, 'rb') as f:
    for chunk in iter(lambda : f.read(8192), b''):
      h.update(chunk)
  return h.hexdigest()

def hash_all(root='/'):
  for dirpath, _, filenames in os.walk(root):
    for name in filenames:
      fpath = os.path.join(dirpath,name)
        try:
          digest = blake2b_file(fpath, size=64)
          print(f"{digest} {fpath}")
        except Exception:
          # skip files with some kind of error silently :)
          pass

if __name__ == '__main__':
  hash_all('/')
