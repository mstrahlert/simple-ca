#!/usr/bin/env python
#
# Magnus Strahlert @ 180523
#   Simple CA handling

import argparse
import os
import sys
import tempfile
import shutil

parser = argparse.ArgumentParser(description='Simple CA tool')
subparsers = parser.add_subparsers(dest="subparser_name")

init_parser = subparsers.add_parser("init",
              help="Inits the current directory as workspace")
ca_parser = subparsers.add_parser("ca", help="Create CA")
ca_parser.add_argument("--cipher", action="store", default="aes256",
          help="The cipher to use to encrypt the private key (default: "
               "%(default)s)")
ca_parser.add_argument("--bits", action="store", default=4096, type=int,
          help="The number of bits to encrypt the private key with "
               "(default: %(default)s)")
ca_parser.add_argument("--days", action="store", default=7300, type=int,
          help="Number of days the certificate is valid for (default: "
               "%(default)s)")
ca_parser.add_argument("--digest", action="store", default="sha256",
          help="Message digest to sign the certificate with (default: "
               "%(default)s)")
int_parser = subparsers.add_parser("int", help="Create Intermediate CA")
int_parser.add_argument("--cipher", action="store", default="aes256",
           help="The cipher to use to encrypt the private key (default: "
                "%(default)s)")
int_parser.add_argument("--bits", action="store", default=4096, type=int,
           help="The number of bits to encrypt the private key with "
                "(default: %(default)s)")
int_parser.add_argument("--days", action="store", default=3650, type=int,
           help="Number of days the certificate is valid for (default: "
                "%(default)s)")
int_parser.add_argument("--digest", action="store", default="sha256",
           help="Message digest to sign the certificate with (default: "
                "%(default)s)")
int_parser.add_argument("--name", action="store", default="Internal",
           help="Name of the Intermediate CA. This will be used for "
                "filenames")
#int_parser.add_argument("--path", action="store", required=True,
#           default="./intermediate", help="Path to Intermediate "
#                   "(default: %(default)s)")
issuing_parser = subparsers.add_parser("issuing", help="Create Issuing CA")
issuing_parser.add_argument("--cipher", action="store", default="aes256",
           help="The cipher to use to encrypt the private key (default: "
                "%(default)s)")
issuing_parser.add_argument("--bits", action="store", default=4096,
           type=int,
           help="The number of bits to encrypt the private key with "
                "(default: %(default)s)")
issuing_parser.add_argument("--days", action="store", default=365, type=int,
           help="Number of days the certificate is valid for (default: "
                "%(default)s)")
issuing_parser.add_argument("--digest", action="store", default="sha256",
           help="Message digest to sign the certificate with (default: "
                "%(default)s)")
issuing_parser.add_argument("--inter", action="store", required=True,
           help="Which Intermediate to use") 
issuing_parser.add_argument("--name", action="store", default="Internal A01",
           help="Name of the Issuing CA. This will be used for filenames")
cert_parser = subparsers.add_parser("cert",
              help="Generate certificate with given common name")
cert_parser.add_argument("cn", action="store",
            help="The common name of the certificate")
cert_parser.add_argument("--altname", action="append", default=[],
            dest="altnames", help="Add subject alternate names. Several "
                 "--altname can be given")
cert_parser.add_argument("--cipher", action="store", default="aes256",
            help="The cipher to use to encrypt the private key. Specify \"nodes\" to create password-less key (default: "
                 "%(default)s)")
cert_parser.add_argument("--bits", action="store", default=2048, type=int,
            help="The number of bits to encrypt the private key with "
                 "(default: %(default)s)")
cert_parser.add_argument("--days", action="store", default=730, type=int,
            help="Number of days the certificate is valid for (default: "
                 "%(default)s)")
cert_parser.add_argument("--digest", action="store", default="sha256",
            help="Message digest to sign the certificate with (default: "
                 "%(default)s)")
cert_parser.add_argument("--issuing", action="store", required=True,
            help="Which Issuing CA to use")
revoke_parser = subparsers.add_parser("revoke",
            help="Revoke a certificate with given common name")
revoke_parser.add_argument("cn", action="store",
            help="The certificate to revoke")
parser.add_argument("--version", action="version", version="%(prog)s 1.0")

results = parser.parse_args()
print(results)

def n2fn(name):
  """ Returns the string as lowercase with all spaces removed
  """
  return "".join(name.lower().split(' '))

if results.subparser_name == "init":
  """ Check if directory structure exists, otherwise create """
  if os.path.exists("certs"):
    print("Directory structure already exists, exiting")
    sys.exit(1)
  else:
    os.system("mkdir certs crl csr newcerts private intermediate issuing "
              "intermediate/certs intermediate/crl intermediate/csr "
              "intermediate/newcerts intermediate/private "
              "issuing/certs issuing/crl issuing/csr issuing/newcerts "
              "issuing/private")
    os.system("chmod 700 private intermediate/private issuing/private")
    os.system("touch index.txt intermediate/index.txt issuing/index.txt")
    os.system("echo 1000 > serial")
    os.system("echo 1000 > intermediate/serial")
    os.system("echo 1000 > issuing/serial")
elif results.subparser_name == "ca":
  """ Check if CA certificate exists, otherwise generate
  """
  if os.path.exists("certs/ca.cert.pem"):
    print("CA certificate already exists, exiting")
    sys.exit(1)
  else:
    os.system("openssl genrsa -%s -out private/ca.key.pem %d" %
              (results.cipher, results.bits))
    if os.path.exists("private/ca.key.pem"):
      os.system("openssl req -config openssl.conf -key private/ca.key.pem "
                "-new -x509 -days %d -%s -extensions v3_ca "
                "-out certs/ca.cert.pem" % (results.days, results.digest))
    else:
      print("No private key available, exiting")
      sys.exit(1)
elif results.subparser_name == "int":
  """ Check if Intermediate CA certificate exists, otherwise generate
  """
  if os.path.exists("intermediate/certs/%s.cert.pem" % n2fn(results.name)):
    print("Intermediate CA certificate already exists, exiting")
    sys.exit(1)
  else:
    os.system("openssl genrsa -%s -out intermediate/private/%s.key.pem %d" %
              (results.cipher, n2fn(results.name), results.bits))
    if os.path.exists("intermediate/private/%s.key.pem" %
                      n2fn(results.name)):
      os.system("openssl req -config openssl.conf "
                "-key intermediate/private/%s.key.pem "
                "-new -%s -out intermediate/csr/%s.csr.pem" %
                (n2fn(results.name), results.digest, n2fn(results.name)))
      if os.path.exists("intermediate/csr/%s.csr.pem" % n2fn(results.name)):
        # Sign the csr with the Root CA using v3_intermediate_ca conf
        os.system("openssl ca -config openssl.conf "
                  "-extensions v3_intermediate_ca -days %d -notext -md %s "
                  "-in intermediate/csr/%s.csr.pem "
                  "-out intermediate/certs/%s.cert.pem" %
                  (results.days, results.digest, n2fn(results.name),
                   n2fn(results.name)))
        # Verify the certificate against the trusted certificate chain
        if os.system("openssl verify -CAfile certs/ca.cert.pem "
                     "intermediate/certs/%s.cert.pem" %
                      n2fn(results.name)) == 0:
          # Under normal circumstances, the root certificate should
          # be in the client's trust store and not needed for inclusion
          os.system("cat intermediate/certs/%s.cert.pem "
                    "certs/ca.cert.pem > "
                    "intermediate/certs/%s.ca-chain.pem" %
                    (n2fn(results.name), n2fn(results.name)))
          sys.exit(0)
  sys.exit(1)
elif results.subparser_name == "issuing":
  """ Check if Issuing CA certificate exists, otherwise generate
  """
  if not os.path.exists("intermediate/certs/%s.cert.pem" % n2fn(results.inter)):
    print("Intermediate CA certificate doesn't exist, exiting")
    sys.exit(1)
  elif os.path.exists("issuing/certs/%s.cert.pem" % n2fn(results.name)):
    print("Issuing CA certificate already exists, exiting")
    sys.exit(1)
  else:
    os.system("openssl genrsa -%s -out issuing/private/%s.key.pem %d" %
              (results.cipher, n2fn(results.name), results.bits))
    if os.path.exists("issuing/private/%s.key.pem" % n2fn(results.name)):
      os.system("openssl req -config openssl.conf "
                "-key issuing/private/%s.key.pem "
                "-new -%s -out issuing/csr/%s.csr.pem" %
                (n2fn(results.name), results.digest, n2fn(results.name)))
      if os.path.exists("issuing/csr/%s.csr.pem" % n2fn(results.name)):
        # Issuing CA uses the named Intermediate as CA
        os.system("openssl ca -config openssl.conf "
                  "-extensions v3_issuing_ca -days %d -notext -md %s "
                  "-in issuing/csr/%s.csr.pem "
                  "-out issuing/certs/%s.cert.pem " 
                  "-cert intermediate/certs/%s.cert.pem "
                  "-keyfile intermediate/private/%s.key.pem" %
                  (results.days, results.digest, n2fn(results.name),
                   n2fn(results.name), n2fn(results.inter),
                   n2fn(results.inter)))
        # Verify the certificate against the trusted certificate chain
        if os.system("openssl verify "
                     "-CAfile intermediate/certs/%s.ca-chain.pem "
                     "issuing/certs/%s.cert.pem" %
                     (n2fn(results.inter), n2fn(results.name))) == 0:
          # Under normal circumstances, the root certificate should
          # be in the client's trust store and not needed for inclusion
          os.system("cat issuing/certs/%s.cert.pem "
                    "intermediate/certs/%s.ca-chain.pem > "
                    "issuing/certs/%s.ca-chain.pem" %
                    (n2fn(results.name), n2fn(results.inter),
                     n2fn(results.name)))
          sys.exit(0)
  sys.exit(1)
elif results.subparser_name == "cert":
  """ Check if certificate exists, otherwise generate 
  """
  if os.path.exists("certs/%s.cert.pem" % results.cn):
    print("Certificate %s already exists, exiting" % results.cn)
    sys.exit(1)
  elif not os.path.exists("issuing/certs/%s.cert.pem" % n2fn(results.issuing)):
    print("Issuing CA certificate doesn't exist, exiting")
    sys.exit(1)
  else:
    # Generate the private key unless we want a password-less key
    if results.cipher != "nodes":
      os.system("openssl genrsa -%s -out private/%s.key.pem %d" %
                (results.cipher, results.cn, results.bits))
    # If requesting a password-less key a key won't exist
    if (results.cipher == "nodes" or
        os.path.exists("private/%s.key.pem" % results.cn)):

      fd, tmpconf = tempfile.mkstemp(text=True)
      shutil.copyfile("openssl.conf", tmpconf)

      if len(results.altnames):
        # Using subject alternate names. Insert config to openssl.conf
        sanconf = "DNS:" + ",DNS:".join(results.altnames)
        sanconf = "DNS:%s,%s" % (results.cn, sanconf)

        with open(tmpconf, 'r+') as fd:
          contents = fd.readlines()
          for i, l in enumerate(contents):
            if 'server_cert' in l:
              contents.insert(i + 1, "subjectAltName=%s\n" % sanconf)
              break
          fd.seek(0)
          fd.writelines(contents)

      # Slight difference whether requesting password-less key or not
      if results.cipher != "nodes":
        os.system("openssl req -config %s "
                  "-key private/%s.key.pem -new -%s "
                  "-out csr/%s.csr.pem" %
                  (tmpconf, results.cn, results.digest, results.cn))
      else:
        # When requesting a password-less key, this will create the key
        os.system("openssl req -config %s -nodes "
                  "-keyout private/%s.key.pem -new -%s "
                  "-out csr/%s.csr.pem" %
                  (tmpconf, results.cn, results.digest, results.cn))

      # Check if the certificate signing request was created successfully
      if os.path.exists("csr/%s.csr.pem" % results.cn):
        os.system("openssl ca -config %s -extensions server_cert "
                  "-days %d -notext -md %s -in csr/%s.csr.pem "
                  "-out certs/%s.cert.pem "
                  "-cert issuing/certs/%s.cert.pem "
                  "-keyfile issuing/private/%s.key.pem" % (tmpconf,
                  results.days, results.digest, results.cn, results.cn,
                  n2fn(results.issuing), n2fn(results.issuing)))
        # Verify the certificate against the trusted certificate chain
        if os.system("openssl verify "
                     "-CAfile issuing/certs/%s.ca-chain.pem "
                     "certs/%s.cert.pem" % (n2fn(results.issuing),
                      results.cn)):
          os.remove(tmpconf)
          sys.exit(0)

      os.remove(tmpconf)
      sys.exit(1)
  sys.exit(1)
elif results.subparser_name == "revoke":
  print("Not implemented yet")
