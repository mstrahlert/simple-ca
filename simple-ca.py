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
ca_parser = subparsers.add_parser("ca", help="Generates CA certificate")
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
int_parser = subparsers.add_parser("int",
             help="Generates Intermediate CA certificate")
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
#int_parser.add_argument("--path", help="Path to Intermediate (default \"./intermediate\")")
cert_parser = subparsers.add_parser("cert",
              help="Generate certificate with given common name")
cert_parser.add_argument("cn", action="store",
            help="The common name of the certificate")
cert_parser.add_argument("--altname", action="append", default=[],
            dest="altnames", help="Add subject alternate names. Several "
                 "--altname can be given")
cert_parser.add_argument("--cipher", action="store", default="aes256",
            help="The cipher to use to encrypt the private key (default: "
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
revoke_parser = subparsers.add_parser("revoke",
            help="Revoke a certificate with given common name")
revoke_parser.add_argument("cn", action="store",
            help="The certificate to revoke")
parser.add_argument("--version", action="version", version="%(prog)s 1.0")

results = parser.parse_args()
print(results)

if results.subparser_name == "init":
  """ Check if directory structure exists, otherwise create """
  if os.path.exists("certs"):
    print("Directory structure already exists, exiting")
    sys.exit(1)
  else:
    os.system("mkdir certs crl newcerts private intermediate "
              "intermediate/certs intermediate/crl intermediate/csr "
              "intermediate/newcerts intermediate/private")
    os.system("chmod 700 private intermediate/private")
    os.system("touch index.txt intermediate/index.txt")
    os.system("echo 1000 > serial")
    os.system("echo 1000 > intermediate/serial")
elif results.subparser_name == "ca":
  """ Check if CA certificate exists, otherwise generate """
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
  """ Check if Intermediate CA certificate exists, otherwise generate """
  if os.path.exists("intermediate/certs/intermediate.cert.pem"):
    print("Intermediate CA certificate already exists, exiting")
    sys.exit(1)
  else:
    os.system("openssl genrsa -%s "
              "-out intermediate/private/intermediate.key.pem %d" %
              (results.cipher, results.bits))
    if os.path.exists("intermediate/private/intermediate.key.pem"):
      os.system("openssl req -config intermediate/openssl.conf "
                "-key intermediate/private/intermediate.key.pem "
                "-new -%s -out intermediate/csr/intermediate.csr.pem" %
                results.digest)
      if os.path.exists("intermediate/csr/intermediate.csr.pem"):
        os.system("openssl ca -config openssl.conf "
                  "-extensions v3_intermediate_ca -days %d -notext -md %s "
                  "-in intermediate/csr/intermediate.csr.pem "
                  "-out intermediate/certs/intermediate.cert.pem" %
                  (results.days, results.digest))
        if os.system("openssl verify -CAfile certs/ca.cert.pem "
                     "intermediate/certs/intermediate.cert.pem") == 0:
          os.system("cat intermediate/certs/intermediate.cert.pem "
                    "certs/ca.cert.pem > "
                    "intermediate/certs/ca-chain.cert.pem")
          sys.exit(0)
  sys.exit(1)
elif results.subparser_name == "cert":
  """ Check if certificate exists, otherwise generate """
  if os.path.exists("intermediate/certs/%s.cert.pem" % results.cn):
    print("Certificate %s already exists, exiting" % results.cn)
    sys.exit(1)
  else:
    os.system("openssl genrsa -%s "
              "-out intermediate/private/%s.key.pem %d" %
              (results.cipher, results.cn, results.bits))
    if os.path.exists("intermediate/private/%s.key.pem" % results.cn):
      if len(results.altnames):
        # Using subject alternate names. Insert config to openssl.conf
        sanconf = "DNS:" + ",DNS:".join(list)
        sanconf = "DNS:%s,%s" % (results.cn, sanconf)
        dnsconf = ""
        for i in range(len(results.altnames)):
          dnsconf += "DNS.%d = %s\n" % (i + 2, results.altnames[i])

        # Different configuration needs for openssl-req and openssl-ca
        fd_req, tmp_req = tempfile.mkstemp(text=True)
        fd_ca, tmp_ca = tempfile.mkstemp(text=True)
        shutil.copyfile("intermediate/openssl.conf", tmp_req)
        shutil.copyfile("intermediate/openssl.conf", tmp_ca)
        fo_req = os.fdopen(fd_req, 'at')
        fo_ca = os.fdopen(fd_req, 'at')
        fo_req.write("\n".join(["", "[SAN]",
                                "subjectAltName=%s" % sanconf]))
        fo_ca.write("\n".join(["", "subjectAltName=@my_subject_alt_names",
                               "", "[ my_subject_alt_names ]", dnsconf ]))
        fo_req.close()
        fo_ca.close()

        os.system("openssl req -config %s -reqexts SAN "
                  "-key intermediate/private/%s.key.pem -new -%s "
                  "-out intermediate/csr/%s.csr.pem" %
                  (tmp_req, results.cn, results.digest, results.cn))
        if os.path.exists("intermediate/csr/%s.csr.pem" % results.cn):
          os.system("openssl ca -config %s -extensions server_cert "
                    "-days %d -notext -md %s "
                    "-in intermediate/csr/%s.csr.pem "
                    "-out intermediate/certs/%s.cert.pem" % (tmp_ca,
                    results.days, results.digest, results.cn, results.cn))
          if os.system("openssl verify "
                       "-CAfile intermediate/certs/ca-chain.cert.pem "
                       "intermediate/%s.cert.pem" % results.cn):
            os.remove(tmp_req)
            os.remove(tmp_ca)
            sys.exit(0)

        os.remove(tmp_req)
        os.remove(tmp_ca)
        sys.exit(1)
      else:
        # Not using subject alternate names
        os.system("openssl req -config intermediate/openssl.conf "
                  "-key intermediate/private/%s.key.pem -new -%s "
                  "-out intermediate/csr/%s.csr.pem" % (results.cn,
                  results.digest, results.cn))
        if os.path.exists("intermediate/csr/%s.csr.pem" % results.cn):
          os.system("openssl ca -config intermediate/openssl.conf "
                    "-extensions server_cert -days %d -notext -md %s "
                    "-in intermediate/csr/%s.csr.pem "
                    "-out intermediate/certs/%s.cert.pem" % (results.days,
                    results.digest, results.cn, results.cn))
          if os.system("openssl verify "
                       "-CAfile intermediate/certs/ca-chain.cert.pem "
                       "intermediate/%s.cert.pem" % results.cn):
            sys.exit(0)
  sys.exit(1)
elif results.subparser_name == "revoke":
  print("Not implemented yet")
