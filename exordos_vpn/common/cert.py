#    Copyright 2025 Genesis Corporation.
#
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from OpenSSL import crypto

OBJTYPE_TO_LOAD_FUNC = {
    crypto.X509: crypto.load_certificate,
    crypto.X509Req: crypto.load_certificate_request,
    crypto.PKey: crypto.load_privatekey,
}


OBJTYPE_TO_DUMP_FUNC = {
    crypto.X509: crypto.dump_certificate,
    crypto.PKey: crypto.dump_privatekey,
    crypto.X509Req: crypto.dump_certificate_request,
}


def dump_file_in_mem(obj, format=crypto.FILETYPE_PEM):
    dump_func = OBJTYPE_TO_DUMP_FUNC[type(obj)]

    return dump_func(format, obj)


def load_from_file(file, objtype, format=crypto.FILETYPE_PEM):
    with open(file, "r") as fp:
        buf = fp.read()

    material = OBJTYPE_TO_LOAD_FUNC[objtype](format, buf)
    return material


def retrieve_key_from_file(keyfile):
    return load_from_file(keyfile, crypto.PKey)


def retrieve_csr_from_file(csrfile):
    return load_from_file(csrfile, crypto.X509Req)


def retrieve_cert_from_file(certfile):
    return load_from_file(certfile, crypto.X509)


def make_keypair(algorithm=crypto.TYPE_RSA, numbits=2048):
    pkey = crypto.PKey()
    pkey.generate_key(algorithm, numbits)
    return pkey


def make_csr(pkey, CN, hashalgorithm="sha256WithRSAEncryption", **kwargs):
    req = crypto.X509Req()
    req.get_subject()
    subj = req.get_subject()
    subj.CN = CN

    for k, v in kwargs.items():
        setattr(subj, k, v)

    req.set_pubkey(pkey)
    req.sign(pkey, hashalgorithm)
    return req


def create_slave_certificate(csr, cakey, cacert, serial, validity_days=365 * 10):
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60 * 60 * 24 * validity_days)
    cert.set_issuer(cacert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.set_version(2)

    extensions = []
    extensions.append(crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"))

    extensions.append(
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert)
    )
    extensions.append(
        crypto.X509Extension(
            b"authorityKeyIdentifier",
            False,
            b"keyid:always,issuer:always",
            subject=cacert,
            issuer=cacert,
        )
    )

    cert.add_extensions(extensions)
    cert.sign(cakey, "sha256WithRSAEncryption")

    return cert
