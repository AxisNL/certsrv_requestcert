import logging
import os
import subprocess

import OpenSSL
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from certsrv import Certsrv


def GenerateKey():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return key


def WriteKey(key, filename):
    pem_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(filename, 'w') as f:
        f.write(pem_key.decode())
        logging.info("wrote key to '{0}'".format(os.path.abspath(filename)))


def CreateCSR(key, cn, subjectalternativenames, organization, ou):
    x509san_array = []
    for san in subjectalternativenames:
        x509san_array.append(x509.DNSName(san))

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou)
        ])
    ).add_extension(
        x509.SubjectAlternativeName(x509san_array),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())
    return csr


def RequestCertificate(csr, hostname, template, username, password, auth_method, cacert):
    pem_req = csr.public_bytes(serialization.Encoding.PEM)

    ca = Certsrv(server=hostname,
                 username=username,
                 password=password,
                 auth_method=auth_method,
                 cafile=cacert
                 )
    logging.info("requesting certificate from CA '{0}' with template '{1}'".format(hostname, template))
    pem_cert = ca.get_cert(pem_req, template)
    return pem_cert


def WriteCertificate(pem_cert, certificate_filename):
    with open(certificate_filename, 'w', newline='\n') as f:
        f.write(pem_cert.decode())
        logging.info("wrote certificate to '{0}'".format(os.path.abspath(certificate_filename)))


def WritePFX(privateykey_filename, certificate_filename, pfx_filename, openssl_export_password):
    with open(privateykey_filename, 'r') as file:
        privateykey = file.read()
    with open(certificate_filename, 'r') as file:
        certificate = file.read()
    key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privateykey)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    pkcs = OpenSSL.crypto.PKCS12()
    pkcs.set_privatekey(key)
    pkcs.set_certificate(cert)

    with open(pfx_filename, 'wb') as file:
        file.write(pkcs.export(passphrase=openssl_export_password.encode('ASCII')))
    logging.info("wrote the PFX file to '{0}' (password is '{1}')".format(pfx_filename, openssl_export_password))


def WriteLegacyPFX(privateykey_filename, certificate_filename, pfx_filename, openssl_executable,
                   openssl_export_password):
    if not os.path.isfile(openssl_executable):
        logging.error("Missing openssl executable '{0}', check your config!".format(openssl_executable))
        exit(1)

    command_line = [openssl_executable,
                    'pkcs12',
                    '-keypbe',
                    'PBE-SHA1-3DES',
                    '-certpbe',
                    'PBE-SHA1-3DES',
                    '-export',
                    '-in',
                    certificate_filename,
                    '-inkey',
                    privateykey_filename,
                    '-out',
                    pfx_filename,
                    '-password',
                    'pass:{0}'.format(openssl_export_password)
                    ]
    logging.debug("starting command: {0}".format(" ".join(command_line)))
    command_result = subprocess.Popen(command_line, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    command_output = command_result.communicate()[0]
    logging.debug("openssl output: {0}".format(command_output))
    command_exitcode = command_result.returncode
    if command_exitcode != 0:
        logging.error('openssl returned an error, quitting')
        exit(1)
    logging.info("wrote the legacy PFX file to '{0}' (password is '{1}')".format(pfx_filename, openssl_export_password))
