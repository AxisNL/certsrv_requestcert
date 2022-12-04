import logging
import os
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
        logging.info("wrote key to {0}.".format(os.path.abspath(filename)))


def CreateCSR(key, certificatename, organization, ou):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, certificatename),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou)
    ])).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(certificatename),
        ]),
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
        logging.info("wrote certificate to {0}.".format(os.path.abspath(certificate_filename)))

    #
    #
    # pfx_filename = os.path.join(certs_dir, '{0}.pfx'.format(hostname))
    #
    # with open(privateykey_filename, 'r') as file:
    #     privateykey = file.read()
    # with open(certificate_filename, 'r') as file:
    #     certificate = file.read()
    # key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privateykey)
    # cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    # pkcs = OpenSSL.crypto.PKCS12()
    # pkcs.set_privatekey(key)
    # pkcs.set_certificate(cert)
    #
    # print(pkcs.get_friendlyname())
    # with open(pfx_filename, 'wb') as file:
    #     file.write(pkcs.export(passphrase="password".encode('ASCII')))
    # logging.debug("converted to PFX: {0} (password is 'password').".format(os.path.abspath(pfx_filename)))
