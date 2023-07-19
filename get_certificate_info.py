import argparse
import configparser
import logging
import os
import functions
import logger
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def main():
    #############################################################
    # PARSE ARGUMENTS
    #############################################################
    helptext = 'This scripts helps get certificate info'

    parser = argparse.ArgumentParser(
        description=helptext)
    parser.add_argument('hostname', action='store', help='the name you want to check the cert for')
    args = parser.parse_args()

    #############################################################
    # LOGGING
    #############################################################
    logger.configureLogging(1)

    #############################################################
    # START THE WORK
    #############################################################
    logging.info("getting certificate info for hostname '{0}'".format(args.hostname))

    certificate: bytes = ssl.get_server_certificate((args.hostname, 443)).encode('utf-8')
    loaded_cert = x509.load_pem_x509_certificate(certificate, default_backend())

    common_name = loaded_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    common_name_0 = common_name[0]
    logging.info("Common name: {0}".format(common_name_0.value))
    logging.info("Not valid before: {0}".format(loaded_cert.not_valid_before))
    logging.info("Not valid after: {0}".format(loaded_cert.not_valid_after))

    # classes must be subtype of:
    #   https://cryptography.io/en/latest/x509/reference/#cryptography.x509.ExtensionType
    san = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    san_dns_names = san.value.get_values_for_type(x509.DNSName)
    logging.info("SAN dns names: {0}".format(san_dns_names))


# MAIN PROGRAM
# ##################################################
if __name__ == "__main__":
    # stuff only to run when not called via 'import' here
    main()
