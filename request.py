# ############################################
# Copyright (c) 2022, Angelo Hongens <angelo.hongens.nl>
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following
# disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
# the following disclaimer in the documentation and/or other materials provided with the distribution. THIS SOFTWARE
# IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import argparse
import configparser
import logging
import os
import functions
import logger


def main():
    #############################################################
    # PARSE ARGUMENTS
    #############################################################
    helptext = 'This scripts helps you request certificates from the Microsoft CA certsrv legacy service. It '
    helptext += 'automatically includes the SAN field need, and exports different files you might need.'
    parser = argparse.ArgumentParser(
        description=helptext)
    parser.add_argument('-v', '--verbose', action='count', default=0, help='show INFO messages, repeat for DEBUG')
    parser.add_argument('certificatename', action='store', help='the name you want to get the certificate for')
    args = parser.parse_args()

    verbosity_level = args.verbose

    #############################################################
    # LOGGING
    #############################################################
    logger.configureLogging(verbosity_level)

    #############################################################
    # START THE WORK
    #############################################################
    logging.info("starting certificate script for hostname '{0}'".format(args.certificatename))

    script_path = os.path.realpath(__file__)
    working_dir = os.path.dirname(script_path)
    certs_dir = os.path.join(working_dir, 'certs')

    config = configparser.ConfigParser()
    config.read(os.path.join(working_dir, "certsrv.ini"))

    ca_server_hostname = config['ca_server']['hostname']
    ca_server_template = config['ca_server']['template']
    ca_server_auth_method = config['ca_server']['auth_method']
    ca_server_cacert = config['ca_server']['cacert']
    ca_server_username = config['ca_server']['username']
    ca_server_password = config['ca_server']['password']
    csr_organization = config['csr']['organization']
    csr_ou = config['csr']['ou']

    openssl_executable = config['openssl']['executable']

    privateykey_filename = os.path.join(certs_dir, '{0}.key'.format(args.certificatename))
    certificate_filename = os.path.join(certs_dir, '{0}.crt'.format(args.certificatename))

    # generate the private key and write it to disk
    key = functions.GenerateKey()
    functions.WriteKey(key, privateykey_filename)

    # generate the CSR (no need to save that to disk)
    csr = functions.CreateCSR(key=key,
                              certificatename=args.certificatename,
                              organization=csr_organization,
                              ou=csr_ou)

    # now request this certificate at our CA server
    certificate = functions.RequestCertificate(csr=csr,
                                               hostname=ca_server_hostname,
                                               template=ca_server_template,
                                               username=ca_server_username,
                                               password=ca_server_password,
                                               auth_method=ca_server_auth_method,
                                               cacert=ca_server_cacert)
    # and write it to disk.
    functions.WriteCertificate(certificate, certificate_filename)

    logging.info("all done!")


# MAIN PROGRAM
# ##################################################
if __name__ == "__main__":
    # stuff only to run when not called via 'import' here
    main()
