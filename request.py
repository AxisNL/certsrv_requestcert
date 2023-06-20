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
    helptext += 'automatically includes the SAN field need, and exports different files you might need. All keys and '
    helptext += 'certificates are written to the certs subfolder'

    parser = argparse.ArgumentParser(
        description=helptext)
    parser.add_argument('-v', '--verbose', action='count', default=0, help='show INFO messages, repeat for DEBUG')
    parser.add_argument('cn', action='store', help='the name you want to get the certificate for')
    parser.add_argument('extra_names', nargs='?', help='comma separated list of extra san names')
    args = parser.parse_args()

    verbosity_level = args.verbose

    #############################################################
    # LOGGING
    #############################################################
    logger.configureLogging(verbosity_level)

    #############################################################
    # START THE WORK
    #############################################################
    logging.info("starting certificate script for hostname '{0}'".format(args.cn))

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
    openssl_export_password = config['openssl']['export_password']

    privateykey_filename = os.path.join(certs_dir, '{0}.key'.format(args.cn))
    certificate_filename = os.path.join(certs_dir, '{0}.crt'.format(args.cn))
    pfx_filename = os.path.join(certs_dir, '{0}.pfx'.format(args.cn))
    pfx_legacy_filename = os.path.join(certs_dir, '{0}.legacy.pfx'.format(args.cn))

    # generate the private key and write it to disk
    key = functions.GenerateKey()
    functions.WriteKey(key, privateykey_filename)

    subjectalternativenames = [args.cn]
    tmp_sans = args.extra_names
    if tmp_sans is not None:
        for name in tmp_sans.split(','):
            subjectalternativenames.append(name.strip())

    csr = functions.CreateCSR(key=key,
                              cn=args.cn,
                              subjectalternativenames=subjectalternativenames,
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

    # write the modern AES256 encrypted PFX file. This is the pythonic way using pyOpenSSL
    functions.WritePFX(privateykey_filename,
                       certificate_filename,
                       pfx_filename,
                       openssl_export_password)

    # write the legacy 3DES/SHA encrypted PFX file. This calls the openssl binary, since pyOpenSSL does not support
    # specifying the encryption methods
    functions.WriteLegacyPFX(privateykey_filename,
                             certificate_filename,
                             pfx_legacy_filename,
                             openssl_executable,
                             openssl_export_password)


    logging.info("all done!")


# MAIN PROGRAM
# ##################################################
if __name__ == "__main__":
    # stuff only to run when not called via 'import' here
    main()
