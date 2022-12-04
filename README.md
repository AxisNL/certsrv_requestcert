# certsrv_requestcert

This is a python script you can use to easily request certificates from your on-prem Microsoft Certificate Authority, 
that uses the legacy 'certsrv' web application that hasn't changed in the past 15 years. This service is installed when
you install the Certificate Enrollment Web Service feature, and you can verify it by going to 
https://ca.domain.local/certsrv. You might need to first install a decent certificate on it (meaning a certificate that
is issued by your own CA server, but with correct CN and SAN name, not expired, etc.). You don't want to send your
admin credentials over the wire.

This script leans heavily on [Magnus Watn's script](https://github.com/magnuswatn/certsrv) to interact with this 
service. This script is a wrapper around his, with a bit of extra features.

This script creates a private key, generates a csr and requests the certificate at your own CA, including the SAN field, 
which is required nowadays.[^1] After that, the script exports the key and certificate to two different PFX containers:
a normal PFX container for use on Windows Server 2019 and higher, and a legacy PFX container for use on Windows Server
2016 and earlier.[^2].

[^1]: Since 2018 (chrome 66 release), SAN fields are required in certificates. You need to manually include the SAN field
in certificate requests, and the MS CA does not issue certificates with SAN fields by default. Read more 
[here](http://terenceluk.blogspot.com/2017/09/adding-san-subject-alternative-name.html) and
[here](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff625722(v=ws.10)?redirectedfrom=MSDN)

[^2]: OpenSSL switched to AES256 as encryption scheme for PKCS12 (PFX) containers, but Microsoft only started supporting
this in Windows Server 2019. Windows Server 2016 and earlier expect 3DES/SHA1 encryption on these containers. If you try
to import an AES256 PFX, windows will just keep saying the password is incorrect, no matter what you do.

## Requirements
This script should work on Windows, MacOS and Linux. Python 3 is required. You might need to install it from 
[python.org](https://www.python.org/), or it might already be installed. Make sure it's your path.

OpenSSL is required. On MacOS and Linux it's included, but on Windows you might need to install it. But it's probably
included with other software, such as git. Specify the location in the configuration file (for example 
`C:\Program Files\Git\usr\bin\openssl.exe`)

## Getting started

Check out the repo or download the zip to some folder, for example `c:\tools\requestcert` or something. Copy the 
config.ini.dist to config.ini and change the values accordingly.

| section    | value           | description                                                                                  | 
|------------|-----------------|----------------------------------------------------------------------------------------------|
| ca_server  | hostname        | The hostname of your Certificate Authority                                                   |
| ca_server  | template        | The CA template, like WebServer or WebServerWithSan or something                             | 
| ca_server  | auth_method     | ntlm (or basic)                                                                              | 
| ca_server  | cacert          | The root certificate, used to trust the SSL connection to your CA                            | 
| ca_server  | username        | The username used to connect to your CA                                                      | 
| ca_server  | password        | The password used to connect to your CA, remove this after use!                              | 
| csr        | organization    | The company name used in your CSR                                                            | 
| csr        | ou              | The department used in your CSR                                                              | 
| openssl    | executable      | Path to openssl, for example `C:\Program Files\Git\usr\bin\openssl.exe` or `/usr/bin/openssl` | 
| openssl    | export_password | All PFX files are encrypted using a password, set it here                                    | 

Open a command prompt, and let's create a virtual env for Python and install all required python packages. 

Windows:

    cd c:\tools\requestcert
    python -m venv venv
    venv\Scripts\activate.bat
    

Linux/Mac:

    cd ~/tools/requestcert
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    
That's it, now you're done.

Keep in mind that if you want to use the script in the future, you first need to activate the venv again, by 
running `venv\Scripts\activate.bat` on windows or `source venv/bin/activate` on linux/mac.

### Usage

    (venv)>python request.py -h
    usage: request.py [-h] [-v] certificatename
    
    This scripts helps you request certificates from the Microsoft CA certsrv legacy service. It automatically includes
    the SAN field need, and exports different files you might need. All keys and certificates are written to the certs
    subfolder.
    
    positional arguments:
      certificatename  the name you want to get the certificate for
    
    optional arguments:
      -h, --help       show this help message and exit
      -v, --verbose    show INFO messages, repeat for DEBUG

### Examples

See the following example. Use the -v for extra output, or you won't see anything:

    python request.py -v webserver1.domain.local

    