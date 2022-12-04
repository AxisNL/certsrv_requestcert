# certsrv_requestcert

This script is intented to make it easy to request certificates with your on-prem Microsoft Certificate Authority, that
uses the legacy 'certsrv' web application that hasn't changed in the past 15 years.

This script leans heavily on Magnus Watn's script to interact with this service: https://github.com/magnuswatn/certsrv,
and this script is a wrapper around his, with a bit of extra features.

This script creates a private key, generates a csr and requests the certificate at your own CA, including the SAN field, 
which is required nowadays.[^1]

[^1]: Since 2018 (chrome 66 release), SAN fields are required in certificates. You need to manually include the SAN field
in certificate requests, and the MS CA does not issue certificates with SAN fields by default. Read more 
[here](http://terenceluk.blogspot.com/2017/09/adding-san-subject-alternative-name.html) and
[here](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff625722(v=ws.10)?redirectedfrom=MSDN)


## Requirements
This script should work on Windows, MacOS and Linux. Python3 is required. If on Windows, download from 
[python.org](https://www.python.org/). Make sure it's on your path.

On windows, be sure to copy openssl.exe to the working dir (the root of this folder), you can find in a lot of places,
for example `c:\program files\git\usr\bin` if you have git installed.

## Getting started

Check out this repo and go to the folder. There, create a virtualenv called 'venv' and activate it:

python3 -m venv venv
