# SIACrawler
*(AIACrawler is a similar but unrelated utility)*

Automatically create a CA Certificate bundle file from a Trust Anchor CA certificate by extracting the Authority Information Access (AIA) Certificate Repository URI from the Subject Information Access (SIA) information in the Trust Root CA Certificate and all subordinate CAs under it.

# Quick Start
`perl SIACrawler.pl`

Using the default configuration, this script will create a ca_bundle.pem file in the directory the script is executed from, containing all Certificate Authority certificates that have been issued under the Federal Common Policy Root CA.  The resulting file can be used with any webserver software that supports a single text file containing a concatenated list of trusted CA certificates (Apache httpd).

---

Dependencies required to execute this script:
 * Network access to the Internet (http_proxy/https_proxy environment variables will be used if defined)
 * OpenSSL (https://www.openssl.org/)
 * Perl Interpreter (https://www.perl.org/)
   <br/>The follow perl modules are used in this script, and can be obtained via CPAN command-line utilities or from http://cpan.org (*Some of the modules used may already be installed in your perl library path*):
   * libwww-perl (https://metacpan.org/pod/LWP)
   * Crypt::X509 (https://metacpan.org/pod/Crypt::X509)
   * File::Copy (https://metacpan.org/pod/File::Copy)
   * File::Path (https://metacpan.org/pod/File::Path)
   * File::Spec (https://metacpan.org/pod/File::Spec)
   * File::Spec::Functions(https://metacpan.org/pod/File::Spec::Functions)
   * MIME::Base64 (https://metacpan.org/pod/MIME::Base64)

---

The Trust Anchor Certificate can be specified as a command-line argument or set in the `$trustRootCAcert` script variable below.  A file path or URL can be used to specify the Trust Anchor CA Certificate to use.

 Trust Anchor Reference: https://tools.ietf.org/html/rfc6024

 This script will obtain the certificate specified in `$trustRootCAcert` variable either through the filesystem or by downloading from the Internet.

The Authority Information Access (AIA) field contained in the Subject Information Access (SIA) field of the Trust Root CA certificate is used to obtain the location of a PKCS7 (.p7c/.p7b) file containing all the CA Certs that have been issued by the Trust Root CA.

Tasks performed by this script:
1. The PKCS7 file is downloaded from the http URI specified in the SIA field of the certificate

2. The openssl command is then used to extract the certificates within the PKCS7 file into a temporary file. (Certificates are extracted using PEM encoding)

3. Each CA Certificate in the temporary file is then parsed and validated against the following requirements:
    * The certificate is not a self-signed certificate
    * The certificate does not have the same Subject Key Identifier as the Trust Root CA (not a Cross Certified CA Certificate)
    * The certificate contains the "Common Authentication" Certificate Policy OID (The "Common Authentication" Policy OID can be changed in the `$oid` hash table if needed)
    * The certificate's subject does not contain any of the strings specified in the `@certsToExcludeFromBundle` array variable

4. If the certificate meets the validation requirements the certificate is added to a temporary file (which will become the ca_bundle file)

5. Using the AIA Certificate Repository data in the SIA field of this certificate, Task #1 is repeated

After all certificates have been processed the temporary ca_bundle file is copied to the file specified in the `$CATrustChainBundleFile` variable

If the `$delete_temp_files` variable is set to `"yes"`, all files created by this script will be deleted.

**Notice:** To avoid unexpected errors with subsequent runs of this script setting `$delete_temp_files` to `"yes"` is recommended

---

**Utility script**
# ca_bundle_parser.pl
Parse a concatenated list of Certificates from a textfile and optionally extract each certificate to a directory

For complete usage details execute ca_bundle_parser.pl with the -h option to view the available command line parameters.

Basic usage:
```
ca_bundle_parser.pl -xnf ca_bundle.pem
```
The above command does the following:
    * (-x) Extract each certificate into a directory named *ca_bundle*.pem_certs
    * (-n) Prepend each extracted certificate file name with a number indicating the order of the cert in the bundle
    * (-f *FILENAME*) Parse the ca_bundle.pem file
