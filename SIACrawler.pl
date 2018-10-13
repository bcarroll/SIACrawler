#!/usr/bin/env perl
use warnings;
use strict;
use LWP::UserAgent;
use File::Copy qw(copy move);
use File::Path qw(remove_tree); # rm -rf for perl
use File::Spec qw(tmpdir); # get OS temp directory
use File::Spec::Functions qw(canonpath); # platform independent paths
use Crypt::X509;
use MIME::Base64;
our $VERSION = '0.0.1';

###############################################################################
# This script can be used to automatically create a ca_bundle file containing
# all of the CA certificates in a trust chain (up to the Trust Root Anchor)
#
# Dependencies required to execute this script:
# Network access to the Internet (http_proxy/https_proxy environment variables will be used if defined)
# OpenSSL (https://www.openssl.org/)
# Perl Interpreter (https://www.perl.org/)
# perl modules: libwww-perl (https://metacpan.org/pod/LWP)
#               File::Copy (https://metacpan.org/pod/File::Copy)
#               File::Path (https://metacpan.org/pod/File::Path)
#               File::Spec (https://metacpan.org/pod/File::Spec)
#               File::Spec::Functions(https://metacpan.org/pod/File::Spec::Functions)
#               Crypt::X509 (https://metacpan.org/pod/Crypt::X509)
#               MIME::Base64 (https://metacpan.org/pod/MIME::Base64)
#
#
# The Trust Anchor Certificate can be specified as a command-line argument
# or set in the $trustRootCAcert script variable below.  A file path or URL can
# be used to specify the Trust Anchor CA Certificate to use.
#
# Trust Anchor Reference: https://tools.ietf.org/html/rfc6024
#
# This script will obtain the certificate specified in $trustRootCAcert variable
# either through the filesystem or by downloading from the Internet.
#
# The Authority Information Access (AIA) field contained in the Subject Information Access (SIA)
# field of the Trust Root CA certificate is used to obtain the location of a PKCS7 (.p7c/.p7b)
# file containing all the CA Certs that have been issued by the Trust Root CA.
#
#  Tasks performed by this script:
#  1 - The PKCS7 file is downloaded from the http URI specified in the SIA field of the certificate
#
#  2 - The openssl command is then used to extract the certificates within the PKCS7 file
#      into a temporary file. (Certificates are extracted using PEM encoding)
#
#  3 - Each CA Certificate in the temporary file is then parsed and validated against
#      the following requirements:
#      - The certificate is not a self-signed certificate
#      - The certificate does not have the same Subject Key Identifier as the Trust Root CA
#        (not a Cross Certified CA Certificate)
#      - The certificate contains the "REQUIRED_OID" Certificate Policy OID specified in the $oid hash
#      - The certificate's subject does not contain any of the strings specified
#        in the @certsToExcludeFromBundle array variable
#
#  4 - If the certificate meets the validation requirements the certificate is added
#      to a temporary file (which will become the ca_bundle file)
#
#  5 - Using the AIA Certificate Repository data in the SIA field of this certificate, Task #1 is repeated
#
#  After all certificates have been processed the temporary ca_bundle file is copied
#  to the file specified in the $CATrustChainBundleFile variable
#
#  If the $delete_temp_files variable is set to "yes", all files created by this
#  script will be deleted.
#
# Notice: To avoid unexpected errors with subsequent runs of this script
#         Setting $delete_temp_files to "yes" is recommended
#
###############################################################################

# Set $DEBUG to 1 to print verbose execution messages to STDOUT
my $DEBUG = 1;

# Specify the filepath to write the created CA Trust Chain bundle to
my $CATrustChainBundleFile = "./ca_bundle.pem";

# $trustRootCAcert specifies the Trust Root CA to start crawling from
my $trustRootCAcert = $ARGV[0] || "http://http.fpki.gov/fcpca/fcpca.crt";

# $delete_temp_files specifies if the downloaded CA Certificates
# and PKCS7 files should be deleted after running
my $delete_temp_files = "no";

# $certsToExcludeFromBundle specifies certificate Subjects that meet the criteria
# for inclusion but should not be included in the resulting CA bundle file
# The elements in the $certsToExcludeFromBundle Array can be the entire SubjectDN
# of the certificate or a subset of text within the Subject (be as specific as possible though)
my @certsToExcludeFromBundle = (
        'CN=DOD EMAIL CA',
        'CN=DOD ID SW CA',
    );

# $tmpdir determines where the CA certificate and PKCS7 files will be downloaded to
# if $tmpdir is set to "USE_SYSTEM_TEMP" the OS temp directory will be used
my $tmpdir = "USE_SYSTEM_TEMP";

# X.509 Certificate Extension OID definitions
my $oid = {
    'Subject Information Access'       => '1.3.6.1.5.5.7.1.11',
    'REQUIRED_OID'                     => '2.16.840.1.101.3.2.1.3.13', # id-fpki-common-authentication
    'Certificate Authority Repository' => '1.3.6.1.5.5.7.48.5',
    'Certificate Authority Issuers'    => '1.3.6.1.5.5.7.48.2',
    'Certificate Policy'               => '2.5.29.32',
};

###############################################################################
# Get the system temp directory
$tmpdir = File::Spec->tmpdir() if $tmpdir eq "USE_SYSTEM_TEMP";
$tmpdir = canonpath("$tmpdir/SIACrawlerCache"); mkdir($tmpdir);

$CATrustChainBundleFile = canonpath($CATrustChainBundleFile); # fix the path if needed

# use a temporary file while building the TrustChainBundleFile, in case of errors
my $tmpTrustChainBundleFile = canonpath("$tmpdir/ca_bundle.pem");
open( my $fh, '>', $tmpTrustChainBundleFile ) || print "Error creating temporary file: $tmpTrustChainBundleFile\n" && exit();
close($fh);

###############################################################################

my $tmpFile = 0;
my $processedFile;
my $trustRootCASKI;

startCrawling();

# Copy $tmpdir/ca_bundle.pem to $CATrustChainBundleFile
copy( $tmpTrustChainBundleFile, $CATrustChainBundleFile );

# delete $tmpdir
if ( lc($delete_temp_files) eq "yes" ){
    print "\t* Deleting downloaded files\n" if $DEBUG;
    remove_tree($tmpdir, { verbose => $DEBUG });
}

sub showHeader {
    print ("********************************************************************\n");
    print ("*                CA Bundle Builder $VERSION\n*\n");
    print ("* Trust Root CA Certificate: $trustRootCAcert\n");
    print ("* TempDir: $tmpdir\n") if $DEBUG;
    print ("* libwww-perl-$LWP::VERSION\n*\n") if $DEBUG;
    print ("********************************************************************\n\n");
}

sub help {
    # TODO: implement command line argument parsing (GetOpt...)
    showHeader();
    use File::Basename;
    print "\nUsage: ", basename($0), " [options]\n";
    print "Options:\n";
    exit();
}

#Get the Trust Root CA certificate from the local filesystem (if a filepath is provided)
# or from the network (using LWP) if a URL is provided, and start SIA crawling
sub startCrawling {
    showHeader() unless shift;
    print "\t* startCrawling()\n" if $DEBUG;
    if ( isURL($trustRootCAcert) ){
        print ("Downloading TrustRootCA certificate from $trustRootCAcert\n") if $DEBUG;
        lwpget($trustRootCAcert);
    } else {
        print ("Using TrustRootCA certificate from $trustRootCAcert\n") if $DEBUG;
        if (-f $trustRootCAcert){
            fsget($trustRootCAcert);
        } else {
            print ("Error:  $trustRootCAcert does not seem to exist...\n");
        }
    }
}

#Determine if the provided string is a URL or a file
sub isURL {
    my $data = shift;
    print "\t* isURL($data)\n" if $DEBUG;
    if ( $data =~ /^http:|https:|ftp:/ && ! -f $data ){
        return(1);
    } elsif ( -f $data ) {
        return(0);
    } else {
        die("IOException: File not found: $data\n");
    }
}

sub fsget {
    my $filename = shift;
    print "\t* fsget($filename)\n" if $DEBUG;
    if (-f $filename && -r $filename){
        parseDownloadedFile($filename);
    } else {
        print ("ERROR: Unable to open $filename for reading\n");
    }
}

sub lwpget {
    my $URL = shift;
    print "\t* lwpget($URL)\n" if $DEBUG;

    $URL =~ /.+\/(.+)$/;
    my $filename = $1;
    my $dlFilePath = canonpath("$tmpdir/$filename");

    # skip files that have already been downloaded
    if ( $processedFile->{$dlFilePath} ){
        print ("\t* $filename already processed, skipping\n") if $DEBUG;
        return();
    }

    my $ua = LWP::UserAgent->new( agent => "SIACrawler $VERSION " );
    $ua->timeout(10);
    $ua->env_proxy;

    # set $trustRootCAcert to the downloaded certificate file path; used in parseCert()
    $trustRootCAcert = $dlFilePath if ( $URL eq $trustRootCAcert );
    print ("\t* Downloading to $dlFilePath\n") if $DEBUG;
    my $res = $ua->mirror( $URL, $dlFilePath );
    if ($res->is_success) {
        print ("\t* Downloaded successfully\n") if $DEBUG;
    } elsif ($res->code eq "304") {
        print ("\t* Skip downloading $URL (cache up-to-date)\n") if $DEBUG;
    } else {
        print ("Error downloading CA Certificate from $URL: ", $res->status_line, "\n");
        return();
    }
    parseDownloadedFile($dlFilePath);
}

sub writeToBundleFile {
    print "\t* writeToBundleFile()\n" if $DEBUG;
    my $x509    = shift;
    my $certPEM = shift;
    my $file    = shift;

    # $tmpTrustChainBundleFile was created earlier
    open( my $fh, '>>', $tmpTrustChainBundleFile ) || print "Error writing to $tmpTrustChainBundleFile\n";
    print $fh "subject= " . joinX509Subject($x509) . "\n";
    print $fh "issuer= " . joinX509Issuer($x509) . "\n";
    print $fh "not_after= " . localtime($x509->not_after) . "\n";
    print $fh $certPEM,"\n";
    close($fh);
}

sub parseDownloadedFile {
    my $file = shift;
    print "\t* parseDownloadedFile($file)\n" if $DEBUG;
    if ( $file =~ /\.p7c$|\.p7b$/ ){
        # file is a PKCS7 file
        parsePKCS7($file) && return();
    }

    if ( $file =~/\.der$|\.pem$|\.cer$|\.crt$/ ){
        # file is an X.509 certificate
        parseCert($file) && return();
    }
}

sub renameTempFile{
    my $file = shift;
    my $x509 = shift;
    my $newfile;
    # rename $file to Subject--Issuer.cer if $file is one of our temp cert files
    if ( $file eq canonpath("$tmpdir/$tmpFile.crt") ) {
        my $subject = @{ $x509->Subject }[-1];
        $subject =~ s/\s//g;
        $subject =~ s/CN=|OU=//;
        my $issuer  = @{ $x509->Issuer }[-1];
        $issuer =~ s/\s//g;
        $issuer =~ s/CN=|OU=//;
        $newfile = canonpath("$tmpdir/$subject--$issuer.cer");
        my $i = 1;
        while ( -f $newfile ){
            $i++;
            print "\t* $newfile already exists, incrementing filename...\n" if $DEBUG;
            $newfile = canonpath("$tmpdir/$subject-$i--$issuer.cer");
        }
        move($file, $newfile);
        print "Renamed $file to $newfile\n" if $DEBUG;
        $file = $newfile;
    }
    return($file);
}

sub parseCert {
    my $file = shift;
    print "\t* parseCert($file)\n" if $DEBUG;
    print "\n------------------------------------------------------------\n" if $DEBUG;
    if ( -B $file ){
        print ("\t* Converting DER encoded certificate to PEM ($file)\n") if $DEBUG;
        print (`openssl x509 -in $file -inform DER -outform PEM -out $file`);
    } elsif ( -z $file ){
        print ("ERROR: Downloaded file $file is empty\n");
        unlink($file); # delete empty file
        return();
    }

    open (my $fh, '<', $file) || print "Error opening $file\n" && return();
    $/ = undef; # slurp mode
    my $certPEM = <$fh>; # slurp $file contents into $certPEM
    close($fh);
    my $certData = $certPEM;
    $certData =~ s/-----.+-----|\n//g;

    # read the certificate into a Crypt::X509 object
    my $x509 = Crypt::X509->new( cert => MIME::Base64::decode($certData) );

    $file = renameTempFile($file, $x509);
    $processedFile->{$file} = 1; # add $file to parse history

    my $extensionData = parseExtensions($x509);

    if ( $trustRootCAcert eq "$file"){
        # Don't check the Trust Root CA Cert for the required extension
        $trustRootCASKI = $x509->subject_keyidentifier; # store trust root SKI for cross cert exclusion
        writeToBundleFile($x509, $certPEM);
        # download and crawl Subject Information Access file
        if ($extensionData->{'sia'}){
            lwpget( $extensionData->{'sia'} );
        } else {
            print "FATAL ERROR: Subject Information Access URI not found in Trust Root CA certificate: ", joinX509Subject($x509), "\n";
            exit();
        }
    } else {
        # Skip self signed certificates (Trust Root CA should be the only self signed cert in the bundle)
        if ( ! defined($x509->key_identifier) || $x509->key_identifier eq $x509->subject_keyidentifier) {
            print ("\t* Skipping self-signed certificate: $file\n") if $DEBUG;
            #print "Delete self-signed: ", unlink($file), "\n" || print "Error deleting self-signed cert: $!\n";
            return();
        }

        # Skip cross certified certs
        if ($trustRootCASKI eq $x509->subject_keyidentifier){
            print "\t* Skipping cross certified CA certificate\n" if $DEBUG;
            return();
        }

        # Skip processing certificates that don't have the extension specified in $oid->{'REQUIRED_OID'}
        if ( hasCommonAuthPolicy($x509) ) {
            print "\t* ", $oid->{'REQUIRED_OID'}, " defined\n" if $DEBUG;
            my $subjectDn = joinX509Subject($x509); # get current cert's subject
            for my $excludedCertData ( @certsToExcludeFromBundle ){
                if (  $subjectDn =~ /$excludedCertData/ ){
                    print ("$subjectDn matches exclusion: $excludedCertData\n");
                    return();
                }
            }
            writeToBundleFile($x509, $certPEM, $file);
            # download and crawl Subject Information Access file
            if ($extensionData->{'sia'}){
                lwpget( $extensionData->{'sia'} );
            } else {
                print "Unable to locate Subject Information Access URI for ", joinX509Subject($x509), "\n" if $DEBUG;
            }
        }
    }
}

sub parseExtensions {
    print "\t* parseExtensions()\n" if $DEBUG;
    my $x509   = shift;
    my $extensionInfo = { 'sia' => undef, 'commonAuth' => undef };

    for my $extension ( @{ $x509->{'tbsCertificate'}{'extensions'} } ){
        if ( $extension->{'extnID'} eq $oid->{'Subject Information Access'} ){
            print "\t* Found Subject Information Access extension\n" if $DEBUG;
            $extensionInfo->{'sia'} = parseSIAuri($extension);
        } elsif ( $extension->{'extnID'} eq $oid->{'REQUIRED_OID'} ){
            print "\t* Found ", $oid->{'REQUIRED_OID'}, " extension\n" if $DEBUG;
            $extensionInfo->{'commonAuth'} = 1;
        }
    }
    return($extensionInfo);
}

sub getTmpFileName {
    $tmpFile++;
    return ( canonpath("$tmpdir/$tmpFile.crt") );
}

sub parsePKCS7 {
    my $file    = shift;
    print "\t* parsePKCS7($file)\n" if $DEBUG;

    $processedFile->{$file} = 1;

    my $tmpBundle   = canonpath("$tmpdir/p7c.tmp");

    my $err = undef;
    # convert p7c to cert bundle file
    if ( -B $file ){
        $err = `openssl pkcs7 -inform der -in $file -print_certs -out $tmpBundle 2>&1`;
    } else {
        $err = `openssl pkcs7 -inform pem -in $file -print_certs -out $tmpBundle 2>&1`;
        if ($err){
            print "Error parsing ", basename($file), ": Attempting to fix Base64 formatting and re-parse\n" if $DEBUG;
            fixPKCS7formatting($file); # reformat the file data
        }
    }

    # catch openssl pkcs7 errors
    print "Error parsing PKCS7 object from ", basename($file), "\n" && return() if $err;

    my $tmpFileName = getTmpFileName();

    print "\t* Parsing $tmpBundle\n" if $DEBUG;
    open(my $fh, '<', $tmpBundle) || print ("Error opening $tmpBundle: $!");
        my $cert   = "";
        my $status = 0;
        for my $line ( split("\n", <$fh>) ){
            next unless $line;
            next if $line =~ /^subject|^issuer/;
            if ( $line =~ /-----BEGIN CERTIFICATE-----/ ){
                print "\t\t* Found certificate in bundle\n" if $DEBUG;
                $status = 1;
                $cert .= "$line\n";
                next;
            } elsif ( $line =~ /-----END CERTIFICATE-----/ ){
                $status = 0;
                $cert .= "$line\n";
                print "\t* Writing certificate data to $tmpFileName\n" if $DEBUG;
                open(my $F, '>', $tmpFileName) || print "Error creating temp file: $tmpFileName\n";
                print $F $cert;
                close($F);
                $cert = "";
                parseCert($tmpFileName);
                $tmpFileName = getTmpFileName();
                next;
            } elsif ($status == 1){
                $cert .= "$line\n";
            }
        }
    close($fh);
}

sub fixPKCS7formatting {
    # add PKCS7 header and footer and re-format the Base64 to 64 chars per line
    my $file = shift;
    open(my $pkcs7, '<', "$file") || print "Error reading $file: $!\n" && return(undef);
        local($/) = undef; #slurp
        my $pkcs7data = <$pkcs7>;
    close($pkcs7);

    my $header = "-----BEGIN PKCS7-----";
    my $footer = "-----END PKCS7-----";

    my $b64Data .= $pkcs7data;
    $b64Data =~ s/(.{1,64})/$1\n/g; # insert line break at 64 chars

    if ( $pkcs7data !~ /^-----BEGIN PKCS7-----/ ){
        # add PKCS7 header to top of the file
        $b64Data = "$header\n$b64Data";
    }

    if ( $pkcs7data !~ /-----END PKCS7-----/ ){
        # append PKCS7 footer to bottom of the file
        $b64Data .= $footer;
    }

    # write Base64 data back to the file with header and footer
    open(my $new_pkcs7, '>', "$file") || print "Error writing $file: $!\n" && return(undef);
        print $new_pkcs7 $b64Data;
    close($new_pkcs7);
    parsePKCS7($file); # try parsing the new file
}

sub parseSIAuri{
    my $siaExtension = shift;
    my @sia = Crypt::X509::_init('SubjectInfoAccessSyntax')->decode($siaExtension->{'extnValue'});
    for my $siaElementArrayRef (@sia){
        for my $siaElement (@{$siaElementArrayRef}){
            if ( $siaElement->{'accessMethod'} eq $oid->{'Certificate Authority Repository'} ){
                my $uri = $siaElement->{'accessLocation'}{'uniformResourceIdentifier'};
                if ($uri =~ /^http/){
                    return($uri);
                }
            }
        }
    }
    return(undef);
}

sub hasCommonAuthPolicy {
    my $x509 = shift;
    my $extension;
    my $CertPolicies = [];
    my $extensions   = $x509->{'tbsCertificate'}->{'extensions'};
    if ( !defined $extensions ) { return undef; }
    ;    # no extensions in certificate
    for $extension ( @{$extensions} ) {
        if ( $extension->{'extnID'} eq $oid->{'Certificate Policy'} ) {
            my @policies = Crypt::X509::_init('CertificatePolicies')->decode( $extension->{'extnValue'} ); # decode the value
            for my $policyArrayRef ( @policies ) {
                for my $policy ( @{$policyArrayRef} ) {
                    if ( $policy->{'policyIdentifier'} eq $oid->{'REQUIRED_OID'} ){
                        return(1);
                    }
                }
            }
        }
    }
    return undef;
}

sub joinX509Subject {
    my $x509 = shift;
    return ( join(',', @{$x509->Subject}) );
}

sub joinX509Issuer {
    my $x509 = shift;
    return ( join(',', @{$x509->Issuer}) );
}
