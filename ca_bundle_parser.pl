use warnings;
use strict;
use Getopt::Long;
use Crypt::X509;
use File::Basename;
use MIME::Base64;
use Try::Tiny;
my $VERSION = '0.0.1';

Getopt::Long::Configure ('bundling', 'ignorecase_always', 'auto_version', 'auto_help');

my $cert_bundle;

my $opts = {
		'Subject'                    => 0,
		'Issuer'                     => 0,
		'KeyUsage'                   => 0,
		'ExtKeyUsage'                => 0,
		'SubjectAltName'             => 0,
		'authorityCertIssuer'        => 0,
		'not_before'                 => 0,
		'not_after'                  => 0,
		'subject_email'              => 0,
		'pubkey_size'                => 0,
		'pubkey_algorithm'           => 0,
		'PubKeyAlg'                  => 0,
		'version'                    => 0,
		'version_string'             => 0,
		'serial'                     => 0,
		'sig_algorithm'              => 0,
		'SigEncAlg'                  => 0,
		'SigHashAlg'                 => 0,
		'authority_serial'           => 0,
		'CertificatePolicies'        => 0,
		'EntrustVersionInfo'         => 0,
		'BasicConstraints'           => 0,
		'SubjectDirectoryAttributes' => 0,
		'PGPExtension'               => 0
	};

my $Crypt_X509_methods = {
		'Subject'                    => \$opts->{'Subject'},
		'Issuer'                     => \$opts->{'Issuer'},
		'KeyUsage'                   => \$opts->{'KeyUsage'},
		'ExtKeyUsage'                => \$opts->{'ExtKeyUsage'},
		'SubjectAltName'             => \$opts->{'SubjectAltName'},
		'authorityCertIssuer'        => \$opts->{'authorityCertIssuer'},
		'not_before'                 => \$opts->{'not_before'},
		'not_after'                  => \$opts->{'not_after'},
		'subject_email'              => \$opts->{'subject_email'},
		'pubkey_size'                => \$opts->{'pubkey_size'},
		'pubkey_algorithm'           => \$opts->{'pubkey_algorithm'},
		'PubKeyAlg'                  => \$opts->{'PubKeyAlg'},
		'version'                    => \$opts->{'version'},
		'version_string'             => \$opts->{'version_string'},
		'serial'                     => \$opts->{'serial'},
		'sig_algorithm'              => \$opts->{'sig_algorithm'},
		'SigEncAlg'                  => \$opts->{'SigEncAlg'},
		'SigHashAlg'                 => \$opts->{'SigHashAlg'},
		'authority_serial'           => \$opts->{'authority_serial'},
		'CertificatePolicies'        => \$opts->{'CertificatePolicies'},
		'EntrustVersionInfo'         => \$opts->{'EntrustVersionInfo'},
		'BasicConstraints'           => \$opts->{'BasicConstraints'},
		'SubjectDirectoryAttributes' => \$opts->{'SubjectDirectoryAttributes'},
		'PGPExtension'               => \$opts->{'PGPExtension'},
	};

GetOptions( %{$Crypt_X509_methods},
           	'v|verbose' => \$opts->{'verbose'},
           	'f|bundle|file=s' => \$cert_bundle,
           	'extract=s' => \$opts->{'extract'},
           	'x' => \$opts->{'extract'},
           	'n' => \$opts->{'numbered'},
           	'h|help|?|man' => sub { HelpMessage(); }
           );

HelpMessage() unless $cert_bundle;

open(my $fh, '<', "$cert_bundle") || die ("$!");
my @certBundle;
my $cert = "";
my $status = 0;
for my $line (<$fh>){
	#chomp($line);
	next unless $line;
	#$line =~ s/^\s+//;
	if ( $line =~ /-----BEGIN CERTIFICATE-----/ ){
		$status = 1;
		#do not include certificate header
		next;
	} elsif ( $line =~ /-----END CERTIFICATE-----/ ){
		$status = 0;
		#do not include certificate footer
		push(@certBundle, $cert);
		$cert = "";
		next;
	}
	if ($status == 1){
		$cert .= $line;
	}
}
close($fh);

if ( $opts->{'extract'} ){
	print("Error: Directory to extract certificates to not specified correctly after -extract option\n") && exit() if ($opts->{'extract'} =~ /^-/);
	if ( $opts->{'extract'} eq "" || $opts->{'extract'} == 1){
		# assume -x option was used, and extract certs to "$cert_bundle"_certs directory
		$opts->{'extract'} = basename($cert_bundle) . "_certs";
	}
	# Create certificates directory if it doesn't already exist
	mkdir($opts->{'extract'}) unless (-d $opts->{'extract'});
}

my $certNumber = 0;
my $certOrder = 0;
for my $cert (@certBundle){
	# read the certificate into a Crypt::X509 object
    my $x509 = Crypt::X509->new( cert => MIME::Base64::decode($cert) );
	if ( $opts->{'extract'} ){
		# Create a new file containing the PEM encoded certificate data
		my $filename = @{$x509->Subject}[-1];
		$filename =~ s/ /_/g;
		$filename =~ s/OU=|CN=//;
		if ($opts->{'numbered'}){
			$certNumber++;
			$certOrder = '0'. $certNumber if ($certNumber < 1000);
			$certOrder = '0'. $certOrder if ($certNumber < 100);
			$certOrder = '0'. $certOrder if ($certNumber < 10);
			open(my $fh, '>', $opts->{'extract'}."/$certOrder-$filename.crt") || die "Error creating " . $opts->{'extract'}."/$certOrder-$filename.crt : $!\n";
			print $fh "-----BEGIN CERTIFICATE-----\n";
			print $fh $cert;
			print $fh "-----END CERTIFICATE-----\n";
			close($fh);
			$certOrder = "";
		} else {
			my $i=1;
			while ( -e $filename.".crt"){
				$filename = $filename."_".$i;
				print ".";
				$i++;
			}
			open(my $fh, '>', $opts->{'extract'}."/$filename.crt") || die "Error creating $filename.crt. $!\n";
			print $fh "-----BEGIN CERTIFICATE-----\n";
			print $fh $cert;
			print $fh "-----END CERTIFICATE-----\n";
			close($fh);
		}
		next
	}

	my $manifest = createManifest($opts->{'extract'} . "/manifest.txt") if $opts->{'extract'};

	print ("\n");
	for my $key ( sort keys %{$Crypt_X509_methods} ){
		if ( $opts->{$key} || $opts->{'verbose'} ){
			try {
				my $value = "UNDEFINED";
				if ( ref($x509->$key) eq "ARRAY" ){
					$value = joinDnArray($x509->$key);
				} elsif ($value) {
					$value = $x509->$key ? $x509->$key : $value;
				}
				$value = localtime($value) if ($key eq "not_before" or $key eq "not_after");
				$value =~ s/policyIdentifier=//g;
				print ("$key: $value\n") if ($value ne "UNDEFINED" || $opts->{'verbose'});
				updateManifest($manifest, "$key: $value\n") if $opts->{'extract'};
			} catch {
				print ("$key: UNDEFINED\n") if $opts->{'verbose'};
			}
		}
		updateManifest($manifest, "\n----------------------------------------\n\n") if $opts->{'extract'};
	}
}

sub joinDnArray {
    my $arrayRef = shift || return ("NOT DEFINED");
    return ( join(',', @{$arrayRef}) );
}

sub createManifest {
	my $filename = shift;
	print "createManifest($filename)\n";
	open(my $fh, '>', $filename) || print "Error creating manifest file: $filename\n: $!" && return(undef);
	close($fh);
	return($filename);
}

sub updateManifest {
	my $filename = shift;
	my $text     = shift;
	print "updateManifest($filename, $text\n";
	return unless $filename;
	open(my $fh, '>>', $filename) || print "Error updating manifest file: $filename\n: $!" && return();
	print $fh $text;
	close($fh);
}

sub HelpMessage {
	print "ca_bundle_parser - Parse a concatenated list of Certificates from a textfile\n\n";
	print "Certificate attributes that do not exist will not be displayed unless -v or --verbose is specified\n";
	print "\nThis tool can also be used to parse a regular PEM encoded X.509 Certificate\n\n";
	print "Available Options:\n";
	print "-h, -help, -man, -?                Display this page\n";
	print "--bundle, --file, -f  [FILENAME]   Text file containing Certificate Bundle to read\n";
	print "--extract [DIRECTORY]              Directory to extract certificates into\n";
	print "-n                                 Prepend each extracted certificate with a number indicating the order it was found in the bundle file\n";
	print "-x                                 Extract certificates in a new directory containing the name of the bundle file\n";
	print "--verbose, -v                      Display all certificate information (same as specifying all options)\n";
	print "--Subject                          Display the certificate Subject\n";
	print "--Issuer                           Display the certificate Issuer\n";
	print "--KeyUsage                         Display the certificate KeyUsage\n";
	print "--ExtKeyUsage                      Display the certificate ExtKeyUsage\n";
	print "--SubjectAltName                   Display the certificate SubjectAltName\n";
	print "--authorityCertIssuer              Display the certificate Authority Cert Issuer\n";
	print "--not_before                       Display the Human readable not_before attribute\n";
	print "--not_after                        Display the Human readable not_after attribute (cert expiration date)\n";
	print "--subject_email                    Display the certificate subject_email\n";
	print "--pubkey_size                      Display the certificate pubkey_size\n";
	print "--pubkey_algorithm                 Display the certificate pubkey_algorithm\n";
	print "--PubKeyAlg                        Display the certificate PubKeyAlg\n";
	print "--version                          Display the certificate version\n";
	print "--version_string                   Display the certificate version_string\n";
	print "--serial                           Display the certificate Serial Number\n";
	print "--sig_algorithm                    Display the certificate sig_algorithm\n";
	print "--SigEncAlg                        Display the certificate Sig Enc Algorithm\n";
	print "--SigHashAlg                       Display the certificate Sig Hash Algorithm\n";
	print "--authority_serial                 Display the certificate Authority Serial Number\n";
	print "--CertificatePolicies              Display the certificate Certificate Policies\n";
	print "--EntrustVersionInfo               Display the certificate Entrust Version Info\n";
	print "--BasicConstraints                 Display the certificate Basic Constraints\n";
	print "--SubjectDirectoryAttributes       Display the certificate Subject Directory Attributes\n";
	print "--PGPExtension                     Display the certificate PGPExtension\n";
	exit();
}
