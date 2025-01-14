<#
.SYNOPSIS
    A class used to perform various rest api tasks with Manage Engine
    Key Manager Plus
.DESCRIPTION
	A class that allows you to perform various rest api tasks with Manage Engine
    Key Manager Plus
.NOTES
	Author:       Kurt Marvin
	
	Changelog:
	   1.0        Initial release
#>

#############################################################
# Import Modules                                            #
#############################################################

#############################################################
# Variables                                                 #
#############################################################
$global:KMPBaseURL = ""
$global:KMPAPIKey  = ""
[hashtable]$global:KMPHeader

$global:apiAddCert                      = "/api/pki/restapi/addCertificate?INPUT_DATA={operation:{Details:{fileType:CERTFILE}}}"
$global:apiCreateCert                   = "/api/pki/restapi/createCertificate"
$global:apiGetAllCerts                  = "/api/pki/restapi/getAllSSLCertificates"
$global:apiGetCertDetails               = "/api/pki/restapi/getCertificateDetails"
$global:apiUpdateAdditionalCertDetails  = "/api/pki/restapi/updateSSLAdditionalFields"

$global:isConnected = $false

#############################################################
# ENUMS                                                     #
#############################################################

enum KMPValidityType {
    days
    hours
    minutes
}

enum KMPKeySize {
    Weak = 2048
    Medium = 3072
    Strong = 4096
}

enum KMPAlgorithm {
    RSA
    DSA
    EC
}

enum KMPSignatureAlgorithm {
    SHA256
    SHA384
    SHA512
}

enum KMPStoreType {
    PKCS12
    JKS
}

#############################################################
# Classes                                                   #
#############################################################
# Used as a object type for KMP Additional Fields
class KMPAdditionalField {
    [string]$ADDITIONALFIELDNAME
    [string]$ADDITIONALFIELDVALUE

    KMPAdditionalField([string]$ADDITIONALFIELDNAME,[string]$ADDITIONALFIELDVALUE) {
        $this.ADDITIONALFIELDNAME = $ADDITIONALFIELDNAME
        $this.ADDITIONALFIELDVALUE = $ADDITIONALFIELDVALUE
    }
}

#############################################################
# Helper Functions                                          #
#############################################################
function Confirm-KMPConnected {
    if (!$global:isConnected) {
        Write-Error "Please connect to KMP first by using the Connect-KMP command."
    }

    return $global:isConnected
}

function ConvertTo-KMPQueryString {
    <#
    .SYNOPSIS
        Initilizes the KMP connection
    .DESCRIPTION
        Initilizes the KMP connection by setting the URL and the API Key.
    .PARAMETER Object
        The object to convert to a query string
    .OUTPUTS
        Returns a string formated for KMP query string
    #>
    Param (
        $Object
    )

    $bodyJson = $Object | ConvertTo-Json -Depth 5
    $bodyJson = ($bodyJson -replace "`r`n", "") -replace '("[^"\r\n]*")|\s*', '$1'
    $bodyJson = [System.Web.HttpUtility]::UrlEncode($bodyJson)
    $bodyJson = "INPUT_DATA=" + $bodyJson

    return $bodyJson
}

#############################################################
# Functions                                                 #
#############################################################
function Connect-KMP {
    <#
    .SYNOPSIS
        Initilizes the KMP connection
    .DESCRIPTION
        Initilizes the KMP connection by setting the URL and the API Key.
    .PARAMETER URL
        The URL to KMP
    .PARAMETER APIKey
        The API key to connect to KMP
    #>
    Param (
        [string]$URL,
        [string]$APIKey
    )

    $global:KMPBaseURL = $URL
    $global:KMPAPIKey  = $APIKey

    $global:KMPHeader  = @{ "AUTHTOKEN" = $global:KMPAPIKey }

    $global:isConnected = $true
}

# Gets all the certificates in KMP
function Get-KMPAllCert {
    <#
    .SYNOPSIS
        Get all the KMP certificates
    .DESCRIPTION
        Get all the KMP certificates based on the ExpiryDaysLessThan which by default is 9000
    .PARAMETER ExpiryDaysLessThan
        The number of days to go back before the certificates expire.
    .OUTPUTS
        An array of certificate objects
    #>
    Param(
        [int]$ExpiryDaysLessThan
    )
    
    #Verify Connection
    if (!(Confirm-KMPConnected)) {return $null}
    
    # URL Variables
    $KMPUri = $global:KMPBaseURL + $global:apiGetAllCerts
    $requestUri = [System.UriBuilder]$KMPUri

    # The query string in object form
    if ($ExpiryDaysLessThan) {
        $body = @{
            operation = @{
                Details = @{
                    withExpiryDaysLessThan = $ExpiryDaysLessThan.ToString()
                }
            }
        }

        # Assign the converted query to the URI if needed
        $requestUri.Query = ConvertTo-KMPQueryString -Object $body
    }
    
    # Make the web request
    $kmpResponse = Invoke-WebRequest -Uri $requestUri.Uri -Headers $global:KMPHeader -Method Get

    # Convert the response json to an object
    $kmpResponse = $kmpResponse.Content | ConvertFrom-Json -Depth 5
    
    return $kmpResponse.details
}

function Get-KMPCert {
    <#
    .SYNOPSIS
        Get a KMP certificate object
    .DESCRIPTION
        Get a KMP certificate. This is the actual certificate data that makes up the certificate file.
    .PARAMETER CN
        The common name of the certificate
    .PARAMETER SerialNumber
        The Serial Number of the certificate
    .OUTPUTS
        The certificate data which can be used to create a certificate file
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [string]$CN,
        [Parameter(Mandatory=$true)]
        [string]$SerialNumber
    )
    #Verify Connection
    if (!(Confirm-KMPConnected)) {return $null}

    # URL Variables
    $KMPUri = $global:KMPBaseURL + $global:apiGetCert

    # The query string in object form
    $body = @{
        operation = @{
            Details = @{
                common_name = $CN
                serial_number = $SerialNumber
            }
        }
    }

    # Convert query string object to KPM query string format
    $bodyJson = ConvertTo-KMPQueryString -Object $body

    # Create the Uri
    $requestUri = [System.UriBuilder]$KMPUri
    $requestUri.Query = $bodyJson

    # Make the web request
    $kmpResponse = Invoke-WebRequest -Uri $requestUri.Uri -Headers $global:KMPHeader -Method Get

    # Convert the response json to an object
    $kmpResponse = $kmpResponse.Content | ConvertFrom-Json -Depth 5

    return $kmpResponse.details
}

function Get-KMPCertDetail {
    <#
    .SYNOPSIS
        Get a KMP certificate details
    .DESCRIPTION
        Get a KMP certificate details. This is the metadata about the certificate.
    .PARAMETER CN
        The common name of the certificate
    .PARAMETER SerialNumber
        The SerialNumber of the certificate
    .OUTPUTS
        The certificate metadata
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [string]$CN,
        [Parameter(Mandatory=$true)]
        [string]$SerialNumber
    )
    #Verify Connection
    if (!(Confirm-KMPConnected)) {return $null}

    # URL Variables
    $KMPUri = $global:KMPBaseURL + $global:apiGetCertDetails
    
    # The query string in object form
    $body = @{
        operation = @{
            Details = @{
                common_name = $CN
                serial_number = $SerialNumber
            }
        }
    }
    
    # Convert query string object to KPM query string format
    $bodyJson = ConvertTo-KMPQueryString -Object $body
    
    # Create the Uri
    $requestUri = [System.UriBuilder]$KMPUri
    $requestUri.Query = $bodyJson
    
    # Make the web request
    $kmpResponse = Invoke-WebRequest -Uri $requestUri.Uri -Headers $global:KMPHeader -Method Get

    # Convert the response json to an object
    $kmpResponse = $kmpResponse.Content | ConvertFrom-Json -Depth 5
    
    return $kmpResponse.details
}

function Add-KMPCert {
    <#
    .SYNOPSIS
        Adds a certificate file to KMP
    .DESCRIPTION
        Adds a certificate file to KMP
    .PARAMETER File
        A file object to add to KMP
    .OUTPUTS
        The certificate id of the newely created certificate
    #>
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.IO.FileSystemInfo] $File
    )
    #Verify Connection
    if (!(Confirm-KMPConnected)) {return $null}

    $KMPUri = $global:KMPBaseURL + $global:apiAddCert

    # Create the form payload
    $body = @{
        File = Get-Item -Path $File
    }

    # Make the web request
    $kmpResponse = Invoke-WebRequest -Uri $KMPUri -Headers $global:KMPHeader -Method Post -Form $body -ContentType "multipart/form-data"

    # Convert the response json to an object
    $kmpResponse = $kmpResponse.Content | ConvertFrom-Json -Depth 5

    return $kmpResponse.result
}

function New-KMPCert {
    <#
    .SYNOPSIS
        Creates a new KMP certificate signed by KMP
    .DESCRIPTION
        Creates a new KMP certificate signed by KMP. 
    .PARAMETER CN
        The common name of the certificate
    .PARAMETER SAN
        The subject alternative names seperated by commas within a string
    .PARAMETER OrgUnit
        The organization unit issuing the certificate
    .PARAMETER Org
        The name of the company
    .PARAMETER Location
        The location of the company issuing the certificate
    .PARAMETER State
        The state of the company issuing the certificate
    .PARAMETER Country
        The 2 letter country code of the company issuing the certificate
    .PARAMETER Password
        The password for the certificate store
    .PARAMETER Email
        The expiry notification email
    .PARAMETER ValidityType
        The type of unit to calculate when the certificate expires. days, hours, or minutes.
    .PARAMETER Validity
        The number of validity type units. Ex. 365 days if validity type is days
    .PARAMETER Algorithm
        The algorithm to use to sign the certificate
    .PARAMETER Length
        The bit length of the encryption used
    .PARAMETER SignatureAlgorithm
        The Signature algorithm to be used
    .PARAMETER StoreType
        The store type of the certificate. PKCS12 or JKS
    .OUTPUTS
        The SSL_RESOURCEID of the newely created certificate
    #>
    Param(
        [string]$CN,
        [string]$SAN,
        [string]$OrgUnit,
        [string]$Org,
        [string]$Location,
        [string]$State,
        [string]$Country,
        [string]$Password,
        [KMPValidityType]$ValidityType = [KMPValidityType]::Days,
        [int]$Validity = 365,
        [KMPAlgorithm]$Algorithm = [KMPAlgorithm]::RSA,
        [KMPKeySize]$Length = [KMPKeySize]::Strong,
        [KMPSignatureAlgorithm]$SignatureAlgorithm = [KMPSignatureAlgorithm]::SHA256,
        [KMPStoreType]$StoreType = [KMPStoreType]::PKCS12
    )
    #Verify Connection
    if (!(Confirm-KMPConnected)) {return $null}

    # URL Variables
    $KMPUri = $global:KMPBaseURL + $global:apiCreateCert
    
    # The query string in object form
    $body = @{
        operation = @{
            Details = @{
                CNAME = $CN
                ALT_NAMES = $SAN
                ORGUNIT = $OrgUnit
                ORG = $Org
                LOCATION = $Location
                STATE = $State
                COUNTRY = $Country
                PASSWORD = $Password
                VALIDITY_TYPE = $ValidityType.ToString()
                VALIDITY = $Validity.ToString()
                ALG = $Algorithm.ToString()
                LEN = ([int]$Length).ToString()
                SIGALG = $SignatureAlgorithm.ToString()
                StoreType = $StoreType.ToString()
            }
        }
    }
    
    # Convert query string object to KPM query string format
    $bodyJson = ConvertTo-KMPQueryString -Object $body
    
    # Create the Uri
    $requestUri = [System.UriBuilder]$KMPUri
    $requestUri.Query = $bodyJson
    
    # Make the web request
    $kmpResponse = Invoke-WebRequest -Uri $requestUri.Uri -Headers $global:KMPHeader -Method Post

    # Convert the response json to an object
    $kmpResponse = $kmpResponse.Content | ConvertFrom-Json -Depth 5
    
    return $kmpResponse.details
}

function Update-KMPCertAdditionalDetail {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$CN,
        [Parameter(Mandatory=$true)]
        [string]$SerialNumber,
        [Parameter(Mandatory=$true)]
        [array]$AdditionalFields
    )
    #Verify Connection
    if (!(Confirm-KMPConnected)) {return $null}

    # URL Variables
    $KMPUri = $global:KMPBaseURL + $global:apiUpdateAdditionalCertDetails

    # The query string in object form
    $body = @{
        operation = @{
            Details = @{
                common_name = $CN
                serial_number = $SerialNumber
                sslAdditionalFieldData = $AdditionalFields
            }
        }
    }
    
    # Create the Uri
    $requestUri = [System.UriBuilder]$KMPUri

    # Create the query and assign it to the request
    $requestUri.Query = ConvertTo-KMPQueryString -Object $body
    
    # Make the web request
    $kmpResponse = Invoke-WebRequest -Uri $requestUri.Uri -Headers $global:KMPHeader -Method Post

    # Convert the response json to an object
    $kmpResponse = $kmpResponse.Content | ConvertFrom-Json -Depth 5
    
    return $kmpResponse.details
}

