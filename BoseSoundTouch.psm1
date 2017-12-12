function Get-SoundTouchAccountToken {
    <#
        .SYNOPSIS
        Requests a Bose SoundTouch account token.
      
        .DESCRIPTION
        Requests a Bose SoundTouch account token from the Bose SoundTouch API.

        .PARAMETER Credential
        A valid Bose SoundTouch username and password.
                
        .PARAMETER ApiUri
        The URI for the Tesla public customer API.  If not specified then 'https://streaming.bose.com/streaming/account' will be used.

        .EXAMPLE
        The following prompts for Bose SoundTouch credentials and returns a token
    
        Get-SoundTouchAccountToken -Credential (Get-Credential)
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipeline)]
        [PSCredential]$Credential,

        [Parameter(Position=1)]
        [string]$ApiUri = "https://streaming.bose.com/streaming/account"
    )

    BEGIN {
        #region Global Variables
        $contentType = "application/vnd.bose.streaming-v1.1+xml"

        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add('Content-Length', '120')
        $headers.Add('Origin', 'file://')

        $headers.Add('version_ProtocolVersion', '59')
        $headers.Add('Authorization', 'null')
        $headers.Add('Accept', 'application/vnd.bose.streaming-v1.1+xml')
        $headers.Add('cache-control', 'no-cache')
        $headers.Add('ClientType', 'SOUNDTOUCH_COMPUTER_APP')
        $headers.Add('Accept-Encoding', 'gzip, deflate')
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Generating XML to POST to Bose SoundTouch API
        $body = @"
<?xml version="1.0" encoding="UTF-8"?><login><username>$($Credential.UserName)</username><password>$($Credential.GetNetworkCredential().password)</password></login>
"@
        #endregion Generating XML to POST to Bose SoundTouch API

        #region Posting credentials to Bose SoundTouch API
        $response = Invoke-WebRequest -Uri "$ApiUri/login" -Method Post -Body $body -Headers $headers -ContentType $contentType -ErrorAction Stop
        if (!$response) {
            throw
        }
        #endregion Posting credentials to Bose SoundTouch API

        #region Returning 'accountid' and 'authorization' as an object
        $xml = [xml]$response.Content
        @{
            AccountId = "$($xml.account.id)"
            Authorization = $response.Headers.Credentials
        }
        #endregion Returning 'accountid' and 'authorization' as an object
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchAccountDevice {
    <#
        .SYNOPSIS
        Gets all Bose SoundTouch devices associated with a SoundTouch account.
      
        .DESCRIPTION
        Gets all Bose SoundTouch devices associated with a SoundTouch account.  Optional paramters allow you to specify a particular device and returns an error if not found.

        .PARAMETER DeviceId
        Gets a device with the specified device ID.  Returns an error if not found.

        .PARAMETER IpAddress
        Gets a device with the specified IP address.  Returns an error if not found.

        .PARAMETER Name
        Gets a device with the specified friendly name.  Returns an error if not found.

        .PARAMETER ApiUri
        The URI for the Bose SoundTouch API.  If not specified then 'https://streaming.bose.com/streaming/account' will be used.

        .EXAMPLE
        The following gets all Bose SoundTouch devices in the SoundTouch account
    
        $Token = Get-SoundTouchAccountToken
        Get-SoundTouchAccountDevice -Token $Token

        .EXAMPLE
        The following gets the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipeline)]
        [psobject]$Token,

        [Parameter(Position=1,ValueFromPipeline)]
        [string]$DeviceId,

        [Parameter(Position=2,ValueFromPipeline)]
        [string]$IpAddress,

        [Parameter(Position=3,ValueFromPipeline)]
        [string]$Name,

        [Parameter(Position=4)]
        [string]$ApiUri = "https://streaming.bose.com/streaming/account"
    )

    BEGIN {
        #region Global Variables
        $contentType = "application/vnd.bose.streaming-v1.1+xml"

        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add('Content-Length', '120')
        $headers.Add('Origin', 'file://')

        $headers.Add('version_ProtocolVersion', '59')
        $headers.Add('Authorization', "$($Token.Authorization)")
        $headers.Add('Accept', 'application/vnd.bose.streaming-v1.1+xml')
        $headers.Add('cache-control', 'no-cache')
        $headers.Add('ClientType', 'SOUNDTOUCH_COMPUTER_APP')
        $headers.Add('Accept-Encoding', 'gzip, deflate')
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that a maximum of 1 of the filter parameters 'DeviceId', 'IpAddress' or 'Name' is specified
        $filterCount = @($DeviceId,$IpAddress,$Name)
        if (($filterCount | Where-Object {$_}).count -gt 1) {
            throw "Multiple filter parameters specified.  Please specify only 'DeviceId', 'IpAddress' or 'Name'"
        }
        #endregion Checking that a maximum of 1 of the filter parameters 'DeviceId', 'IpAddress' or 'Name' is specified

        # Getting devices from Bose SoundTouch API
        $response = Invoke-WebRequest -Uri "$ApiUri/$($Token.AccountId)/devices/?" -Method Get -Headers $headers -ContentType $contentType -ErrorAction Stop
        if (!$response) {
            throw
        }
        
        # Returning devices as objects
        $xml = [xml]$response.content

        if ($DeviceId) {
            $output = (Select-Xml -XPath /devices/device -Xml $xml).node | Where-Object {$_.deviceid -eq $DeviceId}
            if ($output) {
                $output
            } else {
                throw "Device with 'deviceid' $DeviceId not found."
            }
        } elseif ($IpAddress) {
            $output = (Select-Xml -XPath /devices/device -Xml $xml).node | Where-Object {$_.ipaddress -eq $IpAddress}
            if ($output) {
                $output
            } else {
                throw "Device with 'ipaddress' $IpAddress not found."
            }
        } elseif ($Name) {
            $output = (Select-Xml -XPath /devices/device -Xml $xml).node | Where-Object {$_.name -eq $Name}
            if ($output) {
                $output
            } else {
                throw "Device with 'name' $Name not found."
            }
        } else {
            (Select-Xml -XPath /devices/device -Xml $xml).node
        }
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchAccountPreset {
    <#
        .SYNOPSIS
        Gets preset configuration for a Bose SoundTouch account.
      
        .DESCRIPTION
        Gets preset configuration for a Bose SoundTouch account.

        .PARAMETER Preset
        Only the specified preset will be returned.

        .EXAMPLE
        The following gets all presets for the Bose SoundTouch account
    
        $Token = Get-SoundTouchAccountToken
        Get-SoundTouchAccountPreset -Token $Token
            
        .EXAMPLE
        The following gets preset 3 for the Bose SoundTouch account
    
        $Token = Get-SoundTouchAccountToken
        Get-SoundTouchAccountPreset -Preset 3 -Token $Token
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipeline)]
        [psobject]$Token,

        [Parameter(Position=1,ValueFromPipeline)]
        [ValidateRange(1,6)]
        [int]$Preset,

        [Parameter(Position=2)]
        [string]$ApiUri = "https://streaming.bose.com/streaming/account"
    )

    BEGIN {
        #region Global Variables
        $contentType = "application/vnd.bose.streaming-v1.1+xml"

        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add('Content-Length', '120')
        $headers.Add('Origin', 'file://')

        $headers.Add('version_ProtocolVersion', '59')
        $headers.Add('Authorization', "$($Token.Authorization)")
        $headers.Add('Accept', 'application/vnd.bose.streaming-v1.1+xml')
        $headers.Add('cache-control', 'no-cache')
        $headers.Add('ClientType', 'SOUNDTOUCH_COMPUTER_APP')
        $headers.Add('Accept-Encoding', 'gzip, deflate')
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Getting first Bose SoundTouch device
        $devices = Get-SoundTouchAccountDevice -Token $Token -ApiUri $ApiUri
        if ($devices) {
            $device = $devices[0]
        } else {
            throw "No devices found in SountTouch account."
        }
        #endregion Getting first Bose SoundTouch device

        #region Getting presets from Bose SoundTouch API
        $response = Invoke-WebRequest -Uri "$ApiUri/$($Token.AccountId)/device/$($Device.deviceid)/presets?" -Method Get -Headers $Headers -ContentType $ContentType
        if (!$response) {
            throw
        }
        #endregion Getting presets from Bose SoundTouch API

        #region Returning presets as objects
        $xml = [xml]$response.content
        
        if ($Preset) {
            (Select-Xml -XPath /presets/preset -Xml $xml).node | Where-Object {$_.buttonNumber -eq $Preset}
        } else {
            (Select-Xml -XPath /presets/preset -Xml $xml).node
        }
        #endregion Returning presets as objects
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchDevice {
    <#
        .SYNOPSIS
        Gets device information from a Bose SoundTouch device.
      
        .DESCRIPTION
        Gets device information from a Bose SoundTouch device on the local network via the local device API.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following gets device information for the Bose SoundTouch account device on IP address 10.10.10.35
    
        Get-SoundTouchDevice -IpAddress 10.10.10.35

        .EXAMPLE
        The following gets device information for Bose SoundTouch account device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Get-SoundTouchDevice -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting presets from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/info" -Method Get
        if (!$response) {
            throw
        }
        #endregion Getting presets from Bose SoundTouch device API

        #region Returning device info as an objects
        $xml = [xml]$response.content
        $xml.info.setattribute("ipaddress","$deviceIp")

        (Select-Xml -XPath /info -Xml $xml).node
        #endregion Returning device info as an object
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchDeviceBass {
    <#
        .SYNOPSIS
        Gets the bass settings for a Bose SoundTouch device.
      
        .DESCRIPTION
        Gets the bass settings for a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following gets the bass settings for the Bose SoundTouch device on IP address 10.10.10.35
    
        Get-SoundTouchDeviceBass -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following gets the bass settings for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Get-SoundTouchDeviceBass -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting bass settings from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/bass" -Method Get
        if (!$response) {
            throw
        }
        #endregion Getting bass settings from Bose SoundTouch device API


        #region Returning bass settings as an object
        $xml = [xml]$response.content
        (Select-Xml -XPath /bass -Xml $xml).node
        #endregion Returning bass settings as an object
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchDeviceBassCapabilities {
    <#
        .SYNOPSIS
        Gets the bass capabilities for a Bose SoundTouch device.
      
        .DESCRIPTION
        Gets the bass capabilities for a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following gets the bass capabilities for the Bose SoundTouch device on IP address 10.10.10.35
    
        Get-SoundTouchDeviceBassCapabilities -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following gets the bass capabilities for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Get-SoundTouchDeviceBassCapabilities -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting bass capabilities from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/bassCapabilities" -Method Get
        if (!$response) {
            throw
        }
        #endregion Getting bass capabilities from Bose SoundTouch device API


        #region Returning bass capabilities as an object
        $xml = [xml]$response.content
        (Select-Xml -XPath /bassCapabilities -Xml $xml).node
        #endregion Returning pbass capabilities as an object
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchDeviceNowPlaying {
    <#
        .SYNOPSIS
        Gets information on what's now playing on a Bose SoundTouch device.
      
        .DESCRIPTION
        Gets information on what's now playing on a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following gets the bass settings for the Bose SoundTouch device on IP address 10.10.10.35
    
        Get-SoundTouchDeviceNowPlaying -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following gets the bass settings for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Get-SoundTouchDeviceNowPlaying -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting now playing information from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/now_playing" -Method Get
        if (!$response) {
            throw
        }
        #endregion Getting now playing information from Bose SoundTouch device API


        #region Returning now playing info as an dobject
        $xml = [xml]$response.content
        (Select-Xml -XPath /nowPlaying -Xml $xml).node
        #endregion Returning now playing info as an object
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchDevicePreset {
    <#
        .SYNOPSIS
        Gets preset configuration for a Bose SoundTouch device.
      
        .DESCRIPTION
        Gets preset configuration for a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .PARAMETER Preset
        Gets a device with the specified device ID..

        .EXAMPLE
        The following gets all presets for the Bose SoundTouch device on IP address 10.10.10.35
    
        Get-SoundTouchDevicePreset -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following gets preset 3 for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Get-SoundTouchDevicePreset -Device $Device -Preset 3
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress,

        [Parameter(Position=2,ValueFromPipeline)]
        [ValidateRange(1,6)]
        [int]$Preset
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting presets from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/presets" -Method Get
        if (!$response) {
            throw
        }
        #endregion Getting presets from Bose SoundTouch device API


        #region Returning preset info as objects
        $xml = [xml]$response.content
        foreach ($devicePreset in $xml.presets.preset) {
            $devicePreset.contentItem.setattribute("buttonNumber","$($devicePreset.id)")
        }

        if ($Preset) {
            (Select-Xml -XPath /presets/preset/ContentItem -Xml $xml).node | Where-Object {$_.buttonNumber -eq $Preset}
        } else {
            (Select-Xml -XPath /presets/preset/ContentItem -Xml $xml).node
        }
        #endregion Returning preset info as objects
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchDeviceSource {
    <#
        .SYNOPSIS
        Gets all available sources for a Bose SoundTouch device.
      
        .DESCRIPTION
        Gets all available sources for a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following gets all available sources for the Bose SoundTouch device on IP address 10.10.10.35
    
        Get-SoundTouchDeviceSource -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following gets all available sources for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Get-SoundTouchDeviceSource -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting sources from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/sources" -Method Get
        if (!$response) {
            throw
        }
        #endregion Getting sources from Bose SoundTouch device API


        #region Returning source as an object
        $xml = [xml]$response.content
        (Select-Xml -XPath /sources/sourceItem -Xml $xml).node
        #endregion Returning source as an object
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchDeviceTrackInfo {
    <#
        .SYNOPSIS
        Gets the current track information for a Bose SoundTouch device.
      
        .DESCRIPTION
        Gets the current track information for a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following gets the current track information for the Bose SoundTouch device on IP address 10.10.10.35
    
        Get-SoundTouchDeviceTrackInfo -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following gets the current track information for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Get-SoundTouchDeviceTrackInfo -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting track information from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/trackInfo" -Method Get
        if (!$response) {
            throw
        }
        #endregion Getting track information from Bose SoundTouch device API


        #region Returning track info as an dobject
        $xml = [xml]$response.content
        (Select-Xml -XPath /trackInfo -Xml $xml).node
        #endregion Returning track info as an object
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchDeviceVolume {
    <#
        .SYNOPSIS
        Gets the volume for a Bose SoundTouch device.
      
        .DESCRIPTION
        Gets the volume information including current volume level for a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following gets the current volume level for the Bose SoundTouch device on IP address 10.10.10.35
    
        Get-SoundTouchDeviceVolume -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following gets the current volume level for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Get-SoundTouchDeviceVolume -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting volume info from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/volume" -Method Get
        if (!$response) {
            throw
        }
        #endregion Getting volume info from Bose SoundTouch device API


        #region Returning volume info as an dobject
        $xml = [xml]$response.content
        (Select-Xml -XPath /volume -Xml $xml).node
        #endregion Returning Volume info as an object
    } #PROCESS

    END {

    } #END
}

function Get-SoundTouchDeviceZone {
    <#
        .SYNOPSIS
        Gets the current state of the multi-room zone for a Bose SoundTouch device.
      
        .DESCRIPTION
        Gets the current state of the multi-room zone for a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following gets the bass settings for the Bose SoundTouch device on IP address 10.10.10.35
    
        Get-SoundTouchDeviceZone -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following gets the bass settings for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Get-SoundTouchDeviceZone -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting bass capabilities from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/getZone" -Method Get
        if (!$response) {
            throw
        }
        #endregion Getting bass capabilities from Bose SoundTouch device API


        #region Returning zone info as an object
        $xml = [xml]$response.content
        (Select-Xml -XPath /zone -Xml $xml).node
        #endregion Returning zone info as an object
    } #PROCESS

    END {

    } #END
}

function Invoke-SoundTouchDeviceKeyPress {
    <#
        .SYNOPSIS
        Emulates pressing a physical button of a Bose SoundTouch device or its remote.
      
        .DESCRIPTION
        Emulates pressing a physical button of a Bose SoundTouch device or its remote.  The length of the press can also be controlled.

        .PARAMETER Action
        Specifies the action to perform (or key to press).
        
        .PARAMETER PressLength
        Specifies the length of time to wait between pressing and releasing the button in milliseconds between 0 and 5000.  This can be useful with the 'VOLUME_UP' and 'VOLUME_DOWN' actions as well as to store a source to a preset.

        .PARAMETER Device
        Specifies the IP address associated with the Bose SoundTouch account device specified.

        .PARAMETER IpAddress
        Specifies the Bose SoundTouch account device on the IP address specified.
        
        .EXAMPLE
        The following turns on 'Repeat One' for the Bose SoundTouch device on IP address 10.10.10.35
    
        Invoke-SoundTouchDeviceKeyPress -Action REPEAT_ALL -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following emulates pressing the 'volume up' button for 2 seconds for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Invoke-SoundTouchDeviceKeyPress -Action VOLUME_UP -PressLength 2000 -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipeline)]
        [ValidateSet(
            "PLAY",
            "PAUSE",
            "STOP",
            "PREV_TRACK",
            "NEXT_TRACK",
            "THUMBS_UP",
            "THUMBS_DOWN",
            "BOOKMARK",
            "POWER",
            "MUTE",
            "VOLUME_UP",
            "VOLUME_DOWN",
            "PRESET_1",
            "PRESET_2",
            "PRESET_3",
            "PRESET_4",
            "PRESET_5",
            "PRESET_6",
            "AUX_INPUT",
            "SHUFFLE_OFF",
            "SHUFFLE_ON",
            "REPEAT_OFF",
            "REPEAT_ONE",
            "REPEAT_ALL",
            "PLAY_PAUSE",
            "ADD_FAVORITE",
            "REMOVE_FAVORITE"
        )]
        [string]$Action,

        [Parameter(Position=1,ValueFromPipeline)]
        [ValidateRange(0,5000)]
        [int]$PressLength = 200,
        
        [Parameter(Position=2,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=3,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        if ($PressLength -gt 0) {
            #region Sending key press via Bose SoundTouch device API
            $response = Invoke-WebRequest -Uri "$deviceApiUri/key" -Method Post -Body "<key state=`"press`" sender=`"Gabbo`">$Action</key>"
            if (!$response) {
                throw
            }
            #endregion Sending key press via Bose SoundTouch device API

            #region Returning result as an dobject
            $xml = [xml]$response.content
            (Select-Xml -XPath /status -Xml $xml).node
            #endregion Returning result as an object

            #region Sleeping
            Start-Sleep -Milliseconds $PressLength
            #endregion Sleeping
        }

        #region Sending key release via Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/key" -Method Post -Body "<key state=`"release`" sender=`"Gabbo`">$Action</key>"
        if (!$response) {
            throw
        }
        #endregion Sending key release via Bose SoundTouch device API

        #region Returning result as an dobject
        $xml = [xml]$response.content
        (Select-Xml -XPath /status -Xml $xml).node
        #endregion Returning result as an object
    } #PROCESS

    END {

    } #END
}

function Select-SoundTouchDevicePreset {
    <#
        .SYNOPSIS
        Selects a preset on a Bose SoundTouch device.
      
        .DESCRIPTION
        Sets the name of a Bose SoundTouch device.

        .PARAMETER Preset
        Specifies the preset number between 1 and 6.
        
        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address..
        
        .EXAMPLE
        The following selects preset 3 for the Bose SoundTouch device on IP address 10.10.10.35
    
        Select-SoundTouchDevicePreset -Preset 3 -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following selects preset 3 for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Select-SoundTouchDevicePreset -Preset 3 -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipeline)]
        [ValidateRange(1,6)]
        [int]$Preset,

        [Parameter(Position=1,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=2,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Selecting preset via Bose SoundTouch device API
        $key = "PRESET_$Preset"
        Invoke-SoundTouchDeviceKeyPress -Key $key -Device $Device -IpAddress $IpAddress
        #endregion Selecting preset via Bose SoundTouch device API
    } #PROCESS

    END {

    } #END
}

function Select-SoundTouchDeviceSource {
    <#
        .SYNOPSIS
        Selects the source of a Bose SoundTouch device.
      
        .DESCRIPTION
        Selects the source of a Bose SoundTouch device.

        .PARAMETER Source
        Specifies the source to set on the Bose SoundTouch device.
        
        .PARAMETER SourceAccount
        Specifies the source account associated with the source.  This is only required if there are multilpe accounts associated with a source (eg. multiple QPLAY source accounts), if multiple source account exist and a source account isn't specified then the cmdlet will fail.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address..
        
        .EXAMPLE
        The following Selects the source for the Bose SoundTouch device on IP address 10.10.10.35 to 'AUX'
    
        Selects-SoundTouchDeviceSource -Source AUX -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following Selects the source for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20' to 'BLUETOOTH'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Selects-SoundTouchDeviceSource -Source BLUETOOTH -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$Source,

        [Parameter(Position=1,ValueFromPipeline)]
        [string]$SourceAccount,
        
        [Parameter(Position=2,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=3,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting source account (if exists)
        if (!$SourceAccount) {
            $deviceSource = Get-SoundTouchDeviceSource -IpAddress $deviceIp | Where-Object {$_.source -eq $Source}
            if ($deviceSource.count -gt 1) {
                throw "Multiple source accounts available for source $Source.  'SourceAccount' paramter must be specified."
            }
        }
        #endregion Getting source account (if exists)

        #region Setting source via Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/select" -Method Post -Body "<ContentItem source=`"$Source`" sourceAccount=`"$($deviceSource.sourceAccount)`"></ContentItem>"
        if (!$response) {
            throw
        }
        #endregion Setting source via Bose SoundTouch device API

        #region Returning result as an dobject
        $xml = [xml]$response.content
        (Select-Xml -XPath /status -Xml $xml).node
        #endregion Returning result as an object
    } #PROCESS

    END {

    } #END
}

function Set-SoundTouchDeviceBass {
    <#
        .SYNOPSIS
        Sets the bass for a Bose SoundTouch device.
      
        .DESCRIPTION
        Sets the bass for a Bose SoundTouch device.  Note the capability must be supported by the SoundTouch device, this can be confirmed by using the Get-SoundTouchDeviceBassCapabilities cmdlet.

        .PARAMETER Bass
        Specifies the bass level to set.
        
        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following sets the bass level for the Bose SoundTouch device on IP address 10.10.10.35 to -5
    
        Set-SoundTouchDeviceBass -IpAddress 10.10.10.35 -Bass -5
            
        .EXAMPLE
        The following sets the current volume level for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20' to -5
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Set-SoundTouchDeviceBass -Device $Device -Bass 5
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress,

        [Parameter(Position=2,Mandatory,ValueFromPipeline)]
        [ValidateRange(0,100)]
        [int]$Volume
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Setting bass level via Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/bass" -Method Post -Body "<bass>$Bass</bass>"
        if (!$response) {
            throw
        }
        #endregion Setting bass level via Bose SoundTouch device API


        #region Returning result as an dobject
        $xml = [xml]$response.content
        (Select-Xml -XPath /status -Xml $xml).node
        #endregion Returning result as an object
    } #PROCESS

    END {

    } #END
}

function Set-SoundTouchDeviceName {
    <#
        .SYNOPSIS
        Sets the name of a Bose SoundTouch device.
      
        .DESCRIPTION
        Sets the name of a Bose SoundTouch device.

        .PARAMETER Name
        The new name for the Bose SoundTouch device.
        
        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address..
        
        .EXAMPLE
        The following sets the name for the Bose SoundTouch device on IP address 10.10.10.35 to 'New Name'
    
        Set-SoundTouchDeviceName -Name "New Name" -IpAddress 10.10.10.35
            
        .EXAMPLE
        The following gets the name for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20' to 'New Name'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Set-SoundTouchDeviceName -Name "New Name" -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Position=1,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=2,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Setting name via Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/name" -Method Post -Body "<name>$Name</name>"
        if (!$response) {
            throw
        }
        #endregion Setting name via Bose SoundTouch device API


        #region Returning result as an dobject
        $xml = [xml]$response.content
        (Select-Xml -XPath /info -Xml $xml).node
        #endregion Returning result as an object
    } #PROCESS

    END {

    } #END
}

function Set-SoundTouchDeviceVolume {
    <#
        .SYNOPSIS
        Sets the volume for a Bose SoundTouch device.
      
        .DESCRIPTION
        Sets the volume for a Bose SoundTouch device to a value between 0 and 100 (inclusive).

        .PARAMETER Volume
        Specifies the volume level between 0 and 100 (inclusive).
        
        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER IpAddress
        A Bose SoundTouch device IP address.
        
        .EXAMPLE
        The following sets the current volume level for the Bose SoundTouch device on IP address 10.10.10.35 to 50
    
        Set-SoundTouchDeviceVolume -IpAddress 10.10.10.35 -Volume 50
            
        .EXAMPLE
        The following sets the current volume level for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20' to 50
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        Set-SoundTouchDeviceVolume -Device $Device -Volume 50
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory,ValueFromPipeline)]
        [ValidateRange(0,100)]
        [int]$Volume,

        [Parameter(Position=1,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=2,ValueFromPipeline)]
        [System.Net.IPAddress]$IpAddress
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified
        if ($Device -and $IpAddress) {
            throw "Specify only one parameter parameter: 'Device' or 'IpAddress'."
        }

        if (!$Device -and !$IpAddress) {
            throw "Specify parameter 'Device' or 'IpAddress'."
        }
        #endregion Checking that exactly 1 of the paramters 'Device'or 'IpAddress'is specified

        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Setting volume level via Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/volume" -Method Post -Body "<volume>$Volume</volume>"
        if (!$response) {
            throw
        }
        #endregion Setting volume level via Bose SoundTouch device API


        #region Returning result as an dobject
        $xml = [xml]$response.content
        (Select-Xml -XPath /status -Xml $xml).node
        #endregion Returning result as an object
    } #PROCESS

    END {

    } #END
}

function New-SoundTouchDeviceZone {
    <#
        .SYNOPSIS
        Creates a new multi-room zone on a Bose SoundTouch device.
      
        .DESCRIPTION
        Creates a new multi-room zone on a Bose SoundTouch device.  This Bose SoudnTouch device will be the master device for the zone.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .EXAMPLE
        The following gets the bass settings for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20*"
        New-SoundTouchDeviceZone -Device $Device
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Determining device IP address and URI
        $deviceIp = $Device.ipaddress
        $deviceApiUri = "http://$($deviceIp):8090"
        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting bass capabilities from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/setZone" -Method Post -Body "<zone master=`"$($Device.deviceid)`"><member ipaddress=`"$($Device.ipaddress)`">$($Device.deviceid)</member></zone>"
        if (!$response) {
            throw
        }
        #endregion Getting bass capabilities from Bose SoundTouch device API


        #region Returning zone info as an object
        $xml = [xml]$response.content
        (Select-Xml -XPath /zone -Xml $xml).node
        #endregion Returning zone info as an object
    } #PROCESS

    END {

    } #END
}

function Add-SoundTouchDeviceZoneSlave {
    <#
        .SYNOPSIS
        Adds a Bose SoundTouch device to a multi-room zone.
      
        .DESCRIPTION
        Adds a Bose SoundTouch device to a multi-room zone that already exists on a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER SalveDevice
        The Bose SoundTouch device to add as a slave to the multi-room zone.

        .EXAMPLE
        The following gets the bass settings for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20"
        $SlaveDevice = Get-SoundTouchAccountDevice -Token $Token -Name "Bathroom - Bose SoundTouch 10"
        Add-SoundTouchDeviceZone -Device $Device -SlaveDevice $SlaveDevice
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [psobject]$SlaveDevice

    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        $deviceIp = $Device.ipaddress
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting bass capabilities from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/addZoneSlave" -Method Post -Body "<zone master=`"$($Device.deviceid)`"><member ipaddress=`"$($slaveDevice.ipaddress)`">$($slaveDevice.deviceid)</member></zone>"
        if (!$response) {
            throw
        }
        #endregion Getting bass capabilities from Bose SoundTouch device API


        #region Returning zone info as an object
        $xml = [xml]$response.content
        (Select-Xml -XPath /status -Xml $xml).member
        #endregion Returning zone info as an object
    } #PROCESS

    END {

    } #END
}

function Remove-SoundTouchDeviceZoneSlave {
    <#
        .SYNOPSIS
        Removes a Bose SoundTouch device to a multi-room zone.
      
        .DESCRIPTION
        Removes a Bose SoundTouch device to a multi-room zone that already exists on a Bose SoundTouch device.

        .PARAMETER Device
        A Bose SoundTouch device object.

        .PARAMETER SalveDevice
        The Bose SoundTouch device to remove as a slave from the multi-room zone.

        .EXAMPLE
        The following gets the bass settings for the Bose SoundTouch device called 'Kitchen - Bose SoundTouch 20'
    
        $Token = Get-SoundTouchAccountToken
        $Device = Get-SoundTouchAccountDevice -Token $Token -Name "Kitchen - Bose SoundTouch 20"
        $SlaveDevice = Get-SoundTouchAccountDevice -Token $Token -Name "Bathroom - Bose SoundTouch 10"
        Remove-SoundTouchDeviceZone -Device $Device -SlaveDevice $SlaveDevice
            
        .LINK
                https://github.com/andylyonette/BoseSoundTouchPSModule
        
        .OUTPUTS
        <System.RuntimeType>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline)]
        [psobject]$Device,

        [Parameter(Position=1,ValueFromPipeline)]
        [psobject]$SlaveDevice
    )

    BEGIN {
        #region Global Variables
        #endregion Global Variables
    } #BEGIN

    PROCESS {
        #region Determining device IP address and URI
        if ($Device) {
            $deviceIp = $Device.ipaddress
        } elseif ($IpAddress) {
            $Device = Get-SoundTouchDevice -IpAddress $deviceIp
            $deviceIp = $IpAddress
        }
        $deviceApiUri = "http://$($deviceIp):8090"

        #endregion Determining device IP address and URI

        #region Testing connectivity to device
        $ping = Test-Connection -ComputerName $deviceIp -Count 1 -Quiet
        if (!$ping) {
            throw "Failed to ping device on IP $deviceIp"
        }
        #endregion Testing connectivity to device

        #region Getting bass capabilities from Bose SoundTouch device API
        $response = Invoke-WebRequest -Uri "$deviceApiUri/removeZoneSlave" -Method Post -Body "<zone master=`"$($Device.deviceid)`"><member ipaddress=`"$($SlaveDevice.ipAddress)`">$($SlaveDevice.deviceid)</member></zone>"
        if (!$response) {
            throw
        }
        #endregion Getting bass capabilities from Bose SoundTouch device API


        #region Returning zone info as an object
        $xml = [xml]$response.content
        (Select-Xml -XPath /zone -Xml $xml).node
        #endregion Returning zone info as an object
    } #PROCESS

    END {

    } #END
}
