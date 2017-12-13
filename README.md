# Bose SoundTouch PowerShell Module 1.0.0
Interact with your Bose SoundTouch account and devices using PowerShell

## Author
Andy Lyonette

## Prerequisites
PowerShell 3.0



## Installation
1. Create folder C:\Users\\[username]\Documents\WindowsPowerShell\Modules\BoseSoundTouch
2. Copy BoseSoundTouch\BoseSoundTouch.ps1 and BoseSoundTouch\BoseSoundTouch.psm1 into that directory.
3. Unblock BoseSoundTouch.ps1 and BoseSoundTouch.psm1 by right clicking each file and going to properties or using the cmdlet 'Unlock-File'



## Usage
### Finding your Bose SoundTouch Devices
In order to send commands to a Bose SoundTouch device each time you open a new PowerShell session you first need to get a token from the Bose SoundTouch API nd get the a list of Bose SoundTouch devices associated with your account.  This can be achieved with the following commands:

`$token = Get-BoseSoundTouchAccountToken -Credential (Get-Credential)`

`$devices = Get-BoseSoundTouchAccountDevice -Token $token`

You can see all the devices by typing `$devices` and select an individual device by piping th `Where-Object`:

`$device = $devices | Where-Object {$_.name -like "Bose SoundTouch 10 - Bathroom"}`

If you only have one Bose SoundTouch device in your SoundTouch account you just can use:

`$token = Get-BoseSoundTouchAccountToken -Credential (Get-Credential)`

`$device = Get-BoseSoundTouchAccountDevice -Token $token`


This `$device` variable can now be used with each of the Cmdlets.  For example:

`Select-SoundTouchDevicePreset -Preset 4 -Device $device`

`Set-SoundTouhcDeviceVolume -Volume 50 -Device $device`




### Cmdlet Reference
The following cmdlets are available in the module complete with full comment-based help.  In order to find out more about any cmdlet use the Get-Help cmdlet.

Eg. `Get-Help New-BoseSoundTouchDeviceZone -Detailed` or `Get-Help Add-BoseSoundTouchDeviceZoneSlave -Examples`


#### Bose SoundTouch Account cmdlets
* Get-SoundTouchAccountToken
* Get-SoundTouchAccountDevice
* Get-SoundTouchAccountPreset

#### Bose SoundTouch Device cmdlets
* Add-SoundTouchDeviceZoneSlave
* Get-SoundTouchDevice
* Get-SoundTouchDeviceBass
* Get-SoundTouchDeviceBassCapabilities
* Get-SoundTouchDeviceNowPlaying
* Get-SoundTouchDevicePreset
* Get-SoundTouchDeviceSource
* Get-SoundTouchDeviceTrackInfo
* Get-SoundTouchDeviceVolume
* Get-SoundTouchDeviceZone
* Invoke-SoundTouchDeviceKeyPress
* New-SoundTouchDeviceZone
* Remove-SoundTouchDeviceZoneSlave
* Select-SoundTouchDevicePreset
* Select-SoundTouchDeviceSource
* Set-SoundTouchDeviceBass
* Set-SoundTouchDeviceName



## Limitations
* Testing performed against the following devices:
     Bose LifeStyle 535 Series 2 with SoundTouch Wireless Adapter
     Bose SA-4 with SoundTouch Wireless Adapter
     Bose SoundTouch 20 Series 3
     Bose SoundTouch 10
     Bose SoundTouch Wireless Link
* Tested on firmware 17.0.8.39958.2553035



## Change Log
### 1.0.0
* Initial release



## Notes
API refererence from:
* https://developer.bose.com/

**Suggestions, improvements and fixes are all welcome!**
