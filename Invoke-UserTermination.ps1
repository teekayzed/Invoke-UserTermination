#requires -version 2
#Needs to be ran as Administrator
<#
.SYNOPSIS
  Automates termination processes of specified user.

.DESCRIPTION
  This script is deployed easiest on an Exchange server within the domain.
  It can be run from any server, but it needs the ActiveDirectory module,
  and Exchange SnapIns in order to run. This is all contained on an Exchange
  Server so that just makes it easiest.

  Performs the following:
     1.) Remove Inbox Rules (Exchange 2010)
     2.) Disable OWA and ActiveSync (Exchange 2010)
     3.) Remove ActiveSync Devices (Exchange 2010)
     4.) Remove or Set Mail Forwarding Rules (Exchange 2010)
     5.) Grant another user Full Access to Terminated User's Mailbox (Exchange 2010)
     6.) Hide Email Address from Exchange Address Lists (Exchange 2010)
     7.) Remove Group Membership (Including Distro Groups) from AD Object (Active Directory)
     8.) Note all group memberships that were removed in logs (Active Directory)
     9.) Remove Manager Field from AD Object (Active Directory)
    10.) Set AD User Object's Description to Detail Log Location (Active Directory)
    11.) Disable Account (Active Directory)
    12.) Change Account Password to Semi-Random Value (Active Directory)
    13.) Move disabled AD Object to OU specified below in the Declarations

.PARAMETER 
  Supplied within script via user interaction.

.INPUTS
  User Input

.OUTPUTS
  Outputs log file to the script's RunDirectory\Logs

.NOTES
  Version:        1.0
  Author:         teekayzed
  Creation Date:  March 09, 2015
  Purpose/Change: Research and pulled from net, modified into a
                  better format, tweaked, initial script development.
  Credits: Modified from http://poshcode.org/4990
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

Import-Module activedirectory
Add-PSSnapIn *exchange* 

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"

#Company Specific Declarations
$strCompanyName = "" #Appears in script, changes no functionality
$strTerminatedOU = "" #Enter OU to move disabled users to, in the following format: "OU=Inactive Users,DC=domain,DC=local"


#Generic Declarations
$strRunDir = split-path -parent $MyInvocation.MyCommand.Definition
$strDate = get-date -format "yyyy-MMM-dd-HHmm"
$StrUserDesc = ""
$strDebug = ""

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function Invoke-MailboxTermination {
  $strMsg = ""
  $strUserID = $args[0]

  Get-InboxRule -Mailbox $strUserID  | Remove-InboxRule -Confirm:$false -Force      
  Write-Host "Inbox rules removed.`r`n"
  
  Set-CASMailbox -Identity $strUserID -ActiveSyncEnabled:$False -OWAEnabled:$False
  Write-Host "OWA and ActiveSync disabled.`r`n"
  
  Get-ActiveSyncDevice -Mailbox $strUserID | Remove-ActiveSyncDevice -Confirm:$False
  Write-Host "ActiveSync device associations removed.`r`n"
    
  $strMsg += "`r`n"
  $strMsg += "Do you want to forward incoming mail to another mailbox? (Y/N)"
  $strMsg += "`r`n"
  
  $booForward = read-host $strMsg
  
  if($booForward -eq "Y") {
    $strMsg = ""
    $strMsg += "`r`n"
    $strMsg += "Please enter the forwarding address: (jdoe@example.com)"
    $strMsg += "`r`n"
    
    $strForwardingAddress = read-host $strMsg
    
    Set-mailbox -Identity $strUserID -HiddenFromAddressListsEnabled:$true -ForwardingAddress $strForwardingAddress  
    Write-Host "$strUserID has been hidden from Exchange address lists `r`n and mail for $strUserID has been forwarded to $strForwardingAddress`r`n"
  } else {
    $strMsg = ""
    $strMsg += "`r`n"
    $strMsg += "No forwarding address specified. Disabling all forwarding."
    $strMsg += "`r`n"
    
    Write-Host $strMsg
    
    Set-mailbox -Identity $strUserID -HiddenFromAddressListsEnabled:$true -ForwardingAddress $Null
    Write-Host "$strUserID has been hidden from Exchange address lists `r`n and forwarding for $strUserID has been disabled."
  }
}
function Set-FullAccessMailbox {
  $strUserID = $args[0]
  
  $strMsg = ""
  $strMsg += "`r`n"
  $strMsg += "Do you want to grant another user Full Access to this mailbox? (Y/N)"
  $strMsg += "`r`n"
  
  $booAccess = Read-Host $strMsg
  
  if($booAccess -eq "Y") {
    $strMsg = ""
    $strMsg += "`r`n"
    $strMsg += "Enter username to grant full access to the mailbox of $strUserID"
    $strMsg += "`r`n"
    
    $strAccessID = Read-Host $strMsg
    Add-MailboxPermission -Identity $strUserID -User $strAccessID -AccessRights FullAccess -InheritanceType All
    Write-Host "$strAccessID has been granted Full Access to the mailbox for $strUserID"
  } else {
    $strMsg = ""
    $strMsg += "`r`n"
    $strMsg += "Full Access will not be granted to another user account."
    $strMsg += "`r`n"
    Write-Host $strMsg
  }
}
function Invoke-GroupRemoval {
  $strUserID = $args[0]
  Write-Host "`r`n `r`n Group Memberships: `r`n"
  Get-ADPrincipalGroupMembership -Identity $strUserID | Select-object Name
  Write-Host "`r`n`r`n`r`n"
  Get-ADPrincipalGroupMembership -Identity $strUserID | Where {$_.Name -ne "Domain Users"} | ForEach-Object {
    Remove-ADPrincipalGroupMembership -Identity $strUserID -MemberOf $_.SamAccountName -Confirm:$False
    Write-Host "Removed from $($_.Name) `r`n"
  } 
 }
function Get-TempPassword() {
  $length = $args[0]
  $Chars = [Char[]]"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`~!@#$%^&*()-_=+"
  $TempPassword = ($Chars | Get-Random -Count $length) -join ""
  $TempPassword = [string]$TempPassword
  return $TempPassword
}
function Invoke-DeathTo {
  $strUserID = $args[0]
  $newPW = Get-TempPassword 10
  Set-ADAccountPassword -Identity $strUserID -NewPassword (ConvertTo-SecureString -AsPlainText $newPW -Force)
    Disable-ADAccount -identity $strUserID
  Set-ADuser -identity $strUserID -Manager $Null
  Set-AdUser -Identity $strUserID -Description "Termination log located at $strRunLog"
  Get-ADUser -identity $strUserID | Move-ADobject -TargetPath $strTerminatedOU    
}
function enterUser {
     $strMsg2 += "`r`n` "
     $strMsg2 += "Please enter the user's AD Account Name Below: `r`n` "
     $strMsg2 += "`r`n` "
     
     $strUserID = read-host $strMsg2
     $strUserID = $strUserID.Trim()
   return $strUserID
} 
function Main {
  $strMsg1 += "`r`n` "
  $strMsg1 += "User Termination Process Script for $strCompanyName `r`n` "
  $strMsg1 += "`r`n` "
  $strMsg1 += "This script will accomplish the following: `r`n` "
  $strMsg1 += "`r`n` "
  $strMsg1 += " 1.) Remove Inbox Rules (Exchange 2010) `r`n` "
  $strMsg1 += " 2.) Disable OWA and ActiveSync (Exchange 2010) `r`n` "
  $strMsg1 += " 3.) Remove ActiveSync Devices (Exchange 2010) `r`n` "
  $strMsg1 += " 4.) Remove or Set Mail Forwarding Rules (Exchange 2010) `r`n` "
  $strMsg1 += " 5.) Grant Another User FullAccess to Terminated User's Mailbox (Exchange 2010) `r`n` "
  $strMsg1 += " 6.) Hide Email Address from Exchange Address Lists (Exchange 2010) `r`n` "
  $strMsg1 += " 7.) Remove Group Membership (including Distribution Lists) from AD Object (Active Directory) `r`n` "
  $strMsg1 += " 8.) Note All Group Memberships That Were Removed in Logs (Active Directory) `r`n "
  $strMsg1 += " 9.) Remove Manager Field from AD object (Active Directory) `r`n` "
  $strMsg1 += "10.) Set AD User Object's Description to Detail Log Location (Active Directory) `r`n` "
  $strMsg1 += "11.) Disable Account (Active Directory) `r`n` "
  $strMsg1 += "12.) Change Account Password To Semi-Random Value (Active Directory) `r`n "
  $strMsg1 += "13.) Move disabled AD object to Inactive OU `r`n` "
  
  Write-Host $strMsg1
  $strUserID = enterUser
  
  try {
        $blnUserExists = get-aduser $strUserID
    }
    catch {}    

    if($blnUserExists) {
        $strMsg3 += "`r`n` "
      $strMsg3 += "Are you sure you wish to continue? (Y/N) `r`n` "        
        $strMsg3 += "`r`n` "

        $strContinue = read-host $strMsg3
        
        if($strContinue -eq "Y") {    
            $strRunLog = "$strRunDir\Logs\$strUserID-log-$strDate.txt"
            $arrAttachments = @($strRunLog)
            
            start-transcript -path $strRunLog
    }
  }
  Invoke-MailboxTermination $strUserID
  Set-FullAccessMailbox $strUserID
  Invoke-GroupRemoval $strUserID
  Invoke-DeathTo $strUserID

  $strMsg4 += "`r`n` "        
  $strMsg4 += "The Termination script for",$strUserID,"has completed. `r`n` "
  $strMsg4 += " `r`n` "
  $strMsg4 += "A log of the session can be located at: $strRunLog. `r`n` "
  $strMsg4 += "`r`n` "        
  Write-host $strMsg4
  Stop-Transcript
  Start-Process notepad.exe $strRunLog

  $strMsg5 += "`r`n` "
  $strMsg5 += "User account terminated. Do you wish to terminate another account? (Y/N) `r`n` "
  $strMsg5 += "`r`n` "
  $strMsg5 += "`r`n` "
  $strContinue = read-host $strMsg5
  
  if($strContinue -eq "Y") {Main}
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Main
