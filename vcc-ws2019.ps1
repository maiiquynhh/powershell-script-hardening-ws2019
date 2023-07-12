#Start-DscConfiguration -Path .\CIS_Benchmark_WindowsServer2016_v1_0_0  -Force -Verbose -Wait
Configuration vcc_ws2019{
    param (
        [string[]]$ComputerName = 'localhost'
    )

    Import-DscResource -ModuleName 'nPSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'NetworkingDsc'

    Node $ComputerName{

        #Account Policies
        AccountPolicy AccountPolicies{
            Name = 'AccountPolicies'
            Enforce_password_history = '24'
            Maximum_Password_Age = '90'
            Minimum_Password_Age = '1'
            Minimum_Password_Length = '14'
            Password_must_meet_complexity_requirements  = 'Enabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            Account_lockout_duration = '15'
            Account_lockout_threshold = '5'
            Reset_account_lockout_counter_after = '15'
        }

        #Local Policies: User Right Assignment
        UserRightsAssignment Backupfilesanddirectories {
            Policy       = 'Back_up_files_and_directories'
            Identity     = 'Administrators'
        }
        
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Local account and member of Administrators group, Guests'
        }

        UserRightsAssignment Denylogonasabatchjob {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
        }

        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
        }

        UserRightsAssignment Denylogonlocally {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
        }

        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests, Local account'
        }

        UserRightsAssignment Restorefilesanddirectories {
            Policy       = 'Restore_files_and_directories'
            Identity     = 'Administrators'
        }

        #Local Policies: Security Options
        SecurityOption SecurityOptions {
            Name = 'AccountSecurityOptions'
            Accounts_Rename_administrator_account = 'User_Adm' 
            Accounts_Rename_guest_account = 'User_Guest'
            Interactive_logon_Do_not_display_last_user_name = 'Enabled'  
            Interactive_logon_Machine_inactivity_limit = '300'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
            Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication = 'Enabled' 

        }

        #Windows Firewall: Domain Profile
        Registry 'EnableFirewallDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }

        Registry 'DefaultInboundActionDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
            ValueName   = 'DefaultInboundAction'
            ValueType   = 'DWord'
            ValueData   = '1'
        }

        Registry 'DefaultOutboundActionDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }

        Registry 'DisableNotificationsDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '0'
        }

        Registry 'LogFilePathDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath'
            ValueName   = 'DisableNotifications'
            ValueType   = 'String'
            ValueData   = '%windir%\system32\logfiles\firewall\domainfirewall.log'
        }

        Registry 'LogFileSizeDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
            ValueName   = 'LogFileSize'
            ValueType   = 'DWord'
            ValueData   = '16384'
        }

        Registry 'LogDroppedPacketsDomain' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
           ValueName    = 'LogDroppedPackets'
           ValueType    = 'DWord'
           ValueData    = '1'
        }

        Registry 'LogSuccessfulConnectionsDomain' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
           ValueName    = 'LogSuccessfulConnections'
           ValueType    = 'DWord'
           ValueData    = '1'
        }

        #Windows Firewall: Public Profile
        Registry 'EnableFirewallPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'EnableFirewall'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
  
        Registry 'DefaultInboundActionPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'DefaultInboundAction'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
  
        Registry 'DefaultOutboundActionPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'DefaultOutboundAction'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
  
        Registry 'DisableNotificationsPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'DisableNotifications'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
  
        Registry 'AllowLocalPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
  
        Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalIPsecPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
  
        Registry 'LogFilePathPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName    = 'LogFilePath'
            ValueType    = 'String'
            ValueData    = '%windir%\system32\logfiles\firewall\publicfirewall.log'
        }
  
        Registry 'LogFileSizePublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName    = 'LogFileSize'
            ValueType    = 'Dword'
            ValueData    = '16384'
        }
  
        Registry 'LogDroppedPacketsPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName    = 'LogDroppedPackets'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
  
        Registry 'LogSuccessfulConnectionsPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName    = 'LogSuccessfulConnections'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
    
        #Windows Firewall: Private Profile
        Registry 'EnableFirewallPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'EnableFirewall'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
        
        Registry 'DefaultInboundActionPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'DefaultInboundAction'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
  
        Registry 'DefaultOutboundActionPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'DefaultOutboundAction'
            ValueType    = 'DWord'
            ValueData    = '0'
        }

        Registry 'DisableNotificationsPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'DisableNotifications'
            ValueType    = 'DWord'
            ValueData    = '0'
        }

        Registry 'LogFilePathPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName    = 'LogFilePath'
            ValueType    = 'String'
            ValueData    = '%windir%\system32\logfiles\firewall\privatefirewall.log'
        }

        Registry 'LogFileSizePrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName    = 'LogFileSize'
            ValueType    = 'DWord'
            ValueData    = '16384'
        }

        Registry 'LogDroppedPacketsPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName    = 'LogDroppedPackets'
            ValueType    = 'DWord'
            ValueData    = '1'
        }

        Registry 'LogSuccessfulConnectionsPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName    = 'LogSuccessfulConnections'
            ValueType    = 'DWord'
            ValueData    = '1'
        }

        #Audit Policy
        AuditPolicySubcategory "Audit Credential Validation (Success)" {
           Name      = 'Credential Validation'
           Ensure    = 'Present'
           AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Credential Validation (Failure)' {
           Name      = 'Credential Validation'
           Ensure    = 'Present'
           AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Application Group Management (Success)'
        {
            Name      = 'Application Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Application Group Management (Failure)'
        {
            Name      = 'Application Group Management'    
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        <#AuditPolicySubcategory 'Audit Computer Account Management (Failure)' 
        {
            Name      = 'Computer Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'      
        }#>

        AuditPolicySubcategory 'Audit Computer Account Management (Success)' {
            Name      = 'Computer Account Management'
            Ensure    = 'Present'   
            AuditFlag = 'Success'      
        }

        <#AuditPolicySubcategory 'Audit Security Group Management (Failure)' {
            Name      = 'Security Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }#>

        AuditPolicySubcategory 'Audit Security Group Management (Success)' {
            Name      = 'Security Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit PNP Activity (Success)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        <#AuditPolicySubcategory 'Audit PNP Activity (Failure)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }#>

        AuditPolicySubcategory 'Audit Process Creation (Success)' {
            Name      = 'Process Creation'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        <#AuditPolicySubcategory 'Audit Process Creation (Failure)' {
            Name      = 'Process Creation'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Account Lockout (Success)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }#>

        AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Group Membership (Success)' {
            Name      = 'Group Membership'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        <#AuditPolicySubcategory 'Audit Group Membership (Failure)' {
            Name      = 'Group Membership'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }#>

        AuditPolicySubcategory 'Audit Logoff (Success)' {
            Name      = 'Logoff'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        <#AuditPolicySubcategory 'Audit Logoff (Failure)' {
            Name      = 'Logoff'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }#>
        
        AuditPolicySubcategory 'Audit Logon (Success)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Logon (Failure)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        AuditPolicySubcategory 'Audit Special Logon (Success)' {
            Name      = 'Special Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        <#AuditPolicySubcategory 'Audit Special Logon (Failure)' {
            Name      = 'Special Logon'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }#>

        <#AuditPolicySubcategory 'Audit Detailed File Share (Success)' {
            Name      = 'Detailed File Share'
            Ensure    = 'Absent'
            AuditFlag = 'Success'
        }#>

        AuditPolicySubcategory 'Audit Detailed File Share (Failure)' {
            Name      = 'Detailed File Share'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
         }       

        AuditPolicySubcategory 'Audit File Share (Success)' {
            Name      = 'File Share'
            Ensure    = 'Present'
            AuditFlag = 'Success'
         }

        AuditPolicySubcategory 'Audit File Share (Failure)' {
            Name      = 'File Share'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
         }   

        AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Security State Change (Success)' {
            Name      = 'Security State Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        <#AuditPolicySubcategory 'Audit Security State Change (Failure)' {
            Name      = 'Security State Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }#>

        AuditPolicySubcategory 'Audit System Integrity (Failure)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit System Integrity (Success)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        #Network Connections
        Registry 'NC_AllowNetBridge_NLA' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
            ValueName    = 'NC_AllowNetBridge_NLA'
            ValueType    = 'DWord'
            ValueData    = '0'
         }

        Registry 'NC_ShowSharedAccessUI' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
            ValueName    = 'NC_ShowSharedAccessUI'
            ValueType    = 'DWord'
            ValueData    = '0'
        }

        #Tắt IPv6
        Registry 'DisabledComponents' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'
            ValueName    = 'DisabledComponents'
            ValueType    = 'DWord'
            ValueData    = '255'
        }

        #Windows Connect Now
        Registry 'DisableWcnUi' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI'
            ValueName    = 'DisableWcnUi'
            ValueType    = 'DWord'
            ValueData    = '1'
        }

        #Group Policy: Logging and tracing
        Registry 'NoBackgroundPolicy' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName  = 'NoBackgroundPolicy'
            ValueType  = 'DWord'
            ValueData  = '0'
        }
  
        Registry 'NoGPOListChanges' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName  = 'NoGPOListChanges'
            ValueType  = 'DWord'
            ValueData  = '0'
        }

        #Time Providers
        Registry 'EnableNTPClient' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
            ValueName  = 'Enabled'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        Registry 'EnableNTPServer' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer'
            ValueName  = 'Enabled'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        #Event Log: Application
        Registry 'RetentionApplicationLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }

        Registry 'MaxSizeApplicationLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '32768'
        }

        Registry 'AutoBackupLogFilesApplicationLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName  = 'AutoBackupLogFiles'
            ValueType  = 'String'
            ValueData  = '1'
        }

        #Event Log: Security
        Registry 'RetentionSecurityLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }

        Registry 'MaxSizeSecurityLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '196608'
        }

        Registry 'AutoBackupLogFilesSecurityLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName  = 'AutoBackupLogFiles'
            ValueType  = 'String'
            ValueData  = '1'
        }

        #Event Log: Setup
        Registry 'RetentionSetupLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }

        Registry 'MaxSizeSetupLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '32768'
        }

        Registry 'AutoBackupLogFilesSetupLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName  = 'AutoBackupLogFiles'
            ValueType  = 'String'
            ValueData  = '1'
        }

        #Event Log: System
        Registry 'RetentionSystemLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }

        Registry 'MaxSizeSystemLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '32768'
        }

        Registry 'AutoBackupLogFilesSystemLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName  = 'AutoBackupLogFiles'
            ValueType  = 'String'
            ValueData  = '1'
        }

        #Microsoft Defender Antivirus
        Registry 'LocalSettingOverrideSpynetReporting' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\Spynet'
            ValueName  = 'LocalSettingOverrideSpynetReporting'
            ValueType  = 'DWord'
            ValueData  = '0'
        }

        #Microsoft Defender Exploit Guard
        Registry 'ExploitGuard_ASR_Rules' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            ValueName  = 'ExploitGuard_ASR_Rules'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        Registry '26190899-1602-49e8-8b27-eb1d0a1ce869' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = '26190899-1602-49e8-8b27-eb1d0a1ce869'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry '3b576869-a4ec-4529-8536-b80a7769e899' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = '3b576869-a4ec-4529-8536-b80a7769e899'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry '5beb7efe-fd9a-4556-801d-275e5ffc04cc' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry 'd3e037e1-3eb8-44c8-a917-57927947596d' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = 'd3e037e1-3eb8-44c8-a917-57927947596d'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
            ValueType  = 'String'
            ValueData  = '1'
        }

        Registry 'e6db77e5-3df2-4cf1-b95a-636979351e5b' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName  = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
            ValueType  = 'String'
            ValueData  = '1'
        }

        #Network Protection
        Registry 'EnableNetworkProtection' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
            ValueName  = 'EnableNetworkProtection'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        #Real-time Protection
        Registry 'DisableBehaviorMonitoring' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueName  = 'DisableBehaviorMonitoring'
            ValueType  = 'DWord'
            ValueData  = '0'
        }

        Registry 'DisableRealtimeMonitoring' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueName  = 'DisableRealtimeMonitoring'
            ValueType  = 'DWord'
            ValueData  = '0'
        }

        #Scan
        Registry 'DisableRemovableDriveScanning' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\Scan'
            ValueName  = 'DisableRemovableDriveScanning'
            ValueType  = 'DWord'
            ValueData  = '0'
        }

        Registry 'EnableEmailScanning' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\Scan'
            ValueName  = 'EnableEmailScanning'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        #Threats
        Registry 'PUAProtection' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender'
            ValueName  = 'PUAProtection'
            ValueType  = 'DWord'
            ValueData  = '2'
        }

        Registry 'DisableAntiSpyware' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender'
            ValueName  = 'DisableAntiSpyware'
            ValueType  = 'DWord'
            ValueData  = '0'
        }

        #Remote Desktop Services
        Registry 'fSingleSessionPerUser' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fSingleSessionPerUser'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        #RDS Security
        Registry 'fPromptForPassword' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fPromptForPassword'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        Registry 'fEncryptRPCTraffic' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fEncryptRPCTraffic'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        Registry 'SecurityLayer' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
           ValueName  = 'SecurityLayer'
           ValueType  = 'DWord'
           ValueData  = '2'
        }

        Registry 'UserAuthentication' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'UserAuthentication'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
   
        Registry 'MinEncryptionLevel' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'MinEncryptionLevel'
            ValueType  = 'DWord'
            ValueData  = '3'
        }
        
        #RDS Session Timeouts
        Registry 'MaxIdleTime' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'MaxIdleTime'
            ValueType  = 'DWord'
            ValueData  = '900000'
        }

        Registry 'MaxDisconnectionTime' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'MaxDisconnectionTime'
            ValueType  = 'DWord'
            ValueData  = '60000'
        }

        #RDS Temporary Folders
        Registry 'DeleteTempDirsOnExit' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'DeleteTempDirsOnExit'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        Registry 'PerSessionTempDir' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'PerSessionTempDir'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        #Windows Update
        Registry 'NoAutoRebootWithLoggedOnUsers' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueName  = 'NoAutoRebootWithLoggedOnUsers'
            ValueType  = 'DWord'
            ValueData  = '0'
        }

        Registry 'NoAutoUpdate' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueName  = 'NoAutoUpdate'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
  
        Registry 'ScheduledInstallDay' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueName  = 'ScheduledInstallDay'
            ValueType  = 'DWord'
            ValueData  = '0'
        }

    }
}
vcc_ws2019