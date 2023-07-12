Configuration CIS_WindowsServer2019 {
    param (
        [string[]]$ComputerName = 'localhost'
    )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'NetworkingDsc'
 
    Node $ComputerName {
        AccountPolicy AccountPolicies 
        {
            Name                                        = 'PasswordPolicies'
            Store_passwords_using_reversible_encryption = 'Disabled'
            Password_must_meet_complexity_requirements  = 'Enabled'
            Minimum_Password_Length                     = '14'
            Minimum_Password_Age                        = '2'
            Enforce_password_history                     = '24'
            Maximum_Password_Age                        = '50'
        }

        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy   = 'Take_ownership_of_files_or_other_objects'
            Identity = 'Administrators'
        }

        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy   = 'Force_shutdown_from_a_remote_system'
            Identity = 'Administrators'
        }

        UserRightsAssignment Shutdownthesystem {
            Policy   = 'Shut_down_the_system'
            Identity = 'Administrators'
        }

        UserRightsAssignment Restorefilesanddirectories {
            Policy   = 'Restore_files_and_directories'
            Identity = 'Administrators'
        }

        UserRightsAssignment Replaceaprocessleveltoken {
            Policy   = 'Replace_a_process_level_token'
            Identity = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        UserRightsAssignment Profilesystemperformance {
            Policy   = 'Profile_system_performance'
            Identity = 'Administrators, NT SERVICE\WdiServiceHost'
        }

        UserRightsAssignment Profilesingleprocess {
            Policy   = 'Profile_single_process'
            Identity = 'Administrators'
        }

        UserRightsAssignment Performvolumemaintenancetasks {
            Policy   = 'Perform_volume_maintenance_tasks'
            Identity = 'Administrators'
        }

        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy   = 'Modify_firmware_environment_values'
            Identity = 'Administrators'
        }

        UserRightsAssignment Modifyanobjectlabel {
            Policy   = 'Modify_an_object_label'
            Identity = 'No One'
        }

        UserRightsAssignment Lockpagesinmemory {
            Policy   = 'Lock_pages_in_memory'
            Identity = 'No One'
        }

        UserRightsAssignment  Accessthiscomputerfromthenetwork {
            Policy   = 'Access_this_computer_from_the_network'
            Identity = 'Administrators, Authenticated Users'
        }

        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy   = 'Load_and_unload_device_drivers'
            Identity = 'Administrators'
        }    

        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = 'Guests, Local account'
        }

        UserRightsAssignment Denylogonasaservice {
            Policy   = 'Deny_log_on_as_a_service'
            Identity = 'Guests'
        }

        UserRightsAssignment Denylogonasabatchjob {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = 'Guests'
        }

        UserRightsAssignment Createpermanentsharedobjects {
            Policy   = 'Create_permanent_shared_objects'
            Identity = 'No One'
        }

        UserRightsAssignment Createglobalobjects {
            Policy   = 'Create_global_objects'
            Identity = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        }

        UserRightsAssignment Createatokenobject {
            Policy   = 'Create_a_token_object'
            Identity = 'No One'
        }

        UserRightsAssignment Createapagefile {
            Policy   = 'Create_a_pagefile'
            Identity = 'Administrators'
        }

        UserRightsAssignment Bypasstraversechecking {
            Policy   = 'Bypass_traverse_checking'
            Identity = 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
        }

        UserRightsAssignment Changethetimezone {
            Policy   = 'Change_the_time_zone'
            Identity = 'Administrators, LOCAL SERVICE'
        }

        UserRightsAssignment Backupfilesanddirectories {
            Policy   = 'Back_up_files_and_directories'
            Identity = 'Administrators'
        }

        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy   = 'Act_as_part_of_the_operating_system'
            Identity = 'No One'
        }

        UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity = 'No One'
        }

        UserRightsAssignment Createsymboliclinks {
            Policy   = 'Create_symbolic_links'
            Identity = 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
        }

        UserRightsAssignment Allowlogonlocally {
            Policy   = 'Allow_log_on_locally'
            Identity = 'Administrators' 
        }

        UserRightsAssignment Generatesecurityaudits {
            Policy   = 'Generate_security_audits'
            Identity = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        UserRightsAssignment Denylogonlocally {
            Policy   = 'Deny_log_on_locally'
            Identity = 'Guests'
        }

        UserRightsAssignment Changethesystemtime {
            Policy   = 'Change_the_system_time'
            Identity = 'Administrators, LOCAL SERVICE'
        }

        UserRightsAssignment  Manageauditingandsecuritylog {
            Policy   = 'Manage_auditing_and_security_log'
            Identity = 'Administrators'
        }

        UserRightsAssignment  Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy   = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity = 'Administrators'
        }

        UserRightsAssignment  Denyaccesstothiscomputerfromthenetwork {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = 'Guests'
        }

        UserRightsAssignment Increaseschedulingpriority {
            Policy   = 'Increase_scheduling_priority'
            Identity = 'Administrators'
        }

        UserRightsAssignment  AllowlogonthroughRemoteDesktopServices {
            Policy   = 'Allow_log_on_through_Remote_Desktop_Services'
            Identity = 'Administrators'
        }

        AuditPolicySubcategory 'Audit Group Membership (Success)' {
            Name      = 'Group Membership'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Audit Policy Change (Success)' {
            Name      = 'Audit Policy change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Process Creation (Success)' {
            Name      = 'Audit process creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
    
        AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
            Name      = 'Object Access Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
            Name      = 'Object Access Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success)' {
            Name      = 'MPSSVC Rule-Level Policy'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)' {
            Name      = 'MPSSVC Rule-Level Policy'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
       
        AuditPolicySubcategory 'Audit Account Lockout (Success)' {
            Name      = 'Audit Account Lockout'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Audit Account Lockout'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Logon (Success)' {
            Name      = 'Audit Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Logon (Failure)' {
            Name      = 'Audit Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        AuditPolicySubcategory 'Audit Credential Validation (Success)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Credential Validation (Failure)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
       
        AuditPolicySubcategory 'Audit System Integrity (Success)' {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit System Integrity (Failure)' {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        AuditPolicySubcategory 'Audit Special Logon (Success)' {
            Name      = 'Audit Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit PNP Activity (Success)' {
            Name      = 'Audit PNP Activity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Logon/Logoff Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Logon/Logoff Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Logoff (Success)' {
            Name      = 'Audit Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }


        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
           Name      = 'Sensitive Privilege Use'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
           Name      = 'User Account Management'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }
       
        AuditPolicySubcategory 'Audit Security System Extension (Success)' {
           Name      = 'Security System Extension'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Security System Extension (Failure)' {
           Name      = 'Security System Extension'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }
       
        AuditPolicySubcategory 'Audit Security State Change (Success)' {
           Name      = 'Security State Change'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

       
        AuditPolicySubcategory 'Audit Security Group Management (Success)' {
           Name      = 'Security Group Management'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Security Group Management (Failure)' {
           Name      = 'Security Group Management'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }
        
        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
           Name      = 'Removable Storage'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
           Name      = 'Removable Storage'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }

        SecurityOption AccountSecurityOptions {
            Name                                   = 'AccountSecurityOptions'


        Windows_Search_Service           =  'Disabled'    
       
        Interactive_logon_Do_not_display_last_user_name                                                                 = 'Enabled'
        
        Interactive_logon_Do_not_require_CTRL_ALT_DEL                                                                   = 'Disabled'

        Microsoft_network_client_Digitally_sign_communications_always                                                   = 'Enabled'

        Microsoft_network_client_Digitally_sign_communications_if_server_agrees                                         = 'Enabled'

        Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers                                   = 'Disabled'

        Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only                                       = 'Enabled'

        Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on                                                  = 'Disabled'

        Network_access_Remotely_accessible_registry_paths_and_subpaths                                                 = 'System\CurrentControlSet\Control\Print\Printers|#|System\CurrentControlSet\Services\Eventlog|#|Software\Microsoft\OLAP Server|#|Software\Microsoft\Windows NT\CurrentVersion\Print|#|Software\Microsoft\Windows NT\CurrentVersion\Windows|#|System\CurrentControlSet\Control\ContentIndex|#|System\CurrentControlSet\Control\Terminal Server|#|System\CurrentControlSet\Control\Terminal Server\UserConfig|#|System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration|#|Software\Microsoft\Windows NT\CurrentVersion\Perflib|#|System\CurrentControlSet\Services\SysmonLog'

        Network_access_Remotely_accessible_registry_paths                                                               = 'System\CurrentControlSet\Control\ProductOptions|#|System\CurrentControlSet\Control\Server Applications|#|Software\Microsoft\Windows NT\CurrentVersion'

        Network_security_LDAP_client_signing_requirements = 'Negotiate signing'

        System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Enabled'

        Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - local users authenticate as themselves'

        Audit_Shut_down_system_immediately_if_unable_to_log_security_audits                                             = 'Disabled'

        Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'

        Microsoft_network_server_Disconnect_clients_when_logon_hours_expire                                             = 'Enabled'

        Microsoft_network_server_Digitally_sign_communications_if_client_agrees                                         = 'Enabled'

        Microsoft_network_server_Digitally_sign_communications_always                                                   = 'Enabled'

        Network_security_Configure_encryption_types_allowed_for_Kerberos                = 'DES_CBC_CRC', 'DES_CBC_MD5', 'RC4_HMAC_MD5', 'AES128_HMAC_SHA1', 'AES256_HMAC_SHA1', 'FUTURE'

        Devices_Allowed_to_format_and_eject_removable_media                                                             = 'Administrators'

        Devices_Prevent_users_from_installing_printer_drivers                                                           = 'Enabled'

        Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM                                           = 'Enabled'

        Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities                  = 'Disabled'

        Network_access_Let_Everyone_permissions_apply_to_anonymous_users                                                = 'Disabled'

        Network_security_Allow_LocalSystem_NULL_session_fallback                                                = 'Disabled'

        Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'

        Devices_Allow_undock_without_having_to_log_on                                                = 'Disabled'

        User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode            = 'Prompt for consent on the secure desktop'

        }
        
        # Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
        Registry 'SupportedEncryptionTypes' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Sofware\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueName = 'SupportedEncryptionTypes'
            ValueType = 'DWord'
            ValueData = '2147483644'
        }

         
        # Ensure 'Allow Cortana above lock screen' is set to 'Disabled'
        Registry 'AllowCortanaAboveLock' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortanaAboveLock'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)
        Registry 'RestrictRemoteSam' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictRemoteSam'
            ValueType = 'DWord'
            ValueData = 'O:BAG:BAD:(A  RC   BA)'
        }

        # Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
        Registry 'NullSessionShares' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName = 'NullSessionShares'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
        Registry 'LmCompatibilityLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'LmCompatibilityLevel'
            ValueType = 'DWord'
            ValueData = '5'
        }

        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinServerSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinServerSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }

        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinClientSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinClientSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }

        # Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
        Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled' 
        Registry 'EnableUIADesktopToggle' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableUIADesktopToggle'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Allow Cortana' is set to 'Disabled'
        Registry 'AllowCortana' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortana'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Enable 'Turn on behavior monitoring'
        Registry 'DisableBehaviorMonitoring' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection'
            ValueName = 'DisableBehaviorMonitoring'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Enable 'Send file samples when further analysis is required' for 'Send Safe Samples'
        Registry 'SubmitSamplesConsent' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet'
            ValueName = 'SubmitSamplesConsent'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Scan removable drives' is set to 'Enabled'
        Registry 'DisableRemovableDriveScanning' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
            ValueName = 'DisableRemovableDriveScanning'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Detect change from default RDP port' is configured
        Registry 'PortNumber' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp'
            ValueName = 'PortNumber'
            ValueType = 'DWord'
            ValueData = '3389'
        }

        # Ensure 'Allow search and Cortana to use location' is set to 'Disabled'
        Registry 'AllowSearchToUseLocation' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowSearchToUseLocation'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Allow Input Personalization' is set to 'Disabled'
        Registry 'AllowInputPersonalization' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization'
            ValueName = 'AllowInputPersonalization'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Shutdown: Clear virtual memory pagefile' is set to 'Enabled'
        Registry 'ClearPageFileAtShutdown' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management'
            ValueName = 'ClearPageFileAtShutdown'
            ValueType = 'DWord'
            ValueData = '0'
        }
        # Ensure 'Recovery console: Allow floppy copy and access to all drives and all folders' is set to 'Disabled'
        Registry 'AllowAllPaths' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand'
            ValueName = 'AllowAllPaths'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
        Registry 'ConsentPromptBehaviorUser' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'ConsentPromptBehaviorUser'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
        Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Specify the interval to check for definition updates' is set to 'Enabled:1'
        Registry 'SignatureUpdateInterval' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Signature Updates'
            ValueName = 'SignatureUpdateInterval'
            ValueType = 'DWord'
            ValueData = '8'
        }

        # Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes'
        Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }
        # Ensure 'Windows Firewall: Public: Allow unicast response' is set to 'No'
        Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '1'
        }
        
        # Ensure 'Windows Firewall: Private: Allow unicast response' is set to 'No'
        Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Windows Firewall: Domain: Allow unicast response' is set to 'No'
        Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
        Registry 'AllowLocalPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'AllowLocalPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
        Registry 'EnableAuthEpResolution' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName = 'EnableAuthEpResolution'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Enable Windows NTP Client' is set to 'Enabled'
        Registry 'NTPClientEnabled' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
        Registry 'EnumerateAdministrators' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueName = 'EnumerateAdministrators'
            ValueType = 'DWord'
            ValueData = '0'
        }
        # Ensure 'Include command line in process creation events' is set to 'Disabled'
        Registry 'ProcessCreationIncludeCmdLine_Enabled' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Allow Basic authentication' is set to 'Disabled'
        Registry 'AllowBasic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowBasic'
            ValueType = 'DWord'
            ValueData = '0'
        } 
        

        # Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
        Registry 'fMinimizeConnections' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueName = 'fMinimizeConnections'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
        Registry 'DisableAutomaticRestartSignOn' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSetupLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSetupLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
        Registry 'NoAutorun' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoAutorun'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
        Registry 'MaxSizeSecurityLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '196700'
        }

        # Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSecurityLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
        Registry 'NC_AllowNetBridge_NLA' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_AllowNetBridge_NLA'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
        Registry 'NoLockScreenSlideshow' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenSlideshow'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' 
        Registry 'NoLockScreenCamera' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenCamera'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
        Registry 'DisableEnclosureDownload' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName = 'DisableEnclosureDownload'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' 
        Registry 'NoLMHash' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'NoLMHash'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Continue experiences on this device' is set to 'Disabled' 
        Registry 'EnableCdp' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableCdp'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
        Registry 'OfferRemoteAssistance' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'OfferRemoteAssistance'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
        Registry 'DriverLoadPolicy' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName = 'DriverLoadPolicy'
            ValueType = 'DWord'
            ValueData = '3'
        }

        # Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionApplicationLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
        Registry 'DisableRunAs' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'DisableRunAs'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Disallow Digest authentication' is set to 'Enabled'
        Registry 'AllowDigest' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowDigest'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
        Registry 'NoAutoplayfornonVolume' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoAutoplayfornonVolume'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
        Registry 'MSAOptional' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'MSAOptional'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
        Registry 'AllowIndexingEncryptedStoresOrItems' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
        Registry 'BlockUserFromSh owingAccountDetailsOnSignin' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'BlockUserFromShowingAccountDetailsOnSignin'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)
        Registry 'RestrictAnonymousSAM' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictAnonymousSAM'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)
        Registry 'RestrictAnonymous' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictAnonymous'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Require secure RPC communication' is set to 'Enabled'
        Registry 'fEncryptRPCTraffic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEncryptRPCTraffic'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
        Registry 'NC_PersonalFirewallConfig' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_PersonalFirewallConfig'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Do not display the password reveal button' is set to 'Enabled'
        Registry 'DisablePasswordReveal' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
            ValueName = 'DisablePasswordReveal'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
        Registry 'MinEncryptionLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'DWord'
            ValueData = '3'
        }

        # Ensure 'Always install with elevated privileges' is set to 'Disabled'
        Registry 'AlwaysInstallElevated' {
            Ensure    = 'Present'
            Key       = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'AlwaysInstallElevated'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Allow user control over installs' is set to 'Disabled'
        Registry 'EnableUserControl' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueName = 'EnableUserControl'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Allow unencrypted traffic' is set to 'Disabled'
        Registry 'AllowUnencryptedTraffic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'
        Registry 'AllowTelemetry' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
        Registry 'DisablePasswordSaving' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DisablePasswordSaving'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
        Registry 'DeleteTempDirsOnExit' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DeleteTempDirsOnExit'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Do not display network selection UI' is set to 'Enabled'
        Registry 'DontDisplayNetworkSelectionUI' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Always prompt for password upon connection' is set to 'Enabled'
        Registry 'fPromptForPassword' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeApplication' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # Ensure 'Do not show feedback notifications' is set to 'Enabled'
        Registry 'DoNotShowFeedbackNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'DoNotShowFeedbackNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Do not use temporary folders per session' is set to 'Disabled'
        Registry 'PerSessionTempDir' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'PerSessionTempDir'
            ValueType = 'DWord'
            ValueData = '1'
        }
        
        # Ensure 'Enable insecure guest logons' is set to 'Disabled'
        Registry 'AllowInsecureGuestAuth' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
        Registry 'RestrictNullSessAccess' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName = 'RestrictNullSessAccess'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
        Registry 'AllowDomainPINLogon' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
            ValueName = 'AllowDomainPINLogon'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
        Registry 'FilterAdministratorToken' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'FilterAdministratorToken'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
        Registry 'AllowLocalPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }

        # Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPrivate' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
        Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalIPsecPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }

        # Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'
        Registry 'UserAuthentication' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'UserAuthentication'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
        Registry 'turuoffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'turuoffNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
        Registry 'NoDriveTypeAutoRun' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'DWord'
            ValueData = '255'
        }

        # Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
        Registry 'OutboundActionDefault' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
            ValueName = 'OutboundActionDefault'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No''
        Registry 'DisableNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DisableNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
        Registry 'DisableWebPnPDownload' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
            ValueName = 'DisableWebPnPDownload'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
        Registry 'EnableVirtualization' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableVirtualization'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
        Registry 'PromptOnSecureDesktop' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'PromptOnSecureDesktop'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
        Registry 'EnableLUA' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableLUA'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
        Registry 'EnableInstallerDetection' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableInstallerDetection'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallDomain' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
        Registry 'NoDataExecutionPrevention' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoDataExecutionPrevention'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' 
        Registry 'DisableLockScreenAppNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DisableLockScreenAppNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSystemLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSystemLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
        Registry 'ProtectionMode' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'
            ValueName = 'ProtectionMode'
            ValueType = 'String'
            ValueData = '1'
        }

        # Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
        Registry 'ObCaseInsensitive' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'
            ValueName = 'ObCaseInsensitiv'
            ValueType = 'String'
            ValueData = '1'
        }

        # Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPublic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)
        Registry 'OutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'OutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
        Registry 'DefaultOutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
        Registry 'NoHeapTerminationOnCorruption' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoHeapTerminationOnCorruption'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
        Registry 'OffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
            ValueName = 'OffNotifications'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
        Registry 'ExitOnMSICW' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
            ValueName = 'ExitOnMSICW'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
        Registry 'DisableWindowsConsumerFeatures' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Turn off multicast name resolution' is set to 'Enabled' 
        Registry 'EnableMulticast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName = 'EnableMulticast'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Turn off shell protocol protected mode' is set to 'Disabled' 
        Registry 'PreXPSP2ShellProtocolBehavior' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explore r'
            ValueName = 'PreXPSP2ShellProtocolBehavior'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' 
        Registry 'EnableSecureUIAPaths' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableSecureUIAPaths'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' 
        Registry 'EnableSmartScreen' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableSmartScreen'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
        Registry 'fAllowToGetHelp' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fAllowToGetHelp'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'
        Registry 'LocalSettingOverrideSpynetReporting' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'LocalSettingOverrideSpynetReporting'
            ValueType = 'DWord'
            ValueData = '0'
        }
        
        # Ensure 'Configure SMB v1 server' is set to 'Disabled'
        Registry 'SMB1' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName = 'SMB1'
            ValueType = 'DWord'
            ValueData = '0'
        }
    }
}
CIS_Benchmark_WindowsServer2019_v100
