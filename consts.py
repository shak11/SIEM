SYS_PORT = 514
FW_FILE_NAME = './Logs/FW_Log.csv'
WIN_FILE_NAME = './Logs/WIN_Log.csv'
ALERT_FILE_NAME = './Logs/ALERT.csv'
Web_UI = "./index.html"
Days_Back = 3
Refresh_rate = 20
Beautify_FW_Parser = ['Date', 'Time', 'Level', 'Source_IP', 'Dest_IP', 'Destination_Port', 'Proto', 'Action',
                      'Policy_ID', 'Service', 'Sent_Bytes', 'Received_Bytes']

Syslog_FW_Parser = ['Date', 'Time', 'level', 'srcip', 'dstip', 'dstport', 'action', 'policyid',
                    'service', 'sentbyte', 'rcvdbyte']


proto = {
    6: "TCP",
    17: "UDP"
}

Syslog_Windows_Parser = ['Date', 'Time', 'Host_name', 'Priority', 'Event_ID', 'Severity', 'Description']


Severity = {
    0: "EMERGENCY",
    1: "ALERT",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARNING",
    5: "NOTICE",
    6: "INFO",
    7: "DEBUG"
}

# (jumps by 8)
Facility = {

    0: "KERNEL",
    1: "USER_LEVEL",
    2: "MAIL",
    3: "SYSTEM",
    4: "USER_AUTH",
    5: "SYSLOG",
    6: "LPD_PRINTER",
    7: "NEWS_NTP",
    8: "UUCP",
    9: "TIME",
    10: "SECURE_AUTH",
    11: "FTP",
    12: "NTP",
    13: "LOGAUDIT",
    14: "LOGALERT",
    15: "CLOCK",
    16: "LOCAL0",
    17: "LOCAL1",
    18: "LOCAL2",
    19: "LOCAL3",
    20: "LOCAL4",
    21: "LOCAL5",
    22: "LOCAL6",
    23: "LOCAL7"
}

event_id = {
    '1102': 'Critical, Audit log was cleared.'
    , '4618': 'Critical,	A monitored security event pattern has occurred.'
    , '4649': 'Critical,	A replay attack was detected. May be a harmless false positive due to misconfiguration error.'
    , '612':  'Critical,	System audit policy was changed.'
    , '4765': 'Critical,	SID History was added to an account.'
    , '4766': 'Critical,	An attempt to add SID History to an account failed.'
    , '4794': 'Critical,	An attempt was made to set the Directory Services Restore Mode.'
    , '4964': 'Critical,	Special groups have been assigned to a new logon.'
    , '5124': 'Critical,	A security setting was updated on the OCSP Responder Service'
    , '550':  'Critical,	Possible denial-of-service (DoS) attack'
    , '4621': 'Critical,	Administrator recovered system from CrashOnAuditFail. Users who are not administrators will '
              'now be allowed to log on. Some auditable activity might not have been recorded. '
    , '4675': 'Critical,	SIDs were filtered.'
    , '4692': 'Critical,	Backup of data protection master key was attempted.'
    , '4693': 'Critical,	Recovery of data protection master key was attempted.'
    , '4706': 'Critical,	A new trust was created to a domain.'
    , '4713': 'Critical,	Kerberos policy was changed.'
    , '4714': 'Critical,	Encrypted data recovery policy was changed.'
    , '4715': 'Critical,	The audit policy (SACL) on an object was changed.'
    , '4716': 'Critical,	Trusted domain information was modified.'
    , '4719': 'Critical,  System audit policy has changed'
    , '4724': 'Critical,	An attempt was made to reset an accounts password.'
    , '4727': 'Critical,	A security-enabled global group was created.'
    , '4735': 'Critical,	A security-enabled local group was changed.'
    , '4737': 'Critical,	A security-enabled global group was changed.'
    , '4739': 'Critical,	Domain Policy was changed.'
    , '4754': 'Critical,	A security-enabled universal group was created.'
    , '4755': 'Critical,	A security-enabled universal group was changed.'
    , '4764': 'Critical,	A security-disabled group was deleted '
    , '4764': 'Critical,	A groups type was changed.'
    , '4780': 'Critical,	The ACL was set on accounts which are members of administrators groups.'
    , '4816': 'Critical,	RPC detected an integrity violation while decrypting an incoming message.'
    , '4865': 'Critical,	A trusted forest information entry was added.'
    , '4866': 'Critical,	A trusted forest information entry was removed.'
    , '4867': 'Critical,	A trusted forest information entry was modified.'
    , '4868': 'Critical,	The certificate manager denied a pending certificate request.'
    , '4870': 'Critical,	Certificate Services revoked a certificate.'
    , '4882': 'Critical,	The security permissions for Certificate Services changed.'
    , '4885': 'Critical,	The audit filter for Certificate Services changed.'
    , '4890': 'Critical,	The certificate manager settings for Certificate Services changed.'
    , '4892': 'Critical,	A property of Certificate Services changed.'
    , '4896': 'Critical,	One or more rows have been deleted from the certificate database.'
    , '4906': 'Critical,	The CrashOnAuditFail value has changed.'
    , '4907': 'Critical,	Auditing settings on object were changed.'
    , '4908': 'Critical,	Special Groups Logon table modified.'
    , '4912': 'Critical,	Per User Audit Policy was changed.'
    , '4960': 'Critical,	IPsec dropped an inbound packet that failed an integrity check. If this problem '
              'persists, it could indicate a network issue or that packets are being modified in transit to '
              'this computer. Verify that the packets sent from the remote computer are the same as those '
              'received by this computer. This error might also indicate interoperability problems with other '
              'IPsec implementations. '
    , '4961': 'Critical,	IPsec dropped an inbound packet that failed a replay check. If this problem persists, '
              'it could indicate a replay attack against this computer. '
    , '4962': 'Critical,	IPsec dropped an inbound packet that failed a replay check. The inbound packet had too '
              'low a sequence number to ensure it was not a replay. '
    , '4963': 'Critical,	IPsec dropped an inbound clear text packet that should have been secured. This is '
              'usually due to the remote computer changing its IPsec policy without informing this computer. '
              'This could also be a spoofing attack attempt. '
    , '4965': 'Critical,	IPsec received a packet from a remote computer with an incorrect Security Parameter '
              'Index (SPI). This is usually caused by malfunctioning hardware that is corrupting packets. If '
              'these errors persist, verify that the packets sent from the remote computer are the same as '
              'those received by this computer. This error may also indicate interoperability problems with '
              'other IPsec implementations. In that case, if connectivity is not impeded, then these events can '
              'be ignored. '
    , '4976': 'Critical,	During Main Mode negotiation, IPsec received an invalid negotiation packet. If this '
              'problem persists, it could indicate a network issue or an attempt to modify or replay this '
              'negotiation. '
    , '4977': 'Critical,	During Quick Mode negotiation, IPsec received an invalid negotiation packet. If this '
              'problem persists, it could indicate a network issue or an attempt to modify or replay this '
              'negotiation. '
    , '4978': 'Critical,	During Extended Mode negotiation, IPsec received an invalid negotiation packet. If '
              'this problem persists, it could indicate a network issue or an attempt to modify or replay this '
              'negotiation. '
    , '4983': 'Critical,	An IPsec Extended Mode negotiation failed. The corresponding Main Mode security '
              'association has been deleted. '
    , '4984': 'Critical,	An IPsec Extended Mode negotiation failed. The corresponding Main Mode security '
              'association has been deleted. '
    , '5027': 'Critical,	The Windows Firewall Service was unable to retrieve the security policy from the local '
              'storage. The service will continue enforcing the current policy. '
    , '5028': 'Critical,	The Windows Firewall Service was unable to parse the new security policy. The service '
              'will continue with currently enforced policy. '
    , '5029': 'Critical,	The Windows Firewall Service failed to initialize the driver. The service will '
              'continue to enforce the current policy. '
    , '5030': 'Critical,	The Windows Firewall Service failed to start.'
    , '5035': 'Critical,	The Windows Firewall Driver failed to start.'
    , '5037': 'Critical,	The Windows Firewall Driver detected critical runtime error. Terminating'
    , '5038': 'Critical,	Code integrity determined that the image hash of a file is not valid. The file could '
              'be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk '
              'device error. '
    , '5120': 'Critical,	OCSP Responder Service Started'
    , '5121': 'Critical,	OCSP Responder Service Stopped'
    , '5122': 'Critical,	A configuration entry changed in OCSP Responder Service'
    , '5123': 'Critical,	A configuration entry changed in OCSP Responder Service'
    , '5376': 'Critical,	Credential Manager credentials were backed up.'
    , '5377': 'Critical,	Credential Manager credentials were restored from a backup.'
    , '5453': 'Critical,	An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec '
              'Keying Modules (IKEEXT) service is not started. '
    , '5480': 'Critical,	IPsec Services failed to get the complete list of network interfaces on the computer. '
              'This poses a potential security risk because some of the network interfaces may not get the '
              'protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to '
              'diagnose the problem. '
    , '5483': 'Critical,	IPsec Services failed to initialize RPC server. IPsec Services could not be started.'
    , '5484': 'Critical,	IPsec Services has experienced a critical failure and has been shut down. The shutdown '
              'of IPsec Services can put the computer at greater risk of network attack or expose the computer '
              'to potential security risks. '
    , '5485': 'Critical,	IPsec Services failed to process some IPsec filters on a plug-and-play event for '
              'network interfaces. This poses a potential security risk because some of the network interfaces '
              'may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor '
              'snap-in to diagnose the problem. '
    , '6145': 'Critical,	One or more errors occurred while processing security policy in the Group Policy objects.'
    , '6273': 'Critical,	Network Policy Server denied access to a user.'
    , '6274': 'Critical,	Network Policy Server discarded the request for a user.'
    , '6275': 'Critical,	Network Policy Server discarded the accounting request for a user.'
    , '6276': 'Critical,	Network Policy Server quarantined a user.'
    , '6277': 'Critical,	Network Policy Server granted access to a user but put it on probation because the '
              'host did not meet the defined health policy. '
    , '6278': 'Critical,	Network Policy Server granted full access to a user because the host met the defined '
              'health policy. '
    , '6279': 'Critical,	Network Policy Server locked the user account due to repeated failed authentication attempts.'
    , '6280': 'Critical,	Network Policy Server unlocked the user account.'
    , '2458': 'Critical,	An error was encountered converting volume'
    , '2459': 'Critical,	An attempt to automatically restart conversion on volume %2 failed.'
    , '2459': 'Critical,	Metadata write: Volume %2 returning errors while trying to modify metadata. If '
              'failures continue, decrypt volume '
    , '2459': 'Critical,	Metadata rebuild: An attempt to write a copy of metadata on volume %2 failed and may '
              'appear as disk corruption. If failures continue, decrypt volume. '
    , '4608': 'Low,	Windows is starting up.'
    , '4609': 'Low,	Windows is shutting down.'
    , '4610': 'Low,	An authentication package has been loaded by the Local Security Authority.'
    , '4611': 'Low,	A trusted logon process has been registered with the Local Security Authority.'
    , '4612': 'Low,	Internal resources allocated for the queuing of audit messages have been exhausted, '
              'leading to the loss of some audits. '
    , '4614': 'Low,	A notification package has been loaded by the Security Account Manager.'
    , '4615': 'Low,	Invalid use of LPC port.'
    , '4616': 'Low,	The system time was changed.'
    , '4622': 'Low,	A security package has been loaded by the Local Security Authority.'
    , '4624': 'Low,	An account was successfully logged on.'
    , '4625': 'Critical,	An account failed to log on.'
    , '4634': 'Low,	An account was logged off.'
    , '4646': 'Low,	IKE DoS-prevention mode started.'
    , '4647': 'Low,	User initiated logoff.'
    , '4648': 'Critical,	A logon was attempted using explicit credentials.'
    , '4650': 'Low,	An IPsec Main Mode security association was established. Extended Mode was not enabled. '
              'Certificate authentication was not used. '
    , '4651': 'Low,	An IPsec Main Mode security association was established. Extended Mode was not enabled. A '
              'certificate was used for authentication. '
    , '4652': 'Low,	An IPsec Main Mode negotiation failed.'
    , '4653': 'Low,	An IPsec Main Mode negotiation failed.'
    , '4654': 'Low,	An IPsec Quick Mode negotiation failed.'
    , '4655': 'Low,	An IPsec Main Mode security association ended.'
    , '4656': 'Low,	A handle to an object was requested.'
    , '4657': 'Critical,	A registry value was modified.'
    , '4658': 'Low,	The handle to an object was closed.'
    , '4659': 'Low,	A handle to an object was requested with intent to delete.'
    , '4660': 'Low,	An object was deleted.'
    , '4661': 'Low,	A handle to an object was requested.'
    , '4662': 'Low,	An operation was performed on an object.'
    , '4663': 'Low,	An attempt was made to access an object.'
    , '4664': 'Low,	An attempt was made to create a hard link.'
    , '4665': 'Low,	An attempt was made to create an application client context.'
    , '4666': 'Low,	An application attempted an operation:'
    , '4667': 'Low,	An application client context was deleted.'
    , '4668': 'Low,	An application was initialized.'
    , '4670': 'Low,	Permissions on an object were changed.'
    , '4671': 'Low,	An application attempted to access a blocked ordinal through the TBS.'
    , '4672': 'Low,	Special privileges assigned to new logon.'
    , '4673': 'Low,	A privileged service was called.'
    , '4674': 'Low,	An operation was attempted on a privileged object.'
    , '4688': 'Low,	A new process has been created.'
    , '4689': 'Low,	A process has exited.'
    , '4690': 'Low,	An attempt was made to duplicate a handle to an object.'
    , '4691': 'Low,	Indirect access to an object was requested.'
    , '4694': 'Low,	Protection of auditable protected data was attempted.'
    , '4695': 'Low,	Unprotection of auditable protected data was attempted.'
    , '4696': 'Low,	A primary token was assigned to process.'
    , '4697': 'Critical,	Attempt to install a service'
    , '4698': 'Critical,	A scheduled task was created.'
    , '4699': 'Critical,	A scheduled task was deleted.'
    , '4700': 'Critical,	A scheduled task was enabled.'
    , '4701': 'Critical,	A scheduled task was disabled.'
    , '4702': 'Critical,	A scheduled task was updated.'
    , '4704': 'Low,	A user right was assigned.'
    , '4705': 'Low,	A user right was removed.'
    , '4707': 'Low,	A trust to a domain was removed.'
    , '4709': 'Low,	IPsec Services was started.'
    , '4710': 'Low,	IPsec Services was disabled.'
    , '4711': 'Low,	May contain any one of the following: PAStore Engine applied locally cached copy of Active '
              'Directory storage IPsec policy on the computer. PAStore Engine applied Active Directory storage '
              'IPsec policy on the computer. PAStore Engine applied local registry storage IPsec policy on the '
              'computer. PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec '
              'policy on the computer. PAStore Engine failed to apply Active Directory storage IPsec policy on '
              'the computer. PAStore Engine failed to apply local registry storage IPsec policy on the '
              'computer. PAStore Engine failed to apply some rules of the active IPsec policy on the computer. '
              'PAStore Engine failed to load directory storage IPsec policy on the computer. PAStore Engine '
              'loaded directory storage IPsec policy on the computer. PAStore Engine failed to load local '
              'storage IPsec policy on the computer. PAStore Engine loaded local storage IPsec policy on the '
              'computer.PAStore Engine polled for changes to the active IPsec policy and detected no changes. '
    , '4712': 'Low,	IPsec Services encountered a potentially serious failure.'
    , '4717': 'Low,	System security access was granted to an account.'
    , '4718': 'Low,	System security access was removed from an account.'
    , '4720': 'Critical,	A user account was created.'
    , '4722': 'Critical,	A user account was enabled.'
    , '4723': 'Critical,	An attempt was made to change an account'
    , '4725': 'Critical,	A user account was disabled.'
    , '4726': 'Critical,	A user account was deleted.'
    , '4728': 'Critical,	A member was added to a security-enabled global group.'
    , '4729': 'Critical,	A member was removed from a security-enabled global group.'
    , '4730': 'Critical,	A security-enabled global group was deleted.'
    , '4731': 'Critical,	A security-enabled local group was created.'
    , '4732': 'Critical,	A member was added to a security-enabled local group.'
    , '4733': 'Critical,	A member was removed from a security-enabled local group.'
    , '4734': 'Critical,	A security-enabled local group was deleted.'
    , '4738': 'Critical,	A user account was changed.'
    , '4740': 'Critical,	A user account was locked out.'
    , '4741': 'Low,	A computer account was changed.'
    , '4742': 'Low,	A computer account was changed.'
    , '4743': 'Low,	A computer account was deleted.'
    , '4744': 'Low,	A security-disabled local group was created'
    , '4745': 'Low,	A security-disabled local group was changed'
    , '4746': 'Low,	A member was added to a security-disabled local group.'
    , '4747': 'Low,	A member was removed from a security-disabled local group.'
    , '4748': 'Low,	A security-disabled local group was deleted'
    , '4749': 'Low,	A security-disabled global group was created.'
    , '4750': 'Low,	A security-disabled global group was changed.'
    , '4751': 'Low,	A member was added to a security-disabled global group.'
    , '4752': 'Low,	A member was removed from a security-disabled global group.'
    , '4753': 'Low,	A security-disabled global group was deleted.'
    , '4756': 'Critical,	A member was added to a security-enabled universal group.'
    , '4757': 'Critical,	A member was removed from a security-enabled universal group.'
    , '4758': 'Low,	A security-enabled universal group was deleted.'
    , '4759': 'Low,	A security-disabled universal group was created.'
    , '4760': 'Low,	A security-disabled universal group was changed.'
    , '4761': 'Low,	A member was added to a security-disabled universal group.'
    , '4762': 'Low,	A member was removed from a security-disabled universal group.'
    , '4767': 'Critical,	A user account was unlocked.'
    , '4768': 'Low,	A Kerberos authentication ticket (TGT) was requested.'
    , '4769': 'Low,	A Kerberos service ticket was requested.'
    , '4770': 'Low,	A Kerberos service ticket was renewed.'
    , '4771': 'Low,	Kerberos pre-authentication failed.'
    , '4772': 'Critical,	A Kerberos authentication ticket request failed.'
    , '4774': 'Low,	An account was mapped for logon.'
    , '4775': 'Low,	An account could not be mapped for logon'
    , '4776': 'Low,	The domain controller attempted to validate the credentials for an account.'
    , '4777': 'Critical,	The domain controller failed to validate the credentials for an account.'
    , '4778': 'Low,	A session was reconnected to a Window Station.'
    , '4779': 'Low,	A session was disconnected from a Window Station.'
    , '4781': 'Low,	The name of an account was changed:'
    , '4782': 'Critical,	The password hash an account was accessed.'
    , '4783': 'Low,	A basic application group was created.'
    , '4784': 'Low,	A basic application group was changed.'
    , '4785': 'Low,	A member was added to a basic application group.'
    , '4786': 'Low,	A member was removed from a basic application group.'
    , '4787': 'Low,	A nonmember was added to a basic application group.'
    , '4788': 'Low,	A nonmember was removed from a basic application group.'
    , '4789': 'Low,	A basic application group was deleted.'
    , '4790': 'Low,	An LDAP query group was created.'
    , '4793': 'Low,	The Password Policy Checking API was called.'
    , '4800': 'Low,	The workstation was locked.'
    , '4801': 'Low,	The workstation was unlocked.'
    , '4802': 'Low,	The screen saver was invoked.'
    , '4803': 'Low,	The screen saver was dismissed.'
    , '4864': 'Low,	A namespace collision was detected.'
    , '4869': 'Low,	Certificate Services received a resubmitted certificate request.'
    , '4871': 'Low,	Certificate Services received a request to publish the certificate revocation list (CRL).'
    , '4872': 'Low,	Certificate Services published the certificate revocation list (CRL).'
    , '4873': 'Low,	A certificate request extension changed.'
    , '4874': 'Low,	One or more certificate request attributes changed.'
    , '4875': 'Low,	Certificate Services received a request to shut down.'
    , '4876': 'Low,	Certificate Services backup started.'
    , '4877': 'Low,	Certificate Services backup completed.'
    , '4878': 'Low,	Certificate Services restore started.'
    , '4879': 'Low,	Certificate Services restore completed.'
    , '4880': 'Low,	Certificate Services started.'
    , '4881': 'Low,	Certificate Services stopped.'
    , '4883': 'Low,	Certificate Services retrieved an archived key.'
    , '4884': 'Low,	Certificate Services imported a certificate into its database.'
    , '4886': 'Low,	Certificate Services received a certificate request.'
    , '4887': 'Low,	Certificate Services approved a certificate request and issued a certificate.'
    , '4888': 'Low,	Certificate Services denied a certificate request.'
    , '4889': 'Low,	Certificate Services set the status of a certificate request to pending.'
    , '4891': 'Low,	A configuration entry changed in Certificate Services.'
    , '4893': 'Low,	Certificate Services archived a key.'
    , '4894': 'Low,	Certificate Services imported and archived a key.'
    , '4895': 'Low,	Certificate Services published the CA certificate to Active Directory Domain Services.'
    , '4898': 'Low,	Certificate Services loaded a template.'
    , '4902': 'Low,	The Per-user audit policy table was created.'
    , '4904': 'Low,	An attempt was made to register a security event source.'
    , '4905': 'Low,	An attempt was made to unregister a security event source.'
    , '4909': 'Low,	The local policy settings for the TBS were changed.'
    , '4910': 'Low,	The Group Policy settings for the TBS were changed.'
    , '4928': 'Low,	An Active Directory replica source naming context was established.'
    , '4929': 'Low,	An Active Directory replica source naming context was removed.'
    , '4930': 'Low,	An Active Directory replica source naming context was modified.'
    , '4931': 'Low,	An Active Directory replica destination naming context was modified.'
    , '4932': 'Low,	Synchronization of a replica of an Active Directory naming context has begun.'
    , '4933': 'Low,	Synchronization of a replica of an Active Directory naming context has ended.'
    , '4934': 'Low,	Attributes of an Active Directory object were replicated.'
    , '4935': 'Low,	Replication failure begins.'
    , '4936': 'Low,	Replication failure ends.'
    , '4937': 'Low,	A lingering object was removed from a replica.'
    , '4944': 'Low,	The following policy was active when the Windows Firewall started.'
    , '4945': 'Low,	A rule was listed when the Windows Firewall started.'
    , '4946': 'Critical,	A change has been made to Windows Firewall exception list. A rule was added.'
    , '4947': 'Critical,	A change has been made to Windows Firewall exception list. A rule was modified.'
    , '4948': 'Critical,	A change has been made to Windows Firewall exception list. A rule was deleted.'
    , '4949': 'Low,	Windows Firewall settings were restored to the default values.'
    , '4950': 'Critical,	A Windows Firewall setting has changed.'
    , '4951': 'Low,	A rule has been ignored because its major version number was not recognized by Windows Firewall.'
    , '4952': 'Low,	Parts of a rule have been ignored because its minor version number was not recognized by Windows '
              'Firewall. The other parts of the rule will be enforced. '
    , '4953': 'Low,	A rule has been ignored by Windows Firewall because it could not parse the rule.'
    , '4954': 'Critical,	Windows Firewall Group Policy settings have changed. The new settings have been applied.'
    , '4956': 'Low,	Windows Firewall has changed the active profile.'
    , '4957': 'Low,	Windows Firewall did not apply the following rule:'
    , '4958': 'Low,	Windows Firewall did not apply the following rule because the rule referred to items not '
              'configured on this computer: '
    , '4979': 'Low,	IPsec Main Mode and Extended Mode security associations were established.'
    , '4980': 'Low,	IPsec Main Mode and Extended Mode security associations were established.'
    , '4981': 'Low,	IPsec Main Mode and Extended Mode security associations were established.'
    , '4982': 'Low,	IPsec Main Mode and Extended Mode security associations were established.'
    , '4985': 'Low,	The state of a transaction has changed.'
    , '5024': 'Low,	The Windows Firewall Service has started successfully.'
    , '5025': 'Critical,	The Windows Firewall Service has been stopped.'
    , '5031': 'Critical,	The Windows Firewall Service blocked an application from accepting incoming connections '
              'on the network. '
    , '5032': 'Low,	Windows Firewall was unable to notify the user that it blocked an application from accepting '
              'incoming connections on the network. '
    , '5033': 'Low,	The Windows Firewall Driver has started successfully.'
    , '5034': 'Low,	The Windows Firewall Driver has been stopped.'
    , '5039': 'Low,	A registry key was virtualized.'
    , '5040': 'Low,	A change has been made to IPsec settings. An Authentication Set was added.'
    , '5041': 'Low,	A change has been made to IPsec settings. An Authentication Set was modified.'
    , '5042': 'Low,	A change has been made to IPsec settings. An Authentication Set was deleted.'
    , '5043': 'Low,	A change has been made to IPsec settings. A Connection Security Rule was added.'
    , '5044': 'Low,	A change has been made to IPsec settings. A Connection Security Rule was modified.'
    , '5045': 'Low,	A change has been made to IPsec settings. A Connection Security Rule was deleted.'
    , '5046': 'Low,	A change has been made to IPsec settings. A Crypto Set was added.'
    , '5047': 'Low,	A change has been made to IPsec settings. A Crypto Set was modified.'
    , '5048': 'Low,	A change has been made to IPsec settings. A Crypto Set was deleted.'
    , '5050': 'Low,	An attempt to programmatically disable the Windows Firewall using a call to '
              'InetFwProfile.FirewallEnabled(False) '
    , '5051': 'Low,	A file was virtualized.'
    , '5056': 'Low,	A cryptographic self test was performed.'
    , '5057': 'Low,	A cryptographic primitive operation failed.'
    , '5058': 'Low,	Key file operation.'
    , '5059': 'Low,	Key migration operation.'
    , '5060': 'Low,	Verification operation failed.'
    , '5061': 'Low,	Cryptographic operation.'
    , '5062': 'Low,	A kernel-mode cryptographic self test was performed.'
    , '5063': 'Low,	A cryptographic provider operation was attempted.'
    , '5064': 'Low,	A cryptographic context operation was attempted.'
    , '5065': 'Low,	A cryptographic context modification was attempted.'
    , '5066': 'Low,	A cryptographic function operation was attempted.'
    , '5067': 'Low,	A cryptographic function modification was attempted.'
    , '5068': 'Low,	A cryptographic function provider operation was attempted.'
    , '5069': 'Low,	A cryptographic function property operation was attempted.'
    , '5070': 'Low,	A cryptographic function property modification was attempted.'
    , '5125': 'Low,	A request was submitted to the OCSP Responder Service'
    , '5126': 'Low,	Signing Certificate was automatically updated by the OCSP Responder Service'
    , '5127': 'Low,	The OCSP Revocation Provider successfully updated the revocation information'
    , '5136': 'Low,	A directory service object was modified.'
    , '5137': 'Low,	A directory service object was created.'
    , '5138': 'Low,	A directory service object was undeleted.'
    , '5139': 'Low,	A directory service object was moved.'
    , '5140': 'Low,	A network share object was accessed.'
    , '5141': 'Low,	A directory service object was deleted.'
    , '5152': 'Critical,	The Windows Filtering Platform blocked a packet.'
    , '5153': 'Critical,	A more restrictive Windows Filtering Platform filter has blocked a packet.'
    , '5154': 'Low,	The Windows Filtering Platform has permitted an application or service to listen on a port for '
              'incoming connections. '
    , '5155': 'Low,	The Windows Filtering Platform has blocked an application or service from listening on a port for '
              'incoming connections. '
    , '5156': 'Low,	The Windows Filtering Platform has allowed a connection.'
    , '5157': 'Critical,	The Windows Filtering Platform has blocked a connection.'
    , '5158': 'Low,	The Windows Filtering Platform has permitted a bind to a local port.'
    , '5159': 'Low,	The Windows Filtering Platform has blocked a bind to a local port.'
    , '5378': 'Low,	The requested credentials delegation was disallowed by policy.'
    , '5440': 'Low,	The following callout was present when the Windows Filtering Platform Base Filtering Engine started.'
    , '5441': 'Low,	The following filter was present when the Windows Filtering Platform Base Filtering Engine started.'
    , '5442': 'Low,	The following provider was present when the Windows Filtering Platform Base Filtering Engine started.'
    , '5443': 'Low,	The following provider context was present when the Windows Filtering Platform Base Filtering '
              'Engine started. '
    , '5444': 'Low,	The following sublayer was present when the Windows Filtering Platform Base Filtering Engine started.'
    , '5446': 'Low,	A Windows Filtering Platform callout has been changed.'
    , '5447': 'Low,	A Windows Filtering Platform filter has been changed.'
    , '5448': 'Low,	A Windows Filtering Platform provider has been changed.'
    , '5449': 'Low,	A Windows Filtering Platform provider context has been changed.'
    , '5450': 'Low,	A Windows Filtering Platform sublayer has been changed.'
    , '5451': 'Low,	An IPsec Quick Mode security association was established.'
    , '5452': 'Low,	An IPsec Quick Mode security association ended.'
    , '5456': 'Low,	PAStore Engine applied Active Directory storage IPsec policy on the computer.'
    , '5457': 'Low,	PAStore Engine failed to apply Active Directory storage IPsec policy on the computer.'
    , '5458': 'Low,	PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer.'
    , '5459': 'Low,	PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the '
              'computer. '
    , '5460': 'Low,	PAStore Engine applied local registry storage IPsec policy on the computer.'
    , '5461': 'Low,	PAStore Engine failed to apply local registry storage IPsec policy on the computer.'
    , '5462': 'Low,	PAStore Engine failed to apply some rules of the active IPsec policy on the computer. Use the IP '
              'Security Monitor snap-in to diagnose the problem. '
    , '5463': 'Low,	PAStore Engine polled for changes to the active IPsec policy and detected no changes.'
    , '5464': 'Low,	PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them '
              'to IPsec Services. '
    , '5465': 'Low,	PAStore Engine received a control for forced reloading of IPsec policy and processed the control '
              'successfully. '
    ,  '5466': 'Low,	PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active '
              'Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead. '
              'Any changes made to the Active Directory IPsec policy since the last poll could not be applied. '
    , '5467': 'Low,	PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active '
              'Directory can be reached, and found no changes to the policy. The cached copy of the Active Directory '
              'IPsec policy is no longer being used. '
    , '5468': 'Low,	PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active '
              'Directory can be reached, found changes to the policy, and applied those changes. The cached copy of the'
              ' Active Directory IPsec policy is no longer being used. '
    , '5471': 'Low,	PAStore Engine loaded local storage IPsec policy on the computer.'
    , '5472': 'Low,	PAStore Engine failed to load local storage IPsec policy on the computer.'
    , '5473': 'Low,	PAStore Engine loaded directory storage IPsec policy on the computer.'
    , '5474': 'Low,	PAStore Engine failed to load directory storage IPsec policy on the computer.'
    , '5477': 'Low,	PAStore Engine failed to add quick mode filter.'
    , '5479': 'Low,	IPsec Services has been shut down successfully. The shutdown of IPsec Services can put the '
              'computer at greater risk of network attack or expose the computer to potential security risks. '
    , '5632': 'Low,	A request was made to authenticate to a wireless network'
    , '5633': 'Low,	A request was made to authenticate to a wired .'
    , '5712': 'Low,	A Remote Procedure Call (RPC) was attempted'
    , '5888': 'Low,	An object in the COM+ Catalog was modified.'
    , '5889': 'Low,	An object was deleted from the COM+ Catalog'
    , '5890': 'Low,	An object was added to the COM+ Catalog.'
    , '6008': 'Low,	The previous system shutdown was unexpected'
    , '6144': 'Low,	Security policy in the Group Policy objects has been applied successfully.'
    , '6272': 'Low,	Network Policy Server granted access to a user.'
    , '24577': 'Low,	Encryption of volume started'
    , '24578': 'Low,	Encryption of volume stopped'
    , '24579': 'Low,	Encryption of volume completed'
    , '24580': 'Low,	Decryption of volume started'
    , '24581': 'Low,	Decryption of volume stopped'
    , '24582': 'Low,	Decryption of volume completed'
    , '24583': 'Low,	Conversion worker thread for volume started'
    , '24584': 'Low,	Conversion worker thread for volume temporarily stopped'
    , '24588': 'Low,	The conversion operation on volume %2 encountered a bad sector error. Please validate the data on '
               'this volume '
    , '24595': 'Low,	Volume %2 contains bad clusters. These clusters will be skipped during conversion.'
    , '24621': 'Low,	Initial state check: Rolling volume conversion transaction on %2.'
    , '5049': 'Low,	An IPsec Security Association was deleted.'
    , '5478': 'Low,	IPsec Services has started successfully.'
    , '7036': 'Low , Diagnostic service'
    , '7001': 'Low, A user successfully logged in'
}