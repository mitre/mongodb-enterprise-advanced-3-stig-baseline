control "V-81915" do
  title "MongoDB must prohibit the use of cached authenticators after an
  organization-defined time period."
  desc "If cached authentication information is out-of-date, the validity of
  the authentication information may be questionable."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000400-DB-000367"
  tag "gid": "V-81915"
  tag "rid": "SV-96629r1_rule"
  tag "stig_id": "MD3X-00-000710"
  tag "fix_id": "F-88765r1_fix"
  tag "cci": ["CCI-002007"]
  tag "nist": ["IA-5", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": false

  desc "check", "If MongoDB is configured to authenticate using SASL and
  LDAP/Active Directory check the saslauthd command line options in the system
  boot script that starts saslauthd (the location will be dependent on the
  specific Linux operating system and boot script layout and naming conventions).
  If the \"-t\" option is not set for the \"saslauthd\" process in the system
  boot script, this is a finding.
  If any mongos process is running (a MongoDB shared cluster) the
  \"userCacheInvalidationIntervalSecs\" option can be used to specify the cache
  timeout.
  The default is \"30\" seconds and the minimum is \"1\" second.
  
  In the saslauthd file, if MECH is not equal to ldap, this is a finding.
  
  "
  desc "fix", "If MongoDB is configured to authenticate using SASL and
  LDAP/Active Directory modify and restart the saslauthd command line options in
  the system boot script and set the \"-t\" option to the appropriate timeout in
  seconds.
  From the Linux Command line (with root/sudo privs) run the following command to
  restart the saslauthd process after making the change for the \"-t\" parameter:
  systemctl restart saslauthd
  If any mongos process is running (a MongoDB shared cluster) the
  \"userCacheInvalidationIntervalSecs\" option to adjust the timeout in seconds
  can be changed from the default \"30\" seconds.
  This is accomplished by modifying the mongos configuration file (default
  location: /etc/mongod.conf) and then restarting mongos.
  
  In the mongod.conf, set timeoutMS to 1000.
  security:
  ldap:
  timeoutMS: 1000
  
  In the saslauthd file ( default location: /etc/sysconfig/saslauthd ), set FLAGS to -t 900
  FLAGS= -t 900
  
  Also, in the saslauthd file, set MECH to ldap
  MECH=ldap "

  describe ini(input('saslauthd')) do
    its(%w{MECH}) {should cmp 'ldap'}
  end
  describe ini(input('saslauthd')) do
    its('FLAGS') {should eq '-t 900'}
  end
  describe yaml(input('mongod_conf')) do
    its(%w{security authorization}) { should cmp 'enabled'}
  end
  describe yaml(input('mongod_conf')) do
    its(%w{security ldap timeoutMS}) { should cmp '10000' }
  end 
end