control 'V-81843' do
  title "MongoDB must integrate with an organization-level
  authentication/access mechanism providing account management and automation for
  all users, groups, roles, and any other principals."
  desc "MongoDB must integrate with an organization-level
  authentication/access mechanism providing account management and automation for
  all users, groups, roles, and any other principals."

  desc 'check', "Verify that the MongoDB configuration file (default location:
  /etc/mongod.conf) contains the following:

  security:
  authorization: \"enabled\"

  If this parameter is not present, this is a finding."
  desc 'fix', "Edit the MongoDB configuration file (default location:
  /etc/mongod.conf) to include the following:

  security:
  authorization: \"enabled\"

  This will enable SCRAM-SHA-1 authentication (default).

  Instruction on configuring the default authentication is provided here:

  https://docs.mongodb.com/v3.4/tutorial/enable-authentication/

  The high-level steps described by the above will require the following:

  1. Start MongoDB without access control.
  2. Connect to the instance.
  3. Create the user administrator.
  4. Restart the MongoDB instance with access control.
  5. Connect and authenticate as the user administrator.
  6. Create additional users as needed for your deployment."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000023-DB-000001'
  tag "gid": 'V-81843'
  tag "rid": 'SV-96557r1_rule'
  tag "stig_id": 'MD3X-00-000010'
  tag "fix_id": 'F-88693r1_fix'
  tag "cci": ['CCI-000015']
  tag "nist": ['AC-2 (1)']
  tag "documentable": false
  tag "severity_override_guidance": false

  describe yaml(input('mongod_conf')) do
    its(%w(security authorization)) { should cmp 'enabled' }
  end
end
