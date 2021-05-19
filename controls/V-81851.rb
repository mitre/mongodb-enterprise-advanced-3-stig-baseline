  control "V-81851" do
  title 'MongoDB must protect its audit features from unauthorized access.'
  desc  "Protecting audit data also includes identifying and protecting the
  tools used to view and manipulate log data.

      Depending upon the log format and application, system and application log
  tools may provide the only means to manipulate and manage application and
  system log data. It is, therefore, imperative that access to audit tools be
  controlled and protected from unauthorized access.

      Applications providing tools to interface with audit data will leverage
  user permissions and roles identifying the user accessing the tools and the
  corresponding rights the user enjoys in order make access decisions regarding
  the access to audit tools.

      Audit tools include, but are not limited to, OS-provided audit tools,
  vendor-provided audit tools, and open source audit tools needed to successfully
  view and manipulate audit information system activity and records.

      If an attacker were to gain access to audit tools, he could analyze audit
  logs for system weaknesses or weaknesses in the auditing itself. An attacker
  could also manipulate logs to hide evidence of malicious activity.
  "

  desc "check", "Verify User ownership, Group ownership, and permissions on the
  “<MongoDB configuration file>\":

  (default name and location is '/etc/mongod.conf')

  (The name and location for the MongoDB configuration file will vary according
  to local circumstances.)

  Using the default name and location the command would be:

  > ls –ald /etc/mongod.conf

  If the User owner is not \"mongod\", this is a finding.

  If the Group owner is not \"mongod\", this is a finding.

  If the filename is more permissive than \"700\", this is a finding."
  desc "fix", "Run these commands:

  \"chown mongod <MongoDB configuration file>\"
  \"chgrp mongod <MongoDB configuration file>\"
  \"chmod 700 <<MongoDB configuration file>\"

  (The name and location for the MongoDB configuration file will vary according
  to local circumstances. The default name and location is '/etc/mongod.conf'.)

  Using the default name and location the commands would be:

  > chown mongod /etc/mongod.conf
  > chgrp mongod /etc/mongod.conf
  > chmod 700 /etc/mongod.conf"

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000121-DB-000202"
  tag "satisfies": ["SRG-APP-000121-DB-000202", "SRG-APP-000122-DB-000203",
                    "SRG-APP-000122-DB-000204"]
  tag "gid": "V-81851"
  tag "rid": "SV-96565r1_rule"
  tag "stig_id": "MD3X-00-000220"
  tag "fix_id": "F-88701r1_fix"
  tag "cci": ["CCI-001493", "CCI-001494", "CCI-001495"]
  tag "nist": ["AU-9"]
  tag "documentable": false
  tag "severity_override_guidance": false

  mongodb_service_account = input('mongodb_service_account')
  mongodb_service_group = input('mongodb_service_group')
  
  describe file(input('mongod_conf')) do
    it { should_not be_more_permissive_than('0700') } 
    its('owner') { should be_in mongodb_service_account }
    its('group') { should be_in mongodb_service_group }
  end
end
