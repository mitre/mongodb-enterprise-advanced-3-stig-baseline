control "V-81871" do
  title "MongoDB must enforce authorized access to all PKI private keys
  stored/utilized by MongoDB."
  desc "The DoD standard for authentication is DoD-approved PKI certificates.
  PKI certificate-based authentication is performed by requiring the certificate
  holder to cryptographically prove possession of the corresponding private key.

      If the private key is stolen, an attacker can use the private key(s) to
  impersonate the certificate holder. In cases where MongoDB-stored private keys
  are used to authenticate MongoDB to the system’s clients, loss of the
  corresponding private keys would allow an attacker to successfully perform
  undetected man in the middle attacks against MongoDB system and its clients.

      Both the holder of a digital certificate and the issuing authority must
  take careful measures to protect the corresponding private key. Private keys
  should always be generated and protected in FIPS 140-2 validated cryptographic
  modules.

      All access to the private key(s) of MongoDB must be restricted to
  authorized and authenticated users. If unauthorized users have access to one or
  more of MongoDB's private keys, an attacker could gain access to the key(s) and
  use them to impersonate the database on the network or otherwise perform
  unauthorized actions.
  "
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000176-DB-000068"
  tag "gid": "V-81871"
  tag "rid": "SV-96585r1_rule"
  tag "stig_id": "MD3X-00-000360"
  tag "fix_id": "F-88721r1_fix"
  tag "cci": ["CCI-000186"]
  tag "nist": ["IA-5 (2) (b)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "In the MongoDB database configuration file (default location:
  /etc/mongod.conf), review the following parameters:

  net:
  ssl:
  mode: requireSSL
  PEMKeyFile: /etc/ssl/mongodb.pem
  CAFile: /etc/ssl/mongodbca.pem

  Verify ownership, group ownership, and permissions on the file given for
  PEMKeyFile (default 'mongodb.pem').

  Run following command and review its output:
  ls -al /etc/mongod.conf

  typical output:
  -rw------- 1 mongod mongod 566 Apr 26 20:20 /etc/mongod.conf

  If the user owner is not \"mongod\", this is a finding.

  If the group owner is not \"mongod\", this is a finding.

  If the file is more permissive than \"600\", this is a finding.

  Verify ownership, group ownership, and permissions on the file given for CAFile
  (default 'ca.pem').

  If the user owner is not \"mongod\", this is a finding.

  If the group owner is not \"mongod\", this is a finding.

  IF the file is more permissive than \"600\", this is a finding."
  desc "fix", "Run these commands:
  \"chown mongod:mongod /etc/ssl/mongodb.pem\"
  \"chmod 600 /etc/ssl/mongodb.pem\"
  \"chown mongod:mongod /etc/ssl/mongodbca.pem\"
  \"chmod 600 /etc/ssl/mongodbca.pem\""

  describe file('/etc/ssl/mongodb.pem') do
    its('mode') { should cmp <= 0600 }
    its('owner') { should be_in input('mongodb_service_account') }
    its('group') { should be_in input('mongodb_service_group') }
  end

  describe file('/etc/ssl/mongodbca.pem') do
    its('mode') { should cmp <= 0600 }
    its('owner') { should be_in input('mongodb_service_account') }
    its('group') { should be_in input('mongodb_service_group') }
  end
end
