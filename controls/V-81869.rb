control 'V-81869' do
  title "If passwords are used for authentication, MongoDB must transmit only
  encrypted representations of passwords."
  desc "The DoD standard for authentication is DoD-approved PKI certificates.
  Authentication based on User ID and Password may be used only when it is
  not possible to employ a PKI certificate, and requires AO approval.

    In such cases, passwords need to be protected at all times, and encryption
  is the standard method for protecting passwords during transmission.

    DBMS passwords sent in clear text format across the network are vulnerable
  to discovery by unauthorized users. Disclosure of passwords may easily lead to
  unauthorized access to the database.
  "

  desc 'check', "In the MongoDB database configuration file (default location:
/etc/mongod.conf), review the following parameters:

net:
ssl:
mode: requireSSL
PEMKeyFile: /etc/ssl/mongodb.pem
CAFile: /etc/ssl/mongodbca.pem

If the \"CAFile\" parameter is not present, this is a finding.

If the \"allowInvalidCertificates\" parameter is found, this is a finding.

net:
ssl:
allowInvalidCertificates: true"
  desc 'fix', "In the MongoDB database configuration file (default location:
  /etc/mongod.conf) ensure the following parameters following parameter are set
  and configured correctly:

  net:
  ssl:
  mode: requireSSL
  PEMKeyFile: /etc/ssl/mongodb.pem
  CAFile: /etc/ssl/mongodbca.pem

  Remove any occurrence of the \"allowInvalidCertificates\" parameter:

  net:
  ssl:
  allowInvalidCertificates: true

  Stop/start (restart) the mongod or mongos instance using this configuration."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000172-DB-000075'
  tag "satisfies": %w(SRG-APP-000172-DB-000075 SRG-APP-000175-DB-000067)
  tag "gid": 'V-81869'
  tag "rid": 'SV-96583r1_rule'
  tag "stig_id": 'MD3X-00-000340'
  tag "fix_id": 'F-88719r1_fix'
  tag "cci": %w(CCI-000185 CCI-000197)
  tag "nist": ['IA-5 (2) (a)', 'IA-5 (1) (c)']
  tag "documentable": false
  tag "severity_override_guidance": false

  describe.one do
    describe yaml(input('mongod_conf')) do
      its(%w(net ssl allowInvalidCertificates)) { should be nil }
    end
    describe yaml(input('mongod_conf')) do
      its(%w(net ssl allowInvalidCertificates)) { should be false }
    end
  end
  describe yaml(input('mongod_conf')) do
    its(%w(net ssl mode)) { should cmp 'requireSSL' }
  end
  describe yaml(input('mongod_conf')) do
    its(%w(net ssl PEMKeyFile)) { should cmp '/etc/ssl/mongodb.pem' }
  end
  describe yaml(input('mongod_conf')) do
    its(%w(net ssl CAFile)) { should cmp '/etc/ssl/mongodbca.pem' }
  end
end
