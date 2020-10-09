control "V-81919" do
  title "MongoDB must implement cryptographic mechanisms to prevent
  unauthorized modification of organization-defined information at rest (to
  include, at a minimum, PII and classified information) on organization-defined
  information system components."
  desc "DBMSs handling data requiring \"data at rest\" protections must employ
  cryptographic mechanisms to prevent unauthorized disclosure and modification of
  the information at rest. These cryptographic mechanisms may be native to
  MongoDB or implemented via additional software or operating system/file system
  settings, as appropriate to the situation.

      Selection of a cryptographic mechanism is based on the need to protect the
  integrity of organizational information. The strength of the mechanism is
  commensurate with the security category and/or classification of the
  information. Organizations have the flexibility to either encrypt all
  information on storage devices (i.e., full disk encryption) or encrypt specific
  data structures (e.g., files, records, or fields).

      The decision whether and what to encrypt rests with the data owner and is
  also influenced by the physical measures taken to secure the equipment and
  media on which the information resides.

  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000428-DB-000386"
  tag "satisfies": ["SRG-APP-000428-DB-000386", "SRG-APP-000429-DB-000387"]
  tag "gid": "V-81919"
  tag "rid": "SV-96633r1_rule"
  tag "stig_id": "MD3X-00-000740"
  tag "fix_id": "F-88769r1_fix"
  tag "cci": ["CCI-002475"]
  tag "nist": ["SC-28", "Rev_4"]
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
  desc "check", "Review the documentation and/or specification for the
  organization-defined information.

  If any data is PII, classified or is deemed by the organization to be encrypted
  at rest, this is a finding.

  Verify the mongod command line contain the following options:

  --enableEncryption
  --kmipServerName <KMIP Server HostName>
  --kmipPort <KMIP server port>
  --kmipServerCAFile ca.pem
  --kmipClientCertificateFile client.pem

  If these above options are not part of the mongod command line, this is a
  finding.

  Items in the <> above and starting with kmip* are specific to the KMIP
  appliance and need to be set according to the KMIP appliance configuration."
  desc "fix", "Configure MongoDB to use the Encrypted Storage Engine and a KMIP
  appliance as documented here:

  https://docs.mongodb.com/v3.4/core/security-encryption-at-rest/
  https://docs.mongodb.com/v3.4/tutorial/configure-encryption/"

  describe yaml(input('mongod_conf')) do
    its(['security' , 'kmip', 'serverName']) { should_not be_nil }
  end

  describe yaml(input('mongod_conf')) do
    its(['security' , 'kmip', 'port']) { should_not be_nil }
  end

  describe yaml(input('mongod_conf')) do
    its(['security' , 'kmip', 'serverCAFile']) { should_not be_nil }
  end

  describe yaml(input('mongod_conf')) do
    its(['security' , 'kmip', 'clientCertificateFile']) { should_not be_nil }
  end

  describe yaml(input('mongod_conf')) do
    its(['security' , 'enableEncryption']) { should cmp 'true' }
  end
end
