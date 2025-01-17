control 'V-81865' do
  title "If DBMS authentication, using passwords, is employed, MongoDB must
  enforce the DoD standards for password complexity and lifetime."
  desc "OS/enterprise authentication and identification must be used
  (SQL2-00-023600). Native DBMS authentication may be used only when
  circumstances make it unavoidable; and must be documented and AO-approved.

      The DoD standard for authentication is DoD-approved PKI certificates.
  Authentication based on User ID and Password may be used only when it is not
  possible to employ a PKI certificate, and requires AO approval.

      In such cases, the DoD standards for password complexity and lifetime must
  be implemented. DBMS products that can inherit the rules for these from the
  operating system or access control program (e.g., Microsoft Active Directory)
  must be configured to do so. For other DBMSs, the rules must be enforced using
  available configuration parameters or custom code.
  "

  desc 'check', "If MongoDB is using Native LDAP authentication where the LDAP
  server is configured to enforce password complexity and lifetime, this is not a
  finding.

  If MongoDB is using Kerberos authentication where Kerberos is configured to
  enforce password complexity and lifetime, this is not a finding.

  If MongoDB is configured for SCRAM-SHA1, MONGODB-CR, LDAP Proxy authentication,
  this is a finding.

  See: https://docs.mongodb.com/v3.4/core/authentication/#authentication-methods"
  desc 'fix', "Either configure MongoDB for Native LDAP authentication where
  LDAP is configured to enforce password complexity and lifetime.
  OR
  Configure MongoDB Kerberos authentication where Kerberos is configured to
  enforce password complexity and lifetime."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000164-DB-000401'
  tag "gid": 'V-81865'
  tag "rid": 'SV-96579r1_rule'
  tag "stig_id": 'MD3X-00-000320'
  tag "fix_id": 'F-88715r1_fix'
  tag "cci": ['CCI-000192']
  tag "nist": ['IA-5 (1) (a)']
  tag "documentable": false
  tag "severity_override_guidance": false

  if processes('mongod').commands.join =~ /GSSAPI|PLAIN/
    describe 'Manually verify MongoDB server enforces the DoD standards for password complexity and lifetime' do
      skip
    end
  else
    describe 'MongoDB Server should be configured with a non-default authentication Mechanism' do
      subject { processes('mongod') }
      its('commands.join') { should match /authenticationMechanisms/ }
    end

    describe 'MongoDB Server authentication Mechanism' do
      subject { processes('mongod').commands.join }
      it { should_not match /SCRAM-SHA|MONGODB-CR/ }
    end
  end
end
