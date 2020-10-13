control "V-81865" do
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
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000164-DB-000401"
  tag "gid": "V-81865"
  tag "rid": "SV-96579r1_rule"
  tag "stig_id": "MD3X-00-000320"
  tag "fix_id": "F-88715r1_fix"
  tag "cci": ["CCI-000192"]
  tag "nist": ["IA-5", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": false
  
  desc "check", "If MongoDB is using Native LDAP authentication where the LDAP
  server is configured to enforce password complexity and lifetime, this is not a
  finding.

  If MongoDB is using Kerberos authentication where Kerberos is configured to
  enforce password complexity and lifetime, this is not a finding.

  If MongoDB is configured for SCRAM-SHA1, MONGODB-CR, LDAP Proxy authentication,
  this is a finding.

  See: https://docs.mongodb.com/v3.4/core/authentication/#authentication-methods"
  desc "fix", "Either configure MongoDB for Native LDAP authentication where
  LDAP is configured to enforce password complexity and lifetime.
  OR
  Configure MongoDB Kerberos authentication where Kerberos is configured to
  enforce password complexity and lifetime."

  a = []
  dbnames = []
  mongo_user = input('user')
  mongo_password = input('password')

  get_databases = command("mongo -u '#{mongo_user}' -p '#{mongo_password}' --quiet --eval 'JSON.stringify(db.adminCommand( { listDatabases: 1, nameOnly: true}))'").stdout.strip.split('"name":"')

  get_databases.each do |db|
    if db.include? 'databases'

      a.push(db)
      get_databases.delete(db)
    end
  end

  get_databases.each do |db|

    loc_colon = db.index('"')
    names = db[0, loc_colon]
    dbnames.push(names)
  end

  dbnames.each do |dbs|
    users = command("mongo admin -u '#{mongo_user}' -p '#{mongo_password}' --quiet --eval 'db.system.users.find({db: \"#{dbs}\"}, {user: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
    users.each do |t|

      loc_colon = t.index(':')

      user = t[loc_colon+3..-1]

      loc_quote = user.index('"')

      username = user[0, loc_quote]

      getdb_roles = command("mongo admin -u '#{mongo_user}' -p '#{mongo_password}' --quiet --eval 'db.system.users.find({db: \"#{dbs}\", user: \"#{username}\"},{credentials: 1, _id: false})'").stdout.strip.split("\n")

      getdb_roles.each do |r|

        describe "The credential meachanim used for user: #{username}" do
          subject { r }
          it { should_not include 'SCRAM-SHA1' }
        end

      end
    end
  end
  describe yaml(input('mongod_conf')) do
    its(%w{security ldap}) { should be nil }
  end

end
