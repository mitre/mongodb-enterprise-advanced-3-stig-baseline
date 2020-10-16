  control "V-81909" do
  title "MongoDB must prohibit user installation of logic modules (stored
  procedures, functions, triggers, views, etc.) without explicit privileged
  status."
  desc "Allowing regular users to install software, without explicit
  privileges, creates the risk that untested or potentially malicious software
  will be installed on the system. Explicit privileges (escalated or
  administrative privileges) provide the regular user with explicit capabilities
  and control that exceed the rights of a regular user.

  DBMS functionality and the nature and requirements of databases will vary;
  so while users are not permitted to install unapproved software, there may be
  instances where the organization allows the user to install approved software
  packages such as from an approved software repository. The requirements for
  production servers will be more restrictive than those used for development and
  research.

      MongoDB must enforce software installation by users based upon what types
  of software installations are permitted (e.g., updates and security patches to
  existing software) and what types of installations are prohibited (e.g.,
  software whose pedigree with regard to being potentially malicious is unknown
  or suspect) by the organization).

  In the case of a database management system, this requirement covers stored
  procedures, functions, triggers, views, etc.
  "

  desc "check", "If MongoDB supports only software development, experimentation,
  and/or developer-level testing (that is, excluding production systems,
  integration testing, stress testing, and user acceptance testing), this is not
  a finding.

  Review the MongoDB security settings with respect to non-administrative users'
  ability to create, alter, or replace functions or views.

  These MongoDB commands can help with showing existing roles and permissions of
  users of the databases.

  db.getRoles( { rolesInfo: 1, showPrivileges:true, showBuiltinRoles: true })

  If any such permissions exist and are not documented and approved, this is a
  finding."
  desc "fix", "Revoke any roles with unnecessary privileges to privileged
  functionality by executing the revoke command.

  Revoke any unnecessary privileges from any roles by executing the revoke
  command.

  Create, as needed, new role(s) with associated privileges."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000378-DB-000365"
  tag "gid": "V-81909"
  tag "rid": "SV-96623r1_rule"
  tag "stig_id": "MD3X-00-000650"
  tag "fix_id": "F-88759r1_fix"
  tag "cci": ["CCI-001812"]
  tag "nist": ["CM-11 (2)", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": false

  a = []
  dbnames = []

  if input('mongo_use_pki') == 'true'
    get_databases = command("sudo mongo --ssl --sslPEMKeyFile #{input('mongod_client_pem')} --sslCAFile #{input('mongod_cafile')} \
    --authenticationDatabase '$external' --authenticationMechanism MONGODB-X509 --host #{input('mongod_hostname')} \
    --quiet --eval 'JSON.stringify(db.adminCommand( { listDatabases: 1, nameOnly: true}))'").stdout.strip.split('"name":"')
  else
    get_databases = command("mongo -u '#{input('user')}' -p '#{input('password')}' \
    --quiet --eval 'JSON.stringify(db.adminCommand( { listDatabases: 1, nameOnly: true}))'").stdout.strip.split('"name":"')
  end 

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

  if dbnames.empty?
    describe 'There are no mongo databases, therefore for this control is NA' do
      skip 'There are no mongo databases, therefore for this control is NA'
    end
  end

  if !dbnames.empty?
    dbnames.each do |dbs|

      if input('mongo_use_pki') == 'true'
        users = command("sudo mongo admin --ssl --sslPEMKeyFile #{input('mongod_client_pem')} --sslCAFile #{input('mongod_cafile')} \
        --authenticationDatabase '$external' --authenticationMechanism MONGODB-X509 --host #{input('mongod_hostname')} \
        --quiet --eval 'db.system.users.find({db: \"#{dbs}\"}, {user: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
      else
        users = command("mongo admin -u '#{input('user')}' -p '#{input('password')}' \
        --quiet --eval 'db.system.users.find({db: \"#{dbs}\"}, {user: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
      end 
      users.each do |t|

        loc_colon = t.index(':')

        user = t[loc_colon+3..-1]

        loc_quote = user.index('"')

        username = user[0, loc_quote]

        if input('mongo_use_pki') == 'true'
          getdb_roles = command("mongo admin --ssl --sslPEMKeyFile #{input('mongod_client_pem')} --sslCAFile #{input('mongod_cafile')} \
          --authenticationDatabase '$external' --authenticationMechanism MONGODB-X509 --host #{input('mongod_hostname')} \
          --quiet --eval 'db.system.users.find({db: \"#{dbs}\", user: \"#{username}\"}, {roles: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
        else
          getdb_roles = command("mongo admin -u '#{input('user')}' -p '#{input('password')}' \
          --quiet --eval 'db.system.users.find({db: \"#{dbs}\", user: \"#{username}\"}, {roles: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
        end 

        getdb_roles.each do |r|
          remove_role = r.index('[')
          rr = r[remove_role..-1]

          allowed_role = username
          describe "The database role for user: #{username}" do
            subject { rr }
            it { should be_in input("#{allowed_role}_allowed_role") }
          end
        end
      end
    end
  end
end
