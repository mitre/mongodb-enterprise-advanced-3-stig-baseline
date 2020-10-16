  control "V-81845" do
  title "MongoDB must enforce approved authorizations for logical access to
  information and system resources in accordance with applicable access control
  policies."
  desc "MongoDB must enforce approved authorizations for logical access to
  information and system resources in accordance with applicable access control
  policies."
  
  desc "check", "Review the system documentation to determine the required
  levels of protection for DBMS server securables by type of login. Review the
  permissions actually in place on the server. If the actual permissions do not
  match the documented requirements, this is a finding.

  MongoDB commands to view roles in a particular database:

  db.getRoles(
  {
  rolesInfo: 1,
  showPrivileges:true,
  showBuiltinRoles: true
  }
  )"
  desc "fix", "Use createRole(), updateRole(), dropRole(), grantRole()
  statements to add and remove permissions on server-level securables, bringing
  them into line with the documented requirements.

  MongoDB commands for role management can be found here:
  https://docs.mongodb.com/v3.4/reference/method/js-role-management/"

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000033-DB-000084"
  tag "gid": "V-81845"
  tag "rid": "SV-96559r1_rule"
  tag "stig_id": "MD3X-00-000020"
  tag "fix_id": "F-88695r2_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": false
  
  a = []
  dbnames = []

  if input('mongo_use_pki') == 'true'
    get_databases = command("sudo mongo --ssl --sslPEMKeyFile #{input('mongod_client_pem')} --sslCAFile #{input('mongod_cafile')} \
    --authenticationDatabase '$external' --authenticationMechanism MONGODB-X509 --host #{input('mongod_hostname')} \
    --quiet --eval 'JSON.stringify(db.adminCommand( { listDatabases: 1, nameOnly: true}))'").stdout.strip.split('"name":"')
  else
    get_databases = command("mongo -u '#{input('user')}' -p '#{input('password')}' --quiet --eval \
    'JSON.stringify(db.adminCommand( { listDatabases: 1, nameOnly: true}))'").stdout.strip.split('"name":"')
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
        users = command("mongo admin -u '#{input('user')}' -p '#{input('password')}' --quiet --eval \
        'db.system.users.find({db: \"#{dbs}\"}, {user: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
      end 

      users.each do |t|

        loc_colon = t.index(':')

        user = t[loc_colon+3..-1]

        loc_quote = user.index('"')

        username = user[0, loc_quote]

        if input('mongo_use_pki') == 'true'
          getdb_roles = command("sudo mongo admin --ssl --sslPEMKeyFile #{input('mongod_client_pem')} --sslCAFile #{input('mongod_cafile')} \
          --authenticationDatabase '$external' --authenticationMechanism MONGODB-X509 --host #{input('mongod_hostname')} \
          --quiet --eval 'db.system.users.find({db: \"#{dbs}\", user: \"#{username}\"}, {roles: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
        else
          getdb_roles = command("mongo admin -u '#{input('user')}' -p '#{input('password')}' --quiet --eval \
          'db.system.users.find({db: \"#{dbs}\", user: \"#{username}\"}, {roles: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
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
