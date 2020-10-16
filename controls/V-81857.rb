  control "V-81857" do
  title "The role(s)/group(s) used to modify database structure (including but
  not necessarily limited to tables, indexes, storage, etc.) and logic modules
  (stored procedures, functions, triggers, links to software external to MongoDB,
  etc.) must be restricted to authorized users."
  desc  "If MongoDB were to allow any user to make changes to database
  structure or logic, then those changes might be implemented without undergoing
  the appropriate testing and approvals that are part of a robust change
  management process.

      Accordingly, only qualified and authorized individuals must be allowed to
  obtain access to information system components for purposes of initiating
  changes, including upgrades and modifications.

      Unmanaged changes that occur to the database software libraries or
  configuration can lead to unauthorized or compromised installations.
  "
  
  desc "check", "Run the following command to get the roles from a MongoDB
  database.

  For each database in MongoDB:

  use <database>
  db.getRoles(
  {
  rolesInfo: 1,
  showPrivileges:true,
  showBuiltinRoles: true
  }
  )

  Run the following command to the roles assigned to users:

  use admin
  db.system.users.find()

  Analyze the output and if any roles or users have unauthorized access, this is
  a finding."
  desc "fix", "Use the following commands to remove unauthorized access to a
  MongoDB database.

  db.revokePrivilegesFromRole()
  db. revokeRolesFromUser()

  MongoDB commands for role management can be found here:
  https://docs.mongodb.com/v3.4/reference/method/js-role-management/"

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000362"
  tag "gid": "V-81857"
  tag "rid": "SV-96571r1_rule"
  tag "stig_id": "MD3X-00-000270"
  tag "fix_id": "F-88707r1_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
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
          getdb_roles = command("sudo mongo admin --ssl --sslPEMKeyFile #{input('mongod_client_pem')} --sslCAFile #{input('mongod_cafile')} \
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
