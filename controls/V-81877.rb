  control "V-81877" do
  title "MongoDB must uniquely identify and authenticate non-organizational
  users (or processes acting on behalf of non-organizational users)."
  desc  "Non-organizational users include all information system users other
  than organizational users, which include organizational employees or
  individuals the organization deems to have equivalent status of employees
  (e.g., contractors, guest researchers, individuals from allied nations).

      Non-organizational users must be uniquely identified and authenticated for
  all accesses other than those accesses explicitly identified and documented by
  the organization when related to the use of anonymous access, such as accessing
  a web server.

      Accordingly, a risk assessment is used in determining the authentication
  needs of the organization.

      Scalability, practicality, and security are simultaneously considered in
  balancing the need to ensure ease of use for access to federal information and
  information systems with the need to protect and adequately mitigate risk to
  organizational operations, organizational assets, individuals, other
  organizations, and the Nation.
  "
  
  desc "check", "MongoDB grants access to data and commands through role-based
  authorization and provides built-in roles that provide the different levels of
  access commonly needed in a database system. You can additionally create
  user-defined roles.

  Check a user's role to ensure correct privileges for the function:

  Prereq: To view a user's roles, you must have the \"viewUser\" privilege.

  Connect to MongoDB.

  For each database in the system, identify the user's roles for the database:

  use <database>
  db.getUser(\"[username]\")

  The server will return a document with the user's roles.

  View a role's privileges:

  Prereq: To view a user's roles, you must have the \"viewUser\" privilege.

  For each database, identify the privileges granted by a role:

  use <database>
  db.getRole( \"read\", { showPrivileges: true } )

  The server will return a document with the \"privileges\" and
  \"inheritedPrivileges\" arrays. The \"privileges returned document lists the
  privileges directly specified by the role and excludes those privileges
  inherited from other roles. The \"inheritedPrivileges\" returned document lists
  all privileges granted by this role, both directly specified and inherited. If
  the role does not inherit from other roles, the two fields are the same.

  If a user has a role with inappropriate privileges, this is a finding."
  desc "fix", "Prereq: To view a user's roles, must have the \"viewUser\"
  privilege.

  Connect to MongoDB.

  For each database, identify the user's roles for the database.

  use <database>
  db.getUser(\"[username]\")

  The server will return a document with the user's roles.

  To revoke a user's role from a database use the db.revokeRolesFromUser() method.

  To grant a role to a user use the db.grantRolesToUser() method."
 
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000180-DB-000115"
  tag "satisfies": ["SRG-APP-000180-DB-000115", "SRG-APP-000211-DB-000122",
                    "SRG-APP-000211-DB-000124"]
  tag "gid": "V-81877"
  tag "rid": "SV-96591r1_rule"
  tag "stig_id": "MD3X-00-000390"
  tag "fix_id": "F-88727r2_fix"
  tag "cci": ["CCI-000804", "CCI-001082", "CCI-001084"]
  tag "nist": ["IA-8", "SC-2", "SC-3"]
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

  if get_databases.grep(/error/).empty? == false
    describe 'Verify the correct credentials or a valid client certificate is used to execute the query.' do
      skip 'Verify the correct credentials or a valid client certificate is used to execute the query.'
    end
  else
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
            getdb_roles = command("sudo mongo admin --ssl --sslPEMKeyFile #{input('mongod_pem')} --sslCAFile #{input('mongod_cafile')}  \
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
end
