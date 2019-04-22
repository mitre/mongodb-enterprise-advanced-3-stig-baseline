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
  impact 0.5
  tag "gtitle": "SRG-APP-000180-DB-000115"
  tag "satisfies": ["SRG-APP-000180-DB-000115", "SRG-APP-000211-DB-000122",
  "SRG-APP-000211-DB-000124"]
  tag "gid": "V-81877"
  tag "rid": "SV-96591r1_rule"
  tag "stig_id": "MD3X-00-000390"
  tag "fix_id": "F-88727r2_fix"
  tag "cci": ["CCI-000804", "CCI-001082", "CCI-001084"]
  tag "nist": ['IA-8', 'Rev_4']
  tag "nist": ['SC-2', 'Rev_4']
  tag "nist": ['SC-3', 'Rev_4']
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
  tag "check": "MongoDB grants access to data and commands through role-based
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
  tag "fix": "Prereq: To view a user's roles, must have the \"viewUser\"
  privilege.

  Connect to MongoDB.

  For each database, identify the user's roles for the database.

  use <database>
  db.getUser(\"[username]\")

  The server will return a document with the user's roles.

  To revoke a user's role from a database use the db.revokeRolesFromUser() method.

  To grant a role to a user use the db.grantRolesToUser() method."
  a = []
  b = []
  testing = []
  dbnames = []
  mongo_user = attribute('user')
  mongo_password = attribute('password')
  dbrole = []
  
  get_databases = command("mongo -u '#{mongo_user}' -p '#{mongo_password}' --quiet --eval 'JSON.stringify(db.adminCommand( { listDatabases: 1, nameOnly: true}))'").stdout.strip.split('"name":"')
  
  get_databases.each do |db|
    if db.include? "databases"
    
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

      users = command("mongo admin -u '#{mongo_user}' -p '#{mongo_password}' --quiet --eval 'db.system.users.find({db: \"#{dbs}\"}, {user: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
        users.each do |t|
     
          loc_colon = t.index(':')

          user = t[loc_colon+3..-1]
      
          loc_quote = user.index('"')
       
          username = user[0,loc_quote]

          getdb_roles = command("mongo admin -u '#{mongo_user}' -p '#{mongo_password}' --quiet --eval 'db.system.users.find({db: \"#{dbs}\", user: \"#{username}\"}, {roles: 1, _id: false, distinct: 1})'").stdout.strip.split("\n")
    
          getdb_roles.each do |r|
            remove_role = r.index('[')
            rr = r[remove_role..-1]

          allowed_role = username
          describe "The database role for user: #{username}" do
            subject {rr}
            it {should be_in attribute("#{allowed_role}_allowed_role")}
          end
        end
      end
    end
  end
end

