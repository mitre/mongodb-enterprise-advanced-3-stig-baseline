control 'V-81863' do
  title "MongoDB must uniquely identify and authenticate organizational users
  (or processes acting on behalf of organizational users)."
  desc "To assure accountability and prevent unauthenticated access,
  organizational users must be identified and authenticated to prevent potential
  misuse and compromise of the system.

      Organizational users include organizational employees or individuals the
  organization deems to have equivalent status of employees (e.g., contractors).
  Organizational users (and any processes acting on behalf of users) must be
  uniquely identified and authenticated for all accesses, except the following:

      (i) Accesses explicitly identified and documented by the organization.
  Organizations document specific user actions that can be performed on the
  information system without identification or authentication; and
      (ii) Accesses that occur through authorized use of group authenticators
  without individual authentication. Organizations may require unique
  identification of individuals using shared accounts, for detailed
  accountability of individual activity.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000148-DB-000103"
  tag "gid": "V-81863"
  tag "rid": "SV-96577r1_rule"
  tag "stig_id": "MD3X-00-000310"
  tag "fix_id": "F-88713r1_fix"
  tag "cci": ["CCI-000764"]
  tag "nist": ["IA-2", "Rev_4"]
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
  desc "check": "To view another user’s information, you must have the
  \"viewUser\" action on the other user’s database.

  For each database in the system, run the following command:

  db.getUsers()

  Ensure each user identified is a member of an appropriate organization that can
  access the database.

  If a user is found not be a member or an appropriate organization that can
  access the database, this is a finding.

  Verify that the MongoDB configuration file (default location: /etc/mongod.conf)
  contains the following:

  security:
  authorization: \"enabled\"

  If this parameter is not present, this is a finding."
  desc "fix": "Prereq: To drop a user from a database, must have the
  \"dropUser\" action on the database.

  For any user not a member of an appropriate organization and has access to a
  database in the system run the following command:

  // Change to the appropriate database
  use <database>
  db.dropUser(<username>, {w: \"majority\", wtimeout: 5000}

  If the MongoDB configuration file (default location: /etc/mongod.conf) does not
  contain

  security: authorization: \"enabled\"

  Edit the MongoDB configuration file, add these parameters, stop/start (restart)
  any mongod or mongos process using this MongoDB configuration file."

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
      allowed_db = dbs
      describe "Database users of database: #{dbs}" do
        subject { username }
        it { should be_in attribute("#{allowed_db}_db_users") }
      end
    end
  end
  describe yaml(input('mongod_conf')) do
    its(%w{security authorization}) { should cmp 'enabled' }
  end
end
