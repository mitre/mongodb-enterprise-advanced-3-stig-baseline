control 'V-81845' do
  title "MongoDB must enforce approved authorizations for logical access to
  information and system resources in accordance with applicable access control
  policies."
  desc "MongoDB must enforce approved authorizations for logical access to
  information and system resources in accordance with applicable access control
  policies."

  desc 'check', "Review the system documentation to determine the required
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
  desc 'fix', "Use createRole(), updateRole(), dropRole(), grantRole()
  statements to add and remove permissions on server-level securables, bringing
  them into line with the documented requirements.

  MongoDB commands for role management can be found here:
  https://docs.mongodb.com/v3.4/reference/method/js-role-management/"

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000033-DB-000084'
  tag "gid": 'V-81845'
  tag "rid": 'SV-96559r1_rule'
  tag "stig_id": 'MD3X-00-000020'
  tag "fix_id": 'F-88695r2_fix'
  tag "cci": ['CCI-000213']
  tag "nist": ['AC-3']
  tag "documentable": false
  tag "severity_override_guidance": false

  mongo_session = mongo_command(username: input('username'), password: input('password'), host: input('mongod_hostname'), port: input('mongod_port'), ssl: input('ssl'), verify_ssl: input('verify_ssl'), ssl_pem_key_file: input('mongod_client_pem'), ssl_ca_file: input('mongod_cafile'), authentication_database: input('authentication_database'), authentication_mechanism: input('authentication_mechanism'))
  dbs = mongo_session.query("db.adminCommand('listDatabases')")['databases'].map { |x| x['name'] }

  dbs.each do |db|
    db_command = "db = db.getSiblingDB('#{db}');db.getRoles({rolesInfo: 1,showPrivileges:true,showBuiltinRoles: true})"
    results = mongo_session.query(db_command)

    results.each do |entry|
      describe "Manually verify privileges for Role: `#{entry['role']}` within Database: `#{db}`
      Privileges: #{entry['privileges']}" do
        skip
      end
    end
  end

  if dbs.empty?
    describe 'No databases found on the target' do
      skip
    end
  end
end
