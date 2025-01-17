control 'V-81925' do
  title "When invalid inputs are received, MongoDB must behave in a predictable
  and documented manner that reflects organizational and system objectives."
  desc "A common vulnerability is unplanned behavior when invalid inputs are
  received. This requirement guards against adverse or unintended system behavior
  caused by invalid inputs, where information system responses to the invalid
  input may be disruptive or cause the system to fail into an unsafe state.
      The behavior will be derived from the organizational and system
  requirements and includes, but is not limited to, notification of the
  appropriate personnel, creating an audit record, and rejecting invalid input.
      This calls for inspection of application source code, which will require
  collaboration with the application developers. It is recognized that in many
  cases, the database administrator (DBA) is organizationally separate from the
  application developers, and may have limited, if any, access to source code.
  Nevertheless, protections of this type are so important to the secure operation
  of databases that they must not be ignored. At a minimum, the DBA must attempt
  to obtain assurances from the development organization that this issue has been
  addressed, and must document what has been discovered.
  "

  desc 'check', "As a user with the \"dbAdminAnyDatabase\" role, execute the
  following on the database of interest:
  use myDB
  db.getCollectionInfos()
  Where \"myDB\" is the name of the database on which validator rules are to be
  inspected. This returns an array of documents containing all collections
  information within myDB. For each collection's information received.
  If the \"options\" sub-document within each does not contain a \"validator\"
  sub-document, this is a finding."
  desc 'fix', "Document validation can be added at the time of creation of a
  collection. Existing collections can also be modified with document validation
  rules. Use the \"validator\" option to create or update a collection with the
  desired validation rules."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000447-DB-000393'
  tag "gid": 'V-81925'
  tag "rid": 'SV-96639r1_rule'
  tag "stig_id": 'MD3X-00-000780'
  tag "fix_id": 'F-88775r1_fix'
  tag "cci": ['CCI-002754']
  tag "nist": ['SI-10 (3)']
  tag "documentable": false
  tag "severity_override_guidance": false

  validator_exception_dbs = %w(admin local config)

  mongo_session = mongo_command(username: input('username'), password: input('password'), host: input('mongod_hostname'), port: input('mongod_port'), ssl: input('ssl'), verify_ssl: input('verify_ssl'), ssl_pem_key_file: input('mongod_client_pem'), ssl_ca_file: input('mongod_cafile'), authentication_database: input('authentication_database'), authentication_mechanism: input('authentication_mechanism'))

  dbs = mongo_session.query("db.adminCommand('listDatabases')")['databases'].map { |x| x['name'] }

  dbs.each do |db|
    next if validator_exception_dbs.include?(db)

    db_command = "db = db.getSiblingDB('#{db}');db.getCollectionInfos()"
    results = mongo_session.query(db_command)

    results.each do |entry|
      describe "Database: `#{db}`; Collection `#{entry['name']}`" do
        subject { entry }
        its(%w(options validator)) { should_not be nil }
      end
    end
  end

  if dbs.empty?
    describe 'No databases found on the target' do
      skip
    end
  end
end
