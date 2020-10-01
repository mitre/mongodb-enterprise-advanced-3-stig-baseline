control "V-81859" do
  title "Unused database components, DBMS software, and database objects must
  be removed."
  desc "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions).

      It is detrimental for software products to provide, or install by default,
  functionality exceeding requirements or mission objectives.

      DBMSs must adhere to the principles of least functionality by providing
  only essential capabilities.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000091"
  tag "gid": "V-81859"
  tag "rid": "SV-96573r1_rule"
  tag "stig_id": "MD3X-00-000280"
  tag "fix_id": "F-88709r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  desc "check", "Review the list of components and features installed with the
  MongoDB database.

  If unused components are installed and are not documented and authorized, this
  is a finding.

  RPM can also be used to check to see what is installed:

  yum list installed | grep mongodb

  This returns MongoDB database packages that have been installed.

  If any packages displayed by this command are not being used, this is a
  finding."
  desc "fix": "On data-bearing nodes and arbiter nodes, the
  mongodb-enterprise-tools, mongodb-enterprise-shell and
  mongodb-enterprise-mongos can be removed (or not installed).

  On applications servers that typically run the mongos process when connecting
  to a shared cluster, the only package required is the mongodb-enterprise-mongos
  package."
  mongodb_installed_packages = command('rpm -qa | grep mongodb').stdout.strip.split("\n")

  if mongodb_installed_packages.empty?
    describe 'There are no mongo database packages installed, therefore for this control is NA' do
      skip 'There are no mongo database packages installed, therefore for this control is NA'
    end
  end

  if !mongodb_installed_packages.empty?
    mongodb_installed_packages.each do |package|
      describe "The installed mongodb package: #{package}" do
        subject { package }
        it { should be_in input('mongodb_packages_used') }
      end
    end
  end
end
