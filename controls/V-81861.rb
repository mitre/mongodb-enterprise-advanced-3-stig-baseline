control "V-81861" do
  title "Unused database components that are integrated in MongoDB and cannot
  be uninstalled must be disabled."
  desc  "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions).

      It is detrimental for software products to provide, or install by default,
  functionality exceeding requirements or mission objectives.

      DBMSs must adhere to the principles of least functionality by providing
  only essential capabilities.

      Unused, unnecessary DBMS components increase the attack vector for MongoDB
  by introducing additional targets for attack. By minimizing the services and
  applications installed on the system, the number of potential vulnerabilities
  is reduced. Components of the system that are unused and cannot be uninstalled
  must be disabled. The techniques available for disabling components will vary
  by DBMS product, OS, and the nature of the component and may include DBMS
  configuration settings, OS service settings, OS file access security, and DBMS
  user/role permissions.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-DB-000092"
  tag "satisfies": ["SRG-APP-000141-DB-000092", "SRG-APP-000142-DB-000094"]
  tag "gid": "V-81861"
  tag "rid": "SV-96575r1_rule"
  tag "stig_id": "MD3X-00-000290"
  tag "fix_id": "F-88711r1_fix"
  tag "cci": ["CCI-000381", "CCI-000382"]
  tag "nist": ['CM-7 b', 'Rev_4']
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
  tag "check": "In the MongoDB database configuration file (default location:
  /etc/mongod.conf), review the following parameters:

  net:
  http:
  enabled: true
  JSONPEnabled: true
  RESTInterfaceEnabled: true

  If any of the <booleans> are \"True\" or \"Enabled\", this is a finding."
  tag "fix": "In the MongoDB database configuration file (default location:
  /etc/mongod.conf), ensure the following parameters either:

  Does not exist in the file
  OR
  Are set to \"false\" as shown below:

  http:
  enabled: false
  JSONPEnabled: false
  RESTInterfaceEnabled: false"
  describe yaml(attribute('mongod_conf')) do
    its(["net","http", "enabled"]) { should cmp "false" }
  end
  describe yaml(attribute('mongod_conf')) do
    its(["net","http", "JSONPEnabled"]) { should cmp "false" }
  end
  describe yaml(attribute('mongod_conf')) do
    its(["net","http", "RESTInterfaceEnabled"]) { should cmp "false" }
  end
end

