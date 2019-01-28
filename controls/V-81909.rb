#not complete
control "V-81909" do
  title "MongoDB must prohibit user installation of logic modules (stored
  procedures, functions, triggers, views, etc.) without explicit privileged
  status."
  desc  "Allowing regular users to install software, without explicit
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
  impact 0.5
  tag "gtitle": "SRG-APP-000378-DB-000365"
  tag "gid": "V-81909"
  tag "rid": "SV-96623r1_rule"
  tag "stig_id": "MD3X-00-000650"
  tag "fix_id": "F-88759r1_fix"
  tag "cci": ["CCI-001812"]
  tag "nist": ['CM-11 (2)', 'Rev_4']
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
  tag "check": "If MongoDB supports only software development, experimentation,
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
  tag "fix": "Revoke any roles with unnecessary privileges to privileged
  functionality by executing the revoke command.

  Revoke any unnecessary privileges from any roles by executing the revoke
  command.

  Create, as needed, new role(s) with associated privileges."
end

