control "V-81879" do
  title "MongoDB must maintain the authenticity of communications sessions by
  guarding against man-in-the-middle attacks that guess at Session ID values."
  desc "One class of man-in-the-middle, or session hijacking, attack involves
  the adversary guessing at valid session identifiers based on patterns in
  identifiers already known.

      The preferred technique for thwarting guesses at Session IDs is the
  generation of unique session identifiers using a FIPS 140-2 approved random
  number generator.

      However, it is recognized that available DBMS products do not all implement
  the preferred technique yet may have other protections against session
  hijacking. Therefore, other techniques are acceptable, provided they are
  demonstrated to be effective.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-DB-000384"
  tag "gid": "V-81879"
  tag "rid": "SV-96593r1_rule"
  tag "stig_id": "MD3X-00-000410"
  tag "fix_id": "F-88729r1_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23", "Rev_4"]
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
  desc "check": "Check the MongoDB configuration file (default location:
  /etc/mongod.conf).

  The following should be set:

  net:
  ssl:
  mode: requireSSL

  If this is not found in the MongoDB configuration file, this is a finding."
  desc "fix": "Follow the documentation guide at
  https://docs.mongodb.com/v3.4/tutorial/configure-ssl/.

  Stop/start (restart) and mongod or mongos using the MongoDB configuration file."
  describe yaml(input('mongod_conf')) do
    its(%w{net ssl mode}) { should cmp 'requireSSL' }
  end
end
