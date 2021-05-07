# mongodb-enterprise-advanced-stig-baseline

InSpec profile to validate the secure configuration of MongoDB Enterprised Advanced 3, against [DISA](https://iase.disa.mil/stigs/)'s MongoDB Enterprise Advanced 3.x Security Technical Implementation Guide (STIG) Version 1, Release 2.

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __ssh__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
# MongoDB configuration file
mongod_conf: ''

# MongoDB Home Directory'
mongo_data_dir: ''

# MongoDB Server PEM File'
mongod_pem: ''

# MongoDB CA File
mongod_cafile: ''

# MongoDB Client PEM File
mongod_client_pem: ''

# MongoDB Audit Log File
mongod_auditlog: ''

# MongoDB SASLAUTHD File
saslauthd: ''

# MongoDB is Running in Docker Environment - True/False
is_docker: ''

# MongoDB is Using PKI Authentication - True/False
mongo_use_pki: ''

# MongoDB is Using LDAP - True/False
mongo_use_ldap: ''

# MongoDB is Using SASLAUTHD - True/False
mongo_use_saslauthd: ''

# List of MongoDB Redhat Packages
mongodb_redhat_packages: []

# List of MongoDB Debian Packages
mongodb_debian_packages: []

# User to log into the mongo database
user: ''

# password to log into the mongo database
password: ''

# List of authorized users of the admn database
admin_db_users: []

# List of authorized users of the admn database
config_db_users: []

# List of authorized users of the admn database
myUserAdmin_allowed_role: []

# List of authorized users of the admn database
mongoadmin_allowed_role: []

# List of authorized users of the admn database
mongodb_admin_allowed_role: []

# List of authorized users of the admn database
appAdmin_allowed_role: []

# List of authorized users of the admn database
accountAdmin01_allowed_role: []
```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/mongodb-enterprise-advanced-stig-baseline/archive/master.tar.gz -t ssh://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/mongodb-enterprise-advanced-stig-baseline
inspec archive mongodb-enterprise-advanced-stig-baseline
inspec exec <name of generated archive> -t ssh://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd mongodb-enterprise-advanced-stig-baseline
git pull
cd ..
inspec archive mongodb-enterprise-advanced-stig-baseline --overwrite
inspec exec <name of generated archive> -t ssh://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Alicia Sturtevant - [asturtevant](https://github.com/asturtevant)

## Special Thanks 
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/mongodb-enterprise-advanced-stig-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx   

