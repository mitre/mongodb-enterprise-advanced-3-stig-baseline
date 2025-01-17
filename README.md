# mongodb-enterprise-advanced-stig-baseline

InSpec profile to validate the secure configuration of MongoDB Enterprised Advanced 3, against [DISA](https://iase.disa.mil/stigs/)'s MongoDB Enterprise Advanced 3.x Security Technical Implementation Guide (STIG) Version 1, Release 2.

#### Container-Ready: Profile updated to adapt checks when the running against a containerized instance of MongoDB, based on reference container: (docker pull mongo)

## Getting Started  

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
  - name: username
    description: 'User to log into the mongo database'
    value: null
    sensitive: true

  - name: password
    description: 'Password to log into the mongo database'
    value: null
    sensitive: true

  - name: mongod_hostname
    description: 'Hostname for mongodb database'
    type: string
    value: '127.0.0.1'

  - name: mongod_port
    description: 'Port number for the mongodb database'
    type: string
    value: '27017'

  - name: ssl
    description: 'Is ssl enabled'
    type: boolean
    value: false

  - name: verify_ssl
    description: 'Flag for sslAllowInvalidCertificates'
    type: boolean
    value: false

  - name: mongod_client_pem
    description: 'PEM file location on the scan target'
    value: null

  - name: mongod_cafile
    description: 'CAFILE location on the scan target'
    value: null

  - name: authentication_database
    description: 'Flag for authentication database'
    value: null

  - name: authentication_mechanism
    description: 'Flag for authentication mechanism'
    value: null

  - name: mongod_conf
    description: 'MongoDB configuration file'
    type: string
    value: '/etc/mongod.conf'
    required: true

  - name: mongo_data_dir
    description: 'MongoDB Home Directory'
    type: string
    value: '/var/lib/mongo'
    required: true

  - name: mongo_use_ldap
    description: 'MongoDB is Using LDAP - True/False'
    type: boolean
    value: false
    required: true

  - name: mongo_use_saslauthd
    description: 'MongoDB is Using SASLAUTHD - True/False'
    type: boolean
    value: false
    required: true

  - name: approved_mongo_packages
    description: 'List of MongoDB Packages'
    type: array
    value: [
      'mongodb-enterprise',
      'mongodb-enterprise-mongos',
      'mongodb-enterprise-server',
      'mongodb-enterprise-shell',
      'mongodb-enterprise-tools'
    ]
    required: true

  - name: mongodb_service_account
    description: 'Mongodb Service Account'
    type: array
    value: ["mongodb", "mongod"]

  - name: mongodb_service_group
    description: 'Mongodb Service Group'
    type: array
    value: ["mongodb", "mongod"]

  - name: is_sensitive
    description: 'Set to true if target is sensitive as described in control V-81875 and V-81919'
    type: boolean
    value: true

  - name: certificate_key_file
    description: 'Path to server certificate key file'
    type: string
    value: "/etc/ssl/mongodb.pem"
```

# Running This Baseline Directly from Github

Against a _**locally-hosted**_ instance (i.e., InSpec installed on the target)
```bash
inspec exec https://github.com/mitre/mongodb-enterprise-advanced-3-stig-baseline/archive/master.tar.gz --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json>
```

Against a _**docker-containerized**_ instance (i.e., InSpec installed on the node hosting the container):
```bash
inspec exec https://github.com/mitre/mongodb-enterprise-advanced-3-stig-baseline/archive/master.tar.gz -t docker://instance_id --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
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
git clone https://github.com/mitre/mongodb-enterprise-advanced-3-stig-baseline
inspec archive mongodb-enterprise-advanced-3-stig-baseline
inspec exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd mongodb-enterprise-advanced-3-stig-baseline
git pull
cd ..
inspec archive mongodb-enterprise-advanced-3-stig-baseline --overwrite
inspec exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Alicia Sturtevant - [asturtevant](https://github.com/asturtevant)
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Rony Xavier - [rx294](https://github.com/rx294)

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

