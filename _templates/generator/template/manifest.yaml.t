---
to: "<%= `templates/${fileName}-${trigger}/manifest.yaml` %>"
---
id: "<%= id %>"
name: "<%= name %>"
triggers:
	- "<%= trigger %>"
useCases:
	- 
public: true
description: "<%= description %>"
version: "1.0.0"
runtime: "node22"
sourceUrl: "https://github.com/auth0/opensource-marketplace/tree/main/templates/<%= fileName %>-<%= trigger %>/manifest.yaml"
notes: ""

# secrets example:
# 
# secrets:
# 	- label: 'MY_SECRET'
# 	  defaultValue: 'this is the default'
secrets:
	- 

# modules example:
# 
# modules:
# 	- name: 'aws-sdk'
# 	  version: 'latest'
modules:
	- 
