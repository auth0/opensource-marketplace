---
to: "<%= trigger == 'POST_USER_REGISTRATION' ? `templates/${fileName}-${trigger}/manifest.yaml` : null %>"
---
name: "<%= name %>"
triggers:
	- "POST_USER_REGISTRATION"
useCases:
	- 
public: true
description: "<%= description %>"
version: "1.0.0"
runtime: "node18"
secrets:
	- 
config:
	- 
sourceUrl: "https://github.com/auth0/opensource-marketplace/tree/main/templates/<%= fileName %>-<%= trigger %>/manifest.yaml"
modules:
	- 
notes: ""
