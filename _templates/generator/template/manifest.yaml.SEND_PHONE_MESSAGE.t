---
to: "<%= trigger == 'SEND_PHONE_MESSAGE' ? `templates/${fileName}-${trigger}/manifest.yaml` : null %>"
---
name: "<%= name %>"
triggers:
	- "SEND_PHONE_MESSAGE"
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
