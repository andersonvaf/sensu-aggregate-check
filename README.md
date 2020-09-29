# Sensu Go Aggregate Check Plugin

- [Overview](#overview)
- [Files](#files)
- [Usage examples](#usage-examples)
- [Configuration](#configuration)
  - [Sensu Go](#sensu-go)
    - [Asset registration](#asset-registration)
    - [Check definition](#check-definition)
    - [RBAC](#rbac)
  - [Sensu Core](#sensu-core)
- [Installation from source](#installation-from-source)
- [Additional notes](#additional-notes)
- [Contributing](#contributing)

### Overview

This is a fork from [Bonsai's Sensu Go Aggregate Check Plugin](https://github.com/sensu/sensu-aggregate-check), modified to aggregate checks using API calls based on entity and check names, instead of filtering all events.

This plugin allows you to create check aggregates. Suppose that you have web servers serving various applications on different ports: 80, 8080, and 9000. You could create three separate checks, each one monitoring the health of each port. However, if you want to view your web app’s health, these three checks don’t do the best job of providing that insight. These checks are isolated from each other, and each check alerts individually. Instead, it makes more sense to configure this group of checks as an aggregate because you might not care if a check on an individual host fails, but you will certainly care if a large percentage of the checks are in a warning or critical state across a number of hosts.

This plugin allows you to query the Sensu Go Backend API for Events matching certain criteria (labels). This plugin generates a set of counters (e.g. events total, events in an OK state, etc) from the Events query and provides several CLI arguments to evaluate the computed aggregate counters (e.g. --warn-percent=75).

### Files

N/A

## Usage examples

### Help

```
The Sensu Go Event Aggregates Check plugin

Usage:
  sensu-aggregate-check [flags]

Flags:
  -H, --api-host string          Sensu Go Backend API Host (e.g. 'sensu-backend.example.com') (default "127.0.0.1")
  -k, --api-key string           Sensu Go Backend API Key
  -P, --api-pass string          Sensu Go Backend API Password (default "P@ssw0rd!")
  -p, --api-port string          Sensu Go Backend API Port (e.g. 4242) (default "4567")
  -u, --api-user string          Sensu Go Backend API User (default "admin")
  -U, --api-url string           Sensu Go Backend API URL (e.g. http://sensu:4567) (default "http://sensu:4567")
  -l, --check-labels string      Comma-delimited list of Sensu Go Event Check Names to be aggregated (e.g. 'check1,check2,check3')
  -e, --entity-labels string     Comma-delimited list of Sensu Go Event Entity Names to be aggregated (e.g. 'entity1,entity2')
  -n, --namespaces string        Comma-delimited list of Sensu Go Namespaces to query for Events (e.g. 'us-east-1,us-west-2') (default "default")
  -C, --crit-count int           Critical threshold - count of Events in warning state
  -c, --crit-percent int         Critical threshold - % of Events in warning state
  -W, --warn-count int           Warning threshold - count of Events in warning state
  -w, --warn-percent int         Warning threshold - % of Events in warning state
  -i, --insecure-skip-verify     skip TLS certificate verification (not recommended!)
  -s, --secure                   Use TLS connection to API
  -t, --trusted-ca-file string   TLS CA certificate bundle in PEM format
  -o, --output-limit int         If the number of checks is greater than the output limit, only the counters will be printed in the output (default 10)
  -h, --help                     help for sensu-aggregate-check
```

## Configuration

### Sensu Go

#### Check definition

```yaml
api_version: core/v2
type: CheckConfig
metadata:
  namespace: default
  name: dummy-app-aggregate
spec:
  runtime_assets:
  - sensu-aggregate-check
  command: sensu-aggregate-check --api-user=foo --api-pass=bar --check-labels='check1,check2' --entity-labels='entity1,entity2' --warn-percent=75 --crit-percent=50
  subscriptions:
  - backend
  publish: true
  interval: 30
  handlers:
  - slack
  - pagerduty
  - email
```

### RBAC

It is advised to use [RBAC][3] to create a user scoped specifically for purposes such as this check and
to not re-use the admin account.  For this check, in particular, the account would need access to
list and retrieve events.  The example below shows how to create a limited-scope user and the necessary
role and role-binding resources to give it the required access.

```
$ sensuctl user create aggregate --password='4yva#ko!Yq'
Created

$ sensuctl role create get-events --verb list,get --resource events
Created

$ sensuctl role-binding create aggregate-get-events --role=get-events --user=aggregate
Created
```

Though you could use the user and password combination above with this check, the best practice
would be to use an [API key][4] instead.  You can create the API key with sensuctl:

```
$ sensuctl api-key grant aggregate
Created: /api/core/v2/apikeys/03f66dbf-6fe0-40d4-8174-95b5eab95649
```

The key (the text after [...]/apikeys/) above can be used with the `--api-key` argument in place of using `api-user` and `api-pass`.

### Sensu Core

N/A

## Installation from source and contributing

### Sensu Go

To build from source, from the local path of the sensu-aggregate-check repository:
```
go build
```

### Contributing

To contribute to this plugin, see [CONTRIBUTING](https://github.com/sensu/sensu-go/blob/master/CONTRIBUTING.md)

[1]: https://bonsai.sensu.io/assets/sensu/sensu-aggregate-check
[2]: https://github.com/sensu/sensu-aggregate-check/releases
[3]: https://docs.sensu.io/sensu-go/latest/reference/rbac/
[4]: https://docs.sensu.io/sensu-go/latest/reference/apikeys/

