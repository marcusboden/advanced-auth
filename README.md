# charm-local-users

## Description

Charm Local Users is a subordinate charm for creating and managing local user accounts and groups
on principal units. It can be related to any application using the `juju-info` interface.

It can be used to set up an unprivileged user for a hardware inventory system or grant access to
staff members.

Privileged users and management of privileges are out of scope. Integration with external identity
providers, such as LDAP or AD, is also out of scope.

## Usage

Create a configuration file:

```
cat config-local-users.yaml
local-users:
  group: mygroup
  users: |
    alice;Alice;ssh-rsa ABC alice@desktop
    bob;Bob;ssh-rsa XYZ bob@laptop
```

Deploy the application:

```
juju deploy --config config-local-users.yaml local-users
```

Relate to any principal charm application of your choice, e.g.
```
juju relate local-users ubuntu
```

Charm can also be configured after deployment.

Example: to remove `bob`'s account, create an updated user list file `user.lst` that doesn't
include Bob's account anymore and simply update the config:

```
cat user.lst
alice;Alice;ssh-rsa ABC alice@desktop
```
```
juju config local-users users=@user.lst
```

The charm will enter a `blocked` state if you try to add a user account that already exists but
isn't a member of the managed group. If you're sure that you want to add the pre-existing account
to the managed group anyway, making it a charm managed account from now, you can run:
```
juju config local-users allow-existing-users=true
```

Home directories of removed users will be backed up in the location specified in the `backup-path`
config option before being removed.

## Relations

This charm that can be related to any principal charm application using the `juju-info` interface.

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines 
on enhancements to this charm following best practice guidelines, and
`CONTRIBUTING.md` for developer guidance.
