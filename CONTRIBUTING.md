# charm-local-users

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate
    pip install -r requirements-dev.txt

## Building

Run:

    charmcraft pack

## Deploying local version

Deploy a locally built `.charm`:

    juju deploy ./local-users_ubuntu-20.04-amd64.charm

Update:

    juju refresh local-users --path ./local-users_ubuntu-20.04-amd64.charm

## Intended use case

Charm is intended to manage a small group of local user accounts and grant them passwordless SSH
access to the system by configuring their public SSH keys.

Out of scope:
- Privileged users or management of privileges
- User management at scale - this is intended for approximately 1-10 users total
- Integration with LDAP, AD and other external identity providers

## Testing

The Python operator framework includes a very nice harness for testing
operator behaviour without full deployment. Just `run_tests`:

    ./run_tests
