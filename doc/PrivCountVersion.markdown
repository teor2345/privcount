# PrivCount Version Scheme

PrivCount is versioned using Semantic Versioning: http://semver.org/

    Given a version number MAJOR.MINOR.PATCH, increment the:
    1. MAJOR version when you make incompatible API changes,
    2. MINOR version when you add functionality in a backwards-compatible
       manner, and
    3. PATCH version when you make backwards-compatible bug fixes.

For example, when we:
* change the protocol or events in incompatible ways, we go from 0.2.0 to
  1.0.0,
  * when the protocol is incompatible, we also increment
    PrivCountProtocol.HANDSHAKE_VERSION to the latest major version,
* add new events or new counters, we go from 0.2.0 to 0.3.0,
* fix bugs, we go from 0.2.0 to 0.2.1.

PrivCount versions can contain changes to the PrivCount python code, Tor patch,
or both. Changes to upstream Tor are managed using Tor's versioning scheme,
and tags contain both the Tor and PrivCount versions.

## Updating the PrivCount version

You can use bumpversion to bump the PrivCount version in all the relevant
files, in both the PrivCount and Tor repositories:

    bumpversion major|minor|patch

The default configuration creates a git commit, and tags it "privcount-a.b.c".

If the PrivCount protocol changes in an incompatible way, you will need to
update PrivCountProtocol.HANDSHAKE_VERSION manually.

The Tor and PrivCount versions will never clash, because the Tor version has
a leading zero.

# PrivCount Tor Patch

PrivCount obtains its Tor usage data via Tor Control Events. These events have
been implemented specifically for PrivCount: they have not yet been merged into
Tor master.

## Development Branch

The master branch for PrivCount development is called:

    privcount

Updates to this branch are force-pushed to keep it at the latest Tor version.

## Other Branches

Maintenance branches are created as-needed: they are versioned like Tor
maintenance branches, but with a privcount prefix:

    privcount-maint-1.0

## Release Tags

Release tags are created as-needed. They are named after the corresponding
PrivCount release, and the corresponding Tor branch or tag.

Since PrivCount uses [semantic versioning](http://semver.org), patch versions
are always compatible, and minor versions are compatible *if* you don't use
any new features.

Examples:

PrivCount Tor Tag            | Tor Tag      | PrivCount Python Compatibility
-----------------------------|--------------|-------------------------------
privcount-1.0.0-tor-0.3.0.7  | tor-0.3.0.7  | privcount-1.?.*
privcount-1.0.0-tor-0.2.9.10 | tor-0.2.9.10 | privcount-1.?.*
privcount-0.1.1-tor-0.2.7.6  | tor-0.2.7.6  | privcount-0.1.*

Avoid using Tor maint branches, but, if you must, tag it with the latest Tor
minor version and a git commit hash.

Example:

PrivCount Tor Tag                      | Tor Upstream
---------------------------------------|-------------------------------
privcount-1.0.0-tor-0.2.9.10-a7bcab263 | maint-0.2.9 (commit a7bcab263)

## Rebasing onto the Latest Tor Version

Try to use the latest stable release whenever possible: avoid maint tags,
because they change too often, and avoid outdated or alpha versions.

To rebase privcount onto a newer version of tor, use commands like:
```
git checkout -b privcount-0.1.1-tor-0.3.0.7 privcount-0.1.1-tor-0.2.7.6
git rebase --onto tor-0.3.0.7 tor-0.2.7.6 privcount-0.1.1-tor-0.3.0.7
```
Then deal with any merge conflicts until the rebase is completed.

To bump the tor version in the git tags, use:
```
bumpversion --tag-name "privcount-{new_version}-tor-0.3.0.7"
git push --tags privcount-remote
```

To force update the old privcount branch with the newly rebased code:
```
git checkout -b privcount-old privcount
git branch -D privcount
git checkout -b privcount privcount-1.0.0-tor-0.3.0.7
git push --force privcount-remote privcount
```
