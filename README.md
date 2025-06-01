# Discord Multiverse (Goose Edition)

Service module for managing an unlimited number of discord servers from a single auth instance. It can run side by side with the core auth discord service, or completely standalone.

Most of the code is borrowed from Alliance Auth's core Discord Service Module[link] and re-purposed to be guild agnostic.

Active Devs:

- [corgski](https://github.com/digital-pet)

Forked from Solar-Helix-Independent-Transport/allianceauth-discord-multiverse by [AaronKable](https://github.com/pvyParts)

```diff
-                 THIS APPLICATION IS NOT PRODUCTION READY
```

### Installation

1.  pip install `package`
2.  Add `'aadiscordmultiverse',` to your `INSTALLED_APPS` in your projects `local.py`
3.  Configure settings in local.py (TODO: what settings?)
3.  Run migrations, collectstatic and restart auth.
4.  Setup your permissions as documented below

### Access Control and Server Permissions

- First and foremost to access **ANY** server a user must have this permission;
  - `aadiscordmultiverse | discord managed server | Can access the Discord Multiverse services`
- Access control to each server is managed by the Server Model
  - You can grant access by adding one of the following to the managed server in admin.
    - User State
    - User Groups
    - Main Characters Faction
    - Main Characters Alliance
    - Main Characters Corporation
    - Main Character

### Adding a Guild to Auth

1.  Add a new `DISCORD MANAGED SERVER` in admin
2.  Set the guild id to match your new server
3.  set any access control settings you need
4.  Set the included groups for the server. These are the only groups that will not be synced to this discord server. Enable the "managed groups" option if you want the auto corp/ali groups to sync magically too.
5.  Click Save
6.  Restart Auth
7.  Goto Services in the main auth site
8.  Click "Link Discord" on the new server and add your auth bot to the correct server.
9.  People can now join as required
