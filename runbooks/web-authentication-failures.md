# Repeated authentication failures on the web server

## Expected setup

The lab web server is `198.51.100.20` (nginx). The page `/admin/` is protected
by HTTP basic authentication. Approved users connect from the client network
`192.0.2.0/24`. These addresses are reserved for examples and do not identify
real hosts.

## What the alert means

The "Repeated authentication failures" alert fires when one source address
produces five or more failed logins within 60 seconds. In the nginx error log
these appear as `user "<name>": password mismatch` (wrong password) or
`user "<name>" was not found` (unknown user name), each followed by
`client: <source address>`.

## Investigate repeated authentication failures

1. Confirm the source address, the user names tried, and the time range from
   the nginx error log lines in the alert.
2. Check whether the source is a known client. A known user mistyping a
   password usually produces a few failures for one user name; many different
   user names or passwords in a short time suggest password guessing.
3. Check the nginx access log for the same source: a successful request
   (status 200) on `/admin/` after the failures means a login succeeded.
4. If guessing is suspected, an authorized operator may block the source at the
   firewall or rate-limit the page. Do not disable authentication or share
   credentials as a troubleshooting shortcut.

## Evidence and limits

A failed login shows that a request carried wrong or unknown credentials. By
itself, it does not prove an attack, show whether any account was compromised,
or identify the person behind the address. Correlate with other approved
sources before acting.
