# Security policy

## Reporting a vulnerability in ghast

Use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). Please do not open a public issue.

## Reporting something ghast found in someone else's repository

`ghast` is read-only and never interacts with a repository it scans. If it finds
something in a project you do not maintain:

1. **Do not test it.** Confirming a finding by reading the workflow and the data flow
   is enough. Running a payload against someone else's CI is unauthorised access in
   most jurisdictions, including under Part 10.7 of Australia's *Criminal Code Act 1995*.
2. **Report it privately.** Use the project's `SECURITY.md`, or GitHub's private
   vulnerability reporting if the project has it enabled. A critical finding does not
   belong in a public issue.
3. **Give them time.** 90 days is the usual expectation, and longer if they are engaging.
4. **Make it actionable.** Include the data flow, the line numbers, and the fix.
   `ghast scan --explain` produces all three.

Low-severity hygiene findings — unpinned actions, over-broad `permissions:` — are fine
to send as an ordinary pull request.
