**Title:** Identity Info - User Details Lookup

**Description:** Retrieves the latest identity information for specified users including department, MFA status, account status, location, and job title from the past 90 days.

**Query:**
```kql
IdentityInfo
| where TimeGenerated >= ago(90d)
| where AccountUPN in~ ("")
| summarize arg_max(TimeGenerated, *) by AccountUPN
| project TimeGenerated, AccountDisplayName, AccountUPN, Department, IsMFARegistered, IsAccountEnabled, Country, State, JobTitle, UserType
```
