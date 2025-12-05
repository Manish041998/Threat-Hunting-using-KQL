**Title:** SigninLogs - MFA Method Usage Summary

**Description:** Summarizes MFA authentication methods used across successful sign-ins over the last 30 days, showing count of events and unique users per method.

**Query:**
```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| where MfaDetail != "{}" and isnotempty(MfaDetail)
| extend MfaMethod = tostring(parse_json(MfaDetail).authMethod)
| where MfaMethod != "Previously satisfied"
| summarize Count = count(),
            Users = dcount(UserPrincipalName)
        by MfaMethod
| order by Count desc
```
