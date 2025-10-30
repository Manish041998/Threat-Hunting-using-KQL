Here’s a complete mini–toolkit you can use to query it effectively in **Microsoft Sentinel** or **Defender XDR**.
Each query has a clear goal and an example output column set so you can understand what it’s showing.

---

### 🧩 1. View latest sign-ins

See the 20 most recent sign-ins across users.

```kusto
AADSignInEventsBeta
| order by TimeGenerated desc
| project TimeGenerated, AccountUpn, Application, ClientAppUsed, IPAddress, Country, City, Result=ErrorCode
| take 20
```

---

### 🕵️ 2. Show risky sign-ins

Focus on those that Microsoft Identity Protection flagged as risky.

```kusto
AADSignInEventsBeta
| where isnotempty(RiskEventTypes)
| project TimeGenerated, AccountUpn, RiskLevelDuringSignIn, RiskEventTypes, IPAddress, Country, Application
| order by TimeGenerated desc
```

---

### 🌍 3. Sign-ins by location (useful for impossible-travel hunting)

Get a quick map of sign-ins by country.

```kusto
AADSignInEventsBeta
| summarize SignInCount = count() by Country
| sort by SignInCount desc
```

Or visualize by geo (Sentinel map widget):

```kusto
AADSignInEventsBeta
| summarize count() by Country, Latitude, Longitude
```

---

### 🧠 4. Detect “impossible travel” (two logins from different countries close in time)

```kusto
AADSignInEventsBeta
| extend Location = strcat(Country, " - ", City)
| summarize
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    Countries = make_set(Country)
    by AccountUpn, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
| project AccountUpn, StartTime, EndTime, Countries
```

---

### 🧑‍💻 5. Sign-ins by client app or device

```kusto
AADSignInEventsBeta
| summarize Count = count() by ClientAppUsed, OSPlatform
| sort by Count desc
```

---

### 🔑 6. Sign-ins requiring MFA

```kusto
AADSignInEventsBeta
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize Count = count() by AccountUpn
| order by Count desc
```

---

### 🪪 7. Non-interactive sign-ins (token refreshes, service principals, background apps)

```kusto
AADSignInEventsBeta
| where tostring(LogonType) contains "nonInteractive"
| project TimeGenerated, AccountUpn, Application, ClientAppUsed, DeviceName, IPAddress, Country
| order by TimeGenerated desc
```

---

### 🚫 8. Failed sign-ins (useful for brute-force or MFA failure patterns)

```kusto
AADSignInEventsBeta
| where ErrorCode != 0
| summarize Failures = count() by AccountUpn, Application, ResultCode = ErrorCode
| order by Failures desc
```

---

### 🧍 9. Sign-ins per user (frequency summary)

```kusto
AADSignInEventsBeta
| summarize SignIns = count() by AccountUpn
| sort by SignIns desc
```

---

### 🧩 10. Risky sign-ins correlated with URL clicks (your earlier rule)

```kusto
let loopback = 1h;
let UserClicks = UrlClickEvents
| where Timestamp > ago(loopback)
| project AccountUpn, TimestampUrlClick = Timestamp, Url, ClickIP = IPAddress;
AADSignInEventsBeta
| where ErrorCode == 0
| where isnotempty(RiskEventTypes) and isnotempty(RiskLevelDuringSignIn)
| join kind=inner UserClicks on AccountUpn
| where Timestamp > TimestampUrlClick
| extend ClickToSignInMins = datetime_diff("minute", Timestamp, TimestampUrlClick)
| project AccountUpn, RiskLevelDuringSignIn, RiskEventTypes, ClickToSignInMins, IPAddress, Url, Application, Country, City
```

---

### 🧭 11. Track specific user activity

```kusto
AADSignInEventsBeta
| where AccountUpn == "vignesh.sreenivasan@zellis.com"
| project TimeGenerated, Application, ClientAppUsed, IPAddress, Country, City, AuthenticationRequirement, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

---

### 🧠 12. Recent logons from unmanaged or non-compliant devices

```kusto
AADSignInEventsBeta
| where IsManaged == 0 or IsCompliant == 0
| project TimeGenerated, AccountUpn, DeviceName, OSPlatform, IPAddress, Country, Application
```

---


