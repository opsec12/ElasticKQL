# Multi-Cloud Security Incident Detection Queries
## Kibana Discover KQL Queries for Neptune Tortilla Exercise

### Incident Overview
This document contains Kibana KQL (Kibana Query Language) queries for use in Elasticsearch Discover to detect the multi-cloud security incidents involving:
- **AWS S3 Public Bucket Credential Exposure** (July 14-16, 2025)
- **APT40 GCP Crypto Mining Operation** (July 16-17, 2025) 
- **Azure AD Cross-Platform Account Takeover** (July 15-16, 2025)

### How to Use These Queries
1. **Open Kibana Discover**
2. **Select appropriate index pattern** (aws-logs-*, gcp-logs-*, azure-logs-*)
3. **Copy and paste KQL query** into the search bar
4. **Adjust time range** as needed
5. **Apply filters** for further refinement

---

## 🟠 AWS CloudTrail Incident Detection

### 1. Public S3 Bucket Creation Detection
```kql
eventSource:"s3.amazonaws.com" AND eventName:"CreateBucket" AND requestParameters.x-amz-acl:"public-read"
```

### 2. Public Object Uploads to S3
```kql
eventSource:"s3.amazonaws.com" AND eventName:"PutObject" AND requestParameters.x-amz-acl:"public-read" AND requestParameters.key:*credentials*
```

### 3. Anonymous S3 Access Detection
```kql
userIdentity.type:"Anonymous" AND eventSource:"s3.amazonaws.com" AND eventName:"GetObject" AND requestParameters.key:*credentials*
```

### 4. TOR Network Access Attempts
```kql
userIdentity.type:"Anonymous" AND sourceIPAddress:(185.220.100.240 OR 45.146.164.110)
```

### 5. AWS Development Endpoint Probing
```kql
eventSource:"s3.amazonaws.com" AND requestParameters.Host:*:4566 AND errorCode:*
```

### 6. Incident Response Actions Detection
```kql
(eventName:"PutBucketAcl" AND userIdentity.userName:"lisa.huang") OR (eventName:"DeleteObject" AND requestParameters.key:*credentials*) OR (eventName:"CreateAccessKey" AND eventTime:"2025-07-16*")
```

### 7. Compromised Bucket Timeline
```kql
requestParameters.bucketName:"rd-multicloud-config-temp"
```

### 8. Credential File Exposure Timeline
```kql
requestParameters.key:(*gcp-service-account* OR *azure-app-credentials* OR *multi-cloud-setup*)
```

### 9. External Access by Anonymous Users
```kql
userIdentity.type:"Anonymous" AND eventSource:"s3.amazonaws.com" AND sourceIPAddress:(185.220.100.240 OR 45.146.164.110 OR 223.104.6.22)
```

### 10. Failed AWS Development Access
```kql
requestParameters.Host:*:4566 AND (errorCode:"NoSuchBucket" OR errorCode:"AccessDenied")
```

---

## 🔵 GCP APT40 Crypto Mining Detection

### 11. APT40 Initial Access Detection
```kql
protoPayload.authenticationInfo.principalEmail:"secure-rd-gcp@ecogen-rd-project-2025.iam.gserviceaccount.com" AND protoPayload.requestMetadata.callerIp:(185.220.100.240 OR 45.146.164.110 OR 223.104.6.22)
```

### 12. Chinese IP Range Activities
```kql
protoPayload.requestMetadata.callerIp:(103.45.* OR 116.89.* OR 61.145.* OR 202.89.* OR 210.77.* OR 122.225.* OR 58.87.* OR 125.77.*)
```

### 13. APT40 User Agent Detection
```kql
protoPayload.requestMetadata.callerSuppliedUserAgent:(*APT40* OR "terraform/1.5.0 APT40-Auto-Miner" OR "XMRig/6.20.0-APT40")
```

### 14. Bulk GPU Instance Creation
```kql
protoPayload.serviceName:"compute.googleapis.com" AND protoPayload.methodName:"v1.compute.instances.bulkInsert" AND timestamp >= "2025-07-17T00:00:00Z"
```

### 15. Crypto Mining Configuration Detection
```kql
protoPayload.requestMetadata.callerSuppliedUserAgent:*XMRig* OR insertId:*APT40* OR labels.mining_deployment:* OR protoPayload.resourceName:*apt40-mining-config*
```

### 16. Service Account Key Creation (Persistence)
```kql
protoPayload.methodName:"google.iam.admin.v1.CreateServiceAccountKey" AND protoPayload.resourceName:*apt40*
```

### 17. High-Cost Mining Instance Deployment
```kql
protoPayload.methodName:"v1.compute.instances.bulkInsert" AND severity:("CRITICAL" OR "ERROR") AND labels.estimated_cost:*
```

### 18. APT40 Privilege Escalation Detection
```kql
protoPayload.methodName:"SetIamPolicy" AND labels.apt40_operation:*quota* AND severity:"CRITICAL"
```

### 19. Mining Pool Configuration Upload
```kql
protoPayload.requestMetadata.callerSuppliedUserAgent:*XMRig* AND protoPayload.resourceName:*mining-pools*
```

### 20. APT40 Persistence Mechanisms
```kql
protoPayload.resourceName:*apt40* AND (protoPayload.methodName:*CreateServiceAccount* OR protoPayload.methodName:*CreateServiceAccountKey*)
```

---

## 🔴 Azure AD Cross-Platform Attack Detection

### 21. TOR-Based Failed Login Attempts
```kql
Category:"SignInLogs" AND ResultType:"50126" AND IPAddress:"185.220.100.240" AND RiskDetail:"anonymizedIPAddress"
```

### 22. Credential Stuffing from AWS S3 Breach
```kql
Category:"IdentityProtection" AND RiskEventType:"leakedCredentials" AND RiskDetail:*AWS\ S3* AND SourceId:"breach-aws-s3-001"
```

### 23. Failed Password Reset Attempts (Moscow IP)
```kql
Category:"AuditLogs" AND OperationName:"Reset user password" AND ResultType:"failure" AND IPAddress:"45.146.164.110" AND Location:"Moscow, Russia"
```

### 24. R&D Team Targeted Attacks
```kql
OperationName:"Reset user password" AND TargetResources.userPrincipalName:("erichong@ecogen.com" OR "marktombson@ecogen.com" OR "jeremyskeet@ecogen.com")
```

### 25. Dark Web Credential Preparation Detection
```kql
AdditionalInfo:(*Genesis\ Market* OR *RaidForums*) OR Activity:"credential_harvesting" OR RiskDetail:*dark\ web*
```

### 26. High-Risk Identity Protection Events
```kql
Category:"IdentityProtection" AND RiskLevel:"high" AND TimeGenerated >= "2025-07-15T00:00:00Z"
```

### 27. Emergency Account Disable Actions
```kql
OperationName:"Update user" AND ActivityDisplayName:"Disable user account" AND AdditionalDetails:*compromised*
```

### 28. Cross-Platform Azure Service Account Activity
```kql
UserPrincipalName:"rdazure@rd-azure.us" AND (IPAddress:(185.220.100.240 OR 45.146.164.110) OR RiskLevel:"high")
```

### 29. Blocked Azure Login Attempts
```kql
Category:"SignInLogs" AND ResultType:("50126" OR "50053" OR "50055") AND RiskLevelDuringSignIn:"high"
```

### 30. Azure Multi-Cloud App Activity
```kql
AppDisplayName:"Multi-Cloud Integration Service" OR TargetResources.displayName:"Multi-Cloud Integration*"
```

---

## 🔄 Cross-Platform Correlation Queries

### 31. Multi-Cloud Service Account Timeline
```kql
userIdentity.userName:"tory.owens" OR protoPayload.authenticationInfo.principalEmail:"secure-rd-gcp@ecogen-rd-project-2025.iam.gserviceaccount.com" OR UserPrincipalName:"rdazure@rd-azure.us"
```

### 32. Credential File Exposure to Usage Timeline
```kql
requestParameters.key:*credentials* OR protoPayload.resourceName:*credentials* OR AdditionalDetails:*credential*
```

### 33. Attack IP Correlation Across Platforms
```kql
sourceIPAddress:(185.220.100.240 OR 45.146.164.110) OR protoPayload.requestMetadata.callerIp:(185.220.100.240 OR 45.146.164.110) OR IPAddress:(185.220.100.240 OR 45.146.164.110)
```

### 34. Incident Response Actions Across All Platforms
```kql
eventName:("PutBucketAcl" OR "DeleteObject" OR "CreateAccessKey") OR protoPayload.methodName:"google.iam.admin.v1.DisableServiceAccountKey" OR ActivityDisplayName:"Disable user account"
```

### 35. Complete Incident Timeline (July 14-17)
```kql
(requestParameters.bucketName:"rd-multicloud-config-temp" OR insertId:*APT40* OR UserPrincipalName:"rdazure@rd-azure.us" OR sourceIPAddress:(185.220.100.240 OR 45.146.164.110) OR protoPayload.requestMetadata.callerIp:(185.220.100.240 OR 45.146.164.110) OR IPAddress:(185.220.100.240 OR 45.146.164.110)) AND @timestamp >= "2025-07-14T00:00:00Z" AND @timestamp <= "2025-07-17T23:59:59Z"
```

---

## 📊 Security Metrics and Analysis Queries

### 36. Anonymous S3 Access Volume
```kql
userIdentity.type:"Anonymous" AND eventSource:"s3.amazonaws.com"
```

### 37. APT40 Activity Volume
```kql
insertId:*APT40* OR protoPayload.requestMetadata.callerSuppliedUserAgent:*APT40*
```

### 38. High-Risk Azure Events
```kql
Category:"IdentityProtection" AND RiskLevel:"high"
```

### 39. Failed Login Attempts (All Platforms)
```kql
(ResultType:("50126" OR "50053") AND Category:"SignInLogs") OR (userIdentity.type:"Anonymous" AND errorCode:*)
```

### 40. Privilege Escalation Attempts
```kql
(eventName:*Role* OR eventName:*Policy*) OR (protoPayload.methodName:*SetIamPolicy*) OR (OperationName:*role* OR OperationName:*permission*)
```

---

## 🚨 Real-Time Alert Queries

### 41. Public S3 Bucket Alert (Last 5 minutes)
```kql
eventName:"CreateBucket" AND requestParameters.x-amz-acl:"public-read" AND @timestamp >= "now-5m"
```

### 42. Anonymous Credential Access Alert (Last 15 minutes)
```kql
userIdentity.type:"Anonymous" AND requestParameters.key:*credential* AND @timestamp >= "now-15m"
```

### 43. High-Value Target Password Reset Alert (Last 10 minutes)
```kql
OperationName:"Reset user password" AND TargetResources.userPrincipalName:*@ecogen.com AND @timestamp >= "now-10m"
```

### 44. Crypto Mining Instance Alert (Last 30 minutes)
```kql
protoPayload.methodName:"v1.compute.instances.bulkInsert" AND protoPayload.requestMetadata.callerSuppliedUserAgent:*mining* AND @timestamp >= "now-30m"
```

### 45. TOR Network Activity Alert (Last 1 hour)
```kql
(sourceIPAddress:(185.220.100.240 OR 45.146.164.110) OR IPAddress:(185.220.100.240 OR 45.146.164.110) OR protoPayload.requestMetadata.callerIp:(185.220.100.240 OR 45.146.164.110)) AND @timestamp >= "now-1h"
```

---

## 🔍 Investigation Workflow

### Phase 1: Initial Discovery
1. **Start with Query #35** (Complete Incident Timeline) to get overview
2. **Use Query #33** (Attack IP Correlation) to identify related activities
3. **Run Query #31** (Service Account Timeline) to understand credential usage

### Phase 2: Platform-Specific Analysis
1. **AWS**: Use queries #1-10 to analyze S3 breach
2. **GCP**: Use queries #11-20 to investigate crypto mining
3. **Azure**: Use queries #21-30 to examine account takeover attempts

### Phase 3: Impact Assessment
1. **Run Query #17** to assess financial impact (GCP mining costs)
2. **Use Query #39** to count failed access attempts
3. **Check Query #34** to verify incident response actions

### Phase 4: Ongoing Monitoring
1. **Set up alerts** using queries #41-45
2. **Monitor Query #26** for new high-risk events
3. **Track Query #40** for privilege escalation attempts

---

## 💡 KQL Tips and Tricks

### Field Existence Checks
```kql
errorCode:*          # Field exists (any value)
NOT errorCode:*      # Field does not exist
```

### Range Queries
```kql
@timestamp >= "2025-07-14" AND @timestamp <= "2025-07-17"
severity:(ERROR OR CRITICAL)
ResponseElements.ConsoleLogin:(Success OR Failure)
```

### Wildcard and Regex
```kql
eventName:*Bucket*           # Contains "Bucket"
IPAddress:192.168.*          # IP range
userAgent:/.*bot.*/          # Regex pattern
```

### Boolean Logic
```kql
field1:"value1" AND field2:"value2"
field1:"value1" OR field1:"value2"
NOT field1:"value1"
(field1:"value1" OR field1:"value2") AND field2:"value3"
```

### Common KQL Gotchas
- **Spaces in values**: Use quotes `"value with spaces"`
- **Special characters**: Escape with backslash `field:"value\:with\:colons"`
- **Case sensitivity**: KQL is case-sensitive for values
- **Field names**: Use exact field names from your data

---

## 📝 Usage Notes

### Before Running Queries:
1. **Verify index patterns** match your Elasticsearch setup
2. **Adjust field names** if your log format differs
3. **Update date ranges** for your investigation timeframe
4. **Modify IP addresses** based on current threat intelligence

### For Production Use:
1. **Test queries** in development environment first
2. **Add additional filters** to reduce noise
3. **Create saved searches** for frequently used queries
4. **Set up visualizations** for key metrics
5. **Configure alerts** for real-time monitoring

### Performance Tips:
1. **Use specific time ranges** to limit data volume
2. **Add high-cardinality filters first** (like specific IPs)
3. **Combine related conditions** in single queries when possible
4. **Consider using index patterns** specific to your data sources