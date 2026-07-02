# Simple Elasticsearch Dev Tools Queries
## Simplified JSON Queries for Neptune Tortilla Exercise

### How to Use in Dev Tools
1. **Open Kibana Dev Tools**
2. **Copy the entire query** (including GET line)
3. **Click the ▶ button** or press Ctrl+Enter
4. **View results** in the right panel

---

## 🟠 AWS CloudTrail Detection (Simple Format)

### 1. Public S3 Bucket Creation
```json
GET aws-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "eventSource:\"s3.amazonaws.com\" AND eventName:\"CreateBucket\" AND requestParameters.x-amz-acl:\"public-read\""
    }
  }
}
```

### 2. Anonymous S3 Credential Access
```json
GET aws-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "userIdentity.type:\"Anonymous\" AND eventSource:\"s3.amazonaws.com\" AND requestParameters.key:*credentials*"
    }
  }
}
```

### 3. TOR Network Access Attempts
```json
GET aws-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "userIdentity.type:\"Anonymous\" AND (sourceIPAddress:\"185.220.100.240\" OR sourceIPAddress:\"45.146.164.110\")"
    }
  }
}
```

### 4. Compromised Bucket Activity
```json
GET aws-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "requestParameters.bucketName:\"rd-multicloud-config-temp\""
    }
  }
}
```

### 5. Incident Response Actions
```json
GET aws-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "eventName:(\"PutBucketAcl\" OR \"DeleteObject\" OR \"CreateAccessKey\") AND userIdentity.userName:\"lisa.huang\""
    }
  }
}
```

---

## 🔵 GCP APT40 Detection (Simple Format)

### 6. APT40 Initial Access
```json
GET gcp-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "protoPayload.authenticationInfo.principalEmail:\"secure-rd-gcp@ecogen-rd-project-2025.iam.gserviceaccount.com\" AND protoPayload.requestMetadata.callerIp:(185.220.100.240 OR 45.146.164.110)"
    }
  }
}
```

### 7. Chinese IP Activities
```json
GET gcp-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "protoPayload.requestMetadata.callerIp:(103.45.* OR 116.89.* OR 61.145.* OR 202.89.*)"
    }
  }
}
```

### 8. APT40 User Agents
```json
GET gcp-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "protoPayload.requestMetadata.callerSuppliedUserAgent:*APT40*"
    }
  }
}
```

### 9. Crypto Mining Instance Creation
```json
GET gcp-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "protoPayload.methodName:\"v1.compute.instances.bulkInsert\" AND timestamp:[\"2025-07-17T00:00:00Z\" TO *]"
    }
  }
}
```

### 10. Mining Configuration Detection
```json
GET gcp-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "insertId:*APT40* OR protoPayload.resourceName:*apt40-mining-config*"
    }
  }
}
```

---

## 🔴 Azure AD Detection (Simple Format)

### 11. Failed TOR Logins
```json
GET azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "Category:\"SignInLogs\" AND ResultType:\"50126\" AND IPAddress:\"185.220.100.240\""
    }
  }
}
```

### 12. Credential Stuffing Detection
```json
GET azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "Category:\"IdentityProtection\" AND RiskEventType:\"leakedCredentials\" AND RiskDetail:*AWS*"
    }
  }
}
```

### 13. Failed Password Resets
```json
GET azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "OperationName:\"Reset user password\" AND ResultType:\"failure\" AND IPAddress:\"45.146.164.110\""
    }
  }
}
```

### 14. R&D Team Attacks
```json
GET azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "TargetResources.userPrincipalName:(\"erichong@ecogen.com\" OR \"marktombson@ecogen.com\" OR \"jeremyskeet@ecogen.com\")"
    }
  }
}
```

### 15. High-Risk Identity Events
```json
GET azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "Category:\"IdentityProtection\" AND RiskLevel:\"high\" AND TimeGenerated:[\"2025-07-15T00:00:00Z\" TO *]"
    }
  }
}
```

---

## 🔄 Cross-Platform Correlation (Simple Format)

### 16. Attack IP Correlation
```json
GET aws-logs-*,gcp-logs-*,azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "sourceIPAddress:(185.220.100.240 OR 45.146.164.110) OR protoPayload.requestMetadata.callerIp:(185.220.100.240 OR 45.146.164.110) OR IPAddress:(185.220.100.240 OR 45.146.164.110)"
    }
  }
}
```

### 17. Service Account Timeline
```json
GET aws-logs-*,gcp-logs-*,azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "userIdentity.userName:\"tory.owens\" OR UserPrincipalName:\"rdazure@rd-azure.us\" OR protoPayload.authenticationInfo.principalEmail:*secure-rd-gcp*"
    }
  }
}
```

### 18. Credential Exposure Timeline
```json
GET aws-logs-*,gcp-logs-*,azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "requestParameters.key:*credentials* OR protoPayload.resourceName:*credentials* OR AdditionalDetails:*credential*"
    }
  }
}
```

### 19. Complete Incident Timeline
```json
GET aws-logs-*,gcp-logs-*,azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "(requestParameters.bucketName:\"rd-multicloud-config-temp\" OR insertId:*APT40* OR UserPrincipalName:\"rdazure@rd-azure.us\") AND @timestamp:[\"2025-07-14T00:00:00Z\" TO \"2025-07-17T23:59:59Z\"]"
    }
  },
  "sort": [
    {"@timestamp": {"order": "asc"}}
  ],
  "size": 100
}
```

### 20. Incident Response Actions
```json
GET aws-logs-*,gcp-logs-*,azure-logs-*/_search
{
  "query": {
    "query_string": {
      "query": "eventName:(\"PutBucketAcl\" OR \"DeleteObject\") OR protoPayload.methodName:*DisableServiceAccountKey* OR ActivityDisplayName:\"Disable user account\""
    }
  }
}
```

---

## 🚨 Real-Time Monitoring (Simple Format)

### 21. Public S3 Bucket Alert (Last 5 minutes)
```json
GET aws-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "eventName:\"CreateBucket\" AND requestParameters.x-amz-acl:\"public-read\""
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-5m"
            }
          }
        }
      ]
    }
  }
}
```

### 22. Anonymous Credential Access Alert (Last 15 minutes)
```json
GET aws-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "userIdentity.type:\"Anonymous\" AND requestParameters.key:*credential*"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-15m"
            }
          }
        }
      ]
    }
  }
}
```

### 23. Crypto Mining Alert (Last 30 minutes)
```json
GET gcp-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "protoPayload.methodName:\"v1.compute.instances.bulkInsert\""
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-30m"
            }
          }
        }
      ]
    }
  }
}
```

### 24. Failed Login Alert (Last 10 minutes)
```json
GET azure-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "Category:\"SignInLogs\" AND ResultType:(\"50126\" OR \"50053\")"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-10m"
            }
          }
        }
      ]
    }
  }
}
```

### 25. Password Reset Alert (Last 5 minutes)
```json
GET azure-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "OperationName:\"Reset user password\" AND TargetResources.userPrincipalName:*@ecogen.com"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-5m"
            }
          }
        }
      ]
    }
  }
}
```

---

## 📊 Aggregation Queries (Simple Format)

### 26. Attack Volume by Platform
```json
GET aws-logs-*,gcp-logs-*,azure-logs-*/_search
{
  "size": 0,
  "query": {
    "query_string": {
      "query": "userIdentity.type:\"Anonymous\" OR insertId:*APT40* OR RiskLevel:\"high\""
    }
  },
  "aggs": {
    "platforms": {
      "terms": {
        "field": "_index",
        "size": 10
      }
    }
  }
}
```

### 27. Top Source IPs
```json
GET aws-logs-*,gcp-logs-*,azure-logs-*/_search
{
  "size": 0,
  "query": {
    "query_string": {
      "query": "userIdentity.type:\"Anonymous\" OR RiskLevel:\"high\""
    }
  },
  "aggs": {
    "top_ips": {
      "terms": {
        "script": {
          "source": "if (doc['sourceIPAddress'].size() > 0) { return doc['sourceIPAddress'].value } else if (doc['IPAddress'].size() > 0) { return doc['IPAddress'].value } else if (doc['protoPayload.requestMetadata.callerIp'].size() > 0) { return doc['protoPayload.requestMetadata.callerIp'].value } else { return 'unknown' }"
        },
        "size": 10
      }
    }
  }
}
```

### 28. Timeline Analysis
```json
GET aws-logs-*,gcp-logs-*,azure-logs-*/_search
{
  "size": 0,
  "query": {
    "query_string": {
      "query": "@timestamp:[\"2025-07-14T00:00:00Z\" TO \"2025-07-17T23:59:59Z\"] AND (insertId:*APT40* OR requestParameters.bucketName:\"rd-multicloud-config-temp\" OR UserPrincipalName:\"rdazure@rd-azure.us\")"
    }
  },
  "aggs": {
    "timeline": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "1h"
      }
    }
  }
}
```

---

## 💡 Dev Tools Tips

### Query Structure
- **Always start with** `GET index-pattern/_search`
- **Use query_string** for simple KQL-like syntax
- **Use bool queries** for complex logic
- **Add sort and size** for better results

### Common Patterns
```json
// Simple text search
{
  "query": {
    "query_string": {
      "query": "field:value AND other_field:*wildcard*"
    }
  }
}

// Range with text
{
  "query": {
    "bool": {
      "must": [
        {"query_string": {"query": "field:value"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  }
}

// Multiple indices
GET aws-logs-*,gcp-logs-*,azure-logs-*/_search
```

### Performance Tips
1. **Use specific time ranges** to limit data
2. **Add size: 0** for aggregation-only queries  
3. **Use specific index patterns** when possible
4. **Test with small time windows** first

---

## 🔍 Investigation Workflow

### Quick Start Investigation:
1. **Run Query #19** (Complete Timeline) first
2. **Use Query #16** (IP Correlation) to find related events  
3. **Check Query #17** (Service Account Timeline) for credential usage
4. **Verify Query #20** (Incident Response) for remediation actions

### Platform-Specific Deep Dive:
- **AWS**: Queries #1-5 for S3 breach analysis
- **GCP**: Queries #6-10 for crypto mining investigation  
- **Azure**: Queries #11-15 for account takeover attempts

### Set Up Monitoring:
- **Use Queries #21-25** for real-time alerts
- **Run Query #26** for attack volume analysis
- **Check Query #27** for threat actor IP tracking