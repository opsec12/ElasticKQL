# Elasticsearch/Kibana Queries Guide

## Correct Elasticsearch/Kibana Queries

### Basic detection query:
```
network.protocol:"tcp" AND event.action:"connection_attempted"
```

### For high connection volume detection:
```
network.protocol:"tcp" AND @timestamp:[now-1h TO now]
```

## Using Discover Effectively

Since Discover doesn't support the stats command, you'll need to:

### 1. Use Visualizations Instead

Go to **Visualize** → **Create visualization** → **Data Table** or **Metric**:
* **Rows:** source.ip.keyword
* **Rows:** destination.ip.keyword
* **Metrics:** Count

### 2. Use Discover Filtering

In Discover, add these filters step by step:
```
network.protocol : "tcp"
```

Then look at the data and add more filters like:
```
destination.port : [1 TO 1000]
```

### 3. Create Aggregations in Dashboard

For pattern detection, create visualizations:

**Line Chart for timing patterns:**
* X-axis: @timestamp (date histogram, 5-minute intervals)
* Y-axis: Count
* Split series: source.ip.keyword

**Data Table for connection counts:**
* Rows: source.ip.keyword, destination.ip.keyword
* Metrics: Count, Unique count of destination.port

## Alternative Approach in Discover

1. **Start broad:** `network.protocol:"tcp"`
2. **Add time filter:** Last 2 hours
3. **Sort by @timestamp**
4. **Look for patterns** in the results manually
5. **Add filters** based on what you see

For automated detection of the scanning patterns, you'd need to create **Watcher alerts** or use the **Detection Rules** in Elastic Security if available.

Would you like me to show you how to set up specific visualizations for this nmap detection?