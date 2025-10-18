# High CPU Usage on Node

**Symptoms:**
- Node CPU above 90%
- Pods getting evicted or throttled

**Possible Causes:**
- Runaway process or infinite loop
- Insufficient CPU limits
- Misconfigured autoscaler

**Resolution:**
- Identify top consuming pods using `kubectl top pod`
- Adjust CPU limits/requests
- Verify autoscaling configuration
