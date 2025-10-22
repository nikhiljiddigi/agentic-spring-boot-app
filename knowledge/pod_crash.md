# Pod CrashLoopBackOff

**Symptoms:**
- Pod restarts continuously
- Logs show OOMKilled or missing config

**Resolution:**
- Check logs: `kubectl logs <pod> -p`
- Validate environment variables and secrets
- Ensure resource limits are sufficient
