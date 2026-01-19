# Active Context: Zendesk Monitoring Enhancement

This document outlines the plan to enhance the Zendesk monitoring script. The goal is to add a new health check for a specific Zendesk URL while preserving the existing incident-checking functionality.

## Final Plan

The script will be updated to perform two distinct checks in a single, one-time execution run. It will not run continuously.

### 1. No Changes to Existing `getZendeskIncidents`
The original function will be preserved. It will continue to monitor the `globalization-partners` subdomain for active incidents and log the results to Coralogix.

### 2. New `checkZendeskHealth` Function
A new, independent function named `checkZendeskHealth` will be added to `index.js`.

*   **Configuration**: The function will read its target URL from a new environment variable, `ZENDESK_HEALTH_CHECK_URL`, which will be added to the `.env` file. The value will be `https://globalizationpartners1601484985.zendesk.com/`.
*   **Success Condition**: If an HTTP request to the URL returns a `401 Unauthorized` or `403 Forbidden` status, it will be considered a **SUCCESS**. A corresponding "UP" message will be logged to Coralogix.
*   **Failure Condition**: If any other error occurs (e.g., connection timeout, DNS error, 5xx status), it will be considered a **FAILURE**. A corresponding "DOWN" alert will be logged to Coralogix.

### 3. One-Time Execution Flow
The main execution logic will be modified to:
1.  Initialize the Coralogix logger.
2.  Execute both `getZendeskIncidents()` and `checkZendeskHealth()` once.
3.  Wait for both functions to complete.
4.  Flush all buffered logs to ensure they are sent.
5.  Exit the script.

### Visual Workflow

```mermaid
flowchart TD
    Start((Start Script)) --> Initialize[Initialize Coralogix]
    
    subgraph Run Checks Once
        Initialize --> RunInParallel{Execute Both Checks}
        RunInParallel --> IncidentCheck[1. getZendeskIncidents]
        RunInParallel --> HealthCheck[2. checkZendeskHealth]
    end
    
    subgraph Log Results
        IncidentCheck --> LogIncidentResult[Log Incident Status]
        HealthCheck --> LogHealthResult[Log URL Health Status]
    end

    LogIncidentResult --> Flush[Flush All Logs]
    LogHealthResult --> Flush
    Flush --> End((Exit Script))