require('dotenv').config();
const axios = require('axios');
const Coralogix = require('coralogix-logger');

// Global logger instance
let logger;

/**
 * Initializes the Coralogix logger.
 * This must be called before any logging can occur.
 */
function initializeCoralogix() {
  // Validate Coralogix Private Key
  if (!process.env.CORALOGIX_PRIVATE_KEY || process.env.CORALOGIX_PRIVATE_KEY === 'YOUR_PRIVATE_KEY') {
    console.error('FATAL ERROR: CORALOGIX_PRIVATE_KEY is not set.');
    console.error('Please create a .env file and add your Coralogix private key.');
    console.error('Example: CORALOGIX_PRIVATE_KEY=your-actual-private-key-goes-here');
    process.exit(1); // Exit with an error code
  }

  // Coralogix configuration
  const config = new Coralogix.LoggerConfig({
    debug: false,
    privateKey: process.env.CORALOGIX_PRIVATE_KEY,
    applicationName: 'Zendesk-Status-Checker',
    subsystemName: 'Incidents'
  });

  Coralogix.CoralogixLogger.configure(config);
  logger = new Coralogix.CoralogixLogger('ZendeskStatus');

  console.log('Coralogix logger initialized.');
}

/**
 * Sends a log to Coralogix.
 * @param {object} logData - The data to log.
 * @param {Coralogix.Severity} logData.severity - The severity of the log.
 * @param {string} logData.text - The log message.
 * @param {string} logData.className - The class name for the log.
 * @param {string} [logData.methodName] - The method name for context.
 * @param {string} [logData.threadId] - The thread ID for tracing.
 * @param {object} [logData.other] - Any additional structured data.
 */
function sendLog(logData) {
  if (!logger) {
    console.error('Coralogix logger is not initialized. Call initializeCoralogix() first.');
    return;
  }
  logger.addLog(new Coralogix.Log(logData));
}

/**
 * Flushes all buffered logs to Coralogix.
 * This should be called before the application exits to ensure all logs are sent.
 */
async function flushLogs() {
  if (logger) {
    await Coralogix.CoralogixLogger.flush();
    console.log('Coralogix logs flushed.');
  }
}

const ZENDESK_API_URL = 'https://status.zendesk.com/api/incidents/active?subdomain=globalization-partners';

async function getZendeskIncidents() {
  try {
    const response = await axios.get(ZENDESK_API_URL, { timeout: 10000 });
    const { data: incidents, included } = response.data;

    if (incidents && incidents.length > 0) {
      console.log('Active Zendesk Incidents Found. Sending to Coralogix...');
      const servicesMap = new Map(included.map(service => [service.id, service.attributes.name]));

      const detailedIncidents = incidents.map(incident => {
        const impactedServices = incident.relationships.services.data.map(
          serviceIdentifier => servicesMap.get(serviceIdentifier.id)
        ).filter(Boolean);

        return {
          id: incident.id,
          title: incident.attributes.title,
          status: incident.attributes.status,
          impactedServices: impactedServices
        };
      });

      // Send each incident as a separate log to Coralogix
      detailedIncidents.forEach(incident => {
        sendLog({
          severity: Coralogix.Severity.WARNING,
          text: `Active Incident: ${incident.title}`,
          className: 'ZendeskIncident',
          methodName: 'getZendeskIncidents',
          threadId: incident.id,
          other: incident
        });
      });

      console.log('Successfully sent incident data to Coralogix.');

    } else {
      console.log('No active Zendesk incidents found. Sending heartbeat to Coralogix.');
      sendLog({
        severity: Coralogix.Severity.INFO,
        text: 'No active Zendesk incidents found.',
        className: 'ZendeskHealthCheck',
        methodName: 'getZendeskIncidents'
      });
    }
  } catch (error) {
    const isTimeout = error.code === 'ECONNABORTED';
    console.error('Error fetching Zendesk incidents:', error.message);
    // Optionally send error to Coralogix
    sendLog({
      severity: Coralogix.Severity.ERROR,
      text: isTimeout ? 'Timeout fetching Zendesk incidents' : 'Error fetching Zendesk incidents',
      className: 'ZendeskIncidentError',
      methodName: 'getZendeskIncidents',
      other: { error: error.message, isTimeout }
    });
  } finally {
    // In the main execution block, we will flush logs after all checks are done.
    // await flushLogs();
  }
}

/**
 * Checks the health of the primary Zendesk URL.
 * It expects a 401 Unauthorized response as a sign of health.
 */
async function checkZendeskHealth() {
  const url = process.env.ZENDESK_HEALTH_CHECK_URL;
  if (!url) {
    console.error('ZENDESK_HEALTH_CHECK_URL is not set in .env file.');
    sendLog({
      severity: Coralogix.Severity.ERROR,
      text: 'Configuration Error: ZENDESK_HEALTH_CHECK_URL is not set.',
      className: 'ZendeskHealthCheck',
      methodName: 'checkZendeskHealth'
    });
    return;
  }

  try {
    await axios.get(url, { timeout: 10000 });
    // If we get here, it means the request was successful (2xx), which is unexpected.
    // We can log this as a warning or info, as it might indicate a change in auth requirements.
    sendLog({
      severity: Coralogix.Severity.INFO,
      text: `Unexpected 2xx response from ${url}. Expected 401 or 403.`,
      className: 'ZendeskHealthCheck',
      methodName: 'checkZendeskHealth'
    });
  } catch (error) {
    const status = error.response && error.response.status;
    if (status === 401 || status === 403) {
      // This is the SUCCESS case. The server is up and responding.
      console.log(`Health check successful for ${url}. Received expected ${status} status.`);
      sendLog({
        severity: Coralogix.Severity.INFO,
        text: 'Zendesk URL is UP and accessible.',
        className: 'ZendeskHealthCheck',
        methodName: 'checkZendeskHealth',
        other: { url: url, status: status }
      });
    } else {
      // This is the FAILURE case. Any other error (network, timeout, 5xx, etc.).
      const isTimeout = error.code === 'ECONNABORTED';
      console.error(`Error during health check for ${url}:`, error.message);
      sendLog({
        severity: Coralogix.Severity.ERROR,
        text: isTimeout ? 'Zendesk URL timed out' : 'Zendesk URL is DOWN or not responding as expected.',
        className: 'ZendeskHealthCheckError',
        methodName: 'checkZendeskHealth',
        other: { url: url, error: error.message, isTimeout }
      });
    }
  }
}

/**
 * Generic function to check ticket volume for a specific channel.
 * Requires ZENDESK_SUBDOMAIN, ZENDESK_EMAIL, and ZENDESK_API_TOKEN in .env.
 * 
 * @param {string} channelName - The human-readable name of the channel (e.g., 'Email', 'Web').
 * @param {string} searchFilter - The Zendesk search filter (e.g., 'via:mail').
 * @param {string} className - The Coralogix class name for logging.
 */
async function checkTicketVolume(channelName, searchFilter, className) {
  const subdomain = process.env.ZENDESK_SUBDOMAIN;
  const email = process.env.ZENDESK_EMAIL;
  const apiToken = process.env.ZENDESK_API_TOKEN;

  if (!subdomain || !email || !apiToken) {
    console.warn(`Skipping ${channelName} Ticket Volume Check: Missing credentials.`);
    sendLog({
      severity: Coralogix.Severity.WARNING,
      text: `Configuration Warning: Missing Zendesk API credentials for ${channelName} ticket volume check.`,
      className: className,
      methodName: 'checkTicketVolume'
    });
    return;
  }

  // Security: Basic validation to prevent URL injection if env vars are compromised
  if (!/^[a-zA-Z0-9-]+$/.test(subdomain)) {
    console.error('Invalid Subdomain format');
    return;
  }

  // Query for tickets created in the last hour
  const query = `type:ticket created>1hour ${searchFilter}`;
  const url = `https://${subdomain}.zendesk.com/api/v2/search.json?query=${encodeURIComponent(query)}`;
  const auth = Buffer.from(`${email}/token:${apiToken}`).toString('base64');

  try {
    const response = await axios.get(url, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
      },
      timeout: 10000 // 10 second timeout
    });

    const count = response.data.count;
    console.log(`${channelName} Ticket volume check successful. Tickets created in last hour: ${count}`);

 
      sendLog({
      severity: Coralogix.Severity.INFO,
      text: JSON.stringify({
        zendeskActualTicketCount:parseInt(count, 10),
      }),
      className: className,
      methodName: 'checkTicketVolume'

    });
  } catch (error) {
    const isTimeout = error.code === 'ECONNABORTED';
    console.error(`Error checking ${channelName} ticket volume:`, error.message);
    sendLog({
      severity: Coralogix.Severity.ERROR,
      text: isTimeout ? `Timeout checking Zendesk ${channelName} ticket volume` : `Error checking Zendesk ${channelName} ticket volume`,
      className: 'ZendeskTicketCheckError',
      methodName: 'checkTicketVolume',
      other: { error: error.message, isTimeout }
    });
  }
}

/**
 * Main function to orchestrate the monitoring checks.
 */
async function main() {
  // Initialize Coralogix first
  initializeCoralogix();

  console.log('Starting Zendesk monitoring checks...');
  
  // Run all monitoring tasks concurrently
  try {
    // Run all monitoring tasks concurrently and capture results
    const results = await Promise.allSettled([
      getZendeskIncidents(),
      checkZendeskHealth(),
      checkTicketVolume('Email', 'via:mail', 'ZendeskEmailTicketCheck'),
      checkTicketVolume('Web', 'via:web', 'ZendeskWebTicketCheck'),
      checkTicketVolume('Messaging', 'via:native_messaging', 'ZendeskMessagingTicketCheck'),
      checkTicketVolume('API', 'via:api', 'ZendeskApiTicketCheck'),
      checkTicketVolume('Sunshine Conversations API', 'via:sunshine_conversations_api', 'ZendeskSunshineConversationsApiTicketCheck')
    ]);

    // Inspect results to ensure any unhandled rejections are logged
    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        console.error(`Check at index ${index} failed unexpectedly:`, result.reason);
        sendLog({
          severity: Coralogix.Severity.ERROR,
          text: 'Unhandled Monitoring Check Failure',
          className: 'ZendeskMonitoringMain',
          methodName: 'main',
          other: { error: result.reason ? result.reason.message || String(result.reason) : 'Unknown error' }
        });
      }
    });
  } catch (error) {
    console.error('Critical error in main execution:', error);
  } finally {
    console.log('All checks completed. Flushing logs...');
    // Ensure all logs are sent before the application exits
    await flushLogs();
    console.log('Script finished.');
  }
}

// Run the main function

main();

