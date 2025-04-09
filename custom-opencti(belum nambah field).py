#!/usr/bin/env python3

import sys
import json
import requests
from socket import AF_UNIX, SOCK_DGRAM, socket

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}

# Log and socket path
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7


OPENCTI_URL = "http://194.164.148.128:8080/graphql"
OPENCTI_TOKEN = "2e93abec-4d22-4e34-8e73-73afa582c6da"



def main(args):
  try:
    with open(LOG_FILE, 'a') as f:
            f.write(msg)
    if bad_arguments:
            debug('# Error: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

    process_args(args)       



    #results = query_opencti_dns("blackfriday-shoe.top.")
    #print (results)

def process_args(args) -> None:
  alert_file_location: str = args[ALERT_INDEX]
  apikey: str = args[APIKEY_INDEX]

  # Load alert. Parse JSON object.
  json_alert = get_json_alert(alert_file_location)
  msg: any = request_opencti_info(json_alert, apikey)
  send_msg(msg, json_alert['agent'])

def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled.

    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

def request_info_from_api(alert, alert_output, api_key):
    """Request information from an API using the provided alert and API key.

    Parameters
    ----------
    alert : dict
        The alert dictionary containing information for the API request.
    alert_output : dict
        The output dictionary where API response information will be stored.
    api_key : str
        The API key required for making the API request.

    Returns
    -------
    dict
        The response data received from the API.

    Raises
    ------
    Timeout
        If the API request times out.
    Exception
        If an unexpected exception occurs during the API request.
    """
    for attempt in range(retries + 1):
        try:
            opencti_response_data = query_api(alert['data']['mdns_query'], api_key)
            return opencti_response_data
        except Timeout:
            debug('# Error: Request timed out. Remaining retries: %s' % (retries - attempt))
            continue
        except Exception as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_VT)

    debug('# Error: Request timed out and maximum number of retries was exceeded')
    alert_output['opencti']['error'] = 408
    alert_output['opencti']['description'] = 'Error: API request timed out'
    send_msg(alert_output)
    sys.exit(ERR_NO_RESPONSE_VT)

def request_opencti_info(alert: any, apikey: str):
      """Generate the JSON object with the message to be send.

    Parameters
    ----------
    alert : any
        JSON alert object.
    apikey : str
        The API key required for making the API request.

    Returns
    -------
    msg: str
        The JSON message to send
    """
    alert_output = {'opencti': {}, 'integration': 'opencti'}

    # If there is no syscheck block present in the alert. Exit.
    if 'dns_query' not in alert:
        debug('# No dns_query block present in the alert')
        return None


    # Request info using OpenCTI API
    opencti_response_data = request_info_from_api(alert, alert_output, apikey)

    alert_output['opencti']['found'] = 0
    alert_output['opencti']['malicious'] = 0


    alert_output['opencti']['source'] = {
        'alert_id': alert['id'],
        'domain': alert['data']['dns_query'],
    }

"""
    # Check if OpenCTI has any info about the Domain
    if opencti_response_data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious') is not None:
        alert_output['virustotal']['found'] = 1

    # Info about the file found in VirusTotal
    if alert_output['virustotal']['found'] == 1:
        if vt_response_data['attributes']['last_analysis_stats']['malicious'] > 0:
            alert_output['virustotal']['malicious'] = 1

        # Populate JSON Output object with VirusTotal request
        alert_output['virustotal'].update(
            {
                'sha1': vt_response_data['attributes']['sha1'],
                'scan_date': vt_response_data['attributes']['last_analysis_date'],
                'positives': vt_response_data['attributes']['last_analysis_stats']['malicious'],
                'total': vt_response_data['attributes']['last_analysis_stats']['malicious'],
                'permalink': f"https://www.virustotal.com/gui/file/{alert['syscheck']['md5_after']}/detection",
            }
        )

    return alert_output

"""

  def query_api(hash: str, apikey: str) -> any:
    """Send a request to VT API and fetch information to build message.

    Parameters
    ----------
    hash : str
        Hash need it for parameters
    apikey: str
        Authentication API key

    Returns
    -------
    data: any
        JSON with the response

    Raises
    ------
    Exception
        If the status code is different than 200.
    """
    headers = { "Authorization": f"Bearer {OPENCTI_TOKEN}","Content-Type": "application/json"}

    debug('# Querying VirusTotal API')
    
    graphql_query = """ query { stixCyberObservables( search: "blackfriday-shoe.top." types: ["Domain-Name"] first: 5 ) { edges { node { id standard_id observable_value entity_type x_opencti_description x_opencti_score created_at updated_at createdBy { id name entity_type } objectMarking { id definition definition_type x_opencti_order } objectLabel { id value } externalReferences { edges { node { id source_name url description } } } indicators { edges { node { id name pattern pattern_type valid_from created description } } } reports { edges { node { id name description published } } } notes { edges { node { id attribute_abstract content created authors } } } opinions { edges { node { id opinion explanation created } } } importFiles { edges { node { id name size } } } } } } } """
    response = requests.post(OPENCTI_URL, json={"query":graphql_query}, headers=headers)
    #response = requests.get(f'https://www.virustotal.com/api/v3/files/{hash}', headers=headers, timeout=timeout)


    if response.status_code == 200:
        json_response = response.json()
        return json_response['data']
    else:
        alert_output = {}
        alert_output['opencti'] = {}
        alert_output['integration'] = 'opencti'

        alert_output['opencti']['error'] = response.status_code
        alert_output['opencti']['description'] = 'Error: API request fail'
        send_msg(alert_output)
        raise Exception('# Error: Opencti credentials, required privileges error')


def send_msg(msg: any, agent: any = None) -> None:
    if not agent or agent['id'] == '000':
        string = '1:opencti:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any')
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->openctti:{1}'.format(location, json.dumps(msg))

    debug('# Request result from OpenCTI server: %s' % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)


def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file.

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)



if __name__ == "__main__":
    main()


def query_opencti_dns(dns_query):
    graphql_query = """
query {
  stixCyberObservables(
    search: "blackfriday-shoe.top."
    types: ["Domain-Name"]
    first: 5
  ) {
    edges {
      node {
        id
        standard_id
        observable_value
        entity_type
        x_opencti_description
        x_opencti_score
        created_at
        updated_at
        createdBy {
          id
          name
          entity_type
        }
        objectMarking {
          id
          definition
          definition_type
          x_opencti_order
        }
        objectLabel {
          id
          value
        }
        externalReferences {
          edges {
            node {
              id
              source_name
              url
              description
            }
          }
        }
        indicators {
          edges {
            node {
              id
              name
              pattern
              pattern_type
              valid_from
              created
              description
            }
          }
        }
        reports {
          edges {
            node {
              id
              name
              description
              published
            }
          }
        }
        notes {
          edges {
            node {
              id
              attribute_abstract
              content
              created
              authors
            }
          }
        }
        opinions {
          edges {
            node {
              id
              opinion
              explanation
              created
            }
          }
        }
        importFiles {
          edges {
            node {
              id
              name
              size
            }
          }
        }
      }
    }
  }
}
"""

    headers = {
        "Authorization": f"Bearer {OPENCTI_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(OPENCTI_URL, json={"query":graphql_query}, headers=headers)
        data = response.json()
        return data["data"]["stixCyberObservables"]["edges"]
    except Exception as e:
        print(f"Error querying OpenCTI: {e}")
        return []
