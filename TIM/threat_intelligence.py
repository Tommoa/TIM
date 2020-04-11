from . import database
from re import search
import splunklib.results as results
import splunklib.client as client


def gen_brute_force_query(config):
    threat_name = "brute_force"

    # Get brute force threat parameters
    time_window = config['brute_force']["time_window"]
    num_attempts_thresh = config['brute_force']["num_attempts_thresh"]
    num_failures_thresh = config['brute_force']["num_failures_thresh"]

    # Extract window width from time_window SPL arg
    match = search(r'\d+', time_window)

    # Validate threat parameters provided by user
    thresh_params = { "number of attempts threshold": num_attempts_thresh,
                      "number of failures threshold": num_failures_thresh
                      }
    for thresh_name, thresh in thresh_params.items():
        try:
            thresh_int = int(thresh)
        except ValueError as e:
            msg = ("Brute force threat parameter ({}) '{}' is not a base 10 "
                    "integer.").format(thresh_name, thresh)
            raise ValueError(msg)
        if thresh_int < 0:
            msg = ("Brute force threat parameter ({}) '{}' is not a positive "
                    "integer.").format(thresh_name, thresh_int)
            raise ValueError(msg)

    if match:
        delta_t = int(match[0])
    else:
        msg = ("Brute force threat parameter (time window) '{}' not in "
                "correct SPL format.").format(time_window)
        raise ValueError(msg)

    search_query = """
        search * is-ise (cise_passed_authentications
        OR (CISE_Failed_Attempts AND "FailureReason=24408"))
        | sort 0 _time
        | bin _time span={}
        | stats count(eval(searchmatch("CISE_Failed_Attempts")))
        AS num_failures count(eval(searchmatch("cise_passed_authentications")))
        AS num_successes, values(EndPointMACAddress) as mac BY _time UserName
        | streamstats time_window={} min(_time) AS start,  max(_time) AS end,
        sum(num_failures) AS num_failures, sum(num_successes) AS num_sucesses
        BY UserName
        | eval _time = start, end = start + {}, num_attempts =
        num_sucesses + num_failures, threat = "{}"
        | where num_attempts >= {} AND num_successes == 0 AND num_failures >= {}
        | rename UserName as username
        | stats list(start) as time,
        list(mac) as mac, list(num_failures) as num_failures,
        list(num_successes) as num_successes,
        list(num_attempts) as num_attempts, list(username) as username by threat
        """.format(time_window, time_window, delta_t, threat_name,
        num_attempts_thresh, num_failures_thresh)

    return search_query

def gen_multi_logins_query(config):
    threat_name = "multi_logins"

    # Get multi-login threat parameters
    time_window = config['multi_logins']["time_window"]
    unique_logins_thresh = config['multi_logins']["unique_logins_thresh"]

    # Extract window width from time_window SPL arg
    match = search(r'\d+', time_window)

    # Validate threat parameters provided by user
    try:
        unique_logins_thresh_int = int(unique_logins_thresh)
    except ValueError as e:
        msg = ("Multiple logins threat parameter (unique logins threshold) '{}'"
                "is not a base 10 integer.").format(unique_logins_thresh)
        raise ValueError(msg)

    if unique_logins_thresh_int < 0:
        msg = ("Multiple logins threat parameter (unique logins threshold) '{}'"
                "is not a positive integer.").format(unique_logins_thresh_int)
        raise ValueError(msg)

    if match:
        delta_t = int(match[0])
    else:
        msg = ("Multiple logins threat parameter (time window) '{}' not in "
                "correct SPL format.").format(time_window)
        raise ValueError(msg)

    search_query = """
            search * is-ise (cise_passed_authentications
            AND RadiusFlowType=Wireless802_1x)
            | sort 0 _time
            | bin _time span={}
            | stats dc(UserName) AS unique_logins, values(UserName) AS username
            BY _time EndPointMACAddress
            | streamstats time_window={} min(_time) AS start,
            max(_time) AS end, sum(unique_logins) AS unique_logins
            BY EndPointMACAddress
            | eval _time = start, end = start + {}, threat = "{}"
            | where unique_logins >= {}
            | rename EndPointMACAddress AS mac
            | stats list(start) AS time,
            list(mac) as mac, list(unique_logins) AS unique_logins,
            list(username) AS username by threat
            """.format(time_window, time_window, delta_t, threat_name,
            unique_logins_thresh)

    return search_query

def gen_complete_threat_query(config):
    print("Attempting to activate threat detection...")
    # Construct threat queries for correctly enabled threats
    threat_queries = []
    threat_query_generators = { "brute_force": gen_brute_force_query,
                                "multi_logins": gen_multi_logins_query
                                }
    for threat, threat_query_generator in threat_query_generators.items():
        if config[threat]['enabled']:
            try:
                threat_queries.append(threat_query_generator(config))
                continue
            except ValueError as e:
                print(str(e))

        msg = ("'{}' threat detection disabled.").format(threat)
        print(msg)

    # Check if at least one threat query was returned, if not just warn the user
    try:
        complete_threat_query = threat_queries.pop()
    except IndexError as e:
        msg = ("Threat detection fully inactive due to user threat "
                "intelligence configuration or input.")
        raise UserWarning(msg)

    # Construct final Splunk query for detecting all activated threats
    print("Threat detection functional.")
    for threat_query in threat_queries:
        complete_threat_query += " | append [" + threat_query + "]"

    return complete_threat_query

def detect_threats(app, db, threat_query, config):
    print("Detecting_threats.")
    # Set up Splunk config
    HOST = app.config['HOST']
    PORT = app.config['PORT']
    USERNAME = app.config['USERNAME']
    PASSWORD = app.config['PASSWORD']
    service = client.connect(
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD)

    # Generate necessary search parameters and run search
    kwargs_search = {"exec_mode": "blocking"}
    job = service.jobs.create(threat_query, **kwargs_search)

    # Process results and write to database
    reader = results.ResultsReader(job.results())
    for result in reader:
        if isinstance(result, dict):
            if result['threat'] == "brute_force":
                for (_, time, mac, username, num_attempts, num_failures,
                        num_successes) in zip(*list(result.values())):
                    brute_force_threats = {
                        "username": username,
                        "threat": result['threat'],
                        "time": time,
                        "mac": mac,
                        "num_failures": num_failures,
                        "num_successes": num_successes,
                        "num_attempts": num_attempts,
                        "threat_level": config[result['threat']]['threat_level']
                    }
                    db.brute_force_table.insert(brute_force_threats)
            elif result['threat'] == "multi_logins":
                for (_, time, mac, unique_logins, username) in zip(
                        *list(result.values())):
                    multi_logins_threats = {
                        "username": username,
                        "threat": result['threat'],
                        "time": time,
                        "mac": mac,
                        "unique_logins": unique_logins,
                        "threat_level": config[result['threat']]['threat_level']
                    }
                    db.multi_logins_table.insert(multi_logins_threats)
