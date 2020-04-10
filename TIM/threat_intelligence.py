from re import search

def gen_brute_force_query(config):
    # Retrieve brute force parameters
    time_window = config['brute_force']["time_window"]
    num_attempts_thresh = config['brute_force']["num_attempts_thresh"]
    num_failures_thresh = config['brute_force']["num_failures_thresh"]

    # Generate other necessary parameters for search
    threat_name = "brute_force"
    # Get number representing window width from time_window spl arg
    match = search(r'\d+', time_window)
    # TODO: Process and check user inputs externally, with exceptions.
    try:
        msg = ("Brute force threat parameter (number of attempts threshold) "
                "'{}' is not a base 10 integer.").format(num_attempts_thresh)
        num_attempts_thresh_int = int(num_attempts_thresh)
        msg = ("Brute force threat parameter (number of failures threshold) "
                "'{}' is not a base 10 integer.").format(num_failures_thresh)
        num_failures_thresh_int = int(num_failures_thresh)
    except ValueError as e:
        raise ValueError(msg)

    if num_attempts_thresh_int < 0:
        msg = ("Brute force threat parameter (number of attempts threshold)"
                "'{}' is not a positive integer.").format(time_window)
        raise ValueError(msg)
    if num_failures_thresh_int < 0:
        msg = ("Multiple Logins threat parameter (unique logins threshold) '{}'"
                "is not a positive integer.").format(time_window)
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
    # Define multi-login threat parameters
    # TODO: Create config file to define threat identification parameters.
    time_window = config['multi_logins']["time_window"]
    unique_logins_thresh = config['multi_logins']["unique_logins_thresh"]

    # Generate other necessary parameters for search
    threat_name = "multi_logins"
    # Get number representing window width from time_window spl arg
    match = search(r'\d+', time_window)
    # TODO: Process and check user inputs externally, with exceptions.
    try:
        unique_logins_thresh_int = int(unique_logins_thresh)
    except ValueError as e:
        msg = ("Multiple logins threat parameter (unique logins threshold) '{}'"
                "is not a base 10 integer.").format(unique_logins_thresh)
        raise ValueError(msg)

    if unique_logins_thresh_int < 0:
        msg = ("Multiple logins threat parameter (unique logins threshold) '{}'"
                "is not a positive integer.").format(time_window)
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
    threat_querys = []
    threat_query_generators = { "brute_force": gen_brute_force_query,
                                "multi_logins": gen_multi_logins_query
                                }
    for threat, threat_query_generator in threat_query_generators.items():
        try:
            if config[threat]['enabled']:
                threat_querys.append(threat_query_generator(config))
        except ValueError as e:
            print(str(e))
            print(threat + " threat detection disabled.")
            continue

    try:
        complete_threat_query = threat_querys.pop()
    except IndexError as e:
        msg = ("Threat detection fully inactive due to user threat "
                "intelligence configuration or input.")
        raise UserWarning(msg)

    for threat_query in threat_querys:
        complete_threat_query += " | append [" + threat_query + "]"

    return complete_threat_query
