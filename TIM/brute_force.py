from re import search

def gen_brute_force_query():
    # Define brute force parameters
    # TODO: Create config file to define threat identification parameters.
    time_window = "5m"
    num_attempts_thresh = "3"
    num_failures_thresh = "3"

    # Generate other necessary parameters for search
    threat_name = "brute_force"
    # Get number representing window width from time_window spl arg
    match = search(r'\d+', time_window)
    # TODO: Process and check user inputs externally, with exceptions.
    if match:
        delta_t = int(match[0])
    else:
        msg = "Time window parameter '{}' not in correct format.".format(
                time_window)
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
        | stats list(threat) as threat, list(start) as time,
        list(num_failures) as num_failures,
        list(num_successes) as num_successes,
        list(num_attempts) as num_attempts, list(username) as username by mac
        """.format(time_window, time_window, delta_t, threat_name,
        num_attempts_thresh, num_failures_thresh)

    return search_query
