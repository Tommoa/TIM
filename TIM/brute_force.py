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
        AS num_successes, values(EndPointMACAddress) as macs BY _time UserName
        | streamstats time_window=5m min(_time) AS start,  max(_time) AS end,
        sum(num_failures) AS num_failures, sum(num_successes) AS num_sucesses
        BY UserName
        | eval _time = start, end = start + {}
        | eval num_attempts = num_sucesses + num_failures
        | where num_attempts >= {} AND num_successes == 0 AND num_failures >= {}
        | stats values(start) as start_times, values(end) as end_times,
        values(macs) as macs, values(num_failures) as num_failures,
        values(num_successes) as num_successes,
        values(num_attempts) as num_attempts by UserName
    """.format(time_window, delta_t, num_attempts_thresh, num_failures_thresh)

    return search_query
