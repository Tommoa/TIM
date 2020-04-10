from re import search

def gen_multi_logins_query():
    # Define multi-login threat parameters
    # TODO: Create config file to define threat identification parameters.
    time_window = "5m"
    unique_logins_thresh = "1"

    # Generate other necessary parameters for search
    exec_mode = {"exec_mode": "normal"}
    # Get number representing window width from time_window spl arg
    match = search(r'\d+', time_window)
    # TODO: Process and check user inputs externally, with exceptions.
    if match:
        delta_t = int(match[0])
    else:
        msg = "Time window parameter '{}' not in correct format.".format(
                time_window)
        raise ValueError(msg)

    search_string = """
        search * is-ise (cise_passed_authentications
        AND RadiusFlowType=Wireless802_1x)
        | sort 0 _time
        | bin _time span={}
        | stats dc(UserName) AS unique_logins, values(UserName) AS usernames
        BY _time EndPointMACAddress
        | streamstats time_window=5m min(_time) AS start,  max(_time) AS end,
        sum(unique_logins) AS logins BY EndPointMACAddress
        | eval _time = start, end = start + {}
        | where unique_logins >= {}
        | stats values(start) AS start_times, values(end) AS end_times,
        values(usernames) AS usernames, values(unique_logins) AS unique_logins
        BY EndPointMACAddress
    """.format(time_window, delta_t, unique_logins_thresh)

    return search_string
