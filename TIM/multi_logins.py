from re import search

def gen_multi_logins_query():
    # Define multi-login threat parameters
    # TODO: Create config file to define threat identification parameters.
    time_window = "5m"
    unique_logins_thresh = "1"

    # Generate other necessary parameters for search
    threat_name = "multi_logins"
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
            | stats list(threat) AS threat, list(start) AS time,
             list(unique_logins) AS unique_logins, list(username) AS username
             BY mac
            """.format(time_window, time_window, delta_t, threat_name,
            unique_logins_thresh)

    return search_query
