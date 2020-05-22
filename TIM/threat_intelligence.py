from . import database
from re import search
import random as rd
import splunklib.results as results
import splunklib.client as client
from collections import defaultdict
from datetime import datetime, timedelta
from operator import itemgetter
from tinyrecord import transaction


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

    search_query = get_brute_force_string(time_window, delta_t, threat_name,
                                    num_attempts_thresh, num_failures_thresh)

    return search_query

def get_brute_force_string(time_window, delta_t, threat_name,
                            num_attempts_thresh, num_failures_thresh):
    brute_force_string = """
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

    return brute_force_string

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

    search_query = get_multi_logins_string(time_window, delta_t,
                                            threat_name, unique_logins_thresh)

    return search_query

def get_multi_logins_string(time_window, delta_t, threat_name,
                            unique_logins_thresh):

    multi_logins_string = """
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

    return multi_logins_string

def gen_complete_threat_query(config):
    print("Attempting to activate threat detection...")
    # Construct threat queries for correctly enabled threats
    threat_queries = []
    threat_query_generators = { "brute_force": gen_brute_force_query,
                                "multi_logins": gen_multi_logins_query,
                                }
    for threat, threat_query_generator in threat_query_generators.items():
        if config[threat]['enabled']:
            try:
                threat_queries.append(threat_query_generator(config))
                msg = ("'{}' threat detection enabled.").format(threat)
                print(msg)
                continue
            except ValueError as e:
                print(str(e))

        msg = ("'{}' threat detection disabled.").format(threat)
        print(msg)

    # Check if at least one threat query was returned, if not just warn the user
    try:
        complete_threat_query = threat_queries.pop()
    except IndexError as e:
        msg = ("Threat detection fully inactive according to user threat "
                "intelligence configuration or due to incorrect input.")
        raise UserWarning(msg)

    # Construct final Splunk query for detecting all activated threats
    print("Threat detection functional.")
    for threat_query in threat_queries:
        complete_threat_query += " | append [" + threat_query + "]"

    return complete_threat_query

def detect_threats(app, threat_query, geo_locations_intel, config):
    print("Detecting_threats.")
    # Set up Splunk config
    HOST = app.config['SPA_HOST']
    PORT = app.config['SPA_PORT']
    # validate input port
    try:
        PORT = int(PORT)
    except ValueError:
        msg = ("Splunk config input port '{}' is not a base 10 integer."
               ).format(PORT)
        raise ValueError(msg)
    USERNAME = app.config['SPA_USERNAME']
    PASSWORD = app.config['SPA_PASSWORD']
    service = client.connect(
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD)

    # Generate necessary search parameters and run search
    kwargs_search = {"exec_mode": "blocking"}
    job = service.jobs.create(threat_query, **kwargs_search)

    # Process results and write to database
    db = database.db()
    reader = results.ResultsReader(job.results())

    for result in reader:
        if isinstance(result, dict):
            if result['threat'] == "brute_force":
                for (_, time, mac, username, num_attempts, num_failures,
                        num_successes) in zip(*list(result.values())):
                    # TODO: Aloow extraction of location data from logs

                    # randomly skip threat
                    if (config[result['threat']]['randomize'] and
                        rd.choice([False, True])): continue

                    # simulate threat time
                    if config[result['threat']]['sim_time']['enabled']:
                        now = int(datetime.now().timestamp())
                        time_window = config[result['threat']]['sim_time'][
                                            'window']
                        time = rd.randint((now - time_window), now)

                    if config['geo_locations']['default_locations']['enabled']:
                        location = rd.choice(config['geo_locations']
                            ['default_locations']['locations'])
                    brute_force_threats = {
                        "username": username,
                        "threat": result['threat'],
                        "time": time,
                        "mac": mac,
                        "num_failures": num_failures,
                        "num_successes": num_successes,
                        "num_attempts": num_attempts,
                        "threat_level": config[result['threat']]['threat_level'],
                        "location": get_point_location(location,
                            geo_locations_intel,)
                    }
                    with transaction(db.brute_force_table) as inserter:
                        inserter.insert(brute_force_threats)

            elif result['threat'] == "multi_logins":
                for (_, time, mac, unique_logins, username) in zip(
                        *list(result.values())):
                    # TODO: Aloow extraction of location data from logs

                    # randomly skip threat
                    if (config[result['threat']]['randomize'] and
                        rd.choice([False, True])): continue

                    # simulate threat time
                    if config[result['threat']]['sim_time']['enabled']:
                        now = int(datetime.now().timestamp())
                        time_window = config[result['threat']]['sim_time'][
                                            'window']
                        time = rd.randint((now - time_window), now)

                    if config['geo_locations']['default_locations']['enabled']:
                        location = rd.choice(config['geo_locations']
                            ['default_locations']['locations'])
                    multi_logins_threats = {
                        "username": username,
                        "threat": result['threat'],
                        "time": time,
                        "mac": mac,
                        "unique_logins": unique_logins,
                        "threat_level": config[result['threat']]['threat_level'],
                        "location": get_point_location(location,
                            geo_locations_intel,)
                    }
                    with transaction(db.multi_logins_table) as inserter:
                        inserter.insert(multi_logins_threats)

    db.db.close()

def gen_brute_force_desc(threat):
    # Threat summary for brute force attempt instance
    description = ("Brute force attempt detected on device '{}' with {} "
            "login failures and {} login attempts.").format(threat['mac'],
            threat['num_failures'], threat['num_attempts'])

    return description

def gen_multi_logins_desc(threat):
    # Threat summary for multiple login attempt instance
    description = ("{} users logged in to device '{}' within a short space of "
                "time.").format(threat['unique_logins'],
                threat['mac'])

    return description

def gen_geo_locations_intel(config):
    if not config['geo_locations']['enabled']:
        msg = ("'Geographical location' threat intelligence disabled by user.")
        raise UserWarning(msg)

    # Construct geolocation intelligence info according to config
    geo_locations_intel = {}
    gen_geo_loc_rd = rd.Random()
    for location in config['geo_locations']['locations']:
        geo_location = config['geo_locations']['locations'][location]
        if geo_location['enabled'] is False:
            msg = ("'Geographical location' threat intelligence for location "
                "'{}' disabled by user.").format(location)
            print(msg)
            continue

        # Coordinates of bounding box encompassing location in lat/lon
        x1, x2, y1, y2 = (geo_location['boundary']['top_left'][1],
                        geo_location['boundary']['bottom_right'][1],
                        geo_location['boundary']['top_left'][0],
                        geo_location['boundary']['bottom_right'][0])
        num_nodes = geo_location['num_nodes']
        try:
            # Validate geolocation parameters provided by user
            try:
                num_nodes = int(num_nodes)
            except ValueError as e:
                msg = ("Number of nodes '{}' is not a base 10 "
                        "integer.").format(num_nodes)
                raise ValueError(msg)
            if num_nodes < 0:
                msg = ("Number of nodes must be greater than zero.")
                raise ValueError(msg)

            # Maintain static node coordinates every time app runs if set by
            # user
            if geo_location['static_node_coordinates']['enabled']:
                gen_geo_loc_rd.seed(0)
            else:
                gen_geo_loc_rd.seed()
            nodes = [{"lat": gen_geo_loc_rd.uniform(y1, y2), "lon":
                gen_geo_loc_rd.uniform(x1, x2)} for _ in range(0, num_nodes)]

            # Bias likelihood of threats to occur from one random node if set
            # by user
            conc = None
            if geo_location['bias_threat_coordinates']['enabled']:
                rd.shuffle(nodes)
                conc = geo_location['bias_threat_coordinates']['concentration']
                if not (float(conc) > 0 and float(conc) <= 1):
                    msg = ("Concentration must be a number greater than 0 "
                    "and less than or equal to 1.")
                    raise ValueError(msg)
                eq_prob = (1 - conc) / (len(nodes) - 1)
            weights = ([conc] + [eq_prob] * (len(nodes) - 1) if conc is not None
                else [1 / len(nodes)] * len(nodes))

            geo_locations_intel[location] = {'nodes': nodes, 'weights': weights}

        except (TypeError, ValueError) as e:
            msg = ("'Geographical location' threat intelligence for location  "
                "'{}' cannot be instantiated due to incorrect user "
                "configuration. The following internal error was "
                "raised:\n{}").format(location, repr(e))
            print(msg)

    if len(geo_locations_intel) == 0:
        msg = ("'Geographical location' threat intelligence fully inactive for "
            "all locations according to user configuration or do due to "
            "incorrect user input")
        raise UserWarning(msg)

    print("'Geographical location' threat intelligence functional.")

    return geo_locations_intel

def get_point_location(location, geo_locations_intel):
    # Gets the specific coordinates of threats detected in preset locations
    lat_lon = {"lat": None, "lon": None}
    if geo_locations_intel is not None:
        if location in geo_locations_intel:
            lat_lon = rd.choices(geo_locations_intel[location]['nodes'],
                geo_locations_intel[location]['weights'], k=1).pop()
        else:
            msg = ("Threats detected from unrecognized location '{}', or location "
                "is disabled in configuration. 'Geographical location' threat "
                "intelligence not performed.").format(location)
            print(msg)

    return lat_lon

def gen_statistics():
    # generate detected threat statistics
    db = database.db()
    now = datetime.now()
    past_24_hrs = timedelta(hours=24)
    stat_names = ['num_alerts_per_cat', 'num_alerts',
                  'user_threat_count', 'multi_logins_macs',
                  'brute_force']
    stats = {stat_name: defaultdict(int) for stat_name in stat_names}

    for table_name in db.db.tables():
        if table_name != 'default':
            for alert in db.db.table(table_name).all():
                try:
                    threat_time = datetime.fromtimestamp(int(alert['time']))
                except ValueError:
                    continue
                # number of threats per category
                stats['num_alerts_per_cat'][alert['threat']] += 1

                # number of threats in the past 24 hours
                stats['num_alerts']['24_hrs'] += sum([now - past_24_hrs
                                                     <= threat_time <= now])

                # number of threats per user
                stats['user_threat_count'][alert['username']] += 1

                # brute force login failures, attempts and successes in the
                # past 24 hours
                if (alert['threat'] == 'brute_force') and (now - past_24_hrs
                   <= threat_time <= now):
                    stats['brute_force']['num_failures'] += int(alert[
                                                             'num_failures'])
                    stats['brute_force']['num_successes'] += int(alert[
                                                            'num_successes'])
                    stats['brute_force']['num_attempts'] += int(alert[
                                                            'num_attempts'])

                # macs with multiple login threats and count
                if alert['threat'] == 'multi_logins':
                    stats['multi_logins_macs'][alert['mac']] += 1

    db.db.close()

    # only return top counts
    stats['multi_logins_macs'] = dict(sorted(stats['multi_logins_macs'].items(),
                                      key=itemgetter(1), reverse=True)[:5])
    stats['user_threat_count'] = dict(sorted(stats['user_threat_count'].items(),
                                      key=itemgetter(1), reverse=True)[:5])

    return stats
