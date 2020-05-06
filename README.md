# Threat Intelligence Model (TIM)

The TIM is going to be running on a Flask server which can accessed via a RESTful API. It will be able to identify internal threats on the network using a model and leveraging Splunk's SDK. Some of the threats it will attempt to identify will be:
- Privilege escalation
- Example 2
- Example 3

## Setup

### Flask:
Firstly ensure you have Flask setup correctly using venv (easiest) or your preferred environment manager.

Follow this guide to do so:

https://flask.palletsprojects.com/en/1.1.x/installation/

### Config Files:
Next, ensure you create a file `config.py` in the root directory e.g.

```
class DevelopmentConfig(Config):
	HOST = ...
	PORT = ...
	USERNAME = ...
	PASSWORD = ...
	POLLING = True
	POLLING_INTERVAL = 80 # seconds
	# Threat intelligence user config file
	SPA_TI_CONFIG = "threat_intelligence_config.yaml"
    TIM_PASSWORD = ...
```

These details are the credentials to access your local Splunk instance. Except your standard splunk port will not work - you have to find your management port. You can find this under `checking mgmt port : 8089` in the terminal when you start the Splunk server. Default is 8089.

For further details about configuration, please follow the below link.

https://pythonise.com/feed/flask/flask-configuration-files#loading-a-config-file

## Endpoints
Currently the endpoints are:

- Protected:
```
/get_id/
/get_mac/
/get_latest_alert/
```
- Unprotected
```
/login/
/test/
```
You will need to get the token from login and pass it in the header 'x-access-token'.

Use any username and password = `Group1Password`

## Running TIM

#### For Windows:
`runTIM.cmd` is a simple Windows Command Script to run the flask instance.

#### For Mac or Linux (using venv):
Run these commands
```
. venv/bin/activate
export FLASK_APP=TIM
export FLASK_ENV=development
flask run
```


Currently there is only one endpoint - `get_id.py`.

## Development

## Production

If there are any more packages that are used, add them to the requirements.txt file.

To run the docker build on the server, run these 2 commands:
```
docker build -t vm_docker_flask .
docker run -d --name my_container_flask -p 5000:5000 vm_docker_flask
```

They will expose the server on port 5000. You can test it out by trying `{ip}:5000/test/` but replace {ip} with the correct ip address.
