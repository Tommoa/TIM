# Threat Intelligence Model (TIM)


## Setup

### Flask:
Firstly ensure you have Flask setup correctly using venv (easiest) or your preffered environment manager.

Follow this guide to do so:

https://flask.palletsprojects.com/en/1.1.x/installation/

### Config Files:
Next ensure you create a file `config.py` in the root directory. E.g.

```
class DevelopmentConfig(Config):
	HOST = ...
	PORT = ...
	USERNAME = ...
	PASSWORD = ...
```

These details are the credentials to access your local Splunk instance.

For further details about configuration, please follow the below link.

https://pythonise.com/feed/flask/flask-configuration-files#loading-a-config-file


## Running TIM

#### For Windows:
`runTIM.cmd` is a simple Windows Command Script to run the flask instance.

#### For Mac or Linux:
Run these commands
```
export FLASK_APP=TIM
export FLASK_ENV=development
flask run
```


Currently there is only one endpoint - `get_id.py`. 

## Development
## Production