# Threat Intelligence Model (TIM)

## Running TIM

### Development
Ensure you create a file `config.py` in the root directory. E.g.

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

`runTIM.cmd` is a simple Windows Command Script to run the flask instance.

Currently there is only one endpoint - `get_id.py`. 

### Production