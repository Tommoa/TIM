class Config(object):
  SECRET_KEY = 'dev'

class ProductionConfig(Config):
  HOST = "47.74.86.174"
  PORT = 8089
  USERNAME = "Group1"
  PASSWORD = "Group1Password"
