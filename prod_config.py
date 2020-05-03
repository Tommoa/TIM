import os

class ProductionConfig(Config):
    SPA_SECRET_KEY = os.environ['SPA_SECRET_KEY']
    SPA_HOST = os.environ['SPA_HOST']
    SPA_PORT = os.environ['SPA_PORT']
    SPA_USERNAME = os.environ['SPA_USERNAME']
    SPA_PASSWORD = os.environ['SPA_PASSWORD']
    SPA_POLLING = True
    SPA_POLLING_INTERVAL = 80
    SPA_TI_CONFIG = "threat_intelligence_config.yaml"
