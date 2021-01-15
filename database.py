##PyHSS Database Library
##Features classes for different DB backends normalised to each return the same data
##Data is always provided by the function as a Dictionary of the Subscriber's data
import yaml

with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))


class MongoDB
    def __init__():


class MSSQL
    def __init__():