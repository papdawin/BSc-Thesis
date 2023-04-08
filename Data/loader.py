import configparser
import toml

# config exported
config = configparser.ConfigParser()
tml = toml.load('config.toml')
config.read_dict(tml)

