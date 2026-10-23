import yaml

def load(text):
    a = yaml.safe_load(text)
    b = yaml.load(text, Loader=yaml.SafeLoader)
    return a, b
