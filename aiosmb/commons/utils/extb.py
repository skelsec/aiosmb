import traceback

def format_exc(e):
    traceback_str = ''.join(traceback.format_tb(e.__traceback__, 50))
    return str(e) + traceback_str

def pprint_exc(e):
    print(format_exc(e))