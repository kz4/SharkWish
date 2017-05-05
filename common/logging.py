from datetime import datetime


# just for now until we can set up proper logging config.
def debug(context='', msg=''):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print '{} - [{}]: {}'.format(timestamp, context, msg)
