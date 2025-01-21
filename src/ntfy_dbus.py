#!/usr/bin/env python3
''' Ntfy messages to D-Bus org.freedesktop.Notifications service '''

import argparse
import asyncio
import base64
import logging
import json
import os
import signal
import socket
import sys
import tempfile
import zlib
from pathlib import Path
from typing import Union, Callable
import dbus
import websockets.client
import yaml

def min_string_length(min_length: int=0) -> Union[Callable|Exception]:
    ''' String length validation '''
    def validate(param):
        if isinstance(param, str) and len(param) >= min_length:
            return param
        raise argparse.ArgumentTypeError(
            f'String must be at least {min_length} characters long')
    return validate

def str_to_bool() -> Union[Callable|Exception]:
    ''' String to Boolean validation '''
    def validate(param):
        if isinstance(param, bool):
            return param
        if param.lower() in ('yes', 'true', 't', 'y', '1'):
            return True
        if param.lower() in ('no', 'false', 'f', 'n', '0'):
            return False
        raise argparse.ArgumentTypeError('Boolean value expected')

    return validate

def get_args(show_usage: bool = False) -> argparse.Namespace:
    ''' Parse command line arguments '''

    args_parser = argparse.ArgumentParser(
        description="Ntfy messages to D-Bus org.freedesktop.Notifications"
    )
    args_parser.add_argument('--topic', '-t',
                             help='Ntfy Topic. Default: none\n\n',
                             required=False,
                             type=min_string_length(1),
                             default=env_variable_check(
                                name='NTFY_DBUS_TOPIC',
                                min_length=1,
                                default='ntfy'
                                )
                             )
    args_parser.add_argument('--server', '-s',
                             help='Ntfy server. Default: ntfy.sh\n\n',
                             required=False,
                             type=min_string_length(2),
                             default=env_variable_check(
                                name='NTFY_DBUS_SERVER',
                                min_length=2,
                                default='ntfy.sh'
                                )
                             )
    args_parser.add_argument('--token', '-b',
                             help='Ntfy access token for Bearer Token'
                                    'Authentication. Default: None\n\n',
                             required=False,
                             type=min_string_length(32),
                             default=env_variable_check(
                                name='NTFY_DBUS_TOKEN',
                                min_length=32,
                                )
                             )
    args_parser.add_argument('--username', '-u',
                             help='Ntfy access username for Basic'
                                    'Authentication. Default: None\n\n',
                             required=False,
                             type=min_string_length(1),
                             default=env_variable_check(
                                name='NTFY_DBUS_USERNAME',
                                min_length=1
                                )
                             )
    args_parser.add_argument('--password', '-p',
                             help='Ntfy access password for Basic'
                                    'Authentication. Default: None\n\n',
                             required=False,
                             type=min_string_length(1),
                             default=env_variable_check(
                                name='NTFY_DBUS_PASSWORD',
                                min_length=1
                                )
                             )
    args_parser.add_argument('--loglevel', '-l',
                             help='Logging level. Default: INFO\n\n',
                             required=False,
                             type=str,
                             choices=[
                                'NOTSET', 'DEBUG', 'INFO',
                                'WARNING', 'ERROR', 'CRITICAL'],
                             default=env_variable_check(
                                name='NTFY_DBUS_LOGLEVEL',
                                min_length=4,
                                default='INFO'
                                )
                             )
    args_parser.add_argument('--appendurl', '-a',
                             help='Append server URL in front of message. '
                                    'Default: False\n\n',
                             required=False,
                             choices=['yes','no',1,0,True,False],
                             type=str_to_bool(),
                             default=env_variable_check(
                                name='NTFY_DBUS_APPEND_URL',
                                min_length=1,
                                default=0
                                )
                             )

    # Special switcher to show usage
    if show_usage:
        args_parser.print_help()
        # syscxits.h: EX_USAGE
        sys.exit(64)

    return args_parser

def env_variable_check(label: str='CORE', name: str=None, min_length: int=1,
                                default: Union[int,str,bool]=None) -> Union[int,str,bool,None]:
    ''' Check Environment Variable fits to conditions '''

    if os.environ.get(name) and len(os.environ.get(name)) >= min_length:
        return os.environ.get(name)
    if default:
        logger.warning(
            '[%s] Use default value "%s" for "%s"', label, default, name)
        return default
    logger.warning(
            '[%s] Use value "None" for "%s"', label, name)
    return None

def auth_basic_create(label: str='CORE', username: str=None,
                        password: str=None) -> Union[str, None]:
    ''' Prepare Basic Authentication Header '''

    # https://www.rfc-editor.org/rfc/rfc2617#section-2
    if not ':' in username:
        basic_credentials = base64.b64encode(
                f'{username}:{password}'.encode()
            ).decode()
        if len(basic_credentials) > 2:
            return ('Authorization', f'Basic {basic_credentials}')

        logger.critical(
                '[%s] Basic Authentication credentials are malformed',
                label)
    else:
        logger.critical(
            '[%s] Colon is not allowed in the username. Ref: RFC2617', label)
    return None

def auth_bearer_create(label: str='CORE', token: str=None) -> Union[str, None]:
    ''' Prepare Bearer Authentication Header '''

    # https://github.com/binwiederhier/ntfy/blob/main/user/manager.go#L29-L30
    if token and len(token) == 32 and token.startswith('tk_'):
        return ('Authorization', f'Bearer {token}')

    logger.critical('[%s] Bearer Token is malformed', label)
    return None

def embedded_read(label='CORE', pattern: str=None,
                    file: str=None) -> Union[bytes, str, None]:
    ''' Read Embedded Base64 '''

    embedded_data = str()
    if Path(file).is_file():
        logger.debug('[%s] Load file with Embedded Base64 data: %s',
                        label, file)
        file_extension = Path(file).suffix.lower()

        if file_extension in ('.py'):
            with open(file, "r", encoding='utf8') as file_data:
                recording_mode = False
                try:
                    for line in file_data:
                        if not recording_mode:
                            if line.startswith(f'#__{pattern}__'):
                                recording_mode = True
                        elif line in ['\n', '\r\n']:
                            recording_mode = False
                        elif recording_mode:
                            embedded_data += line.strip('#').rstrip()
                except StopIteration:
                    logger.warning(
                        '[%s] Cannot find %s embedded data pattern in %s file',
                        label,
                        pattern,
                        file)

            if len(embedded_data) > 0:
                logger.debug(
                    '[%s] Embedded Base64 data is collected', label)
            else:
                logger.debug(
                    '[%s] Embedded Base64 data was not found', label)
        else:
            logger.critical(
                '[%s] File %s does not have python extension', label, file)
            sys.exit(65)
    else:
        logger.critical('Cannot find file %s', file)

    return embedded_data if embedded_data != '' else None

def b64_decode(label: str='CORE', data: str=None) -> Union[dict, bytes, None]:
    ''' Decode Embedded Base64 Emoji Configuration '''

    if data and len(data) > 0:
        try:
            logger.debug('[%s] Embedded Base64 data is decoded', label)
            return base64.b64decode(data)
        except ValueError as b64_error:
            logger.warning(
                '[%s] Embedded Base64 data cannot be decoded: %s',
                label, b64_error)
            return bytes()
    return bytes()

def data_decompress(
    label: str='CORE', data: bytes=bytes()) -> Union[str, None]:
    ''' Inflate Embedded Emoji Configuration '''

    try:
        decompress = zlib.decompressobj(-zlib.MAX_WBITS)
        data_decompressed = decompress.decompress(data)
        data_decompressed += decompress.flush()
        return data_decompressed
    except zlib.error as zlib_error:
        logger.warning(
            '[%s] Cannot inflate embedded Base64 data: %s',
            label, zlib_error)
        return None

def data_try_as(loader, s, on_error):
    ''' Check what a data is '''
    try:
        loader(s)
        return True
    except on_error:
        return False

def data_is_json(s):
    ''' Check if data is JSON '''
    return data_try_as(json.loads, s, ValueError)

def data_is_yaml(s):
    ''' Check if data is YAML '''
    return data_try_as(
        yaml.safe_load, s,
        (yaml.scanner.ScannerError, yaml.reader.ReaderError)
    )

def data_serialize(
    label: str='CORE', data: Union[
                bytes, str, list, dict]=None) -> Union[bytes, str, list, dict]:
    ''' Serialize Data '''
    if data:
        if data_is_json(data):
            logger.debug('[%s] Data detected as JSON', label)
            return json.loads(data)
        if data_is_yaml(data):
            logger.debug('[%s] Data detected as YAML', label)
            return yaml.safe_load(data)

    logger.debug('[%s] Data is neither JSON nor YAML', label)
    return data

def dbus_notification(**kwargs: str) -> None:
    ''' Send Notification over D-Bus '''

    tag_list = ''
    item = 'org.freedesktop.Notifications'

    # https://docs.ntfy.sh/publish/?h=prio#message-priority
    # ->
    # https://specifications.freedesktop.org/notification-spec/latest/ar01s07.html
    severity_remap = { 1: 0, 2: 0, 3: 1, 4: 2, 5: 2 }

    for tag in kwargs['tags']:
        if tag in kwargs['emoji_tags']:
            logger.debug('[%s] Found known emoji tag "%s"',
                            kwargs['topic'], tag)
            tag_list += kwargs['emoji_tags'][tag]

    del kwargs['emoji_tags']
    logger.debug('[%s] Message: %s', kwargs['topic'], kwargs)

    print(type(kwargs['appendurl']))
    if kwargs['appendurl'] is True:
        message_body = f"https://{kwargs['server']}/{kwargs['topic']}: {kwargs['message']}"
    else:
        message_body = kwargs['message']

    notify_interface = dbus.Interface(
        dbus.SessionBus().get_object(item, f'/{item.replace(".", "/")}'), item)

    # https://specifications.freedesktop.org/notification-spec/latest/ar01s09.html#command-notify
    notify_interface.Notify(
        kwargs['topic'], # app_name
        0, # replaces_id
        str(kwargs['ntfy_logo_file']) or '', # app_icon
        f"{tag_list} {kwargs['title']}", # summary
        message_body, # body
        [], # actions
        { # hints
            "urgency": severity_remap[kwargs['priority']],
            "image_path": str(kwargs['ntfy_logo_file']) or '',
            "image-path": str(kwargs['ntfy_logo_file']) or ''
        },
        3000
    )

    logger.info('[%s] Notification: [%s], [%s], [%s]', kwargs['topic'],
                    kwargs['id'], kwargs['title'], repr(kwargs['message']))

async def wsrun(label: str='CORE', **kwargs: str) -> None:
    ''' WebSocket Client '''

    try:
        logger.debug('[%s] Connecting to %s', label, kwargs['server'])

        # websockets.client.connect is used until final obsolescence
        async with websockets.client.connect(
                uri=f"wss://{kwargs['server']}/{kwargs['topic']}/ws",
                extra_headers=kwargs['headers']) as websocket:

            logger.debug('[%s] Connected to %s', label, kwargs['server'])
            loop = asyncio.get_running_loop()

            # Gracefully close a connection on SIGINT/SIGTERM
            loop.add_signal_handler(
                signal.SIGTERM, loop.create_task, websocket.close())
            loop.add_signal_handler(
                signal.SIGINT, loop.create_task, websocket.close())

            while True:
                try:
                    ws_message = json.loads(await websocket.recv())
                    logger.debug('[%s] Got message:\n%s',
                        label, json.dumps(ws_message, indent=4))
                    if all(key in ws_message for key in (
                        'id', 'topic', 'event', 'title', 'message')):

                        if ws_message['event'] == 'message':
                            dbus_notification(
                                id=ws_message['id'],
                                topic=ws_message['topic'],
                                title=ws_message['title'],
                                message=ws_message['message'],
                                priority=ws_message['priority'] \
                                    if 'priority' in ws_message else 3,
                                tags=ws_message['tags'] \
                                    if 'tags' in ws_message else [],
                                emoji_tags=kwargs['emoji_tags'],
                                ntfy_logo_file = kwargs['ntfy_logo_file'],
                                server=kwargs['server'],
                                appendurl=kwargs['appendurl']
                            )
                    else:
                        for key in ('id','topic','event','title','message'):
                            if (ws_message['event'] == 'message'
                                and not ws_message.get(key)):
                                logger.debug(
                                    '[%s] Cannot find "%s" field in message',
                                    label, key)
                except ValueError as json_error:
                    logger.critical(
                        '[%s] Cannot decode JSON message from Ntfy server: %s',
                        label, json_error)

    except (
            websockets.exceptions.ConnectionClosed,
            websockets.exceptions.ConnectionClosedError,
            websockets.exceptions.ConnectionClosedOK,
            websockets.exceptions.DuplicateParameter,
            websockets.exceptions.InvalidHandshake,
            websockets.exceptions.InvalidHeader,
            websockets.exceptions.InvalidHeaderFormat,
            websockets.exceptions.InvalidHeaderValue,
            websockets.exceptions.InvalidOrigin,
            websockets.exceptions.InvalidParameterName,
            websockets.exceptions.InvalidParameterValue,
            websockets.exceptions.InvalidState,
            websockets.exceptions.InvalidStatus,
            websockets.exceptions.InvalidUpgrade,
            websockets.exceptions.InvalidURI,
            websockets.exceptions.NegotiationError,
            websockets.exceptions.PayloadTooBig,
            websockets.exceptions.ProtocolError,
            websockets.exceptions.SecurityError,
            websockets.exceptions.WebSocketException,
        ) as invalid_ws_error:
        logger.critical(
            '[%s] Failed to connect to %s: %s',
            label, kwargs['server'], invalid_ws_error)

if __name__ == '__main__':

    logger = logging.getLogger(__name__)

    # Default loglevel: INFO
    logger.setLevel(20)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s %(module)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    arguments = get_args().parse_args()

    # Redefine Log Level
    loglevel = logging.getLevelName(arguments.loglevel.upper())
    if isinstance(loglevel, int):
        logger.info('[%s] Set log level %s', 'CORE', arguments.loglevel.upper())
        logger.setLevel(loglevel)
    else:
        logger.warning('[%s] Unknown log level %s',
                            'CORE', arguments.loglevel.upper())

    if arguments.appendurl:
        logger.info('[%s] Server URL adding is enabled: %s', 'CORE', arguments.appendurl)

    # Load Emoji Tags
    emoji_tags = data_serialize(
                    data = data_decompress (
                        data = b64_decode(
                            data = embedded_read(
                                    pattern='NTFY_EMOJI',
                                    file=__file__
                                )
                            )
                        )
                 ) or []

    if len(emoji_tags) > 0:
        logger.info('[%s] Processing of Ntfy emoji tags is enabled', 'CORE')
    else:
        logger.warning('[%s] Processing of Ntfy emoji tags is disabled',
                            'CORE')

    # Load Ntfy Logo
    ntfy_logo_content = data_serialize(
                    data = data_decompress (
                        data = b64_decode(
                            data = embedded_read(
                                    pattern='NTFY_LOGO',
                                    file=__file__
                                )
                            )
                        )
                 ) or bytes()
    ntfy_logo_file = None

    if len(ntfy_logo_content) > 0:
        logger.info('[%s] Processing of Ntfy logo is enabled', 'CORE')
        ntfy_logo_file = Path(f'{tempfile.gettempdir()}/ntfy_logo')
        ntfy_logo_file.write_bytes(ntfy_logo_content)
    else:
        logger.warning('[%s] Processing of Ntfy logo is disabled', 'CORE')

    # Validations
    headers=[]

    if not arguments.topic:
        logger.critical('[%s] Ntfy topic is not set', 'CORE')
        sys.exit(67)

    if arguments.token and len(arguments.token) >= 32:
        headers.append(
            auth_bearer_create(
                token=arguments.token
            )
        )
        logger.info('[%s] Use Bearer Token Authentication', 'CORE')
    elif (arguments.username and arguments.password
            and len(arguments.username) >= 1
            and len(arguments.password) >= 1):
        headers.append(
            auth_basic_create(
                username=arguments.username,
                password=arguments.password
            )
        )
        logger.info('[%s] Use Basic Authentication', 'CORE')

    # Connect to server
    try:
        asyncio.run(
            wsrun(
                server=arguments.server,
                topic=arguments.topic,
                appendurl=arguments.appendurl,
                headers=headers,
                emoji_tags=emoji_tags,
                ntfy_logo_file=ntfy_logo_file
            )
        )
    except socket.gaierror as socket_gia_error:
        logger.critical('[%s] Socket error during connecting %s: %s',
            'CORE', arguments.server, socket_gia_error)
    except TypeError as type_error:
        logger.critical('[%s] Type error during connecting %s: %s',
            'CORE', arguments.server, type_error)

# In memory of Perl __DATA__
#
# Compressed emoji map in YAML format for Ntfy tags:
# https://github.com/ranfdev/Notify/blob/main/ntfy-daemon/data/mailer_emoji_map.json
#__NTFY_EMOJI__
#jX3pUhvLsu7/9RQ31v13b6yIvffa432ZjpbUSG1a3Vo9gOGXRzwhgcQkJM8GCQG2sTE2eIw4j8J+
#gHMi7gvcHKuqBfjcH9jKL6u7q2vIyszKyv7tt99++fOf/vR//sev//Ws9/bXX/78l9//SsT6y19/
#+d9/pp/d9q+//CY/O1Aky71W5FcDrxnU/Ijw3Xu//vKXuHYRv//rL7+nl+APfv3lnxU/Yqrz7tdf
#fPp19+g/T1eAqBC11MGffrXIiBy/QbLK1duh3zUmXgBRrQatnMgHXSKTtBYmMSH7W4DUGkEWzgVe
#xY9rfj0gxuQMGUXEF47xwiAN/cjLU7857y8QPMDbz9Qbfhxmuc93vDeCvwPAwxTeLca7nT++z5UH
#uuaFGf6X2cLfiJM2vWqUVGex/MoRQlCd0LfFsCmioFkJ8T3PB1tyyzpWi0tN4O8HYmHAdenirZuV
#Ah5Y5dca4Is04ZKqH3uZ30ycB5wiq9VIUsZWPgMd+3nShMKR1wj8lBvj4AYyqlCQKrKGVC1JU+dW
#E8TqAXdi9ytTKY+ll0QlkVP8A0EpN2r/OVFFGLlF3giYNQLu2v4YEa7R6mP67afVHOpqL/pIcFgv
#fOjbtFLUHN4h8FqtiJuljePpj8JPQxpR59s9oNN6ABfHzjWfEA0DLnIfiWZQ6qP3iKXJPDyuOjvv
#p1jV860b3FXEqCVFJQrgv/mYevpwilG0CD6wMBc8vFe6yTz0XlNnyfo3ZcwkqT5186NzAXReLYzr
#5m47J5cw+dE7HxxWFMzk9PS7LpjMB6lhLW1fYKVhvcG8vsMz6NMX06jXSBIa+Ev7Dovrc7hUgswr
#LG2Ucac5vlq45dZ0s3RFq1TTLcvLeCLOhxkPjvXblpEUcR6kU/w7yOeR2Nmj32EV5lwe1KBBUhnW
#gyFzZsIqipEM2FEU5nyLoUg34Gcqcc5vtPV+RcUZY/h2WTWIM5BhIkwsE4tnUMMww/b8X3DX89uv
#CEtiZ+68JyhNYr8oPW6AUztvRAG8gZc1Eq5d9xmiTZYKOO1AJnjZQrOSRCQBhlz5Au4Issep6mdB
#XQzlapEn0PTV2azhz/P7Y8m5pOrXEl4FUExd56fvo4BZDNKKH15zZSxIOl4M7r6j51f8Crd09yMT
#XiXJc53gXwWrNkKSsSA0dgQybwLvT8WkwPo2EbJS7K4hVVMxNnpBZDOMcymwcoqICr3dt0TVAYDh
#5IfcesM7hBZBnsNyk8LE48KbCDf8pi/LwpjFMWCpH8YWe40YSXMvA6FMi8tgU14/qnlNaaDuHnXn
#6L3g84nhTFwOdDR1Mz92csRgIm/UuS90Dk15naCtY32YoN58mDegVQNeufpd4UOTcld22kjGvsjR
#9jKRdfzDC258lQvieuTXgqxhX3ZC8DW+zf4GUdwzKyMkUniszru1h4RAjyROE44Z1JWHXicLRLs4
#H3wnejaQKfBZSaN+rNxwIWnd8+EZTqsb7fPtW1J3U0Lb2SlzQ8rwQ0b36De/5fAGE3nBA3l4k2iY
#vjyQ1x8BHfjVhlc0YbDoergiHQ4LMg/kL0zUQN6AUMuk98brBM/pgD1AksfbcEXuwJNj9Qn95nLt
#z0xwM7bp3oFOo30cNkE9jGMpvY5DJgDtpXCa/Tth9bBoWmyfsHAxsNAPgkRmrzMBL4CCmfWMLmON
#pOWZgsOOVD1258VbQnIeKu13SKVNs9yPeWWuBNAWOB91MI9BsFcahdHcxiyeQMNaqEYqiAcfEJkV
#9ek9Ebha6oQafHCHAvPsdBPuDcsNeRqibAENB7qs6re4Ni8RShr+oqzg/VdyVcq9tjoiIm/URP3s
#3EJA+3sEqkQFtOlZuKOoRffx4YdDg4ewcrHMOFBsJvLrPKo+KGQ1vc0dxa4ls9Irt1cUi1BD8jJU
#m+im9kGgzkPn85LsFNj6Pl3AskQMEDcOcT6cP+452PS9NvddJsFepchVGK9jR0UJqNsNUMQDRzK+
#c7vLLeFMne67KZ4jP9+5HYplgp9wsyzhObD8lej5mVAk3CquH1GBgzFhobbWF6Qq83qwLYDtkJ5C
#piH+69mzEWMw5EU3hamzSpg8q4/CMVFpsUUEaT3DE/wdhXOhM1NwHCRNlki9V0jE/KARcbS2m0w0
#/VRWSwfwcr/CFVnrMirUgChukt4uEzAnYx6C+7cJ4Vft4nRIMlCv4f3TxaCezBldHKuJb53k2bzv
#gtjKoKJVcRL+VGSXCpme53LT7KuFelL8Ucjq0Vsleg4WVFcnw0qhCE1Yz9m+R789tANJpeSpd0ao
#K1W275VqO1+WKsLVWsxHvApnLV25d18xHkrLdo6Rvo53qUfJHPfnLg0L0ZmwOY2uMX5O1GIY2bf4
#hJAqLO2nTIHBPxMENX3MDs4bUuz4NkziDMHqzQVyv+6RW30oAGLEz2HaszIOs+UB4cFM1Rcdu/eV
#EFCPG14Y10KwXpNqAP/mOOrzRFbMe29kAEvRuTCFxapscn9h46+SJtUqjH1uCnp9kHGxO9nWCZTh
#Oj4jCgwvI0Zh7u0oaC/b6SjmTlIUuGkRB6FtUeyTooJGXx7wGB7jgl9UVSPZx14suGlXUbiCTUyW
#GuikoFUXYO2q7snmC1j6Mm9fEFH3U3dmHxIIOl+OPe3NgP4va9zdMieDPmMG6qtFCsuW7834WWLv
#dUAMbHrusbdEF9A1tswbxLjVB8v0O4yDLPOyIszBKpsLcz/XobPxQd4gA1OFF8QB0zChsEagBpDa
#zCNoh1nZZTyUKwVqUdym95WciXiQjKCVq341l6otnyApC3z7CIkoiGsiLteWCABJAnJYp/XONoNa
#+bX3SIPKW9PmPmJlHUCxB1YPmBIvydonJXEFFjm9diqgTuN7e6y5ANjSZ62w3VsFuaf6zR6LQ4TS
#hfJgf8M2YRVNBnLXbNPLxzUZwBtv9W41bpz2IVExLHozSSLmCdU9Fmtw+BGpVgDzOZVhQjX4QjD0
#aeRZ/9tzAkEkJCmJ0O0uArK+bdFveFAYWaVs67bUCBgw0wNG1+65kFeDJaumOurWLb0irFRQJsRB
#DkuG0wpj9gVBiaTIgshrJKnIlQ5VMG2B8ghNl4k5uj8gNJWlaHeDyHy+EQSmz3eos0TReke//yJa
#FxILIKvLXXHEmrG0TA+03yo+FZtrhv1xadAqKlFYtW2KDR+AggqjL7L+sH3p74ZI43tnbC0BEMbk
#nBqucZOg+sJv1CWq2fLrspq3vxOisu5MKBbV6GRBR1Lm5Wkgg37tQalI0bpQAF8cDcEAVSarWN4k
#OJAWH98g0uoq7Z4AYLC7GtMpwSAuWj57fLafyUsFWR6L32IZ5yua9OLxXF0nOuIajXtCQR29ago3
#194bnDLHGb/vCGk1CzEyV3/I4xJYJny012Xctg8IbWW5Wel2XyKUgs0AJnxJAdhjB69lQnvJ0LuD
#cJFWG9RjYCCByhE0uY872L+wzhRwQSBSukNFchimRZyq82n5ngUzWTeWlxjLcJpyH7CTrsqyaAkH
#QwSDgafPY+GJHdIVQs2wziHR0HboBtY1iG87lEvDZkWx8ZYFjDoz3nLUGcO1Co3wbyg/nmVVBZ4q
#o2T3FjFaqMfKcHvECNQzn/KEYaOjVEc3HW9PbKwqyTsaG9uG/l2QXUXkioGhtcRIEZ7oG0NDa4mx
#Igo8FkCu6Cqp/CcC/M5kT0nlPxWAt1421pRU/jMB/sbkupLKfy7A35ncUFL5LwT4B5ObSir/pQD/
#ZHJLSeW/EuBfTPaVVP4OARnIA2s5bBgMi7I0mQ3E5bFqmCWfxzJ1f1KwYXxTxgnQfHmEqmOsQ3B5
#ciWfNG/Rc8+H96fLGQ14eTzNymLR1pf3lAUq3owvGys71JJFhfcG2HKvOqs4KHvVRJaLMQ41ePU0
#8au88u8fM5L7oiK3TwlIVM7t8iVJVl5T9mR5T2ZmSKqc9zeY4hccsFu5mshb7eOoT6KarfbuR0Gy
#+UBq1z8iKAoz1S579PAIjMLQ0Tg+INgkkXPevyMPaiZp4qx37wlrwTTmF3/NdKHKWe+LBbwmLs4E
#b76T28UzoNaFnt0PfMgo2Gc19WVvMgTXCkBNENcTD02YRX8O3Sy22ofKBRGTNfzMeaMJs1I/R+89
#vD3W+t8Pt7QyZZ17MC6DIM5SdZJ0P13Ks16IT648vKSg41L45IpG0NjTJPJm40QM7M5QGXNBHAbk
#GQZzSMQ+rhg678TF3z5m7OJAOmJGKPoBXysrBgomUcu7b+j3gu6d/IfMNtbwYH7gcpdkoLSkZjNu
#jw3IagLLKOhuSZg6PUL3K6oNmptmWRo+ktsWuknXPVCSZ6RjqXUv4WBjlx3i50922IBH+rIrqNW9
#kqv8//OaKQe7e9VEr5oNZRr0Vlzop/XsPZp6tLni6idefs1/V0+9iqrLkm6VemZe1No7RFSSBbCD
#ckfw4RKTyr786AYRCzJFNtvch6APgsVX1ZW7d0wYbmJBL6mxs4zCCZ0HosWMtgzt1cEq4hFNtwNB
#qpLotYwssObB+pKRsvqQEHht3SHeXSUkw4UFhGNdbYedpw4OGqtMqmWLZjAjaZacD9blbXgHEtoK
#h53uWr+k32Sdu83T/0F4hmaREWPr2LBmU2+Pd8qqRRWWPBEguzjhipYsPWAlcI/s7hBszNXxTaJD
#aVdcfovUr/qJvfNXwtBsQcEgyv/uMqMLF9yjsnH0bop/cQPJlIgSEgznT48IAVW7uuAF18FUiCWW
#osdlpaXaQ6JQFXdGEYplMOh1iLTfMJ00uUeGt5HOvWQGTCFZqHZxqC7AOiwvtYyDb6FltiL2xOBa
#DEC2XLStoGNqfl3387Z4U7qmhjLU+raSfL/uW6ZJr9UAi7eOHFcmtFWZfUPZddmgeIFUOos6u6vj
#bnyUgrqZTE8U50BvDwnxcazdBUJE6IR3V2qBP2P1bdfZSRx3Y0gxR/923Zq1oBrWiqRwbJXlY4R1
#J2kZidh4fqkGR4i1oOZNnNTOEnSIDFDkwipu8+sKvzKQR2WBvOzKYwdxtfmVJ8qYzZOWV9IfNneF
#lwewfIpfc4ODG2qh30QXPizyLZHYPhi26E4y/q3ec1OOFbeRXBqAglD306obWoNvEmZgGIE6lauy
#8bQMevimwZxyd4mLYSuBq3SdIjzHBlLGjbiDwzFc8O0CuL+OyOIiz5regVCOaAETp3YtrCRFHtpa
#4pgRl/gYa5x4MbxzFBqH2ABLJLLRPtpBQlyMH+m3iPsNJED9lslwwqTIxw5RrYbolav0oGYYmwV/
#wsqfgtO+jQnrj7UkkTrhAE6KekP13fYEAe3Qh9wrqV+XIbz6QEnbHKv4PFhVZLZuIZVgYFm64Dl+
#uH3Ck6gsfnYIbaF8qUTq95qcMhqpj3+MtOxq7oLorRUSKjBaQqLZMt6hXTDManNiqIJcCn5rqmq/
#BncJ/LosVaO7SInWeIt+YyVg3ZOZ950xo3GQESMCf/SFmDiyZ4yytdw2IAd6iZuzY+BMRvUyNGpQ
#Lfya9AI5lkDMBHV5iQH9xjA26ZUlBBYkmo6KQ88Hogj+U6NNCPB0RsgWXU4vef6Y/bxcJGsls1DC
#iVg5f8wBBsE1mNB2Q+98hXesAwycieZsjU/Z8RhEUBze1WtF4i9fXya01TAxYn0C5vxcrh1uITDD
#M+UJ/bby84kjP5HhiMonjqgMyr0qEmsd2w0lu0qwD//3+c0x/L2Ev134eyP0Dyw3F0RJi8MEH/BN
#BRKZZbaJ1mBOBH8U+AIYQQRSJZZ9g3uH7OCEVgSR7XgJQTOStYXIUyQxEsgpAvMhyBth0nLBMwAL
#S35GMmWJ0fvIRAs9rTC4NDQAYxYN3gL930MzVEbxyo7DLGI1oczN54K0DmtN7Kw4MJtBiQBp6IvF
#df4EO+x6K0poD6She1E7bwnGmQ8FIxUAfVDOggWxHNhhACQMuQDVAd54sUzSabb2tJi7KnfXCBIC
#5jJKDVBwGr6Z7f03rELvCTOMPfIcSE0+Enf5gO5OBXQ210oxpzsbLjtrhegcNo/un/BDDtxC6Ohu
#ohUuwn2nx9yWH7GY2hkJUMTia+g+JMTsma28NrRrwoq5yNxQyo4HQtmZMnBmCrOcuTJw5sqMH/kz
#IoXHS0TPXgyIPWBdYgZjk2IvAjWFJc8txJqhbOF095UkW8jsYrL22h1Ncy+WuKxgPUyjUqnxBfaF
#G42vutEld7vsppdV/9K3uOpNfvZCl77Upe925fv97DWvftWfvTEbotPPmVz2AFP0yuJXX3WhTpOr
#K3Ppm09+8ubOZVc+Z/pxU+994YUvedmr3nL6DS+82mWvddX7XPouP3+Jy1/lije6+r1+/npXvOQV
#7/qTN/75i//s9S9phbRZlo+onwGaBBfF2AfkYISEDcpemSAmW5pge8yARjZT8EP7e0SjRGf9/yPS
#onqu4mNA28DQ8YvGjitluVAW1nnPTNEUFCyPNjBZg3/BILbU+ZB1spkwiGpgo1XVGb/SRfBaaF/p
#LQIRhihVQPngqm3dkasBn0mimlR/7SZhTa+VJqjMida19k1LN9GvEbKt03kqaGw3cQ7YNTijvsL1
#XSY8UK1CMfkHPcWuYyQBHQ+Q7nnLnGrqV82StsfYDCqf5W7UG+ECKDbOEiHQfxjFwf5p9VStXcbi
#BdmYFMtDLKTRXs+Y8GygwS4jqMq0Emg6XAlN+c4r4pJv/fFD/q1x7LCmDwVJ4ioaWHW7riOa+iH7
#wu2lqQmt2XmMEA2ev6m+7ji+VojCe4p9OCEga0TmDusjgnIbH777gxEbH3SALRSBxgejFWxPdp+x
#gT9Dd0K1NpyTMz/DQwOzD6GQLh8eEMNsRa5SwaTVWvBqoRjOve+E4bkDMFTEAZfKPOzgHMQ4ODXI
#j5Hm0b1/RL/pWESYsWG6u2KwzC/UEzQEvXlGjGTV4pJ6nW+zjOM8iWsFV/kAdTiNYRt9ZMIGFN9n
#oAVmXC4aJXYAjDoaALNxOCPj4wPBeRHDbLNe+V0UGngIQbew3lvaa4nbafOR1LHA+v/VdDPQpFGh
#cqphwW1UaJPrdtyOcMykdgp+QhIsyZrXCqumZzY5XnNG1fWlNSJAx0S7xMTkHXIMg3BgnC/EgVqf
#905KzCwpUPTZiC6ND6DoBioXQiXUNsVtDEayRhqKy6S9w6AEFuCkS9W5cUrEvNkk7I8soG9/3j+T
#1xLcBNy1XS1XuY5Pbbvt4E6gXtsVzWxRbeIIKYKoVVCtz4ffkMYIIyNfNhxkWqw8QV4coGlQcEzN
#gHfL6n5FzapDDhCp+3bH7pAdMuhIh+EuEQgEpOqVGd8BsmKLw3pXZ9fE+YDjB+qBhG526DcHM59v
#P0QqlpuOnwplTYSnTuMxyzERnjotVA+StO7WGNR8PF3nIK8RSSQ2uwumfz2sQFvk4kKhMm8QFVnZ
#ucmEu1v0BKHUn5GpNuoRLUs/vnWUVMS+Qg8KRhuKD2WVmHMywMYw3OoJdIQuhbt3CZAlGwuDmIg0
#guEb0uRwOB8e828TSLHM78+QaTmC3cYTvm0+W0JaEOaN7pmPYEzWU7+l0+EekmD9BralPjEUe85R
#uBXF7I79lkJu6ONLBZ2WHSiWgbEnwWPmYjccciKgXe4POQQHUBvYdsibsoDRjkLJGbAh+B9FkBlw
#HcGw6VfNLD8khBurf5MJKwNA+NULvxaAsd5ymuWE4KYFPhOg21e3hMq0F3q33E4ilu0iYd5QZo4a
#mvOCZ4iC4MtE6yIQq11g5Kw6Z0dvCCl5fI4V8iq41VVYzlfi6KTonCIpgfEH+HuhNKdgBcVtnqr4
#Xnv3DG1GYs+NR1am845uQDKw1SH9mt+vgYdQU91qaa8Toor0+p6StAS2+HzW+aAnNzOceVooeEV+
#rsxMFblVek7Mes8j/u3hModxBXLgZuc14xUJTes+VtqNAody3xnPGqqu7TwhRDXj3gRJUtb+py6v
#DT+vNvA8hz1htisoKSUWxsKgKbUaSSxzszNmyO7Q7Y8IiUAGTTtlzgccAorzzosTL5gTH+T2AwZr
#XrNaS2I8+FUySl7zGqDzlTd/hQbNq5qkvolu6D1ThnVAtV3InDLpf1EYvfGsrTv7yqi2E7ui+3a9
#NUFaRaTh3VsC8S7MrtZrboGPlnmy2XT+eN1h4R4KnYJUa+fplmHR1oUy4AHvlePIEXPXJ+Y6eb8p
#WfPKeSisekVmn7hp8CLKwxaspXzr61TbTefCVuRet4FwrR40dH7jpMBdsqRlNmpuIpTyirwMOnYj
#hHmuZ96XPyNQb3gVUu5j9XuuLwlubL3uc0Qoos6crtjFER6C1grqVlNF/xArBdp20kpyvynPGYGx
#ATZhg+2B9X2kNHiYffUN1H5T3xlkxwSCcG7J49pvBXGPnAFQ92YTkcV04RGisursUxEN1F39IBSY
#N0a6r6CkSjIKOmYAB1vibL/vnjDgHCtb/ii1zlW2Lr8mUpprZY+oDHX0Oo/HPbkCZFjEsUzny0MH
#8NAAYaOBBdAKtYDZ7HwuFOsUdTyqJ8v3C+Fw463weelGIebYDo7LIoYLFmwbYb87Fg22rAjuIQzG
#sAr2AthhvHi19wQpKqKdPWTAtfJ7DGWzvLt8PjylWgDm3GhEgF2u3/B2gmxELa3jzyBBdaPh+bU5
#PI0vXu0HoAepgt6FURzGeGw0T+UQ29ouQmzHes5uCHCw8rEJqX/DAwuQxDEi3rCKEMagGIU5uTO2
#v3P9Y7CfZKLj5rEr4Hs3y3wwPlK2AO6cycVxUtXA2/49BNAuSfTY6k3eqglJhnNtQXkBpTK21fpE
#wB8W+IjAVBvCfAIZHVBgg3vxe8RTX8YkQfiA3JKw3oWL/qxPe8ZYOxlSoChcwx23pAR3biPc9M0O
#7Vt+yDW/JY/F03lEBVlQ2th56+D1pBKJNtX97ODQ87KbAtW6FqjC3N1EKjWqzVt+42thXUPtx9B5
#15K0pu/+lh1n18SH179Fv+1ic0Y0hV6zDOL+utayl8OUv1bUZPTJismC+FoB6viU5bYDd5z1fQnG
#2XiEFM44Ob486iMA7dywGT6OOHpkNogXnOMe+4hIFGuXfmus8rmEjAJU9VsY0M2lYImdDXFvFAx8
#FfrDDwg2k5gf38XHh2lY8VWlOmIDxwaTPWLC6LRbhrat9s3BOLrWruoDy7OafL9v0awZUqPZS7aR
#KaEo+zeRmA+9mbSQ4bkLkns25rMS1grsOBqk4bphKR0HdwzEjqNaWv8ILkSzsSwv+2CLzCaqVa/u
#ITXLDXgfq5dkyZyERH3jVWY2ta0J83S2mPd1bh2x/jy7kNYXFsudDlp55Fc8E8i7+5UAXTg+UR0j
#n0PHuEQbgZo6RfcfE7ngOWeqV58iVp7Aka9RtO/YlOeztnw81Npg6ycljkSyMOuTshI8XznF/IjM
#S12bW5dwpl0Q9BJ5KEcqSNF5Iq+em6Ok73hnPvKLesOMTdBN0AG14JHxxy10SJja1O3bSIKYVV/G
#O/ZERIFJvbDWQxJM+qig/Ao8b+4KmKp7kXbNz5dYYSTWxb1f2fFFLp9m4eQgvD2rOUkmUkYUNWzz
#oCnVaz9CKqFlZ5l+ttRMXKWXzZJcVCd6k1PE5jCMIQp1UHQ4FioKKzaVzzselxE6N+jmHSIWHPZ3
#ROB9QJyAERQ6zYUDiFoh1eiEwX2E5GDLOvax6vmjm0i0RFzfYcJI1x4BeaOwqYje8dIThYv6oiOs
#G+rLTIFwiJKKsctGOLwTTanRY4JbGCpkfJbr2AIYdd6SMOP2awTQOasRN/t9RCTY8Af+prXbyfIx
#/kAo6NmtJAuNLTPuT8NWKvUdqTRVxpFBfUcG0ZGADCPQueIPGYLB5auZtvYSsTlUs4xWOREID1lq
#hOGyYAtJ4dWDzHhXd54hY/6Cao9j3Bnz42OkY1EWD7Ani+tBs4Jqqe0sWKbZo22jnUDlwiY9X+P3
#bvpVdR685+UXkKBm40Tes9Bs+jW/7md6fo/gQ4Ql5KZNv53NhvUOIVLbbSZs2287bU8cp8W3nRYH
#Xlj15lVv2r9DkDrdxu+RbFxTQ+IGscNIDxSuHRhaFj+G9y3Mrj4TynM4xQEb2zJfIzPy50PbBl8Z
#Wsjc9vpOIJio6sZ+zwLxp3t42hbuDp7BnCe+IyB3HneGSLOZiKdj9Appjeml356TXUj2qjvKKeUC
#EibmAqKd20An+ni9VEkM/7lwKHK6hFpzclN02yMusbL8+p8Z07gVc7PR1M0uiVKR26681hJmf1Y4
#y9+Fw8fUPZslSCr0VfhT+4LaCD1mX3TFcKS+uGLosCdJlcKPeJvVnr3UmOpvtlyC+xuLGFd9edGv
#pmgOM1piNXdOptrDarlSmU2HxZouX3g2dWEzwOhscfvLM9fHzOOorUvauCeVaoVR4gwUTW5HLNmA
#U58aP/371NO11LyPCkYrieT1vk2Vy6ohJmArD9n1Q2E2UnhF84afpq8NTcI5Hes7wsmLmhp2ylpj
#Vo65dqYG1oGyqo0Yalqfqk7vC/PZsC98aB0YBaK7v3d4LbAdWSWPg1JXv3UKwQJQ0Ul7PPVGl6ZQ
#MOyar07u9kMCZP92lydG5iTzekoIrEst0B4Ck3QQ5uGR3u2SQcyjF8++2JismwilWQO9pyVH43ve
#qGmixMHzzWmeYdQf2ttcq0fCjMM/ZN+UrvmIsOzr9j8Rkeny0VsytPVKL5VagZmOV3qptIiIwTJ+
#gESRhrlfWuA+KRwWzmuQbFpINLnAve8iawOf/J0mOUp7E0FnWklgAU0rwakpuAVG30uwUS5/IFwD
#BG2uXP0+HZnYxMlaSSp7xyt3CaRbOPnYRCYFdck1gGtBEKnGeh+pJg+PtSdIxOhaB3vfzKavbrMG
#cc21DR3X7oQaIgYDgxedjQ7RkvGBmGlTY5XHj93OQEbs4vqw1LUIHyOivr2dPlEShjq4h9T1sJrY
#vsIhGoJNIr6u0XOhHXfRAXs9CLa+G5INCIElLs4nkjNhrYZBLVaW4N6t9gy0SNTUTB2bhM966h+E
#MT5kCJYr8XQtLyMShyYnxirTJvqgRy8AFogYizhTQWpAFaiqKJq511BDS6JaMucM3wlise+2xx5B
#wQLvgDj6X1cZJFTmQ1Uhe6fC0A2S3hEB9SRyZ8oxgersWO0p6cTinxCWVLH5FByvMmitkicEgAET
#1FOn3vsMZ0GaiqFNMFVO7dR1JmxAze4bRCipi71kRBj0lmfPjZO0TzIVPBvLQmoqk9EzBGCB9ipq
#5w95Q4LRkrfmRFA8hyTusrYte9kST2s7MnVYDF/JBUWcezOFhFttfRFIAz2ObCmM9ZhKUnZSYpUT
#lJXUhqlCTqayE3d+arGqD6aySXf73OFgLxrGU4dhDkqvrOu91If/Wig5YnJTSHQGy5kXnIjJXBh4
#Tq6UDporyYIvDYMiMlnE0IbS2oFwiqk7fZleO7iaFJn2S2+fyIZJ6NO+QwAJT8dZB887s4w4EcHf
#ObEgjAAx1DrYmYUUWUeRdN2pgebwxAct+HhgylYXhFAMLYgqtNTvLiJNTDOhWt3akKDQBHEc85CO
#yWkNFWnpEawVjp8DFT4tbNFPhGQBZSK1s/8lwmC9e36z0KMtY2i+OKjO5hLF0V1Huu6jjSIb9zV2
#99hNsw4WaYl0pgeeIJK6z1pDJMs596weH9pfQnQqR8sxmzVxUFBOFHvKaRVBHlFLG/Tbwww9jnl6
#zLIOOVZAdC0w7b8aMGsx8K0v/piHEOBZy9etorUjB/HSRDTaLWnt4HqOQ7c66x5Uec08lp9Lm/jT
#hhHddaZiOVDorjP7UCdIfdAmbdXeIKqrECH7griNcEhYI9djo74cXVy+jQxa7P6l29VAX+NLd3Gc
#hDqXjlnpAZvXJmfcYJpEjpizg2PCKG8Oyad1S9ttV8wzCGhdT1Rt3zX0FY0izKtaBixxZ0WUrHIn
#wtBt/v5HAlpBLaDks6qRfCI4ayazJg3Ma4Ti33DDExNxkUnCHByLSTqTRLOl1CLYPPRSeJJqNjGn
#bY5k+COOUWxNTL0V+xf1Yi6kkpPu9wEhkZFd7CoQOjb4Zs0CkpxHdurnMDJQ4/jW1rmYxBNgCxQ5
#hU2AVijeGFARyFP5GvozYRl8l/fKKJcaD5WHSOVJS2TY6jbQul3ZBtHhnuox5CUHR9BcTEDAGffd
#8CU/il9raQt/2pRa3WWiTa+7mn1S2rvbXiLEGSGumo+5LFQz2XqiEEaQ2GTua4oZD8kHRZxzzieI
#qYvmAJQcWTc2eOvPFLz3gcW5Zp4c4k/Zz8RMxzxgeVD1HZ5RA9sOCNYw7ddqiqx1h5f713kJHGwi
#irf8s85mVA/Znsvmw2amOzGTd8gyflCYfaDfupFdm4JciN6+JYyGGb3dVYGcifZGICdXy3lfOq3V
#CItqg/OpD2Gt4H0IHkcPlXSqsm0wN8rsuUHt5tT4hQHdmLKxoCah64iQvJHU0PWnexV9PuObGDfs
#CJZUeKXyrjQoIsk8i78RGIziS1zFZlmwvm0Qwi2Q/2qjro2QrpPOazKqA3xHYM6VXEio4dpthqXF
#nyEVxnkl1bydmxwV2PJnnc8LnLAvFtZd9dmesAsSEFppQ/+SGNoT1p/RveacsfvASIb50/OkHpiz
#BzvvkROrT58up3eLUd8WA+cpATXfUfupGi1MkC6B/WsdB+HrNu/JW7UK38N12A1rO+FVDBQbH8aO
#bjHeYgRWxAVb7DuDWRKhIQ4GBHvkz4fv5P6pEfN3fyikKd1Gj4kECRnhxlspHOjfN75p8TyixFox
#L3F3GSs703ePEc2yAI1EL2vIiw+P5R4Z2eueZG5hHr0PKr6O3nAq5ec9Jzgcj320AjztZ837/hsu
#GWjyoHaXKfXjjAZEg/yXjnpMtATfrSIhceIP5U5xVb3bT5TE5eH88YoWwD7iGo2JzlQw9teRxjPS
#XiPh7JRWZMhSsPOE/ht3bVHHd3eArRGk6BwikanOjc5rwjM8HCrPesUI+l18TfHGj8B85sKyeStK
#Bd6ZAhdcwZoZ56tTxLqndz4b+EoXrz7kW6noVSaglv7qli45eg0D1e4L1x0Z9nwjzIOLBY5tgUt9
#j1rubblcyf1YZjmOR2I4ogdlYABqFp6i4AE5BgUJpD8e3AhjVwJhj4rT5bzPibw13FNSkiOJwijV
#k/XDLwjKVMOxF0o8/yf6LZbkJhGe0aJWsSNCUV97D4lInC8dqNMa6ufLLsr+XSIphLOUIWZZcB3a
#jPLFgRM33SYEl3CNTltDJMXUgU6WbXx6/7k8PavKx0SoaF6FjpzKGnnC/pZWuLgoCfRBecOP5qi1
#uj9mmkKIQA2zEmiVGLlZdvJIE8u3RcBF/oKXpN4FWfRW2PJhECvrcCrgjqOGM8DqTMf89ascMD7u
#KWSOK3XvK2R3BrsPFOOvfPRZVVPI437tLiFkle8TthERSj0n/z226ZM7coeyArVmINZUxbv/RmGj
#7r1xFE5mObrgG0fDbIF9oqEbEyK5vXtEtEwerPYPpNO8qKuJfMK+4wuH418x5lNiUr547S1jZhOT
#KnzBSDliVDxXu+tEorVvczbs4yKP6bX4TZ4QFaGVpk7n9hZh0si9T0RJGNALJkrBRN8tZkYGxico
#aPTyTqlJmemo7W5gT0sVr20hAupgmQVr2JRpUI/hpZw77BwRnC/qNzf2iJ4LOXfNlGEuyyYsruqc
#+KCk5gw5ZcBkl9mTS6bEJ8nNAtNOYp6OxHYuNl3pnH2rSHG5cxXaVwZ1zk08NqCr0O4TqobhEKms
#0ZKFeA3lUqGZXXAFCfOMP6fFYwNGzB++ORfzkTW40mkJmBupX6mIrbB6pKQI1XtIV6vqURk9ITpw
#YnI7hMiROx7LLNVTEByyw/BFqFJ2/r6Avm6Cn/dfyoWiSuPIExejncy3LUbdy3JuR67EwFJJ0Xjf
#0I7oPdZ9C2FTVkqKlJxxBPvA8IKFoKK5N3b2DOweMnAgcTLxyuFlKFsl0mBzVSuoZXm4YcAQgqWF
#ZftRGbSz6ZEzm0olnCn1yJlSqYTurvJvNeEfIyU9fgN/L+p2A5i4KViQoaR3GX8nOklr7iz6zPcO
#1OF9vv1FkJrnJnYm2olU+8BQKcB3PGbwihxkRyXuxQxkwndnzC5CuEeLKYgB+o83UrnIv85HYvv6
#Am6aJuwIPM5Wo09CVfQcXWdLyrb06ML6TSU93Ttav4VQVi3UCWL3hc6HXbkBxleI+2CAEyJwcqB8
#Yh0K5FYSzZmdNtmQeYqM+VCiyrEY6CEJLGMSHzjC2zs1xh7VdaU9YMLmnWtvC+Keim73BcR8fOLW
#7iJEcXRk1bgRc6wbpKod99pMyJqj+2Gge4DUFJVrZxMpma77e0xISYwySZMZ2eJ7hUTkJD3ZviMI
#zFHrlx1/YRSqVk18Y453XhpYg9lBPHxFsGn3ej+xxw06xJ4dQkmouuPyGRO65bvC6cTShLPVe/Yk
#9IBepcBDS65gxhbBRIkyZgb0UqWvOwxeuXN5+usOwpVZXNhaf0ayXlnwymeKHyBsvsizcptJc0bC
#0vZc4W33+cIExVFze2eadK7zzfKdQ4e33QpiXJbTtNDcklP1Pt8/82eCfMHT5hl/MtBcINtXo8+I
#1WEls1/gW0UIg7Dsp0oyc3j+IxLqzruFhPmS4Vf2dGQ++2AljpoSRb0nWL802X3B5HwoC/buPgFi
#D3TuIpV4edIMyCSvhnpE8JT1uAxuzxd+QSLLbFac3k2ngZnlhCXcdJqv/B24NapTHmYzocqmJUSK
#WgiGsW82gk55NQdG7Nt4us3SQ5HlbqZvKuhE2W2WaoIJmsRRP9pA4Lq7R479BhJeEma9Qqqh+WEx
#TIZJ/LAd2FCSZaKHsBvFo1ERh8TIsiTl+GGpNKw2LROZeksBGRFcIL88rdYx/L2Cvw+cViuzR1f6
#75Q0Kuz2DYbma2moDvT9IWG6x7MG62QWyFAZvSZClDUcrHg0Bsl/P+ST0VkQlI/i3SesZmIqlrEW
#QTQjpuzOMZK4wxbZHiUsrbiC6pSgORTPJk3fBi9/VI05Wtb/oW7gLCBZEuOTxXeGIypYwC7RrRt6
#FoguCtwBDalFUV/O5x76xGuKyD7v86kkgGS3cXSfKFg+PbPWjBEKAjaFVrtESVOuDpDC5CIskF/I
#7fDTeXR6nx0Cw4ni8vmPl0SIitzdIEq6YIKEE9AERMt8IWPYlhsxRlGKzOgRqovr5JjIeTWmcNjY
#XAKjVSILDTBDquB8HXZ7E4d9iGEKYEzpRKHmxd4O67hHm+EHEuriMF9DwQW38Fu6g0ylDxktb6Bg
#UEqG5nDTx1D82Bb/hgy0C/9u+j28bvLtZarzr4OZQuug3doeotiaZanV+UG/+bMgQz67kM0W6jS5
#IRTtIZHzvCI7buq+ALZElI9wNEX6cblPRASmP/ofLOCZT9AtCyjnfFD20soaLXjTaRlgOt102Hoe
#xXJRUuD3CJs+umlEXh0xKPGwu0TN+bOuCOUic/Ybrqe81cofG3O+4Av1ldFJnIunLc6Uddlpi1Nl
#orpKG5Ka/XH982Us601Zx5WlqdtH/TtCWVv8VBBpxdtK2hKfGdIGE0+f+k5231/KbqRB4Oqhu0e2
#mE6Q/n3CRCb0V4SyT0ZNwN1rxVEea+zP6jJRsqCvtpEKgsXy9EKhEpMqlerG1MotxsCsm+WTxuz3
#Qawpn+m6Y8hS6v7zPn9aJkv0i3tYw4TP1/ZRxCdV+UrO4BtR+h0rXGqTGaty7XYQiJJmMuWtw/GD
#lU6a9kOop6xvZmpHr+PKIur7Eopae5TgAVHldJ73fshaTwzJkMHZUjxVX8qVOJR1g4sU5mjdqeAt
#TlE452ubdr8TWhNfpMzull9vYPZ9lu9PCEln2eh7ck/LICLa9z0D8Jq+p3T5aFkPFRE8LFFeMB8K
#qlkB7gtdyvW49Uqeywd5nG+V9g4Zrlm9G+Vny5yy2RAJR4g3H3C3b5wqikEnpS8/ba25LNxbb2kt
#esJJdENz/I1I/foaDsA/Ck3SiothGuJpzFnnDA3OqBy/KZPDQhk0ZWNrLGsH5iuBujhD6DWhs6Aj
#Z7C+z4XOVxaOiRUVVfeMzh6BHGXL6HsOXcCPtOOaFXhNjKDSuFByYL0n9hz6xGDh4Vwc1oX/RW/r
#1/Tbniv8TR7cnqyVTvu5CXMM11VH2w7uaKRuwhzNGft6lX+zX2r5GVOyMHEaeZre++Yq1Gdq/lzI
#jpoXFs/szsLOhDEJkXlOlP26wwOmC/Kr09msXKIKsK9zVCejBD94YY5xDG4RI284YaSTz4SxE6lN
#zYtfM7X+lDOpG6AmambYZWQeVWkq9U5KpT6f6yp00q0JPF8JTH71NYQK9GsVOZgvcV1Ce/rDi4yL
#x0GfXFJoXj7Io/lU+4+pkImjV42Fn4zOvukAW9GS82JmhjPtO8nCdreBUxZT2DUFHj3BHAXyoVH9
#/Av0FYdjOiXoq3VOgdF0AV5knRI7psRUcNhTQjmjGCNfCHFTwvY7BPG2cP+G3sp+lOmuoU0KEgqO
#lLGG8qGAydAIJOx1dOogZhKN3NM0lm1nixS4YQvgx070GzajszJo73s2fV8t4dz6rHTrdEbX3ztM
#ltwJd0r3S6dzFN0p3yqM9WsO1NeoLqJizYP3FVEt+bx5KcgU5/2cH1Uwwck1Mu8XXK0Ytd15rf1L
#IhZDu3d0ygF+zndu1oTyMMe3+NtGijla113Cau6z9gkKMMm12X1powSZD5sefbmSZ/97hvRM0spD
#oUut99BtPeU6zffQbT4YrYscN8m12ZOlgcID5JggtuFC7NcTnfkbKGwXUlcj+c6I+UQDiLv8t1S+
#tjeCJTrXUPLlN0iIi6eD5fxQ25lys31F6FroBqmccX/ksJyjGNFdrN0XiDV9admDdSRjv+LnvvNd
#tEeEYmijnq14SMii9eGdcWfmGO/KSgvVS+OjwFbUT2q2T+i3OdejaY0PCNb8JAf4wtNHfDSQ7Qvy
#anRoW1SD8SlCmF28vJltMI8c6SY27ymznNMFrxGJY1nFO9+JZEfXZ/wNq3BucnbAaMsbvjOWz7jT
#p5M/L/NClzdYXPMqh21MmVYc19fkA4EFriUlJYpuagTz+IRJrMbvamrmjaJZyex+b0chCXbqwljL
#7VdcOgdKyquywpCbYNbVt0LJrtNdJDHlkx5MOl95L5c0E8xfmOlRnDPWlfKQzfzSbknJAVcqMZUF
#pMS7wkeX0waEjUjGV6Lzs3d40ypP5LQVVekQgVADq9GSyJPZwERrnbHuB9gCOhd1ldnCWQSPV2GC
#zQC95oz3D4zIlO5SgcScch3TPY25+0koG0y2v4sQ99H6E/rdEEnYmSCZgq4nM54VqTy1D8f74Z6B
#MYE2pVNS36R2HTwmGje2XSf5LqGyJg0eCcW9PVgiUnZGHhIRZ/WAdmIu7NydD8b6UFPIOfakTDSi
#C4wQwBtgbFhL8wUOJiW+o0atEsMoNOvviI7Dmg9meVLx3Q4+Ix4KO9AxvWoRN5xeGhGzaLYkQnIH
#adyTWDDxnh2CWg1Jv7PEJJ0sqKV6SL995sA2j+xzRFWDHQyIarZ0rqHoKLvM8kIj8ZaxC2Ge4u6I
#c0rpNqIgh1zJeoxYqlG0o9tMNoN4SsK/ZwamAgsvfJrujI0FKGASXbxEElZwZyagbJ3jLsDKz+PW
#XY3jRJyEDLKu3cAS2BF/McJoPiltl20whEfaLkajdQ+ZS9/nuYwP0q/421/+wUPz/hlSf/0Tf/nw
#/gek/lbh7yjeh7oWf//9T/zVxPtvkfqHlmQ7EwH+KOL9j0gF/+QvIt4HmVr8489/4Y9M3h8g9bff
#f2fqFKl//VN475Hy/yGbKdApRd1utXxmSVPIJ3gkX2cxi3MrsEVgOJZic2E1KGLM7aXbCz0EYCLp
#vvv6UwRCE8UyukM09gpuQHhBkyKapJNHrAtJgdh8NE+ejnWObfIHULhkkVjaxp8ZJzh0P6O4DYMN
#1nQb6fmZdZXCuSu2UobmCac1KI26zzwsgX/Vp79BmykWK4GrrXxmbQLH4fljjrmdwy8ui4t2PDS0
#tW+HzvqiTMeMHTrLxxyGDOaFrcJnxHL6LE41FKuSGNBbc0EcLIJV7lt0H9E0J0lwiXzFixoSJwOL
#yBymDOFw1kS+crR2jHAtSNxTVWtnCpqPq3XeIBTksaa+/MJ9OBcmmvSp8wXJtM4ZT2Cpn0si/DQ0
#i5hHRKOsM5uTqwg1w3K00A4+SDxgMAPmCrwH5gzViN9N0Mfm4U01r8c9JHX/orTv8wn+DmX/5weV
#sg7Hj4a2O68fnX5TprP1+tHpt3n8wnfmzRQgIJ3NxQPkkHv6km/Y9Q2zjrvyMA4tj94plY3Z88Fz
#eQhIvIqfqb601RVYTH88rMQH5StgO/tyVn71tqLO8XmBnKO+DxAS70T3ERELnnxR7N83juRJ1694
#l55hXnwXkCPzfGh1ALMTLCb9DN4EqZr5QnAPb8If+4nCGfO19xXOUF3mWIvo0X+W8mFMFXNMI1NQ
#egyVwxRHUsNPnc/ZgGCfb6jVsXoslCic2C4Yn0s+I7iuyZKSHYOlyN3zbRxhFHI7lZXyrsE15OUc
#P2nFWFmPsajR/XpvFLwiEuZ4in8xFsaWMH7WnbZi7D8xcTLnh4+Vg4fHi6Z4R2wBdHGVC1jWF+cd
#pq/bPHCZBJfCvrCWYUSnEe3b795ANKbEqSqIVgWybplDvjNm/5NvtD8jMnCUmfYngmRDAgd/It93
#Wv2MhG00oUopUSYmJYrwyklRJiYpinzQYjotigzB5GeJUUplTGqUiUmNwhw3OQp+hZDRK9KjuLe8
#LEHKxCRI0TI2RcrEpEgR3oUkKRMTGS8lptOkTEyaFC5wSaKUiZMohQtdnSplYuLobckrk6VMTBi9
#KXwxXYrbPk7ClImTMEWZF1OmuBeXk6ZMTHYH5l6SNmVizsFxESdxysSJQRfmT1Kn3Lik3OXJU9yS
#U+lTJibwQtiXJVApXe+kUJmYHWnhuUlUJsb5y8xSGpWJcbcoczqRysR4WeSDLPptLCfaZKPEvJhL
#ZWLOMzjFLmZTcV/v0nwqTgE8Sg4GtH73a2BgtZq7POavyp5hbmUSYpAMkhiL/RMi3M857n5AKI1Q
#/LOWvPVZ7iFJQ/bfEZGa2CAUgTYpNg3GqaogwsqXCVvl6AjKT/xk+ddfFnzR9McfkZjaeN+FRy4E
#FCbiBjG/MKizrzc0oBuSuYeoRp9S+pR9RMTNAu8Mw9lbkLSqfY4uXEi8BR7X+yBvF2SvqQ8r9aLz
#SYMfrOsv+rHTijv7iNCZggHUcjGoiCIwWkOK/O1/UvNxMWyCqJsP7P2+Ioipgi/kzIAlaRG/gC4a
#6TMlrUnwzFFZhOdYBM+cUbG4uMivDxPq/wE=

# Compressed Ntfy logo in PNG:
# https://docs.ntfy.sh/static/img/ntfy.png
#__NTFY_LOGO__
#ASsO1PGJUE5HDQoaCgAAAA1JSERSAAAAZQAAAFYIBgAAANaSWMwAAAAJcEhZcwAACgEAAAoBAZHF
#LtgAAAAZdEVYdFNvZnR3YXJlAHd3dy5pbmtzY2FwZS5vcmeb7jwaAAANuElEQVR4nO1dbXBU1Rl+
#zm7CJiFECC5BSSJJaAl+lEBtm0QZ/GppB1tj7ThatWhrR6YzdMZ2oHWc6WinU/92BoWZKgijraWo
#4JTaqWgtGMVWvrZDRCJEoxBIQkIwYZf9vP2xX+e855y79+69CyTZZya5u3vufc973ue873PP3d27
#QBFFFFHEuAQbZ3bHCwwnB7sVPEa2RYjE2CLJSRB5IlSP3ehjPEFFgqF5bIp8AsYT4Onq6rpy3rx5
#DzHGGhljs/OwNxEQikajx0dHR/9VU1PzD2SDn0CWDPrnGhgADwBvOBx+IpFIDBlFCEgkEtFoNPpe
#Z2fnNQCmAigH4ANQCqAkFT/TZLCTKQwAGx0dvamysnIbgKp8WJ1EMMLh8LaysrIHkcyYBIA41Nkj
#wGOxAwaARaPRxyorK99EkRArYD6f7/vxePzQ448/Xo1klpQA8CKrvSoNtpQpDACLRCIPlZaWPuei
#05MG8Xj8RH19fUtfX18EQAzJjKFZk4EVUjz9/f3X+v3+g4yxyXIm5TpCodBbFRUVdyNJShRZUiRi
#cpUvBoD5/f6tRUKcoby8/NZdu3a1IlvG0oIvlTGzQDMAbHh4uH3GjBnvFNDfSYNIJNLl8/luARBB
#MlvSpUzIlpIcdlhVVdWaXJ2NhIJ4/cOD6BkawPloBADL0M0o/+kXGD8jWPIx1wa+LbMyYmQWcUZo
#G8tY5Z3gnqaPlY8T/AfxN/sv41vN1CosrqnFwllzYIYpU6Y0NzY2lvX09PClK5EymClfZpniAeAx
#DOMUgJm6nboHTuLnr2zG2fOhbCDSg+UCltxwNLBswITB6mxIbSY2LNsX+8ppXzUW7pjbm67FypYb
#dKECAAQCgZUtLS3bkM2WKIi2WNGUaWY7/H7ndgUhkAnhjTKyEw0K13nmkTBTeYIFy8Q+/7LKPiVE
#ZV9wXLLP29hxrAuBgRPycRz8fv81SJ4WpzVF4kBHCi8+pboOgpEwugf6pQGBBIwvTTRgjPH7ySSJ
#AVMQwczsM94DbrbzB/IPiR8pu6J9YgPCrjh0+hTMUF5eXodUFYIo9hlYWTwqpkwS4VgMBjOkgJGK
#w2WEPmB0VjNNwMS2HFrEmydE82UxY59yTu1TPyR/GcKJGHLAB3HSS4atlC8LUAdM2ArGxIDRMiCd
#HGjKIp2svLDzAaOZIXhE21Q6AtoGtX3rYIq/jBEzUnL2woRgQiJEmAZ564g6YNTNi6Ujgs/WeaFZ
#IsB5ptDM4B11RUfUrujt29QRRvxIvSbaJzZ4+/lliypLMrB6QTJnH/zg+QGBMcytvlwdMDLYi6Ij
#nN96+0w8TmmfJLADOCQlSbRZwBiAtR0/wm+X3YXay2YoywsNmHAwZ04lvAXXETDpMFVmMHFgjpBr
#RQ8kFzTaniRh59u4jLi5aQGWNMzH6x8FsOGD3RgJBbUBy60jtE0O2IXUEWrfKVwrX5n/Gh0BgBKP
#B9+7ehG23PczPPKNm1FROgV05goBIyPU29cHTAgUIzaE8uVAR+TkdgRHpMgzlcxqkuJplJWU4oeL
#WvHiPY/gjqtb4PV4uAEpRmhFRzQBu3A6Ipe+fOE8UzQ6kn5i5ujMikr8Ysm3sekHD+OmxmZStjT2
#eat0rUIDxh8hBZPY4IcEMhZNZvA64pbIA26VL03AUi/kRN30ajxx6x1Y1/EAFl5RVxAd4X1xrCNa
#++4w46x8gThqsh6xgmb/FfjD8nvxu2/eiaumz8yayltHGPcwvR9fvvLTESYQoaLMGaycfZnDynUt
#m2ivn4e2uibs/rQbf9y7G6fGvshPR1QB05RFRogw0xF+BmTsu5gtLpUvhY5wJP369a3Yf6LXnknG
#sLRhPjbe+SB+ev0STJtSlm6wriPEOfV7LNwgpDaLOmJWFvNALlJMP8nHaElQXH9iYPhwsA+P7vgz
#frnjLzgyaH5pm8JXUop7rvs6XrjrJ7jnuq/B5y1xqCOiMghtQkW0pyNufoTBcaZodYQEDGDY1/cp
#Vm7bjN+8uR29I0O2+pnmK8PDX12CjR0rcGvjAr5LmzpC2lzQEffoSMK18iXVedqW2hoMeOeTI3jo
#5Y148q3XcHJ0xFZXNZVV+NUNyy6wjjBhQFodUZxe5wNHQm+mI8qAIRswAwb+/ckRvPf5MXy3eSHu
#b2nD9LIKe72Tqlk4HeHs68qiS4QAri4e08/FVOcHJA2WMUTjcbz64QHct/VZPL+/E+ciYXvdyzXF
#mY4wurc1HcnOC+fUuFq+VDoi1/lUCwnY+WgULwb+g/tefg7bDx+w1ado36GOcAeY6whvX0pZR3Au
#9NJ/ZAbLNAGj9T7dVuLxYOncL+PGq75kqeeLqyPUvgWXLcKZpjAGOzqSPS77gAFgHg9uaWjGikXt
#mFM13WLfWes0YBdHR9xjxfmKHpBSnYkN0AUMANrqm/DjxTeisdqfb8dCp2YBK7SOuLVWceEyC6mv
#FnVk4ew6PHz9Elwz60rbXQ4Gx4h9RZ3PuOOCjmium+ntO4NjUuzqSOMMPx5Y1IalDfNt9zUWCWNL
#1168diSg0BFxVruqI9nhEfvEhuBP/nChfFnTkfrp1bi/pRW3NV1tO81jiTjeOHYYmwJ7cDYc4vpi
#JDCwpSOSDW5/aeab6ggpiw7hSvkSE1uedY/e8C3c3rwQHptkGIaBnT2HsTnwPk4HxxR1PrXJU0fE
#YTjUEamM5w/nZ1+ZJ6l/Ch1Z2jDfNiH7T36GZ/d34tiZQSlg1nWETwHRMbd1xL31vEvly9J6xCI+
#On0KG/Z3ItB/QpkZ9nSE85F/ptMR5lBHXOLFudCbBMxOcvSf+wKbD+7Bmz2HwQfMfD2SdcIVHSGH
#2tIRyd/8kZMUwzC0wqx0VBEwM5wNh7C1ax9ePXwA0URcKCWCfRoLRcBum9uMVdcvzTUk2+j94gxW
#d+7Q64g8IxzBtbMvqiOZNg1CsSi2du3Dy117EYrFyHFksLTOq4hmDF7mQanH63A8Mkq9Xks6wlwi
#x6XFI9Q6wmQXY4kE/nn0EDYffB9nQueUg82pIxn7qrcMCge9jshl0QlyksIY035slRFhFGoqDRiA
#9z/vwfoPduHE6IhaNB3rSKFhpiPuEAK4unjUB+x//cfx10N7cXjwpCS8NDNkHeHt64W30F/zt64j
#l0j5AnQ6knz85Nt/E5sErcilI9Q+b14W3oJC8Jcvu/JYnMDxh/HoI60op1Od258Jh+t1xP4H6AoF
#kXypbF1K5UurI4zsx71mR0egsy824nRwDPv6P9d5KR9CX9DIQn9oLKeOXFIrejPh5T8P5q6O0Lbk
#7gcGjuPAwAmxlBANoOsn3Q0XZPuyb8I4pcmVP5y9HUwGkXqSeolEvIA6QoWXL4v0upZgg5RF0T6x
#wY8t26C27xAufWkoHRMVITZ1RBMw0T6xwdvXZKO161rEBu+xwJk8geg4naAg30/hGsnMTz2RUl0x
#IE3AKBF6+1DbJ9kiXWiE+CTbplqPcH64lCWAW1+FoJdHUq/xA6Izlz9CajPTEU3AyLQVSg49W5fe
#YxEbuTZFxvH26eSyxkzOO626Vr4AxWCFVCcB05SBgn0xVFUWCRGOdCR1cF3lZbL/HM6fPz+IHLfC
#daV8JTekvGgCBjIgPtPc1xEppEIQZfs0pSC2SQkplt26qVVom1UPMwwPDx8lL0nEOPwssVSLQB2d
#DDoys7wCLdVX4N55X4HPa36Vev369TshZ4qwdeVzX2odAXylJVg8+yq01jagtbYB1eVT3ehu3CIe
#j/c/88wzg5DvTQxua/nmBkowJutIzbQqtNY2oq22EQtn16KkAO9vjFd8/PHHG5ElREUMABimpLS1
#tXmQvIubEvHUu5LN/tlor2tCa20jGmZc7tz7CYhYLDawYMGCDRDv5J0mxhIYgJLjx4+3md3XPRKL
#GWdC5y7IPeTHMxKJRHTt2rXfATAXwBwAfgCXIXkf/CkQ7+qtLV8MAKqrq1vNmCv1ejHda+eLPpMS
#iZ07d65ctWrVESQzJIbsrW/5Mob01vQmbF6vt6WAzk54xOPxsU2bNnUsW7bsbWTvQ6y6rboAU03x
#er3zCuDrhIdhGPGhoaG/t7W1PXb06NEQsmTQG0QrxV5FSuaM3OPx1LrvrxF32eZFh2EYkUQiEYxE
#Ir3d3d2vLF++/NXUjw2kRZ0nRHnXbh5mmsIYY9qbRNtwOBQMBrv7+vreWLFixQt79uwJQXFuPk5B
#/U8Hmf5eCi1btHQJdnKtU2yruGEYoXA43Ds8PLznqaee2vD000/3Q07TBBnEeAf93a30GOPclidD
#t0YBYEJKIBCYA3IBRemNYcTC4fBnQ0NDu1966aU/rV69+lPICyTVlh/EeIeOFNVfzt/l0pLS1NS0
#RNm7YRjxeLx/ZGTkv+++++6Wjo6OD0iHqse6VWzeP7t3iUL1g2gJ8ji9H78VoCXF5/MtzvRkGGeC
#weDB3t7e7e3t7TvOnj1LZ4ZqNqjIML3mMwGgyhjdzwtqoSpPDIBnbGzsbgCz1qxZs2XdunURyL8n
#BZhnBJ0huciYqOTwW/pYCR0pDMmFZZoInpD0gtNMM8yImGglSwXVuCyPVVW++AAmuNfTP77CSLuq
#fgLmmTFRyaDIa5xmp8Q06Iz7U81+uyRMFmJsQ3fKy78vSv8Adc0skuASzNYh0kcDSHuRhAIh1+KQ
#tqdLlwpFElxCzhW7yb5FEoqYPPg/THHUyxMSdXkAAAAASUVORK5CYII=
