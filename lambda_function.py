import json
import datetime
import logging
import os
import traceback
import inspect
import boto3
import re

from fnmatch import fnmatch
from typing import Optional
from urllib.parse import urlparse

from classes import CloudFrontCookieSigner  # type: ignore
from tools import get_alb_privates_ip, override_dns, log_function_call  # type: ignore
from keycloak_tools import KeycloakToolsManager  # type: ignore

# --[ LAMBDA INIT ]-- #
print('--- LAMBDA INIT ---')
logger = logging.getLogger()

# CONFIGURATION
KEYCLOAK_URL = os.environ['KEYCLOAK_URL']
KEYCLOAK_ALB_ARN = os.environ.get('KEYCLOAK_ALB_ARN', None)
REDIRECT_PATH = os.environ['REDIRECT_PATH']
PRIVATE_KEY_PATH = os.environ['PRIVATE_KEY_PATH']
WEBAPP_ACCESS_ROLE_NAME = os.environ['WEBAPP_ACCESS_ROLE_NAME']

KEYCLOAK_ACCOUNT_APPS_URL_PATTERN = r'/realms/(?P<realm_name>[^/]+)/account/applications'

if os.environ.get('PYCHARM_HOSTED', '0') == '1':
    logger.addHandler(logging.StreamHandler())

if os.environ.get('DEBUG', 'false') == 'true':
    DEBUG = True
    logger.setLevel(logging.DEBUG)
    logger.debug('Debug mode enabled !')
else:
    DEBUG = False
    logger.setLevel(logging.INFO)


ec2_client = boto3.client('ec2')

if KEYCLOAK_ALB_ARN:
    kc_alb_alb_privates_ip = get_alb_privates_ip(ec2_client, KEYCLOAK_ALB_ARN)
    kc_hostname = urlparse(KEYCLOAK_URL).hostname
    override_dns(kc_hostname, kc_alb_alb_privates_ip[0])


# GLOBAL OBJECTS:
g_cloudfront_signer: Optional[CloudFrontCookieSigner] = None


def get_cloudfront_signer() -> CloudFrontCookieSigner:
    global g_cloudfront_signer
    if g_cloudfront_signer is None:
        g_cloudfront_signer = CloudFrontCookieSigner(PRIVATE_KEY_PATH)
    return g_cloudfront_signer


# --[ LAMBDA HANDLER ]-- #
def lambda_handler(event, context) -> dict:
    """
    Lambda entry point

    :param event: Lambda Event Object
    :type event: aws_lambda_context.LambdaDict
    :param context: Lambda Context Object
    :type context: aws_lambda_context.LambdaContext
    :return:
    """

    logger.info('-- Starting lambda_handler --')
    logger.info(f'Event: {json.dumps(event, indent=2)}')
    logger.info(f'Context: {context}')

    if 'path' in event:
        path: str = event['path']
    elif 'rawPath' in event:
        path = event['rawPath']
    else:
        logger.error(str(e))
        logger.exception(traceback.format_exc())
        return {
            'status': 403,
            'statusDescription': 'Forbidden',
            'body': 'Forbidden'
        }

    try:
        if path == '/.cdn-auth/_cf_redirect_403':
            logger.info(f'[ path="{path}" ] -> Redirect user to authentication service...')

            # Configure client
            keycloak_openid = KeycloakToolsManager.get_or_add_kc_tools(
                server_url=KEYCLOAK_URL,
                realm_name=event['multiValueHeaders']['kc-realm-name'][0],
                client_id=event['multiValueHeaders']['kc-client-id'][0],
                client_secret_key=event['multiValueHeaders']['kc-client-secret'][0]
            ).openid_client

            # Get Code With Oauth Authorization Request
            auth_url = keycloak_openid.auth_url(
                redirect_uri=f"https://{event['multiValueHeaders']['host'][0]}" + REDIRECT_PATH,
                scope='openid',
                state='your_state_info'
            )

            # Generate HTTP OK response using 200 status code with HTML body.
            response = {
                'statusCode': 200,
                'multiValueHeaders': {
                    'Content-Type': ['text/html']
                },
                'isBase64Encoded': False,
                'body': f'''
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="utf-8">
                        <title>Redirect to authentication service</title>
                        <meta http-equiv="refresh" content="0; URL={auth_url}" />
                    </head>
                    <body>
                        <p>Redirection vers le service d'authentification / Redirect to authentication service...</p>
                        <p><a href="{auth_url}">Cliquez-ici si vous n'êtes pas redirigé automatiquement / Click here if the page doesn't automatically redirect.</a></p>
                    </body>
                    </html>
                '''
            }
            return response

        elif path == REDIRECT_PATH:
            logger.info(f'[ path="{path}" ] -> Exchange code for tokens and generate CF signed cookies...')

            base_url = f"https://{event['multiValueHeaders']['host'][0]}"

            # Configure client
            keycloak_openid = KeycloakToolsManager.get_or_add_kc_tools(
                server_url=KEYCLOAK_URL,
                realm_name=event['multiValueHeaders']['kc-realm-name'][0],
                client_id=event['multiValueHeaders']['kc-client-id'][0],
                client_secret_key=event['multiValueHeaders']['kc-client-secret'][0]
            ).openid_client

            # Get KC tokens with temporary code
            kc_tokens = keycloak_openid.token(
                grant_type='authorization_code',
                code=event['multiValueQueryStringParameters']['code'][0],
                redirect_uri=f"https://{event['multiValueHeaders']['host'][0]}" + REDIRECT_PATH
            )
            logger.debug('{ kc_tokens = keycloak_openid.token(...) } result: %s', json.dumps(kc_tokens))

            introspect = keycloak_openid.introspect(kc_tokens['access_token'])
            logger.debug('{ introspect = keycloak_openid.introspect(...) } result: %s', json.dumps(introspect))

            # Check if user have role "webapp-access" for this client, else return 403
            if WEBAPP_ACCESS_ROLE_NAME in introspect['resource_access'][event['multiValueHeaders']['kc-client-id'][0]]['roles']:
                # Check if host is in allowed-origins, else return 403
                if any(fnmatch(event['multiValueHeaders']['host'][0], pattern) for pattern in introspect['allowed-origins']):
                    signed_cookie_parts = get_cloudfront_signer().signed_cookies(
                        private_key_id=event['multiValueHeaders']['cf-sign-key-id'][0],
                        url=f'{base_url}/*',
                        lifetime=datetime.timedelta(days=1)
                    )

                    response = {
                        'statusCode': 302,
                        'isBase64Encoded': False,
                        'multiValueHeaders': {
                            'location': [base_url],
                            'Set-cookie': [
                                signed_cookie_parts[0],
                                signed_cookie_parts[1],
                                signed_cookie_parts[2],
                                f"JwtAccessToken={kc_tokens['access_token']}; Path=/; Secure; HttpOnly"
                            ]
                        }
                    }
                    return response

                else:
                    logger.error(f"{event['multiValueHeaders']['host'][0]} not like in {introspect['allowed-origins']}")
                    logger.exception(traceback.format_exc())
                    return {
                        'status': '403',
                        'statusDescription': 'Forbidden',
                        'body': 'Missing allowed-origins'
                    }
            else:
                logger.error(f"User {introspect['sub']} ({introspect['username']}) doesn't have role 'webapp-access'")
                logger.exception(traceback.format_exc())
                return {
                    'status': '403',
                    'statusDescription': 'Forbidden',
                    'body': 'Missing webapp-access role'
                }

        elif match_result := re.match(KEYCLOAK_ACCOUNT_APPS_URL_PATTERN, path):
            logger.info(f'[ rawPath="{path}" ] -> Check JWT token and return filtered applications...')

            realm_name = match_result.group('realm_name')
            kc_tools_client = KeycloakToolsManager.get_or_add_kc_tools(KEYCLOAK_URL, realm_name, 'account')
            jwt = kc_tools_client.get_check_jwt(event['headers']['cf-authorization'], True)
            logger.debug('jwt.header content: %s', json.dumps(jwt.header, indent=2))
            logger.debug('jwt.payload content: %s', json.dumps(jwt.payload, indent=2))

            apps = kc_tools_client.account_client.get_applications(jwt.encoded)
            logger.debug(
                    '{ apps = kc_tools_client.account_client.get_applications(...) } result: %s',
                    json.dumps(apps, indent=2)
                )
            roles = jwt.payload.get('resource_access', {})
            allowed_apps = []

            for app in apps:
                if app['inUse']:
                    allowed_apps.append(app)
                elif app['clientId'] in list(roles):
                    # if WEBAPP_ACCESS_ROLE_NAME in roles[app['clientId']]['roles']:
                    allowed_apps.append(app)

            allowed_apps_sorted = sorted(allowed_apps, key=lambda allowed_app: allowed_app['clientName'])
            logger.debug('{ allowed_apps = allowed_apps_sorted } result: %s', json.dumps(allowed_apps_sorted))

            response = {
                'statusCode': '200',
                'headers': {
                    'Content-Type': 'application/json',
                },
                'isBase64Encoded': False,
                'body': json.dumps(allowed_apps_sorted)
            }
            return response

        elif path == 'warmup':
            logger.info(f'[ path="{path}" ] -> Warmup Lambda function...')
            get_cloudfront_signer()
            return {
                'statusCode': 200,
                'multiValueHeaders': {
                    'Content-Type': ['text/plain'],
                },
                'isBase64Encoded': False,
                'body': 'OK'
            }

        else:
            return {
                'status': 404,
                'statusDescription': 'Not Found',
                'body': 'Not Found'
            }

    except Exception as e:
        logger.error(str(e))
        logger.exception(traceback.format_exc())
        return {
            'status': 403,
            'statusDescription': 'Forbidden',
            'body': 'Forbidden'
        }


# --[ DEBUG ALL FUNCTIONS CALLS ]-- #
if DEBUG:
    functions = [obj for name, obj in globals().items() if inspect.isfunction(obj)]
    for func in functions:
        globals()[func.__name__] = log_function_call(func)
