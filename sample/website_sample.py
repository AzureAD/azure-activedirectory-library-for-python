try:
    from http import server as httpserver
    from http import cookies as Cookie
except ImportError:
    import SimpleHTTPServer as httpserver
    import Cookie as Cookie

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

try:
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs

import json
import os
import random
import string
import sys

from adal import AuthenticationContext

# You can provide account information by using a JSON file. Either
# through a command line argument, 'python sample.py parameters.json', or
# specifying in an environment variable of ADAL_SAMPLE_PARAMETERS_FILE.
#
# The information inside such file can be obtained via app registration.
# See https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki/Register-your-application-with-Azure-Active-Directory
#
# {
#    "resource": "your_resource",
#    "tenant" : "rrandallaad1.onmicrosoft.com",
#    "authorityHostUrl" : "https://login.microsoftonline.com",
#    "clientId" : "624ac9bd-4c1c-4687-aec8-b56a8991cfb3",
#    "clientSecret" : "verySecret=""
# }

parameters_file = (sys.argv[1] if len(sys.argv) == 2 else
                   os.environ.get('ADAL_SAMPLE_PARAMETERS_FILE'))

if parameters_file:
    with open(parameters_file, 'r') as f:
        parameters = f.read()
    sample_parameters = json.loads(parameters)
else:
    raise ValueError('Please provide parameter file with account information.')

PORT = 8088
TEMPLATE_AUTHZ_URL = ('https://login.windows.net/{}/oauth2/authorize?'+
                      'response_type=code&client_id={}&redirect_uri={}&'+
                      'state={}&resource={}')
GRAPH_RESOURCE = '00000002-0000-0000-c000-000000000000'
RESOURCE = sample_parameters.get('resource', GRAPH_RESOURCE)
REDIRECT_URI = 'http://localhost:{}/getAToken'.format(PORT)

authority_url = (sample_parameters['authorityHostUrl'] + '/' +
                 sample_parameters['tenant'])

class OAuth2RequestHandler(httpserver.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(307)
            login_url = 'http://localhost:{}/login'.format(PORT)
            self.send_header('Location', login_url)
            self.end_headers()
        elif self.path == '/login':
            auth_state = (''.join(random.SystemRandom()
                                  .choice(string.ascii_uppercase + string.digits)
                                  for _ in range(48)))
            cookie = Cookie.SimpleCookie()
            cookie['auth_state'] = auth_state
            authorization_url = TEMPLATE_AUTHZ_URL.format(
                sample_parameters['tenant'],
                sample_parameters['clientId'],
                REDIRECT_URI,
                auth_state,
                RESOURCE)
            self.send_response(307)
            self.send_header('Set-Cookie', cookie.output(header=''))
            self.send_header('Location', authorization_url)
            self.end_headers()
        elif self.path.startswith('/getAToken'):
            is_ok = True
            try:
                token_response = self._acquire_token()
                message = 'response: ' + json.dumps(token_response)
                #Later, if the access token is expired it can be refreshed.
                auth_context = AuthenticationContext(authority_url, api_version=None)
                token_response = auth_context.acquire_token_with_refresh_token(
                    token_response['refreshToken'],
                    sample_parameters['clientId'],
                    RESOURCE,
                    sample_parameters['clientSecret'])
                message = (message + '*** And here is the refresh response:' +
                           json.dumps(token_response))
            except ValueError as exp:
                message = str(exp)
                is_ok = False
            self._send_response(message, is_ok)

    def _acquire_token(self):
        parsed = urlparse(self.path)
        code = parse_qs(parsed.query)['code'][0]
        state = parse_qs(parsed.query)['state'][0]
        cookie = Cookie.SimpleCookie(self.headers["Cookie"])
        if state != cookie['auth_state'].value:
            raise ValueError('state does not match')
        ### Main logic begins
        auth_context = AuthenticationContext(authority_url, api_version=None)
        return auth_context.acquire_token_with_authorization_code(
            code,
            REDIRECT_URI,
            RESOURCE,
            sample_parameters['clientId'],
            sample_parameters['clientSecret'])
        ### Main logic ends

    def _send_response(self, message, is_ok=True):
        self.send_response(200 if is_ok else 400)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        if is_ok:
            #todo, pretty format token response in json
            message_template = ('<html><head><title>Succeeded</title></head>'
                                '<body><p>{}</p></body></html>')
        else:
            message_template = ('<html><head><title>Failed</title></head>'
                                '<body><p>{}</p></body></html>')

        output = message_template.format(message)
        self.wfile.write(output.encode())

httpd = socketserver.TCPServer(('', PORT), OAuth2RequestHandler)

print('serving at port', PORT)
httpd.serve_forever()

