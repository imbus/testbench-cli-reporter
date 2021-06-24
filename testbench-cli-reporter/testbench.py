import requests
import urllib3
#from functools import wraps

default_header = {
  'Content-Type': 'application/vnd.testbench+json; charset=utf-8'
}

class ActionLog(object):
    def __init__(
        self
    ):
        pass

# save connection data
# for each connection data, save an arbitrary amount of actions (request type + parameters)
# possible to export all 
# after connection cut -> still possible to generate log
# if connection cut then login with same connection data -> data should be combined
# data should be held as dictionaries (?), exporting should produce JSON
"""
ACTION LOG / CONFIGURATION EXPORT

Requirements:
Must Have:
- Export current connection + action -> import allows executing given action in automatic mode
- Export all/selected actions with their respective connections => import allows executing given set of actions in automatic mode
Optional:
- Export current connection only => import allows manual mode skipping login
- Export current action only => import allows executing pre-defined action in manual mode
- Export all/selected actions only => import allows executing pre-defined set of actions in manual mode
Probably not useful:
- Exporting multiple connections without actions


Implementation Thoughts:
- Track all relevant data to be able to export more then just the last action
- Save data in dictionary, as this makes it easier to add more
- Add data each time a relevant action is performed (import/export | successful login is only relevant if optional requirements are implemented)
- Export to JSON on request (Requires selection of: what export, if supporting selected actions a one-by-one selection of connections, and actions per connection)
- IDEA: log as part of connection => then if connection is cut, either ask one last time if export should be performed, or store it (in login menu?) (is support after changed login important?)

Example structure of how a configuration file could look like:

{
   "configuration":[
      {
         "connection":{
            "server_url":"test",
            "username":"test",
            "password":"123456"
         },
         "actions":[
            {
               "type":"exportXML",
               "parameters":{
                  "param1":"1234",
                  "param2":"5678"
               }
            },
            {
               "type":"importXML",
               "parameters":{
                  "param1":"abc",
                  "param2":"def"
               }
            }
         ]
      },
      {
         "connection":{
            "server_url":"test2",
            "username":"userB",
            "password":"123456"
         },
         "actions":[
            {
               "type":"exportXML",
               "parameters":{
                  "param1":"1234",
                  "param2":"5678"
               }
            }
         ]
      }
   ]
}
"""


class Connection(object):
    def __init__(
        self,
        server_url,
        username,
        password,
    ):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.server_url = server_url
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({
            'Content-Type': 'application/vnd.testbench+json; charset=utf-8'
        })
        self.session.hooks = {
            'response': lambda r, *args, **kwargs: 
                r.raise_for_status()
        }
        # TODO: timeout handling
        # TODO: use with for reliable session closing?
        
    """    
    @staticmethod
    def handle_connection_errors(f: function):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except SomeException as e:
                return my_exception_response
            except OtherException as e:
                return other_response

        return decorated
    """

    def check_is_working(self) -> bool:
        response = self.session.get(
            self.server_url + 'projects',
            verify=False, # TODO: throws SSL error in test env if True
            params={
                "includeTOVs": "false",
                "includeCycles": "false",
        })

        response.json()
        
        return True
        
    def get_all_projects(self) -> dict:
        all_projects = self.session.get(
            self.server_url + 'projects',
            verify=False,
            params={
                "includeTOVs": "false",
                "includeCycles": "false"
            })

        return all_projects