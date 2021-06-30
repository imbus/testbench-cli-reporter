# Copyright 2021 - imbus AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import json
from testbench import ConnectionLog
import util

__version__ = '0.0.1'

def main(args):
    if has_config_file(args):
        run_automatic_mode(args)
    else:
        print("No config file given")
        run_manual_mode()  

def has_config_file(args):    
    if args.configFile is None:
        return False
    else:
        return True

def get_configuration(args):
    print("Trying to read config file")
    with open(args.configFile, 'r') as configFile:
        configuration = json.load(configFile)
        # handle various file opening errors
        # handle json parse errors
        # try to execute orders as configured (what if this leads to an error, e.g. insufficient data or project not found?)

    return configuration

def run_manual_mode():
    # TODO gracefully exit on keyboard interrupt
    print("Starting manual mode")
    connection_log = ConnectionLog()
    
    while True:
        active_connection = util.login()
        connection_log.add_connection(active_connection)
        next_action = util.choose_action()
        while next_action is not None:
            execution_success = next_action.execute(connection_log)
            if execution_success: 
                active_connection.add_action(next_action)
            active_connection = connection_log.active_connection()
            next_action = util.choose_action()

def run_automatic_mode():
    print("Run Automatic Mode (not implemented yet)")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--configFile", help="Path to a config file to execute pre-set actions based on the given configuration.", type=str)
    args = parser.parse_args()
    main(args)