#!/usr/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# All rights reserved.

# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import os
import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath
import platform

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
elif platform.system() == 'Darwin':
    LOG_FILE = "/Library/Ossec/logs/active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg +"\n")


def setup_and_check_message(argv):

    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return message


def main(argv):

    write_debug_file(argv[0], "Started")

    # validate json and get command
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:

        """ Start Custom Action Add Delete User in Database"""
        import subprocess

        # Configure MySQl Access
        db_user = "wordpress_user" #Database user
        db_pass = "12345678" #Database password
        db_name = "wordpress_db" #Database name
        admin_asli = "'arif', 'wahyu', 'farah', 'bagas', 'firmino'" # Change based on authenticated user

        # Query SQL for delete unauthenticated user from CSRF
        sql_query = f"DELETE FROM wp_users WHERE user_login NOT IN ({admin_asli}) AND ID IN (SELECT user_id FROM wp_usermeta \
                    WHERE meta_key='wp_user_level' AND meta_value='10'); DELETE FROM wp_usermeta WHERE user_id NOT IN (SELECT \
                    ID FROM wp_users);"

        try:
            # Executing SQL Command
            cmd = f'mysql -u"{db_user}" -p"{db_pass}" "{db_name}" -e "{sql_query}"'
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            write_debug_file(argv[0], f"Successfully removed unauthorized administrators from database.")
        except subprocess.CalledProcessError as e:
            write_debug_file(argv[0], f"Error executing MySQL query: {e.stderr.decode().strip()}")

        """ End Custom Action Add """

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")

    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)