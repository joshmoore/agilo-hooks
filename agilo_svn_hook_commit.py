#!/usr/bin/python2.6
# -*- encoding: utf-8 -*-
#   Copyright 2008 Agile42 GmbH, Berlin (Germany)
#   Copyright 2007 Andrea Tomasini <andrea.tomasini_at_agile42.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#   Author: Andrea Tomasini <andrea.tomasini_at_agile42.com>

"""
agilo_svn_pre_commit.py

Created by Andrea Tomasini on 2008-03-12.
Copyright (c) 2008 Agile42 GmbH, Berlin - Germany. All rights reserved.

This is a script to hook the subversion events pre-commit and post-commit.
In order to use it, create two scripts in the /svn/repos/hooks directory
something like this:

pre-commit:
[----------- cut here -------------]
#!/bin/sh
REPOS="$1"
TXN="$2"
# Make sure that the log message contains some text.
SVNLOOK=/usr/bin/svnlook
PYTHON_EGG_CACHE=/var/cache/python
TRAC_ENV="/var/lib/trac/test"
LOG=`$SVNLOOK log -t "$TXN" "$REPOS"`
/where/ever/is/agilo_svn_hook_commit.py -s pre -e "$TRAC_ENV" -l "$LOG" || exit 1
[----------- cut here -------------]

post-commit:
[----------- cut here -------------]
#!/bin/sh
REPOS="$1"
REV="$2"
TRAC_ENV='/var/lib/trac/test/'
/var/lib/svn/local/hooks/agilo_svn_hook_commit.py -s post -e "$TRAC_ENV" -r "$REV" || exit 1
[----------- cut here -------------]
"""

import sys
import getopt
from agilo.utils.svn_hooks import AgiloSVNPreCommit, AgiloSVNPostCommit

help_message = '''
Use as a SVN hook, options:
     -s --svn_hook= [pre|post] default to pre.
     -e --env=      <trac_env> 
     -l --log=      <svn_log>
     -r --rev=      <revision>, should be an integer.
'''


class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg


def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        env = log = rev = None
        hook = 'pre'
        try:
            opts, args = getopt.getopt(argv[1:], "he:l:s:r:", ["help", "env=", "svn_hook=", "log=", "rev="])
        except getopt.error, msg:
            raise Usage(msg)
            
        # option processing
        for option, value in opts:
            if option in ("-h", "--help"):
                raise Usage(help_message)
            if option in ("-e", "--env"):
                env = str(value)
            if option in ("-l", "--log"):
                log = unicode(value)
            if option in ("-s", "--svn_hook"):
                if value == 'post':
                    hook = value
            if option in ("-r", "--rev"):
                rev = int(value)
        if (env is None or log is None) and (hook == 'post' and rev is None):
            raise Usage(help_message)
        else:
            if hook == 'pre':
                agilo_hook = AgiloSVNPreCommit(project=env, log=log)
            else:
                agilo_hook = AgiloSVNPostCommit(project=env, rev=rev)
            try:
                if agilo_hook.execute():
                    return 0
            except Exception, e:
                print >> sys.stderr, str(e)
                return 2
                
    except Usage, err:
        print >> sys.stderr, sys.argv[0].split("/")[-1] + ": " + str(err.msg)
        print >> sys.stderr, "\t for help use --help"
        return 2


if __name__ == "__main__":
    sys.exit(main())
