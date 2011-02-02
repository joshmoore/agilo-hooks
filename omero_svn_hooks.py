# -*- encoding: utf-8 -*-
#   Copyright 2008 Agile42 GmbH, Berlin (Germany)
#   Copyright 2007 Andrea Tomasini <andrea.tomasini__at__agile42.com>
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
#   Authors: 
#        - Andrea Tomasini <andrea.tomasini__at__agile42.com>

import sys
import re

from trac.env import Environment
from trac.util.text import to_unicode

from agilo.ticket.model import AgiloTicket, AgiloTicketModelManager
from agilo.utils import Key, Status
from agilo.utils.errors import *
from agilo.utils.config import AgiloConfig
#TODO: Import and use to invalidate cache from the SVN hook, only works when 
# there will be a .lock file as invalidation.
# from agilo.charts.chart_generator import ChartGenerator

__all__ = ['AgiloSVNPreCommit', 'AgiloSVNPostCommit']

# Commands definition and regular expressions .....................................

CLOSE_COMMANDS = ['close', 'closed', 'closes', 'fix', 'fixed', 'fixes']
REFER_COMMANDS = ['addresses', 're', 'references', 'refs', 'see']
REMAIN_COMMANDS = ['remaining', 'still', 'rem_time', 'time', 'rem']
ALL_COMMANDS = CLOSE_COMMANDS + REFER_COMMANDS + REMAIN_COMMANDS
COMMANDS_PATTERN = r'(?P<command>' + r'|'.join(ALL_COMMANDS) + r')'
TIME_PATTERN = r'(?:[0-9]+)(?:\.[0-9]+)?[hd]?' # REFACT: consider to enforce a word break after the time pattern
 # REFACT: having the colon with the time pattern is wrong - but since this regex is not used to 
TICKET_PATTERN = r'#[0-9]+(\:' + TIME_PATTERN + r')?'
TICKETS_PATTERN = r'(?P<ticket>' + TICKET_PATTERN + r'(?:(?:\s*(,|&|(?:and))\s*)' + TICKET_PATTERN + r')*)'
COMMAND_AND_TICKET_PATTERN = COMMANDS_PATTERN + r'\s*' + TICKETS_PATTERN
COMMAND_AND_TICKET_REGEX = re.compile(COMMAND_AND_TICKET_PATTERN, re.DOTALL|re.IGNORECASE)
# REFACT: try to use this ticket pattern above too (but to do so we'd need to get 
# rid of the named groups as the pattern is used more than once)
TICKET_REGEX = re.compile(r'#(?P<ticket_id>[0-9]+)(?:\:(?P<remaining_time>' + TIME_PATTERN + '))?')

# Parser ...........................................................................

class CommitMessageCommandParser(object):
    
    def __init__(self,env, a_commit_message):
        self.env = env
        self.message = a_commit_message
        # REFACT: rename tm to ticket_model_manager to make the type clearer
        self.tm = AgiloTicketModelManager(self.env)
        
        self.validation_errors = list()
        self.commands = list()
    
    def validate_and_parse_commit_message(self):
        if '' == self.message:
            self.abort_with_usage("Please provide a comment")
        
        # Now get all the commands and tickets out of the log and check whether are valid or not
        #print "Message: %s" % repr(self.message)
        #print 'regex:', COMMAND_AND_TICKET_PATTERN
        for match in COMMAND_AND_TICKET_REGEX.finditer(self.message):
            command = match.group('command')
            #print "Expression matching: <%s> <%s> group(0) <%s>" % (match.group('command'), match.group('ticket'), match.group(0))
            for ticket_id, remaining_time in TICKET_REGEX.findall(match.group('ticket')):
                #print 'command', command, 'ticket_id', ticket_id, 'remaining_time', remaining_time
                # Check that the ticket is existing first
                ticket = self.validate_and_get_ticket(ticket_id)
                
                if not ticket:
                    continue
                
                if self.does_command_require_remaining_time(command):
                    self.validate_is_remaining_time_set(command, remaining_time)
                    self.validate_includes_configured_unit_in_remaining_time(remaining_time)
                    self.validate_can_change_remaining_time_on_ticket(ticket, remaining_time)
                else:
                    self.validate_no_remaining_time_set(command, remaining_time)
                
                self.commands.append((command, ticket_id, remaining_time))
        if len(self.validation_errors) > 0:
            #print >> sys.stderr, "\n".join(self.validation_errors)
            raise InvalidAttributeError("\n".join(self.validation_errors))
        
        return self.commands
    
    def validate_and_get_ticket(self, ticket_id):
        try:
            t_id = int(ticket_id.replace('#', ''))
            ticket = self.tm.get(tkt_id=t_id)
            return ticket
        except Exception, e:
            self.validation_errors.append("Unable to verify ticket #%s, reason: '%s'" % (ticket_id, to_unicode(e)))
            return None
    
    def does_command_require_remaining_time(self, command):
        return command.lower() in REMAIN_COMMANDS
    
    def validate_is_remaining_time_set(self, command, remaining_time):
        if '' == remaining_time:
            self.validation_errors.append("Missing remaining time for command '%s'" % command)
    
    def validate_no_remaining_time_set(self, command, remaining_time):
        if '' != remaining_time:
            self.validation_errors.append("Cannot set remaining time with command '%s'" % command)
    
    def validate_can_change_remaining_time_on_ticket(self, ticket, remaining_time):
        if not ticket.is_readable_field(Key.REMAINING_TIME):
            self.validation_errors.append("Remaining time is not an allowed property for this ticket #%s" \
                " of type: '%s', with remaining time: %s" % (ticket.id, ticket.get_type(), remaining_time[1:]))
        #print "Error: %s" % self.validation_errors[-1:]
    
    def validate_includes_configured_unit_in_remaining_time(self, remaining_time):
        if len(remaining_time) > 0 and remaining_time[-1] not in ('h', 'd'):
            self.validation_errors.append("Need h(our) or d(ay) unit for remaining time '%s'" % remaining_time)
            return
        
        config = AgiloConfig(self.env)
        if config.use_days and remaining_time.endswith('h'):
            self.validation_errors.append("Wrong unit used in remaining time '%s' (Agilo is configured to use days)" % remaining_time)
        if not config.use_days and remaining_time.endswith('d'):
            self.validation_errors.append("Wrong unit used in remaining time '%s' (Agilo is configured to use hours)" % remaining_time)
    
    # REFACT: consider to add a custom abort message
    # TODO: unused - remove? Use for empty commit message?
    def abort_with_usage(self, message):
        raise ParsingError("%s\n" \
           "Supported commands include:\n" \
           "Close Tickets: %s\n" \
           "Refer Tickets: %s\n" \
           "Remaining Time: %s\n" % \
           (message, CLOSE_COMMANDS, REFER_COMMANDS, REMAIN_COMMANDS))

# SVN Hooks ...........................................................................

class AgiloSVNPreCommit(object):
    """
    An Agilo SVN hook to process the SVN comment before the commit.
    It checks whether there are valid tickets number into the comment, 
    and in case there are valid tickets, it checks that if there is a
    remaining_time specified than the ticket is of type task and it is 
    not closed.
    """
    def __init__(self, project, log, env=None):
        """Initialize the class with the project path and the revision"""
        try:
            self.env = env or Environment(project)
            self.parser = CommitMessageCommandParser(self.env, log)
        except Exception, e:
            #print_exc()
            print >> sys.stderr, "An Error occured while opening Trac project: '%s' => %s" % \
                                 (project, to_unicode(e))
            print >> sys.stderr, "AgiloSVNPreCommit initialized with: '%s' %s, '%s' %s" % \
                                 (project, type(project), log, type(log))
            sys.exit(1)
        
    def execute(self):
        """Execute the hook"""
        return self.parser.validate_and_parse_commit_message()
    

class AgiloSVNPostCommit(object):
    """
    An Agilo SVN hook to process the SVN comment after the commit.
    To use it just call it as AgiloSVNPostCommit() from a script called
    post-commit into the <repository>/hooks/ folder of your SVN server.
    Tries to keep compatibility with the trac-post-commit-hook.py written
    by Stephen Hansen, Copyright (c) 2004 and distributed. 
    """
    def __init__(self, project, rev, repo, env=None):
        """Initialize the class with the project path and the revision"""
        try:
            self.env = env or Environment(project)
            self.tm = AgiloTicketModelManager(self.env)
            self.repo = repo
            repos = self.env.get_repository(self.repo)
            repos.sync()
        except Exception, e:
            print >> sys.stderr, "An Error occurred while opening Trac project: %s => %s" % (project, to_unicode(e))
            sys.exit(1)
        # Now let's read the last committed revision data
        try:
            self.changeset = repos.get_changeset(rev)
        except Exception, e:
            print >> sys.stderr, "Impossible to open revision: %s, due to the following error: %s" % (rev, to_unicode(e))
            sys.exit(1)
        self.author = self.changeset.author
        self.rev = rev
        suffix = self.repo is not None and "/%s" % self.repo or ""
        self.message = "(In [%s%s]) %s" % (rev, suffix, self.changeset.message)
    
    def execute(self):
        """Execute the parsed commands"""
        #print "Commands: %s" % self.commands
        # Now parse the command in the ticket, and react accordingly
        # Cannnot produce error messages, as the pre-commit-hook would have failed already
        parser = CommitMessageCommandParser(self.env, self.changeset.message)
        parsed_commands = parser.validate_and_parse_commit_message()
        self.commands = dict()
        for command, ticket_id, remaining_time in parsed_commands:
            # REFACT: the parser should give the ids as ints already
            ticket_id = int(ticket_id)
            self.commands.setdefault(ticket_id, list())
            self.commands.get(ticket_id).append(
                self.findCommand(command, remaining=remaining_time[:-1]))
        # Sort the ticket in reverse order by id, it will be most likely
        # that a task is existing after a User Story has been created, 
        # in which case it will be possible to execute multiple command in
        # a hierarchy. TODO: Check hierarchy, but very expensive
        keys = self.commands.keys()
        keys.sort(reverse=True)
        for t_id, cmds in [(key, self.commands[key]) for key in keys]:
            ticket = self.tm.get(tkt_id=t_id)
            for cmd in cmds:
                cmd(ticket)
            self.tm.save(ticket, author=self.author, comment=self.message)
            from trac.ticket.notification import TicketNotifyEmail
            tn = TicketNotifyEmail(self.env)
            tn.notify(ticket, newticket=False, modtime=ticket.time_changed)
        # We need to invalidate the chart cache here because some tickets may
        # have been closed through commit comments. Unfortunately there is 
        # no way to access the shared memory right now, see #565
        return True
    
    def findCommand(self, cmd, **kwargs):
        """
        Returns the command corresponding to the given pattern, and
        the given parameter, so that the method can be called later
        """
        def closeCommand():
            """
            Closes a ticket and applies all the defined rules
            """
            def execute(ticket):
                if isinstance(ticket, AgiloTicket):
                    if ticket.is_writeable_field(Key.REMAINING_TIME):
                        # Check if the task as been assigned
                        if ticket[Key.STATUS] in (Status.ACCEPTED, Status.ASSIGNED) or True: ## OMERO-specific behavior
                            # If the author is the owner of the ticket close it
                            owner = ticket[Key.OWNER]
                            if owner == self.author or True: ## OMERO-specific behavior
                                ticket[Key.STATUS] = Status.CLOSED
                                ticket[Key.RESOLUTION] = Status.RES_FIXED
                                ticket[Key.REMAINING_TIME] = '0'
                            else:
                                raise NotOwnerError("You (%s) are not the owner of this task (%s)," \
                                                    " can't close it!" % (self.author, owner))
                        else:
                            raise NotAssignedError("The task(#%d) is not assigned (%s), you have to accept" \
                                                   " it before closing it!" % \
                                                   (ticket.get_id(), ticket[Key.STATUS]))
                    else:
                        # Check if all the linked items are closed than close it
                        close = True
                        for linked in ticket.get_outgoing():
                            if linked[Key.STATUS] != Status.CLOSED:
                                close = False
                                break
                        if close:
                            ticket[Key.STATUS] = Status.CLOSED
                            ticket[Key.RESOLUTION] = Status.RES_FIXED
                        else:
                            raise DependenciesError("The ticket(#%d) of type: '%s' has still "\
                                                    "some open dependencies... can't close it!" % \
                                                    (ticket.get_id(), ticket.get_type()))
            # Return the method
            return execute
        
        def remainCommand(**kwargs):
            """
            Sets the remaining time for the given linked end point
            """
            remaining_time = 0
            #print "Arguments: %s" % kwargs
            if kwargs and len(kwargs) > 0:
                if kwargs.has_key('remaining'):
                    # If conversion fails it will raise an exception
                    remaining_time = kwargs['remaining']
                    #print "Remaining time detected: %s" % remaining_time
            def execute(ticket):
                if isinstance(ticket, AgiloTicket) and ticket.is_writeable_field(Key.REMAINING_TIME):
                    # Check if the task is assigned and the current author is the owner
                    owner = ticket[Key.OWNER]
                    if owner == self.author or True: ## OMERO-speciic behavior
                        ticket[Key.REMAINING_TIME] = remaining_time
                        if ticket[Key.STATUS] not in (Status.ASSIGNED, Status.ACCEPTED):
                            # If the ticket is not already accepted, set it to assigned
                            ticket[Key.STATUS] = Status.ACCEPTED
                    else:
                        raise NotOwnerError("You (%s) are not the owner (%s) of the task(#%d)"\
                                            " changing the remaining time is not allowed!" % \
                                            (self.author, owner, ticket.get_id()))
                else:
                    raise InvalidAttributeError("The ticket(#%d) type %s, doesn't allow the attribute: %s" % \
                                                (ticket.get_id(), ticket.get_type(), Key.REMAINING_TIME))
            # Return the method
            return execute
            
        def voidCommand(**kwargs):
            """Does intentionally nothing"""
            def execute(ticket):
                pass
            # Return the doing nothing method ;-)
            return execute
        
        # Find the right command
        cmd = cmd.lower()
        #print "Command received: %s" % cmd
        if cmd in CLOSE_COMMANDS:
            return closeCommand()
        elif cmd in REFER_COMMANDS:
            return voidCommand()
        elif cmd in REMAIN_COMMANDS:
            return remainCommand(**kwargs)
        else:
            return voidCommand()
        
