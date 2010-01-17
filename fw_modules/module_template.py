#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# module_template.py - WIDS/WIPS framework template library module
# Copyright (C)  2009 Peter Krebs, Herbert Haas
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2 as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see http://www.gnu.org/licenses/gpl-2.0.html

"""Module template

Library module containing common code for framework modules.
To create new modules or templates subclass the appropriate classes
and overwrite the necessary functions.

"""

# Imports
#
# Custom modules
from fw_modules.module_exceptions import *

# Standard modules
import copy
import logging
import os, os.path
import Queue
import re
import socket
import sys
import threading
import time

# Third-party modules
try:
    from lxml import etree
    from lxml.etree import DocumentInvalid
except ImportError:
    print "Couldn't import module 'lxml'"
    sys.exit(1)

# Top level definitions and functions
def normalise_xml_text(xml_text):
    """normalise_xml_text()
    
    Helper function. Removes redundant whitespace and quotes from parsed text.
    
    """
    
    # Remove whitespace around parsed text.
    normalised_text = ' '.join(xml_text.split())
    # Remove first occurence of double or single quotes around parsed text.
    normalised_text = re.sub('^\"', '', normalised_text, 1)
    normalised_text = re.sub('\"$', '', normalised_text, 1)
    return normalised_text

def parse_xml_content(xml_text, type=None):
    """parse_xml_content()
    
    Returns the content of an xml element normalised 
    and in the right type (e. g. as list or hex)
    
    """
    
    xml_text_normalised = normalise_xml_text(xml_text)
    if type == None:
        return xml_text_normalised
    elif type == 'int':
        return int(xml_text_normalised)
    elif type == 'long':
        return long(xml_text_normalised)
    elif type == 'float':
        return float(xml_text_normalised)
    elif type == 'hex':
        return xml_text_normalised.decode('hex')
    elif type == 'list':
        if xml_text_normalised:
            return xml_text_normalised.split(',')
        else:
            return []
    else:
        print "ERROR: Type", type, "not valid"
        return None

def validate_xml_config(xmlfile, schemafile):
    """validate_xml_config()
    
    Validates a XML configuration file with a XML schema.
    Returns True if file is valid.
  
    """
  
    # Check if files are available
    if not os.path.isfile(xmlfile):
        print "ERROR: Couldn't find xml file:", xmlfile
        raise FwFileNotAvailableError(xmlfile)
        return False
    if not os.path.isfile(schemafile):
        print "ERROR: Couldn't find schema file:", schemafile
        raise FwFileNotAvailableError(schemafile)
        return False
    config_object = etree.parse(xmlfile)                # create xml tree object for configuration file
    schema_object = etree.XMLSchema(etree.parse(schemafile))            # create tree object for schema
    try:
        schema_object.assertValid(config_object)            # validate xml tree object
    except DocumentInvalid as err:
        print "ERROR: Validation FAILED"
        del config_object, schema_object
        raise FwConfigNotValidError(err.__str__())
    else:
        print "Validation SUCCESSFUL"
        del config_object, schema_object
        return True
    

# Base classes for modules and templates.
class ModuleClass(threading.Thread):
    """ModuleClass
    
    Defines common methods for framework modules.
    Methods might be overwritten in subclasses (this is not an interface!)
    
    """
        
    def __init__(self, controller, param_dict, logger):
        """Constructor
        
        Common constructor for all module classes.
        Requires three parameters:
            controller ... reference of the local controller instance
            param_dict ... dictionary containing the instance parameters
            logger     ... logger object for submodule logging
        
        """
        
        # Call constructor of Thread class for inheritance.
        threading.Thread.__init__(self)
        # Get default values from parameter dictionary.
        self.param_dict = copy.deepcopy(param_dict)         # Make a deepcopy of the param dict to decouple from calling module (controller).
        self.controller_reference = controller
        try:
            self.module_identifier = self.param_dict['module_identifier']
        except KeyError:
            raise FwModuleSetupError, self.module_identifier + ": ERROR: No module identifier specified!"
        if logger:
            self.module_logger = logger
        else:
            raise FwModuleSetupError, "No module logger set for module " + self.module_identifier
        try:
            self.module_address = self.param_dict['module_address']
        except KeyError:
            self.module_address = None
        try:
            self.template_config_dict = self.param_dict['template_config']
        except KeyError:
            self.template_config_dict = {}
        try:
            self.default_target_group = self.param_dict['default_target_group']
        except KeyError:
            self.default_target_group = None
        # Helper variables.
        self.stop_thread = False
        self.socket_thread = None           # holds socket thread if started
        self.communication_socket = None            # Holds socket object for remote connection
        self.input_buffer = Queue.Queue()
        self.msg_id_counter = 0
        self.target_reference_dict = {'local':{}, 'remote':{}}
        self.template_status_dict = {}
        
    def add_target(self, target_identifier, target_type, target_groups, target_reference=None):
        """add_target()
        
        Adds a target module instance to the target reference dict.
        
        """
        
        if target_type == 'local':
            self.target_reference_dict['local'][target_identifier] = {'target_reference':target_reference, 'target_groups':target_groups}
            self.module_logger.info("Added local target " + target_identifier + " to module instance")
        elif target_type == 'remote':
            remote_address = target_identifier.split(':')
            if len(remote_address) == 2:
                hostname = remote_address[0]
                port = int(remote_address[1])
                self.target_reference_dict['remote'][target_identifier] = {'hostname':hostname, 'port':port, 'target_groups':target_groups}
                self.module_logger.info("Added remote target with address " + hostname + " and portnumber " + port + " to module instance")
            else:
                self.module_logger.error("Couldn't resolve remote target identifier " + target_identifier)   
        self.module_logger.debug("Target dictionary after target add: " + str(self.target_reference_dict))
        
    def add_template(self, template_identifier, template_reference):
        """add_template()
        
        Adds context information of a template to the template status dictionary.
        
        """
        
        self.module_logger.info("Add template " + template_identifier + " to status dict")
        self.template_status_dict[template_identifier] = {'template_reference':template_reference}
        self.module_logger.debug("Template status dictionary: " + str(self.template_status_dict))

    def after_run(self):
        """before_run()
        
        Is executed right after the module instance exits the main action loop.
        Method is overwritten in concrete modules to implement logic which should
        be executed after the main loop (e. g. file close)
        
        Must return True on success and False on error.
        
        """
        
        self.module_logger.debug("after_run method not implemented")
        return True

    def before_run(self):
        """before_run()
        
        Is executed right before the module instance enters the main action loop.
        Method is overwritten in concrete modules to implement logic which should
        be executed before the main loop (e. g. file checks)
        
        Must return True on success and False on error.
        
        """
        
        self.module_logger.debug("before_run method not implemented")
        return True
    
    def generate_message(self, msg_type, msg_name, msg_description, msg_rule, msg_severity, msg_subtype, msg_data, frame_data, receiver_group=None):
        """generate_message()
        
        Generates messages for inter-module communication.
        Each message is assigned a unique identifier and must
        adhere to a set structure.
        
        """
        
        # Generate a unique event id by concatenating detection module identifier, timestamp and an incrementing counter.
        if self.msg_id_counter >= 1000000000:
            self.msg_id_counter = 0
        msg_identifier = self.module_identifier + '_' + str(int(time.time())) + '_' + str(self.msg_id_counter).zfill(9) 
        self.msg_id_counter = self.msg_id_counter + 1
        # Send event data as output.
        self.module_logger.debug("Received message data: " + str(msg_identifier) + " ; " + str(msg_name) + " ; " + str(msg_description) + " ; " + str(msg_rule) + " ; " + str(msg_severity) + " ; " + str(msg_subtype) + " ; " + str(msg_data))
        try:
            self.output(''.join(['MSGTYPE_', msg_type, '|MSGID_', msg_identifier, '|MSGNAME_', msg_name, '|MSGDESCR_', msg_description, '|MSGRULE_', msg_rule, '|MSGSEV_', str(msg_severity), '|MSGSUBTYPE_', msg_subtype, '|MSGDATA_', msg_data, '|FRAMEDATA_', frame_data]), receiver_group)
        except TypeError as err:
            self.module_logger.error("Received message data not valid; details: " + err.__str__())
        
    def initialise(self):
        """initialise()
        
        Executes the before_run method to set up the module in an initial state and
        starts the module in a thread by calling the start method afterwards.
        Assures that the module setup is finished before starting the thread.
        
        """
        
        self.module_logger.info("Initialising...")
        if not self.before_run():
            self.module_logger.error("Module setup failed!")
            return False
        else:
            self.module_logger.info("Starting module main thread")
            self.start()
            return True

    def input(self, input):
        """input()
        
        Input interface.
        Writes input into the module's input buffer.
        
        """
        
        self.module_logger.debug("Received input: " + str(input))
        try:
            self.input_buffer.put_nowait(input)
        except Queue.Full:          # this should not happen because we use an unboundd queue, but for safety...
            pass
        self.module_logger.debug("Buffer size: " + str(self.input_buffer.qsize()))
        
    def input_socket(self):
        """input_socket()
        
        Reads remote input from UDP socket and puts it into the input buffer.
        Is executed in a separate thread to allow parallel local input
        through the (blocking) input buffer queue.
        
        """
        
        self.module_logger.info("Entering socket receiver thread")
        while not self.stop_thread:
            input_data, addr = self.communication_socket.recvfrom(65535)            # read from socket with max buffersize
            self.input(input_data)
            
    def load_templates(self):
        """load_templates()
        
        Loads all configured templates for the module.
        Creates and adds a child logger for the template 
        based on the module logger.
        
        """
        
        self.module_logger.info("Loading templates")
        for template_identifier, template_info in self.template_config_dict.items():
            template_module_path = template_info['template_name']
            self.module_logger.info("Loading template " + template_identifier + " with name " + template_module_path)
            # Import templates.
            try:
                __import__(template_module_path)
            except ImportError:
                raise FwTemplateSetupError, "Couldn't import template " + template_module_path
                return False
            else:
                try:
                    template_module = sys.modules[template_module_path]
                except (NameError, AttributeError) as err:
                    raise FwTemplateSetupError, "Couldn't create reference for template " + template_identifier + "; Detail: " + err.__str__()
                    return False
                else:
                    try:
                        if self.module_logger:
                            template_logger = logging.getLogger(self.module_logger.__dict__['name'] + "." + template_identifier)
                            if template_info['template_loglevel']:
                                self.module_logger.info("Setting custom loglevel '" + template_info['template_loglevel']['loglevel_name'] + "' for template " + template_identifier)
                                template_logger.setLevel(template_info['template_loglevel']['loglevel_object'])
                        else:
                            template_logger = None
                        template_reference = template_module.main(self, template_info['template_values'], template_logger)
                    except FwTemplateSetupError:
                        raise
                    else:
                        if template_reference.template_setup():
                            self.module_logger.info("Set up template " + template_identifier)
                            self.add_template(template_identifier, template_reference)
                        else:
                            raise FwTemplateSetupError, "Couldn't set up template " + str(template_identifier)
        
    def output(self, output, target_group=None):
        """output()
        
        Sends output data to all configured target module instances.
        Distinguishes between local targets (through reference) and remote targets (through socket).
        If a target group is specified, output only goes to targets belonging to this group.
        
        """
        
        self.module_logger.debug("Target dictionary: " + str(self.target_reference_dict))
        # Set target group to default if not set.
        if not target_group:
            target_group = self.default_target_group
        # Send to local modules through references.
        for target_id in self.target_reference_dict['local'].keys():
            if target_group and target_group not in self.target_reference_dict['local'][target_id]['target_groups']:        # if target does not belong to specified group, skip it
                self.module_logger.info("Skipped local target " + str(target_id) + ", receiver group does not match")
                continue
            self.module_logger.info("Sending frame data to local target with id: " + str(target_id))
            self.module_logger.debug("Data sent: " + str(output))
            try:
                self.target_reference_dict['local'][target_id]['target_reference'].input(output)
            except AttributeError:
                self.module_logger.error("Local target with id " + str(target_id) + " is not a suitable target reference")        
        for target_id in self.target_reference_dict['remote'].keys():
            if self.communication_socket:
                if target_group and target_group not in self.target_reference_dict['remote'][target_id]['target_groups']:        # if target does not belong to specified group, skip it
                    self.module_logger.info("Skipped remote target " + str(target_id) + ", receiver group does not match")
                    continue
                self.module_logger.info("Sending frame data to remote target with address: " + str(target_id))
                self.module_logger.debug("Data sent: " + str(output))
                try:
                    self.communication_socket.sendto(output, (self.target_reference_dict['remote'][target_id]['hostname'], self.target_reference_dict['remote'][target_id]['port']))
                except socket.error as err:
                    self.module_logger.error("Couldn't send output to remote target; details:" + err.__str__())
            else:
                self.module_logger.warning("Couldn't send output to remote target, no socket available")
        
    def process(self, input):
        """process()
        
        Is executed when new input is available.
        Is implemented in the concrete module to do some action with the input.
        
        """
        
        self.module_logger.info("No process function implemented, nothing to do")       
        
    def remove_target(self, target_identifier):
        """remove_target()
        
        Removes a target module instance from the target reference dict.
        
        """
        
        if self.target_reference_dict['local'].has_key(target_identifier):
            del self.target_reference_dict['local'][target_identifier]
            self.module_logger.info("Removed local target " + target_identifier + " from module instance")
        elif self.target_reference_dict['remote'].has_key(target_identifier):
            del self.target_reference_dict['remote'][target_identifier]
            self.module_logger.info("Removed remote target " + target_identifier + " from module instance")
        else:
            pass            # if module to remove is not a target just ignore it
        self.module_logger.debug("Target dictionary after target remove: " + str(self.target_reference_dict))
        
    def remove_template(self, template_identifier):
        """remove_template()
        
        Removes a template reference from the template status dictionary.
        
        """
        
        try:
            del self.template_status_dict[template_identifier]
            self.module_logger.info("Removed template with identifier " + template_identifier + " from status dict")
        except KeyError:
            self.module_logger.warning("Couldn't remove template with identifier " + str(template_identifier) + " from template status dictionary, template not present")
        
    def run(self):
        """run()
        
        Starts the main loop of the module instance.
        Receives local data over input buffer and remote data through socket.
        
        """
        
        self.controller_reference.set_module_status(self.module_identifier, 'running')
        self.communication_socket = self.set_socket()
        # Enter module instance main action loop
        if self.module_address and self.communication_socket:           # if module instance listens to remote data, start socket listener additionally
            # Start socket listener in separate thread to allow concurrent local and remote inputs.
            self.socket_thread = threading.Thread(target=self.input_socket, args=())
            self.socket_thread.start()
        self.module_logger.info("Enter main loop for local input")
        self.controller_reference.unlock_next_thread()
        while not self.stop_thread:
            # Process next input item from buffer if present.
            next_input = self.input_buffer.get()
            if next_input != 'STOP':
                self.process(next_input)
            else:
                self.module_logger.info("Received STOP directive from controller")
        self.module_logger.info("Leaving main loop")
        # Run some cleanup logic
        if self.communication_socket:
            self.communication_socket.close()           # close active socket
        self.after_run()
        self.controller_reference.set_module_status(self.module_identifier, 'stopped')
        return True         # at this point the module instance thread stops
            
    def set_socket(self):
        """set_socket()
        
        Sets up an UDP socket for sending and receiving 
        remote data to and from other modules.
        
        """
        
        # Set socket only if at least one receiver is remote or module has local address configured.
        if self.module_address or self.target_reference_dict['remote']:
            self.module_logger.info("Setting up socket")
            try:
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)            # enable reuse of socket address in case program breaks and blocks socket
                if self.module_address:
                    address = (self.param_dict['module_address']['hostname'], self.param_dict['module_address']['port'])
                    udp_socket.bind(address)            # bind socket to local address only if needed
                return udp_socket
            except (socket.error, TypeError) as err:
                self.module_logger.error("Couldn't set up socket; details " + err.__str__())
                raise
                return False
            
    def shutdown_templates(self):
        """shutdown_templates()
        
        Calls the shutdown method of all loaded templates for clean exit.
        
        """
        
        self.module_logger.info("Shutting down templates")
        for template_identifier, template_info in self.template_status_dict.items():
            self.module_logger.info("Shutting down template " + template_identifier)
            if not template_info['template_reference'].template_shutdown():
                self.module_logger.error("Couldn't shut down template " + template_identifier)
            else:
                self.module_logger.info("Removing template " + template_identifier + " from status dictionary")
                self.remove_template(template_identifier)
        return True
            
    def stop(self):
        """exit()
        
        Sets the stop flag of the module instance process
        to terminate module main loop and thread.
        
        """
        
        self.module_logger.info("Stopping...")
        self.stop_thread = 1


class TemplateClass():
    """TemplateClass
    
    Base class for templates.
    
    """
    
    def __init__(self, engine=None, param_dict=None, logger=None):
        """Template constructor
        
        """
        
        if param_dict:
            self.param_dict = param_dict
        else:
            raise FwTemplateSetupError, "No template parameter dict provided"
        try:
            self.template_identifier = self.param_dict['template_identifier']
        except KeyError:
            raise FwTemplateSetupError, "No template identifier specified"
        if logger:
            self.template_logger = logger
        else:
            raise FwTemplateSetupError, "No module logger set for module " + self.template_identifier
        self.engine_reference = engine              # reference to requesting engine module
        self.target_template_dict = {}
        
    def template_add_target(self, target_identifier, target_reference):
        """template_add_target()
        
        Adds a new target template to target template dictionary.
        Not yet used.
        
        """
        
        self.target_template_dict[target_identifier] = target_reference
        self.template_logger.info("Added target template with identifier " + target_identifier)
        
    def template_input(self, input):
        """template_input()
        
        Standard input interface for template.
        Is implemented in concrete template to process input.
        
        """
        
        self.template_logger.info("No input processing method implemented, nothing to do")
        return True
        
    def template_output(self, output):
        """
        
        Standard output interface for template.
        Is implemented in concrete template.
        
        """
        
        self.template_logger.info("No output method implemented, nothing to do")
        return True
        
    def template_remove_target(self, target_identifier):
        """template_remove_target()
        
        Removes a target template from the target template dictionary.
        Not yet used.
        
        """
        
        try:
            del self.target_template_dict[target_identifier]
            self.template_logger.info("Removed target " + target_identifier + " from module instance")
        except KeyError:
            self.template_logger.warning("Couldn't remove template with identifier " + str(target_identifier) + " from target dictionary, template not present")
        
    def template_setup(self):
        """template_setup()
        
        Configures the template.
        Is implemented in concrete template.
        Must return True if successful.
        
        """

        self.template_logger.info("No setup method implemented, nothing to do")
        return True
    
    def template_shutdown(self):
        """template_shutdown()
        
        Runs cleanup tasks for the template.
        Is implemented in concrete template.
        Must return True if successful.
        
        """
        
        self.template_logger.info("No shutdown method implemented, nothing to do")
        return True
        
if __name__ == "__main__":
    print "Warning: This module is not intended to be executed directly. Only do this for test purposes."