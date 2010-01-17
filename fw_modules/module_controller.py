#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# module_controller.py - WIDS/WIPS framework controller module
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

"""Controller module

Starts and stops a framework instance.
Configures and manages other modules.

"""

# Imports

# Standard modules
import copy
import logging
import optparse
import os, os.path
import signal
import sys
import threading
import time

# Custom modules
try:
    import fw_modules.module_daemon
except ImportError:
    print "Couldn't find framework module 'module_daemon'. Did you add the framework package to the Python module search path? (See INSTALL for details)"
    sys.exit(1)
try:
    from fw_modules.module_exceptions import *
except ImportError:
    print "Couldn't find framework module 'module_exceptions'. Did you add the framework package to the Python module search path? (See INSTALL for details)"
    sys.exit(1)
try:
    import fw_modules.module_template
except ImportError:
    print "Couldn't find framework module 'module_template'. Did you add the framework package to the Python module search path? (See INSTALL for details)"
    sys.exit(1)

# Third-party modules
try:
    from lxml import etree
except ImportError:
    print "Couldn't import module 'lxml'"
    sys.exit(1)

# Top-level methods
def get_loglevel(requested_loglevel):
    """get_loglevel()
    
    Returns a loglevel object of a requested loglevel
    or None if the request is invalid.
    
    """
    
    loglevel_dict = { 'debug': logging.DEBUG,
                      'info': logging.INFO,
                      'warning': logging.WARNING,
                      'error': logging.ERROR,
                      'critical': logging.CRITICAL}
    try:
        loglevel_object = loglevel_dict[requested_loglevel]
        return loglevel_object
    except KeyError:
        return None
    
def parse_xml_config(xmlfile=None, schemafile=None, includeschemafile=None, break_after=None, verbose=True):
    """parse_xml_config()
    
    Validates and parses the XML configuration file and returns a config dictionary.
        break_after ... name of xml-element which causes parser stop upon encountering
    
    """
    
    in_config = False
    in_controller_config = False
    in_module_config = False
    in_module_config_type = None
    in_module_config_identifier = None
    in_misc_config = False
    in_template_config = False
    in_template_config_type = None
    in_template_config_identifier = None
    in_module_properties = False
    in_module_properties_type = None
    in_template_properties = False
    in_template_properties_type = None
    module_id_counter = 1           # internal counter for creating standard submodule identifiers
    template_id_counter = 1         # internal counter for creating standard template identifiers
    default_loglevel = 'info'           # default loglevel, is used if not set in controller attribute
    enabled_events = ('start', 'end')
    # Build config dict prototype.
    config_dict = {'controller_config':{'module_properties':{}, 'template_properties':{}, 'controller_values':{'controller_config_file':xmlfile, 'controller_verbose_setting':verbose}}, 'module_config':{}, 'misc_config':{'remote_alias':{}}}
    # Validate the configuration file against schema.
    if verbose: print "Validating configuration file with schema:", schemafile
    try:
        fw_modules.module_template.validate_xml_config(xmlfile, schemafile)
    except FwFileNotAvailableError as err:
        raise FwFileNotAvailableError(err.file)
        return False
    except FwConfigNotValidError:
        raise 
        return False
    # Parse the configuration file.
    if verbose: print "Parsing configuration file"
    xml_element_tree_parser = etree.iterparse(xmlfile, events=enabled_events)           # Create iterative parser and iterate over element tree
    for event, element in xml_element_tree_parser:          # Note: event defaults to end only so start has to enabled explicitly
        # Set entry flags.
        element_name = element.tag
        if element_name == 'config':
            if event == 'start':
                if verbose: print "Entering configuration"
                in_config = True            # Mark entry of configuration portion
            elif event == 'end':
                if verbose: print "Leaving configuration"
                in_config = False           # Mark exit of configuration portion
        elif element_name == 'controller_config' and in_config:
            if event == 'start':
                if verbose: print "Entering controller configuration"
                in_controller_config = True         # Mark entry of controller configuration portion
                try:
                    in_controller_loglevel = element.attrib['loglevel']
                except KeyError:
                    if verbose: print "No loglevel set, using default:", default_loglevel
                    in_controller_loglevel = default_loglevel
                loglevel_object = get_loglevel(in_controller_loglevel)
                if loglevel_object:
                    config_dict['controller_config']['loglevel'] = {'loglevel_name':in_controller_loglevel, 'loglevel_object':loglevel_object}
                else:
                    print "ERROR: Requested loglevel", in_controller_loglevel, "is invalid; setting level to 'NOTSET'"
                    config_dict['controller_config']['loglevel'] = {'loglevel_name':'notset' ,'loglevel_object':logging.NOTSET}
            elif event == 'end':
                if verbose: print "Leaving controller configuration"
                in_controller_config = False            # Mark exit of controller configuration portion
        elif element_name == 'module_config' and in_config:
            if event == 'start':
                if verbose: print "Entering module configuration"
                in_module_config = True
                try:
                    in_module_config_type = element.attrib['module_type']
                except KeyError:
                    print "ERROR: No type specified for module"
                else:  
                    try:
                        in_module_config_identifier = element.attrib['module_identifier']
                    except KeyError:
                        in_module_config_identifier = 'submodule_' + str(module_id_counter)         # create temporal identifier for submodule
                        module_id_counter = module_id_counter + 1
                        if verbose: print "No identifier specified for module type:", in_module_config_type
                        if verbose: print "Using random identifier:", in_module_config_identifier
                    if verbose: print "Entering module configuration for module:", in_module_config_identifier          # Mark entry of module configuration portion
                    config_dict['module_config'][in_module_config_identifier] = {'module_type':in_module_config_type, 'module_receivers':{}, 'module_parameter_dictionary':{'module_identifier':in_module_config_identifier, 'module_address':{}, 'controller_config_file':xmlfile}, 'module_priority':None, 'module_loglevel':None}            # create config dict entry for module
                    try:
                        in_module_address = element.attrib['module_address']
                        address = in_module_address.split(':')
                        if len(address) == 2:
                            hostname = address[0]
                            try:
                                port = int(address[1])
                            except ValueError:
                                print "ERROR: Portnumber invalid:", address[1]
                            else:
                                config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary']['module_address']['hostname'] = hostname
                                config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary']['module_address']['port'] = port
                        else:
                            print "ERROR: Module adress invalid:", address
                    except KeyError:
                        if verbose: print "No remote address for module", in_module_config_identifier, "has been configured"
                    try:
                        in_module_config_priority = element.attrib['module_priority']
                        if verbose: print "Found custom priority for module instance", in_module_config_identifier
                    except KeyError:
                        if verbose: print "Using default priority for module instance", in_module_config_identifier
                    else:
                        config_dict['module_config'][in_module_config_identifier]['module_priority'] = float(in_module_config_priority)
                    try:
                        in_module_config_loglevel = element.attrib['module_loglevel']
                    except KeyError:
                        if verbose: print "No custom loglevel for module", in_module_config_identifier, "specified"
                    else:
                        loglevel_object = get_loglevel(in_module_config_loglevel)
                        if loglevel_object:
                            config_dict['module_config'][in_module_config_identifier]['module_loglevel'] = {'loglevel_name':in_module_config_loglevel, 'loglevel_object':loglevel_object}
                        else:
                            print "ERROR: Requested module loglevel", in_module_config_loglevel, "for module", in_module_config_identifier, "is invalid"
            elif event == 'end':
                if verbose: print "Leaving module configuration for module", in_module_config_identifier
                in_module_config = False            # Mark exit of module configuration portion
                in_module_config_type = None
                in_module_config_identifier = None
        elif element_name == 'module_properties' and in_controller_config:
            if event == 'start':
                try:
                    in_module_properties_type = element.attrib['module_type']
                except KeyError:
                    print "ERROR: No type specified for module"
                else:
                    try:
                        in_module_properties_priority = element.attrib['module_priority']
                    except KeyError:
                        print "ERROR: No priority specified for module type", in_module_properties_type
                    else:
                        if verbose: print "Entering module properties for type:", in_module_properties_type
                        in_module_properties = True         # Mark entry of module properties portion
                        config_dict['controller_config']['module_properties'][in_module_properties_type] = {'module_priority':in_module_properties_priority}            # Create property entry for module type
            elif event == 'end':
                if verbose: print "Leaving module properties"
                in_module_properties = False            # Mark exit of module properties portion
                in_module_properties_type = None
        elif element_name == 'template_properties' and in_controller_config:
            if event == 'start':
                try:
                    in_template_properties_type = element.attrib['template_type']
                except KeyError:
                    print "ERROR: No type specified for template"
                else:
                    if verbose: print "Entering template properties for template type", in_template_properties_type
                    in_template_properties = True
                    config_dict['controller_config']['template_properties'][in_template_properties_type] = {}
            elif event == 'end':
                in_template_properties = False
                in_template_properties_type = None
        elif element_name == 'template_configuration' and in_module_config and in_module_config_identifier:
            if event == 'start':
                if verbose: print "Entering template configuration"
                in_template_config = True
                try:
                    in_template_config_type = element.attrib['template_type']
                except KeyError:
                    print "ERROR: No type specified for template"
                else:
                    try:
                        template_name = config_dict['controller_config']['template_properties'][in_template_config_type]['template_name']
                    except KeyError:
                        print "ERROR: Couldn't find template name for type", in_template_config_type
                    else:
                        try:
                            in_template_config_identifier = element.attrib['template_identifier']
                        except KeyError:
                            in_template_config_identifier = 'template_' + str(template_id_counter)          # create temporal identifier for submodule
                            template_id_counter = template_id_counter + 1
                            if verbose: print "No identifier specified for template type:", in_template_config_type
                            if verbose: print "Using random identifier:", in_template_config_identifier
                        if not config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary'].has_key('template_config'):
                            config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary']['template_config'] = {}
                        config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary']['template_config'][in_template_config_identifier] = {'template_name':template_name, 'template_loglevel':None,'template_values':{'template_identifier':in_template_config_identifier}}
                        try:
                            in_template_config_loglevel = element.attrib['template_loglevel']
                        except KeyError:
                            if verbose: print "No custom loglevel for template", in_template_config_identifier, "specified"
                        else:
                            loglevel_object = get_loglevel(in_template_config_loglevel)
                            if loglevel_object:
                                config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary']['template_config'][in_template_config_identifier]['template_loglevel'] = {'loglevel_name':in_template_config_loglevel, 'loglevel_object':loglevel_object}
                            else:
                                print "ERROR: Requested template loglevel", in_module_config_loglevel, "for template", in_template_config_identifier, "is invalid"
            elif event == 'end':
                if verbose: print "Leaving template configuration"
                in_template_config = False
                in_template_config_type = None
                in_template_config_identifier = None
        elif element_name == 'misc_config' and in_config:
            if event == 'start':
                if verbose: print "Entering misc config"
                in_misc_config = True
            elif event == 'end':
                if verbose: print "Leaving misc config"
                in_misc_config = False
        # Extract information from elements
        if event == 'end':          # Only parse elements when end event is encountered otherwise content is not yet available
            element_content = element.text
            if break_after and element.tag == break_after:          # Watch for optional breakpoint
                if verbose: print "Encountered element", break_after, ",stopping parser"
                if element.tag == 'pidfile' and in_controller_config:
                    config_dict['controller_config']['pidfile'] = fw_modules.module_template.parse_xml_content(element_content)
                return config_dict          # End parser prematurely, we don't need any more values
            else:
                if element_name == 'module_name' and in_controller_config and in_module_properties:
                    config_dict['controller_config']['module_properties'][in_module_properties_type]['module_name'] = fw_modules.module_template.parse_xml_content(element_content)
                elif element_name == 'template_name' and in_template_properties:
                    config_dict['controller_config']['template_properties'][in_template_properties_type]['template_name'] = fw_modules.module_template.parse_xml_content(element_content)
                elif element_name == 'pidfile' and in_controller_config:
                    config_dict['controller_config']['pidfile'] = fw_modules.module_template.parse_xml_content(element_content)
                elif element_name == 'module_receivers' and in_module_config:
                    try:
                        receiver_type = element.attrib['receiver_type']
                    except KeyError:
                        receiver_type = 'local'         # if receiver_type not set, default to local
                    try:
                        receiver_groups_list = fw_modules.module_template.parse_xml_content(element.attrib['receiver_groups'], 'list')
                    except KeyError:
                        receiver_groups_list = []
                    temp_receivers_list = fw_modules.module_template.parse_xml_content(element_content, 'list')
                    for receiver in temp_receivers_list:
                        config_dict['module_config'][in_module_config_identifier]['module_receivers'][receiver] =  {'receiver_type':receiver_type, 'receiver_groups':receiver_groups_list}          # add receiver and its type/group to receiver list of module
                elif element_name == 'value':
                    try:
                        value_name = element.attrib['value_name']
                    except KeyError:
                        print "ERROR: No name specified for value"
                    else:
                        try:
                            value_type = element.attrib['value_type']
                        except KeyError:
                            value_type = None
                        value = fw_modules.module_template.parse_xml_content(element_content, value_type)
                        if in_controller_config:
                            config_dict['controller_config']['controller_values'][value_name] = value
                        elif in_module_config and not in_template_config and in_module_config_identifier:
                            config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary'][value_name] = value
                        elif in_module_config and in_template_config and in_template_config_identifier:
                            config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary']['template_config'][in_template_config_identifier]['template_values'][value_name] = value
                elif element_name == 'include' and in_module_config and in_module_config_identifier:
                    if verbose: print "Encountered include file in configuration for module", in_module_config_identifier
                    includexmlfile = fw_modules.module_template.parse_xml_content(element_content)
                    try:
                        include_values_dict = parse_xml_include(includexmlfile, includeschemafile, verbose=verbose)
                    except FwFileNotAvailableError as err:
                        print "ERROR: Couldn't access file", err.file
                        include_values_dict = None
                    except FwConfigNotValidError as err:
                        print "ERROR: Include file", includexmlfile ,"not valid, Details:", err.reason
                        include_values_dict = None
                    else:
                        if include_values_dict:
                            for value_name, value in include_values_dict.iteritems():           # transfer gathered values to module param dict
                                if in_template_config and in_template_config_identifier:
                                    config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary']['template_config'][in_template_config_identifier]['template_values'][value_name] = value
                                elif not in_template_config:
                                    config_dict['module_config'][in_module_config_identifier]['module_parameter_dictionary'][value_name] = value    
                elif element_name == 'remote_alias' and in_misc_config:
                    try:
                        alias_id = element.attrib['alias_identifier']
                    except KeyError:
                        print "ERROR: No alias identifier specified"
                    else:
                        try:
                            remote_portnumber = element.attrib['remote_portnumber']
                        except:
                            print "ERROR: No portnumber specified for remote alias", alias_id
                        else:
                            try:
                                remote_hostname = element.attrib['remote_hostname']
                            except KeyError:
                                if verbose: print "No remote hostname specified for remote alias", alias_id,", using default 'localhost'"
                                remote_hostname = 'localhost'
                            config_dict['misc_config']['remote_alias'][alias_id] = remote_hostname + ':' + remote_portnumber
            
    if verbose: print "Finished parsing configuration file"
    if verbose: print "Configuration dictionary:"
    if verbose: print config_dict  
    return config_dict
    
def parse_xml_include(include_xmlfile, include_schemafile, verbose=True):
    """parse_xml_include()
    
    Downsized parser for include files.
    Validates include file and gathers values from it.
    
    """
    
    enabled_events = ('start', 'end')
    in_include_values = False
    include_values_dict = {}
    # Validate includefile with include schema.
    if verbose: print "Validating include file", include_xmlfile, "with schema", include_schemafile
    try:
        fw_modules.module_template.validate_xml_config(include_xmlfile, include_schemafile)
    except FwFileNotAvailableError as e:
        raise FwFileNotAvailableError(e.file)
        return False
    except FwConfigNotValidError:
        raise
        return False
    # Parse include file
    if verbose: print "Parsing include file", include_xmlfile
    xml_element_tree_parser = etree.iterparse(include_xmlfile, events=enabled_events)           # Create iterative parser and iterate over element tree
    for event, element in xml_element_tree_parser:          # Note: event defaults to end only so start has to enabled explicitly
        # Set entry flags.
        element_name = element.tag
        if element_name == 'include_values':
            if event == 'start':
                if verbose: print "Entering include_values"
                in_include_values = True
            elif event == 'end':
                if verbose: print "Leaving include_values"
                in_include_values = False
        if event == "end":
            element_content = element.text
            if element_name == 'value' and in_include_values:
                try:
                    value_name = element.attrib['value_name']
                except KeyError:
                    print "ERROR: Value name missing for include value element in file", include_xmlfile
                else:
                    try:
                        value_type = element.attrib['value_type']
                    except KeyError:
                        value_type = None           # if value_type not set, default to string
                    include_values_dict[value_name] = fw_modules.module_template.parse_xml_content(element_content, value_type)
    if verbose: print "Include value dictionary:"
    if verbose: print include_values_dict
    return include_values_dict
            

class ControllerClass(fw_modules.module_daemon.DaemonClass):
    """Controller Class
    
    Class for creating a controller object which manages zero to many
    module objects.
    
    """
    
    def __init__(self, configuration_dictionary, mode='start'):
        """Constructor
        
        Controller class inherits from Daemon class to works as a
        daemon process.
        
        """

        self.config_dict = copy.deepcopy(configuration_dictionary)          # controller gets a copy of the configuration dictionary, changes in the dictionary do not affect controller directly
        self.pidpath = os.path.abspath(self.config_dict['controller_config']['pidfile'])
        self.loglevel = self.config_dict['controller_config']['loglevel']['loglevel_object']
        self.controller_config_file = self.config_dict['controller_config']['controller_values']['controller_config_file']
        try:
            self.verbose = self.config_dict['controller_config']['controller_values']['controller_verbose_setting']
        except KeyError:
            self.verbose = True
        try:
            self.outfile = self.config_dict['controller_config']['controller_values']['outfile']
        except KeyError:
            self.outfile = "./controller.out"           # default outfile, for runtime errors and print output
            if self.verbose: print "Outfile not set, using default", self.outfile
        try:
            self.logfile = self.config_dict['controller_config']['controller_values']['logfile']
        except KeyError:
            self.logfile = "./controller.log"           # default logfile
            if self.verbose: print "Logfile not set, using default", self.logfile
        # Call constructor of daemon class for inheritance.
        fw_modules.module_daemon.DaemonClass.__init__(self, self.pidpath, stdout=self.outfile, stderr=self.outfile)
        # Create signal handlers for processing signals sent to daemon process.
        signal.signal(signal.SIGHUP, self.signal_handler)
        signal.signal(signal.SIGUSR1, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        # Create root and controller logger.
        self.controller_logger = None
        self.root_logger_identifier = "fw"
        if mode == 'start':
            self.root_logger = self.get_logger(self.root_logger_identifier, self.loglevel, self.logfile)            # create root logger, is not used directly
            self.controller_logger = logging.getLogger(self.root_logger_identifier + ".controller")         # create child logger for controller
            self.controller_logger.info("Controller pidfile: " + str(self.pidpath))
        # Some helper variables/objects.
        self.thread_lock_semaphore = threading.BoundedSemaphore(1)          # used to stall thread start until previous thread is running
        self.stop_controller = False            # flag controlling lifetime of controller main thread
        self.join_timeout = 10          # seconds to wait for module shutdown after issuing stop command
        self.module_start_order = []
        self.status_dict = {}

    def add_submodule(self, module_identifier, module_reference, module_status):
        """add_submodule()
        
        Adds context information of a submodule to the controller's status dictionary.
        
        """
        
        self.controller_logger.info("Add module " + module_identifier + " with status " + module_status + " to status dictionary")
        self.status_dict[module_identifier] = {'module_reference':module_reference, 'module_receivers':None,'module_status':module_status}
        self.controller_logger.debug("Status dictionary: " + str(self.status_dict))
        
    def add_submodule_receivers(self, module_identifier, module_receivers):
        """add_submodule_receivers()
        
        Adds receivers to context information of a submodule
        in the controller's status dictionary.
        
        """
        
        try:
            self.status_dict[module_identifier]['module_receivers'] = module_receivers
        except KeyError:
            self.controller_logger.error("Couldn't add receivers to module " + module_identifier + ", not in status dict")
        self.controller_logger.debug("Status dictionary: " + str(self.status_dict))
        
    def build_start_order(self):
        """build_start_order()
        
        Builds a module start order for the modules configured in the configuration file.
        
        """
        
        def return_next(idlist, priolist):
            next_index = priolist.index(min(priolist))
            priolist.pop(next_index)
            return idlist.pop(next_index)
        
        self.module_start_order = []            # clear order list
        module_id_list = []
        module_prio_list = []
        for module_id in self.config_dict['module_config'].keys():
            try:
                module_type = self.config_dict['module_config'][module_id]['module_type']
            except KeyError:
                self.controller_logger.error("Couldn't resolve module type of module " + module_id)
                raise
            else:
                try:
                    if self.config_dict['module_config'][module_id]['module_priority']:         # check if custom priority is specified
                        module_priority = self.config_dict['module_config'][module_id]['module_priority']
                    else:
                        module_priority = self.config_dict['controller_config']['module_properties'][module_type]['module_priority']            # otherwise take the default priority
                except KeyError:
                    self.controller_logger.error("Couldn't resolve module priority for module " + module_id + " with type " + module_type)
                    raise
                else:
                    module_id_list.append(module_id)
                    module_prio_list.append(module_priority)
        self.controller_logger.debug("Module ID list: " + str(module_id_list))
        self.controller_logger.debug("Module priority list: " + str(module_prio_list))
        while module_id_list and module_prio_list:
            self.module_start_order.append(return_next(module_id_list, module_prio_list))
        self.controller_logger.debug("Module start order: " + str(self.module_start_order)) 

    def get_logger(self, log_identifier, log_level, log_file):
        """get_logger()
        
        Creates and returns a root logger for the framework instance.
        Controller and submodules are configured with a child logger
        of the root logger and inherit the log destination and format.
        
        'log_level' is a loglevel object of the logging module (e. g. logging.INFO).
        
        """
        
        if self.verbose: print "Generating root logger with loglevel", log_level, "and logfile", log_file
        logger = logging.getLogger(log_identifier)
        logger.setLevel(log_level)
        log_filehandler = logging.FileHandler(log_file, 'w')            # handler for wroting log messages to a logfile, a new file is created at every start
        log_formatter = logging.Formatter('%(name)s: %(levelname)s: %(message)s')
        log_filehandler.setFormatter(log_formatter)
        logger.addHandler(log_filehandler)
        return logger

    def remove_submodule(self, module_identifier):
        """remove_submodule()
        
        Removes a module instance and its context information 
        from the controller status dictionary.
        
        """
        
        if self.status_dict.has_key(module_identifier):
            self.controller_logger.info("Removing module with id " + module_identifier + " from status dict")
            del self.status_dict[module_identifier]
        else:
            raise FwNoStatusEntryError(module_identifier)
        
    def run(self):
        """run()
        
        Enter controller main action thread.
        Overwrites the same named method in  the daemon class.
        
        """                

        self.controller_logger.info("Starting main action")
        self.controller_logger.debug("Current working directory: " + os.getcwd())
        # Build module start order.
        self.controller_logger.info("Building module start order")
        self.build_start_order()
        # Start configured submodules and enter main loop.
        try:
            self.setup_all_submodules()
        except FwModuleSetupError as err:
            self.controller_logger.error(err.errmsg)
            self.shutdown_controller()
        else:
            counter = 0
            while not self.stop_controller:
                self.controller_logger.info("Controller Heartbeat..." + str(counter))
                counter += 1
                self.controller_logger.debug("Status dictionary: " + str(self.status_dict))
                time.sleep(2)
        self.controller_logger.info("End of main action loop")
        self.delpid()
                
    def set_module_status(self, module_identifier, new_status):
        """set_module_status()
        
        Sets status of module in status dictionary.
        Is called by submodules to update their status in the controller.
        
        """
        
        self.controller_logger.info("Set status of module " + module_identifier + " to " + new_status)
        self.status_dict[module_identifier]['module_status'] = new_status
        self.controller_logger.debug("Status dictionary: " + str(self.status_dict))

    def setup_all_submodules(self):
        """setup_all_submodules()
        
        Function for setting up all submodules.
        Set module values, add them to status dict and start threads.
        
        """
        
        self.controller_logger.info("Setting up submodules")
        for module_identifier in self.module_start_order:
            try:
                self.setup_submodule(module_identifier)
            except FwModuleSetupError:
                raise
        self.controller_logger.info("Setting up submodule receivers")
        for module_identifier in self.module_start_order:
            try:
                self.setup_submodule_receivers(module_identifier)
            except FwModuleSetupError:
                raise
        self.controller_logger.info("Starting submodule main threads")
        self.thread_lock_semaphore.acquire()
        for module_identifier in self.module_start_order:
            self.controller_logger.info("Starting module " + module_identifier)
            try:
                module_reference = self.status_dict[module_identifier]['module_reference']
            except KeyError:
                raise FwModuleSetupError, "Couldn't get module reference for module" + module_identifier + "from status dict"
            else:
                if not module_reference.initialise():
                    raise FwModuleSetupError, "Couldn't initialise module " + module_identifier
                else:
                    self.status_dict[module_identifier]['module_status'] = 'running'  
        return True
    
    def setup_submodule(self, module_identifier):
        """setup_submodule()
        
        Sets up a single module.
        Sets module values, adds it to status dict and starts its thread.
        
        """
        
        self.controller_logger.info("Setting up module " + module_identifier)
        module_reference = None
        # Extract information on the module from the controller's config dictionary.
        try:
            try:
                module_type = self.config_dict['module_config'][module_identifier]['module_type']
                module_name = self.config_dict['controller_config']['module_properties'][module_type]['module_name']
                module_receivers = self.config_dict['module_config'][module_identifier]['module_receivers']
                module_priority = self.config_dict['controller_config']['module_properties'][module_type]['module_priority']
                module_param_dict = self.config_dict['module_config'][module_identifier]['module_parameter_dictionary']
            except KeyError:
                raise
        except KeyError as err:
            self.controller_logger.error("Configuration dictionary corrupt; details: " + err.__str__())
            self.shutdown_controller()
        module_status = 'init'
        module_actual_receivers = {}
        # Create module instance.
        # Import module beforehand if needed.
        self.controller_logger.info("Importing module " + module_name)
        try:
            __import__(module_name)         # standard import function does not accept strings
        except ImportError as err:
            raise FwModuleSetupError, "Couldn't import module " + module_name + "; details: " + err.__str__()
            return False
        except FwModuleSetupError:
            raise
        try:            
            module_reference = sys.modules[module_name]
        except KeyError as err:
            raise FwModuleSetupError, "Could't resolve module reference for module name " + module_name + "; details: " + err.__str__()
        else:
            try:
                # Create logger for submodule and add reference to param dict before getting module object.
                module_logger = logging.getLogger(self.controller_logger.__dict__['name'] + "." + module_identifier)
                if self.config_dict['module_config'][module_identifier]['module_loglevel']:
                    self.controller_logger.info("Setting custom loglevel '" + self.config_dict['module_config'][module_identifier]['module_loglevel']['loglevel_name'] + "' for module " + module_identifier)
                    module_logger.setLevel(self.config_dict['module_config'][module_identifier]['module_loglevel']['loglevel_object'])
                module_class_reference = module_reference.main(self, module_param_dict, module_logger)
            except FwModuleSetupError:
                raise
            else:
                self.controller_logger.info("Class reference created for module " + str(module_identifier))
        self.add_submodule(module_identifier, module_class_reference, 'init')
        return True
                    
    def setup_submodule_receivers(self, module_identifier):
        """setup_submodule_receivers()
        
        Sets up receivers of single submodule.
        Is called after all module references are resolved
        to allow arbitrary communication paths between modules.
        
        """
        
        self.controller_logger.info("Setting up receivers for module " + module_identifier)
        # Add module receivers to module instance.
        try:
            module_receivers = self.config_dict['module_config'][module_identifier]['module_receivers']
        except KeyError as err:
            self.controller_logger.error("Configuration dictionary corrupt; details: " + err.__str__())
            self.shutdown_controller()
        else:
            module_actual_receivers = {}
            try:
                module_reference = self.status_dict[module_identifier]['module_reference']
            except KeyError:
                raise FwModuleSetupError, "Couldn't get module reference for module" + module_identifier + "from status dict"
            else:
                for module_receiver, receiver_infos in module_receivers.items():
                    receiver_type = receiver_infos['receiver_type']
                    receiver_groups = receiver_infos['receiver_groups']
                    if receiver_type == 'local':
                        try:
                            receiver_reference = self.status_dict[module_receiver]['module_reference']
                        except KeyError as err:
                            raise FwModuleSetupError, "Couldn't resolve receiver reference for module " + module_identifier + " and receiver " + module_receiver + "; Detail: " + err.__str__()
                        else:
                            module_reference.add_target(module_receiver, 'local', receiver_groups, receiver_reference)
                    elif receiver_type == 'remote':
                        try:
                            module_receiver = self.config_dict['misc_config']['remote_alias'][module_receiver]          # interpolate alias if available
                        except KeyError:
                            pass
                        module_reference.add_target(module_receiver, 'remote', receiver_groups)
                    module_actual_receivers[module_receiver] = receiver_type
                try:
                    self.add_submodule_receivers(module_identifier, module_actual_receivers)
                except FwNoStatusEntryError as err:
                    self.controller_logger.error("Couldn't add receivers to module " + err.missingentry + ", not in status dict")
        return True
          
    def shutdown_all_submodules(self):
        """shutdown_modules()
        
        Terminates all running modules and cleans up.
        
        """
        
        # Shutdown submodules in correct order
        self.controller_logger.info("Shutting down submodules")
        for module_identifier in reversed(self.module_start_order):
            self.shutdown_submodule(module_identifier)
            
    def shutdown_controller(self):
        """shutdown_controller()
        
        Shuts down all running modules and the controller itself.
        
        """
        
        self.shutdown_all_submodules()
        self.controller_logger.info("Shutting down controller, bye")
        self.stop_controller = True


    def shutdown_submodule(self, module_identifier):
        """shutdown_submodule()
        
        Terminates a single submodule.
        
        """
        
        # Check if module status is 'running' in status_dict prior
        self.controller_logger.info("Shutting down module " + module_identifier)
        if self.status_dict.has_key(module_identifier):
            if self.status_dict[module_identifier]['module_status'] == 'running':
                self.controller_logger.info("Stopping module" + module_identifier)
                module_reference = self.status_dict[module_identifier]['module_reference']
                if module_reference:
                    # Call stop function of module instance and send a 'STOP' directive to its input buffer.
                    module_reference.stop()
                    module_reference.input('STOP')
                    module_reference.join(self.join_timeout)
                    for active_module_id in self.status_dict:
                        try:
                            self.status_dict[active_module_id]['module_reference'].remove_target(module_identifier)         # remove inactive module from receiver lists of remaining modules
                        except FwNoStatusEntryError as err:
                            self.controller.logger.error("Couldn't remove module " + err.missingentry + ", not in status dict")
                    
    def signal_handler(self, signum, frame):
        """signal_handler()
        
        Handler for signal receipt.
        
        """
        
        if signum == 1:             # SIGHUP
            self.controller_logger.info("Received SIGHUP, restarting")
            self.restart()
        elif signum == 10:          # SIGUSR1
            self.controller_logger.info("Received SIGUSR1, shutting down running modules")
            self.shutdown_all_submodules()
        elif signum == 15:          # SIGTERM
            self.controller_logger.info("Received SIGTERM, shutting down")
            self.shutdown_controller()
        
    def unlock_next_thread(self):
        """unlock_next_thread()
        
        Unlocks semaphore to signalise that next thread can be started.
        Is called by a recently started thread to tell controller that
        thread is up and running.
        
        """
        
        try:
            self.thread_lock_semaphore.release()
        except ValueError:
            self.controller_logger.warning("Thread lock semaphore is already released")
        
def main(command, config_file, schema_file, include_schemafile, pid_file, verbose_setting=True):
    # Generation of controller and startup process is dependent on requested command
    config_dict = {}
    
    if command == 'start':          # Start normally
        break_element = None
    elif command == 'stop':         # No need to parse the whole config, parse with modified parser instead whicb breaks after pidfile entry is found
        # Parse config file in short mode (break after pidfile)
        break_element='controller_config'           # Search only for pidfile element
    elif command == 'restart':
        break_element = None
    # Parse config file for configuration.
    try:
        config_dict = parse_xml_config(xmlfile=config_file, schemafile=schema_file, includeschemafile=include_schemafile, break_after=break_element, verbose=verbose_setting)
    except FwFileNotAvailableError as err:
        print "ERROR: Couldn't access file", err.file
        sys.exit(1)
    except FwConfigNotValidError as err:
        print "ERROR: Configuration file not valid; details:", err.reason
        sys.exit(1)
    if pid_file and config_dict:
        try:
            config_dict['controller_config']['pidfile'] = pid_file
        except KeyError:
            print "ERROR: Couldn't set custom pidfile!"
            sys.exit(1)
    if command == 'start':
        # Clear outfile of controller
        if os.path.isfile(config_dict['controller_config']['controller_values']['outfile']):
            try:
                os.remove(config_dict['controller_config']['controller_values']['outfile'])
            except OSError as err:
                print "ERROR: Couldn't remove outfile", config_dict['controller_config']['controller_values']['outfile'], "; details:", err.__str__()
                sys.exit(1)
    # Get controller object.
    controller_class = ControllerClass(config_dict, command)
    return controller_class
        
if __name__ == "__main__":
    # Set default values.
    config_file = 'fw_data/fw_general_config.xml'             # Default configuration file
    schema_file = 'fw_data/fw_general_schema.xsd'             # Default XML schema file
    include_schemafile = 'fw_data/fw_include_schema.xsd'      # default XML-schema file for include files
    pid_file = None
    # Parse commandline options.
    usage = "usage: %prog [options] start|stop|restart"
    parser = optparse.OptionParser(usage=usage, version="WIDS/WIPS framework version 1.1")
    parser.add_option("-c", "--config-file", dest="config_file", help="parse CONFIG instead of default configuration file", metavar="CONFIG")
    parser.add_option("-p", "--pid-file", dest="pid_file", help="use PIDFILE for process control instead of default pidfile", metavar="PIDFILE")
    parser.add_option("-s", "--schema-file", dest="schema_file", help="validate configuration with SCHEMAFILE instead of default schema", metavar="SCHEMAFILE")
    parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=True, help="suppress controller startup messages")
    try:
        (options, args) = parser.parse_args()
    except (optparse.OptionError, TypeError):
        parser.print_usage()
        sys.exit(2)
    if len(args) != 1:           # only one argument allowed
        parser.print_usage()
        sys.exit(2)
    else:
        controller_mode = args[0]
    print options
    if options.config_file:
        config_file = os.path.abspath(options.config_file)
    if options.schema_file:
        schema_file = os.path.abspath(options.schema_file)
    if options.pid_file:
        try:
            pid_file = os.path.abspath(options.pid_file)            # overwrite pidfile in config file
        except OSError:
            print "ERROR: Invalid pathname for custom pidfile:", options.pid_file
            sys.exit(2)
        else:
            if not os.path.isdir(os.path.dirname(pid_file)):
                print "ERROR: Invalid path for pidfile:", os.path.dirname(pid_file)
                sys.exit(2)
    # Change current working directory to parent directory of controller.
    os.chdir("..")
    # Execute controller in requested mode.
    if controller_mode == 'start':
        print "Starting controller..."
        controller_class = main('start', config_file, schema_file, include_schemafile, pid_file, verbose_setting=options.verbose)
        controller_class.start()
    elif controller_mode == 'stop':
        print "Stopping controller..."
        controller_class = main('stop', config_file, schema_file, include_schemafile, pid_file, verbose_setting=options.verbose)
        controller_class.stop()
    elif controller_mode == 'restart':
        print "Restarting controller..."
        controller_class = main('restart', config_file, schema_file, include_schemafile, pid_file, verbose_setting=options.verbose)
        controller_class.restart()
    else:
        parser.print_usage()
        sys.exit(2)
    sys.exit(0)