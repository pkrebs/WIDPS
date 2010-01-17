#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# template_sessioncon.py - WIDS/WIPS framework session containment prevention template
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

"""Session containment prevention template

Receives alarm messages from the signature template and schedules
a session containment dos attack against a rogue device via the executor.

"""

# Imports
#
# Custom modules
import fw_modules.module_template
from fw_modules.module_exceptions import *

# Standard modules


# Third-party modules
try:
    from lxml import etree
except ImportError:
    raise FwTemplateSetupError, "Couldn't import required module 'lxml.etree'"

class TemplateSessionConClass(fw_modules.module_template.TemplateClass):
    """TemplateSessionConClass
    
    Processes incoming alarm messages and sends out commands to an executor module
    for scheduling a session containment flood.
    
    """
    
    def __init__(self, engine_reference, parameter_dictionary, template_logger):
        """Constructor
        
        Constructor description.
        
        """
        
        fw_modules.module_template.TemplateClass.__init__(self, engine=engine_reference, param_dict=parameter_dictionary, logger=template_logger)
        # Default values.
        try:
            self.rules_file = self.param_dict['rules_file']
        except KeyError:
            self.template_logger.error("No rules file specified")
            self.rules_file = '' 
        try:
            self.rules_schema = self.param_dict['rules_schema']
        except KeyError:
            self.template_logger.error("No rules schema specified")
            self.rules_schema = ''  
        self.command_receiver_group, self.prevention_receiver_group = self.engine_reference.get_receiver_groups()
        # Helper values.
        self.rule_info_dict = {}
        self.trace_flood_dict = {'flood_identifier':None, 'flood_interruptible':True, 'flood_signature':None, 'flood_active':False}
        
    def parse_xml_config(self, xmlfile, schemafile):
        """parse_xml_config()
        
        Parses template xml configuration file for signature data.
        
        """
        
        def calculate_time(timevalue, timescale, timetype='int'):
            """calculate_time()
            
            Calculates time value in seconds depending on timescale.
            
            """
            
            try:
                if timetype == 'int':
                    print "int"
                    timevalue = int(timevalue)
                elif timetype == 'float':
                    print "float"
                    timevalue = float(timevalue)
                else:
                    self.template_logger.warning("Unrecognised time conversion type " + str(timetype))
            except ValueError as err:
                self.template_logger.warning("Unrecognised time conversion type " + str(timetype))
                return None
            if timevalue <= 0:
                self.template_logger.warning("Time value must be greater than 0 but is " + str(timevalue))
                return None
                
            if timescale == 'h':
                return timevalue * 3600
            elif timescale == 'min':
                return timevalue * 60
            elif timescale == 's':
                return timevalue
            elif timescale == 'ms':
                return timevalue * 0.001
            else:
                self.template_logger.warning("Timescale " + str(timescale) + " not valid")
                return None
        
        in_template_config = False
        in_rule = False
        rule_identifier = None
        severity = None
        action = None
        interruptible = None
        enabled_events = ('start', 'end')
        # Validate the configuration file against schema.
        self.template_logger.info("Validating configuration file with schema: " + schemafile)
        try:
            fw_modules.module_template.validate_xml_config(xmlfile, schemafile)
        except FwFileNotAvailableError as err:
            raise FwFileNotAvailableError(err.file)
            return False
        except FwConfigNotValidError:
            raise 
            return False
        # Parse the configuration file
        self.template_logger.info("Parsing configuration file " + xmlfile)
        xml_element_tree_parser = etree.iterparse(xmlfile, events=enabled_events)            # Create iterative parser and iterate over element tree
        for event, element in xml_element_tree_parser:          # Note: event defaults to end only so start has to enabled explicitly
            # Set entry flags.
            element_name = element.tag
            if element_name == 'template_config':
                if event == 'start':
                    self.template_logger.debug("Entering template configuration")
                    in_template_config = True                    # Mark entry of template configuration portion
                elif event == 'end':
                    self.template_logger.debug("Leaving template configuration")
                    in_template_config = False                    # Mark exit of template configuration portion
            elif element_name == 'containment_rule' and in_template_config:
                if event == 'start':
                    self.template_logger.debug("Entering rule configuration")
                    try:
                        rule_identifier = element.attrib['rule_identifier']
                        self.template_logger.debug("Rule identifier: " + rule_identifier)
                    except KeyError:
                        self.template_logger.error("No rule identifier specified")
                    else:
                        try:
                            enable = element.attrib['enable']
                            self.template_logger.debug("Enable setting: " + str(enable))
                        except KeyError:
                            enable = 1
                        if enable:
                            in_rule = True
                            self.rule_info_dict[rule_identifier] = {'action':1, 'data':'', 'description':'', 'rule_identifier':rule_identifier, 'severity':0, 'trigger_signature':'', 'frame_type':'DISASSOCIATION', 'sleeptime':0.5, 'duration':60, 'impersonate':'SRC', 'interruptible':0}
                            try:
                                severity = element.attrib['rule_severity']
                                self.template_logger.debug("Severity setting: " + str(severity))
                            except KeyError:
                                self.template_logger.debug("No custom severity for rule " + rule_identifier + " specified, using default severity 0")
                            else:
                                self.rule_info_dict[rule_identifier]['severity'] = fw_modules.module_template.parse_xml_content(severity, 'int')
                                severity = None
                            try:
                                action = element.attrib['rule_action']
                                self.template_logger.debug("Action setting: " + str(action))
                            except KeyError:
                                self.template_logger.debug("No custom action setting for rule " + rule_identifier + " specified, using default setting 1")
                            else:
                                self.rule_info_dict[rule_identifier]['action'] = fw_modules.module_template.parse_xml_content(action, 'int')
                                action = None
                            try:
                                interruptible = element.attrib['rule_interruptible']
                                self.template_logger.debug("Interruptible setting: " + str(interruptible))
                            except KeyError:
                                self.template_logger.debug("No custom interruptible setting for rule " + rule_identifier + " specified, using default setting 0")
                            else:
                                self.rule_info_dict[rule_identifier]['interruptible'] = fw_modules.module_template.parse_xml_content(interruptible, 'int')
                                interruptible = None
                        else:
                            in_rule = False
                            self.template_logger.debug("Skipping disabled rule " + rule_identifier)
                elif event == 'end':
                    self.template_logger.debug("Leaving rule configuration")
                    in_rule = False         # Mark exit of rule element
            # Extract information from elements
            if event == 'end':          # Only parse elements when end event is encountered otherwise content is not yet available
                element_content = element.text
                if in_template_config:
                    if element_name == 'rule_description' and in_rule:
                        self.rule_info_dict[rule_identifier]['description'] = fw_modules.module_template.parse_xml_content(element_content)
                    elif element_name == 'rule_data' and in_rule:
                        self.rule_info_dict[rule_identifier]['data'] = fw_modules.module_template.parse_xml_content(element_content)
                    elif element_name == 'trigger_signature' and in_rule:
                        trigger_signature = fw_modules.module_template.parse_xml_content(element_content)
                        if trigger_signature:
                            self.rule_info_dict[rule_identifier]['trigger_signature'] = trigger_signature
                            self.template_logger.debug("Trigger signature(s): " + str(trigger_signature))
                        else:
                            self.template_logger.warning("No trigger signature specified for rule " + rule_identifier)
                    elif element_name == 'frame_type' and in_rule:
                        self.rule_info_dict[rule_identifier]['frame_type'] = fw_modules.module_template.parse_xml_content(element_content)
                    elif element_name == 'duration' and in_rule:
                        try:
                            timescale = element.attrib['time_scale']
                            self.template_logger.debug("Timescale setting: " + str(timescale))
                        except KeyError:
                            self.template_logger.debug("No custom timescale specified for duration of rule " + rule_identifier + ", using default, seconds")
                            timescale = 's'
                        duration = calculate_time(fw_modules.module_template.parse_xml_content(element_content), timescale)
                        if duration:
                            self.rule_info_dict[rule_identifier]['duration'] = duration
                            self.template_logger.debug("Duration: " + str(duration))
                        else:
                            self.template_logger.warning("Duration for rule " + rule_identifier + "not specified or invalid, using default")
                        timescale = None
                        duration = None
                    elif element_name == 'sleep_time' and in_rule:
                        try:
                            timescale = element.attrib['time_scale']
                            self.template_logger.debug("Timescale setting for sleeptime: "+ str(timescale))
                        except KeyError:
                            self.template_logger.debug("No custom timescale specified for sleeptime of rule " + rule_identifier + ", using default, seconds")
                            timescale = 's'
                        sleeptime = calculate_time(fw_modules.module_template.parse_xml_content(element_content), timescale, timetype='float')
                        if sleeptime:
                            if self.rule_info_dict[rule_identifier]['duration'] > sleeptime:
                                self.rule_info_dict[rule_identifier]['sleeptime'] = sleeptime
                            else:
                                self.template_logger.warning("Sleeptime " + str(sleeptime) + " must be shorter than duration " + str(duration))
                        else:
                            self.template_logger.warning("Sleeptime not specified for rule " + rule_identifier + " or invalid, using default")
                        timescale = None
                        sleeptime = None
                    elif element_name == 'impersonate_rule' and in_rule:
                        impersonate_rule = fw_modules.module_template.parse_xml_content(element_content)
                        self.rule_info_dict[rule_identifier]['impersonate'] = impersonate_rule
                        self.template_logger.debug("Impersonate rule: " + impersonate_rule)
            
        self.template_logger.info("Finished parsing template configuration file")
        self.template_logger.debug("Rule information dictionary: " +str(self.rule_info_dict))
    
    def template_input(self, input):
        """input()
        
        Input interface.
        Decodes received frame data and schedules frame floods.
        
        """
        
        rule_info_dict = self.rule_info_dict
        trace_flood_dict = self.trace_flood_dict
        
        self.template_logger.debug("Raw input: " + str(input))
        
        try:
            if input['MSGTYPE'] == 'ALARM' and input['MSGSUBTYPE'] == 'TRIGGER' and rule_info_dict.has_key(input['MSGNAME']):
                if (trace_flood_dict['flood_active'] and input['MSGNAME'] != trace_flood_dict['flood_signature']) or not trace_flood_dict['flood_active']:
                    if trace_flood_dict['flood_interruptible'] or not trace_flood_dict['flood_active']:
                        self.template_logger.info("Scheduling new flood")
                        new_flood_signature = input['MSGNAME']
                        # Generate command and prevention event for new flood.
                        try:
                            frame_data_dict = dict(item.split('_', 1) for item in input['FRAMEDATA'].split(','))
                        except KeyError:
                            self.template_logger.warning("No frame data in input")
                        else:
                            if rule_info_dict[new_flood_signature]['action']:
                                try:
                                    if frame_data_dict['FSUBTYPE'] == 'BEACON' or frame_data_dict['FSUBTYPE'] == 'PROBEREQUEST':
                                        self.template_logger.info("Beacon or proberequest frame ignored")
                                        return True
                                except KeyError:
                                    pass
                                try:
                                    if rule_info_dict[new_flood_signature]['impersonate'] == 'SRC':
                                        flood_frame_srcaddr = frame_data_dict['ADDR2']
                                        flood_frame_destaddr = frame_data_dict['ADDR1']
                                    elif rule_info_dict[new_flood_signature]['impersonate'] == 'BCASTSRC':
                                        flood_frame_srcaddr = frame_data_dict['ADDR2']
                                        flood_frame_destaddr = 'FFFFFFFFFFFF'
                                    elif rule_info_dict[new_flood_signature]['impersonate'] == 'DEST':
                                        flood_frame_srcaddr = frame_data_dict['ADDR1']
                                        flood_frame_destaddr = frame_data_dict['ADDR2']
                                    elif rule_info_dict[new_flood_signature]['impersonate'] == 'BCASTDEST':
                                        flood_frame_srcaddr = frame_data_dict['ADDR1']
                                        flood_frame_destaddr = 'FFFFFFFFFFFF'
                                    else:
                                        self.template_logger.warning("Invalid impersonate rule " + str(rule_info_dict[new_flood_signature]['impersonate']) + " for rule " + str(rule_info_dict[new_flood_signature]['rule_identifier']))
                                        return False
                                except KeyError as err:
                                    self.template_logger.warning("Address information missing in frame data; details: " + err.__str__())
                                    return False
                                else:
                                    if rule_info_dict[new_flood_signature]['frame_type'] == 'DISASSOCIATION':
                                        flood_frame_fsubtype = 'DISASSOCIATION'
                                    elif rule_info_dict[new_flood_signature]['frame_type'] == 'DEAUTHENTICATION':
                                        flood_frame_fsubtype = 'DEAUTHENTICATION'
                                    else:
                                        self.template_logger.warning("Unsupported frame subtype " + str(rule_info_dict[new_flood_signature]['frame_type']))
                                        return False
                                    # Add flood to trace dict.
                                    trace_flood_dict['flood_identifier'] = rule_info_dict[new_flood_signature]['rule_identifier']
                                    trace_flood_dict['flood_interruptible'] = rule_info_dict[new_flood_signature]['interruptible']
                                    trace_flood_dict['flood_signature'] = new_flood_signature
                                    self.engine_reference.generate_message('COMMAND', rule_info_dict[new_flood_signature]['rule_identifier'], '', '', rule_info_dict[new_flood_signature]['severity'], 'FLOOD', 'SLEEPTIME_' + str(rule_info_dict[new_flood_signature]['sleeptime']) + ',DURATION_' + str(rule_info_dict[new_flood_signature]['duration']), ''.join(['FTYPE_MANAGEMENT', ',FSUBTYPE_', flood_frame_fsubtype, ',ADDR1_', flood_frame_destaddr, ',ADDR2_', flood_frame_srcaddr, ',ADDR3_', flood_frame_srcaddr]), self.command_receiver_group)
                                    trace_flood_dict['flood_active'] = True
                            # Generate event even if action is false.
                            self.engine_reference.generate_message('PREVENTION', rule_info_dict[new_flood_signature]['rule_identifier'], rule_info_dict[new_flood_signature]['description'], new_flood_signature, rule_info_dict[new_flood_signature]['severity'], 'SESSIONCON', '', input['FRAMEDATA'], self.prevention_receiver_group)
                    else:
                        self.template_logger.info("New flood ignored due to active flood " + trace_flood_dict['flood_signature'] + " with interruptible flag false")
                else:
                    self.template_logger.info("Flood with same parameters active, ignoring new request")
            elif input['MSGTYPE'] == 'EVENT' and input['MSGSUBTYPE'] == 'FLOODTIMEOUT':
                self.template_logger.info("Received flood timeout event")
                if trace_flood_dict['flood_active']:
                    self.template_logger.info("Setting status of active flood to inactive")
                    trace_flood_dict['flood_active'] = False
                    trace_flood_dict['flood_identifier'] = None
                    trace_flood_dict['flood_interruptible'] = True
                    trace_flood_dict['flood_signature'] = None
                else:
                    self.template_logger.warning("No active flood, event ignored")
        except KeyError as err:
            self.template_logger.warning("Input invalid; details: " + err.__str__())
        self.template_logger.debug("Trace flood dictionary: " + str(trace_flood_dict))
        
    def template_setup(self):
        """template_setup()
        
        Parses rule file and builds rule dictionary.
        
        """
        
        self.template_logger.info("Setting up session containment template")
        # Parse xml configuration file for rule definitions.
        try:
            self.parse_xml_config(self.rules_file, self.rules_schema)
        except FwFileNotAvailableError as err:
            self.template_logger.error("Couldn't access file " + err.file)
            return False
        except FwConfigNotValidError as err:
            self.template_logger.error("Signature file not valid; details: " + err.reason)
            return False
        # Swap keys with signature names.
        temp_dict = {}
        for rule_identifier, rule_infos in self.rule_info_dict.iteritems():
            if rule_infos['trigger_signature']:
                temp_dict[rule_infos['trigger_signature']] = rule_infos
        self.rule_info_dict = temp_dict
        self.template_logger.debug("Rule information dictionary: " +str(self.rule_info_dict))    
        return True
        
def main(engine_reference, parameter_dictionary, template_logger):
    sessioncon_template_class = TemplateSessionConClass(engine_reference, parameter_dictionary, template_logger)
    return sessioncon_template_class
        
if __name__ == "__main__":
    print "Warning: This module is not intended to be executed directly. Only do this for test purposes."