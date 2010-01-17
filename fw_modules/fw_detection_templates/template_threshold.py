#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# template_threshold.py - WIDS/WIPS framework threshold detection template
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

"""Threshold template

Simple threshold-based detection template.

Observes occurence of certain frame types (e. g. beacons, disassocs)
in a given time window and alerts if occurence is higher than a set threshold.

"""

# Imports
#
# Custom modules
import fw_modules.module_template
from fw_modules.module_exceptions import *

# Standard modules
import collections
import Queue
import sys

# Third-party modules
try:
    from lxml import etree
except ImportError:
    raise FwTemplateSetupError, "Couldn't import required module 'lxml.etree'"


class TemplateThresholdClass(fw_modules.module_template.TemplateClass):
    """TemplateThresholdClass
    
    Builds trace dictionary consisting of arrays and observes frequency of
    incoming frame messages of a given type.
    
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
            self.template_logger.warning("No rules file specified")
            self.rules_file = ''
        try:
            self.rules_schema = self.param_dict['rules_schema']
        except KeyError:
            self.template_logger.warning("No rules schema specified")
            self.rules_schema = ''
        # Helper values.
        self.rule_info_dict = {}
        self.frame_occurence_dict = {}          # holds a deque (bounded queue) of frame occurences per threshold/timerange pair
        self.rule_status_dict = {}
        self.rule_shortcut_dict = {}            # holds references to the occurence infos from each rule to have dircet access to queue values 
        self.raised_alarms = []

    def parse_xml_config(self, xmlfile, schemafile):
        """parse_xml_config()
        
        Parses template xml configuration file for signature data.
        
        """
        
        def calculate_timerange(timerange, timescale):
            """calculate_timerange()
            
            Calculates timerange in microseconds depending on timescale.
            
            """
            
            if not timerange.isdigit():
                self.template_logger.warning("Invalid timerange " + str(timerange))
                return None
            else:
                timerange = int(timerange)
                if timerange <= 0:
                    self.template_logger.warning("Timerange " + str(timerange) + " must be greater than 0")
                    return None
            if timescale == 'h':
                return timerange * 3600000000
            elif timescale == 'min':
                return timerange * 60000000
            elif timescale == 's':
                return timerange * 1000000
            elif timescale == 'ms':
                return timerange * 1000
            elif timescale == 'us':
                return timerange
            else:
                self.template_logger.warning("Timescale " + str(timescale) + " not valid")
                return None
                
        in_template_config = False
        in_rule = False
        rule_identifier = None
        severity = None
        silent = None
        frame_value = None
        timescale = None
        timerange = None
        
        enabled_events = ('start', 'end')
        # Validate the configuration file against schema
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
        xml_element_tree_parser = etree.iterparse(xmlfile, events=enabled_events)           # Create iterative parser and iterate over element tree
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
            elif element_name == 'threshold_rule' and in_template_config:
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
                            enable = fw_modules.module_template.parse_xml_content(enable, 'int')
                        except KeyError:
                            enable = 1
                        if enable:
                            in_rule = True
                            self.rule_info_dict[rule_identifier] = {'data':'', 'description':'', 'severity':0, 'silent':0, 'threshold':None, 'timerange':None, 'frame_value':None, 'frame_patterns':[]}
                            try:
                                severity = element.attrib['rule_severity']
                                self.template_logger.debug("Severity setting: " + str(severity))
                            except KeyError:
                                self.template_logger.debug("No custom severity for rule " + rule_identifier + " specified, using default severity 0")
                            else:
                                self.rule_info_dict[rule_identifier]['severity'] = fw_modules.module_template.parse_xml_content(severity, 'int')
                                severity = None
                            try:
                                silent = element.attrib['rule_silent']
                                self.template_logger.debug("Silent setting: " + str(silent))
                            except KeyError:
                                self.template_logger.debug("No custom silent setting for rule " + rule_identifier + " specified, using default setting 0")
                            else:
                                self.rule_info_dict[rule_identifier]['silent'] = fw_modules.module_template.parse_xml_content(silent, 'int')
                                silent = None
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
                    if in_rule:
                        if element_name == 'rule_description':
                            self.rule_info_dict[rule_identifier]['description'] = fw_modules.module_template.parse_xml_content(element_content)
                        elif element_name == 'rule_data':
                            self.rule_info_dict[rule_identifier]['data'] = fw_modules.module_template.parse_xml_content(element_content)
                        elif element_name == 'timerange' and in_rule:
                            try:
                                timescale = element.attrib['time_scale']
                                self.template_logger.debug("Timescale: " + str(timescale))
                            except KeyError:
                                self.template_logger.debug("No custom timescale specified for rule " + rule_identifier, + ", using default, microseconds")
                                timescale = 'us'
                            timerange = calculate_timerange(fw_modules.module_template.parse_xml_content(element_content), timescale)
                            if timerange:
                                self.rule_info_dict[rule_identifier]['timerange'] = timerange
                            timescale = None
                            timerange = None
                        elif element_name == 'rule_content' and in_rule:
                            try:
                                frame_value = element.attrib['frame_value']
                                self.template_logger.debug("Frame value: " + str(frame_value))
                            except KeyError:
                                self.template_logger.warning("No frame value specified for rule " + str(rule_identifier))
                            else:
                                try:
                                    threshold = int(element.attrib['threshold'])
                                    self.template_logger.debug("Threshold: " + str(threshold))
                                except KeyError:
                                    self.template_logger.debug("No threshold specified for rule " + str(rule_identifier))
                                else:
                                    self.rule_info_dict[rule_identifier]['frame_value'] = frame_value
                                    self.rule_info_dict[rule_identifier]['threshold'] = threshold
                                    self.rule_info_dict[rule_identifier]['frame_patterns'] = fw_modules.module_template.parse_xml_content(element_content, 'list')
                                frame_value = None
                                threshold = None
                                
        self.template_logger.info("Finished parsing template configuration file")
        self.template_logger.debug("Rule information dictionary: " + str(self.rule_info_dict))
        
    def template_input(self, input):
        """input()
        
        Input interface.
        Decodes received frame data.
        Input is frame content in a dictionary with tags as keys.
        
        """
        
        self.template_logger.debug("Raw input: " + str(input))
        
        raised_alarms = self.raised_alarms
        shortcut_dict = self.rule_shortcut_dict
        # Calculate frame timestamp.
        try:
            timestamp = (int(input['TSSEC']) * 1000000) + int(input['TSUSEC'])
        except KeyError:
            self.template_logger.warning("Couldn't get timestamp information from frame")
        except ValueError as err:
            self.template_logger.warning("Timestamp information invalid; Details: " + err.__str__())
        else:
            for frame_value, frame_patterns_dict in self.frame_occurence_dict.iteritems():
                for frame_pattern, threshold_infos in frame_patterns_dict.iteritems():
                    try:
                        if input[frame_value] == frame_pattern:
                            self.template_logger.info("Match in frame for value " + str(frame_value) + " and pattern " + str(frame_pattern))
                            self.template_logger.debug("Frame timestamp in microseconds: " + str(timestamp))
                            for threshold, timerange_infos in threshold_infos.iteritems():
                                for timerange, queue_infos in timerange_infos.iteritems():
                                    delta_time = timestamp - timerange
                                    # Check frame occurence against timesatmp to determine threshold violations.
                                    if queue_infos['frame_queue']:
                                        if max(queue_infos['frame_queue']) >= delta_time:           # newest timestamp not older than timerange
                                            if len(queue_infos['frame_queue']) < threshold:         # check bounds of queue
                                                queue_infos['frame_queue'].append(timestamp)
                                            else:
                                                queue_infos['frame_queue'].remove(min(queue_infos['frame_queue']))          # discard oldest timestamp if queue is filled
                                                queue_infos['frame_queue'].append(timestamp)
                                                if min(queue_infos['frame_queue']) >= delta_time:
                                                    if not self.rule_status_dict[queue_infos['rule_identifier']]:
                                                        self.template_logger.info("RAISE ALARM for rule " + str(queue_infos['rule_identifier']))
                                                        self.rule_status_dict[queue_infos['rule_identifier']] = 1
                                                        raised_alarms.append(queue_infos['rule_identifier'])
                                                        self.engine_reference.generate_message('ALARM', queue_infos['rule_identifier'], self.rule_info_dict[queue_infos['rule_identifier']]['description'], frame_pattern + '>=' + str(threshold) + '_' + str(timerange), str(self.rule_info_dict[queue_infos['rule_identifier']]['severity']), 'RAISE', self.rule_info_dict[queue_infos['rule_identifier']]['data'], input['RAWFRAME'])
                                                else:
                                                    if self.rule_status_dict[queue_infos['rule_identifier']]:
                                                        self.template_logger.info("CLEAR ALARM for rule " + str(queue_infos['rule_identifier']))
                                                        self.rule_status_dict[queue_infos['rule_identifier']] = 0
                                                        raised_alarms.remove(queue_infos['rule_identifier'])
                                                        self.engine_reference.generate_message('ALARM', queue_infos['rule_identifier'], self.rule_info_dict[queue_infos['rule_identifier']]['description'], frame_pattern + '>=' + str(threshold) + '_' + str(timerange), str(self.rule_info_dict[queue_infos['rule_identifier']]['severity']), 'CLEAR', self.rule_info_dict[queue_infos['rule_identifier']]['data'], input['RAWFRAME'])              
                                        else:                   # newest timestamp older than timerange -> data in queue not longer interesting
                                            queue_infos['frame_queue'] = [timestamp]
                                            if self.rule_status_dict[queue_infos['rule_identifier']]:
                                                self.template_logger.info("CLEAR ALARM for rule " + str(queue_infos['rule_identifier']))
                                                self.rule_status_dict[queue_infos['rule_identifier']] = 0
                                                raised_alarms.remove(queue_infos['rule_identifier'])
                                                self.engine_reference.generate_message('ALARM', queue_infos['rule_identifier'], self.rule_info_dict[queue_infos['rule_identifier']]['description'], frame_pattern + '>=' + str(threshold) + '_' + str(timerange), str(self.rule_info_dict[queue_infos['rule_identifier']]['severity']), 'CLEAR', self.rule_info_dict[queue_infos['rule_identifier']]['data'], input['RAWFRAME'])   
                                    else:
                                        queue_infos['frame_queue'].append(timestamp)
                        else:
                            # Check if raised alarms should be cleared.
                            for raised_alarm_identifier in raised_alarms:
                                if (timestamp - max(shortcut_dict[raised_alarm_identifier]['frame_queue'])) > self.rule_info_dict[raised_alarm_identifier]['timerange']:
                                    self.template_logger.info("CLEAR ALARM for rule " + str(queue_infos['rule_identifier']))
                                    shortcut_dict[raised_alarm_identifier]['frame_queue'] = []
                                    self.rule_status_dict[raised_alarm_identifier] = 0
                                    raised_alarms.remove(raised_alarm_identifier)
                                    self.engine_reference.generate_message('ALARM', raised_alarm_identifier, self.rule_info_dict[raised_alarm_identifier]['description'], self.rule_info_dict[raised_alarm_identifier]['frame_value'] + '>=' + str(self.rule_info_dict[raised_alarm_identifier]['threshold']) + '_' + str(self.rule_info_dict[raised_alarm_identifier]['timerange']), str(self.rule_info_dict[raised_alarm_identifier]['severity']), 'CLEAR', self.rule_info_dict[raised_alarm_identifier]['data'], input['RAWFRAME'])
                    except KeyError:
                        self.template_logger.info("No frame value " + str(frame_value) + " in frame")
        self.template_logger.debug("Frame occurence dictionary: " + str(self.frame_occurence_dict))
        
    def template_setup(self):
        """template_setup()
        
        Sets up arrays for tracking occurence
        of frames for each threshold.
        
        """
        
        # Parse xml configuration file for rule definitions.
        try:
            self.parse_xml_config(self.rules_file, self.rules_schema)
        except FwFileNotAvailableError as err:
            self.template_logger.error("Couldn't access file " + err.file)
            return False
        except FwConfigNotValidError:
            self.template_logger.error("Signature file not valid " + err.reason)
            return False
        # Build frame occurence dict for tracing frames.
        self.template_logger.info("Building trace dictionary for observing frame occurence")
        for rule_identifier, rule_information in self.rule_info_dict.items():
            self.template_logger.debug("Generating trace dict entry for rule " + str(rule_identifier))
            if not self.frame_occurence_dict.has_key(rule_information['frame_value']):
                self.frame_occurence_dict[rule_information['frame_value']] = {}
            for frame_pattern in rule_information['frame_patterns']:
                if not self.frame_occurence_dict[rule_information['frame_value']].has_key(frame_pattern):
                    self.frame_occurence_dict[rule_information['frame_value']][frame_pattern] = {}
                if not self.frame_occurence_dict[rule_information['frame_value']][frame_pattern].has_key(rule_information['threshold']):
                    self.frame_occurence_dict[rule_information['frame_value']][frame_pattern][rule_information['threshold']] = {}
                self.frame_occurence_dict[rule_information['frame_value']][frame_pattern][rule_information['threshold']][rule_information['timerange']] = {'frame_queue':None, 'rule_identifier':rule_identifier, 'over_threshold':0}
                self.rule_shortcut_dict[rule_identifier] = self.frame_occurence_dict[rule_information['frame_value']][frame_pattern][rule_information['threshold']][rule_information['timerange']]
                # Create deque for rule
                self.frame_occurence_dict[rule_information['frame_value']][frame_pattern][rule_information['threshold']][rule_information['timerange']]['frame_queue'] = []
                self.rule_status_dict[rule_identifier] = 0
        self.template_logger.debug("Frame occurence dictionary: " + str(self.frame_occurence_dict))
        self.template_logger.debug("Rule status dictionary: " + str(self.rule_status_dict))
        self.template_logger.debug("Rule shortcut dictionary: " + str(self.rule_shortcut_dict))        
        return True
        
def main(engine_reference, parameter_dictionary, template_logger):
    threshold_template_class = TemplateThresholdClass(engine_reference, parameter_dictionary, template_logger)
    return threshold_template_class
        
if __name__ == "__main__":
    print "Warning: This module is not intended to be executed directly. Only do this for test purposes."