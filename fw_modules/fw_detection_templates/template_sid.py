#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# template_sid.py - WIDS/WIPS framework signature detection template
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

"""SID template

Simple signature-based detection template.

Matches configured signatures/patterns against frame data.
Uses Ternary Search Tree string matching algorithm.

"""

# Imports
#
# Custom modules
import fw_modules.module_template
from fw_modules.module_exceptions import *

# Standard modules
import string

# Third-party modules
try:
    from lxml import etree
except ImportError:
    raise FwTemplateSetupError, "Couldn't import required module 'lxml.etree'"
try:
    import tst
except ImportError:
    raise FwTemplateSetupError, "Couldn't import required module 'tst'"


class TemplateSIDClass(fw_modules.module_template.TemplateClass):
    """TemplateSIDClass
    
    Builds ternary search tree and matches with incoming frame data.
    Generates alarms on matches.
    
    """
    
    def __init__(self, engine_reference, parameter_dictionary, template_logger):
        """Constructor
        
        Constructor description.
        
        """
        
        fw_modules.module_template.TemplateClass.__init__(self, engine=engine_reference, param_dict=parameter_dictionary, logger=template_logger)
        # Default values.
        try:
            self.signature_file = self.param_dict['signature_file']
        except KeyError:
            self.template_logger.warning("No rules file specified!")
            self.signature_file = ''
        try:
            self.signature_schema = self.param_dict['signature_schema']
        except KeyError:
            self.template_logger.warning("No signature schema specified!")
            self.signature_schema = ''
        # Helper variables.
        self.inverted_signatures_list = []          # list of signatures with invert true, to shorten iteration
        self.signature_tree_dict = {}           # includes signatures for every tag
        self.signature_info_dict = {}           # includes signature information from config file
        self.tst_tree_dict = {}
        self.signature_status_dict = {}
        
    def parse_xml_config(self, xmlfile, schemafile):
        """parse_xml_config()
        
        Parses template xml configuration file for signature data.
        
        """
        
        in_template_config = False
        in_signature = False
        in_simple_signature = False
        in_complex_signature = False
        signature_identifier = None
        severity = None
        logic = None
        silent = None
        invert = None
        frame_value = None
        pattern_type = None
        enable = None
        
        enabled_events = ('start', 'end')
        # Validate the configuration file against schema
        print "Validating configuration file with schema:", schemafile
        self.template_logger.info("Validating configuration file with schema: " + schemafile)
        try:
            fw_modules.module_template.validate_xml_config(xmlfile, schemafile)
        except FwFileNotAvailableError:
            raise
        except FwConfigNotValidError: 
            raise
        # Parse the configuration file
        print "Parsing configuration file"
        self.template_logger.info("Parsing configuration file " + xmlfile)
        xml_element_tree_parser = etree.iterparse(xmlfile, events=enabled_events)           # Create iterative parser and iterate over element tree
        for event, element in xml_element_tree_parser:          # Note: event defaults to end only so start has to enabled explicitly
            # Set entry flags.
            element_name = element.tag
            if element_name == 'template_config':
                if event == 'start':
                    self.template_logger.debug("Entering template configuration")
                    in_template_config = True           # Mark entry of template configuration portion
                elif event == 'end':
                    self.template_logger.debug("Leaving template configuration")
                    in_template_config = False          # Mark exit of template configuration portion
            elif element_name == 'simple_signature' or element_name == 'complex_signature' and in_template_config:
                if event == 'start':
                    self.template_logger.debug("Entering signature configuration")
                    try:
                        signature_identifier = element.attrib['signature_identifier']
                        self.template_logger.debug("Signature identifier: " + signature_identifier)
                    except KeyError:
                        self.template_logger.error("No signature identifier specified")
                    else:
                        try:
                            enable = element.attrib['enable']
                            enable = fw_modules.module_template.parse_xml_content(enable, 'int')
                            self.template_logger.debug("Enable setting: " + str(enable))
                        except KeyError:
                            enable = 1
                        if enable:
                            in_signature = True         # Mark entry of simple signature element
                            self.signature_info_dict[signature_identifier] = {'count':0, 'data':'', 'description':'', 'invert':0, 'logic':'OR', 'metasignatures':[], 'patterns':{}, 'severity':0, 'silent':0, 'type':None}
                            try:
                                severity = element.attrib['signature_severity']
                                self.template_logger.debug("Severity setting: " + str(severity))
                            except KeyError:
                                self.template_logger.debug("No custom severity for signature " + signature_identifier + " specified, using default severity 0")
                            else:
                                self.signature_info_dict[signature_identifier]['severity'] = fw_modules.module_template.parse_xml_content(severity, 'int')
                                severity = None
                            try:
                                logic = element.attrib['signature_logic']
                                self.template_logger.debug("Logic setting: " + logic)
                            except KeyError:
                                self.template_logger.debug("No custom logic for signature " + signature_identifier + " specified, using default logic OR")
                            else:
                                self.signature_info_dict[signature_identifier]['logic'] = fw_modules.module_template.parse_xml_content(logic)
                                logic = None
                            try:
                                silent = element.attrib['signature_silent']
                                self.template_logger.debug("Silent setting: " + str(silent))
                            except KeyError:
                                self.template_logger.debug("No custom silent setting for signature " + signature_identifier + " specified, using default setting 0")
                            else:
                                self.signature_info_dict[signature_identifier]['silent'] = fw_modules.module_template.parse_xml_content(silent, 'int')
                                silent = None
                            try:
                                invert = element.attrib['signature_invert']
                                self.template_logger.debug("Invert setting: " + invert)
                            except KeyError:
                                self.template_logger.debug("No custom invert setting for signature " + signature_identifier + "specified, using default setting 0")
                            else:
                                invert = fw_modules.module_template.parse_xml_content(invert, 'int')
                                self.signature_info_dict[signature_identifier]['invert'] = invert
                                if invert == 1 and signature_identifier not in self.inverted_signatures_list:
                                    print self.template_identifier,": INFO: Adding inverted signature", signature_identifier, "to invert list"
                                    self.template_logger.debug("Adding inverted signature " + signature_identifier + " to invert list")
                                    self.inverted_signatures_list.append(signature_identifier)
                                invert = None
                            if element_name == 'simple_signature':
                                in_simple_signature = True
                                self.signature_info_dict[signature_identifier]['type'] = 'simple'
                            elif element_name == 'complex_signature':
                                in_complex_signature = True
                                self.signature_info_dict[signature_identifier]['type'] = 'complex'
                        else:
                            in_signature = False
                            self.template_logger.debug("Skipping disabled signature " + signature_identifier)
                elif event == 'end':
                    self.template_logger.debug("Leaving signature configuration")
                    in_signature = False        # Mark exit of signature element
                    in_simple_signature = False
                    in_complex_signature = False
            # Extract information from elements
            if event == 'end':                          # Only parse elements when end event is encountered otherwise content is not yet available
                element_content = element.text
                if in_template_config:
                    if in_signature:
                        if element_name == 'signature_description':
                            self.signature_info_dict[signature_identifier]['description'] = fw_modules.module_template.parse_xml_content(element_content)
                        elif element_name == 'signature_data':
                            self.signature_info_dict[signature_identifier]['data'] = fw_modules.module_template.parse_xml_content(element_content)
                        elif element_name == 'signature_patterns' and in_simple_signature:
                            try:
                                frame_value = element.attrib['frame_value'].upper().replace(' ', '')
                            except KeyError:
                                self.template_logger.warning("Frame value for patterns in signature " + signature_identifier + " not specified")
                            else:
                                self.signature_info_dict[signature_identifier]['patterns'][frame_value] = {'pattern_list':fw_modules.module_template.parse_xml_content(element_content, 'list'), 'pattern_type':'hex'}
                                self.signature_info_dict[signature_identifier]['count'] = self.signature_info_dict[signature_identifier]['count'] + 1               # count is number of different frame-values to check
                                try:
                                    pattern_type = element.attrib['pattern_type']
                                except KeyError:
                                    self.template_logger.debug("No custom pattern type for signature " + signature_identifier + " specified, using default hex")
                                else:
                                    self.signature_info_dict[signature_identifier]['patterns'][frame_value]['pattern_type'] = pattern_type
                                if not self.signature_tree_dict.has_key(frame_value):
                                    self.signature_tree_dict[frame_value] = []
                                self.template_logger.debug("Append signature " + signature_identifier + " to signature tree dict")
                                self.signature_tree_dict[frame_value].append(signature_identifier)      # add signature to tree dict entry for frame value 
                        elif element_name == 'signature_subsignatures' and in_complex_signature:
                            self.signature_info_dict[signature_identifier]['subsignatures'] = fw_modules.module_template.parse_xml_content(element_content, 'list')
                            self.signature_info_dict[signature_identifier]['count'] = len(self.signature_info_dict[signature_identifier]['subsignatures'])
        # Set metasignatures in subsignature entries
        for signature, signature_info in self.signature_info_dict.items():
            if signature_info['type'] == 'complex':
                for subsignature in signature_info['subsignatures']:
                    try:
                        self.signature_info_dict[subsignature]['metasignatures'].append(signature)
                    except KeyError:
                        print self.template_identifier,": WARN: Subsignature", subsignature, "of metasignature", signature, "missing or disabled"
                        self.template_logger.warning("Subsignature " + subsignature + " of metasignature " + signature + " missing or disabled")
        self.template_logger.debug("Signature information dicitonary: " + str(self.signature_info_dict))
        self.template_logger.debug("Signature tree ditcionary: " + str(self.signature_tree_dict))
        self.template_logger.debug("Inverted signatures: " + str(self.inverted_signatures_list))
        self.template_logger.info("Finished parsing template configuration file")
        
    def template_input(self, input):
        """input()
        
        Input interface.
        Looks for matches in received frame data and generates alarms if applicable.
        Input is frame content in a dictionary with tags as keys.
        
        """
        
        processed_signatures_list = []


        def process_metasignature(signature_name):
            """process_metasignature()
            
            Checks recursively if a metasignature should be triggered.
            
            """
            
            self.template_logger.debug("Processing metasignature " + signature_name)
            processed_signatures_list.append(signature_name)
            if self.signature_status_dict[signature_name]['logic'] == 'OR':         # if singature is OR type and any of its patterns match, fire it
                self.template_logger.debug("Processing OR metasignature")
                self.signature_status_dict[signature_name]['hits'] = self.signature_status_dict[signature_name]['hits'] + 1
                if not self.signature_status_dict[signature_name]['silent'] and not self.signature_status_dict[matched_signature]['invert']:                     # check if signature should trigger alarm or stay silent
                    self.template_logger.info("ALARM for OR metasignature " + str(signature_name))
                    self.engine_reference.generate_message('ALARM', signature_name, self.signature_info_dict[signature_name]['description'], tree_tag+'='+pattern, self.signature_info_dict[signature_name]['severity'], 'TRIGGER', '', input['RAWFRAME'])
                # Do checkup for all metasignatures.
                for metasignature_name in self.signature_status_dict[signature_name]['metasignatures']:
                    process_metasignature(metasignature_name)
            elif self.signature_status_dict[signature_name]['logic'] == 'AND':
                self.template_logger.debug("Processing AND metasignature")
                self.signature_status_dict[signature_name]['hits'] = self.signature_status_dict[signature_name]['hits'] + 1
                if self.signature_status_dict[signature_name]['hits'] == self.signature_status_dict[signature_name]['count'] and not self.signature_status_dict[signature_name]['silent'] and not self.signature_status_dict[matched_signature]['invert']:
                    self.template_logger.info("ALARM for AND metasignature " + str(signature_name))
                    self.engine_reference.generate_message('ALARM', signature_name, self.signature_info_dict[signature_name]['description'], tree_tag+'='+pattern, self.signature_info_dict[signature_name]['severity'], 'TRIGGER', '', input['RAWFRAME'])
                for metasignature_name in self.signature_status_dict[signature_name]['metasignatures']:
                    process_metasignature(metasignature_name)
        self.template_logger.debug("Signature status dictionary: " + str(self.signature_status_dict))
        
        
        self.template_logger.debug("Raw input: " + str(input))
        # Match frame content against tst trees.
        for tree_tag, tree in self.tst_tree_dict.iteritems():
            try:
                for pattern, length, signature_list in tree.scan(input[tree_tag], tst.TupleListAction()):
                    if length > 0:          # watch only for full matches, prefixes are indicated by negative lengths
                        self.template_logger.debug("Found match for signature(s) " + str(signature_list) + " in value " + str(tree_tag) + " with pattern " + str(pattern))
                        # Check if any matched signature is triggered, look also for metasignatures which will trigger too
                        for matched_signature in signature_list:
                            processed_signatures_list.append(matched_signature)
                            if self.signature_status_dict[matched_signature]['logic'] == 'OR':         # if signature is OR type and any of its patterns match, fire it
                                self.template_logger.debug("Processing OR signature")
                                self.signature_status_dict[matched_signature]['hits'] = self.signature_status_dict[matched_signature]['hits'] + 1
                                if not self.signature_status_dict[matched_signature]['silent'] and not self.signature_status_dict[matched_signature]['invert']:                     # check if signature should trigger alarm or stay silent
                                    self.template_logger.info("ALARM for OR signature " + str(matched_signature) + " with value " + str(tree_tag) + " and pattern " + str(pattern))
                                    self.engine_reference.generate_message('ALARM', matched_signature, self.signature_info_dict[matched_signature]['description'], tree_tag+'='+pattern, self.signature_info_dict[matched_signature]['severity'], 'TRIGGER', '', input['RAWFRAME'])
                                # Do checkup for all metasignatures.
                                for metasignature_name in self.signature_status_dict[matched_signature]['metasignatures']:
                                    process_metasignature(metasignature_name)
                            elif self.signature_status_dict[matched_signature]['logic'] == 'AND':
                                self.template_logger.debug("Processing AND signature")
                                self.signature_status_dict[matched_signature]['hits'] = self.signature_status_dict[matched_signature]['hits'] + 1
                                if self.signature_status_dict[matched_signature]['hits'] == self.signature_status_dict[matched_signature]['count'] and not self.signature_status_dict[matched_signature]['invert']:
                                    if not self.signature_status_dict[matched_signature]['silent']:
                                        self.template_logger.info("ALARM for AND signature " + str(matched_signature) + " with value " + str(tree_tag) + " and pattern " + str(pattern))
                                        self.engine_reference.generate_message('ALARM', matched_signature, self.signature_info_dict[matched_signature]['description'], tree_tag+'='+pattern, self.signature_info_dict[matched_signature]['severity'], 'TRIGGER', '', input['RAWFRAME'])
                                    # Do checkup for metasignatures only if signature matches.
                                    for metasignature_name in self.signature_status_dict[matched_signature]['metasignatures']:
                                        process_metasignature(metasignature_name)
            except KeyError as err:
                self.template_logger.warning("Error with signature keys; details: " + err.__str__())
        # Process inverted signatures.
        for inverted_signature_identifier in self.inverted_signatures_list:
            if self.signature_status_dict[inverted_signature_identifier]['logic'] == 'OR' and self.signature_status_dict[inverted_signature_identifier]['hits'] == 0:
                if not self.signature_status_dict[inverted_signature_identifier]['silent']:
                    self.template_logger.info("ALARM for inverted OR signature " + inverted_signature_identifier)
                    self.engine_reference.generate_message('ALARM', inverted_signature_identifier, self.signature_info_dict[inverted_signature_identifier]['description'], 'NOT ' + inverted_signature_identifier, self.signature_info_dict[inverted_signature_identifier]['severity'], 'TRIGGER', '', input['RAWFRAME'])
                for metasignature_name in self.signature_status_dict[inverted_signature_identifier]['metasignatures']:
                                    process_metasignature(metasignature_name)
            elif self.signature_status_dict[inverted_signature_identifier]['logic'] == 'AND' and self.signature_status_dict[inverted_signature_identifier]['hits'] < self.signature_status_dict[inverted_signature_identifier]['count']:
                if not self.signature_status_dict[inverted_signature_identifier]['silent']:
                    self.template_logger.info("ALARM for inverted AND signature " + inverted_signature_identifier)
                    self.engine_reference.generate_message('ALARM', inverted_signature_identifier, self.signature_info_dict[inverted_signature_identifier]['description'], 'NOT ' + inverted_signature_identifier, self.signature_info_dict[inverted_signature_identifier]['severity'], 'TRIGGER', '', input['RAWFRAME'])
                for metasignature_name in self.signature_status_dict[inverted_signature_identifier]['metasignatures']:
                                    process_metasignature(metasignature_name)
        self.template_logger.debug("Signature status dictionary: " + str(self.signature_status_dict))
        # Reset hit counter for all matched signatures.
        for processed_singature in processed_signatures_list:
            self.signature_status_dict[processed_singature]['hits'] = 0
        
    def template_setup(self):
        """template_setup()
        
        Sets up TST tree for matching.
        A separate tree is built for each distinct frame value
        (e. g. one tree for rtheader matches, one for address matches).
        
        """
        
        def process_pattern(base_pattern, pattern_tag, pattern_type):
            """process_pattern()
            
            Preprocesses patterns, e. g. normalises pattern and expands wildcards.
            
            """
            
            max_wildcards = 6
            hexdigits_uppercase = '0123456789ABCDEF'
            subpattern_list = []
            wildcard_alphabet = hexdigits_uppercase         # wildcard alphabet defults to hex characters
      
            def check_pattern(pattern, tag):
                """check_pattern()
                
                Checks if pattern has correct structure.
                
                """
                
                if tag == 'ADDR1' or tag == 'ADDR2' or tag == 'ADDR3' or tag == 'ADDR4':
                    if len(pattern) != 12:
                        self.template_logger.warning("Length of address " + pattern + " invalid")
                        return False
                    elif not pattern.replace('*', '').isalnum():
                        self.template_logger.warning("Address " + pattern + " contains invalid characters")
                        return False
                elif tag == 'FTYPE' or tag == 'FSUBTYPE':
                    if not pattern.replace('*', '').isalpha():
                        self.template_logger.warning("Type or subtype " + pattern + " contains invalid characters")
                        return False
                return True
            
            def expand_wildcards(subpattern, wildcard_index):
                """expand_wildcards()
                
                Is called recursively if a wildcard is encountered.
                Creates a list of all possible subpatterns.
                
                """
                
                wildcard_index = subpattern.find('*', wildcard_index)
                if wildcard_index < 0:
                    subpattern_list.append(subpattern)
                    return True
                else:
                    for wildcard_char in wildcard_alphabet:
                        subsubpattern = subpattern.replace(subpattern[wildcard_index], wildcard_char, 1)        # replace the first wildcard with the next character in substitution alphabet
                        if wildcard_index == subpattern.rfind('*'):
                            subpattern_list.append(subsubpattern)
                        else:
                            expand_wildcards(subsubpattern, wildcard_index)
                    
            # Preprocess pattern
            base_pattern_normalised = str(base_pattern).upper().replace(' ', '')
            if check_pattern(base_pattern_normalised, pattern_tag):
                    if '*' in base_pattern_normalised:
                        if base_pattern_normalised.count('*') <= max_wildcards:
                            # set alphabet to substitute wildcards with.
                            if pattern_type == 'word':
                                wildcard_alphabet = string.ascii_letters+string.digits+' '+string.punctuation.replace('*', '')      # wildcard is not inserted, would result in infinite loop
                            elif pattern_type == 'bit':
                                wildcard_alphabet = '01'
                            elif pattern_type == 'decimal':
                                wildcard_alphabet = string.digits
                            # Create all possible subpatterns for wildcards.
                            expand_wildcards(base_pattern_normalised, 0)
                            self.template_logger.debug("Created " + str(len(subpattern_list)) + " subpatterns for wildcard base pattern " + base_pattern_normalised)
                        else:
                            self.template_logger.warning("Not more than " + max_wildcards + " wildcards allowed")
                            return []
                    else:
                        subpattern_list.append(base_pattern_normalised)
            else:
                self.template_logger.warning("Pattern " + base_pattern_normalised + " is invalid")
                return []
            return subpattern_list
        
        # Parse xml configuration file for signature definitions.
        try:
            self.parse_xml_config(self.signature_file, self.signature_schema)
        except FwFileNotAvailableError as err:
            self.template_logger.error("Couldn't access file " + err.file)
            return False
        except FwConfigNotValidError as err:
            self.template_logger.error("Signature file not valid; details: " + err.reason)
            return False
        # Create TST tree dictionary
        self.tst_tree_dict = {}         # clear tree dict in case something has changed
        self.template_logger.info("Creating TST trees")
        if self.signature_tree_dict and self.signature_info_dict:
            for frame_value_tag, signature_list in self.signature_tree_dict.items():
                # Create a tree for each tag and add all patterns to it.
                frame_value_tag_normalised = str(frame_value_tag).upper().replace(' ', '')
                tst_tree = tst.TST()
                self.template_logger.debug("Created TST tree for tag " + frame_value_tag_normalised)
                for signature in signature_list:
                    if self.signature_info_dict[signature]['type'] == 'simple':                # only simple signatures have patterns
                        try:
                            for frame_value_pattern in self.signature_info_dict[signature]['patterns'][frame_value_tag]['pattern_list']:        # add all patterns for the current tag
                                    frame_value_pattern_type = self.signature_info_dict[signature]['patterns'][frame_value_tag]['pattern_type']
                                    for subpattern in process_pattern(frame_value_pattern, frame_value_tag_normalised, frame_value_pattern_type):
                                        if not tst_tree[subpattern]:
                                            self.template_logger.debug("Created new entry in tst tree for tag " +frame_value_tag_normalised + " with pattern " + subpattern)
                                            tst_tree[subpattern] = []           # create new pattern entry for tst tree
                                        tst_tree[subpattern].append(signature)          # append signature to pattern entry of tree
                                        self.template_logger.debug("Created new entry in tst tree for tag " +frame_value_tag_normalised + " with pattern " + subpattern)
                                        self.template_logger.debug("TST tree for subpattern " + str(subpattern) + ": " + str(tst_tree[subpattern]))
                        except KeyError:
                            self.template_logger.warning("Couldn't find tag " + frame_value_tag_normalised + " for signature " + signature)
                # Add finished tree to tree dict
                self.tst_tree_dict[frame_value_tag_normalised] = tst_tree
            self.template_logger.info("Created TST tree dictionary")
            self.template_logger.debug("TST tree dictionary: " + str(self.tst_tree_dict))
            self.template_logger.info("Creating signature status dictionary")
            self.signature_status_dict = {}
            for signature_name, signature_info in self.signature_info_dict.items():
                # Create status entry for each signature (simple and complex)
                self.signature_status_dict[signature_name] = {'hits':0, 'count':0, 'logic':'', 'silent':0, 'invert':0, 'metasignatures':[]}
                try:
                    self.signature_status_dict[signature_name]['count'] = signature_info['count']           # count is total number of patterns or subsignatures, is set by parser
                    self.signature_status_dict[signature_name]['logic'] = signature_info['logic']
                    self.signature_status_dict[signature_name]['silent'] = signature_info['silent']
                    self.signature_status_dict[signature_name]['invert'] = signature_info['invert']
                    self.signature_status_dict[signature_name]['metasignatures'] = signature_info['metasignatures']
                except KeyError:
                    self.template_logger.warning("Couldn't create signature status entry for signature " + signature_name)
                else:
                    self.template_logger.debug("Created signatures status entry for signature " + signature_name)
            self.template_logger.debug("Signature status dictionary: " + str(self.signature_status_dict))
        return True
    
        
def main(engine_reference, parameter_dictionary, template_logger):
    sid_template_class = TemplateSIDClass(engine_reference, parameter_dictionary, template_logger)
    return sid_template_class
        
if __name__ == "__main__":
    print "Warning: This module is not intended to be executed directly. Only do this for test purposes."