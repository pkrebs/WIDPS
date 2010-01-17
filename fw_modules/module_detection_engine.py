#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# module_detection_engine.py - WIDS/WIPS framework detection engine module
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

"""Detection engine module

Receives frame data and analyses the information with different detection templates.

"""

# Imports
#
# Custom modules
from fw_modules.module_exceptions import *
import fw_modules.module_template

# Standard modules

# Third-party modules



class DetectionEngineClass(fw_modules.module_template.ModuleClass):
    """DetectionEngineClass
    
    Receives frame data and relays it to different detection templates
    for analysis.
    
    """
    
    def __init__(self, controller_reference, parameter_dictionary, module_logger):
        """Constructor
        
        Constructor description.
        
        """
        
        fw_modules.module_template.ModuleClass.__init__(self, controller=controller_reference, param_dict=parameter_dictionary, logger=module_logger)
        # Helper values.
        self.event_id_counter = 0
        
    def after_run(self):
        """after_run()
        
        Calls termination method of all templates.
        
        """
        
        self.shutdown_templates()

    def before_run(self):
        """
        before_run()
        
        Loads all requested detection templates.
        
        """
        
        # Load detection templates.
        try:
            self.load_templates()
        except FwTemplateSetupError as err:
            self.module_logger.error(err.errmsg)
            return False
        else:
            return True
        
    def process(self, input):
        """input()
        
        Input interface.
        Decodes received frame data and forwards it to templates.
        
        """
        
        self.module_logger.debug("Raw input: " + str(input))
        # Decode and check received frame data.
        try:
            pseudo_frame_dict = dict(item.split('_', 1) for item in input.split('|'))
        except ValueError as err:
                self.module_logger.warning("Frame information not valid; details " + err.__str__())
        pseudo_frame_dict['RAWFRAME'] = input.replace('|', ',')
        print pseudo_frame_dict
        for template_identifier, template_info in self.template_status_dict.items():
            self.module_logger.info("Sending frame data to template " + template_identifier)
            try:
                template_info['template_reference'].template_input(pseudo_frame_dict)
            except AttributeError as err:
                self.module_logger.error("Template reference for template " + template_identifier + " invalid; details: " + err.__str__())
        
def main(controller_reference, parameter_dictionary, module_logger):
    detection_engine_class = DetectionEngineClass(controller_reference, parameter_dictionary, module_logger)
    return detection_engine_class
        
if __name__ == "__main__":
    print "Warning: This module is not intended to be executed directly. Only do this for test purposes."