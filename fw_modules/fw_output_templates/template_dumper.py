#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# template_dumper.py - WIDS/WIPS framework file dumper output template
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

"""Dumper output template

Dumps input into a file.

"""

# Imports
#
# Custom modules
import fw_modules.module_template
from fw_modules.module_exceptions import *

# Standard modules


# Third-party modules


class TemplateDumperClass(fw_modules.module_template.TemplateClass):
    """TemplateDumperClass
    
    Receives inout messages and writes them to a dumpfile.
    
    """
    
    def __init__(self, engine_reference, parameter_dictionary, template_logger):
        """Constructor
        
        Constructor description.
        
        """
        
        fw_modules.module_template.TemplateClass.__init__(self, engine=engine_reference, param_dict=parameter_dictionary, logger=template_logger)
        # Default values.
        try:
            self.dumpfile_path = self.param_dict['dumpfile']
        except KeyError:
            raise FwTemplateSetupError, "No dumpfile path specified"
        # Helper values.
        self.DUMPFILE = None
        
    def template_input(self, input):
        """input()
        
        Input interface.
        Decodes received frame data.
        
        """
        
        msg_stringified = []
        
        self.template_logger.debug("Raw input: " + str(input))
        try:
            for msg_tag, msg_value in input.items():
                msg_stringified.append(msg_tag + ':' + msg_value)
        except (AttributeError, TypeError, ValueError) as err:
            self.template_logger.warning("Message data invalid; details: " + err.__str__())
        else:
            try:
                self.DUMPFILE.write(','.join(msg_stringified) + "\n")
                self.DUMPFILE.flush()
            except IOError as err:
                self.template_logger.warning("Couldn't dump to file; details: " + err.__str__())
            
        
    def template_setup(self):
        """template_setup()
        
        """
        
        self.template_logger.info("Setting up template...")
        try:
            self.DUMPFILE = open(self.dumpfile_path, "w")
        except IOError:
            self.template_logger.error("Couldn't open file " + self.dumpfile_path)
            return False
        return True
    
    def template_shutdown(self):
        """template_shutdown()
        
        Close dumpfile.
        
        """
        
        self.template_logger.info("Shutting down")
        close(self.DUMPFILE)
        
        
def main(engine_reference, parameter_dictionary, template_logger):
    dumper_template_class = TemplateDumperClass(engine_reference, parameter_dictionary, template_logger)
    return dumper_template_class
        
if __name__ == "__main__":
    print "Warning: This template is not intended to be executed directly. Only do this for test purposes."