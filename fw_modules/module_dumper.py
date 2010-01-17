#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# module_dumper.py - WIDS/WIPS framework file dumper module
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

"""Dumper module

Test module which outputs any input values in a file.

"""

# Imports
#
# Custom modules
import fw_modules.module_template
from fw_modules.module_exceptions import *
# Standard modules
import time

# Third-party modules


class DumperClass(fw_modules.module_template.ModuleClass):
    """DumperClass
    
    Receives messages and dumps them into file.
    
    """
    
    def __init__(self, controller_reference, parameter_dictionary, module_logger):
        """Constructor
        
        """
        
        fw_modules.module_template.ModuleClass.__init__(self, controller=controller_reference, param_dict=parameter_dictionary, logger=module_logger)
        # Default values.
        try:
            self.dumpfile_path = self.param_dict['dumpfile']
        except KeyError:
            raise FwModuleSetupError, self.module_identifier + ": ERROR: No dumpfile specified"
            self.module_logger.error("No dumpfile specified")
            return None
        # Helper values.
        self.DUMPFILE = None

    def after_run(self):
        """after_run()
        
        Closes dumpfile.
        
        """
        
        try:
            self.DUMPFILE.close()
        except IOError:
            self.module_logger.warning("Couldn't close dumpfile properly")

    def before_run(self):
        """before_run()
        
        Opens dumpfile.
        
        """
        
        try:
            self.DUMPFILE = open(self.dumpfile_path, "w")
        except IOError:
            self.module_logger.error("Couldn't open file " + str(self.dumpfile_path))
            return False
        else:
            return True
        
    def dump_to_file(self, data):
		"""dump_to_file()
		
			Dumps input to file.
		
		"""
        self.module_logger.debug("Dumped data: " + str(data))
        try:
            self.DUMPFILE.write(data + "\n")
            self.DUMPFILE.flush()
        except IOError as err:
            self.module_logger.warning("Couldn't dump to file; details: " + err.__str__())
        
    def process(self, input):
        """process()
        
        Main action.
        
        """
        
        self.module_logger.debug("Raw input: " + str(input))
        self.dump_to_file(input)
        
def main(controller_reference, parameter_dictionary, module_logger):
    dumper_class = DumperClass(controller_reference, parameter_dictionary, module_logger)
    return dumper_class
        
if __name__ == "__main__":
    print "Warning: This module is not intended to be executed directly. Only do this for test purposes."