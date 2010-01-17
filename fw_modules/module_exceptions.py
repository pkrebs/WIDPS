#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# module_exceptions.py - WIDS/WIPS framework exception library module
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

"""Module exceptions

Collection of exception classes for the framework.

"""

# Imports
#
# Standard modules


# Third-party modules


# Custom modules


class FwErrorClass(Exception):
    """FwErrorClass
    
    Base class for framework exceptions and warnings
    
    """
    
    pass

class FwConfigNotValidError(FwErrorClass):
    """FwConfigNotValidError
    
    Raised if validation of configuration file with schema fails.
    
    """
    
    def __init__(self, reason):
        self.reason = reason

class FwFileNotAvailableError(FwErrorClass):
    """FwFileNotAvailableError
    
    Raised if a required file is not found or accessible
    
    """
    
    def __init__(self, file):
        self.file = file   

class FwModuleNotFoundError(FwErrorClass):
    """FwModuleNotFoundError
    
    Raised when a required module is not found at import.
    
    """
    
    def __init__(self, missmodule):
        self.missing_module = missmodule        

class FwNoStatusEntryError(FwErrorClass):
    """FwMissingStatusEntryError
    
    Raised when a module's status information in the controller status dict is requested but no valid entry is found.
    
    """
    
    def __init__(self, missentry):
        self.missing_entry = missentry
        
class FwPermissionError(FwErrorClass):
    """FwPermissionError
    
    Raised when a user executes framework functions without the proper permissions.
    
    """
    
    def __init__(self, wrongperm, neededperm):
        self.wrong_permission = wrongperm
        self.needed_permission = neededperm
        
class FwModuleInitError(FwErrorClass):
    """FwModuleInitError
    
    Raised if something goes wrong during initialising of module.
    
    """
    
    def __init__(self, errmsg):
        self.errmsg = errmsg
        
class FwModuleSetupError(FwErrorClass):
    """FwModulesSetupError
    
    Raised if something goes wrong during setup of a module.
    
    """
    
    def __init__(self, errmsg):
        self.errmsg = errmsg
        
class FwTemplateSetupError(FwErrorClass):
    """FwTemplateSetupError
    
    Raised if something goes wrong during setup of a template.
    
    """
    
    def __init__(self, errmsg):
        self.errmsg = errmsg
        