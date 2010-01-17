#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# template_dbdumper_mysql.py - WIDS/WIPS framework database dumper output template
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

"""MySQL database output template

Writes alarm data to a mysql database.

"""

# Imports
#
# Custom modules
import fw_modules.module_template
from fw_modules.module_exceptions import *

# Standard modules


# Third-party modules
try:
    import MySQLdb
except ImportError:
    raise FwTemplateSetupError, "Couldn't import required module 'MySQLdb'"


class TemplateMySqlClass(fw_modules.module_template.TemplateClass):
    """TemplateMySqlClass
    
    Receives alarm messages and writes them into a MySQL database.
    
    """
    
    def __init__(self, engine_reference, parameter_dictionary, template_logger):
        """Constructor
        
        Constructor description.
        
        """
        
        fw_modules.module_template.TemplateClass.__init__(self, engine=engine_reference, param_dict=parameter_dictionary, logger=template_logger)
        # Default values.
        try:
            self.host_name = self.param_dict['host_name']
        except KeyError:
            self.template_logger.info("No hostname specified, using localhost as default")
            self.host_name = 'localhost'
        try:
            self.db_name = self.param_dict['db_name']
            self.db_tablename = self.param_dict['db_tablename']
            self.db_user = self.param_dict['db_user']
            self.db_pwd = self.param_dict['db_pwd']
        except KeyError as err:
            raise FwTemplateSetupError, "One or more database credentials are missing; Details:", err.__str__()
        # Helper values.
        self.db_handle = None
        self.db_cursor = None
        
    def template_input(self, input):
        """input()
        
        Input interface.
        Updates or inserts received alarm data into mysql db.
        
        """
        
        self.template_logger.debug("Raw input: " + str(input))
        
        try:
            if input['MSGTYPE'] == 'ALARM':
                self.template_logger.info("Writing alarm input to database")
                try:
                    count = self.db_cursor.execute("""UPDATE """ + self.db_tablename +  """ SET EVENT_TYPE = %s, EVENT_NAME = %s, 
                    EVENT_DESCRIPTION = %s, EVENT_SEVERITY = %s, EVENT_RULE = %s, DATETIME = NOW() 
                    WHERE EVENT_ID = %s""", (input['MSGSUBTYPE'], input['MSGNAME'], input['MSGDESCR'], input['MSGSEV'], input['MSGRULE'], input['MSGID']))
                    if self.db_cursor.rowcount <= 0:
                        self.template_logger.debug("Insert alarm data into database " + str(self.db_name))
                        self.db_cursor.execute("""INSERT INTO """ + self.db_tablename + """ (EVENT_ID, EVENT_TYPE, EVENT_NAME,
                        EVENT_DESCRIPTION, EVENT_SEVERITY, EVENT_RULE, DATETIME) 
                        VALUES (%s,%s,%s,%s,%s,%s,NOW())""", (input['MSGID'], input['MSGSUBTYPE'], input['MSGNAME'], input['MSGDESCR'], input['MSGSEV'], input['MSGRULE']))
                    else:
                        self.template_logger.debug("Updated alarm data in database " + str(self.db_name))
                except MySQLdb.Error as err:
                    self.template_logger.warning("Couldn't write to database; details: " + err.args[0].__str__() + " : " + err.args[1].__str__())
        except KeyError as err:
            self.template_logger.warning("Input is invalid; details: " + err.__str__())
        
    def template_setup(self):
        """template_setup()
        
        Connects to mysql database with specified credentials.
        
        """
        
        self.template_logger.info("Opening connection to database " + str(self.db_name) + " with user " + str(self.db_user))
        try:
            self.db_handle = MySQLdb.connect(host=self.host_name, user=self.db_user, passwd=self.db_pwd,db=self.db_name)
            self.db_cursor = self.db_handle.cursor()
            self.db_cursor.execute("set autocommit = 1")
        except MySQLdb.Error as err:
            self.template_logger.error("Couldn't connect to database; details: " + err.args[0].__str__() + " : " + err.args[1].__str__())
            return False
        else:
            return True
        
    def template_shutdown(self):
        """template_shutdown()
        
        Close cursor and db connection.
        
        """
        
        self.template_logger.info("Closing connection to database " + str(self.db_name))
        self.db_handle.close()
        
        
def main(engine_reference, parameter_dictionary, template_logger):
    mysql_template_class = TemplateMySqlClass(engine_reference, parameter_dictionary, template_logger)
    return mysql_template_class
        
if __name__ == "__main__":
    print "Warning: This template is not intended to be executed directly. Only do this for test purposes."