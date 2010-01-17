#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# template_gui.py - WIDS/WIPS framework GUI output template
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

"""GUI output template

Displays alarm and prevention events on a simple GUI.

"""

# Imports
#
# Custom modules
import fw_modules.module_template
from fw_modules.module_exceptions import *
import fw_modules.fw_output_templates.ui_template_gui_v2

# Standard modules
import sys
import threading
import time

# Third-party modules
try:
    from PyQt4 import QtCore, QtGui
except ImportError:
    raise FwTemplateSetupError, "Couldn't import required module 'PyQt4.QtCore or PyQt4.QtGui'"

class TemplateGuiClass(threading.Thread, QtCore.QObject, fw_modules.module_template.TemplateClass):
    """TemplateGuiClass
    
    Base template class for GUI.
    Implements the 'business logic' for the GUI.
    
    """
    
    def __init__(self, engine_reference, parameter_dictionary, template_logger):
        """Constructor
        
        Constructor description.
        
        """
        
        # Template starts separate thread for non-blocking GUI.
        threading.Thread.__init__(self)
        QtCore.QObject.__init__(self)
        fw_modules.module_template.TemplateClass.__init__(self, engine=engine_reference, param_dict=parameter_dictionary, logger=template_logger)
        # Helper values.
        self.gui_reference = None
        self.gui_lock = threading.Lock()
        self.raised_alarms_count = 0
        self.triggered_alarms_count = 0
        self.still_raised = False
        self.raise_changed = False
        self.alarm_status_dict = {}
        
    def run(self):
        app = QtGui.QApplication(sys.argv, True)
        gui_reference = TemplateGuiInterfaceClass(self)
        gui_reference.show()
        self.gui_reference = gui_reference
        app.exec_()
        self.template_logger.info("Exiting GUI")
        self.template_shutdown()
        
    def set_trigger_count(self, new_count):
        """set_trigger_count()
        
        Setter for triggered_alarms_count attribute.
        Called from GUI on clear button activation to reset state.
        Lock avoids updating the count if it is increased through input
        at the same time.
        
        """
        
        self.template_logger.debug("Setting trigger alarm count to new value " + str(new_count))
        self.gui_lock.acquire()
        self.triggered_alarms_count = new_count
        self.gui_lock.release()
        
    def template_input(self, input):
        """input()
        
        Input interface.
        Relays information to gui and calculates alarm counters.
        
        """
        
        self.template_logger.debug("Raw input received:" + str(input))
        try:
            if input['MSGTYPE'] == 'ALARM':
                self.template_logger.debug("Received ALARM message")
                self.emit(QtCore.SIGNAL("newAlarmInput"), ' '.join([input['MSGID']+':', input['MSGSUBTYPE'], 'ALARM:', input['MSGDESCR'], ', Severity:', input['MSGSEV']]))
                try:
                    if input['MSGSUBTYPE'] == 'TRIGGER':
                        self.template_logger.debug("Received ALARM message of subtype 'TRIGGER'")
                        self.gui_lock.acquire()
                        self.triggered_alarms_count = self.triggered_alarms_count + 1
                        self.gui_lock.release()
                        self.emit(QtCore.SIGNAL("newTriggerCount"), self.triggered_alarms_count)
                        self.template_logger.debug("Update triggered alarms count to " + str(self.triggered_alarms_count))
                    elif input['MSGSUBTYPE'] == 'RAISE':
                        self.template_logger.debug("Received ALARM message of subtype 'RAISE'")
                        self.raised_alarms_count = self.raised_alarms_count + 1
                        self.raise_changed = True
                        self.template_logger.debug("Increasing raised alarms count to " + str(self.raised_alarms_count))
                    elif input['MSGSUBTYPE'] == 'CLEAR':
                        self.template_logger.debug("Received ALARM message of subtype 'CLEAR'")
                        if self.raised_alarms_count > 0:
                            self.raised_alarms_count = self.raised_alarms_count - 1
                            self.raise_changed = True
                            self.template_logger.debug("Dereasing raised alarms count to " + str(self.raised_alarms_count))
                except KeyError as err:
                    self.template_logger.warning("Input invalid; details: " + err.__str__())
            elif input['MSGTYPE'] == 'PREVENTION':
                self.template_logger.debug("Received PREVENTION message")
                self.emit(QtCore.SIGNAL("newPreventionMsgInput"), ' '.join([input['MSGID']+':', input['MSGSUBTYPE'], 'Description:', input['MSGDESCR'], ', Severity:', input['MSGSEV']]))
            elif input['MSGTYPE'] == 'COMMAND':
                self.template_logger.debug("Received COMMAND message")
                if input['MSGSUBTYPE'] == 'FLOOD':
                    self.template_logger.debug("Received COMMAND message of subtype 'FLOOD'")
                    self.emit(QtCore.SIGNAL("newPreventionCmdInput"), ' '.join([input['MSGID']+':', input['MSGSUBTYPE'], 'Description:' + input['MSGDESCR'], 'Data:' + input['MSGDATA']]))
                    self.emit(QtCore.SIGNAL("newPreventionStatus"), 'Active session containment flood!!!', 'red')
                elif input['MSGSUBTYPE'] == 'STOPFLOOD':
                    self.template_logger.debug("Received COMMAND message of subtype 'STOPFLOOD'")
                    self.emit(QtCore.SIGNAL("newPreventionCmdInput"), ' '.join([input['MSGID']+':', input['MSGSUBTYPE'], 'Description:' + input['MSGDESCR']]))
            elif input['MSGTYPE'] == 'EVENT':
                self.template_logger.debug("Received EVENT message")
                if input['MSGSUBTYPE'] == 'FLOODTIMEOUT':
                    self.template_logger.debug("Received EVENT message of subtype 'FLOODTIMEOUT'")
                    self.emit(QtCore.SIGNAL("newPreventionCmdInput"), ' '.join([input['MSGID']+':', input['MSGSUBTYPE'], 'Description:' + input['MSGDESCR']]))
                    self.emit(QtCore.SIGNAL("newPreventionStatus"), 'No active prevention actions', 'green')
        except KeyError as err:
            self.template_logger.warning("Input invalid; details: " + err.__str__())
        else:
            if self.raised_alarms_count > 0 and not self.still_raised:
                self.emit(QtCore.SIGNAL("newAlarmStatus"), 'Active alarms!!!', 'red')
                self.still_raised = True
            elif self.raised_alarms_count <= 0 and self.still_raised:
                self.emit(QtCore.SIGNAL("newAlarmStatus"), 'No active alarms', 'green')
                self.still_raised = False
            if self.raised_alarms_count >= 0 and self.raise_changed:
                self.emit(QtCore.SIGNAL("newRaiseCount"), self.raised_alarms_count)
                self.raise_changed = False
        
    def template_shutdown(self):
        """template_shutdown()
        
        Removes reference to template from engine module.
        
        """
        
        self.engine_reference.remove_template(self.template_identifier)
        
        
    def template_setup(self):
        """template_setup()
        
        Starts GUI in separate thread.
        
        """
        
        self.template_logger.info("Setting up template...")
        counter = 0
        self.start()
        return True

class TemplateGuiInterfaceClass(QtGui.QTabWidget):
    """Class description
    
    Represents the GUI. Is set up by the template which implements the
    'business logic'.
    
    """
    
    def __init__(self, template_reference, parent=None):
        QtGui.QTabWidget.__init__(self, parent)
        self.gui = fw_modules.fw_output_templates.ui_template_gui_v2.Ui_mainWindow()
        self.gui.setupUi(self)
        self.template_reference = template_reference
        # Connect slots.
        self.connect(self.gui.buttonQuit, QtCore.SIGNAL('clicked()'), self.on_quit)
        self.connect(self.gui.buttonQuit2, QtCore.SIGNAL('clicked()'), self.on_quit)
        self.connect(self.gui.buttonClear, QtCore.SIGNAL('clicked()'), self.on_clear_alarm)
        self.connect(self.gui.buttonClearPrev, QtCore.SIGNAL('clicked()'), self.on_clear_prevention)
        self.connect(self.template_reference, QtCore.SIGNAL('newAlarmInput'), self.update_alarms)
        self.connect(self.template_reference, QtCore.SIGNAL('newTriggerCount'), self.update_trigger_count)
        self.connect(self.template_reference, QtCore.SIGNAL('newRaiseCount'), self.update_raise_count)
        self.connect(self.template_reference, QtCore.SIGNAL('newAlarmStatus'), self.update_alarm_status)
        self.connect(self.template_reference, QtCore.SIGNAL('newPreventionMsgInput'), self.update_prevention_messages)
        self.connect(self.template_reference, QtCore.SIGNAL('newPreventionCmdInput'), self.update_prevention_commands)
        self.connect(self.template_reference, QtCore.SIGNAL('newPreventionStatus'), self.update_prevention_status)
        # Inital setup.
        self.update_alarm_status('No active alarms', 'green')
        self.update_prevention_status('No active prevention actions', 'green')
        
    def on_clear_alarm(self):
        """on_clear_alarm()
        
        Executed when alarm clear button is clicked.
        Resets alarm statistics and status and clears alarm view.
        
        """
        
        self.template_reference.set_trigger_count(0)
        self.gui.showAlarms.clear()
        self.gui.labelShowRaiseAlarms.setText('0')
        self.gui.labelShowTriggAlarms.setText('0')
        self.update_alarm_status('No active alarms', 'green')
        
    def on_clear_prevention(self):
        """on_clear_prevention()
        
        Executed when prevention clear button is clicked.
        Resets prevention status and clears both prevention views.
        
        """
        
        self.gui.showPreventionCmd.clear()
        self.gui.showPreventionMsg.clear()
        self.update_prevention_status('No active prevention actions', 'green')
        
    def on_quit(self):
        """on_quit()
        
        Executed when quit button is clicked.
        
        """
        
        self.close()
        
    def update_alarms(self, input):
        """update_alarms()
        
        Prints new alarm info to gui textedit.
        
        """
        
        self.gui.showAlarms.append(input)
        
    def update_alarm_status(self, status, color):
        """update_alarm_status()
        
        Updates alarm status text and its color.
        
        """
        
        self.gui.labelShowStatus.setText("<font color='" + color + "'>" + status + "</font>")

    def update_prevention_commands(self, input):
        """update_prevention_commands()
        
        Prints new prevention command info to gui textedit.
        
        """
        
        self.gui.showPreventionCmd.append(input)
       
    def update_prevention_messages(self, input):
        """update_prevention_messages()
        
        Prints new prevention info to gui textedit.
        
        """
        
        self.gui.showPreventionMsg.append(input)
        
    def update_prevention_status(self, status, color):
        """update_prevention_status()
        
        Updates prevention status text and its color.
        
        """
        
        self.gui.labelShowPrevStatus.setText("<font color='" + color + "'>" + status + "</font>")
        
        
    def update_raise_count(self, new_count):
        """update_raise_count()
        
        Updates counter for raise/clear alarms.
        
        """
        
        self.gui.labelShowRaiseAlarms.setText(str(new_count))
        
    def update_trigger_count(self, new_count):
        """update_trigger_count()
        
        Updates counter for triggered alarms.
        
        """
        
        self.gui.labelShowTriggAlarms.setText(str(new_count))
        
        
def main(engine_reference, parameter_dictionary, template_logger):
    gui_template_class = TemplateGuiClass(engine_reference, parameter_dictionary, template_logger)
    return gui_template_class
        
if __name__ == "__main__":
    print "Warning: This template is not intended to be executed directly. Only do this for test purposes."