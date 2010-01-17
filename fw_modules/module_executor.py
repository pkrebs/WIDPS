#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# module_executor.py - WIDS/WIPS framework executor module
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

"""Executor module

Receives prevention commands from the prevention engine
and forges and sends frames accordingly over the WLAN interface.

"""

# Imports
#
# Custom modules
try:
    import fw_modules.module_template
    from fw_modules.module_exceptions import *
except ImportError:
    raise

# Standard modules
from socket import error as SocketError
import threading
import time

# Third-party modules
try:
    import scapy.all
except ImportError:
    raise FwModuleSetupError, "Couldn't import required module 'scapy.all'"


class ExecutorClass(fw_modules.module_template.ModuleClass):
    """ExecutorClass
    
    Provides a facility for crafting and sending WLAN frames.
    Accepts commands from other modules.
    
    """
    
    def __init__(self, controller_reference, parameter_dictionary, module_logger):
        """Constructor
        
        """
        
        fw_modules.module_template.ModuleClass.__init__(self, controller=controller_reference, param_dict=parameter_dictionary, logger=module_logger)
        # Default values.
        try:
            self.sending_interface = self.param_dict['sending_interface']
        except KeyError:
            raise FwModuleSetupError, self.module_identifier + ": ERROR: No sending interface specified"
        # Helper values.
        self.active_flood = False
        self.stop_flood = False
        self.flood_thread = None
        self.flood_thread_timeout = 5
        
        self.scapy_type_dict = {'MANAGEMENT':'Management', 
                                'DATA':'Data', 
                                'CONTROL':'Control', 
                                'RESERVED':'Reserved'}


    def after_run(self):
        """after_run()
        
        Stops running flood thread for clean exit.
        
        """
        
        if self.active_flood and self.flood_thread:
            if not self.stop_flooding():
                return False
        return True

    def before_run(self):
        """before_run()
        
        Sets up sending interface.
        
        """
        
        self.module_logger.info("Setting sending interface to " + str(self.sending_interface))
        scapy.all.conf.iface = self.sending_interface
        return True
    
    def craft_frame(self, frame_data, mode, count=None, sleeptime=None, duration=None):
        """craft_frame()
        
        Assembles a frame in scapy syntax based on the received request.
        
        """
        
        # Craft basic wlan frame.
        frame_base = scapy.all.Dot11()
        try:
            try:
                frame_base.type = frame_data['FTYPE']
            except KeyError:
                pass
            try:
                frame_base.proto = frame_data['PROTV'] # bit value
            except KeyError:
                pass
            # FCfield
            try:
                frame_base.addr1 = ':'.join(frame_data['ADDR1'][c:c+2] for c in range(0, 12, 2)).upper()
            except KeyError:
                pass
            try:
                frame_base.addr2 = ':'.join(frame_data['ADDR2'][c:c+2] for c in range(0, 12, 2)).upper()
            except KeyError:
                pass
            try:
                frame_base.addr3 = ':'.join(frame_data['ADDR3'][c:c+2] for c in range(0, 12, 2)).upper()
            except KeyError:
                pass
            try:
                frame_base.addr4 = ':'.join(frame_data['ADDR4'][c:c+2] for c in range(0, 12, 2)).upper()
            except KeyError:
                pass
        except ValueError as err:
            self.module_logger.warning("Encountered invalid frame value; details: " + err.__str__())
        else:
            try:
                if frame_data['FTYPE'] == 'MANAGEMENT':
                    frame_ext = None
                    if frame_data['FSUBTYPE'] == 'ASSOCIATIONREQUEST':
                        frame_base = frame_base/scapy.all.Dot11AssoReq()
                        try:
                           frame_base = frame_base/scapy.all.Dot11Elt(info=frame_data['ESSID'])
                        except KeyError:
                            pass
                    elif frame_data['FSUBTYPE'] == 'ASSOCIATIONRESPONSE':
                        frame_base = frame_base/scapy.all.Dot11AssoResp()
                    elif frame_data['FSUBTYPE'] == 'REASSOCIATIONREQUEST':
                        frame_base = frame_base/scapy.all.Dot11ReassoReq()
                        try:
                           frame_base = frame_base/Dot11Elt(info=frame_data['ESSID'])
                        except KeyError:
                            pass
                    elif frame_data['FSUBTYPE'] == 'REASSOCIATIONRESPONSE':
                        frame_base = frame_base/scapy.all.Dot11ReassoResp()
                    elif frame_data['FSUBTYPE'] == 'PROBEREQUEST':
                        frame_base = frame_base/scapy.all.Dot11ProbeReq()
                        try:
                           frame_base = frame_base/scapy.all.Dot11Elt(info=frame_data['ESSID'])
                        except KeyError:
                            pass
                    elif frame_data['FSUBTYPE'] == 'PROBERESPONSE':
                        frame_base = frame_base/scapy.all.Dot11ProbeResp()
                        try:
                           frame_base = frame_base/scapy.all.Dot11Elt(info=frame_data['ESSID'])
                        except KeyError:
                            pass
                    elif frame_data['FSUBTYPE'] == 'BEACON':
                        frame_base = frame_base/scapy.all.Dot11Beacon()
                        try:
                           frame_base = frame_base/scapy.all.Dot11Elt(info=frame_data['ESSID'])
                        except KeyError:
                            pass
                    elif frame_data['FSUBTYPE'] == 'ATIM':
                        frame_base = frame_base/scapy.all.Dot11ATIM()
                    elif frame_data['FSUBTYPE'] == 'DISASSOCIATION':
                        frame_base = frame_base/scapy.all.Dot11Disas()
                    elif frame_data['FSUBTYPE'] == 'AUTHENTICATION':
                        frame_base = frame_base/scapy.all.Dot11Auth()
                    elif frame_data['FSUBTYPE'] == 'DEAUTHENTICATION':
                        frame_base = frame_base/scapy.all.Dot11Deauth()
            except KeyError:
                pass
            if mode == 'CRAFT':
                # Send out single frame.
                self.module_logger.info("Sending out frame, " + str(count) + " times")
                self.module_logger.debug("Frame: " + str(frame_base.show()))
                try:
                    for n in xrange(count):
                        scapy.all.sendp(frame_base)
                except SocketError as err:
                    self.module_logger.error("Sending of forged frame failed; details: " + err.__str__())
            elif mode == 'FLOOD':
                # Start flooding in separate thread.
                if self.active_flood and self.flood_thread:
                    self.module_logger.info("Stopping active flooding thread")
                    if not self.stop_flooding():
                        self.module_logger.error("Flooding thread not stopped, won't accept further flood requests")
                        return False
                if not self.active_flood:
                    self.module_logger.info("Starting frame flood with sleeptime " + str(sleeptime))
                    self.stop_flood = False
                    self.flood_thread = threading.Thread(target=self.flood_frames, args=(frame_base, sleeptime, duration))          # start flooding in separate thread
                    self.flood_thread.start()
                    self.active_flood = True
            
    def flood_frames(self, frame, sleeptime, duration):
        """flood_frames()
        
        Sends out a frame continuously.
        Is executed in a separate thread to allow
        concurrent crafting of single frames.
        
        """
        
        if duration != 0:
            expire_time = int(time.time()) + duration
            try:    
                while not self.stop_flood:
                    scapy.all.sendp(frame)
                    time.sleep(sleeptime)
                    if time.time() >= expire_time:
                        self.module_logger.info("Flood timeout reached, stopping flooding thread")
                        self.stop_flood = True
            except SocketError as err:
                self.module_logger.error("Sending of forged frame failed; details: " + err.__str__())
        else:
            try:
                while not self.stop_flood:
                    scapy.all.sendp(frame)
                    time.sleep(sleeptime)
            except SocketError as err:
                self.module_logger.error("Sending of forged frame failed; details: " + err.__str__())
        self.module_logger.info("Exiting flooding loop")
        self.active_flood = False
        self.generate_message('EVENT', self.module_identifier, 'Flood timed out', '', 0, 'FLOODTIMEOUT', '', '')
        return True

    def process(self, input):
        """process()
        
        Receives commands, crafts frame and sends them out.
        
        """
        
        self.module_logger.debug("Raw input: " + str(input))
        cmd_dict = {}
        cmd_data_dict = {}  
        try:
            cmd_dict = dict(item.split('_', 1) for item in input.split('|'))
            if cmd_dict['MSGTYPE'] == 'COMMAND':
                try:
                   cmd_data_dict = dict(item.split('_', 1) for item in cmd_dict['MSGDATA'].split(','))
                except KeyError:
                    pass
            else:
                return True                         # executor is only interested in commands
        except ValueError as err:
                self.module_logger.warning("Message information not valid; details: " + err.__str__())
        else:
            print cmd_dict
            print cmd_data_dict
            try:
                if cmd_dict['MSGSUBTYPE'] == 'CRAFT':
                    try:
                        framedata_dict = dict(item.split('_', 1) for item in cmd_dict['FRAMEDATA'].split(','))
                        print framedata_dict
                    except KeyError:
                        self.module_logger.warning("Command does not include necessary frame data")
                    else:
                        try:
                            count = int(cmd_data_dict['FRAMECOUNT'])
                        except ValueError:
                            self.module_logger.warning("Frame count is not an integer: " + str(cmd_data_dict['FRAMECOUNT']))
                        except KeyError:
                            count = 1 
                        self.module_logger.info("Received single frame craft request, count : " + str(count))
                        self.craft_frame(framedata_dict, 'CRAFT', count=count)
                elif cmd_dict['MSGSUBTYPE'] == 'FLOOD':
                    try:
                        framedata_dict = dict(item.split('_', 1) for item in cmd_dict['FRAMEDATA'].split(','))
                    except KeyError:
                        self.module_logger.warning("Command does not include necessary frame data")
                    else:
                        try:
                            sleeptime = float(cmd_data_dict['SLEEPTIME'])
                        except KeyError:
                            sleeptime = 0.5
                        try:
                            duration = int(cmd_data_dict['DURATION'])
                        except KeyError:
                            duration = 0
                        self.module_logger.info("Received frame flooding request with sleeptime: " + str(sleeptime) +  " and duration " + str(duration))
                        self.craft_frame(framedata_dict, 'FLOOD', sleeptime=sleeptime, duration=duration)
                elif cmd_dict['MSGSUBTYPE'] == 'STOPFLOOD':
                    self.module_logger.info("Received frame flood stop request")
                    self.stop_flooding()
            except KeyError as err:
                self.module_logger.warning("Command invalid, details: " + err.__str__())
                
    def stop_flooding(self):
        """stop_flooding()
        
        Stops the flooding thread.
        
        """
        
        if self.active_flood and self.flood_thread:
            self.module_logger.info("Stopping flooding thread")
            self.stop_flood = True
            self.flood_thread.join(self.flood_thread_timeout)           # wait until thread finishes
            if self.flood_thread.is_alive():
                self.module_logger.error("Couldn't stop flooding thread")
                self.active_flood = True
                return False
            else:
                self.module_logger.info("Flooding thread stopped")
                self.active_flood = False
                return True
        else:
            self.module_logger.info("No active flooding thread to stop")
        
def main(controller_reference, parameter_dictionary, module_logger):
    executor_class = ExecutorClass(controller_reference, parameter_dictionary, module_logger)
    return executor_class
        
if __name__ == "__main__":
    print "Warning: This module is not intended to be executed directly. Only do this for test purposes."