#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# module_capture_pcapy.py - WIDS/WIPS framework frame capture module using pcapy
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

"""Capture module

Captures WLAN frames from WNIC and decodes them.

"""

# Imports
#
# Custom modules
from fw_modules.module_exceptions import *
import fw_modules.module_template

# Standard modules
import os, os.path
import threading

# Third-party modules
try:
    import pcapy
except ImportError:
    raise FwModuleSetupError, "Couldn't import required module 'pcapy'"


class CaptureClass(fw_modules.module_template.ModuleClass):
    """CaptureClass
    
    Captures frames via libpcap from a live interface or pcap file and decodes them.
    
    """
    
    def __init__(self, controller_reference, parameter_dictionary, module_logger):
        """Constructor
        
        Constructor description.
        
        """
        
        fw_modules.module_template.ModuleClass.__init__(self, controller=controller_reference, param_dict=parameter_dictionary, logger=module_logger)
        # Default values from parameter dictionary.
        try:
            self.capture_mode = int(self.param_dict['capture_mode'])
        except KeyError:
            self.module_logger.error("Capture mode not specified!")
            raise FwModuleSetupError, self.module_identifier + ": ERROR: Capture mode not specified!"
        except ValueError:
            self.module_logger.error("Capture mode invalid!")
            raise FwModuleSetupError, self.module_identifier + ": ERROR: Capture mode invalid!"
        try:
            self.capture_source = self.param_dict['capture_source']
        except KeyError:
            self.module_logger.error("Capture source not specified!")
            raise FwModuleSetupError, self.module_identifier + ": ERROR: Capture source not specified!"
        try:
            self.capture_signature = self.param_dict['capture_signature']           # signature for frame data messages
        except KeyError:
            self.module_logger.error("No capture signature specified!")
            raise FwModuleSetupError, self.module_identifier + ": ERROR: No capture signature specified!"
        try:
            self.header_type = self.param_dict['header_type']
        except KeyError:
            self.module_logger.warning("Header type not specified, assuming that RTAP header is present")
            print self.module_identifier,": WARNING: Header type not specified, assuming that RTAP header is present"
            self.header_type = 1
        # Helper variables.
        self.capture_thread = None
        self.frame_counter = 1
        self.join_timeout = 5
        # Lookup table for hex bit conversion.
        self.hex_to_bits = {'0':'0000',         # LSB first!!!
                              '1':'1000',
                              '2':'0100',
                              '3':'1100',
                              '4':'0010',
                              '5':'1010',
                              '6':'0110',
                              '7':'1110',
                              '8':'0001',
                              '9':'1001',
                              'A':'0101',
                              'B':'1101',
                              'C':'0011',
                              'D':'1011',
                              'E':'0111',
                              'F':'1111',
                              'a':'0101',
                              'b':'1101',
                              'c':'0011',
                              'd':'1011',
                              'e':'0111',
                              'f':'1111'
                              }
        # Lookup table for frame types and subtypes
        self.frametype_lookup = {'00':{'type':'MANAGEMENT',          # LSB first!!!
                                         '0000':'ASSOCIATIONREQUEST',
                                         '1000':'ASSOCIATIONRESPONSE',
                                         '0100':'REASSOCIATIONREQUEST',
                                         '1100':'REASSOCIATIONRESPONSE',
                                         '0010':'PROBEREQUEST',
                                         '1010':'PROBERESPONSE',
                                         '0110':'RESERVED',
                                         '1110':'RESERVED',
                                         '0001':'BEACON',
                                         '1001':'ATIM',
                                         '0101':'DISASSOCIATION',
                                         '1101':'AUTHENTICATION',
                                         '0011':'DEAUTHENTICATION',
                                         '1011':'ACTION',
                                         '0111':'RESERVED',
                                         '1111':'RESERVED'
                                         },
                                    '10':{'type':'CONTROL',
                                          '0000':'RESERVED',
                                          '1000':'RESERVED',
                                          '0100':'RESERVED',
                                          '1100':'RESERVED',
                                          '0010':'RESERVED',
                                          '1010':'RESERVED',
                                          '0110':'RESERVED',
                                          '1110':'RESERVED',
                                          '0001':'BLOCKACKREQUEST',
                                          '1001':'BLOCKACK',
                                          '0101':'PSPOLL',
                                          '1101':'RTS',
                                          '0011':'CTS',
                                          '1011':'ACK',
                                          '0111':'CFEND',
                                          '1111':'CFEND+CFACK'
                                          },
                                    '01':{'type':'DATA',
                                          },
                                    '11':{'type':'RESERVED',
                                          }
                                    }
    def after_run(self):
        """after_run()
        
        Waits for an active capture thread to terminate.
        
        """
        
        if self.capture_thread:
            self.capture_thread.join(self.join_timeout)
        if self.capture_thread.isAlive():
            self.module_logger.error("Couldn't terminate capture thread")
            return False
        return True
        
    def before_run(self):
        """before_run()
        
        Check file presence if offline capture is requested.
	Start capture in a separate thread, either from file or interface.
        
        """
        
        if self.capture_mode == 1:
            if not os.path.isfile(os.path.abspath(self.capture_source)):
                self.module_logger.error("Couldn't find capture file " + self.capture_source)
                return False 
        if self.capture_mode == 0:
            self.capture_thread = threading.Thread(target=self.capture_frames_from_live, args=(self.capture_source,))
            self.capture_thread.start()
        elif self.capture_mode == 1:
            self.capture_thread = threading.Thread(target=self.capture_frames_from_file, args=(self.capture_source,))
            self.capture_thread.start()
        return True
    
    def capture_frames_from_cisco(self, filename):
        """Function name
        
        Opens a pcap session and captures frames from a pcap dumpfile
	supported from a Cisco WLC.
	Not yet implemented.
        
        """
          
    def capture_frames_from_file(self, filename):
        """capture_frames_from_file()
        
        Opens a pcap session and captures frames from a pcap dumpfile.
        
        """
        
        self.module_logger.info("Opening file capture session for file " + filename)
        # Capture offline from pcap file.
        capture_descriptor = pcapy.open_offline(filename)
        # Next is needed for thread control because loop can't be aborted via condition and function has to return.
        (header, data) = capture_descriptor.next()
        while not self.stop_thread and header:
            self.decode_WLAN_frame(header, data)
            try:
                (header, data) = capture_descriptor.next()          # throws exception at file end!?
            except pcapy.PcapError:         # disable exception temporarily
                return True
        self.module_logger.info("No more frames to parse from file " + filename)
        return True
        
    def capture_frames_from_live(self, interface):
        """capture_frames_from_live()
        
        Open a pcap live session and capture frames from an interface.
        
        """
        
        self.module_logger.info("Opening live capture session on interface " + interface)
        # Set max length for frames to not truncate them and set no read timeout.
        capture_descriptor = pcapy.open_live(interface, 65535, 0, 0)
        # Next is needed for thread control because loop can't be aborted via condition, and function has to return.
        while not self.stop_thread:
            (header, data) = capture_descriptor.next()
            if header and data:
                self.decode_WLAN_frame(header, data)
            else:
                break
            
    def decode_hex_to_bits(self, hexbyte):
        """decode_hex_to_bits()
        
        Decodes a pair of hex numbers to a binary byte representation.
        Byte is in little-endian form (LSB leftmost).
        No longer needed, is done inline in decode_WLAN_frame().
        
        """
        return self.hex_to_bits[hexbyte[1]] + self.hex_to_bits[hexbyte[0]]
    
    def decode_WLAN_frame(self, header, data):
        """decode_WLAN_frame()
        
        Dissects a WLAN frame in its contents considering different frame types.
        Works like a state machine with the states corresponding to remaining frame data.
        
        """
        
        no_fcs = False
        frame_type = ''
        frame_subtype = ''
        self.frame_counter = self.frame_counter + 1         # increasing counter for identifying frame messages
        decoded_frame_data = ['COUNTER_', str(self.frame_counter), '|CAPSIG_', self.capture_signature]          # holds decoded data as list, will be joinet to string at end (faster than string concatenation)
        
        self.module_logger.debug("="*40)
        self.module_logger.debug('%s: captured %d bytes, truncated to %d bytes' %(header.getts(), header.getlen(), header.getcaplen()))
        data = data.encode("hex")
        self.module_logger.debug("Data(Hex): " + data)
        (tstamp_second, tstamp_msecond) = header.getts()
        self.module_logger.debug("Timestamp: " + str(tstamp_second) + ' ' + str(tstamp_msecond))
        decoded_frame_data.extend(['|TSSEC_', str(tstamp_second), '|TSUSEC_', str(tstamp_msecond)])
        try:
            if self.header_type == 0:
                no_fcs = True
            elif self.header_type == 1:         # rtap header
                rtap_length = int(data[6:8] + data[4:6], 16) * 2            # convert hex to decimal to get lenght of rtap header
                self.module_logger.debug("Radiotap-Header: " + data[0:rtap_length])
                decoded_frame_data.extend(['|AUXHEADER_', data[0:rtap_length]])
                data = data[rtap_length:]
            elif self.header_type == 2:         # prism header
                self.module_logger.debug("Prism-Header: " + data[0:288])
                decoded_frame_data.extend(['|AUXHEADER_', data[0:288]])
                data = data[288:]
                no_fcs = True
            
            self.module_logger.debug("Frame-Control-Feld: " + data[0:4])
            fc_field = self.hex_to_bits[data[1:2]] + self.hex_to_bits[data[0:1]] + self.hex_to_bits[data[3:4]] + self.hex_to_bits[data[2:3]]
            self.module_logger.debug("FC-Field in bin(LSB first): " + fc_field)
            self.module_logger.debug("Protocol Version: " + fc_field[0:2])
            decoded_frame_data.extend(['|PROTV_', fc_field[0:2]])
            try:
				# look up frame type
                frame_type = self.frametype_lookup[fc_field[2:4]]['type']
                self.module_logger.debug("Frame Type: " + frame_type)
                decoded_frame_data.extend(['|FTYPE_', frame_type])
            except KeyError:
                self.module_logger.warning("Couldn't resolve frame type: " + fc_field[2:4])
                return False
            if frame_type != 'DATA' and frame_type != 'RESERVED':
                try:
					# look up frame subtype
                    frame_subtype = self.frametype_lookup[fc_field[2:4]][fc_field[4:8]]
                    self.module_logger.debug("Frame Subtype: " + frame_subtype)
                    decoded_frame_data.extend(['|FSUBTYPE_', frame_subtype])
                except KeyError:
                    self.module_logger.warning("Couldn't resolve subtype: " + fc_field[4:8])
                    return False
            
            decoded_frame_data.extend(['|TODS_', fc_field[8], '|FROMDS_' + fc_field[9], '|MOREFRAG_', fc_field[10], '|RETRY_', fc_field[11], '|PWRMAN_', fc_field[12], '|MOREDATA_', fc_field[13], '|PROTFRAME_', fc_field[14], '|ORDER_', fc_field[15]])
            self.module_logger.debug("Duration/ID-Feld: " + data[4:8])
            decoded_frame_data.extend(['|DURID_', data[4:8]])
            self.module_logger.debug("Address 1: " + data[8:20])
            decoded_frame_data.extend(['|ADDR1_', data[8:20]])
            # CTS and ACK frame endcheck.
            if frame_subtype == 'CTS' or frame_subtype == 'ACK':
                if len(data[20:]) == 8:
                    self.module_logger.debug("FCS: " + data[-8:])
                    decoded_frame_data.extend(['|FCS_', data[-8:]])
                    self.output(''.join(decoded_frame_data).upper())
                    return True
                elif no_fcs:
                    self.output(''.join(decoded_frame_data).upper())
                    return True
                else:
                    self.module_logger.warning("CTS or ACK Frame is too short!")
                    return False
            self.module_logger.debug("Address 2: " + data[20:32])
            decoded_frame_data.extend(['|ADDR2_', data[20:32]])
            # RTS, PS Poll, CF end and CF and+CF ack frame endcheck.
            if frame_subtype == 'RTS' or frame_subtype == 'PSPOLL' or frame_subtype == 'CFEND' or frame_subtype == 'CFEND+CFACK':
                if len(data[32:]) == 8:
                    self.module_logger.debug("FCS: " + data[-8:])
                    decoded_frame_data.extend(['|FCS_', data[-8:]])
                    self.output(''.join(decoded_frame_data).upper())
                    return True
                elif no_fcs:
                    self.output(''.join(decoded_frame_data).upper())
                    return True
                else:
                    self.module_logger.warning("RTS or PS POLL or CF END or CF END+CF ACK Frame is too short!")
                    return False
            # Block ack and Block ack request frame endcheck
            if frame_subtype == 'BLOCKACKREQUEST':
                self.module_logger.debug("BAR-Control-Field: " + data[32:36])
                self.module_logger.debug("BA Starting Sequence: " + data[36:40])
                decoded_frame_data.extend(['|BARCONTR_', data[32:36], '|BASTART_', data[36:40]])
                if len(data[40:]) == 8:
                    self.module_logger.debug("FCS: " + data[-8:])
                    decoded_frame_data.extend(['|FCS_', data[-8:]])
                    self.output(''.join(decoded_frame_data).upper())
                    return True
                elif no_fcs:
                    self.output(''.join(decoded_frame_data).upper())
                    return True
                else:
                    self.module_logger.warning("BLOCK ACK REQUEST Frame is too short!")
                    return False            
            if frame_subtype == 'BLOCKACK':
                self.module_logger.debug("BA-Control-Field: " + data[32:36])
                self.module_logger.debug("BA Starting Sequence: " + data[36:40])
                self.module_logger.debug("BA-Bitmap: " + data[40:292])
                decoded_frame_data.extend(['|BACONTR_', data[84:88], '|BASTART_', data[36:40], '|BABITM_', data[40:292]])
                if len(data[292:]) == 8:
                    self.module_logger.debug("FCS: " + data[-8:])
                    decoded_frame_data.extend(['|FCS_', data[-8:]])
                    self.output(''.join(decoded_frame_data).upper())
                    return True
                elif no_fcs:
                    self.output(''.join(decoded_frame_data).upper())
                    return True
                else:
                    self.module_logger.warning("BLOCK ACK Frame is too short!")
                    return False  
            self.module_logger.debug("Address 3: " + data[32:44])
            decoded_frame_data.extend(['|ADDR3_', data[32:44]])
            self.module_logger.debug("Sequence-Control-Feld: " + data[44:48])
            self.module_logger.debug("Fragment number: " + data[44])
            self.module_logger.debug("Sequence number: " + data[45:48])
            decoded_frame_data.extend(['|FRAGNR_', data[44], '|SEQNR_', data[45:48]])
            if frame_type == 'DATA':
                if fc_field[8] == 1 and fc_field[9] == 1:                   # check for presence of 4th address
                    self.module_logger.debug("Address 4: " + data[48:60])
                    decoded_frame_data.extend(['|ADDR4_', data[48:60]])
                    if fc_field[7] == 1:
                        self.module_logger.debug("QoS-Control Field: " + data[60:64])
                        if not no_fcs:
                            self.module_logger.debug("Frame Body: " + data[64:-8])
                            decoded_frame_data.extend(['|QOSCONTR_', data[60:64], '|FBODY_', data[64:-8]])
                        else:
                            self.module_logger.debug("Frame Body: " + data[64:])
                            decoded_frame_data.extend(['|QOSCONTR_', data[60:64], '|FBODY_', data[64:]])
                            self.output(''.join(decoded_frame_data).upper())
                            return True
                    else:
                        if not no_fcs:
                            self.module_logger.debug("Frame Body: " + data[64:-8])
                            decoded_frame_data.extend(['|FBODY_', data[64:-8]])
                        else:
                            self.module_logger.debug("Frame Body: " + data[64:])
                            decoded_frame_data.extend(['|FBODY_', data[64:]])
                            self.output(''.join(decoded_frame_data).upper())
                            return True
                else:
                    if fc_field[7] == 1:
                        self.module_logger.debug("QoS-Control Field: " + data[48:52])
                        if not no_fcs:
                            self.module_logger.debug("Frame Body: " + data[52:-8])
                            decoded_frame_data.extend(['|QOSCONTR_', data[48:52], '|FBODY_', data[52:-8]])
                        else:
                            self.module_logger.debug("Frame Body: " + data[52:])
                            decoded_frame_data.extend(['|QOSCONTR_', data[48:52], '|FBODY_', data[52:-8]])
                            self.output(''.join(decoded_frame_data).upper())
                            return True
                    else:
                        if not no_fcs:
                            self.module_logger.debug("Frame Body: " + data[48:-8])
                            decoded_frame_data.extend(['|FBODY_', data[48:-8]])
                        else:
                            self.module_logger.debug("Frame Body: " + data[48:])
                            decoded_frame_data.extend(['|FBODY_', data[48:]])
                            self.output(''.join(decoded_frame_data).upper())
                            return True
            elif frame_type == 'MANAGEMENT':
                if not no_fcs:
                    self.module_logger.debug("Frame Body: " + data[48:-8])
                    decoded_frame_data.extend(['|FBODY_', data[48:-8]])
                else:
                    self.module_logger.debug("Frame Body: " + data[48:])
                    decoded_frame_data.extend(['|FBODY_', data[48:]])
                    self.output(''.join(decoded_frame_data).upper())
                    return True
            self.module_logger.debug("FCS: " + data[-8:])
            decoded_frame_data.extend(['|FCS_', data[-8:]])
        except IndexError:
            self.module_logger.error("Couldn't decode frame: " + data + "; try changing header_type option in config file")
        else:     
            self.output(''.join(decoded_frame_data).upper())            # join decoded frame fields into a single string and convert to uppervase before sending to target modules

def main(controller_reference, parameter_dictionary, module_logger):
    capture_class = CaptureClass(controller_reference, parameter_dictionary, module_logger)
    return capture_class

        
if __name__ == "__main__":
    print "Warning: This module is not intended to be executed directly. Only do this for test purposes."