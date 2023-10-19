#!/usr/bin/python

##########################################################################
# Copyright (C) 2021 Carmine Scarpitta - (University of Rome "Tor Vergata")
# www.uniroma2.it/netgroup
#
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Exceptions used by STAMP library
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""
Exceptions used by STAMP library.
"""


class InvalidSTAMPPacketError(Exception):
    """
    Exception raised for errors in the STAMP packet.

    Attributes
    ----------
        packet : scapy.packet.Packet
            STAMP packet which caused the error.
        message : str
            Explanation of the error.
    """

    def __init__(self, packet, message='STAMP packet is invalid'):
        """
        Constructs all the necessary attributes for the Invalid STAMP Packet
         Error.

        Parameters
        ----------
            packet : scapy.packet.Packet
                STAMP packet which caused the error.
        """

        self.packet = packet
        self.message = message
        super().__init__(self.message)
