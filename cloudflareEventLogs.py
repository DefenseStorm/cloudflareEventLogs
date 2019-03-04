#!/usr/bin/env python

import sys,os,getopt
import traceback
import os
import time
from datetime import datetime
import calendar
import pickle
import json

sys.path.insert(0, 'python-cloudflare')
import CloudFlare

sys.path.insert(0, 'ds-integration')
from DefenseStorm import DefenseStorm

class integration(object):


    # I think I want to map Event Type to differnt types of logs: Logpull, Audit, etc
    # Name will be the Zone Name

    CEF_field_mappings = {
        'RayID' : None,
        #'SecurityLevel' : 'flexString1',
        'SecurityLevel' : None,
        'ZoneID' : None,
        'OriginIP' : 'dst',
        'CacheResponse' : None,
        'ClientASN' : None,
        'ClientCountry' : None,
        'ClientDeviceType' : None,
        'ClientIP' : 'src',
        'ClientSSLProtocol' : 'proto',
        'ClientRequestBytes' : None,
        'ClientRequestHost' : 'dhost',
        'ClientRequestMethod' : None,
        'ClientRequestPath' : None,
        'ClientRequestReferer' : None,
        'ClientRequestURI' : 'cs5',
        'ClientRequestUserAgent' : 'cs6',
        'ClientRequestProtocol' : None,
        #'EdgeEndTimestamp' : 'end',
        'EdgeEndTimestamp' : None,
        'EdgePathingSrc' : None,
        'EdgePathingStatus' : None,
        'EdgeResponseBytes' : None,
        'EdgeResponseStatus' : None,
        #'EdgeStartTimestamp' : 'start',
        'EdgeStartTimestamp' : 'rt',
        'OriginResponseStatus' : 'cn3',
        'WAFAction' : 'cs1',
        'WAFFlags' : 'cn1',
        #'WAFMatchedVar' : 'cs2',
        'WAFMatchedVar' : None,
        'WAFProfile' : 'cs3',
        'WAFRuleID' : 'cs2',
        #'WAFRuleID' : None,
        'WAFRuleMessage' : 'cs4'
    }
    CEF_custom_field_list = ['cs1','cs2','cs3','cs4','cs5','cs6','cn1','cn2','cn3','flexDate1','flexString1','flexString2']

    CEF_custom_field_labels = {
        'cs1Label' : 'WAFAction',
        'cs2Label' : 'WAFRuleID',
        'cs3Label' : 'WAFProfile',
        'cs4Label' : 'WAFRuleMessage',
        'cs5Label' : 'ClientRequestURI',
        'cs6Label' : 'ClientRequestUserAgent',
        'cn1Label' : 'WAFFlags',
        'cn2Label' : 'WAFRuleID',
        'cn3Label' : 'OriginResponseStatus',
        'flexDate1Label' : None,
        'flexString1Label' : 'SecurityLevel',
        'flexString2Label' : None,
    }


    def get_zone_logs(self, zone, start_time, end_time):
        keylist = ""
        first = True
        for key in self.CEF_field_mappings.keys():
            if first:
                keylist += '%s' %key
                first = False
            else:
                keylist += ',%s' %key
        if keylist == "":
            logs = self.cf.zones.logs.received(zone['id'], params={'start':start_time, 'end':end_time})
        else:
            logs = self.cf.zones.logs.received(zone['id'], params={'start':start_time, 'end':end_time, 'fields':keylist})
        return logs

    def get_active_zones(self):
        zones = self.cf.zones.get()
        for zone in zones:
            if zone['status'] != 'active':
                zones.remove(zone)
        return zones

    def process_logs(self, zone, logs):
        #self.ds.writeCEFEvent()
        extension = {}
        for log in logs:
            for item in log.keys():
                if item in self.CEF_field_mappings.keys():
                    if self.CEF_field_mappings[item] != None:
                        if self.CEF_field_mappings[item] == 'rt':
                            extension[self.CEF_field_mappings[item]] = str(int(log[item]) / 1000)
                        else:
                            extension[self.CEF_field_mappings[item]] = str(log[item])
                        if self.CEF_field_mappings[item] in self.CEF_custom_field_list:
                            extension[self.CEF_field_mappings[item] + 'Label'] = self.CEF_custom_field_labels[self.CEF_field_mappings[item] + 'Label']
                        del log[item]
            First = True
            msg = ""
            for item in log.keys():
                if First:
                    msg += "%s\=%s" %(item, log[item])
                    First = False
                else:
                    msg += " %s\=%s" %(item, log[item])

            extension['msg'] = msg
            self.ds.writeCEFEvent(type='request', action=extension['cs1'], dataDict=extension)
        return

    def run(self):
        global time
        last_run = self.ds.get_state()
        start_time = None
        current_run = 60 * ((time.time() - 120) // 60)
        if last_run == None:
            end_time = datetime.utcfromtimestamp(current_run)
            start_time = datetime.utcfromtimestamp(current_run - int(self.ds.config_get('cloudflare', 'run_interval')))
        else:
            start_time = datetime.utcfromtimestamp(last_run)
            end_time = datetime.utcfromtimestamp(current_run)

        start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
 
        self.ds.log('INFO', 'Retrieving logs from ' + start_time_str + ' - ' + end_time_str)

        #self.cf = CloudFlare.CloudFlare(debug=True, email=self.ds.config_get('cloudflare', 'account-email'), token=self.ds.config_get('cloudflare', 'api-key'))
        self.cf = CloudFlare.CloudFlare(email=self.ds.config_get('cloudflare', 'account-email'), token=self.ds.config_get('cloudflare', 'api-key'))

        zones = self.get_active_zones()
        self.ds.store_state(current_run)
        for zone in zones:
            self.ds.log('INFO', 'Retrieving logs for zone: ' + zone['name'])
            logs = self.get_zone_logs(zone, start_time_str, end_time_str)
            if isinstance(logs, list):
                self.ds.log('INFO', 'Processing ' + str(len(logs)) + ' for zone: ' + zone['name'])
                self.process_logs(zone, logs)
            else:
                self.ds.log('INFO', 'No logs received for zone: ' + zone['name'])

    
    def usage(self):
        print
        print os.path.basename(__file__)
        print
        print '  No Options: Run a normal cycle'
        print
        print '  -t    Testing mode.  Do all the work but do not send events to GRID via '
        print '        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\''
        print '        in the current directory'
        print
        print '  -l    Log to stdout instead of syslog Local6'
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
    
        try:
            opts, args = getopt.getopt(argv,"htnld:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('cloudflareEventLogs', testing=self.testing, send_syslog = self.send_syslog, store_state = True)
        except Exception ,e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
