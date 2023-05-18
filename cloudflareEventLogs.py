#!/usr/bin/env python3

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

    JSON_field_mappings = {
        'OriginIP' : 'ip_dest',
        'ClientIP' : 'ip_src',
        'ClientSSLProtocol' : 'protocol',
        'ClientRequestBytes' : 'bytes',
        'ClientRequestHost' : 'http_host',
        'ClientRequestMethod' : 'http_method',
        'ClientRequestPath' : 'http_path',
        'ClientRequestURI' : 'http_uri',
        'ClientRequestUserAgent' : 'http_user_agent',
        'EdgeResponseBytes' : 'bytes_sent',
        'SecurityLevel' : 'message',
        'FirewallMatchesActions' : 'action',
        'FirewallMatchesSources' : 'action_source',
        'FirewallMatchesRuleIDs' : 'activity_id',
        'RequestHeaders': 'request',
        'ResponseHeaders': 'response',
	'Cookies': None,
        'RayID' : None,
        'SecurityLevel' : None,
        'ZoneID' : None,
        'CacheResponse' : None,
        'ClientASN' : None,
        'ClientCountry' : None,
        'ClientDeviceType' : None,
        'ClientRequestReferer' : None,
        'ClientRequestProtocol' : None,
        'EdgeEndTimestamp' : None,
        'EdgePathingSrc' : None,
        'EdgePathingStatus' : None,
        'EdgeResponseStatus' : None,
        'EdgeStartTimestamp' : None,
        'OriginResponseStatus' : None,
        'WAFAction' : None,
        'WAFFlags' : None,
        'WAFMatchedVar' : None,
        'WAFProfile' : None,
        'WAFRuleID' : None,
        'WAFRuleMessage' : None,
        'BotScore' : 'score',
        'BotScoreSrc' : None,
        'EdgeRateLimitAction' : None,
        'EdgeRateLimitID' : None,
        'JA3Hash': None
    }

    def get_zone_logs(self, zone, start_time, end_time):
        keylist = ""
        first = True
        for key in self.JSON_field_mappings.keys():
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
        page_number = 0
        zones_list = []
        while True:
            page_number += 1
            zones = self.cf.zones.get(params = {'per_page':100, 'page':page_number})
            if len(zones) == 0:
                break
            else:
                zones_list += zones

        for zone in zones_list:
            if zone['status'] != 'active':
                zones_list.remove(zone)
        return zones_list

    def process_logs(self, zone, logs):
        for log in logs:
           log['category'] = zone['name']
           log['timestamp'] = str(int(log['EdgeEndTimestamp']) / 1000000000)
           if 'RequestHeaders' in log.keys():
               if 'x-forwarded-for' in log['RequestHeaders'].keys():
                   tmp_list = log['RequestHeaders']['x-forwarded-for'].split(',')
                   if len(tmp_list) > 1:
                       log['forwarded_for'] = tmp_list[0]
                       tmp_list.pop(0)
                       log['RequestHeaders']['x-forwarded-for'] = tmp_list
           
           if 'FirewallMatchesActions' in log.keys() and isinstance(log['FirewallMatchesActions'], list) and len(log['FirewallMatchesActions']) > 0:
               log['FirewallMatchesActions_list'] = log['FirewallMatchesActions']
               log['FirewallMatchesActions'] = log['FirewallMatchesActions'][0]
           if 'FirewallMatchesSources' in log.keys() and isinstance(log['FirewallMatchesSources'], list) and len(log['FirewallMatchesSources']) > 0:
               log['FirewallMatchesSources_list'] = log['FirewallMatchesSources']
               log['FirewallMatchesSources'] = log['FirewallMatchesSources'][0]
           if 'FirewallMatchesRuleIDs' in log.keys() and isinstance(log['FirewallMatchesRuleIDs'], list) and len(log['FirewallMatchesRuleIDs']) > 0:
               log['FirewallMatchesRuleIDs_list'] = log['FirewallMatchesRuleIDs']
               log['FirewallMatchesRuleIDs'] = log['FirewallMatchesRuleIDs'][0]
           self.ds.writeJSONEvent(log, JSON_field_mappings = self.JSON_field_mappings)
        return

    def run(self):
        global time
        self.state_dir = self.ds.config_get('cloudflare', 'state_dir')
        last_run = self.ds.get_state(self.state_dir)
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
        self.ds.log('INFO', 'Found Zone Count: ' + str(len(zones)))
        for zone in zones:
            self.ds.log('INFO', 'Retrieving logs for zone: ' + zone['name'])
            try:
                logs = self.get_zone_logs(zone, start_time_str, end_time_str)
            except Exception as e:
                self.ds.log('ERROR', 'Failed getting zone logs for ' + zone['name'])
                traceback.print_exc()
            if isinstance(logs, list):
                self.ds.log('INFO', 'Processing ' + str(len(logs)) + ' for zone: ' + zone['name'])
                try:
                    self.process_logs(zone, logs)
                except Exception as e:
                    self.ds.log('ERROR', 'Failed processing logs for zone: ' + zone['name'])
                    traceback.print_exc()
            elif isinstance(logs, dict):
                self.ds.log('INFO', 'Returned single entry, converting to list')
                if 'result' not in logs.keys():
                    new_logs = []
                    new_logs.append(logs)
                    try:
                        self.process_logs(zone, new_logs)
                    except Exception as e:
                        self.ds.log('ERROR', 'Failed processing logs for zone: ' + zone['name'])
                        traceback.print_exc()
                else:
                    self.ds.log('INFO', 'Response: ' + str(logs)[:500])
                    self.ds.log('INFO', 'No logs received for zone: ' + zone['name'])
            else:
                self.ds.log('INFO', 'Response: ' + str(logs)[:500])
                self.ds.log('INFO', 'No logs received for zone: ' + zone['name'])
        self.ds.set_state(self.state_dir, current_run)

    
    def usage(self):
        print('')
        print(os.path.basename(__file__))
        print('')
        print('  No Options: Run a normal cycle')
        print('')
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print('')
        print('  -l    Log to stdout instead of syslog Local6')
        print('')
    
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
            self.ds = DefenseStorm('cloudflareEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    try:
        i.run()
    except Exception as e:
        traceback.print_exc()
