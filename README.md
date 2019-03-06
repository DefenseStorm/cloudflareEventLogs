Cloudflare Integration for DefenseStorm

to pull this repository and submodules:

git clone --recurse-submodules https://github.com/DefenseStorm/cloudflareEventLogs.git

1. If this is the first integration on this DVM, Do the following:

  cp ds-integration/ds_events.conf to /etc/syslog-ng/conf.d

  Edit /etc/syslog-ng/syslog-ng.conf and add local7 to the excluded list for filter f_syslog3.  The line should look like the following:

  filter f_syslog3 { not facility(auth, authpriv, mail, local7) and not filter(f_debug); };

  Restart syslog-ng
    service syslog-ng restart

2. Copy the template config file and update the settings

  cp cloudflareEventLogs.conf.template cloudflareEventLogs.conf

  change the following items in the config file based on your configuration

3. Add the following entry to the root crontab so the script will run every
   5 minutes.

   */5 * * * * /usr/local/cloudflareEventLogs/cloudflareEventLogs.py
