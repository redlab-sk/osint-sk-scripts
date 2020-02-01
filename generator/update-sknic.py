#! /usr/bin/env python
import urllib
import os
import time
import json
import logging
import datetime
#from datetime import datetime
from optparse import OptionParser


# Path to global or local config file
config_global = "/usr/local/etc/osint/config.json"
config_local = os.path.expanduser("~/.osint.json")

testmode = False

if os.path.exists(config_global) and os.path.getsize(config_global) > 0:
        with open(config_global) as json_file:
                config = json.load(json_file)
else:
        if os.path.exists(config_local) and os.path.getsize(config_local) > 0:
                with open(config_local) as json_file:
                        config = json.load(json_file)
        else:
                print("No configuration file found in %s or %s" % (config_global,config_local))
                exit(1)


# populate variables with values from config
path_basedir = config["path"]["basedir"]
path_logdir = config["path"]["logdir"]
file_log = os.path.join(path_logdir,"updates.log")
# subfolders
path_actual = os.path.join(path_basedir,"actual","domain")
path_trends = os.path.join(path_basedir,"trends","domain")
# temp dir to store raw unprocessed data
path_raw = os.path.join(path_basedir,"raw","domain")
path_raw_domains = os.path.join(path_raw,"domains")
path_raw_registrars = os.path.join(path_raw,"registrars")
# files to store actual stats
file_actual_stats_sk_domains = os.path.join(path_actual,"sk-domains.txt")
file_actual_stats_domain_changes = os.path.join(path_actual,"stats-domain-changes.json")
file_actual_stats_count_by_registrar = os.path.join(path_actual,"stats-count-by-registrar.json")
file_actual_stats_domains_by_registrar = os.path.join(path_actual,"stats-domains-by-registrar.json")
# files to store trends
file_actual_trends_sk_domains = os.path.join(path_actual,"sk-domains.txt")
file_actual_trends_domain_changes = os.path.join(path_actual,"trends-domain-changes.json")
file_actual_trends_count_by_registrar = os.path.join(path_actual,"trends-count-by-registrar.json")
file_actual_trends_domains_by_registrar = os.path.join(path_actual,"trends-domains-by-registrar.json")
# Source data from SK-NIC
url_domains="https://sk-nic.sk/subory/domains.txt"
url_registrators="https://sk-nic.sk/subory/registrars.txt"

suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
def humansize(nbytes):
    i = 0
    while nbytes >= 1024 and i < len(suffixes)-1:
        nbytes /= 1024.
        i += 1
    f = ('%.2f' % nbytes).rstrip('0').rstrip('.')
    return '%s %s' % (f, suffixes[i])

def date_today():
    return datetime.datetime.now().strftime("%Y-%m-%d")

def get_domains_file(localname):
    if not os.path.isfile(localname):
        try:
            urllib.urlretrieve(url_domains, localname)
        except Exception, e:
            print "[!] Unable to download domains list.", e
            logging.error('Unable to download domains list.')
        logging.info('Downloaded file size : '+str(os.path.getsize(localname)))
        return os.path.getsize(localname)
    else:
        logging.warning('File '+localname+' already exists. Size: '+str(os.path.getsize(localname)))
        return 0

def get_registrators_file(localname):
    if not os.path.isfile(localname):
        try:
            urllib.urlretrieve(url_registrators, localname)
        except Exception, e:
            print "[!] Unable to download registrators list: ", e
            logging.error('Unable to download registrators list.')
        logging.info('Downloaded file size : '+str(os.path.getsize(localname)))
        return os.path.getsize(localname)
    else:
        logging.warning('File '+localname+' already exists. Size: '+str(os.path.getsize(localname)))
        return 0

def create_dir(path):
    try:
        if not os.path.exists(path):
            logging.info("Creting directory: "+path)
            os.makedirs(path)
    except Exception, e:
        print "[!] Unable to create directory %s : %s" % path, e            

def create_dirs():
    create_dir(path_raw_domains)
    create_dir(path_raw_registrars)

def download_source_data():
    status = {'domains':{},'registrars':{}}
    domains_save_to=os.path.join(path_raw_domains,'domains_'+date_today()+'.txt')
    registrators_save_to=os.path.join(path_raw_registrars,'registrars_'+date_today()+'.txt')
    logging.info('[+] Downloading domains file to : ' + domains_save_to)
    domains_file_size = get_domains_file(domains_save_to)
    status['domains']={'file':domains_save_to,'size':humansize(domains_file_size)}
    logging.info('[+] Downloading registrators file to : ' + registrators_save_to)
    registrators_file_size = get_registrators_file(registrators_save_to)
    status['registrars']={'file':registrators_save_to,'size':humansize(registrators_file_size)}
    return status

def parse_domains_file(filename):
    
    result_actual_stats_sk_domains = []

    with open(filename) as fp:
        line = fp.readline()
        cnt = 1
        while line:
            line = fp.readline()
            cnt += 1
            # Skip the first 9 lines containing the header
            if cnt >=  9:
                fields=line.split(';')
                # append to list of domains
                result_actual_stats_sk_domains.append(fields[0])
        logging.debug("Processed %d lines from %s" % (cnt,filename))

    # Save the domains file 
    with open(file_actual_stats_sk_domains, "w") as text_file:
        text_file.write('\n'.join(result_actual_stats_sk_domains))
    logging.debug("Wrote %d lines to %s" % (len(result_actual_stats_sk_domains),file_actual_stats_sk_domains))



def main():

    usage = "usage: %prog [options] "
    parser = OptionParser(usage)
    parser.add_option("-f", "--file", dest="filename", help="read data from FILE", metavar="FILE")
    parser.add_option("-t", "--test", action="store_true", dest="testmode",help="Test mode, no file modification.")
    parser.add_option("-a", "--actual", action="store_true", dest="actual",help="Update actual stats")
    parser.add_option("-u", "--update", action="store_true", dest="update",help="Update trends")
    parser.add_option("-d", "--debug", action="store_true", dest="debugmode",help="Enable DEBUG logging")
    # Parse arguments
    (options, args) = parser.parse_args()

    if options.filename:
        if not os.path.isfile(options.filename):
            logging.error('File not found!')
            print("[!] File not found!")
            exit(1)
    else:
        if options.actual or options.update:
            print("[!] Input file not specified!")
            exit(2)

    # create logger
    if options.debugmode:
            logging.basicConfig(filename=file_log,level=logging.DEBUG,format='%(asctime)s - sknic-update - %(levelname)s - %(message)s')
    else:
            logging.basicConfig(filename=file_log,level=logging.INFO,format='%(asctime)s - sknic-update - %(levelname)s - %(message)s')
    logging.info('Update BEGIN.')
    

    if options.testmode:
            testmode=True
            print("Running in TESTMODE")
            logging.info("Running in TESTMODE")
    else:        
        # create the subfolder structure
        create_dirs()
        # download source data from SK-NIC
        status = download_source_data()
        print json.dumps(status, indent=4)
    

    # Parse the input file
    parse_domains_file(options.filename)



    logging.info('Update END.')

if __name__ == '__main__':
    main()


