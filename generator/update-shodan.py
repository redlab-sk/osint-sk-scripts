#!/usr/bin/env python

from shodan import Shodan
from optparse import OptionParser
from datetime import datetime
from time import sleep
import json
import os
import logging

# Path to global or local config file
config_global = "/usr/local/etc/osint/config.json"
config_local = os.path.expanduser("~/.osint.json")

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
SHODAN_API_KEY = config["keys"]["shodan"]
path_basedir = config["path"]["basedir"]
path_logdir = config["path"]["logdir"]
file_log = os.path.join(path_logdir,"updates.log")

# SHODAN init
api = Shodan(SHODAN_API_KEY)

# subfolders
path_actual = os.path.join(path_basedir,"actual","shodan")
path_trends = os.path.join(path_basedir,"trends","shodan")
# files to store actual stats
file_actual_stats_db = os.path.join(path_actual,"stats-db.json")
file_actual_stats_ics = os.path.join(path_actual,"stats-ics.json")
file_actual_stats_cve = os.path.join(path_actual,"stats-cve.json")
file_actual_stats_ports = os.path.join(path_actual,"stats-ports.json")
file_actual_stats_bluekeep_org = os.path.join(path_actual,"stats-bluekeep_org.json")
file_actual_stats_ssl = os.path.join(path_actual,"stats-ssl.json")
# files to store trends
file_trends_stats_db = os.path.join(path_trends,"trends-db.json")
file_trends_stats_ics = os.path.join(path_trends,"trends-ics.json")
file_trends_stats_cve = os.path.join(path_trends,"trends-cve.json")
file_trends_stats_ports = os.path.join(path_trends,"trends-ports.json")
file_trends_stats_bluekeep_org = os.path.join(path_trends,"trends-bluekeep_org.json")
file_trends_stats_ssl = os.path.join(path_trends,"trends-ssl.json")


# Get today's date as str
def date_today():
    return datetime.now().strftime("%Y-%m-%d")

# get all the stats for DB
def get_stats_db():
        # Stats for databases
        stats_db = {}
        stats_db['MySQL']=api.count('product:MySQL country:"SK"')['total']
        sleep(2)
        stats_db['MongoDB']=api.count('product:MongoDB country:"SK"')['total']
        sleep(2)
        stats_db['Memcached']=api.count('product:Memcached country:"SK"')['total']
        sleep(2)
        stats_db['CouchDB']=api.count('product:CouchDB country:"SK"')['total']
        sleep(2)
        stats_db['PostgreSQL']=api.count('port:5432 PostgreSQL country:"SK"')['total']
        sleep(2)
        stats_db['Riak']=api.count('port:8087 Riak country:"SK"')['total']
        sleep(2)
        stats_db['Redis']=api.count('product:Redis country:"SK"')['total']
        sleep(2)
        stats_db['Cassandra']=api.count('product:Cassandra country:"SK"')['total']
        sleep(2)
        stats_db['Elastic']=api.count('port:9200 json country:"SK"')['total']
        return stats_db

# get all the stats for ICS
def get_stats_ics():
        # Stats for ICS
        stats_ics = {}
        sleep(2)
        stats_ics['Modbus']=api.count('port:502 country:"SK"')['total']
        sleep(2)
        stats_ics['Niagara']=api.count('port:1911,4911 product:Niagara country:"SK"')['total']
        sleep(2)
        stats_ics['GE-SRTP']=api.count('port:18245,18246 product:"general electric" country:"SK"')['total']
        sleep(2)
        stats_ics['MELSEC-Q']=api.count('port:5006,5007 product:mitsubishi country:"SK"')['total']
        sleep(2)
        stats_ics['CODESYS']=api.count('port:2455 operating system country:"SK"')['total']
        sleep(2)
        stats_ics['Siemens-S7']=api.count('port:102 country:"SK"')['total']
        sleep(2)
        stats_ics['BACnet']=api.count('port:47808 country:"SK"')['total']
        sleep(2)
        stats_ics['HART-IP']=api.count('port:5094 hart-ip country:"SK"')['total']
        sleep(2)
        stats_ics['OMRON-FINS']=api.count('port:9600 response code country:"SK"')['total']
        sleep(2)
        stats_ics['IEC-60870-5-104']=api.count('port:2404 asdu address country:"SK"')['total']
        sleep(2)
        stats_ics['DNP3']=api.count('port:20000 source address country:"SK"')['total']
        sleep(2)
        stats_ics['EtherNet-IP']=api.count('port:44818 country:"SK"')['total']
        sleep(2)
        stats_ics['PCWorx']=api.count('port:1962 PLC country:"SK"')['total']
        sleep(2)
        stats_ics['Crimson-v3']=api.count('port:789 product:"Red Lion Controls" country:"SK"')['total']
        sleep(2)
        stats_ics['ProConOS']=api.count('port:20547 PLC country:"SK"')['total']
        return stats_ics

# get all the stats for CVEs
def get_stats_cve():
        # CVE stats for country
        stats_cve = {}
        sleep(2)
        results_cve = api.count('country:"SK"',facets=[('vuln',20)])['facets']['vuln']
        for result in results_cve:
                stats_cve[result['value']]=result['count']
        return stats_cve


# get all the stats for PORTS
def get_stats_ports():
        # port stats for country
        stats_ports = {}
        sleep(2)
        results_ports = api.count('country:"SK"',facets=[('port',20)])['facets']['port']
        for result in results_ports:
                stats_ports[result['value']]=result['count']
        return stats_ports

# get all the stats for the BLUEKEEP CVE grouped by ORG
def get_stats_bluekeep():
        # bluekeep stats per org
        stats_bluekeep_org = {}
        sleep(2)
        results_bluekeep_org = api.count('vuln:cve-2019-0708 country:"SK"',facets=[('org',20)])['facets']['org']
        for result in results_bluekeep_org:
                stats_bluekeep_org[result['value']]=result['count']
        return stats_bluekeep_org

# get all the stats regarding SSL
def get_stats_ssl():
        stats_ssl = {}
        sleep(2)
        stats_ssl['http'] = api.count('country:SK HTTP')['total']
        sleep(2)
        stats_ssl['https'] = api.count('country:SK has_ssl:true HTTP')['total']
        sleep(2)
        stats_ssl['cert_expired'] = api.count('has_ssl:true ssl.cert.expired:true country:SK HTTP')['total']
        return stats_ssl

# Fix/Update trends from local actual stats (not shodan)
def fix_trends(stats_file,trends_file):
        # read actual stats
        with open(stats_file) as json_file:
                data_stats = json.load(json_file)
        # read actual trends
        with open(trends_file) as json_file:
                data_trends = json.load(json_file)

        data_stats["date"]= date_today()

        # append last stats to trends
        data_trends[data_trends.keys()[0]].append(data_stats)
        
        # print(data_trends)
        with open(trends_file, 'w') as outfile:
                json.dump(data_trends, outfile, indent=4)

# Update trends json with actual stats from shodan
def update_trends(trends_file,data_stats):
        # read actual trends
        with open(trends_file) as json_file:
                data_trends = json.load(json_file)

        data_stats["date"]= date_today()

        # append last stats to trends
        data_trends[data_trends.keys()[0]].append(data_stats)
        
        # print(data_trends)
        with open(trends_file, 'w') as outfile:
                json.dump(data_trends, outfile, indent=4)

# Save actual stats to json files
def save_actual(json_file,json_data):
        with open(json_file, 'w') as outfile:
                json.dump(json_data, outfile, indent=4)


def main():
        usage = "usage: %prog [options]"
        parser = OptionParser(usage)
        parser.add_option("-t", "--test", action="store_true", dest="testmode",help="Test mode, no file modification.")
        parser.add_option("-a", "--actual", action="store_true", dest="actual",help="Update actual stats")
        parser.add_option("-u", "--update", action="store_true", dest="update",help="Update trends")
        parser.add_option("-f", "--fix", action="store_true", dest="fix",help="Fix trends (append) from actual stats")
        parser.add_option("-d", "--debug", action="store_true", dest="debugmode",help="Enable DEBUG logging")
        # Parse arguments
        (options, args) = parser.parse_args()

        # create logger
        if options.debugmode:
                logging.basicConfig(filename=file_log,level=logging.DEBUG,format='%(asctime)s - shodan-update - %(levelname)s - %(message)s')
        else:
                logging.basicConfig(filename=file_log,level=logging.INFO,format='%(asctime)s - shodan-update - %(levelname)s - %(message)s')
        logging.info('Update BEGIN.')
        

        if options.testmode:
                print("Running in TESTMODE")
                logging.info("Running in TESTMODE")

        if not options.fix:
                # Get data from shodan
                stats_db_json = get_stats_db()
                stats_ics_json = get_stats_ics()
                stats_cve_json = get_stats_cve()
                stats_ports_json = get_stats_ports()
                stats_bluekeep_json = get_stats_bluekeep()
                stats_ssl_json = get_stats_ssl()


        # Print them if in test mode
        if options.testmode:
                print("[+] Output file : %s" % file_actual_stats_db)
                print(json.dumps(stats_db_json, indent=4))
                print("[+] Output file : %s" % file_actual_stats_ics)
                print(json.dumps(stats_ics_json, indent=4))
                print("[+] Output file : %s" % file_actual_stats_cve)
                print(json.dumps(stats_cve_json, indent=4))
                print("[+] Output file : %s" % file_actual_stats_ports)
                print(json.dumps(stats_ports_json, indent=4))
                print("[+] Output file : %s" % file_actual_stats_bluekeep_org)
                print(json.dumps(stats_bluekeep_json, indent=4))
                print("[+] Output file : %s" % file_actual_stats_ssl)
                print(json.dumps(stats_ssl_json, indent=4))


        # write data to actual dataset
        if options.actual:
                logging.debug("Updating actual datasets - BEGIN")
                save_actual(file_actual_stats_db,stats_db_json)
                save_actual(file_actual_stats_ics,stats_ics_json)
                save_actual(file_actual_stats_cve,stats_cve_json)
                save_actual(file_actual_stats_ports,stats_ports_json)
                save_actual(file_actual_stats_bluekeep_org,stats_bluekeep_json)
                save_actual(file_actual_stats_ssl,stats_ssl_json)
                logging.debug("Updating actual datasets - END")


        if options.fix:
                logging.debug("Fixing trends - BEGIN")
                fix_trends(file_actual_stats_db,file_trends_stats_db)
                fix_trends(file_actual_stats_ics,file_trends_stats_ics)
                fix_trends(file_actual_stats_cve,file_trends_stats_cve)
                fix_trends(file_actual_stats_ports,file_trends_stats_ports)
                fix_trends(file_actual_stats_bluekeep_org,file_trends_stats_bluekeep_org)
                fix_trends(file_actual_stats_ssl,file_trends_stats_ssl)
                logging.debug("Fixing trends - END")

        if options.update:
                logging.debug("Updating trends - BEGIN")
                update_trends(file_trends_stats_db,stats_db_json)
                update_trends(file_trends_stats_ics,stats_ics_json)
                update_trends(file_trends_stats_cve,stats_cve_json)
                update_trends(file_trends_stats_ports,stats_ports_json)
                update_trends(file_trends_stats_bluekeep_org,stats_bluekeep_json)
                update_trends(file_trends_stats_ssl,stats_ssl_json)
                logging.debug("Updating trends - END")

        logging.info('Update END.')

if __name__ == "__main__":
        main()