#! /usr/bin/env python
import os
import time
import json
import logging
import datetime
import operator
import collections
from optparse import OptionParser
from collections import defaultdict
from itertools import islice
import dns.resolver
import subprocess
import geoip2.database

# Path to global or local config file
config_global = "/usr/local/etc/osint/config.json"
config_local = os.path.expanduser("~/.osint.json")
# Do we run in testmode?
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
path_geoip = config["path"]["geoip"]
file_log = os.path.join(path_logdir,"updates.log")
# subfolders
path_actual = os.path.join(path_basedir,"actual","resolve")
path_trends = os.path.join(path_basedir,"trends","resolve")
# resolvers list from data
path_actual_resolvers = os.path.join(path_actual,"open-resolvers.txt")
# source list of active SLDs
path_actual_domains = os.path.join(path_basedir,"actual","domain","sk-domains.txt")
# temp dir to store raw unprocessed data
path_raw = os.path.join(path_basedir,"raw","resolve")
filename_raw_resolvers = "working-resolvers.txt"
filename_raw_domains = "domains-to-resolve.txt"
filename_raw_domains_r2 = "domains-to-resolve-r2.txt"
filename_raw_massdns_r1 = "massdns-resolved-r1.txt"
filename_raw_massdns_r2 = "massdns-resolved-r2.txt"
path_raw_resolvers = os.path.join(path_raw,filename_raw_resolvers)
path_raw_domains = os.path.join(path_raw,filename_raw_domains)
path_raw_domains_r2 = os.path.join(path_raw,filename_raw_domains_r2)
path_raw_massdns_r1 = os.path.join(path_raw,filename_raw_massdns_r1) # round 1 (host -> A/CNAME)
path_raw_massdns_r2 = os.path.join(path_raw,filename_raw_massdns_r2) # round 2 (CNAME -> A)
# files to store actual stats
file_actual_resolved = os.path.join(path_actual,"sk-www-domains-resolved.json")
file_trends_resolved_country = os.path.join(path_trends,"sk-resolved-country.json")
file_trends_resolved_ip = os.path.join(path_trends,"sk-resolved-ip.json")
# path to docker bin
bin_docker = "/usr/bin/docker"


# Today's date in YMD format
def date_today():
    return datetime.datetime.now().strftime("%Y-%m-%d")

def test_resolver(resolver):
    # Create our own resolver instance
    my_resolver = dns.resolver.Resolver()
    my_resolver.timeout = 1
    my_resolver.lifetime = 1
    my_resolver.nameservers = [resolver]
    # Check if the resolver is working
    try:
        result = str(my_resolver.query('osint.sk', 'A')[0])
        if result == '91.210.182.151':
            #print("%s > %s > OK" % (resolver,result))
            return True
        else:
            #print("%s > %s > NOK" % (resolver,result))
            return False
    except dns.exception.Timeout:
        #print("%s timeout." % resolver)
        return False
    return True

# Generate all the stats and trends from downloaded files
def create_resolvers_list(filename_resolvers_data,filename_resolvers_active):
    # list of public resolvers
    resolvers_list = ['8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1']
    # load list of public resolvers
    with open(filename_resolvers_data) as fp:
        line = fp.readline().strip()
        cnt = 0
        cnt_ok = 0
        cnt_nok = 0
        while line:
            cnt += 1
            # is it a working resolver
            if '.' in line:
                if test_resolver(line):
                    cnt_ok += 1
                    resolvers_list.append(line)
                else:
                    cnt_nok +=1
            line = fp.readline().strip()
        logging.debug("Processed %d lines from %s" % (cnt,filename_resolvers_data))

    print("Resolvers test (ok/nok/total): %d/%d/%d" % (cnt_ok,cnt_nok,cnt))
    # write to temporary list
    with open(filename_resolvers_active, 'w') as f:
        for resolver in resolvers_list:
            f.write("%s\n" % resolver)

def create_domains_list(filename_domains_src,filename_domains_dst):
    # list fo domains
    domains = []
    with open(filename_domains_src) as fp:
        line = fp.readline().strip()
        cnt = 0
        while line:
            cnt += 1
            if '.' in line:
                domains.append(line)
            line = fp.readline().strip()
        logging.debug("Processed %d lines from %s" % (cnt,filename_domains_src))

    # write to temporary list
    with open(filename_domains_dst, 'w') as f:
        for domain in domains:
            f.write("www.%s\n" % domain)

def run_massdns(file_resolvers, file_domains,file_output):
    command = [ bin_docker, 'run', '-t', '--rm', '-v', 
                path_raw+':/data',  
                'massdns', 
                '-r', os.path.join("/data",file_resolvers), 
                '-w', os.path.join("/data",file_output), 
                '-c', '50',
                '-t', 'A', 
                '-o', 'S',
                os.path.join("/data",file_domains)
                ]
    logging.debug(command)
    # result = subprocess.check_output(command,shell=True)
    result = subprocess.Popen(command, stdout=subprocess.PIPE)
    out = result.stdout.read()
    # return result
    return out
    
def create_r2_inputfiles(output_r1,input_r2):
    # list fo domains
    domains = []
    with open(output_r1) as fp:
        line = fp.readline().strip()
        cnt = 0
        while line:
            cnt += 1
            if ' CNAME ' in line:
                domains.append(line.split(' ')[2])
            line = fp.readline().strip()
        logging.debug("Processed %d lines from %s" % (cnt,output_r1))

    # write to temporary list
    with open(input_r2, 'w') as f:
        for domain in domains:
            f.write("%s\n" % domain)

def import_results_file():
    # final dictionary
    resolved_dict = {}
    resolved_dict = defaultdict(list)
    # cname lookup table
    cname_dict = {}
    # populate data into the CNAME lookup table
    with open(path_raw_massdns_r2) as rfp:
        line = rfp.readline().strip()
        while line:
            line_fields = line.split(' ')
            resolved_ip = line_fields[2]
            resolved_host = line_fields[0][:-1]
            cname_dict[resolved_host]= resolved_ip
            # read next line
            line = rfp.readline().strip()
    # load round-1 results and lookup CNAMEs
    with open(path_raw_massdns_r1) as rfp:
        line = rfp.readline().strip()
        while line:
            line_fields = line.split(' ')
            if ' A ' in line:
                resolved_ip = line_fields[2]
                resolved_host = line_fields[0][:-1] # strip the last dot '.sk.'
                resolved_dict[resolved_ip].append(resolved_host)
            # for aliases do a lookup in R2 table
            if ' CNAME ' in line:
                try:
                    resolved_ip = cname_dict[line_fields[2][:-1]] # strip the last dot '.sk.'
                except:
                    resolved_ip = 'NX'
                resolved_host = line_fields[0][:-1] # strip the last dot '.sk.'
                resolved_dict[resolved_ip].append(resolved_host)
            # read next line
            line = rfp.readline().strip()

    return resolved_dict

def generate_actual():
    resolved_dict_r1 = import_results_file() # result from r1
    resolved_dict_r2 = {} # results grouped by country-code
    resolved_dict_r2 = defaultdict(dict)
    # prepare geoip reader
    reader = geoip2.database.Reader(path_geoip)
    for ip in resolved_dict_r1:
        try:
            iso_code = reader.country(ip).country.iso_code
        except:
            iso_code = 'NX'
        resolved_dict_r2[iso_code][ip] = resolved_dict_r1[ip]
   
    del(resolved_dict_r1) # R1 data are no longer needed
    reader.close() # close geoip db
    return resolved_dict_r2


# Save actual stats to json files (sorted)
def save_actual(json_file,json_data):

        for country in json_data:
            for ip in json_data[country]:
                json_data[country][ip].sort()

        with open(json_file, 'w') as outfile:
                json.dump(json_data, outfile, indent=4, sort_keys=True) 


def dict_stats(dict):
    country = len(dict)
    ips = 0
    hosts = 0
    for iso in dict:
        ips += len(dict[iso])
        for ip in dict[iso]:
            hosts += len(dict[iso][ip])
    return (country,ips,hosts)

def get_top10(data_stats):
    # create an ordered list DESC by VALUE
    data_stats = collections.OrderedDict(sorted(data_stats.items(), reverse=True, key=operator.itemgetter(1)))
    # get only the Top10
    data_stats = dict(data_stats.items()[:10])
    return data_stats

def generate_trends(actual_dict):
    trends_country = {}
    trends_ip = {}
    for country in actual_dict:
        trends_country[country] = len(actual_dict[country])
        for ip in actual_dict[country]:
            trends_ip[ip] = len(actual_dict[country][ip])
    return (get_top10(trends_country),get_top10(trends_ip))

# If there are no trends data create a dummy file
def dummy_trends_file(trends_file,dict_key):
    data = {dict_key:[]}
    with open(trends_file, 'w+') as outfile:
        json.dump(data, outfile, indent=4)
    outfile.close()

def save_trends(trends_file,data_stats,dict_key):
    # make dummy if file not found
    if not os.path.isfile(trends_file):
        dummy_trends_file(trends_file,dict_key)

    # read actual trends
    with open(trends_file) as json_file:
            data_trends = json.load(json_file)

    data_stats["date"]= date_today()
    # append last stats to trends
    data_trends[data_trends.keys()[0]].append(data_stats)
   
    # print(data_trends)
    with open(trends_file, 'w') as outfile:
            json.dump(data_trends, outfile, indent=4)




def main():
    global testmode

    usage = "usage: %prog [options] "
    parser = OptionParser(usage)
    parser.add_option("-t", "--test", action="store_true", dest="testmode",help="Test mode, no file modification.")
    parser.add_option("-a", "--actual", action="store_true", dest="actual",help="Update actual stats")
    parser.add_option("-u", "--update", action="store_true", dest="update",help="Update trends")
    parser.add_option("-d", "--debug", action="store_true", dest="debugmode",help="Enable DEBUG logging")
    # Parse arguments
    (options, _) = parser.parse_args()

    # create logger
    if options.debugmode:
            logging.basicConfig(filename=file_log,level=logging.DEBUG,format='%(asctime)s - resolve-update - %(levelname)s - %(message)s')
    else:
            logging.basicConfig(filename=file_log,level=logging.INFO,format='%(asctime)s - resolve-update - %(levelname)s - %(message)s')
    logging.info('Update BEGIN.')
    

    if options.testmode:
            testmode=True
            print("Running in TESTMODE")
            logging.info("Running in TESTMODE")

    if options.actual:
        # prepare resolvers list
        create_resolvers_list(path_actual_resolvers,path_raw_resolvers)
        create_domains_list(path_actual_domains, path_raw_domains)
        logging.info('Finished processing of input files.')
        result = run_massdns(filename_raw_resolvers,filename_raw_domains,filename_raw_massdns_r1)
        logging.info('Massdns Round-1 finished.')
        logging.debug(result)
        ##print(result) #debug

        # Prepare Round-2
        create_r2_inputfiles(path_raw_massdns_r1,path_raw_domains_r2)
        # Run Phase-2
        result = run_massdns(filename_raw_resolvers,filename_raw_domains_r2,filename_raw_massdns_r2)
        logging.info('Massdns Round-2 finished.')
        logging.debug(result)
        ##print(result) #debug

        # Process combined results from both rounds
        actual_dict = generate_actual()
        ##print(actual_dict) # debug
        # update actual stats
        if not testmode:
            save_actual(file_actual_resolved,actual_dict)
        else:
            print("Actual stats [country/ip/hosts]: %d/%d/%d" % dict_stats(actual_dict)) 

    if options.update:
        # get actual trends
        trends_country,trends_ip = generate_trends(actual_dict)
        if not testmode:
            save_trends(file_trends_resolved_country,trends_country,"resolved_by_country")
            save_trends(file_trends_resolved_ip,trends_ip,"resolved_by_ip")
        else:
            print(trends_country)
            print(trends_ip)

    logging.info('Update END.')

if __name__ == '__main__':
    main()


