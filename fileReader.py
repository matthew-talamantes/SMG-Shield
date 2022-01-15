from datetime import datetime, timedelta
import os


def get_line_list(line):
    linelist = line.split(",")
    for pos, item in enumerate(linelist):
        linelist[pos] = item.strip()
    return linelist

def getDateFromStr(dateStr):
    year = int(dateStr[0:4:])
    month = int(dateStr[5:7:])
    day = int(dateStr[8:10:])
    hour = int(dateStr[11:13:])
    minute = int(dateStr[14:16:])
    second = int(dateStr[17:19:])
    millisecond = int(dateStr[20::])
    date = datetime(year, month, day, hour, minute, second, millisecond)
    return date



#read file function
def read_value(file_name, type):
    current_time = datetime.now()
#open file
    file = open(file_name, "r")
    file.readline()
    results_dict = {}
#for each line in file, it will create a dict entry with the URL/IP as the key and the value will be another dict with harmless, malicious, etc. as the keys 
#and the count as the value
    for line in file:
        linelist = get_line_list(line)
        timestamp = getDateFromStr(linelist[2])
        if timestamp >= (current_time - timedelta(days=7)) and linelist[1] == type:
            results_dict[linelist[0]] = {"harmless": int(linelist[3]), "malicious": int(linelist[4]), "suspicious": int(linelist[5]), "undetected": int(linelist[6]), "timeout": int(linelist[7])}
    file.close()
    return results_dict

#return results dict


#Write file function

def write_value(results_dict, file_name):
    
    existingUrls = read_value(file_name, 'urls')
    existingIps = read_value(file_name, 'ips')
#Take the dict of URLs and IP's and it'll take file name
#Open the file that is passed through
    current_time = datetime.now()
    fileExists = os.path.isfile(file_name)
    file = open(file_name, "a")
    if not fileExists:
        file.write("URL/IP, type, timestamp, harmless, malicious, suspicious, undetected, timeout\n")
#loop through the URLs and IPs
    for key, value in results_dict.items():
#For each URL/IP, we'll write to the file the URL/IP, the time and their stats. 
        for item, stats in value.items():
            if item not in existingUrls and item not in existingIps and ',' not in item:
                file.write(f"{item}, {key}, {current_time}, {stats['harmless']}, {stats['malicious']}, {stats['suspicious']}, {stats['undetected']}, {stats['timeout']}\n")
#Close file
    file.close()
    print("Done. Here you go:")
