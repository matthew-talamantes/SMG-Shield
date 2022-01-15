from datetime import datetime, timedelta

#Write file function

def write_value(results_dict, file_name):

#Open the file that is passed through
    current_time = datetime.now()
    file = open(file_name, "w")
    file.write("URL/IP, type, timestamp, harmless, malicious, suspicious, undetected, timeout\n")
#Loop through the URLs and IPs
    for key, value in results_dict.items():
#For each URL/IP, we'll write to the file the URL/IP, the time and their stats. 
        for item, stats in value.items():
            file.write(f"{item}, {key}, {current_time}, {stats['harmless']}, {stats['malicious']}, {stats['suspicious']}, {stats['undetected']}, {stats['timeout']}\n")
#Close file
    file.close()
    print("Message")

def get_line_list(line):
    linelist = line.split(",")
    for pos, item in enumerate(linelist):
        linelist[pos] = item.strip()
    return linelist


#read file function
def read_value(file_name):
    current_time = datetime.now()
#open file
    file = open(file_name, "r")
    file.readline()
    results_dict = {}
#for each line in file, it will create a dict entry with the URL/IP as the key and the value will be another dict with harmless, malicious, etc. as the keys 
#and the count as the value
    for line in file:
        linelist = get_line_list(line)
        timestamp = datetime(linelist[2])
        if linelist[2] >= (current_time - timedelta(days=7)):
            results_dict[linelist[1]] [linelist[0]] = {"harmless": int(linelist[3]), "malicious": int(linelist[4]), "suspicious": int(linelist[5]), "undetected": int(linelist[6]), "timeout": int(linelist[7])}
    file.close()
    return results_dict

