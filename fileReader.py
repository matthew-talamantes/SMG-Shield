from datetime import datetime

#Write file function

def write_value(results_dict, file_name):

#Take the dict of URLs and IP's and it'll take file name
#Open the file that is passed through
    current_time = datetime.now()
    file = open(file_name, "w")
    file.write("URL/IP, type, timestamp, harmless, malicious, suspicious, undetected, timeout\n")
#loop through the URLs and IPs
    for key, value in results_dict.items():
#For each URL/IP, we'll write to the file the URL/IP, the time and their stats. 
        for item, stats in value.items():
            file.write(f"{item}, {key}, {current_time}, {stats['harmless']}, {stats['malicious']}, {stats['suspicious']}, {stats['undetected']}, {stats['timeout']}\n")
#Close file
    file.close()
    print("Message")
#read file function
#it'll take a file name
#for each line in file, it will create a dict entry with the URL/IP as the key and the value will be another dict with harmless, malicious, etc. as the keys 
#and the count as the value

#build a results dict

#return results dict
