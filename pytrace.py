#!/usr/bin/python3
"""RZFeeser || Alta3 Research
Summary:
    Loop across all capture files within pcap/
    Looks for source / dest MACs within pcap/maclist.txt
    Results are stored in archive/{jobnum}/{macaddress}/
    
Updates to Make:
    Continue to make functions (some of these may be handeled better by scapy, not sure...)
    Add argparse
    Look at scapy.py library for detailed *pcap analysis
    """

import subprocess
import argparse
import os
import uuid
from datetime import datetime
import pyshark

#import scapy # v heavy on memory, but good for small pcap analysis. Use tshark to reduce pcaps > use scapy to dig

# Open the file /pcaps/maclist.txt (list of macs to watch for)
def whatMacsAttack(macfile):
    """looks for the input file pcaps/maclist.txt and returns a dictionary with two lists"""
    with open(macfile) as maclist:
        perps = maclist.read().splitlines() # read the entire file into a single string, then split across "\n"
        maclist.seek(0) # move the cursor back to the start of the file (prevents having to close and reopen)
        shortenedperps = maclist.read().replace(":", "").splitlines() # strip out the : from the mac addresses
    return (perps, shortenedperps)  # this returns TWO values

# creates folders to store outputs in
def profilegenerator(shortperps, jobnum):
    for perp in shortperps:
        if not os.path.exists(f"archives/{jobnum}/{perp}"):
            os.makedirs(f"archives/{jobnum}/{perp}")
    return None

# define a function that can dynamically create filters
def filtergenerator():
    return None

def trashorjson(cap, jobnum, sp, pcapNoExt):
    """This function returns path to file if JSON was created, and None if the file did not contain packets and was deleted"""
    pathandfile = f"archives/{jobnum}/{sp}/trace_{pcapNoExt}_containing_{sp}"
    
    if len(cap._packets) == 0:
        os.remove(pathandfile + ".pcap")
        return
    else:
        runme = ["tshark", "-r", pathandfile + ".pcap",  "-T", "json"]  # change json to jsonraw for hexadecimal
        with open(pathandfile + ".json", "w") as jfile:
            subprocess.call(runme, stdout=jfile)
        return pathandfile 

# define a function that scrubs directories that contain no pcaps
def cleanup(jobnum):
    counter = 0
    for root, dirs, files in os.walk(f"archives/{jobnum}/"):
        if counter == 0:
            counter += 1
            continue
        if not files:
            os.rmdir(root)
    return None


def main():
    """pull together all of our functions into our trace program
    perps - ([mac list], [no colon mac list])
    movehere - directory location of our script
    jobnum - a unique string YYYY-MM-DD_HH-MM-SS used to create a folder to store the work
    pcapNoExt - A variable of the current pcap being iterated over without the .cap or .pcap extension
    """

    # returns two lists one with colons and one without
    perps = whatMacsAttack(args.macfile)     # returns a tuple ([mac list], [no colon mac list])

    # change to the real directory of where the script resides
    movehere = os.path.dirname(os.path.realpath(__file__))
    os.chdir(movehere) # changes our current working directory

    # create a YYYY-MM-DD_HH-MM-SS string
    jobnum = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    print(f"Profile reporting for this run available @ {movehere}archives/{jobnum}/")

    # create a series of user profiles
    profilegenerator(perps[1], jobnum)
      
    # obtain the list of input files to process
    for pcap in os.listdir("pcaps/"):
        # if a file is a network capture
        if pcap.endswith(".pcap") or pcap.endswith(".cap"):
            pcapNoExt = pcap.rstrip(".pcap").rstrip(".cap")
            # then search that network capture for a "bad mac"
            for mac, sp in zip(perps[0], perps[1]):
                # create our displayfilter to pass to pyshark
                df = f"eth.dst=={mac} or eth.src=={mac}"
                # open a pcapfile, and apply our custom display filter
                cap = pyshark.FileCapture("pcaps/"+pcap, display_filter=df, output_file=f"archives/{jobnum}/{sp}/trace_{pcapNoExt}_containing_{sp}.pcap")
                
                # this is REQUIRED for the "primed" cap object to run with the display filter
                cap.load_packets() # this line creates the output_file
                

                # pcaps have been created. Unforunately, pcaps are even created containing no packets.
                # determine if pcaps have packets in them or not. if not, they need to be deleted
                # if they are kept they need to be turned into JSON
                toj = trashorjson(cap, jobnum, sp, pcapNoExt)
                if toj:
                    print(f"Profile Created @:\n\t{toj}.pcap\n\t{toj}.json")

    # almost done, call our function to remove directories that do not contain pcaps
    cleanup(jobnum)


# IF you are run via the CMD line, or invoked directly, call main
# IF you are imported... chill out.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='''
            Search for MAC and IP address within all *.pcap files found within local directory pcaps/.
            Results are outputted to archives/YYYY-MM-DD_HH-MM-SS/[offending IP or MAC]''')
    
    parser.add_argument('-m', '--macfile', default='pcaps/maclist.txt', help='File containing the MAC addresses to scan for')

    args = parser.parse_args()
    
    main()
