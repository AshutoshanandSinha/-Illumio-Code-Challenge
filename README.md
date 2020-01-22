# -Illumio-Code-Challenge

Coding Assignment


Run: python test_firewall.py 

To use your own csv, change the filename in firewall_test.py and add test cases accordingly
I have not provided option for CLI file path.

Logic:
parse the input csv and for each combination of direction, protocol, and port create an entry in hash table.
key will be combination of these three added with underscore(_). and value will be ip address/ranges.
I have not combined ip ranges which could be done to optimize and reduce the decision time.
