"""                                                 
Author : Hariscats
Date   : 2023-02-17
Purpose: Get DNS records
"""

import dns.resolver

host = "dns.google"

records = ['A','AAAA','NS','SOA','MX','TXT']
for record in records:
    try:
        responses = dns.resolver.resolve(host, record)
        print("\nResponse: ",record)
        print("-----------------------------------")
        for response in responses:
            print(response)
    except Exception as exception:
        print(f"{record} QUERY CANNOT BE RESOLVED")
        print("ERROR OBTAINING RECORD", exception)
