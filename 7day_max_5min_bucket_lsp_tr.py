#!/opt/gums/bin/python3
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-

# It is a very basic druid sql query hack. To be used as an example for more sophisticated queries for data exploration from various cubes.

import json
import requests 
query = { "query": "SELECT distinct lsp FROM \"lsp-zoom\" WHERE \"__time\" >= CURRENT_TIMESTAMP - INTERVAL \'7\' DAY " }
url = 'http://alex-broker03.ip.gin.ntt.net:8888/druid/v2/sql/'
headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
res = requests.post(url, data=json.dumps(query), headers=headers)
for item in res.json():
    print ("Getting data for " + item['lsp'])
    lsp = item['lsp']
    lsp_query_str = "SELECT   lsp , TIME_FLOOR(__time, \'PT5M\') as time_bucket, AVG( out_mbps ) as avg_mbps FROM \"lsp-zoom\" WHERE \"__time\" >= CURRENT_TIMESTAMP - INTERVAL '7' DAY  and lsp = '" +  lsp + "' group by 1, 2"
    lsp_query = {}
    lsp_query["query"] = lsp_query_str
    res = requests.post(url, data=json.dumps(lsp_query), headers=headers)
    max_mbps = 0.0
    # for results
    for subitem in res.json():
        lsp = subitem['lsp']
        btime = subitem['time_bucket'] 
        avg_mbps = float(subitem['avg_mbps'])
        if (avg_mbps > max_mbps):
            max_mbps = avg_mbps 
            max_time = btime
    print("time = " + max_time)
    print("max_mbps = " + str(max_mbps))
