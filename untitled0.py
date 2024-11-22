# -*- coding: utf-8 -*-
"""
Created on Wed Aug  3 16:43:05 2022

@author: net
"""


import requests
url="https://www.fast2sms.com/dev/bulk"
params={

     "authorization":"RDM931xscvkd2Q7WA4uXah5qyiYJnmH6ITwtjEPS0grG8FKpObcyZnfzSN1krjCKuJOhmFwYRbad2BPs",
     "sender_id":"SMSINI",
     "message":"1234",
     "language":"english",
     "route":"p",
     "numbers":"7038046083"
}
requests.get(url,params=params)