#!/usr/bin/env python3

from selenium import webdriver
import pandas as pd
import numpy as np
import requests
import json
import signal
import sys
import asyncio
import aiohttp



breakpoint()
cf_cookie = os.env["XFORCE_CF_COOKIE"]
host = "exchange.xforce.ibmcloud.com"
scheme = "https://"

headers = {
	"x-ui" : "XFE",
	"Accept" : "application/json, text/plain, */*",
	"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/560000.0",
	
}

cookies = {
	"__cfduid" : cf_cookie
}

all_cves = pd.read_csv("../datasets/TrainingV2/Train_test_validation/all_data.csv")

cve_list = all_cves[~pd.isnull(all_cves["CVE"])]["CVE"].values
cwe_list = all_cves[~pd.isnull(all_cves["CVE"])]["CWE-ID"].values

api = "/api/vulnerabilities/search/{}"

x_force_data = {
	"CWE-ID" : [],
	"CVE" : [],
	"Description" : []
}

issue_list = []
curr_dataframe = pd.read_csv("../datasets/x_force_dataset.csv")

"""
async def get_xfrc_desc(session, i, cve):
	print("here")
	async with session.get(scheme + host + api.format(cve)) as response:
		response =  await response.text()
		return [response, cve, cwe_list[i]]
	
async def main():
	tasks = []
	async with aiohttp.ClientSession(headers=headers, cookies=cookies) as session:
		for i, cve in enumerate(cve_list):
			if curr_dataframe.loc[curr_dataframe["CVE"] == cve].empty:
				tasks.append(get_xfrc_desc(session, i, cve))
		issues = await asyncio.gather(*tasks)
	breakpoint()
	for issue in issues:
		response, cve, cwe = tuple(issue)
		if response != '{"error":"Not found."}' and \
		   response != '{"error":"Not authorized."}' and \
		   response != '{"error":"Invalid input."}':
			try:
				res = json.loads(response)
				desc = res[0]['description']
				new_issue = [cwe, desc, cve]
				issue_list.append(new_issue)
				print("Collected:\n\t{}: {}".format(cve, desc))

				if len(issue_list) % 10 == 0:
					print("Reached {} issues".format(len(issue_list)))
			except Exception as e:
				print("Exception! {}\n{}".format(e.message,response))
				continue
	breakpoint()
	for issue in issue_list:
		cwe, desc, cve = tuple(issue)
		x_force_data['Description'].append(desc)
		x_force_data['CVE'].append(cve)	
		x_force_data['CWE-ID'].append(cwe)
	new_df = pd.DataFrame(data=x_force_data)
	frames = [curr_dataframe, new_df]	
	final_df = pd.concat(frames)
	print("Final df")
	breakpoint()	
	final_df.to_csv("../datasets/x_force_dataset.csv",index=False)


if __name__ == "__main__":
	asyncio.run(main())
	breakpoint()


"""


for i, cve in enumerate(cve_list):
	# If we havent already fetched a description for this cve
	if curr_dataframe.loc[curr_dataframe["CVE"] == cve].empty:
		
		try:
			r = requests.get(scheme + host + api.format(cve), headers=headers, cookies=cookies)
			if r.text != '{"error":"Not found."}' and r.text != '{"error":"Not authorized."}' and r.text != '{"error":"Invalid input."}':
				res = json.loads(r.text)
				
				desc = res[0]['description']
				x_force_data['Description'].append(desc)
				x_force_data['CVE'].append(cve)
				x_force_data['CWE-ID'].append(cwe_list[i])
				if len(x_force_data['CWE-ID']) % 100 == 0:
					print("Checkpoint")
					
					new_data = pd.DataFrame(data=x_force_data)
					merged_df = pd.concat([new_data, curr_dataframe])
					merged_df.to_csv("../datasets/x_force_dataset.csv",index=False)

				print("Collected:\n\t{}: {}".format(cve, desc))
		except Exception as e:
			print("Error! \nException: {}\n\tResponse text: \n{}".format(e,r.text))
			new_data = pd.DataFrame(data=x_force_data)
			merged_df = pd.concat([new_data, curr_dataframe])
			merged_df.to_csv("../datasets/x_force_dataset.csv",index=False)


new_data = pd.DataFrame(data=x_force_data)
merged_df = pd.concat([new_data, curr_dataframe])
merged_df.to_csv("../datasets/x_force_dataset.csv",index=False)
breakpoint()

"""
driver = webdriver.Firefox()
driver.get(scheme + host)
tos_elem = driver.find_element_by_xpath('//*[@id="termsCheckbox"]')
tos_elem.click()
guest_button_elem = driver.find_element_by_xpath("/html/body/div[1]/div/div/div[4]/p/a")
guest_button_elem.click()
search_box_elem = driver.find_element_by_xpath('//*[@id="top_search"]')
search_box_elem.send_keys('CVE-2003-0020')
search_box_elem.submit()



driver.get(scheme + host + "/vulnerabilities/11412")


driver.delete_all_cookies()
driver.add_cookie({"name" : "__cfduid", "value" : cf_cookie, "domain" : host})
driver.get(scheme + host + "/api/vulnerabilities/search/CVE-2003-0020")
content = driver.page_source
print(content)
"""
