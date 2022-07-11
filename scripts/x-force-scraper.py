#!/usr/bin/env python3

from bs4 import BeautifulSoup
import pandas as pd
import requests
import os
import base64

api_key = os.env["XFORCE_API_KEY"]
api_password = os.env["XFORCE_API_PASSWORD"]
api_url = "https://exchange.xforce.ibmcloud.com/api/vulnerabilities/{}"

un_pw = api_key + ":" + api_password
un_pw = base64.b64encode(un_pw.encode('ascii'))

headers = {
	"Accept" : "application/json",
	"Authorization" : "Basic " + un_pw
}

mapping_file = "../datasets/XForce/source-XF.html"
cve_lookup_file = "../datasets/TrainingV2/nvd_observed_all.csv"
xforce_data_dir = "../datasets/XForce/"

cve_frame = pd.read_csv(cve_lookup_file, index_col=False)
cve_frame = cve_frame.loc[cve_frame["CVE"] != "N/A"]

with open(mapping_file, 'r') as f:
	mapping = f.read()

soup = BeautifulSoup(mapping, 'html.parser')

tables = soup.find_all("table")

rows = tables[1].find_all("tr")

for row in rows:
	cves, descriptions, cwes = [],[], []
	row_elems = tuple(row.find_all("td"))
	xforce_id, cve = row_elems
	
	# Entries may have multiple CVEs
	links = cve.find_all("a")
	cves = [link.text.strip() for link in links]

	xforce_id = xforce_id.text[ xforce_id.text.find("(") + 1 : xforce_id.text.find(")")]
	# Just take the first CVE's CWE, the CWEs would (should) be the same
	cwes_from_dataset = cve_frame.loc[cve_frame["CVE"] == cves[0]]
	# This CVE may not be in the dataset (e.g. if pre-2009), skip this row if it isnt
	if not len(cwes_from_dataset):
		continue	
		
		
	cwes += [cwes_from_dataset["CWE-ID"].values[0]] * len(cves)
	if len(cwes) > 1:
		breakpoint()

	if not os.path.exists(xforce_data_dir + str(xforce_id) + ".json"):
		r = requests.get(api_url.format(xforce_id), headers=headers)
		

