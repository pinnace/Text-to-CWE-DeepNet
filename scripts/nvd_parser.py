#!/usr/bin/env python3

import json
import os
import pandas as pd
import numpy as np

nvd_data_dir = "../datasets/NVD/"
cwe_lookup_table_file = "../datasets/cwe-lookup-table.csv"
output_file = "../datasets/nvd-parsed-dataset.csv"
cwe_lookup_table = pd.read_csv(cwe_lookup_table_file)
cwe_categories: list = cwe_lookup_table.loc[cwe_lookup_table['Is_Category']==True]['CWE-ID'].values

nvd_data_files = [f for f in os.listdir(nvd_data_dir) if os.path.isfile(os.path.join(nvd_data_dir, f)) and f.endswith(".json")]

columns = ["CWE-ID", "Description", "CVE"]

cwes, descriptions, cves = [], [], []

total_count = 0
count_no_cwe = 0
count_multi_cwe = 0
# Helpers
def get_cwe(cwe_description_obj: dict) -> int:
	assigned_cwes = [
			int(cwe["value"].split("-")[1]) 
			for cwe in cwe_description_obj 
			if cwe["value"] != 'NVD-CWE-noinfo' and cwe["value"] != 'NVD-CWE-Other'
		]
	if not assigned_cwes:
		return -1
	if len(assigned_cwes) == 1:
		return assigned_cwes[0]

	# If more than one CWE is assigned:
	# - If all of them are categories of CWEs, then just return the first found
	# - If any are categories, then mask those and return the more specific CWE
	# - Otherwise, just return the first CWE in the chain. Can probably find a better solution later.

	category_mask = list(map(lambda check: True if check in cwe_categories else False, assigned_cwes))
	
	if all(category_mask):
		print("[!] More than one CWE found, but they were all categorical. Returning first.")
		return assigned_cwes[0]
	if any(category_mask):
		x = np.array(assigned_cwes)
		y = np.array(category_mask)
		m = np.ma.masked_where(y==0, x)		
		masked_cwes = list(np.ma.compressed(m))
		if len(masked_cwes) == 1:
			return masked_cwes[0]
		else:
			# Hasn't actually happened in testing. Throw error
			raise Exception("More than one CWE after masking categories")
	else:
		global count_multi_cwe 
		count_multi_cwe += 1
		return assigned_cwes[0]
	raise Exception("How did we get here? What a poorly written function")	


for nvd_data in nvd_data_files:
	cve_data = None
	with open(nvd_data_dir + nvd_data, 'r') as f:
		cve_data = json.load(f)

	for cve in cve_data["CVE_Items"]:
		cve = cve['cve']
		total_count += 1
		# ID CWE

		
		if len(cve["problemtype"]["problemtype_data"]) > 1 or len(cve["problemtype"]["problemtype_data"]) == 0:
			# Shouldn't happen
			raise Exception('Problemtype data is a weird size')
		cwe = get_cwe(cve["problemtype"]["problemtype_data"][0]["description"])
		# If the CWE was a noinfo, skip this cve
		if cwe == -1:
			count_no_cwe += 1
			continue
		
		cve_num = cve["CVE_data_meta"]["ID"]

		cve_desc = ""
		if len(cve["description"]["description_data"]) == 0:
			raise Exception("No description")
		if len(cve["description"]["description_data"]) >= 1:
			# Manually combed through data, first value almost always the best. others are unusuable, usually just hyperlinks
			cve_desc = cve["description"]["description_data"][0]["value"]

		cwes.append(cwe)
		cves.append(cve_num)
		descriptions.append(cve_desc)

dataset = pd.DataFrame(data={"CWE-ID": cwes, "Description" : descriptions, "CVE" : cves})
print("Dumping to file: {}".format(output_file))
dataset.to_csv(output_file, index=False)

print("Stats:\n\tTotal CVEs: {}\n\tWith CWEs: {}\n\tWithout CWEs: {}\n\tWith Multiple CWEs: {}".format(total_count, total_count - count_no_cwe, count_no_cwe, count_multi_cwe))
