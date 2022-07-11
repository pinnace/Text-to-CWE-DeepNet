#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import pandas as pd
import itertools
import os 
import json
from timeit import default_timer as timer

schema_filename = "../datasets/cwec_v4.0.xml"
observed_examples_filename = "../datasets/TrainingV2/observed-examples.csv"
name = lambda n: "{{http://cwe.mitre.org/cwe-6}}{}".format(n)
root = ET.parse(schema_filename).getroot()

# Build lookup object for CVEs
nvd_data_dir = "../datasets/NVD/"
nvd_data_files = [f for f in os.listdir(nvd_data_dir) if os.path.isfile(os.path.join(nvd_data_dir, f)) and f.endswith(".json")]

cve_by_year = {}
for nvd_data in nvd_data_files:
	cve_data = None
	with open(nvd_data_dir + nvd_data, 'r') as f:
		cve_data = json.load(f)
	year = int(nvd_data.split("-")[-1].split(".")[0])
	cve_by_year[year] = cve_data["CVE_Items"]

observed_desc = []
observed_cves = []
observed_cwes = []
for weakness in root.find(name('Weaknesses')).iter(name('Weakness')):
	start = timer()
	ID = weakness.attrib['ID']

	oe_elem = weakness.find(name("Observed_Examples"))
	examples = []
	if oe_elem is not None:
		examples = [
			(oe.find(name("Description")).text, oe.find(name("Reference")).text)
			for oe in oe_elem
		]
		pre_2009_nvd_examples = []
		for example in examples:
			desc, cve_num = example
			try:
				year = int(cve_num.split("-")[1])
			except:
				continue # Happens if the vulnerability does not have CVE label (e.g. SECUNIA)
			if year < 2009:
				# 1999 - 2002 data in 2002 json file
				year_key = year if year > 2001 else 2002
				print("[+] Searching for {}...".format(cve_num))
				for cve in cve_by_year[year_key]:
					if cve["cve"]["CVE_data_meta"]["ID"] == cve_num:
						nvd_desc = cve['cve']['description']['description_data'][0]['value']
						print("[+] Found {}:\n\rCWE Desc: {}\n\tNVD Desc: {}".format(cve["cve"]["CVE_data_meta"]["ID"], desc, nvd_desc))
						pre_2009_nvd_examples.append((nvd_desc, cve_num))		
						break
		examples += pre_2009_nvd_examples
	end = timer()
	print("Search for CWE {} took {} sec".format(ID,end - start))
	if examples:
		descriptions, cves = zip(*examples)
		observed_desc.append(descriptions)
		observed_cves.append(cves)
		observed_cwes.append([ID] * len(examples))

observed_desc = list(itertools.chain(*observed_desc))
observed_cves = list(itertools.chain(*observed_cves))
observed_cwes = list(itertools.chain(*observed_cwes))
observed_examples_dataset = pd.DataFrame(data={"CWE-ID" : observed_cwes, "Description" : observed_desc, "CVE" : observed_cves})		
breakpoint()
observed_examples_dataset.to_csv(observed_examples_filename, index=False)
