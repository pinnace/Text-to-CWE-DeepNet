#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import pandas as pd
import itertools

cwe_ids, cwe_names, categories = [], [], []


schema_filename = "../datasets/cwec_v4.0.xml"
lookup_table_filename = "../datasets/cwe-lookup-table.csv"
dataset_filename = "../datasets/TrainingV2/cwe-schema-descriptions.csv"

cwe_ids_list = []
cwe_descriptions_list = []

name = lambda n: "{{http://cwe.mitre.org/cwe-6}}{}".format(n)
root = ET.parse(schema_filename).getroot()

for weakness in root.find(name('Weaknesses')).iter(name('Weakness')): 
	ID = weakness.attrib['ID']
	cwe_name = weakness.attrib['Name']
	is_category = False
	cwe_ids.append(ID)
	cwe_names.append(cwe_name)
	categories.append(False)
	#cwe_lookup_table.append({"CWE-ID" : ID, "Description" : cwe_name}, ignore_index=True)
	
	description, extended_description, background_details, consequences, introductions = None, None, None, None, None

	# Build a new dataset with the description texts

	# Every element with have a description
	description = weakness.find(name("Description")).text
	combined_descriptions = [description]

	# Some will have an extended description
	ed_elem = weakness.find(name("Extended_Description"))
	if ed_elem is not None and (ed_elem or ed_elem.text):
		extended_descriptions = []
		if len(ed_elem) > 1:
			extended_descriptions = [p.text for p in ed_elem]
		else:
			extended_descriptions = [ed_elem.text]
		combined_descriptions += extended_descriptions
	else:
                print("No extended description for ID: {}, Desc: {}".format(ID, cwe_name))

	# Some will have background details
	bgd_elem = weakness.find(name("Background_Details"))
	if bgd_elem is not None and (bgd_elem or bdg_elem.text):
		background_details: list = [background_detail.text for background_detail in bgd_elem]
		combined_descriptions += background_details
	else:
		print("No background details found for ID: {}, Desc: {}".format(ID, cwe_name))

	# Some will have consequences
	consq_elem = weakness.find(name("Common_Consequences"))
	if consq_elem is not None and (consq_elem or consq_elem.text):
		consequences: list = [
			consequence.find(name("Note")).text 
			for consequence in consq_elem if consequence.find(name("Note")) is not None and  consequence.find(name("Note")).text
		]

		combined_descriptions += consequences
	else:
                print("No consequences found for ID: {}, Desc: {}".format(ID, cwe_name))

	# Some will have modes of introduction
	modes_elem = weakness.find(name("Modes_Of_Introduction"))
	if modes_elem is not None and (modes_elem or modes_elem.text):
		introductions: list = [
			introduction.find(name("Note")).text 
			for introduction in modes_elem if introduction.find(name("Note")) is not None and introduction.find(name("Note")).text
		]

		combined_descriptions += introductions
	else:
                print("No mode of introduction found for ID: {}, Desc: {}".format(ID, cwe_name))

	combined_descriptions = [d.replace("\n"," ").replace("\t"," ").replace("   "," ") for d in combined_descriptions if d != None and d.strip() != '']

	# Will flatten these at the end
	cwe_ids_list.append([ID] * len(combined_descriptions))
	cwe_descriptions_list.append(combined_descriptions)


# Not creating training examples from the category descriptions. They are too broad. Just use for lookup table.
for category in root.find(name('Categories')).iter(name('Category')):
	ID = category.attrib['ID']
	cwe_name = category.attrib['Name']
	cwe_ids.append(ID)
	cwe_names.append(cwe_name)
	categories.append(True)
	#cwe_lookup_table.append({"CWE-ID" : ID, "Description" : cwe_name}, ignore_index=True)

cwe_lookup_table = pd.DataFrame(data={'CWE-ID' : cwe_ids, 'Description':cwe_names, 'Is_Category':categories})
print("Removing potential duplicates")
cwe_lookup_table = cwe_lookup_table.drop_duplicates(subset='CWE-ID',keep='first', inplace=False)
print("Dumping to file: {}".format(lookup_table_filename)) 
cwe_lookup_table.to_csv(lookup_table_filename,index=False)


cwes = list(itertools.chain(*cwe_ids_list))
cwe_descriptions = list(itertools.chain(*cwe_descriptions_list))
cwe_dataset = pd.DataFrame(data={"CWE-ID" : cwes, "Description" : cwe_descriptions, "CVE" : ["NA"] * len(cwes)})
print("Number of data points: {}".format(len(cwe_descriptions)))
print("Dumping Dataset to file: {}".format(dataset_filename))
cwe_dataset.to_csv(dataset_filename, index=False)
