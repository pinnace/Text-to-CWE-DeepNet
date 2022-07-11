#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import pandas as pd
import itertools

cwe_ids, cwe_names, categories = [], [], []


schema_filename = "../datasets/cwec_v4.0.xml"

name = lambda n: "{{http://cwe.mitre.org/cwe-6}}{}".format(n)
root = ET.parse(schema_filename).getroot()

classes = []
for weakness in root.find(name('Weaknesses')).iter(name('Weakness')):
	ID = weakness.attrib['ID']
	cwe_name = weakness.attrib['Name']
	abstraction = weakness.attrib["Abstraction"]
	if abstraction == "Class":
		print("Found class:\n\tWeakness: {}\n\tCWE: {}".format(cwe_name, ID))
		classes.append(int(ID))

print(classes)
